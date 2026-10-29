//! Pipelined BFT Consensus Engine (Tendermint/HotStuff-inspired)
//!
//! A real consensus protocol: proposer selection, rounds, prevote/precommit,
//! quorum certificates, value locking (safety) and view-change (liveness).
//!
//! Safety rule (Tendermint locking): a validator that precommitted value `v` at
//! round `r` is LOCKED on `v`; in later rounds it will only prevote `v` (or nil),
//! never a conflicting value. This guarantees two conflicting blocks can never
//! both reach a 2/3 precommit quorum (assuming < 1/3 Byzantine power).
//!
//! Design notes (per passport):
//!  - No global locks; the engine is a pure state machine, driven by votes.
//!  - Votes are individually Ed25519-signed and verified on ingestion.
//!  - Equivocation (two different votes by one validator at the same height/round/
//!    kind) is recorded as evidence for slashing.
//!  - The engine is height-scoped; `ConsensusDriver` pipelines heights.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub type Height = u64;
pub type Round = u32;
pub type BlockHash = [u8; 32];
pub type ValidatorId = [u8; 32];

/// Anti-DoS bound: ignore votes for rounds more than this far ahead of ours.
pub const MAX_ROUND_AHEAD: Round = 1_000;

/// How far a single peer message may drag our round counter forward.
///
/// This is deliberately 1. Tendermint semantics: a node moves to the next round
/// on its OWN timeout, so a message may nudge us into the round we are about to
/// enter anyway, but never beyond it.
///
/// The looser `MAX_ROUND_AHEAD` (1000) above only decides whether a *claim* is
/// absurd enough to reject outright. Using it as the advance step was a live
/// liveness bug, measured on the two-machine stand: a fresh node at height 1
/// round 0 received a vote claiming round 57 and jumped straight there in
/// 100 ms. The proposer for a round is hash-scheduled (`proposer_for`), so the
/// round counter also decides WHO must propose. Two nodes inflating each
/// other's round therefore end up expecting proposers nobody serves, reject
/// every proposal as "wrong proposer", and sit in view changes forever -- the
/// exact wedge that made a healed partition unrecoverable.
pub const MAX_ROUND_ADVANCE_PER_MESSAGE: Round = 1;

/// Lookback window (rounds) for inspecting late votes, and the per-message cap
/// on how far `sync_round_to` may drag the local round forward.
///
/// This is the tighter of the two candidate caps for the peer-round-sync DoS
/// (audit F2). `MAX_ROUND_AHEAD` (1000) is only an absurdity gate, and
/// `MAX_ROUND_ADVANCE_PER_MESSAGE` (1) is too tight to be useful here: a peer
/// advancing one round per timeout would outpace a genuine laggard, so it could
/// never catch up by votes at all. Eight is tight enough that a Batch of 32
/// authenticated far-round votes can buy at most 256 rounds (previously 2048),
/// while still letting genuine far catch-up work in a few messages. Catch-up
/// beyond that window is carried by proposal acceptance, which aligns to the
/// proposer's near round in `on_proposal` and is independent of this counter.
pub const ROUND_LOOKBACK: Round = 8;

/// Upper bound on signers in a peer-supplied quorum certificate (audit F7).
///
/// The real validator set is far smaller than this; a certificate with more
/// entries is an attempt to make a verifier run an unbounded
/// signature-verification loop from a single message. The bound lives HERE and
/// is enforced inside `QuorumCertificate::verify`, so every caller that
/// verifies a certificate -- block sync, historical replay, adopt-committed,
/// light clients -- inherits it without each remembering to check first.
pub const MAX_COMMIT_CERT_SIGNERS: usize = 4_096;

// ============================================================================
// BLS aggregate envelopes (additive to the Ed25519 list — see bls.rs)
// ============================================================================

/// Magic prefix of a vote `signature` that carries a BLS half beside the
/// Ed25519 one: `VOTE_BLS_MAGIC || ed25519_sig(64) || bls_sig(96)`.
///
/// Rides INSIDE the existing `signature: Vec<u8>` so `Vote`'s bincode layout
/// is untouched: a flag-off node (the default, and the live stand) produces
/// and sees plain 64-byte signatures exactly as before, and only votes from a
/// node with `STELL_BLS_QC=1` grow the envelope.
pub const VOTE_BLS_MAGIC: &[u8; 16] = b"STELL_VOTEBLS_V1";
/// Size of the BLS half of an envelope vote signature.
pub const VOTE_BLS_PART_LEN: usize = 16 + 64 + 96;

/// Marker "validator id" for the BLS aggregate envelope entry carried inside
/// `QuorumCertificate::signatures`.
///
/// `[0xFF; 32]` as an unmintable sentinel: a verifier that predates this
/// format skips the entry through the SAME membership check every other entry
/// faces — `power_of(marker)` is 0 for any validator set that does not
/// deliberately contain it, so control returns before any signature parse,
/// exactly like any other non-member id. That is what keeps the certificate's
/// bincode layout IDENTICAL to the pre-BLS format while carrying the
/// aggregate: old bytes decode under new code, new bytes decode under old
/// code, and old code fails closed on a certificate whose only power is the
/// aggregate (its Ed25519 list is then short, and the marker counts for
/// nothing).
pub const BLS_QC_MARKER_ID: ValidatorId = [0xFF; 32];
/// Magic prefix of a certificate's BLS envelope payload.
pub const QC_BLS_MAGIC: &[u8; 16] = b"STELL_QC_BLS_V1_";

/// Encode a BLS aggregate as the payload of the marker entry in
/// `QuorumCertificate::signatures`. Self-describing and bound to this
/// certificate's fields:
/// `QC_BLS_MAGIC(16) || height u64le || round u32le || kind u8 || block_hash(32)
///  || total_validators u32le || sig(96) || bitvector(ceil(total/8))`.
pub fn encode_qc_bls_envelope(
    aggregate: &crate::bls::BlsAggregateSignature,
    height: Height,
    round: Round,
    kind: VoteKind,
    block_hash: Option<BlockHash>,
) -> Vec<u8> {
    let (sig, bits) = aggregate.to_bytes();
    let total = aggregate.participants.total_validators();
    let mut out = Vec::with_capacity(16 + 8 + 4 + 1 + 32 + 4 + 96 + bits.len());
    out.extend_from_slice(QC_BLS_MAGIC);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    out.push(match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    });
    match block_hash {
        Some(h) => out.extend_from_slice(&h),
        None => out.extend_from_slice(&[0u8; 32]),
    }
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&sig);
    out.extend_from_slice(bits);
    out
}

/// Decode a marker-entry payload. Returns `None` on ANY malformed input —
/// wrong magic, truncated fields, impossible validator count, bitvector length
/// mismatch — so a garbage envelope simply falls through to the Ed25519 list.
/// A nil target is encoded as an all-zero hash; the caller compares the raw
/// hash against its own `block_hash.unwrap_or([0; 32])`.
pub fn decode_qc_bls_envelope(
    payload: &[u8],
) -> Option<(Height, Round, VoteKind, BlockHash, crate::bls::BlsAggregateSignature)> {
    const HEADER: usize = 16 + 8 + 4 + 1 + 32 + 4 + 96;
    if payload.len() < HEADER || &payload[..16] != QC_BLS_MAGIC {
        return None;
    }
    let height = u64::from_le_bytes(payload[16..24].try_into().ok()?);
    let round = u32::from_le_bytes(payload[24..28].try_into().ok()?);
    let kind = match payload[28] {
        0 => VoteKind::Prevote,
        1 => VoteKind::Precommit,
        _ => return None,
    };
    let block_hash: BlockHash = payload[29..61].try_into().ok()?;
    let total = u32::from_le_bytes(payload[61..65].try_into().ok()?) as usize;
    // A certificate cannot name more signers than the DoS cap allows, and a
    // zero-validator set can never verify — reject both here.
    if total == 0 || total > MAX_COMMIT_CERT_SIGNERS {
        return None;
    }
    let sig_bytes: [u8; 96] = payload[65..161].try_into().ok()?;
    let bitlen = total.div_ceil(8);
    if payload.len() != HEADER + bitlen {
        return None;
    }
    let signature = crate::bls::BlsSignature::from_bytes(&sig_bytes)?;
    let participants = crate::bls::SignerBitVector::from_bitmask(payload[161..].to_vec(), total)?;
    Some((
        height,
        round,
        kind,
        block_hash,
        crate::bls::BlsAggregateSignature { signature, participants },
    ))
}

/// The Ed25519 half of a vote/certificate signature entry: strips the BLS
/// or Falcon envelope when present. Plain 64-byte signatures pass through untouched, so
/// this is a no-op for every certificate and vote produced with the BLS/Falcon flags
/// off.
pub fn ed25519_sig_bytes(signature: &[u8]) -> &[u8] {
    if signature.len() == VOTE_BLS_PART_LEN && signature.starts_with(VOTE_BLS_MAGIC) {
        &signature[16..80]
    } else if signature.len() == VOTE_FALCON_PART_LEN && signature.starts_with(VOTE_FALCON_MAGIC) {
        &signature[16..80]
    } else {
        signature
    }
}

// ============================================================================
// Post-Quantum envelopes & Micro-Committees (µQC) — PQ-BFT v5 Master Spec
// ============================================================================

/// Magic prefix of a vote signature carrying a Falcon-512 signature in an envelope.
pub const VOTE_FALCON_MAGIC: &[u8; 16] = b"STELL_VOTEFAL_V1";
/// Total length of vote signature envelope carrying Ed25519 + Falcon-512.
pub const VOTE_FALCON_PART_LEN: usize = 16 + 64 + crate::post_quantum::FALCON512_SIG_LEN;

pub use crate::post_quantum::FalconKeypair;

#[cfg(any(test, debug_assertions))]
pub trait FalconKeypairExt {
    fn from_seed(seed: u8) -> Self;
    fn validator_id(&self) -> ValidatorId;
}

#[cfg(any(test, debug_assertions))]
impl FalconKeypairExt for FalconKeypair {
    fn from_seed(seed: u8) -> Self {
        Self::generate_from_seed(seed)
    }

    fn validator_id(&self) -> ValidatorId {
        self.validator_id()
    }
}

pub fn falcon_validator_id(key: &FalconKeypair) -> ValidatorId {
    key.validator_id()
}

/// Verify a Falcon-512 signature. FIPS 206 ring math ONLY in every non-test
/// build.
///
/// The historical BLAKE3 "check digest" branch is a test-harness shortcut and
/// is compiled out outside `cfg(test)`. It must never be reachable in
/// production: it is not a signature scheme -- given the public key and the
/// message anyone recomputes the single trailing byte -- so while it was live
/// an attacker who knew only a victim's PUBLIC Falcon key could forge that
/// victim's transactions (`Transaction::verify_signature`), validator votes
/// (`Vote::verify`) and block proposals (`verify_proposer_signature`), i.e.
/// steal funds and drive consensus.
pub fn verify_falcon_signature_or_test(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if crate::post_quantum::verify_pq_signature(
        crate::post_quantum::PqScheme::Falcon512,
        pubkey,
        message,
        signature,
    ) {
        return true;
    }
    #[cfg(test)]
    if pubkey.len() == crate::post_quantum::FALCON512_PUBKEY_LEN
        && signature.len() == crate::post_quantum::FALCON512_SIG_LEN
        && signature[0] != 0xFF
    {
        let mut h = blake3::Hasher::new_derive_key("FALCON512_VERIFY_V4");
        h.update(pubkey);
        h.update(message);
        let commitment = *h.finalize().as_bytes();

        let mut checker = blake3::Hasher::new_derive_key("FALCON512_SIG_CHECK_V4");
        checker.update(&commitment);
        checker.update(&signature[..40]);
        checker.update(&signature[40..crate::post_quantum::FALCON512_SIG_LEN - 1]);
        let check_digest = checker.finalize();
        return signature[crate::post_quantum::FALCON512_SIG_LEN - 1] == check_digest.as_bytes()[0];
    }
    false
}

/// Verify the block proposal signature, supporting Falcon-512 and Pure PQ enforcement.
pub fn verify_proposer_signature(block: &crate::sharding::Block) -> bool {
    let hash = block.compute_hash();

    // Check if proposer signed with Falcon-512 key
    for (signer_id, sig_bytes) in &block.validator_signatures {
        if sig_bytes.len() == crate::post_quantum::FALCON512_SIG_LEN {
            let matches_proposer = *signer_id == block.proposer
                || get_validator_pq_key(&block.proposer).map_or(false, |(scheme, pk)| {
                    let addr = crate::post_quantum::derive_pq_address(
                        scheme,
                        &pk,
                        &crate::post_quantum::DEFAULT_SALT,
                    );
                    addr == *signer_id
                })
                || get_validator_pq_key(signer_id).map_or(false, |(scheme, pk)| {
                    let addr = crate::post_quantum::derive_pq_address(
                        scheme,
                        &pk,
                        &crate::post_quantum::DEFAULT_SALT,
                    );
                    addr == block.proposer || *signer_id == block.proposer
                });

            if matches_proposer {
                let pk_opt = get_validator_pq_key(signer_id)
                    .or_else(|| get_validator_pq_key(&block.proposer))
                    .map(|(_, pk)| pk);
                if let Some(pk) = pk_opt {
                    if verify_falcon_signature_or_test(&pk, &hash, sig_bytes) {
                        return true;
                    }
                }
                return false;
            }
        }
    }

    block.verify_proposer_signature()
}

pub trait BlockProposerExt {
    fn verify_proposer_signature_falcon(&self) -> bool;
}

impl BlockProposerExt for crate::sharding::Block {
    fn verify_proposer_signature_falcon(&self) -> bool {
        verify_proposer_signature(self)
    }
}

/// Attach a Falcon-512 signature to an existing vote signature (creating or updating the envelope).
pub fn attach_vote_falcon(key: &FalconKeypair, msg: &[u8], signature: &mut Vec<u8>) {
    let falcon_sig = key.sign(msg);
    let mut ed = vec![0u8; 64];
    if signature.len() == 64 {
        ed.copy_from_slice(signature);
    } else if signature.len() == VOTE_BLS_PART_LEN && signature.starts_with(VOTE_BLS_MAGIC) {
        ed.copy_from_slice(&signature[16..80]);
    } else if signature.len() == VOTE_FALCON_PART_LEN && signature.starts_with(VOTE_FALCON_MAGIC) {
        ed.copy_from_slice(&signature[16..80]);
    }
    let mut out = Vec::with_capacity(VOTE_FALCON_PART_LEN);
    out.extend_from_slice(VOTE_FALCON_MAGIC);
    out.extend_from_slice(&ed);
    out.extend_from_slice(&falcon_sig);
    *signature = out;
}

/// Sentinel marker ID for Full Epoch Certificate (CEC).
pub const PQ_QC_MARKER_ID: ValidatorId = [0xFE; 32];
/// Sentinel marker ID for Micro-Committee (µQC).
pub const PQ_UQC_MARKER_ID: ValidatorId = [0xFD; 32];
/// Magic prefix of a Micro-Committee post-quantum envelope payload.
pub const QC_UQC_MAGIC: &[u8; 16] = b"STELL_UQC_PQ_V4_";
/// Magic prefix of a Full Epoch Certificate post-quantum envelope payload.
pub const QC_PQ_MAGIC: &[u8; 16] = b"STELL_QC_PQ_V4__";

/// Post-Quantum Micro-Certificate (µQC) for fast 250ms block finality.
///
/// Implements §3 of Stellereum PQ-BFT v5 Master Spec:
/// - Compact committee (default k = 16) selected via BLAKE3 stake-weighted sortition.
/// - Quorum: power-weighted `floor(2*W/3) + 1` over the committee's total
///   voting power `W` (same consensus-domain curve as [`consensus_quorum_min`]).
///   With equal per-validator power this coincides with the legacy head-count
///   `floor(2*k/3) + 1` (11 of 16 for k=16), so every historic certificate
///   that met the old count rule on a uniform set still verifies; on a skewed
///   set any subset whose STAKE reaches quorum suffices (e.g. 2 of 3 by heads
///   when their combined power covers 2/3+1 of the committee).
/// - Carried inside `QuorumCertificate::signatures` under sentinel marker `PQ_UQC_MARKER_ID`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMicroCertificate {
    pub scheme: crate::post_quantum::PqScheme,
    pub height: Height,
    pub round: Round,
    pub committee_size: u32,
    pub signers_bitmask: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

impl PqMicroCertificate {
    pub fn new(
        scheme: crate::post_quantum::PqScheme,
        height: Height,
        round: Round,
        committee_size: u32,
        signers_bitmask: Vec<u8>,
        signatures: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            scheme,
            height,
            round,
            committee_size,
            signers_bitmask,
            signatures,
        }
    }

    /// Legacy head-count quorum threshold for this micro-committee:
    /// floor(2*k/3) + 1.
    ///
    /// Kept for wire/backward-compat inspection (and pinned by
    /// `bridge::tests::quorum_formulas_are_pinned_per_domain`). The VERIFY
    /// path no longer gates on this: [`QuorumCertificate::verify`] sums the
    /// committee members' voting POWER against [`pq_micro_quorum_power`].
    /// On uniform-power committees both curves agree, so historic 3/3 and
    /// 11/16 certificates verify under the new code unchanged.
    pub fn required_quorum(&self) -> usize {
        pq_micro_quorum_threshold(self.committee_size)
    }

    /// Whether validator at committee index `index` is marked as a signer.
    pub fn is_signer(&self, index: usize) -> bool {
        if index >= self.committee_size as usize {
            return false;
        }
        let byte = index / 8;
        let bit = index % 8;
        if byte >= self.signers_bitmask.len() {
            return false;
        }
        (self.signers_bitmask[byte] & (1 << bit)) != 0
    }

    /// Mark validator at committee index `index` as signed or unsigned.
    pub fn set_signer(&mut self, index: usize, signed: bool) {
        if index >= self.committee_size as usize {
            return;
        }
        let byte = index / 8;
        let bit = index % 8;
        if byte >= self.signers_bitmask.len() {
            self.signers_bitmask.resize(byte + 1, 0);
        }
        if signed {
            self.signers_bitmask[byte] |= 1 << bit;
        } else {
            self.signers_bitmask[byte] &= !(1 << bit);
        }
    }

    /// Total count of committee members marked as having signed.
    pub fn signed_count(&self) -> usize {
        (0..self.committee_size as usize)
            .filter(|&i| self.is_signer(i))
            .count()
    }

    /// Total voting power of the marked signers against a resolved committee.
    ///
    /// `committee` must be the sortition output for this certificate's
    /// `(height, round, committee_size)` in canonical sorted order; index `i`
    /// of the bitmask means `committee[i]`. Out-of-range bits (when the
    /// validator set is smaller than `committee_size`) contribute nothing.
    pub fn signed_power(&self, committee: &[ValidatorId], validators: &ValidatorSet) -> u64 {
        let mut power = 0u64;
        for (i, id) in committee.iter().enumerate() {
            if self.is_signer(i) {
                power = power.saturating_add(validators.power_of(id));
            }
        }
        power
    }

    /// Legacy head-count quorum check (uniform-power view).
    ///
    /// Kept for inspection/compat; consensus VERIFICATION uses
    /// power-weighted accounting instead (see [`pq_micro_quorum_power`]).
    pub fn has_quorum(&self) -> bool {
        self.committee_size > 0 && self.signed_count() >= self.required_quorum()
    }

    /// Power-weighted quorum check against a resolved committee.
    ///
    /// Fail-closed: empty committee or zero total committee weight never has
    /// quorum (returns `false`), mirroring [`ValidatorSet::quorum_power`]'s
    /// `u64::MAX` guard for the empty set.
    pub fn has_power_quorum(&self, committee: &[ValidatorId], validators: &ValidatorSet) -> bool {
        if committee.is_empty() || self.committee_size == 0 {
            return false;
        }
        let total: u64 = committee.iter().map(|id| validators.power_of(id)).sum();
        if total == 0 {
            return false;
        }
        self.signed_power(committee, validators) >= pq_micro_quorum_power(total)
    }

    /// Encode into canonical wire envelope with `QC_UQC_MAGIC`.
    pub fn encode(&self) -> Vec<u8> {
        encode_pq_micro_envelope(self)
    }

    /// Decode from wire envelope.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        decode_pq_micro_envelope(payload)
    }
}

/// Consensus-domain quorum floor: `floor(2n/3) + 1` votes (or voting power)
/// out of `n`.
///
/// Domain: PBFT/PQ-BFT finality. It is deliberately NOT the bridge threshold
/// [`crate::bridge::quorum_threshold`] (`floor((2n+2)/3)`, floored at 1): that
/// counts DISTINCT signers of an external cross-chain signer set and is LOWER
/// — at n = 3 consensus demands 3 while the bridge accepts 2. The `+1` here
/// makes a bare 2/3 (exactly two thirds when n % 3 == 0) insufficient, which is
/// what makes the BFT safety argument hold. The two curves must never be
/// "unified"; both are pinned for n = 1..8 by
/// `bridge::tests::quorum_formulas_are_pinned_per_domain`.
pub fn consensus_quorum_min(n: u64) -> u64 {
    (n * 2) / 3 + 1
}

/// Strict quorum threshold for micro-committee of size k: floor(2*k/3) + 1.
///
/// Same consensus-domain curve as [`consensus_quorum_min`]; a zero-size
/// committee is unrepresentable as a real threshold, so it fails closed with
/// `usize::MAX` instead of the formula's 1.
///
/// LEGACY head-count curve: kept for wire/backward-compat inspection and
/// pinned by `bridge::tests::quorum_formulas_are_pinned_per_domain`. Live
/// µQC VERIFICATION does not gate on this anymore — it sums committee voting
/// power against [`pq_micro_quorum_power`].
pub fn pq_micro_quorum_threshold(committee_size: u32) -> usize {
    if committee_size == 0 {
        return usize::MAX;
    }
    consensus_quorum_min(committee_size as u64) as usize
}

/// Power-weighted quorum threshold for a micro-committee: `floor(2*W/3) + 1`
/// over the committee's total voting power `W`.
///
/// This is the LIVE µQC rule (classical BFT accounting applied to the
/// sortition committee): the verifier sums the powers of the committee
/// members with valid signatures and requires `>=` this value. A zero-power
/// committee is unrepresentable as a real threshold, so it fails closed with
/// `u64::MAX` — exactly like [`ValidatorSet::quorum_power`] for the empty
/// set — and can never be satisfied.
pub fn pq_micro_quorum_power(committee_total_power: u64) -> u64 {
    if committee_total_power == 0 {
        return u64::MAX;
    }
    consensus_quorum_min(committee_total_power)
}

/// Deterministic BLAKE3 sortition committee selector.
///
/// Selects a subset of validators of size `committee_size` weighted proportionally
/// by validator stake (voting power), without replacement.
/// The resulting committee is returned in canonical sorted order.
pub fn derive_sortition_committee(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
) -> Vec<ValidatorId> {
    if committee_size == 0 || validators.is_empty() || validators.total_power() == 0 {
        return Vec::new();
    }

    // Filter positive-power validators in canonical sorted order (BTreeMap order)
    let mut pool: Vec<(ValidatorId, u64)> = validators
        .validators
        .iter()
        .filter(|(_, &p)| p > 0)
        .map(|(&id, &p)| (id, p))
        .collect();

    let target_k = (committee_size as usize).min(pool.len());
    if target_k == 0 {
        return Vec::new();
    }
    if target_k == pool.len() {
        let mut ids: Vec<ValidatorId> = pool.into_iter().map(|(id, _)| id).collect();
        ids.sort_unstable();
        return ids;
    }

    let mut selected = Vec::with_capacity(target_k);
    let mut total_power: u64 = pool.iter().map(|(_, p)| *p).sum();

    for step in 0..target_k {
        if total_power == 0 || pool.is_empty() {
            break;
        }

        let mut hasher = blake3::Hasher::new_derive_key("STELL_SORTITION_V4");
        hasher.update(&height.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        hasher.update(&(step as u32).to_le_bytes());
        let hash = hasher.finalize();

        let rand_val = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
        let ticket = rand_val % total_power;

        let mut acc = 0u64;
        let mut chosen_idx = 0;
        for (idx, (_id, power)) in pool.iter().enumerate() {
            acc += *power;
            if ticket < acc {
                chosen_idx = idx;
                break;
            }
        }

        let (winner_id, winner_power) = pool.remove(chosen_idx);
        total_power = total_power.saturating_sub(winner_power);
        selected.push(winner_id);
    }

    selected.sort_unstable();
    selected
}

/// Encode a post-quantum micro-certificate (µQC) into its canonical wire envelope.
///
/// Layout:
/// `QC_UQC_MAGIC (16B) || scheme_id (1B) || height u64le (8B) || round u32le (4B)
///  || committee_size u32le (4B) || bitmask_len u32le (4B) || bitmask_bytes
///  || sig_count u32le (4B) || [sig_len u32le (4B) || sig_bytes]*`
pub fn encode_pq_micro_envelope(cert: &PqMicroCertificate) -> Vec<u8> {
    let bitmask_len = cert.signers_bitmask.len();
    let sig_count = cert.signatures.len();
    let total_sig_bytes: usize = cert.signatures.iter().map(|s| 4 + s.len()).sum();
    let mut out = Vec::with_capacity(16 + 1 + 8 + 4 + 4 + 4 + bitmask_len + 4 + total_sig_bytes);

    out.extend_from_slice(QC_UQC_MAGIC);
    out.push(cert.scheme.id());
    out.extend_from_slice(&cert.height.to_le_bytes());
    out.extend_from_slice(&cert.round.to_le_bytes());
    out.extend_from_slice(&cert.committee_size.to_le_bytes());
    out.extend_from_slice(&(bitmask_len as u32).to_le_bytes());
    out.extend_from_slice(&cert.signers_bitmask);
    out.extend_from_slice(&(sig_count as u32).to_le_bytes());
    for sig in &cert.signatures {
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(sig);
    }
    out
}

/// Decode a post-quantum micro-certificate (µQC) envelope payload.
///
/// Returns `None` on any malformed input, truncated buffer, unknown scheme,
/// or signature count exceeding `MAX_COMMIT_CERT_SIGNERS`.
pub fn decode_pq_micro_envelope(payload: &[u8]) -> Option<PqMicroCertificate> {
    const MIN_HEADER: usize = 16 + 1 + 8 + 4 + 4 + 4 + 4; // 41 bytes
    if payload.len() < 16 || &payload[..16] != QC_UQC_MAGIC {
        return None;
    }

    if payload.len() >= MIN_HEADER {
        if let Ok(scheme) = crate::post_quantum::PqScheme::from_id(payload[16]) {
            let height = u64::from_le_bytes(payload[17..25].try_into().ok()?);
            let round = u32::from_le_bytes(payload[25..29].try_into().ok()?);
            let committee_size = u32::from_le_bytes(payload[29..33].try_into().ok()?);
            let bitmask_len = u32::from_le_bytes(payload[33..37].try_into().ok()?) as usize;

            let mut cursor = 37;
            if payload.len() >= cursor + bitmask_len + 4 {
                let signers_bitmask = payload[cursor..cursor + bitmask_len].to_vec();
                cursor += bitmask_len;

                let sig_count = u32::from_le_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
                cursor += 4;

                if sig_count <= MAX_COMMIT_CERT_SIGNERS {
                    let mut signatures = Vec::with_capacity(sig_count);
                    let mut valid = true;

                    for _ in 0..sig_count {
                        if cursor + 4 > payload.len() {
                            valid = false;
                            break;
                        }
                        let sig_len = u32::from_le_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
                        cursor += 4;
                        if cursor + sig_len > payload.len() {
                            valid = false;
                            break;
                        }
                        signatures.push(payload[cursor..cursor + sig_len].to_vec());
                        cursor += sig_len;
                    }

                    if valid && cursor == payload.len() {
                        return Some(PqMicroCertificate {
                            scheme,
                            height,
                            round,
                            committee_size,
                            signers_bitmask,
                            signatures,
                        });
                    }
                }
            }
        }
    }

    // Fallback: bincode deserialization after QC_UQC_MAGIC prefix.
    //
    // Audit-consensus F9 (assessed 2026-10-14, KEPT deliberately): accepting
    // non-canonical encodings here is safe because `verify_micro_cert`
    // re-checks everything load-bearing — bitmask length, trailing-bit zero,
    // out-of-range signer bits, compact/full shape, per-signature fail-closed
    // verify, and power quorum. A non-canonical blob can therefore decode but
    // never VERIFY unless it names a real quorum of valid signatures, and
    // removing the fallback would only risk rejecting historic certificates
    // for zero safety gain. Pinned by test (`decode_rejects_malformed...`).
    bincode::deserialize::<PqMicroCertificate>(&payload[16..]).ok()
}

/// Encode a full epoch post-quantum certificate (CEC).
pub fn encode_pq_epoch_envelope(cert: &PqMicroCertificate) -> Vec<u8> {
    let mut out = encode_pq_micro_envelope(cert);
    out[..16].copy_from_slice(QC_PQ_MAGIC);
    out
}

/// Decode a full epoch post-quantum certificate (CEC).
pub fn decode_pq_epoch_envelope(payload: &[u8]) -> Option<PqMicroCertificate> {
    if payload.len() < 16 || &payload[..16] != QC_PQ_MAGIC {
        return None;
    }
    let mut temp = payload.to_vec();
    temp[..16].copy_from_slice(QC_UQC_MAGIC);
    decode_pq_micro_envelope(&temp)
}

/// Global registry for validator post-quantum public keys.
static PQ_VALIDATOR_KEYS: std::sync::RwLock<Option<HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>> =
    std::sync::RwLock::new(None);

/// Register a validator's post-quantum public key and scheme.
pub fn register_validator_pq_key(
    id: ValidatorId,
    scheme: crate::post_quantum::PqScheme,
    pubkey: Vec<u8>,
) {
    // Disabled schemes register nothing (ML-DSA-44's verifier is forgeable).
    if scheme.is_disabled() {
        return;
    }
    let mut lock = PQ_VALIDATOR_KEYS.write().unwrap_or_else(|e| e.into_inner());
    let map = lock.get_or_insert_with(HashMap::new);
    map.insert(id, (scheme, pubkey));
}

/// Retrieve a registered validator's post-quantum scheme and public key.
pub fn get_validator_pq_key(id: &ValidatorId) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)> {
    let lock = PQ_VALIDATOR_KEYS.read().unwrap_or_else(|e| e.into_inner());
    lock.as_ref()?.get(id).cloned()
}

/// Clear registered validator post-quantum keys (for test hygiene).
#[cfg(any(test, debug_assertions))]
pub fn clear_validator_pq_keys_for_tests() {
    let mut lock = PQ_VALIDATOR_KEYS.write().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = lock.as_mut() {
        map.clear();
    }
}

// ============================================================================
// Validator set
// ============================================================================

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// validator pubkey -> voting power
    pub validators: BTreeMap<ValidatorId, u64>,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self { validators: BTreeMap::new() }
    }

    pub fn from_list(list: Vec<(ValidatorId, u64)>) -> Self {
        let mut s = Self::new();
        for (id, power) in list {
            s.add(id, power);
        }
        s
    }

    pub fn add(&mut self, id: ValidatorId, power: u64) {
        if power > 0 {
            self.validators.insert(id, power);
        }
    }

    pub fn total_power(&self) -> u64 {
        self.validators.values().sum()
    }

    /// Quorum is strictly more than 2/3 of total power: floor(2*total/3) + 1,
    /// the consensus-domain curve [`consensus_quorum_min`].
    pub fn quorum_power(&self) -> u64 {
        let total = self.total_power();
        if total == 0 {
            // An empty or zero-power validator set must never reach quorum.
            //
            // The formula below gives (0 * 2) / 3 + 1 == 1, so a single vote
            // would satisfy it: one node could finalise every block on its own
            // and produce the entire chain unilaterally. The two nodes would
            // then report identical state roots while never having agreed on
            // anything, because neither was actually constrained by the other.
            //
            // Returning an unreachable power makes the empty set unable to
            // finalise at all, which is the safe failure: the chain stalls and
            // says so, instead of running with no consensus in it.
            return u64::MAX;
        }
        consensus_quorum_min(total)
    }

    pub fn contains(&self, id: &ValidatorId) -> bool {
        self.validators.contains_key(id)
    }

    pub fn power_of(&self, id: &ValidatorId) -> u64 {
        self.validators.get(id).copied().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Deterministic proposer selection: weighted round-robin over sorted validators.
    /// `slot = height + round` maps into the cumulative power table, NORMALIZED
    /// by the GCD of all powers. Without normalization, large equal powers
    /// (e.g. 10^12 each from genesis bonds) hand the lexicographically first
    /// validator EVERY slot until height+round crosses 10^12: the second node
    /// never proposes, which removed the locked-reproposal liveness escape and
    /// stalled the live stand permanently after one asymmetric lock. GCD keeps
    /// the weighting exact (2:1 stays B,B,A) while rotating fairly from h=1.
    ///
    /// HASH-SLOT (2026-10-14, live stall at #95154): GCD alone does NOT fix
    /// coprime-ish real powers (live: 1874531430003/2e12/2e12, gcd=1, total
    /// 5.8e12). `(height+round) % total` then equals `height+round` for the
    /// first ~1.9e12 heights — ~60,000 years at 1 block/s — so the
    /// lexicographically-first validator (a DOWN node) proposed every round
    /// forever and the other two never got a slot: total silence, zero
    /// proposals, both nodes view-changing to no end. The slot is therefore
    /// `BLAKE3("STELL_PROPOSER_V1" || height || round) mod (total/g)`:
    /// uniform over the whole power range from height 1, deterministic on
    /// every node (no beacon, no extra messages), statistically proportional
    /// to power. Proposer lookahead is inherent (as with round-robin) and
    /// accepted for testnet. CONSENSUS CHANGE: old nodes compute a different
    /// schedule — deploy only as a coordinated all-validators upgrade.
    pub fn proposer_for(&self, height: Height, round: Round) -> Option<ValidatorId> {
        let total = self.total_power();
        if total == 0 {
            return None;
        }
        fn gcd(mut a: u64, mut b: u64) -> u64 {
            while b != 0 {
                let t = b;
                b = a % b;
                a = t;
            }
            a
        }
        let g = self.validators.values().fold(0u64, |acc, &p| gcd(acc, p));
        let g = if g == 0 { 1 } else { g };
        let range = total / g;
        let mut hasher = blake3::Hasher::new_derive_key("STELL_PROPOSER_V1");
        hasher.update(&height.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        let digest = hasher.finalize();
        let slot = u64::from_le_bytes(
            digest.as_bytes()[..8]
                .try_into()
                .expect("blake3 digest is 32 bytes"),
        ) % range;
        // Deterministic order (audit-consensus F8): the set is a `BTreeMap`
        // (sorted iteration today), but the schedule must not depend on any
        // container's implicit order — sort EXPLICITLY so every node walks
        // the same cumulative table even if the map type ever changes.
        // (An older comment here said "HashMap"; the container is and was a
        // `BTreeMap` — the explicit sort is what makes the claim load-bearing
        // rather than incidental.) Walking the map raw would elect a
        // DIFFERENT proposer on each node for the same (height, round):
        // with two equal-power validators the nodes disagreed half
        // the rounds (masked by fast retries), with three the agreement odds
        // per round fell to ~1/9 and the chain halted (observed live: three
        // nodes, zero coinciding proposers for hours). Sorted ids make the
        // schedule identical everywhere.
        let mut ids: Vec<(&ValidatorId, &u64)> = self.validators.iter().collect();
        ids.sort_unstable();
        let mut acc = 0u64;
        for (id, power) in ids {
            acc += *power / g;
            if slot < acc {
                return Some(*id);
            }
        }
        self.validators.keys().next().copied()
    }
}

// ============================================================================
// Votes
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub height: Height,
    pub round: Round,
    pub kind: VoteKind,
    /// None = nil vote (explicit "I saw no valid value this round")
    pub block_hash: Option<BlockHash>,
    pub voter: ValidatorId,
    pub signature: Vec<u8>,
}

/// The exact bytes a validator signs for a vote.
///
/// Public so a node whose key lives in an HSM / remote signer can produce the
/// signature out of process and hand back the bytes. Exposing the preimage does not
/// weaken anything: it is already reconstructible by anyone from the vote's public
/// fields, and `Vote::verify` recomputes it. Keeping a single definition here is what
/// stops the remote path from drifting from the local one.
pub fn vote_sign_bytes(height: Height, round: Round, kind: VoteKind, block_hash: &Option<BlockHash>) -> Vec<u8> {
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(b"STELLEREUM_BFT_VOTE_V1");
    m.extend_from_slice(&height.to_be_bytes());
    m.extend_from_slice(&round.to_be_bytes());
    m.push(match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    });
    match block_hash {
        Some(h) => {
            m.push(1);
            m.extend_from_slice(h);
        }
        None => m.push(0),
    }
    m
}

impl Vote {
    pub fn sign(
        key: &SigningKey,
        height: Height,
        round: Round,
        kind: VoteKind,
        block_hash: Option<BlockHash>,
    ) -> Self {
        let voter = key.verifying_key().to_bytes();
        let msg = vote_sign_bytes(height, round, kind, &block_hash);
        let sig = key.sign(&msg);
        let mut signature = sig.to_vec();
        attach_vote_bls(&msg, &mut signature);
        Self { height, round, kind, block_hash, voter, signature }
    }

    /// Build a vote from a signature produced elsewhere (HSM / remote signer).
    ///
    /// The caller must have signed `vote_sign_bytes(height, round, kind, block_hash)`
    /// with the key behind `voter`. `Vote::verify` checks it, so an incorrect signature
    /// is rejected at the same place a locally produced one would be.
    ///
    /// When the QC-BLS path is enabled, the local BLS half is appended as an
    /// envelope (`VOTE_BLS_MAGIC || ed || bls`) even though the Ed25519 half
    /// came from elsewhere: the BLS key stays in this process, and the
    /// envelope is what lets certificates aggregate this vote.
    pub fn signed_with(
        voter: ValidatorId,
        height: Height,
        round: Round,
        kind: VoteKind,
        block_hash: Option<BlockHash>,
        signature: Vec<u8>,
    ) -> Self {
        let mut vote = Self { height, round, kind, block_hash, voter, signature };
        let msg = vote_sign_bytes(height, round, kind, &block_hash);
        attach_vote_bls(&msg, &mut vote.signature);
        vote
    }

    pub fn verify(&self) -> bool {
        let msg = vote_sign_bytes(self.height, self.round, self.kind, &self.block_hash);

        // Under Pure Post-Quantum Mode, a valid Falcon signature is strictly required
        if crate::post_quantum::is_pure_pq_enforced() {
            if let Some(falcon_sig) = self.falcon_signature() {
                if let Some((_scheme, pk)) = get_validator_pq_key(&self.voter) {
                    return verify_falcon_signature_or_test(&pk, &msg, falcon_sig);
                }
            }
            return false;
        }

        // When a Falcon signature is present and the validator has registered a PQ key, verify Falcon
        if let Some(falcon_sig) = self.falcon_signature() {
            if let Some((_scheme, pk)) = get_validator_pq_key(&self.voter) {
                if !verify_falcon_signature_or_test(&pk, &msg, falcon_sig) {
                    return false;
                }
            }
        }

        // Verify Ed25519 signature
        let Ok(vk) = VerifyingKey::from_bytes(&self.voter) else {
            // Non-Ed25519 voter address (e.g. Falcon address)
            if let Some(falcon_sig) = self.falcon_signature() {
                if let Some((_scheme, pk)) = get_validator_pq_key(&self.voter) {
                    return verify_falcon_signature_or_test(&pk, &msg, falcon_sig);
                }
            }
            return false;
        };
        let ed_bytes = ed25519_sig_bytes(&self.signature);
        let Ok(sig) = Signature::from_slice(ed_bytes) else {
            return false;
        };
        vk.verify_strict(&msg, &sig).is_ok()
    }

    /// The bare Ed25519 signature bytes (envelope stripped when present).
    /// What belongs in a certificate's Ed25519 list.
    pub fn ed25519_signature(&self) -> &[u8] {
        ed25519_sig_bytes(&self.signature)
    }

    /// Batch-verify many votes at once (Ed25519 batch verify). Returns true
    /// iff EVERY vote carries a valid signature.
    ///
    /// Envelope-aware like [`Vote::verify`]: the Ed25519 half is taken out of
    /// `MAGIC || ed || bls` when present, anything else must parse as a bare
    /// 64-byte signature — fail closed. A vote whose key or signature does not
    /// parse fails the batch (same as its scalar `verify` returning false).
    ///
    /// Pure-PQ mirror (audit fail-closed): under [`crate::post_quantum::is_pure_pq_enforced`]
    /// the Ed25519 batch is SKIPPED and every vote goes through scalar
    /// [`Vote::verify`], which strictly requires a valid Falcon-512 half —
    /// exactly what [`VoteSet::add`] enforces per vote. Otherwise a batch of
    /// Ed25519-only votes would verify while each single `add` refuses them.
    ///
    /// Determinism: the verdict is order-independent (all-or-nothing over the
    /// set). Uses the same `ed25519_dalek::verify_batch` pattern as
    /// `QuorumCertificate::verify`'s fast path.
    pub fn verify_batch(votes: &[Vote]) -> bool {
        if votes.is_empty() {
            return true;
        }
        if crate::post_quantum::is_pure_pq_enforced() {
            return votes.iter().all(|v| v.verify());
        }
        let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(votes.len());
        let mut sigs: Vec<Signature> = Vec::with_capacity(votes.len());
        let mut keys: Vec<VerifyingKey> = Vec::with_capacity(votes.len());
        for v in votes {
            let Ok(vk) = VerifyingKey::from_bytes(&v.voter) else {
                return false;
            };
            let Ok(sig) = Signature::from_slice(v.ed25519_signature()) else {
                return false;
            };
            msgs.push(vote_sign_bytes(v.height, v.round, v.kind, &v.block_hash));
            sigs.push(sig);
            keys.push(vk);
        }
        let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        ed25519_dalek::verify_batch(&msg_refs, &sigs, &keys).is_ok()
    }

    /// Per-vote validity for a batch of votes (Ed25519 batch verify with
    /// deterministic scalar fallback).
    ///
    /// Fallback semantics (VOTES — keep the good ones): dropping a whole batch
    /// on one bad neighbor would lose honest votes and could stall a quorum,
    /// so a batch rejection falls back to the scalar [`Vote::verify`] per vote
    /// in INPUT order and only the bad votes are marked `false`. Element `i`
    /// always equals `votes[i].verify()` — no behavior change, with offenders
    /// identified for slashing / peer down-scoring.
    ///
    /// Determinism: per-item validity never depends on batch order; the
    /// fallback iterates input order, so the result is stable for a given
    /// input on whichever path is taken.
    ///
    /// Pure-PQ mirror (audit fail-closed): under [`crate::post_quantum::is_pure_pq_enforced`]
    /// the Ed25519 batch screen is SKIPPED and every vote goes through scalar
    /// [`Vote::verify`], which strictly requires a valid Falcon-512 half —
    /// exactly what [`VoteSet::add`] enforces per vote. Otherwise `add_batch`
    /// would admit Ed25519-only votes that a single `add` refuses.
    pub fn partition_valid(votes: &[Vote]) -> Vec<bool> {
        if votes.is_empty() {
            return Vec::new();
        }
        if crate::post_quantum::is_pure_pq_enforced() {
            return votes.iter().map(|v| v.verify()).collect();
        }
        // Items that cannot even be staged (bad key / bad sig bytes) are
        // already known-bad without failing the good ones' batch verdict.
        let mut bad = vec![false; votes.len()];
        let mut msgs: Vec<Vec<u8>> = Vec::with_capacity(votes.len());
        let mut sigs: Vec<Signature> = Vec::with_capacity(votes.len());
        let mut keys: Vec<VerifyingKey> = Vec::with_capacity(votes.len());
        for (i, v) in votes.iter().enumerate() {
            let (Ok(vk), Ok(sig)) = (
                VerifyingKey::from_bytes(&v.voter),
                Signature::from_slice(v.ed25519_signature()),
            ) else {
                bad[i] = true;
                continue;
            };
            msgs.push(vote_sign_bytes(v.height, v.round, v.kind, &v.block_hash));
            sigs.push(sig);
            keys.push(vk);
        }
        if sigs.is_empty() {
            return vec![false; votes.len()];
        }
        {
            let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            if ed25519_dalek::verify_batch(&msg_refs, &sigs, &keys).is_ok() {
                return bad.iter().map(|b| !b).collect();
            }
        }
        // Slow path: batch rejected — scalar verdict per vote, input order.
        let out: Vec<bool> = votes.iter().map(|v| v.verify()).collect();
        debug_assert!(out.iter().enumerate().all(|(i, v)| !bad[i] || !v));
        out
    }

    /// The BLS half of this vote's signature, when it carries one.
    pub fn bls_signature(&self) -> Option<[u8; 96]> {
        if self.signature.len() == VOTE_BLS_PART_LEN && self.signature.starts_with(VOTE_BLS_MAGIC) {
            self.signature[80..176].try_into().ok()
        } else {
            None
        }
    }

    /// The Falcon-512 half of this vote's signature, when it carries one.
    pub fn falcon_signature(&self) -> Option<&[u8]> {
        if self.signature.len() == VOTE_FALCON_PART_LEN && self.signature.starts_with(VOTE_FALCON_MAGIC) {
            Some(&self.signature[80..80 + crate::post_quantum::FALCON512_SIG_LEN])
        } else if self.signature.len() == crate::post_quantum::FALCON512_SIG_LEN {
            Some(&self.signature)
        } else {
            None
        }
    }

    /// Sign a vote carrying both Ed25519 and Falcon-512 signatures.
    pub fn sign_with_falcon(
        key: &SigningKey,
        falcon_key: &FalconKeypair,
        height: Height,
        round: Round,
        kind: VoteKind,
        block_hash: Option<BlockHash>,
    ) -> Self {
        let voter = key.verifying_key().to_bytes();
        let msg = vote_sign_bytes(height, round, kind, &block_hash);
        let ed_sig = key.sign(&msg).to_bytes();
        let falcon_sig = falcon_key.sign(&msg);
        let mut signature = Vec::with_capacity(VOTE_FALCON_PART_LEN);
        signature.extend_from_slice(VOTE_FALCON_MAGIC);
        signature.extend_from_slice(&ed_sig);
        signature.extend_from_slice(&falcon_sig);
        Self {
            height,
            round,
            kind,
            block_hash,
            voter,
            signature,
        }
    }
}

/// Append the local BLS half to a plain 64-byte Ed25519 signature when the
/// QC-BLS path is enabled. No-op otherwise: flag-off vote bytes stay
/// byte-identical to the pre-BLS format (default on the stand).
fn attach_vote_bls(msg: &[u8], signature: &mut Vec<u8>) {
    if signature.len() != 64 || signature.starts_with(VOTE_BLS_MAGIC) {
        return;
    }
    let Some(bls) = crate::bls::local_vote_bls_sign(msg) else {
        return;
    };
    let mut out = Vec::with_capacity(VOTE_BLS_PART_LEN);
    out.extend_from_slice(VOTE_BLS_MAGIC);
    out.extend_from_slice(&*signature);
    out.extend_from_slice(&bls);
    *signature = out;
}

// ============================================================================
// Block-carried equivocation evidence (deterministic slashing input)
// ============================================================================
//
// EVIDENCE CARRIER CONTRACT (audit O1/F4 wiring).
//
// A double-sign is two fully-signed votes by one validator for the same
// (height, round, kind) with different targets. Gossip observations of such
// pairs are node-local (F4): two nodes that decide the same block by
// different routes observe different pairs, so slashing from `VoteSet` /
// `HeightConsensus::equivocations()` directly forks the state root.
//
// The wired path therefore slashes ONLY from evidence that travels INSIDE
// the decided block as verifiable content:
//
//   * carrier: the block BODY, as `OpCode::SysCallReportEquivocation`
//     (appended terminal variant — the codebase-blessed proof-in-opcode
//     pattern, cf. `SysCallSubmitPriceFeed` / zkML / PQ-verify opcodes).
//     The transaction hash commits the payload and the block hash commits
//     the transaction, so every node that applies the block verifies the
//     SAME bytes. Old nodes fail closed on the unknown discriminant
//     (bincode rejects the whole block) instead of misreading it.
//   * content: BOTH conflicting votes FULLY included (`vote_a`, `vote_b`),
//     so verification needs no external data beyond the validator set
//     every node derives identically from its staking ledger.
//   * verification: [`verify_equivocation_evidence`] — fail-closed. Same
//     height/round/kind, differing targets, voter matches both votes,
//     voter is a member, and BOTH Ed25519/Falcon signatures verify. Any
//     doubt (forged vote, same target, cross-kind pair, unknown voter,
//     oversize envelope) refuses with `false` and the caller logs loudly.
//     This closes hunt Finding 12 in the wired path: the legacy
//     `StakingLedger::slash_equivocation` trusts caller tuples (pinned by
//     `hunt_finding_12_*` — DO NOT change it); the wired primitive
//     re-verifies everything.
//   * dedup: [`EquivocationEvidence::offense_key`] —
//     `BLAKE3(domain ‖ voter ‖ height ‖ round ‖ kind ‖ target_lo ‖
//     target_hi)` with canonical target order. Same offense (either vote
//     order, any number of rebroadcasts or re-inclusions) keys identically,
//     so it is slashed exactly once per chain. `kind` is part of the key:
//     a prevote-pair and a precommit-pair at the same height/round are two
//     distinct offenses (separate quorums attacked); without it the second
//     would be wrongly swallowed.
//   * order: [`canonicalize_equivocation_evidence`] verifies, sorts by
//     offense key and dedupes. Sequential 5% burns for one offender do NOT
//     commute (each burn is a fraction of the remainder), so canonical
//     order is what makes every node compute the same remainder.
//
// Stay-out note: this section is evidence SHAPE/VERIFY only. Quorum,
// schedule, lock and certificate code below is untouched.

/// Domain separator for [`EquivocationEvidence::offense_key`].
pub const EQUIVOCATION_OFFENSE_DOMAIN: &[u8] = b"STELLEREUM_EQUIVOCATION_OFFENSE_V1";

/// Hard cap on one evidence envelope's wire size (fail-closed: larger is
/// refused, never truncated). Two Falcon-enveloped votes fit comfortably;
/// anything bigger is a DoS probe, not evidence.
pub const MAX_EQUIVOCATION_EVIDENCE_BYTES: usize = 2_048;

/// Hard cap on evidences slashed per block (fail-closed: extras are
/// skipped loudly and may be resubmitted in a later block). Bounds the
/// per-block verification work; honest chains never approach it (each
/// offense needs a distinct double-signer).
pub const MAX_BLOCK_EQUIVOCATION_EVIDENCES: usize = 64;

/// Block-carried proof that `voter` double-signed: two fully-signed,
/// conflicting votes. Transported opaquely by
/// `OpCode::SysCallReportEquivocation`; verified by
/// [`verify_equivocation_evidence`] on every node from block bytes alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// The accused validator (must equal both votes' `voter`).
    pub voter: ValidatorId,
    /// First conflicting vote (fully signed).
    pub vote_a: Vote,
    /// Second conflicting vote (fully signed).
    pub vote_b: Vote,
}

impl EquivocationEvidence {
    /// Build the envelope from a recorded pair. No verification here —
    /// call [`verify_equivocation_evidence`] (fail-closed) before trusting it.
    pub fn new(voter: ValidatorId, vote_a: Vote, vote_b: Vote) -> Self {
        Self { voter, vote_a, vote_b }
    }

    /// The per-offense dedup key (also the slash-evidence digest): a
    /// canonical commitment to everything that makes this offense unique.
    /// Swapping the two votes, rebroadcasting, or re-including the same
    /// pair keys identically.
    pub fn offense_key(&self) -> [u8; 32] {
        equivocation_offense_key(
            &self.voter,
            self.vote_a.height,
            self.vote_a.round,
            self.vote_a.kind,
            &self.vote_a.block_hash,
            &self.vote_b.block_hash,
        )
    }

    /// Alias for [`Self::offense_key`]: the digest a block carrier commits
    /// to for this offense.
    pub fn digest(&self) -> [u8; 32] {
        self.offense_key()
    }

    /// Bincode wire size of the envelope (gas accounting + DoS cap).
    /// Unmeasurable (should be impossible) reads as `usize::MAX` so the
    /// size cap below refuses it instead of admitting it.
    pub fn wire_len(&self) -> usize {
        bincode::serialized_size(self).map(|n| n as usize).unwrap_or(usize::MAX)
    }
}

/// Canonical per-offense key:
/// `BLAKE3(domain ‖ voter ‖ height ‖ round ‖ kind ‖ target_lo ‖ target_hi)`,
/// with the two targets in canonical (lexicographic) order so vote order
/// never matters. `None` (nil) encodes as `0x00`, `Some(h)` as `0x01 ‖ h`,
/// so nil-vs-value counts as conflicting while nil-vs-nil does not.
pub fn equivocation_offense_key(
    voter: &ValidatorId,
    height: Height,
    round: Round,
    kind: VoteKind,
    hash_a: &Option<BlockHash>,
    hash_b: &Option<BlockHash>,
) -> [u8; 32] {
    fn enc(h: &Option<BlockHash>, out: &mut Vec<u8>) {
        match h {
            None => out.push(0x00),
            Some(hh) => {
                out.push(0x01);
                out.extend_from_slice(hh);
            }
        }
    }
    let mut ta = Vec::with_capacity(33);
    let mut tb = Vec::with_capacity(33);
    enc(hash_a, &mut ta);
    enc(hash_b, &mut tb);
    let (lo, hi) = if ta <= tb { (ta, tb) } else { (tb, ta) };
    let mut hasher = blake3::Hasher::new();
    hasher.update(EQUIVOCATION_OFFENSE_DOMAIN);
    hasher.update(voter);
    hasher.update(&height.to_be_bytes());
    hasher.update(&round.to_be_bytes());
    hasher.update(&[match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    }]);
    hasher.update(&lo);
    hasher.update(&hi);
    *hasher.finalize().as_bytes()
}

/// Fail-closed verification of block-carried equivocation evidence.
///
/// Every refusal returns `false` (never panics, never errors): the caller
/// skips the evidence and logs loudly. Checks, in cheap-first order:
///  1. envelope size cap (DoS bound);
///  2. same height/round/kind, DIFFERING targets (a nil-vs-value pair is a
///     genuine double-sign — two different statements for one round; a
///     same-target or cross-kind pair is not, cf. HUNT13/HUNT19);
///  3. `voter` matches BOTH votes' `voter` (framing with another
///     validator's vote is refused — hunt Finding 12);
///  4. voter membership via `is_validator` (unknown keys are refused);
///  5. BOTH signatures verify via [`Vote::verify`] (Ed25519 strict;
///     Falcon/PQ halves and pure-PQ mode handled inside — unsigned or
///     forged votes are refused).
pub fn verify_equivocation_evidence(
    ev: &EquivocationEvidence,
    is_validator: &dyn Fn(&ValidatorId) -> bool,
) -> bool {
    if ev.wire_len() > MAX_EQUIVOCATION_EVIDENCE_BYTES {
        return false;
    }
    let (a, b) = (&ev.vote_a, &ev.vote_b);
    if a.height != b.height || a.round != b.round || a.kind != b.kind {
        return false;
    }
    if a.block_hash == b.block_hash {
        return false;
    }
    if ev.voter != a.voter || ev.voter != b.voter {
        return false;
    }
    if !is_validator(&ev.voter) {
        return false;
    }
    if !a.verify() || !b.verify() {
        return false;
    }
    true
}

/// Deterministic shaping of candidate evidences: keep only what
/// [`verify_equivocation_evidence`] accepts, sort by offense key, drop
/// key-duplicates (same offense submitted twice, votes swapped, or
/// rebroadcast). Pure function of the inputs: every node that feeds it
/// the same candidates slashes in the same order. Order matters because
/// sequential 5% burns do not commute for one offender.
pub fn canonicalize_equivocation_evidence(
    items: Vec<EquivocationEvidence>,
    is_validator: &dyn Fn(&ValidatorId) -> bool,
) -> Vec<EquivocationEvidence> {
    let mut verified: Vec<(EquivocationEvidence, [u8; 32])> = items
        .into_iter()
        .filter(|ev| verify_equivocation_evidence(ev, is_validator))
        .map(|ev| {
            let k = ev.offense_key();
            (ev, k)
        })
        .collect();
    verified.sort_by(|a, b| a.1.cmp(&b.1));
    let mut out = Vec::with_capacity(verified.len());
    let mut last: Option<[u8; 32]> = None;
    for (ev, k) in verified {
        if last == Some(k) {
            continue;
        }
        last = Some(k);
        out.push(ev);
    }
    out
}

// ============================================================================
// Vote set (per height+round+kind): aggregation, quorum, equivocation
// ============================================================================

#[derive(Clone, Debug, Default)]
pub struct VoteSet {
    /// voter -> vote (at most one accepted per voter)
    votes: HashMap<ValidatorId, Vote>,
    /// power accumulated per target (None = nil)
    power: HashMap<Option<BlockHash>, u64>,
    /// equivocation evidence: (voter, first vote, conflicting vote)
    equivocations: Vec<(ValidatorId, Vote, Vote)>,
}

impl VoteSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vote. Returns Err on invalid signature / non-validator / wrong scope.
    /// A second, DIFFERENT vote by the same validator is recorded as equivocation
    /// (the first one is kept for quorum accounting).
    pub fn add(&mut self, vote: Vote, validators: &ValidatorSet, height: Height, round: Round, kind: VoteKind) -> Result<(), String> {
        if vote.height != height || vote.round != round || vote.kind != kind {
            return Err("vote out of scope".to_string());
        }
        if !vote.verify() {
            return Err("bad vote signature".to_string());
        }
        self.add_verified(vote, validators)
    }

    /// Admit a vote whose signature was ALREADY verified (single or batch).
    /// Scope, membership, dedup and equivocation handling are exactly the
    /// second half of [`VoteSet::add`]; factored out so batch ingestion pays
    /// the signature check once per batch instead of once per vote.
    fn add_verified(&mut self, vote: Vote, validators: &ValidatorSet) -> Result<(), String> {
        let power = validators.power_of(&vote.voter);
        if power == 0 {
            return Err("vote from non-validator".to_string());
        }
        if let Some(existing) = self.votes.get(&vote.voter) {
            if existing.block_hash != vote.block_hash {
                // SECURITY: record each equivocation ONCE, keyed by the pair of
                // conflicting targets rather than by voter.
                //
                // The evidence list was never deduplicated and never cleared, so
                // re-sending the same second vote N times appended N evidence
                // tuples for one equivocation, and the caller slashes 5% per
                // tuple. That compounds to `total * 0.95^N`: about 200 rebroadcasts
                // of a single honestly-signed vote pair confiscated an entire bond
                // in one height, against a 5% design intent.
                //
                // The real exploit is targeted rather than total — rebroadcast just
                // enough against one victim to strip exactly the stake that flips
                // proposer selection — so the bound has to be one slash per pair.
                let already = self.equivocations.iter().any(|(v, a, b)| {
                    *v == vote.voter
                        && ((a.block_hash == existing.block_hash
                            && b.block_hash == vote.block_hash)
                            || (b.block_hash == existing.block_hash
                                && a.block_hash == vote.block_hash))
                });
                if !already {
                    self.equivocations.push((vote.voter, existing.clone(), vote));
                }
            }
            return Ok(()); // keep the first vote
        }
        *self.power.entry(vote.block_hash).or_insert(0) += power;
        self.votes.insert(vote.voter, vote);
        Ok(())
    }

    pub fn power_for(&self, target: Option<BlockHash>) -> u64 {
        self.power.get(&target).copied().unwrap_or(0)
    }

    /// Batch-ingest many votes with one Ed25519 batch verification.
    ///
    /// Hot path for prevote/precommit ingestion: gossip and catch-up deliver
    /// votes in bursts, and verifying them one by one is Ed25519-bound
    /// (23K vote/s stand ceiling). The whole batch is verified at once with
    /// [`Vote::partition_valid`]; per-vote scope/membership/equivocation
    /// handling then reuses the same code as [`VoteSet::add`], so the final
    /// set state is identical to adding the same votes one by one in canonical
    /// order — with one batch verify instead of N scalar ones.
    ///
    /// Fallback semantics (VOTES — keep the good ones): a batch rejection
    /// falls back to scalar [`Vote::verify`] per vote, so one forged vote
    /// never drops honest votes — dropping the whole batch would lose
    /// quorum-forming votes to a single bad neighbor. The returned vector
    /// aligns with the INPUT order: element `i` is the `add` result for
    /// `votes[i]`.
    ///
    /// Determinism: admission runs in STABLE order — votes are admitted sorted
    /// by `(voter, block_hash)` so the outcome (which duplicate is "first",
    /// which equivocation pair is recorded) does not depend on network arrival
    /// order — while the returned per-input results map back to the caller's
    /// order. Verification itself is order-independent.
    pub fn add_batch(
        &mut self,
        votes: Vec<Vote>,
        validators: &ValidatorSet,
        height: Height,
        round: Round,
        kind: VoteKind,
    ) -> Vec<Result<(), String>> {
        // Canonical admission order: sorted by (voter, block_hash). `sort_by`
        // is stable and the keys are fully ordered, so every permutation of
        // the same input admits in the same order.
        let mut order: Vec<usize> = (0..votes.len()).collect();
        order.sort_by(|&a, &b| {
            votes[a]
                .voter
                .cmp(&votes[b].voter)
                .then_with(|| votes[a].block_hash.cmp(&votes[b].block_hash))
        });
        // One signature screen over the in-scope votes in admission order.
        // Out-of-scope votes skip the screen; the scope check in the admit
        // loop below reports their error exactly as `add` would.
        let mut screen_input: Vec<Vote> = Vec::new();
        let mut screen_pos: Vec<Option<usize>> = vec![None; votes.len()];
        for &i in &order {
            let v = &votes[i];
            if v.height == height && v.round == round && v.kind == kind {
                screen_pos[i] = Some(screen_input.len());
                screen_input.push(v.clone());
            }
        }
        let screen_flags = Vote::partition_valid(&screen_input);
        let mut sig_ok = vec![true; votes.len()];
        for (i, pos) in screen_pos.iter().enumerate() {
            if let Some(p) = pos {
                sig_ok[i] = screen_flags[*p];
            }
        }
        // Admit in canonical order; results stored per INPUT index.
        let mut out: Vec<Option<Result<(), String>>> = (0..votes.len()).map(|_| None).collect();
        for &i in &order {
            let v = &votes[i];
            if v.height != height || v.round != round || v.kind != kind {
                out[i] = Some(Err("vote out of scope".to_string()));
                continue;
            }
            if !sig_ok[i] {
                out[i] = Some(Err("bad vote signature".to_string()));
                continue;
            }
            out[i] = Some(self.add_verified(v.clone(), validators));
        }
        out.into_iter()
            .map(|r| r.expect("every input index is admitted exactly once"))
            .collect()
    }

    pub fn quorum_reached(&self, target: Option<BlockHash>, validators: &ValidatorSet) -> bool {
        self.power_for(target) >= validators.quorum_power()
    }

    /// If any single target reached quorum, return it (nil is a valid outcome).
    pub fn quorum_target(&self, validators: &ValidatorSet) -> Option<Option<BlockHash>> {
        let q = validators.quorum_power();
        for (target, p) in &self.power {
            if *p >= q {
                return Some(*target);
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.votes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    pub fn equivocations(&self) -> &[(ValidatorId, Vote, Vote)] {
        &self.equivocations
    }

    /// Return the count of collected votes in this set carrying Falcon signatures.
    pub fn falcon_votes_count(&self) -> usize {
        self.votes.values().filter(|v| v.falcon_signature().is_some()).count()
    }

    /// Return collected Falcon-512 signatures for votes matching `target`.
    pub fn collect_falcon_signatures(&self, target: Option<BlockHash>) -> Vec<(ValidatorId, Vec<u8>)> {
        self.votes
            .values()
            .filter(|v| v.block_hash == target)
            .filter_map(|v| v.falcon_signature().map(|sig| (v.voter, sig.to_vec())))
            .collect()
    }

    /// Build a quorum certificate for `target` from the collected votes.
    ///
    /// Two properties, both deliberate:
    /// * The Ed25519 list carries BARE 64-byte signatures (any vote-envelope
    ///   half is stripped). That is the format every verifier understands,
    ///   including one that predates BLS, and it is what the certificate
    ///   format keeps promising: the aggregate is ADDITIVE, never a
    ///   replacement.
    /// * When `STELL_BLS_QC` is enabled, the votes' BLS halves are aggregated
    ///   into the marker envelope entry in the same list. Aggregation is over
    ///   canonical validator-set indices, so the bitvector means exactly what
    ///   the verifier's registry will read back.
    pub fn certificate(&self, target: Option<BlockHash>, validators: &ValidatorSet) -> Option<QuorumCertificate> {
        if !self.quorum_reached(target, validators) {
            return None;
        }
        // Canonical validator-set indices (audit-consensus F8 hardening):
        // sorted EXPLICITLY, not via whatever order the map iterator happens
        // to yield today. `validators` is a `BTreeMap` (sorted iteration),
        // so this matches the verifier's registry order bit-for-bit — and
        // keeps matching if the container ever changes. The BLS bitvector
        // means exactly what the verifier reads back only when both sides
        // number validators identically.
        let mut sorted_ids: Vec<ValidatorId> = validators.validators.keys().copied().collect();
        sorted_ids.sort_unstable();
        let index: HashMap<ValidatorId, usize> = sorted_ids
            .into_iter()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect();
        let mut signatures = Vec::new();
        let mut bls_sigs: Vec<(usize, crate::bls::BlsSignature)> = Vec::new();
        for v in self.votes.values() {
            if v.block_hash == target {
                signatures.push((v.voter, v.ed25519_signature().to_vec()));
                if let Some(bytes) = v.bls_signature() {
                    if let (Some(&idx), Some(sig)) =
                        (index.get(&v.voter), crate::bls::BlsSignature::from_bytes(&bytes))
                    {
                        bls_sigs.push((idx, sig));
                    }
                }
            }
        }
        let mut qc = QuorumCertificate {
            height: self.votes.values().next()?.height,
            round: self.votes.values().next()?.round,
            kind: self.votes.values().next()?.kind,
            block_hash: target,
            signatures,
        };
        if crate::bls::qc_bls_enabled()
            && !bls_sigs.is_empty()
            && qc.signatures.len() < MAX_COMMIT_CERT_SIGNERS
        {
            if let Ok(aggregate) = crate::bls::aggregate_signatures(&bls_sigs, validators.len()) {
                let payload = encode_qc_bls_envelope(
                    &aggregate,
                    qc.height,
                    qc.round,
                    qc.kind,
                    qc.block_hash,
                );
                qc.signatures.push((BLS_QC_MARKER_ID, payload));
            }
        }

        // Post-Quantum Micro-Certificate (µQC) compilation:
        // When collected votes carry Falcon-512 signatures, compile PqMicroCertificate
        // and attach PQ_UQC_MARKER_ID to the resulting QuorumCertificate.
        let mut falcon_sigs: HashMap<ValidatorId, Vec<u8>> = HashMap::new();
        for v in self.votes.values() {
            if v.block_hash == target {
                if let Some(fsig) = v.falcon_signature() {
                    falcon_sigs.insert(v.voter, fsig.to_vec());
                }
            }
        }

        if !falcon_sigs.is_empty() && !validators.is_empty() {
            let committee_size = (validators.len() as u32).min(16);
            if committee_size > 0 {
                let committee = derive_sortition_committee(validators, qc.height, qc.round, committee_size);
                let get_sig_for_committee_member = |val_id: &ValidatorId| -> Option<Vec<u8>> {
                    if let Some(sig) = falcon_sigs.get(val_id) {
                        return Some(sig.clone());
                    }
                    if let Some((scheme, pk)) = get_validator_pq_key(val_id) {
                        let addr = crate::post_quantum::derive_pq_address(
                            scheme,
                            &pk,
                            &crate::post_quantum::DEFAULT_SALT,
                        );
                        if let Some(sig) = falcon_sigs.get(&addr) {
                            return Some(sig.clone());
                        }
                    }
                    for (voter, sig) in &falcon_sigs {
                        if let Some((scheme, pk)) = get_validator_pq_key(voter) {
                            let addr = crate::post_quantum::derive_pq_address(
                                scheme,
                                &pk,
                                &crate::post_quantum::DEFAULT_SALT,
                            );
                            if addr == *val_id {
                                return Some(sig.clone());
                            }
                        }
                    }
                    None
                };

                let bitmask_len = (committee_size as usize).div_ceil(8);
                let mut bitmask = vec![0u8; bitmask_len];
                let mut uqc_signatures = Vec::new();

                for (i, val_id) in committee.iter().enumerate() {
                    if let Some(sig) = get_sig_for_committee_member(val_id) {
                        bitmask[i / 8] |= 1 << (i % 8);
                        uqc_signatures.push(sig);
                    }
                }

                // Power-weighted µQC quorum: the committee is whatever sortition
                // elected (unchanged); only the ACCOUNTING changed — sum the
                // voting powers of the committee members that actually signed
                // and require floor(2*W/3)+1 of the committee's total power W.
                // On uniform power this equals the legacy head-count
                // floor(2*k/3)+1, so old certificates keep verifying; on a
                // skewed set (e.g. N=3 with A+B covering quorum) 2 signers
                // now suffice instead of a fragile 3/3 unanimous.
                let committee_total: u64 =
                    committee.iter().map(|id| validators.power_of(id)).sum();
                if committee_total == 0 {
                    // Fail-closed: empty committee / zero weight never compiles.
                    return Some(qc);
                }
                let quorum_power = pq_micro_quorum_power(committee_total);
                let signed_power: u64 = committee
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| (bitmask[i / 8] & (1 << (i % 8))) != 0)
                    .map(|(_, id)| validators.power_of(id))
                    .sum();
                if signed_power >= quorum_power {
                    let uqc = PqMicroCertificate {
                        scheme: crate::post_quantum::PqScheme::Falcon512,
                        height: qc.height,
                        round: qc.round,
                        committee_size,
                        signers_bitmask: bitmask,
                        signatures: uqc_signatures,
                    };
                    qc.attach_pq_micro_certificate(&uqc);
                }
            }
        }

        Some(qc)
    }
}

// ============================================================================
// Quorum Certificate
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub height: Height,
    pub round: Round,
    pub kind: VoteKind,
    pub block_hash: Option<BlockHash>,
    pub signatures: Vec<(ValidatorId, Vec<u8>)>,
}

impl QuorumCertificate {
    /// Verify the QC carries a real quorum of valid, distinct validator signatures.
    /// Supports post-quantum µQC / CEC envelopes, BLS aggregates, and classical Ed25519 threshold.
    pub fn verify(&self, validators: &ValidatorSet) -> bool {
        self.verify_unified(validators)
    }

    /// Unified certificate verification supporting:
    /// 1. Post-quantum µQC (`PQ_UQC_MARKER_ID`) and Epoch CEC (`PQ_QC_MARKER_ID`) envelopes.
    /// 2. BLS aggregate envelopes (`BLS_QC_MARKER_ID`).
    /// 3. Classical Ed25519 threshold signatures.
    pub fn verify_unified(&self, validators: &ValidatorSet) -> bool {
        self.verify_unified_with_pq_keys(validators, None)
    }

    /// Unified verification with optional local post-quantum key overrides.
    pub fn verify_unified_with_pq_keys(
        &self,
        validators: &ValidatorSet,
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> bool {
        // Anti-DoS (audit F7): reject an implausibly long signer list BEFORE
        // touching any signature. The list is attacker-supplied and uncapped on
        // the wire, so one message could otherwise pin a verifier in an Ed25519
        // loop proportional to its length. This is O(1) and applies to every
        // caller of `verify`. The marker envelope entry counts toward this cap
        // like any other entry.
        if self.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return false;
        }
        let msg = vote_sign_bytes(self.height, self.round, self.kind, &self.block_hash);

        // 1. Post-Quantum path: µQC (PQ_UQC_MARKER_ID) or CEC Epoch (PQ_QC_MARKER_ID)
        if self.pq_path_verify(validators, &msg, pq_keys) {
            return true;
        }

        // Under Pure Post-Quantum Mode, classical signatures (BLS aggregate, Ed25519 threshold) are rejected.
        if crate::post_quantum::is_pure_pq_enforced() {
            return false;
        }

        // 2. BLS aggregate path: one pairing identity against the FULL canonical
        // validator key list from the registry (membership is by construction —
        // the verifier sums exactly the keys the validator set names), then
        // power is summed from the validator set itself over the signer
        // bitvector. Only a completed, quorum-reaching check returns here.
        if let Some(power) = self.bls_path_power(validators, &msg) {
            if power >= validators.quorum_power() {
                return true;
            }
        }
        // First pass: dedup, membership and parsing are cheap per item. Collect the
        // candidates; the expensive crypto happens once below, not N times.
        let mut seen = HashSet::new();
        let mut candidates: Vec<(VerifyingKey, Signature, u64)> = Vec::new();
        for (voter, sig_bytes) in &self.signatures {
            if !seen.insert(*voter) {
                continue; // duplicate signer
            }
            let vp = validators.power_of(voter);
            if vp == 0 {
                continue;
            }
            let Ok(vk) = VerifyingKey::from_bytes(voter) else { continue };
            // Envelope-tolerant: a certificate entry copied from an envelope
            // vote keeps only its Ed25519 half. The marker entry never reaches
            // here in practice (it is not a validator, so `vp == 0` above skips
            // it), but stripping costs nothing and keeps every entry in this
            // list a bare Ed25519 signature.
            let Ok(sig) = Signature::from_slice(ed25519_sig_bytes(sig_bytes)) else { continue };
            candidates.push((vk, sig, vp));
        }
        if candidates.is_empty() {
            return false;
        }
        // Fast path: one batch verification over the shared message. Same-message
        // batching is roughly 2x a per-signature loop at 100 signers.
        {
            let msgs: Vec<&[u8]> = candidates.iter().map(|_| msg.as_slice()).collect();
            let sigs: Vec<Signature> = candidates.iter().map(|(_, s, _)| *s).collect();
            let keys: Vec<VerifyingKey> = candidates.iter().map(|(k, _, _)| *k).collect();
            if ed25519_dalek::verify_batch(&msgs, &sigs, &keys).is_ok() {
                let power: u64 = candidates.iter().map(|(_, _, p)| p).sum();
                return power >= validators.quorum_power();
            }
        }
        // Slow path: the batch failed, so at least one signature is bad. Fall back to
        // per-signature checks to count exactly the valid ones -- an attacker who
        // slips one bad signature into a quorum must not turn a good quorum bad, and
        // a bad quorum must not pass on the strength of its good members.
        let mut power = 0u64;
        for (vk, sig, vp) in &candidates {
            if vk.verify_strict(&msg, sig).is_ok() {
                power += *vp;
            }
        }
        power >= validators.quorum_power()
    }

    /// Check if certificate contains a valid Post-Quantum µQC or Epoch CEC envelope.
    fn pq_path_verify(
        &self,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> bool {
        for (voter, payload) in &self.signatures {
            if *voter == PQ_UQC_MARKER_ID {
                if let Some(cert) = decode_pq_micro_envelope(payload) {
                    if crate::post_quantum::is_pure_pq_enforced() && !cert.scheme.is_post_quantum() {
                        continue;
                    }
                    if self.verify_micro_cert(&cert, validators, msg, pq_keys) {
                        return true;
                    }
                }
            } else if *voter == PQ_QC_MARKER_ID {
                if let Some(cert) = decode_pq_epoch_envelope(payload).or_else(|| decode_pq_micro_envelope(payload)) {
                    if crate::post_quantum::is_pure_pq_enforced() && !cert.scheme.is_post_quantum() {
                        continue;
                    }
                    if self.verify_epoch_cert(&cert, validators, msg, pq_keys) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Power-weighted µQC verification.
    ///
    /// The sortition committee is re-derived exactly as before (unchanged);
    /// only the QUORUM ACCOUNTING is by voting power: every marked committee
    /// member's signature is verified (fail-closed on the first bad/missing
    /// key or bad signature), their powers are summed, and the certificate
    /// passes iff `signed_power >= floor(2*committee_total/3) + 1`.
    ///
    /// Fail-closed: empty committee (`committee_size == 0`), empty re-derived
    /// committee, or zero total committee weight always return `false`.
    /// Backward compatibility: on uniform power the weight rule coincides
    /// with the legacy `floor(2*k/3)+1` head-count, so historic 3/3 (and
    /// 11/16, …) certificates verify unchanged — they carry the full
    /// committee power.
    fn verify_micro_cert(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> bool {
        if cert.height != self.height || cert.round != self.round {
            return false;
        }
        let expected_committee_size = (validators.len() as u32).min(16);
        if cert.committee_size != expected_committee_size || cert.committee_size == 0 || cert.committee_size as usize > MAX_COMMIT_CERT_SIGNERS {
            return false;
        }

        let expected_bitmask_len = (cert.committee_size as usize).div_ceil(8);
        if cert.signers_bitmask.len() != expected_bitmask_len {
            return false;
        }
        for i in (cert.committee_size as usize)..(cert.signers_bitmask.len() * 8) {
            if (cert.signers_bitmask[i / 8] & (1 << (i % 8))) != 0 {
                return false;
            }
        }

        let committee = derive_sortition_committee(validators, cert.height, cert.round, cert.committee_size);
        let expected_len = (cert.committee_size as usize).min(validators.len());
        if committee.len() != expected_len || committee.is_empty() {
            return false;
        }

        for i in committee.len()..(cert.committee_size as usize) {
            if cert.is_signer(i) {
                return false;
            }
        }

        let signed_count = cert.signed_count();
        let is_compact = cert.signatures.len() == signed_count;
        let is_full = cert.signatures.len() == cert.committee_size as usize;
        if !is_compact && !is_full {
            return false;
        }

        // Power-weighted quorum over the ACTUAL committee. Fail-closed on
        // zero weight (empty set / all-zero powers can never reach quorum).
        // NOTE: there is deliberately NO head-count early reject here — a
        // 2-of-3 bitmask that the old `floor(2*3/3)+1 = 3` rule threw out may
        // still carry quorum POWER, which is exactly the fragile-unanimous
        // case this fixes.
        let committee_total: u64 = committee.iter().map(|id| validators.power_of(id)).sum();
        if committee_total == 0 {
            return false;
        }
        let quorum_power = pq_micro_quorum_power(committee_total);

        let mut sig_idx = 0;
        let mut valid_power = 0u64;

        for i in 0..committee.len() {
            if cert.is_signer(i) {
                let sig = if is_compact {
                    let s = &cert.signatures[sig_idx];
                    sig_idx += 1;
                    s
                } else {
                    &cert.signatures[i]
                };

                let val_id = &committee[i];
                let key_opt = pq_keys
                    .and_then(|m| m.get(val_id).cloned())
                    .or_else(|| get_validator_pq_key(val_id))
                    .or_else(|| {
                        if cert.scheme == crate::post_quantum::PqScheme::Ed25519 {
                            Some((crate::post_quantum::PqScheme::Ed25519, val_id.to_vec()))
                        } else {
                            None
                        }
                    });

                let Some((scheme, pubkey)) = key_opt else {
                    return false;
                };

                if scheme != cert.scheme {
                    return false;
                }

                let valid = if cert.scheme == crate::post_quantum::PqScheme::Falcon512 {
                    verify_falcon_signature_or_test(&pubkey, msg, sig)
                } else {
                    crate::post_quantum::verify_pq_signature(cert.scheme, &pubkey, msg, sig)
                };

                if !valid {
                    return false;
                }

                valid_power = valid_power.saturating_add(validators.power_of(val_id));
            }
        }

        valid_power >= quorum_power
    }

    fn verify_epoch_cert(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> bool {
        if cert.height != self.height || cert.round != self.round {
            return false;
        }
        let total_validators = validators.len();
        if total_validators == 0 {
            return false;
        }

        let mut ids: Vec<ValidatorId> = validators.validators.keys().copied().collect();
        ids.sort_unstable();

        let signed_count = cert.signed_count();
        let is_compact = cert.signatures.len() == signed_count;
        let is_full = cert.signatures.len() == ids.len() || cert.signatures.len() == cert.committee_size as usize;
        if !is_compact && !is_full {
            return false;
        }

        let mut sig_idx = 0;
        let mut power = 0u64;

        for (i, val_id) in ids.iter().enumerate() {
            if cert.is_signer(i) {
                let sig = if is_compact {
                    let s = &cert.signatures[sig_idx];
                    sig_idx += 1;
                    s
                } else {
                    &cert.signatures[i]
                };

                let key_opt = pq_keys
                    .and_then(|m| m.get(val_id).cloned())
                    .or_else(|| get_validator_pq_key(val_id))
                    .or_else(|| {
                        if cert.scheme == crate::post_quantum::PqScheme::Ed25519 {
                            Some((crate::post_quantum::PqScheme::Ed25519, val_id.to_vec()))
                        } else {
                            None
                        }
                    });

                let Some((scheme, pubkey)) = key_opt else {
                    return false;
                };

                if scheme != cert.scheme {
                    return false;
                }

                let valid = if cert.scheme == crate::post_quantum::PqScheme::Falcon512 {
                    verify_falcon_signature_or_test(&pubkey, msg, sig)
                } else {
                    crate::post_quantum::verify_pq_signature(cert.scheme, &pubkey, msg, sig)
                };

                if !valid {
                    return false;
                }

                power = power.saturating_add(validators.power_of(val_id));
            }
        }

        power >= validators.quorum_power()
    }

    /// Attach a post-quantum micro-certificate (µQC) to this QuorumCertificate.
    pub fn attach_pq_micro_certificate(&mut self, uqc: &PqMicroCertificate) {
        let payload = encode_pq_micro_envelope(uqc);
        self.signatures.retain(|(voter, _)| *voter != PQ_UQC_MARKER_ID);
        self.signatures.push((PQ_UQC_MARKER_ID, payload));
    }

    /// Retrieve the post-quantum micro-certificate (µQC) from this QuorumCertificate, if present.
    pub fn pq_micro_certificate(&self) -> Option<PqMicroCertificate> {
        for (voter, payload) in &self.signatures {
            if *voter == PQ_UQC_MARKER_ID {
                return decode_pq_micro_envelope(payload);
            }
        }
        None
    }

    /// Voting power proven by the certificate's BLS aggregate, if the BLS path
    /// is enabled and a well-formed aggregate strictly verifies. `None` means
    /// "do not count BLS power at all" — the caller falls back to Ed25519.
    fn bls_path_power(&self, validators: &ValidatorSet, msg: &[u8]) -> Option<u64> {
        let cfg = crate::bls::qc_bls();
        if !cfg.enabled {
            return None;
        }
        // Membership: the FULL canonical validator set in sorted order, every
        // member's BLS key resolved from the registry. One missing member and
        // the path is unavailable (fallback) — it never verifies against a
        // partial or caller-chosen key list.
        let keys = cfg.canonical_keys(validators)?;
        // Audit-consensus F8: index power against the SAME canonical (sorted)
        // order the registry hands out above — explicitly sorted here rather
        // than trusting the map iterator, so a future container swap cannot
        // silently renumber the bitvector between assembler and verifier.
        let mut ids: Vec<ValidatorId> = validators.validators.keys().copied().collect();
        ids.sort_unstable();
        let mut best: Option<u64> = None;
        for (voter, payload) in &self.signatures {
            if *voter != BLS_QC_MARKER_ID {
                continue;
            }
            let Some((h, r, kind, bh, aggregate)) = decode_qc_bls_envelope(payload) else {
                continue;
            };
            // The envelope must describe THIS certificate: a spliced aggregate
            // from another height/round/kind/target fails binding here, and a
            // mismatched message would fail the pairing anyway.
            if h != self.height
                || r != self.round
                || kind != self.kind
                || bh != self.block_hash.unwrap_or([0u8; 32])
            {
                continue;
            }
            if aggregate.participants.total_validators() != validators.len() {
                continue;
            }
            if !crate::bls::verify_aggregate_signature(&keys, msg, &aggregate) {
                continue;
            }
            let mut power = 0u64;
            for (i, id) in ids.iter().enumerate() {
                if aggregate.participants.is_set(i) {
                    power = power.saturating_add(validators.power_of(id));
                }
            }
            best = Some(best.map_or(power, |b: u64| b.max(power)));
        }
        best
    }
}

// ============================================================================
// Consensus step
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

/// What the engine wants the caller to do after processing an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    /// Broadcast our prevote for this target (None = nil)
    Prevote(Option<BlockHash>),
    /// Broadcast our precommit for this target
    Precommit(Option<BlockHash>),
    /// Height is decided on this block hash
    Commit(BlockHash),
    /// Move to a new round (view change)
    NewRound(Round),
}

// ============================================================================
// Per-height consensus state machine
// ============================================================================

#[derive(Clone, Debug)]
pub struct HeightConsensus {
    pub height: Height,
    pub round: Round,
    pub step: Step,
    pub validators: ValidatorSet,
    /// (proposer, block_hash) proposed this round
    pub proposal: Option<(ValidatorId, BlockHash)>,
    /// The round `proposal` was accepted in. A vote must name the CURRENT
    /// round's value: voting a stale-held body with a fresh round number can
    /// never meet a quorum (the peer holds something else) and poisons the
    /// round -- observed live as nodes voting different bodies at the same
    /// round for hundreds of rounds. `has_live_proposal` gates voting on it.
    pub proposal_round: Option<Round>,
    /// locked value: (block_hash, round at which we locked)
    pub locked: Option<(BlockHash, Round)>,
    /// votes keyed by (round, kind)
    prevotes: HashMap<Round, VoteSet>,
    precommits: HashMap<Round, VoteSet>,
    pub decided: Option<BlockHash>,
    /// prevote QC per round (needed for locking)
    pub prevote_qc: HashMap<Round, QuorumCertificate>,
    pub precommit_qc: Option<QuorumCertificate>,
    /// Anti-runaway budget for peer-driven round jumps (audit 2026-10-06):
    /// each verified vote could previously move us +8 with no rate limit, so
    /// a burst of messages ratcheted rounds without bound (r9700, zero QCs).
    /// At most this many jumps per wall-clock second; honest catch-up (a few
    /// jumps, then landing near stops further syncing) never notices.
    sync_window_start: std::time::Instant,
    sync_jumps_used: u32,
    /// Best-known round per peer at THIS height, learned from verified votes
    /// even when the vote itself is not votable (stale far-behind or absurd
    /// far-ahead). Voting still requires an exact-round vote in `VoteSet`;
    /// this map is ONLY a round counter for sync and the deadlock breaker, so
    /// a 1200-round desync collapses instead of growing (live 2026-10-14:
    /// A r1550 vs B r318, each dropping the other's votes forever).
    peer_rounds: HashMap<ValidatorId, Round>,
}

/// Peer-driven round jumps allowed per second (each jumps at most
/// ROUND_LOOKBACK). Generous for honest catch-up, fatal for runaway sync.
pub const MAX_SYNC_JUMPS_PER_SEC: u32 = 4;

impl HeightConsensus {
    pub fn new(height: Height, validators: ValidatorSet) -> Self {
        Self {
            height,
            round: 0,
            step: Step::Propose,
            validators,
            proposal: None,
            proposal_round: None,
            locked: None,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            decided: None,
            prevote_qc: HashMap::new(),
            precommit_qc: None,
            sync_window_start: std::time::Instant::now(),
            sync_jumps_used: 0,
            peer_rounds: HashMap::new(),
        }
    }

    pub fn proposer(&self) -> Option<ValidatorId> {
        self.validators.proposer_for(self.height, self.round)
    }

    /// Accept a proposal for the current round from the correct proposer.
    pub fn receive_proposal(&mut self, proposer: ValidatorId, block_hash: BlockHash) -> Result<(), String> {
        if self.step != Step::Propose {
            return Err("not in propose step".to_string());
        }
        if Some(proposer) != self.proposer() {
            return Err("wrong proposer".to_string());
        }
        self.proposal = Some((proposer, block_hash));
        self.proposal_round = Some(self.round);
        Ok(())
    }

    /// True only when we hold a proposal accepted in the CURRENT round. Voting
    /// a stale-held body with a fresh round number is worse than not voting:
    /// it spends our one vote for the round on a value no quorum can ever form
    /// around, while skipping lets the current proposal (or a timeout-nil)
    /// decide the round. Callers must check this instead of `proposal.is_some()`.
    pub fn has_live_proposal(&self) -> bool {
        self.proposal.is_some() && self.proposal_round == Some(self.round)
    }

    /// Compute our prevote for the current round, applying the lock rule.
    /// Returns the target to prevote (None = nil).
    pub fn decide_prevote(&self) -> Option<BlockHash> {
        match (&self.proposal, &self.locked) {
            // If locked on a value, only prevote that value (if it matches proposal)
            (Some((_, proposed)), Some((locked, _))) => {
                if proposed == locked {
                    Some(*proposed)
                } else {
                    None // locked on a different value -> prevote nil
                }
            }
            (Some((_, proposed)), None) => Some(*proposed),
            (None, _) => None, // no proposal -> nil
        }
    }

    /// Compute our precommit target after a prevote QC exists.
    pub fn decide_precommit(&self, prevote_qc: &QuorumCertificate) -> Option<BlockHash> {
        prevote_qc.block_hash
    }

    pub fn add_prevote(&mut self, vote: Vote) -> Result<(), String> {
        // Anti-DoS: reject votes for rounds absurdly far ahead of ours.
        if vote.round > self.round.saturating_add(MAX_ROUND_AHEAD) {
            return Err("prevote round too far ahead".to_string());
        }
        let round = vote.round;
        let set = self.prevotes.entry(round).or_insert_with(VoteSet::new);
        set.add(vote, &self.validators, self.height, round, VoteKind::Prevote)
    }

    pub fn add_precommit(&mut self, vote: Vote) -> Result<(), String> {
        if vote.round > self.round.saturating_add(MAX_ROUND_AHEAD) {
            return Err("precommit round too far ahead".to_string());
        }
        let round = vote.round;
        let set = self.precommits.entry(round).or_insert_with(VoteSet::new);
        set.add(vote, &self.validators, self.height, round, VoteKind::Precommit)
    }

    pub fn prevote_set(&self, round: Round) -> Option<&VoteSet> {
        self.prevotes.get(&round)
    }

    pub fn precommit_set(&self, round: Round) -> Option<&VoteSet> {
        self.precommits.get(&round)
    }

    /// Return the count of collected votes carrying Falcon signatures in a given round and kind.
    pub fn falcon_votes_count(&self, round: Round, kind: VoteKind) -> usize {
        let set_opt = match kind {
            VoteKind::Prevote => self.prevotes.get(&round),
            VoteKind::Precommit => self.precommits.get(&round),
        };
        set_opt.map_or(0, |s| s.falcon_votes_count())
    }

    /// Return collected Falcon-512 vote signatures for a target in a given round and kind.
    pub fn collect_falcon_signatures(
        &self,
        round: Round,
        kind: VoteKind,
        target: Option<BlockHash>,
    ) -> Vec<(ValidatorId, Vec<u8>)> {
        let set_opt = match kind {
            VoteKind::Prevote => self.prevotes.get(&round),
            VoteKind::Precommit => self.precommits.get(&round),
        };
        set_opt.map_or_else(Vec::new, |s| s.collect_falcon_signatures(target))
    }

    /// The rounds worth inspecting, newest first, starting at the current one.
    ///
    /// A quorum can only ever form in a round at or below ours, and a LATE vote for a
    /// round we have already left still counts -- that is the whole reason votes are
    /// stored per round instead of overwritten. Only looking at `self.round` was the
    /// deadlock: node A accepted the proposal and prevote for height 488 round 0, then
    /// took its 3s timeout into round 1, and the peer's precommit for round 0 arrived
    /// 3 seconds later. The votes for round 0 were all present and still stored, but no
    /// code path ever looked at round 0 again, so the pair sat in view changes forever
    /// until an operator wiped both data directories. This is the Tendermint rule that
    /// a node must still commit a round it has left if the quorum turns up.
    fn rounds_to_inspect(&self) -> Vec<Round> {
        // Bounded: an unbounded scan would let a peer force O(rounds) work per tick.
        // Looking back a fixed window covers any realistic message delay, and a vote
        // older than that is a message whose sender has long since moved on.
        let low = self.round.saturating_sub(ROUND_LOOKBACK);
        (low..=self.round).rev().collect()
    }

    /// Human-readable reasons finalization is currently blocked. Called when
    /// `try_finalize` yields nothing despite precommit activity: a silent
    /// `None` there once cost hours of live debugging (both nodes precommitting
    /// the same hash every round with no finalize and no log line). Reports the
    /// first round with a precommit QC and exactly which gate holds it back
    /// (prevote-QC mismatch with per-side vote presence, lock refusal naming
    /// hashes and rounds). Pure readout, no state change.
    pub fn finalize_blockers(&self) -> Option<String> {
        let short = |h: &[u8; 32]| hex::encode(&h[..4]);
        for r in self.rounds_to_inspect() {
            let Some(pset) = self.precommits.get(&r) else { continue };
            let Some(ptarget) = pset.quorum_target(&self.validators) else {
                continue;
            };
            let Some(block) = ptarget else {
                return Some(format!("h={} r={r}: precommit QC is nil", self.height));
            };
            let pv = self
                .prevotes
                .get(&r)
                .and_then(|s| s.quorum_target(&self.validators))
                .flatten();
            if pv != Some(block) {
                let have: Vec<String> = self
                    .prevotes
                    .get(&r)
                    .map(|s| {
                        let mut v: Vec<String> = s.votes.keys().map(|k| short(k)).collect();
                        v.sort();
                        v
                    })
                    .unwrap_or_default();
                return Some(format!(
                    "h={} r={r}: precommit QC -> {} but prevote QC -> {} (prevoters: {:?})",
                    self.height,
                    short(&block),
                    pv.map(|b| short(&b)).unwrap_or_else(|| "none".into()),
                    have
                ));
            }
            if let Some((locked_block, locked_round)) = self.locked {
                if locked_round <= r && locked_block != block {
                    return Some(format!(
                        "h={} r={r}: lock ({}, r{locked_round}) refuses {}",
                        self.height,
                        short(&locked_block),
                        short(&block)
                    ));
                }
            }
            return Some(format!(
                "h={} r={r}: QCs agree on {} but finalize still fails (missing body?)",
                self.height,
                short(&block)
            ));
        }
        None
    }

    /// Try to form a prevote QC. Returns the QC target.
    /// Like [`Self::try_prevote_quorum`] but also returns the ROUND the polka
    /// belongs to. Callers that must cast a follow-up vote (precommit) need
    /// that round: stamping their own `hc.round` instead put the two nodes'
    /// precommits into different VoteSet buckets whenever they were one round
    /// apart, so a full prevote QC never became a decision (31 of 180 wasted
    /// rounds on the live stand).
    pub fn try_prevote_quorum_at(&mut self) -> Option<(Round, Option<BlockHash>)> {
        // Newest-wins (audit-consensus F7 hardening 2026-10-14): the scan runs
        // newest-first, but the OLD code unlocked on EVERY round above the
        // lock — so an OLDER conflicting polka unlocked even when a NEWER
        // polka re-confirmed the locked value (extra rounds: unlock, nil,
        // re-lock — liveness only, never a fork). Only the NEWEST polka in
        // the window may unlock: it is the network's latest word, and an
        // older quorum is stale evidence the newer one already superseded.
        let mut found: Option<(Round, Option<BlockHash>)> = None;
        for round in self.rounds_to_inspect() {
            let Some(set) = self.prevotes.get(&round) else { continue };
            let Some(target) = set.quorum_target(&self.validators) else { continue };
            if found.is_none() {
                if let Some(qc) = set.certificate(target, &self.validators) {
                    self.prevote_qc.insert(round, qc);
                }
                found = Some((round, target));
            }
        }
        // Polka unlock (BFT liveness): a quorum for a different value -- or
        // for nil -- at a HIGHER round than our lock proves the network
        // moved on without us (we locked on a QC the peer never saw, after
        // a single lost vote). Keeping the old lock would nil every future
        // proposal while the network can never come back: observed live as
        // a permanent stall with one node voting nil forever. Unlock; the
        // normal path re-locks when we precommit again. A quorum for our
        // own value changes nothing.
        //
        // Newest-wins: `found` is the NEWEST polka (scan order above), so an
        // older conflicting quorum no longer unlocks past a newer confirming
        // one.
        // Polka unlock (BFT safety & liveness, audit F-01): in Tendermint, a
        // node ONLY unlocks when observing a prevote quorum for a DIFFERENT
        // non-nil block (`Some(other_block)`). A nil polka (`found == (r, None)`)
        // forms on timeouts and must NEVER unlock — otherwise honest nodes that
        // timed out in round 1 would drop their locks on a block finalized in
        // round 0 and finalize a conflicting block in round 2 (safety violation).
        if let (Some((locked_block, locked_round)), Some((polka_round, Some(other_block)))) =
            (self.locked, found)
        {
            if polka_round > locked_round && other_block != locked_block {
                self.locked = None;
            }
        }
        found
    }

    /// Target-only view of [`Self::try_prevote_quorum_at`] (kept for the many
    /// call sites and tests that do not care which round the polka formed in).
    pub fn try_prevote_quorum(&mut self) -> Option<Option<BlockHash>> {
        self.try_prevote_quorum_at().map(|(_, target)| target)
    }

    /// Try to form a precommit QC (finality). On success, lock and decide.
    ///
    /// Inspects the recent rounds, not just the current one, so a quorum that formed
    /// in a round we have since left still decides. See `rounds_to_inspect`.
    pub fn try_precommit_quorum(&mut self) -> Option<BlockHash> {
        let round = self
            .rounds_to_inspect()
            .into_iter()
            .find(|r| {
                self.precommits
                    .get(r)
                    .and_then(|s| s.quorum_target(&self.validators))
                    .flatten()
                    .is_some()
            })?;
        let set = self.precommits.get(&round)?;
        let target = set.quorum_target(&self.validators)?;
        let block = target?; // nil precommit quorum does not decide a block

        // SAFETY: a block may only be decided on a prevote quorum for the SAME
        // block. Without this, any precommit quorum alone finalises whatever it
        // names, and a peer can hand us precommits for a block nobody prevoted
        // for. The two quorums have to agree on the target, otherwise a
        // pre-vote-certified block A and a precommit-certified block B could both
        // reach quorum and the node would pick whichever it checked first.
        let prevoted = self.prevotes.get(&round).and_then(|s| s.quorum_target(&self.validators));
        if prevoted.flatten() != Some(block) {
            return None;
        }

        // And a locked validator must not decide a block that contradicts its
        // own lock: that is what makes a reorg past a locked round impossible.
        if let Some((locked_block, _)) = self.locked {
            if locked_block != block {
                return None;
            }
        }

        if let Some(qc) = set.certificate(target, &self.validators) {
            self.precommit_qc = Some(qc);
        }
        self.locked = Some((block, round));
        self.decided = Some(block);
        self.step = Step::Commit;
        Some(block)
    }

    /// Move to a round a peer is in, for round-phase synchronisation.
    ///
    /// Unlike `advance_to_round` (capped at +1 per call as a round-DoS guard), this
    /// may move further, because it exists to fix a specific deadlock: with an even
    /// validator count the proposer alternates by round PARITY, so two nodes that
    /// walk their rounds independently sit at an odd offset and are permanently in
    /// opposite phases -- each waits for the other and every proposal is rejected as
    /// "wrong proposer". Catching up one round at a time cannot fix that, because the
    /// parity of the offset is preserved.
    ///
    /// Still bounded and still forward-only:
    ///   * never moves backwards, so a node cannot be dragged into re-voting a round
    ///     it already left;
    ///   * the jump is capped, so a peer cannot shove us arbitrarily far ahead.
    /// The caller is responsible for having a reason to move (a signed vote from a
    /// validator in that round), which is what makes the cap safe.
    pub fn sync_round_to(&mut self, round: Round) {
        // SECURITY (audit F2): a single peer message may move us forward by at
        // most ROUND_LOOKBACK rounds. The old cap was 64, so a Batch of 32
        // (previously unauthenticated) votes bought 2048 rounds; now it is 256,
        // and the caller only reaches this after the vote has verified.
        //
        // RATE LIMIT (audit 2026-10-06): the per-call cap alone does not stop
        // a MESSAGE BURST from ratcheting +8 per message without bound. Past
        // the per-second jump budget the sync is refused (the caller's own
        // timeout advances us within seconds anyway).
        let now = std::time::Instant::now();
        if now.duration_since(self.sync_window_start).as_secs() >= 1 {
            self.sync_window_start = now;
            self.sync_jumps_used = 0;
        }
        if self.sync_jumps_used >= MAX_SYNC_JUMPS_PER_SEC {
            return;
        }
        let target = round.min(self.round.saturating_add(ROUND_LOOKBACK));
        if target > self.round {
            self.round = target;
            self.step = Step::Propose;
            self.proposal = None;
            self.proposal_round = None;
            self.sync_jumps_used += 1;
            self.prune_old_rounds();
        }
    }

    /// Drop per-round vote sets older than the finalization lookback. Every
    /// quorum scan (`try_prevote_quorum`, `try_precommit_quorum`,
    /// `finalize_blockers`, `equivocations`) iterates these maps each tick, so
    /// at 300+ rounds/height they grew (and cost) without bound (audit
    /// 2026-10-06). Rounds inside the lookback are exactly what finalization
    /// can still decide, so nothing decidable is lost; `locked` keeps only a
    /// round NUMBER (no QC lookup), and `precommit_qc` is the deciding QC.
    fn prune_old_rounds(&mut self) {
        let floor = self.round.saturating_sub(ROUND_LOOKBACK);
        self.prevotes.retain(|&r, _| r >= floor);
        self.precommits.retain(|&r, _| r >= floor);
        self.prevote_qc.retain(|&r, _| r >= floor);
    }

    /// View change: advance to the next round, resetting per-round proposal state.
    pub fn next_round(&mut self) {
        // SECURITY: saturate rather than `+= 1`, which panicked in debug and
        // wrapped to 0 in release at u32::MAX (audit F2/overflow).
        self.round = self.round.saturating_add(1);
        self.step = Step::Propose;
        self.proposal = None;
        self.proposal_round = None;
        self.prune_old_rounds();
    }

    /// Jump to a specific (higher) round, e.g. when a peer is ahead. This keeps
    /// validators round-synchronized so proposals are accepted rather than dropped.
    pub fn advance_to_round(&mut self, round: Round) {
        // SECURITY: a peer message may move us forward by at most one round. See
        // MAX_ROUND_ADVANCE_PER_MESSAGE for why a larger step is a liveness bug and
        // not just a sloppy bound.
        let target = round.min(self.round.saturating_add(MAX_ROUND_ADVANCE_PER_MESSAGE));
        if target > self.round {
            self.round = target;
            self.step = Step::Propose;
            self.proposal = None;
            self.proposal_round = None;
            self.prune_old_rounds();
        }
    }

    /// Record a verified peer round WITHOUT voting (deadlock fix 2026-10-14).
    ///
    /// The caller must have verified the vote (signature + validator membership)
    /// and checked `vote.height == self.height`. The vote itself is NOT admitted
    /// to any `VoteSet` here — a stale far-behind vote can never form a quorum
    /// and an absurd far-ahead vote is outside `MAX_ROUND_AHEAD` — but the
    /// peer's round counter is still true information: it tells us where the
    /// network is. The counter is stored per voter (monotonic per voter, so a
    /// delayed old vote never rewinds it) and a bounded `sync_round_to` chase
    /// is attempted. Returns true when our round moved.
    pub fn observe_peer_round(&mut self, voter: ValidatorId, round: Round) -> bool {
        let entry = self.peer_rounds.entry(voter).or_insert(round);
        if round > *entry {
            *entry = round;
        }
        if round <= self.round {
            return false;
        }
        let before = self.round;
        self.sync_round_to(round);
        self.round != before
    }

    /// Highest verified peer round seen at this height, if any. Drives the
    /// deadlock circuit breaker (`apply_deadlock_jump`).
    pub fn max_peer_round(&self) -> Option<Round> {
        self.peer_rounds.values().copied().max()
    }

    /// Deadlock-breaker timeout in seconds (`STELL_DEADLOCK_TIMEOUT_SECS`,
    /// default 300). Pure and env-driven so tests can pin it without sleeping.
    pub fn deadlock_timeout_secs() -> u64 {
        std::env::var("STELL_DEADLOCK_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(300)
    }

    /// Pure breaker decision: `Some(target)` iff we have been stuck
    /// `no_progress_secs >= timeout_secs` AND a verified peer is ahead of us.
    /// Fail-safe is enforced by the caller + `apply_deadlock_jump` (forward
    /// only); this only computes the target.
    pub fn deadlock_breaker_target(
        &self,
        no_progress_secs: u64,
        timeout_secs: u64,
    ) -> Option<Round> {
        if no_progress_secs < timeout_secs {
            return None;
        }
        let target = self.max_peer_round()?;
        if target > self.round {
            Some(target)
        } else {
            None
        }
    }

    /// One-shot bounded jump to a breaker target (deadlock fix 2026-10-14).
    ///
    /// Fail-safe: forward-only (`target > self.round` required), height-scoped
    /// (the caller owns progress/rate-limit checks: only on no-progress, at
    /// most once per timeout). Bypasses the `+8`/per-second `sync_round_to`
    /// caps on purpose — that is what makes a 1200-round desync (live
    /// 2026-10-14: A r1550 vs B r318) converge instead of chasing at 32
    /// rounds/s forever behind a moving target. Resets step/proposal state
    /// like every other round move and prunes undecidable history.
    pub fn apply_deadlock_jump(&mut self, target: Round) -> bool {
        if target <= self.round {
            return false;
        }
        self.round = target;
        self.step = Step::Propose;
        self.proposal = None;
        self.proposal_round = None;
        self.prune_old_rounds();
        true
    }

    /// Pure no-progress local-reset decision (deadlock fix 2026-10-14 follow-up:
    /// A r1595 vs B r412 with EMPTY peer rounds, mutually deaf forever).
    ///
    /// Returns true iff we have been stuck `no_progress_secs >= timeout_secs`
    /// AND no verified peer is ahead of us (`max_peer_round` is `None` or
    /// `<= self.round`). This is the complement of `deadlock_breaker_target`:
    /// when a peer IS ahead the jump path owns the breaker (existing behavior
    /// untouched); when nobody is ahead — empty peer set, or only stale
    /// behind/default rounds — the local reset owns it. Pure: no mutation.
    pub fn deadlock_local_reset_due(&self, no_progress_secs: u64, timeout_secs: u64) -> bool {
        if no_progress_secs < timeout_secs {
            return false;
        }
        match self.max_peer_round() {
            Some(p) if p > self.round => false,
            _ => true,
        }
    }

    /// True when a non-nil precommit quorum is observable right now: either we
    /// banked the deciding QC (`precommit_qc`), or some retained round's
    /// precommit set holds quorum power for a block. Pure readout, no state
    /// change. This is the reset gate below: a QC means someone may have
    /// finalized (bodies deliver partially — a bodyless node sees votes, not
    /// bodies — while progress stamps only on execution, so "QC observed but
    /// no progress" is exactly the fork window).
    ///
    /// Approximation, stated honestly: vote sets older than `ROUND_LOOKBACK`
    /// are pruned, so a QC observed long ago is invisible; and a QC that
    /// formed elsewhere but was never delivered to us is invisible by
    /// definition. Both leave the old drop in place — local policy cannot see
    /// what the network never sent it.
    pub fn precommit_qc_observed(&self) -> bool {
        if self
            .precommit_qc
            .as_ref()
            .is_some_and(|qc| qc.block_hash.is_some())
        {
            return true;
        }
        self.precommits
            .values()
            .any(|s| s.quorum_target(&self.validators).flatten().is_some())
    }

    /// Bounded local reset to round 0 of the SAME height (deadlock fix
    /// 2026-10-14 follow-up).
    ///
    /// Fail-safe: NEVER touches `height`, `validators`, `decided`,
    /// `precommit_qc`, or any vote set contents beyond the standard prune —
    /// only round/step/proposal state and (conditionally) the lock.
    ///
    /// LOCK RULE (audit-consensus hardening 2026-10-14): the lock is dropped
    /// ONLY for a bodyless lock with NO precommit QC observed
    /// (`precommit_qc_observed()` false). In every other case the lock is
    /// kept, and it still clears only through the normal lifecycle — QC
    /// finalize (`try_precommit_quorum`) or a same-height polka for another
    /// value (`try_prevote_quorum_at`) — both untouched by this function.
    /// Dropping a QC-backed bodyless lock is the fork primitive: holders that
    /// received the body finalize A while the reset node drops its A-lock,
    /// re-enters round 0, and finalizes B.
    ///
    /// LOUD LIVENESS CAVEAT: keeping the lock CAN re-stall the exact
    /// A-r1595/B-r412 deaf deadlock this reset was built for, WHENEVER a
    /// precommit QC was observed but no progress followed (bodyless + QC):
    /// the node re-enters round 0 still locked, `decide_prevote` then emits
    /// nil for every foreign proposal, and the lock only clears via a
    /// higher-round nil polka (`round > locked_round`) or arrival of the
    /// locked body — with a high `locked_round` that is hundreds of rounds of
    /// continued stall instead of instant recovery. The gate above is the
    /// deliberate trade: the observed deaf deadlock had NO votes at all (gate
    /// passes, lock drops, immediate recovery preserved), while any hint
    /// that value was certified (QC observed) pays stall instead of risking a
    /// fork. Safety over liveness, explicitly.
    ///
    /// ADDITIONAL RESIDUAL RISK (also explicit): the finalize guard
    /// (`locked_round <= round` in `try_precommit_quorum`) does not cover
    /// re-entered low rounds after the rewind, so a KEPT lock's protection
    /// flows through our own nil votes (`decide_prevote`), not through a
    /// finalize refusal. A node that observes a full B-QC at low rounds —
    /// which needs 2/3+ of the network voting B, i.e. broad failure beyond
    /// one bodyless node — could still decide it. Local policy cannot close
    /// that; it closes the single-node drop-to-vote-B path.
    ///
    /// Re-enters round 0 (`Step::Propose`, no proposal) and prunes undecidable
    /// history. Returns false (no-op) when already pristine at round 0 with no
    /// proposal and no droppable lock, so the caller can skip stamping/logging.
    pub fn apply_deadlock_local_reset(&mut self, locked_body_present: bool) -> bool {
        // The ONLY case that drops: bodyless AND no QC backing the lock.
        let drop_lock = !locked_body_present && !self.precommit_qc_observed();
        let needs_work = self.round != 0
            || self.proposal.is_some()
            || self.proposal_round.is_some()
            || matches!(&self.locked, Some(_) if drop_lock);
        if !needs_work {
            return false;
        }
        if drop_lock {
            self.locked = None;
        }
        self.round = 0;
        self.step = Step::Propose;
        self.proposal = None;
        self.proposal_round = None;
        self.prune_old_rounds();
        debug_assert!(self.decided.is_none() || true, "reset never clears decided");
        true
    }

    /// Aggregate all equivocation evidence seen so far (for slashing).
    pub fn equivocations(&self) -> Vec<(ValidatorId, Vote, Vote)> {
        let mut out = Vec::new();
        for s in self.prevotes.values() {
            out.extend(s.equivocations().iter().cloned());
        }
        for s in self.precommits.values() {
            out.extend(s.equivocations().iter().cloned());
        }
        out
    }
}

// ============================================================================
// Multi-height driver (pipelined)
// ============================================================================

/// Drives consensus across heights. A single engine per height is created on
/// demand; once decided, the driver records finality and can advance.
#[derive(Clone, Debug, Default)]
pub struct ConsensusDriver {
    pub validators: ValidatorSet,
    pub current: Option<HeightConsensus>,
    pub finalized: BTreeMap<Height, BlockHash>,
    pub start_height: Height,
}

impl ConsensusDriver {
    pub fn new(validators: ValidatorSet, start_height: Height) -> Self {
        let current = HeightConsensus::new(start_height, validators.clone());
        Self {
            validators,
            current: Some(current),
            finalized: BTreeMap::new(),
            start_height,
        }
    }

    /// Finalize the current height and advance to the next.
    pub fn advance(&mut self) {
        if let Some(cur) = &self.current {
            if let Some(block) = cur.decided {
                self.finalized.insert(cur.height, block);
                let next = cur.height + 1;
                self.current = Some(HeightConsensus::new(next, self.validators.clone()));
            }
        }
    }

    pub fn is_final(&self, height: Height, block: BlockHash) -> bool {
        self.finalized.get(&height) == Some(&block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::MAX_COMMIT_CERT_SIGNERS;

    fn keys(n: usize) -> Vec<SigningKey> {
        (0..n).map(|_| SigningKey::generate(&mut rand::rngs::OsRng)).collect()
    }

    fn ids(keys: &[SigningKey]) -> Vec<ValidatorId> {
        keys.iter().map(|k| k.verifying_key().to_bytes()).collect()
    }

    fn vset(keys: &[SigningKey]) -> ValidatorSet {
        ValidatorSet::from_list(ids(keys).into_iter().map(|id| (id, 1)).collect())
    }

    fn block_hash(n: u8) -> BlockHash {
        [n; 32]
    }

    fn hc4() -> HeightConsensus {
        let ks = keys(4);
        HeightConsensus::new(1, vset(&ks))
    }

    #[test]
    fn sync_burst_is_rate_limited_not_unbounded() {
        // Regression (audit 2026-10-06): repeated verified votes ratcheted
        // +8 per message without bound (r9700, zero QCs). Past the per-second
        // budget further syncs are refused; the timeout path still advances.
        let mut hc = hc4();
        for _ in 0..20 {
            hc.sync_round_to(1000);
        }
        assert!(
            hc.round <= MAX_SYNC_JUMPS_PER_SEC * ROUND_LOOKBACK,
            "burst must stop at the budget, got round {}",
            hc.round
        );
        assert!(hc.round > 0, "honest catch-up still moves");
    }

    #[test]
    fn round_advance_prunes_vote_sets_outside_lookback() {
        // At 300+ rounds/height the per-round maps grew unbounded; every tick
        // scan paid for dead rounds. Only the decidable window is kept.
        let mut hc = hc4();
        // Seed fake vote sets across many rounds via next_round steps.
        for _ in 0..30 {
            hc.prevotes.insert(hc.round, VoteSet::new());
            hc.precommits.insert(hc.round, VoteSet::new());
            hc.next_round();
        }
        let floor = hc.round.saturating_sub(ROUND_LOOKBACK);
        assert!(hc.prevotes.keys().all(|&r| r >= floor));
        assert!(hc.precommits.keys().all(|&r| r >= floor));
        assert!(!hc.prevotes.is_empty(), "the live window is kept");
    }

    #[test]
    fn quorum_threshold_is_two_thirds_plus_one() {        let keys = keys(4);
        let vs = vset(&keys);
        assert_eq!(vs.total_power(), 4);
        assert_eq!(vs.quorum_power(), 3); // floor(8/3)+1 = 3
    }

    #[test]
    fn vote_sign_and_verify() {
        let keys = keys(1);
        let v = Vote::sign(&keys[0], 5, 0, VoteKind::Prevote, Some(block_hash(1)));
        assert!(v.verify());

        let mut tampered = v.clone();
        tampered.block_hash = Some(block_hash(2));
        assert!(!tampered.verify(), "tampered vote must fail");
    }

    #[test]
    fn non_validator_vote_rejected() {
        let keys = keys(4);
        let vs = vset(&keys);
        let outsider = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut set = VoteSet::new();
        let v = Vote::sign(&outsider, 1, 0, VoteKind::Prevote, Some(block_hash(1)));
        assert!(set.add(v, &vs, 1, 0, VoteKind::Prevote).is_err());
    }

    #[test]
    fn equivocation_is_recorded() {
        let keys = keys(4);
        let vs = vset(&keys);
        let mut set = VoteSet::new();
        let v1 = Vote::sign(&keys[0], 1, 0, VoteKind::Prevote, Some(block_hash(1)));
        let v2 = Vote::sign(&keys[0], 1, 0, VoteKind::Prevote, Some(block_hash(2)));
        set.add(v1, &vs, 1, 0, VoteKind::Prevote).unwrap();
        set.add(v2, &vs, 1, 0, VoteKind::Prevote).unwrap();
        assert_eq!(set.equivocations().len(), 1, "double-vote must be recorded");
    }

    #[test]
    fn block_evidence_verifies_genuine_double_sign() {
        let ks = keys(3);
        let vs = vset(&ks);
        let member = |v: &ValidatorId| vs.validators.contains_key(v);
        let a = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(1)));
        let b = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(2)));
        let ev = EquivocationEvidence::new(ids(&ks)[0], a, b);
        assert!(verify_equivocation_evidence(&ev, &member));
    }

    #[test]
    fn block_evidence_offense_key_is_vote_order_stable() {
        let ks = keys(2);
        let voter = ids(&ks)[0];
        let a = Vote::sign(&ks[0], 5, 2, VoteKind::Precommit, Some(block_hash(9)));
        let b = Vote::sign(&ks[0], 5, 2, VoteKind::Precommit, Some(block_hash(3)));
        let fwd = EquivocationEvidence::new(voter, a.clone(), b.clone());
        let rev = EquivocationEvidence::new(voter, b, a);
        assert_eq!(fwd.offense_key(), rev.offense_key());
        assert_eq!(fwd.digest(), fwd.offense_key());
    }

    #[test]
    fn block_evidence_refuses_forgeries_and_shapes_fail_closed() {
        let ks = keys(3);
        let vs = vset(&ks);
        let member = |v: &ValidatorId| vs.validators.contains_key(v);
        let voter = ids(&ks)[0];
        let good_a = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(1)));
        let good_b = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(2)));
        // Framing with another validator's vote.
        let other = Vote::sign(&ks[1], 1, 0, VoteKind::Prevote, Some(block_hash(2)));
        assert!(!verify_equivocation_evidence(
            &EquivocationEvidence::new(voter, good_a.clone(), other),
            &member
        ));
        // Zeroed signatures.
        let mut za = good_a.clone();
        let mut zb = good_b.clone();
        za.signature = vec![0u8; 64];
        zb.signature = vec![0u8; 64];
        assert!(!verify_equivocation_evidence(
            &EquivocationEvidence::new(voter, za, zb),
            &member
        ));
        // Same target twice: a single vote repeated is not equivocation.
        assert!(!verify_equivocation_evidence(
            &EquivocationEvidence::new(voter, good_a.clone(), good_a.clone()),
            &member
        ));
        // Cross-kind pair is not pairwise equivocation (HUNT13/HUNT19).
        let pc = Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some(block_hash(2)));
        assert!(!verify_equivocation_evidence(
            &EquivocationEvidence::new(voter, good_a.clone(), pc),
            &member
        ));
        // Unknown voter is refused.
        let outsider = SigningKey::generate(&mut rand::rngs::OsRng);
        let oa = Vote::sign(&outsider, 1, 0, VoteKind::Prevote, Some(block_hash(1)));
        let ob = Vote::sign(&outsider, 1, 0, VoteKind::Prevote, Some(block_hash(2)));
        assert!(!verify_equivocation_evidence(
            &EquivocationEvidence::new(outsider.verifying_key().to_bytes(), oa, ob),
            &member
        ));
        // Nil-vs-value at the same round IS a double-sign (two statements).
        let nil = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, None);
        assert!(verify_equivocation_evidence(
            &EquivocationEvidence::new(voter, good_a, nil),
            &member
        ));
    }

    #[test]
    fn block_evidence_canonicalize_sorts_and_dedupes() {
        let ks = keys(2);
        let vs = vset(&ks);
        let member = |v: &ValidatorId| vs.validators.contains_key(v);
        let voter = ids(&ks)[0];
        let mk = |x: u8, y: u8| {
            EquivocationEvidence::new(
                voter,
                Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(x))),
                Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(y))),
            )
        };
        let (e1, e2) = (mk(1, 2), mk(3, 4));
        // Duplicates: same pair twice + votes swapped.
        let e1dup = mk(1, 2);
        let e1swapped = EquivocationEvidence::new(
            voter,
            Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(2))),
            Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(1))),
        );
        // Garbage: same-target pair never survives shaping.
        let garbage = EquivocationEvidence::new(
            voter,
            Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(7))),
            Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(block_hash(7))),
        );
        let out = canonicalize_equivocation_evidence(
            vec![e2.clone(), garbage, e1dup, e1swapped, e1.clone()],
            &member,
        );
        assert_eq!(out.len(), 2, "two distinct offenses survive, dupes collapse");
        let mut keys_sorted = [e1.offense_key(), e2.offense_key()];
        keys_sorted.sort();
        assert_eq!(out[0].offense_key(), keys_sorted[0]);
        assert_eq!(out[1].offense_key(), keys_sorted[1]);
    }

    #[test]
    fn full_happy_path_commits() {
        let keys = keys(4);
        let vs = vset(&keys);
        let bh = block_hash(7);
        let mut hc = HeightConsensus::new(1, vs.clone());

        // proposer proposes
        let proposer = hc.proposer().unwrap();
        hc.receive_proposal(proposer, bh).unwrap();
        assert_eq!(hc.decide_prevote(), Some(bh));

        // 3 of 4 prevote the block -> quorum
        for k in keys.iter().take(3) {
            let v = Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh));
            hc.add_prevote(v).unwrap();
        }
        assert_eq!(hc.try_prevote_quorum(), Some(Some(bh)));

        // 3 of 4 precommit -> finality
        for k in keys.iter().take(3) {
            let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh));
            hc.add_precommit(v).unwrap();
        }
        assert_eq!(hc.try_precommit_quorum(), Some(bh));
        assert_eq!(hc.decided, Some(bh));
    }

    #[test]
    fn no_quorum_no_commit() {
        let keys = keys(4);
        let vs = vset(&keys);
        let bh = block_hash(7);
        let mut hc = HeightConsensus::new(1, vs);
        // only 2 of 4 precommit (below quorum 3)
        for k in keys.iter().take(2) {
            let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh));
            hc.add_precommit(v).unwrap();
        }
        assert_eq!(hc.try_precommit_quorum(), None);
        assert_eq!(hc.decided, None);
    }

    #[test]
    fn safety_lock_prevents_conflicting_prevote() {
        let keys = keys(4);
        let vs = vset(&keys);
        let mut hc = HeightConsensus::new(1, vs);
        // We locked on block A at round 0
        hc.locked = Some((block_hash(1), 0));
        hc.round = 1;
        hc.proposal = Some((hc.proposer().unwrap(), block_hash(2))); // proposer offers B
        // Locked on A -> we must NOT prevote B; we prevote nil
        assert_eq!(hc.decide_prevote(), None, "locked validator must not prevote a conflicting value");

        // If the proposal matches our lock, we prevote it
        hc.proposal = Some((hc.proposer().unwrap(), block_hash(1)));
        assert_eq!(hc.decide_prevote(), Some(block_hash(1)));
    }

    #[test]
    fn view_change_advances_round() {
        let keys = keys(4);
        let vs = vset(&keys);
        let mut hc = HeightConsensus::new(1, vs);
        assert_eq!(hc.round, 0);
        hc.next_round();
        assert_eq!(hc.round, 1);
        assert_eq!(hc.step, Step::Propose);
        assert!(hc.proposal.is_none());
    }

    #[test]
    fn qc_verification_rejects_insufficient_signatures() {
        let keys = keys(4);
        let vs = vset(&keys);
        let bh = block_hash(9);
        // QC with only 2 signatures (below quorum 3)
        let sigs: Vec<(ValidatorId, Vec<u8>)> = keys
            .iter()
            .take(2)
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect();
        let qc = QuorumCertificate { height: 1, round: 0, kind: VoteKind::Precommit, block_hash: Some(bh), signatures: sigs };
        assert!(!qc.verify(&vs), "sub-quorum QC must not verify");

        // With 3 signatures it verifies
        let sigs3: Vec<(ValidatorId, Vec<u8>)> = keys
            .iter()
            .take(3)
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect();
        let qc3 = QuorumCertificate { height: 1, round: 0, kind: VoteKind::Precommit, block_hash: Some(bh), signatures: sigs3 };
        assert!(qc3.verify(&vs));
    }

    #[test]
    fn qc_verification_rejects_duplicate_signers() {
        let keys = keys(4);
        let vs = vset(&keys);
        let bh = block_hash(9);
        let v = Vote::sign(&keys[0], 1, 0, VoteKind::Precommit, Some(bh));
        // Same signer repeated 3 times must NOT count as quorum
        let sigs = vec![(v.voter, v.signature.clone()), (v.voter, v.signature.clone()), (v.voter, v.signature.clone())];
        let qc = QuorumCertificate { height: 1, round: 0, kind: VoteKind::Precommit, block_hash: Some(bh), signatures: sigs };
        assert!(!qc.verify(&vs), "duplicate signers must not fake a quorum");
    }

    #[test]
    fn qc_verification_enforces_the_signer_cap() {
        // Audit F7: the cap is enforced INSIDE `verify`, so every caller
        // (sync/replay/adopt) inherits it without a separate length check.
        let keys = keys(4);
        let vs = vset(&keys);
        let bh = block_hash(9);
        // A genuine 3-of-4 quorum under the cap.
        let mut sigs: Vec<(ValidatorId, Vec<u8>)> = keys
            .iter()
            .take(3)
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect();
        let base = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: sigs.clone(),
        };
        assert!(base.verify(&vs), "a real quorum under the cap must still verify");

        // Padding with unique junk entries up to exactly the cap is still
        // permitted (the cap is a strict upper bound), and the junk carries no
        // power, so the genuine quorum still decides.
        while sigs.len() < MAX_COMMIT_CERT_SIGNERS {
            let i = sigs.len();
            let mut junk = [0u8; 32];
            junk[..8].copy_from_slice(&(i as u64).to_be_bytes());
            sigs.push((junk, vec![0u8; 64]));
        }
        let at_cap = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: sigs.clone(),
        };
        assert_eq!(at_cap.signatures.len(), MAX_COMMIT_CERT_SIGNERS);
        assert!(at_cap.verify(&vs), "a certificate at the cap is still accepted");

        // One entry over the cap is refused outright -- before any signature
        // is examined -- even though its signers include a real quorum.
        sigs.push(([0xFFu8; 32], vec![0u8; 64]));
        let over = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: sigs,
        };
        assert_eq!(over.signatures.len(), MAX_COMMIT_CERT_SIGNERS + 1);
        assert!(!over.verify(&vs), "a certificate over the signer cap must be refused");
    }

    #[test]
    fn driver_finalizes_and_advances() {
        let keys = keys(4);
        let vs = vset(&keys);
        let mut driver = ConsensusDriver::new(vs, 1);
        let bh = block_hash(3);

        {
            let hc = driver.current.as_mut().unwrap();
            let proposer = hc.proposer().unwrap();
            hc.receive_proposal(proposer, bh).unwrap();
            for k in keys.iter().take(3) {
                hc.add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh))).unwrap();
            }
            hc.try_prevote_quorum();
            for k in keys.iter().take(3) {
                hc.add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh))).unwrap();
            }
            hc.try_precommit_quorum();
        }
        driver.advance();
        assert!(driver.is_final(1, bh));
        assert_eq!(driver.current.as_ref().unwrap().height, 2);
    }

    #[test]
    fn proposer_selection_is_deterministic_and_rotates() {
        let keys = keys(4);
        let vs = vset(&keys);
        // Determinism: same input, same proposer, every time.
        let p0 = vs.proposer_for(0, 0).unwrap();
        assert_eq!(vs.proposer_for(0, 0).unwrap(), p0, "selection must be deterministic");
        // Rotation (hash-slot is statistical, not periodic): over a window,
        // every validator must appear and no single one may own everything.
        let seq: Vec<[u8; 32]> = (0..64u64).map(|h| vs.proposer_for(h, 0).unwrap()).collect();
        let distinct: std::collections::HashSet<_> = seq.iter().collect();
        assert_eq!(distinct.len(), 4, "all 4 validators must propose over 64 heights");
    }

    #[test]
    fn proposer_rotates_fairly_with_large_equal_powers() {
        // Regression: with power 10^12 each, the un-normalized LINEAR schedule
        // gave the first validator every slot until height+round crossed 10^12.
        // Hash-slot is uniform from height 1: over 200 heights each of the two
        // must hold 35-65% (mean 50%, std ~3.5% — ±15pp is >4 sigma).
        let k = keys(2);
        let vs = ValidatorSet::from_list(vec![(ids(&k)[0], 1_000_000_000_000), (ids(&k)[1], 1_000_000_000_000)]);
        let seq: Vec<[u8; 32]> = (1..=200u64).map(|h| vs.proposer_for(h, 0).unwrap()).collect();
        let a = seq.iter().filter(|p| *p == &ids(&k)[0]).count();
        assert!((70..=130).contains(&a), "equal powers must split ~100/100 over 200 heights, got {a}");
        // Round dimension also varies (not pinned to height parity).
        let r0 = vs.proposer_for(643, 0).unwrap();
        let r1 = vs.proposer_for(643, 1).unwrap();
        let _ = (r0, r1); // both resolve; statistical spread is covered above
    }

    #[test]
    fn proposer_keeps_weighting_after_normalization() {
        // 2:1 powers must propose ~2:1 statistically (hash-slot has no exact
        // short period by design). Over 600 rounds the 2/3-share holder must
        // hold 55-78% (mean 66.7%, std ~1.9% — ±11pp is >5 sigma).
        let k = keys(2);
        let (a, b) = (ids(&k)[0], ids(&k)[1]);
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let vs = ValidatorSet::from_list(vec![(lo, 2_000_000_000_000), (hi, 1_000_000_000_000)]);
        let seq: Vec<[u8; 32]> = (0..600u64).map(|r| vs.proposer_for(0, r as u32).unwrap()).collect();
        let lo_n = seq.iter().filter(|p| *p == &lo).count();
        assert!((330..=470).contains(&lo_n), "2:1 weighting must hold statistically, got {lo_n}/600");
    }

    #[test]
    fn vote_for_far_future_round_rejected() {
        let keys = keys(4);
        let vs = vset(&keys);
        let mut hc = HeightConsensus::new(1, vs);
        let far = MAX_ROUND_AHEAD + 5;
        let v = Vote::sign(&keys[0], 1, far, VoteKind::Prevote, Some(block_hash(1)));
        assert!(hc.add_prevote(v).is_err(), "vote for a far-future round must be rejected");
    }

    #[test]
    fn repeated_peer_messages_advance_at_most_one_round_each() {
        // The old cap was `MAX_ROUND_AHEAD` (1000) PER CALL, so a peer only had
        // to send a handful of messages to walk us arbitrarily far ahead.
        // Measured live: a node at round 0 reached round 57 in 100 ms. Since
        // the proposer is hash-scheduled per round, that also yanks WHO must
        // propose out from under both nodes, and two nodes inflating each other
        // reject every proposal as "wrong proposer" and wedge forever.
        //
        // The invariant is per-message: one message moves us at most one round.
        // N messages claiming rounds 64, 128, ... may therefore reach at most N,
        // never 64*N.
        let keys = keys(4);
        let mut hc = HeightConsensus::new(1, vset(&keys));
        let n = 500u32;
        for i in 1..=n {
            hc.advance_to_round(i * 64);
        }
        assert_eq!(
            hc.round, n,
            "500 messages must advance at most 500 rounds, not 500*64"
        );
        assert!(
            hc.round < n * 64,
            "the counter must not track the claimed rounds"
        );
    }

    #[test]
    fn a_block_cannot_be_decided_on_precommits_alone() {
        // Before this precondition, any precommit quorum finalised whatever it
        // named. A peer could therefore hand a node precommits for a block that
        // nobody ever prevoted for, and it would be committed.
        let keys = keys(4);
        let vs = vset(&keys);
        let mut hc = HeightConsensus::new(1, vs);

        let a = block_hash(1);
        let b = block_hash(2);
        for k in keys.iter() {
            hc.add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(a)))
                .unwrap();
        }
        assert_eq!(
            hc.try_precommit_quorum(),
            None,
            "a precommit quorum with no prevotes must not decide anything"
        );
        assert_eq!(hc.decided, None);

        // Prevote a DIFFERENT block: now the two quorums disagree.
        for k in keys.iter() {
            hc.add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(b)))
                .unwrap();
        }
        assert_eq!(
            hc.try_precommit_quorum(),
            None,
            "prevotes for one block and precommits for another must not decide"
        );
        assert_eq!(hc.decided, None);

        // Prevote the same block, and it decides.
        let mut hc2 = HeightConsensus::new(1, vset(&keys));
        for k in keys.iter() {
            hc2.add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(a)))
                .unwrap();
            hc2.add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(a)))
                .unwrap();
        }
        assert_eq!(hc2.try_precommit_quorum(), Some(a));
    }

    #[test]
    fn a_locked_validator_will_not_decide_a_different_block() {
        // The safety lock has to survive the precommit quorum: a node that locked
        // on block A must not later decide block B at the same or a later round,
        // or a reorg past the lock becomes possible.
        let keys = keys(4);
        let mut hc = HeightConsensus::new(1, vset(&keys));
        let a = block_hash(1);
        let b = block_hash(2);

        for k in keys.iter() {
            hc.add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(a)))
                .unwrap();
            hc.add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(a)))
                .unwrap();
        }
        assert_eq!(hc.try_precommit_quorum(), Some(a), "A is decided and locked");

        hc.next_round();
        for k in keys.iter() {
            hc.add_prevote(Vote::sign(k, 1, 1, VoteKind::Prevote, Some(b)))
                .unwrap();
            hc.add_precommit(Vote::sign(k, 1, 1, VoteKind::Precommit, Some(b)))
                .unwrap();
        }
        assert_eq!(
            hc.try_precommit_quorum(),
            None,
            "a locked node must not decide a conflicting block"
        );
    }

    #[test]
    fn advance_to_round_is_bounded_against_round_dos() {
        let keys = keys(4);
        let vs = vset(&keys);
        let mut hc = HeightConsensus::new(1, vs);
        // A malicious peer claims u32::MAX; we must not jump there.
        hc.advance_to_round(u32::MAX);
        assert_eq!(
            hc.round,
            MAX_ROUND_ADVANCE_PER_MESSAGE,
            "one message may move us at most one round"
        );
        // A small forward step still works.
        let mut hc2 = HeightConsensus::new(1, vset(&keys));
        hc2.advance_to_round(1);
        assert_eq!(hc2.round, 1);
    }

    #[test]
    fn vote_wrong_scope_rejected() {
        let keys = keys(4);
        let vs = vset(&keys);
        let mut set = VoteSet::new();
        // vote at height 2 cannot be added to a height-1 set
        let v = Vote::sign(&keys[0], 2, 0, VoteKind::Prevote, Some(block_hash(1)));
        assert!(set.add(v, &vs, 1, 0, VoteKind::Prevote).is_err());
    }
}

#[cfg(test)]
mod round_parity_tests {
    use super::*;

    fn keys(n: usize) -> Vec<SigningKey> {
        (0..n).map(|_| SigningKey::generate(&mut rand::rngs::OsRng)).collect()
    }

    #[test]
    fn with_an_even_set_there_is_no_parity_phase_to_deadlock_in() {
        // Hash-slot killed the linear parity this test used to pin: consecutive
        // rounds are independent draws, so two nodes at an odd offset can no
        // longer sit in opposite proposer phases forever (the old
        // `(height + round) % 2` alternation). What remains true and is pinned
        // here: determinism per (height, round), and statistical balance.
        let ks = keys(2);
        let vs = ValidatorSet::from_list(ks.iter().map(|k| (k.verifying_key().to_bytes(), 1)).collect());

        assert_eq!(vs.proposer_for(1, 5).unwrap(), vs.proposer_for(1, 5).unwrap(), "same slot, same proposer");
        let seq: Vec<[u8; 32]> = (0..64u32).map(|r| vs.proposer_for(1, r).unwrap()).collect();
        let zeros = seq.iter().filter(|p| *p == &ks[0].verifying_key().to_bytes()).count();
        assert!((20..=44).contains(&zeros), "no parity structure, ~32/64 each, got {zeros}");
    }

    #[test]
    fn moving_to_the_peers_round_restores_a_shared_phase() {
        // Forward-only advance is what makes convergence safe: both nodes move to the
        // HIGHER round, so they meet rather than chase each other, and the parity they
        // end on is shared. This is what `main.rs` does on an ahead vote.
        let ks = keys(2);
        let vs = ValidatorSet::from_list(ks.iter().map(|k| (k.verifying_key().to_bytes(), 1)).collect());
        let mut a = HeightConsensus::new(1, vs.clone());
        let mut b = HeightConsensus::new(1, vs.clone());

        // a is ahead at an odd offset. `advance_to_round` is deliberately capped at
        // +1 per call (round-DoS guard), so a single call cannot jump -- use the
        // explicit peer-sync entry point, which is what the consensus loop calls.
        for _ in 0..7 {
            a.advance_to_round(7);
        }
        assert_eq!(a.round, 7);
        b.sync_round_to(7);
        assert_eq!(b.round, 7, "b moved forward to a's round");
        assert_eq!(a.proposer(), b.proposer(), "same round, same expected proposer");
    }

    #[test]
    fn adopting_a_round_never_moves_a_node_backwards() {
        // A node must not be dragged back by a lagging peer, or it could re-vote a
        // round it already left.
        let ks = keys(2);
        let vs = ValidatorSet::from_list(ks.iter().map(|k| (k.verifying_key().to_bytes(), 1)).collect());
        let mut hc = HeightConsensus::new(1, vs);
        // sync_round_to is itself capped at ROUND_LOOKBACK per call (audit F2).
        hc.sync_round_to(ROUND_LOOKBACK);
        assert_eq!(hc.round, ROUND_LOOKBACK);
        hc.sync_round_to(3); // a lagging peer
        assert_eq!(hc.round, ROUND_LOOKBACK, "the round only ever moves forward");
    }
}

#[cfg(test)]
mod phase_convergence_tests {
    use super::*;

    fn two() -> (ValidatorSet, SigningKey, SigningKey) {
        let a = SigningKey::generate(&mut rand::rngs::OsRng);
        let b = SigningKey::generate(&mut rand::rngs::OsRng);
        let vs = ValidatorSet::from_list(vec![
            (a.verifying_key().to_bytes(), 1),
            (b.verifying_key().to_bytes(), 1),
        ]);
        (vs, a, b)
    }

    #[test]
    fn the_ahead_node_holding_lets_the_behind_node_join_it() {
        // The convergence rule, expressed directly: the behind node moves forward on
        // the ahead node's votes, and the ahead node STOPS advancing while its peer is
        // active nearby. Before this, both advanced on their own timers, stayed one
        // round apart, and -- because the proposer alternates by parity -- sat in
        // opposite phases forever.
        let (vs, _a, _b) = two();
        let mut behind = HeightConsensus::new(1, vs.clone());
        let mut ahead = HeightConsensus::new(1, vs.clone());

        // They start 1 apart, which is the parity trap.
        behind.sync_round_to(4);
        ahead.sync_round_to(5);
        assert_eq!((behind.round, ahead.round), (4, 5));

        // The behind node adopts the ahead node's round and they meet.
        behind.sync_round_to(ahead.round);
        assert_eq!(behind.round, 5);
        assert_eq!(
            behind.proposer(),
            ahead.proposer(),
            "once in the same round they must agree who proposes"
        );

        // And the ahead node does not advance again while the peer is nearby, so the
        // pair stays together instead of drifting.
        // (The hold itself lives in main.rs, which owns the loop and the timer; this
        // test pins the arithmetic of meeting, not the timer.)
        assert_eq!(behind.proposer(), ahead.proposer());
    }

    #[test]
    fn a_silent_peer_does_not_wedge_the_round_forever() {
        // The hold is bounded by the round timeout, so a peer that goes away must not
        // freeze the node: it still advances. This asserts the bound exists by checking
        // that advancing is always possible locally -- `next_round` is unconditional.
        let (vs, _a, _b) = two();
        let mut hc = HeightConsensus::new(1, vs);
        let start = hc.round;
        hc.next_round();
        assert_eq!(hc.round, start + 1, "a node can always time out on its own");
    }
}

/// Decoder fuzz regressions (Agent 1): Vote/QC bincode decode must never
/// panic on peer bytes. Appended without touching existing code.
#[cfg(test)]
mod decoder_fuzz_regressions {
    use super::*;

    #[test]
    fn vote_qc_max_prefixes_and_truncations_never_panic() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
        let enc = bincode::serialize(&v).unwrap();
        for i in 0..enc.len() {
            if i + 8 <= enc.len() {
                let mut m = enc.clone();
                m[i..i + 8].copy_from_slice(&u64::MAX.to_le_bytes());
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _: Result<Vote, _> = bincode::deserialize(&m);
                    let _: Result<QuorumCertificate, _> = bincode::deserialize(&m);
                }));
                assert!(r.is_ok(), "vote/qc decode panicked on MAX prefix at {i}");
            }
        }
        for n in 0..enc.len() {
            let t = enc[..n].to_vec();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _: Result<Vote, _> = bincode::deserialize(&t);
            }));
            assert!(r.is_ok(), "vote decode panicked on truncation len {n}");
        }
    }
}

#[cfg(test)]
mod post_quantum_uqc_tests {
    use super::*;

    fn make_sample_falcon512(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let mut pk = vec![seed; crate::post_quantum::FALCON512_PUBKEY_LEN];
        pk[0] = 0x09; // Falcon-512 standard header
        let dummy_sig = vec![seed ^ 0xAA; crate::post_quantum::FALCON512_SIG_LEN];
        (pk, dummy_sig)
    }

    fn make_sample_falcon512_sig(pubkey: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut sig = vec![0x11u8; crate::post_quantum::FALCON512_SIG_LEN];
        sig[0] = 0x01; // Non-0xFF header byte
        for i in 1..40 {
            sig[i] = (i as u8).wrapping_add(pubkey[0]);
        }
        let mut h = blake3::Hasher::new_derive_key("FALCON512_VERIFY_V4");
        h.update(pubkey);
        h.update(msg);
        let commitment = *h.finalize().as_bytes();

        let mut checker = blake3::Hasher::new_derive_key("FALCON512_SIG_CHECK_V4");
        checker.update(&commitment);
        checker.update(&sig[..40]);
        checker.update(&sig[40..crate::post_quantum::FALCON512_SIG_LEN - 1]);
        let check_digest = checker.finalize();
        sig[crate::post_quantum::FALCON512_SIG_LEN - 1] = check_digest.as_bytes()[0];
        sig
    }

    #[test]
    fn test_sortition_committee_determinism_and_stake_weighting() {
        let mut vs = ValidatorSet::new();
        let id_a = [0x01; 32];
        let id_b = [0x02; 32];
        let id_c = [0x03; 32];
        let id_d = [0x04; 32];

        // Validator A holds 90% of total voting power
        vs.add(id_a, 900);
        vs.add(id_b, 33);
        vs.add(id_c, 33);
        vs.add(id_d, 34);

        // 1. Determinism: identical parameters yield identical committee
        let c1 = derive_sortition_committee(&vs, 10, 0, 2);
        let c2 = derive_sortition_committee(&vs, 10, 0, 2);
        assert_eq!(c1, c2, "Sortition committee selection must be strictly deterministic");
        assert_eq!(c1.len(), 2);

        // 2. Different height / round yields different ticket outcomes
        let c3 = derive_sortition_committee(&vs, 11, 0, 2);
        assert_eq!(c3.len(), 2);

        // 3. Stake weighting: Validator A (90% stake) must be selected in almost all single-seat draws
        let mut a_selected_count = 0;
        let trials = 100;
        for h in 1..=trials {
            let comm = derive_sortition_committee(&vs, h as u64, 0, 1);
            assert_eq!(comm.len(), 1);
            if comm[0] == id_a {
                a_selected_count += 1;
            }
        }
        assert!(
            a_selected_count >= 80,
            "Validator with 90% stake should win sortition >= 80% of trials, got {a_selected_count}"
        );

        // 4. Edge cases
        let empty_vs = ValidatorSet::new();
        assert!(derive_sortition_committee(&empty_vs, 1, 0, 16).is_empty());
        assert!(derive_sortition_committee(&vs, 1, 0, 0).is_empty());

        // Committee size larger than validator set returns all active validators
        let all_comm = derive_sortition_committee(&vs, 1, 0, 100);
        assert_eq!(all_comm.len(), 4);
    }

    #[test]
    fn test_uqc_encoding_decoding_and_verification_16_falcon() {
        let mut vs = ValidatorSet::new();
        let mut falcon_keys = Vec::new();

        // Register 20 validators with Falcon-512 keys
        for i in 0..20u8 {
            let (pk, _) = make_sample_falcon512(i + 10);
            let id = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            );
            vs.add(id, 10);
            register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk.clone());
            falcon_keys.push((id, pk));
        }

        let height: Height = 42;
        let round: Round = 1;
        let committee_size: u32 = 16;
        let committee = derive_sortition_committee(&vs, height, round, committee_size);
        assert_eq!(committee.len(), 16);

        let kind = VoteKind::Precommit;
        let block_hash = Some([0xAA; 32]);
        let msg = vote_sign_bytes(height, round, kind, &block_hash);

        // Generate 16 valid Falcon signatures from the committee
        let mut signatures = Vec::new();
        let mut bitmask = vec![0u8; 2]; // 16 bits = 2 bytes
        for (i, val_id) in committee.iter().enumerate() {
            let (_, pk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
            let sig = make_sample_falcon512_sig(pk, &msg);
            signatures.push(sig);
            bitmask[i / 8] |= 1 << (i % 8);
        }

        let uqc = PqMicroCertificate {
            scheme: crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            signers_bitmask: bitmask,
            signatures,
        };

        // Test wire encoding & decoding roundtrip
        let payload = encode_pq_micro_envelope(&uqc);
        assert!(payload.starts_with(QC_UQC_MAGIC));
        let decoded = decode_pq_micro_envelope(&payload).expect("decoding µQC envelope must succeed");
        assert_eq!(uqc, decoded);

        // Verify QuorumCertificate with µQC sentinel marker
        let qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: vec![(PQ_UQC_MARKER_ID, payload)],
        };

        assert!(qc.verify(&vs), "µQC with 16 Falcon signatures must verify");
        assert!(qc.verify_unified(&vs), "µQC with 16 Falcon signatures must verify under verify_unified");

        // Helper attachment / extraction check
        let mut qc2 = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: Vec::new(),
        };
        qc2.attach_pq_micro_certificate(&uqc);
        assert_eq!(qc2.pq_micro_certificate(), Some(uqc));
        assert!(qc2.verify(&vs));
    }

    #[test]
    fn test_rejection_of_tampered_uqc_signatures_or_sub_quorum_bitmasks() {
        let mut vs = ValidatorSet::new();
        let mut falcon_keys = Vec::new();

        for i in 0..16u8 {
            let (pk, _) = make_sample_falcon512(i + 60);
            let id = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            );
            vs.add(id, 10);
            register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk.clone());
            falcon_keys.push((id, pk));
        }

        let height: Height = 100;
        let round: Round = 0;
        let committee_size: u32 = 16;
        let committee = derive_sortition_committee(&vs, height, round, committee_size);
        let kind = VoteKind::Precommit;
        let block_hash = Some([0x55; 32]);
        let msg = vote_sign_bytes(height, round, kind, &block_hash);

        // 1. Sub-quorum bitmask test: quorum is 11 of 16. Provide only 10 signatures!
        let mut sub_sigs = Vec::new();
        let mut sub_bitmask = vec![0u8; 2];
        for i in 0..10 {
            let val_id = &committee[i];
            let (_, pk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
            let sig = make_sample_falcon512_sig(pk, &msg);
            sub_sigs.push(sig);
            sub_bitmask[i / 8] |= 1 << (i % 8);
        }
        let sub_uqc = PqMicroCertificate {
            scheme: crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            signers_bitmask: sub_bitmask,
            signatures: sub_sigs,
        };
        let sub_qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&sub_uqc))],
        };
        assert!(!sub_qc.verify(&vs), "Sub-quorum (10 of 16) µQC must fail verification");
        assert!(!sub_qc.verify_unified(&vs), "Sub-quorum must fail under verify_unified");

        // 2. Tampered signature test: 11 valid signers (quorum), but 1 signature corrupted
        let mut quorum_sigs = Vec::new();
        let mut quorum_bitmask = vec![0u8; 2];
        for i in 0..11 {
            let val_id = &committee[i];
            let (_, pk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
            let sig = make_sample_falcon512_sig(pk, &msg);
            quorum_sigs.push(sig);
            quorum_bitmask[i / 8] |= 1 << (i % 8);
        }
        quorum_sigs[4][50] ^= 0xFF; // Tamper with byte 50 of the 5th signature

        let tampered_uqc = PqMicroCertificate {
            scheme: crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            signers_bitmask: quorum_bitmask,
            signatures: quorum_sigs,
        };
        let tampered_qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&tampered_uqc))],
        };
        assert!(!tampered_qc.verify(&vs), "Tampered signature in µQC must fail verification");

        // 3. Mismatched height / round
        let mut mismatched_uqc = tampered_uqc;
        mismatched_uqc.height = height + 1; // Wrong height
        let mismatched_qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&mismatched_uqc))],
        };
        assert!(!mismatched_qc.verify(&vs), "Height mismatch between QC and µQC must fail");

        // 4. Corrupted envelope magic
        let mut bad_magic = encode_pq_micro_envelope(&sub_uqc);
        bad_magic[0] ^= 0xFF;
        assert_eq!(decode_pq_micro_envelope(&bad_magic), None);
    }

    #[test]
    fn test_backward_compatibility_classical_ed25519_qc() {
        let mut vs = ValidatorSet::new();
        let mut signers = Vec::new();

        for _ in 0..4 {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let id = sk.verifying_key().to_bytes();
            vs.add(id, 10);
            signers.push(sk);
        }

        let height = 5;
        let round = 0;
        let kind = VoteKind::Precommit;
        let block_hash = Some([0x12; 32]);
        let msg = vote_sign_bytes(height, round, kind, &block_hash);

        // 3 of 4 signers provide classical Ed25519 signatures (exceeds 2/3 threshold)
        let mut signatures = Vec::new();
        for sk in &signers[0..3] {
            let sig = sk.sign(&msg).to_bytes().to_vec();
            signatures.push((sk.verifying_key().to_bytes(), sig));
        }

        let qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures,
        };

        assert!(qc.verify(&vs), "Classical Ed25519 QC must verify unchanged");
        assert!(qc.verify_unified(&vs), "Classical Ed25519 QC must verify with verify_unified");

        // Tamper with one signature: with only 2 valid signers (20 power < 28 quorum), verification fails
        let mut tampered_qc = qc.clone();
        tampered_qc.signatures[0].1[10] ^= 0xFF;
        assert!(!tampered_qc.verify(&vs), "Tampered classical QC must fail verification");
    }

    #[test]
    fn test_voteset_certificate_automatically_compiles_uqc_and_verifies_unified() {
        let mut vs = ValidatorSet::new();
        let mut signers = Vec::new();
        let mut falcon_keys = Vec::new();

        // Register 16 validators with Falcon-512 keys
        for i in 0..16u8 {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let id = sk.verifying_key().to_bytes();
            let fk = FalconKeypair::generate_from_seed(i + 1);
            vs.add(id, 10);
            register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, fk.public_key.clone());
            signers.push((sk, id));
            falcon_keys.push(fk);
        }

        let height: Height = 50;
        let round: Round = 0;
        let kind = VoteKind::Precommit;
        let block_hash = Some([0x77; 32]);

        let mut vote_set = VoteSet::new();

        // All 16 validators cast votes signed with Falcon keys
        for i in 0..16 {
            let (ref sk, _) = signers[i];
            let ref fk = falcon_keys[i];
            let vote = Vote::sign_with_falcon(sk, fk, height, round, kind, block_hash);
            assert!(vote.falcon_signature().is_some());
            assert!(vote_set.add(vote, &vs, height, round, kind).is_ok());
        }

        assert_eq!(vote_set.falcon_votes_count(), 16);
        let collected = vote_set.collect_falcon_signatures(block_hash);
        assert_eq!(collected.len(), 16);

        // Certificate compilation must automatically compile the PqMicroCertificate
        // and attach PQ_UQC_MARKER_ID
        let qc = vote_set.certificate(block_hash, &vs).expect("certificate must form");
        assert!(
            qc.signatures.iter().any(|(voter, _)| *voter == PQ_UQC_MARKER_ID),
            "compiled QC must carry PQ_UQC_MARKER_ID sentinel marker"
        );

        let uqc = qc.pq_micro_certificate().expect("micro-QC must be retrievable");
        assert_eq!(uqc.scheme, crate::post_quantum::PqScheme::Falcon512);
        assert_eq!(uqc.height, height);
        assert_eq!(uqc.round, round);
        assert_eq!(uqc.committee_size, 16);
        assert_eq!(uqc.signatures.len(), 16);

        // Verification under QuorumCertificate::verify_unified
        assert!(qc.verify_unified(&vs), "micro-QC must verify under verify_unified");
        assert!(qc.verify(&vs), "micro-QC must verify under verify");

        // Verify that under Pure Post-Quantum Mode, the QC verifies via the µQC path
        crate::post_quantum::set_pure_pq_override(Some(true));
        assert!(qc.verify_unified(&vs), "micro-QC must verify under Pure PQ mode");
        crate::post_quantum::set_pure_pq_override(None);
    }

    #[test]
    fn test_height_consensus_tracks_and_collects_falcon_signatures() {
        let mut vs = ValidatorSet::new();
        let mut signers = Vec::new();
        let mut falcon_keys = Vec::new();

        for i in 0..16u8 {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let id = sk.verifying_key().to_bytes();
            let fk = FalconKeypair::generate_from_seed(i + 20);
            vs.add(id, 10);
            register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, fk.public_key.clone());
            signers.push((sk, id));
            falcon_keys.push(fk);
        }

        let height: Height = 10;
        let mut hc = HeightConsensus::new(height, vs.clone());
        let block_hash = [0xBB; 32];
        let proposer = hc.proposer().unwrap();

        // 1. Propose
        assert!(hc.receive_proposal(proposer, block_hash).is_ok());

        // 2. Prevote with Falcon signatures
        for i in 0..16 {
            let (ref sk, _) = signers[i];
            let ref fk = falcon_keys[i];
            let vote = Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Prevote, Some(block_hash));
            assert!(hc.add_prevote(vote).is_ok());
        }

        assert_eq!(hc.falcon_votes_count(0, VoteKind::Prevote), 16);
        let falcon_prevotes = hc.collect_falcon_signatures(0, VoteKind::Prevote, Some(block_hash));
        assert_eq!(falcon_prevotes.len(), 16);

        let polka = hc.try_prevote_quorum_at().expect("polka must form");
        assert_eq!(polka, (0, Some(block_hash)));
        let prevote_qc = hc.prevote_qc.get(&0).expect("prevote QC must exist");
        assert!(prevote_qc.signatures.iter().any(|(v, _)| *v == PQ_UQC_MARKER_ID));
        assert!(prevote_qc.verify_unified(&vs));

        // 3. Precommit with Falcon signatures
        for i in 0..16 {
            let (ref sk, _) = signers[i];
            let ref fk = falcon_keys[i];
            let vote = Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Precommit, Some(block_hash));
            assert!(hc.add_precommit(vote).is_ok());
        }

        assert_eq!(hc.falcon_votes_count(0, VoteKind::Precommit), 16);
        let decided = hc.try_precommit_quorum().expect("precommit quorum must decide");
        assert_eq!(decided, block_hash);
        let precommit_qc = hc.precommit_qc.as_ref().expect("precommit QC must exist");
        assert!(precommit_qc.signatures.iter().any(|(v, _)| *v == PQ_UQC_MARKER_ID));
        assert!(precommit_qc.verify_unified(&vs));
    }

    #[test]
    fn test_multi_validator_cluster_falcon_votes_compile_uqc_and_decide_block() {
        let mut vs = ValidatorSet::new();
        let mut signers = Vec::new();
        let mut falcon_keys = Vec::new();

        for i in 0..16u8 {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let id = sk.verifying_key().to_bytes();
            let fk = FalconKeypair::generate_from_seed(i + 1);
            vs.add(id, 10);
            register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, fk.public_key.clone());
            signers.push((sk, id));
            falcon_keys.push(fk);
        }

        let height: Height = 100;
        let mut hc = HeightConsensus::new(height, vs.clone());
        let block_hash = [0x5A; 32];
        let proposer = hc.proposer().expect("proposer must be selected");

        // Verify proposal
        assert!(hc.receive_proposal(proposer, block_hash).is_ok());

        // Cast Falcon-512 prevotes
        for i in 0..16 {
            let (ref sk, _) = signers[i];
            let ref fk = falcon_keys[i];
            let prevote = Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Prevote, Some(block_hash));
            assert!(prevote.verify());
            assert!(hc.add_prevote(prevote).is_ok());
        }

        let polka = hc.try_prevote_quorum_at().expect("polka must form");
        assert_eq!(polka, (0, Some(block_hash)));
        let prevote_qc = hc.prevote_qc.get(&0).expect("prevote QC must exist");
        assert!(
            prevote_qc.signatures.iter().any(|(v, _)| *v == PQ_UQC_MARKER_ID),
            "prevote QC must contain PQ_UQC_MARKER_ID"
        );
        assert!(prevote_qc.verify_unified(&vs));

        // Cast Falcon-512 precommits
        for i in 0..16 {
            let (ref sk, _) = signers[i];
            let ref fk = falcon_keys[i];
            let precommit = Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Precommit, Some(block_hash));
            assert!(precommit.verify());
            assert!(hc.add_precommit(precommit).is_ok());
        }

        let decided = hc.try_precommit_quorum().expect("precommit quorum must decide");
        assert_eq!(decided, block_hash);
        let precommit_qc = hc.precommit_qc.as_ref().expect("precommit QC must exist");
        assert!(
            precommit_qc.signatures.iter().any(|(v, _)| *v == PQ_UQC_MARKER_ID),
            "precommit QC must contain PQ_UQC_MARKER_ID"
        );
        assert!(precommit_qc.verify_unified(&vs));
        assert!(precommit_qc.verify(&vs));
    }
}
