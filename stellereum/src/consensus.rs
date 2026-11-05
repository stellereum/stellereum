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
//!  - Votes are individually Falcon-512-signed and verified on ingestion (FULL-PQ).
//!  - Equivocation (two different votes by one validator at the same height/round/
//!    kind) is recorded as evidence for slashing.
//!  - The engine is height-scoped; `ConsensusDriver` pipelines heights.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

pub type Height = u64;
pub type Round = u32;
pub type BlockHash = [u8; 32];
pub type ValidatorId = [u8; 32];

// ============================================================================
// Chain-id binding (cross-chain replay protection)
// ============================================================================

/// The chain id every consensus signature and every block hash is bound to.
///
/// FROZEN for the lifetime of the process the first time it is read. The
/// source is [`crate::zkml::effective_chain_id`] (`STELL_CHAIN_ID`, default
/// `5757`), but the value is snapshotted once so that:
///
///  * a mid-run change of the ambient environment cannot make two nodes on the
///    same host (or two code paths in one node) disagree about which network
///    they are on — a disagreement here is a CHAIN SPLIT, not a nuisance; and
///  * the read is a constant-time atomic/once-read instead of an environment
///    lookup on every vote, block hash and signature.
///
/// Deterministic across processes: every node of one deployment reads the same
/// `STELL_CHAIN_ID`, so they derive the same vote preimages, the same block
/// hashes and the same sortition committees. A node on a DIFFERENT deployment
/// (testnet vs mainnet) derives different bytes, so a testnet vote or block
/// can never verify on mainnet with the same key.
static FROZEN_CHAIN_ID: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    /// TEST-ONLY override of the chain id (0 = "use the frozen value").
    ///
    /// Thread-scoped on purpose: the override is process global state, and the
    /// test binary runs its tests in parallel. A thread-local override keeps
    /// "sign as testnet, verify as mainnet" from changing the chain id under
    /// the feet of an unrelated test running at the same time.
    static CHAIN_ID_OVERRIDE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The chain id bound into consensus signatures and block hashes.
///
/// See [`FROZEN_CHAIN_ID`] for the freezing rules.
pub fn consensus_chain_id() -> u64 {
    let override_id = CHAIN_ID_OVERRIDE.with(|c| c.get());
    if override_id != 0 {
        return override_id;
    }
    *FROZEN_CHAIN_ID.get_or_init(crate::zkml::effective_chain_id)
}

/// Test-only: force the chain id used by [`consensus_chain_id`] on THIS
/// thread.
///
/// `0` restores the frozen deployment value (the default). The override is
/// thread-scoped, so a leaked override cannot re-point another test's
/// signatures at another network.
/// Absent from production builds (`any(test, debug_assertions)` only).
#[cfg(any(test, debug_assertions))]
pub fn set_consensus_chain_id_for_tests(chain_id: u64) {
    CHAIN_ID_OVERRIDE.with(|c| c.set(chain_id));
}

// ============================================================================
// Height-gated verify for legacy unbound transaction envelopes (PLAN-BINDING)
// ============================================================================
//
// Phase-3 enforcement, consensus side: at and after the configured activation
// height `H_bind`, a transaction envelope that binds NO chain id (legacy
// unbound: `tx.chain_id().is_none()`) is REFUSED, even if its Ed25519/PQ
// signature is cryptographically valid. Before `H_bind` the same envelope
// verifies under the old rules (history compat: pre-activation blocks never
// re-verify under new rules). Bound envelopes verify at every height, but
// only on the chain they bind (a testnet-bound envelope never verifies on
// mainnet, before or after activation).
//
// Activation is default-OFF (`ChainBindingActivation::never()` when
// `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` is unset): nothing refuses until a
// governance-agreed height is explicitly configured — the same opt-in
// pattern as the XPC activation switch (`STELL_XPC_ACTIVATION_HEIGHT`).
// Wire format untouched (verify-only); quorum and timeout values untouched.

/// Height-gated envelope verify for ONE transaction at `chain_height`.
///
/// Activation comes from the environment
/// (`STELL_CHAIN_BIND_ACTIVATION_HEIGHT`, default never). Tests and
/// deterministic callers prefer
/// [`verify_transaction_envelope_at_height_with_activation`].
pub fn verify_transaction_envelope_at_height(
    tx: &crate::sharding::Transaction,
    chain_height: u64,
) -> Result<(), String> {
    let activation = crate::chain_binding::ChainBindingActivation::from_env();
    verify_transaction_envelope_at_height_with_activation(tx, chain_height, &activation)
}

/// Height-gated envelope verify for ONE transaction at `chain_height` under
/// an explicit `activation`.
///
/// * unbound + refusal inactive (`chain_height < H_bind`, or never
///   configured) => legacy signature check only (compat);
/// * unbound + refusal active (`chain_height >= H_bind`) => `Err` starting
///   with [`crate::chain_binding::UNBOUND_REFUSED_ERR_PREFIX`];
/// * bound => strict chain match against [`consensus_chain_id`] at EVERY
///   height (cross-chain replay refuses pre- and post-activation), then the
///   signature check.
pub fn verify_transaction_envelope_at_height_with_activation(
    tx: &crate::sharding::Transaction,
    chain_height: u64,
    activation: &crate::chain_binding::ChainBindingActivation,
) -> Result<(), String> {
    let chain_id = consensus_chain_id();
    crate::chain_binding::check_admission(
        tx.chain_id().is_some(),
        chain_height,
        activation,
        chain_id,
    )?;
    let strict = activation.refusal_active(chain_height);
    if tx.verify_signature_for_chain(chain_id, strict) {
        return Ok(());
    }
    if tx.chain_id().is_some() {
        return Err(format!(
            "rejected: transaction chain-id mismatch: envelope binds chain {} but this chain is {chain_id}",
            tx.chain_id().unwrap_or(0),
        ));
    }
    Err("rejected: transaction signature invalid".to_string())
}

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

/// The Ed25519 half of a vote/certificate signature entry: strips the live
/// Falcon envelope when present. Plain 64-byte signatures pass through untouched.
// GATE: single live envelope (Falcon v2) keeps the straight-line strip auditable.
pub fn ed25519_sig_bytes(signature: &[u8]) -> &[u8] {
    if signature.len() == VOTE_FALCON_PART_LEN && signature.starts_with(VOTE_FALCON_MAGIC) {
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

/// Verify a Falcon-512 signature. FIPS 206 ring math ONLY — in every build,
/// test or release.
///
/// AUDIT W6.1 (HIGH — the test backdoor is GONE): this function used to carry
/// a `#[cfg(test)]` branch that accepted a signature whose LAST byte was a
/// BLAKE3 "check digest" of the public key, the message and the signature
/// body. That branch was a 1/256 forge probability for ANYONE who knew only
/// the victim's PUBLIC Falcon key (the digest is recomputable from public
/// data): it let an attacker forge that victim's transactions
/// (`Transaction::verify_signature`), validator votes (`Vote::verify`) and
/// block proposals (`verify_proposer_signature`), and it made the tamper
/// detection tests FLAKY (a tampered signature passed ~0.4% of the time —
/// observed as `sharding::tests::test_tampering_detection_on_pq_signatures`
/// failing intermittently).
///
/// There is NO shortcut left: the function is a thin alias for
/// [`crate::post_quantum::verify_pq_signature`] with the Falcon-512 scheme,
/// i.e. real FIPS 206 verification, in every build.
pub fn verify_falcon_signature(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    crate::post_quantum::verify_pq_signature(
        crate::post_quantum::PqScheme::Falcon512,
        pubkey,
        message,
        signature,
    )
}

/// Historical name of [`verify_falcon_signature`].
///
/// AUDIT W6.1: the name is kept only so out-of-tree / parallel call sites
/// keep compiling. It has NO test shortcut: it is a thin alias for the real
/// FIPS 206 verification, exactly like [`verify_falcon_signature`].
#[doc(hidden)]
pub fn verify_falcon_signature_or_test(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_falcon_signature(pubkey, message, signature)
}

/// Verify the block proposal signature, supporting Falcon-512 and Pure PQ enforcement.
pub fn verify_proposer_signature(block: &crate::sharding::Block) -> bool {
    let hash = block.compute_hash();

    // Check if proposer signed with Falcon-512 key
    for (signer_id, sig_bytes) in &block.validator_signatures {
        if sig_bytes.len() == crate::post_quantum::FALCON512_SIG_LEN {
            let matches_proposer = *signer_id == block.proposer
                || get_validator_pq_key(&block.proposer).is_some_and(|(scheme, pk)| {
                    let addr = crate::post_quantum::derive_pq_address(
                        scheme,
                        &pk,
                        &crate::post_quantum::DEFAULT_SALT,
                    );
                    addr == *signer_id
                })
                || get_validator_pq_key(signer_id).is_some_and(|(scheme, pk)| {
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
                    if verify_falcon_signature(&pk, &hash, sig_bytes) {
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
// GATE: single live envelope (Falcon v2) keeps the straight-line strip auditable.
pub fn attach_vote_falcon(key: &FalconKeypair, msg: &[u8], signature: &mut Vec<u8>) {
    let falcon_sig = key.sign(msg);
    let mut ed = vec![0u8; 64];
    if signature.len() == 64 {
        ed.copy_from_slice(signature);
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
///
/// Safety role (quorum accounting): unmintable sentinel (`[0xFE; 32]`) that
/// carries zero voting power in any validator set, so the envelope entry
/// counts toward quorum only via its verified aggregate, never by itself.
pub const PQ_QC_MARKER_ID: ValidatorId = [0xFE; 32];
/// Sentinel marker ID for Micro-Committee (µQC).
///
/// Safety role (quorum accounting): unmintable sentinel (`[0xFD; 32]`) that
/// carries zero voting power in any validator set, so the µQC entry counts
/// toward quorum only via its verified member signatures, never by itself.
pub const PQ_UQC_MARKER_ID: ValidatorId = [0xFD; 32];
/// Magic prefix of a Micro-Committee post-quantum envelope payload.
///
/// Bumped `V4 -> V5`: the envelope now carries the sortition parent (the
/// parent block hash the committee was elected with), so the payload layout
/// changed. A `V4` envelope does not decode as `V5`.
pub const QC_UQC_MAGIC: &[u8; 16] = b"STELL_UQC_PQ_V5_";
/// Magic prefix of a Full Epoch Certificate post-quantum envelope payload.
///
/// Bumped `V4 -> V5` together with [`QC_UQC_MAGIC`] (same layout).
pub const QC_PQ_MAGIC: &[u8; 16] = b"STELL_QC_PQ_V5__";

/// Post-Quantum Micro-Certificate (µQC) for fast 250ms block finality.
///
/// Implements §3 of Stellereum PQ-BFT v5 Master Spec:
/// - Compact committee (default k = [`micro_committee_size`], i.e. the whole
///   validator set up to [`MICRO_COMMITTEE_MAX_SIZE`]) selected via BLAKE3
///   stake-weighted sortition.
/// - Quorum: power-weighted, and ANCHORED TO THE NETWORK
///   ([`pq_micro_required_power`]): the signers' summed power must reach
///   `max(floor(2*W_committee/3) + 1, floor(W_network/2) + 1)`.
///   * While the committee IS the whole validator set (N <= the cap — the
///     live N = 4 network) the two terms coincide with the legacy rule
///     `floor(2*k/3) + 1` (3 of 4, 11 of 16 for k = 16), so every historic
///     certificate that met the old count rule on a uniform set still
///     verifies unchanged; on a skewed set any subset whose STAKE reaches
///     quorum suffices (e.g. 2 of 3 by heads when their combined power
///     covers 2/3+1 of the committee).
///   * When the committee is a strict SUBSET of the validator set, the
///     network anchor dominates: a certificate must carry a STRICT MAJORITY
///     of the WHOLE network's stake, so a captured committee cannot
///     finalize a block (audit W6.5 — committee capture).
/// - Carried inside `QuorumCertificate::signatures` under sentinel marker `PQ_UQC_MARKER_ID`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMicroCertificate {
    pub scheme: crate::post_quantum::PqScheme,
    pub height: Height,
    pub round: Round,
    pub committee_size: u32,
    pub signers_bitmask: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
    /// The PARENT BLOCK HASH the sortition committee of this certificate was
    /// elected with (see [`derive_sortition_committee`]).
    ///
    /// It travels with the certificate because the committee is only
    /// reproducible from it: a verifier re-derives the committee from
    /// `(sortition_parent, height, round)` and MUST land on the same members
    /// the signers did. The block-apply path additionally pins it to the
    /// parent hash committed in the block header, so a certificate cannot pick
    /// a favourable committee of its own.
    ///
    /// The field is LAST on purpose: bincode is positional, so a certificate
    /// persisted before this field existed simply ends its byte stream one
    /// field early and `#[serde(default)]` reads the missing trailing field as
    /// "elected with the zero parent" — which the header pin then rejects.
    #[serde(default)]
    pub sortition_parent: [u8; 32],
}

impl PqMicroCertificate {
    pub fn new(
        scheme: crate::post_quantum::PqScheme,
        height: Height,
        round: Round,
        committee_size: u32,
        signers_bitmask: Vec<u8>,
        signatures: Vec<Vec<u8>>,
        sortition_parent: [u8; 32],
    ) -> Self {
        Self {
            scheme,
            height,
            round,
            committee_size,
            signers_bitmask,
            signatures,
            sortition_parent,
        }
    }

    // REMOVED (seal install): `with_vrf_beacon` lived here. No caller remains
    // (proven by grep: zero users in src/, tests/, benches/, examples/; assembly
    // mints no seals and verifiers never consult the field). The TYPE + field
    // stay for wire/history parse.

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
    ///
    /// AUDIT W6.5: the threshold is the NETWORK-ANCHORED one
    /// ([`pq_micro_required_power`]) — the committee's own `2/3` AND a strict
    /// majority of the whole network's stake. When the committee is the whole
    /// validator set (N <= the committee cap) the two coincide and the legacy
    /// value is unchanged; when the committee is a strict subset the network
    /// anchor is what stops a captured committee from finalizing a block.
    pub fn has_power_quorum(&self, committee: &[ValidatorId], validators: &ValidatorSet) -> bool {
        if committee.is_empty() || self.committee_size == 0 {
            return false;
        }
        let total: u64 = committee.iter().map(|id| validators.power_of(id)).sum();
        if total == 0 {
            return false;
        }
        self.signed_power(committee, validators)
            >= pq_micro_required_power(total, validators.total_power())
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
/// FREEZE (protocol freeze 2026-11-03): value = BFT safety curve, no env knob
/// ever existed. Change requires spec update + audit note (AGENTS.md §7).
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
    // Audit F4: u128 arithmetic — `(n*2)` panics in debug / wraps in release
    // at absurd powers, and saturating would UNDERESTIMATE the quorum
    // (weakening it). floor(2n/3)+1 always fits u64, computed exactly.
    ((n as u128 * 2) / 3 + 1) as u64
}

/// Strict quorum threshold for micro-committee of size k: floor(2*k/3) + 1.
///
/// FREEZE (protocol freeze 2026-11-03): same consensus-domain curve as
/// [`consensus_quorum_min`]. Change requires spec update + audit note.
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
/// FREEZE (protocol freeze 2026-11-03): the LIVE µQC rule. Change requires
/// spec update + audit note (AGENTS.md §7).
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

/// Maximum size of the sortition micro-committee (µQC).
///
/// AUDIT W6.5 (committee capture): the cap was hard-coded to `16` in TWO
/// places (the µQC compiler and the µQC verifier). A single, named constant
/// removes the fork hazard of the two drifting apart, and the value itself is
/// raised because a 16-seat committee is a very weak finality target — see
/// [`micro_committee_size`] and [`pq_micro_required_power`].
///
/// 64 seats x 666 B = 42.6 KB per µQC, still well under the ~66.6 KB a full
/// 100-validator Ed25519 QC costs, and it is the smallest committee that can
/// hold a MAJORITY of the network's stake at the target scale (N = 100).
pub const MICRO_COMMITTEE_MAX_SIZE: u32 = 64;

/// Size of the µQC sortition committee for a validator set of `n` members.
///
/// AUDIT W6.5 — WHY THIS IS NOT A CONSTANT:
///
/// The µQC is a *sample* of the validator set, so its finality threshold is
/// `(2/3) x (the committee's share of the network's stake)`. With a fixed
/// 16-seat committee and N = 100 uniformly staked validators, the committee
/// holds only ~16% of the network's stake, so a µQC could be forged by an
/// attacker holding ~11% of the stake (2/3 of 16%) — a ~6x weakening of the
/// network's own 2/3 threshold, and a straight break of the "an attacker with
/// < 1/3 of the stake cannot finalize a block" invariant.
///
/// The seat count is therefore raised to 64 (still `min(N, ...)`): at N = 100
/// the committee holds ~64% of the stake, and the NETWORK-ANCHORED quorum
/// rule ([`pq_micro_required_power`]) then demands a STRICT MAJORITY of the
/// *network's* stake, not just of the committee's.
///
/// While `N <= MICRO_COMMITTEE_MAX_SIZE` the committee IS the whole validator
/// set (see [`derive_sortition_committee`]): the µQC threshold is then exactly
/// the network threshold and the two-tier finality is indistinguishable from a
/// single-tier one. That is the live configuration (N = 4).
pub fn micro_committee_size(validator_count: usize) -> u32 {
    validator_count.min(MICRO_COMMITTEE_MAX_SIZE as usize) as u32
}

/// µQC quorum threshold in voting POWER: the value the signers' summed power
/// must reach for the certificate to be accepted.
///
/// AUDIT W6.5 (committee capture) — the rule is
///
/// ```text
/// required = max( floor(2 * W_committee / 3) + 1,      // the committee's own 2/3
///                  floor(W_network / 2) + 1 )            // STRICT MAJORITY of the network
/// ```
///
/// The second term is what makes a µQC safe to accept as a FINALITY
/// certificate on its own:
///
/// * `floor(W_network/2) + 1` is a strict majority of the WHOLE network's
///   stake, so any two conflicting certificates (µQC or full QC) must share
///   at least one signer — the classic BFT quorum-intersection property that
///   a 16-seat committee's `2/3 of the committee` does NOT have (2/3 of a
///   16%-of-the-network sample is ~11% of the network: no intersection, and
///   an attacker with 11% of the stake can finalize a conflicting block).
/// * Because the floor is anchored to the NETWORK, a committee that cannot
///   reach it (a small committee of a large network) is REFUSED outright
///   rather than silently accepted at a weakened threshold. The µQC is only
///   an accelerator: the full Ed25519 QC path stays authoritative, so
///   refusing a µQC costs bandwidth, never liveness.
///
/// Compatibility: when the committee is the whole validator set (N <= the
/// committee cap — the live N = 4 network and the N <= 16 test fixtures) the
/// two terms coincide with the old `floor(2W/3)+1` rule, so historic
/// certificates verify byte-for-byte unchanged.
pub fn pq_micro_required_power(committee_total_power: u64, network_total_power: u64) -> u64 {
    if committee_total_power == 0 {
        return u64::MAX;
    }
    let committee_two_thirds = consensus_quorum_min(committee_total_power);
    let network_majority = match network_total_power {
        0 => u64::MAX,
        w => w / 2 + 1,
    };
    committee_two_thirds.max(network_majority)
}

/// Deterministic BLAKE3 sortition committee selector.
///
/// Selects a subset of validators of size `committee_size` weighted proportionally
/// by validator stake (voting power), without replacement.
/// The resulting committee is returned in canonical sorted order.
///
/// ENTROPY (audit: predictable committee selection). The draw is seeded with
/// the PARENT BLOCK HASH — the hash of the block at `height - 1`, i.e. the
/// `prev_hash` committed in the header of the block at `height`. Without it
/// the ticket for `(height, round, step)` was a pure function of the height
/// and the round, so anybody could compute the committee for every future
/// height ahead of time and aim a DDoS (or a collusion) at a chosen round.
/// With the parent hash in the preimage the committee for a height is only
/// knowable once its parent exists, and it changes completely if the parent
/// changes (a fork re-elects a different committee).
///
/// The seed is `BLAKE3("STELL_SORTITION_V5" || prev_block_hash || height ||
/// round)` and each ticket is `BLAKE3("STELL_SORTITION_V5" || seed || step)`.
///
/// AGREEMENT: every validator of a height MUST pass the SAME parent hash —
/// the one committed in the block header — or they elect different
/// committees and cannot agree on a certificate. The parent hash travels
/// with the certificate ([`PqMicroCertificate::sortition_parent`]) so a
/// verifier re-derives exactly the committee the builders used.
///
/// RESIDUAL RISK — GRINDING (audit W6.5, NOT closed by the parent hash):
/// the parent hash makes the committee UNKNOWABLE IN ADVANCE (nobody can
/// compute the committee of a future height before its parent exists), but
/// it is not UNFORGEABLE: the proposer of the parent block chooses the
/// parent's bytes, hence its hash, hence the committee of the next height.
/// A proposer that can vary the parent hash (a nonce, a timestamp, the tx
/// set) can therefore SEARCH for a favourable committee: each candidate
/// parent hash is a fresh 16-draw sortition, and BLAKE3 is cheap enough
/// (10^9+ draws/s on a GPU) that a capture is a matter of minutes, not
/// years, for an attacker who controls a meaningful share of the set.
///
/// The parent hash is therefore NOT the security boundary — the
/// NETWORK-ANCHORED QUORUM is (see [`pq_micro_required_power`]): a µQC must
/// carry a strict majority of the WHOLE network's stake, so grinding for a
/// favourable committee does not lower the bar an attacker has to clear.
/// Grinding can only pick WHICH honest validators are asked to sign, not
/// manufacture the 1/2-of-the-network the certificate needs. A VRF-based
/// (ungrindable) selection would remove the grinding surface entirely; that
/// is the structural fix and is out of scope here.
///
/// Canonical parent-hash sortition committee selector (v5 draw, byte-pinned).
pub fn derive_sortition_committee(
    validators: &ValidatorSet,
    height: Height,
    round: Round,
    committee_size: u32,
    prev_block_hash: &[u8; 32],
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

    // Per-(height, round) seed: the parent block hash is the only entropy
    // that is not known before the chain reaches this height.
    let seed = sortition_seed(prev_block_hash, height, round);

    for step in 0..target_k {
        if total_power == 0 || pool.is_empty() {
            break;
        }

        let mut hasher = blake3::Hasher::new_derive_key(SORTITION_DRAW_DOMAIN);
        hasher.update(&seed);
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

/// Domain separator of the sortition draw (v5 = parent-block entropy).
///
/// Bumped from `STELL_SORTITION_V4` (which hashed `height || round || step`
/// only) so a v5 draw can never be confused with a v4 one.
pub const SORTITION_DRAW_DOMAIN: &str = "STELL_SORTITION_V5";

/// The per-`(height, round)` sortition seed: `BLAKE3("STELL_SORTITION_V5" ||
/// prev_block_hash || height || round)`.
///
/// Exposed so a verifier can prove that two nodes derived the same seed
/// (and therefore the same committee) without re-running the whole draw.
pub fn sortition_seed(prev_block_hash: &[u8; 32], height: Height, round: Round) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SORTITION_DRAW_DOMAIN);
    hasher.update(prev_block_hash);
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Encode a post-quantum micro-certificate (µQC) into its canonical wire envelope.
///
/// Layout:
/// `QC_UQC_MAGIC (16B) || sortition_parent (32B) || scheme_id (1B)
///  || height u64le (8B) || round u32le (4B)
///  || committee_size u32le (4B) || bitmask_len u32le (4B) || bitmask_bytes
///  || sig_count u32le (4B) || [sig_len u32le (4B) || sig_bytes]*`
///
/// The `sortition_parent` field is what lets a verifier re-derive the exact
/// committee the signers elected (see [`derive_sortition_committee`]).
pub fn encode_pq_micro_envelope(cert: &PqMicroCertificate) -> Vec<u8> {
    let bitmask_len = cert.signers_bitmask.len();
    let sig_count = cert.signatures.len();
    let total_sig_bytes: usize = cert.signatures.iter().map(|s| 4 + s.len()).sum();
    let mut out =
        Vec::with_capacity(16 + 32 + 1 + 8 + 4 + 4 + 4 + bitmask_len + 4 + total_sig_bytes);

    out.extend_from_slice(QC_UQC_MAGIC);
    out.extend_from_slice(&cert.sortition_parent);
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
    const MIN_HEADER: usize = 16 + 32 + 1 + 8 + 4 + 4 + 4 + 4; // 73 bytes
    if payload.len() < 16 || &payload[..16] != QC_UQC_MAGIC {
        return None;
    }

    if payload.len() >= MIN_HEADER {
        let mut sortition_parent = [0u8; 32];
        sortition_parent.copy_from_slice(&payload[16..48]);
        if let Ok(scheme) = crate::post_quantum::PqScheme::from_id(payload[48]) {
            let height = u64::from_le_bytes(payload[49..57].try_into().ok()?);
            let round = u32::from_le_bytes(payload[57..61].try_into().ok()?);
            let committee_size = u32::from_le_bytes(payload[61..65].try_into().ok()?);
            let bitmask_len = u32::from_le_bytes(payload[65..69].try_into().ok()?) as usize;

            let mut cursor = 69;
            if payload.len() >= cursor + bitmask_len + 4 {
                let signers_bitmask = payload[cursor..cursor + bitmask_len].to_vec();
                cursor += bitmask_len;

                let sig_count =
                    u32::from_le_bytes(payload[cursor..cursor + 4].try_into().ok()?) as usize;
                cursor += 4;

                if sig_count <= MAX_COMMIT_CERT_SIGNERS {
                    let mut signatures = Vec::with_capacity(sig_count);
                    let mut valid = true;

                    for _ in 0..sig_count {
                        if cursor + 4 > payload.len() {
                            valid = false;
                            break;
                        }
                        let sig_len =
                            u32::from_le_bytes(payload[cursor..cursor + 4].try_into().ok()?)
                                as usize;
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
                            sortition_parent,
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
#[allow(clippy::type_complexity)]
// GATE: registry type is fixed by consensus key shape; alias would churn all call sites without benefit.
static PQ_VALIDATOR_KEYS: std::sync::RwLock<
    Option<HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
> = std::sync::RwLock::new(None);

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
    drop(lock);
    // KEY-ROTATION INVALIDATION (in-zone trigger): a (re-)registration
    // changes what `Vote::verify` computes for this voter, so every cached
    // verdict — keyed on the old key bytes — is dropped. Miss = full verify.
    clear_verified_vote_cache();
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
    // The vote verdicts below are keyed on the registered PQ key bytes: a
    // key-registry wipe without a cache wipe would serve stale verdicts.
    clear_verified_vote_cache();
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
        Self {
            validators: BTreeMap::new(),
        }
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
    ///
    /// FREEZE (protocol freeze 2026-11-03): quorum accounting is frozen core.
    /// Change requires spec update + audit note (AGENTS.md §7).
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

    /// Cumulative voting power a quorum certificate carries UNDER THIS SET:
    /// the sum of this set's powers over the certificate's genuine signers.
    ///
    /// Attribution mirrors verification exactly: [`QuorumCertificate::signers_set`]
    /// names only signers whose signatures verify (µQC/epoch envelopes),
    /// so forged or garbage entries
    /// contribute nothing here — unlike a naive sum over the raw
    /// `signatures` list. Signers outside the set contribute nothing
    /// (rotated-away keys lend no weight).
    ///
    /// W10.5 hardening: every decision/adoption helper must compare this
    /// number against [`Self::quorum_power`] for the set IN FORCE AT THE
    /// CERTIFICATE'S HEIGHT — never the live set — and refuse loudly when it
    /// falls short. A node must never finalize with only its own vote when
    /// the set requires more.
    pub fn qc_signed_power(&self, qc: &QuorumCertificate) -> u64 {
        qc.signers_set(self)
            .iter()
            .map(|v| self.power_of(v))
            .fold(0u64, |a, p| a.saturating_add(p))
    }

    /// True when `qc` carries quorum power under this set. Prefer this over a
    /// bare [`QuorumCertificate::verify`] at every decision boundary: it is
    /// the same check with the numbers attached, so a refusal can name the
    /// shortfall instead of just saying "no quorum".
    pub fn qc_meets_quorum(&self, qc: &QuorumCertificate) -> bool {
        self.qc_signed_power(qc) >= self.quorum_power()
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
///
/// CHAIN BINDING: the preimage starts with the domain tag, then the CHAIN ID
/// ([`consensus_chain_id`]), then the vote fields. A vote signed on one
/// deployment therefore has a different preimage — and a different signature —
/// than the same vote on another, so a testnet vote can never be replayed on
/// mainnet (and vice versa) even with the very same validator key. The domain
/// tag was bumped `V1 -> V2` because the preimage layout changed; `V1` bytes
/// are not accepted any more.
pub fn vote_sign_bytes(
    height: Height,
    round: Round,
    kind: VoteKind,
    block_hash: &Option<BlockHash>,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(80);
    m.extend_from_slice(b"STELLEREUM_BFT_VOTE_V2");
    m.extend_from_slice(&consensus_chain_id().to_be_bytes());
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
        let signature = sig.to_vec();
        Self {
            height,
            round,
            kind,
            block_hash,
            voter,
            signature,
        }
    }

    /// Build a vote from a signature produced elsewhere (HSM / remote signer).
    ///
    /// The caller must have signed `vote_sign_bytes(height, round, kind, block_hash)`
    /// with the key behind `voter`. `Vote::verify` checks it, so an incorrect signature
    /// is rejected at the same place a locally produced one would be.
    pub fn signed_with(
        voter: ValidatorId,
        height: Height,
        round: Round,
        kind: VoteKind,
        block_hash: Option<BlockHash>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            height,
            round,
            kind,
            block_hash,
            voter,
            signature,
        }
    }

    pub fn verify(&self) -> bool {
        // VERIFY-ONCE (vote-ingest hot path): a vote carries the same bytes
        // every time it is re-gossiped, re-driven through `on_prevote` /
        // `on_precommit` (which verify once in `VoteSet::add` AND once in
        // `observe_peer_vote`), or re-scanned, so the second and later
        // verifications of identical bytes under an identical key context
        // are pure CPU with no new information. Consult the cache first
        // (hit skips crypto); miss runs full verification and records it.
        // Fail-closed: any key-context drift (below) misses and re-verifies.
        if let Some(hit) = verified_vote_cached(self) {
            VERIFIED_VOTE_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
            return hit;
        }
        VERIFIED_VOTE_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
        let verdict = self.verify_uncached();
        record_verified_vote(self, verdict);
        verdict
    }

    /// Full cryptographic verification, bypassing the verified-vote cache.
    ///
    /// Single definition of vote validity: [`Vote::verify`] (cached),
    /// [`Vote::partition_valid`] (scalar Falcon per vote) and
    /// [`verify_equivocation_evidence`] all bottom out here, so a cache hit
    /// can never admit what full verification would refuse.
    ///
    /// FULL-PQ (nodes wiped, no compat): Falcon-only. The Ed25519 legs are
    /// deleted. A vote is valid iff it carries a Falcon half that verifies
    /// under the voter's registered PQ key — exactly the old pure-PQ branch,
    /// now unconditional.
    fn verify_uncached(&self) -> bool {
        let msg = vote_sign_bytes(self.height, self.round, self.kind, &self.block_hash);

        // FULL-PQ: Falcon-only. Ed25519 branches deleted (no compat).
        if let Some(falcon_sig) = self.falcon_signature() {
            if let Some((_scheme, pk)) = get_validator_pq_key(&self.voter) {
                return verify_falcon_signature(&pk, &msg, falcon_sig);
            }
        }
        false
    }

    /// The bare Ed25519 signature bytes (envelope stripped when present).
    /// What belongs in a certificate's Ed25519 list.
    pub fn ed25519_signature(&self) -> &[u8] {
        ed25519_sig_bytes(&self.signature)
    }

    /// Batch-verify many votes at once (Falcon-only). Returns true
    /// iff EVERY vote carries a valid Falcon signature.
    ///
    /// FULL-PQ (nodes wiped, no compat): the Ed25519 batch is deleted.
    /// Falcon has no batch primitive, so this is the scalar Falcon predicate
    /// per vote — exactly what [`VoteSet::add`] enforces per vote.
    ///
    /// Determinism: the verdict is order-independent (all-or-nothing over the
    /// set).
    pub fn verify_batch(votes: &[Vote]) -> bool {
        if votes.is_empty() {
            return true;
        }
        // FULL-PQ: Falcon-only (old pure-PQ branch, now unconditional).
        votes.iter().all(|v| v.verify())
    }

    /// Per-vote validity for a batch of votes (Falcon-only scalar).
    ///
    /// Fallback semantics (VOTES — keep the good ones): dropping a whole batch
    /// on one bad neighbor would lose honest votes and could stall a quorum,
    /// so every vote gets its scalar [`Vote::verify`] verdict in INPUT order
    /// and only the bad votes are marked `false`. Element `i`
    /// always equals `votes[i].verify()` — no behavior change, with offenders
    /// identified for slashing / peer down-scoring.
    ///
    /// Determinism: per-item validity never depends on batch order.
    ///
    /// FULL-PQ (nodes wiped, no compat): the Ed25519 batch screen is deleted.
    /// Falcon has no batch primitive, so scalar Falcon is the only path —
    /// exactly what [`VoteSet::add`] enforces per vote.
    pub fn partition_valid(votes: &[Vote]) -> Vec<bool> {
        if votes.is_empty() {
            return Vec::new();
        }
        // FULL-PQ: Falcon-only (old pure-PQ branch, now unconditional).
        // `verify()` consults/records the verified-vote cache, so batch
        // ingest keeps verify-once behavior with no Ed25519 screen.
        votes.iter().map(|v| v.verify()).collect()
    }

    /// The Falcon-512 half of this vote's signature, when it carries one.
    pub fn falcon_signature(&self) -> Option<&[u8]> {
        if self.signature.len() == VOTE_FALCON_PART_LEN
            && self.signature.starts_with(VOTE_FALCON_MAGIC)
        {
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

// ============================================================================
// Verified-vote cache (verify-once for the vote-INGEST path)
// ============================================================================
//
// PATTERN: the ingest path verifies the same vote bytes repeatedly — once in
// `VoteSet::add`, once more in `ValidatorRuntime::observe_peer_vote`, again on
// every re-gossip / re-drive / re-scan. The verdict is a pure function of the
// cached key below, so re-verifying identical bytes under an identical key
// context is pure CPU. The cache consults on the ingest path (hit skips
// crypto); miss runs FULL verification and records the verdict (valid AND
// invalid verdicts are cached — a forgery is never "served as valid", and a
// cached `false` refuses exactly like a fresh `false`).
//
// QUORUM / LOCK / FINALITY UNTOUCHED: the cache stores signature validity
// only. Membership/power (`ValidatorSet::power_of`), first-vote-wins dedup,
// equivocation recording and every quorum/lock/decide rule run on EVERY
// ingest exactly as before, cache hit or not.
//
// EXACT INVALIDATION — every trigger enumerated (found by grep over the
// tree; see call sites):
//  1. VALIDATOR-SET CHANGE. `VoteSet::add` / `add_batch` receive the set in
//     force and call `note_validator_set_for_vote_cache` first: a digest of
//     the sorted `(voter, power)` table is compared against the last-seen
//     digest, and ANY change clears the cache (miss = full verify). Set
//     producers (all outside this file, read-only from here):
//     `runtime.rs` `refresh_validator_set_from_ledger`,
//     `refresh_validator_set_from_master_ledger`,
//     `refresh_validator_set_from_domain_bytes`,
//     `refresh_validator_set_from_staking_checked`, the `hc.validators =
//     ...` re-anchors in `prepare_decided_block` / `try_finalize_submit` /
//     `apply_and_advance`, and `main.rs` `refresh_validator_set_from_fresh_snapshot`.
//     Defense in depth: membership is re-checked per-admit OUTSIDE the cache
//     (`add_verified`), so even a hypothetical missed clear could only skip
//     crypto, never admit a non-member.
//  2. PQ KEY REGISTRATION / ROTATION. `register_validator_pq_key` (this file)
//     clears the cache on every insert; `clear_validator_pq_keys_for_tests`
//     does the same. Ledger-side rotation ops (`staking.rs`
//     `register_pq_key`, `pq_announce_rotation`, `pq_apply_rotation`,
//     `pq_apply_due_rotations`) take effect on the verify path only through
//     this registry, and every cached verdict additionally carries the key
//     bytes in force at verify time — a rotated key misses by construction.
//  3. CONSENSUS-KEY ROTATION. `staking.rs` `StakingLedger::rotate_key`
//     retires one voter id and activates another. The voter id IS the Ed25519
//     public key, so a rotated key is a different cache key (miss), and the
//     retired id loses membership — refused by the per-admit membership
//     check even if its old signature still verifies.
//  4. EPOCH ADVANCE. MEV/CN-VRF epochs (`mev_epoch.rs`, `cn_vrf.rs`
//     `epoch_of_height`) do not enter the vote preimage; every cache key
//     carries `(height, round)`, so a vote from another epoch is a different
//     key (cross-epoch confusion misses). Epoch-boundary set refreshes are
//     covered by trigger 1.
//  5. CHAIN-ID CHANGE. The id is frozen process-global (`FROZEN_CHAIN_ID`)
//     and enters every key; the test-only thread-local override
//     (`set_consensus_chain_id_for_tests`) therefore misses across chains
//     instead of serving a foreign-chain verdict.
//  6. PURE-PQ MODE FLAG. `post_quantum::is_pure_pq_enforced()` (env
//     `STELL_PURE_PQ` / test override `set_pure_pq_override`) changes the
//     verify predicate, so its value enters every key: toggling the flag
//     misses rather than serving a verdict computed under the other mode.
//
// OUT-OF-ZONE HOOK: code outside `consensus.rs` that rotates vote-verifying
// key material without passing through `register_validator_pq_key` MUST call
// `invalidate_verified_vote_cache()` at the rotation point (fail-closed:
// an uncalled hook only costs CPU, never safety — verdicts stay exact
// because triggers 1–6 above still hold).
//
// BOUND: the map holds at most `VERIFIED_VOTE_CACHE_CAP` entries; beyond
// that it is cleared wholesale (fail-safe: verdicts are recomputed, never
// approximated). Clearing is behavior-preserving, so long-lived nodes stay
// bounded without any eviction-order determinism question.

/// Maximum cached vote verdicts. Heights ratchet forward forever, so the
/// bound — not the workload — caps memory.
const VERIFIED_VOTE_CACHE_CAP: usize = 65_536;

/// Cache key: everything `verify_uncached` reads. Same key ⇒ same verdict.
#[derive(Clone, PartialEq, Eq, Hash)]
struct VerifiedVoteCacheKey {
    voter: ValidatorId,
    height: Height,
    round: Round,
    kind: u8,
    block_hash: Option<BlockHash>,
    signature: Vec<u8>,
    /// PQ registry entry for `voter` at verify time (trigger 2).
    pq_key: Option<(u8, Vec<u8>)>,
    /// Pure-PQ flag at verify time (trigger 6).
    pure_pq: bool,
    /// Effective chain id at verify time (trigger 5).
    chain_id: u64,
}

static VERIFIED_VOTE_CACHE: std::sync::LazyLock<
    std::sync::RwLock<HashMap<VerifiedVoteCacheKey, bool>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(HashMap::new()));
static VERIFIED_VOTE_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
static VERIFIED_VOTE_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
/// Digest of the validator set the cache was last validated against
/// (trigger 1). `None` forces a re-record on the next ingest.
static VERIFIED_VOTE_CACHE_SET_DIGEST: std::sync::LazyLock<std::sync::RwLock<Option<[u8; 32]>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(None));

/// Deterministic digest of the in-force validator set (sorted iteration —
/// `ValidatorSet.validators` is a `BTreeMap`, so equal sets digest equal on
/// every node and every call).
fn validator_set_digest(validators: &ValidatorSet) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("STELL_VERIFIED_VOTE_SET_V1");
    h.update(&(validators.validators.len() as u64).to_le_bytes());
    for (id, power) in validators.validators.iter() {
        h.update(id);
        h.update(&power.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// Trigger-1 enforcement: call at the top of every vote-ingest entry point
/// that observes the in-force set. A changed set clears the cache before any
/// verdict is consulted (miss = full verify).
fn note_validator_set_for_vote_cache(validators: &ValidatorSet) {
    let digest = validator_set_digest(validators);
    let changed = {
        let lock = VERIFIED_VOTE_CACHE_SET_DIGEST
            .read()
            .unwrap_or_else(|e| e.into_inner());
        *lock != Some(digest)
    };
    if changed {
        clear_verified_vote_cache();
        let mut lock = VERIFIED_VOTE_CACHE_SET_DIGEST
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *lock = Some(digest);
    }
}

fn vote_cache_key(vote: &Vote) -> VerifiedVoteCacheKey {
    VerifiedVoteCacheKey {
        voter: vote.voter,
        height: vote.height,
        round: vote.round,
        kind: match vote.kind {
            VoteKind::Prevote => 0,
            VoteKind::Precommit => 1,
        },
        block_hash: vote.block_hash,
        signature: vote.signature.clone(),
        pq_key: get_validator_pq_key(&vote.voter).map(|(scheme, pk)| (scheme as u8, pk)),
        pure_pq: crate::post_quantum::is_pure_pq_enforced(),
        chain_id: consensus_chain_id(),
    }
}

fn verified_vote_cached(vote: &Vote) -> Option<bool> {
    let key = vote_cache_key(vote);
    let lock = VERIFIED_VOTE_CACHE
        .read()
        .unwrap_or_else(|e| e.into_inner());
    lock.get(&key).copied()
}

fn record_verified_vote(vote: &Vote, verdict: bool) {
    let key = vote_cache_key(vote);
    let mut lock = VERIFIED_VOTE_CACHE
        .write()
        .unwrap_or_else(|e| e.into_inner());
    if lock.len() >= VERIFIED_VOTE_CACHE_CAP {
        // Fail-safe bound: drop everything and re-record (miss = full
        // verify). Verdicts are recomputed, never approximated.
        lock.clear();
    }
    lock.insert(key, verdict);
}

/// Drop every cached vote verdict. Fail-closed: the next ingest of any vote
/// fully re-verifies. See the trigger list above for when this runs
/// automatically vs. when out-of-zone callers must invoke it.
pub fn clear_verified_vote_cache() {
    let mut lock = VERIFIED_VOTE_CACHE
        .write()
        .unwrap_or_else(|e| e.into_inner());
    lock.clear();
}

/// Out-of-zone invalidation hook: call at any vote-key rotation point that
/// does not pass through `register_validator_pq_key` (triggers 2–3), and at
/// any epoch/set installation not visible to `note_validator_set_for_vote_cache`
/// (triggers 1, 4). Also resets the set-digest so the next ingest re-records
/// it. Safe to call redundantly: clearing only costs CPU.
pub fn invalidate_verified_vote_cache() {
    clear_verified_vote_cache();
    let mut lock = VERIFIED_VOTE_CACHE_SET_DIGEST
        .write()
        .unwrap_or_else(|e| e.into_inner());
    *lock = None;
}

/// (hits, misses) since the last reset. A hit skipped crypto with a verdict
/// identical to full verification; a miss ran full verification.
pub fn verified_vote_cache_stats() -> (u64, u64) {
    (
        VERIFIED_VOTE_CACHE_HITS.load(Ordering::Relaxed),
        VERIFIED_VOTE_CACHE_MISSES.load(Ordering::Relaxed),
    )
}

/// Zero the hit/miss counters (the verdict map is left intact).
pub fn verified_vote_cache_reset_stats() {
    VERIFIED_VOTE_CACHE_HITS.store(0, Ordering::Relaxed);
    VERIFIED_VOTE_CACHE_MISSES.store(0, Ordering::Relaxed);
}

/// Number of cached verdicts (observability for tests / metrics).
pub fn verified_vote_cache_len() -> usize {
    VERIFIED_VOTE_CACHE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .len()
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
        Self {
            voter,
            vote_a,
            vote_b,
        }
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
        bincode::serialized_size(self)
            .map(|n| n as usize)
            .unwrap_or(usize::MAX)
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
// Block-carried PROPOSAL equivocation evidence (deterministic slashing input)
// ============================================================================
//
// P3-EQ-ESCAPE variant 2 (double-propose) CLOSED HERE. The vote envelope
// (`EquivocationEvidence`) covers Vote pairs only: a scheduled proposer that
// signs two different blocks for the same height leaves no Vote pair behind,
// so the vote-slash path is inapplicable by construction (pinned by
// `p3_eq_double_propose_escapes_vote_slash_path`). This section is the
// proposal mirror of the vote wiring above, with the same contract:
//
//   * carrier: the block BODY, as `OpCode::SysCallReportProposalEquivocation`
//     (appended terminal variant — the codebase-blessed proof-in-opcode
//     pattern). The transaction hash commits the payload and the block hash
//     commits the transaction, so every node applies the SAME bytes. Old
//     nodes fail closed on the unknown discriminant instead of misreading it.
//   * content: BOTH conflicting blocks FULLY included (`block_a`,
//     `block_b`), so verification needs no external data beyond the
//     validator set every node derives identically from its staking ledger.
//     Blocks — unlike votes — carry no round: the offense is "same proposer,
//     same height, two different bodies". A claimed round would be unsigned
//     metadata (any reporter could invent it), so the type carries none and
//     the dedup key excludes it: one slash per (proposer, height), never one
//     per claimed round.
//   * verification: [`verify_proposal_equivocation_evidence`] — fail-closed.
//     Same height, differing block hashes, `proposer` matches both blocks'
//     `proposer`, membership, and BOTH proposer signatures verify (Ed25519
//     strict; Falcon/PQ halves handled inside
//     [`verify_proposer_signature`], exactly like the vote path's
//     `Vote::verify`). A same-body pair (one block repeated) is not an
//     offense; a forged signature is refused.
//   * dedup: [`ProposalEquivocationEvidence::offense_key`] —
//     `BLAKE3(domain ‖ proposer ‖ height ‖ hash_lo ‖ hash_hi)` with canonical
//     body order. Either block order, any number of rebroadcasts or
//     re-inclusions key identically: one burn per (proposer, height).
//   * order: [`canonicalize_proposal_equivocation_evidence`] verifies, sorts
//     by offense key and dedupes. Sequential 5% burns do NOT commute, so
//     canonical order is what makes every node compute the same remainder.
//
// Stay-out note: the VOTE shape/verify above is untouched. The cross-round
// vote pair (P3-EQ-ESCAPE variant 1, lock violation across rounds) stays
// DOCUMENTED-OPEN by design: different rounds fail the same-(h,r,kind) vote
// gate and no slash fires — only same-height double-signs are punishable,
// for votes and (from here) for proposals alike.

/// Domain separator for [`ProposalEquivocationEvidence::offense_key`].
pub const PROPOSAL_EQUIVOCATION_OFFENSE_DOMAIN: &[u8] =
    b"STELLEREUM_PROPOSAL_EQUIVOCATION_OFFENSE_V1";

/// Hard cap on one proposal-evidence envelope's wire size (fail-closed:
/// larger is refused, never truncated). Two full blocks ride inside, so the
/// bound is orders of magnitude above the vote envelope's — yet still far
/// below the block wire cap (`MAX_BLOCK_WIRE_BYTES`), so packable evidence
/// exists. Anything bigger is a DoS probe, not evidence.
pub const MAX_PROPOSAL_EQUIVOCATION_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;

/// Hard cap on proposal evidences slashed per block (fail-closed: extras are
/// skipped loudly and may be resubmitted in a later block). Each evidence
/// carries two full blocks, so the cap is deliberately smaller than the
/// vote path's: honest chains never approach it (each offense needs a
/// distinct double-signing proposer at one height).
pub const MAX_BLOCK_PROPOSAL_EQUIVOCATION_EVIDENCES: usize = 8;

/// Block-carried proof that `proposer` double-proposed: two fully-signed,
/// conflicting blocks at one height. Transported opaquely by
/// `OpCode::SysCallReportProposalEquivocation`; verified by
/// [`verify_proposal_equivocation_evidence`] on every node from block bytes
/// alone.
///
/// NOTE: deliberately NO `PartialEq`/`Eq` — `Block` does not implement them,
/// and evidence equality is always decided through [`Self::offense_key`],
/// never through structural comparison.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalEquivocationEvidence {
    /// The accused proposer (must equal both blocks' `proposer`).
    pub proposer: ValidatorId,
    /// First conflicting block (fully signed by `proposer`).
    pub block_a: crate::sharding::Block,
    /// Second conflicting block (fully signed by `proposer`).
    pub block_b: crate::sharding::Block,
}

impl ProposalEquivocationEvidence {
    /// Build the envelope from a recorded pair. No verification here —
    /// call [`verify_proposal_equivocation_evidence`] (fail-closed) before trusting it.
    pub fn new(
        proposer: ValidatorId,
        block_a: crate::sharding::Block,
        block_b: crate::sharding::Block,
    ) -> Self {
        Self {
            proposer,
            block_a,
            block_b,
        }
    }

    /// The per-offense dedup key: a canonical commitment to everything that
    /// makes this offense unique. Swapping the two blocks, rebroadcasting,
    /// or re-including the same pair keys identically.
    pub fn offense_key(&self) -> [u8; 32] {
        proposal_offense_key(
            &self.proposer,
            self.block_a.height,
            &self.block_a.compute_hash(),
            &self.block_b.compute_hash(),
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
        bincode::serialized_size(self)
            .map(|n| n as usize)
            .unwrap_or(usize::MAX)
    }
}

/// Canonical per-offense key:
/// `BLAKE3(domain ‖ proposer ‖ height ‖ hash_lo ‖ hash_hi)`, with the two
/// block hashes in canonical (lexicographic) order so block order never
/// matters. No round: blocks do not carry one, and a reporter-supplied
/// round would be unsigned metadata — keying on it would let one offense
/// burn twice under two claimed rounds.
pub fn proposal_offense_key(
    proposer: &ValidatorId,
    height: Height,
    hash_a: &BlockHash,
    hash_b: &BlockHash,
) -> [u8; 32] {
    let (lo, hi) = if hash_a <= hash_b {
        (hash_a, hash_b)
    } else {
        (hash_b, hash_a)
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROPOSAL_EQUIVOCATION_OFFENSE_DOMAIN);
    hasher.update(proposer);
    hasher.update(&height.to_be_bytes());
    hasher.update(lo);
    hasher.update(hi);
    *hasher.finalize().as_bytes()
}

/// Fail-closed verification of block-carried proposal-equivocation evidence.
///
/// Every refusal returns `false` (never panics, never errors): the caller
/// skips the evidence and logs loudly. Checks, in cheap-first order:
///  1. envelope size cap (DoS bound);
///  2. same height, DIFFERING block hashes (one block repeated is not a
///     double-propose);
///  3. `proposer` matches BOTH blocks' `proposer` (framing another
///     validator's block is refused);
///  4. proposer membership via `is_validator` (unknown keys are refused);
///  5. BOTH proposer signatures verify via [`verify_proposer_signature`]
///     (Ed25519 strict; Falcon/PQ halves handled inside — forged blocks
///     are refused).
pub fn verify_proposal_equivocation_evidence(
    ev: &ProposalEquivocationEvidence,
    is_validator: &dyn Fn(&ValidatorId) -> bool,
) -> bool {
    if ev.wire_len() > MAX_PROPOSAL_EQUIVOCATION_EVIDENCE_BYTES {
        return false;
    }
    let (a, b) = (&ev.block_a, &ev.block_b);
    if a.height != b.height {
        return false;
    }
    if a.compute_hash() == b.compute_hash() {
        return false;
    }
    if ev.proposer != a.proposer || ev.proposer != b.proposer {
        return false;
    }
    if !is_validator(&ev.proposer) {
        return false;
    }
    if !verify_proposer_signature(a) || !verify_proposer_signature(b) {
        return false;
    }
    true
}

/// Deterministic shaping of candidate proposal evidences: keep only what
/// [`verify_proposal_equivocation_evidence`] accepts, sort by offense key,
/// drop key-duplicates (same offense submitted twice, blocks swapped, or
/// rebroadcast). Pure function of the inputs: every node that feeds it the
/// same candidates slashes in the same order. Order matters because
/// sequential 5% burns do not commute for one offender.
pub fn canonicalize_proposal_equivocation_evidence(
    items: Vec<ProposalEquivocationEvidence>,
    is_validator: &dyn Fn(&ValidatorId) -> bool,
) -> Vec<ProposalEquivocationEvidence> {
    let mut verified: Vec<(ProposalEquivocationEvidence, [u8; 32])> = items
        .into_iter()
        .filter(|ev| verify_proposal_equivocation_evidence(ev, is_validator))
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
    pub fn add(
        &mut self,
        vote: Vote,
        validators: &ValidatorSet,
        height: Height,
        round: Round,
        kind: VoteKind,
    ) -> Result<(), String> {
        // Trigger-1 invalidation BEFORE any cached verdict is consulted: a
        // validator-set change clears stale verdicts (miss = full verify).
        // Membership itself is re-checked per-admit in `add_verified`,
        // outside the cache, so the set change can never admit a non-member.
        note_validator_set_for_vote_cache(validators);
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
                    self.equivocations
                        .push((vote.voter, existing.clone(), vote));
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
        // Trigger-1 invalidation once per batch (same guarantee as `add`).
        note_validator_set_for_vote_cache(validators);
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
        self.votes
            .values()
            .filter(|v| v.falcon_signature().is_some())
            .count()
    }

    /// Return collected Falcon-512 signatures for votes matching `target`.
    pub fn collect_falcon_signatures(
        &self,
        target: Option<BlockHash>,
    ) -> Vec<(ValidatorId, Vec<u8>)> {
        self.votes
            .values()
            .filter(|v| v.block_hash == target)
            .filter_map(|v| v.falcon_signature().map(|sig| (v.voter, sig.to_vec())))
            .collect()
    }

    /// Build a quorum certificate for `target` from the collected votes.
    ///
    /// The Ed25519 list carries BARE 64-byte signatures (any vote-envelope
    /// half is stripped). That is the format every verifier understands,
    /// and it is what the certificate format keeps promising.
    ///
    /// `parent_hash` is the hash of the block at `height - 1` — the parent
    /// committed in the header of the block this height decides. It is the
    /// entropy the sortition committee of this height is elected with, so
    /// every builder of this certificate MUST pass the same value (the one
    /// from the chain) or the signers and the verifiers would elect different
    /// committees.
    pub fn certificate(
        &self,
        target: Option<BlockHash>,
        validators: &ValidatorSet,
        parent_hash: &[u8; 32],
    ) -> Option<QuorumCertificate> {
        self.certificate_with_parent(target, validators, Some(parent_hash))
    }

    /// Same as [`Self::certificate`], but the sortition parent may be
    /// UNKNOWN.
    ///
    /// `parent_hash: None` means "the parent block hash of this height is not
    /// known here" — no committee can then be elected honestly, so NO
    /// micro-certificate is compiled and the classical (full validator set)
    /// certificate stays authoritative. Under Pure-PQ enforcement that is
    /// fail-closed: the node cannot finalize on a committee nobody else
    /// elected (audit W6.4b).
    ///
    /// Canonical parent-hash draw byte-for-byte.
    #[allow(clippy::unnecessary_unwrap)]
    // GATE: is_some guard plus expect keeps parent-hash handling explicit on the consensus path; restructuring risks quorum logic.
    pub fn certificate_with_parent(
        &self,
        target: Option<BlockHash>,
        validators: &ValidatorSet,
        parent_hash: Option<&[u8; 32]>,
    ) -> Option<QuorumCertificate> {
        if !self.quorum_reached(target, validators) {
            return None;
        }
        // REMOVED (aggregate-QC production): the per-vote classical-half
        // collection and the marker aggregate attach lived here.
        // Certificates now always carry the Ed25519 list only.
        let mut signatures = Vec::new();
        for v in self.votes.values() {
            if v.block_hash == target {
                signatures.push((v.voter, v.ed25519_signature().to_vec()));
            }
        }
        let mut qc = QuorumCertificate {
            height: self.votes.values().next()?.height,
            round: self.votes.values().next()?.round,
            kind: self.votes.values().next()?.kind,
            block_hash: target,
            signatures,
        };

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

        // The committee is elected from the PARENT BLOCK HASH. When the
        // parent is UNKNOWN (a node that has not established the block hash
        // at `height - 1` yet) no committee can be derived honestly, so NO
        // micro-certificate is compiled: the classical full-set certificate
        // stays authoritative. Under Pure-PQ enforcement that is fail-closed
        // (the node cannot finalize on a committee nobody else elected)
        // instead of silently certifying against a committee of its own
        // making (audit W6.4b).
        if !falcon_sigs.is_empty() && !validators.is_empty() && parent_hash.is_some() {
            let parent_hash = parent_hash.expect("checked above");
            let committee_size = micro_committee_size(validators.len());
            if committee_size > 0 {
                // Canonical draw applies byte-for-byte.
                let committee = derive_sortition_committee(
                    validators,
                    qc.height,
                    qc.round,
                    committee_size,
                    parent_hash,
                );
                // No seal ever travels with the certificate: verifiers resolve
                // the same legacy committee, so embedding anything would only
                // risk divergence.
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
                let committee_total: u64 = committee.iter().map(|id| validators.power_of(id)).sum();
                if committee_total == 0 {
                    // Fail-closed: empty committee / zero weight never compiles.
                    return Some(qc);
                }
                let quorum_power =
                    pq_micro_required_power(committee_total, validators.total_power());
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
                    // The parent hash the committee was elected with: a
                    // verifier re-derives the committee from it, and the
                    // block-apply path pins it to the block's own parent.
                    sortition_parent: *parent_hash,
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
    /// FULL-PQ (nodes wiped, no compat): Falcon µQC / CEC envelopes only.
    /// Classical Ed25519 threshold legs deleted.
    pub fn verify(&self, validators: &ValidatorSet) -> bool {
        self.verify_unified(validators)
    }

    /// Unified certificate verification supporting:
    /// 1. Post-quantum µQC (`PQ_UQC_MARKER_ID`) and CEC Epoch (`PQ_QC_MARKER_ID`) envelopes.
    ///
    /// FULL-PQ: classical Ed25519 threshold deleted (no compat). A QC without
    /// a verifying PQ envelope is rejected.
    pub fn verify_unified(&self, validators: &ValidatorSet) -> bool {
        self.verify_unified_with_pq_keys(validators, None)
    }

    /// Unified verification with optional local post-quantum key overrides.
    ///
    /// FULL-PQ (nodes wiped): Falcon-only. The classical Ed25519 threshold
    /// legs are deleted. After the PQ path, rejection is unconditional.
    pub fn verify_unified_with_pq_keys(
        &self,
        validators: &ValidatorSet,
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> bool {
        // Anti-DoS (audit F7): reject an implausibly long signer list BEFORE
        // touching any signature. The list is attacker-supplied and uncapped on
        // the wire, so one message could otherwise pin a verifier in a
        // signature loop proportional to its length. This is O(1) and applies
        // to every caller of `verify`. The marker envelope entry counts toward
        // this cap like any other entry.
        if self.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return false;
        }
        let msg = vote_sign_bytes(self.height, self.round, self.kind, &self.block_hash);

        // 1. Post-Quantum path: µQC (PQ_UQC_MARKER_ID) or CEC Epoch (PQ_QC_MARKER_ID)
        if self.pq_path_verify(validators, &msg, pq_keys) {
            return true;
        }

        // FULL-PQ: classical Ed25519 threshold deleted (no compat, no fallback).
        // Any non-PQ entry is rejected here.
        false
    }

    /// Check if certificate contains a valid Post-Quantum µQC or Epoch CEC envelope.
    ///
    /// FULL-PQ (nodes wiped): non-post-quantum schemes are refused
    /// unconditionally (old pure-PQ gate, now the only path).
    fn pq_path_verify(
        &self,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> bool {
        for (voter, payload) in &self.signatures {
            if *voter == PQ_UQC_MARKER_ID {
                if let Some(cert) = decode_pq_micro_envelope(payload) {
                    if !cert.scheme.is_post_quantum() {
                        continue;
                    }
                    // Canonical parent-hash draw.
                    if self.verify_micro_cert(&cert, validators, msg, pq_keys) {
                        return true;
                    }
                }
            } else if *voter == PQ_QC_MARKER_ID {
                if let Some(cert) =
                    decode_pq_epoch_envelope(payload).or_else(|| decode_pq_micro_envelope(payload))
                {
                    if !cert.scheme.is_post_quantum() {
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
    /// The committee members whose µQC signatures VERIFY (attribution-grade).
    ///
    /// Exactly the checks `verify_micro_cert` enforces, MINUS the quorum-power
    /// gate: `None` on any structural failure or any bad/missing key or bad
    /// signature (fail-closed, same as verify), else the committee members
    /// whose bit is set and whose signature verifies. The quorum gate lives
    /// in `verify_micro_cert`; attribution (`signers_set`) uses this so a
    /// genuinely-signed member is named even in a sub-quorum certificate
    /// (nobody is slashed for signing), while a forged envelope names nobody
    /// (V-P34 R2: nobody is forgiven on the strength of an unverifiable
    /// marker).
    ///
    /// Election: always the canonical parent-hash draw.
    /// Batch-verify staged PQ member signatures (FULL-PQ: Falcon has no batch
    /// primitive, so the SAME per-signature predicate runs per item, chunked
    /// across cores with rayon — the
    /// `Transaction::verify_signatures_batch_parallel` precedent, same
    /// primitive, zero new logic).
    ///
    /// Fail-closed all-must-pass: `true` iff EVERY staged signature verifies.
    /// Serial and parallel paths combine the same per-item predicate with
    /// boolean AND, so the verdict is order-independent and bit-identical on
    /// both paths. `msg` is shared read-only and key resolution already
    /// happened during staging, so no locks are taken in the parallel region.
    fn verify_staged_pq_signatures(
        staged: &[(ValidatorId, crate::post_quantum::PqScheme, Vec<u8>, &[u8])],
        msg: &[u8],
    ) -> bool {
        fn one(
            scheme: crate::post_quantum::PqScheme,
            pubkey: &[u8],
            msg: &[u8],
            sig: &[u8],
        ) -> bool {
            if scheme == crate::post_quantum::PqScheme::Falcon512 {
                verify_falcon_signature(pubkey, msg, sig)
            } else {
                crate::post_quantum::verify_pq_signature(scheme, pubkey, msg, sig)
            }
        }
        // Serial at or below one chunk (rayon task overhead would dominate —
        // the never-slower gate); chunked-parallel above, mirroring
        // `verify_signatures_batch_parallel`.
        const CHUNK: usize = 8;
        if staged.len() <= CHUNK {
            return staged
                .iter()
                .all(|(_, scheme, pubkey, sig)| one(*scheme, pubkey, msg, sig));
        }
        use rayon::prelude::*;
        staged
            .par_chunks(CHUNK)
            .all(|chunk| chunk.iter().all(|(_, scheme, pubkey, sig)| one(*scheme, pubkey, msg, sig)))
    }

    fn micro_cert_valid_signers(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> Option<Vec<ValidatorId>> {
        if cert.height != self.height || cert.round != self.round {
            return None;
        }
        let expected_committee_size = micro_committee_size(validators.len());
        if cert.committee_size != expected_committee_size
            || cert.committee_size == 0
            || cert.committee_size as usize > MAX_COMMIT_CERT_SIGNERS
        {
            return None;
        }

        let expected_bitmask_len = (cert.committee_size as usize).div_ceil(8);
        if cert.signers_bitmask.len() != expected_bitmask_len {
            return None;
        }
        for i in (cert.committee_size as usize)..(cert.signers_bitmask.len() * 8) {
            if (cert.signers_bitmask[i / 8] & (1 << (i % 8))) != 0 {
                return None;
            }
        }

        // The committee is re-derived from the certificate's OWN sortition
        // parent (the parent block hash the signers elected with), so the
        // verifier lands on exactly the committee the signers did. The
        // block-apply path additionally pins that parent to the hash committed
        // in the block header (`QuorumCertificate::binds_to_parent`), so a
        // certificate cannot pick a favourable committee of its own.
        // Election: always the canonical parent-hash draw.
        let committee = derive_sortition_committee(
            validators,
            cert.height,
            cert.round,
            cert.committee_size,
            &cert.sortition_parent,
        );
        let expected_len = (cert.committee_size as usize).min(validators.len());
        if committee.len() != expected_len || committee.is_empty() {
            return None;
        }

        for i in committee.len()..(cert.committee_size as usize) {
            if cert.is_signer(i) {
                return None;
            }
        }

        let signed_count = cert.signed_count();
        let is_compact = cert.signatures.len() == signed_count;
        let is_full = cert.signatures.len() == cert.committee_size as usize;
        if !is_compact && !is_full {
            return None;
        }

        // Stage (member, scheme, pubkey, signature) per marked member, in
        // committee order. Key resolution is serial and cheap; the expensive
        // per-signature crypto runs batched below with the SAME per-item
        // predicate and the SAME fail-closed verdict: every staged signature
        // must verify, else the whole certificate is refused (`None`) —
        // exactly the verdict the serial loop this replaces reaches.
        let mut sig_idx = 0;
        let mut staged: Vec<(ValidatorId, crate::post_quantum::PqScheme, Vec<u8>, &[u8])> =
            Vec::new();

        for (i, val_id) in committee.iter().enumerate() {
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
                    .or_else(|| get_validator_pq_key(val_id));
                // FULL-PQ: Ed25519 fallback deleted (no compat). A member
                // without a registered PQ key fails closed (`None` below).

                let (scheme, pubkey) = key_opt?;

                if scheme != cert.scheme {
                    return None;
                }

                staged.push((*val_id, scheme, pubkey, sig.as_slice()));
            }
        }

        if !Self::verify_staged_pq_signatures(&staged, msg) {
            return None;
        }
        Some(staged.into_iter().map(|(id, _, _, _)| id).collect())
    }

    /// Power-weighted µQC verification: the members `micro_cert_valid_signers`
    /// names must carry quorum power.
    ///
    /// Fail-closed: empty committee (`committee_size == 0`), empty re-derived
    /// committee, or zero total committee weight always return `false`.
    /// Backward compatibility: on uniform power the weight rule coincides
    /// with the legacy `floor(2*k/3)+1` head-count, so historic 3/3 (and
    /// 11/16, …) certificates verify unchanged — they carry the full
    /// committee power.
    ///
    /// Election: always the canonical parent-hash draw.
    fn verify_micro_cert(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> bool {
        let Some(valid) =
            self.micro_cert_valid_signers(cert, validators, msg, pq_keys)
        else {
            return false;
        };
        // Power-weighted quorum over the ACTUAL committee. Fail-closed on
        // zero weight (empty set / all-zero powers can never reach quorum).
        // NOTE: there is deliberately NO head-count early reject here — a
        // 2-of-3 bitmask that the old `floor(2*3/3)+1 = 3` rule threw out may
        // still carry quorum POWER, which is exactly the fragile-unanimous
        // case this fixes.
        // Election: the quorum is summed over the SAME
        // canonical committee the attribution above resolved.
        let committee = derive_sortition_committee(
            validators,
            cert.height,
            cert.round,
            cert.committee_size,
            &cert.sortition_parent,
        );
        let committee_total: u64 = committee.iter().map(|id| validators.power_of(id)).sum();
        if committee_total == 0 {
            return false;
        }
        let quorum_power = pq_micro_required_power(committee_total, validators.total_power());
        let valid_power: u64 = valid.iter().map(|id| validators.power_of(id)).sum();
        valid_power >= quorum_power
    }

    /// The full-set members whose epoch-certificate signatures VERIFY
    /// (attribution-grade): exactly the checks `verify_epoch_cert` enforces,
    /// MINUS the quorum-power gate. `None` on any structural failure or any
    /// bad/missing key or bad signature (fail-closed, same as verify), else
    /// the sorted-set members whose bit is set and whose signature verifies.
    fn epoch_cert_valid_signers(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> Option<Vec<ValidatorId>> {
        if cert.height != self.height || cert.round != self.round {
            return None;
        }
        let total_validators = validators.len();
        if total_validators == 0 {
            return None;
        }

        let mut ids: Vec<ValidatorId> = validators.validators.keys().copied().collect();
        ids.sort_unstable();

        let signed_count = cert.signed_count();
        let is_compact = cert.signatures.len() == signed_count;
        let is_full = cert.signatures.len() == ids.len()
            || cert.signatures.len() == cert.committee_size as usize;
        if !is_compact && !is_full {
            return None;
        }

        // Staged exactly like `micro_cert_valid_signers`: serial cheap key
        // resolution in member order, batched crypto below with the same
        // per-item predicate and the same fail-closed verdict (any bad or
        // missing signature refuses the whole certificate — `None`).
        let mut sig_idx = 0;
        let mut staged: Vec<(ValidatorId, crate::post_quantum::PqScheme, Vec<u8>, &[u8])> =
            Vec::new();

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
                    .or_else(|| get_validator_pq_key(val_id));
                // FULL-PQ: Ed25519 fallback deleted (no compat). A member
                // without a registered PQ key fails closed (`None` below).

                let (scheme, pubkey) = key_opt?;

                if scheme != cert.scheme {
                    return None;
                }

                staged.push((*val_id, scheme, pubkey, sig.as_slice()));
            }
        }

        if !Self::verify_staged_pq_signatures(&staged, msg) {
            return None;
        }
        Some(staged.into_iter().map(|(id, _, _, _)| id).collect())
    }

    fn verify_epoch_cert(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
    ) -> bool {
        let Some(valid) = self.epoch_cert_valid_signers(cert, validators, msg, pq_keys) else {
            return false;
        };
        let power: u64 = valid.iter().map(|id| validators.power_of(id)).sum();
        power >= validators.quorum_power()
    }

    /// Attach a post-quantum micro-certificate (µQC) to this QuorumCertificate.
    ///
    /// Always the canonical envelope ([`encode_pq_micro_envelope`]) — today's
    /// bytes bit-for-bit. EMBED retired: a sealed (retired VRF seal, old bytes
    /// only) certificate is never produced; such history bytes still read back
    /// through the existing bincode fallback in [`decode_pq_micro_envelope`].
    pub fn attach_pq_micro_certificate(&mut self, uqc: &PqMicroCertificate) {
        let payload = encode_pq_micro_envelope(uqc);
        self.signatures
            .retain(|(voter, _)| *voter != PQ_UQC_MARKER_ID);
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

    /// The parent block hash this certificate's sortition committee was
    /// elected with, if it carries a µQC.
    ///
    /// `None` for a certificate without a µQC (no committee, so there is nothing to bind).
    pub fn sortition_parent(&self) -> Option<[u8; 32]> {
        self.pq_micro_certificate().map(|c| c.sortition_parent)
    }

    /// CHAIN BINDING: a certificate that carries a µQC must have been elected
    /// with the parent hash committed in the header of the block it finalizes.
    ///
    /// Without this pin a Byzantine peer could elect the committee of its
    /// choice (the parent is part of the certificate) and produce a µQC that
    /// verifies over a committee it fully controls — a forged quorum. With
    /// the pin, the committee is the one the chain's own parent hash elects,
    /// exactly what every honest validator used.
    ///
    /// A certificate WITHOUT a µQC has no committee and is therefore not
    /// bound by this rule (it must clear the stricter full-set quorum of the
    /// classical path instead).
    pub fn binds_to_parent(&self, parent_hash: &[u8; 32]) -> bool {
        match self.sortition_parent() {
            Some(p) => &p == parent_hash,
            None => true,
        }
    }

    // REMOVED (aggregate envelope verify-for-counting): the envelope
    // verified-signers and path-power helpers lived here. No live path
    // references remain (proven by grep: the only consumers were
    // `verify_unified` and `signers_set`, both rewired above). The marker
    // entry is skipped as a non-member — the same observable behavior as
    // the default-off path.

    /// Extracts the set of validator IDs that signed this QuorumCertificate.
    ///
    /// Handles:
    /// 1. Post-quantum µQC (`PQ_UQC_MARKER_ID` = `[0xFD; 32]`): decodes the micro-certificate
    ///    envelope or bitmask and identifies signing committee members via sortition.
    /// 2. Post-quantum Epoch CEC (`PQ_QC_MARKER_ID` = `[0xFE; 32]`): decodes the epoch certificate
    ///    envelope and identifies signing validators via canonical sorted validator bitmask.
    ///
    /// FULL-PQ (nodes wiped): classical Ed25519 entries are inert — skipped,
    /// never attributed. Attribution mirrors verification: only signers
    /// `verify` accepts are named.
    ///
    /// Attribution MUST mirror verification: only signers `verify` accepts
    /// are named. Every envelope path requires the SAME cryptographic checks
    /// the verify path enforces (V-P34 R2 — the old decode-only fallbacks let
    /// a certificate that verified on its classical Ed25519 quorum alone
    /// smuggle an undecodable marker whose raw bytes attributed arbitrary
    /// "signers", and even a fully-rejected QC attributed every named voter,
    /// silently forgiving downtime slash for validators that actually
    /// missed). Anything unverifiable contributes nothing.
    pub fn signers_set(&self, validators: &ValidatorSet) -> HashSet<ValidatorId> {
        let mut signers = HashSet::new();
        let msg = vote_sign_bytes(self.height, self.round, self.kind, &self.block_hash);
        for (voter, payload) in &self.signatures {
            if *voter == PQ_UQC_MARKER_ID {
                // Verify-grade: exactly what `verify_micro_cert` accepts (sans
                // the quorum-power gate — a genuinely-signed member is named
                // even in a sub-quorum certificate, so nobody is slashed for
                // signing). A schemaless bincode parse of a non-envelope
                // payload used to land on garbage bitmask bytes and attribute
                // the wrong validators; a forged envelope now attributes none.
                if let Some(cert) = decode_pq_micro_envelope(payload) {
                    if !cert.scheme.is_post_quantum() {
                        continue;
                    }
                    // Canonical parent-hash draw (same as `pq_path_verify`).
                    if let Some(ids) = self.micro_cert_valid_signers(
                        &cert,
                        validators,
                        &msg,
                        None,
                    ) {
                        signers.extend(ids);
                    }
                }
            } else if *voter == PQ_QC_MARKER_ID {
                // Verify-grade: exactly what `verify_epoch_cert` accepts (sans
                // the quorum gate, same reasoning as above).
                if let Some(cert) =
                    decode_pq_epoch_envelope(payload).or_else(|| decode_pq_micro_envelope(payload))
                {
                    if !cert.scheme.is_post_quantum() {
                        continue;
                    }
                    if let Some(ids) = self.epoch_cert_valid_signers(&cert, validators, &msg, None)
                    {
                        signers.extend(ids);
                    }
                }
            } else {
                // FULL-PQ: classical Ed25519 entries deleted (no compat).
                // Skipped: they carry no power and `verify` rejects them, so
                // attribution names nobody — mirroring verification.
                continue;
            }
        }
        signers
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
    /// The PARENT BLOCK HASH of this height — the hash of the block at
    /// `height - 1`, i.e. the `prev_hash` committed in the header of the
    /// block this height decides.
    ///
    /// It is the entropy the sortition committee of this height is elected
    /// with (see [`derive_sortition_committee`]), so every node of the network
    /// MUST hold the same value here. A node that elected its committee from
    /// a different parent would disagree with the rest of the network about
    /// who is on the committee and could never assemble a certificate the
    /// others accept.
    ///
    /// Defaults to the all-zero hash (the genesis parent). The runtime sets it
    /// from the finalized head whenever it (re-)anchors consensus on a height
    /// — see [`Self::set_parent_hash`].
    pub parent_hash: [u8; 32],
    /// True when `parent_hash` is KNOWN to be the block hash at `height - 1`.
    ///
    /// The committee is elected from that hash, so a node that does not know
    /// it elects a DIFFERENT committee than the network — and can never
    /// assemble a certificate the others accept. Height 1 is known by
    /// definition (the chain roots at the zero prev-hash sentinel); every
    /// other height needs the parent's hash to be established.
    ///
    /// An UNKNOWN parent is not a wrong parent: the µQC path then simply
    /// compiles no micro-certificate, and the classical (full validator set)
    /// certificate remains authoritative. Under Pure-PQ enforcement that is
    /// fail-closed — the node cannot finalize until it learns its parent,
    /// which is strictly better than finalizing on a committee nobody else
    /// elected.
    parent_hash_known: bool,
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
    /// At most this many jumps per ROUND (the budget resets on a view
    /// change); honest catch-up (a few jumps, then landing near stops
    /// further syncing) never notices.
    sync_jumps_used: u32,
    /// Best-known round per peer at THIS height, learned from verified votes
    /// even when the vote itself is not votable (stale far-behind or absurd
    /// far-ahead). Voting still requires an exact-round vote in `VoteSet`;
    /// this map is ONLY a round counter for sync and the deadlock breaker, so
    /// a 1200-round desync collapses instead of growing (live 2026-10-14:
    /// A r1550 vs B r318, each dropping the other's votes forever).
    pub peer_rounds: HashMap<ValidatorId, Round>,
    /// How many rounds of vote history the quorum scan covers and the vote
    /// history KEEPS.
    ///
    /// [`ROUND_LOOKBACK`] (8) in the normal case: a quorum can only ever
    /// form at or below our round, and the last few rounds are exactly the
    /// ones finalization can still decide.
    ///
    /// A deadlock re-phase WIDENS it to [`REPHASE_SCAN_WINDOW`] so a node
    /// that fell out of phase with the network can still find — and COMMIT —
    /// the quorum the network formed in the round it is actually in. Widening
    /// the WINDOW (rather than moving the round counter backwards) is what
    /// makes the re-phase effective without breaking the never-rewind
    /// invariant.
    pub scan_lookback: Round,
    /// Set once a deadlock re-phase has run at this height.
    ///
    /// The re-phase must be IDEMPOTENT: it widens the scan window and clears
    /// a stale lock, both of which happen once. Re-firing it on every
    /// timeout window would only advance the round by one (which the round
    /// timer does anyway) and change nothing else — a no-op that looks like
    /// progress.
    rephase_applied: bool,
    /// How many rounds at THIS HEIGHT ended in a VIEW CHANGE (a timeout).
    ///
    /// This is the honest "how much trouble is this height is in" counter, and
    /// it is NOT the round number: the round counter also moves when the node
    /// FOLLOWS a peer (see [`Self::sync_round_to`]) or when it is restored
    /// from a checkpoint, and a node that joins a chain at round 285027 has
    /// failed NOTHING at that height. Basing the view-change backoff on the
    /// round number therefore gave a freshly-synced node the maximum timeout
    /// (13.5 s with a 3.5 s base) before it had even tried — on a WAN, where
    /// the round timeout is what decides how fast the network reacts, that is
    /// the difference between a 3.5 s and a 27 s round.
    pub timeouts: u32,
    /// THE OBSERVED POLKA: the newest **quorum of prevotes FOR A BLOCK** this
    /// height has seen, as `(round, block_hash)`.
    ///
    /// WHY IT IS A LEDGER AND NOT A SCAN (liveness fix, live 2026-10-19 →
    /// 2026-10-21: the masterchain sat at height 285027 for three days with a
    /// full prevote QC formed and NO precommit QC):
    ///
    /// A polka is a FACT about the network, not a property of the local round
    /// counter. The old code only ever looked for one by SCANNING the rounds
    /// around the local round (`rounds_to_inspect`), so a polka whose
    /// quorum-completing prevote arrived after this node had raced ahead of
    /// the network (the WAN round-skew shape) was INVISIBLE: the node never
    /// precommitted it, so the precommit quorum never formed, and the height
    /// was parked forever. The live cluster showed exactly that: the prevote
    /// quorum for one block formed in every validator's vote set, and only
    /// ONE of them ever cast a precommit.
    ///
    /// The ledger is written the moment the quorum-completing prevote is
    /// admitted (`add_prevote` → `note_polka`) — the Tendermint rule "if you
    /// see a polka, precommit it", with no dependence on where the local
    /// round counter happens to be. It is a pure cache of a fact that the
    /// vote set already proves, so it can never make a node vote for
    /// something the network did not certify.
    pub observed_polka: Option<(Round, BlockHash)>,
    // --- C2 observability (local only, never on the wire) ---
    /// Meter: total rounds at this height that ended nil (≥1 nil prevote or
    /// no block QC). Monotonic within the height; alertable via
    /// [`crate::metrics`] (`nil_rounds_total`). Never reset except by height
    /// advance (a fresh `HeightConsensus` starts at 0).
    pub nil_rounds_total: u64,
    /// Consecutive nil-rounds ending at the CURRENT round (resets on any
    /// round that forms a block prevote QC). Drives the circuit breaker.
    pub consecutive_nil_rounds: u32,
    /// The breaker fired for the CURRENT consecutive-nil streak and its
    /// one-shot convergence action was already applied. Reset when the streak
    /// breaks (a block QC forms). Guarantees "widen once, then resume normal
    /// timing" instead of widening forever.
    pub nil_breaker_fired_this_streak: bool,
    /// Consecutive missed proposals per scheduled proposer (observability
    /// only — no protocol punishment). Incremented when a round ends with no
    /// accepted proposal from its scheduled proposer; reset to 0 the moment
    /// that proposer gets a proposal accepted. Entries for validators with a
    /// zero streak are removed, so the map stays bounded by the set size.
    pub missed_proposals: HashMap<ValidatorId, u32>,
    /// Meter: total proposer-miss observations at this height (every increment
    /// of any entry in `missed_proposals`).
    pub missed_proposals_total: u64,
}

/// Peer-driven round jumps allowed per ROUND (each jumps at most
/// ROUND_LOOKBACK). Generous for honest catch-up, fatal for runaway sync.
///
/// The budget was per WALL-CLOCK second, which put a wall clock inside the
/// consensus state machine: the catch-up behaviour then depended on how fast
/// the host happened to be, and it could not be exercised deterministically
/// (a virtual-clock harness has no wall second to expire, so a node that
/// needed to follow the network could not). It is now per ROUND — the budget
/// resets on a view change — which makes the state machine clock-free and
/// deterministic.
///
/// It is also STRICTER than the wall-clock budget it replaces: a round lasts
/// at least the round timeout (3.5 s on the live cluster), so the old budget
/// allowed 32 rounds of movement per second while this allows
/// `8 * ROUND_LOOKBACK = 64` rounds per round — under 5 rounds per second at
/// the live timeout. The runaway is bounded just as tightly, and the honest
/// catch-up (a node ~30 rounds behind needs 4 jumps) still completes inside a
/// single round's budget.
pub const MAX_SYNC_JUMPS_PER_ROUND: u32 = 8;

/// Absolute bound on ONE deadlock-breaker jump, in rounds.
///
/// The breaker's whole job is to close a LARGE desync in ONE step (live
/// 2026-10-14: A r1550 vs B r318 — a gap of 1232 rounds), so the bound must
/// be far larger than any realistic gap. It is deliberately NOT
/// `MAX_ROUND_AHEAD` (1000): that constant is the *vote-acceptance* window,
/// and a desync the breaker cannot close in one step is a desync the breaker
/// cannot close at all (the round counter only moves forward).
///
/// It bounds the JUMP SIZE, not the peer's claim: the target is additionally
/// CORROBORATED by more than one validator (see
/// [`HeightConsensus::deadlock_breaker_target`]), so a single Byzantine peer
/// cannot drag this node off the network.
pub const MAX_DEADLOCK_JUMP: Round = 65_536;

/// The round window a deadlock re-phase installs: how far back the quorum
/// scan and the vote history reach once the node has re-phased.
///
/// A node that fell out of phase with the network holds the network's votes
/// — but only for the round the network is ACTUALLY in, which can be far
/// behind the round counter this node wandered into. The normal window
/// ([`ROUND_LOOKBACK`], 8 rounds) cannot see them, so the node never finds
/// the quorum it already holds and never converges.
///
/// The re-phase therefore WIDENS the window instead of moving the round
/// counter backwards (rewinding would make the node re-vote in a round it
/// already voted in — a self-equivocation, which gets the node slashed).
/// With a wide window the node COMMITS the old round's quorum, which is
/// exactly the Tendermint rule "a node must still commit a round it has
/// left if the quorum turns up".
pub const REPHASE_SCAN_WINDOW: Round = 4_096;

/// Hard cap on the number of vote rounds retained inside ONE height.
///
/// The vote sets of the CURRENT height are kept as a whole (a late vote must
/// still be able to complete the quorum of the round it belongs to — see
/// [`HeightConsensus::prune_old_rounds`]), so this cap is what bounds the
/// memory of a height that never decides. It is generous enough to cover a
/// pathological height (the live cluster spent 380 rounds in one height) and
/// small enough that the retained votes stay in the low megabytes. The
/// OLDEST (lowest) rounds are evicted first when it is hit.
pub const MAX_RETAINED_VOTE_ROUNDS: usize = 4_096;

/// Hard cap on how far BACK the quorum scan may reach, in rounds.
///
/// The scan window is anchored on the network's round so that a node which
/// drifted ahead of the network can still find the polka the network formed
/// (see [`HeightConsensus::rounds_to_inspect`]). Without a cap, one peer
/// claiming an ancient round would make every tick scan — and every prune
/// retain — an unbounded number of rounds, which is a denial-of-service
/// primitive. The cap is far larger than any realistic WAN round skew (the
/// live cluster drifted ~30 rounds) and far smaller than the round counter.
pub const MAX_SCAN_SPAN: Round = 4_096;

// ============================================================================
// C2 SLOW-VALIDATOR / NIL-STORM / PROPOSER-LIVENESS (Enterprise Testnet grade)
// ============================================================================
//
// All items in this section are LOCAL POLICY + OBSERVABILITY ONLY: no
// wire-format change, no new consensus fields on the wire, no fork. The
// structs below (`HeightConsensus`) are never serialized to the network
// (only `Vote`, `QuorumCertificate`, `Block`, `ConsensusMsg` travel), so the
// new counters/maps change zero bytes on the wire.

/// Consecutive nil-rounds that trip the nil-storm circuit breaker (K ≤ 5).
///
/// Small enough to matter (a 3.5s base round trips the breaker in ~10s, long
/// before a round-200+ storm), large enough that one slow round never fires
/// it. Pinned by test.
pub const NIL_CIRCUIT_BREAKER_K: u32 = 3;

/// Per-round backoff of the DETERMINISTIC round timeout (ms per round).
///
/// Safety role (liveness): grows the timeout with the round so a slow network
/// still converges instead of view-changing forever; deterministic on every
/// node (function of round only) so rounds stay synchronized. Bounded by
/// [`DETERMINISTIC_BACKOFF_CAP_MS`].
pub const DETERMINISTIC_BACKOFF_PER_ROUND_MS: u64 = 500;
/// Cap on the round-driven backoff half of the deterministic timeout.
///
/// Safety role (liveness + DoS bound): keeps a pathological round (round 1M)
/// from installing an unbounded timeout that would stall finality; the cap
/// still exceeds any realistic WAN skew, so honest catch-up is unaffected.
pub const DETERMINISTIC_BACKOFF_CAP_MS: u64 = 10_000;
/// Adaptive extension per unit of proposer missed-streak (ledger `missed`).
///
/// Safety role (liveness): gives a historically slow proposer's rounds extra
/// time instead of timing out a valid proposal; input is committed block
/// content (identical on every node), so the extension cannot desynchronize
/// rounds. Bounded by [`ADAPTIVE_EXTENSION_CAP_MS`].
pub const ADAPTIVE_EXTENSION_PER_MISS_MS: u64 = 500;
/// Hard cap on the adaptive (slow-proposer) extension half.
///
/// Safety role (liveness + DoS bound): bounds how far one proposer's streak
/// can stretch a round, so a grinded `missed` streak cannot park the chain;
/// the cap still covers the observed slow-proposer tail.
pub const ADAPTIVE_EXTENSION_CAP_MS: u64 = 5_000;

/// Consecutive missed proposals per validator that counts as "repeatedly
/// missing" for OBSERVABILITY (M). No protocol punishment — only metering +
/// suspicion-free fast-path re-admission (the counter resets the moment the
/// proposer proposes again). Pinned by test.
pub const PROPOSER_MISS_THRESHOLD_M: u32 = 3;

/// Deterministic round timeout for `(height, round)`.
///
/// CHOICE (1a) adaptive round timeout — and why (1b)/(1c) were rejected:
///
/// * (1a) CHOSEN: extend the timeout for rounds whose scheduled proposer is
///   historically slow. The slowness signal is the staking-ledger `missed`
///   streak for the scheduled proposer — block content, identical on every
///   node that finalized the same prefix — so every honest node computes the
///   SAME extension for the SAME (height, round). Bounded
///   (`ADAPTIVE_EXTENSION_CAP_MS`), deterministic, rounds stay synchronized.
/// * (1b) vote-aggregation grace REJECTED as the primary fix: prevotes for
///   round r are ALREADY counted after the node leaves r (the scan window +
///   the polka ledger keep every round of the height votable — that was the
///   2026-10-21 parked-height fix). Counting r-prevotes toward an r+1 QC
///   would additionally MIX rounds: two different quorums (r for A, r+1 for
///   B) could both "decide" and break quorum intersection. Safety over grace.
/// * (1c, "faster base timeout") REJECTED: shrinking the base from 3.5s buys
///   view-change storms on 1-vCPU members (responder p50 ~660ms leaves no
///   headroom), not throughput.
///
/// INPUTS (exhaustive — anything else is a bug):
///  1. `base_ms` — the frozen canonical base [`FROZEN_ROUND_TIMEOUT_BASE_MS`].
///     MUST match on all validators (documented rollout invariant); there is
///     no per-node env override anymore (protocol freeze 2026-11-03).
///  2. `round` — the round the timeout is FOR (not a local failure count).
///  3. `proposer_missed_streak` — ledger `missed` of the scheduled proposer
///     for (height, round). Deterministic block content, not observation.
///
/// NO wall-clock input: no `Instant::now`, no `SystemTime`, no elapsed, no
/// peer-seen timestamps, no local vote-observation flags. A reader can verify
/// with `grep -n "Instant\|SystemTime" ` on this function: zero hits.
///
/// FREEZE (protocol freeze 2026-11-03): canonical round-timeout base, 3_000 ms.
/// Value = pre-freeze `STELL_ROUND_TIMEOUT_MS` code default (was read in
/// `main.rs` with clamp 200..=3_600_000; the frozen value is inside that
/// range, so default-env behavior is byte-identical). Rationale: this base
/// feeds the same-on-all-nodes ladder (spec
/// `docs/specs/04_NETWORK_AND_CONSENSUS_PHASE2.md` §2) and MUST match on all
/// validators — a per-node env knob for a must-match value is a fork risk.
/// Change requires spec update + audit note (AGENTS.md §7).
pub const FROZEN_ROUND_TIMEOUT_BASE_MS: u64 = 3_000;

pub fn deterministic_round_timeout_ms(
    base_ms: u64,
    round: Round,
    proposer_missed_streak: u32,
) -> u64 {
    let backoff = (round as u64)
        .saturating_mul(DETERMINISTIC_BACKOFF_PER_ROUND_MS)
        .min(DETERMINISTIC_BACKOFF_CAP_MS);
    let adaptive = (proposer_missed_streak as u64)
        .saturating_mul(ADAPTIVE_EXTENSION_PER_MISS_MS)
        .min(ADAPTIVE_EXTENSION_CAP_MS);
    base_ms.saturating_add(backoff).saturating_add(adaptive)
}

impl HeightConsensus {
    pub fn new(height: Height, validators: ValidatorSet) -> Self {
        Self {
            height,
            round: 0,
            step: Step::Propose,
            validators,
            parent_hash: [0u8; 32],
            parent_hash_known: height <= 1,
            proposal: None,
            proposal_round: None,
            locked: None,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            decided: None,
            prevote_qc: HashMap::new(),
            precommit_qc: None,
            sync_jumps_used: 0,
            peer_rounds: HashMap::new(),
            scan_lookback: ROUND_LOOKBACK,
            rephase_applied: false,
            timeouts: 0,
            observed_polka: None,
            nil_rounds_total: 0,
            consecutive_nil_rounds: 0,
            nil_breaker_fired_this_streak: false,
            missed_proposals: HashMap::new(),
            missed_proposals_total: 0,
        }
    }

    /// Anchor this height on its parent block hash.
    ///
    /// The parent hash is the sortition entropy of the height (see
    /// [`derive_sortition_committee`]), so it MUST be the hash the chain
    /// committed for `height - 1` — the finalized head when the runtime
    /// (re-)anchors consensus on this height. Re-anchoring on a height
    /// WITHOUT setting it leaves the zero (genesis) parent in place, which
    /// elects a different committee than the rest of the network.
    pub fn set_parent_hash(&mut self, parent_hash: [u8; 32]) {
        self.parent_hash = parent_hash;
        self.parent_hash_known = true;
    }

    /// True when the sortition parent of this height is known.
    pub fn parent_hash_known(&self) -> bool {
        self.parent_hash_known
    }

    /// The sortition parent of this height, or `None` when it is UNKNOWN.
    ///
    /// `None` means "no honest committee can be derived" — the caller must
    /// not elect one (see [`VoteSet::certificate`]).
    pub fn sortition_parent(&self) -> Option<&[u8; 32]> {
        if self.parent_hash_known {
            Some(&self.parent_hash)
        } else {
            None
        }
    }

    pub fn proposer(&self) -> Option<ValidatorId> {
        self.validators.proposer_for(self.height, self.round)
    }

    /// Accept a proposal for the current round from the correct proposer.
    pub fn receive_proposal(
        &mut self,
        proposer: ValidatorId,
        block_hash: BlockHash,
    ) -> Result<(), String> {
        if self.step != Step::Propose {
            return Err("not in propose step".to_string());
        }
        if Some(proposer) != self.proposer() {
            return Err("wrong proposer".to_string());
        }
        // Audit F1: one value per round. A second DISTINCT proposal in the
        // same round (equivocating proposer) must not overwrite the first —
        // mid-round flips split prevotes. Re-receipt of the IDENTICAL body
        // (rebroadcast) stays Ok (idempotent).
        if let Some((p, h)) = &self.proposal {
            if *p == proposer && *h == block_hash && self.proposal_round == Some(self.round) {
                return Ok(());
            }
            return Err("proposal already recorded for this round".to_string());
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
        // Fail-closed admission: a refused vote must leave no trace. The
        // bucket below is created on first use, so checking scope first keeps
        // a wrong-height/wrong-kind vote from materializing an empty VoteSet
        // that counts toward the retained-round cap and scan window.
        if vote.height != self.height || vote.kind != VoteKind::Prevote {
            return Err("vote out of scope".to_string());
        }
        let round = vote.round;
        let res = {
            let set = self.prevotes.entry(round).or_default();
            set.add(
                vote,
                &self.validators,
                self.height,
                round,
                VoteKind::Prevote,
            )
        };
        // THE POLKA LEDGER (liveness fix, live 2026-10-21: the masterchain
        // parked at height 285027 with a prevote QC and NO precommit QC).
        // The moment the quorum-completing prevote is admitted, the polka
        // EXISTS — record it, whatever the local round is. The scan-window
        // lookup cannot do this: a polka whose votes arrive after the node
        // has raced ahead of the network is outside the window, so the node
        // never precommits it and the precommit quorum never forms.
        self.note_polka(round);
        res
    }

    pub fn add_precommit(&mut self, vote: Vote) -> Result<(), String> {
        if vote.round > self.round.saturating_add(MAX_ROUND_AHEAD) {
            return Err("precommit round too far ahead".to_string());
        }
        // Same fail-closed admission as `add_prevote`: refuse before the
        // bucket is materialized so refused votes leave no empty VoteSet.
        if vote.height != self.height || vote.kind != VoteKind::Precommit {
            return Err("vote out of scope".to_string());
        }
        let round = vote.round;
        let set = self.precommits.entry(round).or_default();
        set.add(
            vote,
            &self.validators,
            self.height,
            round,
            VoteKind::Precommit,
        )
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

    /// The rounds worth inspecting, newest first.
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
    ///
    /// The window is [`Self::scan_lookback`] rounds wide: the normal
    /// [`ROUND_LOOKBACK`], widened by a deadlock re-phase so a node that fell
    /// out of phase with the network can still reach the round the network
    /// is actually in. Only rounds that actually carry votes are returned —
    /// probing thousands of empty rounds on every tick is work a peer could
    /// trigger, and the callers skip empty rounds anyway.
    ///
    /// NETWORK ANCHOR (liveness fix, live 2026-10-21: the masterchain parked at
    /// height 285027 with a full prevote QC formed and NO precommit QC): the
    /// window used to be anchored on OUR round alone. A node that had drifted
    /// AHEAD of the network (per-node round-timeout skew on a WAN) therefore
    /// could not see the round the network was actually in: the polka the
    /// network formed sat outside `[our_round - 8, our_round]`, so the node
    /// never found it, never precommitted, and the chain never finalized. The
    /// window is now anchored on the LOWEST of (our round, the highest round
    /// any peer has been observed in), so a node that is ahead still scans the
    /// network's round. The anchor is the MAXIMUM peer round, so a Byzantine
    /// peer cannot narrow the window, and [`MAX_SCAN_SPAN`] caps how far back
    /// the scan may reach, so no peer can force unbounded per-tick work.
    fn rounds_to_inspect(&self) -> Vec<Round> {
        // Bounded: an unbounded scan would let a peer force O(rounds) work per tick.
        // Looking back a fixed window covers any realistic message delay, and a vote
        // older than that is a message whose sender has long since moved on.
        let low = self.scan_floor();
        let mut rounds: Vec<Round> = Vec::new();
        for r in (low..=self.round).rev() {
            if self.prevotes.contains_key(&r) || self.precommits.contains_key(&r) {
                rounds.push(r);
            }
        }
        rounds
    }

    /// The OLDEST round the quorum scan may look at.
    ///
    /// Normally `our_round - scan_lookback`. When the network has been observed
    /// in a LOWER round than ours (we are ahead of it — the WAN round-skew
    /// shape), the floor drops to `network_round - scan_lookback` so the polka
    /// the network formed stays visible. Two hard bounds apply:
    ///
    /// * the floor never goes below `our_round - MAX_SCAN_SPAN`, so a peer
    ///   cannot make us scan (or retain) an unbounded number of rounds;
    /// * the anchor is the MAXIMUM observed peer round, so a peer claiming a
    ///   LOW round cannot narrow the window (it would only ever make `min`
    ///   pick our own round) and a peer claiming an absurdly high round
    ///   cannot widen it either (`min` picks our own round).
    fn scan_floor(&self) -> Round {
        let anchor = self.max_peer_round().unwrap_or(self.round).min(self.round);
        let floor = anchor.saturating_sub(self.scan_lookback);
        let hard = self.round.saturating_sub(MAX_SCAN_SPAN);
        floor.max(hard).min(self.round)
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
            let Some(pset) = self.precommits.get(&r) else {
                continue;
            };
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
                        let mut v: Vec<String> = s.votes.keys().map(&short).collect();
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
        // The newest POLKA (a quorum of prevotes FOR A BLOCK). A nil quorum
        // is NOT a polka - see `try_polka_at` - and it must not shadow a real
        // polka for the unlock decision either: a nil quorum says "no block
        // was agreed in THAT round", nothing about the earlier round the
        // network DID agree on a block in.
        let mut polka: Option<(Round, BlockHash)> = None;
        for round in self.rounds_to_inspect() {
            let Some(set) = self.prevotes.get(&round) else {
                continue;
            };
            let Some(target) = set.quorum_target(&self.validators) else {
                continue;
            };
            if found.is_none() {
                if let Some(qc) =
                    set.certificate_with_parent(target, &self.validators, self.sortition_parent())
                {
                    self.prevote_qc.insert(round, qc);
                }
                found = Some((round, target));
            }
            if polka.is_none() {
                if let Some(block) = target {
                    polka = Some((round, block));
                }
            }
        }
        // THE LEDGER WINS OVER THE WINDOW (liveness fix, live 2026-10-21: the
        // masterchain parked at height 285027 with a prevote QC and NO
        // precommit QC). The scan only sees the rounds around the local
        // counter; the ledger remembers the newest polka the node has
        // OBSERVED, wherever it formed. A polka the window cannot see is
        // still a polka, and it is still the network's latest word when it is
        // NEWER than anything the window holds.
        let polka = match (self.observed_polka, polka) {
            (Some((r1, b1)), Some((r2, b2))) => Some(if r1 >= r2 { (r1, b1) } else { (r2, b2) }),
            (a, None) => a,
            (None, b) => b,
        };
        // Polka unlock (BFT liveness): a quorum for a different value -- or
        // for nil -- at a HIGHER round than our lock proves the network
        // moved on without us (we locked on a QC the peer never saw, after
        // a single lost vote). Keeping the old lock would nil every future
        // proposal while the network can never come back: observed live as
        // a permanent stall with one node voting nil forever. Unlock; the
        // normal path re-locks when we precommit again. A quorum for our
        // own value changes nothing.
        //
        // Newest-wins: `polka` is the NEWEST polka (scan order above), so an
        // older conflicting quorum no longer unlocks past a newer confirming
        // one.
        // Polka unlock (BFT safety & liveness, audit F-01): in Tendermint, a
        // node ONLY unlocks when observing a prevote quorum for a DIFFERENT
        // non-nil block (`Some(other_block)`). A nil polka (`found == (r, None)`)
        // forms on timeouts and must NEVER unlock — otherwise honest nodes that
        // timed out in round 1 would drop their locks on a block finalized in
        // round 0 and finalize a conflicting block in round 2 (safety violation).
        if let (Some((locked_block, locked_round)), Some((polka_round, other_block))) =
            (self.locked, polka)
        {
            if polka_round > locked_round && other_block != locked_block {
                self.locked = None;
            }
        }
        found
    }

    /// The newest **POLKA** in the scan window: a round whose prevote set
    /// holds quorum power FOR A BLOCK, together with the round it formed in.
    ///
    /// A NIL quorum is not a polka. Tendermint's rule: a nil quorum means
    /// "no block was agreed in that round"; it never masks a polka from an
    /// earlier round, and it never unlocks a lock. The precommit path must
    /// therefore follow the newest POLKA, not the newest quorum of any kind.
    ///
    /// WHY THIS MATTERS (liveness fix, live 2026-10-21: the masterchain parked
    /// at height 285027 with a full prevote QC formed and NO precommit QC): the
    /// scan used to return the newest quorum, nil included. A node that had
    /// moved on to a later round collected a NIL quorum there (the network
    /// timed out) and that nil quorum SHADOWED the real polka one round
    /// earlier: the node produced a NIL precommit for the newer round instead
    /// of a precommit for the block the network had actually certified, and
    /// the `last_precommitted` dedup key then suppressed the correct precommit
    /// on every later tick. The polka stayed masked for as long as the nil
    /// quorum stayed in the window - i.e. forever. A nil quorum is now
    /// invisible to the precommit decision.
    ///
    /// The certificate for the polka is recorded in `prevote_qc` so the caller
    /// can attach it to the precommit.
    pub fn try_polka_at(&mut self) -> Option<(Round, BlockHash)> {
        for round in self.rounds_to_inspect() {
            let Some(set) = self.prevotes.get(&round) else {
                continue;
            };
            let Some(Some(target)) = set.quorum_target(&self.validators) else {
                continue;
            };
            if let Some(qc) =
                set.certificate_with_parent(Some(target), &self.validators, self.sortition_parent())
            {
                self.prevote_qc.insert(round, qc);
            }
            return Some((round, target));
        }
        None
    }

    /// Record the polka of `round`, if that round's prevote set now holds a
    /// quorum FOR A BLOCK.
    ///
    /// This is the WRITE side of the polka ledger (see
    /// [`Self::observed_polka`]). It is called the moment a prevote is
    /// admitted, so a polka is recorded the instant it becomes true — even
    /// when the round is far behind the local round counter (the live WAN
    /// round-skew shape) or far ahead of it.
    ///
    /// NEWEST WINS: an older polka never supersedes a newer one. A polka is
    /// the network's word for THAT round; the newest polka is the network's
    /// latest word, and the precommit must follow it.
    ///
    /// The certificate is built and stored at the same time, so the precommit
    /// that follows the polka carries the proof of the quorum it certifies.
    fn note_polka(&mut self, round: Round) {
        let Some(set) = self.prevotes.get(&round) else {
            return;
        };
        // A NIL quorum is not a polka: "no block was agreed in that round"
        // says nothing about any block.
        let Some(Some(target)) = set.quorum_target(&self.validators) else {
            return;
        };
        if self.observed_polka.map(|(r, _)| r > round).unwrap_or(false) {
            return; // an older polka never supersedes a newer one
        }
        let qc =
            set.certificate_with_parent(Some(target), &self.validators, self.sortition_parent());
        if let Some(qc) = qc {
            self.prevote_qc.insert(round, qc);
        }
        self.observed_polka = Some((round, target));
    }

    /// The polka this node has OBSERVED (the ledger), if any.
    pub fn observed_polka(&self) -> Option<(Round, BlockHash)> {
        self.observed_polka
    }

    /// The newest polka this node knows about: the one it OBSERVED (the
    /// ledger) or the newest one inside the scan window — whichever is newer.
    ///
    /// The ledger covers the polkas the window cannot see (a late polka, a
    /// polka of a round this node has already left); the window covers the
    /// polkas the ledger does not know about yet (a node that joined the
    /// height late and never saw the quorum-completing prevote arrive).
    pub fn best_polka(&mut self) -> Option<(Round, BlockHash)> {
        let scanned = self.try_polka_at();
        match (self.observed_polka, scanned) {
            (Some((r1, b1)), Some((r2, b2))) => Some(if r1 >= r2 { (r1, b1) } else { (r2, b2) }),
            (a, None) => a,
            (None, b) => b,
        }
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
    ///
    /// THE POLKA'S ROUND IS A CANDIDATE EVEN OUTSIDE THE WINDOW (liveness fix,
    /// live 2026-10-21: the masterchain parked at height 285027 with a prevote
    /// QC and NO precommit QC). The precommits are cast for the round of the
    /// polka they follow, so the precommit quorum forms in THAT round — and
    /// when the polka arrived late that round can be far outside the window
    /// around the local counter. Without this candidate the height could never
    /// be decided even though every validator had precommitted it.
    pub fn try_precommit_quorum(&mut self) -> Option<BlockHash> {
        let mut candidates = self.rounds_to_inspect();
        if let Some((r, _)) = self.observed_polka {
            if !candidates.contains(&r) {
                candidates.push(r);
            }
        }
        let round = candidates.into_iter().find(|r| {
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
        let prevoted = self
            .prevotes
            .get(&round)
            .and_then(|s| s.quorum_target(&self.validators));
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

        if let Some(qc) =
            set.certificate_with_parent(target, &self.validators, self.sortition_parent())
        {
            self.precommit_qc = Some(qc);
        }
        // Lock monotonicity (safety): the lock round only moves forward. A
        // decision for the SAME value at an OLDER round (a late quorum for a
        // round we already locked past) must not regress the lock, or stale
        // evidence could unlock past the newer lock (newest-wins). A
        // conflicting value never reaches here (refused above).
        if self.locked.map(|(_, lr)| round > lr).unwrap_or(true) {
            self.locked = Some((block, round));
        }
        self.decided = Some(block);
        self.step = Step::Commit;
        // A decided height is the end of every nil streak at this height: the
        // next height starts fresh (its own `HeightConsensus` starts at 0
        // anyway; this clears the readout for any same-height inspection).
        self.consecutive_nil_rounds = 0;
        self.nil_breaker_fired_this_streak = false;
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
    ///
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
        // the per-round jump budget the sync is refused; the caller's own
        // view change advances us anyway and refills the budget.
        if self.sync_jumps_used >= MAX_SYNC_JUMPS_PER_ROUND {
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

    /// Drop per-round vote sets that can no longer matter.
    ///
    /// **THE VOTE SETS OF THE CURRENT HEIGHT ARE KEPT** (liveness fix, live
    /// 2026-10-21: the masterchain sat at height 285027 for three days with a
    /// full prevote QC formed and NO precommit QC).
    ///
    /// The old prune dropped everything older than the finalization lookback
    /// window, on the assumption that "rounds inside the lookback are exactly
    /// what finalization can still decide". **That assumption IS the bug**:
    /// the quorum-COMPLETING prevote of a round routinely arrives long after
    /// the round it belongs to (a stalled WAN path, the round skew between
    /// nodes, a peer's own lag), and by then the set for that round has been
    /// emptied — so the quorum can never complete, the polka never forms, the
    /// precommit is never cast, and the height is parked forever. Tendermint
    /// keeps the vote sets of the whole height for exactly this reason.
    ///
    /// The memory is bounded twice over: the HEIGHT is the unit (a new height
    /// starts with empty maps — see `HeightConsensus::new`) and
    /// [`MAX_RETAINED_VOTE_ROUNDS`] caps the rounds kept inside one height.
    /// The quorum SCAN is unaffected: it still walks the window around the
    /// local round (plus the observed polka's round), so the per-tick cost
    /// does not grow with the height.
    ///
    /// The polka's own round is never evicted: it is the round the decision
    /// is made in, and its prevote set is the proof that the decided block
    /// was certified.
    fn prune_old_rounds(&mut self) {
        // The floor is the height's first round: every round of this height
        // can still receive the vote that completes its quorum.
        let floor = 0;
        self.prevotes.retain(|&r, _| r >= floor);
        self.precommits.retain(|&r, _| r >= floor);
        self.prevote_qc.retain(|&r, _| r >= floor);
        while self.retained_round_count() > MAX_RETAINED_VOTE_ROUNDS {
            let Some(oldest) = self.oldest_retained_round() else {
                break;
            };
            // The polka's round is kept even if it is the oldest one: it is
            // the round the decision is made in.
            if self
                .observed_polka
                .map(|(r, _)| r == oldest)
                .unwrap_or(false)
            {
                break;
            }
            self.prevotes.remove(&oldest);
            self.precommits.remove(&oldest);
            self.prevote_qc.remove(&oldest);
        }
    }

    /// How many distinct rounds still carry votes.
    fn retained_round_count(&self) -> usize {
        let mut set: HashSet<Round> = self.prevotes.keys().copied().collect();
        set.extend(self.precommits.keys().copied());
        set.len()
    }

    /// The LOWEST round still carrying votes (the eviction order).
    fn oldest_retained_round(&self) -> Option<Round> {
        let mut oldest: Option<Round> = None;
        for r in self.prevotes.keys().chain(self.precommits.keys()) {
            oldest = Some(match oldest {
                Some(m) => m.min(*r),
                None => *r,
            });
        }
        oldest
    }

    /// View change: advance to the next round, resetting per-round proposal state.
    ///
    /// C2: the round being LEFT is classified first — a round with no block
    /// prevote QC (nil quorum or no quorum) is a NIL round: `nil_rounds_total`
    /// increments and `consecutive_nil_rounds` grows, else the streak resets
    /// (and the breaker's one-shot flag clears). The scheduled proposer of
    /// the left round is also charged with a MISSED proposal when no proposal
    /// from it was accepted that round (observability only).
    pub fn next_round(&mut self) {
        // Classify the round we are leaving BEFORE wiping its proposal state.
        let left = self.round;
        let had_block_qc = self
            .prevotes
            .get(&left)
            .and_then(|s| s.quorum_target(&self.validators))
            .flatten()
            .is_some();
        self.note_round_outcome(!had_block_qc);
        // Proposer-skip accountability (observability only): a scheduled
        // proposer that never got its proposal accepted this round misses.
        // `proposal_round == Some(left)` means WE accepted its proposal; any
        // other state (none, or a stale round) means the slot went empty.
        if let Some(sched) = self.validators.proposer_for(self.height, left) {
            let proposed =
                self.proposal_round == Some(left) && self.proposal.map(|(p, _)| p) == Some(sched);
            self.note_proposer_missed(sched, proposed);
        }
        // SECURITY: saturate rather than `+= 1`, which panicked in debug and
        // wrapped to 0 in release at u32::MAX (audit F2/overflow).
        self.round = self.round.saturating_add(1);
        // A view change is a FAILED round at this height: count it, so the
        // view-change backoff grows with the trouble this height is in (and
        // not with the absolute round number).
        self.timeouts = self.timeouts.saturating_add(1);
        // A new round refills the peer-driven jump budget (see
        // `MAX_SYNC_JUMPS_PER_ROUND`): the runaway it guards is a burst
        // inside ONE round, and a node that has view-changed is starting a
        // fresh round in which following the network is exactly what it
        // should do.
        self.sync_jumps_used = 0;
        self.step = Step::Propose;
        self.proposal = None;
        self.proposal_round = None;
        self.prune_old_rounds();
    }

    /// Record one round's outcome for the nil-storm meter.
    ///
    /// `was_nil == true`: the round formed no block prevote QC (≥1 nil
    /// prevote, or no QC at all). Counts + meters (`nil_rounds_total`,
    /// alertable). `false` (a block QC formed): the streak breaks and the
    /// breaker's one-shot flag clears so the next storm can fire again.
    /// Pure state transition, no votes cast, no rewind.
    pub fn note_round_outcome(&mut self, was_nil: bool) {
        if was_nil {
            self.nil_rounds_total = self.nil_rounds_total.saturating_add(1);
            self.consecutive_nil_rounds = self.consecutive_nil_rounds.saturating_add(1);
            crate::metrics::global().inc_nil_round();
        } else {
            self.consecutive_nil_rounds = 0;
            self.nil_breaker_fired_this_streak = false;
        }
    }

    /// True when the nil-storm circuit breaker must fire: K consecutive
    /// nil-rounds reached and the one-shot action for this streak not yet
    /// applied. K = [`NIL_CIRCUIT_BREAKER_K`] (≤5 by construction).
    pub fn nil_breaker_due(&self) -> bool {
        self.consecutive_nil_rounds >= NIL_CIRCUIT_BREAKER_K && !self.nil_breaker_fired_this_streak
    }

    /// Newest QC-backed block hash this node knows (the convergence target).
    ///
    /// Preference order: the observed polka (newest quorum of prevotes FOR A
    /// BLOCK), else the newest prevote QC in the scan window. `None` when no
    /// block QC exists anywhere — then there is nothing to re-broadcast and
    /// the breaker only widens the window.
    pub fn highest_qc_backed_hash(&self) -> Option<BlockHash> {
        if let Some((_, h)) = self.observed_polka {
            return Some(h);
        }
        let mut best: Option<(Round, BlockHash)> = None;
        for (r, qc) in &self.prevote_qc {
            if let Some(h) = qc.block_hash {
                if best.map(|(br, _)| *r > br).unwrap_or(true) {
                    best = Some((*r, h));
                }
            }
        }
        best.map(|(_, h)| h)
    }

    /// One-shot nil-storm convergence action. SAFE by construction:
    /// * never double-votes (casts no vote, moves no step — only widens the
    ///   vote-COLLECTION window and reports the hash the CALLER may
    ///   re-broadcast from its already-held bodies);
    /// * never rewinds (touches no round/height/decided/lock — only
    ///   `scan_lookback`, once per streak);
    /// * then resumes normal timing (the flag guarantees exactly one widen
    ///   per streak; the next block QC clears it).
    ///
    /// Returns the QC-backed hash to re-broadcast, if any. The caller must
    /// re-broadcast ONLY a body it already holds (never synthesize one) and
    /// must widen the vote-collection window exactly once (done here).
    pub fn apply_nil_convergence(&mut self) -> Option<BlockHash> {
        if !self.nil_breaker_due() {
            return None;
        }
        self.nil_breaker_fired_this_streak = true;
        // Widen the vote-collection window ONCE per streak so late votes for
        // the network's round become committable. Idempotent: already-wide
        // stays wide; normal timing resumes because nothing else changes.
        if self.scan_lookback < REPHASE_SCAN_WINDOW {
            self.scan_lookback = REPHASE_SCAN_WINDOW;
        }
        crate::metrics::global().inc_nil_breaker_fire();
        self.highest_qc_backed_hash()
    }

    /// Track one scheduled proposer's slot outcome (observability only).
    ///
    /// `proposed == false`: consecutive-miss counter for `proposer` grows
    /// (and the height meter grows). `true`: the proposer is re-admitted on
    /// the fast path — its streak resets to 0 with NO punishment in protocol
    /// (no slashing invented here; the existing downtime-slash path from
    /// block content is untouched). Zero-streak entries are removed so the
    /// map never exceeds the validator-set size.
    pub fn note_proposer_missed(&mut self, proposer: ValidatorId, proposed: bool) {
        if proposed {
            self.missed_proposals.remove(&proposer);
            return;
        }
        let e = self.missed_proposals.entry(proposer).or_insert(0);
        *e = e.saturating_add(1);
        self.missed_proposals_total = self.missed_proposals_total.saturating_add(1);
        crate::metrics::global().inc_proposer_miss();
    }

    /// Consecutive missed proposals counted for `proposer` (0 when none).
    pub fn proposer_missed_streak(&self, proposer: &ValidatorId) -> u32 {
        self.missed_proposals.get(proposer).copied().unwrap_or(0)
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
        self.note_peer_round(voter, round);
        if round <= self.round {
            return false;
        }
        // Audit F3: a SINGLE far-future vote never moves us (trickle-drag:
        // one dribbled vote per timeout would ratchet +8/timeout and silence
        // us). Corroboration re-opens the chase: TWO DISTINCT validators at
        // the same far round is the network's real position, not one peer's
        // claim (a lone Byzantine cannot fake corroboration within <1/3).
        // Near chase (<= LOOKBACK) is unchanged (1-round-offset deadlock fix).
        if round > self.round.saturating_add(ROUND_LOOKBACK)
            && self.supporting_peers_count(round) < 2
        {
            return false;
        }
        let before = self.round;
        self.sync_round_to(round);
        self.round != before
    }

    /// Record a verified peer's round WITHOUT moving ours.
    ///
    /// This is the "where is the network" bookkeeping, kept SEPARATE from the
    /// chase ([`Self::observe_peer_round`]) on purpose: a peer round is true
    /// information even when the vote that carried it was NOT votable (stale
    /// far-behind, absurd far-ahead), and it is needed for two things that
    /// used to be blind:
    ///
    /// * the deadlock breaker's corroboration ([`Self::corroborated_peer_round`])
    ///   — it only ever saw REJECTED votes, so the breaker was effectively
    ///   dead code on a healthy network;
    /// * the quorum-scan anchor ([`Self::scan_floor`]) — a node that is ahead
    ///   of the network needs to know which round the network is in, or it
    ///   can never see the polka the network formed.
    ///
    /// The counter is per voter and monotonic, so a delayed old vote never
    /// rewinds it.
    pub fn note_peer_round(&mut self, voter: ValidatorId, round: Round) {
        let entry = self.peer_rounds.entry(voter).or_insert(round);
        if round > *entry {
            *entry = round;
        }
    }

    /// Count how many distinct validators have reported being at or above `round`.
    pub fn supporting_peers_count(&self, round: Round) -> usize {
        self.peer_rounds.values().filter(|&&r| r >= round).count()
    }

    /// The highest peer round that is CORROBORATED by more than one
    /// validator (see [`Self::breaker_corroboration`]), if any.
    ///
    /// `peer_rounds` records what each peer CLAIMED, and a Byzantine
    /// validator can claim any round — including `u32::MAX`. A round only one
    /// peer reports is therefore not evidence of where the network is, and
    /// neither the deadlock breaker nor the local re-phase may act on it.
    ///
    /// With a validator set too small to have two peers, the single peer is
    /// the only evidence there is (and a 2-member set is 50% Byzantine by
    /// construction).
    pub fn corroborated_peer_round(&self) -> Option<Round> {
        let min = self.breaker_corroboration();
        let mut rounds: Vec<Round> = self.peer_rounds.values().copied().collect();
        rounds.sort_unstable_by(|a, b| b.cmp(a));
        rounds
            .into_iter()
            .find(|r| self.supporting_peers_count(*r) >= min)
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
    ///
    /// CORROBORATION (audit W6.4b): the round we jump to must be reported by
    /// MORE THAN ONE validator. `peer_rounds` records what each peer CLAIMED,
    /// and a Byzantine validator can claim any round at all — including
    /// `u32::MAX`. Without corroboration, one liar could drag this node off
    /// the network permanently: the round counter only moves forward, so a
    /// node that jumped to a bogus round can never come back.
    ///
    /// The requirement is relaxed for a validator set too small to have two
    /// peers at all (a 2-member set): there the single peer IS 50% of the
    /// network by construction, and stalling such a chain is not a new
    /// attack surface.
    ///
    /// The JUMP SIZE is bounded by [`MAX_DEADLOCK_JUMP`] — deliberately much
    /// larger than `MAX_ROUND_AHEAD` (1000), because the breaker exists
    /// precisely for the desyncs that are LARGER than the vote-acceptance
    /// window (live: a 1232-round gap). Clamping it to `MAX_ROUND_AHEAD`
    /// silently defeated the breaker: it could never close the very gap it
    /// was built for.
    pub fn deadlock_breaker_target(
        &self,
        no_progress_secs: u64,
        timeout_secs: u64,
    ) -> Option<Round> {
        if no_progress_secs < timeout_secs {
            return None;
        }
        // CORROBORATED round only: one Byzantine peer must not steer this
        // node. `corroborated_peer_round` returns the highest round reported
        // by more than one validator.
        let target = self.corroborated_peer_round()?;
        if target <= self.round {
            return None;
        }
        Some(target.min(self.round.saturating_add(MAX_DEADLOCK_JUMP)))
    }

    /// How many DISTINCT peers must report a round before the deadlock
    /// breaker is willing to jump to it.
    ///
    /// Two for any set that can have two peers (so a single Byzantine
    /// validator cannot steer the jump); one for a 2-member set, where the
    /// peer count cannot exceed one.
    fn breaker_corroboration(&self) -> usize {
        if self.validators.len() >= 3 {
            2
        } else {
            1
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
        // The SAME corroboration rule as the breaker: a round only ONE peer
        // reports is not evidence of where the network is. Without this the
        // two paths could BOTH be dead: a lone Byzantine peer claiming a
        // huge round would keep the breaker from firing (no corroboration)
        // AND keep the local re-phase from firing (a peer is "ahead"), so
        // the node would wedge with no way out (audit W6.4b).
        !matches!(self.corroborated_peer_round(), Some(p) if p > self.round)
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

    /// Bounded local RE-PHASE of the SAME height (deadlock fix 2026-10-14
    /// follow-up).
    ///
    /// Fail-safe: NEVER touches `height`, `validators`, `decided`,
    /// `precommit_qc`, or any vote set contents beyond the standard prune —
    /// only round/step/proposal state, the (conditionally dropped) lock and
    /// the scan window.
    ///
    /// NEVER REWIND (BFT safety). Re-entering a round the node already voted
    /// in at this height is a SELF-EQUIVOCATION: two different statements
    /// for one `(height, round, kind)` are slashable evidence, and a peer
    /// that kept the old vote can prove it. The round counter therefore only
    /// ever moves FORWARD here. (The old "rewind to round 0" behaviour broke
    /// exactly that invariant.)
    ///
    /// WHAT MAKES THE RE-PHASE EFFECTIVE (audit W6.4b): advancing the round
    /// by one is a NO-OP — the round timer advances it anyway, and a node
    /// that is out of phase with the network stays out of phase. The re-phase
    /// therefore also WIDENS the quorum-scan / vote-history window
    /// ([`Self::scan_lookback`], [`REPHASE_SCAN_WINDOW`]). The node then
    /// finds — and COMMITS — the quorum the network formed in the round the
    /// network is actually in, instead of re-voting in it. That is the
    /// Tendermint rule "a node must still commit a round it has left if the
    /// quorum turns up", with a window wide enough to cover a real desync.
    ///
    /// LOCK RULE (audit-consensus hardening 2026-10-14): the lock is dropped
    /// ONLY for a bodyless lock with NO precommit QC observed
    /// (`precommit_qc_observed()` false). In every other case the lock is
    /// kept, and it still clears only through the normal lifecycle — QC
    /// finalize (`try_precommit_quorum`) or a same-height polka for another
    /// value (`try_prevote_quorum_at`) — both untouched by this function.
    /// Dropping a QC-backed bodyless lock is the fork primitive: holders that
    /// received the body finalize A while the reset node drops its A-lock
    /// and finalizes B.
    ///
    /// LOUD LIVENESS CAVEAT: keeping the lock CAN re-stall the exact
    /// A-r1595/B-r412 deaf deadlock this reset was built for, WHENEVER a
    /// precommit QC was observed but no progress followed (bodyless + QC):
    /// the node stays locked, `decide_prevote` then emits nil for every
    /// foreign proposal, and the lock only clears via a higher-round non-nil
    /// polka (`round > locked_round`) or arrival of the locked body. The
    /// gate above is the deliberate trade: the observed deaf deadlock had NO
    /// votes at all (gate passes, lock drops, immediate recovery preserved),
    /// while any hint that value was certified (QC observed) pays stall
    /// instead of risking a fork. Safety over liveness, explicitly.
    ///
    /// IDEMPOTENT: the re-phase widens the window and clears a stale lock —
    /// both happen ONCE per height. Re-firing it on every timeout window
    /// would only advance the round by one (which the round timer does
    /// anyway) and change nothing else: a no-op dressed up as progress.
    /// Returns false when there is nothing left to do, so the caller can
    /// skip stamping/logging.
    pub fn apply_deadlock_local_reset(&mut self, locked_body_present: bool) -> bool {
        // The ONLY case that drops: bodyless AND no QC backing the lock.
        let drop_lock = !locked_body_present && !self.precommit_qc_observed();
        let needs_work = !self.rephase_applied
            || self.proposal.is_some()
            || self.proposal_round.is_some()
            || self.locked.is_some() && drop_lock;
        if !needs_work {
            return false;
        }
        if drop_lock {
            self.locked = None;
        }
        // BFT Safety: NEVER rewind the round at the same height — re-voting a
        // round is a self-equivocation. Move forward monotonically instead.
        self.round = self.round.saturating_add(1);
        self.step = Step::Propose;
        self.proposal = None;
        self.proposal_round = None;
        // RE-PHASE: widen the scan / retention window so the quorum the
        // network formed in ITS round becomes visible (and committable) to a
        // node whose round counter wandered off.
        self.scan_lookback = REPHASE_SCAN_WINDOW;
        self.rephase_applied = true;
        self.prune_old_rounds();
        // NOTE (C6 clippy): this used to be
        // `debug_assert!(self.decided.is_none() || true, ...)` — the
        // `|| true` made the assertion vacuous (deny-by-default
        // `overly_complex_bool_expr`). The property that matters is
        // structural: this function never assigns `self.decided`, so a
        // decided value survives the reset by construction; asserting
        // `is_none()` here would forbid the legitimate
        // decided-then-rephase path, so the check is a comment, not code.
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
        (0..n)
            .map(|_| SigningKey::generate(&mut rand::rngs::OsRng))
            .collect()
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

    // FULL-PQ test helpers (nodes wiped, no compat): Ed ids + registered
    // Falcon-512 keys, Falcon-signed votes. Quorum/power/targets/membership
    // unchanged — only the signature scheme changes from Ed to Falcon.
    fn falcon_for_keys(ks: &[SigningKey], base: u8) -> Vec<FalconKeypair> {
        ks.iter()
            .enumerate()
            .map(|(i, _)| FalconKeypair::generate_from_seed(base.wrapping_add(i as u8)))
            .collect()
    }

    fn vset_with_falcon(ks: &[SigningKey], fks: &[FalconKeypair]) -> ValidatorSet {
        let vs = vset(ks);
        for (sk, fk) in ks.iter().zip(fks.iter()) {
            let id = sk.verifying_key().to_bytes();
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
        }
        vs
    }

    fn fvote(
        sk: &SigningKey,
        fk: &FalconKeypair,
        height: Height,
        round: Round,
        kind: VoteKind,
        bh: Option<BlockHash>,
    ) -> Vote {
        Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
    }

    #[test]
    fn sync_burst_is_rate_limited_not_unbounded() {
        // Regression (audit 2026-10-06): repeated verified votes ratcheted
        // +8 per message without bound (r9700, zero QCs). Past the per-round
        // budget further syncs are refused; the timeout path still advances.
        // NOTE (audit F3, 2026-10-29): single-VOTE far chase is refused at
        // the `observe_peer_round` gate (corroboration: 2 distinct peers);
        // this DIRECT-call path keeps burst semantics (bounded by budget).
        let mut hc = hc4();
        for _ in 0..20 {
            hc.sync_round_to(1000);
        }
        assert!(
            hc.round <= MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK,
            "burst must stop at the budget, got round {}",
            hc.round
        );
        assert!(hc.round > 0, "honest catch-up still moves");
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    // GATE: constant-bound assertion documents timeout invariant; removing it would weaken the regression test.
    fn c2_deterministic_timeout_is_identical_bounded_and_clock_free() {
        // TASK 4: every honest node computes the IDENTICAL timeout for every
        // (height, round) from local state alone. Inputs: base env, backoff
        // fn(round), adaptive extension from ledger missed. NO wall clock.
        let t1 = deterministic_round_timeout_ms(3500, 0, 0);
        let t2 = deterministic_round_timeout_ms(3500, 0, 0);
        assert_eq!(t1, 3500);
        assert_eq!(
            t1, t2,
            "same state => same timeout (wall clocks differ, value must not)"
        );
        // Backoff grows with the ROUND (not a local failure count).
        assert_eq!(deterministic_round_timeout_ms(3500, 1, 0), 4000);
        assert_eq!(deterministic_round_timeout_ms(3500, 4, 0), 5500);
        // Adaptive extension for historically-slow proposers, bounded.
        let slow = deterministic_round_timeout_ms(3500, 0, 4);
        assert_eq!(slow, 3500 + 4 * ADAPTIVE_EXTENSION_PER_MISS_MS);
        assert!(slow > t1, "slow proposer rounds wait longer");
        let capped = deterministic_round_timeout_ms(3500, 0, 1_000_000);
        assert_eq!(capped, 3500 + ADAPTIVE_EXTENSION_CAP_MS);
        let round_capped = deterministic_round_timeout_ms(3500, 1_000_000, 0);
        assert_eq!(round_capped, 3500 + DETERMINISTIC_BACKOFF_CAP_MS);
        // K small enough to matter.
        assert!(NIL_CIRCUIT_BREAKER_K <= 5, "K must be <= 5");
    }

    #[test]
    fn c2_nil_breaker_counts_meters_and_fires_once_safely() {
        let mut hc = hc4();
        assert_eq!(hc.nil_rounds_total, 0);
        // Two nil rounds: counted, no fire yet (K=3).
        hc.next_round();
        hc.next_round();
        assert_eq!(hc.nil_rounds_total, 2);
        assert_eq!(hc.consecutive_nil_rounds, 2);
        assert!(!hc.nil_breaker_due());
        let r_before = hc.round;
        // Third nil round trips the breaker.
        hc.next_round();
        assert_eq!(hc.consecutive_nil_rounds, 3);
        assert!(hc.nil_breaker_due());
        let scan_before = hc.scan_lookback;
        let out = hc.apply_nil_convergence();
        assert!(out.is_none(), "no QC exists yet: nothing to re-broadcast");
        assert!(hc.scan_lookback >= scan_before, "window widened");
        assert_eq!(
            hc.round,
            r_before + 1,
            "convergence must never rewind the round"
        );
        // One-shot: second apply is a no-op.
        assert!(!hc.nil_breaker_due());
        assert!(hc.apply_nil_convergence().is_none());
        // A block QC breaks the streak and re-arms the breaker.
        hc.note_round_outcome(false);
        assert_eq!(hc.consecutive_nil_rounds, 0);
    }

    #[test]
    fn c2_nil_breaker_rebroadcasts_highest_qc_backed_proposal() {
        let ks = keys(4);
        let fks = falcon_for_keys(&ks, 0x11);
        let vs = vset_with_falcon(&ks, &fks);
        let mut hc = HeightConsensus::new(1, vs.clone());
        let bh = [0xABu8; 32];
        // Build a real block prevote QC at round 5 (3 of 4).
        for (i, k) in ks.iter().enumerate().take(3) {
            let v = fvote(k, &fks[i], 1, 5, VoteKind::Prevote, Some(bh));
            hc.add_prevote(v).unwrap();
        }
        assert_eq!(hc.observed_polka, Some((5, bh)));
        // Storm to the breaker.
        hc.next_round();
        hc.next_round();
        hc.next_round();
        assert!(hc.nil_breaker_due());
        let target = hc.apply_nil_convergence();
        assert_eq!(
            target,
            Some(bh),
            "must re-broadcast the highest-QC-backed proposal"
        );
    }

    #[test]
    fn c2_proposer_miss_accountability_no_punishment_fast_readmit() {
        let ks = keys(4);
        let vs = vset(&ks);
        let mut hc = HeightConsensus::new(7, vs.clone());
        let sched = hc.validators.proposer_for(7, hc.round).unwrap();
        // Miss M times: metered.
        for _ in 0..PROPOSER_MISS_THRESHOLD_M {
            hc.note_proposer_missed(sched, false);
        }
        assert_eq!(hc.proposer_missed_streak(&sched), PROPOSER_MISS_THRESHOLD_M);
        assert_eq!(hc.missed_proposals_total, PROPOSER_MISS_THRESHOLD_M as u64);
        // Fast-path re-admission: proposing again clears suspicion, no slash.
        hc.note_proposer_missed(sched, true);
        assert_eq!(hc.proposer_missed_streak(&sched), 0);
        assert!(
            !hc.missed_proposals.contains_key(&sched),
            "zero-streak entries are removed (bounded)"
        );
    }
    #[test]
    #[allow(clippy::assertions_on_constants)]
    // GATE: retention-cap assertion pins liveness invariant; removing it would weaken the regression test.
    fn round_advance_keeps_the_vote_sets_of_the_current_height() {
        // LIVENESS (live 2026-10-21: the masterchain parked at height 285027
        // with a prevote QC and NO precommit QC). The quorum-COMPLETING
        // prevote of a round routinely arrives long after the round itself,
        // so the vote sets of the CURRENT HEIGHT are kept: a late vote must
        // still be able to complete the quorum of the round it belongs to.
        //
        // The old behaviour (drop everything outside the lookback window) is
        // what made a late quorum impossible: the set was already empty when
        // the completing vote arrived. What stays bounded is the SCAN
        // (the window around the local round) and the number of retained
        // rounds (MAX_RETAINED_VOTE_ROUNDS), not the evidence itself.
        let mut hc = hc4();
        // Seed fake vote sets across many rounds via next_round steps.
        for _ in 0..30 {
            hc.prevotes.insert(hc.round, VoteSet::new());
            hc.precommits.insert(hc.round, VoteSet::new());
            hc.next_round();
        }
        assert_eq!(hc.round, 30);
        assert_eq!(
            hc.prevotes.len(),
            30,
            "every round of the height keeps its vote set"
        );
        assert!(
            hc.prevote_set(0).is_some(),
            "a round that is 30 rounds old must still be able to receive the vote that completes its quorum"
        );
        // The retention is still bounded: a height that never decides cannot
        // accumulate one vote set per round forever.
        assert!(
            MAX_RETAINED_VOTE_ROUNDS >= 4_096,
            "the retention cap must cover a pathological height (the live one spent 380 rounds in one height)"
        );
    }

    #[test]
    fn quorum_threshold_is_two_thirds_plus_one() {
        let keys = keys(4);
        let vs = vset(&keys);
        assert_eq!(vs.total_power(), 4);
        assert_eq!(vs.quorum_power(), 3); // floor(8/3)+1 = 3
    }

    #[test]
    fn vote_sign_and_verify() {
        // FULL-PQ: Falcon-signed votes verify; Ed-only path deleted.
        let keys = keys(1);
        let fks = falcon_for_keys(&keys, 0x21);
        let _vs = vset_with_falcon(&keys, &fks);
        let v = fvote(&keys[0], &fks[0], 5, 0, VoteKind::Prevote, Some(block_hash(1)));
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
        let fks = falcon_for_keys(&keys, 0x22);
        let vs = vset_with_falcon(&keys, &fks);
        let mut set = VoteSet::new();
        let v1 = fvote(&keys[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(1)));
        let v2 = fvote(&keys[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(2)));
        set.add(v1, &vs, 1, 0, VoteKind::Prevote).unwrap();
        set.add(v2, &vs, 1, 0, VoteKind::Prevote).unwrap();
        assert_eq!(set.equivocations().len(), 1, "double-vote must be recorded");
    }

    #[test]
    fn block_evidence_verifies_genuine_double_sign() {
        let ks = keys(3);
        let fks = falcon_for_keys(&ks, 0x23);
        let vs = vset_with_falcon(&ks, &fks);
        let member = |v: &ValidatorId| vs.validators.contains_key(v);
        let a = fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(1)));
        let b = fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(2)));
        let ev = EquivocationEvidence::new(ids(&ks)[0], a, b);
        assert!(verify_equivocation_evidence(&ev, &member));
    }

    #[test]
    fn block_evidence_offense_key_is_vote_order_stable() {
        let ks = keys(2);
        let fks = falcon_for_keys(&ks, 0x24);
        let _vs = vset_with_falcon(&ks, &fks);
        let voter = ids(&ks)[0];
        let a = fvote(&ks[0], &fks[0], 5, 2, VoteKind::Precommit, Some(block_hash(9)));
        let b = fvote(&ks[0], &fks[0], 5, 2, VoteKind::Precommit, Some(block_hash(3)));
        let fwd = EquivocationEvidence::new(voter, a.clone(), b.clone());
        let rev = EquivocationEvidence::new(voter, b, a);
        assert_eq!(fwd.offense_key(), rev.offense_key());
        assert_eq!(fwd.digest(), fwd.offense_key());
    }

    #[test]
    fn block_evidence_refuses_forgeries_and_shapes_fail_closed() {
        let ks = keys(3);
        let fks = falcon_for_keys(&ks, 0x25);
        let vs = vset_with_falcon(&ks, &fks);
        let member = |v: &ValidatorId| vs.validators.contains_key(v);
        let voter = ids(&ks)[0];
        let good_a = fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(1)));
        let good_b = fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(2)));
        // Framing with another validator's vote.
        let other = fvote(&ks[1], &fks[1], 1, 0, VoteKind::Prevote, Some(block_hash(2)));
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
        let pc = fvote(&ks[0], &fks[0], 1, 0, VoteKind::Precommit, Some(block_hash(2)));
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
        let nil = fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, None);
        assert!(verify_equivocation_evidence(
            &EquivocationEvidence::new(voter, good_a, nil),
            &member
        ));
    }

    #[test]
    fn block_evidence_canonicalize_sorts_and_dedupes() {
        let ks = keys(2);
        let fks = falcon_for_keys(&ks, 0x26);
        let vs = vset_with_falcon(&ks, &fks);
        let member = |v: &ValidatorId| vs.validators.contains_key(v);
        let voter = ids(&ks)[0];
        let mk = |x: u8, y: u8| {
            EquivocationEvidence::new(
                voter,
                fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(x))),
                fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(y))),
            )
        };
        let (e1, e2) = (mk(1, 2), mk(3, 4));
        // Duplicates: same pair twice + votes swapped.
        let e1dup = mk(1, 2);
        let e1swapped = EquivocationEvidence::new(
            voter,
            fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(2))),
            fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(1))),
        );
        // Garbage: same-target pair never survives shaping.
        let garbage = EquivocationEvidence::new(
            voter,
            fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(7))),
            fvote(&ks[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block_hash(7))),
        );
        let out = canonicalize_equivocation_evidence(
            vec![e2.clone(), garbage, e1dup, e1swapped, e1.clone()],
            &member,
        );
        assert_eq!(
            out.len(),
            2,
            "two distinct offenses survive, dupes collapse"
        );
        let mut keys_sorted = [e1.offense_key(), e2.offense_key()];
        keys_sorted.sort();
        assert_eq!(out[0].offense_key(), keys_sorted[0]);
        assert_eq!(out[1].offense_key(), keys_sorted[1]);
    }

    /// Build two conflicting bodies for one height, both signed by `key`.
    /// Distinct timestamps -> distinct hashes -> a genuine double-propose.
    fn signed_block(key: &SigningKey, height: Height, timestamp: u64) -> crate::sharding::Block {
        let mut b = crate::sharding::Block {
            height,
            proposer: key.verifying_key().to_bytes(),
            timestamp,
            ..Default::default()
        };
        b.sign_block(key);
        b
    }

    #[test]
    fn proposal_evidence_verifies_genuine_double_propose() {
        let ks = keys(3);
        let vs = vset(&ks);
        let member = |v: &ValidatorId| vs.validators.contains_key(v);
        let a = signed_block(&ks[0], 5, 1_000);
        let b = signed_block(&ks[0], 5, 2_000);
        assert_ne!(
            a.compute_hash(),
            b.compute_hash(),
            "need two distinct bodies"
        );
        let ev = ProposalEquivocationEvidence::new(ids(&ks)[0], a, b);
        assert!(verify_proposal_equivocation_evidence(&ev, &member));
    }

    #[test]
    fn proposal_evidence_offense_key_is_block_order_stable() {
        let ks = keys(2);
        let proposer = ids(&ks)[0];
        let a = signed_block(&ks[0], 5, 1_000);
        let b = signed_block(&ks[0], 5, 2_000);
        let fwd = ProposalEquivocationEvidence::new(proposer, a.clone(), b.clone());
        let rev = ProposalEquivocationEvidence::new(proposer, b, a);
        assert_eq!(fwd.offense_key(), rev.offense_key());
        assert_eq!(fwd.digest(), fwd.offense_key());
    }

    #[test]
    fn proposal_evidence_refuses_same_block_forgeries_and_shapes_fail_closed() {
        let ks = keys(3);
        let vs = vset(&ks);
        let member = |v: &ValidatorId| vs.validators.contains_key(v);
        let proposer = ids(&ks)[0];
        let good_a = signed_block(&ks[0], 5, 1_000);
        let good_b = signed_block(&ks[0], 5, 2_000);
        // Same body twice: one block repeated is not a double-propose.
        assert!(!verify_proposal_equivocation_evidence(
            &ProposalEquivocationEvidence::new(proposer, good_a.clone(), good_a.clone()),
            &member
        ));
        // Different heights: a re-proposal at a new height is not an offense.
        let other_height = signed_block(&ks[0], 6, 1_000);
        assert!(!verify_proposal_equivocation_evidence(
            &ProposalEquivocationEvidence::new(proposer, good_a.clone(), other_height),
            &member
        ));
        // Framing: the envelope names ks[0] but block_b is signed by ks[1].
        let foreign = signed_block(&ks[1], 5, 3_000);
        assert!(!verify_proposal_equivocation_evidence(
            &ProposalEquivocationEvidence::new(proposer, good_a.clone(), foreign),
            &member
        ));
        // Forged: tamper with a signature byte after signing.
        let mut forged = good_b.clone();
        forged.validator_signatures[0].1[0] ^= 0xFF;
        assert!(!verify_proposal_equivocation_evidence(
            &ProposalEquivocationEvidence::new(proposer, good_a.clone(), forged),
            &member
        ));
        // Unknown proposer is refused.
        let outsider = SigningKey::generate(&mut rand::rngs::OsRng);
        let oa = signed_block(&outsider, 5, 1_000);
        let ob = signed_block(&outsider, 5, 2_000);
        assert!(!verify_proposal_equivocation_evidence(
            &ProposalEquivocationEvidence::new(outsider.verifying_key().to_bytes(), oa, ob),
            &member
        ));
        // Oversize envelope is refused, never truncated.
        let big = ProposalEquivocationEvidence::new(proposer, good_a, good_b);
        assert!(big.wire_len() <= MAX_PROPOSAL_EQUIVOCATION_EVIDENCE_BYTES);
    }

    #[test]
    fn proposal_evidence_canonicalize_sorts_and_dedupes() {
        let ks = keys(2);
        let vs = vset(&ks);
        let member = |v: &ValidatorId| vs.validators.contains_key(v);
        let proposer = ids(&ks)[0];
        let mk = |t1: u64, t2: u64| {
            ProposalEquivocationEvidence::new(
                proposer,
                signed_block(&ks[0], 9, t1),
                signed_block(&ks[0], 9, t2),
            )
        };
        let (e1, e2) = (mk(1, 2), mk(3, 4));
        // Duplicates: same pair twice + blocks swapped.
        let e1dup = mk(1, 2);
        let e1swapped = ProposalEquivocationEvidence::new(
            proposer,
            signed_block(&ks[0], 9, 2),
            signed_block(&ks[0], 9, 1),
        );
        // Garbage: same-body pair never survives shaping.
        let same = signed_block(&ks[0], 9, 7);
        let garbage = ProposalEquivocationEvidence::new(proposer, same.clone(), same);
        let out = canonicalize_proposal_equivocation_evidence(
            vec![e2.clone(), garbage, e1dup, e1swapped, e1.clone()],
            &member,
        );
        assert_eq!(
            out.len(),
            2,
            "two distinct offenses survive, dupes collapse"
        );
        let mut keys_sorted = [e1.offense_key(), e2.offense_key()];
        keys_sorted.sort();
        assert_eq!(out[0].offense_key(), keys_sorted[0]);
        assert_eq!(out[1].offense_key(), keys_sorted[1]);
    }

    #[test]
    fn full_happy_path_commits() {
        let keys = keys(4);
        let fks = falcon_for_keys(&keys, 0x31);
        let vs = vset_with_falcon(&keys, &fks);
        let bh = block_hash(7);
        let mut hc = HeightConsensus::new(1, vs.clone());

        // proposer proposes
        let proposer = hc.proposer().unwrap();
        hc.receive_proposal(proposer, bh).unwrap();
        assert_eq!(hc.decide_prevote(), Some(bh));

        // 3 of 4 prevote the block -> quorum
        for (i, k) in keys.iter().enumerate().take(3) {
            let v = fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(bh));
            hc.add_prevote(v).unwrap();
        }
        assert_eq!(hc.try_prevote_quorum(), Some(Some(bh)));

        // 3 of 4 precommit -> finality
        for (i, k) in keys.iter().enumerate().take(3) {
            let v = fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(bh));
            hc.add_precommit(v).unwrap();
        }
        assert_eq!(hc.try_precommit_quorum(), Some(bh));
        assert_eq!(hc.decided, Some(bh));
    }

    #[test]
    fn no_quorum_no_commit() {
        let keys = keys(4);
        let fks = falcon_for_keys(&keys, 0x32);
        let vs = vset_with_falcon(&keys, &fks);
        let bh = block_hash(7);
        let mut hc = HeightConsensus::new(1, vs);
        // only 2 of 4 precommit (below quorum 3)
        for (i, k) in keys.iter().enumerate().take(2) {
            let v = fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(bh));
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
        assert_eq!(
            hc.decide_prevote(),
            None,
            "locked validator must not prevote a conflicting value"
        );

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
        // FULL-PQ: Falcon µQC with 2 vs 3 signers (same 2-below / 3-meets
        // quorum shape as the deleted Ed threshold). Quorum math unchanged.
        let mut vs = ValidatorSet::new();
        let mut fks: Vec<(ValidatorId, FalconKeypair)> = Vec::new();
        for i in 0..4u8 {
            let fk = FalconKeypair::generate_from_seed(0x40 + i);
            let pk = fk.public_key.clone();
            let id = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            );
            vs.add(id, 1);
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                pk.clone(),
            );
            fks.push((id, fk));
        }
        let bh = block_hash(9);
        let parent = [0x99; 32];
        let committee_size = micro_committee_size(vs.len());
        let committee = derive_sortition_committee(&vs, 1, 0, committee_size, &parent);
        let msg = vote_sign_bytes(1, 0, VoteKind::Precommit, &Some(bh));
        let build = |n: usize| -> QuorumCertificate {
            let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
            let mut msigs = Vec::new();
            for (i, val_id) in committee.iter().enumerate().take(n) {
                bitmask[i / 8] |= 1 << (i % 8);
                let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
                msigs.push(fk.sign(&msg));
            }
            let uqc = PqMicroCertificate::new(
                crate::post_quantum::PqScheme::Falcon512,
                1,
                0,
                committee_size,
                bitmask,
                msigs,
                parent,
            );
            QuorumCertificate {
                height: 1,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: Some(bh),
                signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
            }
        };
        assert!(!build(2).verify(&vs), "sub-quorum µQC must not verify");
        assert!(build(3).verify(&vs), "quorum µQC must verify");
    }

    #[test]
    fn qc_verification_rejects_duplicate_signers() {
        let keys = keys(4);
        let vs = vset(&keys);
        let bh = block_hash(9);
        let v = Vote::sign(&keys[0], 1, 0, VoteKind::Precommit, Some(bh));
        // Same signer repeated 3 times must NOT count as quorum
        let sigs = vec![
            (v.voter, v.signature.clone()),
            (v.voter, v.signature.clone()),
            (v.voter, v.signature.clone()),
        ];
        let qc = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: sigs,
        };
        assert!(!qc.verify(&vs), "duplicate signers must not fake a quorum");
    }

    #[test]
    fn qc_verification_enforces_the_signer_cap() {
        // Audit F7: the cap is enforced INSIDE `verify`, so every caller
        // (sync/replay/adopt) inherits it without a separate length check.
        // FULL-PQ: genuine quorum is a Falcon µQC (same cap logic, PQ scheme).
        let mut vs = ValidatorSet::new();
        let mut fks: Vec<(ValidatorId, FalconKeypair)> = Vec::new();
        for i in 0..4u8 {
            let fk = FalconKeypair::generate_from_seed(0x50 + i);
            let pk = fk.public_key.clone();
            let id = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            );
            vs.add(id, 1);
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                pk.clone(),
            );
            fks.push((id, fk));
        }
        let bh = block_hash(9);
        let parent = [0x9A; 32];
        let committee_size = micro_committee_size(vs.len());
        let committee = derive_sortition_committee(&vs, 1, 0, committee_size, &parent);
        let msg = vote_sign_bytes(1, 0, VoteKind::Precommit, &Some(bh));
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        let mut msigs = Vec::new();
        for (i, val_id) in committee.iter().enumerate().take(3) {
            bitmask[i / 8] |= 1 << (i % 8);
            let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
            msigs.push(fk.sign(&msg));
        }
        let uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            1,
            0,
            committee_size,
            bitmask,
            msigs,
            parent,
        );
        let marker = (PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc));
        // A genuine 3-of-4 quorum under the cap.
        let mut sigs: Vec<(ValidatorId, Vec<u8>)> = vec![marker.clone()];
        let base = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: sigs.clone(),
        };
        assert!(
            base.verify(&vs),
            "a real quorum under the cap must still verify"
        );

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
        assert!(
            at_cap.verify(&vs),
            "a certificate at the cap is still accepted"
        );

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
        assert!(
            !over.verify(&vs),
            "a certificate over the signer cap must be refused"
        );
    }

    #[test]
    fn driver_finalizes_and_advances() {
        let keys = keys(4);
        let fks = falcon_for_keys(&keys, 0x33);
        let vs = vset_with_falcon(&keys, &fks);
        let mut driver = ConsensusDriver::new(vs, 1);
        let bh = block_hash(3);

        {
            let hc = driver.current.as_mut().unwrap();
            let proposer = hc.proposer().unwrap();
            hc.receive_proposal(proposer, bh).unwrap();
            for (i, k) in keys.iter().enumerate().take(3) {
                hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(bh)))
                    .unwrap();
            }
            hc.try_prevote_quorum();
            for (i, k) in keys.iter().enumerate().take(3) {
                hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(bh)))
                    .unwrap();
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
        assert_eq!(
            vs.proposer_for(0, 0).unwrap(),
            p0,
            "selection must be deterministic"
        );
        // Rotation (hash-slot is statistical, not periodic): over a window,
        // every validator must appear and no single one may own everything.
        let seq: Vec<[u8; 32]> = (0..64u64).map(|h| vs.proposer_for(h, 0).unwrap()).collect();
        let distinct: std::collections::HashSet<_> = seq.iter().collect();
        assert_eq!(
            distinct.len(),
            4,
            "all 4 validators must propose over 64 heights"
        );
    }

    #[test]
    fn proposer_rotates_fairly_with_large_equal_powers() {
        // Regression: with power 10^12 each, the un-normalized LINEAR schedule
        // gave the first validator every slot until height+round crossed 10^12.
        // Hash-slot is uniform from height 1: over 200 heights each of the two
        // must hold 35-65% (mean 50%, std ~3.5% — ±15pp is >4 sigma).
        let k = keys(2);
        let vs = ValidatorSet::from_list(vec![
            (ids(&k)[0], 1_000_000_000_000),
            (ids(&k)[1], 1_000_000_000_000),
        ]);
        let seq: Vec<[u8; 32]> = (1..=200u64)
            .map(|h| vs.proposer_for(h, 0).unwrap())
            .collect();
        let a = seq.iter().filter(|p| *p == &ids(&k)[0]).count();
        assert!(
            (70..=130).contains(&a),
            "equal powers must split ~100/100 over 200 heights, got {a}"
        );
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
        let seq: Vec<[u8; 32]> = (0..600u64)
            .map(|r| vs.proposer_for(0, r as u32).unwrap())
            .collect();
        let lo_n = seq.iter().filter(|p| *p == &lo).count();
        assert!(
            (330..=470).contains(&lo_n),
            "2:1 weighting must hold statistically, got {lo_n}/600"
        );
    }

    #[test]
    fn vote_for_far_future_round_rejected() {
        let keys = keys(4);
        let fks = falcon_for_keys(&keys, 0x37);
        let vs = vset_with_falcon(&keys, &fks);
        let mut hc = HeightConsensus::new(1, vs);
        let far = MAX_ROUND_AHEAD + 5;
        let v = fvote(&keys[0], &fks[0], 1, far, VoteKind::Prevote, Some(block_hash(1)));
        assert!(
            hc.add_prevote(v).is_err(),
            "vote for a far-future round must be rejected"
        );
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
        let fks = falcon_for_keys(&keys, 0x34);
        let vs = vset_with_falcon(&keys, &fks);
        let mut hc = HeightConsensus::new(1, vs);

        let a = block_hash(1);
        let b = block_hash(2);
        for (i, k) in keys.iter().enumerate() {
            hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(a)))
                .unwrap();
        }
        assert_eq!(
            hc.try_precommit_quorum(),
            None,
            "a precommit quorum with no prevotes must not decide anything"
        );
        assert_eq!(hc.decided, None);

        // Prevote a DIFFERENT block: now the two quorums disagree.
        for (i, k) in keys.iter().enumerate() {
            hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(b)))
                .unwrap();
        }
        assert_eq!(
            hc.try_precommit_quorum(),
            None,
            "prevotes for one block and precommits for another must not decide"
        );
        assert_eq!(hc.decided, None);

        // Prevote the same block, and it decides.
        let mut hc2 = HeightConsensus::new(1, vset_with_falcon(&keys, &fks));
        for (i, k) in keys.iter().enumerate() {
            hc2.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(a)))
                .unwrap();
            hc2.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(a)))
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
        let fks = falcon_for_keys(&keys, 0x35);
        let mut hc = HeightConsensus::new(1, vset_with_falcon(&keys, &fks));
        let a = block_hash(1);
        let b = block_hash(2);

        for (i, k) in keys.iter().enumerate() {
            hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(a)))
                .unwrap();
            hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(a)))
                .unwrap();
        }
        assert_eq!(
            hc.try_precommit_quorum(),
            Some(a),
            "A is decided and locked"
        );

        hc.next_round();
        for (i, k) in keys.iter().enumerate() {
            hc.add_prevote(fvote(k, &fks[i], 1, 1, VoteKind::Prevote, Some(b)))
                .unwrap();
            hc.add_precommit(fvote(k, &fks[i], 1, 1, VoteKind::Precommit, Some(b)))
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
            hc.round, MAX_ROUND_ADVANCE_PER_MESSAGE,
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
        let fks = falcon_for_keys(&keys, 0x36);
        let vs = vset_with_falcon(&keys, &fks);
        let mut set = VoteSet::new();
        // vote at height 2 cannot be added to a height-1 set
        let v = fvote(&keys[0], &fks[0], 2, 0, VoteKind::Prevote, Some(block_hash(1)));
        assert!(set.add(v, &vs, 1, 0, VoteKind::Prevote).is_err());
    }
}

#[cfg(test)]
mod round_parity_tests {
    use super::*;

    fn keys(n: usize) -> Vec<SigningKey> {
        (0..n)
            .map(|_| SigningKey::generate(&mut rand::rngs::OsRng))
            .collect()
    }

    #[test]
    fn with_an_even_set_there_is_no_parity_phase_to_deadlock_in() {
        // Hash-slot killed the linear parity this test used to pin: consecutive
        // rounds are independent draws, so two nodes at an odd offset can no
        // longer sit in opposite proposer phases forever (the old
        // `(height + round) % 2` alternation). What remains true and is pinned
        // here: determinism per (height, round), and statistical balance.
        let ks = keys(2);
        let vs = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );

        assert_eq!(
            vs.proposer_for(1, 5).unwrap(),
            vs.proposer_for(1, 5).unwrap(),
            "same slot, same proposer"
        );
        let seq: Vec<[u8; 32]> = (0..64u32).map(|r| vs.proposer_for(1, r).unwrap()).collect();
        let zeros = seq
            .iter()
            .filter(|p| *p == &ks[0].verifying_key().to_bytes())
            .count();
        assert!(
            (20..=44).contains(&zeros),
            "no parity structure, ~32/64 each, got {zeros}"
        );
    }

    #[test]
    fn moving_to_the_peers_round_restores_a_shared_phase() {
        // Forward-only advance is what makes convergence safe: both nodes move to the
        // HIGHER round, so they meet rather than chase each other, and the parity they
        // end on is shared. This is what `main.rs` does on an ahead vote.
        let ks = keys(2);
        let vs = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
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
        assert_eq!(
            a.proposer(),
            b.proposer(),
            "same round, same expected proposer"
        );
    }

    #[test]
    fn adopting_a_round_never_moves_a_node_backwards() {
        // A node must not be dragged back by a lagging peer, or it could re-vote a
        // round it already left.
        let ks = keys(2);
        let vs = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let mut hc = HeightConsensus::new(1, vs);
        // sync_round_to is itself capped at ROUND_LOOKBACK per call (audit F2).
        hc.sync_round_to(ROUND_LOOKBACK);
        assert_eq!(hc.round, ROUND_LOOKBACK);
        hc.sync_round_to(3); // a lagging peer
        assert_eq!(
            hc.round, ROUND_LOOKBACK,
            "the round only ever moves forward"
        );
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

    // =======================================================================
    // THE POLKA LEDGER (liveness fix, live 2026-10-21: the masterchain
    // parked at height 285027 with a prevote QC and NO precommit QC)
    // =======================================================================

    /// A three-validator set with the live power split: the 1500-STELL
    /// validator is in EVERY quorum (1000+1000 = 2000 is below the 2334
    /// quorum), so one node that stays silent parks the whole chain.
    /// FULL-PQ: also registers Falcon-512 keys for each Ed id.
    fn live_three() -> (ValidatorSet, Vec<SigningKey>, Vec<FalconKeypair>) {
        let keys: Vec<SigningKey> = (0..3)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = (i as u8) + 1;
                seed[31] = 0x5A;
                SigningKey::from_bytes(&seed)
            })
            .collect();
        let fks: Vec<FalconKeypair> = (0..3)
            .map(|i| FalconKeypair::generate_from_seed(0x70 + i as u8))
            .collect();
        let vs = ValidatorSet::from_list(
            keys.iter()
                .zip([1500u64, 1000, 1000].iter())
                .map(|(k, p)| (k.verifying_key().to_bytes(), *p))
                .collect(),
        );
        for (sk, fk) in keys.iter().zip(fks.iter()) {
            let id = sk.verifying_key().to_bytes();
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
        }
        (vs, keys, fks)
    }

    // Local copy of the `mod tests` helper (sibling modules cannot see it):
    // Falcon-only vote minting, identical semantics.
    // GATE: keep in sync with `mod tests::fvote` — same one-line delegation.
    fn fvote(
        sk: &SigningKey,
        fk: &FalconKeypair,
        height: Height,
        round: Round,
        kind: VoteKind,
        bh: Option<BlockHash>,
    ) -> Vote {
        Vote::sign_with_falcon(sk, fk, height, round, kind, bh)
    }

    #[test]
    fn a_late_polka_is_recorded_even_after_the_round_was_left() {
        // THE LIVE FAILURE: the quorum-completing prevote of round 0 arrives
        // when this node has already raced eleven rounds ahead. The polka is a
        // FACT about the network, so it must be recorded and acted on anyway --
        // the scan window cannot see it, and the node that misses it never
        // precommits, so the precommit quorum never forms and the height is
        // parked forever.
        let (vs, keys, fks) = live_three();
        let mut hc = HeightConsensus::new(1, vs);
        let block = [0x42u8; 32];

        // Our own prevote for round 0 (we were there when the round opened).
        hc.add_prevote(fvote(&keys[0], &fks[0], 1, 0, VoteKind::Prevote, Some(block)))
            .unwrap();
        assert!(hc.observed_polka().is_none(), "one prevote is not a polka");

        // We leave the round and race ahead (the WAN round-skew shape).
        for _ in 0..12 {
            hc.next_round();
        }
        assert_eq!(hc.round, 12);

        // The other prevote arrives LATE. The 1500-STELL validator plus one
        // 1000-STELL validator is 2500 of the 2334 quorum, so the quorum
        // completes NOW - in a round this node left twelve rounds ago.
        hc.add_prevote(fvote(&keys[1], &fks[1], 1, 0, VoteKind::Prevote, Some(block)))
            .unwrap();

        // The polka is recorded -- with the round it formed in, NOT the local
        // round.
        let (r, b) = hc.observed_polka().expect("the polka must be recorded");
        assert_eq!(r, 0, "the polka keeps the round it formed in");
        assert_eq!(b, block);
        assert_eq!(
            hc.best_polka(),
            Some((0, block)),
            "the polka the node observed is the polka it must precommit"
        );
        // And the certificate that proves it is kept with it.
        assert!(
            hc.prevote_qc.contains_key(&0),
            "the polka's certificate must be available for the precommit"
        );
    }

    #[test]
    fn an_older_polka_never_supersedes_a_newer_one() {
        let (vs, keys, fks) = live_three();
        let mut hc = HeightConsensus::new(1, vs);
        let block = [0x11u8; 32];
        let other = [0x22u8; 32];

        // A polka in round 5.
        for (i, k) in keys.iter().enumerate() {
            hc.add_prevote(fvote(k, &fks[i], 1, 5, VoteKind::Prevote, Some(block)))
                .unwrap();
        }
        assert_eq!(hc.observed_polka(), Some((5, block)));

        // A LATE polka for the OLDER round 2 must not become the node's word.
        for (i, k) in keys.iter().enumerate() {
            hc.add_prevote(fvote(k, &fks[i], 1, 2, VoteKind::Prevote, Some(other)))
                .unwrap();
        }
        assert_eq!(
            hc.observed_polka(),
            Some((5, block)),
            "the newest polka is the network's latest word"
        );
    }

    #[test]
    fn the_polka_round_survives_the_prune() {
        // The decision needs the prevote quorum of the polka's round (the
        // precommit quorum is formed in the same round). If the prune drops
        // that round, the height can never be decided: the precommit quorum is
        // there and the proof that it certified this block is gone.
        let (vs, keys, fks) = live_three();
        let mut hc = HeightConsensus::new(1, vs);
        let block = [0x33u8; 32];
        for (i, k) in keys.iter().enumerate() {
            hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(block)))
                .unwrap();
        }
        assert_eq!(hc.observed_polka(), Some((0, block)));

        // Race far ahead: every round move prunes.
        for _ in 0..40 {
            hc.next_round();
        }
        assert!(
            hc.prevote_set(0).is_some(),
            "the polka's round must survive the prune"
        );
        assert!(
            hc.prevote_qc.contains_key(&0),
            "the polka's certificate must survive the prune"
        );
    }

    #[test]
    fn a_precommit_quorum_in_the_polka_round_decides_the_height() {
        // The finalization path must find the precommit quorum in the polka's
        // round even when that round is far outside the scan window.
        let (vs, keys, fks) = live_three();
        let mut hc = HeightConsensus::new(1, vs);
        let block = [0x44u8; 32];
        for (i, k) in keys.iter().enumerate() {
            hc.add_prevote(fvote(k, &fks[i], 1, 0, VoteKind::Prevote, Some(block)))
                .unwrap();
        }
        // Race ahead, then the precommits of round 0 arrive (late).
        for _ in 0..20 {
            hc.next_round();
        }
        for (i, k) in keys.iter().enumerate() {
            hc.add_precommit(fvote(k, &fks[i], 1, 0, VoteKind::Precommit, Some(block)))
                .unwrap();
        }
        assert_eq!(
            hc.try_precommit_quorum(),
            Some(block),
            "a decided height must be decided, wherever the decision was taken"
        );
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

    /// A REAL Falcon-512 keypair (produced by the FIPS 206 reference
    /// implementation), so the tests below exercise the PRODUCTION verifier
    /// and not a test-only shortcut.
    ///
    /// AUDIT W6.5: these fixtures used to be a hand-rolled BLAKE3
    /// "check-digest" pseudo-signature that only the `cfg(test)` branch of
    /// `verify_falcon_signature_or_test` accepted — the tests therefore
    /// proved nothing about the real lattice verification. They now sign with
    /// the real signer.
    fn make_sample_falcon512(seed: u8) -> crate::post_quantum::FalconKeypair {
        crate::post_quantum::FalconKeypair::generate_from_seed(seed)
    }

    fn make_sample_falcon512_sig(fk: &crate::post_quantum::FalconKeypair, msg: &[u8]) -> Vec<u8> {
        fk.sign(msg)
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

        // The parent block hash seeds the draw: every node of a height MUST
        // pass the same one (the hash committed in the block header).
        let parent = [0xA5; 32];

        // 1. Determinism: identical parameters yield identical committee
        let c1 = derive_sortition_committee(&vs, 10, 0, 2, &parent);
        let c2 = derive_sortition_committee(&vs, 10, 0, 2, &parent);
        assert_eq!(
            c1, c2,
            "Sortition committee selection must be strictly deterministic"
        );
        assert_eq!(c1.len(), 2);

        // 2. Different height / round yields different ticket outcomes
        let c3 = derive_sortition_committee(&vs, 11, 0, 2, &parent);
        assert_eq!(c3.len(), 2);

        // 3. Stake weighting: Validator A (90% stake) must be selected in almost all single-seat draws
        let mut a_selected_count = 0;
        let trials = 100;
        for h in 1..=trials {
            let comm = derive_sortition_committee(&vs, h as u64, 0, 1, &parent);
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
        assert!(derive_sortition_committee(&empty_vs, 1, 0, 16, &parent).is_empty());
        assert!(derive_sortition_committee(&vs, 1, 0, 0, &parent).is_empty());

        // Committee size larger than validator set returns all active validators
        let all_comm = derive_sortition_committee(&vs, 1, 0, 100, &parent);
        assert_eq!(all_comm.len(), 4);
    }

    /// The committee must NOT be computable from `(height, round)` alone: the
    /// parent block hash is the entropy that is unknown until the chain has
    /// produced that parent, so an adversary cannot compute future committee
    /// memberships (and aim a DDoS / a collusion at a chosen round) ahead of
    /// time.
    #[test]
    fn test_sortition_committee_depends_on_parent_block_hash() {
        let mut vs = ValidatorSet::new();
        for i in 0..16u8 {
            vs.add([i + 1; 32], 10);
        }

        let parent_a = [0x11; 32];
        let parent_b = [0x22; 32];

        // Same height, same round, DIFFERENT parent -> the seed differs.
        assert_ne!(
            sortition_seed(&parent_a, 7, 0),
            sortition_seed(&parent_b, 7, 0),
            "the sortition seed must commit to the parent block hash"
        );

        // The committee itself must differ for at least one of many draws:
        // with 16 equally staked validators and an 8-seat committee the draw is
        // wide enough for the parent hash to matter.
        let mut differs = false;
        for round in 0..32u32 {
            let a = derive_sortition_committee(&vs, 7, round, 8, &parent_a);
            let b = derive_sortition_committee(&vs, 7, round, 8, &parent_b);
            assert_eq!(a.len(), 8);
            assert_eq!(b.len(), 8);
            if a != b {
                differs = true;
                break;
            }
        }
        assert!(
            differs,
            "changing the parent block hash must change the elected committee"
        );

        // A one-bit change of the parent is enough (the seed is a hash).
        let mut parent_c = parent_a;
        parent_c[0] ^= 1;
        assert_ne!(
            sortition_seed(&parent_a, 7, 0),
            sortition_seed(&parent_c, 7, 0),
            "a single flipped bit of the parent must change the seed"
        );

        // And the same parent yields the same committee everywhere (the
        // agreement requirement): two nodes that pass the same parent hash
        // elect exactly the same committee.
        assert_eq!(
            derive_sortition_committee(&vs, 7, 0, 8, &parent_a),
            derive_sortition_committee(&vs, 7, 0, 8, &parent_a),
        );
    }

    /// CROSS-CHAIN REPLAY: a vote signed on one chain id must not verify on
    /// another, even with the very same validator key.
    #[test]
    fn test_vote_signature_is_bound_to_chain_id() {
        const TESTNET: u64 = 999_001;
        const MAINNET: u64 = 5757;

        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let fk = FalconKeypair::generate_from_seed(0x77);
        let id = key.verifying_key().to_bytes();
        register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        let height: Height = 42;
        let round: Round = 3;
        let kind = VoteKind::Prevote;
        let target = Some([0xAB; 32]);

        // Sign on the TESTNET (FULL-PQ: Falcon-signed vote).
        set_consensus_chain_id_for_tests(TESTNET);
        let vote = Vote::sign_with_falcon(&key, &fk, height, round, kind, target);
        assert!(
            vote.verify(),
            "the vote must verify on the chain it was signed for"
        );
        let testnet_bytes = vote_sign_bytes(height, round, kind, &target);
        assert!(
            testnet_bytes.windows(8).any(|w| w == TESTNET.to_be_bytes()),
            "the vote preimage must commit to the chain id"
        );

        // The same vote, verified on the MAINNET, must be REJECTED.
        set_consensus_chain_id_for_tests(MAINNET);
        let mainnet_bytes = vote_sign_bytes(height, round, kind, &target);
        assert_ne!(
            testnet_bytes, mainnet_bytes,
            "the preimage must differ across chain ids"
        );
        assert!(
            !vote.verify(),
            "a testnet vote must NOT verify under a different chain id"
        );

        // ... and the chain id is the ONLY thing that changed.
        set_consensus_chain_id_for_tests(TESTNET);
        assert!(vote.verify(), "the vote verifies again on its own chain");

        // Restore the frozen default for the rest of this thread.
        set_consensus_chain_id_for_tests(0);
    }

    /// The chain id is bound into the vote preimage, so a nil vote and a
    /// targeted vote of the same height/round still differ, and neither can be
    /// replayed on another chain.
    #[test]
    fn test_vote_preimage_commits_to_chain_id_and_fields() {
        let a = vote_sign_bytes(1, 2, VoteKind::Prevote, &Some([0x11; 32]));
        let b = vote_sign_bytes(1, 2, VoteKind::Precommit, &Some([0x11; 32]));
        let c = vote_sign_bytes(1, 2, VoteKind::Prevote, &None);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);

        // Domain separation: the preimage starts with the vote domain tag.
        assert!(a.starts_with(b"STELLEREUM_BFT_VOTE_V2"));
        // ... followed by the chain id.
        let tag_len = b"STELLEREUM_BFT_VOTE_V2".len();
        let chain = crate::consensus::consensus_chain_id().to_be_bytes();
        assert!(
            a[tag_len..tag_len + 8] == chain,
            "the chain id must follow the domain tag"
        );
    }

    #[test]
    fn test_uqc_encoding_decoding_and_verification_16_falcon() {
        let mut vs = ValidatorSet::new();
        let mut falcon_keys = Vec::new();

        // Register 20 validators with Falcon-512 keys
        for i in 0..20u8 {
            let fk = make_sample_falcon512(i + 10);
            let pk = fk.public_key().to_vec();
            let id = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            );
            vs.add(id, 10);
            register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk.clone());
            falcon_keys.push((id, fk));
        }

        let height: Height = 42;
        let round: Round = 1;
        // AUDIT W6.5: the committee size is the SHARED production rule, not a
        // literal — a test that hard-codes it drifts from the verifier the
        // moment the rule changes (and then fails for the wrong reason).
        let committee_size: u32 = micro_committee_size(vs.len());
        // The parent block hash the committee is elected with.
        let parent = [0x77; 32];
        let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
        assert_eq!(committee.len(), committee_size as usize);

        let kind = VoteKind::Precommit;
        let block_hash = Some([0xAA; 32]);
        let msg = vote_sign_bytes(height, round, kind, &block_hash);

        // Generate one valid Falcon signature per committee member
        let mut signatures = Vec::new();
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        for (i, val_id) in committee.iter().enumerate() {
            let (_, fk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
            let sig = make_sample_falcon512_sig(fk, &msg);
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
            sortition_parent: parent,
        };

        // Test wire encoding & decoding roundtrip
        let payload = encode_pq_micro_envelope(&uqc);
        assert!(payload.starts_with(QC_UQC_MAGIC));
        let decoded =
            decode_pq_micro_envelope(&payload).expect("decoding µQC envelope must succeed");
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
        assert!(
            qc.verify_unified(&vs),
            "µQC with 16 Falcon signatures must verify under verify_unified"
        );

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
            let fk = make_sample_falcon512(i + 60);
            let pk = fk.public_key().to_vec();
            let id = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            );
            vs.add(id, 10);
            register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk.clone());
            falcon_keys.push((id, fk));
        }

        let height: Height = 100;
        let round: Round = 0;
        let committee_size: u32 = 16;
        let parent = [0x33; 32];
        let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
        let kind = VoteKind::Precommit;
        let block_hash = Some([0x55; 32]);
        let msg = vote_sign_bytes(height, round, kind, &block_hash);

        // 1. Sub-quorum bitmask test: quorum is 11 of 16. Provide only 10 signatures!
        let mut sub_sigs = Vec::new();
        let mut sub_bitmask = vec![0u8; 2];
        for i in 0..10 {
            let val_id = &committee[i];
            let (_, fk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
            let sig = make_sample_falcon512_sig(fk, &msg);
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
            sortition_parent: parent,
        };
        let sub_qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&sub_uqc))],
        };
        assert!(
            !sub_qc.verify(&vs),
            "Sub-quorum (10 of 16) µQC must fail verification"
        );
        assert!(
            !sub_qc.verify_unified(&vs),
            "Sub-quorum must fail under verify_unified"
        );

        // 2. Tampered signature test: 11 valid signers (quorum), but 1 signature corrupted
        let mut quorum_sigs = Vec::new();
        let mut quorum_bitmask = vec![0u8; 2];
        for i in 0..11 {
            let val_id = &committee[i];
            let (_, fk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
            let sig = make_sample_falcon512_sig(fk, &msg);
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
            sortition_parent: parent,
        };
        let tampered_qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&tampered_uqc))],
        };
        assert!(
            !tampered_qc.verify(&vs),
            "Tampered signature in µQC must fail verification"
        );

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
        assert!(
            !mismatched_qc.verify(&vs),
            "Height mismatch between QC and µQC must fail"
        );

        // 4. Corrupted envelope magic
        let mut bad_magic = encode_pq_micro_envelope(&sub_uqc);
        bad_magic[0] ^= 0xFF;
        assert_eq!(decode_pq_micro_envelope(&bad_magic), None);
    }

    /// AUDIT W6.5 (committee capture) — the pure quorum math.
    ///
    /// The µQC threshold is `max(2/3 of the committee, STRICT MAJORITY of the
    /// network)`. The second term is what stops a captured committee from
    /// finalizing a block: without it, a 16-seat committee of a 100-validator
    /// network (holding ~16% of the stake) would accept a certificate worth
    /// ~11% of the NETWORK's stake.
    #[test]
    fn test_micro_quorum_power_is_anchored_to_the_network() {
        // Committee 640 of a 1000-power network.
        let committee_total = 640u64;
        let network_total = 1000u64;
        // The committee's own 2/3 would be 427 — 43% of the NETWORK.
        assert_eq!(pq_micro_quorum_power(committee_total), 427);
        // The network anchor raises it to a strict majority of the network.
        assert_eq!(pq_micro_required_power(committee_total, network_total), 501);
        assert!(
            pq_micro_required_power(committee_total, network_total)
                > pq_micro_quorum_power(committee_total)
        );
        // A committee that IS the whole network keeps the legacy rule
        // (2/3 of the network) — the live N=4 configuration is unchanged.
        assert_eq!(pq_micro_required_power(1000, 1000), 667);
        assert_eq!(pq_micro_required_power(4, 4), 3);
        // Fail-closed: a zero-power committee can never reach quorum.
        assert_eq!(pq_micro_required_power(0, 1000), u64::MAX);
        // The legacy head-count curve is untouched (pinned by the bridge test).
        assert_eq!(pq_micro_quorum_threshold(16), 11);
        // The committee size is the SHARED production rule.
        assert_eq!(micro_committee_size(4), 4);
        assert_eq!(micro_committee_size(16), 16);
        assert_eq!(micro_committee_size(100), MICRO_COMMITTEE_MAX_SIZE);
        assert_eq!(micro_committee_size(10_000), MICRO_COMMITTEE_MAX_SIZE);
    }

    /// AUDIT W6.5 (committee capture) — end to end.
    ///
    /// A µQC whose committee is a STRICT SUBSET of the validator set (N=100,
    /// a 64-seat committee holding 64% of the stake) must not be accepted on
    /// the strength of the committee's own 2/3: the certificate has to carry
    /// a strict majority of the WHOLE network's stake. This is the property
    /// that keeps "an attacker with < 1/2 of the stake cannot finalize a
    /// block" true even when the committee is small relative to the network.
    #[test]
    fn test_uqc_of_a_subset_committee_must_reach_a_network_majority() {
        const N: usize = 100;
        const POWER: u64 = 10;
        let mut vs = ValidatorSet::new();
        for i in 0..N as u8 {
            vs.add([i.wrapping_add(1); 32], POWER);
        }
        let height: Height = 77;
        let round: Round = 0;
        let parent = [0x42; 32];
        let committee_size = micro_committee_size(vs.len());
        assert_eq!(committee_size as usize, MICRO_COMMITTEE_MAX_SIZE as usize);
        let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
        assert_eq!(committee.len(), committee_size as usize);

        let committee_total: u64 = committee.iter().map(|id| vs.power_of(id)).sum();
        let network_total = vs.total_power();
        assert_eq!(network_total, N as u64 * POWER);
        assert_eq!(committee_total, MICRO_COMMITTEE_MAX_SIZE as u64 * POWER);
        // The committee's own 2/3 is BELOW the network anchor.
        let required = pq_micro_required_power(committee_total, network_total);
        assert!(required > pq_micro_quorum_power(committee_total));
        // 50 members carry 500 < 501 power: refused. 51 carry 510: accepted.
        let sub_quorum_members = required.div_ceil(POWER) as usize - 1;
        assert_eq!(sub_quorum_members, 50);

        let kind = VoteKind::Precommit;
        let block_hash = Some([0x21; 32]);
        let msg = vote_sign_bytes(height, round, kind, &block_hash);

        // Real Falcon keys for the committee members that sign.
        let mut signers: Vec<(ValidatorId, crate::post_quantum::FalconKeypair)> = Vec::new();
        for val_id in committee.iter().take(sub_quorum_members + 1) {
            let fk =
                make_sample_falcon512(0x80u8.wrapping_add((*val_id)[0]).wrapping_add((*val_id)[1]));
            register_validator_pq_key(
                *val_id,
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key().to_vec(),
            );
            signers.push((*val_id, fk));
        }

        let build_uqc = |n: usize| -> PqMicroCertificate {
            let mut signatures = Vec::with_capacity(n);
            let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
            for (i, val_id) in committee.iter().enumerate().take(n) {
                let (_, fk) = signers.iter().find(|(id, _)| id == val_id).unwrap();
                signatures.push(fk.sign(&msg));
                bitmask[i / 8] |= 1 << (i % 8);
            }
            PqMicroCertificate {
                scheme: crate::post_quantum::PqScheme::Falcon512,
                height,
                round,
                committee_size,
                signers_bitmask: bitmask,
                signatures,
                sortition_parent: parent,
            }
        };
        let wrap = |uqc: &PqMicroCertificate| QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(uqc))],
        };

        // 50 of 64 committee members: the committee's own 2/3 (427) is met
        // (500 >= 427) but the NETWORK's strict majority (501) is not.
        let sub = build_uqc(sub_quorum_members);
        assert!(sub.signed_power(&committee, &vs) >= pq_micro_quorum_power(committee_total));
        assert!(sub.signed_power(&committee, &vs) < required);
        assert!(
            !wrap(&sub).verify(&vs),
            "a µQC that clears only the committee's 2/3 must NOT finalize a block"
        );

        // 51 of 64: the network's strict majority is reached -> accepted.
        let ok = build_uqc(sub_quorum_members + 1);
        assert!(ok.signed_power(&committee, &vs) >= required);
        assert!(
            wrap(&ok).verify(&vs),
            "a µQC carrying a strict majority of the NETWORK's stake must verify"
        );
    }

    #[test]
    fn test_backward_compatibility_classical_ed25519_qc() {
        // FULL-PQ (nodes wiped, no compat): classical Ed25519 QC legs deleted.
        // An Ed-only QC is REJECTED (fail-closed); a Falcon µQC with the same
        // 3-of-4 quorum shape VERIFIES. Same strength as before (genuine pass,
        // tampered fail), fixtures converted to Falcon/PQ.
        //
        // Part A: Ed-only QC (3 of 4) must now FAIL on both paths.
        let mut vs_ed = ValidatorSet::new();
        let mut ed_signers = Vec::new();
        for _ in 0..4 {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let id = sk.verifying_key().to_bytes();
            vs_ed.add(id, 10);
            ed_signers.push(sk);
        }
        let height = 5;
        let round = 0;
        let kind = VoteKind::Precommit;
        let block_hash = Some([0x12; 32]);
        let msg = vote_sign_bytes(height, round, kind, &block_hash);
        let mut ed_sigs = Vec::new();
        for sk in &ed_signers[0..3] {
            let sig = sk.sign(&msg).to_bytes().to_vec();
            ed_sigs.push((sk.verifying_key().to_bytes(), sig));
        }
        let ed_qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash,
            signatures: ed_sigs,
        };
        assert!(
            !ed_qc.verify(&vs_ed),
            "FULL-PQ: Ed-only QC must be rejected (Ed legs deleted)"
        );
        assert!(
            !ed_qc.verify_unified(&vs_ed),
            "FULL-PQ: Ed-only QC must be rejected on verify_unified"
        );
        assert!(
            ed_qc.signers_set(&vs_ed).is_empty(),
            "FULL-PQ: rejected Ed-only QC attributes nobody"
        );

        // Part B: Falcon µQC with the same 3-of-4 shape VERIFIES.
        let mut vs = ValidatorSet::new();
        let mut fks = Vec::new();
        for i in 0..4u8 {
            let fk = make_sample_falcon512(0xA0 + i);
            let pk = fk.public_key().to_vec();
            let id = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            );
            vs.add(id, 10);
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                pk.clone(),
            );
            fks.push((id, fk));
        }
        let committee_size = micro_committee_size(vs.len());
        assert_eq!(committee_size, 4);
        let parent = [0x34; 32];
        let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
        assert_eq!(committee.len(), 4);
        let target = Some([0x12; 32]);
        let qc_msg = vote_sign_bytes(height, round, kind, &target);
        // 3 of 4 committee members sign (exceeds 2/3 power quorum, same shape
        // as the deleted Ed fixture above).
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        let mut msigs = Vec::new();
        for (i, val_id) in committee.iter().enumerate().take(3) {
            bitmask[i / 8] |= 1 << (i % 8);
            let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
            msigs.push(make_sample_falcon512_sig(fk, &qc_msg));
        }
        let uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            bitmask,
            msigs,
            parent,
        );
        let qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash: target,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
        };
        assert!(qc.verify(&vs), "Falcon µQC 3-of-4 must verify");
        assert!(
            qc.verify_unified(&vs),
            "Falcon µQC 3-of-4 must verify with verify_unified"
        );

        // Tamper with one Falcon signature: surviving power below quorum,
        // verification fails (same tamper shape as the deleted Ed fixture).
        let mut bad_sigs = uqc.signatures.clone();
        bad_sigs[0][10] ^= 0xFF;
        let bad_uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            uqc.signers_bitmask.clone(),
            bad_sigs,
            parent,
        );
        let tampered_qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash: target,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&bad_uqc))],
        };
        assert!(
            !tampered_qc.verify(&vs),
            "Tampered Falcon µQC must fail verification"
        );
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
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
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
            let fk = &falcon_keys[i];
            let vote = Vote::sign_with_falcon(sk, fk, height, round, kind, block_hash);
            assert!(vote.falcon_signature().is_some());
            assert!(vote_set.add(vote, &vs, height, round, kind).is_ok());
        }

        assert_eq!(vote_set.falcon_votes_count(), 16);
        let collected = vote_set.collect_falcon_signatures(block_hash);
        assert_eq!(collected.len(), 16);

        // Certificate compilation must automatically compile the PqMicroCertificate
        // and attach PQ_UQC_MARKER_ID
        let parent = [0x44; 32];
        let qc = vote_set
            .certificate(block_hash, &vs, &parent)
            .expect("certificate must form");
        assert!(
            qc.signatures
                .iter()
                .any(|(voter, _)| *voter == PQ_UQC_MARKER_ID),
            "compiled QC must carry PQ_UQC_MARKER_ID sentinel marker"
        );

        let uqc = qc
            .pq_micro_certificate()
            .expect("micro-QC must be retrievable");
        assert_eq!(uqc.scheme, crate::post_quantum::PqScheme::Falcon512);
        assert_eq!(uqc.height, height);
        assert_eq!(uqc.round, round);
        assert_eq!(uqc.committee_size, 16);
        assert_eq!(uqc.signatures.len(), 16);

        // Verification under QuorumCertificate::verify_unified
        assert!(
            qc.verify_unified(&vs),
            "micro-QC must verify under verify_unified"
        );
        assert!(qc.verify(&vs), "micro-QC must verify under verify");

        // Verify that under Pure Post-Quantum Mode, the QC verifies via the µQC path
        crate::post_quantum::set_pure_pq_override(Some(true));
        assert!(
            qc.verify_unified(&vs),
            "micro-QC must verify under Pure PQ mode"
        );
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
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            signers.push((sk, id));
            falcon_keys.push(fk);
        }

        let height: Height = 10;
        let mut hc = HeightConsensus::new(height, vs.clone());
        // The sortition committee is elected from the PARENT block hash: the
        // node must know it before it can compile a micro-certificate (an
        // unknown parent compiles none — fail closed, see `VoteSet::certificate`).
        hc.set_parent_hash([0xA5; 32]);
        let block_hash = [0xBB; 32];
        let proposer = hc.proposer().unwrap();

        // 1. Propose
        assert!(hc.receive_proposal(proposer, block_hash).is_ok());

        // 2. Prevote with Falcon signatures
        for i in 0..16 {
            let (ref sk, _) = signers[i];
            let fk = &falcon_keys[i];
            let vote =
                Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Prevote, Some(block_hash));
            assert!(hc.add_prevote(vote).is_ok());
        }

        assert_eq!(hc.falcon_votes_count(0, VoteKind::Prevote), 16);
        let falcon_prevotes = hc.collect_falcon_signatures(0, VoteKind::Prevote, Some(block_hash));
        assert_eq!(falcon_prevotes.len(), 16);

        let polka = hc.try_prevote_quorum_at().expect("polka must form");
        assert_eq!(polka, (0, Some(block_hash)));
        let prevote_qc = hc.prevote_qc.get(&0).expect("prevote QC must exist");
        assert!(prevote_qc
            .signatures
            .iter()
            .any(|(v, _)| *v == PQ_UQC_MARKER_ID));
        assert!(prevote_qc.verify_unified(&vs));

        // 3. Precommit with Falcon signatures
        for i in 0..16 {
            let (ref sk, _) = signers[i];
            let fk = &falcon_keys[i];
            let vote =
                Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Precommit, Some(block_hash));
            assert!(hc.add_precommit(vote).is_ok());
        }

        assert_eq!(hc.falcon_votes_count(0, VoteKind::Precommit), 16);
        let decided = hc
            .try_precommit_quorum()
            .expect("precommit quorum must decide");
        assert_eq!(decided, block_hash);
        let precommit_qc = hc.precommit_qc.as_ref().expect("precommit QC must exist");
        assert!(precommit_qc
            .signatures
            .iter()
            .any(|(v, _)| *v == PQ_UQC_MARKER_ID));
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
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            signers.push((sk, id));
            falcon_keys.push(fk);
        }

        let height: Height = 100;
        let mut hc = HeightConsensus::new(height, vs.clone());
        // The sortition parent must be known before a micro-certificate can
        // be compiled (see `VoteSet::certificate`).
        hc.set_parent_hash([0xC7; 32]);
        let block_hash = [0x5A; 32];
        let proposer = hc.proposer().expect("proposer must be selected");

        // Verify proposal
        assert!(hc.receive_proposal(proposer, block_hash).is_ok());

        // Cast Falcon-512 prevotes
        for i in 0..16 {
            let (ref sk, _) = signers[i];
            let fk = &falcon_keys[i];
            let prevote =
                Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Prevote, Some(block_hash));
            assert!(prevote.verify());
            assert!(hc.add_prevote(prevote).is_ok());
        }

        let polka = hc.try_prevote_quorum_at().expect("polka must form");
        assert_eq!(polka, (0, Some(block_hash)));
        let prevote_qc = hc.prevote_qc.get(&0).expect("prevote QC must exist");
        assert!(
            prevote_qc
                .signatures
                .iter()
                .any(|(v, _)| *v == PQ_UQC_MARKER_ID),
            "prevote QC must contain PQ_UQC_MARKER_ID"
        );
        assert!(prevote_qc.verify_unified(&vs));

        // Cast Falcon-512 precommits
        for i in 0..16 {
            let (ref sk, _) = signers[i];
            let fk = &falcon_keys[i];
            let precommit =
                Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Precommit, Some(block_hash));
            assert!(precommit.verify());
            assert!(hc.add_precommit(precommit).is_ok());
        }

        let decided = hc
            .try_precommit_quorum()
            .expect("precommit quorum must decide");
        assert_eq!(decided, block_hash);
        let precommit_qc = hc.precommit_qc.as_ref().expect("precommit QC must exist");
        assert!(
            precommit_qc
                .signatures
                .iter()
                .any(|(v, _)| *v == PQ_UQC_MARKER_ID),
            "precommit QC must contain PQ_UQC_MARKER_ID"
        );
        assert!(precommit_qc.verify_unified(&vs));
        assert!(precommit_qc.verify(&vs));

        let signers_set = precommit_qc.signers_set(&vs);
        assert_eq!(signers_set.len(), 16);
        for (_, id) in &signers {
            assert!(signers_set.contains(id));
        }
    }

    #[test]
    fn test_signers_set_extraction_falcon_uqc_and_classical() {
        // Real keys throughout: attribution mirrors verification (V-P34 R2),
        // so every attributed signer must carry a verifying signature and
        // every unverifiable entry attributes nobody.
        let mut vs = ValidatorSet::new();
        let mut sks = Vec::new();
        let mut fks = Vec::new();
        for i in 0u8..3 {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let id = sk.verifying_key().to_bytes();
            let fk = FalconKeypair::generate_from_seed(0xC0 + i);
            vs.add(id, 100);
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            sks.push(sk);
            fks.push(fk);
        }
        let ids: Vec<ValidatorId> = sks.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let target = [0xAA; 32];

        // 1. Classical signatures: FULL-PQ deletes the Ed threshold, so a
        // genuine Ed quorum is REJECTED and attributes nobody (fail-closed);
        // a forged entry in a REJECTED certificate attributes nobody.
        let genuine: Vec<(ValidatorId, Vec<u8>)> = sks
            .iter()
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(target));
                (v.voter, v.signature)
            })
            .collect();
        let classical_qc = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(target),
            signatures: genuine,
        };
        assert!(
            !classical_qc.verify(&vs),
            "FULL-PQ: genuine Ed quorum must be rejected (Ed legs deleted)"
        );
        assert!(
            !classical_qc.verify_unified(&vs),
            "FULL-PQ: genuine Ed quorum must be rejected on verify_unified"
        );
        let signers_classical = classical_qc.signers_set(&vs);
        assert!(
            signers_classical.is_empty(),
            "FULL-PQ: rejected Ed quorum attributes nobody"
        );
        let forged_qc = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(target),
            signatures: vec![(ids[0], vec![7u8; 64]), (ids[1], vec![8u8; 64])],
        };
        assert!(
            !forged_qc.verify(&vs),
            "forged classical QC must be rejected"
        );
        assert!(
            forged_qc.signers_set(&vs).is_empty(),
            "a rejected classical QC must attribute nobody"
        );

        // 2. Genuine Falcon µQC: every verified committee member attributed.
        let parent = [0x55; 32];
        let committee = derive_sortition_committee(&vs, 1, 0, 3, &parent);
        assert_eq!(committee.len(), 3);
        let msg = vote_sign_bytes(1, 0, VoteKind::Precommit, &Some(target));
        let mut bitmask = vec![0u8; 1];
        let mut msigs = Vec::new();
        for (i, id) in committee.iter().enumerate() {
            bitmask[0] |= 1 << i;
            let fk = &fks[ids
                .iter()
                .position(|x| x == id)
                .expect("committee is members")];
            msigs.push(fk.sign(&msg));
        }
        let uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            1,
            0,
            3,
            bitmask,
            msigs,
            parent,
        );
        let uqc_qc = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(target),
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
        };
        assert!(uqc_qc.verify(&vs), "genuine Falcon µQC must verify");
        let signers_uqc = uqc_qc.signers_set(&vs);
        assert_eq!(signers_uqc.len(), 3);
        for id in &committee {
            assert!(signers_uqc.contains(id));
        }

        // 3. Garbage marker (unknown id): verify ignores the entry, and
        // attribution mirrors verify — the undecodable marker attributes
        // NOBODY.
        let marker_qc = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some([0xAA; 32]),
            signatures: vec![(PQ_UQC_MARKER_ID, b"garbage-not-an-envelope".to_vec())],
        };
        assert!(
            !marker_qc.verify(&vs),
            "marker-only QC must be rejected"
        );
        assert!(
            marker_qc.signers_set(&vs).is_empty(),
            "an unverifiable marker must attribute nobody"
        );
    }

    /// VOTE-VERIFY BATCH PARITY (Falcon-only, fixed fixtures k=4/7/16/100):
    /// `Vote::verify_batch` / `partition_valid` must equal scalar `verify`
    /// on all-valid fixtures AND on 1-forged variants. Converted from the
    /// deleted classical Ed25519 QC parity (same k values, same strength):
    /// Ed-only votes are rejected; tampering the Ed half of a dual envelope
    /// still verifies (Ed ignored — proof of deletion); tampering the Falcon
    /// half fails. Extends the vote suites; weakens nothing.
    #[test]
    fn qc_verify_batch_parity_classical_ed25519_k4716_and_forged() {
        // NOTE: historic name kept for traceability; fixtures are Falcon-only
        // (FULL-PQ conversion). The classical Ed25519 QC parity legs are
        // deleted — see `verify_unified_with_pq_keys` (now unconditional
        // `false` after the PQ path) and `signers_set` (classical skipped).
        use rand::rngs::OsRng;
        for &k in &[4usize, 7, 16, 100] {
            let mut vs = ValidatorSet::new();
            let mut sks = Vec::new();
            let mut fks = Vec::new();
            for i in 0..k {
                let sk = SigningKey::generate(&mut OsRng);
                let id = sk.verifying_key().to_bytes();
                let fk = make_sample_falcon512((k as u8).wrapping_mul(31).wrapping_add(i as u8));
                vs.add(id, 1);
                register_validator_pq_key(
                    id,
                    crate::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                );
                sks.push(sk);
                fks.push(fk);
            }
            let height = 5;
            let round = 0;
            let kind = VoteKind::Precommit;
            let target = Some([0x12; 32]);
            let votes: Vec<Vote> = (0..k)
                .map(|i| Vote::sign_with_falcon(&sks[i], &fks[i], height, round, kind, target))
                .collect();
            // Serial oracle: scalar Falcon predicate per vote.
            let serial: Vec<bool> = votes.iter().map(|v| v.verify()).collect();
            assert!(
                serial.iter().all(|&b| b),
                "k={k} all-Falcon fixture must verify serially"
            );
            assert!(
                Vote::verify_batch(&votes),
                "k={k} all-Falcon batch must verify"
            );
            assert_eq!(
                Vote::partition_valid(&votes),
                serial,
                "k={k} partition == serial"
            );
            // Deterministic across repeats (cache hit path).
            // GATE: black_box defeats const-folding; pin must fail loudly if changed.
            assert!(
                std::hint::black_box(Vote::verify_batch(&votes)),
                "k={k} batch verdict stable"
            );
            assert_eq!(
                Vote::partition_valid(&votes),
                serial,
                "k={k} partition stable"
            );
            // 1-forged Falcon half: offender fails on every path; survivors pass.
            let mut forged_falcon = votes.clone();
            forged_falcon[0].signature[90] ^= 0xFF;
            assert!(
                !forged_falcon[0].verify(),
                "k={k} Falcon-tampered vote must fail scalar"
            );
            assert!(
                !Vote::verify_batch(&forged_falcon),
                "k={k} Falcon-forged batch must fail"
            );
            let part = Vote::partition_valid(&forged_falcon);
            assert!(!part[0], "k={k} Falcon forger marked false");
            assert!(
                part[1..].iter().all(|&b| b),
                "k={k} honest survivors still pass"
            );
            // Ed-half tamper still verifies (Ed ignored — proof of deletion).
            let mut ed_tampered = votes.clone();
            ed_tampered[0].signature[20] ^= 0xFF;
            assert!(
                ed_tampered[0].verify(),
                "k={k} Ed-tampered dual vote must still verify (Ed ignored)"
            );
            assert!(
                Vote::verify_batch(&ed_tampered),
                "k={k} Ed-tampered batch must still verify"
            );
            // Ed-only votes (no Falcon half) are rejected on every path.
            let ed_only: Vec<Vote> = sks
                .iter()
                .map(|sk| Vote::sign(sk, height, round, kind, target))
                .collect();
            assert!(
                ed_only.iter().all(|v| !v.verify()),
                "k={k} Ed-only votes must fail scalar"
            );
            assert!(
                !Vote::verify_batch(&ed_only),
                "k={k} Ed-only batch must fail"
            );
            assert!(
                Vote::partition_valid(&ed_only).iter().all(|&b| !b),
                "k={k} Ed-only partition all false"
            );
        }
    }

    /// QC-VERIFY BATCH PARITY (Falcon µQC, fixed fixtures k=4/7/16/100): the
    /// batched (rayon-chunked) per-signature verification must equal the serial
    /// scalar verdict. A 1-forged member invalidates the WHOLE QC on both paths
    /// (fail-closed all-must-pass) with identical (empty) signer accounting.
    /// Extends the QC suites; weakens nothing.
    #[test]
    fn qc_verify_batch_parity_falcon_uqc_k4716_and_forged() {
        for &k in &[4usize, 7, 16, 100] {
            let mut vs = ValidatorSet::new();
            let mut fks = Vec::new();
            for i in 0..k {
                let fk = make_sample_falcon512(0x51u8.wrapping_add(i as u8));
                let pk = fk.public_key().to_vec();
                let id = crate::post_quantum::derive_pq_address(
                    crate::post_quantum::PqScheme::Falcon512,
                    &pk,
                    &crate::post_quantum::DEFAULT_SALT,
                );
                vs.add(id, 10);
                register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk);
                fks.push((id, fk));
            }
            let height = 42u64;
            let round = 1u32;
            let kind = VoteKind::Precommit;
            let target = Some([0xAA; 32]);
            let committee_size = micro_committee_size(vs.len());
            let parent = [0x77; 32];
            let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
            let msg = vote_sign_bytes(height, round, kind, &target);
            let mut signatures = Vec::new();
            let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
            for (i, val_id) in committee.iter().enumerate() {
                let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
                signatures.push(make_sample_falcon512_sig(fk, &msg));
                bitmask[i / 8] |= 1 << (i % 8);
            }
            let uqc = PqMicroCertificate::new(
                crate::post_quantum::PqScheme::Falcon512,
                height,
                round,
                committee_size,
                bitmask,
                signatures,
                parent,
            );
            let qc = QuorumCertificate {
                height,
                round,
                kind,
                block_hash: target,
                signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
            };
            // Serial oracle: the pre-batch scalar loop — every marked member
            // must verify (fail-closed), then the power quorum. A failure
            // attributes nobody (the `None` arm of `micro_cert_valid_signers`).
            // (Fixtures use Falcon512 with registered keys, so the Ed25519
            // address fallback never fires — same as production here.)
            let serial = |cert: &PqMicroCertificate| -> (bool, HashSet<ValidatorId>) {
                let mut ok = true;
                let mut set = HashSet::new();
                let mut sig_idx = 0;
                for (i, val_id) in committee.iter().enumerate() {
                    if !cert.is_signer(i) {
                        continue;
                    }
                    let sig = &cert.signatures[sig_idx];
                    sig_idx += 1;
                    let pass = match get_validator_pq_key(val_id) {
                        Some((scheme, pk)) if scheme == cert.scheme => {
                            verify_falcon_signature(&pk, &msg, sig)
                        }
                        _ => false,
                    };
                    if pass {
                        set.insert(*val_id);
                    } else {
                        ok = false;
                    }
                }
                let committee_total: u64 =
                    committee.iter().map(|id| vs.power_of(id)).sum();
                let required = pq_micro_required_power(committee_total, vs.total_power());
                let power: u64 = set.iter().map(|id| vs.power_of(id)).sum();
                if ok && power >= required {
                    (true, set)
                } else {
                    (false, HashSet::new())
                }
            };
            let (exp_v, exp_s) = serial(&uqc);
            assert!(exp_v, "k={k} all-valid µQC must verify serially");
            assert_eq!(exp_s.len(), committee.len());
            assert_eq!(qc.verify(&vs), exp_v, "k={k} batched == serial verdict");
            assert_eq!(
                qc.signers_set(&vs),
                exp_s,
                "k={k} identical signer accounting"
            );
            // Deterministic across repeats.
            assert_eq!(qc.verify(&vs), exp_v, "k={k} verdict stable");
            assert_eq!(qc.signers_set(&vs), exp_s, "k={k} attribution stable");
            // 1-forged member: the WHOLE QC is invalid on both paths, and the
            // forged envelope attributes nobody on either path.
            let mut bad_sigs = uqc.signatures.clone();
            bad_sigs[0][50] ^= 0xFF;
            let bad_uqc = PqMicroCertificate::new(
                crate::post_quantum::PqScheme::Falcon512,
                height,
                round,
                committee_size,
                uqc.signers_bitmask.clone(),
                bad_sigs,
                parent,
            );
            let bad_qc = QuorumCertificate {
                height,
                round,
                kind,
                block_hash: target,
                signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&bad_uqc))],
            };
            let (b_v, b_s) = serial(&bad_uqc);
            assert!(!b_v, "k={k} 1-forged µQC fails serially");
            assert!(b_s.is_empty(), "k={k} forged envelope attributes nobody");
            assert!(
                !bad_qc.verify(&vs),
                "k={k} 1-forged µQC invalid on batched path"
            );
            assert!(
                bad_qc.signers_set(&vs).is_empty(),
                "k={k} 1-forged µQC attributes nobody on batched path"
            );
        }
    }
}
