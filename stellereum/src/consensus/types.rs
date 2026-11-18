use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use super::rotation::pq_key_at_height;
use super::sortition::{
    cnvrf_v3_active_at, cnvrf_v3_beacon_draw_committee, cnvrf_v3_epoch_of_height,
    cnvrf_v3_proposer_seed, consensus_quorum_min, derive_sortition_committee, micro_committee_size,
    mixed_quorum_pair_safe, pq_micro_quorum_threshold, pq_micro_required_power, qc_split_active_at,
};

pub type Height = u64;
pub type Round = u32;
pub type BlockHash = [u8; 32];
pub type ValidatorId = [u8; 32];

/// Epoch-bound 48-byte CN-VRF v3 randomness beacon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochBeacon {
    pub epoch: u64,
    pub output: [u8; 48],
}

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

/// Verify the block proposal signature: Falcon-only, height-indexed, no
/// classical fallback.
///
/// Resolution uses the SAME height-indexed committed-registry source as the
/// vote path ([`pq_key_at_height`] at `block.height`): the key authoritative
/// for the block's height verifies, anything else (unknown validator, no key
/// at that height, wrong-scheme or tampered signature) refuses fail-closed.
/// The legacy `Block::verify_proposer_signature` Ed25519 fallback is deleted
/// (no new fallback): an Ed-only proposal refuses here. The function itself
/// is KEPT (not deleted) — callers in staking/main/consensus_net/runtime
/// depend on it.
pub fn verify_proposer_signature(block: &crate::sharding::Block) -> bool {
    let hash = block.compute_hash();

    // Height-indexed committed read (rotation-aware): fail-closed when the
    // proposer has no key at this height (unknown validator, pre-activation,
    // or pruned history).
    let Some((scheme, pk)) = pq_key_at_height(&block.proposer, block.height) else {
        return false;
    };
    if scheme.is_disabled() {
        return false;
    }
    // The Falcon address this key controls (runtime stores the Falcon half
    // under the derived address, not under the Ed proposer id).
    let expected_addr =
        crate::post_quantum::derive_pq_address(scheme, &pk, &crate::post_quantum::DEFAULT_SALT);
    for (signer_id, sig_bytes) in &block.validator_signatures {
        // Same registered-key source as votes: only the proposer's slot (by
        // Ed id or by derived Falcon address) counts; a neighbor's valid
        // signature never verifies for this proposer.
        if *signer_id != block.proposer && *signer_id != expected_addr {
            continue;
        }
        // Size-gated to the registered scheme (Falcon-512 today, Hybrid
        // tomorrow): an Ed-only 64-byte entry never reaches crypto here.
        if sig_bytes.len() != scheme.signature_size() {
            continue;
        }
        if crate::post_quantum::verify_pq_signature(scheme, &pk, &hash, sig_bytes) {
            return true;
        }
        // A matching slot with a bad signature refuses at once: the Ed
        // fallback is gone, so there is no second chance for this block.
        return false;
    }
    false
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
    attach_vote_falcon_sig(&falcon_sig, signature);
}

/// Deterministic variant of [`attach_vote_falcon`] for reproducible simulation
/// harnesses (`ConsensusCluster`). Production paths MUST use [`attach_vote_falcon`].
pub fn attach_vote_falcon_deterministic(key: &FalconKeypair, msg: &[u8], signature: &mut Vec<u8>) {
    let mut h = blake3::Hasher::new();
    h.update(b"STELL_SIM_VOTE_SEED_V1");
    h.update(&key.validator_id());
    h.update(msg);
    let seed: [u8; 32] = *h.finalize().as_bytes();
    let falcon_sig = key.sign_deterministic_for_sim(msg, &seed);
    attach_vote_falcon_sig(&falcon_sig, signature);
}

fn attach_vote_falcon_sig(falcon_sig: &[u8], signature: &mut Vec<u8>) {
    let mut ed = vec![0u8; 64];
    if signature.len() == 64 {
        ed.copy_from_slice(signature);
    } else if signature.len() == VOTE_FALCON_PART_LEN && signature.starts_with(VOTE_FALCON_MAGIC) {
        ed.copy_from_slice(&signature[16..80]);
    }
    let mut out = Vec::with_capacity(VOTE_FALCON_PART_LEN);
    out.extend_from_slice(VOTE_FALCON_MAGIC);
    out.extend_from_slice(&ed);
    out.extend_from_slice(falcon_sig);
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
///   `max(floor(2*W_committee/3) + 1, floor(2*W_network/3) + 1)`.
///   * While the committee IS the whole validator set (N <= the cap — the
///     live N = 4 network) the two terms coincide with the legacy rule
///     `floor(2*k/3) + 1` (3 of 4, 11 of 16 for k = 16), so every historic
///     certificate that met the old count rule on a uniform set still
///     verifies unchanged; on a skewed set any subset whose STAKE reaches
///     quorum suffices (e.g. 2 of 3 by heads when their combined power
///     covers 2/3+1 of the committee).
///   * When the committee is a strict SUBSET of the validator set, the
///     network anchor dominates: a certificate must carry TWO THIRDS of the
///     WHOLE network's stake — a strict majority (`floor(W/2)+1`) does NOT
///     intersect honestly (`2t − W ∈ {1,2}`, `papers/01_quorum.md` §4) — so a
///     captured committee cannot finalize a block (audit W6.5 + P1).
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
        let max_bits = self.signers_bitmask.len().saturating_mul(8);
        let limit = (self.committee_size as usize).min(max_bits);
        (0..limit).filter(|&i| self.is_signer(i)).count()
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
    /// ([`pq_micro_required_power`]) — the committee's own `2/3` AND two-thirds
    /// of the whole network's stake. When the committee is the whole
    /// validator set (N <= the committee cap) the two coincide and the legacy
    /// value is unchanged; when the committee is a strict subset the network
    /// anchor is what stops a captured committee from finalizing a block.
    pub fn has_power_quorum(&self, committee: &[ValidatorId], validators: &ValidatorSet) -> bool {
        if committee.is_empty() || self.committee_size == 0 {
            return false;
        }
        let total: u64 = committee
            .iter()
            .fold(0u64, |acc, id| acc.saturating_add(validators.power_of(id)));
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

    /// Sum of the set's voting power, computed EXACTLY in `u128`.
    ///
    /// The per-validator powers are `u64` and the set is small (tens of
    /// members), so `u128` can never overflow. This is the value quorum
    /// accounting must use: [`Self::total_power`] saturates for wire/config
    /// representability, and a saturated SUM is not a valid denominator for a
    /// 2/3 threshold.
    pub fn total_power_exact(&self) -> u128 {
        self.validators.values().map(|&p| p as u128).sum()
    }

    /// True when [`Self::total_power_exact`] fits in `u64`, i.e. every
    /// saturated power sum in this module is the TRUE sum.
    ///
    /// PENTEST F-6 (LOW): a set whose true total exceeds `u64::MAX` (four
    /// validators at `2^63`) saturates at `u64::MAX`; `quorum_power` then
    /// understates the real 2/3 threshold, and attribution
    /// (`qc_signed_power`/`qc_meets_quorum`) accepted a 2-of-4 minority that
    /// the exact `u128` verifier refuses. Such a set is an absurd
    /// configuration (total supply above `u64::MAX`), so it is REFUSED at
    /// the quorum-accounting boundary rather than silently weakened.
    pub fn power_total_representable(&self) -> bool {
        self.total_power_exact() <= u64::MAX as u128
    }

    /// Sum of the set's voting power, saturating at `u64::MAX`.
    ///
    /// Saturating is deliberate for display/serialization, but a saturated
    /// total is NOT a usable quorum denominator when it differs from the true
    /// sum. Use [`Self::total_power_exact`] for consensus math and gate on
    /// [`Self::power_total_representable`] (as [`Self::qc_meets_quorum`] and
    /// [`Self::quorum_power`] do).
    pub fn total_power(&self) -> u64 {
        self.validators
            .values()
            .fold(0u64, |acc, &p| acc.saturating_add(p))
    }

    /// Quorum is strictly more than 2/3 of total power: floor(2*total/3) + 1,
    /// the consensus-domain curve [`consensus_quorum_min`].
    ///
    /// FREEZE (protocol freeze 2026-11-03): quorum accounting is frozen core.
    /// Change requires spec update + audit note (AGENTS.md §7).
    ///
    /// EXACT TOTAL (PENTEST F-6): the threshold is computed over the `u128`
    /// total, so it is the TRUE 2/3 even when `total_power()` saturates. When
    /// the true total does not fit `u64` the quorum is unrepresentable and
    /// this returns `u64::MAX` (fail closed); [`Self::qc_meets_quorum`] also
    /// refuses such a set outright, so the `u64::MAX` value cannot be met by
    /// a saturated attribution sum.
    pub fn quorum_power(&self) -> u64 {
        let total = self.total_power_exact();
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
        if total > u64::MAX as u128 {
            // True total above u64::MAX: no representable quorum exists.
            return u64::MAX;
        }
        consensus_quorum_min(total as u64)
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
    ///
    /// FAIL CLOSED ON AN UNREPRESENTABLE TOTAL (PENTEST F-6): when the true
    /// power total exceeds `u64::MAX`, both the quorum and the attribution sum
    /// saturate, and comparing two saturated numbers cannot prove a real 2/3.
    /// Such a set has no representable quorum, so the answer is `false`
    /// (matching the exact `u128` verifier, which also refuses).
    pub fn qc_meets_quorum(&self, qc: &QuorumCertificate) -> bool {
        self.power_total_representable() && self.qc_signed_power(qc) >= self.quorum_power()
    }

    /// Cumulative voting power a quorum certificate carries under this set,
    /// using the CN-VRF v3 epoch beacon draw at/after `CNVRF_V3_ACTIVATION_HEIGHT`.
    pub fn qc_signed_power_with_beacon(
        &self,
        qc: &QuorumCertificate,
        beacon: Option<&EpochBeacon>,
    ) -> u64 {
        self.qc_signed_power_with_beacon_inner(qc, beacon, cnvrf_v3_active_at(qc.height))
    }

    /// True when `qc` carries quorum power under this set using [`Self::qc_signed_power_with_beacon`].
    ///
    /// Same unrepresentable-total fail-closed rule as [`Self::qc_meets_quorum`]
    /// (PENTEST F-6).
    pub fn qc_meets_quorum_with_beacon(
        &self,
        qc: &QuorumCertificate,
        beacon: Option<&EpochBeacon>,
    ) -> bool {
        self.power_total_representable()
            && self.qc_signed_power_with_beacon(qc, beacon) >= self.quorum_power()
    }

    fn qc_signed_power_with_beacon_inner(
        &self,
        qc: &QuorumCertificate,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> u64 {
        qc.signers_set_with_beacon_inner(self, beacon, cnvrf_v3_active)
            .iter()
            .map(|v| self.power_of(v))
            .fold(0u64, |a, p| a.saturating_add(p))
    }

    #[cfg(test)]
    pub(crate) fn qc_signed_power_with_beacon_active(
        &self,
        qc: &QuorumCertificate,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> u64 {
        self.qc_signed_power_with_beacon_inner(qc, beacon, cnvrf_v3_active)
    }

    #[cfg(test)]
    pub(crate) fn qc_meets_quorum_with_beacon_active(
        &self,
        qc: &QuorumCertificate,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> bool {
        self.qc_signed_power_with_beacon_inner(qc, beacon, cnvrf_v3_active) >= self.quorum_power()
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Map a 32-byte digest into the normalized `total / gcd` cumulative power
    /// slot over explicitly sorted validator IDs.
    fn proposer_from_digest(&self, digest: &[u8; 32]) -> Option<ValidatorId> {
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
        let slot =
            u64::from_le_bytes(digest[..8].try_into().expect("blake3 digest is 32 bytes")) % range;
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
            acc = acc.saturating_add(*power / g);
            if slot < acc {
                return Some(*id);
            }
        }
        self.validators.keys().next().copied()
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
        if self.total_power() == 0 {
            return None;
        }
        let mut hasher = blake3::Hasher::new_derive_key("STELL_PROPOSER_V1");
        hasher.update(&height.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        let digest = hasher.finalize();
        self.proposer_from_digest(digest.as_bytes())
    }

    /// Beacon-seeded proposer selection (CN-VRF v3):
    /// - Below `CNVRF_V3_ACTIVATION_HEIGHT`: delegates directly to [`Self::proposer_for`].
    /// - At/after `CNVRF_V3_ACTIVATION_HEIGHT`: requires `Some(b)` with
    ///   `b.epoch == cnvrf_v3_epoch_of_height(height)` (returns `None` fail-closed if
    ///   missing or wrong epoch), and maps `cnvrf_v3_proposer_seed` into the
    ///   normalized `total / gcd` cumulative power slot.
    pub fn proposer_for_with_beacon(
        &self,
        height: Height,
        round: Round,
        beacon: Option<&EpochBeacon>,
    ) -> Option<ValidatorId> {
        self.proposer_for_with_beacon_inner(height, round, beacon, cnvrf_v3_active_at(height))
    }

    fn proposer_for_with_beacon_inner(
        &self,
        height: Height,
        round: Round,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> Option<ValidatorId> {
        if !cnvrf_v3_active {
            return self.proposer_for(height, round);
        }
        let b = beacon?;
        if b.epoch != cnvrf_v3_epoch_of_height(height) {
            return None;
        }
        let seed = cnvrf_v3_proposer_seed(&b.output, b.epoch, height, round);
        self.proposer_from_digest(&seed)
    }

    #[cfg(test)]
    pub(crate) fn proposer_for_with_beacon_active(
        &self,
        height: Height,
        round: Round,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> Option<ValidatorId> {
        self.proposer_for_with_beacon_inner(height, round, beacon, cnvrf_v3_active)
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
    /// under the voter's REGISTERED key AT THE VOTE'S HEIGHT — exactly the
    /// old pure-PQ branch, now height-indexed.
    ///
    /// Rotation: `self.height` threads into [`pq_key_at_height`] (the
    /// committed [`crate::pq_registry::PqRegistry::get_active_key`] read,
    /// reused not duplicated). After `effective_height` only the new key
    /// verifies; before it only the old one; a validator with no key at
    /// this height refuses fail-closed (`None`).
    fn verify_uncached(&self) -> bool {
        let msg = vote_sign_bytes(self.height, self.round, self.kind, &self.block_hash);

        // FULL-PQ: Falcon-only. Ed25519 branches deleted (no compat).
        if let Some(falcon_sig) = self.falcon_signature() {
            if let Some((scheme, pk)) = pq_key_at_height(&self.voter, self.height) {
                return crate::post_quantum::verify_pq_signature(scheme, &pk, &msg, falcon_sig);
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
        use rayon::prelude::*;
        if votes.is_empty() {
            return true;
        }
        // FULL-PQ: Falcon-only (old pure-PQ branch, now unconditional).
        if votes.len() < 4 {
            votes.iter().all(|v| v.verify())
        } else {
            votes.par_iter().all(|v| v.verify())
        }
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
        use rayon::prelude::*;
        if votes.is_empty() {
            return Vec::new();
        }
        // FULL-PQ: Falcon-only (old pure-PQ branch, now unconditional).
        // `verify()` consults/records the verified-vote cache, so batch
        // ingest keeps verify-once behavior with no Ed25519 screen.
        if votes.len() < 4 {
            votes.iter().map(|v| v.verify()).collect()
        } else {
            votes.par_iter().map(|v| v.verify()).collect()
        }
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
///
/// Rotation-safe: the PQ entry is the key bytes AT THE VOTE'S HEIGHT
/// ([`pq_key_at_height`]), not the head key — an old-vs-new key at the same
/// `(voter, height, round, ...)` misses by construction, so a cached verdict
/// from before `effective_height` can never serve after it (and vice versa).
#[derive(Clone, PartialEq, Eq, Hash)]
struct VerifiedVoteCacheKey {
    voter: ValidatorId,
    height: Height,
    round: Round,
    kind: u8,
    block_hash: Option<BlockHash>,
    signature: Vec<u8>,
    /// PQ registry entry for `voter` AT `height` at verify time (trigger 2).
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
pub(super) fn note_validator_set_for_vote_cache(validators: &ValidatorSet) {
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
        pq_key: pq_key_at_height(&vote.voter, vote.height).map(|(scheme, pk)| (scheme as u8, pk)),
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

    /// Verify the QC using the CN-VRF v3 epoch beacon draw when
    /// `cnvrf_v3_active_at(self.height)` is true; below `CNVRF_V3_ACTIVATION_HEIGHT`
    /// behaves byte-identically to [`Self::verify`].
    ///
    /// Fail-closed (`false`) if CN-VRF v3 is active and `beacon` is `None` or
    /// carries the wrong epoch for `self.height`.
    pub fn verify_with_beacon(
        &self,
        validators: &ValidatorSet,
        beacon: Option<&EpochBeacon>,
    ) -> bool {
        self.verify_unified_with_pq_keys_and_beacon_inner(
            validators,
            None,
            beacon,
            cnvrf_v3_active_at(self.height),
        )
    }

    #[cfg(test)]
    pub(crate) fn verify_with_beacon_active(
        &self,
        validators: &ValidatorSet,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> bool {
        self.verify_unified_with_pq_keys_and_beacon_inner(validators, None, beacon, cnvrf_v3_active)
    }

    /// Unified certificate verification supporting:
    /// 1. Post-quantum µQC (`PQ_UQC_MARKER_ID`) and CEC Epoch (`PQ_QC_MARKER_ID`) envelopes.
    ///
    /// C1 split (FIXES §1.7): at/after `QC_SPLIT_ACTIVATION_HEIGHT` the µQC
    /// branch is advisory-only and refuses (`verify_micro_cert` fails closed
    /// when the split is active), so only the full network QC (epoch/CEC,
    /// ≥ `pq_full_required_power`) verifies. Pre-activation the legacy
    /// network-anchored `max` rule applies unchanged.
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
        self.verify_unified_with_pq_keys_and_beacon_inner(validators, pq_keys, None, false)
    }

    fn verify_unified_with_pq_keys_and_beacon_inner(
        &self,
        validators: &ValidatorSet,
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
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
        if self.pq_path_verify_with_beacon(validators, &msg, pq_keys, beacon, cnvrf_v3_active) {
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
    fn pq_path_verify_with_beacon(
        &self,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> bool {
        // AMBIGUITY FAILS CLOSED (PENTEST F-4): `binds_to_parent` pins the
        // µQC parent, while the loop below accepts ANY verifying envelope. If
        // the markers disagree about the sortition parent, the two would
        // describe different committees, so the certificate is refused before
        // either verdict can disagree. A repeated identical marker still
        // resolves and is handled by the loop unchanged.
        if self.resolve_micro_certificate().is_err() {
            return false;
        }
        for (voter, payload) in &self.signatures {
            if *voter == PQ_UQC_MARKER_ID {
                if let Some(cert) = decode_pq_micro_envelope(payload) {
                    if !cert.scheme.is_post_quantum() {
                        continue;
                    }
                    // Borrow-compat: `verify_micro_cert_with_beacon` takes an owned snapshot;
                    // clone the (small, test/override-only) map. Same data.
                    if self.verify_micro_cert_with_beacon(
                        &cert,
                        validators,
                        msg,
                        pq_keys.cloned(),
                        beacon,
                        cnvrf_v3_active,
                    ) {
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
        staged.par_chunks(CHUNK).all(|chunk| {
            chunk
                .iter()
                .all(|(_, scheme, pubkey, sig)| one(*scheme, pubkey, msg, sig))
        })
    }

    fn micro_cert_valid_signers_with_beacon(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> Option<Vec<ValidatorId>> {
        self.micro_cert_valid_signers_and_committee_with_beacon(
            cert,
            validators,
            msg,
            pq_keys,
            beacon,
            cnvrf_v3_active,
        )
        .map(|(signers, _)| signers)
    }

    fn micro_cert_valid_signers_and_committee_with_beacon(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<&HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> Option<(Vec<ValidatorId>, Vec<ValidatorId>)> {
        // C1 split (FIXES §1.7), fail-closed at the SHARED choke point: at/
        // after `QC_SPLIT_ACTIVATION_HEIGHT` the µQC is advisory-only, so it
        // names no signers and carries no power. `verify_micro_cert_with_beacon`
        // already refuses it; gating here as well makes ATTRIBUTION
        // (`signers_set` → `qc_signed_power` → `qc_meets_quorum`) refuse it
        // too. Without this, a decision boundary that counts power through
        // attribution (the recommended primitive) would accept the very
        // certificate the verifier refuses — the split would be bypassed.
        if qc_split_active_at(self.height) {
            return None;
        }
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

        // Pre-activation: the committee is re-derived from the certificate's OWN
        // sortition parent (`derive_sortition_committee`), while `binds_to_parent`
        // pins that parent to `block.prev_hash`.
        // Post-activation (CN-VRF v3): the committee is drawn from the
        // 7,200-block epoch beacon (`cnvrf_v3_beacon_draw_committee`) without
        // mixing `sortition_parent` (eliminating parent-hash grinding), while
        // `binds_to_parent` STILL pins `cert.sortition_parent == block.prev_hash`
        // so certificates remain chain-bound. Fails closed if beacon is missing
        // or carries the wrong epoch.
        let committee = if cnvrf_v3_active {
            let b = beacon?;
            if b.epoch != cnvrf_v3_epoch_of_height(cert.height) {
                return None;
            }
            cnvrf_v3_beacon_draw_committee(
                validators,
                cert.height,
                cert.round,
                cert.committee_size,
                &b.output,
                b.epoch,
            )
        } else {
            derive_sortition_committee(
                validators,
                cert.height,
                cert.round,
                cert.committee_size,
                &cert.sortition_parent,
            )
        };
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
                    .or_else(|| pq_key_at_height(val_id, cert.height));
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
        Some((
            staged.into_iter().map(|(id, _, _, _)| id).collect(),
            committee,
        ))
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
    /// Election: parent-hash draw before `CNVRF_V3_ACTIVATION_HEIGHT`, or
    /// CN-VRF v3 epoch-beacon draw when `cnvrf_v3_active` is true.
    fn verify_micro_cert_with_beacon(
        &self,
        cert: &PqMicroCertificate,
        validators: &ValidatorSet,
        msg: &[u8],
        pq_keys: Option<HashMap<ValidatorId, (crate::post_quantum::PqScheme, Vec<u8>)>>,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> bool {
        // C1 split (FIXES §1.7): at/after `QC_SPLIT_ACTIVATION_HEIGHT` the
        // µQC is ADVISORY-ONLY and never finalizes — refuse outright, even
        // at full-network power. Finality requires the full network QC (the
        // epoch/CEC path, `verify_epoch_cert` ≥ `pq_full_required_power`).
        // Before activation this gate is inert (`u64::MAX` default) and the
        // legacy network-anchored `max` rule below applies byte-identically.
        if qc_split_active_at(self.height) {
            return false;
        }
        let Some((valid, committee)) = self.micro_cert_valid_signers_and_committee_with_beacon(
            cert,
            validators,
            msg,
            pq_keys.as_ref(),
            beacon,
            cnvrf_v3_active,
        ) else {
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
        let committee_total_u128: u128 = committee
            .iter()
            .map(|id| validators.power_of(id) as u128)
            .sum();
        if committee_total_u128 == 0 {
            return false;
        }
        let committee_total: u64 = committee_total_u128.min(u64::MAX as u128) as u64;
        let network_total_u128: u128 = validators.validators.values().map(|&p| p as u128).sum();
        let quorum_power = pq_micro_required_power(committee_total, validators.total_power());
        // Cross-level gate (P1, `papers/01_quorum.md` §4 Cor. 3): a µQC that
        // verifies here must ALSO intersect every full-QC threshold honestly —
        // `T_µ + T_f − W > B`. With the network term at the BFT floor this
        // holds by construction for all `B_w < W/3`; the check stays as a
        // fail-closed tripwire so a future threshold edit that breaks the
        // pair condition refuses instead of finalizing. On the live
        // (whole-set committee) topology the predicate is identically true.
        if !mixed_quorum_pair_safe(
            quorum_power,
            validators.quorum_power(),
            validators.total_power(),
        ) {
            return false;
        }
        let valid_power: u128 = valid.iter().map(|id| validators.power_of(id) as u128).sum();
        let network_required: u128 = (network_total_u128 * 2) / 3 + 1;
        let committee_required: u128 = (committee_total_u128 * 2) / 3 + 1;
        valid_power
            >= (quorum_power as u128)
                .max(network_required)
                .max(committee_required)
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
        if cert.committee_size == 0
            || cert.committee_size as usize > MAX_COMMIT_CERT_SIGNERS
            || cert.committee_size as usize != total_validators
        {
            return None;
        }

        let expected_bitmask_len = total_validators.div_ceil(8);
        if cert.signers_bitmask.len() != expected_bitmask_len {
            return None;
        }
        for i in total_validators..(cert.signers_bitmask.len() * 8) {
            if (cert.signers_bitmask[i / 8] & (1 << (i % 8))) != 0 {
                return None;
            }
        }

        let mut ids: Vec<ValidatorId> = validators.validators.keys().copied().collect();
        ids.sort_unstable();

        let signed_count = cert.signed_count();
        let is_compact = cert.signatures.len() == signed_count;
        let is_full = cert.signatures.len() == ids.len();
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
                    .or_else(|| pq_key_at_height(val_id, cert.height));
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
        let power: u128 = valid.iter().map(|id| validators.power_of(id) as u128).sum();
        let total: u128 = validators.validators.values().map(|&p| p as u128).sum();
        if total == 0 {
            return false;
        }
        let required: u128 = (total * 2) / 3 + 1;
        power >= required
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

    /// Resolve the single µQC this certificate carries, refusing AMBIGUITY.
    ///
    /// PENTEST F-4 (LOW): `pq_micro_certificate` used to return the FIRST
    /// decodable `PQ_UQC_MARKER_ID` entry, while `pq_path_verify_with_beacon`
    /// accepted ANY verifying envelope. A QC carrying a decoy µQC (elected
    /// with the correct parent) followed by a genuine µQC elected with
    /// another parent therefore had `binds_to_parent` inspect the decoy and
    /// `verify` inspect the genuine one: the parent pin described a
    /// certificate that was not the one that verified.
    ///
    /// Every decodable µQC marker must name the SAME `sortition_parent` (a
    /// repeated identical marker is harmless and still resolves), otherwise
    /// the certificate is ambiguous and is refused as a whole (`Err`).
    /// An over-cap signer list is refused here too, so binding cannot walk an
    /// unbounded attacker-supplied list before `verify`'s cap runs.
    fn resolve_micro_certificate(&self) -> Result<Option<PqMicroCertificate>, ()> {
        if self.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return Err(());
        }
        let mut found: Option<PqMicroCertificate> = None;
        for (voter, payload) in &self.signatures {
            if *voter != PQ_UQC_MARKER_ID {
                continue;
            }
            // An undecodable marker can never verify (both the canonical and
            // the bincode decode are tried by `decode_pq_micro_envelope`), so
            // it carries no committee and is ignored — exactly as it
            // contributes nothing to verification or attribution.
            let Some(cert) = decode_pq_micro_envelope(payload) else {
                continue;
            };
            match &found {
                None => found = Some(cert),
                Some(first) if first.sortition_parent != cert.sortition_parent => return Err(()),
                Some(_) => {}
            }
        }
        Ok(found)
    }

    /// Retrieve the post-quantum micro-certificate (µQC) from this
    /// QuorumCertificate, if present.
    ///
    /// `None` when the certificate carries no µQC OR carries ambiguous µQC
    /// markers (see [`Self::resolve_micro_certificate`]). Callers that need to
    /// distinguish "no µQC" from "ambiguous" use [`Self::binds_to_parent`],
    /// which fails closed on ambiguity.
    pub fn pq_micro_certificate(&self) -> Option<PqMicroCertificate> {
        self.resolve_micro_certificate().ok().flatten()
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
    ///
    /// AMBIGUITY FAILS CLOSED (PENTEST F-4): a certificate carrying µQC
    /// markers that name different sortition parents is refused (`false`)
    /// rather than bound to whichever marker happened to come first. The
    /// verifier refuses the same certificate (see
    /// [`Self::resolve_micro_certificate`]), so binding and verification can
    /// never describe different committees.
    pub fn binds_to_parent(&self, parent_hash: &[u8; 32]) -> bool {
        match self.resolve_micro_certificate() {
            Err(()) => false,
            Ok(Some(cert)) => &cert.sortition_parent == parent_hash,
            Ok(None) => true,
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
    /// C1 split: at/after `QC_SPLIT_ACTIVATION_HEIGHT` a µQC is
    /// advisory-only, so it attributes NOBODY here (the gate lives in
    /// `micro_cert_valid_signers_and_committee_with_beacon`). That keeps
    /// `qc_signed_power` / `qc_meets_quorum` fail-closed for the same
    /// certificate `verify` refuses — a decision boundary cannot promote a
    /// µQC through power accounting.
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
        self.signers_set_with_beacon_inner(validators, None, false)
    }

    /// Extracts verified signer IDs using the CN-VRF v3 epoch beacon draw when
    /// `cnvrf_v3_active_at(self.height)` is true; below `CNVRF_V3_ACTIVATION_HEIGHT`
    /// behaves byte-identically to [`Self::signers_set`].
    pub fn signers_set_with_beacon(
        &self,
        validators: &ValidatorSet,
        beacon: Option<&EpochBeacon>,
    ) -> HashSet<ValidatorId> {
        self.signers_set_with_beacon_inner(validators, beacon, cnvrf_v3_active_at(self.height))
    }

    fn signers_set_with_beacon_inner(
        &self,
        validators: &ValidatorSet,
        beacon: Option<&EpochBeacon>,
        cnvrf_v3_active: bool,
    ) -> HashSet<ValidatorId> {
        // ANTI-DoS (pentest P1): `verify` already rejects an implausibly long
        // signer list BEFORE touching crypto, but ATTRIBUTION (`signers_set` /
        // `qc_signed_power` / `qc_meets_quorum`) walked the attacker-supplied
        // marker list unconditionally: 4,100 markers cost ~921 ms on the
        // proposal gate and ~971 ms in the sync refusal path, and a QC is
        // excluded from `compute_hash`, so a public block could be re-served
        // with a giant forged certificate WITHOUT any validator key. The same
        // cap now gates attribution: an over-limit list attributes NOBODY,
        // which is exactly the fail-closed verdict `verify` reaches.
        if self.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return HashSet::new();
        }
        // AMBIGUITY FAILS CLOSED (PENTEST F-4): attribution must describe the
        // same µQC `verify`/`binds_to_parent` resolve. Markers naming
        // different sortition parents attribute NOBODY, matching the
        // verifier's refusal for the same input.
        if self.resolve_micro_certificate().is_err() {
            return HashSet::new();
        }
        let mut signers = HashSet::new();
        let msg = vote_sign_bytes(self.height, self.round, self.kind, &self.block_hash);
        for (voter, payload) in &self.signatures {
            if *voter == PQ_UQC_MARKER_ID {
                // Verify-grade: exactly what `verify_micro_cert_with_beacon` accepts
                // (sans the quorum-power gate — a genuinely-signed member is named
                // even in a sub-quorum certificate, so nobody is slashed for
                // signing). A schemaless bincode parse of a non-envelope
                // payload used to land on garbage bitmask bytes and attribute
                // the wrong validators; a forged envelope now attributes none.
                if let Some(cert) = decode_pq_micro_envelope(payload) {
                    if !cert.scheme.is_post_quantum() {
                        continue;
                    }
                    if let Some(ids) = self.micro_cert_valid_signers_with_beacon(
                        &cert,
                        validators,
                        &msg,
                        None,
                        beacon,
                        cnvrf_v3_active,
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

#[cfg(test)]
mod audit_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn make_validator_set(
        n: usize,
        power: u64,
    ) -> (ValidatorSet, Vec<(ValidatorId, FalconKeypair)>) {
        let mut vs = ValidatorSet::new();
        let mut keys = Vec::with_capacity(n);
        for i in 0..n {
            let fk = FalconKeypair::generate_from_seed(0x40 + i as u8);
            let mut id = [0u8; 32];
            id[0] = (i + 1) as u8;
            id[1] = 0xA5;
            vs.add(id, power);
            keys.push((id, fk));
        }
        (vs, keys)
    }

    #[test]
    fn epoch_cert_committee_size_u32_max_fails_fast() {
        let (vs, _) = make_validator_set(4, 100);
        let cert = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            10,
            1,
            u32::MAX,
            vec![0x0F],
            Vec::new(),
            [0u8; 32],
        );
        let qc = QuorumCertificate {
            height: 10,
            round: 1,
            kind: VoteKind::Precommit,
            block_hash: Some([0x11u8; 32]),
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&cert))],
        };

        let start = Instant::now();
        assert!(!qc.verify(&vs));
        assert!(qc.signers_set(&vs).is_empty());
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(5),
            "u32::MAX committee_size DoS check took too long: {elapsed:?}"
        );
    }

    #[test]
    fn epoch_cert_rejects_trailing_nonzero_bits_and_bad_committee_sizes() {
        let (vs, keys) = make_validator_set(3, 100);
        let mut pq_map = HashMap::new();
        for (id, fk) in &keys {
            pq_map.insert(
                *id,
                (
                    crate::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                ),
            );
        }

        let mut ids: Vec<ValidatorId> = vs.validators.keys().copied().collect();
        ids.sort_unstable();
        let block_hash = Some([0x22u8; 32]);
        let msg = vote_sign_bytes(5, 0, VoteKind::Precommit, &block_hash);
        let sigs: Vec<Vec<u8>> = ids
            .iter()
            .map(|id| {
                let (_, fk) = keys.iter().find(|(k_id, _)| k_id == id).unwrap();
                fk.sign(&msg)
            })
            .collect();

        // Valid 3-of-3 epoch cert passes with explicit pq_keys.
        let valid_cert = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            5,
            0,
            3,
            vec![0b0000_0111],
            sigs.clone(),
            [0u8; 32],
        );
        let valid_qc = QuorumCertificate {
            height: 5,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash,
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&valid_cert))],
        };
        assert!(valid_qc.verify_unified_with_pq_keys(&vs, Some(&pq_map)));

        // Trailing non-zero bit (bit 3 set for 3 validators) must fail closed.
        let mut trailing_cert = valid_cert.clone();
        trailing_cert.signers_bitmask = vec![0b0000_1111];
        let trailing_qc = QuorumCertificate {
            height: 5,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash,
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&trailing_cert))],
        };
        assert!(!trailing_qc.verify_unified_with_pq_keys(&vs, Some(&pq_map)));
        assert!(trailing_qc.signers_set(&vs).is_empty());

        // committee_size == 0 must fail closed.
        let mut zero_cert = valid_cert.clone();
        zero_cert.committee_size = 0;
        let zero_qc = QuorumCertificate {
            height: 5,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash,
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&zero_cert))],
        };
        assert!(!zero_qc.verify_unified_with_pq_keys(&vs, Some(&pq_map)));
        assert!(zero_qc.signers_set(&vs).is_empty());

        // committee_size != total_validators must fail closed.
        let mut mismatch_cert = valid_cert.clone();
        mismatch_cert.committee_size = 4;
        let mismatch_qc = QuorumCertificate {
            height: 5,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash,
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&mismatch_cert))],
        };
        assert!(!mismatch_qc.verify_unified_with_pq_keys(&vs, Some(&pq_map)));
        assert!(mismatch_qc.signers_set(&vs).is_empty());

        // Extra unverified signature beyond ids.len() must fail closed.
        let mut extra_sig_cert = valid_cert;
        extra_sig_cert.signatures.push(vec![0u8; 666]);
        let extra_sig_qc = QuorumCertificate {
            height: 5,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash,
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&extra_sig_cert))],
        };
        assert!(!extra_sig_qc.verify_unified_with_pq_keys(&vs, Some(&pq_map)));
        assert!(extra_sig_qc.signers_set(&vs).is_empty());
    }

    #[test]
    fn stake_summation_never_panics_or_wraps_above_u64_max() {
        let huge = u64::MAX / 2 + 100;
        let (vs, keys) = make_validator_set(3, huge);
        // Must saturate instead of panicking or wrapping around u64::MAX.
        assert_eq!(vs.total_power(), u64::MAX);
        assert!(vs.proposer_for(1, 0).is_some());

        let mut pq_map = HashMap::new();
        for (id, fk) in &keys {
            pq_map.insert(
                *id,
                (
                    crate::post_quantum::PqScheme::Falcon512,
                    fk.public_key.clone(),
                ),
            );
        }

        let mut ids: Vec<ValidatorId> = vs.validators.keys().copied().collect();
        ids.sort_unstable();
        let block_hash = Some([0x33u8; 32]);
        let msg = vote_sign_bytes(7, 0, VoteKind::Precommit, &block_hash);
        let sigs: Vec<Vec<u8>> = ids
            .iter()
            .map(|id| {
                let (_, fk) = keys.iter().find(|(k_id, _)| k_id == id).unwrap();
                fk.sign(&msg)
            })
            .collect();

        // 1-of-3 holds < 2/3 of network stake; must fail without wraparound.
        let one_cert = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            7,
            0,
            3,
            vec![0b0000_0001],
            vec![sigs[0].clone()],
            [0u8; 32],
        );
        let one_qc = QuorumCertificate {
            height: 7,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash,
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&one_cert))],
        };
        assert!(!one_qc.verify_unified_with_pq_keys(&vs, Some(&pq_map)));

        // 3-of-3 holds 100% of stake; u128 sum passes without panicking/wrapping.
        let full_cert = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            7,
            0,
            3,
            vec![0b0000_0111],
            sigs,
            [0u8; 32],
        );
        let full_qc = QuorumCertificate {
            height: 7,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash,
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&full_cert))],
        };
        assert!(full_qc.verify_unified_with_pq_keys(&vs, Some(&pq_map)));
    }
}
