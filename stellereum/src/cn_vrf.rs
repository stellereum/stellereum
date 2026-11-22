//! Committed-Nonce VRF (CN-VRF) — SANDBOX pure module.
//!
//! Spec: `docs/PQ_CN_VRF_SPEC.md` (lead-REVIEWED, SPEC ONLY). This module is the
//! sandbox implementation: pure functions + Known-Answer Tests, NO consensus
//! wiring (forbidden before external audit, spec §7).
//!
//! Construction: two-phase per-validator verifiable randomness. COMMIT in epoch
//! N−1, OPEN+PROVE in epoch N. Primitives: Falcon-512 EUF-CMA signatures +
//! SHAKE-256 only (assumptions A1/A2), 32 fresh OS-random nonce bytes per
//! (validator, epoch) (A3).
//!
//! Purity contract: this module imports NOTHING from `consensus` or `staking`.
//! `validator_id` is `[u8; 32]`, `chain_id`/`epoch`/`height` are `u64` params.
//! Consensus-owned reads (active key at height, canonical alpha, current epoch)
//! are caller-supplied arguments — never resolved here.
//!
//! Lead decisions on the spec open questions (baked in as consts, documented):
//! - O1: [`EPOCH_LEN`] = 30000 heights (== `PQ_ROTATION_DELAY_HEIGHTS`); one
//!   rotation window = one epoch. `epoch(N)` = heights `[N*30000, (N+1)*30000)`.
//! - O2: per-draw tickets (each validator's verified beta is their ticket);
//!   missing beta → [`cnvrf_verify`] returns `None`, caller falls back to the
//!   legacy draw (mirrors `vrf_verify`'s `Option` shape).
//! - O3: same-block reveal allowed (reveal rides the draw block); leak window
//!   = 0 pre-block.
//! - O4: block-carried carriers + staking-hook-shaped pure functions: commit /
//!   open / verify are provided as pure fns ([`cnvrf_commit`], [`cnvrf_open`],
//!   [`cnvrf_verify`]); NO hooks are wired here.
//! - O5: abort calibration reuse-as-is — no new counters; absence flows into
//!   the EXISTING downtime path via [`cnvrf_draw_absence`] (caller-tested;
//!   see `tests/cn_vrf_tests.rs` group 6).
//! - O6: nonce custody signer-side 0600 ([`load_cnvrf_nonce_from_file`] /
//!   [`save_cnvrf_nonce_to_file`], mirroring the `node_keys.rs` secret-file
//!   posture — the old `vrf.rs` secret helpers were deleted with ECVRF).
//! - O7: caller-held side map ([`CnVrfCommitments`]) + pure transition fns
//!   ([`cnvrf_commit_state`], [`cnvrf_mark_revealed`], [`cnvrf_expire_before`]);
//!   NO persistence wiring.
//! - O8: SHAKE-256 via the tree hand-rolled NIST-KAT-pinned sponge: the
//!   permutation is `crate::post_quantum::keccak_f1600` (same code path as
//!   `post_quantum.rs:657-744`), wrapped in a local absorb/squeeze that is
//!   pinned against the same NIST vectors (see `tests/cn_vrf_tests.rs`).
//!   No new dependencies.
//! - O9: activation waits one full epoch ([`first_usable_epoch`]).
//! - O10: max one pending commitment — commit only for `current_epoch + 1`
//!   ([`cnvrf_commit_state`] refuses anything else).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::post_quantum::{
    verify_pq_signature, FalconKeypair, PqScheme, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN,
};

// ---------------------------------------------------------------------------
// Lead-decided constants (O1, O8, spec §1.2 / §1.7)
// ---------------------------------------------------------------------------

/// Epoch length in heights (O1): one PQ rotation window = one epoch.
///
/// RULESET v2: 30,000 heights x 240 ms = **7,200 s (2 h)**. The v1 value of
/// 7,200 heights was calibrated at 3 s blocks but had shrunk to ~28.8 min at
/// the live ~240 ms tempo. Full table: `docs/RULESET_V2.md`.
///
/// FREEZE (protocol freeze 2026-11-03): deterministic const, never env
/// (spec docs/specs/02_CRYPTO_AND_PQ_PHASE2.md §6, == PQ_ROTATION_DELAY_HEIGHTS).
/// Change requires spec update + audit note (AGENTS.md §7).
pub const EPOCH_LEN: u64 = 30_000;

/// Domain separation: commitment preimage (spec §1.2).
pub const CNVRF_COMMIT_DST: &[u8] = b"STELL_CNVRF_COMMIT_V1";
/// Domain separation: commit-carrier authentication signature over the public commitment.
pub const CNVRF_COMMIT_SIG_DST: &[u8] = b"STELL_CNVRF_COMMIT_SIG_V1";
/// Domain separation: Falcon-signed open message (spec §1.2).
pub const CNVRF_OPEN_DST: &[u8] = b"STELL_CNVRF_OPEN_V1";
/// Domain separation: beta derivation (spec §1.2).
pub const CNVRF_BETA_DST: &[u8] = b"STELL_CNVRF_BETA_V1";

/// Falcon-512 proof length: `pi` is EXACTLY 666 bytes (spec §3.3).
pub const CNVRF_PI_LEN: usize = FALCON512_SIG_LEN;
/// Falcon-512 public key length: `pk` is EXACTLY 897 bytes.
pub const CNVRF_PK_LEN: usize = FALCON512_PUBKEY_LEN;
/// `nonce` / `c` / `beta` / `alpha` are EXACTLY 32 bytes (spec §3.3).
pub const CNVRF_FIELD_LEN: usize = 32;

/// Commitment preimage length: 21 + 8 + 32 + 8 + 32 = 101 B (spec §1.3).
///
/// SPEC ARITHMETIC NOTE: §1.3 prints "20 B" for the tag and "total: 100 B",
/// but the normative tag VALUE `b"STELL_CNVRF_COMMIT_V1"` is 21 bytes
/// (6+6+6+3), so the true total is 101. Tag values are authoritative; the
/// spec's totals are off by one. Same for the open (131, not 130) and beta
/// (123, not 122) preimages below.
pub const COMMIT_PREIMAGE_LEN: usize = 101;
/// Commit-carrier signature message length: 25 + 8 + 32 + 8 + 32 = 105 B.
pub const COMMIT_SIG_MESSAGE_LEN: usize = 105;
/// Open message length: 19 + 8 + 32 + 8 + 32 + 32 = 131 B (spec §1.4; the
/// normative `CNVRF_OPEN_DST` is 19 bytes, spec prints 18 — see note above).
pub const OPEN_MESSAGE_LEN: usize = 131;
/// Beta preimage length: 19 + 32 + 32 + 32 + 8 = 123 B (spec §1.4; the
/// normative `CNVRF_BETA_DST` is 19 bytes, spec prints 18 — see note above).
pub const BETA_PREIMAGE_LEN: usize = 123;

/// `CommitCarrier` on-wire bytes: 32 + 666 + 32 + 8 = 738 B (spec §1.7).
pub const COMMIT_CARRIER_LEN: usize = 738;
/// `RevealCarrier` on-wire bytes: 32 + 8 + 32 + 32 + 666 = 770 B (spec §1.7).
pub const REVEAL_CARRIER_LEN: usize = 770;

/// Validator identity: the 32 consensus validator-id bytes (spec §1.1).
/// Local alias (NOT `crate::consensus::ValidatorId` — no consensus imports).
pub type ValidatorId = [u8; 32];

/// Caller-held commitment store (O7, spec §3.1): deterministic `BTreeMap`
/// (never `HashMap`), mirroring the `PqRegistry` precedent.
pub type CnVrfCommitments = BTreeMap<(ValidatorId, u64), CommitmentRecord>;

// ---------------------------------------------------------------------------
// SHAKE-256 (O8): tree sponge permutation, local absorb/squeeze
// ---------------------------------------------------------------------------

/// SHAKE-256 squeeze of exactly 32 bytes over `data`.
///
/// Absorb/squeeze replicates `post_quantum.rs:663-708` (`Shake256Reader`,
/// which is module-private): 136-byte rate, `0x1F` domain pad, `0x80` final
/// bit. The permutation IS the tree one
/// (`crate::post_quantum::keccak_f1600`) — same code path as the NIST-KAT
/// test `test_shake256_matches_the_nist_test_vectors` (post_quantum.rs). Pinned against the NIST vectors in
/// `tests/cn_vrf_tests.rs` (empty + "abc" 32-byte digests, 64-byte squeeze).
pub fn shake256_32(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256_xof(data, &mut out);
    out
}

/// General SHAKE-256 XOF squeeze (any output length; same sponge as
/// [`shake256_32`]).
pub fn shake256_xof(data: &[u8], out: &mut [u8]) {
    const RATE: usize = 136;
    const WORDS: usize = RATE / 8;
    let mut state = [0u64; 25];
    let mut offset = 0;
    while offset + RATE <= data.len() {
        for (word, chunk) in state
            .iter_mut()
            .take(WORDS)
            .zip(data[offset..offset + RATE].chunks_exact(8))
        {
            let bytes: [u8; 8] = chunk.try_into().expect("chunks_exact(8) yields 8 bytes");
            *word ^= u64::from_le_bytes(bytes);
        }
        crate::post_quantum::keccak_f1600(&mut state);
        offset += RATE;
    }
    let mut block = [0u8; RATE];
    let rem = data.len() - offset;
    block[..rem].copy_from_slice(&data[offset..]);
    block[rem] = 0x1F;
    block[RATE - 1] |= 0x80;
    for (word, chunk) in state.iter_mut().take(WORDS).zip(block.chunks_exact(8)) {
        let bytes: [u8; 8] = chunk.try_into().expect("chunks_exact(8) yields 8 bytes");
        *word ^= u64::from_le_bytes(bytes);
    }
    crate::post_quantum::keccak_f1600(&mut state);
    let mut done = 0;
    while done < out.len() {
        for word in state.iter().take(WORDS) {
            if done >= out.len() {
                return;
            }
            let bytes = word.to_le_bytes();
            let take = core::cmp::min(8, out.len() - done);
            out[done..done + take].copy_from_slice(&bytes[..take]);
            done += take;
        }
        if done < out.len() {
            crate::post_quantum::keccak_f1600(&mut state);
        }
    }
}

// ---------------------------------------------------------------------------
// Exact byte-level preimages (spec §1.3 / §1.4)
// ---------------------------------------------------------------------------

/// `commit_preimage = COMMIT_DST || chain_id(le) || validator_id || epoch(le)
/// || nonce` — exactly 100 bytes (spec §1.3).
pub fn commit_preimage_bytes(
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMMIT_PREIMAGE_LEN);
    out.extend_from_slice(CNVRF_COMMIT_DST);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(validator_id);
    out.extend_from_slice(&epoch_n.to_le_bytes());
    out.extend_from_slice(nonce);
    debug_assert_eq!(out.len(), COMMIT_PREIMAGE_LEN);
    out
}

/// `open_message(alpha) = OPEN_DST || chain_id(le) || validator_id ||
/// epoch(le) || nonce || alpha` — exactly 130 bytes (spec §1.4).
pub fn open_message_bytes(
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    nonce: &[u8; 32],
    alpha: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(OPEN_MESSAGE_LEN);
    out.extend_from_slice(CNVRF_OPEN_DST);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(validator_id);
    out.extend_from_slice(&epoch_n.to_le_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(alpha);
    debug_assert_eq!(out.len(), OPEN_MESSAGE_LEN);
    out
}

/// `beta_preimage = BETA_DST || nonce || alpha || validator_id || epoch(le)`
/// — exactly 122 bytes (spec §1.4). Nonce BEFORE alpha by construction.
pub fn beta_preimage_bytes(
    nonce: &[u8; 32],
    alpha: &[u8; 32],
    validator_id: &[u8; 32],
    epoch_n: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(BETA_PREIMAGE_LEN);
    out.extend_from_slice(CNVRF_BETA_DST);
    out.extend_from_slice(nonce);
    out.extend_from_slice(alpha);
    out.extend_from_slice(validator_id);
    out.extend_from_slice(&epoch_n.to_le_bytes());
    debug_assert_eq!(out.len(), BETA_PREIMAGE_LEN);
    out
}

/// `commit_sig_message = COMMIT_SIG_DST || chain_id(le) || validator_id ||
/// epoch(le) || commitment` — exactly 105 bytes. Signs the PUBLIC commitment
/// `c` (never the secret `nonce`) so epoch N−1 verifiers can authenticate
/// `CommitCarrier` without learning `nonce`.
pub fn commit_sig_message_bytes(
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    commitment: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMMIT_SIG_MESSAGE_LEN);
    out.extend_from_slice(CNVRF_COMMIT_SIG_DST);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(validator_id);
    out.extend_from_slice(&epoch_n.to_le_bytes());
    out.extend_from_slice(commitment);
    debug_assert_eq!(out.len(), COMMIT_SIG_MESSAGE_LEN);
    out
}

/// `c = SHAKE256(commit_preimage, 32)` (spec §1.3).
pub fn commit_hash(
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    nonce: &[u8; 32],
) -> [u8; 32] {
    shake256_32(&commit_preimage_bytes(
        chain_id,
        validator_id,
        epoch_n,
        nonce,
    ))
}

// ---------------------------------------------------------------------------
// Carriers (spec §1.3 / §1.4, byte budgets §1.7)
// ---------------------------------------------------------------------------

/// Commitment carrier published in epoch N−1 (spec §1.3). On-wire 738 B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCarrier {
    /// The 32-byte consensus validator id.
    pub validator_id: [u8; 32],
    /// The FUTURE epoch this commits to.
    pub epoch_n: u64,
    /// `c = SHAKE256(commit_preimage, 32)`.
    pub c: [u8; 32],
    /// Falcon-512 sig over `commit_sig_message_bytes(chain_id, validator_id, epoch_n, c)`
    /// by the registered PQ key (verifiable in epoch N−1 without `nonce`).
    pub sig: [u8; FALCON512_SIG_LEN],
}

impl CommitCarrier {
    /// On-wire byte budget: 738 B (spec §1.7).
    pub const fn encoded_len(&self) -> usize {
        COMMIT_CARRIER_LEN
    }
}

/// Reveal carrier published in epoch N per draw (spec §1.4). On-wire 770 B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevealCarrier {
    /// The 32-byte consensus validator id.
    pub validator_id: [u8; 32],
    /// The epoch this reveals for.
    pub epoch_n: u64,
    /// The epoch secret, revealed.
    pub nonce: [u8; 32],
    /// Echoed draw input; verifier checks it equals the canonical alpha.
    pub alpha: [u8; 32],
    /// Falcon-512 sig over `open_message(alpha)`. Randomized witness:
    /// fresh bytes EVERY call — beta does NOT depend on them (spec §2.2).
    pub pi: [u8; FALCON512_SIG_LEN],
}

impl RevealCarrier {
    /// On-wire byte budget: 770 B (spec §1.7).
    pub const fn encoded_len(&self) -> usize {
        REVEAL_CARRIER_LEN
    }
}

// ---------------------------------------------------------------------------
// API shapes (spec §3.3)
// ---------------------------------------------------------------------------

/// Error returned by commit-carrier verification and authenticated state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CnVrfError {
    /// Public key length is not `CNVRF_PK_LEN` (897 bytes).
    InvalidPublicKeyLength,
    /// Commit carrier signature is empty/zeroed or failed Falcon-512 verification.
    InvalidCommitSignature,
    /// Commitment state transition refused (stale/current or too far ahead).
    CommitState(CommitError),
}

impl core::fmt::Display for CnVrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicKeyLength => {
                write!(
                    f,
                    "invalid Falcon-512 public key length (expected {CNVRF_PK_LEN})"
                )
            }
            Self::InvalidCommitSignature => {
                write!(f, "invalid or empty commit carrier signature")
            }
            Self::CommitState(CommitError::StaleOrCurrent) => {
                write!(f, "commit epoch is stale or current (must be current + 1)")
            }
            Self::CommitState(CommitError::TooFarAhead) => {
                write!(f, "commit epoch is too far ahead (must be current + 1)")
            }
            Self::CommitState(CommitError::PastCommitCutoff) => {
                write!(
                    f,
                    "commit arrived at or after lookahead freeze cutoff H_freeze"
                )
            }
        }
    }
}

impl std::error::Error for CnVrfError {}

impl From<CommitError> for CnVrfError {
    fn from(err: CommitError) -> Self {
        Self::CommitState(err)
    }
}

/// Computes `c = commit_hash(chain_id, validator_id, epoch_n, nonce)` and signs
/// the PUBLIC commit-signature message `commit_sig_message_bytes(chain_id,
/// validator_id, epoch_n, &c)` with the registered Falcon key (never signing
/// the secret `nonce`, so epoch N−1 verifiers can authenticate the carrier).
/// Returns the commit carrier for epoch N (publish in epoch N−1).
///
/// `nonce`/`validator_id` lengths are type-enforced (`[u8; 32]`). If the
/// signer refuses (incomplete key — `sign` returns short), the carrier keeps
/// a zeroed `sig` so [`cnvrf_verify_commit`] and every downstream path
/// fail-closes cleanly.
pub fn cnvrf_commit(
    sk: &FalconKeypair,
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    nonce: &[u8; 32],
) -> CommitCarrier {
    let c = commit_hash(chain_id, validator_id, epoch_n, nonce);
    let msg = commit_sig_message_bytes(chain_id, validator_id, epoch_n, &c);
    let sig = sk.sign(&msg);
    let mut sig_arr = [0u8; FALCON512_SIG_LEN];
    if sig.len() == FALCON512_SIG_LEN {
        sig_arr.copy_from_slice(&sig);
    }
    CommitCarrier {
        validator_id: *validator_id,
        epoch_n,
        c,
        sig: sig_arr,
    }
}

/// Verifies a [`CommitCarrier`] in epoch N−1 WITHOUT knowing the secret `nonce`.
///
/// Fails closed on:
/// - `pk.len() != CNVRF_PK_LEN`
/// - empty / all-zero `carrier.sig`
/// - invalid Falcon-512 signature over `commit_sig_message_bytes(chain_id,
///   &carrier.validator_id, carrier.epoch_n, &carrier.c)`
pub fn cnvrf_verify_commit(
    carrier: &CommitCarrier,
    chain_id: u64,
    pk: &[u8],
) -> Result<(), CnVrfError> {
    if pk.len() != CNVRF_PK_LEN {
        return Err(CnVrfError::InvalidPublicKeyLength);
    }
    if carrier.sig.iter().all(|&b| b == 0) {
        return Err(CnVrfError::InvalidCommitSignature);
    }
    let msg =
        commit_sig_message_bytes(chain_id, &carrier.validator_id, carrier.epoch_n, &carrier.c);
    if !verify_pq_signature(PqScheme::Falcon512, pk, &msg, &carrier.sig) {
        return Err(CnVrfError::InvalidCommitSignature);
    }
    Ok(())
}

/// Signs `open_message(alpha)` (§1.4). Randomized under the hood
/// (`FalconKeypair::sign` mixes fresh OS entropy per call), but beta is
/// signature-independent (spec §2.2): any number of valid `pi` for the same
/// open message recompute the SAME beta.
pub fn cnvrf_open(
    sk: &FalconKeypair,
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    nonce: &[u8; 32],
    alpha: &[u8; 32],
) -> RevealCarrier {
    let msg = open_message_bytes(chain_id, validator_id, epoch_n, nonce, alpha);
    let pi = sk.sign(&msg);
    let mut pi_arr = [0u8; FALCON512_SIG_LEN];
    if pi.len() == FALCON512_SIG_LEN {
        pi_arr.copy_from_slice(&pi);
    }
    RevealCarrier {
        validator_id: *validator_id,
        epoch_n,
        nonce: *nonce,
        alpha: *alpha,
        pi: pi_arr,
    }
}

/// Pure beta recomputation, no key (spec §3.3). Used by verifiers after the
/// `pi` checks pass.
pub fn cnvrf_beta(
    nonce: &[u8; 32],
    alpha: &[u8; 32],
    validator_id: &[u8; 32],
    epoch_n: u64,
) -> [u8; 32] {
    shake256_32(&beta_preimage_bytes(nonce, alpha, validator_id, epoch_n))
}

/// The §1.6 VERIFY algorithm (cryptographic checks 1–3).
///
/// Check order fixed, cheapest structural checks first; ANY failure ⇒ `None`
/// (fail-closed, mirrors `vrf_verify`'s `Option` return):
/// 1. length checks FIRST (`pk` == 897, `pi` == 666 — refuse else);
/// 2. recompute `c'` over the commitment preimage; mismatch ⇒ refuse;
/// 3. `Falcon.Verify(pk, open_message(alpha_canonical), pi)`; false ⇒ refuse;
/// 4. output `beta` recomputed from `(nonce, alpha_canonical, validator_id,
///    epoch_n)`.
///
/// Replay guards (§1.6 step 4) are caller-side and NOT resolved here (that
/// would need consensus/staking reads):
/// - 4a (epoch): caller compares `epoch_n` against
///   [`epoch_of_height`](epoch_of_height) of the draw height, or uses
///   [`cnvrf_verify_carrier`] with `expected_epoch`.
/// - 4b (chain): automatic — the caller passes ITS `chain_id`; a foreign
///   chain's bytes recompute different preimages and fail check 2/3.
/// - 4c (key freshness): the caller MUST pass the `pq_active_key`-at-height
///   read, never a carrier-supplied key; see [`cnvrf_verify_with_resolver`].
/// - 4d (alpha echo): caller compares the echoed alpha to the canonical one;
///   see [`cnvrf_verify_carrier`].
///
/// O2: missing beta → `None`; the CALLER falls back to the legacy draw.
#[allow(clippy::too_many_arguments)] // GATE: spec §3.3 pins this exact 8-arg shape; a params struct would change the mandated API.
pub fn cnvrf_verify(
    pk: &[u8],
    commitment: &[u8; 32],
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    alpha: &[u8; 32],
    nonce: &[u8; 32],
    pi: &[u8],
) -> Option<[u8; 32]> {
    // Length checks FIRST (envelope-strictness precedent).
    if pk.len() != CNVRF_PK_LEN {
        return None;
    }
    if pi.len() != CNVRF_PI_LEN {
        return None;
    }
    // Check 1: commitment binding.
    let c_prime = commit_hash(chain_id, validator_id, epoch_n, nonce);
    if c_prime != *commitment {
        return None;
    }
    // Check 2: Falcon authorization over the CANONICAL alpha's open message.
    let msg = open_message_bytes(chain_id, validator_id, epoch_n, nonce, alpha);
    if !verify_pq_signature(PqScheme::Falcon512, pk, &msg, pi) {
        return None;
    }
    // Check 3: deterministic beta (unique per commitment+alpha, §2.2).
    Some(cnvrf_beta(nonce, alpha, validator_id, epoch_n))
}

/// Carrier-level verify: guards 4a (epoch) + 4d (alpha echo) + validator
/// binding, then [`cnvrf_verify`].
///
/// - `expected_epoch`: the caller's current epoch (from [`epoch_of_height`]
///   of the draw height). `carrier.epoch_n != expected_epoch` ⇒ `None`.
/// - `alpha_canonical`: recomputed by the caller from the block header
///   (spec §1.5); echoed mismatch ⇒ `None`.
/// - `validator_id`: must equal the carrier's; mismatch ⇒ `None`.
/// - `pk`: MUST be the key-at-draw-height read (guard 4c), never a
///   carrier-supplied key.
/// - `commitment`: the stored `c` for `(validator_id, expected_epoch)`.
pub fn cnvrf_verify_carrier(
    pk: &[u8],
    commitment: &[u8; 32],
    chain_id: u64,
    validator_id: &[u8; 32],
    expected_epoch: u64,
    carrier: &RevealCarrier,
    alpha_canonical: &[u8; 32],
) -> Option<[u8; 32]> {
    if carrier.validator_id != *validator_id {
        return None;
    }
    if carrier.epoch_n != expected_epoch {
        return None;
    }
    if carrier.alpha != *alpha_canonical {
        return None;
    }
    cnvrf_verify(
        pk,
        commitment,
        chain_id,
        validator_id,
        expected_epoch,
        alpha_canonical,
        &carrier.nonce,
        &carrier.pi,
    )
}

/// Height-indexed verification (guard 4c shape, spec §2.9): resolves the
/// authoritative key AT THE DRAW HEIGHT through a caller-supplied resolver
/// (in production: the `pq_active_key(validator, height)` read; in tests: a
/// mock closure — NEVER a staking import here), then [`cnvrf_verify`].
/// Unresolvable key ⇒ `None`.
#[allow(clippy::too_many_arguments)] // GATE: mirrors the spec-pinned cnvrf_verify shape plus the caller-held resolver; grouping would diverge from §3.3.
pub fn cnvrf_verify_with_resolver(
    key_at_height: &dyn Fn([u8; 32], u64) -> Option<Vec<u8>>,
    commitment: &[u8; 32],
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    draw_height: u64,
    alpha: &[u8; 32],
    nonce: &[u8; 32],
    pi: &[u8],
) -> Option<[u8; 32]> {
    let pk = key_at_height(*validator_id, draw_height)?;
    cnvrf_verify(
        &pk,
        commitment,
        chain_id,
        validator_id,
        epoch_n,
        alpha,
        nonce,
        pi,
    )
}

// ---------------------------------------------------------------------------
// Epoch helpers (O1, O9)
// ---------------------------------------------------------------------------

/// `epoch(h) = h / EPOCH_LEN`; `epoch(N)` covers `[N*EPOCH_LEN, (N+1)*EPOCH_LEN)` (O1).
pub const fn epoch_of_height(height: u64) -> u64 {
    height / EPOCH_LEN
}

/// First height of epoch N (saturates at `u64::MAX` on overflow).
pub const fn epoch_start_height(epoch_n: u64) -> u64 {
    epoch_n.saturating_mul(EPOCH_LEN)
}

/// First usable epoch after activation (O9): activation waits one full epoch
/// (no N−1 exists for the activation epoch itself, spec O9), so the first
/// committable epoch is `activation_epoch + 1`.
pub const fn first_usable_epoch(activation_epoch: u64) -> u64 {
    activation_epoch.saturating_add(1)
}

// ---------------------------------------------------------------------------
// State machine (O7, spec §3.1)
// ---------------------------------------------------------------------------

/// Stored commitment per (validator, epoch) (spec §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentRecord {
    /// The commitment `c`.
    pub c: [u8; 32],
    /// Height that carried the commit (first wins).
    pub commit_height: u64,
    /// Set once a valid reveal lands (O3 timing: same-block reveal allowed).
    pub revealed: bool,
}

/// Outcome of [`cnvrf_commit_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// First valid commit for (validator, epoch): stored.
    Accepted,
    /// Double-commit for the same epoch: ignored, NOT an offense (spec §2.3:
    /// a commitment is not a vote, so no equivocation arm applies).
    IgnoredDuplicate,
}

/// Refusal of [`cnvrf_commit_state`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitError {
    /// Commit for a PAST or CURRENT epoch (backdating rule, mirrors
    /// `ActivationInPast`).
    StaleOrCurrent,
    /// Commit for epoch > current + 1 (at most one epoch lookahead, O10).
    TooFarAhead,
    /// Commit arrived inside the lookahead freeze window (`height >= H_freeze`).
    PastCommitCutoff,
}

/// Pure commit transition (O7/O10, spec §3.1 lifecycle):
/// ABSENT → COMMITTED. Refuses backdated (`epoch_n <= current_epoch`) and
/// far-future (`epoch_n > current_epoch + 1`) commits; second commit for the
/// same (validator, epoch) is ignored (first-committed-wins), never slashed.
pub fn cnvrf_commit_state(
    store: &mut CnVrfCommitments,
    validator_id: &[u8; 32],
    epoch_n: u64,
    c: &[u8; 32],
    commit_height: u64,
    current_epoch: u64,
) -> Result<CommitOutcome, CommitError> {
    if epoch_n <= current_epoch {
        return Err(CommitError::StaleOrCurrent);
    }
    if epoch_n > current_epoch.saturating_add(1) {
        return Err(CommitError::TooFarAhead);
    }
    use std::collections::btree_map::Entry;
    match store.entry((*validator_id, epoch_n)) {
        Entry::Occupied(_) => Ok(CommitOutcome::IgnoredDuplicate),
        Entry::Vacant(slot) => {
            slot.insert(CommitmentRecord {
                c: *c,
                commit_height,
                revealed: false,
            });
            Ok(CommitOutcome::Accepted)
        }
    }
}

/// Authenticated commit state transition: verifies `carrier.sig` against `pk`
/// and `chain_id` via [`cnvrf_verify_commit`] BEFORE inserting into `store`.
/// Blocks unauthenticated slot squatting (first-committed-wins cannot be
/// hijacked by forged or empty-sig `CommitCarrier`s).
pub fn cnvrf_commit_verified_state(
    store: &mut CnVrfCommitments,
    carrier: &CommitCarrier,
    chain_id: u64,
    pk: &[u8],
    commit_height: u64,
    current_epoch: u64,
) -> Result<CommitOutcome, CnVrfError> {
    cnvrf_verify_commit(carrier, chain_id, pk)?;
    cnvrf_commit_state(
        store,
        &carrier.validator_id,
        carrier.epoch_n,
        &carrier.c,
        commit_height,
        current_epoch,
    )
    .map_err(CnVrfError::CommitState)
}

/// Pure reveal-marking (O7): sets `revealed` once a VALID reveal lands.
/// Returns `true` iff an entry for `(validator_id, epoch_n)` exists AND
/// `epoch_n == current_epoch` (guard 4a: reveals are valid only in their
/// epoch). The caller MUST run [`cnvrf_verify`] (or
/// [`cnvrf_verify_carrier`]) BEFORE calling this — this fn marks, it does
/// not authenticate (O3: same-block reveal allowed, so no lead-time check).
pub fn cnvrf_mark_revealed(
    store: &mut CnVrfCommitments,
    validator_id: &[u8; 32],
    epoch_n: u64,
    current_epoch: u64,
) -> bool {
    if epoch_n != current_epoch {
        return false;
    }
    match store.get_mut(&(*validator_id, epoch_n)) {
        Some(rec) => {
            rec.revealed = true;
            true
        }
        None => false,
    }
}

/// Pure expiry (O7, spec §3.1): drops every entry with `epoch_n <
/// current_epoch` (epoch N ends without reveal ⇒ EXPIRED, treated absent per
/// §2.5). Deterministic (`BTreeMap` order). Returns the count removed.
pub fn cnvrf_expire_before(store: &mut CnVrfCommitments, current_epoch: u64) -> usize {
    let stale: Vec<(ValidatorId, u64)> = store
        .keys()
        .filter(|(_, epoch_n)| *epoch_n < current_epoch)
        .copied()
        .collect();
    let n = stale.len();
    for k in stale {
        store.remove(&k);
    }
    n
}

/// Abort-path predicate (O2/O5, spec §2.5): `true` = the validator contributes
/// NO ticket to this draw (no commitment, or committed-but-unrevealed) ⇒ the
/// caller falls back to the legacy draw for them AND charges absence through
/// the EXISTING downtime path (`note_missed_heights` — no new counters, no
/// equivocation arm; deliberate abort is downtime-only).
pub fn cnvrf_draw_absence(store: &CnVrfCommitments, validator_id: &[u8; 32], epoch_n: u64) -> bool {
    match store.get(&(*validator_id, epoch_n)) {
        Some(rec) => !rec.revealed,
        None => true,
    }
}

// ---------------------------------------------------------------------------
// Nonce custody (O6): signer-side 0600 file posture, mirrors the
// `node_keys.rs` secret-file discipline (the old `vrf.rs` secret-file
// helpers were deleted with the ECVRF excision).
// ---------------------------------------------------------------------------

/// Save an epoch nonce to `path` with owner-only (0600) permissions.
///
/// Mirrors the `node_keys.rs` secret-file posture: hex-encoded first line.
/// Refuses symlinks on `path` and its immediate parent, creates a unique temp
/// file in the same directory with `O_CREAT | O_EXCL` and `0o600` mode (no
/// world-readable window), writes + syncs, and atomically renames into `path`.
/// Unit-tested with temp dirs only.
pub fn save_cnvrf_nonce_to_file(path: &Path, nonce: &[u8; 32]) -> Result<(), String> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            match std::fs::symlink_metadata(parent) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(format!(
                            "[cnvrf] REFUSING: nonce parent {} is a symbolic link",
                            parent.display()
                        ));
                    }
                    if !meta.is_dir() {
                        return Err(format!(
                            "[cnvrf] REFUSING: nonce parent {} is not a directory",
                            parent.display()
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir_all(parent).map_err(|err| {
                        format!(
                            "[cnvrf] cannot create nonce dir {}: {err}",
                            parent.display()
                        )
                    })?;
                }
                Err(e) => {
                    return Err(format!(
                        "[cnvrf] cannot stat nonce dir {}: {e}",
                        parent.display()
                    ));
                }
            }
        }
    }

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "[cnvrf] REFUSING: nonce path {} is a symbolic link",
                path.display()
            ));
        }
        if !meta.is_file() {
            return Err(format!(
                "[cnvrf] REFUSING: nonce path {} is not a regular file",
                path.display()
            ));
        }
    }

    let file_name = path
        .file_name()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| format!("[cnvrf] invalid nonce file path {}", path.display()))?;
    let pid = std::process::id();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".tmp.{pid}.{seq}"));
    let tmp_path = path.with_file_name(tmp_name);

    let payload = format!("{}\n", hex::encode(nonce));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut f = opts.open(&tmp_path).map_err(|e| {
        format!(
            "[cnvrf] cannot create temp nonce file {}: {e}",
            tmp_path.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = f.set_permissions(std::fs::Permissions::from_mode(0o600)) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!(
                "[cnvrf] cannot chmod 0600 temp nonce file {}: {e}",
                tmp_path.display()
            ));
        }
    }

    if let Err(e) = f.write_all(payload.as_bytes()).and_then(|()| f.sync_all()) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!(
            "[cnvrf] cannot write temp nonce file {}: {e}",
            tmp_path.display()
        ));
    }
    drop(f);

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!(
                "[cnvrf] REFUSING: nonce path {} is a symbolic link",
                path.display()
            ));
        }
        if !meta.is_file() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(format!(
                "[cnvrf] REFUSING: nonce path {} is not a regular file",
                path.display()
            ));
        }
    }

    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!(
            "[cnvrf] cannot install nonce file {}: {e}",
            path.display()
        ));
    }
    Ok(())
}

/// Parse a 32-byte hex nonce (optional `0x` prefix). Hex format mirrors the
/// deleted VRF secret-file posture; current analogue is `node_keys.rs`.
pub fn parse_cnvrf_nonce_hex(raw: &str) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    let hex_part = trimmed.strip_prefix("0x").unwrap_or(trimmed).trim();
    let bytes = hex::decode(hex_part).map_err(|e| format!("[cnvrf] invalid nonce hex: {e}"))?;
    if bytes.len() != CNVRF_FIELD_LEN {
        return Err(format!(
            "[cnvrf] invalid nonce length: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

/// Load an epoch nonce from `path`: symlink-refused (`symlink_metadata` +
/// fd identity check), owner-only permissions checked (`(mode & 0o077) == 0`,
/// fail-closed), first non-empty line, hex. Same discipline as `node_keys.rs`
/// (the old `load_vrf_secret_from_file` was deleted with ECVRF).
/// Unit-tested with temp dirs only.
pub fn load_cnvrf_nonce_from_file(path: &Path) -> Result<[u8; 32], String> {
    use std::io::Read;

    let lmeta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("[cnvrf] cannot stat nonce file {}: {e}", path.display()))?;
    if lmeta.file_type().is_symlink() {
        return Err(format!(
            "[cnvrf] REFUSING: nonce path {} is a symbolic link",
            path.display()
        ));
    }
    if !lmeta.is_file() {
        return Err(format!(
            "[cnvrf] REFUSING: nonce path {} is not a file",
            path.display()
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = lmeta.permissions().mode() & 0o777;
        if (mode & 0o077) != 0 {
            return Err(format!(
                "[cnvrf] REFUSING: nonce file {} has insecure permissions 0o{:03o} \
                 (group/other must have NO access — chmod 0600 {})",
                path.display(),
                mode,
                path.display()
            ));
        }
    }

    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("[cnvrf] cannot open nonce file {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let fmeta = file
            .metadata()
            .map_err(|e| format!("[cnvrf] cannot fstat nonce file {}: {e}", path.display()))?;
        if fmeta.file_type().is_symlink() || !fmeta.is_file() {
            return Err(format!(
                "[cnvrf] REFUSING: nonce path {} is not a regular file",
                path.display()
            ));
        }
        if lmeta.dev() != fmeta.dev() || lmeta.ino() != fmeta.ino() {
            return Err(format!(
                "[cnvrf] REFUSING: nonce path {} changed concurrently (TOCTOU)",
                path.display()
            ));
        }
        let fmode = fmeta.permissions().mode() & 0o777;
        if (fmode & 0o077) != 0 {
            return Err(format!(
                "[cnvrf] REFUSING: nonce file {} has insecure permissions 0o{:03o} \
                 (group/other must have NO access — chmod 0600 {})",
                path.display(),
                fmode,
                path.display()
            ));
        }
    }

    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .map_err(|e| format!("[cnvrf] cannot read nonce file {}: {e}", path.display()))?;
    let line = raw
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    if line.is_empty() {
        return Err(format!(
            "[cnvrf] REFUSING: nonce file {} is empty",
            path.display()
        ));
    }
    parse_cnvrf_nonce_hex(line).map_err(|e| format!("{e} (in {})", path.display()))
}

// ===========================================================================
// CN-VRF v3 — 16-segment BLAKE3 48-byte XOF reverse hash-chain
// ===========================================================================

/// Hash-chain link length in bytes (384-bit / 128-bit quantum BHT collision security).
pub const V3_LINK_LEN: usize = 48;
/// Number of segments partitioning an epoch's reverse hash-chain.
pub const V3_SEGMENTS: usize = 16;
/// Number of slots per segment (`16 * 1875 == 30000 == EPOCH_LEN`).
pub const V3_SEGMENT_LEN: u64 = 1_875;
/// Lookahead cutoff before epoch `N+1` starts
/// (`H_freeze = (N+1)*EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS`).
///
/// RULESET v2: 682 heights x 240 ms = **163.68 s**. Derived from the measured
/// MinRoot evaluation (3,000,000 steps = 20.455 s on one core of the
/// measurement host), with a 4x allowance for the weakest 1-vCPU validator
/// class and a further 2x scheduling headroom:
/// `ceil(20.455 s * 4 * 2 / 0.24 s) = 682`. The epoch VDF therefore has at
/// least 2x headroom even on a 4x-slower host. Measurement and trade-off:
/// `docs/RULESET_V2.md` §VDF.
pub const V3_COMMIT_LOOKAHEAD_BLOCKS: u64 = 682;

const _: () = assert!(V3_SEGMENTS as u64 * V3_SEGMENT_LEN == EPOCH_LEN);

/// On-wire encoded byte length of [`CommitCarrierV3`]:
/// `32 (validator_id) + 8 (epoch_n) + 16*48 (anchors) + 666 (Falcon-512 sig) = 1474`.
pub const COMMIT_CARRIER_V3_LEN: usize = 32 + 8 + V3_SEGMENTS * V3_LINK_LEN + FALCON512_SIG_LEN;

/// Domain separation tag: reverse hash-chain step (`BLAKE3-XOF-48`).
pub const DST_CHAIN_V3: &str = "STELL_CNVRF_CHAIN_V3";
/// Domain separation tag: Falcon-512 commit authentication over 16 anchors.
pub const DST_COMMIT_SIG_V3: &str = "STELL_CNVRF_COMMIT_SIG_V3";
/// Domain separation tag: rolling beacon mix (`rolling_mix`) update per reveal.
pub const DST_BETA_V3: &str = "STELL_CNVRF_BETA_V3";
/// Domain separation tag: deterministic epoch raw seed derivation (with or without reveals).
pub const DST_EPOCH_RAW_SEED_V3: &str = "STELL_CNVRF_EPOCH_RAW_SEED_V3";
/// Domain separation tag: deterministic per-epoch v3 secret seed derivation.
pub const DST_V3_SEED_DERIVE: &str = "STELL_CNVRF_SEED_DERIVE_V3";

/// Zero-allocation 48-byte BLAKE3-XOF keyed derivation over `parts` under `domain`.
pub fn blake3_xof_48(domain: &str, parts: &[&[u8]]) -> [u8; V3_LINK_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; V3_LINK_LEN];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Derive a deterministic 48-byte epoch secret `s_{i,N}` from a node master secret.
pub fn derive_v3_epoch_secret(
    master_seed: &[u8],
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
) -> Zeroizing<[u8; V3_LINK_LEN]> {
    Zeroizing::new(blake3_xof_48(
        DST_V3_SEED_DERIVE,
        &[
            master_seed,
            &chain_id.to_le_bytes(),
            validator_id,
            &epoch_n.to_le_bytes(),
        ],
    ))
}

mod serde_bytes_48 {
    use super::V3_LINK_LEN;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; V3_LINK_LEN], s: S) -> Result<S::Ok, S::Error> {
        let mut tup = s.serialize_tuple(V3_LINK_LEN)?;
        for byte in val {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; V3_LINK_LEN], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; V3_LINK_LEN];
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "a {V3_LINK_LEN}-byte array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; V3_LINK_LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(V3_LINK_LEN, V)
    }
}

mod serde_anchors_16_48 {
    use super::{serde_bytes_48, V3_LINK_LEN, V3_SEGMENTS};
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    struct Link48([u8; V3_LINK_LEN]);
    impl Serialize for Link48 {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            serde_bytes_48::serialize(&self.0, s)
        }
    }
    impl<'de> Deserialize<'de> for Link48 {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            serde_bytes_48::deserialize(d).map(Link48)
        }
    }

    pub fn serialize<S: Serializer>(
        val: &[[u8; V3_LINK_LEN]; V3_SEGMENTS],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tup = s.serialize_tuple(V3_SEGMENTS)?;
        for anchor in val {
            tup.serialize_element(&Link48(*anchor))?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[[u8; V3_LINK_LEN]; V3_SEGMENTS], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [[u8; V3_LINK_LEN]; V3_SEGMENTS];
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "an array of {V3_SEGMENTS} 48-byte anchors")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [[0u8; V3_LINK_LEN]; V3_SEGMENTS];
                for (i, slot) in out.iter_mut().enumerate() {
                    let link: Link48 = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                    *slot = link.0;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(V3_SEGMENTS, V)
    }
}

mod serde_falcon_sig {
    use super::FALCON512_SIG_LEN;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        val: &[u8; FALCON512_SIG_LEN],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tup = s.serialize_tuple(FALCON512_SIG_LEN)?;
        for byte in val {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; FALCON512_SIG_LEN], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; FALCON512_SIG_LEN];
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "a {FALCON512_SIG_LEN}-byte Falcon-512 signature")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; FALCON512_SIG_LEN];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(FALCON512_SIG_LEN, V)
    }
}

/// Compute one reverse hash-chain step: `x_t = H(DST_CHAIN_V3, chain_id || validator_id || epoch_n || t || x_{t+1})`.
#[inline]
fn v3_chain_step(
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    step_t: u64,
    next_link: &[u8; V3_LINK_LEN],
) -> [u8; V3_LINK_LEN] {
    blake3_xof_48(
        DST_CHAIN_V3,
        &[
            &chain_id.to_le_bytes(),
            validator_id,
            &epoch_n.to_le_bytes(),
            &step_t.to_le_bytes(),
            next_link,
        ],
    )
}

/// Compute the 16 segment anchors `anchors[seg] = x_{seg * V3_SEGMENT_LEN}` in O(1) memory.
pub fn compute_v3_anchors(
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    s_secret: &[u8; V3_LINK_LEN],
) -> [[u8; V3_LINK_LEN]; V3_SEGMENTS] {
    let mut anchors = [[0u8; V3_LINK_LEN]; V3_SEGMENTS];
    let mut cur = *s_secret;
    for t in (0..EPOCH_LEN).rev() {
        cur = v3_chain_step(chain_id, validator_id, epoch_n, t, &cur);
        if t % V3_SEGMENT_LEN == 0 {
            let seg = (t / V3_SEGMENT_LEN) as usize;
            anchors[seg] = cur;
        }
    }
    cur.zeroize();
    anchors
}

/// Validator-side precomputed 16-segment reverse hash-chain for a single `(chain_id, validator_id, epoch_n)`.
///
/// Links `x_0 ..= x_{EPOCH_LEN}` are zeroized on drop. Slot `t` (`0..EPOCH_LEN`) reveals `x_{t+1}`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CnVrfV3Chain {
    chain_id: u64,
    validator_id: [u8; 32],
    epoch_n: u64,
    links: Vec<[u8; V3_LINK_LEN]>,
    anchors: [[u8; V3_LINK_LEN]; V3_SEGMENTS],
}

impl core::fmt::Debug for CnVrfV3Chain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CnVrfV3Chain")
            .field("chain_id", &self.chain_id)
            .field("validator_id", &hex::encode(self.validator_id))
            .field("epoch_n", &self.epoch_n)
            .field("anchor_0", &hex::encode(self.anchors[0]))
            .finish_non_exhaustive()
    }
}

impl CnVrfV3Chain {
    /// Generate the complete `EPOCH_LEN + 1`-link reverse hash-chain from `s_secret = x_{EPOCH_LEN}`.
    pub fn generate(
        chain_id: u64,
        validator_id: &[u8; 32],
        epoch_n: u64,
        s_secret: &[u8; V3_LINK_LEN],
    ) -> Self {
        let len = EPOCH_LEN as usize + 1;
        let mut links = vec![[0u8; V3_LINK_LEN]; len];
        links[EPOCH_LEN as usize] = *s_secret;
        let mut anchors = [[0u8; V3_LINK_LEN]; V3_SEGMENTS];
        for t in (0..EPOCH_LEN).rev() {
            let next = links[t as usize + 1];
            let x_t = v3_chain_step(chain_id, validator_id, epoch_n, t, &next);
            links[t as usize] = x_t;
            if t % V3_SEGMENT_LEN == 0 {
                anchors[(t / V3_SEGMENT_LEN) as usize] = x_t;
            }
        }
        Self {
            chain_id,
            validator_id: *validator_id,
            epoch_n,
            links,
            anchors,
        }
    }

    /// Return the 16 segment anchors `[x_0, x_{S}, ..., x_{15*S}]` (`S = V3_SEGMENT_LEN`).
    pub const fn anchors(&self) -> &[[u8; V3_LINK_LEN]; V3_SEGMENTS] {
        &self.anchors
    }

    /// Return the root anchor `x_0`.
    pub const fn root_anchor(&self) -> [u8; V3_LINK_LEN] {
        self.anchors[0]
    }

    /// Return the chain ID this chain was generated for.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Return the validator ID this chain was generated for.
    pub const fn validator_id(&self) -> &[u8; 32] {
        &self.validator_id
    }

    /// Return the epoch this chain was generated for.
    pub const fn epoch_n(&self) -> u64 {
        self.epoch_n
    }

    /// Reveal `x_{slot_t + 1}` for slot `t` in `0..EPOCH_LEN`.
    pub fn reveal_for_slot(&self, slot_t: u64) -> Option<[u8; V3_LINK_LEN]> {
        if slot_t >= EPOCH_LEN {
            return None;
        }
        self.links.get(slot_t as usize + 1).copied()
    }

    /// Reveal the link for block `height`, verifying `epoch_of_height(height) == self.epoch_n`.
    pub fn reveal_for_height(&self, height: u64) -> Option<[u8; V3_LINK_LEN]> {
        if epoch_of_height(height) != self.epoch_n {
            return None;
        }
        self.reveal_for_slot(height % EPOCH_LEN)
    }

    /// Build and sign a [`CommitCarrierV3`] from the precomputed anchors.
    pub fn commit_carrier(&self, sk: &FalconKeypair) -> CommitCarrierV3 {
        let msg = commit_v3_sig_message_bytes(
            self.chain_id,
            &self.validator_id,
            self.epoch_n,
            &self.anchors,
        );
        let sig = sk.sign(&msg);
        let mut sig_arr = [0u8; FALCON512_SIG_LEN];
        if sig.len() == FALCON512_SIG_LEN {
            sig_arr.copy_from_slice(&sig);
        }
        CommitCarrierV3 {
            validator_id: self.validator_id,
            epoch_n: self.epoch_n,
            anchors: self.anchors,
            sig: sig_arr,
        }
    }
}

/// Exact Falcon-512 commit signature message for CN-VRF v3:
/// `DST_COMMIT_SIG_V3 || chain_id(le) || validator_id || epoch_n(le) || anchors[0..16]`.
pub fn commit_v3_sig_message_bytes(
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    anchors: &[[u8; V3_LINK_LEN]; V3_SEGMENTS],
) -> Vec<u8> {
    let cap = DST_COMMIT_SIG_V3.len() + 8 + 32 + 8 + V3_SEGMENTS * V3_LINK_LEN;
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(DST_COMMIT_SIG_V3.as_bytes());
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(validator_id);
    out.extend_from_slice(&epoch_n.to_le_bytes());
    for anchor in anchors {
        out.extend_from_slice(anchor);
    }
    debug_assert_eq!(out.len(), cap);
    out
}

/// CN-VRF v3 commitment carrier published before `H_freeze` of epoch `N-1`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitCarrierV3 {
    /// Validator identity committing to `epoch_n`.
    pub validator_id: [u8; 32],
    /// Future epoch `N` being committed to.
    pub epoch_n: u64,
    /// 16 segment anchors `[x_0, x_{S}, ..., x_{15*S}]` (`S = V3_SEGMENT_LEN`).
    #[serde(with = "serde_anchors_16_48")]
    pub anchors: [[u8; V3_LINK_LEN]; V3_SEGMENTS],
    /// Falcon-512 signature over [`commit_v3_sig_message_bytes`].
    #[serde(with = "serde_falcon_sig")]
    pub sig: [u8; FALCON512_SIG_LEN],
}

impl CommitCarrierV3 {
    /// Fixed on-wire encoded byte length (`1474` bytes).
    pub const fn encoded_len(&self) -> usize {
        COMMIT_CARRIER_V3_LEN
    }
}

/// Compute the 16 segment anchors from `s_secret` and sign a [`CommitCarrierV3`].
///
/// Fails closed if `sk` cannot sign (leaves zeroed `sig` which [`cnvrf_v3_verify_commit`] rejects).
pub fn cnvrf_v3_commit(
    sk: &FalconKeypair,
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    s_secret: &[u8; V3_LINK_LEN],
) -> CommitCarrierV3 {
    let anchors = compute_v3_anchors(chain_id, validator_id, epoch_n, s_secret);
    let msg = commit_v3_sig_message_bytes(chain_id, validator_id, epoch_n, &anchors);
    let sig = sk.sign(&msg);
    let mut sig_arr = [0u8; FALCON512_SIG_LEN];
    if sig.len() == FALCON512_SIG_LEN {
        sig_arr.copy_from_slice(&sig);
    }
    CommitCarrierV3 {
        validator_id: *validator_id,
        epoch_n,
        anchors,
        sig: sig_arr,
    }
}

/// Verify a [`CommitCarrierV3`] against `chain_id` and active Falcon-512 public key `pk`.
///
/// Fails closed on `pk.len() != CNVRF_PK_LEN`, all-zero signature, or invalid Falcon signature.
pub fn cnvrf_v3_verify_commit(
    carrier: &CommitCarrierV3,
    chain_id: u64,
    pk: &[u8],
) -> Result<(), CnVrfError> {
    if pk.len() != CNVRF_PK_LEN {
        return Err(CnVrfError::InvalidPublicKeyLength);
    }
    if carrier.sig.iter().all(|&b| b == 0) {
        return Err(CnVrfError::InvalidCommitSignature);
    }
    let msg = commit_v3_sig_message_bytes(
        chain_id,
        &carrier.validator_id,
        carrier.epoch_n,
        &carrier.anchors,
    );
    if !verify_pq_signature(PqScheme::Falcon512, pk, &msg, &carrier.sig) {
        return Err(CnVrfError::InvalidCommitSignature);
    }
    Ok(())
}

/// On-chain commitment record for a validator in an epoch (CN-VRF v3).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CnVrfV3Record {
    /// 16 segment anchors `[x_0, x_{S}, ..., x_{15*S}]` (`S = V3_SEGMENT_LEN`).
    #[serde(with = "serde_anchors_16_48")]
    pub anchors: [[u8; V3_LINK_LEN]; V3_SEGMENTS],
    /// Most recently revealed link `x_{last_step}` (initialized to `anchors[0] = x_0`).
    #[serde(with = "serde_bytes_48")]
    pub head: [u8; V3_LINK_LEN],
    /// Next expected chain step (`0` initially; `slot_t + 1` after revealing at `slot_t`).
    pub last_step: u64,
    /// Block height at which the commitment was admitted.
    pub commit_height: u64,
    /// Original `validator_id` bound in the hash-chain preimage at commit time
    /// (preserved across [`CnVrfV3State::migrate_validator`] key rotations).
    pub anchor_validator_id: [u8; 32],
}

/// Verify a reveal `x_{slot_t + 1}` against `state` in at most `V3_SEGMENT_LEN` BLAKE3 steps.
///
/// Returns the number of hash steps checked (`1..=V3_SEGMENT_LEN`), or a static error reason on failure.
pub fn cnvrf_v3_verify_reveal(
    state: &CnVrfV3Record,
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    slot_t: u64,
    reveal: &[u8; V3_LINK_LEN],
) -> Result<u64, &'static str> {
    if slot_t >= EPOCH_LEN {
        return Err("slot_t out of epoch bounds");
    }
    if slot_t < state.last_step {
        return Err("stale or replayed slot reveal");
    }
    let seg = (slot_t / V3_SEGMENT_LEN) as usize;
    let seg_start = (seg as u64) * V3_SEGMENT_LEN;

    let (target_step, target_hash) = if state.last_step > seg_start && state.last_step <= slot_t {
        (state.last_step, &state.head)
    } else {
        (seg_start, &state.anchors[seg])
    };

    let mut cur = *reveal;
    for step in (target_step..=slot_t).rev() {
        cur = v3_chain_step(chain_id, validator_id, epoch_n, step, &cur);
    }
    if cur != *target_hash {
        return Err("hash-chain reveal mismatch");
    }
    Ok(slot_t - target_step + 1)
}

/// Outcome of [`CnVrfV3State::apply_slot_reveal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotRevealOutcome {
    /// Committed proposer supplied a valid reveal; verified in `steps <= V3_SEGMENT_LEN` BLAKE3 calls.
    Revealed {
        /// Number of reverse hash-chain steps verified.
        steps: u64,
    },
    /// Committed proposer supplied an invalid or stale/replayed reveal (caller rejects block).
    InvalidReveal,
    /// Committed proposer omitted the reveal (caller enforces abort/miss policy).
    CommittedMissingReveal,
    /// Uncommitted proposer omitted the reveal (e.g. mid-epoch newcomer, admissible).
    AbsentNoCommit,
    /// Uncommitted proposer injected a reveal (caller rejects block).
    UnexpectedReveal,
}

/// Deterministic on-chain state machine for CN-VRF v3 commitments and slot reveals.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CnVrfV3State {
    /// Active per-`(validator_id, epoch_n)` commitment records (`BTreeMap` for determinism).
    pub records: BTreeMap<(ValidatorId, u64), CnVrfV3Record>,
    /// Current rolling mix (`[0u8; 48]` before any reveal in the active epoch).
    #[serde(with = "serde_bytes_48")]
    pub rolling_mix: [u8; V3_LINK_LEN],
    /// Epoch corresponding to `rolling_mix`.
    pub rolling_mix_epoch: u64,
    /// Per-epoch rolling mix archive (allows clean epoch boundary transitions).
    #[serde(default)]
    pub epoch_rolling_mixes: BTreeMap<u64, Vec<u8>>,
}

impl Default for CnVrfV3State {
    fn default() -> Self {
        Self {
            records: BTreeMap::new(),
            rolling_mix: [0u8; V3_LINK_LEN],
            rolling_mix_epoch: 0,
            epoch_rolling_mixes: BTreeMap::new(),
        }
    }
}

impl CnVrfV3State {
    /// Create a fresh empty CN-VRF v3 state machine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a validator's commitment record for `epoch_n`.
    pub fn get_record(&self, validator_id: &[u8; 32], epoch_n: u64) -> Option<&CnVrfV3Record> {
        self.records.get(&(*validator_id, epoch_n))
    }

    /// Return the rolling mix recorded for `epoch_n` (all-zero if no reveals occurred).
    pub fn rolling_mix_for_epoch(&self, epoch_n: u64) -> [u8; V3_LINK_LEN] {
        if let Some(bytes) = self.epoch_rolling_mixes.get(&epoch_n) {
            if bytes.len() == V3_LINK_LEN {
                let mut out = [0u8; V3_LINK_LEN];
                out.copy_from_slice(bytes);
                return out;
            }
        }
        if epoch_n == self.rolling_mix_epoch {
            return self.rolling_mix;
        }
        [0u8; V3_LINK_LEN]
    }

    /// Admit a [`CommitCarrierV3`] at `current_height`:
    /// - Enforces `carrier.epoch_n == current_epoch + 1`
    /// - Enforces `current_height < (carrier.epoch_n * EPOCH_LEN) - V3_COMMIT_LOOKAHEAD_BLOCKS` (`H_freeze`)
    /// - Verifies Falcon-512 signature once against `pk`
    /// - Preserves first-committed-wins (`IgnoredDuplicate`)
    pub fn admit_commit(
        &mut self,
        carrier: &CommitCarrierV3,
        current_height: u64,
        chain_id: u64,
        pk: &[u8],
    ) -> Result<CommitOutcome, CnVrfError> {
        let current_epoch = epoch_of_height(current_height);
        if carrier.epoch_n <= current_epoch {
            return Err(CnVrfError::CommitState(CommitError::StaleOrCurrent));
        }
        if carrier.epoch_n > current_epoch.saturating_add(1) {
            return Err(CnVrfError::CommitState(CommitError::TooFarAhead));
        }
        let h_freeze = carrier
            .epoch_n
            .saturating_mul(EPOCH_LEN)
            .saturating_sub(V3_COMMIT_LOOKAHEAD_BLOCKS);
        if current_height >= h_freeze {
            return Err(CnVrfError::CommitState(CommitError::PastCommitCutoff));
        }

        cnvrf_v3_verify_commit(carrier, chain_id, pk)?;

        use std::collections::btree_map::Entry;
        match self.records.entry((carrier.validator_id, carrier.epoch_n)) {
            Entry::Occupied(_) => Ok(CommitOutcome::IgnoredDuplicate),
            Entry::Vacant(slot) => {
                slot.insert(CnVrfV3Record {
                    anchors: carrier.anchors,
                    head: carrier.anchors[0],
                    last_step: 0,
                    commit_height: current_height,
                    anchor_validator_id: carrier.validator_id,
                });
                Ok(CommitOutcome::Accepted)
            }
        }
    }

    /// Apply an optional block-proposer reveal at `height`.
    pub fn apply_slot_reveal(
        &mut self,
        chain_id: u64,
        proposer: &[u8; 32],
        height: u64,
        reveal: Option<&[u8; V3_LINK_LEN]>,
    ) -> SlotRevealOutcome {
        let epoch = epoch_of_height(height);
        let slot_t = height % EPOCH_LEN;
        let Some(rec) = self.records.get_mut(&(*proposer, epoch)) else {
            return match reveal {
                None => SlotRevealOutcome::AbsentNoCommit,
                Some(_) => SlotRevealOutcome::UnexpectedReveal,
            };
        };
        let Some(rev) = reveal else {
            return SlotRevealOutcome::CommittedMissingReveal;
        };
        let anchor_vid = rec.anchor_validator_id;
        match cnvrf_v3_verify_reveal(rec, chain_id, &anchor_vid, epoch, slot_t, rev) {
            Ok(steps) => {
                rec.head = *rev;
                rec.last_step = slot_t + 1;
                if self.rolling_mix_epoch != epoch {
                    self.rolling_mix = self
                        .epoch_rolling_mixes
                        .get(&epoch)
                        .and_then(|b| b.as_slice().try_into().ok())
                        .unwrap_or([0u8; V3_LINK_LEN]);
                    self.rolling_mix_epoch = epoch;
                }
                self.rolling_mix = blake3_xof_48(
                    DST_BETA_V3,
                    &[&self.rolling_mix, rev, proposer, &height.to_le_bytes()],
                );
                self.epoch_rolling_mixes
                    .insert(epoch, self.rolling_mix.to_vec());
                SlotRevealOutcome::Revealed { steps }
            }
            Err(_) => SlotRevealOutcome::InvalidReveal,
        }
    }

    /// Migrate committed records for `old_id` to `new_id` starting at `from_epoch`
    /// (preserving `anchor_validator_id` so the hash-chain preimage remains valid).
    pub fn migrate_validator(&mut self, old_id: &[u8; 32], new_id: &[u8; 32], from_epoch: u64) {
        if old_id == new_id {
            return;
        }
        let keys_to_move: Vec<(ValidatorId, u64)> = self
            .records
            .keys()
            .filter(|(vid, epoch)| vid == old_id && *epoch >= from_epoch)
            .copied()
            .collect();
        for key in keys_to_move {
            if let Some(rec) = self.records.remove(&key) {
                self.records.entry((*new_id, key.1)).or_insert(rec);
            }
        }
    }

    /// Expire commitment records strictly older than `current_epoch`, returning count removed.
    pub fn expire_before(&mut self, current_epoch: u64) -> usize {
        let stale: Vec<(ValidatorId, u64)> = self
            .records
            .keys()
            .filter(|(_, epoch_n)| *epoch_n < current_epoch)
            .copied()
            .collect();
        let count = stale.len();
        for k in stale {
            self.records.remove(&k);
        }
        let stale_mix_epoch = current_epoch.saturating_sub(1);
        let stale_mixes: Vec<u64> = self
            .epoch_rolling_mixes
            .keys()
            .copied()
            .filter(|&e| e < stale_mix_epoch)
            .collect();
        for e in stale_mixes {
            self.epoch_rolling_mixes.remove(&e);
        }
        count
    }
}

/// Deterministic epoch raw seed combining `(chain_id, epoch_n, prev_beacon, freeze_block_hash, rolling_mix)`.
///
/// Produces a deterministic fallback seed even when zero validators revealed (`rolling_mix == [0u8; 48]`),
/// and stays identical across all honest nodes regardless of whether `1` or `N` validators revealed.
pub fn epoch_raw_seed(
    chain_id: u64,
    epoch_n: u64,
    prev_beacon: &[u8; V3_LINK_LEN],
    freeze_block_hash: &[u8; 32],
    rolling_mix: &[u8; V3_LINK_LEN],
) -> [u8; V3_LINK_LEN] {
    blake3_xof_48(
        DST_EPOCH_RAW_SEED_V3,
        &[
            &chain_id.to_le_bytes(),
            &epoch_n.to_le_bytes(),
            prev_beacon,
            freeze_block_hash,
            rolling_mix,
        ],
    )
}

// ---------------------------------------------------------------------------
// THE ONE EPOCH-SEED RULE (review F3)
// ---------------------------------------------------------------------------
//
// Three code paths derive the `raw_seed` of an epoch:
//
//  1. the PRODUCER's `H_freeze` dispatch (`runtime::prepare_cnvrf_v3_epoch_hooks`),
//  2. the VALIDATOR's boundary-payload check
//     (`runtime::validate_cnvrf_v3_payload`), and
//  3. the STATE ENGINE's beacon admission (`state_engine::apply_cnvrf_v3`).
//
// If any two disagree, the first boundary block under the activation gate can
// never verify and the beacon chain never starts (exactly review finding F3).
// They therefore all call [`epoch_seed`] — there is no second derivation.
//
// THE BOOTSTRAP / FIRST-EPOCH RULE, stated once:
//
//  * Epoch 0 has no predecessor, so its seed never chains a beacon (the
//    all-zero link, exactly the pre-fix behavior; block 0 is not a boundary).
//  * An epoch whose `H_freeze` (= `epoch * EPOCH_LEN - V3_COMMIT_LOOKAHEAD`)
//    ran BEFORE the activation height never dispatched a VDF, so it has no
//    committed beacon. Its CANONICAL beacon is the deterministic bootstrap
//    output [`epoch_bootstrap_beacon`] — NOT the all-zero link. The next
//    epoch's seed chains THAT value.
//  * Every later epoch chains the committed (on-chain) beacon of its
//    predecessor.
//
// The pre-fix code chained zeros in the producer and the bootstrap value in
// the validator, so the first post-activation boundary could never verify.

/// `H_freeze` of `epoch`: the height whose applied block snapshots the VDF
/// inputs and dispatches the MinRoot worker for that epoch.
///
/// `epoch * EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS`, saturating at 0 (epoch 0
/// has no freeze height).
pub const fn freeze_height_of_epoch(epoch: u64) -> u64 {
    epoch_start_height(epoch).saturating_sub(V3_COMMIT_LOOKAHEAD_BLOCKS)
}

/// True when `epoch` is a VDF-bearing epoch under `activation_height`: its
/// `H_freeze` ran at/after activation, so a MinRoot beacon was dispatched for
/// it and MUST appear on chain.
///
/// Epoch 0 is never VDF-bearing: it is the chain's first epoch and has no
/// predecessor to chain.
pub const fn epoch_had_vdf(epoch: u64, activation_height: u64) -> bool {
    if epoch == 0 {
        return false;
    }
    freeze_height_of_epoch(epoch) >= activation_height
}

/// The deterministic BOOTSTRAP beacon of `epoch` — what an epoch whose
/// `H_freeze` preceded activation uses as its (never-VDF'd) beacon.
///
/// This is [`epoch_raw_seed`] over the all-zero predecessor link, zero freeze
/// hash and zero rolling mix: a pure function of `(chain_id, epoch)`, so every
/// node derives the same value without any on-chain data. It is the value the
/// first post-activation epoch chains, and it is what
/// [`crate::runtime::ValidatorRuntime::active_epoch_beacon`] returns for a
/// pre-activation epoch.
pub fn epoch_bootstrap_beacon(chain_id: u64, epoch: u64) -> [u8; V3_LINK_LEN] {
    epoch_raw_seed(
        chain_id,
        epoch,
        &[0u8; V3_LINK_LEN],
        &[0u8; 32],
        &[0u8; V3_LINK_LEN],
    )
}

/// THE epoch-seed rule (see the block comment above): the single derivation
/// shared by the producer, the validator and the state engine.
///
/// * `committed_prev_beacon` — the on-chain beacon of `epoch - 1`, if this node
///   holds it.
/// * `prev_epoch_freeze_active` — whether `H_freeze(epoch - 1)` ran at/after
///   the activation height ([`epoch_had_vdf`] with the caller's activation).
///
/// Deterministic for every `(chain_id, epoch, committed_prev_beacon,
/// prev_epoch_freeze_active, freeze_block_hash, rolling_mix)` tuple: no clock,
/// no env, no map iteration.
pub fn epoch_seed(
    chain_id: u64,
    epoch: u64,
    committed_prev_beacon: Option<&[u8; V3_LINK_LEN]>,
    prev_epoch_freeze_active: bool,
    freeze_block_hash: &[u8; 32],
    rolling_mix: &[u8; V3_LINK_LEN],
) -> [u8; V3_LINK_LEN] {
    let prev_beacon = match (epoch, committed_prev_beacon) {
        // No predecessor epoch: the historical all-zero link.
        (0, _) => [0u8; V3_LINK_LEN],
        (_, Some(beacon)) => *beacon,
        // The predecessor's H_freeze preceded activation (or it was epoch 0):
        // no VDF ran, so chain its deterministic bootstrap beacon.
        (_, None) if epoch == 1 || !prev_epoch_freeze_active => {
            epoch_bootstrap_beacon(chain_id, epoch - 1)
        }
        // A VDF-bearing predecessor with no committed beacon here: the beacon
        // is missing, not bootstrapped. Chaining zeros is deterministic and
        // fail-closed — no honest node records a beacon for this seed, so the
        // chain stalls loudly instead of accepting a beacon nobody derived.
        (_, None) => [0u8; V3_LINK_LEN],
    };
    epoch_raw_seed(
        chain_id,
        epoch,
        &prev_beacon,
        freeze_block_hash,
        rolling_mix,
    )
}

/// The beacon of `epoch` as every consumer (proposer schedule, committee draw,
/// light client) must see it: the committed on-chain beacon when available,
/// else the deterministic bootstrap output for an epoch that never ran a VDF,
/// else `None` (fail closed: a VDF-bearing epoch whose beacon is not known
/// here cannot be guessed).
pub fn epoch_beacon_for(
    chain_id: u64,
    epoch: u64,
    committed_beacon: Option<&[u8; V3_LINK_LEN]>,
    activation_height: u64,
) -> Option<[u8; V3_LINK_LEN]> {
    epoch_beacon_for_active(
        chain_id,
        epoch,
        committed_beacon,
        epoch_had_vdf(epoch, activation_height),
    )
}

/// [`epoch_beacon_for`] for callers that know only their own
/// `is_active_at(height)` predicate (the state engine, the sync walk): pass
/// `epoch_freeze_active = is_active_at(freeze_height_of_epoch(epoch))`.
///
/// Same rule, one implementation: committed beacon, else the bootstrap beacon
/// for an epoch that never ran a VDF, else `None` (fail closed).
pub fn epoch_beacon_for_active(
    chain_id: u64,
    epoch: u64,
    committed_beacon: Option<&[u8; V3_LINK_LEN]>,
    epoch_freeze_active: bool,
) -> Option<[u8; V3_LINK_LEN]> {
    if let Some(beacon) = committed_beacon {
        return Some(*beacon);
    }
    if epoch == 0 || !epoch_freeze_active {
        return Some(epoch_bootstrap_beacon(chain_id, epoch));
    }
    None
}

// ---------------------------------------------------------------------------
// CN-VRF v3 encrypted secret custody (enc2: via node_keys)
// ---------------------------------------------------------------------------

/// Save a 48-byte CN-VRF v3 epoch secret `s_{i,N}` to `path` with `enc2:`
/// encryption (Argon2id + XChaCha20-Poly1305) and atomic `0600` file write.
///
/// Refuses symlinks and fails closed when no passphrase is available unless
/// `STELL_KEY_PLAINTEXT=1` is explicitly set.
pub fn save_cnvrf_v3_secret(path: &Path, secret: &[u8; V3_LINK_LEN]) -> anyhow::Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "refusing to write CN-VRF v3 secret to symlink {}",
                path.display()
            );
        }
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(meta) = std::fs::symlink_metadata(parent) {
                if meta.file_type().is_symlink() {
                    anyhow::bail!(
                        "refusing to use symlinked parent directory {}",
                        parent.display()
                    );
                }
            }
            crate::node_keys::ensure_secure_dir(parent)?;
        }
    }
    let secret_hex = Zeroizing::new(hex::encode(secret));
    let content: Zeroizing<Vec<u8>> = if crate::node_keys::plaintext_keys_allowed() {
        tracing::warn!(
            "{} set: saving CN-VRF v3 secret in PLAINTEXT",
            crate::node_keys::ENV_PLAINTEXT,
        );
        Zeroizing::new(format!("{}\n", secret_hex.as_str()).into_bytes())
    } else {
        let pass = crate::node_keys::passphrase_for_write("cnvrf_v3.secret")?;
        Zeroizing::new(
            crate::node_keys::encrypt_bytes(secret_hex.as_bytes(), pass.as_str())?.into_bytes(),
        )
    };
    crate::node_keys::atomic_write_private(path, &content)
}

/// Load a 48-byte CN-VRF v3 epoch secret `s_{i,N}` from `path`, verifying `0600`
/// file permissions and decrypting `enc2:` (Argon2id + XChaCha20-Poly1305).
///
/// Fails closed on symlinks, loose permissions, missing/wrong passphrase for
/// encrypted secrets, or invalid length/hex.
pub fn load_cnvrf_v3_secret(path: &Path) -> anyhow::Result<Zeroizing<[u8; V3_LINK_LEN]>> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(meta) = std::fs::symlink_metadata(parent) {
                if meta.file_type().is_symlink() {
                    anyhow::bail!(
                        "refusing CN-VRF v3 secret under symlinked directory {}",
                        parent.display()
                    );
                }
            }
        }
    }
    crate::node_keys::verify_file_perms(path)?;
    let raw = Zeroizing::new(
        std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("read CN-VRF v3 secret {}: {e}", path.display()))?,
    );
    let pass = Zeroizing::new(crate::node_keys::get_passphrase());
    let plain = Zeroizing::new(crate::node_keys::decrypt_bytes(&raw, pass.as_deref())?);
    let text = std::str::from_utf8(&plain)
        .map_err(|e| anyhow::anyhow!("invalid UTF-8 in CN-VRF v3 secret: {e}"))?
        .trim();
    let hex_part = text.strip_prefix("0x").unwrap_or(text).trim();
    let decoded = Zeroizing::new(
        hex::decode(hex_part).map_err(|e| anyhow::anyhow!("invalid CN-VRF v3 secret hex: {e}"))?,
    );
    if decoded.len() != V3_LINK_LEN {
        anyhow::bail!(
            "invalid CN-VRF v3 secret length: expected {} bytes, got {}",
            V3_LINK_LEN,
            decoded.len()
        );
    }
    let mut out = Zeroizing::new([0u8; V3_LINK_LEN]);
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Startup check verifying that a loaded 48-byte secret `s_{i,N}` derives
/// the exact 16 segment anchors committed on-chain for `(chain_id, validator_id, epoch_n)`.
pub fn verify_v3_secret_matches_commit(
    secret: &[u8; V3_LINK_LEN],
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    commit_anchors: &[[u8; V3_LINK_LEN]; V3_SEGMENTS],
) -> bool {
    let computed = compute_v3_anchors(chain_id, validator_id, epoch_n, secret);
    computed == *commit_anchors
}
