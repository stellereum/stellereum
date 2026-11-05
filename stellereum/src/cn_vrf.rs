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
//! - O1: [`EPOCH_LEN`] = 7200 heights (== `PQ_ROTATION_DELAY_HEIGHTS`); one
//!   rotation window = one epoch. `epoch(N)` = heights `[N*7200, (N+1)*7200)`.
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

use crate::post_quantum::{
    FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN, FalconKeypair, PqScheme,
    verify_pq_signature,
};

// ---------------------------------------------------------------------------
// Lead-decided constants (O1, O8, spec §1.2 / §1.7)
// ---------------------------------------------------------------------------

/// Epoch length in heights (O1): one PQ rotation window = one epoch.
///
/// FREEZE (protocol freeze 2026-11-03): 7,200 heights ≈ 6 h at 3 s blocks
/// (spec docs/specs/02_CRYPTO_AND_PQ_PHASE2.md §6, == PQ_ROTATION_DELAY_HEIGHTS).
/// Change requires spec update + audit note (AGENTS.md §7).
pub const EPOCH_LEN: u64 = 7200;

/// Domain separation: commitment preimage (spec §1.2).
pub const CNVRF_COMMIT_DST: &[u8] = b"STELL_CNVRF_COMMIT_V1";
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
/// test at `post_quantum.rs:2450`. Pinned against the NIST vectors in
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
        for (word, chunk) in state.iter_mut().take(WORDS).zip(
            data[offset..offset + RATE].chunks_exact(8),
        ) {
            let bytes: [u8; 8] = chunk
                .try_into()
                .expect("chunks_exact(8) yields 8 bytes");
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
        let bytes: [u8; 8] = chunk
            .try_into()
            .expect("chunks_exact(8) yields 8 bytes");
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
    /// Falcon-512 sig over the commit preimage by the registered PQ key.
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

/// Signs the §1.3 commitment preimage with the registered Falcon key.
/// Returns the commit carrier for epoch N (publish in epoch N−1).
///
/// `nonce`/`validator_id` lengths are type-enforced (`[u8; 32]`). If the
/// signer refuses (incomplete key — `sign` returns short), the carrier keeps
/// a zeroed `sig` so every downstream path fail-closes at verify.
pub fn cnvrf_commit(
    sk: &FalconKeypair,
    chain_id: u64,
    validator_id: &[u8; 32],
    epoch_n: u64,
    nonce: &[u8; 32],
) -> CommitCarrier {
    let preimage = commit_preimage_bytes(chain_id, validator_id, epoch_n, nonce);
    let sig = sk.sign(&preimage);
    let mut sig_arr = [0u8; FALCON512_SIG_LEN];
    if sig.len() == FALCON512_SIG_LEN {
        sig_arr.copy_from_slice(&sig);
    }
    CommitCarrier {
        validator_id: *validator_id,
        epoch_n,
        c: commit_hash(chain_id, validator_id, epoch_n, nonce),
        sig: sig_arr,
    }
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

/// `epoch(h) = h / EPOCH_LEN`; `epoch(N)` covers `[N*7200, (N+1)*7200)` (O1).
pub const fn epoch_of_height(height: u64) -> u64 {
    height / EPOCH_LEN
}

/// First height of epoch N.
pub const fn epoch_start_height(epoch_n: u64) -> u64 {
    epoch_n * EPOCH_LEN
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
pub fn cnvrf_draw_absence(
    store: &CnVrfCommitments,
    validator_id: &[u8; 32],
    epoch_n: u64,
) -> bool {
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
/// Mirrors the `vrf.rs:360-421` secret-file posture: hex-encoded first line.
/// Parent directories are created as needed; permissions are forced to 0600
/// after writing (umask-independent). Unit-tested with temp dirs only.
pub fn save_cnvrf_nonce_to_file(path: &Path, nonce: &[u8; 32]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("[cnvrf] cannot create nonce dir {}: {e}", parent.display()))?;
        }
    }
    std::fs::write(path, format!("{}\n", hex::encode(nonce)))
        .map_err(|e| format!("[cnvrf] cannot write nonce file {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            format!(
                "[cnvrf] cannot chmod 0600 nonce file {}: {e}",
                path.display()
            )
        })?;
    }
    Ok(())
}

/// Parse a 32-byte hex nonce (optional `0x` prefix). Hex format mirrors the
/// deleted VRF secret-file posture; current analogue is `node_keys.rs`.
pub fn parse_cnvrf_nonce_hex(raw: &str) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    let hex_part = trimmed.strip_prefix("0x").unwrap_or(trimmed).trim();
    let bytes =
        hex::decode(hex_part).map_err(|e| format!("[cnvrf] invalid nonce hex: {e}"))?;
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

/// Load an epoch nonce from `path`: 0600-checked (owner-only, fail-closed),
/// first non-empty line, hex. Same discipline as `node_keys.rs`
/// (the old `load_vrf_secret_from_file` was deleted with ECVRF).
/// Unit-tested with temp dirs only.
pub fn load_cnvrf_nonce_from_file(path: &Path) -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("[cnvrf] cannot stat nonce file {}: {e}", path.display()))?;
        if !meta.is_file() {
            return Err(format!(
                "[cnvrf] REFUSING: nonce path {} is not a file",
                path.display()
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "[cnvrf] REFUSING: nonce file {} has insecure permissions 0o{:03o} \
                 (group/other must have NO access — chmod 0600 {})",
                path.display(),
                mode,
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        if !path.is_file() {
            return Err(format!(
                "[cnvrf] REFUSING: nonce path {} is not a file",
                path.display()
            ));
        }
    }
    let raw = std::fs::read_to_string(path)
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
