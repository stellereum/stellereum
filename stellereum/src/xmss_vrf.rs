//! Stateful XMSS-VRF beacon (post-quantum unique signatures).
//!
//! WOTS+ (`w = 16`, `n = 32`, `len1 = 64`, `len2 = 3`, `len = 67`) plus a
//! Merkle tree over epoch-bound leaves (leaf index = epoch number), with a
//! deterministic VRF output `y = H(seed || sigma)`.
//!
//! Shapes are ported from the P14/P15 prototype (`code/xmss_vrf.py`,
//! `code/xmss_vrf_stateful.py` in `stellereum-math`, papers
//! `14_pq_vrf_and_2pc_refinement.md` and
//! `15_refinement_proof_and_vrf_hardening.md`): the WOTS+ digit layout, the
//! checksum, the leaf/node/VRF domain separation, the monotone leaf counter,
//! and the signature-size formula `67*32 + h*32`. The prototype's toy field
//! is NOT ported: every hash is SHAKE256 (the tree's sponge, reached through
//! [`crate::post_quantum::keccak_f1600`] — reuse, not a second Keccak), and
//! all byte handling is explicit (big-endian leaf index, nibble MSB-first,
//! order-sensitive node hashing).
//!
//! # Stateful contract
//!
//! * One leaf per epoch. `sign(epoch, seed)` is allowed **only** when
//!   `epoch == next_leaf` (the monotone counter). The check happens BEFORE
//!   the one-time key is touched, so grinding through this API is impossible.
//! * Re-signing an already-used epoch (`epoch < next_leaf`) is refused with
//!   [`XmssError::LeafReuse`], which carries forensic evidence bytes (see
//!   [Evidence](#evidence)). Bypassing the counter (a second valid signature
//!   on one leaf built outside this API) burns the WOTS+ key — the two
//!   signatures are a public equivocation proof (P14 toy forgery) — and is
//!   checkable with [`verify_equivocation`].
//! * Verification ([`XmssVrf::verify`] / [`verify_signature`]) refuses a
//!   wrong epoch, a wrong seed, a wrong `y`, a foreign root, and an
//!   over-height or over-capacity epoch. It returns `bool`, never a signature.
//! * Signing is deterministic: no RNG anywhere. Same `(master, epoch, seed)`
//!   always yields the same `(y, sigma)`.
//! * Leaf exhaustion is fail-closed: once `next_leaf == 2^h`, every further
//!   `sign` returns [`XmssError::Exhausted`]. There is no silent rotation.
//!
//! # Height, sizes, and honest lifetime limits
//!
//! The constructor takes the tree height `h` ([`XmssVrf::new`]); the default
//! ([`XmssVrf::with_default_height`], `h = 10`) documents the tradeoff below.
//! `h` MUST satisfy `1 <= h <= `[`MAX_HEIGHT`] (12); anything else is refused
//! fail-closed at construction. `h > 12` is refused as a DoS/OOM guard: the
//! build cost doubles per height bit and a long-lived key needs XMSS^MT
//! (multi-tree) key rotation, which this module does NOT implement.
//!
//! | `h` | leaves | signature bytes (`67*32 + h*32`) | public key | VRF output |
//! |---:|---:|---:|---:|---:|
//! | 6 | 64 | **2336** | 32 | 32 |
//! | 8 | 256 | **2400** | 32 | 32 |
//! | 10 | 1024 | **2464** | 32 | 32 |
//!
//! Key lifetime at 128 blocks/epoch and 0.6 s/block (one beacon signature per
//! epoch, epoch = 76.8 s): `h = 10` covers 1024 epochs ≈ **22 hours** —
//! `h = 10` is a day-key, not a forever-key. Longer service needs `h` up to
//! the build-cost ceiling (`h = 12`: 4096 leaves, one-time build of a few
//! seconds, ~4.6 days at the same cadence) or, beyond that, XMSS^MT /
//! hierarchical rotation plus Falcon for the non-beacon paths (P14 C, P15 B.3).
//! This module deliberately does NOT silently extend lifetime: exhaustion
//! returns an error and the operator must rotate the key.
//!
//! # Persistence
//!
//! The leaf counter is file-backed: [`XmssVrf::save_counter`] writes
//! `XMSSCTR1 || height || next_leaf || root` (56 bytes) and
//! [`XmssVrf::open`] / [`load_counter`] read it back. Files are written with
//! the `node_keys.rs` discipline — 0600, symlink-refused
//! ([`crate::node_keys::write_private_file`]) — and loads verify 0600 plus
//! symlink refusal ([`crate::node_keys::verify_file_perms`]), then check the
//! magic, the height range, `next_leaf <= capacity`, and (on `open`) that the
//! stored root matches the recomputed root for the supplied master secret
//! (fail-closed on key/counter mismatch). No paths are hardwired: both
//! functions take `&Path`. The seed history is intentionally NOT persisted
//! (seeds are public beacon inputs); post-restart refusal evidence carries
//! the attempted seed only — see below.
//!
//! # Evidence
//!
//! * API-level refusal: [`XmssError::LeafReuse`] carries
//!   `XMSS-EQV1 || root(32) || epoch_be64 || attempted_seed`. This is a
//!   forensic attempt record for operator logs — it is NOT a standalone
//!   fraud proof (the second signature was never created, by design).
//!   Parse it with [`parse_refusal_evidence`].
//! * Standalone slashable proof: two valid signatures on the same
//!   `(root, epoch)` with different seeds. [`verify_equivocation`] checks
//!   both and returns canonical bytes
//!   `XMSS-EQV1 || root || epoch_be64 || seed_a || sig_a || seed_b || sig_b`
//!   (length-prefixed); parse with [`parse_equivocation_evidence`].
//!
//! # What this module is NOT
//!
//! No consensus wiring (beacon activation / slashing dispatch is a sibling
//! workstream), no network code, no key generation ceremony beyond holding a
//! caller-supplied 32-byte master secret (wiped on drop via `Zeroizing`).

use std::path::Path;

use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Parameters (P14 A.1, ported shapes)
// ---------------------------------------------------------------------------

/// Winternitz parameter: 4-bit digits.
pub const WOTS_W: u32 = 16;
/// Hash output length in bytes (SHAKE256-256).
pub const WOTS_N: usize = 32;
/// WOTS+ message digits for `n = 32`, `w = 16`.
pub const WOTS_LEN1: usize = 64;
/// WOTS+ checksum digits.
pub const WOTS_LEN2: usize = 3;
/// WOTS+ chain count (`len1 + len2`).
pub const WOTS_LEN: usize = WOTS_LEN1 + WOTS_LEN2; // 67
/// Public-key bytes (Merkle root).
pub const PUBLIC_KEY_LEN: usize = 32;
/// VRF output bytes.
pub const VRF_OUTPUT_LEN: usize = 32;
/// Default tree height: 1024 leaves, 2464 B signatures, ~22 h at
/// 128 blocks/epoch and 0.6 s/block. A day-key, not a forever-key.
pub const DEFAULT_HEIGHT: u8 = 10;
/// Minimum tree height (2 leaves).
pub const MIN_HEIGHT: u8 = 1;
/// Maximum tree height (4096 leaves). Fail-closed DoS/OOM guard: the build
/// cost doubles per height bit; beyond this needs XMSS^MT (not implemented).
pub const MAX_HEIGHT: u8 = 12;
/// Evidence prefix shared by refusal records and equivocation proofs.
pub const EQUIVOCATION_PREFIX: &[u8; 9] = b"XMSS-EQV1";
/// Counter-file magic (`XMSSCTR1`).
const STATE_MAGIC: &[u8; 8] = b"XMSSCTR1";
/// Counter-file length: magic(8) + height(1) + reserved(7) + next_leaf(8) + root(32).
const STATE_LEN: usize = 56;

// Domain separators: same positions as the P14 prototype (`\x01`..`\x07`),
// applied to SHAKE256 instead of the prototype's SHA-256.
const D_CHAIN: u8 = 0x01;
const D_MSG: u8 = 0x02;
const D_SK: u8 = 0x03;
const D_LEAFSEED: u8 = 0x04;
const D_LEAF: u8 = 0x05;
const D_NODE: u8 = 0x06;
const D_VRF: u8 = 0x07;

// ---------------------------------------------------------------------------
// Errors (all fail-closed; reuse carries evidence)
// ---------------------------------------------------------------------------

/// Fail-closed errors for key construction, signing, and persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmssError {
    /// Height outside `MIN_HEIGHT..=MAX_HEIGHT`.
    InvalidHeight(u8),
    /// In-range epoch that is not the next unused leaf (a skip would burn
    /// intermediate leaves, so it is refused rather than fast-forwarded).
    UnexpectedEpoch {
        /// The only epoch this instance will sign.
        expected: u64,
        /// The epoch that was requested.
        got: u64,
    },
    /// The epoch was already signed. Carries forensic evidence bytes
    /// (`XMSS-EQV1 || root || epoch_be64 || attempted_seed`); see
    /// [`parse_refusal_evidence`]. The one-time key is NOT touched.
    LeafReuse {
        /// Reused leaf (= epoch number).
        epoch: u64,
        /// Forensic attempt record (NOT a standalone fraud proof).
        evidence: Vec<u8>,
    },
    /// No signature can ever cover this epoch: the key is exhausted
    /// (`next_leaf == capacity`) or the epoch is beyond capacity. Rotate.
    Exhausted {
        /// Tree capacity (`2^h`).
        capacity: u64,
        /// The epoch that was requested.
        epoch: u64,
    },
    /// Malformed signature bytes or counter file.
    Corrupt(String),
    /// Filesystem failure (missing file, bad permissions, write error).
    Io(String),
}

impl std::fmt::Display for XmssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeight(h) => write!(
                f,
                "invalid XMSS tree height {h}: must be {MIN_HEIGHT}..={MAX_HEIGHT} \
                 (larger needs XMSS^MT rotation, not implemented)"
            ),
            Self::UnexpectedEpoch { expected, got } => write!(
                f,
                "epoch {got} is not the next unused leaf {expected}: XMSS leaves \
                 are one-time and sequential, skipping would burn leaves"
            ),
            Self::LeafReuse { epoch, .. } => write!(
                f,
                "leaf {epoch} already signed: re-signing an epoch is refused; \
                 the attempt is recorded as slashable evidence bytes"
            ),
            Self::Exhausted { capacity, epoch } => write!(
                f,
                "XMSS key exhausted (capacity {capacity} leaves): epoch {epoch} \
                 can never be signed, rotate the key (XMSS^MT for longer life)"
            ),
            Self::Corrupt(s) => write!(f, "corrupt XMSS bytes: {s}"),
            Self::Io(s) => write!(f, "XMSS state I/O: {s}"),
        }
    }
}

impl std::error::Error for XmssError {}

// ---------------------------------------------------------------------------
// SHAKE256 XOF over the tree's Keccak sponge (reuse, not a second Keccak)
// ---------------------------------------------------------------------------

const SHAKE_RATE: usize = 136;

/// SHAKE256 `input -> out.len()` bytes, built on
/// [`crate::post_quantum::keccak_f1600`] (the same sponge the Falcon path
/// links). Padding is FIPS 202 SHAKE (`0x1F`, `0x80` in the last rate byte).
fn shake256(input: &[u8], out: &mut [u8]) {
    use crate::post_quantum::keccak_f1600;
    let mut st = [0u64; 25];
    // GATE: byte-exact block XOR, same shape as `post_quantum::Shake256Reader`
    // (mirror, not a copy: the reader type is private, the permutation is the
    // shared primitive). Full 136-byte blocks are absorbed; the tail goes
    // through the FIPS 202 SHAKE pad below.
    let mut blocks = input.chunks_exact(SHAKE_RATE);
    for block in &mut blocks {
        for (slot, lane) in st.iter_mut().zip(block.chunks_exact(8)) {
            let bytes: [u8; 8] = lane.try_into().unwrap();
            *slot ^= u64::from_le_bytes(bytes);
        }
        keccak_f1600(&mut st);
    }
    let mut pad = [0u8; SHAKE_RATE];
    let rem = blocks.remainder();
    pad[..rem.len()].copy_from_slice(rem);
    pad[rem.len()] = 0x1F;
    pad[SHAKE_RATE - 1] |= 0x80;
    for (slot, lane) in st.iter_mut().zip(pad.chunks_exact(8)) {
        let bytes: [u8; 8] = lane.try_into().unwrap();
        *slot ^= u64::from_le_bytes(bytes);
    }
    keccak_f1600(&mut st);
    let mut pos = 0usize;
    while pos < out.len() {
        // Squeeze exactly one rate block (17 lanes) per permutation: lanes
        // past the rate are sponge capacity, never output.
        for slot in st.iter().take(SHAKE_RATE / 8) {
            if pos >= out.len() {
                break;
            }
            let bytes = slot.to_le_bytes();
            let take = core::cmp::min(8, out.len() - pos);
            out[pos..pos + take].copy_from_slice(&bytes[..take]);
            pos += take;
        }
        if pos < out.len() {
            keccak_f1600(&mut st);
        }
    }
}

/// SHAKE256 compressed to 32 bytes.
fn shake32(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(input, &mut out);
    out
}

// ---------------------------------------------------------------------------
// WOTS+ (w = 16, n = 32, len = 67)
// ---------------------------------------------------------------------------

/// One hash-chain step block: `chain(x, steps) = H(D_CHAIN || .)^steps (x)`.
fn chain(mut x: [u8; 32], steps: u32) -> [u8; 32] {
    for _ in 0..steps {
        let mut input = [0u8; 33];
        input[0] = D_CHAIN;
        input[1..].copy_from_slice(&x);
        x = shake32(&input);
    }
    x
}

/// Message digits: 64 base-`w` nibbles (MSB-first) of `H(D_MSG || msg)` plus
/// the 3-nibble big-endian checksum (P14 `wots_digits` / `csum_digits`).
fn wots_digits(msg: &[u8]) -> [u32; WOTS_LEN] {
    let mut prefixed = Vec::with_capacity(1 + msg.len());
    prefixed.push(D_MSG);
    prefixed.extend_from_slice(msg);
    let mh = shake32(&prefixed);
    let mut digits = [0u32; WOTS_LEN];
    for (i, b) in mh.iter().enumerate() {
        digits[2 * i] = (b >> 4) as u32;
        digits[2 * i + 1] = (b & 0x0F) as u32;
    }
    let csum: u32 = digits[..WOTS_LEN1]
        .iter()
        .map(|d| (WOTS_W - 1) - d)
        .sum();
    for i in 0..WOTS_LEN2 {
        let shift = 4 * (WOTS_LEN2 - 1 - i);
        digits[WOTS_LEN1 + i] = (csum >> shift) & 0x0F;
    }
    digits
}

/// `sk[i] = H(D_SK || leaf_seed || i)` — deterministic, no RNG.
fn wots_sk(leaf_seed: &[u8; 32], i: u8) -> [u8; 32] {
    let mut input = [0u8; 34];
    input[0] = D_SK;
    input[1..33].copy_from_slice(leaf_seed);
    input[33] = i;
    shake32(&input)
}

/// Leaf seed: `H(D_LEAFSEED || master || idx_be32)`.
fn leaf_seed(master: &[u8; 32], idx: u64) -> [u8; 32] {
    let mut input = [0u8; 1 + 32 + 4];
    input[0] = D_LEAFSEED;
    input[1..33].copy_from_slice(master);
    let idx32 = u32::try_from(idx).unwrap_or(u32::MAX);
    input[33..37].copy_from_slice(&idx32.to_be_bytes());
    shake32(&input)
}

/// Leaf public value: `H(D_LEAF || pk_0 || ... || pk_66)`.
fn leaf_hash(wots_pk: &[[u8; 32]; WOTS_LEN]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + WOTS_LEN * WOTS_N);
    input.push(D_LEAF);
    for part in wots_pk.iter() {
        input.extend_from_slice(part);
    }
    shake32(&input)
}

/// Internal node: `H(D_NODE || left || right)` (order-sensitive).
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 65];
    input[0] = D_NODE;
    input[1..33].copy_from_slice(left);
    input[33..65].copy_from_slice(right);
    shake32(&input)
}

/// VRF output: `y = H(D_VRF || seed || wots_sig_concat)`.
fn vrf_output(seed: &[u8], wots_sig: &[[u8; 32]; WOTS_LEN]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + seed.len() + WOTS_LEN * WOTS_N);
    input.push(D_VRF);
    input.extend_from_slice(seed);
    for part in wots_sig.iter() {
        input.extend_from_slice(part);
    }
    shake32(&input)
}

// ---------------------------------------------------------------------------
// Signatures (wire shape: wots_concat || auth_concat, epoch carried aside)
// ---------------------------------------------------------------------------

/// An XMSS signature for one epoch: the WOTS+ signature plus the Merkle
/// authentication path. Wire bytes are exactly
/// `67*32 + h*32` (2336 B at `h = 6` … 2464 B at `h = 10`); the epoch travels
/// as the leaf index alongside, not inside, the bytes (P14 sizing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmssSignature {
    /// Leaf index = epoch number.
    pub epoch: u64,
    /// WOTS+ signature (67 one-time chain outputs).
    pub wots_sig: [[u8; 32]; WOTS_LEN],
    /// Sibling hashes from leaf level to below the root (`len == height`).
    pub auth_path: Vec<[u8; 32]>,
}

impl XmssSignature {
    /// Canonical bytes: `wots_sig` concat then `auth_path` concat.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WOTS_LEN * WOTS_N + self.auth_path.len() * 32);
        for part in self.wots_sig.iter() {
            out.extend_from_slice(part);
        }
        for sib in self.auth_path.iter() {
            out.extend_from_slice(sib);
        }
        out
    }

    /// Decode bytes produced by [`XmssSignature::to_bytes`] for the given
    /// tree height and epoch. Refuses truncated, padded, or re-framed bytes.
    pub fn from_bytes(height: u8, epoch: u64, bytes: &[u8]) -> Result<Self, XmssError> {
        check_height(height)?;
        let want = signature_len(height);
        if bytes.len() != want {
            return Err(XmssError::Corrupt(format!(
                "XMSS signature length mismatch for h={height}: expected {want}, got {}",
                bytes.len()
            )));
        }
        let mut wots_sig = [[0u8; 32]; WOTS_LEN];
        for (i, part) in wots_sig.iter_mut().enumerate() {
            part.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
        }
        let mut auth_path = Vec::with_capacity(height as usize);
        let base = WOTS_LEN * 32;
        for i in 0..height as usize {
            let mut sib = [0u8; 32];
            sib.copy_from_slice(&bytes[base + i * 32..base + (i + 1) * 32]);
            auth_path.push(sib);
        }
        Ok(Self {
            epoch,
            wots_sig,
            auth_path,
        })
    }
}

/// Wire length for tree height `h`: `67*32 + h*32` (2336 at h=6 … 2464 at h=10).
pub const fn signature_len(height: u8) -> usize {
    WOTS_LEN * WOTS_N + (height as usize) * WOTS_N
}

/// Tree capacity (`2^h`) for a valid height.
pub fn capacity_for_height(height: u8) -> Result<u64, XmssError> {
    check_height(height)?;
    Ok(1u64 << height)
}

fn check_height(height: u8) -> Result<(), XmssError> {
    if !(MIN_HEIGHT..=MAX_HEIGHT).contains(&height) {
        return Err(XmssError::InvalidHeight(height));
    }
    Ok(())
}

/// Recompute the Merkle root for `(seed, sig)` with a tree of `height`.
fn recover_root(seed: &[u8], sig: &XmssSignature, height: u8) -> Result<[u8; 32], XmssError> {
    check_height(height)?;
    if sig.auth_path.len() != height as usize {
        return Err(XmssError::Corrupt(format!(
            "auth path length {} does not match height {height}",
            sig.auth_path.len()
        )));
    }
    let digits = wots_digits(seed);
    let mut pk = [[0u8; 32]; WOTS_LEN];
    for i in 0..WOTS_LEN {
        pk[i] = chain(sig.wots_sig[i], (WOTS_W - 1) - digits[i]);
    }
    let mut node = leaf_hash(&pk);
    let mut idx = sig.epoch;
    for sib in sig.auth_path.iter() {
        node = if idx & 1 == 1 {
            node_hash(sib, &node)
        } else {
            node_hash(&node, sib)
        };
        idx >>= 1;
    }
    Ok(node)
}

/// Stateless verification against a trusted root: checks `sig.epoch ==
/// epoch`, `epoch < 2^height`, the recomputed root, and `y`. Pure function —
/// no state, no I/O; this is what third parties (and the future consensus
/// sibling) call.
pub fn verify_signature(
    root: &[u8; 32],
    height: u8,
    epoch: u64,
    seed: &[u8],
    y: &[u8; 32],
    sig: &XmssSignature,
) -> bool {
    if check_height(height).is_err() {
        return false;
    }
    if sig.epoch != epoch {
        return false;
    }
    if epoch >= (1u64 << height) {
        return false;
    }
    let recovered = match recover_root(seed, sig, height) {
        Ok(r) => r,
        Err(_) => return false,
    };
    if &recovered != root {
        return false;
    }
    &vrf_output(seed, &sig.wots_sig) == y
}

// ---------------------------------------------------------------------------
// Evidence helpers
// ---------------------------------------------------------------------------

fn refusal_evidence(root: &[u8; 32], epoch: u64, attempted_seed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(EQUIVOCATION_PREFIX.len() + 32 + 8 + attempted_seed.len());
    out.extend_from_slice(EQUIVOCATION_PREFIX);
    out.extend_from_slice(root);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(attempted_seed);
    out
}

/// Parse refusal evidence bytes from [`XmssError::LeafReuse`] into
/// `(root, epoch, attempted_seed)`. Returns `None` on a bad prefix or shape.
pub fn parse_refusal_evidence(bytes: &[u8]) -> Option<([u8; 32], u64, Vec<u8>)> {
    let ep = EQUIVOCATION_PREFIX.len();
    if bytes.len() < ep + 32 + 8 {
        return None;
    }
    if &bytes[..ep] != EQUIVOCATION_PREFIX {
        return None;
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[ep..ep + 32]);
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&bytes[ep + 32..ep + 40]);
    Some((root, u64::from_be_bytes(epoch_bytes), bytes[ep + 40..].to_vec()))
}

/// Canonical slashable proof for two valid signatures on one leaf.
///
/// Checks `seed_a != seed_b`, both signatures decode for `height`, both
/// verify under `(root, epoch)`. Returns the canonical evidence bytes
/// `XMSS-EQV1 || root || epoch_be64 || len_a || seed_a || sig_a || len_b ||
/// seed_b || sig_b` (lengths: u16le seeds, u32le sigs), or `None` when this
/// is NOT a valid equivocation proof. Two `Some` outputs for one epoch mean
/// the WOTS+ key is burned and the signer is slashable.
pub fn verify_equivocation(
    root: &[u8; 32],
    height: u8,
    epoch: u64,
    seed_a: &[u8],
    sig_a: &[u8],
    seed_b: &[u8],
    sig_b: &[u8],
) -> Option<Vec<u8>> {
    if seed_a == seed_b {
        return None;
    }
    let a = XmssSignature::from_bytes(height, epoch, sig_a).ok()?;
    let b = XmssSignature::from_bytes(height, epoch, sig_b).ok()?;
    let ya = vrf_output(seed_a, &a.wots_sig);
    let yb = vrf_output(seed_b, &b.wots_sig);
    if !verify_signature(root, height, epoch, seed_a, &ya, &a) {
        return None;
    }
    if !verify_signature(root, height, epoch, seed_b, &yb, &b) {
        return None;
    }
    let mut out = Vec::with_capacity(49 + seed_a.len() + sig_a.len() + seed_b.len() + sig_b.len());
    out.extend_from_slice(EQUIVOCATION_PREFIX);
    out.extend_from_slice(root);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&(seed_a.len() as u16).to_le_bytes());
    out.extend_from_slice(seed_a);
    out.extend_from_slice(&(sig_a.len() as u32).to_le_bytes());
    out.extend_from_slice(sig_a);
    out.extend_from_slice(&(seed_b.len() as u16).to_le_bytes());
    out.extend_from_slice(seed_b);
    out.extend_from_slice(&(sig_b.len() as u32).to_le_bytes());
    out.extend_from_slice(sig_b);
    Some(out)
}

/// Parsed equivocation proof (see [`verify_equivocation`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationEvidence {
    /// Merkle root both signatures verify under.
    pub root: [u8; 32],
    /// Doubly-signed epoch.
    pub epoch: u64,
    /// First seed and signature bytes.
    pub seed_a: Vec<u8>,
    /// First signature bytes.
    pub sig_a: Vec<u8>,
    /// Second (different) seed and signature bytes.
    pub seed_b: Vec<u8>,
    /// Second signature bytes.
    pub sig_b: Vec<u8>,
}

/// Parse canonical equivocation evidence bytes. Returns `None` on a bad
/// prefix, truncation, padding, or an empty seed leg.
pub fn parse_equivocation_evidence(bytes: &[u8]) -> Option<EquivocationEvidence> {
    let ep = EQUIVOCATION_PREFIX.len();
    if bytes.len() < ep + 32 + 8 + 2 {
        return None;
    }
    if &bytes[..ep] != EQUIVOCATION_PREFIX {
        return None;
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[ep..ep + 32]);
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&bytes[ep + 32..ep + 40]);
    let epoch = u64::from_be_bytes(epoch_bytes);
    let mut cur = ep + 40;
    let take = |cur: &mut usize, n: usize| -> Option<Vec<u8>> {
        let end = (*cur).checked_add(n)?;
        if end > bytes.len() {
            return None;
        }
        let v = bytes[*cur..end].to_vec();
        *cur = end;
        Some(v)
    };
    let read_u16 = |cur: &mut usize| -> Option<usize> {
        let raw = take(cur, 2)?;
        Some(u16::from_le_bytes([raw[0], raw[1]]) as usize)
    };
    let read_u32 = |cur: &mut usize| -> Option<usize> {
        let raw = take(cur, 4)?;
        Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize)
    };
    let la = read_u16(&mut cur)?;
    let seed_a = take(&mut cur, la)?;
    let sa = read_u32(&mut cur)?;
    let sig_a = take(&mut cur, sa)?;
    let lb = read_u16(&mut cur)?;
    let seed_b = take(&mut cur, lb)?;
    let sb = read_u32(&mut cur)?;
    let sig_b = take(&mut cur, sb)?;
    if cur != bytes.len() || seed_a.is_empty() || seed_b.is_empty() {
        return None;
    }
    Some(EquivocationEvidence {
        root,
        epoch,
        seed_a,
        sig_a,
        seed_b,
        sig_b,
    })
}

// ---------------------------------------------------------------------------
// Stateful signer
// ---------------------------------------------------------------------------

/// File-backed counter snapshot (see [`XmssVrf::save_counter`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// Tree height the counter belongs to.
    pub height: u8,
    /// Next unused leaf (= number of signatures issued).
    pub next_leaf: u64,
    /// Merkle root the counter was saved with.
    pub root: [u8; 32],
}

/// Stateful XMSS-VRF signer: one WOTS+ leaf per epoch, monotone counter,
/// cached Merkle tree. The master secret is wiped on drop.
pub struct XmssVrf {
    master: Zeroizing<[u8; 32]>,
    height: u8,
    levels: Vec<Vec<[u8; 32]>>,
    root: [u8; 32],
    next_leaf: u64,
    /// First seed signed per used leaf (in-memory forensics only; the
    /// refusal evidence carries the attempted seed, so restarts stay valid).
    first_seeds: Vec<Option<Vec<u8>>>,
}

impl std::fmt::Debug for XmssVrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XmssVrf")
            .field("height", &self.height)
            .field("root", &hex::encode(self.root))
            .field("next_leaf", &self.next_leaf)
            .field("capacity", &self.capacity())
            .field("master", &"[redacted]")
            .finish()
    }
}

impl Drop for XmssVrf {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}

impl XmssVrf {
    /// Build a signer of tree height `h` (`1..=12`), computing and caching
    /// the full Merkle tree. Cost doubles per height bit (one-time).
    ///
    /// # Errors
    ///
    /// [`XmssError::InvalidHeight`] when `h` is outside `1..=12`.
    pub fn new(master: [u8; 32], height: u8) -> Result<Self, XmssError> {
        check_height(height)?;
        let leaves = 1usize << height;
        let mut level0 = Vec::with_capacity(leaves);
        for i in 0..leaves {
            let ls = leaf_seed(&master, i as u64);
            let mut pk = [[0u8; 32]; WOTS_LEN];
            for (j, slot) in pk.iter_mut().enumerate() {
                *slot = chain(wots_sk(&ls, j as u8), WOTS_W - 1);
            }
            level0.push(leaf_hash(&pk));
        }
        let mut levels: Vec<Vec<[u8; 32]>> = vec![level0];
        while levels.last().is_some_and(|l| l.len() > 1) {
            let cur = levels.last().map(Vec::as_slice).unwrap_or(&[]);
            let mut next = Vec::with_capacity(cur.len() / 2);
            for pair in cur.chunks_exact(2) {
                next.push(node_hash(&pair[0], &pair[1]));
            }
            levels.push(next);
        }
        let root = levels.last().and_then(|l| l.first()).copied().unwrap_or([0u8; 32]);
        let capacity = leaves as u64;
        Ok(Self {
            master: Zeroizing::new(master),
            height,
            levels,
            root,
            next_leaf: 0,
            first_seeds: vec![None; capacity as usize],
        })
    }

    /// Build a signer with [`DEFAULT_HEIGHT`] (10): 1024 leaves, 2464 B
    /// signatures, ~22 h of beacon at 128 blocks/epoch and 0.6 s/block.
    /// Choose explicit [`XmssVrf::new`] heights only after reading the
    /// lifetime table in the module docs.
    ///
    /// # Errors
    ///
    /// Only when the compiled-in default ever leaves `1..=12` (cannot happen;
    /// fail-closed anyway).
    pub fn with_default_height(master: [u8; 32]) -> Result<Self, XmssError> {
        Self::new(master, DEFAULT_HEIGHT)
    }

    /// Merkle root = the VRF public key (32 bytes).
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Tree height.
    pub fn height(&self) -> u8 {
        self.height
    }

    /// Tree capacity in leaves (`2^h`).
    pub fn capacity(&self) -> u64 {
        1u64 << self.height
    }

    /// Next unused leaf (= epochs signed so far).
    pub fn next_leaf(&self) -> u64 {
        self.next_leaf
    }

    /// First seed signed for `epoch`, if this instance signed it (in-memory
    /// only; `None` for unsigned epochs and after a restart).
    pub fn first_seed(&self, epoch: u64) -> Option<&[u8]> {
        self.first_seeds
            .get(epoch as usize)
            .and_then(|s| s.as_deref())
    }

    fn auth_path(&self, idx: u64) -> Vec<[u8; 32]> {
        let mut path = Vec::with_capacity(self.height as usize);
        let mut i = idx as usize;
        for level in self.levels.iter().take(self.height as usize) {
            path.push(level[i ^ 1]);
            i >>= 1;
        }
        path
    }

    /// Sign `seed` for `epoch` and return `(y, sigma)`.
    ///
    /// Allowed ONLY when `epoch == next_leaf`; the counter advances on
    /// success. Deterministic: the same inputs always give the same outputs.
    ///
    /// # Errors
    ///
    /// * [`XmssError::Exhausted`] — key used up or epoch beyond capacity.
    /// * [`XmssError::LeafReuse`] — epoch already signed (with evidence).
    /// * [`XmssError::UnexpectedEpoch`] — in-range future epoch (refused so a
    ///   skip cannot silently burn leaves).
    pub fn sign(&mut self, epoch: u64, seed: &[u8]) -> Result<([u8; 32], XmssSignature), XmssError> {
        let capacity = self.capacity();
        if self.next_leaf >= capacity || epoch >= capacity {
            return Err(XmssError::Exhausted { capacity, epoch });
        }
        if epoch < self.next_leaf {
            return Err(XmssError::LeafReuse {
                epoch,
                evidence: refusal_evidence(&self.root, epoch, seed),
            });
        }
        if epoch != self.next_leaf {
            return Err(XmssError::UnexpectedEpoch {
                expected: self.next_leaf,
                got: epoch,
            });
        }
        let ls = leaf_seed(&self.master, epoch);
        let digits = wots_digits(seed);
        let mut wots_sig = [[0u8; 32]; WOTS_LEN];
        for i in 0..WOTS_LEN {
            wots_sig[i] = chain(wots_sk(&ls, i as u8), digits[i]);
        }
        let y = vrf_output(seed, &wots_sig);
        let sig = XmssSignature {
            epoch,
            wots_sig,
            auth_path: self.auth_path(epoch),
        };
        self.first_seeds[epoch as usize] = Some(seed.to_vec());
        self.next_leaf += 1;
        Ok((y, sig))
    }

    /// Verify `(epoch, seed, y, sig)` against this signer's root. Thin
    /// wrapper over [`verify_signature`].
    pub fn verify(&self, epoch: u64, seed: &[u8], y: &[u8; 32], sig: &XmssSignature) -> bool {
        verify_signature(&self.root, self.height, epoch, seed, y, sig)
    }

    // -- persistence -------------------------------------------------------

    /// Save the leaf counter to `path` (no hardwired paths): 56 bytes
    /// `XMSSCTR1 || height || reserved || next_leaf_le64 || root`, written
    /// 0600 and symlink-refused via `node_keys::write_private_file` (parent
    /// dir created 0700 when missing, mirroring `save_node_keys`).
    ///
    /// # Errors
    ///
    /// [`XmssError::Io`] when the directory cannot be prepared or the file
    /// cannot be written.
    pub fn save_counter(&self, path: &Path) -> Result<(), XmssError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                crate::node_keys::ensure_secure_dir(parent)
                    .map_err(|e| XmssError::Io(format!("counter dir {}: {e}", parent.display())))?;
            }
        }
        let mut buf = Vec::with_capacity(STATE_LEN);
        buf.extend_from_slice(STATE_MAGIC);
        buf.push(self.height);
        buf.extend_from_slice(&[0u8; 7]);
        buf.extend_from_slice(&self.next_leaf.to_le_bytes());
        buf.extend_from_slice(&self.root);
        crate::node_keys::write_private_file(path, &buf)
            .map_err(|e| XmssError::Io(format!("write counter {}: {e}", path.display())))
    }

    /// Reopen a signer from a counter file: loads and validates the snapshot,
    /// rebuilds the tree from `master`, and refuses on root mismatch (the
    /// file belongs to a different key) or on counter/state corruption.
    ///
    /// # Errors
    ///
    /// [`XmssError::Io`] (missing file, non-0600 mode, symlink) or
    /// [`XmssError::Corrupt`] (bad magic/shape, root mismatch).
    pub fn open(master: [u8; 32], path: &Path) -> Result<Self, XmssError> {
        let snap = load_counter(path)?;
        let mut signer = Self::new(master, snap.height)?;
        if signer.root != snap.root {
            return Err(XmssError::Corrupt(format!(
                "counter {} belongs to a different key: stored root {} != recomputed root {}",
                path.display(),
                hex::encode(snap.root),
                hex::encode(signer.root)
            )));
        }
        signer.next_leaf = snap.next_leaf;
        Ok(signer)
    }
}

/// Load and validate a counter file written by [`XmssVrf::save_counter`]:
/// enforces 0600 + symlink refusal, the `XMSSCTR1` magic, exact length, a
/// valid height, and `next_leaf <= capacity`.
///
/// # Errors
///
/// [`XmssError::Io`] (missing file, bad mode, symlink) or
/// [`XmssError::Corrupt`] (bad magic/shape/range).
pub fn load_counter(path: &Path) -> Result<CounterSnapshot, XmssError> {
    crate::node_keys::verify_file_perms(path)
        .map_err(|e| XmssError::Io(format!("counter {}: {e}", path.display())))?;
    let raw =
        std::fs::read(path).map_err(|e| XmssError::Io(format!("read {}: {e}", path.display())))?;
    if raw.len() != STATE_LEN {
        return Err(XmssError::Corrupt(format!(
            "counter length: expected {STATE_LEN}, got {}",
            raw.len()
        )));
    }
    if &raw[..8] != STATE_MAGIC {
        return Err(XmssError::Corrupt("counter magic mismatch".to_string()));
    }
    let height = raw[8];
    check_height(height)?;
    if raw[9..16].iter().any(|b| *b != 0) {
        return Err(XmssError::Corrupt("counter reserved bytes must be zero".to_string()));
    }
    let mut next_bytes = [0u8; 8];
    next_bytes.copy_from_slice(&raw[16..24]);
    let next_leaf = u64::from_le_bytes(next_bytes);
    let mut root = [0u8; 32];
    root.copy_from_slice(&raw[24..56]);
    let capacity = 1u64 << height;
    if next_leaf > capacity {
        return Err(XmssError::Corrupt(format!(
            "counter next_leaf {next_leaf} exceeds capacity {capacity}"
        )));
    }
    Ok(CounterSnapshot {
        height,
        next_leaf,
        root,
    })
}

// ---------------------------------------------------------------------------
// Tests (unit scope: `cargo test --lib xmss_vrf::`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const KAT_MASTER: [u8; 32] = [7u8; 32];
    const KAT_SEED: &[u8] = b"kat-seed-0";
    // Independent cross-implementation vector (SHAKE256 shapes replicated in
    // Munin-python before this module was written): h=2, epoch 0.
    const KAT_ROOT: &str = "2dcd11f747a293b3b98a90136853e8d93e2bc19a28ea3e963c1d9205929afb0c";
    const KAT_Y: &str = "282a351f42ca3c7f53d533cb967af5c53293fc761e29e954e9186e733e9b3547";
    const KAT_WOTS0: &str = "9acfdf3ae5c00ee9cfc0f50b7099f16d93e49fc37b9260b0a7d8456d40c6f1fd";
    const KAT_WOTS66: &str = "5de821b50ab4b3374350541b31060a9ba9f3a408b6982b67e6b603c1c318a28c";
    const KAT_AUTH0: &str = "b6f9bdd4753170c67675c67bc93742df575e648d03f5246f1a576fbe3376ea75";

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xmss_vrf_{tag}_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn shake256_kat_empty_and_abc() {
        // FIPS 202 reference outputs (pinned via `hashlib.shake_256`).
        let mut out = [0u8; 64];
        shake256(b"", &mut out);
        assert_eq!(
            hex::encode(out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
        shake256(b"abc", &mut out);
        assert_eq!(
            hex::encode(out),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        );
    }

    #[test]
    fn shake256_kat_multiblock_absorb_and_squeeze() {
        // 300-byte input (> 136-byte rate) with 200-byte output exercises the
        // multi-block absorb and multi-perm squeeze paths.
        let input = vec![0xABu8; 300];
        let mut out = [0u8; 200];
        shake256(&input, &mut out);
        assert_eq!(
            hex::encode(out),
            "6bd7620c8d0546e8e1dfa14fd024f478a0635a7a0bcd8b1d42f2e7a354c286c639658aba14f6e9134af21ab5582ef7e663d53486383eecd3265aae07ab1566fbf88b10255697cd0e4e70910eff7f005ac9a552e1f14eb3a86c513820da57c0162ccfc98d3bfa8c22b10a0519201a248a68596b6f83fd1af948317306a0de934c80212e75a1a10a662b39638982b5e337893a2fb392a8bb9e978ed5a6303a305112bb934b1f7a6419a69c848765cf2d2263401ff3aacac21a73f73fb2514c6225a3a7bbf1a8f65c74"
        );
    }

    #[test]
    fn determinism_vectors_match_cross_implementation_kat() {
        let mut v = XmssVrf::new(KAT_MASTER, 2).unwrap();
        let (y1, sig1) = v.sign(0, KAT_SEED).unwrap();
        assert_eq!(hex::encode(v.root()), KAT_ROOT);
        assert_eq!(hex::encode(y1), KAT_Y);
        assert_eq!(hex::encode(sig1.wots_sig[0]), KAT_WOTS0);
        assert_eq!(hex::encode(sig1.wots_sig[66]), KAT_WOTS66);
        assert_eq!(hex::encode(sig1.auth_path[0]), KAT_AUTH0);
        assert!(v.verify(0, KAT_SEED, &y1, &sig1));
        // Determinism: a fresh instance with the same master signs identically.
        let mut v2 = XmssVrf::new(KAT_MASTER, 2).unwrap();
        let (y2, sig2) = v2.sign(0, KAT_SEED).unwrap();
        assert_eq!(y1, y2);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn signature_bytes_roundtrip_and_sizes_pinned() {
        // P14/P15 report sizes: 2336 @ h=6, 2400 @ h=8, 2464 @ h=10.
        assert_eq!(signature_len(6), 2336);
        assert_eq!(signature_len(8), 2400);
        assert_eq!(signature_len(10), 2464);
        assert_eq!(PUBLIC_KEY_LEN, 32);
        assert_eq!(VRF_OUTPUT_LEN, 32);
        let mut v = XmssVrf::new([9u8; 32], 3).unwrap();
        let (y, sig) = v.sign(0, b"size-seed").unwrap();
        assert_eq!(sig.to_bytes().len(), 67 * 32 + 3 * 32);
        let back = XmssSignature::from_bytes(3, 0, &sig.to_bytes()).unwrap();
        assert_eq!(back, sig);
        assert!(v.verify(0, b"size-seed", &y, &back));
        // Truncated / padded encodings are refused, not reinterpreted.
        assert!(XmssSignature::from_bytes(3, 0, &sig.to_bytes()[..100]).is_err());
        let mut padded = sig.to_bytes();
        padded.push(0);
        assert!(XmssSignature::from_bytes(3, 0, &padded).is_err());
    }

    #[test]
    fn wrong_epoch_and_seed_are_refused() {
        let mut v = XmssVrf::new([11u8; 32], 3).unwrap();
        let (y, sig) = v.sign(0, b"epoch-seed").unwrap();
        assert!(v.verify(0, b"epoch-seed", &y, &sig));
        // Wrong epoch, wrong seed, wrong y, tampered signature: all false.
        assert!(!v.verify(1, b"epoch-seed", &y, &sig));
        assert!(!v.verify(0, b"other-seed", &y, &sig));
        assert!(!v.verify(0, b"epoch-seed", &[0u8; 32], &sig));
        let mut bad = sig.clone();
        bad.wots_sig[0][0] ^= 0xFF;
        assert!(!v.verify(0, b"epoch-seed", &y, &bad));
        // A leaf from another epoch does not verify at this epoch.
        let (y1, sig1) = v.sign(1, b"epoch-seed").unwrap();
        assert!(!v.verify(0, b"epoch-seed", &y1, &sig1));
        // A foreign root never verifies.
        let other = XmssVrf::new([12u8; 32], 3).unwrap();
        assert!(!other.verify(0, b"epoch-seed", &y, &sig));
        // Stateless path agrees.
        assert!(verify_signature(&v.root(), 3, 1, b"epoch-seed", &y1, &sig1));
        assert!(!verify_signature(&v.root(), 3, 0, b"epoch-seed", &y1, &sig1));
    }

    #[test]
    fn double_sign_refused_with_evidence_shape() {
        let mut v = XmssVrf::new([13u8; 32], 2).unwrap();
        let (y0, _) = v.sign(0, b"first").unwrap();
        assert_eq!(v.next_leaf(), 1);
        let err = match v.sign(0, b"second") {
            Err(XmssError::LeafReuse { epoch, evidence }) => {
                assert_eq!(epoch, 0);
                evidence
            }
            other => panic!("double-sign must be LeafReuse, got {other:?}"),
        };
        // Evidence shape: prefix || root || epoch_be64 || attempted seed.
        let (root, epoch, seed) = parse_refusal_evidence(&err).expect("evidence must parse");
        assert_eq!(root, v.root());
        assert_eq!(epoch, 0);
        assert_eq!(seed, b"second");
        // Bad prefixes / truncation do not parse.
        assert!(parse_refusal_evidence(b"SHORT").is_none());
        let mut bad_prefix = err.clone();
        bad_prefix[0] ^= 0xFF;
        assert!(parse_refusal_evidence(&bad_prefix).is_none());
        // The first signature still verifies; the counter did not move.
        assert_eq!(v.next_leaf(), 1);
        assert_eq!(v.first_seed(0), Some(b"first".as_slice()));
        let _ = y0;
        // A future epoch is refused as out-of-order (no silent leaf burn)...
        let err = v.sign(3, b"skip").unwrap_err();
        assert!(matches!(
            err,
            XmssError::UnexpectedEpoch {
                expected: 1,
                got: 3
            }
        ));
        // ...but the next leaf still signs fine.
        let (y1, sig1) = v.sign(1, b"second-epoch").unwrap();
        assert!(v.verify(1, b"second-epoch", &y1, &sig1));
    }

    #[test]
    fn equivocation_proof_shape_and_negative_cases() {
        // Two instances, one master: the only way to hold two valid sigs on
        // one leaf (the API refuses the second) — i.e. the burn case.
        let mut a = XmssVrf::new([21u8; 32], 3).unwrap();
        let mut b = XmssVrf::new([21u8; 32], 3).unwrap();
        let (_, sig_a) = a.sign(0, b"seed-A").unwrap();
        let (_, sig_b) = b.sign(0, b"seed-B").unwrap();
        assert_ne!(sig_a.to_bytes(), sig_b.to_bytes());
        let root = a.root();
        let ev = verify_equivocation(
            &root,
            3,
            0,
            b"seed-A",
            &sig_a.to_bytes(),
            b"seed-B",
            &sig_b.to_bytes(),
        )
        .expect("two valid same-leaf sigs are an equivocation proof");
        let parsed = parse_equivocation_evidence(&ev).expect("proof must parse");
        assert_eq!(parsed.root, root);
        assert_eq!(parsed.epoch, 0);
        assert_eq!(parsed.seed_a, b"seed-A");
        assert_eq!(parsed.seed_b, b"seed-B");
        assert_eq!(parsed.sig_a, sig_a.to_bytes());
        assert_eq!(parsed.sig_b, sig_b.to_bytes());
        // Negative cases: same seed, swapped epoch, garbage sig, truncation.
        assert!(verify_equivocation(&root, 3, 0, b"s", &sig_a.to_bytes(), b"s", &sig_b.to_bytes())
            .is_none());
        assert!(verify_equivocation(
            &root,
            3,
            1,
            b"seed-A",
            &sig_a.to_bytes(),
            b"seed-B",
            &sig_b.to_bytes()
        )
        .is_none());
        assert!(verify_equivocation(&root, 3, 0, b"seed-A", b"junk", b"seed-B", &sig_b.to_bytes())
            .is_none());
        let mut truncated = ev.clone();
        truncated.pop();
        assert!(parse_equivocation_evidence(&truncated).is_none());
        let mut padded = ev.clone();
        padded.push(0);
        assert!(parse_equivocation_evidence(&padded).is_none());
    }

    #[test]
    fn persistence_roundtrip_in_temp_dirs() {
        let dir = temp_dir("persist");
        let path = dir.join("counter.bin");
        let mut v = XmssVrf::new([31u8; 32], 3).unwrap();
        let _ = v.sign(0, b"s0").unwrap();
        let _ = v.sign(1, b"s1").unwrap();
        v.save_counter(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "counter file must be owner-only, got {mode:o}");
        }
        let snap = load_counter(&path).unwrap();
        assert_eq!(snap.height, 3);
        assert_eq!(snap.next_leaf, 2);
        assert_eq!(snap.root, v.root());
        // Reopen restores the counter: old leaves refused, next leaf signs.
        let mut reopened = XmssVrf::open([31u8; 32], &path).unwrap();
        assert_eq!(reopened.next_leaf(), 2);
        assert!(matches!(
            reopened.sign(0, b"s0-again"),
            Err(XmssError::LeafReuse { .. })
        ));
        let (y, sig) = reopened.sign(2, b"s2").unwrap();
        assert!(reopened.verify(2, b"s2", &y, &sig));
        // A counter file for another key is refused on open (root mismatch).
        assert!(matches!(
            XmssVrf::open([99u8; 32], &path),
            Err(XmssError::Corrupt(_))
        ));
        // Corrupt bytes (bad magic / length / range) fail closed.
        let mut bad = std::fs::read(&path).unwrap();
        bad[0] ^= 0xFF;
        std::fs::write(&path, &bad).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(load_counter(&path), Err(XmssError::Corrupt(_))));
        assert!(std::fs::remove_dir_all(&dir).is_ok());
    }

    #[test]
    fn leaf_exhaustion_is_fail_closed() {
        assert!(XmssVrf::new([1u8; 32], 0).is_err());
        assert!(XmssVrf::new([1u8; 32], MAX_HEIGHT + 1).is_err());
        let mut v = XmssVrf::new([41u8; 32], 2).unwrap();
        assert_eq!(v.capacity(), 4);
        for epoch in 0..4u64 {
            let seed = format!("e{epoch}");
            let (y, sig) = v.sign(epoch, seed.as_bytes()).unwrap();
            assert!(v.verify(epoch, seed.as_bytes(), &y, &sig));
        }
        // Key fully used: any further epoch (in-range or not) is Exhausted.
        assert!(matches!(
            v.sign(4, b"late"),
            Err(XmssError::Exhausted { .. })
        ));
        assert!(matches!(
            v.sign(0, b"again"),
            Err(XmssError::Exhausted { .. })
        ));
        // Exhaustion survives a save/load round-trip.
        let dir = temp_dir("exhaust");
        let path = dir.join("counter.bin");
        v.save_counter(&path).unwrap();
        let mut reopened = XmssVrf::open([41u8; 32], &path).unwrap();
        assert!(matches!(
            reopened.sign(4, b"late"),
            Err(XmssError::Exhausted { .. })
        ));
        assert!(std::fs::remove_dir_all(&dir).is_ok());
    }

    #[test]
    fn insecure_counter_file_mode_is_refused() {
        let dir = temp_dir("perms");
        let path = dir.join("counter.bin");
        let v = XmssVrf::new([51u8; 32], 2).unwrap();
        v.save_counter(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let err = load_counter(&path).unwrap_err();
            assert!(
                matches!(err, XmssError::Io(_)) && format!("{err}").contains("0o600"),
                "world-readable counter must be refused, got: {err}"
            );
        }
        assert!(std::fs::remove_dir_all(&dir).is_ok());
    }
}
