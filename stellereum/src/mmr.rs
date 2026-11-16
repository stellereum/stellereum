//! Merkle Mountain Range (MMR) over finalized block hashes — the V5 Tier-2
//! promise, shipped.
//!
//! The V5 master spec (`docs/handoff/STELLEREUM_PQ_BFT_V5_MASTER_SPEC.txt`
//! §3.2) promises that "every 128 blocks (an epoch) the full validator set
//! signs a Merkle Mountain Range (MMR) epoch root". Until this module, no
//! MMR existed anywhere in the codebase: Tier-2 finality ran purely on
//! precommit-QC checkpoints (`precommit_qc`, `stell_getFinalizedCheckpoint`).
//! This module closes that gap: a minimal, deterministic MMR over finalized
//! block hashes, committed every 128 blocks into the masterchain block
//! (`Block::mmr_epoch_root`), served over RPC (`stell_getEpochRoot`) and
//! verifiable by light clients (`crate::light_client`).
//!
//! # What the MMR proves (and what it does NOT)
//!
//! * PROVES: that a block hash at height H belongs to the finalized chain of
//!   epoch E — inclusion of a finalized leaf under the epoch root the quorum
//!   signed. A bridge or a cross-chain transfer can therefore anchor on ONE
//!   32-byte epoch root instead of 128 individual checkpoints.
//! * DOES NOT prove finality by itself: the root is only as trustworthy as
//!   the quorum signatures over the block hash that carries it. A root from
//!   an unverified block is trust-in-the-serving-node (the same caveat as
//!   `light_client::verify_epoch_key_against_block`).
//! * DOES NOT replace QC checkpoints: finality evidence stays the precommit
//!   QC (`precommit_qc`, `stell_getFinalizedCheckpoint`, sync). The MMR is an
//!   inclusion commitment *under* finality, not a finality mechanism.
//!
//! # `no_std` compatibility
//!
//! The logic below uses only `core`/`alloc`-level APIs (`Vec`, slices,
//! integer arithmetic) plus `sha2` and `serde` — no threads, no time, no
//! filesystem, no environment. It compiles under `no_std + alloc`
//! unchanged.
//!
//! # Determinism
//!
//! Leaf, node and bag hashes are domain-separated SHA-256 with fixed layouts,
//! peaks are listed left-to-right, siblings carry an explicit direction bit,
//! and the bag commits to the peak count. There is exactly one valid proof
//! per (leaf, tree size).
//!
//! # Multiproof validity bound (FIXES.md §2.11)
//!
//! The compact multiproof ([`MmrMultiproof`], via [`Mmr::prove_multi`]) is
//! valid ONLY when all `q` leaves lie within ONE mountain (one perfect
//! subtree): the shared-path compression formula holds there. A set spanning
//! several peaks has NO shared path to compress — its cost is `q·|π|`, i.e.
//! one single proof per leaf (see [`Mmr::prove_many`]). The compact
//! constructor enforces this fail-closed: a mixed-peak set is refused with
//! [`MmrMultiproofError::MixedPeaks`], never silently proven.
//!
//! # Hash strength (FIXES.md §1.3, notes only — NOT a migration)
//!
//! The MMR still commits with 256-bit SHA-256 (history compat: block/state
//! roots are fork-level frozen, so the hash function does NOT change here).
//! Documented strength of the 256-bit roots, quantum model:
//! collision `λ = n_h/3 ≈ 85.3`; second-preimage `λ = n_h/2 − h/2`
//! (classical: `n_h − h`), i.e. 118 bits at MMR depth `h=20` and 96 bits at
//! `h=64` (pinned by [`MMR_SECOND_PREIMAGE_BITS_QUANTUM_H20`]/
//! [`MMR_SECOND_PREIMAGE_BITS_QUANTUM_H64`]). A 128-bit collision-resistance
//! target needs a 384-bit hash; a 128-bit second-preimage target at depth
//! 256 needs 512 bits. Migrating roots to 384+ bits is a separate
//! wire/state project, and is explicitly NOT done by this module.
//!
//! # Size rows (FIXES.md §2.6/§3.4, pins only)
//!
//! The QC/checkpoint byte rows are pinned as consts for auditability
//! ([`QC_BYTES_K128`], [`CHECKPOINT_BYTES_K128_H20`], [`qc_bytes`],
//! [`checkpoint_bytes_h20`]); the single-proof hash bound
//! `|π| ≤ floor(log2 n) + popcount(n) − 1` is pinned by
//! [`max_proof_hashes`]. These pins change nothing on the wire.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Blocks per MMR epoch. Identical to the MEV epoch length: one MMR root
/// per MEV epoch, committed by the first masterchain block of the NEXT
/// epoch (see [`commits_epoch_root`]).
///
/// FREEZE (protocol freeze 2026-11-03): 128 blocks per epoch, == MEV
/// EPOCH_BLOCKS (compile-asserted below). Change requires spec update +
/// audit note (AGENTS.md §7).
pub const MMR_EPOCH_BLOCKS: u64 = 128;

// The MMR epoch and the MEV epoch must stay the same epoch: the RPC answer,
// the light-client helper and the block commitment all index epochs by
// `height / 128`, and two different divisors would name two different
// epochs "epoch E".
const _: () = assert!(MMR_EPOCH_BLOCKS == crate::mev_epoch::EPOCH_BLOCKS);

/// Domain separator of a leaf hash: `H(LEAF || block_hash)`.
pub const MMR_LEAF_DOMAIN: &[u8] = b"STELL_MMR_LEAF_V1";
/// Domain separator of an interior node: `H(NODE || left || right)`.
pub const MMR_NODE_DOMAIN: &[u8] = b"STELL_MMR_NODE_V1";
/// Domain separator of the peak bag (the epoch root):
/// `H(BAG || num_peaks u32 BE || peak_0 || ...)`.
pub const MMR_BAG_DOMAIN: &[u8] = b"STELL_MMR_BAG_V1";

/// FIXES.md §1.3 pin: the MMR commits with 256-bit SHA-256. Documented here
/// so the strength notes below stay tied to the hash they describe; changing
/// this number is a fork-level migration (wire/state), NOT a one-file edit.
pub const MMR_HASH_BITS: u32 = 256;

/// FIXES.md §1.3 pin: quantum second-preimage bits of a 256-bit root at
/// depth `h=20` — `n_h/2 − h/2 = 128 − 10 = 118`.
pub const MMR_SECOND_PREIMAGE_BITS_QUANTUM_H20: u32 = 118;

/// FIXES.md §1.3 pin: quantum second-preimage bits of a 256-bit root at
/// depth `h=64` — `n_h/2 − h/2 = 128 − 32 = 96`.
pub const MMR_SECOND_PREIMAGE_BITS_QUANTUM_H64: u32 = 96;

/// FIXES.md §2.6/§3.4 pin: Falcon-512 signature bytes per signer in the QC
/// size row (`666 B` per signature plus one bitmap bit per signer).
pub const FALCON512_SIG_BYTES: u64 = 666;

/// FIXES.md §2.6 pin: threshold-signature bytes assumed by the `k=128`
/// checkpoint row (`3309 B`).
pub const CHECKPOINT_TS_SIG_BYTES: u64 = 3_309;

/// FIXES.md §3.4 row: QC bytes at `k=128` — `666·128 + ceil(128/8) = 85 264`.
pub const QC_BYTES_K128: u64 = 85_264;

/// FIXES.md §2.6/§3.4 row: checkpoint bytes at `k=128, h=20` —
/// `3309 + 20·32 + ceil(128/8) = 3 965`.
pub const CHECKPOINT_BYTES_K128_H20: u64 = 3_965;

/// FIXES.md §2.6/§3.4: QC bytes for committee size `k` —
/// `|QC| = 666·k + ceil(k/8)` (Falcon-512 + bitmap).
pub const fn qc_bytes(k: u64) -> u64 {
    k.saturating_mul(FALCON512_SIG_BYTES)
        .saturating_add(k.div_ceil(8))
}

/// FIXES.md §2.6: checkpoint bytes for committee size `k` at depth `h=20` —
/// `|checkpoint| = |TS_sig| + h·32 + ceil(k/8)` with `|TS_sig| = 3309`.
pub const fn checkpoint_bytes_h20(k: u64) -> u64 {
    CHECKPOINT_TS_SIG_BYTES
        .saturating_add(20 * 32)
        .saturating_add(k.div_ceil(8))
}

/// FIXES.md §2.11 pin: the single-proof hash bound
/// `|π| ≤ floor(log2 n) + popcount(n) − 1`.
///
/// `|π|` counts the proof hashes besides the leaf itself and its own
/// (recomputed) peak: the sibling path plus the FOREIGN peaks
/// (`siblings.len() + peaks.len() − 1`). The maximum is attained by a leaf
/// in the largest mountain; `n = 0` and `n = 1` carry no hashes.
pub const fn max_proof_hashes(n: u64) -> u64 {
    if n <= 1 {
        return 0;
    }
    (63 - n.leading_zeros()) as u64 + n.count_ones() as u64 - 1
}

/// The MMR epoch a height belongs to.
#[inline]
pub fn epoch_of_height(height: u64) -> u64 {
    height / MMR_EPOCH_BLOCKS
}

/// First height of epoch `epoch`.
#[inline]
pub fn epoch_start(epoch: u64) -> u64 {
    epoch.saturating_mul(MMR_EPOCH_BLOCKS)
}

/// Last height of epoch `epoch`.
#[inline]
pub fn epoch_end(epoch: u64) -> u64 {
    epoch
        .saturating_mul(MMR_EPOCH_BLOCKS)
        .saturating_add(MMR_EPOCH_BLOCKS - 1)
}

/// Which epoch's root the block at `height` commits to, if any.
///
/// The FIRST masterchain block of epoch E (height E*128, height > 0)
/// commits the MMR root of epoch E-1 — the previous epoch, whose 128
/// finalized hashes already exist. Committing the *previous* epoch is what
/// keeps the commitment non-circular: a block never commits to a root that
/// includes its own hash. Every other height commits to nothing (zero).
pub fn commits_epoch_root(height: u64) -> Option<u64> {
    if height > 0 && height.is_multiple_of(MMR_EPOCH_BLOCKS) {
        Some(height / MMR_EPOCH_BLOCKS - 1)
    } else {
        None
    }
}

/// Hash of one leaf (a finalized block hash) in the tree.
pub fn leaf_hash(leaf: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MMR_LEAF_DOMAIN);
    h.update(leaf);
    h.finalize().into()
}

/// Hash of one interior node.
pub fn parent_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MMR_NODE_DOMAIN);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Bag a peak list into the single epoch root.
///
/// The peak count is committed explicitly so a one-peak tree and a bare
/// peak hash can never coincide, and two peak lists of different lengths
/// can never bag to the same root. The empty tree bags to the all-zero
/// root — the same "no commitment" sentinel the block hash uses.
pub fn bag_peaks(peaks: &[[u8; 32]]) -> [u8; 32] {
    if peaks.is_empty() {
        return [0u8; 32];
    }
    let mut h = Sha256::new();
    h.update(MMR_BAG_DOMAIN);
    h.update((peaks.len() as u32).to_be_bytes());
    for p in peaks {
        h.update(p);
    }
    h.finalize().into()
}

/// The Merkle root of a power-of-two leaf chunk (one mountain).
fn chunk_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    debug_assert!(
        leaves.len().is_power_of_two(),
        "a mountain always covers a power-of-two leaf count"
    );
    if leaves.len() == 1 {
        return leaf_hash(&leaves[0]);
    }
    let mid = leaves.len() / 2;
    let left = chunk_root(&leaves[..mid]);
    let right = chunk_root(&leaves[mid..]);
    parent_hash(&left, &right)
}

/// Split `n` leaves into mountains: `(offset, size)` left-to-right, each
/// size a power of two, sizes strictly decreasing (the classic MMR
/// decomposition by descending set bits).
fn mountain_ranges(n: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut offset = 0u64;
    let mut remaining = n;
    while remaining > 0 {
        // Largest power of two <= remaining.
        let size = 1u64 << (63 - remaining.leading_zeros());
        out.push((offset, size));
        offset += size;
        remaining -= size;
    }
    out
}

/// An MMR over finalized block hashes: append-only, deterministic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mmr {
    leaves: Vec<[u8; 32]>,
}

impl Mmr {
    /// An empty MMR (root is the all-zero "no commitment" sentinel).
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Build an MMR over a fixed leaf set.
    pub fn of(leaves: &[[u8; 32]]) -> Self {
        Self {
            leaves: leaves.to_vec(),
        }
    }

    /// Append one finalized block hash.
    pub fn push(&mut self, leaf: [u8; 32]) {
        self.leaves.push(leaf);
    }

    /// How many leaves are committed.
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// True when nothing is committed.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The mountain peaks, left-to-right.
    pub fn peaks(&self) -> Vec<[u8; 32]> {
        mountain_ranges(self.len())
            .into_iter()
            .map(|(off, size)| {
                let (o, s) = (off as usize, size as usize);
                chunk_root(&self.leaves[o..o + s])
            })
            .collect()
    }

    /// The epoch root: the bag of the peaks (`[0; 32]` when empty).
    pub fn root(&self) -> [u8; 32] {
        bag_peaks(&self.peaks())
    }

    /// Prove inclusion of the leaf at `leaf_index`.
    ///
    /// `None` when the index is out of range. The proof carries the
    /// sibling path up to the leaf's mountain peak plus every peak, so a
    /// verifier needs nothing but the proof and the trusted root.
    pub fn prove(&self, leaf_index: u64) -> Option<MmrProof> {
        let n = self.len();
        if leaf_index >= n {
            return None;
        }
        let peaks = self.peaks();
        let ranges = mountain_ranges(n);
        for (peak_index, (off, size)) in ranges.iter().enumerate() {
            if leaf_index < *off || leaf_index >= off + size {
                continue;
            }
            let mut siblings = Vec::new();
            let mut lo = *off;
            let mut hi = off + size;
            let idx = leaf_index;
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                if idx < mid {
                    let (m, h) = (mid as usize, hi as usize);
                    siblings.push(MmrSibling {
                        hash: chunk_root(&self.leaves[m..h]),
                        sibling_is_left: false,
                    });
                    hi = mid;
                } else {
                    let (l, m) = (lo as usize, mid as usize);
                    siblings.push(MmrSibling {
                        hash: chunk_root(&self.leaves[l..m]),
                        sibling_is_left: true,
                    });
                    lo = mid;
                }
            }
            // CODE FIX (A9): the descent above pushes the TOP sibling first,
            // but the documented contract (`MmrProof::siblings`: "leaf first")
            // and `verify`'s leaf-first consumption require the leaf-level
            // sibling first. Without this reversal every proof over a
            // mountain of 4+ leaves failed verification (proven by
            // `mmr_append_1_to_129_and_prove_every_leaf`,
            // `mmr_128_boundary_is_a_single_peak`, `mmr_tampered_proof_refuses`).
            siblings.reverse();
            return Some(MmrProof {
                leaf_index,
                leaf: self.leaves[leaf_index as usize],
                siblings,
                peaks,
                peak_index,
                num_leaves: n,
            });
        }
        None
    }
}

/// One step of an inclusion path: the sibling hash and which side it is on.
///
/// The direction bit is explicit (not positional) so a proof with a flipped
/// step fails instead of verifying a different leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrSibling {
    /// The sibling subtree hash.
    pub hash: [u8; 32],
    /// True when the sibling is LEFT of the running hash.
    pub sibling_is_left: bool,
}

/// An inclusion proof for one finalized block hash under an epoch root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrProof {
    /// Index of the proven leaf (the height's offset inside the epoch).
    pub leaf_index: u64,
    /// The proven leaf (the finalized block hash).
    pub leaf: [u8; 32],
    /// The sibling path from the leaf up to its mountain peak (leaf first).
    pub siblings: Vec<MmrSibling>,
    /// Every peak of the tree at proof time, left-to-right.
    pub peaks: Vec<[u8; 32]>,
    /// Which peak is the leaf's mountain.
    pub peak_index: usize,
    /// How many leaves the tree held at proof time.
    pub num_leaves: u64,
}

impl MmrProof {
    /// Verify this proof against a trusted epoch `root`.
    ///
    /// Refuses (returns `false`, never panics) on every malformed proof:
    /// out-of-range index, wrong sibling count, flipped direction bits, a
    /// peak that does not recompute, or a bag that does not match the root.
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        if self.num_leaves == 0 || self.peaks.is_empty() {
            return false;
        }
        if self.peak_index >= self.peaks.len() {
            return false;
        }
        let ranges = mountain_ranges(self.num_leaves);
        if ranges.len() != self.peaks.len() || self.peak_index >= ranges.len() {
            return false;
        }
        let (off, size) = ranges[self.peak_index];
        if self.leaf_index < off || self.leaf_index >= off + size {
            return false;
        }
        if size == 0 || !size.is_power_of_two() {
            return false;
        }
        // A mountain of `size` leaves has exactly log2(size) path steps.
        if self.siblings.len() != size.trailing_zeros() as usize {
            return false;
        }
        let mut cur = leaf_hash(&self.leaf);
        let mut lo = off;
        let mut hi = off + size;
        let idx = self.leaf_index;
        // Siblings are stored leaf-first (nearest first), so they are folded
        // in vector order, driven SOLELY by their direction bits: at each
        // step the running hash sits on the side the bit names. The range
        // walk below only tracks depth (it must end exactly on the leaf);
        // re-deriving the EXPECTED side from the range here would be wrong —
        // the first-consumed sibling belongs to the DEEPEST level, while the
        // range starts at the WIDEST. A flipped direction bit still refuses:
        // it folds a different parent, and the peak comparison below fails.
        for s in &self.siblings {
            if hi - lo < 2 {
                return false;
            }
            let mid = lo + (hi - lo) / 2;
            if s.sibling_is_left {
                cur = parent_hash(&s.hash, &cur);
            } else {
                cur = parent_hash(&cur, &s.hash);
            }
            if idx < mid {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        if lo != idx || hi != idx + 1 {
            return false;
        }
        if cur != self.peaks[self.peak_index] {
            return false;
        }
        bag_peaks(&self.peaks) == *root
    }
}

/// One helper node of a compact multiproof: the hash of the leaf range
/// `[offset, offset + size)` — a subtree containing NONE of the proven
/// leaves, so the verifier can fold it in as-is while rebuilding the peak.
///
/// `size` is always a power of two and the range is always aligned to it
/// (`(offset − mountain_start) % size == 0`); the prover emits the maximal
/// frontier (a helper's parent always covers a proven leaf) left-to-right,
/// and the verifier refuses anything else, fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrHelper {
    /// First leaf index covered by this helper.
    pub offset: u64,
    /// Leaf count covered (a power of two).
    pub size: u64,
    /// `chunk_root` over the covered leaves.
    pub hash: [u8; 32],
}

/// A compact multiproof for `q` leaves of ONE mountain (FIXES.md §2.11).
///
/// Carries the `q` leaves plus the minimal helper frontier needed to rebuild
/// their mountain peak — the shared-path compression, which is valid ONLY
/// inside one perfect subtree. A set spanning several peaks has no shared
/// path: use [`Mmr::prove_many`] (the `q·|π|` form) for those sets instead;
/// [`Mmr::prove_multi`] refuses them fail-closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrMultiproof {
    /// Proven leaf indices, strictly increasing, all in one mountain.
    pub leaf_indices: Vec<u64>,
    /// Proven leaves (the finalized block hashes), same order as
    /// `leaf_indices`.
    pub leaves: Vec<[u8; 32]>,
    /// The maximal helper frontier over the leaf complement,
    /// left-to-right (canonical form — see [`MmrHelper`]).
    pub helpers: Vec<MmrHelper>,
    /// Every peak of the tree at proof time, left-to-right.
    pub peaks: Vec<[u8; 32]>,
    /// Which peak is the leaves' mountain.
    pub peak_index: usize,
    /// How many leaves the tree held at proof time.
    pub num_leaves: u64,
}

/// Why a compact multiproof was refused. Fail-closed by construction:
/// [`Mmr::prove_multi`] returns one of these instead of a proof that the
/// validity bound does not cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmrMultiproofError {
    /// No leaves were requested — a multiproof proves at least one leaf.
    EmptySet,
    /// `index` is outside the tree (`index >= num_leaves`).
    OutOfRange {
        /// The offending index.
        index: u64,
        /// How many leaves the tree holds.
        num_leaves: u64,
    },
    /// `index` was requested twice.
    Duplicate {
        /// The repeated index.
        index: u64,
    },
    /// The set spans more than one mountain. The compact formula is valid
    /// only inside one perfect subtree; prove the set with
    /// [`Mmr::prove_many`] (the `q·|π|` form) instead.
    MixedPeaks,
}

impl core::fmt::Display for MmrMultiproofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::EmptySet => write!(f, "multiproof needs at least one leaf index"),
            Self::OutOfRange { index, num_leaves } => write!(
                f,
                "multiproof index {index} out of range (tree holds {num_leaves} leaves)"
            ),
            Self::Duplicate { index } => {
                write!(f, "multiproof index {index} requested twice")
            }
            Self::MixedPeaks => write!(
                f,
                "multiproof spans several peaks; the compact form is valid only \
                 inside one perfect subtree — use one single proof per leaf \
                 (the q·|π| form)"
            ),
        }
    }
}

impl Mmr {
    /// Prove `q` leaves with one compact multiproof (FIXES.md §2.11).
    ///
    /// Valid ONLY when every requested index lies in the SAME mountain (one
    /// perfect subtree) — the shared-path compression formula holds there.
    /// Anything else is refused fail-closed: empty sets, out-of-range
    /// indices, duplicates, and (the bound itself) mixed-peak sets. For a
    /// cross-peak set use [`Mmr::prove_many`], whose `q` single proofs are
    /// the documented `q·|π|` form.
    ///
    /// The returned proof is canonical: indices sorted strictly increasing,
    /// helpers the maximal left-to-right frontier.
    pub fn prove_multi(&self, indices: &[u64]) -> Result<MmrMultiproof, MmrMultiproofError> {
        if indices.is_empty() {
            return Err(MmrMultiproofError::EmptySet);
        }
        let n = self.len();
        for &i in indices {
            if i >= n {
                return Err(MmrMultiproofError::OutOfRange {
                    index: i,
                    num_leaves: n,
                });
            }
        }
        let mut sorted = indices.to_vec();
        sorted.sort_unstable();
        for w in sorted.windows(2) {
            if w[0] == w[1] {
                return Err(MmrMultiproofError::Duplicate { index: w[0] });
            }
        }
        let ranges = mountain_ranges(n);
        let (peak_index, (off, size)) = ranges
            .iter()
            .enumerate()
            .find(|(_, (off, size))| sorted[0] >= *off && sorted[0] < off + size)
            .map(|(pi, r)| (pi, *r))
            .unwrap_or((0, (0, 0)));
        if size == 0 || sorted[sorted.len() - 1] >= off + size {
            return Err(MmrMultiproofError::MixedPeaks);
        }
        let mut helpers = Vec::new();
        collect_helpers(&self.leaves, off, off + size, &sorted, &mut helpers);
        // `collect_helpers` meets the right (wanted-free) subtrees first;
        // the canonical frontier is left-to-right (disjoint ranges, so the
        // sort is total), matching what `verify` and `rebuild_peak` consume.
        helpers.sort_by_key(|h| h.offset);
        let leaves = sorted.iter().map(|&i| self.leaves[i as usize]).collect();
        Ok(MmrMultiproof {
            leaf_indices: sorted,
            leaves,
            helpers,
            peaks: self.peaks(),
            peak_index,
            num_leaves: n,
        })
    }

    /// Prove each index separately: the `q·|π|` form (FIXES.md §2.11).
    ///
    /// This is the correct multiproof for a set spanning several peaks
    /// (where the compact formula does NOT hold) — and a valid, merely
    /// larger, proof for any set. `None` when any index is out of range.
    pub fn prove_many(&self, indices: &[u64]) -> Option<Vec<MmrProof>> {
        indices.iter().map(|&i| self.prove(i)).collect()
    }
}

/// Push the maximal helper frontier of `wanted` (sorted, inside
/// `[lo, hi)`) onto `out`, left-to-right: every maximal sub-range covering
/// no wanted leaf contributes its `chunk_root`; wanted leaves contribute
/// nothing.
fn collect_helpers(
    leaves: &[[u8; 32]],
    lo: u64,
    hi: u64,
    wanted: &[u64],
    out: &mut Vec<MmrHelper>,
) {
    let lo_pos = wanted.partition_point(|&i| i < lo);
    let hi_pos = wanted.partition_point(|&i| i < hi);
    if lo_pos == hi_pos {
        out.push(MmrHelper {
            offset: lo,
            size: hi - lo,
            hash: chunk_root(&leaves[lo as usize..hi as usize]),
        });
    } else if hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        collect_helpers(leaves, lo, mid, wanted, out);
        collect_helpers(leaves, mid, hi, wanted, out);
    }
    // Else: `hi - lo == 1` with a wanted leaf — no helper to store.
}

impl MmrMultiproof {
    /// Verify this multiproof against a trusted epoch `root`.
    ///
    /// Refuses (returns `false`, never panics) every malformed proof:
    /// empty or unordered index sets, leaves escaping their mountain,
    /// non-canonical helpers (misaligned, overlapping, gapped, or hiding a
    /// wanted leaf), a peak that does not rebuild, or a bag that does not
    /// match the root. Helpers are untrusted inputs pinned by
    /// `(offset, size, hash)` — a forged helper rebuilds a different peak
    /// and fails the peak comparison (same trust model as the siblings of
    /// [`MmrProof::verify`]).
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        if self.num_leaves == 0 || self.peaks.is_empty() {
            return false;
        }
        if self.peak_index >= self.peaks.len() {
            return false;
        }
        let ranges = mountain_ranges(self.num_leaves);
        if ranges.len() != self.peaks.len() || self.peak_index >= ranges.len() {
            return false;
        }
        let (off, size) = ranges[self.peak_index];
        if size == 0 || !size.is_power_of_two() {
            return false;
        }
        let q = self.leaf_indices.len();
        if q == 0 || self.leaves.len() != q {
            return false;
        }
        for (k, &idx) in self.leaf_indices.iter().enumerate() {
            if idx < off || idx >= off + size {
                return false;
            }
            if k > 0 && self.leaf_indices[k - 1] >= idx {
                return false;
            }
        }
        // Helpers: canonical maximal frontier — inside the mountain,
        // power-of-two aligned, strictly increasing, disjoint.
        let mut prev_end: Option<u64> = None;
        let mut covered: u64 = 0;
        for h in &self.helpers {
            if h.size == 0 || !h.size.is_power_of_two() {
                return false;
            }
            if h.offset < off {
                return false;
            }
            let rel = h.offset - off;
            if rel % h.size != 0 {
                return false;
            }
            let end = match h.offset.checked_add(h.size) {
                Some(end) if end <= off + size => end,
                _ => return false,
            };
            if let Some(prev) = prev_end {
                if h.offset < prev {
                    return false;
                }
            }
            prev_end = Some(end);
            match covered.checked_add(h.size) {
                Some(next) => covered = next,
                None => return false,
            }
        }
        // Exact partition: helpers plus the `q` wanted singletons tile the
        // mountain, and no wanted leaf hides inside a helper range.
        match covered.checked_add(q as u64) {
            Some(total) if total == size => {}
            _ => return false,
        }
        {
            let mut hi = 0usize;
            for h in &self.helpers {
                while hi < q && self.leaf_indices[hi] < h.offset {
                    hi += 1;
                }
                if hi < q {
                    let end = h.offset + h.size;
                    if self.leaf_indices[hi] >= h.offset && self.leaf_indices[hi] < end {
                        return false;
                    }
                }
            }
        }
        // Rebuild the peak from the leaves plus the frontier.
        let mut consumed = 0usize;
        let rebuilt = match rebuild_peak(
            &self.leaf_indices,
            &self.leaves,
            &self.helpers,
            &mut consumed,
            off,
            off + size,
        ) {
            Some(hash) => hash,
            None => return false,
        };
        if consumed != self.helpers.len() {
            return false;
        }
        if rebuilt != self.peaks[self.peak_index] {
            return false;
        }
        bag_peaks(&self.peaks) == *root
    }
}

/// Rebuild the peak over `[lo, hi)` from the wanted `leaves` plus the
/// canonical `helpers` frontier, consuming helpers in order. `None` on any
/// deviation from the canonical shape (fail-closed).
fn rebuild_peak(
    wanted: &[u64],
    leaves: &[[u8; 32]],
    helpers: &[MmrHelper],
    consumed: &mut usize,
    lo: u64,
    hi: u64,
) -> Option<[u8; 32]> {
    let lo_pos = wanted.partition_point(|&i| i < lo);
    let hi_pos = wanted.partition_point(|&i| i < hi);
    if lo_pos == hi_pos {
        // A wanted-free range folds in as one helper (singletons included:
        // a helper-covered leaf contributes its subtree hash, not itself).
        let h = helpers.get(*consumed)?;
        if h.offset == lo && h.size == hi - lo {
            *consumed += 1;
            return Some(h.hash);
        }
        return None;
    }
    if hi - lo == 1 {
        if wanted.binary_search(&lo).is_ok() {
            let pos = wanted.partition_point(|&i| i < lo);
            return Some(leaf_hash(&leaves[pos]));
        }
        return None;
    }
    let mid = lo + (hi - lo) / 2;
    let left = rebuild_peak(wanted, leaves, helpers, consumed, lo, mid)?;
    let right = rebuild_peak(wanted, leaves, helpers, consumed, mid, hi)?;
    Some(parent_hash(&left, &right))
}

/// The epoch root and peaks for a fixed leaf set.
///
/// Convenience for the block commitment, the RPC layer and the tests: one
/// call, no retained state.
pub fn mmr_root_for_leaves(leaves: &[[u8; 32]]) -> ([u8; 32], Vec<[u8; 32]>) {
    let m = Mmr::of(leaves);
    (m.root(), m.peaks())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test leaves: `[i; 32]`-derived, distinct per index.
    fn leaf(i: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&i.to_be_bytes());
        b[8..16].copy_from_slice(&(!i).to_be_bytes());
        b
    }

    #[test]
    fn mmr_empty_root_is_zero_and_prove_refuses() {
        let m = Mmr::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
        assert_eq!(m.root(), [0u8; 32]);
        assert!(m.peaks().is_empty());
        assert!(m.prove(0).is_none());
        // A default-constructed proof verifies against nothing.
        let bogus = MmrProof {
            leaf_index: 0,
            leaf: [0u8; 32],
            siblings: vec![],
            peaks: vec![],
            peak_index: 0,
            num_leaves: 0,
        };
        assert!(!bogus.verify(&[0u8; 32]));
    }

    #[test]
    fn mmr_single_leaf_bags_its_peak() {
        let mut m = Mmr::new();
        m.push(leaf(0));
        let peaks = m.peaks();
        assert_eq!(peaks.len(), 1);
        assert_eq!(peaks[0], leaf_hash(&leaf(0)));
        assert_eq!(m.root(), bag_peaks(&peaks));
        assert_ne!(m.root(), [0u8; 32]);
        let p = m.prove(0).expect("the only leaf proves");
        assert!(p.siblings.is_empty());
        assert!(p.verify(&m.root()));
    }

    /// The required sweep: append 1..=129 leaves (across the 128 epoch
    /// boundary) and prove/verify EVERY leaf at EVERY size.
    #[test]
    fn mmr_append_1_to_129_and_prove_every_leaf() {
        let mut m = Mmr::new();
        for n in 1u64..=129 {
            m.push(leaf(n - 1));
            assert_eq!(m.len(), n);
            let root = m.root();
            assert_ne!(root, [0u8; 32]);
            for i in 0..n {
                let proof = m
                    .prove(i)
                    .unwrap_or_else(|| panic!("leaf {i} proves at size {n}"));
                assert_eq!(proof.leaf, leaf(i));
                assert_eq!(proof.num_leaves, n);
                assert!(proof.verify(&root), "leaf {i} verifies at size {n}");
                // A proof for size n must NOT verify against another size's root.
                if n > 1 {
                    let other = Mmr::of(&(0..n - 1).map(leaf).collect::<Vec<_>>()).root();
                    if other != root {
                        assert!(
                            !proof.verify(&other),
                            "leaf {i} must not verify under a foreign root"
                        );
                    }
                }
            }
            assert!(
                m.prove(n).is_none(),
                "index == len is out of range at size {n}"
            );
        }
    }

    #[test]
    fn mmr_128_boundary_is_a_single_peak() {
        let leaves127: Vec<[u8; 32]> = (0..127).map(leaf).collect();
        let leaves128: Vec<[u8; 32]> = (0..128).map(leaf).collect();
        let leaves129: Vec<[u8; 32]> = (0..129).map(leaf).collect();
        // 127 = 64+32+16+8+4+2+1 -> 7 peaks.
        assert_eq!(Mmr::of(&leaves127).peaks().len(), 7);
        // 128 = 2^7 -> exactly one peak: the epoch boundary is clean.
        let m128 = Mmr::of(&leaves128);
        assert_eq!(m128.peaks().len(), 1);
        // 129 = 128+1 -> two peaks.
        assert_eq!(Mmr::of(&leaves129).peaks().len(), 2);
        // Every leaf still proves on both sides of the boundary.
        for (leaves, n) in [(&leaves128, 128u64), (&leaves129, 129u64)] {
            let m = Mmr::of(leaves);
            let root = m.root();
            for i in 0..n {
                assert!(
                    m.prove(i).unwrap().verify(&root),
                    "leaf {i} verifies at size {n}"
                );
            }
        }
    }

    #[test]
    fn mmr_tampered_proof_refuses() {
        let leaves: Vec<[u8; 32]> = (0..130).map(leaf).collect();
        let m = Mmr::of(&leaves);
        let root = m.root();
        // Pick a leaf deep inside the first mountain (multi-step path) and
        // one in the trailing 2-leaf mountain.
        for idx in [0u64, 17, 127, 128, 129] {
            let good = m.prove(idx).expect("in range");
            assert!(good.verify(&root));
            // 1. Tampered leaf.
            let mut bad = good.clone();
            bad.leaf[0] ^= 0xFF;
            assert!(!bad.verify(&root), "tampered leaf refuses (idx {idx})");
            // 2. Tampered sibling (when the path is non-empty).
            if !good.siblings.is_empty() {
                let mut bad = good.clone();
                bad.siblings[0].hash[31] ^= 0x01;
                assert!(!bad.verify(&root), "tampered sibling refuses (idx {idx})");
                // 3. Flipped direction bit.
                let mut bad = good.clone();
                bad.siblings[0].sibling_is_left = !bad.siblings[0].sibling_is_left;
                assert!(!bad.verify(&root), "flipped direction refuses (idx {idx})");
                // 4. Truncated path.
                let mut bad = good.clone();
                bad.siblings.pop();
                assert!(!bad.verify(&root), "truncated path refuses (idx {idx})");
            }
            // 5. Tampered peak list.
            let mut bad = good.clone();
            bad.peaks[bad.peak_index][0] ^= 0x01;
            assert!(!bad.verify(&root), "tampered peak refuses (idx {idx})");
            // 6. Wrong peak index.
            if bad.peaks.len() > 1 {
                let mut bad = good.clone();
                bad.peak_index = (bad.peak_index + 1) % bad.peaks.len();
                assert!(!bad.verify(&root), "wrong peak index refuses (idx {idx})");
            }
            // 7. Wrong root.
            let mut wrong = root;
            wrong[0] ^= 0x01;
            assert!(!good.verify(&wrong), "wrong root refuses (idx {idx})");
            // 8. Wrong tree size.
            let mut bad = good.clone();
            bad.num_leaves += 1;
            assert!(!bad.verify(&root), "wrong size refuses (idx {idx})");
        }
    }

    #[test]
    fn mmr_root_is_deterministic_and_order_sensitive() {
        let a: Vec<[u8; 32]> = (0..64).map(leaf).collect();
        let (r1, p1) = mmr_root_for_leaves(&a);
        let (r2, p2) = mmr_root_for_leaves(&a);
        assert_eq!(r1, r2);
        assert_eq!(p1, p2);
        let mut b = a.clone();
        b.swap(0, 1);
        let (r3, _) = mmr_root_for_leaves(&b);
        assert_ne!(r1, r3, "leaf order moves the root");
    }

    #[test]
    fn mmr_epoch_helpers_name_previous_epoch_at_first_height() {
        assert_eq!(epoch_of_height(0), 0);
        assert_eq!(epoch_of_height(127), 0);
        assert_eq!(epoch_of_height(128), 1);
        assert_eq!(epoch_start(0), 0);
        assert_eq!(epoch_end(0), 127);
        assert_eq!(epoch_start(1), 128);
        assert_eq!(epoch_end(1), 255);
        // Only the first height of an epoch commits, and it commits the
        // PREVIOUS epoch (non-circular).
        assert_eq!(commits_epoch_root(0), None);
        assert_eq!(commits_epoch_root(1), None);
        assert_eq!(commits_epoch_root(127), None);
        assert_eq!(commits_epoch_root(128), Some(0));
        assert_eq!(commits_epoch_root(129), None);
        assert_eq!(commits_epoch_root(256), Some(1));
    }

    /// FIXES.md §2.11: the compact multiproof proves any single-mountain
    /// set — singletons, partial overlaps, and the whole mountain.
    #[test]
    fn mmr_multiproof_single_mountain_happy() {
        // One perfect subtree: 128 leaves, one peak.
        let leaves128: Vec<[u8; 32]> = (0..128).map(leaf).collect();
        let m = Mmr::of(&leaves128);
        let root = m.root();
        for set in [
            vec![0u64],
            vec![127],
            vec![0, 1],
            vec![0, 63, 64, 127],
            (0..128u64).collect::<Vec<_>>(),
            (0..128u64).step_by(7).collect::<Vec<_>>(),
        ] {
            let mp = m.prove_multi(&set).unwrap_or_else(|e| {
                panic!("single-mountain set of {} leaves proves: {e:?}", set.len())
            });
            assert_eq!(mp.leaf_indices.len(), set.len());
            assert!(mp.verify(&root), "multiproof over {set:?} verifies");
            // Canonical form: sorted indices, leaves aligned to them.
            let mut sorted = set.clone();
            sorted.sort_unstable();
            assert_eq!(mp.leaf_indices, sorted);
            for (k, &idx) in mp.leaf_indices.iter().enumerate() {
                assert_eq!(mp.leaves[k], leaf(idx));
            }
            // A full-mountain set needs no helpers; a partial set does.
            if set.len() == 128 {
                assert!(mp.helpers.is_empty(), "full mountain needs no helpers");
            }
            // Compact form never exceeds the q single proofs it replaces
            // (each single carries its leaf plus its whole sibling path).
            let singles = m.prove_many(&set).expect("in range");
            let single_hashes: usize = singles
                .iter()
                .map(|p| 1 + p.siblings.len() + p.peaks.len())
                .sum();
            let multi_hashes = mp.leaves.len() + mp.helpers.len() + mp.peaks.len();
            assert!(
                multi_hashes <= single_hashes,
                "compact multiproof ({multi_hashes} hashes) is no bigger than q singles ({single_hashes})"
            );
        }
        // Shuffled input proves the same canonical proof.
        let a = m.prove_multi(&[3, 1, 2]).expect("in range");
        let b = m.prove_multi(&[1, 2, 3]).expect("in range");
        assert_eq!(a, b, "input order does not move the proof");
        // A trailing partial mountain works too (129 = 128 + 1).
        let leaves129: Vec<[u8; 32]> = (0..129).map(leaf).collect();
        let m129 = Mmr::of(&leaves129);
        let root129 = m129.root();
        let tail = m129.prove_multi(&[128]).expect("singleton proves");
        assert!(tail.verify(&root129));
        assert_eq!(tail.peak_index, 1);
        let head = m129
            .prove_multi(&(0..64u64).step_by(3).collect::<Vec<_>>())
            .expect("first-mountain subset proves");
        assert!(head.verify(&root129));
        assert_eq!(head.peak_index, 0);
    }

    /// FIXES.md §2.11: the compact constructor refuses everything the bound
    /// does not cover — fail-closed, with a distinct clear error each.
    #[test]
    fn mmr_multiproof_constructor_refuses() {
        let leaves: Vec<[u8; 32]> = (0..129).map(leaf).collect();
        let m = Mmr::of(&leaves);
        // Empty set.
        assert_eq!(m.prove_multi(&[]), Err(MmrMultiproofError::EmptySet));
        // Out of range (== len and beyond).
        assert_eq!(
            m.prove_multi(&[129]),
            Err(MmrMultiproofError::OutOfRange {
                index: 129,
                num_leaves: 129
            })
        );
        assert_eq!(
            m.prove_multi(&[0, 10_000]),
            Err(MmrMultiproofError::OutOfRange {
                index: 10_000,
                num_leaves: 129
            })
        );
        // Duplicates.
        assert_eq!(
            m.prove_multi(&[5, 5]),
            Err(MmrMultiproofError::Duplicate { index: 5 })
        );
        assert_eq!(
            m.prove_multi(&[1, 2, 3, 2]),
            Err(MmrMultiproofError::Duplicate { index: 2 })
        );
        // Mixed peaks: 129 = 128 + 1, so 0 and 128 live on different peaks.
        assert_eq!(
            m.prove_multi(&[0, 128]),
            Err(MmrMultiproofError::MixedPeaks)
        );
        assert_eq!(
            m.prove_multi(&[127, 128]),
            Err(MmrMultiproofError::MixedPeaks)
        );
        // Three peaks: 100 = 64 + 32 + 4; one leaf per peak.
        let m100 = Mmr::of(&(0..100).map(leaf).collect::<Vec<_>>());
        assert_eq!(
            m100.prove_multi(&[0, 64, 96]),
            Err(MmrMultiproofError::MixedPeaks)
        );
        // Every error explains itself (rendered without allocation, so the
        // module keeps its `no_std + alloc` shape).
        struct MsgBuf {
            buf: [u8; 256],
            len: usize,
        }
        impl core::fmt::Write for MsgBuf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                if self.len + bytes.len() > self.buf.len() {
                    return Err(core::fmt::Error);
                }
                self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
                self.len += bytes.len();
                Ok(())
            }
        }
        fn err_msg(e: MmrMultiproofError) -> MsgBuf {
            let mut out = MsgBuf {
                buf: [0u8; 256],
                len: 0,
            };
            core::fmt::write(&mut out, format_args!("{e}")).expect("stack buffer fits");
            out
        }
        for e in [
            MmrMultiproofError::EmptySet,
            MmrMultiproofError::OutOfRange {
                index: 9,
                num_leaves: 3,
            },
            MmrMultiproofError::Duplicate { index: 9 },
            MmrMultiproofError::MixedPeaks,
        ] {
            let rendered = err_msg(e);
            let msg = core::str::from_utf8(&rendered.buf[..rendered.len]).expect("UTF-8");
            assert!(!msg.is_empty(), "{e:?} renders a message");
        }
        let rendered = err_msg(MmrMultiproofError::MixedPeaks);
        let msg = core::str::from_utf8(&rendered.buf[..rendered.len]).expect("UTF-8");
        assert!(
            msg.contains("q·|π|"),
            "mixed-peak error names the q·|π| form: {msg}"
        );
    }

    /// FIXES.md §2.11: a tampered multiproof refuses — same fail-closed
    /// bar as the single proofs.
    #[test]
    fn mmr_multiproof_tampered_refuses() {
        let leaves: Vec<[u8; 32]> = (0..128).map(leaf).collect();
        let m = Mmr::of(&leaves);
        let root = m.root();
        let set = vec![0u64, 17, 63, 64, 127];
        let good = m.prove_multi(&set).expect("in range");
        assert!(!good.helpers.is_empty(), "partial set needs helpers");
        assert!(good.verify(&root));
        // 1. Tampered leaf.
        let mut bad = good.clone();
        bad.leaves[0][0] ^= 0xFF;
        assert!(!bad.verify(&root), "tampered leaf refuses");
        // 2. Tampered helper hash.
        let mut bad = good.clone();
        bad.helpers[0].hash[0] ^= 0x01;
        assert!(!bad.verify(&root), "tampered helper refuses");
        // 3. Tampered helper range (same hashes, moved window).
        let mut bad = good.clone();
        let last = bad.helpers.len() - 1;
        bad.helpers.swap(0, last);
        if bad.helpers != good.helpers {
            assert!(!bad.verify(&root), "reordered helpers refuse");
        }
        // 4. Dropped helper.
        let mut bad = good.clone();
        bad.helpers.pop();
        assert!(!bad.verify(&root), "dropped helper refuses");
        // 5. Non-maximal helper: split the first helper wider than one leaf
        //    into its two halves (correct hashes) — refused, the frontier
        //    must be canonical.
        if let Some(h) = good.helpers.iter().find(|h| h.size > 1).copied() {
            let mut bad = good.clone();
            let pos = bad.helpers.iter().position(|x| *x == h).expect("present");
            let half = h.size / 2;
            let left = MmrHelper {
                offset: h.offset,
                size: half,
                hash: chunk_root(&leaves[h.offset as usize..(h.offset + half) as usize]),
            };
            let right = MmrHelper {
                offset: h.offset + half,
                size: half,
                hash: chunk_root(&leaves[(h.offset + half) as usize..(h.offset + h.size) as usize]),
            };
            bad.helpers.splice(pos..pos + 1, [left, right]);
            assert!(!bad.verify(&root), "non-maximal frontier refuses");
        }
        // 6. Unsorted indices.
        let mut bad = good.clone();
        bad.leaf_indices.swap(0, 1);
        assert!(!bad.verify(&root), "unsorted indices refuse");
        // 7. Index escaping the mountain.
        let mut bad = good.clone();
        bad.leaf_indices[0] = 128;
        assert!(!bad.verify(&root), "out-of-mountain index refuses");
        // 8. Tampered peak list / wrong root / wrong size.
        let mut bad = good.clone();
        bad.peaks[bad.peak_index][0] ^= 0x01;
        assert!(!bad.verify(&root), "tampered peak refuses");
        let mut wrong = root;
        wrong[0] ^= 0x01;
        assert!(!good.verify(&wrong), "wrong root refuses");
        let mut bad = good.clone();
        bad.num_leaves += 1;
        assert!(!bad.verify(&root), "wrong size refuses");
        let mut bad = good.clone();
        bad.leaves.pop();
        bad.leaf_indices.pop();
        assert!(!bad.verify(&root), "emptied set refuses");
    }

    /// FIXES.md §2.11: cross-peak sets use the `q·|π|` form — one single
    /// proof per leaf — which verifies end to end.
    #[test]
    fn mmr_multiproof_cross_peak_costs_q_times_pi() {
        let leaves: Vec<[u8; 32]> = (0..129).map(leaf).collect();
        let m = Mmr::of(&leaves);
        let root = m.root();
        // The compact form refuses this set (different peaks)...
        let set = vec![0u64, 128];
        assert_eq!(m.prove_multi(&set), Err(MmrMultiproofError::MixedPeaks));
        // ...while the q·|π| form proves it.
        let proofs = m.prove_many(&set).expect("in range");
        assert_eq!(proofs.len(), 2);
        for p in &proofs {
            assert!(p.verify(&root), "each single proof verifies");
        }
        // Per-proof hash count honours the §2.11 bound, so the bundle is
        // bounded by q·(|π|_max + 1) hashes including the recomputed peaks.
        let bound = max_proof_hashes(129);
        let mut total = 0usize;
        for p in &proofs {
            let pi = p.siblings.len() as u64 + p.peaks.len() as u64 - 1;
            assert!(pi <= bound, "|π| bound holds per proof");
            total += p.siblings.len() + p.peaks.len();
        }
        assert!(total as u64 <= 2 * (bound + 1), "q·|π| form is bounded");
        // Three peaks, one leaf each.
        let m100 = Mmr::of(&(0..100).map(leaf).collect::<Vec<_>>());
        let root100 = m100.root();
        let proofs = m100.prove_many(&[0, 64, 96]).expect("in range");
        assert_eq!(proofs.len(), 3);
        for p in &proofs {
            assert!(p.verify(&root100));
        }
        // Out of range poisons the whole bundle (fail-closed).
        assert!(m.prove_many(&[0, 129]).is_none());
        assert!(m.prove_many(&[]).expect("empty bundle").is_empty());
    }

    /// FIXES.md §2.11: `|π| ≤ floor(log2 n) + popcount(n) − 1` holds for
    /// every single proof, and the maximum is attained.
    #[test]
    fn mmr_single_proof_size_bound_pins_section_2_11() {
        assert_eq!(max_proof_hashes(0), 0);
        assert_eq!(max_proof_hashes(1), 0);
        // 127 = 64+32+16+8+4+2+1: 6 + 7 − 1 = 12.
        assert_eq!(max_proof_hashes(127), 12);
        // 128 = 2^7: 7 + 1 − 1 = 7.
        assert_eq!(max_proof_hashes(128), 7);
        // 129 = 128+1: 7 + 2 − 1 = 8.
        assert_eq!(max_proof_hashes(129), 8);
        for n in [2u64, 3, 64, 100, 255, 256, 257] {
            let expect = (63 - n.leading_zeros()) as u64 + n.count_ones() as u64 - 1;
            assert_eq!(max_proof_hashes(n), expect, "bound formula at n={n}");
        }
        for n in 1u64..=160 {
            let leaves: Vec<[u8; 32]> = (0..n).map(leaf).collect();
            let m = Mmr::of(&leaves);
            let root = m.root();
            let bound = max_proof_hashes(n);
            let mut max_seen = 0u64;
            for i in 0..n {
                let p = m
                    .prove(i)
                    .unwrap_or_else(|| panic!("leaf {i} proves at size {n}"));
                assert!(p.verify(&root));
                let pi = p.siblings.len() as u64 + p.peaks.len() as u64 - 1;
                assert!(
                    pi <= bound,
                    "|π|={pi} exceeds bound {bound} at n={n}, i={i}"
                );
                max_seen = max_seen.max(pi);
            }
            assert_eq!(max_seen, bound, "bound is tight at n={n}");
        }
    }

    /// Differential sweep: on multi-peak trees every mountain's subsets
    /// multiproof-verify, agree with the single proofs leaf-for-leaf, and
    /// mixed-mountain sets refuse.
    #[test]
    fn mmr_multiproof_differential_across_sizes() {
        // Deterministic xorshift — no RNG dependency in the module.
        fn next(state: &mut u64) -> u64 {
            let mut x = *state;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *state = x;
            x
        }
        for n in [
            2u64, 3, 5, 9, 33, 64, 100, 127, 128, 129, 130, 200, 255, 256,
        ] {
            let leaves: Vec<[u8; 32]> = (0..n).map(leaf).collect();
            let m = Mmr::of(&leaves);
            let root = m.root();
            let peaks = m.peaks();
            // Recompute the mountain list the way the prover sees it.
            let mut off = 0u64;
            let mut sizes = Vec::new();
            let mut rem = n;
            while rem > 0 {
                let size = 1u64 << (63 - rem.leading_zeros());
                sizes.push((off, size));
                off += size;
                rem -= size;
            }
            assert_eq!(sizes.len(), peaks.len());
            let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ n;
            for (pi, &(mo, ms)) in sizes.iter().enumerate() {
                // Strided subset + pseudorandom subset of this mountain.
                let stride = 1 + next(&mut state) % 5;
                let mut set: Vec<u64> = (mo..mo + ms).step_by(stride as usize).collect();
                for k in 0..ms {
                    if next(&mut state).is_multiple_of(3) {
                        set.push(mo + k);
                    }
                }
                set.sort_unstable();
                set.dedup();
                let mp = m.prove_multi(&set).expect("same-mountain set proves");
                assert_eq!(mp.peak_index, pi);
                assert!(
                    mp.verify(&root),
                    "multiproof verifies at n={n}, mountain {pi}"
                );
                assert_eq!(mp.peaks[mp.peak_index], peaks[pi]);
                // Leaf-for-leaf agreement with the single proofs.
                for (k, &idx) in set.iter().enumerate() {
                    let single = m.prove(idx).expect("in range");
                    assert!(single.verify(&root));
                    assert_eq!(single.leaf, mp.leaves[k]);
                    assert_eq!(single.peak_index, pi);
                }
            }
            // A set touching two mountains refuses (when there are ≥2).
            if sizes.len() > 1 {
                let cross = vec![sizes[0].0, sizes[1].0];
                assert_eq!(
                    m.prove_multi(&cross),
                    Err(MmrMultiproofError::MixedPeaks),
                    "cross-mountain set refuses at n={n}"
                );
            }
        }
    }

    /// Compact multiproofs stay small: helpers ≤ q·h for a mountain of
    /// height h (each level contributes at most one helper per leaf).
    #[test]
    fn mmr_multiproof_helper_bound() {
        let leaves: Vec<[u8; 32]> = (0..128).map(leaf).collect();
        let m = Mmr::of(&leaves);
        let root = m.root();
        // Mountain size 128 → height 7.
        for (set, h) in [
            (vec![0u64], 7u64),
            ((0..64u64).collect::<Vec<_>>(), 7),
            ((0..128u64).step_by(3).collect::<Vec<_>>(), 7),
            ((0..128u64).collect::<Vec<_>>(), 7),
        ] {
            let mp = m.prove_multi(&set).expect("single mountain");
            assert!(mp.verify(&root));
            assert!(
                mp.helpers.len() as u64 <= set.len() as u64 * h,
                "helpers ({}) ≤ q·h ({}·{h})",
                mp.helpers.len(),
                set.len()
            );
        }
    }

    /// FIXES.md §2.6/§3.4: the QC/checkpoint size rows, pinned as consts.
    #[test]
    fn mmr_section_3_4_size_rows_pinned() {
        // Formula pins.
        for k in [0u64, 1, 7, 64, 100, 128, 1024] {
            assert_eq!(qc_bytes(k), 666 * k + k.div_ceil(8), "QC formula at k={k}");
            assert_eq!(
                checkpoint_bytes_h20(k),
                3_309 + 20 * 32 + k.div_ceil(8),
                "checkpoint formula at k={k}"
            );
        }
        // §3.4 table rows.
        assert_eq!(qc_bytes(64), 42_632);
        assert_eq!(qc_bytes(128), 85_264);
        assert_eq!(QC_BYTES_K128, 85_264);
        assert_eq!(qc_bytes(1024), 682_112);
        assert_eq!(checkpoint_bytes_h20(128), 3_965);
        assert_eq!(CHECKPOINT_BYTES_K128_H20, 3_965);
        assert_eq!(FALCON512_SIG_BYTES, 666);
        assert_eq!(CHECKPOINT_TS_SIG_BYTES, 3_309);
    }

    /// FIXES.md §1.3: the hash-strength notes, pinned as consts (the MMR
    /// keeps 256-bit SHA-256 — history compat forbids migrating here).
    #[test]
    fn mmr_section_1_3_hash_strength_documented() {
        assert_eq!(MMR_HASH_BITS, 256);
        // Quantum second-preimage λ = n_h/2 − h/2.
        assert_eq!(MMR_SECOND_PREIMAGE_BITS_QUANTUM_H20, 256 / 2 - 20 / 2);
        assert_eq!(MMR_SECOND_PREIMAGE_BITS_QUANTUM_H64, 256 / 2 - 64 / 2);
        assert_eq!(MMR_SECOND_PREIMAGE_BITS_QUANTUM_H20, 118);
        assert_eq!(MMR_SECOND_PREIMAGE_BITS_QUANTUM_H64, 96);
    }
}
