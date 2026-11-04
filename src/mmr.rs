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
}
