//! Quorum-certificate aggregation framework.
//!
//! Three pieces live here, and nothing else:
//!
//! 1. **Concatenation baseline** — the CURRENT wire behavior, pinned
//!    byte-for-byte: a QC carries the raw concatenation of the `k`
//!    Falcon-512 signatures (666 B each,
//!    [`crate::post_quantum::FALCON512_SIG_LEN`]) plus a `ceil(k/8)`-byte
//!    validator bitmap, for a total of
//!
//!    ```text
//!    |QC_raw| = 666·k + ceil(k/8).
//!    ```
//!
//! 2. **Merkle-tree-of-signatures** — a commitment over the same `k`
//!    signatures with per-signer inclusion proofs, so a light client checks
//!    membership with `O(log k)` SHA-256 hashes plus ONE Falcon-512 verify
//!    (the signature itself is revealed alongside the proof).
//!
//! 3. **Multisig + bitmap** ([`verify_multisig_bitmap`]) — the ONLY
//!    slashing-relevant QC presentation: every claimed signer bit is bound
//!    to one checked Falcon-512 verify, so the signer set is explicit and
//!    attributable. Threshold signatures (TSS) MUST NOT be used here: a TSS
//!    hides WHO signed, and a bitmap stapled next to a TSS is not binding
//!    (the TSS commits to nothing about the bitmap — frameability).
//!
//! # Honest scope (read before extending)
//!
//! * **Lower bound (P10 §C.1, Thm C1).** Without interaction and without a
//!   succinct proof, checking `k` independent signatures needs
//!   `|C| = Ω(k·λ)` bytes. The Merkle tree here does NOT beat that bound:
//!   the root alone proves nothing — the verifier still sees one full
//!   666-byte signature per check. It cuts *per-check* work, not total size.
//! * **No naive sums (P11 §E.1, `Δλ ≈ ½·log₂k`).** Linearly combining
//!   lattice signatures (`Σσᵢ`) inflates the norm by `~√k` and costs about
//!   half a bit of security per doubling (`k=64` → 3 bits, `k=1024` → 5).
//!   That construction is deliberately NOT provided: there is no
//!   `aggregate_sum`, and none may be added without a spec update + audit.
//! * **No STARK backend exists in this repo.** The size-crossover math below
//!   (`k* = (S+32)/666`, P10 §C.3) is a documented decision rule for when a
//!   future succinct proof would pay off — not a claim that one is wired.
//!   At `k=64` raw Falcon-512 bytes (42 632 B) beat any STARK ≥ 50 KiB.
//!
//! Math references (read-only): `stellereum-math` papers
//! `10_pq_new_theorems.md` (§C) and `11_pq_phase3.md` (§E.1).

use sha2::{Digest, Sha256};

use crate::post_quantum::{verify_pq_signature, PqScheme, FALCON512_SIG_LEN};

/// Domain separator for QC Merkle leaves (mirrors the `mmr.rs` convention of
/// distinct leaf/node domains so a leaf hash can never equal a node hash).
pub const QC_LEAF_DOMAIN: &[u8] = b"STELL_QC_LEAF_V1";
/// Domain separator for QC Merkle interior nodes.
pub const QC_NODE_DOMAIN: &[u8] = b"STELL_QC_NODE_V1";

// ---------------------------------------------------------------------------
// Size model: concatenation baseline vs a hypothetical STARK certificate.
// ---------------------------------------------------------------------------

/// Validator-bitmap length in bytes for a `k`-signer QC.
#[must_use]
pub const fn bitmap_len(k: usize) -> usize {
    k.div_ceil(8)
}

/// Wire size of the concatenation-baseline QC with `k` Falcon-512 signatures:
/// `666·k + ceil(k/8)` (P10 §C.3, `|C_raw| = 666k + k/8`).
#[must_use]
pub const fn concat_qc_size(k: usize) -> usize {
    FALCON512_SIG_LEN
        .saturating_mul(k)
        .saturating_add(bitmap_len(k))
}

/// Wire size of a hypothetical STARK certificate for `k` signers:
/// `S + 32 + ceil(k/8)` — the STARK proof (`S` bytes) plus a 32-byte Merkle
/// root plus the same bitmap (P10 §C.3). No STARK backend exists; this is the
/// accounting rule only.
#[must_use]
pub const fn stark_qc_size(stark_proof_bytes: usize, k: usize) -> usize {
    stark_proof_bytes
        .saturating_add(32)
        .saturating_add(bitmap_len(k))
}

/// Break-even committee size for a STARK of `S` bytes: the smallest `k` with
/// `stark_qc_size(S, k) <= concat_qc_size(k)`, i.e. `ceil((S + 32) / 666)`
/// (P10 §C.3, Eq. 7). Integer division rounds UP so the table values
/// (77 / 154 / 308 / 769) hold exactly.
#[must_use]
pub const fn stark_crossover_k(stark_proof_bytes: usize) -> usize {
    stark_proof_bytes
        .saturating_add(32)
        .div_ceil(FALCON512_SIG_LEN)
}

/// Reference STARK sizes (bytes) from the P10 §C.3 crossover table.
pub const STARK_PROOF_50KIB: usize = 51_200;
/// Reference STARK sizes (bytes) from the P10 §C.3 crossover table.
pub const STARK_PROOF_100KIB: usize = 102_400;
/// Reference STARK sizes (bytes) from the P10 §C.3 crossover table.
pub const STARK_PROOF_200KIB: usize = 204_800;
/// Reference STARK sizes (bytes) from the P10 §C.3 crossover table.
pub const STARK_PROOF_500KIB: usize = 512_000;

/// Raw concatenation size at `k = 64`: `666·64 + 8 = 42 632` B — smaller
/// than any STARK ≥ 50 KiB, so small committees stay raw (P10 §C, вывод C).
pub const RAW_QC_64: usize = 42_632;

/// Raw concatenation size at `k = 128`: `666·128 + 16 = 85 264` B
/// (FIXES §2.6: "`k=128`: QC = **85 264 B**").
pub const RAW_QC_128: usize = 85_264;

/// Raw concatenation size at `k = 1024`: `666·1024 + 128 = 682 112` B
/// (FIXES §2.6: "`k=1024`: QC ≈ **682 КБ**").
pub const RAW_QC_1024: usize = 682_112;

/// Checkpoint size model (FIXES §2.6): `|checkpoint| = |TS_sig| + h·32 +
/// ceil(n/8)` — the threshold-signature bytes, plus `h` 32-byte hashes,
/// plus the `n`-member validator bitmap (same [`bitmap_len`] as the QC).
#[must_use]
pub const fn checkpoint_size(ts_sig_bytes: usize, h: usize, n: usize) -> usize {
    ts_sig_bytes
        .saturating_add(h.saturating_mul(32))
        .saturating_add(bitmap_len(n))
}

/// Pinned FIXES §2.6 row: `TS_sig = 3309`, `h = 20`, `n = 128` →
/// `3309 + 640 + 16 = 3 965` B.
pub const CHECKPOINT_128_H20: usize = 3_965;

/// Concatenate `k` signatures in order, byte-for-byte the current behavior.
///
/// Every signature must be exactly [`FALCON512_SIG_LEN`] bytes; anything else
/// panics (fail-closed constructor — a short/long entry would silently shift
/// every later offset on the wire).
#[must_use]
pub fn concat_signatures(sigs: &[impl AsRef<[u8]>]) -> Vec<u8> {
    for (i, s) in sigs.iter().enumerate() {
        assert_eq!(
            s.as_ref().len(),
            FALCON512_SIG_LEN,
            "qc_aggregate::concat_signatures: sig {i} has wrong length"
        );
    }
    let mut out = Vec::with_capacity(FALCON512_SIG_LEN.saturating_mul(sigs.len()));
    for s in sigs {
        out.extend_from_slice(s.as_ref());
    }
    out
}

// ---------------------------------------------------------------------------
// Merkle-tree-of-signatures.
// ---------------------------------------------------------------------------

/// Hash of one QC Merkle leaf: `SHA256(QC_LEAF_DOMAIN || sig)`.
#[must_use]
pub fn qc_leaf_hash(sig: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(QC_LEAF_DOMAIN);
    h.update(sig);
    h.finalize().into()
}

/// Hash of one QC Merkle interior node: `SHA256(QC_NODE_DOMAIN || l || r)`.
#[must_use]
pub fn qc_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(QC_NODE_DOMAIN);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Depth (proof length) of a `leaf_count`-leaf tree: `ceil(log2(n))`, with
/// `depth(0) = depth(1) = 0`.
#[must_use]
pub const fn tree_depth(leaf_count: usize) -> usize {
    if leaf_count <= 1 {
        return 0;
    }
    (usize::BITS - (leaf_count - 1).leading_zeros()) as usize
}

/// A Merkle tree over QC signatures, built by [`aggregate_merkle`].
///
/// Level 0 holds the leaf hashes; each higher level halves (rounding up, the
/// odd leaf duplicated Bitcoin-style). The empty tree has no levels and the
/// all-zero root (the same "no commitment" sentinel `mmr.rs` uses).
#[derive(Debug, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
    leaf_count: usize,
}

impl MerkleTree {
    /// Number of signature leaves committed to.
    #[must_use]
    pub const fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Number of hashes a membership proof carries (`ceil(log2(n))`).
    #[must_use]
    pub fn height(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    /// The Merkle root (all-zero for the empty tree).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().map_or([0u8; 32], |top| top[0])
    }
}

/// Commit to `k` signatures: returns `(root, tree)`.
///
/// Every signature must be exactly [`FALCON512_SIG_LEN`] bytes (panics
/// otherwise — same fail-closed rule as [`concat_signatures`]). The tree is
/// a pure function of the ordered leaves: same order → same root.
#[must_use]
pub fn aggregate_merkle(sigs: &[impl AsRef<[u8]>]) -> ([u8; 32], MerkleTree) {
    let mut leaves = Vec::with_capacity(sigs.len());
    for (i, s) in sigs.iter().enumerate() {
        assert_eq!(
            s.as_ref().len(),
            FALCON512_SIG_LEN,
            "qc_aggregate::aggregate_merkle: sig {i} has wrong length"
        );
        leaves.push(qc_leaf_hash(s.as_ref()));
    }
    if leaves.is_empty() {
        return (
            [0u8; 32],
            MerkleTree {
                levels: Vec::new(),
                leaf_count: 0,
            },
        );
    }
    let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves];
    while levels.last().is_some_and(|top| top.len() > 1) {
        let top = &levels[levels.len() - 1];
        let mut next = Vec::with_capacity(top.len().div_ceil(2));
        for pair in top.chunks(2) {
            let (l, r) = if pair.len() == 2 {
                (pair[0], pair[1])
            } else {
                (pair[0], pair[0])
            };
            next.push(qc_node_hash(&l, &r));
        }
        levels.push(next);
    }
    let root = levels.last().map_or([0u8; 32], |top| top[0]);
    (
        root,
        MerkleTree {
            levels,
            leaf_count: sigs.len(),
        },
    )
}

/// An inclusion proof for one signature: the sibling hashes from leaf level
/// up, plus the position they belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipProof {
    /// Index of the proven leaf.
    pub leaf_index: usize,
    /// Leaf count of the tree the proof was issued against.
    pub leaf_count: usize,
    /// Sibling hashes, leaf level first (`len == ceil(log2(leaf_count))`).
    pub siblings: Vec<[u8; 32]>,
}

/// Issue the inclusion proof for leaf `index`, or `None` when out of range.
#[must_use]
pub fn prove_membership(tree: &MerkleTree, index: usize) -> Option<MembershipProof> {
    if index >= tree.leaf_count {
        return None;
    }
    let mut siblings = Vec::with_capacity(tree.height());
    let mut idx = index;
    for level in tree.levels.iter().take(tree.levels.len().saturating_sub(1)) {
        let peer = idx ^ 1;
        // Odd tail duplicates itself (matches `aggregate_merkle`).
        siblings.push(if peer < level.len() {
            level[peer]
        } else {
            level[idx]
        });
        idx /= 2;
    }
    Some(MembershipProof {
        leaf_index: index,
        leaf_count: tree.leaf_count,
        siblings,
    })
}

/// Check a proof: recompute the leaf hash and fold `O(log k)` node hashes up
/// to `root`. Pure SHA-256 — no signature check here (pair with one Falcon
/// verify via [`verify_membership_with_falcon`]).
///
/// Refuses (returns `false`, never panics on attacker input): wrong-length
/// leaves, out-of-range indices, empty trees, truncated/padded sibling
/// vectors, and any mismatch of leaf, sibling, or root bytes.
#[must_use]
pub fn verify_membership(root: &[u8; 32], leaf_sig: &[u8], proof: &MembershipProof) -> bool {
    if leaf_sig.len() != FALCON512_SIG_LEN {
        return false;
    }
    if proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count {
        return false;
    }
    if proof.siblings.len() != tree_depth(proof.leaf_count) {
        return false;
    }
    let mut acc = qc_leaf_hash(leaf_sig);
    let mut idx = proof.leaf_index;
    for sib in &proof.siblings {
        acc = if (idx & 1) == 0 {
            qc_node_hash(&acc, sib)
        } else {
            qc_node_hash(sib, &acc)
        };
        idx >>= 1;
    }
    idx == 0 && acc == *root
}

/// Full light-client check: Merkle membership (`O(log k)` hashes) AND one
/// Falcon-512 verify of `signature` under `public_key` on `message`.
///
/// Both halves must pass; the Falcon half reuses
/// [`verify_pq_signature`](crate::post_quantum::verify_pq_signature), so key
/// and signature lengths are re-checked by the verifier itself.
#[must_use]
pub fn verify_membership_with_falcon(
    root: &[u8; 32],
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    proof: &MembershipProof,
) -> bool {
    if signature.len() != FALCON512_SIG_LEN {
        return false;
    }
    verify_membership(root, signature, proof)
        && verify_pq_signature(PqScheme::Falcon512, public_key, message, signature)
}

// ---------------------------------------------------------------------------
// Multisig + bitmap: the slashing-relevant QC presentation (FIXES §1.12).
// ---------------------------------------------------------------------------
//
// Accountability needs to name WHO signed so a faulty signer can be slashed.
// A threshold signature (TSS) verifies but hides the composition — and a
// bitmap stapled next to a TSS is NOT binding, because the TSS commits to
// nothing about the bitmap: a presenter can claim any signer set it likes,
// framing honest members or exonerating faulty ones (frameability). So for
// slashing, the QC MUST be multisig + bitmap, never an opaque aggregate:
// every set bit below is bound to exactly one checked Falcon-512 verify
// under that index's key, which makes the claimed signer set explicit and
// attributable.
//
// Bit convention: LSB-first — signer `i` is claimed iff
// `bitmap[i / 8] & (1 << (i % 8)) != 0`.

/// Verify a multisig + bitmap QC claim over `message`.
///
/// * `pubkeys[i]` is member `i`'s Falcon-512 public key (`k` members total).
/// * `bitmap` is exactly `bitmap_len(k)` bytes; trailing bits past `k`
///   must be zero (a set trailing bit is a tampered bitmap — refuse).
/// * `signatures` carries ONE 666-byte signature per SET bit, in ascending
///   signer-index order; `signatures.len()` must equal the bitmap popcount
///   (flipping any claimed bit breaks the count — tampered bitmaps refuse).
/// * `threshold` distinct verified signers are required: the SAME key in two
///   committee slots counts ONCE (one key, one voice — no double-counting
///   toward quorum), and `threshold == 0` / `threshold > k` refuse
///   fail-closed.
///
/// Pure verification over caller-supplied bytes: returns `false` (never
/// panics) on every malformed, mismatched, or unverifying input.
#[must_use]
pub fn verify_multisig_bitmap(
    pubkeys: &[impl AsRef<[u8]>],
    message: &[u8],
    signatures: &[impl AsRef<[u8]>],
    bitmap: &[u8],
    threshold: usize,
) -> bool {
    let k = pubkeys.len();
    if k == 0 || threshold == 0 || threshold > k {
        return false;
    }
    if bitmap.len() != bitmap_len(k) {
        return false;
    }
    // Trailing bits past `k` must be zero (at most 7 are checked).
    for i in k..bitmap.len().saturating_mul(8) {
        if bitmap[i / 8] & (1u8 << (i % 8)) != 0 {
            return false;
        }
    }
    // Claimed signer indices, ascending.
    let mut claimed: Vec<usize> = Vec::new();
    for i in 0..k {
        if bitmap[i / 8] & (1u8 << (i % 8)) != 0 {
            claimed.push(i);
        }
    }
    // Bitmap↔presentation binding: exactly one blob per claimed signer.
    if claimed.len() != signatures.len() {
        return false;
    }
    // One key, one voice: duplicate committee keys count once toward quorum.
    {
        let mut distinct: std::collections::HashSet<&[u8]> =
            std::collections::HashSet::with_capacity(claimed.len());
        for &i in &claimed {
            distinct.insert(pubkeys[i].as_ref());
        }
        if distinct.len() < threshold {
            return false;
        }
    }
    // Every claimed bit verifies under its own index's key, in order.
    for (blob, &i) in signatures.iter().zip(claimed.iter()) {
        let sig = blob.as_ref();
        if sig.len() != FALCON512_SIG_LEN {
            return false;
        }
        if !verify_pq_signature(PqScheme::Falcon512, pubkeys[i].as_ref(), message, sig) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::post_quantum::FalconKeypair;

    /// Deterministic 666-byte test signature: `(k*666 + j + i*131) % 251`.
    fn test_sig(i: u8, n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|k| {
                (0..FALCON512_SIG_LEN)
                    .map(|j| ((k * 666 + j + i as usize * 131) % 251) as u8)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn concat_baseline_byte_pin() {
        let sigs = test_sig(3, 3);
        let qc = concat_signatures(&sigs);
        // The constructor emits exactly the ordered concatenation (666 B per
        // sig); the bitmap lives in the size model, not in this blob.
        assert_eq!(qc.len(), FALCON512_SIG_LEN * 3);
        assert_eq!(concat_qc_size(3), FALCON512_SIG_LEN * 3 + 1);
        // Order + contiguity pin: sig boundaries land exactly at 666-step offsets.
        assert_eq!(&qc[0..FALCON512_SIG_LEN], sigs[0].as_slice());
        assert_eq!(
            &qc[FALCON512_SIG_LEN..2 * FALCON512_SIG_LEN],
            sigs[1].as_slice()
        );
        assert_eq!(&qc[2 * FALCON512_SIG_LEN..], sigs[2].as_slice());
        // Spot bytes of the deterministic pattern (any reorder/pad breaks these).
        assert_eq!(qc[0], sigs[0][0]);
        assert_eq!(qc[665], sigs[0][665]);
        assert_eq!(qc[666], sigs[1][0]);
        assert_eq!(qc[qc.len() - 1], sigs[2][FALCON512_SIG_LEN - 1]);
        assert_ne!(
            qc[0], qc[666],
            "distinct sigs must stay distinct in the blob"
        );
    }

    #[test]
    fn concat_size_formula() {
        // |QC| = 666k + ceil(k/8), pinned across bitmap boundaries.
        for k in [0usize, 1, 7, 8, 9, 64, 177, 256] {
            assert_eq!(concat_qc_size(k), 666 * k + k.div_ceil(8), "k={k}");
        }
        assert_eq!(bitmap_len(0), 0);
        assert_eq!(bitmap_len(1), 1);
        assert_eq!(bitmap_len(8), 1);
        assert_eq!(bitmap_len(9), 2);
        assert_eq!(concat_qc_size(64), RAW_QC_64);
        assert_eq!(RAW_QC_64, 42_632);
    }

    #[test]
    fn stark_crossover_table() {
        // P10 §C.3 table: ceil((S + 32) / 666).
        assert_eq!(stark_crossover_k(STARK_PROOF_50KIB), 77);
        assert_eq!(stark_crossover_k(STARK_PROOF_100KIB), 154);
        assert_eq!(stark_crossover_k(STARK_PROOF_200KIB), 308);
        assert_eq!(stark_crossover_k(STARK_PROOF_500KIB), 769);
        // Monotonicity: bigger proofs cross over later.
        assert!(stark_crossover_k(0) <= stark_crossover_k(STARK_PROOF_50KIB));
    }

    #[test]
    fn raw_64_beats_stark() {
        // P10 §C вывод C: at k=64 raw Falcon bytes beat any STARK ≥ 50 KiB.
        assert_eq!(concat_qc_size(64), 42_632);
        assert!(concat_qc_size(64) < STARK_PROOF_50KIB);
        assert!(concat_qc_size(64) < stark_qc_size(STARK_PROOF_50KIB, 64));
        assert_eq!(stark_qc_size(STARK_PROOF_50KIB, 64), 51_200 + 32 + 8);
        // And the crossover agrees: 64 < 77.
        assert!(64 < stark_crossover_k(STARK_PROOF_50KIB));
    }

    #[test]
    fn merkle_round_trip_falcon() {
        let msg = b"qc-aggregate round-trip";
        let keys: Vec<FalconKeypair> = (0..4).map(FalconKeypair::generate_from_seed).collect();
        let sigs: Vec<Vec<u8>> = keys.iter().map(|kp| kp.sign(msg)).collect();
        for s in &sigs {
            assert_eq!(s.len(), FALCON512_SIG_LEN);
        }
        let (root, tree) = aggregate_merkle(&sigs);
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.root(), root);
        assert_eq!(tree.height(), 2);
        for (i, (kp, sig)) in keys.iter().zip(sigs.iter()).enumerate() {
            let proof = prove_membership(&tree, i).expect("in-range prove must succeed");
            assert_eq!(proof.siblings.len(), 2, "k=4 proofs carry 2 hashes");
            assert!(verify_membership(&root, sig, &proof));
            assert!(verify_membership_with_falcon(
                &root,
                kp.pubkey(),
                msg,
                sig,
                &proof
            ));
        }
        assert!(prove_membership(&tree, 4).is_none());
    }

    #[test]
    fn merkle_proof_tamper_refusal() {
        let msg = b"qc-aggregate tamper";
        let keys: Vec<FalconKeypair> = (0..3).map(FalconKeypair::generate_from_seed).collect();
        let sigs: Vec<Vec<u8>> = keys.iter().map(|kp| kp.sign(msg)).collect();
        let (root, tree) = aggregate_merkle(&sigs);
        let proof0 = prove_membership(&tree, 0).expect("prove 0");
        let proof1 = prove_membership(&tree, 1).expect("prove 1");

        // Wrong leaf bytes.
        let mut bad_leaf = sigs[0].clone();
        bad_leaf[100] ^= 0x01;
        assert!(!verify_membership(&root, &bad_leaf, &proof0));

        // Wrong leaf length.
        assert!(!verify_membership(&root, &sigs[0][..600], &proof0));

        // Flipped sibling.
        let mut bad_sib = proof0.clone();
        bad_sib.siblings[0][0] ^= 0x01;
        assert!(!verify_membership(&root, &sigs[0], &bad_sib));

        // Flipped root.
        let mut bad_root = root;
        bad_root[0] ^= 0x01;
        assert!(!verify_membership(&bad_root, &sigs[0], &proof0));

        // Cross-index proof (leaf 0 against leaf-1 path).
        assert!(!verify_membership(&root, &sigs[0], &proof1));
        assert!(!verify_membership(&root, &sigs[1], &proof0));

        // Truncated / padded sibling vector.
        let mut short = proof0.clone();
        short.siblings.pop();
        assert!(!verify_membership(&root, &sigs[0], &short));
        let mut long = proof0.clone();
        long.siblings.push([7u8; 32]);
        assert!(!verify_membership(&root, &sigs[0], &long));

        // Forged index beyond the committed count.
        let mut bad_idx = proof0.clone();
        bad_idx.leaf_index = 9;
        assert!(!verify_membership(&root, &sigs[0], &bad_idx));

        // Falcon half refuses too: right proof, wrong message / wrong key.
        assert!(!verify_membership_with_falcon(
            &root,
            keys[0].pubkey(),
            b"other message",
            &sigs[0],
            &proof0
        ));
        assert!(!verify_membership_with_falcon(
            &root,
            keys[1].pubkey(),
            msg,
            &sigs[0],
            &proof0
        ));
    }

    #[test]
    fn merkle_empty_and_singleton() {
        // Empty: zero root, no proofs, every check refuses.
        let empty: Vec<Vec<u8>> = vec![];
        let (root, tree) = aggregate_merkle(&empty);
        assert_eq!(root, [0u8; 32]);
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.height(), 0);
        assert!(prove_membership(&tree, 0).is_none());
        let empty_proof = MembershipProof {
            leaf_index: 0,
            leaf_count: 0,
            siblings: vec![],
        };
        assert!(!verify_membership(
            &root,
            &[0u8; FALCON512_SIG_LEN],
            &empty_proof
        ));

        // Singleton: root IS the leaf hash, proof is empty, round-trips.
        let msg = b"qc-aggregate singleton";
        let kp = FalconKeypair::generate_from_seed(0xA5);
        let sig = kp.sign(msg);
        let (sroot, stree) = aggregate_merkle(std::slice::from_ref(&sig));
        assert_eq!(sroot, qc_leaf_hash(&sig));
        assert_eq!(stree.height(), 0);
        let sproof = prove_membership(&stree, 0).expect("singleton prove");
        assert!(sproof.siblings.is_empty());
        assert!(verify_membership(&sroot, &sig, &sproof));
        assert!(verify_membership_with_falcon(
            &sroot,
            kp.pubkey(),
            msg,
            &sig,
            &sproof
        ));
        let mut wrong = sroot;
        wrong[31] ^= 0x01;
        assert!(!verify_membership(&wrong, &sig, &sproof));
    }

    #[test]
    fn odd_leaf_count_round_trip() {
        // k=5 exercises the odd-tail duplication on two levels.
        let msg = b"qc-aggregate odd";
        let keys: Vec<FalconKeypair> = (10..15).map(FalconKeypair::generate_from_seed).collect();
        let sigs: Vec<Vec<u8>> = keys.iter().map(|kp| kp.sign(msg)).collect();
        let (root, tree) = aggregate_merkle(&sigs);
        assert_eq!(tree.height(), 3);
        for (i, sig) in sigs.iter().enumerate() {
            let proof = prove_membership(&tree, i).expect("in-range prove");
            assert_eq!(proof.siblings.len(), 3, "k=5 proofs carry 3 hashes");
            assert!(verify_membership(&root, sig, &proof));
        }
    }

    #[test]
    #[should_panic(expected = "wrong length")]
    fn aggregate_rejects_bad_sig_len() {
        let _ = aggregate_merkle(&[vec![0u8; 100]]);
    }

    #[test]
    #[should_panic(expected = "wrong length")]
    fn concat_rejects_bad_sig_len() {
        let _ = concat_signatures(&[vec![0u8; 665]]);
    }

    #[test]
    fn size_rows_128_and_checkpoint_pin() {
        // FIXES §2.6: `|QC| = 666k + ceil(k/8)` — the k=128 and k=1024 rows.
        assert_eq!(concat_qc_size(128), RAW_QC_128);
        assert_eq!(RAW_QC_128, 85_264);
        assert_eq!(concat_qc_size(128), 666 * 128 + 128usize.div_ceil(8));
        assert_eq!(concat_qc_size(1024), RAW_QC_1024);
        assert_eq!(RAW_QC_1024, 682_112);
        // FIXES §2.6: `|checkpoint| = |TS_sig| + h·32 + ceil(n/8)` —
        // 3309 + 640 + 16 = 3 965 B (h=20, n=128).
        assert_eq!(checkpoint_size(3_309, 20, 128), CHECKPOINT_128_H20);
        assert_eq!(CHECKPOINT_128_H20, 3_965);
        assert_eq!(checkpoint_size(3_309, 20, 128), 3_309 + 20 * 32 + 16);
    }

    /// LSB-first bitmap with `bits` set over `k` members.
    fn bitmap_of(k: usize, bits: &[usize]) -> Vec<u8> {
        let mut b = vec![0u8; bitmap_len(k)];
        for &i in bits {
            b[i / 8] |= 1u8 << (i % 8);
        }
        b
    }

    #[test]
    fn multisig_bitmap_round_trip_and_threshold() {
        let msg = b"multisig-bitmap qc";
        let keys: Vec<FalconKeypair> = (0..5).map(FalconKeypair::generate_from_seed).collect();
        let pubs: Vec<Vec<u8>> = keys.iter().map(|k| k.pubkey().to_vec()).collect();
        let claimed = [0usize, 2, 4];
        let sigs: Vec<Vec<u8>> = claimed.iter().map(|&i| keys[i].sign(msg)).collect();
        let bitmap = bitmap_of(5, &claimed);
        // Quorum met: 3 distinct verified signers ≥ 3.
        assert!(verify_multisig_bitmap(&pubs, msg, &sigs, &bitmap, 3));
        // Quorum missed: 3 < 4.
        assert!(!verify_multisig_bitmap(&pubs, msg, &sigs, &bitmap, 4));
        // Degenerate thresholds refuse fail-closed.
        assert!(!verify_multisig_bitmap(&pubs, msg, &sigs, &bitmap, 0));
        assert!(!verify_multisig_bitmap(&pubs, msg, &sigs, &bitmap, 6));
        // Empty committee refuses at any threshold.
        let empty: Vec<Vec<u8>> = vec![];
        let no_sigs: Vec<Vec<u8>> = vec![];
        assert!(!verify_multisig_bitmap(&empty, msg, &no_sigs, &[], 1));
        assert!(!verify_multisig_bitmap(&empty, msg, &no_sigs, &[], 0));
        // Nobody claimed: popcount 0 < threshold 1.
        assert!(!verify_multisig_bitmap(
            &pubs,
            msg,
            &no_sigs,
            &bitmap_of(5, &[]),
            1
        ));
    }

    #[test]
    fn multisig_bitmap_duplicate_signer_counts_once() {
        let msg = b"multisig-bitmap dup";
        let ka = FalconKeypair::generate_from_seed(0xA0);
        let kb = FalconKeypair::generate_from_seed(0xB0);
        let pa = ka.pubkey().to_vec();
        // Committee slots 0 and 1 hold the SAME key (one key, two slots).
        let pubs = vec![pa.clone(), pa.clone(), kb.pubkey().to_vec()];
        // Both A-slots claimed, two (distinct, valid) A signatures shown.
        let bitmap = bitmap_of(3, &[0, 1]);
        let sigs = vec![ka.sign(msg), ka.sign(msg)];
        // Popcount is 2 but distinct signers are 1: quorum 2 must refuse.
        assert!(!verify_multisig_bitmap(&pubs, msg, &sigs, &bitmap, 2));
        // ...while quorum 1 (the one distinct voice) passes.
        assert!(verify_multisig_bitmap(&pubs, msg, &sigs, &bitmap, 1));
        // A + B claimed: two distinct voices reach quorum 2.
        let bitmap_ab = bitmap_of(3, &[0, 2]);
        let sigs_ab = vec![ka.sign(msg), kb.sign(msg)];
        assert!(verify_multisig_bitmap(&pubs, msg, &sigs_ab, &bitmap_ab, 2));
    }

    #[test]
    fn multisig_bitmap_tamper_refusal() {
        let msg = b"multisig-bitmap tamper";
        let keys: Vec<FalconKeypair> = (20..25).map(FalconKeypair::generate_from_seed).collect();
        let pubs: Vec<Vec<u8>> = keys.iter().map(|k| k.pubkey().to_vec()).collect();
        let claimed = [0usize, 2, 4];
        let sigs: Vec<Vec<u8>> = claimed.iter().map(|&i| keys[i].sign(msg)).collect();
        let bitmap = bitmap_of(5, &claimed);
        assert!(verify_multisig_bitmap(&pubs, msg, &sigs, &bitmap, 3));

        // Clearing a claimed bit breaks the bitmap↔presentation count.
        assert!(!verify_multisig_bitmap(
            &pubs,
            msg,
            &sigs,
            &bitmap_of(5, &[0, 4]),
            2
        ));
        // Setting an extra bit breaks the count the other way.
        assert!(!verify_multisig_bitmap(
            &pubs,
            msg,
            &sigs,
            &bitmap_of(5, &[0, 1, 2, 4]),
            3
        ));
        // Wrong bitmap length (truncated / padded) refuses.
        assert!(!verify_multisig_bitmap(&pubs, msg, &sigs, &[], 1));
        let mut long = bitmap.clone();
        long.push(0);
        assert!(!verify_multisig_bitmap(&pubs, msg, &sigs, &long, 3));
        // Trailing bit past k=5 with a MATCHING popcount still refuses:
        // bits {0,2,7} carry 3 blobs, but bit 7 is outside the member set.
        let mut trailing = bitmap_of(5, &[0, 2]);
        trailing[0] |= 1u8 << 7;
        let three = vec![keys[0].sign(msg), keys[2].sign(msg), keys[4].sign(msg)];
        assert_eq!(three.len(), 3);
        assert!(!verify_multisig_bitmap(&pubs, msg, &three, &trailing, 2));
        // Flipped signature byte under a correctly-claimed bit refuses.
        let mut bad = sigs.clone();
        bad[1][100] ^= 0x01;
        assert!(!verify_multisig_bitmap(&pubs, msg, &bad, &bitmap, 3));
        // Swapped presentation order refuses (blob `j` must verify under
        // claimed index `j`'s own key).
        let swapped = vec![sigs[1].clone(), sigs[0].clone(), sigs[2].clone()];
        assert!(!verify_multisig_bitmap(&pubs, msg, &swapped, &bitmap, 3));
        // Short blob in a claimed slot refuses.
        let short = vec![sigs[0].clone(), vec![0u8; 100], sigs[2].clone()];
        assert!(!verify_multisig_bitmap(&pubs, msg, &short, &bitmap, 3));
        // Right blobs, wrong message refuse.
        assert!(!verify_multisig_bitmap(
            &pubs,
            b"other message",
            &sigs,
            &bitmap,
            3
        ));
    }
}
