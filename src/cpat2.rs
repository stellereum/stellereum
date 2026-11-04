//! Compressed Patricia-Merkle trie — v2, relative-skip model.
//!
//! Node model (relative, depth-free):
//!   Leaf{key, value}
//!   Branch{skip: u16, branch_bit: u8, left, right}
//!
//! Invariant: all keys under a Branch share their next `skip` bits (relative to
//! the parent's consumption point), then differ at bit `skip` (branch_bit). We do
//! NOT store absolute depth, so an insertion that lands inside a branch's skip
//! range simply splits the branch and recomputes only the two new nodes' skips.
//!
//! This is a full Patricia trie: the path to a key is deterministic and needs no
//! absolute prefix bookkeeping. Insert descends following bits; when the incoming
//! key diverges from an existing leaf or from inside a branch's skip, we split
//! with the correct relative skip.
//!
//! Hashing:
//!   Leaf:   blake3("L" || key || len(value) || value)
//!   Branch: blake3("B" || skip_be || branch_bit || left || right)
//!   Empty:  blake3("CPAT2_EMPTY")

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type Key = [u8; 32];
pub type H = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Leaf(Key, Vec<u8>),
    Branch {
        skip: u16,
        bit: u8,
        left: Box<Node>,
        right: Box<Node>,
        hash: H,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub sibling_right: bool,
    pub sibling_hash: H,
    pub skip: u16,
    pub bit: u8,
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub key: Key,
    pub path: Vec<Step>,
    pub leaf_hash: H,
}

pub fn leaf_hash(key: &Key, val: &[u8]) -> H {
    let mut h = blake3::Hasher::new();
    h.update(b"L");
    h.update(key);
    h.update(&(val.len() as u32).to_le_bytes());
    h.update(val);
    let o = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(o.as_bytes());
    k
}
pub fn branch_hash(skip: u16, bit: u8, l: &H, r: &H) -> H {
    let mut h = blake3::Hasher::new();
    h.update(b"B");
    h.update(&skip.to_be_bytes());
    h.update(&[bit & 1]);
    h.update(l);
    h.update(r);
    let o = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(o.as_bytes());
    k
}

#[inline]
fn bit(k: &Key, d: usize) -> u8 {
    if d >= 256 {
        return 0;
    }
    (k[d / 8] >> (7 - (d % 8))) & 1
}

/// Length of common prefix of two keys from absolute depth `from`.
fn common(a: &Key, b: &Key, from: usize) -> usize {
    let mut d = from;
    while d < 256 && bit(a, d) == bit(b, d) {
        d += 1;
    }
    d
}

fn node_hash(node: &Node) -> H {
    match node {
        Node::Leaf(k, v) => leaf_hash(k, v),
        Node::Branch { hash, .. } => *hash,
    }
}

/// Build a branch node, computing and caching its hash from children.
fn mk_branch(skip: u16, bit: u8, left: Node, right: Node) -> Node {
    let l = node_hash(&left);
    let r = node_hash(&right);
    let h = branch_hash(skip, bit, &l, &r);
    Node::Branch {
        skip,
        bit,
        left: Box::new(left),
        right: Box::new(right),
        hash: h,
    }
}

/// Insert `key` into subtree rooted at `node`, consuming keys from absolute
/// depth `depth` (depth is only used to compute skips, not stored).
fn insert(node: Option<Node>, key: Key, val: Vec<u8>, depth: usize) -> Node {
    match node {
        None => Node::Leaf(key, val),
        Some(Node::Leaf(ek, ev)) => {
            if ek == key {
                return Node::Leaf(key, val);
            }
            let cp = common(&ek, &key, depth);
            // cp < 256. Divergence at cp.
            let skip = (cp - depth) as u16;
            let bit0 = bit(&ek, cp); // existing key's bit at divergence
                                     // left = bit 0, right = bit 1
            let (left, right) = if bit0 == 0 {
                (Node::Leaf(ek, ev), Node::Leaf(key, val))
            } else {
                (Node::Leaf(key, val), Node::Leaf(ek, ev))
            };
            let _ = bit0;
            mk_branch(skip, 0, left, right)
        }
        Some(Node::Branch {
            skip,
            bit: bbit,
            left,
            right,
            hash,
        }) => {
            let bp = depth + skip as usize; // absolute divergence point of this branch
            if bp >= 256 {
                return Node::Branch {
                    skip,
                    bit: bbit,
                    left,
                    right,
                    hash,
                };
            }
            // Does the incoming key match all skipped bits [depth, bp)?
            let cp_skip =
                common_prefix_len(&key, left.as_ref(), right.as_ref(), depth, skip as usize);
            if cp_skip < skip as usize {
                // Incoming key diverges BEFORE this branch's divergence point.
                // Split here: new branch at (depth + cp_skip).
                // The existing branch moves one level deeper, so its relative skip
                // shrinks by (cp_skip + 1) (the +1 is the new branch's own bit).
                let new_skip = cp_skip as u16;
                let diverge_at = depth + cp_skip;
                let new_bit = bit(&key, diverge_at);
                let existing_skip = (skip as usize - cp_skip - 1) as u16;
                let existing = mk_branch(existing_skip, bbit, *left, *right);
                let incoming = Node::Leaf(key, val);
                let (l, r) = if new_bit == 0 {
                    (incoming, existing)
                } else {
                    (existing, incoming)
                };
                return mk_branch(new_skip, 0, l, r);
            }
            // Key follows the skipped bits; descend on its bit at bp.
            if bit(&key, bp) == 0 {
                let nl = insert(Some(*left), key, val, bp + 1);
                mk_branch(skip, bbit, nl, *right)
            } else {
                let nr = insert(Some(*right), key, val, bp + 1);
                mk_branch(skip, bbit, *left, nr)
            }
        }
    }
}

/// How many bits the incoming key shares with the branch's skipped prefix.
/// We recover the skipped bits from a representative leaf under either child.
fn common_prefix_len(key: &Key, left: &Node, right: &Node, depth: usize, skip: usize) -> usize {
    // Representative sibling key from one side gives the branch's implied bits.
    let rep = representative_key(left).or_else(|| representative_key(right));
    match rep {
        Some(rk) => {
            let mut d = 0;
            while d < skip && bit(key, depth + d) == bit(&rk, depth + d) {
                d += 1;
            }
            d
        }
        None => skip, // no keys -> trivially matches
    }
}

fn representative_key(n: &Node) -> Option<Key> {
    match n {
        Node::Leaf(k, _) => Some(*k),
        Node::Branch { left, .. } => representative_key(left),
    }
}

/// Collapse a parent branch when one child has been deleted.
/// If the remaining sibling is a Leaf, it collapses to that Leaf.
/// If the remaining sibling is a Branch, its skip is extended by
/// `parent_skip + 1` to account for the bypassed parent branch.
fn collapse(parent_skip: u16, sibling: Node) -> Node {
    match sibling {
        Node::Leaf(k, v) => Node::Leaf(k, v),
        Node::Branch {
            skip: sib_skip,
            bit: sib_bit,
            left: sib_left,
            right: sib_right,
            ..
        } => {
            let new_skip = parent_skip + 1 + sib_skip;
            mk_branch(new_skip, sib_bit, *sib_left, *sib_right)
        }
    }
}

impl Node {
    /// Recursively removes `key` from the subtree rooted at `self`.
    /// Returns `None` if the subtree becomes completely empty,
    /// or `Some(new_node)` with the updated/collapsed subtree.
    fn remove_node(self, key: &Key, depth: usize) -> Option<Node> {
        match self {
            Node::Leaf(k, v) => {
                if &k == key {
                    None
                } else {
                    Some(Node::Leaf(k, v))
                }
            }
            Node::Branch {
                skip,
                bit: bbit,
                left,
                right,
                hash,
            } => {
                let bp = depth + skip as usize;
                if bp >= 256 {
                    return Some(Node::Branch {
                        skip,
                        bit: bbit,
                        left,
                        right,
                        hash,
                    });
                }
                if common_prefix_len(key, left.as_ref(), right.as_ref(), depth, skip as usize)
                    < skip as usize
                {
                    return Some(Node::Branch {
                        skip,
                        bit: bbit,
                        left,
                        right,
                        hash,
                    });
                }
                let _ = hash;
                if bit(key, bp) == 0 {
                    let nl = left.remove_node(key, bp + 1);
                    match nl {
                        Some(nl) => Some(mk_branch(skip, bbit, nl, *right)),
                        None => Some(collapse(skip, *right)),
                    }
                } else {
                    let nr = right.remove_node(key, bp + 1);
                    match nr {
                        Some(nr) => Some(mk_branch(skip, bbit, *left, nr)),
                        None => Some(collapse(skip, *left)),
                    }
                }
            }
        }
    }
}

/// Standalone helper for `remove_node` on a `Node`.
#[allow(dead_code)]
fn remove_node(node: Node, key: &Key, depth: usize) -> Option<Node> {
    node.remove_node(key, depth)
}

#[derive(Clone, Debug, Default)]
pub struct CompressedTrie {
    root: Option<Node>,
    pub entries: HashMap<Key, Vec<u8>>,
}

impl CompressedTrie {
    pub fn new() -> Self {
        Self {
            root: None,
            entries: HashMap::new(),
        }
    }
    pub fn insert(&mut self, key: &Key, value: &[u8]) {
        self.entries.insert(*key, value.to_vec());
        let r = self.root.take();
        self.root = Some(insert(r, *key, value.to_vec(), 0));
    }
    pub fn get(&self, key: &Key) -> Option<&[u8]> {
        self.entries.get(key).map(|v| v.as_slice())
    }
    pub fn remove(&mut self, key: &Key) -> Option<Vec<u8>> {
        let v = self.entries.remove(key)?;
        if let Some(r) = self.root.take() {
            self.root = r.remove_node(key, 0);
        }
        Some(v)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Root hash (computed on demand — O(n); call once per block, not per insert).
    pub fn root_hash(&self) -> H {
        match &self.root {
            None => [0u8; 32],
            Some(n) => node_hash(n),
        }
    }

    fn walk(&self, key: &Key) -> Option<(Vec<Step>, H)> {
        let mut path = Vec::new();
        let mut node = self.root.as_ref()?;
        let mut depth = 0usize;
        loop {
            match node {
                Node::Leaf(k, _) if k == key => {
                    path.reverse();
                    return Some((path, leaf_hash(k, &self.entries[k])));
                }
                Node::Leaf(_, _) => return None,
                Node::Branch {
                    skip,
                    bit: bbit,
                    left,
                    right,
                    ..
                } => {
                    let bp = depth + *skip as usize;
                    if bp >= 256 {
                        return None;
                    }
                    // verify skipped bits match
                    if common_prefix_len(key, left, right, depth, *skip as usize) < *skip as usize {
                        return None;
                    }
                    let go_right = bit(key, bp) == 1;
                    let (sib, sib_right) = if go_right {
                        (left, false)
                    } else {
                        (right, true)
                    };
                    path.push(Step {
                        sibling_right: sib_right,
                        sibling_hash: node_hash(sib),
                        skip: *skip,
                        bit: *bbit,
                    });
                    node = if go_right { right } else { left };
                    depth = bp + 1;
                }
            }
        }
    }

    pub fn proof(&self, key: &Key) -> Option<Proof> {
        let (path, lh) = self.walk(key)?;
        Some(Proof {
            key: *key,
            path,
            leaf_hash: lh,
        })
    }

    pub fn verify(root: &H, key: &Key, value: &[u8], p: &Proof) -> bool {
        if &p.key != key {
            return false;
        }
        let lh = leaf_hash(key, value);
        if p.leaf_hash != lh {
            return false;
        }
        let mut cur = lh;
        for s in &p.path {
            let (l, r) = if s.sibling_right {
                (cur, s.sibling_hash)
            } else {
                (s.sibling_hash, cur)
            };
            cur = branch_hash(s.skip, s.bit, &l, &r);
        }
        &cur == root
    }

    // ------------------------------------------------------------------
    // Merkle proofs (inclusion + exclusion)
    // ------------------------------------------------------------------

    /// Inclusion proof for `key`, or `None` when the key is not in the trie.
    ///
    /// The proof carries the leaf value it commits to, so a verifier can
    /// recompute the leaf hash itself instead of trusting the server's word
    /// for it.
    pub fn generate_proof(&self, key: &Key) -> Option<MerkleProof> {
        let (path, witness) = self.prove(key)?;
        match witness {
            Witness::Inclusion { value, leaf_hash } => Some(MerkleProof {
                key: *key,
                value,
                leaf_hash,
                path,
                kind: ProofKind::Inclusion,
                witness_key: None,
                divergence: None,
            }),
            // The key is absent: an inclusion proof would be a lie, and an
            // absent key has no inclusion proof to hand out.
            Witness::ExclusionLeaf { .. } | Witness::ExclusionBranch { .. } => None,
        }
    }

    /// Exclusion (non-inclusion) proof for `key`, or `None` when the key *is*
    /// in the trie or the trie is empty.
    ///
    /// This is the other half of [`CompressedTrie::generate_proof`]: without
    /// it, a client can prove "this account is there" but never "this account
    /// is not there", and every caller has to take the server's word for
    /// absence — which is the trust assumption an SPV client exists to remove.
    pub fn generate_exclusion_proof(&self, key: &Key) -> Option<MerkleProof> {
        let (path, witness) = self.prove(key)?;
        match witness {
            Witness::Inclusion { .. } => None,
            Witness::ExclusionLeaf {
                key: wkey,
                value,
                leaf_hash,
            } => Some(MerkleProof {
                key: *key,
                value,
                leaf_hash,
                path,
                kind: ProofKind::Exclusion,
                witness_key: Some(wkey),
                divergence: Some(Divergence::Leaf),
            }),
            Witness::ExclusionBranch {
                step,
                key: wkey,
                value,
                leaf_hash,
            } => Some(MerkleProof {
                key: *key,
                value,
                leaf_hash,
                path,
                kind: ProofKind::Exclusion,
                witness_key: Some(wkey),
                divergence: Some(Divergence::Branch { step }),
            }),
        }
    }

    /// Verify an inclusion proof against `root`.
    ///
    /// See [`verify_proof`]; this is the same check under the trie's name.
    pub fn verify_proof(root: &[u8; 32], key: &Key, value: &[u8], proof: &MerkleProof) -> bool {
        verify_proof(root, key, value, proof)
    }

    /// Verify an exclusion proof against `root`.
    ///
    /// See [`verify_exclusion_proof`]; this is the same check under the trie's
    /// name.
    pub fn verify_exclusion_proof(root: &[u8; 32], key: &Key, proof: &MerkleProof) -> bool {
        verify_exclusion_proof(root, key, proof)
    }

    /// Walk the trie and produce either an inclusion or an exclusion witness
    /// for `key`.
    ///
    /// Returns the path in LEAF → ROOT order together with the witness.
    fn prove(&self, key: &Key) -> Option<(Vec<Step>, Witness)> {
        let root = self.root.as_ref()?;
        let mut steps: Vec<Step> = Vec::new(); // ROOT → LEAF order while walking
        let mut node = root;
        let mut depth = 0usize;
        loop {
            match node {
                Node::Leaf(k, v) => {
                    let lh = leaf_hash(k, v);
                    if k == key {
                        return Some((
                            steps.into_iter().rev().collect(),
                            Witness::Inclusion {
                                value: v.clone(),
                                leaf_hash: lh,
                            },
                        ));
                    }
                    // Divergence at the leaf: the path leads to a leaf whose key
                    // differs, which witnesses the absence of `key`.
                    return Some((
                        steps.into_iter().rev().collect(),
                        Witness::ExclusionLeaf {
                            key: *k,
                            value: v.clone(),
                            leaf_hash: lh,
                        },
                    ));
                }
                Node::Branch {
                    skip,
                    bit: bbit,
                    left,
                    right,
                    ..
                } => {
                    let bp = depth + *skip as usize;
                    if bp >= 256 {
                        return None; // cannot descend any further
                    }
                    if common_prefix_len(key, left, right, depth, *skip as usize) < *skip as usize {
                        // The queried key diverges INSIDE this branch's skipped
                        // prefix. The witness is a leaf under the branch: every
                        // key under a branch shares its skipped prefix, so that
                        // leaf's bits in [depth, bp) are the shared prefix the
                        // queried key contradicts.
                        let (wkey, wval) = match leftmost_leaf(left) {
                            Node::Leaf(k, v) => (*k, v.clone()),
                            _ => return None,
                        };
                        let lh = leaf_hash(&wkey, &wval);
                        // Steps from the witness leaf up to this branch's child.
                        let mut path = collect_path_up(left, bp + 1, &wkey)?;
                        let div_step = path.len();
                        // The branch itself: we descend into its LEFT child, so
                        // the sibling sits on the right.
                        path.push(Step {
                            sibling_right: true,
                            sibling_hash: node_hash(right),
                            skip: *skip,
                            bit: *bbit,
                        });
                        // Then the ancestors, root-most last (path is leaf → root).
                        for s in steps.into_iter().rev() {
                            path.push(s);
                        }
                        return Some((
                            path,
                            Witness::ExclusionBranch {
                                step: div_step,
                                key: wkey,
                                value: wval,
                                leaf_hash: lh,
                            },
                        ));
                    }
                    // The skipped bits match: descend on the queried key's bit.
                    let go_right = bit(key, bp) == 1;
                    let (sib, sib_right) = if go_right {
                        (left, false)
                    } else {
                        (right, true)
                    };
                    steps.push(Step {
                        sibling_right: sib_right,
                        sibling_hash: node_hash(sib),
                        skip: *skip,
                        bit: *bbit,
                    });
                    node = if go_right { right } else { left };
                    depth = bp + 1;
                }
            }
        }
    }
}

/// The witness a trie walk produced for a queried key.
enum Witness {
    /// The queried key is in the trie.
    Inclusion { value: Vec<u8>, leaf_hash: H },
    /// The path ends at a leaf whose key differs from the queried key.
    ExclusionLeaf {
        key: Key,
        value: Vec<u8>,
        leaf_hash: H,
    },
    /// The path crosses a branch whose skipped prefix diverges from the
    /// queried key; `step` indexes that branch inside the (leaf → root) path.
    ExclusionBranch {
        step: usize,
        key: Key,
        value: Vec<u8>,
        leaf_hash: H,
    },
}

/// The leftmost leaf under `node` (every subtree here holds at least one key).
fn leftmost_leaf(node: &Node) -> &Node {
    match node {
        Node::Leaf(_, _) => node,
        Node::Branch { left, .. } => leftmost_leaf(left),
    }
}

/// Steps from the leaf holding `target` up to `node`, in LEAF → ROOT order.
///
/// `target` must live under `node`; `None` means it does not.
fn collect_path_up(node: &Node, depth: usize, target: &Key) -> Option<Vec<Step>> {
    match node {
        Node::Leaf(k, _) => {
            if k == target {
                Some(Vec::new())
            } else {
                None
            }
        }
        Node::Branch {
            skip,
            bit: bbit,
            left,
            right,
            ..
        } => {
            let bp = depth + *skip as usize;
            if bp >= 256 {
                return None;
            }
            let (child, sib, sib_right) = if bit(target, bp) == 0 {
                (left, right, true)
            } else {
                (right, left, false)
            };
            let mut path = collect_path_up(child, bp + 1, target)?;
            path.push(Step {
                sibling_right: sib_right,
                sibling_hash: node_hash(sib),
                skip: *skip,
                bit: *bbit,
            });
            Some(path)
        }
    }
}

// ============================================================================
// Merkle proofs
// ============================================================================

/// Maximum number of branch points a genuine 32-byte key path can contain.
///
/// The trie walks one bit of the key per branch and refuses to descend past
/// depth 256, so a real path has at most 256 steps. A longer path can only be
/// a forgery, and every extra step is another blake3 hash an attacker gets the
/// verifier to compute.
pub const MAX_PROOF_STEPS: usize = 256;

/// What a [`MerkleProof`] claims about the key it is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofKind {
    /// The leaf holding this key (and value) is in the trie.
    Inclusion,
    /// The key is NOT in the trie.
    Exclusion,
}

/// Where the queried key diverges from the proof's witness leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Divergence {
    /// The path ends at the witness leaf; the queried key differs from the
    /// witness key at or after the depth the path consumed.
    Leaf,
    /// The path crosses a branch whose *skipped* prefix diverges from the
    /// queried key. `step` is that branch's index inside [`MerkleProof::path`]
    /// (which runs leaf → root).
    Branch { step: usize },
}

/// A Merkle proof over the compressed Patricia trie.
///
/// One type carries both claims a client needs about a key:
///
///  * **inclusion** — the leaf with this key and value is in the trie at the
///    root the proof folds to;
///  * **exclusion** — the key is *not* in the trie at that root, witnessed by
///    the leaf the path leads to.
///
/// The value is carried inside the proof rather than trusted from the server:
/// the leaf hash is `blake3("L" || key || len(value) || value)`, so a verifier
/// that recomputes it from the proof's own bytes learns the value from the
/// commitment instead of from the peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The key the proof is about.
    pub key: Key,
    /// The leaf value. For an inclusion proof this is the value of `key`; for
    /// an exclusion proof it is the value of the *witness* leaf.
    pub value: Vec<u8>,
    /// Hash of the leaf node this proof authenticates.
    pub leaf_hash: H,
    /// The branch steps from the leaf up to the root.
    pub path: Vec<Step>,
    /// Whether this is an inclusion or an exclusion claim.
    pub kind: ProofKind,
    /// Exclusion only: the key of the witness leaf.
    #[serde(default)]
    pub witness_key: Option<Key>,
    /// Exclusion only: where the queried key diverges from the witness.
    #[serde(default)]
    pub divergence: Option<Divergence>,
}

/// Wire tag: the leaf node of a proof.
const NODE_LEAF: u8 = b'L';
/// Wire tag: a branch step of a proof.
const NODE_BRANCH: u8 = b'B';
/// Wire flag: inclusion claim.
const KIND_INCLUSION: u8 = 0;
/// Wire flag: exclusion claim.
const KIND_EXCLUSION: u8 = 1;
/// Wire flag: the divergence is at the witness leaf.
const DIV_LEAF: u8 = 0;
/// Wire flag: the divergence is inside a branch's skipped prefix.
const DIV_BRANCH: u8 = 1;

impl MerkleProof {
    /// Canonical hex encoding of the proof: one string per node, leaf first.
    ///
    /// This is the wire form `stell_getProof` serves, and the form a light
    /// client parses back. It is canonical (one byte per field, fixed widths,
    /// big-endian lengths) so two encoders cannot disagree about what a proof
    /// says.
    pub fn to_nodes(&self) -> Vec<String> {
        let mut nodes = Vec::with_capacity(self.path.len() + 1);
        let (div_kind, div_step) = match self.divergence {
            None | Some(Divergence::Leaf) => (DIV_LEAF, 0u16),
            Some(Divergence::Branch { step }) => (DIV_BRANCH, step as u16),
        };
        let kind = match self.kind {
            ProofKind::Inclusion => KIND_INCLUSION,
            ProofKind::Exclusion => KIND_EXCLUSION,
        };
        // The witness leaf's key. For an inclusion proof the witness IS the
        // queried key.
        let leaf_key = self.witness_key.unwrap_or(self.key);
        let mut leaf = Vec::with_capacity(105 + self.value.len());
        leaf.push(NODE_LEAF);
        leaf.push(kind);
        leaf.push(div_kind);
        leaf.extend_from_slice(&div_step.to_be_bytes());
        leaf.extend_from_slice(&self.key);
        leaf.extend_from_slice(&leaf_key);
        leaf.extend_from_slice(&(self.value.len() as u32).to_be_bytes());
        leaf.extend_from_slice(&self.value);
        leaf.extend_from_slice(&self.leaf_hash);
        nodes.push(hex::encode(leaf));
        for s in &self.path {
            let mut b = Vec::with_capacity(37);
            b.push(NODE_BRANCH);
            b.extend_from_slice(&s.skip.to_be_bytes());
            b.push(s.bit & 1);
            b.push(u8::from(s.sibling_right));
            b.extend_from_slice(&s.sibling_hash);
            nodes.push(hex::encode(b));
        }
        nodes
    }

    /// Parse the canonical hex encoding produced by [`MerkleProof::to_nodes`].
    ///
    /// Every length is checked before it is used, so a hostile peer cannot
    /// make the parser read out of bounds or allocate without bound.
    pub fn from_nodes(nodes: &[String]) -> Result<Self, String> {
        if nodes.is_empty() {
            return Err("empty proof: a missing proof is not evidence of absence".to_string());
        }
        if nodes.len() > MAX_PROOF_STEPS + 1 {
            return Err(format!(
                "proof has {} nodes, more than a {MAX_PROOF_STEPS}-step path can need",
                nodes.len()
            ));
        }
        let leaf =
            hex::decode(&nodes[0]).map_err(|_| "proof leaf node is not valid hex".to_string())?;
        if leaf.len() < 105 {
            return Err("proof leaf node is truncated".to_string());
        }
        if leaf[0] != NODE_LEAF {
            return Err("proof does not start with a leaf node".to_string());
        }
        let kind = match leaf[1] {
            KIND_INCLUSION => ProofKind::Inclusion,
            KIND_EXCLUSION => ProofKind::Exclusion,
            other => return Err(format!("unknown proof kind {other}")),
        };
        let div_kind = leaf[2];
        let div_step = u16::from_be_bytes([leaf[3], leaf[4]]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&leaf[5..37]);
        let mut witness_key = [0u8; 32];
        witness_key.copy_from_slice(&leaf[37..69]);
        let vlen = u32::from_be_bytes([leaf[69], leaf[70], leaf[71], leaf[72]]) as usize;
        if leaf.len() != 73 + vlen + 32 {
            return Err("proof leaf node length does not match its value length".to_string());
        }
        let value = leaf[73..73 + vlen].to_vec();
        let mut leaf_hash = [0u8; 32];
        leaf_hash.copy_from_slice(&leaf[73 + vlen..]);

        let mut path = Vec::with_capacity(nodes.len() - 1);
        for node in &nodes[1..] {
            let b =
                hex::decode(node).map_err(|_| "proof branch node is not valid hex".to_string())?;
            if b.len() != 37 {
                return Err("proof branch node has the wrong length".to_string());
            }
            if b[0] != NODE_BRANCH {
                return Err("proof contains a node that is neither leaf nor branch".to_string());
            }
            let skip = u16::from_be_bytes([b[1], b[2]]);
            let bit = b[3] & 1;
            let sibling_right = b[4] & 1 == 1;
            let mut sibling_hash = [0u8; 32];
            sibling_hash.copy_from_slice(&b[5..37]);
            path.push(Step {
                sibling_right,
                sibling_hash,
                skip,
                bit,
            });
        }

        let (witness_key, divergence) = match kind {
            ProofKind::Inclusion => (None, None),
            ProofKind::Exclusion => {
                let divergence = match div_kind {
                    DIV_LEAF => Divergence::Leaf,
                    DIV_BRANCH => Divergence::Branch {
                        step: div_step as usize,
                    },
                    other => return Err(format!("unknown divergence kind {other}")),
                };
                (Some(witness_key), Some(divergence))
            }
        };
        Ok(MerkleProof {
            key,
            value,
            leaf_hash,
            path,
            kind,
            witness_key,
            divergence,
        })
    }

    /// Verify an inclusion claim against `root`.
    pub fn verify_inclusion(&self, root: &[u8; 32], key: &Key, value: &[u8]) -> bool {
        verify_proof(root, key, value, self)
    }

    /// Verify an exclusion claim against `root`.
    pub fn verify_exclusion(&self, root: &[u8; 32], key: &Key) -> bool {
        verify_exclusion_proof(root, key, self)
    }
}

/// Absolute branch positions of a leaf → root path.
///
/// Returns, for every step, the branch's absolute bit position and the depth
/// consumed before it, plus the depth the whole path consumes (the leaf's
/// depth). `None` when the path is longer than a 32-byte key can need or
/// descends past bit 256.
fn path_positions(path: &[Step]) -> Option<(Vec<(u16, u16)>, u16)> {
    if path.len() > MAX_PROOF_STEPS {
        return None;
    }
    let mut depth: u32 = 0;
    let mut out = Vec::with_capacity(path.len());
    // The path runs leaf → root; walk it backwards to accumulate depths, so
    // `out` comes out in root → leaf order.
    for s in path.iter().rev() {
        let bp = depth + s.skip as u32;
        if bp >= 256 {
            return None;
        }
        out.push((bp as u16, depth as u16));
        depth = bp + 1;
    }
    Some((out, depth as u16))
}

/// Does the path follow the key's own bits?
///
/// At every branch the path must turn the way the key's bit at that branch's
/// position turns. The root hash already pins the path's *shape*, but not the
/// key it belongs to: without this check a proof for one key could be
/// replayed as a proof for another.
fn path_follows_key(path: &[Step], key: &Key) -> bool {
    let (positions, _) = match path_positions(path) {
        Some(p) => p,
        None => return false,
    };
    // `positions` is root → leaf; `path` is leaf → root.
    for (i, s) in path.iter().enumerate() {
        let (bp, _) = positions[path.len() - 1 - i];
        // sibling on the right ⇒ we descended into the LEFT child ⇒ bit 0.
        let expected = if s.sibling_right { 0u8 } else { 1u8 };
        if bit(key, bp as usize) != expected {
            return false;
        }
    }
    true
}

/// Fold a leaf hash up a leaf → root path.
fn fold_path(leaf: &H, path: &[Step]) -> H {
    let mut cur = *leaf;
    for s in path {
        let (l, r) = if s.sibling_right {
            (cur, s.sibling_hash)
        } else {
            (s.sibling_hash, cur)
        };
        cur = branch_hash(s.skip, s.bit, &l, &r);
    }
    cur
}

/// Verify an inclusion proof: is `key == value` in the trie at `root`?
///
/// The check is: the leaf hash of `key`/`value` must equal the proof's leaf
/// hash, the path must be the key's own path, and folding the path up must
/// reproduce `root`.
pub fn verify_proof(root: &[u8; 32], key: &Key, value: &[u8], proof: &MerkleProof) -> bool {
    if proof.kind != ProofKind::Inclusion {
        return false;
    }
    if &proof.key != key {
        return false;
    }
    if proof.value != value {
        return false;
    }
    let lh = leaf_hash(key, value);
    if lh != proof.leaf_hash {
        return false;
    }
    if !path_follows_key(&proof.path, key) {
        return false;
    }
    &fold_path(&lh, &proof.path) == root
}

/// Verify an exclusion proof: is `key` provably ABSENT from the trie at `root`?
///
/// The witness is a leaf that really is in the trie at `root` (its hash is
/// recomputed from the witness key and value, and the path folds to the root),
/// and the queried key must fall outside the range that leaf covers:
///
///  * divergence at the leaf — the queried key differs from the witness key at
///    or after the depth the path consumed, so the witness leaf is the only
///    key in that range and it is not the queried one;
///  * divergence inside a branch's skipped prefix — the queried key
///    contradicts the prefix every key under that branch shares, so it cannot
///    live under that branch, and the ancestors' turns match the queried key's
///    bits, so its path would have led there.
///
/// Either way the answer is "not in this state", which is a claim about the
/// world rather than a shrug.
pub fn verify_exclusion_proof(root: &[u8; 32], key: &Key, proof: &MerkleProof) -> bool {
    if proof.kind != ProofKind::Exclusion {
        return false;
    }
    if &proof.key != key {
        return false;
    }
    let witness = match proof.witness_key {
        Some(w) => w,
        None => return false,
    };
    if &witness == key {
        return false; // the witness must be a DIFFERENT key
    }
    // The witness leaf must be the real leaf the proof commits to.
    if leaf_hash(&witness, &proof.value) != proof.leaf_hash {
        return false;
    }
    // ...and it must really be in the trie at this root.
    if &fold_path(&proof.leaf_hash, &proof.path) != root {
        return false;
    }
    let (positions, leaf_depth) = match path_positions(&proof.path) {
        Some(p) => p,
        None => return false,
    };
    let cp = common(&witness, key, 0);
    match proof.divergence {
        Some(Divergence::Leaf) => {
            // The path ends at the witness leaf; the queried key must differ
            // from it at or after the leaf's depth.
            if cp < leaf_depth as usize {
                return false;
            }
            // Every turn on the path must be the queried key's own turn.
            path_follows_key(&proof.path, key)
        }
        Some(Divergence::Branch { step }) => {
            if step >= proof.path.len() {
                return false;
            }
            // The divergent branch's range, in root → leaf indexing.
            let i = proof.path.len() - 1 - step;
            let (bp, depth_before) = positions[i];
            // The queried key must contradict the prefix that every key under
            // that branch shares.
            if cp < depth_before as usize || cp >= bp as usize {
                return false;
            }
            // The turns above the divergent branch must be the queried key's.
            for (j, s) in proof.path.iter().enumerate() {
                if j <= step {
                    break; // the divergent branch and everything below it
                }
                let (b, _) = positions[proof.path.len() - 1 - j];
                let expected = if s.sibling_right { 0u8 } else { 1u8 };
                if bit(key, b as usize) != expected {
                    return false;
                }
            }
            true
        }
        None => false,
    }
}

/// Canonical length of a legacy / dormant account leaf (balance: 8B || nonce: 8B)
pub const ACCOUNT_LEAF_LEN_LEGACY: usize = 16;

/// A per-key ARCHIVE proof: the claim "key K held value V (or nothing) at
/// height H", verifiable against a HISTORICAL state root.
///
/// This is the wire form `stell_getArchiveProof` serves and the form an
/// archive node builds from its persisted snapshot history (see
/// `crate::storage::Storage::serve_archive_proof`), not from the live trie.
///
/// Layout (JSON):
/// ```text
/// { "height": H, "state_root": <hex>, "key": <hex>,
///   "value": <hex|null>, "proof": [...], "proof_type": "inclusion"|"exclusion" }
/// ```
/// `proof` is the canonical `MerkleProof::to_nodes` hex-node list (leaf
/// first). `value` is `null` if and only if `proof_type` is `exclusion`.
///
/// Verification is two steps, in this order: the proof nodes must parse and
/// authenticate against `state_root` for `key` (inclusion: `key == value` is
/// in the trie; exclusion: `key` is provably absent), and the proven value
/// must equal `value` (`None` for exclusion). A separate step the caller
/// owns: `state_root` itself must be authenticated from a trusted anchor
/// (see `stell_getHistoricalRoot` / `crate::light_client`) — a proof against
/// an untrusted root proves nothing.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArchiveProof {
    /// Height whose post-state this proof is about.
    pub height: u64,
    /// The historical state root the proof authenticates against.
    pub state_root: H,
    /// The state-trie key the proof is about (see the slot model in
    /// `crate::storage`: account leaf, storage cell, contract code hash,
    /// staking entry, ...).
    pub key: Key,
    /// The proven value (`None` when the key is proven absent).
    #[serde(default)]
    pub value: Option<Vec<u8>>,
    /// The Merkle proof, in `MerkleProof::to_nodes` wire form.
    pub proof_nodes: Vec<String>,
    /// Whether this is an inclusion or an exclusion claim.
    pub proof_type: ArchiveProofType,
}

/// Whether an [`ArchiveProof`] claims presence or absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveProofType {
    Inclusion,
    Exclusion,
}

impl ArchiveProof {
    /// Build an inclusion archive proof from a generated trie proof.
    ///
    /// Returns `None` when `proof` is not an inclusion proof for `key`.
    pub fn inclusion(height: u64, state_root: H, key: Key, proof: &MerkleProof) -> Option<Self> {
        if proof.kind != ProofKind::Inclusion || proof.key != key {
            return None;
        }
        Some(Self {
            height,
            state_root,
            key,
            value: Some(proof.value.clone()),
            proof_nodes: proof.to_nodes(),
            proof_type: ArchiveProofType::Inclusion,
        })
    }

    /// Build an exclusion archive proof from a generated trie proof.
    ///
    /// Returns `None` when `proof` is not an exclusion proof for `key`.
    pub fn exclusion(height: u64, state_root: H, key: Key, proof: &MerkleProof) -> Option<Self> {
        if proof.kind != ProofKind::Exclusion || proof.key != key {
            return None;
        }
        Some(Self {
            height,
            state_root,
            key,
            value: None,
            proof_nodes: proof.to_nodes(),
            proof_type: ArchiveProofType::Exclusion,
        })
    }

    /// Verify this proof against its own `state_root`.
    ///
    /// This checks the proof is genuine; it does NOT check the root is
    /// trusted — the caller must authenticate `state_root` from a trusted
    /// anchor (a quorum-certified header) first.
    pub fn verify(&self) -> bool {
        let proof = match MerkleProof::from_nodes(&self.proof_nodes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        match self.proof_type {
            ArchiveProofType::Inclusion => {
                if proof.kind != ProofKind::Inclusion {
                    return false;
                }
                let value = match &self.value {
                    Some(v) => v,
                    None => return false,
                };
                if proof.value != *value {
                    return false;
                }
                verify_proof(&self.state_root, &self.key, value, &proof)
            }
            ArchiveProofType::Exclusion => {
                if proof.kind != ProofKind::Exclusion {
                    return false;
                }
                if self.value.is_some() {
                    return false;
                }
                verify_exclusion_proof(&self.state_root, &self.key, &proof)
            }
        }
    }

    /// Canonical JSON form served by `stell_getArchiveProof`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "height": self.height,
            "state_root": hex::encode(self.state_root),
            "key": hex::encode(self.key),
            "value": self.value.as_ref().map(hex::encode),
            "proof": self.proof_nodes,
            "proof_type": self.proof_type,
        })
    }

    /// Parse the canonical JSON form.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let height = v
            .get("height")
            .and_then(|h| h.as_u64())
            .ok_or_else(|| "archive proof has no height".to_string())?;
        let root_hex = v
            .get("state_root")
            .or_else(|| v.get("stateRoot"))
            .and_then(|s| s.as_str())
            .ok_or_else(|| "archive proof has no state root".to_string())?;
        let root_raw =
            hex::decode(root_hex).map_err(|_| "archive proof state root is not hex".to_string())?;
        if root_raw.len() != 32 {
            return Err("archive proof state root is not 32 bytes".to_string());
        }
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&root_raw);
        let key_hex = v
            .get("key")
            .and_then(|s| s.as_str())
            .ok_or_else(|| "archive proof has no key".to_string())?;
        let key_raw = hex::decode(key_hex.trim_start_matches("0x"))
            .map_err(|_| "archive proof key is not hex".to_string())?;
        if key_raw.len() != 32 {
            return Err("archive proof key is not 32 bytes".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_raw);
        let value = match v.get("value") {
            Some(serde_json::Value::String(s)) => {
                Some(hex::decode(s).map_err(|_| "archive proof value is not hex".to_string())?)
            }
            Some(serde_json::Value::Null) | None => None,
            Some(_) => return Err("archive proof value must be hex or null".to_string()),
        };
        let proof_nodes = match v.get("proof").and_then(|p| p.as_array()) {
            Some(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for n in arr {
                    match n.as_str() {
                        Some(s) => out.push(s.to_string()),
                        None => return Err("archive proof node is not a hex string".to_string()),
                    }
                }
                out
            }
            None => return Err("archive proof has no proof nodes".to_string()),
        };
        let proof_type = match v.get("proof_type").and_then(|s| s.as_str()) {
            Some("inclusion") => ArchiveProofType::Inclusion,
            Some("exclusion") => ArchiveProofType::Exclusion,
            Some(other) => return Err(format!("unknown archive proof type {other}")),
            None => {
                // Infer from the value only when the server omitted the tag:
                // a value means presence, null means absence.
                if value.is_some() {
                    ArchiveProofType::Inclusion
                } else {
                    ArchiveProofType::Exclusion
                }
            }
        };
        Ok(Self {
            height,
            state_root,
            key,
            value,
            proof_nodes,
            proof_type,
        })
    }
}

/// Canonical length of a post-quantum pinned account leaf
/// Canonical length of a post-quantum pinned account leaf
/// (balance: 8B || nonce: 8B || scheme: 1B || pubkey_hash: 32B)
pub const ACCOUNT_LEAF_LEN_PQ: usize = 49;

/// Canonical length of a consensus domain commitment leaf
pub const COMMITMENT_LEAF_LEN: usize = 32;

/// Account leaf representation supporting both 16-byte legacy/dormant leaves
/// and 49-byte post-quantum consensus state pinned leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLeaf {
    pub balance: u64,
    pub nonce: u64,
    pub scheme: u8,
    pub pubkey_hash: Option<[u8; 32]>,
}

impl AccountLeaf {
    /// Creates an unpinned / dormant account leaf (16 bytes).
    pub fn new_unpinned(balance: u64, nonce: u64) -> Self {
        Self {
            balance,
            nonce,
            scheme: 0,
            pubkey_hash: None,
        }
    }

    /// Creates a pinned post-quantum account leaf (49 bytes).
    pub fn new_pinned(balance: u64, nonce: u64, scheme: u8, pubkey_hash: [u8; 32]) -> Self {
        Self {
            balance,
            nonce,
            scheme,
            pubkey_hash: Some(pubkey_hash),
        }
    }

    /// Encode into canonical bytes: 49 bytes if pinned, 16 bytes if dormant.
    pub fn encode(&self) -> Vec<u8> {
        if let Some(h) = self.pubkey_hash {
            let mut out = Vec::with_capacity(ACCOUNT_LEAF_LEN_PQ);
            out.extend_from_slice(&self.balance.to_be_bytes());
            out.extend_from_slice(&self.nonce.to_be_bytes());
            out.push(self.scheme);
            out.extend_from_slice(&h);
            out
        } else {
            let mut out = Vec::with_capacity(ACCOUNT_LEAF_LEN_LEGACY);
            out.extend_from_slice(&self.balance.to_be_bytes());
            out.extend_from_slice(&self.nonce.to_be_bytes());
            out
        }
    }

    /// Force encoding into fixed 49-byte format.
    pub fn encode_49(&self) -> [u8; ACCOUNT_LEAF_LEN_PQ] {
        let mut out = [0u8; ACCOUNT_LEAF_LEN_PQ];
        out[0..8].copy_from_slice(&self.balance.to_be_bytes());
        out[8..16].copy_from_slice(&self.nonce.to_be_bytes());
        out[16] = self.scheme;
        if let Some(h) = self.pubkey_hash {
            out[17..49].copy_from_slice(&h);
        }
        out
    }

    /// Decode from either 16-byte or 49-byte leaf format.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() == ACCOUNT_LEAF_LEN_LEGACY {
            let balance = u64::from_be_bytes(
                bytes[0..8]
                    .try_into()
                    .map_err(|_| "invalid balance slice".to_string())?,
            );
            let nonce = u64::from_be_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| "invalid nonce slice".to_string())?,
            );
            Ok(Self {
                balance,
                nonce,
                scheme: 0,
                pubkey_hash: None,
            })
        } else if bytes.len() == ACCOUNT_LEAF_LEN_PQ {
            let balance = u64::from_be_bytes(
                bytes[0..8]
                    .try_into()
                    .map_err(|_| "invalid balance slice".to_string())?,
            );
            let nonce = u64::from_be_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| "invalid nonce slice".to_string())?,
            );
            let scheme = bytes[16];
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes[17..49]);
            let pubkey_hash = if h == [0u8; 32] && scheme == 0 {
                None
            } else {
                Some(h)
            };
            Ok(Self {
                balance,
                nonce,
                scheme,
                pubkey_hash,
            })
        } else {
            Err(format!(
                "Invalid leaf format length: expected {} or {}, got {}",
                ACCOUNT_LEAF_LEN_LEGACY,
                ACCOUNT_LEAF_LEN_PQ,
                bytes.len()
            ))
        }
    }
}

/// Compute the cryptographic leaf hash for an AccountLeaf.
pub fn account_leaf_hash(key: &Key, leaf: &AccountLeaf) -> H {
    leaf_hash(key, &leaf.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Merkle proofs
    // ------------------------------------------------------------------

    /// A deterministic key generator (xorshift) so the property tests below
    /// fail the same way every run.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn key(&mut self) -> Key {
            let mut k = [0u8; 32];
            for c in k.chunks_mut(8) {
                c.copy_from_slice(&self.next().to_be_bytes());
            }
            k
        }
    }

    #[test]
    fn test_generate_proof_roundtrips_through_the_wire_encoding() {
        let mut trie = CompressedTrie::new();
        let mut rng = Rng(0xA11C_E123_4567_89AB);
        let mut entries = Vec::new();
        for _ in 0..40 {
            let k = rng.key();
            let v = vec![rng.next() as u8; 16];
            trie.insert(&k, &v);
            entries.push((k, v));
        }
        let root = trie.root_hash();

        for (k, v) in &entries {
            let proof = trie.generate_proof(k).expect("inclusion proof");
            assert_eq!(proof.kind, ProofKind::Inclusion);
            assert_eq!(proof.key, *k);
            assert_eq!(&proof.value, v);
            assert!(verify_proof(&root, k, v, &proof));
            assert!(CompressedTrie::verify_proof(&root, k, v, &proof));

            // Wire form: hex nodes, parsed back into an equivalent proof.
            let nodes = proof.to_nodes();
            assert!(!nodes.is_empty());
            let parsed = MerkleProof::from_nodes(&nodes).expect("parse");
            assert_eq!(parsed, proof);
            assert!(verify_proof(&root, k, v, &parsed));
        }
    }

    #[test]
    fn test_generate_proof_refuses_an_absent_key() {
        let mut trie = CompressedTrie::new();
        let k = [0x11u8; 32];
        trie.insert(&k, b"value");
        let missing = [0x22u8; 32];
        assert!(trie.generate_proof(&missing).is_none());
    }

    #[test]
    fn test_exclusion_proof_witnesses_an_absent_key() {
        let mut trie = CompressedTrie::new();
        let present = [0x11u8; 32];
        trie.insert(&present, b"value");
        let root = trie.root_hash();

        let missing = [0x22u8; 32];
        let proof = trie
            .generate_exclusion_proof(&missing)
            .expect("exclusion proof");
        assert_eq!(proof.kind, ProofKind::Exclusion);
        assert_eq!(proof.key, missing);
        assert_ne!(proof.witness_key, Some(missing));
        assert!(verify_exclusion_proof(&root, &missing, &proof));

        // A key that IS in the trie has no exclusion proof.
        assert!(trie.generate_exclusion_proof(&present).is_none());

        // The wire form keeps the claim verifiable.
        let parsed = MerkleProof::from_nodes(&proof.to_nodes()).expect("parse");
        assert!(verify_exclusion_proof(&root, &missing, &parsed));
    }

    #[test]
    fn test_exclusion_proof_rejects_a_key_that_is_present() {
        // Forged: take the exclusion proof of an absent key and claim it for
        // a key that IS in the trie. The witness is a different leaf, so the
        // claim must not verify.
        let mut trie = CompressedTrie::new();
        let present = [0x11u8; 32];
        trie.insert(&present, b"value");
        let root = trie.root_hash();

        let missing = [0x22u8; 32];
        let mut proof = trie
            .generate_exclusion_proof(&missing)
            .expect("exclusion proof");
        proof.key = present;
        assert!(!verify_exclusion_proof(&root, &present, &proof));
    }

    #[test]
    fn test_exclusion_proof_rejects_a_tampered_root_or_witness() {
        let mut trie = CompressedTrie::new();
        let present = [0x11u8; 32];
        trie.insert(&present, b"value");
        let root = trie.root_hash();
        let missing = [0x22u8; 32];
        let proof = trie
            .generate_exclusion_proof(&missing)
            .expect("exclusion proof");

        // Another root: the proof is not about that state.
        assert!(!verify_exclusion_proof(&[0xFFu8; 32], &missing, &proof));

        // A witness key that is not the leaf the proof commits to.
        let mut forged = proof.clone();
        forged.witness_key = Some([0x33u8; 32]);
        assert!(!verify_exclusion_proof(&root, &missing, &forged));

        // A value that does not hash to the committed leaf.
        let mut forged = proof.clone();
        forged.value = b"other".to_vec();
        assert!(!verify_exclusion_proof(&root, &missing, &forged));
    }

    #[test]
    fn test_inclusion_proof_cannot_be_replayed_for_another_key() {
        let mut trie = CompressedTrie::new();
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        trie.insert(&a, b"same-value");
        trie.insert(&b, b"same-value");
        let root = trie.root_hash();
        let proof = trie.generate_proof(&a).expect("proof");
        // The value is identical, so only the key binding can tell them apart.
        assert!(!verify_proof(&root, &b, b"same-value", &proof));
        assert!(verify_proof(&root, &a, b"same-value", &proof));
    }

    #[test]
    fn test_exclusion_proofs_hold_for_random_absent_keys() {
        let mut trie = CompressedTrie::new();
        let mut rng = Rng(0xDEAD_BEEF_0102_0304);
        let mut present = std::collections::HashSet::new();
        for _ in 0..60 {
            let k = rng.key();
            trie.insert(&k, &[rng.next() as u8; 8]);
            present.insert(k);
        }
        let root = trie.root_hash();

        let mut checked = 0usize;
        for _ in 0..200 {
            let k = rng.key();
            if present.contains(&k) {
                continue;
            }
            let proof = trie.generate_exclusion_proof(&k).expect("exclusion proof");
            assert!(
                verify_exclusion_proof(&root, &k, &proof),
                "exclusion proof must verify for an absent key"
            );
            // The same proof must not work for a key that is present.
            if let Some(p) = present.iter().next() {
                let mut forged = proof.clone();
                forged.key = *p;
                assert!(!verify_exclusion_proof(&root, p, &forged));
            }
            checked += 1;
        }
        assert!(
            checked > 100,
            "expected many absent keys to check, got {checked}"
        );
    }

    #[test]
    fn test_exclusion_proof_covers_divergence_inside_a_skipped_prefix() {
        // Two keys that share a long prefix force a branch with a skipped
        // prefix; an absent key that contradicts that prefix must still get a
        // verifiable exclusion proof.
        let mut trie = CompressedTrie::new();
        let mut a = [0u8; 32];
        a[0] = 0xF0;
        let mut b = [0u8; 32];
        b[0] = 0xF0;
        b[31] = 0x01;
        trie.insert(&a, b"a");
        trie.insert(&b, b"b");
        let root = trie.root_hash();

        // Differs from both inside the shared prefix region.
        let mut missing = [0u8; 32];
        missing[0] = 0x0F;
        let proof = trie
            .generate_exclusion_proof(&missing)
            .expect("exclusion proof");
        assert!(verify_exclusion_proof(&root, &missing, &proof));
        // The divergence really is inside a skipped prefix.
        assert!(matches!(proof.divergence, Some(Divergence::Branch { .. })));
    }

    #[test]
    fn test_exclusion_proof_rejects_a_tampered_divergence() {
        // Two keys that share a long prefix force a branch with a skipped
        // prefix, so the divergence happens INSIDE that prefix. Claiming it
        // happened at the leaf instead must not verify.
        let mut trie = CompressedTrie::new();
        let mut a = [0u8; 32];
        a[0] = 0xF0;
        let mut b = [0u8; 32];
        b[0] = 0xF0;
        b[31] = 0x01;
        trie.insert(&a, b"a");
        trie.insert(&b, b"b");
        let root = trie.root_hash();

        let mut missing = [0u8; 32];
        missing[0] = 0x0F;
        let proof = trie
            .generate_exclusion_proof(&missing)
            .expect("exclusion proof");
        assert!(matches!(proof.divergence, Some(Divergence::Branch { .. })));

        let mut forged = proof.clone();
        forged.divergence = Some(Divergence::Leaf);
        assert!(!verify_exclusion_proof(&root, &missing, &forged));

        // Pointing the divergence at a step that does not exist must not
        // verify either.
        let mut forged = proof.clone();
        forged.divergence = Some(Divergence::Branch { step: 5 });
        assert!(!verify_exclusion_proof(&root, &missing, &forged));
    }

    #[test]
    fn test_proof_parsing_rejects_malformed_nodes() {
        assert!(MerkleProof::from_nodes(&[]).is_err());
        assert!(MerkleProof::from_nodes(&["zz".to_string()]).is_err());
        assert!(MerkleProof::from_nodes(&["00".to_string()]).is_err());
        // A valid leaf node with a truncated body.
        let mut trie = CompressedTrie::new();
        let k = [0x11u8; 32];
        trie.insert(&k, b"v");
        let proof = trie.generate_proof(&k).expect("proof");
        let mut nodes = proof.to_nodes();
        nodes[0] = nodes[0][..20].to_string();
        assert!(MerkleProof::from_nodes(&nodes).is_err());
    }

    #[test]
    fn test_leaf_format_encoding_and_decoding_roundtrip() {
        // Legacy 16-byte leaf
        let legacy = AccountLeaf::new_unpinned(100_000_000, 42);
        let bytes_16 = legacy.encode();
        assert_eq!(bytes_16.len(), ACCOUNT_LEAF_LEN_LEGACY);
        let decoded_16 = AccountLeaf::decode(&bytes_16).unwrap();
        assert_eq!(decoded_16, legacy);

        // Post-quantum 49-byte leaf
        let pk_hash = [0x55u8; 32];
        let pq = AccountLeaf::new_pinned(250_000_000, 7, 2, pk_hash);
        let bytes_49 = pq.encode();
        assert_eq!(bytes_49.len(), ACCOUNT_LEAF_LEN_PQ);
        let decoded_49 = AccountLeaf::decode(&bytes_49).unwrap();
        assert_eq!(decoded_49, pq);

        // Fixed 49-byte encoding
        let enc49 = pq.encode_49();
        assert_eq!(enc49.len(), 49);
        assert_eq!(&enc49[..], bytes_49.as_slice());
    }

    #[test]
    fn test_trie_handles_49_byte_leaf_and_commitments() {
        let mut trie = CompressedTrie::new();
        let k1: Key = [0x11; 32];
        let k2: Key = [0x22; 32];
        let k3_commitment: Key = [0xcc; 32];

        // 16-byte dormant leaf
        let leaf_16 = AccountLeaf::new_unpinned(1_000, 0).encode();
        // 49-byte PQ pinned leaf
        let leaf_49 = AccountLeaf::new_pinned(2_000, 1, 2, [0xaa; 32]).encode();
        // 32-byte consensus commitment
        let commitment_32 = [0x77u8; COMMITMENT_LEAF_LEN];

        trie.insert(&k1, &leaf_16);
        trie.insert(&k2, &leaf_49);
        trie.insert(&k3_commitment, &commitment_32);

        assert_eq!(trie.len(), 3);
        assert_eq!(trie.get(&k1), Some(leaf_16.as_slice()));
        assert_eq!(trie.get(&k2), Some(leaf_49.as_slice()));
        assert_eq!(trie.get(&k3_commitment), Some(commitment_32.as_slice()));

        let root = trie.root_hash();
        assert_ne!(root, [0u8; 32]);

        // Merkle proofs for 49-byte leaf
        let p_49 = trie.proof(&k2).unwrap();
        assert!(CompressedTrie::verify(&root, &k2, &leaf_49, &p_49));

        // Merkle proofs for 32-byte commitment
        let p_comm = trie.proof(&k3_commitment).unwrap();
        assert!(CompressedTrie::verify(
            &root,
            &k3_commitment,
            &commitment_32,
            &p_comm
        ));

        // Merkle proof for 16-byte legacy leaf
        let p_16 = trie.proof(&k1).unwrap();
        assert!(CompressedTrie::verify(&root, &k1, &leaf_16, &p_16));
    }

    #[test]
    fn test_remove_single_key_makes_trie_empty() {
        let mut trie = CompressedTrie::new();
        let k: Key = [0x11; 32];
        trie.insert(&k, b"hello");
        assert_eq!(trie.len(), 1);
        assert_eq!(trie.remove(&k), Some(b"hello".to_vec()));
        assert_eq!(trie.len(), 0);
        assert!(trie.is_empty());
        assert_eq!(trie.root_hash(), [0u8; 32]);
        assert_eq!(trie.get(&k), None);
    }

    #[test]
    fn test_remove_branch_collapses_to_leaf() {
        let mut trie = CompressedTrie::new();
        let k1: Key = [0x00; 32];
        let mut k2: Key = [0x00; 32];
        k2[0] = 0x80;

        trie.insert(&k1, b"val1");
        trie.insert(&k2, b"val2");
        assert_eq!(trie.len(), 2);

        // Remove k1, branch should collapse to Leaf(k2)
        assert_eq!(trie.remove(&k1), Some(b"val1".to_vec()));
        assert_eq!(trie.len(), 1);
        assert_eq!(trie.get(&k2), Some(b"val2".as_slice()));
        assert_eq!(trie.get(&k1), None);

        // Hash should match a fresh trie with only k2
        let mut trie_k2 = CompressedTrie::new();
        trie_k2.insert(&k2, b"val2");
        assert_eq!(trie.root_hash(), trie_k2.root_hash());
    }

    #[test]
    fn test_remove_branch_collapses_to_branch_with_extended_skip() {
        let mut trie = CompressedTrie::new();
        let mut k1: Key = [0x00; 32];
        k1[0] = 0x80;
        let mut k2: Key = [0x00; 32];
        k2[1] = 0x00;
        let mut k3: Key = [0x00; 32];
        k3[1] = 0x80;

        trie.insert(&k1, b"val1");
        trie.insert(&k2, b"val2");
        trie.insert(&k3, b"val3");

        assert_eq!(trie.remove(&k1), Some(b"val1".to_vec()));
        assert_eq!(trie.len(), 2);

        let mut fresh = CompressedTrie::new();
        fresh.insert(&k2, b"val2");
        fresh.insert(&k3, b"val3");
        assert_eq!(trie.root_hash(), fresh.root_hash());

        let r = trie.root_hash();
        let p2 = trie.proof(&k2).unwrap();
        assert!(CompressedTrie::verify(&r, &k2, b"val2", &p2));
        let p3 = trie.proof(&k3).unwrap();
        assert!(CompressedTrie::verify(&r, &k3, b"val3", &p3));
    }

    // ------------------------------------------------------------------
    // Differential test: in-place `remove` vs a from-scratch rebuild
    // ------------------------------------------------------------------

    /// Rebuild a trie from scratch out of `(key, value)` pairs.
    fn rebuild(entries: &[(Key, Vec<u8>)]) -> CompressedTrie {
        let mut t = CompressedTrie::new();
        for (k, v) in entries {
            t.insert(k, v);
        }
        t
    }

    /// THE property the in-place `remove` must satisfy (audit W6.6, item 6):
    /// removing a key must leave the trie in EXACTLY the state a from-scratch
    /// rebuild of the remaining keys produces - same root hash, same proofs.
    ///
    /// The root hash commits to every branch's `skip`, so a wrong relative-skip
    /// arithmetic in `collapse` (a branch collapsing into a BRANCH rather than
    /// into a leaf) changes the hash of accounts that were NOT touched - the
    /// worst possible failure mode for a state root. This test asserts the
    /// equality after EVERY removal, for random tries with random key shapes
    /// (fully random keys, keys sharing long prefixes, keys sharing only a
    /// suffix), so both the leaf-collapse and the branch-collapse paths are
    /// exercised.
    #[test]
    fn test_remove_is_differential_against_rebuild() {
        let mut rng = Rng(0xD1FF_EE01_2345_6789);
        for round in 0..64u64 {
            let n = 1 + (rng.next() % 40) as usize;
            // Three key shapes, cycled per round:
            //   0 -> fully random keys (deep, bushy tries)
            //   1 -> keys sharing a long prefix (deep chains, long skips)
            //   2 -> keys sharing only a suffix (shallow top, deep bottom)
            let shape = round % 3;
            let mut entries: Vec<(Key, Vec<u8>)> = Vec::with_capacity(n);
            for i in 0..n {
                let mut k = rng.key();
                match shape {
                    1 => {
                        k[0] = 0xAB;
                        k[1] = 0xCD;
                        k[2] = (i % 4) as u8;
                    }
                    2 => {
                        k[0] = (i % 8) as u8;
                        k[30] = 0x5A;
                        k[31] = 0x5A;
                    }
                    _ => {}
                }
                let v = vec![(rng.next() & 0xff) as u8; 1 + (rng.next() % 8) as usize];
                entries.push((k, v));
            }
            // De-duplicate (a repeated key would just overwrite).
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            entries.dedup_by(|a, b| a.0 == b.0);

            let mut trie = rebuild(&entries);
            assert_eq!(trie.root_hash(), rebuild(&entries).root_hash());

            // Removal order: a deterministic shuffle of the key indices.
            let mut order: Vec<usize> = (0..entries.len()).collect();
            for i in (1..order.len()).rev() {
                let j = (rng.next() % (i as u64 + 1)) as usize;
                order.swap(i, j);
            }

            let mut live: Vec<(Key, Vec<u8>)> = entries.clone();
            for &idx in &order {
                let (k, v) = &entries[idx];
                assert_eq!(
                    trie.remove(k).as_deref(),
                    Some(v.as_slice()),
                    "remove must return the removed value"
                );
                live.retain(|(lk, _)| lk != k);

                let fresh = rebuild(&live);
                assert_eq!(
                    trie.root_hash(),
                    fresh.root_hash(),
                    "in-place remove diverged from a rebuild (round {round}, shape {shape}, left {})",
                    live.len()
                );

                // Every SURVIVING key must still prove against the (new) root.
                let root = trie.root_hash();
                for (lk, lv) in &live {
                    let p = trie
                        .proof(lk)
                        .unwrap_or_else(|| panic!("proof must exist for {lk:02x?}"));
                    assert!(
                        CompressedTrie::verify(&root, lk, lv, &p),
                        "proof for a surviving key broke after a removal"
                    );
                    let fp = fresh
                        .proof(lk)
                        .unwrap_or_else(|| panic!("rebuild proof must exist"));
                    assert_eq!(
                        p.path, fp.path,
                        "the proof path of a surviving key differs from the rebuild"
                    );
                    // The value must still be readable.
                    assert_eq!(trie.get(lk), Some(lv.as_slice()));
                }
                assert_eq!(trie.len(), live.len());
            }
            assert!(trie.is_empty());
            assert_eq!(trie.root_hash(), [0u8; 32]);
        }
    }

    /// The same differential property, but the removals are applied to a trie
    /// that was built in a RANDOM insertion order (the trie structure depends
    /// on the insertion order, so this covers shapes the sorted rebuild does
    /// not).
    #[test]
    fn test_remove_is_differential_against_rebuild_random_insert_order() {
        let mut rng = Rng(0x1234_5678_9ABC_DEF0);
        for round in 0..32u64 {
            let n = 2 + (rng.next() % 30) as usize;
            let mut entries: Vec<(Key, Vec<u8>)> = Vec::new();
            for _ in 0..n {
                let mut k = rng.key();
                // Force some collisions in the first bytes so the tries have
                // real branch structure instead of a flat fan-out.
                k[0] &= 0x0F;
                let v = vec![(rng.next() & 0xff) as u8; 4];
                entries.push((k, v));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            entries.dedup_by(|a, b| a.0 == b.0);
            if entries.len() < 2 {
                continue;
            }

            // Insert in a shuffled order.
            let mut ins: Vec<usize> = (0..entries.len()).collect();
            for i in (1..ins.len()).rev() {
                let j = (rng.next() % (i as u64 + 1)) as usize;
                ins.swap(i, j);
            }
            let mut trie = CompressedTrie::new();
            for &i in &ins {
                trie.insert(&entries[i].0, &entries[i].1);
            }
            let mut live: Vec<(Key, Vec<u8>)> = entries.clone();

            for &idx in &ins {
                let (k, _) = &entries[idx];
                trie.remove(k);
                live.retain(|(lk, _)| lk != k);
                let fresh = rebuild(&live);
                assert_eq!(
                    trie.root_hash(),
                    fresh.root_hash(),
                    "in-place remove diverged from a rebuild (round {round})"
                );
                let root = trie.root_hash();
                for (lk, lv) in &live {
                    let p = trie.proof(lk).expect("proof");
                    assert!(CompressedTrie::verify(&root, lk, lv, &p));
                }
            }
        }
    }

    #[test]
    fn test_remove_random_keys_matches_fresh_trie() {
        let mut trie = CompressedTrie::new();
        let mut keys = Vec::new();
        for i in 0..100u8 {
            let mut k = [0u8; 32];
            k[0] = i;
            k[1] = i.wrapping_mul(7);
            k[2] = i.wrapping_mul(13);
            let v = vec![i; 32];
            trie.insert(&k, &v);
            keys.push((k, v));
        }

        for (k, ref_v) in keys.iter().take(50) {
            let removed = trie.remove(k);
            assert_eq!(removed.as_ref(), Some(ref_v));
        }
        assert_eq!(trie.len(), 50);

        let mut fresh = CompressedTrie::new();
        for (k, v) in keys.iter().take(100).skip(50) {
            fresh.insert(k, v);
        }

        assert_eq!(trie.root_hash(), fresh.root_hash());

        let r = trie.root_hash();
        for (k, v) in keys.iter().take(100).skip(50) {
            let p = trie.proof(k).expect("proof must exist");
            assert!(CompressedTrie::verify(&r, k, v, &p));
        }
    }

    // ------------------------------------------------------------------
    // Archive proofs
    // ------------------------------------------------------------------

    fn archive_trie() -> (CompressedTrie, H, Key, Vec<u8>, Key) {
        let mut trie = CompressedTrie::new();
        let present = [0xABu8; 32];
        let value = b"archive-value".to_vec();
        trie.insert(&present, &value);
        trie.insert(&[0xCDu8; 32], b"neighbour");
        let missing = [0xEEu8; 32];
        let root = trie.root_hash();
        (trie, root, present, value, missing)
    }

    #[test]
    fn test_archive_proof_inclusion_verifies() {
        let (trie, root, present, value, _) = archive_trie();
        let proof = trie.generate_proof(&present).expect("inclusion proof");
        let archive = ArchiveProof::inclusion(41, root, present, &proof).expect("archive proof");
        assert_eq!(archive.proof_type, ArchiveProofType::Inclusion);
        assert_eq!(archive.height, 41);
        assert_eq!(archive.state_root, root);
        assert_eq!(archive.value.as_deref(), Some(&value[..]));
        assert!(archive.verify());
    }

    #[test]
    fn test_archive_proof_exclusion_verifies() {
        let (trie, root, _, _, missing) = archive_trie();
        let proof = trie
            .generate_exclusion_proof(&missing)
            .expect("exclusion proof");
        let archive = ArchiveProof::exclusion(41, root, missing, &proof).expect("archive proof");
        assert_eq!(archive.proof_type, ArchiveProofType::Exclusion);
        assert_eq!(archive.value, None);
        assert!(archive.verify());
    }

    #[test]
    fn test_archive_proof_rejects_tampering() {
        let (trie, root, present, _, missing) = archive_trie();
        let proof = trie.generate_proof(&present).expect("inclusion proof");
        let mut archive =
            ArchiveProof::inclusion(41, root, present, &proof).expect("archive proof");

        // Wrong root: the proof is not about that state.
        archive.state_root = [0xFFu8; 32];
        assert!(!archive.verify());
        archive.state_root = root;

        // Wrong value: the leaf the proof commits to differs.
        archive.value = Some(b"something-else".to_vec());
        assert!(!archive.verify());

        // Inclusion proof relabeled as exclusion must not verify.
        let mut relabeled =
            ArchiveProof::inclusion(41, root, present, &proof).expect("archive proof");
        relabeled.proof_type = ArchiveProofType::Exclusion;
        relabeled.value = None;
        assert!(!relabeled.verify());

        // An exclusion proof served as an inclusion proof must not verify.
        let excl = trie
            .generate_exclusion_proof(&missing)
            .expect("exclusion proof");
        let mut forged = ArchiveProof::exclusion(41, root, missing, &excl).expect("archive proof");
        forged.proof_type = ArchiveProofType::Inclusion;
        forged.value = Some(b"made-up".to_vec());
        assert!(!forged.verify());

        // Garbage nodes fail closed.
        let mut broken = ArchiveProof::inclusion(41, root, present, &proof).expect("archive proof");
        broken.proof_nodes = vec!["zz".to_string()];
        assert!(!broken.verify());
    }

    #[test]
    fn test_archive_proof_json_roundtrip() {
        let (trie, root, present, value, missing) = archive_trie();
        let incl = ArchiveProof::inclusion(
            41,
            root,
            present,
            &trie.generate_proof(&present).expect("inclusion proof"),
        )
        .expect("archive proof");
        let parsed = ArchiveProof::from_json(&incl.to_json()).expect("parse");
        assert_eq!(parsed, incl);
        assert!(parsed.verify());
        assert_eq!(parsed.value.as_deref(), Some(&value[..]));

        let excl = ArchiveProof::exclusion(
            41,
            root,
            missing,
            &trie
                .generate_exclusion_proof(&missing)
                .expect("exclusion proof"),
        )
        .expect("archive proof");
        let parsed_excl = ArchiveProof::from_json(&excl.to_json()).expect("parse");
        assert_eq!(parsed_excl, excl);
        assert!(parsed_excl.verify());

        // Malformed JSON fails closed, never as an empty proof.
        assert!(ArchiveProof::from_json(&serde_json::json!({})).is_err());
        assert!(!ArchiveProof::from_json(&serde_json::json!({
            "height": 41u64,
            "state_root": hex::encode(root),
            "key": hex::encode(present),
            "value": hex::encode(&value),
            "proof": [],
            "proof_type": "inclusion",
        }))
        .map(|p| p.verify())
        .unwrap_or(false));
    }
}
