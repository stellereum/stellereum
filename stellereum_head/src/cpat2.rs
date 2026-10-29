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

use std::collections::HashMap;

pub type Key = [u8; 32];
pub type H = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Leaf(Key, Vec<u8>),
    Branch { skip: u16, bit: u8, left: Box<Node>, right: Box<Node>, hash: H },
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
    if d >= 256 { return 0; }
    (k[d / 8] >> (7 - (d % 8))) & 1
}

/// Length of common prefix of two keys from absolute depth `from`.
fn common(a: &Key, b: &Key, from: usize) -> usize {
    let mut d = from;
    while d < 256 && bit(a, d) == bit(b, d) { d += 1; }
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
    Node::Branch { skip, bit, left: Box::new(left), right: Box::new(right), hash: h }
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
        Some(Node::Branch { skip, bit: bbit, left, right, hash }) => {
            let bp = depth + skip as usize; // absolute divergence point of this branch
            if bp >= 256 {
                return Node::Branch { skip, bit: bbit, left, right, hash };
            }
            // Does the incoming key match all skipped bits [depth, bp)?
            let cp_skip = common_prefix_len(&key, left.as_ref(), right.as_ref(), depth, skip as usize);
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

#[derive(Clone, Debug, Default)]
pub struct CompressedTrie {
    root: Option<Node>,
    pub entries: HashMap<Key, Vec<u8>>,
}

impl CompressedTrie {
    pub fn new() -> Self {
        Self { root: None, entries: HashMap::new() }
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
        let all: Vec<(Key, Vec<u8>)> = self.entries.iter().map(|(k, v)| (*k, v.clone())).collect();
        self.root = None;
        for (k, val) in all {
            let r = self.root.take();
            self.root = Some(insert(r, k, val, 0));
        }
        Some(v)
    }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
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
                Node::Branch { skip, bit: bbit, left, right, .. } => {
                    let bp = depth + *skip as usize;
                    if bp >= 256 {
                        return None;
                    }
                    // verify skipped bits match
                    if common_prefix_len(key, left, right, depth, *skip as usize) < *skip as usize {
                        return None;
                    }
                    let go_right = bit(key, bp) == 1;
                    let (sib, sib_right) = if go_right { (left, false) } else { (right, true) };
                    path.push(Step { sibling_right: sib_right, sibling_hash: node_hash(sib), skip: *skip, bit: *bbit });
                    node = if go_right { right } else { left };
                    depth = bp + 1;
                }
            }
        }
    }

    pub fn proof(&self, key: &Key) -> Option<Proof> {
        let (path, lh) = self.walk(key)?;
        Some(Proof { key: *key, path, leaf_hash: lh })
    }

    pub fn verify(root: &H, key: &Key, value: &[u8], p: &Proof) -> bool {
        if &p.key != key { return false; }
        let lh = leaf_hash(key, value);
        if p.leaf_hash != lh { return false; }
        let mut cur = lh;
        for s in &p.path {
            let (l, r) = if s.sibling_right { (cur, s.sibling_hash) } else { (s.sibling_hash, cur) };
            cur = branch_hash(s.skip, s.bit, &l, &r);
        }
        &cur == root
    }
}

/// Canonical length of a legacy / dormant account leaf (balance: 8B || nonce: 8B)
pub const ACCOUNT_LEAF_LEN_LEGACY: usize = 16;

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
        assert!(CompressedTrie::verify(&root, &k3_commitment, &commitment_32, &p_comm));

        // Merkle proof for 16-byte legacy leaf
        let p_16 = trie.proof(&k1).unwrap();
        assert!(CompressedTrie::verify(&root, &k1, &leaf_16, &p_16));
    }
}
