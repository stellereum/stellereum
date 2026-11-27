//! Clean-room `cpat2` Merkle proofs and non-trie commitment digests.
//!
//! This module is deliberately independent of `stellereum`: it re-derives the
//! compressed-Patricia-trie v2 node hashing, the inclusion/exclusion proof
//! walk, the trie key that carries the non-trie commitment, and the canonical
//! domain assembly used by the `CommitmentSnapshot` v5 digest.
//!
//! # `cpat2` hashing
//!
//! ```text
//! Leaf:   BLAKE3("L" || key[32] || len_le_u32(value) || value)
//! Branch: BLAKE3("B" || skip_be_u16 || (bit & 1) || left[32] || right[32])
//! Empty:  [0u8; 32]                       (an empty trie has no root hash)
//! ```
//!
//! A proof path is ordered leaf → root. At each step the folded node is the
//! left child when the sibling is on the right, and vice versa. The path's
//! every turn must follow the queried key's own bit at the branch position,
//! and the branch positions must stay below bit 256.
//!
//! # Commitment digest
//!
//! [`VerifierCommitmentSnapshot`] does not re-implement the per-subsystem
//! state serializers (tokens, staking, PMM, …); those belong to the state
//! engine that owns the state. It consumes the *already captured* per-domain
//! preimage bytes and applies the exact top-level framing that
//! `stellereum::commitment::commitment_digest` applies:
//!
//! ```text
//! SHA-256(
//!     put_u64("COMMITMENT_VERSION", version) ||
//!     tokens || staking || pmm || contracts || escrow || governance ||
//!     oracle || session_keys || books || bridge || cross_shard || xpc ||
//!     zkml || cnvrf || [put_u64("total_minted_nano", n) if n != 0] ||
//!     evm_bindings || pq_registry
//! )
//! ```
//!
//! where each domain blob contributes zero bytes when its subsystem is empty
//! (the conditional `session_keys` / `bridge` / `cross_shard` / `xpc` rule is
//! therefore expressed by passing an empty blob). `put_u64` is the tagged
//! framing `len_be_u64(tag) || tag || len_be_u64(8) || value_be_u64`.
//!
//! This split is the honest boundary for an independent verifier: the digest
//! *assembly* is consensus-critical and is verified here bit-for-bit, while
//! the domain preimages are a deterministic function of state that the
//! verifier is handed. A caller that recomputes those preimages from its own
//! state engine does not need this crate to trust the node it is checking.

use sha2::{Digest, Sha256};

use crate::VerifyError;

/// Maximum number of branch points a genuine 32-byte key path can contain.
pub const MAX_PROOF_STEPS: usize = 256;

/// Domain separator of the trie key that carries the non-trie commitment.
pub const COMMITMENT_KEY_DOMAIN: &[u8] = b"STELL_CONSENSUS_COMMITMENT_V1";

/// Version of the `CommitmentSnapshot` framing implemented here.
pub const COMMITMENT_VERSION: u32 = 5;

/// Root hash of an empty trie (`CompressedTrie::root_hash` returns zeroes).
pub const EMPTY_ROOT: [u8; 32] = [0u8; 32];

/// The single trie key under which the non-trie commitment digest is stored.
pub fn commitment_key() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMITMENT_KEY_DOMAIN);
    h.finalize().into()
}

/// Leaf hash: `BLAKE3("L" || key || len_le_u32(value) || value)`.
pub fn leaf_hash(key: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let mut header = [0u8; 37];
    header[0] = b'L';
    header[1..33].copy_from_slice(key);
    header[33..37].copy_from_slice(&(value.len() as u32).to_le_bytes());
    let mut h = blake3::Hasher::new();
    h.update(&header);
    h.update(value);
    *h.finalize().as_bytes()
}

/// Branch hash: `BLAKE3("B" || skip_be_u16 || (bit & 1) || left || right)`.
pub fn branch_hash(skip: u16, bit: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 68];
    buf[0] = b'B';
    buf[1..3].copy_from_slice(&skip.to_be_bytes());
    buf[3] = bit & 1;
    buf[4..36].copy_from_slice(left);
    buf[36..68].copy_from_slice(right);
    *blake3::hash(&buf).as_bytes()
}

/// Bit `depth` of a key, most-significant-bit first. Depths past 256 read 0.
pub fn key_bit(key: &[u8; 32], depth: usize) -> u8 {
    if depth >= 256 {
        return 0;
    }
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

/// Length in bits of the common prefix of two keys, starting at `from`.
pub fn common_prefix_len(a: &[u8; 32], b: &[u8; 32], from: usize) -> usize {
    if from >= 256 {
        return 256;
    }
    let off = from % 8;
    let mut i = from / 8;
    let x = (a[i] ^ b[i]) & (0xFFu8 >> off);
    if x != 0 {
        return i * 8 + x.leading_zeros() as usize;
    }
    i += 1;
    while i < 32 {
        let x = a[i] ^ b[i];
        if x != 0 {
            return i * 8 + x.leading_zeros() as usize;
        }
        i += 1;
    }
    256
}

/// One branch step on the leaf → root path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub sibling_right: bool,
    pub sibling_hash: [u8; 32],
    pub skip: u16,
    pub bit: u8,
}

/// Whether a proof claims presence or absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    Inclusion,
    Exclusion,
}

/// Where a queried key diverges from the exclusion witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Divergence {
    /// The path ends at the witness leaf.
    Leaf,
    /// The queried key contradicts a branch's skipped prefix. `step` indexes
    /// the leaf → root path.
    Branch { step: usize },
}

/// A `cpat2` proof: inclusion or exclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// The key the proof is about.
    pub key: [u8; 32],
    /// The value of `key` (inclusion) or of the witness leaf (exclusion).
    pub value: Vec<u8>,
    /// Leaf hash the proof authenticates.
    pub leaf_hash: [u8; 32],
    /// Branch steps from the leaf up to the root.
    pub path: Vec<Step>,
    pub kind: ProofKind,
    /// Exclusion only: the witness leaf's key.
    pub witness_key: Option<[u8; 32]>,
    /// Exclusion only: where the queried key diverges.
    pub divergence: Option<Divergence>,
}

/// Wire tag of the proof's leaf node.
const NODE_LEAF: u8 = b'L';
/// Wire tag of a proof branch step.
const NODE_BRANCH: u8 = b'B';
/// Wire flag: inclusion claim.
const KIND_INCLUSION: u8 = 0;
/// Wire flag: exclusion claim.
const KIND_EXCLUSION: u8 = 1;
/// Wire flag: the divergence is at the witness leaf.
const DIVERGENCE_LEAF: u8 = 0;
/// Wire flag: the divergence is inside a branch's skipped prefix.
const DIVERGENCE_BRANCH: u8 = 1;

impl MerkleProof {
    /// Verify an inclusion claim against `root`.
    pub fn verify_inclusion(&self, root: &[u8; 32], key: &[u8; 32], value: &[u8]) -> bool {
        verify_proof(root, key, value, self)
    }

    /// Verify an exclusion claim against `root`.
    pub fn verify_exclusion(&self, root: &[u8; 32], key: &[u8; 32]) -> bool {
        verify_exclusion_proof(root, key, self)
    }

    /// Parse the canonical node encoding `stellereum::cpat2::MerkleProof::to_nodes`
    /// produces: one hex string per node, leaf first.
    ///
    /// This is the wire form `stell_getProof` serves, so an offline verifier
    /// must accept exactly those bytes and no looser encoding. Every length is
    /// validated before it is used, which keeps a hostile proof from making the
    /// parser read out of bounds or allocate without bound.
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
        let divergence_kind = leaf[2];
        let divergence_step = u16::from_be_bytes([leaf[3], leaf[4]]);

        let mut key = [0u8; 32];
        key.copy_from_slice(&leaf[5..37]);
        let mut witness_key = [0u8; 32];
        witness_key.copy_from_slice(&leaf[37..69]);
        let value_len = u32::from_be_bytes([leaf[69], leaf[70], leaf[71], leaf[72]]) as usize;
        if leaf.len() != 73 + value_len + 32 {
            return Err("proof leaf node length does not match its value length".to_string());
        }
        let value = leaf[73..73 + value_len].to_vec();
        let mut leaf_hash = [0u8; 32];
        leaf_hash.copy_from_slice(&leaf[73 + value_len..]);

        let mut path = Vec::with_capacity(nodes.len() - 1);
        for node in &nodes[1..] {
            let branch =
                hex::decode(node).map_err(|_| "proof branch node is not valid hex".to_string())?;
            if branch.len() != 37 {
                return Err("proof branch node has the wrong length".to_string());
            }
            if branch[0] != NODE_BRANCH {
                return Err("proof contains a node that is neither leaf nor branch".to_string());
            }
            let skip = u16::from_be_bytes([branch[1], branch[2]]);
            let bit = branch[3] & 1;
            let sibling_right = branch[4] & 1 == 1;
            let mut sibling_hash = [0u8; 32];
            sibling_hash.copy_from_slice(&branch[5..37]);
            path.push(Step {
                sibling_right,
                sibling_hash,
                skip,
                bit,
            });
        }

        let divergence = match (kind, divergence_kind) {
            (ProofKind::Inclusion, _) => None,
            (ProofKind::Exclusion, DIVERGENCE_LEAF) => Some(Divergence::Leaf),
            (ProofKind::Exclusion, DIVERGENCE_BRANCH) => Some(Divergence::Branch {
                step: divergence_step as usize,
            }),
            (ProofKind::Exclusion, other) => {
                return Err(format!("unknown proof divergence kind {other}"))
            }
        };

        Ok(Self {
            key,
            value,
            leaf_hash,
            path,
            kind,
            witness_key: match kind {
                ProofKind::Exclusion => Some(witness_key),
                ProofKind::Inclusion => None,
            },
            divergence,
        })
    }
}

/// Absolute `(branch_position, depth_before)` of every step, in ROOT → LEAF
/// order. Returns the depth the whole path consumes, or `None` if the path is
/// longer than a 32-byte key can need or descends past bit 256.
fn path_positions(path: &[Step], out: &mut [(u16, u16); MAX_PROOF_STEPS]) -> Option<u16> {
    if path.len() > MAX_PROOF_STEPS {
        return None;
    }
    let mut depth: u32 = 0;
    for (idx, step) in path.iter().rev().enumerate() {
        let bp = depth + step.skip as u32;
        if bp >= 256 {
            return None;
        }
        out[idx] = (bp as u16, depth as u16);
        depth = bp + 1;
    }
    Some(depth as u16)
}

fn path_follows_key_with_positions(
    path: &[Step],
    key: &[u8; 32],
    positions: &[(u16, u16)],
) -> bool {
    for (i, step) in path.iter().enumerate() {
        let (bp, _) = positions[path.len() - 1 - i];
        // A sibling on the right means we descended into the LEFT child (bit 0).
        let expected = if step.sibling_right { 0u8 } else { 1u8 };
        if key_bit(key, bp as usize) != expected {
            return false;
        }
    }
    true
}

fn path_follows_key(path: &[Step], key: &[u8; 32]) -> bool {
    let mut positions = [(0u16, 0u16); MAX_PROOF_STEPS];
    if path_positions(path, &mut positions).is_none() {
        return false;
    }
    path_follows_key_with_positions(path, key, &positions[..path.len()])
}

/// Fold a leaf hash up a leaf → root path.
pub fn fold_path(leaf: &[u8; 32], path: &[Step]) -> [u8; 32] {
    let mut cur = *leaf;
    for step in path {
        let (left, right) = if step.sibling_right {
            (cur, step.sibling_hash)
        } else {
            (step.sibling_hash, cur)
        };
        cur = branch_hash(step.skip, step.bit, &left, &right);
    }
    cur
}

/// Verify that `key == value` is in the trie at `root`.
pub fn verify_proof(root: &[u8; 32], key: &[u8; 32], value: &[u8], proof: &MerkleProof) -> bool {
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

/// Verify that `key` is provably absent from the trie at `root`.
pub fn verify_exclusion_proof(root: &[u8; 32], key: &[u8; 32], proof: &MerkleProof) -> bool {
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
        return false;
    }
    if leaf_hash(&witness, &proof.value) != proof.leaf_hash {
        return false;
    }
    if &fold_path(&proof.leaf_hash, &proof.path) != root {
        return false;
    }
    let mut positions = [(0u16, 0u16); MAX_PROOF_STEPS];
    let leaf_depth = match path_positions(&proof.path, &mut positions) {
        Some(d) => d,
        None => return false,
    };
    let positions = &positions[..proof.path.len()];
    let cp = common_prefix_len(&witness, key, 0);
    match proof.divergence {
        Some(Divergence::Leaf) => {
            if cp < leaf_depth as usize {
                return false;
            }
            path_follows_key_with_positions(&proof.path, key, positions)
        }
        Some(Divergence::Branch { step }) => {
            if step >= proof.path.len() {
                return false;
            }
            let i = proof.path.len() - 1 - step;
            let (bp, depth_before) = positions[i];
            if cp < depth_before as usize || cp >= bp as usize {
                return false;
            }
            for (j, s) in proof.path.iter().enumerate() {
                if j <= step {
                    break;
                }
                let (b, _) = positions[proof.path.len() - 1 - j];
                let expected = if s.sibling_right { 0u8 } else { 1u8 };
                if key_bit(key, b as usize) != expected {
                    return false;
                }
            }
            true
        }
        None => false,
    }
}

/// Verify that a state root commits to `snapshot`'s digest.
///
/// This is the real `state_root` ↔ `CommitmentSnapshot` check the node makes
/// when it folds the non-trie commitment into the trie: the digest of
/// `snapshot` must be the value stored under [`commitment_key`], and `proof`
/// must be a `cpat2` inclusion proof of that exact `key → digest` leaf against
/// `state_root`.
///
/// Returns the digest that was verified, so a caller can print or pin it. Any
/// mismatch — a different digest, a proof for another key or value, a path
/// that does not fold to `state_root`, or an unknown snapshot framing version —
/// is refused.
pub fn verify_state_root_against_snapshot(
    state_root: &[u8; 32],
    snapshot: &VerifierCommitmentSnapshot,
    proof: &MerkleProof,
) -> Result<[u8; 32], VerifyError> {
    if snapshot.version != COMMITMENT_VERSION {
        return Err(VerifyError::Commitment(format!(
            "snapshot framing version {} is not the supported version {COMMITMENT_VERSION}",
            snapshot.version
        )));
    }
    let digest = snapshot.digest();
    let key = commitment_key();
    if proof.kind != ProofKind::Inclusion {
        return Err(VerifyError::Commitment(
            "the commitment leaf proof must be an inclusion proof".to_string(),
        ));
    }
    if proof.key != key {
        return Err(VerifyError::Commitment(format!(
            "proof is for trie key {}, expected the commitment key {}",
            hex::encode(proof.key),
            hex::encode(key)
        )));
    }
    if proof.value != digest {
        return Err(VerifyError::Commitment(format!(
            "proof carries commitment {} but the snapshot digests to {}",
            hex::encode(&proof.value),
            hex::encode(digest)
        )));
    }
    if !verify_proof(state_root, &key, &digest, proof) {
        return Err(VerifyError::Commitment(format!(
            "commitment leaf {} -> {} does not fold to state root {}",
            hex::encode(key),
            hex::encode(digest),
            hex::encode(state_root)
        )));
    }
    Ok(digest)
}

/// Verify that `state_root` is exactly the `cpat2` root built from the supplied
/// trie leaves plus the `commitment_key() -> digest` leaf.
///
/// `account_leaves` must contain every trie leaf that is not the commitment
/// leaf — account records and the namespaced derived keys (token balances,
/// contract code, …) alike. Supplying only account addresses proves the root
/// of a smaller trie, which will (correctly) not match. Supplying the
/// commitment key is refused: its value is derived from `snapshot` here, never
/// trusted from the caller, so the digest cannot be chosen independently of
/// the state it claims to commit.
///
/// The leaf set is sorted by key and folded with the same compressed-Patricia
/// rule the node uses: branches sit at the longest common prefix of each key
/// subset, left = bit 0, right = bit 1, and each branch hash carries its
/// relative skip. A duplicate key is refused rather than silently overwritten,
/// because two values for one key cannot both be the trie's leaf.
pub fn verify_state_root_full(
    state_root: &[u8; 32],
    snapshot: &VerifierCommitmentSnapshot,
    account_leaves: &[([u8; 32], Vec<u8>)],
) -> Result<(), VerifyError> {
    if snapshot.version != COMMITMENT_VERSION {
        return Err(VerifyError::Commitment(format!(
            "snapshot framing version {} is not the supported version {COMMITMENT_VERSION}",
            snapshot.version
        )));
    }
    let digest = snapshot.digest();
    let key = commitment_key();

    let mut leaves: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(account_leaves.len() + 1);
    for (leaf_key, value) in account_leaves {
        if *leaf_key == key {
            return Err(VerifyError::Commitment(
                "account leaves must not include the commitment key; its value is derived from the snapshot"
                    .to_string(),
            ));
        }
        leaves.push((*leaf_key, leaf_hash(leaf_key, value)));
    }
    leaves.push((key, leaf_hash(&key, &digest)));
    leaves.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    if leaves.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(VerifyError::Commitment(
            "duplicate trie key in the supplied leaf set".to_string(),
        ));
    }

    let rebuilt = build_root(&leaves)?;
    if &rebuilt != state_root {
        return Err(VerifyError::Commitment(format!(
            "rebuilt trie root {} does not match state root {}",
            hex::encode(rebuilt),
            hex::encode(state_root)
        )));
    }
    Ok(())
}

/// Root hash of a key-sorted, duplicate-free leaf set.
fn build_root(leaves: &[([u8; 32], [u8; 32])]) -> Result<[u8; 32], VerifyError> {
    if leaves.is_empty() {
        return Ok(EMPTY_ROOT);
    }
    build_subtree(leaves, 0)
}

/// Recursively fold a sorted leaf slice whose keys share every bit before
/// `depth`.
///
/// The subtree's branch point is the longest common prefix of the smallest and
/// largest key (equal to the common prefix of the whole sorted slice). Keys are
/// partitioned on that bit: bit 0 goes left, bit 1 goes right, which is exactly
/// how the node's insert splits a leaf set.
fn build_subtree(leaves: &[([u8; 32], [u8; 32])], depth: usize) -> Result<[u8; 32], VerifyError> {
    if leaves.len() == 1 {
        return Ok(leaves[0].1);
    }
    let first = &leaves[0].0;
    let last = &leaves[leaves.len() - 1].0;
    let branch_position = common_prefix_len(first, last, depth);
    if branch_position >= 256 {
        return Err(VerifyError::Commitment(
            "two distinct trie leaves share all 256 key bits".to_string(),
        ));
    }
    if branch_position < depth {
        return Err(VerifyError::Commitment(
            "leaf set is not sorted by key".to_string(),
        ));
    }
    let split = leaves.partition_point(|(leaf_key, _)| key_bit(leaf_key, branch_position) == 0);
    if split == 0 || split == leaves.len() {
        return Err(VerifyError::Commitment(
            "leaf set does not split at its common prefix".to_string(),
        ));
    }
    let skip = (branch_position - depth) as u16;
    let left = build_subtree(&leaves[..split], branch_position + 1)?;
    let right = build_subtree(&leaves[split..], branch_position + 1)?;
    Ok(branch_hash(skip, 0, &left, &right))
}

/// Tagged preimage write shared by the commitment framing.
fn put_bytes(h: &mut Sha256, tag: &[u8], bytes: &[u8]) {
    h.update((tag.len() as u64).to_be_bytes());
    h.update(tag);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn put_u64(h: &mut Sha256, tag: &[u8], value: u64) {
    put_bytes(h, tag, &value.to_be_bytes());
}

/// Per-domain preimages of the non-trie consensus state.
///
/// Each `Vec<u8>` is the exact byte stream the corresponding domain contributes
/// to `commitment_digest` (for example
/// `stellereum::commitment::tokens_preimage(&snapshot.tokens)`). An empty
/// subsystem must be an empty blob: the conditional domains write zero bytes
/// rather than a zero length prefix, which is what keeps pre-feature digests
/// byte-identical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierCommitmentSnapshot {
    /// Framing version (5 for the current `CommitmentSnapshot`).
    pub version: u32,
    pub tokens: Vec<u8>,
    pub staking: Vec<u8>,
    pub pmm: Vec<u8>,
    pub contracts: Vec<u8>,
    pub escrow: Vec<u8>,
    pub governance: Vec<u8>,
    pub oracle: Vec<u8>,
    /// Zero bytes when no session key has ever been registered.
    pub session_keys: Vec<u8>,
    pub books: Vec<u8>,
    /// Zero bytes when the bridge domain is empty.
    pub bridge: Vec<u8>,
    /// Zero bytes when every cross-shard replay set is empty.
    pub cross_shard: Vec<u8>,
    /// Zero bytes when no 2PC record exists.
    pub xpc: Vec<u8>,
    /// Zero bytes when the zkML model & VK registries are empty.
    pub zkml: Vec<u8>,
    /// Zero bytes when the CN-VRF v3 state, abort counters, and epoch beacons are empty.
    pub cnvrf: Vec<u8>,
    /// Global minted supply counter (contributes zero bytes when `0`).
    pub total_minted_nano: u64,
    /// Zero bytes when the canonical EVM bindings domain is empty.
    pub evm_bindings: Vec<u8>,
    /// Zero bytes when the canonical PQ key registry domain is empty.
    pub pq_registry: Vec<u8>,
}

impl Default for VerifierCommitmentSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierCommitmentSnapshot {
    /// An all-empty snapshot at the current framing version.
    pub fn new() -> Self {
        Self {
            version: COMMITMENT_VERSION,
            tokens: Vec::new(),
            staking: Vec::new(),
            pmm: Vec::new(),
            contracts: Vec::new(),
            escrow: Vec::new(),
            governance: Vec::new(),
            oracle: Vec::new(),
            session_keys: Vec::new(),
            books: Vec::new(),
            bridge: Vec::new(),
            cross_shard: Vec::new(),
            xpc: Vec::new(),
            zkml: Vec::new(),
            cnvrf: Vec::new(),
            total_minted_nano: 0,
            evm_bindings: Vec::new(),
            pq_registry: Vec::new(),
        }
    }

    /// `SHA-256` over the canonical domain sequence, matching
    /// `stellereum::commitment::commitment_digest_with_all_domains` byte-for-byte.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        put_u64(&mut h, b"COMMITMENT_VERSION", self.version as u64);
        h.update(&self.tokens);
        h.update(&self.staking);
        h.update(&self.pmm);
        h.update(&self.contracts);
        h.update(&self.escrow);
        h.update(&self.governance);
        h.update(&self.oracle);
        h.update(&self.session_keys);
        h.update(&self.books);
        h.update(&self.bridge);
        h.update(&self.cross_shard);
        h.update(&self.xpc);
        h.update(&self.zkml);
        h.update(&self.cnvrf);
        if self.total_minted_nano != 0 {
            put_u64(&mut h, b"total_minted_nano", self.total_minted_nano);
        }
        h.update(&self.evm_bindings);
        h.update(&self.pq_registry);
        h.finalize().into()
    }
}
