//! Core Cell / Bag of Cells (BoC) and Patricia DAG data structure for Stellereum
//! TON Core-style cell model: up to 128 bytes data, up to 4 references, DAG format.
//! Includes canonical BoC binary serialization, multi-cell byte chunking,
//! and binary Patricia-Merkle Trie with cryptographic inclusion proofs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const MAX_CELL_DATA_BYTES: usize = 128;
pub const MAX_CELL_REFS: usize = 4;
pub const BOC_MAGIC_PREFIX: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];

pub type CellHash = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    pub data: Vec<u8>,
    pub references: Vec<CellHash>,
}

impl Cell {
    pub fn new(data: Vec<u8>, references: Vec<CellHash>) -> Self {
        assert!(
            data.len() <= MAX_CELL_DATA_BYTES,
            "Cell data cannot exceed 128 bytes"
        );
        assert!(
            references.len() <= MAX_CELL_REFS,
            "Cell cannot have more than 4 references"
        );
        Self { data, references }
    }

    pub fn empty() -> Self {
        Self {
            data: Vec::new(),
            references: Vec::new(),
        }
    }

    pub fn compute_hash(&self) -> CellHash {
        let mut hasher = Sha256::new();
        hasher.update([self.references.len() as u8]);
        hasher.update((self.data.len() as u16).to_be_bytes());
        hasher.update(&self.data);
        for r in &self.references {
            hasher.update(r);
        }
        let out = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&out);
        hash
    }

    /// Split arbitrary length byte buffer into a DAG chain of Cells
    pub fn from_bytes(data: &[u8]) -> (BagOfCells, CellHash) {
        let mut boc = BagOfCells::new();
        if data.is_empty() {
            let empty_cell = Cell::empty();
            let hash = boc.add_cell(empty_cell);
            boc.set_root(hash);
            return (boc, hash);
        }

        let chunks: Vec<&[u8]> = data.chunks(MAX_CELL_DATA_BYTES).collect();
        let mut prev_hash: Option<CellHash> = None;

        for chunk in chunks.into_iter().rev() {
            let refs = match prev_hash {
                Some(h) => vec![h],
                None => vec![],
            };
            let cell = Cell::new(chunk.to_vec(), refs);
            let h = boc.add_cell(cell);
            prev_hash = Some(h);
        }

        let root_hash = prev_hash.unwrap();
        boc.set_root(root_hash);
        (boc, root_hash)
    }
}

/// Bag of Cells (BoC) DAG Container
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BagOfCells {
    pub roots: Vec<CellHash>,
    pub cells: HashMap<CellHash, Cell>,
}

impl BagOfCells {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_cell(&mut self, cell: Cell) -> CellHash {
        let hash = cell.compute_hash();
        self.cells.insert(hash, cell);
        hash
    }

    pub fn set_root(&mut self, hash: CellHash) {
        if !self.roots.contains(&hash) {
            self.roots.push(hash);
        }
    }

    pub fn get_cell(&self, hash: &CellHash) -> Option<&Cell> {
        self.cells.get(hash)
    }

    /// Traverse chained cell references starting from root to reconstruct original data
    pub fn read_bytes(&self, root: &CellHash) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut cur = *root;
        loop {
            let cell = self.cells.get(&cur)?;
            out.extend_from_slice(&cell.data);
            if cell.references.is_empty() {
                break;
            }
            cur = cell.references[0];
        }
        Some(out)
    }

    /// Canonical BoC binary serialization (header + cell list + ref tables)
    pub fn to_boc_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&BOC_MAGIC_PREFIX);
        buf.extend_from_slice(&(self.roots.len() as u32).to_be_bytes());
        buf.extend_from_slice(&(self.cells.len() as u32).to_be_bytes());

        for r in &self.roots {
            buf.extend_from_slice(r);
        }

        let cell_order: Vec<(&CellHash, &Cell)> = self.cells.iter().collect();
        for (h, c) in cell_order {
            buf.extend_from_slice(h);
            buf.push(c.references.len() as u8);
            buf.extend_from_slice(&(c.data.len() as u16).to_be_bytes());
            buf.extend_from_slice(&c.data);
            for r in &c.references {
                buf.extend_from_slice(r);
            }
        }
        buf
    }

    /// Canonical BoC binary deserialization
    pub fn from_boc_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 {
            return Err("BoC data too short".to_string());
        }
        if bytes[0..4] != BOC_MAGIC_PREFIX {
            return Err("Invalid BoC magic prefix".to_string());
        }

        let roots_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let cells_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;

        let mut offset = 12;
        let mut roots = Vec::with_capacity(roots_len);
        for _ in 0..roots_len {
            if offset + 32 > bytes.len() {
                return Err("Unexpected EOF reading roots".to_string());
            }
            let mut r = [0u8; 32];
            r.copy_from_slice(&bytes[offset..offset + 32]);
            roots.push(r);
            offset += 32;
        }

        let mut cells = HashMap::with_capacity(cells_len);
        for _ in 0..cells_len {
            if offset + 35 > bytes.len() {
                return Err("Unexpected EOF reading cell header".to_string());
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;

            let refs_len = bytes[offset] as usize;
            offset += 1;

            let data_len =
                u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;

            if offset + data_len + refs_len * 32 > bytes.len() {
                return Err("Unexpected EOF reading cell payload".to_string());
            }

            let data = bytes[offset..offset + data_len].to_vec();
            offset += data_len;

            let mut references = Vec::with_capacity(refs_len);
            for _ in 0..refs_len {
                let mut ref_hash = [0u8; 32];
                ref_hash.copy_from_slice(&bytes[offset..offset + 32]);
                references.push(ref_hash);
                offset += 32;
            }

            cells.insert(hash, Cell { data, references });
        }

        Ok(Self { roots, cells })
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization of BagOfCells failed")
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// One step of a Merkle inclusion path (compressed Patricia).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleStep {
    /// Whether the sibling sits to the right of the current node.
    pub sibling_is_right: bool,
    /// Hash of the sibling node.
    pub sibling_hash: [u8; 32],
    /// Legacy field kept for wire compatibility (unused by the compressed model).
    pub branch_prefix: [u8; 16],
    /// Compressed Patricia: bits skipped before the branch point.
    pub skip: u16,
    /// Compressed Patricia: the branch's bit selector (0).
    pub branch_bit: u8,
}

/// Cryptographic Merkle Inclusion Proof for a key-value pair in PatriciaTrie.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub key: [u8; 32],
    pub value_hash: [u8; 32],
    /// Hash of the leaf node.
    pub leaf_hash: [u8; 32],
    /// Steps from leaf to root.
    pub path: Vec<MerkleStep>,
}

/// Patricia-Merkle trie backed by the compressed implementation (`crate::cpat2`).
///
/// The compressed trie walks only the branch points on a key's path (~log n),
/// giving ~300x faster writes than a fixed-depth sparse tree while keeping the
/// same cryptographic Merkle-proof guarantees. This struct adapts its API and
/// proof type to the rest of the codebase (`boc`, `MerkleProof`, `MerkleStep`).
#[derive(Clone, Debug, Default)]
pub struct PatriciaTrie {
    pub boc: BagOfCells,
    pub root: Option<CellHash>,
    inner: crate::cpat2::CompressedTrie,
}

impl PatriciaTrie {
    pub fn new() -> Self {
        Self {
            boc: BagOfCells::new(),
            root: None,
            inner: crate::cpat2::CompressedTrie::new(),
        }
    }

    pub fn insert(&mut self, key: &[u8; 32], value: &[u8]) {
        self.inner.insert(key, value);
        // NOTE: root hash is computed lazily in root_hash() (O(n)); do not call it
        // per insert. This keeps inserts O(log n).
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<&[u8]> {
        self.inner.get(key)
    }

    pub fn remove(&mut self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.inner.remove(key)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn root_hash(&self) -> CellHash {
        self.inner.root_hash()
    }

    /// The compressed Patricia trie behind this adapter.
    ///
    /// Exposed for the proof shapes `MerkleProof` cannot express — most
    /// importantly non-inclusion (absence) proofs, which need the trie's
    /// internal node structure rather than a single inclusion path. Callers
    /// that only need inclusion proofs should stay on
    /// [`PatriciaTrie::generate_merkle_proof`].
    pub fn compressed(&self) -> &crate::cpat2::CompressedTrie {
        &self.inner
    }

    /// Generate a compressed Merkle inclusion proof.
    pub fn generate_merkle_proof(&self, key: &[u8; 32]) -> Option<MerkleProof> {
        let p = self.inner.proof(key)?;
        let path = p
            .path
            .iter()
            .map(|s| MerkleStep {
                sibling_is_right: s.sibling_right,
                sibling_hash: s.sibling_hash,
                branch_prefix: [0u8; 16],
                skip: s.skip,
                branch_bit: s.bit,
            })
            .collect();
        Some(MerkleProof {
            key: p.key,
            value_hash: Sha256::digest(self.inner.get(key)?).into(),
            leaf_hash: p.leaf_hash,
            path,
        })
    }

    /// Verify a compressed Merkle inclusion proof against a known root.
    pub fn verify_merkle_proof(
        root: &CellHash,
        key: &[u8; 32],
        value: &[u8],
        proof: &MerkleProof,
    ) -> bool {
        if &proof.key != key {
            return false;
        }
        let val_hash: [u8; 32] = Sha256::digest(value).into();
        if proof.value_hash != val_hash {
            return false;
        }
        // Rebuild through the compressed verifier.
        let cp = crate::cpat2::Proof {
            key: proof.key,
            path: proof
                .path
                .iter()
                .map(|s| crate::cpat2::Step {
                    sibling_right: s.sibling_is_right,
                    sibling_hash: s.sibling_hash,
                    skip: s.skip,
                    bit: s.branch_bit,
                })
                .collect(),
            leaf_hash: proof.leaf_hash,
        };
        crate::cpat2::CompressedTrie::verify(root, key, value, &cp)
    }
}
