//! Isolated W2 building blocks, not a network protocol or a DA claim.
//!
//! A root supplied to `verify_chunk` is UNTRUSTED until the caller binds it
//! to an independently validated block/QC and checks the intended context.
//! No such binding, availability, retrieval, or consensus policy is provided.
//!
//! V1 chunk encoding (all integers little-endian): magic `SDP1`, version u8,
//! total length u64, chunk size u32, index u32, payload length u32, payload.
//! There is exactly one empty chunk for an empty object. All other chunks are
//! full-sized except the last. Merkle nodes duplicate the last hash on odd
//! levels. Leaves commit to version, total length, chunk size, index, length,
//! and bytes; internal nodes have a different BLAKE3 domain.
//!
//! These hard caps are provisional local resource limits, not chain parameters.
//! Integration requires an agreed canonical format, limits, context binding,
//! and validated block/QC commitment before accepting a root as authoritative.

use std::fmt;

pub const VERSION: u8 = 1;
pub const MAX_DATA_SIZE: u64 = 16 * 1024 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
pub const MAX_CHUNKS: u32 = 65_536;
pub const MAX_PROOF_DEPTH: usize = 16;
const HEADER: usize = 25;
const MAGIC: &[u8; 4] = b"SDP1";
const LEAF_DOMAIN: &[u8] = b"stellereum/data-plane/v1/leaf\0";
const NODE_DOMAIN: &[u8] = b"stellereum/data-plane/v1/node\0";

pub type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidParameters,
    IndexOutOfBounds,
    InvalidLength,
    InvalidEncoding,
    InvalidProof,
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    pub total_len: u64,
    pub chunk_size: u32,
}

impl Parameters {
    /// Validate all limits before using these parameters for sizing/allocation.
    pub fn chunk_count(self) -> Result<u32, Error> {
        if self.chunk_size == 0
            || self.chunk_size > MAX_CHUNK_SIZE
            || self.total_len > MAX_DATA_SIZE
        {
            return Err(Error::InvalidParameters);
        }
        let size = u64::from(self.chunk_size);
        let count = if self.total_len == 0 {
            1
        } else {
            self.total_len
                .checked_add(size - 1)
                .ok_or(Error::Overflow)?
                / size
        };
        if count > u64::from(MAX_CHUNKS) {
            return Err(Error::InvalidParameters);
        }
        u32::try_from(count).map_err(|_| Error::Overflow)
    }

    pub fn payload_len(self, index: u32) -> Result<usize, Error> {
        let count = self.chunk_count()?;
        if index >= count {
            return Err(Error::IndexOutOfBounds);
        }
        let start = u64::from(index)
            .checked_mul(u64::from(self.chunk_size))
            .ok_or(Error::Overflow)?;
        let len = self.total_len.checked_sub(start).ok_or(Error::Overflow)?;
        usize::try_from(len.min(u64::from(self.chunk_size))).map_err(|_| Error::Overflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chunk<'a> {
    pub parameters: Parameters,
    pub index: u32,
    pub payload: &'a [u8],
}

impl Chunk<'_> {
    fn validate(&self) -> Result<(), Error> {
        if self.payload.len() != self.parameters.payload_len(self.index)? {
            return Err(Error::InvalidLength);
        }
        Ok(())
    }
}

/// Encode only canonical chunks; checks precede allocation.
pub fn encode_chunk(chunk: Chunk<'_>) -> Result<Vec<u8>, Error> {
    chunk.validate()?;
    let capacity = HEADER
        .checked_add(chunk.payload.len())
        .ok_or(Error::Overflow)?;
    let len = u32::try_from(chunk.payload.len()).map_err(|_| Error::Overflow)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&chunk.parameters.total_len.to_le_bytes());
    out.extend_from_slice(&chunk.parameters.chunk_size.to_le_bytes());
    out.extend_from_slice(&chunk.index.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(chunk.payload);
    Ok(out)
}

/// Decode without allocating; rejects trailing bytes and noncanonical lengths.
pub fn decode_chunk(bytes: &[u8]) -> Result<Chunk<'_>, Error> {
    if bytes.len() < HEADER || &bytes[..4] != MAGIC || bytes[4] != VERSION {
        return Err(Error::InvalidEncoding);
    }
    let total_len = u64::from_le_bytes(
        bytes[5..13]
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    );
    let chunk_size = u32::from_le_bytes(
        bytes[13..17]
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    );
    let index = u32::from_le_bytes(
        bytes[17..21]
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    );
    let len = u32::from_le_bytes(
        bytes[21..25]
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    );
    let parameters = Parameters {
        total_len,
        chunk_size,
    };
    let expected = parameters.payload_len(index)?;
    let len = usize::try_from(len).map_err(|_| Error::Overflow)?;
    if len != expected || HEADER.checked_add(len).ok_or(Error::Overflow)? != bytes.len() {
        return Err(Error::InvalidLength);
    }
    Ok(Chunk {
        parameters,
        index,
        payload: &bytes[HEADER..],
    })
}

fn leaf_hash(chunk: Chunk<'_>) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(&[VERSION]);
    hasher.update(&chunk.parameters.total_len.to_le_bytes());
    hasher.update(&chunk.parameters.chunk_size.to_le_bytes());
    hasher.update(&chunk.index.to_le_bytes());
    // Payload length was validated against a u32 chunk_size before this call.
    hasher.update(&(chunk.payload.len() as u32).to_le_bytes());
    hasher.update(chunk.payload);
    *hasher.finalize().as_bytes()
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn depth(mut count: u32) -> usize {
    let mut result = 0;
    while count > 1 {
        count = count / 2 + count % 2;
        result += 1;
    }
    result
}

/// Build a root and bottom-up sibling path for one chunk of a complete object.
/// The resulting root is not authenticated.
pub fn make_proof(data: &[u8], chunk_size: u32, index: u32) -> Result<(Hash, Vec<Hash>), Error> {
    let total_len = u64::try_from(data.len()).map_err(|_| Error::Overflow)?;
    let parameters = Parameters {
        total_len,
        chunk_size,
    };
    let count = parameters.chunk_count()?;
    parameters.payload_len(index)?;
    let capacity = usize::try_from(count).map_err(|_| Error::Overflow)?;
    let mut level = Vec::with_capacity(capacity);
    for i in 0..count {
        let start = u64::from(i)
            .checked_mul(u64::from(chunk_size))
            .ok_or(Error::Overflow)?;
        let start = usize::try_from(start).map_err(|_| Error::Overflow)?;
        let end = start
            .checked_add(parameters.payload_len(i)?)
            .ok_or(Error::Overflow)?;
        level.push(leaf_hash(Chunk {
            parameters,
            index: i,
            payload: &data[start..end],
        }));
    }
    let mut position = usize::try_from(index).map_err(|_| Error::Overflow)?;
    let mut proof = Vec::with_capacity(depth(count));
    while level.len() > 1 {
        let sibling = if position % 2 == 0 {
            (position + 1).min(level.len() - 1)
        } else {
            position - 1
        };
        proof.push(level[sibling]);
        let mut next = Vec::with_capacity(level.len() / 2 + level.len() % 2);
        for pair in level.chunks(2) {
            next.push(node_hash(&pair[0], pair.get(1).unwrap_or(&pair[0])));
        }
        position /= 2;
        level = next;
    }
    Ok((level[0], proof))
}

/// Verify membership relative to `untrusted_root`, not authenticity or DA.
pub fn verify_chunk(chunk: Chunk<'_>, proof: &[Hash], untrusted_root: &Hash) -> Result<(), Error> {
    chunk.validate()?;
    let mut count = chunk.parameters.chunk_count()?;
    if proof.len() > MAX_PROOF_DEPTH || proof.len() != depth(count) {
        return Err(Error::InvalidProof);
    }
    let mut position = chunk.index;
    let mut hash = leaf_hash(chunk);
    for sibling in proof {
        if position.is_multiple_of(2) {
            if position + 1 == count && sibling != &hash {
                return Err(Error::InvalidProof);
            }
            hash = node_hash(&hash, sibling);
        } else {
            hash = node_hash(sibling, &hash);
        }
        position /= 2;
        count = count / 2 + count % 2;
    }
    if &hash != untrusted_root {
        return Err(Error::InvalidProof);
    }
    Ok(())
}
