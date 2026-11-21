//! Isolated pure-Rust GF(2^8) Reed-Solomon `(k, n)` codec and `data_plane`
//! Merkle commitment binding.
//!
//! # Security Notice: NOT a Data Availability (DA) Proof
//!
//! This module is **only** a local erasure-coding and bounded-repair building
//! block. Neither `chunk_root`, `SDP1` Merkle proofs, nor Reed-Solomon parity
//! shards constitute a proof of Data Availability (DA / DAS) or block validity.
//! Any `chunk_root` and `RsParameters` supplied to `verify_shard` or
//! `reconstruct_committed` are **UNTRUSTED** until independently authenticated
//! by the caller for the target consensus context (for example via proposer
//! Falcon signature or validated QC commitment). After reconstruction, callers
//! must still run strict canonical deserialization, `Block::compute_hash()`,
//! and all BFT consensus checks before accepting or voting on a block.
//!
//! # Construction
//!
//! - Finite field `GF(2^8)` with primitive polynomial `0x1D`
//!   (`x^8 + x^4 + x^3 + x^2 + 1`), matching `reed-solomon-erasure::galois_8`.
//! - Compile-time `const fn` lookup tables (`LOG_TABLE`, `EXP_TABLE`,
//!   `MUL_LOW`, `MUL_HIGH`, ~8.75 KiB `.rodata`), zero `build.rs`.
//! - Systematic Vandermonde encoding matrix (`I_k` top rows, parity bottom
//!   rows) with direct in-place `k x k` Gauss-Jordan inversion on erasure.
//! - Zero `LruCache`, zero `Mutex`, zero `unsafe`, zero new dependencies.

use std::fmt;

use crate::data_plane::{
    encode_chunk, verify_chunk, Chunk, Hash, Parameters, MAX_CHUNK_SIZE, MAX_DATA_SIZE, VERSION,
};

/// Primitive polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1 (0x11D -> 0x1D).
pub const GENERATING_POLYNOMIAL: u16 = 0x1D;
pub const GF_ORDER: usize = 256;
pub const MIN_DATA_SHARDS: usize = 1;
pub const MAX_TOTAL_SHARDS: usize = GF_ORDER;

/// Contract ceiling on canonical object size before RS padding (16 MiB).
pub const W2_MAX_OBJECT_BYTES: u64 = MAX_DATA_SIZE;
/// Target wire shard size for overlay transport (256 KiB).
pub const W2_WIRE_CHUNK_SIZE: u32 = 256 * 1024;
/// Hard per-shard ceiling inherited from `data_plane::MAX_CHUNK_SIZE` (1 MiB).
pub const MAX_SHARD_SIZE: u32 = MAX_CHUNK_SIZE;
/// Maximum total committed codeword bytes (`n * shard_len`) accepted by `data_plane`.
pub const MAX_CODEWORD_BYTES: u64 = MAX_DATA_SIZE;
/// Maximum total raw (uncommitted) codeword bytes (`2 * W2_MAX_OBJECT_BYTES`).
pub const MAX_RAW_CODEWORD_BYTES: u64 = 2 * W2_MAX_OBJECT_BYTES;

const EXP_TABLE_SIZE: usize = GF_ORDER * 2 - 2;
const LEAF_DOMAIN: &[u8] = b"stellereum/data-plane/v1/leaf\0";
const NODE_DOMAIN: &[u8] = b"stellereum/data-plane/v1/node\0";

const LOG_TABLE: [u8; GF_ORDER] = gen_log_table();
const EXP_TABLE: [u8; EXP_TABLE_SIZE] = gen_exp_table(&LOG_TABLE);
const MUL_LOW: [[u8; 16]; GF_ORDER] = gen_mul_low();
const MUL_HIGH: [[u8; 16]; GF_ORDER] = gen_mul_high();

const fn gen_log_table() -> [u8; GF_ORDER] {
    let mut table = [0u8; GF_ORDER];
    let mut b: u16 = 1;
    let mut log: usize = 0;
    while log < GF_ORDER - 1 {
        table[b as usize] = log as u8;
        b <<= 1;
        if b >= GF_ORDER as u16 {
            b = (b - GF_ORDER as u16) ^ GENERATING_POLYNOMIAL;
        }
        log += 1;
    }
    table
}

const fn gen_exp_table(log_table: &[u8; GF_ORDER]) -> [u8; EXP_TABLE_SIZE] {
    let mut table = [0u8; EXP_TABLE_SIZE];
    let mut i: usize = 1;
    while i < GF_ORDER {
        let log = log_table[i] as usize;
        table[log] = i as u8;
        table[log + GF_ORDER - 1] = i as u8;
        i += 1;
    }
    table
}

const fn gf_mul_const(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP_TABLE[LOG_TABLE[a as usize] as usize + LOG_TABLE[b as usize] as usize]
    }
}

const fn gen_mul_low() -> [[u8; 16]; GF_ORDER] {
    let mut table = [[0u8; 16]; GF_ORDER];
    let mut a = 0;
    while a < GF_ORDER {
        let mut nib = 0;
        while nib < 16 {
            table[a][nib] = gf_mul_const(a as u8, nib as u8);
            nib += 1;
        }
        a += 1;
    }
    table
}

const fn gen_mul_high() -> [[u8; 16]; GF_ORDER] {
    let mut table = [[0u8; 16]; GF_ORDER];
    let mut a = 0;
    while a < GF_ORDER {
        let mut nib = 0;
        while nib < 16 {
            table[a][nib] = gf_mul_const(a as u8, (nib << 4) as u8);
            nib += 1;
        }
        a += 1;
    }
    table
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidParameters,
    IndexOutOfBounds,
    DuplicateIndex,
    InvalidShardLength,
    TooFewShards,
    NonCanonicalPadding,
    InvalidProof,
    InconsistentCodeword,
    SingularMatrix,
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

/// GF(2^8) addition (XOR).
#[inline]
pub fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(2^8) multiplication using compile-time nibble tables.
#[inline]
pub fn gf_mul(a: u8, b: u8) -> u8 {
    MUL_LOW[a as usize][(b & 0x0F) as usize] ^ MUL_HIGH[a as usize][(b >> 4) as usize]
}

/// GF(2^8) division; returns `Err(Error::SingularMatrix)` if `b == 0`.
#[inline]
pub fn gf_div(a: u8, b: u8) -> Result<u8, Error> {
    if b == 0 {
        return Err(Error::SingularMatrix);
    }
    if a == 0 {
        return Ok(0);
    }
    let log_a = LOG_TABLE[a as usize] as usize;
    let log_b = LOG_TABLE[b as usize] as usize;
    let diff = log_a + (GF_ORDER - 1) - log_b;
    Ok(EXP_TABLE[diff])
}

/// GF(2^8) exponentiation (`0^0 == 1`).
#[inline]
pub fn gf_exp(a: u8, power: usize) -> u8 {
    if power == 0 {
        1
    } else if a == 0 {
        0
    } else {
        let log_a = LOG_TABLE[a as usize] as usize;
        let log_res = (log_a * (power % (GF_ORDER - 1))) % (GF_ORDER - 1);
        EXP_TABLE[log_res]
    }
}

fn mul_slice(c: u8, input: &[u8], out: &mut [u8]) {
    debug_assert_eq!(input.len(), out.len());
    if c == 0 {
        out.fill(0);
        return;
    }
    if c == 1 {
        out.copy_from_slice(input);
        return;
    }
    let low = &MUL_LOW[c as usize];
    let high = &MUL_HIGH[c as usize];
    for (dst, &src) in out.iter_mut().zip(input.iter()) {
        *dst = low[(src & 0x0F) as usize] ^ high[(src >> 4) as usize];
    }
}

fn mul_slice_xor(c: u8, input: &[u8], out: &mut [u8]) {
    debug_assert_eq!(input.len(), out.len());
    if c == 0 {
        return;
    }
    if c == 1 {
        for (dst, &src) in out.iter_mut().zip(input.iter()) {
            *dst ^= src;
        }
        return;
    }
    let low = &MUL_LOW[c as usize];
    let high = &MUL_HIGH[c as usize];
    for (dst, &src) in out.iter_mut().zip(input.iter()) {
        *dst ^= low[(src & 0x0F) as usize] ^ high[(src >> 4) as usize];
    }
}

/// Direct in-place Gauss-Jordan inversion of a `dim x dim` row-major GF(2^8) matrix.
///
/// Row-swap permutations are tracked in `swaps` and applied in reverse as column swaps
/// at completion, avoiding an augmented `[A | I]` copy.
pub fn invert_matrix_in_place(matrix: &mut [u8], dim: usize) -> Result<(), Error> {
    if dim == 0 {
        return Err(Error::InvalidParameters);
    }
    let expected = dim.checked_mul(dim).ok_or(Error::Overflow)?;
    if matrix.len() != expected {
        return Err(Error::InvalidParameters);
    }

    let mut swaps = vec![0usize; dim];

    for i in 0..dim {
        let mut pivot_row = None;
        for r in i..dim {
            if matrix[r * dim + i] != 0 {
                pivot_row = Some(r);
                break;
            }
        }
        let p = pivot_row.ok_or(Error::SingularMatrix)?;
        swaps[i] = p;

        if p != i {
            let row_i = i * dim;
            let row_p = p * dim;
            for c in 0..dim {
                matrix.swap(row_i + c, row_p + c);
            }
        }

        let inv_pivot = gf_div(1, matrix[i * dim + i])?;
        matrix[i * dim + i] = 1;
        for cell in &mut matrix[i * dim..(i + 1) * dim] {
            *cell = gf_mul(*cell, inv_pivot);
        }

        for r in 0..dim {
            if r == i {
                continue;
            }
            let factor = matrix[r * dim + i];
            if factor != 0 {
                matrix[r * dim + i] = 0;
                for c in 0..dim {
                    let prod = gf_mul(factor, matrix[i * dim + c]);
                    matrix[r * dim + c] ^= prod;
                }
            }
        }
    }

    for i in (0..dim).rev() {
        let p = swaps[i];
        if p != i {
            for r in 0..dim {
                matrix.swap(r * dim + i, r * dim + p);
            }
        }
    }

    Ok(())
}

/// Canonical RS `(k, n)` geometry for an object of `orig_len` bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RsParameters {
    pub orig_len: u64,
    pub k: u16,
    pub n: u16,
    pub shard_len: u32,
}

impl RsParameters {
    fn expected_shard_len(orig_len: u64, k: u16) -> Result<u32, Error> {
        let k_usize = usize::from(k);
        if k_usize < MIN_DATA_SHARDS {
            return Err(Error::InvalidParameters);
        }
        let shard_len_u64 = if orig_len == 0 {
            1
        } else {
            orig_len.div_ceil(u64::from(k))
        };
        u32::try_from(shard_len_u64).map_err(|_| Error::Overflow)
    }

    /// Construct and validate canonical RS parameters before any allocation.
    pub fn new(orig_len: u64, k: u16, n: u16) -> Result<Self, Error> {
        if usize::from(k) < MIN_DATA_SHARDS
            || n <= k
            || usize::from(n) > MAX_TOTAL_SHARDS
            || orig_len > W2_MAX_OBJECT_BYTES
        {
            return Err(Error::InvalidParameters);
        }
        let shard_len = Self::expected_shard_len(orig_len, k)?;
        let params = Self {
            orig_len,
            k,
            n,
            shard_len,
        };
        params.validate()?;
        Ok(params)
    }

    /// Default W2 `(k, n)` geometry targeting `W2_WIRE_CHUNK_SIZE` and 1.5x redundancy.
    pub fn default_for_len(orig_len: u64) -> Result<Self, Error> {
        if orig_len > W2_MAX_OBJECT_BYTES {
            return Err(Error::InvalidParameters);
        }
        let k_u64 = orig_len
            .max(1)
            .div_ceil(u64::from(W2_WIRE_CHUNK_SIZE))
            .clamp(4, 128);
        let k = u16::try_from(k_u64).map_err(|_| Error::Overflow)?;
        let m = k.div_ceil(2).max(2).min(MAX_TOTAL_SHARDS as u16 - k);
        let n = k.checked_add(m).ok_or(Error::Overflow)?;
        Self::new(orig_len, k, n)
    }

    /// Validate all bounds, canonical shard sizing, and overflow checks before allocating.
    pub fn validate(self) -> Result<(), Error> {
        if usize::from(self.k) < MIN_DATA_SHARDS
            || self.n <= self.k
            || usize::from(self.n) > MAX_TOTAL_SHARDS
            || self.orig_len > W2_MAX_OBJECT_BYTES
        {
            return Err(Error::InvalidParameters);
        }
        if self.shard_len == 0 || self.shard_len > MAX_SHARD_SIZE {
            return Err(Error::InvalidParameters);
        }
        let expected_shard = Self::expected_shard_len(self.orig_len, self.k)?;
        if self.shard_len != expected_shard {
            return Err(Error::InvalidParameters);
        }
        let padded_data = u64::from(self.k)
            .checked_mul(u64::from(self.shard_len))
            .ok_or(Error::Overflow)?;
        if padded_data < self.orig_len {
            return Err(Error::InvalidParameters);
        }
        let total_codeword = u64::from(self.n)
            .checked_mul(u64::from(self.shard_len))
            .ok_or(Error::Overflow)?;
        if total_codeword > MAX_CODEWORD_BYTES {
            return Err(Error::InvalidParameters);
        }
        usize::try_from(total_codeword).map_err(|_| Error::Overflow)?;
        usize::try_from(self.orig_len).map_err(|_| Error::Overflow)?;
        Ok(())
    }

    pub fn parity_count(self) -> Result<u16, Error> {
        self.validate()?;
        Ok(self.n - self.k)
    }

    pub fn padded_data_len(self) -> Result<u64, Error> {
        self.validate()?;
        u64::from(self.k)
            .checked_mul(u64::from(self.shard_len))
            .ok_or(Error::Overflow)
    }

    pub fn total_codeword_len(self) -> Result<u64, Error> {
        self.validate()?;
        u64::from(self.n)
            .checked_mul(u64::from(self.shard_len))
            .ok_or(Error::Overflow)
    }

    pub fn data_plane_parameters(self) -> Result<Parameters, Error> {
        let total_len = self.total_codeword_len()?;
        let dp = Parameters {
            total_len,
            chunk_size: self.shard_len,
        };
        let count = dp.chunk_count().map_err(|_| Error::InvalidParameters)?;
        if count != u32::from(self.n) {
            return Err(Error::InvalidParameters);
        }
        Ok(dp)
    }
}

/// Deterministically split `data` into `k` zero-padded shards of `params.shard_len`.
pub fn pad_data(data: &[u8], params: RsParameters) -> Result<Vec<Vec<u8>>, Error> {
    params.validate()?;
    let data_len = u64::try_from(data.len()).map_err(|_| Error::Overflow)?;
    if data_len != params.orig_len {
        return Err(Error::InvalidParameters);
    }
    let k = usize::from(params.k);
    let shard_len = usize::try_from(params.shard_len).map_err(|_| Error::Overflow)?;
    let mut shards = Vec::with_capacity(k);
    for i in 0..k {
        let start = i.checked_mul(shard_len).ok_or(Error::Overflow)?;
        let mut shard = vec![0u8; shard_len];
        if start < data.len() {
            let end = start.saturating_add(shard_len).min(data.len());
            let copy_len = end - start;
            shard[..copy_len].copy_from_slice(&data[start..end]);
        }
        shards.push(shard);
    }
    Ok(shards)
}

/// Reassemble `k` data shards and reject any non-zero canonical padding bytes.
pub fn unpad_canonical(data_shards: &[Vec<u8>], params: RsParameters) -> Result<Vec<u8>, Error> {
    params.validate()?;
    let k = usize::from(params.k);
    if data_shards.len() != k {
        return Err(Error::InvalidParameters);
    }
    let shard_len = usize::try_from(params.shard_len).map_err(|_| Error::Overflow)?;
    for shard in data_shards {
        if shard.len() != shard_len {
            return Err(Error::InvalidShardLength);
        }
    }
    let padded_len = k.checked_mul(shard_len).ok_or(Error::Overflow)?;
    let orig_len = usize::try_from(params.orig_len).map_err(|_| Error::Overflow)?;
    let mut assembled = Vec::with_capacity(padded_len);
    for shard in data_shards {
        assembled.extend_from_slice(shard);
    }
    if assembled[orig_len..].iter().any(|&b| b != 0) {
        return Err(Error::NonCanonicalPadding);
    }
    assembled.truncate(orig_len);
    Ok(assembled)
}

/// Pure-Rust GF(2^8) Reed-Solomon `(k, n)` codec (systematic Vandermonde, polynomial `0x1D`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReedSolomon8 {
    k: usize,
    m: usize,
    n: usize,
    /// Row-major `n x k` systematic encoding matrix (`I_k` on top, parity rows below).
    matrix: Vec<u8>,
}

impl ReedSolomon8 {
    /// Build a systematic `(k, n)` Vandermonde RS codec for `1 <= k < n <= 256`.
    pub fn new(k: usize, n: usize) -> Result<Self, Error> {
        if k < MIN_DATA_SHARDS || n <= k || n > MAX_TOTAL_SHARDS {
            return Err(Error::InvalidParameters);
        }
        let m = n - k;

        let vandermonde_len = n.checked_mul(k).ok_or(Error::Overflow)?;
        let mut vandermonde = vec![0u8; vandermonde_len];
        for r in 0..n {
            let base = r as u8;
            for c in 0..k {
                vandermonde[r * k + c] = gf_exp(base, c);
            }
        }

        let top_len = k.checked_mul(k).ok_or(Error::Overflow)?;
        let mut top_inv = vandermonde[..top_len].to_vec();
        invert_matrix_in_place(&mut top_inv, k)?;

        let mut matrix = vec![0u8; vandermonde_len];
        for r in 0..n {
            for c in 0..k {
                let mut acc = 0u8;
                for j in 0..k {
                    acc ^= gf_mul(vandermonde[r * k + j], top_inv[j * k + c]);
                }
                matrix[r * k + c] = acc;
            }
        }

        Ok(Self { k, m, n, matrix })
    }

    pub fn data_shards(&self) -> usize {
        self.k
    }

    pub fn parity_shards(&self) -> usize {
        self.m
    }

    pub fn total_shards(&self) -> usize {
        self.n
    }

    pub fn parity_row(&self, parity_index: usize) -> Option<&[u8]> {
        if parity_index >= self.m {
            return None;
        }
        let row = self.k + parity_index;
        Some(&self.matrix[row * self.k..(row + 1) * self.k])
    }

    fn validate_shard_len(&self, shard_len: usize) -> Result<(), Error> {
        if shard_len == 0 || shard_len > MAX_SHARD_SIZE as usize {
            return Err(Error::InvalidShardLength);
        }
        let total_bytes = (self.n as u64)
            .checked_mul(shard_len as u64)
            .ok_or(Error::Overflow)?;
        if total_bytes > MAX_RAW_CODEWORD_BYTES {
            return Err(Error::InvalidParameters);
        }
        Ok(())
    }

    /// Encode parity shards `shards[k..n]` in-place from data shards `shards[0..k]`.
    pub fn encode_shards(&self, shards: &mut [Vec<u8>]) -> Result<(), Error> {
        if shards.len() != self.n {
            return Err(Error::InvalidParameters);
        }
        let shard_len = shards[0].len();
        self.validate_shard_len(shard_len)?;
        for shard in shards.iter() {
            if shard.len() != shard_len {
                return Err(Error::InvalidShardLength);
            }
        }

        let (data, parity) = shards.split_at_mut(self.k);
        for (p_idx, parity_shard) in parity.iter_mut().enumerate() {
            let row = &self.matrix[(self.k + p_idx) * self.k..(self.k + p_idx + 1) * self.k];
            mul_slice(row[0], &data[0], parity_shard);
            for (d_idx, coeff) in row.iter().enumerate().skip(1) {
                mul_slice_xor(*coeff, &data[d_idx], parity_shard);
            }
        }
        Ok(())
    }

    /// Verify that all `n` shards form a valid RS codeword.
    pub fn verify_shards<T: AsRef<[u8]>>(&self, shards: &[T]) -> Result<bool, Error> {
        if shards.len() != self.n {
            return Err(Error::InvalidParameters);
        }
        let shard_len = shards[0].as_ref().len();
        self.validate_shard_len(shard_len)?;
        for shard in shards {
            if shard.as_ref().len() != shard_len {
                return Err(Error::InvalidShardLength);
            }
        }

        let mut expected = vec![0u8; shard_len];
        for p_idx in 0..self.m {
            let row = &self.matrix[(self.k + p_idx) * self.k..(self.k + p_idx + 1) * self.k];
            mul_slice(row[0], shards[0].as_ref(), &mut expected);
            for (d_idx, coeff) in row.iter().enumerate().skip(1) {
                mul_slice_xor(*coeff, shards[d_idx].as_ref(), &mut expected);
            }
            if expected.as_slice() != shards[self.k + p_idx].as_ref() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Reconstruct only missing data shards `0..k` from any `k` present shards.
    pub fn reconstruct_data(&self, shards: &mut [Option<Vec<u8>>]) -> Result<(), Error> {
        self.reconstruct_internal(shards, false)
    }

    /// Reconstruct all missing data and parity shards `0..n` from any `k` present shards.
    pub fn reconstruct(&self, shards: &mut [Option<Vec<u8>>]) -> Result<(), Error> {
        self.reconstruct_internal(shards, true)
    }

    fn reconstruct_internal(
        &self,
        shards: &mut [Option<Vec<u8>>],
        reconstruct_parity: bool,
    ) -> Result<(), Error> {
        if shards.len() != self.n {
            return Err(Error::InvalidParameters);
        }

        let mut present_count = 0usize;
        let mut shard_len: Option<usize> = None;
        for shard in shards.iter().flatten() {
            let len = shard.len();
            self.validate_shard_len(len)?;
            if let Some(expected) = shard_len {
                if len != expected {
                    return Err(Error::InvalidShardLength);
                }
            } else {
                shard_len = Some(len);
            }
            present_count += 1;
        }

        if present_count < self.k {
            return Err(Error::TooFewShards);
        }
        let shard_len = shard_len.ok_or(Error::TooFewShards)?;

        let all_data_present = shards[..self.k].iter().all(Option::is_some);
        if !all_data_present {
            let mut present_indices = Vec::with_capacity(self.k);
            for (idx, shard) in shards.iter().enumerate() {
                if shard.is_some() {
                    present_indices.push(idx);
                    if present_indices.len() == self.k {
                        break;
                    }
                }
            }

            let mat_len = self.k.checked_mul(self.k).ok_or(Error::Overflow)?;
            let mut sub_matrix = vec![0u8; mat_len];
            for (row_idx, &shard_idx) in present_indices.iter().enumerate() {
                let src = &self.matrix[shard_idx * self.k..(shard_idx + 1) * self.k];
                let dst = &mut sub_matrix[row_idx * self.k..(row_idx + 1) * self.k];
                dst.copy_from_slice(src);
            }
            invert_matrix_in_place(&mut sub_matrix, self.k)?;

            let mut recovered_data: Vec<(usize, Vec<u8>)> = Vec::new();
            for d in 0..self.k {
                if shards[d].is_none() {
                    let row = &sub_matrix[d * self.k..(d + 1) * self.k];
                    let mut out = vec![0u8; shard_len];
                    let first_src = shards[present_indices[0]]
                        .as_deref()
                        .ok_or(Error::TooFewShards)?;
                    mul_slice(row[0], first_src, &mut out);
                    for (col, &coeff) in row.iter().enumerate().skip(1) {
                        let src = shards[present_indices[col]]
                            .as_deref()
                            .ok_or(Error::TooFewShards)?;
                        mul_slice_xor(coeff, src, &mut out);
                    }
                    recovered_data.push((d, out));
                }
            }
            for (d, buf) in recovered_data {
                shards[d] = Some(buf);
            }
        }

        if reconstruct_parity {
            let mut recovered_parity: Vec<(usize, Vec<u8>)> = Vec::new();
            for p_idx in 0..self.m {
                let idx = self.k + p_idx;
                if shards[idx].is_none() {
                    let row = &self.matrix[idx * self.k..(idx + 1) * self.k];
                    let mut out = vec![0u8; shard_len];
                    let first_data = shards[0].as_deref().ok_or(Error::TooFewShards)?;
                    mul_slice(row[0], first_data, &mut out);
                    for (d_idx, &coeff) in row.iter().enumerate().skip(1) {
                        let src = shards[d_idx].as_deref().ok_or(Error::TooFewShards)?;
                        mul_slice_xor(coeff, src, &mut out);
                    }
                    recovered_parity.push((idx, out));
                }
            }
            for (idx, buf) in recovered_parity {
                shards[idx] = Some(buf);
            }
        }

        Ok(())
    }
}

fn leaf_hash(dp_params: Parameters, index: u32, payload: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(&[VERSION]);
    hasher.update(&dp_params.total_len.to_le_bytes());
    hasher.update(&dp_params.chunk_size.to_le_bytes());
    hasher.update(&index.to_le_bytes());
    hasher.update(&(payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn build_merkle_tree(
    shards: &[Vec<u8>],
    dp_params: Parameters,
) -> Result<(Hash, Vec<Vec<Hash>>), Error> {
    let count = dp_params
        .chunk_count()
        .map_err(|_| Error::InvalidParameters)?;
    let n = usize::try_from(count).map_err(|_| Error::Overflow)?;
    if n == 0 || shards.len() != n {
        return Err(Error::InvalidParameters);
    }

    let mut level = Vec::with_capacity(n);
    for (i, shard) in shards.iter().enumerate() {
        let index = u32::try_from(i).map_err(|_| Error::Overflow)?;
        let expected_len = dp_params
            .payload_len(index)
            .map_err(|_| Error::InvalidParameters)?;
        if shard.len() != expected_len {
            return Err(Error::InvalidShardLength);
        }
        level.push(leaf_hash(dp_params, index, shard));
    }

    let mut positions: Vec<usize> = (0..n).collect();
    let mut proofs = vec![Vec::new(); n];

    while level.len() > 1 {
        for (idx, pos) in positions.iter_mut().enumerate() {
            let sibling = if (*pos).is_multiple_of(2) {
                (*pos + 1).min(level.len() - 1)
            } else {
                *pos - 1
            };
            proofs[idx].push(level[sibling]);
            *pos /= 2;
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(node_hash(&pair[0], pair.get(1).unwrap_or(&pair[0])));
        }
        level = next;
    }

    Ok((level[0], proofs))
}

fn compute_merkle_root(shards: &[Vec<u8>], dp_params: Parameters) -> Result<Hash, Error> {
    let count = dp_params
        .chunk_count()
        .map_err(|_| Error::InvalidParameters)?;
    let n = usize::try_from(count).map_err(|_| Error::Overflow)?;
    if n == 0 || shards.len() != n {
        return Err(Error::InvalidParameters);
    }

    let mut level = Vec::with_capacity(n);
    for (i, shard) in shards.iter().enumerate() {
        let index = u32::try_from(i).map_err(|_| Error::Overflow)?;
        let expected_len = dp_params
            .payload_len(index)
            .map_err(|_| Error::InvalidParameters)?;
        if shard.len() != expected_len {
            return Err(Error::InvalidShardLength);
        }
        level.push(leaf_hash(dp_params, index, shard));
    }

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(node_hash(&pair[0], pair.get(1).unwrap_or(&pair[0])));
        }
        level = next;
    }

    Ok(level[0])
}

/// Complete `(k, n)` RS codeword bound to a `data_plane` Merkle root over all `n` shards.
///
/// NOTE: Not a DA proof. The caller must authenticate `chunk_root` and `params`
/// independently before relying on any shard or reconstructed payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedCodeword {
    pub params: RsParameters,
    pub dp_params: Parameters,
    pub chunk_root: Hash,
    pub shards: Vec<Vec<u8>>,
    pub proofs: Vec<Vec<Hash>>,
}

/// One received RS shard with its `data_plane` Merkle membership proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardPiece<'a> {
    pub index: u32,
    pub payload: &'a [u8],
    pub proof: &'a [Hash],
}

impl CommittedCodeword {
    pub fn chunk(&self, index: u32) -> Result<Chunk<'_>, Error> {
        let idx = usize::try_from(index).map_err(|_| Error::IndexOutOfBounds)?;
        let payload = self.shards.get(idx).ok_or(Error::IndexOutOfBounds)?;
        Ok(Chunk {
            parameters: self.dp_params,
            index,
            payload,
        })
    }

    pub fn piece(&self, index: u32) -> Result<ShardPiece<'_>, Error> {
        let idx = usize::try_from(index).map_err(|_| Error::IndexOutOfBounds)?;
        let payload = self.shards.get(idx).ok_or(Error::IndexOutOfBounds)?;
        let proof = self.proofs.get(idx).ok_or(Error::IndexOutOfBounds)?;
        Ok(ShardPiece {
            index,
            payload,
            proof,
        })
    }

    pub fn encode_wire_chunk(&self, index: u32) -> Result<Vec<u8>, Error> {
        let chunk = self.chunk(index)?;
        encode_chunk(chunk).map_err(|_| Error::InvalidParameters)
    }
}

/// Encode `data` into `n = k + m` RS shards and build a `data_plane` Merkle root over all `n` shards.
///
/// NOTE: Not a DA proof; `chunk_root` only commits to the `n`-shard vector.
pub fn encode_committed(data: &[u8], k: u16, n: u16) -> Result<CommittedCodeword, Error> {
    let orig_len = u64::try_from(data.len()).map_err(|_| Error::Overflow)?;
    let params = RsParameters::new(orig_len, k, n)?;
    let dp_params = params.data_plane_parameters()?;
    let k_usize = usize::from(params.k);
    let n_usize = usize::from(params.n);
    let shard_len = usize::try_from(params.shard_len).map_err(|_| Error::Overflow)?;

    let mut shards = pad_data(data, params)?;
    shards.resize_with(n_usize, || vec![0u8; shard_len]);

    let rs = ReedSolomon8::new(k_usize, n_usize)?;
    rs.encode_shards(&mut shards)?;

    let (chunk_root, proofs) = build_merkle_tree(&shards, dp_params)?;

    Ok(CommittedCodeword {
        params,
        dp_params,
        chunk_root,
        shards,
        proofs,
    })
}

/// Verify a single data or parity shard against `untrusted_root` via `data_plane::verify_chunk`.
///
/// NOTE: `untrusted_root` is NOT authenticated by this function; the caller must
/// bind `(untrusted_root, params)` to an authenticated header/QC before accepting shards.
pub fn verify_shard(
    params: RsParameters,
    index: u32,
    payload: &[u8],
    proof: &[Hash],
    untrusted_root: &Hash,
) -> Result<(), Error> {
    params.validate()?;
    if index >= u32::from(params.n) {
        return Err(Error::IndexOutOfBounds);
    }
    let expected_len = usize::try_from(params.shard_len).map_err(|_| Error::Overflow)?;
    if payload.len() != expected_len {
        return Err(Error::InvalidShardLength);
    }
    let dp_params = params.data_plane_parameters()?;
    let chunk = Chunk {
        parameters: dp_params,
        index,
        payload,
    };
    verify_chunk(chunk, proof, untrusted_root).map_err(|_| Error::InvalidProof)
}

/// Verify every supplied shard against `untrusted_root`, reconstruct via GF(2^8) RS,
/// enforce canonical zero-padding, re-encode all `n` shards, and verify the re-encoded
/// codeword and Merkle root match all supplied shards and `untrusted_root`.
///
/// NOTE: Not a DA proof. Callers must independently authenticate `(untrusted_root, params)`
/// and validate the reconstructed payload (e.g. strict decode + `compute_hash()`).
pub fn reconstruct_committed(
    params: RsParameters,
    untrusted_root: &Hash,
    pieces: &[ShardPiece<'_>],
) -> Result<Vec<u8>, Error> {
    params.validate()?;
    let dp_params = params.data_plane_parameters()?;
    let k = usize::from(params.k);
    let n = usize::from(params.n);
    let shard_len = usize::try_from(params.shard_len).map_err(|_| Error::Overflow)?;

    let mut seen = [false; MAX_TOTAL_SHARDS];
    let mut unique_count = 0usize;
    for piece in pieces {
        if piece.index >= u32::from(params.n) {
            return Err(Error::IndexOutOfBounds);
        }
        let idx = piece.index as usize;
        if seen[idx] {
            return Err(Error::DuplicateIndex);
        }
        seen[idx] = true;
        if piece.payload.len() != shard_len {
            return Err(Error::InvalidShardLength);
        }
        unique_count += 1;
    }

    if unique_count < k {
        return Err(Error::TooFewShards);
    }

    for piece in pieces {
        let chunk = Chunk {
            parameters: dp_params,
            index: piece.index,
            payload: piece.payload,
        };
        verify_chunk(chunk, piece.proof, untrusted_root).map_err(|_| Error::InvalidProof)?;
    }

    let mut slots: Vec<Option<Vec<u8>>> = vec![None; n];
    for piece in pieces {
        slots[piece.index as usize] = Some(piece.payload.to_vec());
    }

    let rs = ReedSolomon8::new(k, n)?;
    rs.reconstruct(&mut slots)?;

    let mut data_shards = Vec::with_capacity(k);
    for slot in slots.iter().take(k) {
        data_shards.push(slot.as_ref().ok_or(Error::TooFewShards)?.clone());
    }
    let payload = unpad_canonical(&data_shards, params)?;

    // Re-encode the full n-shard codeword and verify consistency against both
    // every supplied verified shard and `untrusted_root`.
    let mut reencoded = data_shards;
    reencoded.resize_with(n, || vec![0u8; shard_len]);
    rs.encode_shards(&mut reencoded)?;

    for (idx, shard) in reencoded.iter().enumerate() {
        if let Some(existing) = &slots[idx] {
            if shard != existing {
                return Err(Error::InconsistentCodeword);
            }
        }
    }

    let reencoded_root = compute_merkle_root(&reencoded, dp_params)?;
    if reencoded_root != *untrusted_root {
        return Err(Error::InconsistentCodeword);
    }

    Ok(payload)
}
