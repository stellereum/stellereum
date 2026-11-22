//! Pure-Rust 256-bit Prime Field + Time-Asymmetric Checkpointed `MinRoot` Post-Quantum VDF
//! for Stellereum's CN-VRF v3.
//!
//! # Prime Field
//! Uses the verified 256-bit safe prime:
//! `p = 2^256 - 36113 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff72ef`
//! where:
//! - `p < 2^256` (exact 256-bit prime; `(p - 1) / 2` is also prime),
//! - `p ≡ 2 (mod 3)`, so `gcd(3, p - 1) = 1` and every `z in F_p` has a unique cube root
//!   `z^((2p - 1) / 3) mod p`.
//!
//! # Time Asymmetry
//! - **Forward step (`eval`)**:
//!   `x_{i+1} = (x_i + y_i + c_i)^((2p - 1) / 3) mod p`, `y_{i+1} = x_i`.
//!   Costs 294 field ops per step (255 squarings + 39 multiplications via an exact addition chain
//!   for `(2p - 1) / 3`) and is strictly sequential.
//! - **Backward step (`verify`)**:
//!   `x_i = y_{i+1}`, `y_i = (x_{i+1}^3 - y_{i+1} - c_i) mod p`.
//!   Costs only **2 modular multiplications per step** (`x_{i+1}^2 * x_{i+1}`) and can be
//!   verified in parallel across checkpoint segments via `rayon`.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Domain separator for mapping the 48-byte `seed` to initial `(x_0, y_0) in F_p x F_p`.
pub const MINROOT_INIT_DST: &str = "STELL_MINROOT_VDF_V1_INIT";

/// Domain separator for deriving the canonical 48-byte VDF beacon output.
pub const MINROOT_OUT_DST: &str = "STELL_MINROOT_VDF_V1_OUT";

/// Anti-DoS upper bound on the number of checkpoints accepted in a [`MinRootProof`].
pub const MAX_VDF_CHECKPOINTS: usize = 4096;

/// Fast unit-test step count.
pub const TEST_VDF_STEPS: u64 = 64;

/// Calibrated default VDF steps per epoch.
///
/// RULESET v2 MEASUREMENT (2026-11-19, release build, one core, AMD Ryzen 5
/// 3600): 3,000,000 steps = **20.455 s** (146,662 steps/s); 300,000 steps =
/// 2.023 s (linear). The epoch length is 30,000 heights = 2 h at 240 ms, so
/// the evaluation is ~0.28% of the epoch. The commit lookahead
/// [`crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS`] (682 heights = 163.68 s) is
/// derived from this measurement with a 4x weak-host allowance and 2x
/// scheduling headroom. See `docs/RULESET_V2.md` §VDF.
pub const DEFAULT_VDF_STEPS_PER_EPOCH: u64 = 3_000_000;

/// 256-bit safe prime `p = 2^256 - 36113` in little-endian `[u64; 4]` limbs.
/// `p ≡ 2 (mod 3)`, `q = (p - 1) / 2` is prime.
pub const P_LIMBS: [u64; 4] = [
    0xffff_ffff_ffff_72ef,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// Montgomery radix `R = 2^256 mod p = 36113`.
const R_MOD_P: [u64; 4] = [0x8d11, 0, 0, 0];

/// `R^2 mod p = 36113^2 mod p = 1304148769`.
const R2_MOD_P: [u64; 4] = [0x4dbb_bb21, 0, 0, 0];

/// `-p[0]^(-1) mod 2^64`.
const P_INV: u64 = 0x31d7_7e87_7094_03f1;

/// Cube-root exponent `(2p - 1) / 3` in little-endian `[u64; 4]` limbs.
/// `0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4c9f`.
pub const CUBE_ROOT_EXP: [u64; 4] = [
    0xaaaa_aaaa_aaaa_4c9f,
    0xaaaa_aaaa_aaaa_aaaa,
    0xaaaa_aaaa_aaaa_aaaa,
    0xaaaa_aaaa_aaaa_aaaa,
];

/// Domain-separated round constant high limbs in Montgomery representation.
/// Because `ROUND_C_LIMB3 < P_LIMBS[3] == u64::MAX`, `[step + 1, C1, C2, C3]` is strictly `< p`
/// and non-zero for every `step: u64`, breaking polynomial homogeneity with zero loop overhead.
const ROUND_C_LIMB1: u64 = 0x5354_454c_4c5f_4d52; // "STELL_MR"
const ROUND_C_LIMB2: u64 = 0x5644_465f_5631_5f43; // "VDF_V1_C"
const ROUND_C_LIMB3: u64 = 0x4d49_4e52_5631_3031; // "MINRV101"

/// Element of `F_p` stored in canonical Montgomery representation (`limbs * R mod p`, `< p`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Fe256(pub [u64; 4]);

impl Fe256 {
    /// Additive identity `0` in Montgomery form (`0 * R mod p = 0`).
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// Multiplicative identity `1` in Montgomery form (`1 * R mod p = R mod p`).
    pub const ONE: Self = Self(R_MOD_P);

    /// Returns `true` iff this element is `0`.
    #[inline]
    pub fn is_zero(&self) -> bool {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0
    }

    /// Converts a canonical `[u64; 4]` integer `< p` into Montgomery form.
    ///
    /// Returns `None` if `limbs >= p`.
    #[inline]
    pub fn from_canonical_limbs(limbs: [u64; 4]) -> Option<Self> {
        if !lt_p(&limbs) {
            return None;
        }
        Some(Self(mont_mul(&limbs, &R2_MOD_P)))
    }

    /// Converts a `u64` into Montgomery form.
    #[inline]
    pub fn from_u64(v: u64) -> Self {
        Self(mont_mul(&[v, 0, 0, 0], &R2_MOD_P))
    }

    /// Converts from Montgomery form back to canonical integer limbs `< p`.
    #[inline]
    pub fn to_canonical_limbs(self) -> [u64; 4] {
        mont_reduce_256(&self.0)
    }

    /// Decodes a little-endian 32-byte canonical field element `< p`.
    ///
    /// Rejects (`None`) any non-canonical encoding `>= p`.
    #[inline]
    pub fn from_bytes_canonical(bytes: &[u8; 32]) -> Option<Self> {
        let limbs = [
            u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes")),
            u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")),
            u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes")),
            u64::from_le_bytes(bytes[24..32].try_into().expect("8 bytes")),
        ];
        Self::from_canonical_limbs(limbs)
    }

    /// Encodes this field element as canonical little-endian 32 bytes `< p`.
    #[inline]
    pub fn to_bytes_canonical(self) -> [u8; 32] {
        let limbs = self.to_canonical_limbs();
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&limbs[0].to_le_bytes());
        out[8..16].copy_from_slice(&limbs[1].to_le_bytes());
        out[16..24].copy_from_slice(&limbs[2].to_le_bytes());
        out[24..32].copy_from_slice(&limbs[3].to_le_bytes());
        out
    }

    /// Constant-time conditional select: returns `a` if `choice == 1`, `b` if `choice == 0`.
    #[inline(always)]
    fn ct_select(a: Self, b: Self, choice: u64) -> Self {
        let mask = 0u64.wrapping_sub(choice & 1);
        Self([
            b.0[0] ^ (mask & (a.0[0] ^ b.0[0])),
            b.0[1] ^ (mask & (a.0[1] ^ b.0[1])),
            b.0[2] ^ (mask & (a.0[2] ^ b.0[2])),
            b.0[3] ^ (mask & (a.0[3] ^ b.0[3])),
        ])
    }

    /// Modular addition `(self + rhs) mod p` in constant time.
    #[allow(clippy::should_implement_trait)] // GATE: inherent constant-time field op API alongside core::ops::Add
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        let (s, carry) = add_256(&self.0, &rhs.0);
        Self(reduce_once_p(&s, carry))
    }

    /// Modular subtraction `(self - rhs) mod p` in constant time.
    #[allow(clippy::should_implement_trait)] // GATE: inherent constant-time field op API alongside core::ops::Sub
    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        let (d, borrow) = sub_256(&self.0, &rhs.0);
        let (s, _) = add_256(&d, &P_LIMBS);
        let mask = 0u64.wrapping_sub(borrow);
        Self([
            d[0] ^ (mask & (s[0] ^ d[0])),
            d[1] ^ (mask & (s[1] ^ d[1])),
            d[2] ^ (mask & (s[2] ^ d[2])),
            d[3] ^ (mask & (s[3] ^ d[3])),
        ])
    }

    /// Modular multiplication `(self * rhs) mod p` in Montgomery form (CIOS).
    #[allow(clippy::should_implement_trait)] // GATE: inherent constant-time field op API alongside core::ops::Mul
    #[inline]
    pub fn mul(self, rhs: Self) -> Self {
        Self(mont_mul(&self.0, &rhs.0))
    }

    /// Modular squaring `self^2 mod p` in Montgomery form (dedicated SOS).
    #[inline]
    pub fn sqr(self) -> Self {
        Self(mont_sqr(&self.0))
    }

    /// Constant-time 4-bit windowed modular exponentiation `self^exp mod p`.
    pub fn pow(self, exp: &[u64; 4]) -> Self {
        let mut table = [Self::ONE; 16];
        table[1] = self;
        for i in 2..16 {
            table[i] = table[i - 1].mul(self);
        }

        let mut acc = Self::ONE;
        for limb in exp.iter().rev() {
            for shift in (0..64).step_by(4).rev() {
                acc = acc.sqr().sqr().sqr().sqr();
                let idx = ((limb >> shift) & 0xf) as usize;
                let mut selected = Self::ONE;
                for (j, &entry) in table.iter().enumerate() {
                    let eq = u64::from(j == idx);
                    selected = Self::ct_select(entry, selected, eq);
                }
                acc = acc.mul(selected);
            }
        }
        acc
    }

    /// Unique modular cube root `self^((2p - 1) / 3) mod p`.
    ///
    /// Uses a fixed, branchless addition chain for
    /// `CUBE_ROOT_EXP = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4c9f`
    /// (255 squarings + 39 multiplications = 294 field ops).
    #[inline]
    pub fn cube_root(self) -> Self {
        let x2 = self.sqr();
        let x3 = x2.mul(self);
        let x4 = x2.sqr();
        let x8 = x4.sqr();
        let x9 = x8.mul(self);
        let x10 = x8.mul(x2);
        let x12 = x8.mul(x4);
        let x15 = x12.mul(x3);

        // x^0xaa = (x^10)^16 * x^10
        let x_aa = x10.sqr().sqr().sqr().sqr().mul(x10);

        // Byte 31 is 0xaa.
        let mut acc = x_aa;
        // Bytes 30 down to 2 (29 bytes) are all 0xaa.
        for _ in 0..29 {
            acc = acc.sqr().sqr().sqr().sqr().sqr().sqr().sqr().sqr();
            acc = acc.mul(x_aa);
        }

        // Byte 1 is 0x4c -> nibbles 0x4, 0xc (12).
        acc = acc.sqr().sqr().sqr().sqr().mul(x4);
        acc = acc.sqr().sqr().sqr().sqr().mul(x12);

        // Byte 0 is 0x9f -> nibbles 0x9, 0xf (15).
        acc = acc.sqr().sqr().sqr().sqr().mul(x9);
        acc = acc.sqr().sqr().sqr().sqr().mul(x15);

        acc
    }
}

impl core::ops::Add for Fe256 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Fe256::add(self, rhs)
    }
}

impl core::ops::Sub for Fe256 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Fe256::sub(self, rhs)
    }
}

impl core::ops::Mul for Fe256 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Fe256::mul(self, rhs)
    }
}

/// Checkpointed MinRoot VDF proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinRootProof {
    /// Total number of sequential MinRoot steps `T`.
    pub steps: u64,
    /// Final state `(x_T, y_T)` encoded as canonical 32-byte little-endian elements `< p`.
    pub final_xy: ([u8; 32], [u8; 32]),
    /// Strictly increasing intermediate checkpoints `(step_idx, x_idx, y_idx)` inside `(0, steps)`.
    pub checkpoints: Vec<(u64, [u8; 32], [u8; 32])>,
}

/// Deterministically maps a 48-byte `seed` via `BLAKE3` (`derive_key`) to `(x_0, y_0) in F_p x F_p`.
pub fn init_state_from_seed(seed: &[u8; 48]) -> (Fe256, Fe256) {
    let mut hasher = blake3::Hasher::new_derive_key(MINROOT_INIT_DST);
    hasher.update(seed);
    let mut buf = [0u8; 64];
    hasher.finalize_xof().fill(&mut buf);

    let mut x0 = reduce_le_256_bytes_to_fe(&buf[0..32]);
    let mut y0 = reduce_le_256_bytes_to_fe(&buf[32..64]);
    if x0.is_zero() {
        x0 = Fe256::ONE;
    }
    if y0.is_zero() {
        y0 = Fe256::ONE;
    }
    (x0, y0)
}

/// Evaluates the MinRoot VDF sequentially for `steps` steps from `seed`, recording up to
/// `num_checkpoints` evenly spaced intermediate states inside `(0, steps)`.
///
/// # Panics
/// Panics if `steps == 0`.
pub fn eval(seed: &[u8; 48], steps: u64, num_checkpoints: usize) -> MinRootProof {
    assert!(steps > 0, "MinRoot VDF steps must be > 0");

    let target_cps = if num_checkpoints == 0 || steps <= 1 {
        0
    } else {
        num_checkpoints
            .min(MAX_VDF_CHECKPOINTS)
            .min((steps - 1) as usize)
    };

    let mut cp_indices = Vec::with_capacity(target_cps);
    for j in 1..=target_cps {
        let idx = (((j as u128) * (steps as u128)) / ((target_cps + 1) as u128)) as u64;
        cp_indices.push(idx);
    }

    let (mut x, mut y) = init_state_from_seed(seed);
    let mut checkpoints = Vec::with_capacity(target_cps);
    let mut next_cp_cursor = 0usize;

    for step in 0..steps {
        (x, y) = step_forward(x, y, step);
        let state_idx = step + 1;
        if next_cp_cursor < cp_indices.len() && state_idx == cp_indices[next_cp_cursor] {
            checkpoints.push((state_idx, x.to_bytes_canonical(), y.to_bytes_canonical()));
            next_cp_cursor += 1;
        }
    }

    MinRootProof {
        steps,
        final_xy: (x.to_bytes_canonical(), y.to_bytes_canonical()),
        checkpoints,
    }
}

/// Verifies a [`MinRootProof`] against `(seed, steps)` using backward step inversion
/// (`2 modular multiplications per step`), parallelizing across checkpoint segments via `rayon`.
///
/// Returns `Some(output)` (the canonical 48-byte VDF beacon output) iff all validation and
/// algebraic segment checks pass, or `None` on any invalid/non-canonical/tampered input.
pub fn verify(seed: &[u8; 48], steps: u64, proof: &MinRootProof) -> Option<[u8; 48]> {
    if steps == 0 || proof.steps != steps {
        return None;
    }
    if proof.checkpoints.len() > MAX_VDF_CHECKPOINTS {
        return None;
    }

    let final_x = Fe256::from_bytes_canonical(&proof.final_xy.0)?;
    let final_y = Fe256::from_bytes_canonical(&proof.final_xy.1)?;
    let start_xy = init_state_from_seed(seed);

    if proof.checkpoints.is_empty() {
        if verify_segment(0, start_xy, steps, (final_x, final_y)) {
            return Some(derive_vdf_output(seed, proof));
        }
        return None;
    }

    let mut decoded_cps = Vec::with_capacity(proof.checkpoints.len());
    let mut prev_idx = 0u64;
    for &(idx, ref cx_bytes, ref cy_bytes) in &proof.checkpoints {
        if idx == 0 || idx >= steps || idx <= prev_idx {
            return None;
        }
        let cx = Fe256::from_bytes_canonical(cx_bytes)?;
        let cy = Fe256::from_bytes_canonical(cy_bytes)?;
        decoded_cps.push((idx, (cx, cy)));
        prev_idx = idx;
    }

    let mut segments = Vec::with_capacity(decoded_cps.len() + 1);
    let mut cur_start_idx = 0u64;
    let mut cur_start_xy = start_xy;
    for (cp_idx, cp_xy) in decoded_cps {
        segments.push((cur_start_idx, cur_start_xy, cp_idx, cp_xy));
        cur_start_idx = cp_idx;
        cur_start_xy = cp_xy;
    }
    segments.push((cur_start_idx, cur_start_xy, steps, (final_x, final_y)));

    let valid = segments
        .par_iter()
        .all(|&(s_idx, s_xy, e_idx, e_xy)| verify_segment(s_idx, s_xy, e_idx, e_xy));

    if valid {
        Some(derive_vdf_output(seed, proof))
    } else {
        None
    }
}

/// Derives the canonical 48-byte VDF beacon output:
/// `BLAKE3_XOF("STELL_MINROOT_VDF_V1_OUT", seed || steps_le || final_x || final_y, 48)`.
pub fn derive_vdf_output(seed: &[u8; 48], proof: &MinRootProof) -> [u8; 48] {
    let mut hasher = blake3::Hasher::new_derive_key(MINROOT_OUT_DST);
    hasher.update(seed);
    hasher.update(&proof.steps.to_le_bytes());
    hasher.update(&proof.final_xy.0);
    hasher.update(&proof.final_xy.1);
    let mut out = [0u8; 48];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Cheap, unique, non-zero round constant `c_i` in canonical Montgomery form.
#[inline(always)]
fn round_constant(step: u64) -> Fe256 {
    Fe256([
        step.wrapping_add(1),
        ROUND_C_LIMB1,
        ROUND_C_LIMB2,
        ROUND_C_LIMB3,
    ])
}

/// One sequential forward step `i`:
/// `x_{i+1} = (x_i + y_i + c_i)^((2p - 1) / 3) mod p`, `y_{i+1} = x_i`.
#[inline]
fn step_forward(x: Fe256, y: Fe256, step: u64) -> (Fe256, Fe256) {
    let c = round_constant(step);
    let sum = x.add(y).add(c);
    let next_x = sum.cube_root();
    (next_x, x)
}

/// One backward verification step `i`:
/// `x_i = y_{i+1}`, `y_i = (x_{i+1}^3 - y_{i+1} - c_i) mod p` (only 2 modular multiplications).
#[inline]
fn step_backward(x_next: Fe256, y_next: Fe256, step: u64) -> (Fe256, Fe256) {
    let c = round_constant(step);
    let x3 = x_next.sqr().mul(x_next);
    let y = x3.sub(y_next).sub(c);
    (y_next, y)
}

#[inline]
fn verify_segment(
    start_step: u64,
    expected_start: (Fe256, Fe256),
    end_step: u64,
    end_xy: (Fe256, Fe256),
) -> bool {
    let (mut x, mut y) = end_xy;
    for step in (start_step..end_step).rev() {
        (x, y) = step_backward(x, y, step);
    }
    x == expected_start.0 && y == expected_start.1
}

/// Reduces a 32-byte little-endian integer modulo `p` and converts to Montgomery form.
fn reduce_le_256_bytes_to_fe(bytes: &[u8]) -> Fe256 {
    let raw = [
        u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes")),
        u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes")),
        u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes")),
        u64::from_le_bytes(bytes[24..32].try_into().expect("8 bytes")),
    ];
    let reduced = reduce_once_p(&raw, 0);
    Fe256(mont_mul(&reduced, &R2_MOD_P))
}

// ---------------------------------------------------------------------------
// Constant-time [u64; 4] limb & Montgomery arithmetic primitives
// ---------------------------------------------------------------------------

#[inline(always)]
fn add_256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let sum = (a[i] as u128) + (b[i] as u128) + carry;
        out[i] = sum as u64;
        carry = sum >> 64;
    }
    (out, carry as u64)
}

#[inline(always)]
fn sub_256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = u64::from(b1 | b2);
    }
    (out, borrow)
}

#[inline(always)]
fn lt_p(a: &[u64; 4]) -> bool {
    let (_, borrow) = sub_256(a, &P_LIMBS);
    borrow == 1
}

/// Given `a + (hi << 256) < 2*p`, returns `(a + (hi << 256)) mod p` in constant time.
#[inline(always)]
fn reduce_once_p(a: &[u64; 4], hi: u64) -> [u64; 4] {
    let (d, borrow) = sub_256(a, &P_LIMBS);
    let take_diff = (hi != 0) || (borrow == 0);
    let mask = 0u64.wrapping_sub(u64::from(take_diff));
    [
        a[0] ^ (mask & (d[0] ^ a[0])),
        a[1] ^ (mask & (d[1] ^ a[1])),
        a[2] ^ (mask & (d[2] ^ a[2])),
        a[3] ^ (mask & (d[3] ^ a[3])),
    ]
}

/// CIOS Montgomery multiplication: `(a * b * R^(-1)) mod p` for `a, b < p`.
#[inline]
fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut t = [0u64; 4];
    let mut t4 = 0u64;

    for &bi in b {
        // Multiply-accumulate: t += a * bi
        let mut carry = 0u128;
        for j in 0..4 {
            let prod = (t[j] as u128) + (a[j] as u128) * (bi as u128) + carry;
            t[j] = prod as u64;
            carry = prod >> 64;
        }
        let sum4 = (t4 as u128) + carry;
        t4 = sum4 as u64;
        let t5 = (sum4 >> 64) as u64;

        // Montgomery reduction step: t = (t + m * p) / 2^64
        let m = t[0].wrapping_mul(P_INV);
        let prod0 = (t[0] as u128) + (m as u128) * (P_LIMBS[0] as u128);
        let mut r_carry = prod0 >> 64;
        for j in 1..4 {
            let prod = (t[j] as u128) + (m as u128) * (P_LIMBS[j] as u128) + r_carry;
            t[j - 1] = prod as u64;
            r_carry = prod >> 64;
        }
        let sum_top = (t4 as u128) + r_carry;
        t[3] = sum_top as u64;
        t4 = t5.wrapping_add((sum_top >> 64) as u64);
    }

    reduce_once_p(&t, t4)
}

/// SOS Montgomery squaring: `(a^2 * R^(-1)) mod p` for `a < p`.
#[inline]
fn mont_sqr(a: &[u64; 4]) -> [u64; 4] {
    let mut r = [0u64; 8];

    // 1. Cross-products (i < j)
    for i in 0..4 {
        let mut carry = 0u128;
        for j in (i + 1)..4 {
            let prod = (r[i + j] as u128) + (a[i] as u128) * (a[j] as u128) + carry;
            r[i + j] = prod as u64;
            carry = prod >> 64;
        }
        r[i + 4] = carry as u64;
    }

    // 2. Double cross-products (left shift by 1 across 8 limbs)
    let mut prev_top = 0u64;
    for limb in &mut r {
        let next_top = *limb >> 63;
        *limb = (*limb << 1) | prev_top;
        prev_top = next_top;
    }

    // 3. Add diagonal squares a[i]^2
    let mut carry = 0u128;
    for i in 0..4 {
        let sq = (a[i] as u128) * (a[i] as u128);
        let lo = (r[2 * i] as u128) + (sq as u64 as u128) + carry;
        r[2 * i] = lo as u64;
        let hi = (r[2 * i + 1] as u128) + (sq >> 64) + (lo >> 64);
        r[2 * i + 1] = hi as u64;
        carry = hi >> 64;
    }

    mont_reduce_512(&mut r)
}

/// Reduces a 512-bit product `< p^2` in-place via 4 Montgomery steps.
#[inline(always)]
fn mont_reduce_512(r: &mut [u64; 8]) -> [u64; 4] {
    let mut overflow = 0u64;
    for i in 0..4 {
        let m = r[i].wrapping_mul(P_INV);
        let mut carry = 0u128;
        for j in 0..4 {
            let prod = (r[i + j] as u128) + (m as u128) * (P_LIMBS[j] as u128) + carry;
            r[i + j] = prod as u64;
            carry = prod >> 64;
        }
        // Propagate carry through upper limbs
        for rk in &mut r[(i + 4)..8] {
            let sum = (*rk as u128) + carry;
            *rk = sum as u64;
            carry = sum >> 64;
        }
        overflow = overflow.wrapping_add(carry as u64);
    }

    let res = [r[4], r[5], r[6], r[7]];
    reduce_once_p(&res, overflow)
}

/// Converts a 256-bit Montgomery value `a < p` back to `(a * R^(-1)) mod p`.
#[inline]
fn mont_reduce_256(a: &[u64; 4]) -> [u64; 4] {
    let mut r = [a[0], a[1], a[2], a[3], 0, 0, 0, 0];
    mont_reduce_512(&mut r)
}

// ---------------------------------------------------------------------------
// Comprehensive Unit Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // Independent schoolbook 256-bit modular arithmetic (not using Montgomery)
    // to verify primality and cross-check Montgomery field operations.
    fn cmp_256(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            if a[i] != b[i] {
                return a[i].cmp(&b[i]);
            }
        }
        core::cmp::Ordering::Equal
    }

    fn shl1_256(a: &mut [u64; 4]) -> u64 {
        let mut carry = 0u64;
        for limb in a.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        carry
    }

    fn add_mod_schoolbook(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
        let (mut s, mut carry) = add_256(a, b);
        if carry != 0 || cmp_256(&s, m) != core::cmp::Ordering::Less {
            let (d, borrow) = sub_256(&s, m);
            s = d;
            carry = carry.saturating_sub(borrow);
            let _ = carry;
        }
        s
    }

    fn mul_mod_schoolbook(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
        let mut res = [0u64; 4];
        let mut cur = *a;
        for limb in b {
            for bit in 0..64 {
                if ((limb >> bit) & 1) == 1 {
                    res = add_mod_schoolbook(&res, &cur, m);
                }
                let hi = shl1_256(&mut cur);
                if hi != 0 || cmp_256(&cur, m) != core::cmp::Ordering::Less {
                    let (d, _) = sub_256(&cur, m);
                    cur = d;
                }
            }
        }
        res
    }

    fn pow_mod_schoolbook(base: &[u64; 4], exp: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
        let mut res = [1, 0, 0, 0];
        let mut b = *base;
        for limb in exp {
            for bit in 0..64 {
                if ((limb >> bit) & 1) == 1 {
                    res = mul_mod_schoolbook(&res, &b, m);
                }
                b = mul_mod_schoolbook(&b, &b, m);
            }
        }
        res
    }

    fn is_prime_miller_rabin_256(n: &[u64; 4]) -> bool {
        // n - 1 = d * 2^s (since n is odd with n[0] & 1 == 1)
        let (n_minus_1, _) = sub_256(n, &[1, 0, 0, 0]);
        let mut d = n_minus_1;
        let mut s = 0u32;
        while (d[0] & 1) == 0 {
            for i in 0..3 {
                d[i] = (d[i] >> 1) | (d[i + 1] << 63);
            }
            d[3] >>= 1;
            s += 1;
        }

        // 46 strong prime bases
        const BASES: [u64; 46] = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199,
        ];

        for &a in &BASES {
            let mut x = pow_mod_schoolbook(&[a, 0, 0, 0], &d, n);
            if x == [1, 0, 0, 0] || x == n_minus_1 {
                continue;
            }
            let mut witness = true;
            for _ in 0..(s - 1) {
                x = mul_mod_schoolbook(&x, &x, n);
                if x == n_minus_1 {
                    witness = false;
                    break;
                }
            }
            if witness {
                return false;
            }
        }
        true
    }

    #[test]
    fn test_prime_properties_and_safe_prime_primality() {
        // 1. Exact 256-bit prime (MSB == 1)
        assert_ne!(P_LIMBS[3] >> 63, 0, "p must have bit 255 set");

        // 2. p % 3 == 2
        let rem3 = P_LIMBS
            .iter()
            .rev()
            .fold(0u128, |acc, &limb| ((acc << 64) | (limb as u128)) % 3);
        assert_eq!(rem3, 2, "p must satisfy p ≡ 2 (mod 3)");

        // 3. Deterministic/strong Miller-Rabin with 46 bases on p AND q = (p - 1) / 2
        assert!(
            is_prime_miller_rabin_256(&P_LIMBS),
            "p failed Miller-Rabin primality test"
        );
        let (p_minus_1, _) = sub_256(&P_LIMBS, &[1, 0, 0, 0]);
        let q = [
            (p_minus_1[0] >> 1) | (p_minus_1[1] << 63),
            (p_minus_1[1] >> 1) | (p_minus_1[2] << 63),
            (p_minus_1[2] >> 1) | (p_minus_1[3] << 63),
            p_minus_1[3] >> 1,
        ];
        assert!(
            is_prime_miller_rabin_256(&q),
            "q = (p - 1) / 2 failed Miller-Rabin primality test"
        );

        // 4. Verify 3 * CUBE_ROOT_EXP ≡ 1 (mod p - 1)
        let prod = mul_mod_schoolbook(&[3, 0, 0, 0], &CUBE_ROOT_EXP, &p_minus_1);
        assert_eq!(prod, [1, 0, 0, 0], "3 * ((2p-1)/3) must be 1 mod (p-1)");

        // 5. Verify Montgomery constants
        assert_eq!(P_LIMBS[0].wrapping_mul(P_INV), u64::MAX);
    }

    #[test]
    fn test_montgomery_arithmetic_and_cube_root() {
        let (p_minus_1, _) = sub_256(&P_LIMBS, &[1, 0, 0, 0]);
        let (p_minus_2, _) = sub_256(&P_LIMBS, &[2, 0, 0, 0]);
        let samples: [[u64; 4]; 7] = [
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            [
                0x1234_5678_9abc_def0,
                0xfedc_ba98_7654_3210,
                0xdead_beef_cafe_babe,
                0x0123_4567_89ab_cdef,
            ],
            [u64::MAX, u64::MAX, u64::MAX, 0x7fff_ffff_ffff_ffff],
            p_minus_2,
            p_minus_1,
        ];

        for &a_raw in &samples {
            let a = Fe256::from_canonical_limbs(a_raw).expect("valid limb < p");
            assert_eq!(a.to_canonical_limbs(), a_raw);

            // sqr == mul(a, a) == schoolbook
            let sq_mont = a.sqr().to_canonical_limbs();
            let mul_self = a.mul(a).to_canonical_limbs();
            let sq_sb = mul_mod_schoolbook(&a_raw, &a_raw, &P_LIMBS);
            assert_eq!(sq_mont, mul_self);
            assert_eq!(sq_mont, sq_sb);

            // cube_root matches pow(&CUBE_ROOT_EXP) and (cube_root(a))^3 == a
            let cr = a.cube_root();
            let cr_pow = a.pow(&CUBE_ROOT_EXP);
            assert_eq!(cr, cr_pow, "cube_root addition chain must match pow");
            let cubed = cr.sqr().mul(cr);
            assert_eq!(cubed, a, "(cube_root(a))^3 must equal a");

            for &b_raw in &samples {
                let b = Fe256::from_canonical_limbs(b_raw).expect("valid limb < p");
                assert_eq!(
                    a.mul(b).to_canonical_limbs(),
                    mul_mod_schoolbook(&a_raw, &b_raw, &P_LIMBS)
                );
                assert_eq!(
                    a.add(b).to_canonical_limbs(),
                    add_mod_schoolbook(&a_raw, &b_raw, &P_LIMBS)
                );
                assert_eq!(a.add(b).sub(b), a);
            }
        }

        // Reject >= p in canonical decoding
        assert!(Fe256::from_canonical_limbs(P_LIMBS).is_none());
        assert!(Fe256::from_canonical_limbs([u64::MAX; 4]).is_none());
    }

    #[test]
    fn test_eval_verify_roundtrip_and_tamper_rejection() {
        let seed = [0x42u8; 48];

        // 0 checkpoints
        let proof0 = eval(&seed, TEST_VDF_STEPS, 0);
        assert!(proof0.checkpoints.is_empty());
        let out0 = verify(&seed, TEST_VDF_STEPS, &proof0).expect("0-cp proof should verify");

        // 16 checkpoints
        let proof16 = eval(&seed, TEST_VDF_STEPS, 16);
        assert_eq!(proof16.checkpoints.len(), 16);
        let out16 = verify(&seed, TEST_VDF_STEPS, &proof16).expect("16-cp proof should verify");
        assert_eq!(out0, out16);
        assert_eq!(out0, derive_vdf_output(&seed, &proof0));

        // 1 step edge case
        let proof1 = eval(&seed, 1, 16);
        assert!(proof1.checkpoints.is_empty());
        assert!(verify(&seed, 1, &proof1).is_some());

        // Tamper final_xy
        let mut bad = proof16.clone();
        bad.final_xy.0[0] ^= 1;
        assert!(verify(&seed, TEST_VDF_STEPS, &bad).is_none());

        let mut bad = proof16.clone();
        bad.final_xy.1[17] ^= 0x80;
        assert!(verify(&seed, TEST_VDF_STEPS, &bad).is_none());

        // Tamper checkpoint state
        let mut bad = proof16.clone();
        bad.checkpoints[7].1[0] ^= 1;
        assert!(verify(&seed, TEST_VDF_STEPS, &bad).is_none());

        // Non-canonical >= p in final_xy and in checkpoint
        let p_bytes = Fe256(P_LIMBS); // raw p bytes
        let mut p_raw_bytes = [0u8; 32];
        for (i, limb) in p_bytes.0.iter().enumerate() {
            p_raw_bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        let mut bad = proof0.clone();
        bad.final_xy.0 = p_raw_bytes;
        assert!(verify(&seed, TEST_VDF_STEPS, &bad).is_none());

        let mut bad = proof16.clone();
        bad.checkpoints[0].2 = [0xffu8; 32];
        assert!(verify(&seed, TEST_VDF_STEPS, &bad).is_none());

        // Duplicate / out-of-order / boundary checkpoint indices
        let mut bad = proof16.clone();
        bad.checkpoints[1].0 = bad.checkpoints[0].0;
        assert!(verify(&seed, TEST_VDF_STEPS, &bad).is_none());

        let mut bad = proof16.clone();
        bad.checkpoints.swap(2, 3);
        assert!(verify(&seed, TEST_VDF_STEPS, &bad).is_none());

        let mut bad = proof16.clone();
        bad.checkpoints[0].0 = 0;
        assert!(verify(&seed, TEST_VDF_STEPS, &bad).is_none());

        let mut bad = proof16.clone();
        bad.checkpoints[15].0 = TEST_VDF_STEPS;
        assert!(verify(&seed, TEST_VDF_STEPS, &bad).is_none());

        // Wrong steps / zero steps / wrong seed
        assert!(verify(&seed, 0, &proof0).is_none());
        assert!(verify(&seed, TEST_VDF_STEPS + 1, &proof0).is_none());
        let mut bad_steps = proof0.clone();
        bad_steps.steps = TEST_VDF_STEPS + 1;
        assert!(verify(&seed, TEST_VDF_STEPS, &bad_steps).is_none());
        let mut wrong_seed = seed;
        wrong_seed[0] ^= 1;
        assert!(verify(&wrong_seed, TEST_VDF_STEPS, &proof16).is_none());

        // Anti-DoS checkpoint cap rejection
        let mut dos_proof = proof0.clone();
        dos_proof.checkpoints = vec![(1, [0u8; 32], [0u8; 32]); MAX_VDF_CHECKPOINTS + 1];
        assert!(verify(&seed, TEST_VDF_STEPS, &dos_proof).is_none());

        // Distinct seeds produce distinct outputs
        let mut seed2 = [0x42u8; 48];
        seed2[47] ^= 1;
        let proof_s2 = eval(&seed2, TEST_VDF_STEPS, 4);
        let out_s2 = verify(&seed2, TEST_VDF_STEPS, &proof_s2).expect("seed2 verifies");
        assert_ne!(out0, out_s2);
    }

    #[test]
    fn bench_eval_vs_verify_asymmetry() {
        let seed = [0x99u8; 48];
        #[cfg(not(debug_assertions))]
        let steps: u64 = 50_000;
        #[cfg(debug_assertions)]
        let steps: u64 = 1_000;

        let t0 = std::time::Instant::now();
        let proof_no_cp = eval(&seed, steps, 0);
        let eval_dur = t0.elapsed();

        let t1 = std::time::Instant::now();
        let out_1core = verify(&seed, steps, &proof_no_cp).expect("verify 0-cp");
        let verify_1core_dur = t1.elapsed();

        let proof_cp = eval(&seed, steps, 16);
        let t2 = std::time::Instant::now();
        let out_par = verify(&seed, steps, &proof_cp).expect("verify 16-cp");
        let verify_par_dur = t2.elapsed();

        assert_eq!(out_1core, out_par);

        let eval_sps = steps as f64 / eval_dur.as_secs_f64();
        let verify_1core_sps = steps as f64 / verify_1core_dur.as_secs_f64();
        let verify_par_sps = steps as f64 / verify_par_dur.as_secs_f64();
        let ratio_1core = eval_dur.as_secs_f64() / verify_1core_dur.as_secs_f64();
        let ratio_par = eval_dur.as_secs_f64() / verify_par_dur.as_secs_f64();

        println!(
            "MINROOT_BENCH steps={} eval={:.3}ms ({:.0} steps/s) verify_1core={:.3}ms ({:.0} steps/s, ratio={:.1}x) verify_16cp_par={:.3}ms ({:.0} steps/s, ratio={:.1}x)",
            steps,
            eval_dur.as_secs_f64() * 1000.0,
            eval_sps,
            verify_1core_dur.as_secs_f64() * 1000.0,
            verify_1core_sps,
            ratio_1core,
            verify_par_dur.as_secs_f64() * 1000.0,
            verify_par_sps,
            ratio_par,
        );
    }
}
