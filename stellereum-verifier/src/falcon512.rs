//! Independent pure-Rust NIST FIPS 206 (FN-DSA) Falcon-512 verifier and PQ address derivation.
//!
//! Enforces Stellereum chain-canonical framing strictly (fail-closed):
//! - Public key: 897 bytes, `pubkey[0] == 0x09`, canonical 14-bit big-endian coefficients `< 12289`
//! - Signature: 666 bytes, `sig[0] == 0x29` (rejects PQClean `0x39`), non-zero 40-byte nonce,
//!   canonical compressed `s2` with strict all-zero trailing bit and byte padding
//! - Challenge: `SHAKE256(nonce || message)` rejection-sampled into `Z_12289[x]/(x^512 + 1)`
//! - Verification: `s1 = c - s2 * h mod 12289` via NTT, `||(s1, s2)||^2 <= 34_034_726`
//! - Address derivation: `BLAKE3("STL_ADDR_V4" || scheme_id || pubkey || salt)`

/// Domain separation prefix for Stellereum PQ addresses (V4).
pub const PQ_ADDRESS_DOMAIN: &[u8] = b"STL_ADDR_V4";

/// Default 16-byte zero salt for standard address derivation.
pub const DEFAULT_SALT: [u8; 16] = [0u8; 16];

/// Canonical Falcon-512 scheme identifier.
pub const FALCON512_SCHEME_ID: u8 = 0x02;

/// Canonical Falcon-512 public key byte length (`0x09` header + 896 bytes of 14-bit packed `h`).
pub const FALCON512_PUBKEY_LEN: usize = 897;

/// Canonical Falcon-512 signature byte length (`0x29` header + 40-byte nonce + 625-byte compressed `s2`).
pub const FALCON512_SIG_LEN: usize = 666;

/// Chain-canonical Falcon-512 public key header byte.
pub const FALCON512_PUBKEY_HEADER: u8 = 0x09;

/// Chain-canonical Falcon-512 signature header byte (not PQClean `0x39`).
pub const FALCON512_SIG_HEADER: u8 = 0x29;

/// Falcon-512 prime modulus `q = 12289`.
pub const FALCON_MODULUS_Q: u32 = 12289;

/// Falcon-512 polynomial degree `N = 512`.
pub const FALCON_N: usize = 512;

/// NIST FIPS 206 Falcon-512 centered Euclidean norm squared bound (`floor(beta^2)`).
pub const FALCON_NORM_BOUND_SQ: i64 = 34_034_726;

/// Derive a 32-byte Stellereum V4 post-quantum address:
/// `BLAKE3("STL_ADDR_V4" || scheme_id || pubkey || salt)`.
pub fn derive_pq_address(scheme_id: u8, pubkey: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PQ_ADDRESS_DOMAIN);
    hasher.update(&[scheme_id]);
    hasher.update(pubkey);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

/// Derive a 32-byte Falcon-512 address (`scheme_id = 0x02`).
pub fn derive_falcon512_address(pubkey: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    derive_pq_address(FALCON512_SCHEME_ID, pubkey, salt)
}

/// Keccak-f[1600] permutation (NIST FIPS 202).
fn keccak_f1600(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000_0000_0000_0001,
        0x0000_0000_0000_8082,
        0x8000_0000_0000_808A,
        0x8000_0000_8000_8000,
        0x0000_0000_0000_808B,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8009,
        0x0000_0000_0000_008A,
        0x0000_0000_0000_0088,
        0x0000_0000_8000_8009,
        0x0000_0000_8000_000A,
        0x0000_0000_8000_808B,
        0x8000_0000_0000_008B,
        0x8000_0000_0000_8089,
        0x8000_0000_0000_8003,
        0x8000_0000_0000_8002,
        0x8000_0000_0000_0080,
        0x0000_0000_0000_800A,
        0x8000_0000_8000_000A,
        0x8000_0000_8000_8081,
        0x8000_0000_0000_8080,
        0x0000_0000_8000_0001,
        0x8000_0000_8000_8008,
    ];
    const ROTC: [[u32; 5]; 5] = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ];

    let mut a = [[0u64; 5]; 5];
    for x in 0..5 {
        for y in 0..5 {
            a[x][y] = state[x + 5 * y];
        }
    }

    for &rc in &RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for (ax, &dx) in a.iter_mut().zip(d.iter()) {
            for slot in ax.iter_mut() {
                *slot ^= dx;
            }
        }

        let mut b = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                b[y][(2 * x + 3 * y) % 5] = a[x][y].rotate_left(ROTC[x][y]);
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                a[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
            }
        }

        a[0][0] ^= rc;
    }

    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] = a[x][y];
        }
    }
}

/// Incremental SHAKE256 XOF reader (FIPS 202, rate = 136 bytes).
pub struct Shake256Reader {
    state: [u64; 25],
    buffer: [u8; 136],
    buf_pos: usize,
}

impl Shake256Reader {
    /// Absorb `part1 || part2`, apply FIPS 202 SHAKE256 padding (`0x1F` .. `0x80`),
    /// and prepare the first squeezed block.
    pub fn from_parts(part1: &[u8], part2: &[u8]) -> Self {
        const RATE: usize = 136;
        let mut state = [0u64; 25];
        let mut block = [0u8; RATE];
        let mut pos = 0usize;

        for slice in [part1, part2] {
            let mut off = 0usize;
            if pos > 0 {
                let take = (RATE - pos).min(slice.len());
                block[pos..pos + take].copy_from_slice(&slice[..take]);
                pos += take;
                off += take;
                if pos == RATE {
                    for (i, slot) in state.iter_mut().enumerate().take(RATE / 8) {
                        let val = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
                        *slot ^= val;
                    }
                    keccak_f1600(&mut state);
                    pos = 0;
                }
            }
            while off + RATE <= slice.len() {
                for (i, slot) in state.iter_mut().enumerate().take(RATE / 8) {
                    let chunk = &slice[off + i * 8..off + i * 8 + 8];
                    let val = u64::from_le_bytes(chunk.try_into().unwrap());
                    *slot ^= val;
                }
                keccak_f1600(&mut state);
                off += RATE;
            }
            let rem = slice.len() - off;
            if rem > 0 {
                block[..rem].copy_from_slice(&slice[off..]);
                pos = rem;
            }
        }

        block[pos..].fill(0);
        block[pos] = 0x1F;
        block[RATE - 1] |= 0x80;

        for (i, slot) in state.iter_mut().enumerate().take(RATE / 8) {
            let val = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
            *slot ^= val;
        }
        keccak_f1600(&mut state);

        let mut reader = Self {
            state,
            buffer: [0u8; RATE],
            buf_pos: 0,
        };
        reader.refill();
        reader
    }

    fn refill(&mut self) {
        for i in 0..(136 / 8) {
            self.buffer[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        keccak_f1600(&mut self.state);
        self.buf_pos = 0;
    }

    #[inline(always)]
    fn next_u16_be(&mut self) -> u16 {
        if self.buf_pos >= 136 {
            self.refill();
        }
        let b0 = self.buffer[self.buf_pos];
        self.buf_pos += 1;
        if self.buf_pos >= 136 {
            self.refill();
        }
        let b1 = self.buffer[self.buf_pos];
        self.buf_pos += 1;
        ((b0 as u16) << 8) | (b1 as u16)
    }

    /// Squeeze `n` bytes from the SHAKE256 sponge.
    pub fn squeeze(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if self.buf_pos >= 136 {
                self.refill();
            }
            out.push(self.buffer[self.buf_pos]);
            self.buf_pos += 1;
        }
        out
    }
}

/// NIST FIPS 206 `HashToPoint` using `SHAKE256(nonce || message)`.
pub fn hash_to_point(nonce: &[u8; 40], message: &[u8]) -> [u16; FALCON_N] {
    let mut reader = Shake256Reader::from_parts(nonce, message);
    let mut c = [0u16; FALCON_N];
    let mut count = 0usize;
    while count < FALCON_N {
        let t = reader.next_u16_be();
        if t < 61445 {
            c[count] = t % (FALCON_MODULUS_Q as u16);
            count += 1;
        }
    }
    c
}

/// Decode 896 bytes of 14-bit big-endian packed coefficients modulo `12289`.
fn modq_decode(x: &mut [u16; FALCON_N], input: &[u8]) -> bool {
    if input.len() != 896 {
        return false;
    }
    let mut acc = 0u32;
    let mut acc_len = 0u32;
    let mut in_idx = 0usize;
    let mut u = 0usize;
    while u < FALCON_N {
        if in_idx >= input.len() {
            return false;
        }
        acc = (acc << 8) | (input[in_idx] as u32);
        in_idx += 1;
        acc_len += 8;
        if acc_len >= 14 {
            acc_len -= 14;
            let w = (acc >> acc_len) & 0x3FFF;
            if w >= FALCON_MODULUS_Q {
                return false;
            }
            x[u] = w as u16;
            u += 1;
        }
    }
    (acc & ((1u32 << acc_len) - 1)) == 0
}

/// Strictly decode Falcon-512 compressed `s2` polynomial, enforcing canonical
/// non-negative-zero sign/magnitude, range `[-2047, 2047]`, and all-zero
/// trailing bit and byte padding up to the end of `input`.
fn comp_decode(x: &mut [i16; FALCON_N], input: &[u8]) -> Option<usize> {
    let mut acc = 0u32;
    let mut acc_len = 0u32;
    let mut v = 0usize;

    for slot in x.iter_mut() {
        if v >= input.len() {
            return None;
        }
        acc = (acc << 8) | (input[v] as u32);
        v += 1;
        let b = acc >> acc_len;
        let s = (b & 128) != 0;
        let mut m = b & 127;

        loop {
            if acc_len == 0 {
                if v >= input.len() {
                    return None;
                }
                acc = (acc << 8) | (input[v] as u32);
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return None;
            }
        }

        if s && m == 0 {
            return None;
        }

        *slot = if s { -(m as i16) } else { m as i16 };
    }

    let mut pad = (acc & ((1u32 << acc_len).wrapping_sub(1))) as u8;
    for &b in &input[v..] {
        pad |= b;
    }
    if pad != 0 {
        return None;
    }

    Some(v)
}

const PSI: u32 = 10302;
const INV_PSI: u32 = 8974;
const OMEGA: u32 = 3400;
const INV_OMEGA: u32 = 2859;
const INV_N: u32 = 12265;

const fn mod_pow(mut base: u32, mut exp: u32) -> u32 {
    let mut res = 1u32;
    base %= FALCON_MODULUS_Q;
    while exp > 0 {
        if exp & 1 == 1 {
            res = (res * base) % FALCON_MODULUS_Q;
        }
        base = (base * base) % FALCON_MODULUS_Q;
        exp >>= 1;
    }
    res
}

const fn build_bit_rev() -> [u16; FALCON_N] {
    let mut out = [0u16; FALCON_N];
    let mut i = 0usize;
    while i < FALCON_N {
        let mut x = i;
        let mut y = 0usize;
        let mut k = 0;
        while k < 9 {
            y = (y << 1) | (x & 1);
            x >>= 1;
            k += 1;
        }
        out[i] = y as u16;
        i += 1;
    }
    out
}

const fn build_pow_table(base: u32, init: u32) -> [u16; FALCON_N] {
    let mut out = [0u16; FALCON_N];
    let mut cur = init % FALCON_MODULUS_Q;
    let mut i = 0usize;
    while i < FALCON_N {
        out[i] = cur as u16;
        cur = (cur * base) % FALCON_MODULUS_Q;
        i += 1;
    }
    out
}

const fn build_twiddle_table(root: u32) -> [[u16; 256]; 9] {
    let mut out = [[0u16; 256]; 9];
    let mut stage = 0usize;
    let mut step = 2usize;
    while stage < 9 {
        let half = step / 2;
        let w_step = mod_pow(root, (FALCON_N / step) as u32);
        let mut w_cur = 1u32;
        let mut j = 0usize;
        while j < half {
            out[stage][j] = w_cur as u16;
            w_cur = (w_cur * w_step) % FALCON_MODULUS_Q;
            j += 1;
        }
        stage += 1;
        step *= 2;
    }
    out
}

const BIT_REV_512: [u16; FALCON_N] = build_bit_rev();
const PSI_POWS_512: [u16; FALCON_N] = build_pow_table(PSI, 1);
const INV_PSI_N_POWS_512: [u16; FALCON_N] = build_pow_table(INV_PSI, INV_N);
const NTT_TWIDDLES: [[u16; 256]; 9] = build_twiddle_table(OMEGA);
const INTT_TWIDDLES: [[u16; 256]; 9] = build_twiddle_table(INV_OMEGA);

#[inline(always)]
const fn barrett_reduce_q(x: u32) -> u16 {
    const BARRETT_MU: u64 = (1u64 << 32) / (FALCON_MODULUS_Q as u64);
    let t = (((x as u64) * BARRETT_MU) >> 32) as u32;
    let mut r = x - t * FALCON_MODULUS_Q;
    if r >= FALCON_MODULUS_Q {
        r -= FALCON_MODULUS_Q;
    }
    r as u16
}

/// Forward negacyclic NTT over `Z_12289[x]/(x^512 + 1)`.
pub fn ntt(a: &mut [u16; FALCON_N]) {
    for (v, &psi) in a.iter_mut().zip(PSI_POWS_512.iter()) {
        *v = barrett_reduce_q(*v as u32 * psi as u32);
    }
    for (i, &j) in BIT_REV_512.iter().enumerate() {
        let j = j as usize;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut stage = 0usize;
    let mut step = 2usize;
    while step <= FALCON_N {
        let half = step / 2;
        let twiddles = &NTT_TWIDDLES[stage][..half];
        for i in (0..FALCON_N).step_by(step) {
            for (j, &w_cur) in twiddles.iter().enumerate() {
                let u = a[i + j] as u32;
                let v = barrett_reduce_q(a[i + j + half] as u32 * w_cur as u32) as u32;
                let sum = u + v;
                a[i + j] = if sum >= FALCON_MODULUS_Q {
                    (sum - FALCON_MODULUS_Q) as u16
                } else {
                    sum as u16
                };
                let diff = if u >= v {
                    u - v
                } else {
                    u + FALCON_MODULUS_Q - v
                };
                a[i + j + half] = diff as u16;
            }
        }
        stage += 1;
        step *= 2;
    }
}

/// Inverse negacyclic NTT over `Z_12289[x]/(x^512 + 1)`.
pub fn intt(a: &mut [u16; FALCON_N]) {
    for (i, &j) in BIT_REV_512.iter().enumerate() {
        let j = j as usize;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut stage = 0usize;
    let mut step = 2usize;
    while step <= FALCON_N {
        let half = step / 2;
        let twiddles = &INTT_TWIDDLES[stage][..half];
        for i in (0..FALCON_N).step_by(step) {
            for (j, &w_cur) in twiddles.iter().enumerate() {
                let u = a[i + j] as u32;
                let v = barrett_reduce_q(a[i + j + half] as u32 * w_cur as u32) as u32;
                let sum = u + v;
                a[i + j] = if sum >= FALCON_MODULUS_Q {
                    (sum - FALCON_MODULUS_Q) as u16
                } else {
                    sum as u16
                };
                let diff = if u >= v {
                    u - v
                } else {
                    u + FALCON_MODULUS_Q - v
                };
                a[i + j + half] = diff as u16;
            }
        }
        stage += 1;
        step *= 2;
    }
    for (v, &inv_psi_n) in a.iter_mut().zip(INV_PSI_N_POWS_512.iter()) {
        *v = barrett_reduce_q(*v as u32 * inv_psi_n as u32);
    }
}

/// Multiply polynomial `a` by `b` in `Z_12289[x]/(x^512 + 1)` via NTT.
pub fn poly_mul(a: &[u16; FALCON_N], b: &[u16; FALCON_N]) -> [u16; FALCON_N] {
    let mut a_ntt = *a;
    let mut b_ntt = *b;
    ntt(&mut a_ntt);
    ntt(&mut b_ntt);
    for (ai, &bi) in a_ntt.iter_mut().zip(b_ntt.iter()) {
        *ai = barrett_reduce_q(*ai as u32 * bi as u32);
    }
    intt(&mut a_ntt);
    a_ntt
}

/// Unpack a canonical 897-byte Falcon-512 public key (`pubkey[0] == 0x09`).
pub fn unpack_falcon_pubkey(pubkey: &[u8]) -> Option<[u16; FALCON_N]> {
    if pubkey.len() != FALCON512_PUBKEY_LEN || pubkey[0] != FALCON512_PUBKEY_HEADER {
        return None;
    }
    let mut h = [0u16; FALCON_N];
    if !modq_decode(&mut h, &pubkey[1..]) {
        return None;
    }
    Some(h)
}

/// Unpack a canonical 666-byte Falcon-512 signature (`sig[0] == 0x29`, non-zero nonce,
/// strict all-zero trailing padding).
pub fn unpack_falcon_sig(sig: &[u8]) -> Option<([u8; 40], [i16; FALCON_N])> {
    if sig.len() != FALCON512_SIG_LEN || sig[0] != FALCON512_SIG_HEADER {
        return None;
    }
    let mut nonce = [0u8; 40];
    nonce.copy_from_slice(&sig[1..41]);
    if nonce.iter().all(|&b| b == 0) {
        return None;
    }
    let mut s2 = [0i16; FALCON_N];
    comp_decode(&mut s2, &sig[41..])?;
    Some((nonce, s2))
}

/// Verify a canonical Falcon-512 signature against `pubkey` and `message`
/// according to NIST FIPS 206 with Stellereum canonical framing (`0x09` / `0x29`).
pub fn verify_falcon512(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Some(h) = unpack_falcon_pubkey(pubkey) else {
        return false;
    };
    let Some((nonce, s2)) = unpack_falcon_sig(signature) else {
        return false;
    };

    let c = hash_to_point(&nonce, message);

    let mut s2_modq = [0u16; FALCON_N];
    for i in 0..FALCON_N {
        s2_modq[i] = (s2[i] as i32).rem_euclid(FALCON_MODULUS_Q as i32) as u16;
    }

    let s2_h = poly_mul(&s2_modq, &h);

    let mut norm_sq = 0i64;
    for i in 0..FALCON_N {
        let s1_val =
            (c[i] as i32 + FALCON_MODULUS_Q as i32 - s2_h[i] as i32) % (FALCON_MODULUS_Q as i32);
        let s1_c = if s1_val > (FALCON_MODULUS_Q as i32 / 2) {
            s1_val - (FALCON_MODULUS_Q as i32)
        } else {
            s1_val
        } as i64;
        let s2_c = s2[i] as i64;
        norm_sq += s1_c * s1_c + s2_c * s2_c;
    }

    norm_sq <= FALCON_NORM_BOUND_SQ
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake256_matches_nist_vectors() {
        let mut empty = Shake256Reader::from_parts(b"", b"");
        assert_eq!(
            hex::encode(empty.squeeze(32)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
        let mut abc = Shake256Reader::from_parts(b"abc", b"");
        assert_eq!(
            hex::encode(abc.squeeze(32)),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        );
        let mut split = Shake256Reader::from_parts(b"ab", b"c");
        assert_eq!(
            hex::encode(split.squeeze(32)),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        );
    }
}
