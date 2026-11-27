//! Standalone zero-C-toolchain WebAssembly Falcon-512 signer and address
//! derivation crate for Stellereum (`wasm32-unknown-unknown`).
//!
//! Exports a minimal C ABI (`alloc`, `dealloc`, `falcon_keygen`,
//! `falcon_sign_with_entropy`, `falcon_verify`, `falcon_derive_address`)
//! without `wasm-bindgen` or `js-sys`.

use core::alloc::Layout;
use core::slice;

use falcon_rust::falcon512;
use zeroize::{Zeroize, Zeroizing};

/// Canonical Falcon-512 public key length in bytes (header `0x09` + 896B).
pub const FALCON512_PUBKEY_LEN: usize = 897;
/// Canonical Falcon-512 secret key length in bytes (header `0x59` + 1280B).
pub const FALCON512_SECKEY_LEN: usize = 1281;
/// Canonical Falcon-512 signature length in bytes (`0x29` + 40B nonce + 625B compressed `s2`).
pub const FALCON512_SIG_LEN: usize = 666;
/// Keygen seed length in bytes.
pub const FALCON_KEYGEN_SEED_LEN: usize = 32;
/// 32-byte Stellereum PQ address length.
pub const PQ_ADDRESS_LEN: usize = 32;
/// 16-byte sub-account salt length.
pub const PQ_SALT_LEN: usize = 16;
/// Default 16-byte zero salt.
pub const DEFAULT_SALT: [u8; PQ_SALT_LEN] = [0u8; PQ_SALT_LEN];
/// Domain separation prefix for Stellereum PQ addresses (`STL_ADDR_V4`).
pub const PQ_ADDRESS_DOMAIN: &[u8] = b"STL_ADDR_V4";
/// `PqScheme::Falcon512 as u8`.
pub const PQ_SCHEME_FALCON512: u8 = 0x02;
/// Chain-canonical Falcon-512 signature header byte (`0x29`).
pub const CHAIN_SIG_HEADER: u8 = 0x29;
/// `falcon-rust` native Falcon-512 signature header byte (`0x59`).
pub const FALCON_RUST_SIG_HEADER: u8 = 0x59;
/// Canonical Falcon-512 public key header byte (`0x09`).
pub const FALCON_PUBKEY_HEADER: u8 = 0x09;
/// Falcon-512 prime modulus `q = 12289`.
pub const FALCON_MODULUS_Q: u16 = 12289;
/// Falcon-512 polynomial degree `n = 512`.
pub const FALCON_N: usize = 512;
/// Maximum number of attempts if a zero nonce is ever drawn.
const MAX_SIGN_ATTEMPTS: usize = 4;

// Status codes returned by the C ABI.
pub const STATUS_OK: i32 = 0;
pub const ERR_NULL_PTR: i32 = -1;
pub const ERR_INVALID_LEN: i32 = -2;
pub const ERR_KEYGEN_FAILED: i32 = -3;
pub const ERR_INVALID_KEY: i32 = -4;
pub const ERR_SIGN_FAILED: i32 = -5;
pub const ERR_VERIFY_FAILED: i32 = -6;
pub const ERR_ENTROPY_FAILED: i32 = -7;

// ============================================================================
// wasm32-unknown-unknown getrandom 0.4.3 custom backend -> JS crypto.getRandomValues
// ============================================================================

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
unsafe extern "C" {
    fn stellereum_getrandom(dest: *mut u8, len: usize) -> i32;
}

/// Custom `getrandom 0.4.3` backend hook (`--cfg getrandom_backend="custom"`).
///
/// # Safety
/// `dest` must be valid for writes of `len` bytes.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[no_mangle]
pub unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    if len == 0 {
        return Ok(());
    }
    if dest.is_null() {
        return Err(getrandom::Error::UNEXPECTED);
    }
    // Initialize buffer before calling into JS host `crypto.getRandomValues`.
    // SAFETY: caller guarantees `dest` is valid for `len` bytes.
    unsafe { core::ptr::write_bytes(dest, 0, len) };
    // SAFETY: `stellereum_getrandom` fills `[dest, dest + len)` via `crypto.getRandomValues`
    // and returns 0 on success.
    let rc = unsafe { stellereum_getrandom(dest, len) };
    if rc == 0 {
        if len >= 16 {
            let filled = unsafe { core::slice::from_raw_parts(dest, len) };
            if filled.iter().all(|&b| b == 0) {
                return Err(getrandom::Error::new_custom(2));
            }
        }
        Ok(())
    } else {
        Err(getrandom::Error::new_custom(1))
    }
}

// ============================================================================
// Pure-Rust core logic
// ============================================================================

/// Validate canonical FIPS 206 `modq` encoding of an 897-byte Falcon-512 public key.
///
/// Mirrors `stellereum/src/post_quantum.rs::modq_decode`:
/// - Header byte must be `0x09`.
/// - Every 14-bit coefficient must be `< 12289` (`FALCON_MODULUS_Q`).
/// - Trailing padding bits (if any) must be zero.
pub fn is_canonical_falcon512_pubkey(pubkey: &[u8]) -> bool {
    if pubkey.len() != FALCON512_PUBKEY_LEN || pubkey[0] != FALCON_PUBKEY_HEADER {
        return false;
    }
    let input = &pubkey[1..];
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
            let w = ((acc >> acc_len) & 0x3FFF) as u16;
            if w >= FALCON_MODULUS_Q {
                return false;
            }
            u += 1;
        }
    }
    (acc & ((1u32 << acc_len) - 1)) == 0
}

/// Derive a 32-byte Stellereum PQ address:
/// `BLAKE3("STL_ADDR_V4" || 0x02 || pubkey || salt)`.
pub fn derive_pq_address(
    pubkey: &[u8],
    salt: &[u8; PQ_SALT_LEN],
) -> Result<[u8; PQ_ADDRESS_LEN], i32> {
    if !is_canonical_falcon512_pubkey(pubkey) {
        return Err(ERR_INVALID_KEY);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(PQ_ADDRESS_DOMAIN);
    hasher.update(&[PQ_SCHEME_FALCON512]);
    hasher.update(pubkey);
    hasher.update(salt);
    Ok(*hasher.finalize().as_bytes())
}

/// Verify a chain-canonical Falcon-512 signature (`0x29` header, 40B non-zero nonce,
/// strict zero-padded compressed `s2`, and FIPS 206 Euclidean norm bound).
pub fn verify_falcon512_canonical(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if !is_canonical_falcon512_pubkey(pubkey) {
        return false;
    }
    if signature.len() != FALCON512_SIG_LEN || signature[0] != CHAIN_SIG_HEADER {
        return false;
    }
    // Reject all-zero nonce (matches `stellereum/src/post_quantum.rs::unpack_falcon_sig`).
    if signature[1..41].iter().all(|&b| b == 0) {
        return false;
    }

    let Ok(pk) = falcon512::PublicKey::from_bytes(pubkey) else {
        return false;
    };

    // Translate chain header `0x29` -> `falcon-rust` header `0x59` in a local buffer.
    let mut local = [0u8; FALCON512_SIG_LEN];
    local.copy_from_slice(signature);
    local[0] = FALCON_RUST_SIG_HEADER;

    let Ok(sig) = falcon512::Signature::from_bytes(&local) else {
        return false;
    };

    // `falcon512::verify` decompresses `s2` (validating unary coding, rejecting `-0`,
    // enforcing zero bit-padding and zero trailing byte-padding) and verifies
    // `||(s1, s2)||^2 < 34034726` against `HashToPoint(nonce || message)`.
    falcon512::verify(message, &sig, &pk)
}

/// RAII guard that runs `falcon512::SecretKey`'s destructor (freeing its
/// heap-allocated polynomials and LDL tree without leaking) and then scrubs its
/// stack representation with volatile byte writes.
struct SecretKeyGuard(core::mem::ManuallyDrop<falcon512::SecretKey>);

impl SecretKeyGuard {
    fn new(sk: falcon512::SecretKey) -> Self {
        Self(core::mem::ManuallyDrop::new(sk))
    }
}

impl core::ops::Deref for SecretKeyGuard {
    type Target = falcon512::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SecretKeyGuard {
    fn drop(&mut self) {
        // SAFETY: `self.0` is valid and has not been dropped yet because `Drop` runs once.
        unsafe { core::mem::ManuallyDrop::drop(&mut self.0) };
        let base = core::ptr::addr_of_mut!(self.0).cast::<u8>();
        let size = core::mem::size_of::<falcon512::SecretKey>();
        // SAFETY: `base` points to `size` bytes of the now-dropped `ManuallyDrop` storage.
        // Volatile writes scrub the stack representation without leaking heap fields or UB.
        for i in 0..size {
            unsafe { core::ptr::write_volatile(base.add(i), 0u8) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Generate a Falcon-512 keypair from a 32-byte seed.
pub fn keygen_from_seed(
    seed: &[u8; FALCON_KEYGEN_SEED_LEN],
) -> (
    [u8; FALCON512_PUBKEY_LEN],
    Zeroizing<[u8; FALCON512_SECKEY_LEN]>,
) {
    let mut seed_buf = Zeroizing::new([0u8; FALCON_KEYGEN_SEED_LEN]);
    seed_buf.copy_from_slice(seed);
    let (sk_raw, pk) = falcon512::keygen(*seed_buf);
    let sk = SecretKeyGuard::new(sk_raw);
    seed_buf.zeroize();

    let mut pk_bytes = [0u8; FALCON512_PUBKEY_LEN];
    let pk_vec = pk.to_bytes();
    pk_bytes.copy_from_slice(&pk_vec);

    let mut sk_bytes = Zeroizing::new([0u8; FALCON512_SECKEY_LEN]);
    let mut sk_vec = Zeroizing::new(sk.to_bytes());
    sk_bytes.copy_from_slice(&sk_vec);
    sk_vec.zeroize();

    (pk_bytes, sk_bytes)
}

/// Sign `message` using `sk_bytes` (1281B `falcon-rust` secret key), rewrite header
/// `0x59` -> `0x29`, and immediately verify the resulting signature with pure-Rust
/// Falcon-512 norm and padding checks before returning.
///
/// When `entropy` is non-empty it is used as a fail-closed freshness gate: an
/// all-zero buffer indicates the JS `crypto.getRandomValues` source failed, so
/// signing is refused. Cryptographic sampling randomness for `falcon-rust`'s
/// discrete Gaussian sampler always comes from `getrandom`, which on wasm is
/// wired to the same `env.stellereum_getrandom` host import.
pub fn sign_canonical_with_entropy(
    sk_bytes: &[u8],
    message: &[u8],
    entropy: &[u8],
) -> Result<[u8; FALCON512_SIG_LEN], i32> {
    if sk_bytes.len() != FALCON512_SECKEY_LEN {
        return Err(ERR_INVALID_KEY);
    }
    let sk = SecretKeyGuard::new(
        falcon512::SecretKey::from_bytes(sk_bytes).map_err(|_| ERR_INVALID_KEY)?,
    );
    let pk = falcon512::PublicKey::from_secret_key(&sk);
    let pk_vec = pk.to_bytes();
    if pk_vec.len() != FALCON512_PUBKEY_LEN {
        return Err(ERR_INVALID_KEY);
    }

    // Fail closed on short (< 16B) or degenerate (all-zero) explicit entropy:
    // a working `crypto.getRandomValues` provides at least 16 non-zero bytes.
    // Empty entropy (`entropy.is_empty()`) falls through to `getrandom`.
    if !entropy.is_empty() && (entropy.len() < 16 || entropy.iter().all(|&b| b == 0)) {
        return Err(ERR_ENTROPY_FAILED);
    }

    for _ in 0..MAX_SIGN_ATTEMPTS {
        let sig = falcon512::sign(message, &sk);
        let mut sig_vec = Zeroizing::new(sig.to_bytes());
        if sig_vec.len() != FALCON512_SIG_LEN {
            return Err(ERR_SIGN_FAILED);
        }
        if sig_vec[0] != FALCON_RUST_SIG_HEADER && sig_vec[0] != CHAIN_SIG_HEADER {
            return Err(ERR_SIGN_FAILED);
        }
        // Rewrite `falcon-rust` header `0x59` -> chain-canonical `0x29`.
        sig_vec[0] = CHAIN_SIG_HEADER;

        // Immediately verify with pure-Rust Falcon-512 norm + padding + nonce check.
        if verify_falcon512_canonical(&pk_vec, message, &sig_vec) {
            let mut out = [0u8; FALCON512_SIG_LEN];
            out.copy_from_slice(&sig_vec);
            sig_vec.zeroize();
            return Ok(out);
        }
        sig_vec.zeroize();
    }

    Err(ERR_VERIFY_FAILED)
}

// ============================================================================
// Pure C WebAssembly ABI (zero wasm-bindgen)
// ============================================================================

/// Allocate `len` zero-initialized bytes in linear memory.
/// Returns null on `len == 0` or allocation failure.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return core::ptr::null_mut();
    }
    let Ok(layout) = Layout::from_size_align(len, 1) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `len > 0` and alignment 1 is a non-zero power of two.
    unsafe { std::alloc::alloc_zeroed(layout) }
}

/// Zeroize and free `len` bytes previously returned by `alloc`.
///
/// # Safety
/// `ptr` must have been allocated by `alloc(len)` and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    // Zeroize linear memory before returning it to the allocator.
    // SAFETY: caller guarantees `ptr` is valid for `len` bytes.
    unsafe { slice::from_raw_parts_mut(ptr, len) }.zeroize();
    if let Ok(layout) = Layout::from_size_align(len, 1) {
        // SAFETY: `ptr` was allocated with `alloc(len)` (alignment 1).
        unsafe { std::alloc::dealloc(ptr, layout) };
    }
}

/// Generate a Falcon-512 keypair.
///
/// - If `seed_len == 32` and `seed_ptr != null`, uses the caller's 32-byte seed.
/// - If `seed_len == 0`, draws 32 bytes from `getrandom::fill` (host CSPRNG).
/// - Writes 897-byte public key to `pk_out_ptr` (`pk_out_len >= 897`) and
///   1281-byte secret key to `sk_out_ptr` (`sk_out_len >= 1281`).
///
/// # Safety
/// All non-null pointers must be valid for their corresponding byte lengths.
#[no_mangle]
pub unsafe extern "C" fn falcon_keygen(
    seed_ptr: *const u8,
    seed_len: usize,
    pk_out_ptr: *mut u8,
    pk_out_len: usize,
    sk_out_ptr: *mut u8,
    sk_out_len: usize,
) -> i32 {
    if pk_out_ptr.is_null() || sk_out_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if pk_out_len < FALCON512_PUBKEY_LEN || sk_out_len < FALCON512_SECKEY_LEN {
        return ERR_INVALID_LEN;
    }

    let mut seed_buf = Zeroizing::new([0u8; FALCON_KEYGEN_SEED_LEN]);
    if seed_len == 0 {
        if getrandom::fill(&mut *seed_buf).is_err() {
            return ERR_ENTROPY_FAILED;
        }
    } else if seed_len == FALCON_KEYGEN_SEED_LEN {
        if seed_ptr.is_null() {
            return ERR_NULL_PTR;
        }
        // SAFETY: caller guarantees `seed_ptr` is valid for `FALCON_KEYGEN_SEED_LEN` bytes.
        let src = unsafe { slice::from_raw_parts(seed_ptr, FALCON_KEYGEN_SEED_LEN) };
        seed_buf.copy_from_slice(src);
    } else {
        return ERR_INVALID_LEN;
    }

    let (pk_bytes, mut sk_bytes) = keygen_from_seed(&seed_buf);
    seed_buf.zeroize();

    // SAFETY: caller guarantees output buffers are valid for their lengths.
    let pk_out = unsafe { slice::from_raw_parts_mut(pk_out_ptr, FALCON512_PUBKEY_LEN) };
    // SAFETY: caller guarantees output buffers are valid for their lengths.
    let sk_out = unsafe { slice::from_raw_parts_mut(sk_out_ptr, FALCON512_SECKEY_LEN) };
    pk_out.copy_from_slice(&pk_bytes);
    sk_out.copy_from_slice(&*sk_bytes);
    sk_bytes.zeroize();

    STATUS_OK
}

/// Sign `msg` with a 1281-byte `falcon-rust` secret key, rewriting header
/// `0x59` -> `0x29` and verifying the signature before writing to `sig_out_ptr`.
///
/// # Safety
/// All non-null pointers must be valid for their corresponding byte lengths.
#[no_mangle]
pub unsafe extern "C" fn falcon_sign_with_entropy(
    sk_ptr: *const u8,
    sk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    entropy_ptr: *const u8,
    entropy_len: usize,
    sig_out_ptr: *mut u8,
    sig_out_len: usize,
) -> i32 {
    if sk_ptr.is_null() || sig_out_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if msg_len > 0 && msg_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if entropy_len > 0 && entropy_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if sk_len != FALCON512_SECKEY_LEN || sig_out_len < FALCON512_SIG_LEN {
        return ERR_INVALID_LEN;
    }
    if entropy_len > 0 && entropy_len < 16 {
        return ERR_ENTROPY_FAILED;
    }

    // SAFETY: `sk_ptr` is non-null and valid for `sk_len` bytes.
    let sk_slice = unsafe { slice::from_raw_parts(sk_ptr, sk_len) };
    // SAFETY: `msg_ptr` is valid for `msg_len` bytes when `msg_len > 0`.
    let msg_slice = if msg_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(msg_ptr, msg_len) }
    };
    // SAFETY: `entropy_ptr` is valid for `entropy_len` bytes when `entropy_len > 0`.
    let entropy_slice = if entropy_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(entropy_ptr, entropy_len) }
    };

    let sig = match sign_canonical_with_entropy(sk_slice, msg_slice, entropy_slice) {
        Ok(sig) => sig,
        Err(code) => return code,
    };

    // SAFETY: `sig_out_ptr` is non-null and valid for `FALCON512_SIG_LEN` bytes.
    let sig_out = unsafe { slice::from_raw_parts_mut(sig_out_ptr, FALCON512_SIG_LEN) };
    sig_out.copy_from_slice(&sig);

    STATUS_OK
}

/// Verify a chain-canonical Falcon-512 signature (`0x29` header, 666 bytes).
///
/// Returns `1` if valid, `0` if invalid, or a negative error code on null pointers.
///
/// # Safety
/// All non-null pointers must be valid for their corresponding byte lengths.
#[no_mangle]
pub unsafe extern "C" fn falcon_verify(
    pk_ptr: *const u8,
    pk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> i32 {
    if pk_ptr.is_null() || sig_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if msg_len > 0 && msg_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    // SAFETY: pointers and lengths validated above.
    let pk_slice = unsafe { slice::from_raw_parts(pk_ptr, pk_len) };
    let msg_slice = if msg_len == 0 {
        &[]
    } else {
        // SAFETY: `msg_ptr` is non-null when `msg_len > 0`.
        unsafe { slice::from_raw_parts(msg_ptr, msg_len) }
    };
    // SAFETY: `sig_ptr` is non-null and valid for `sig_len` bytes.
    let sig_slice = unsafe { slice::from_raw_parts(sig_ptr, sig_len) };

    if verify_falcon512_canonical(pk_slice, msg_slice, sig_slice) {
        1
    } else {
        0
    }
}

/// Derive a 32-byte Stellereum PQ address (`BLAKE3("STL_ADDR_V4" || 0x02 || pk || salt)`).
///
/// If `salt_len == 0`, uses `DEFAULT_SALT` (`[0u8; 16]`). Otherwise `salt_len` must be 16.
///
/// # Safety
/// All non-null pointers must be valid for their corresponding byte lengths.
#[no_mangle]
pub unsafe extern "C" fn falcon_derive_address(
    pk_ptr: *const u8,
    pk_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    addr_out_ptr: *mut u8,
    addr_out_len: usize,
) -> i32 {
    if pk_ptr.is_null() || addr_out_ptr.is_null() {
        return ERR_NULL_PTR;
    }
    if addr_out_len < PQ_ADDRESS_LEN {
        return ERR_INVALID_LEN;
    }
    let salt = if salt_len == 0 {
        DEFAULT_SALT
    } else if salt_len == PQ_SALT_LEN {
        if salt_ptr.is_null() {
            return ERR_NULL_PTR;
        }
        let mut buf = [0u8; PQ_SALT_LEN];
        // SAFETY: `salt_ptr` is non-null and valid for 16 bytes.
        buf.copy_from_slice(unsafe { slice::from_raw_parts(salt_ptr, PQ_SALT_LEN) });
        buf
    } else {
        return ERR_INVALID_LEN;
    };

    // SAFETY: `pk_ptr` is non-null and valid for `pk_len` bytes.
    let pk_slice = unsafe { slice::from_raw_parts(pk_ptr, pk_len) };
    let addr = match derive_pq_address(pk_slice, &salt) {
        Ok(addr) => addr,
        Err(code) => return code,
    };

    // SAFETY: `addr_out_ptr` is non-null and valid for `PQ_ADDRESS_LEN` bytes.
    let addr_out = unsafe { slice::from_raw_parts_mut(addr_out_ptr, PQ_ADDRESS_LEN) };
    addr_out.copy_from_slice(&addr);

    STATUS_OK
}

// ============================================================================
// Native Rust unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_sign_rewrites_header_to_0x29_and_verifies() {
        let seed = [0x42u8; FALCON_KEYGEN_SEED_LEN];
        let (pk, sk) = keygen_from_seed(&seed);
        assert_eq!(pk[0], FALCON_PUBKEY_HEADER);
        assert!(is_canonical_falcon512_pubkey(&pk));

        let msg = b"stellereum wave10 browser wasm signer";
        let entropy = [0xA5u8; 32];
        let sig = sign_canonical_with_entropy(&*sk, msg, &entropy).expect("signing must succeed");

        assert_eq!(sig.len(), FALCON512_SIG_LEN);
        assert_eq!(sig[0], CHAIN_SIG_HEADER);
        assert_eq!(sig[0], 0x29);
        assert!(
            sig[1..41].iter().any(|&b| b != 0),
            "nonce must not be all-zero"
        );
        assert!(verify_falcon512_canonical(&pk, msg, &sig));

        // Flipping header back to 0x59 or 0x39 must fail chain-canonical verification.
        let mut wrong_header = sig;
        wrong_header[0] = FALCON_RUST_SIG_HEADER;
        assert!(!verify_falcon512_canonical(&pk, msg, &wrong_header));
        wrong_header[0] = 0x39;
        assert!(!verify_falcon512_canonical(&pk, msg, &wrong_header));

        // Tampered message must fail.
        assert!(!verify_falcon512_canonical(&pk, b"tampered", &sig));

        // Non-zero trailing padding byte must fail strict padding check.
        let mut dirty_pad = sig;
        dirty_pad[FALCON512_SIG_LEN - 1] ^= 0x01;
        assert!(!verify_falcon512_canonical(&pk, msg, &dirty_pad));
    }

    #[test]
    fn rejects_degenerate_zero_entropy_before_signing() {
        let (pk, sk) = keygen_from_seed(&[0x01u8; FALCON_KEYGEN_SEED_LEN]);
        assert!(matches!(
            sign_canonical_with_entropy(&*sk, b"entropy gate", &[0u8; 32]),
            Err(ERR_ENTROPY_FAILED)
        ));
        // Short non-empty entropy (< 16 bytes) must fail closed.
        assert!(matches!(
            sign_canonical_with_entropy(&*sk, b"entropy gate", &[0x11u8; 15]),
            Err(ERR_ENTROPY_FAILED)
        ));
        let mut out_sig = [0u8; FALCON512_SIG_LEN];
        let short_ent = [0x22u8; 15];
        let msg = b"entropy gate";
        let rc = unsafe {
            falcon_sign_with_entropy(
                sk.as_ptr(),
                sk.len(),
                msg.as_ptr(),
                msg.len(),
                short_ent.as_ptr(),
                short_ent.len(),
                out_sig.as_mut_ptr(),
                out_sig.len(),
            )
        };
        assert_eq!(rc, ERR_ENTROPY_FAILED);

        // Empty entropy is allowed (sampler randomness still comes from getrandom).
        let sig = sign_canonical_with_entropy(&*sk, b"entropy gate", &[]).expect("sign");
        assert_eq!(sig[0], CHAIN_SIG_HEADER);
        assert!(verify_falcon512_canonical(&pk, b"entropy gate", &sig));
    }

    #[test]
    fn derive_pq_address_matches_stl_addr_v4_domain() {
        let seed = [0x11u8; FALCON_KEYGEN_SEED_LEN];
        let (pk, _sk) = keygen_from_seed(&seed);

        let derived = derive_pq_address(&pk, &DEFAULT_SALT).expect("valid pubkey");

        let mut expected_hasher = blake3::Hasher::new();
        expected_hasher.update(b"STL_ADDR_V4");
        expected_hasher.update(&[0x02u8]);
        expected_hasher.update(&pk);
        expected_hasher.update(&[0u8; 16]);
        let expected = *expected_hasher.finalize().as_bytes();

        assert_eq!(derived, expected);

        let custom_salt = [0x99u8; 16];
        let salted = derive_pq_address(&pk, &custom_salt).expect("valid pubkey with salt");
        assert_ne!(derived, salted);

        // Fixed cross-vector (independently checked against BLAKE3("STL_ADDR_V4"
        // || 0x02 || 0x09||0^896 || 0^16)):
        let mut zero_pk = [0u8; FALCON512_PUBKEY_LEN];
        zero_pk[0] = FALCON_PUBKEY_HEADER;
        let zero_addr = derive_pq_address(&zero_pk, &DEFAULT_SALT).expect("canonical zero pubkey");
        let known_vector: [u8; PQ_ADDRESS_LEN] = [
            0xc5, 0x23, 0x25, 0x22, 0x73, 0xb8, 0xab, 0x4d, 0xd0, 0x4c, 0x3b, 0x9a, 0xce, 0x49,
            0xe2, 0x58, 0x76, 0x7e, 0x16, 0x57, 0x26, 0x97, 0xcf, 0x0b, 0xfc, 0x2a, 0x9c, 0x47,
            0xf3, 0xd7, 0x6b, 0x68,
        ];
        assert_eq!(zero_addr, known_vector);
    }

    #[test]
    fn c_abi_roundtrip_and_zeroizing_dealloc() {
        let mut seed = [0x77u8; FALCON_KEYGEN_SEED_LEN];
        let seed_ptr = alloc(seed.len());
        let pk_ptr = alloc(FALCON512_PUBKEY_LEN);
        let sk_ptr = alloc(FALCON512_SECKEY_LEN);
        let addr_ptr = alloc(PQ_ADDRESS_LEN);
        let msg = b"c abi wasm test payload";
        let msg_ptr = alloc(msg.len());
        let entropy = [0x33u8; 32];
        let entropy_ptr = alloc(entropy.len());
        let sig_ptr = alloc(FALCON512_SIG_LEN);

        unsafe {
            slice::from_raw_parts_mut(seed_ptr, seed.len()).copy_from_slice(&seed);
            seed.zeroize();

            assert_eq!(
                falcon_keygen(
                    seed_ptr,
                    FALCON_KEYGEN_SEED_LEN,
                    pk_ptr,
                    FALCON512_PUBKEY_LEN,
                    sk_ptr,
                    FALCON512_SECKEY_LEN,
                ),
                STATUS_OK
            );
            assert_eq!(
                falcon_derive_address(
                    pk_ptr,
                    FALCON512_PUBKEY_LEN,
                    core::ptr::null(),
                    0,
                    addr_ptr,
                    PQ_ADDRESS_LEN,
                ),
                STATUS_OK
            );

            slice::from_raw_parts_mut(msg_ptr, msg.len()).copy_from_slice(msg);
            slice::from_raw_parts_mut(entropy_ptr, entropy.len()).copy_from_slice(&entropy);

            assert_eq!(
                falcon_sign_with_entropy(
                    sk_ptr,
                    FALCON512_SECKEY_LEN,
                    msg_ptr,
                    msg.len(),
                    entropy_ptr,
                    entropy.len(),
                    sig_ptr,
                    FALCON512_SIG_LEN,
                ),
                STATUS_OK
            );

            let sig_slice = slice::from_raw_parts(sig_ptr, FALCON512_SIG_LEN);
            assert_eq!(sig_slice[0], 0x29);

            assert_eq!(
                falcon_verify(
                    pk_ptr,
                    FALCON512_PUBKEY_LEN,
                    msg_ptr,
                    msg.len(),
                    sig_ptr,
                    FALCON512_SIG_LEN,
                ),
                1
            );

            let pk_slice = slice::from_raw_parts(pk_ptr, FALCON512_PUBKEY_LEN);
            let addr_slice = slice::from_raw_parts(addr_ptr, PQ_ADDRESS_LEN);
            assert_eq!(
                addr_slice,
                &derive_pq_address(pk_slice, &DEFAULT_SALT).unwrap()
            );

            dealloc(seed_ptr, FALCON_KEYGEN_SEED_LEN);
            dealloc(pk_ptr, FALCON512_PUBKEY_LEN);
            dealloc(sk_ptr, FALCON512_SECKEY_LEN);
            dealloc(addr_ptr, PQ_ADDRESS_LEN);
            dealloc(msg_ptr, msg.len());
            dealloc(entropy_ptr, entropy.len());
            dealloc(sig_ptr, FALCON512_SIG_LEN);
        }
    }
}
