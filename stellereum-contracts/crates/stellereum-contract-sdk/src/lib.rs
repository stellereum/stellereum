//! Stellereum Smart Contract SDK (Pure Rust)
//!
//! Provides idiomatic Rust bindings for the Stellereum WASM runtime.
//! Compiles under `wasm32-unknown-unknown` without std, and runs unit tests
//! with mock storage under native targets.

#![cfg_attr(target_arch = "wasm32", no_std)]

pub mod address;
pub mod storage;

pub use address::{calculate_domain_hue, hash_domain, BURN_ADDRESS};
pub use storage::{StorageItem, StorageMap};

// Standard return / status codes
pub const SUCCESS: i64 = 0;
pub const ERR_UNAUTHORIZED: i64 = -1;
pub const ERR_INSUFFICIENT_BALANCE: i64 = -2;
pub const ERR_INVALID_ARGUMENT: i64 = -3;
pub const ERR_EXPIRED: i64 = -4;
pub const ERR_ALREADY_EXISTS: i64 = -5;
pub const ERR_NOT_FOUND: i64 = -6;
pub const ERR_OVERFLOW: i64 = -7;

pub const MAX_CALLDATA_BYTES: usize = 64 * 1024;
pub const MAX_RETURN_DATA_BYTES: usize = 64 * 1024;

#[cfg(target_arch = "wasm32")]
mod host {
    #[link(wasm_import_module = "host")]
    extern "C" {
        pub fn sload(key: i64) -> i64;
        pub fn sstore(key: i64, val: i64);
        pub fn emit(topic: i64, val: i64);
        /// Authenticated tx sender (32 bytes) written to `dest_ptr`.
        /// Audit B-CT: contracts MUST authenticate with this, never with
        /// caller-supplied integer ids (replayable — all ids are public).
        pub fn caller(dest_ptr: i32);
        /// Immutable transaction origin (`tx.from`, 32 bytes) written to `dest_ptr`.
        pub fn origin(dest_ptr: i32);
        /// Native value attached to the call.
        pub fn value() -> i64;
        /// Current block timestamp in seconds since Unix epoch.
        pub fn block_time() -> i64;
        /// Parent block hash (32 bytes) written to `dest_ptr`.
        pub fn block_hash(dest_ptr: i32);
        /// Copies ABI-encoded calldata into `dest_ptr` and returns byte length.
        pub fn calldata(dest_ptr: i32) -> i64;
        /// Sets the contract return data buffer from `[ptr .. ptr + len]`.
        pub fn return_data(ptr: i32, len: i32);
        /// Computes SHA-256 over `[src_ptr .. src_ptr + src_len]`, writing 32 bytes to `dest_ptr`.
        pub fn sha256(src_ptr: i32, src_len: i32, dest_ptr: i32);
        /// Computes BLAKE3 over `[src_ptr .. src_ptr + src_len]`, writing 32 bytes to `dest_ptr`.
        pub fn blake3(src_ptr: i32, src_len: i32, dest_ptr: i32);
        /// Verifies a Falcon-512 signature; returns 1 if valid, 0 otherwise.
        pub fn falcon512_verify(
            msg_ptr: i32,
            msg_len: i32,
            pk_ptr: i32,
            pk_len: i32,
            sig_ptr: i32,
            sig_len: i32,
        ) -> i32;
        /// Enqueues an outbound actor message; returns positive message number or negative error code.
        pub fn send_message(
            recipient_ptr: i64,
            recipient_len: i64,
            value_nano: i64,
            payload_ptr: i64,
            payload_len: i64,
            bounce_flag: i64,
        ) -> i64;
    }
}

#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn sload(key: i64) -> i64 {
    unsafe { host::sload(key) }
}

#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn sstore(key: i64, val: i64) {
    unsafe { host::sstore(key, val) }
}

#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn emit(topic: i64, val: i64) {
    unsafe { host::emit(topic, val) }
}

#[cfg(target_arch = "wasm32")]
static mut CALLER_BUF: [u8; 32] = [0u8; 32];

/// Authenticated transaction sender (audit B-CT: the ONLY trustworthy
/// caller identity — never accept `from`/`owner`/`caller_id` args for auth).
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn caller() -> [u8; 32] {
    unsafe {
        host::caller(core::ptr::addr_of_mut!(CALLER_BUF) as i32);
        core::ptr::read(core::ptr::addr_of!(CALLER_BUF))
    }
}

#[cfg(target_arch = "wasm32")]
static mut ORIGIN_BUF: [u8; 32] = [0u8; 32];

/// Immutable transaction origin (`tx.from`).
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn origin() -> [u8; 32] {
    unsafe {
        host::origin(core::ptr::addr_of_mut!(ORIGIN_BUF) as i32);
        core::ptr::read(core::ptr::addr_of!(ORIGIN_BUF))
    }
}

/// Native value attached to the current call.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn value() -> u64 {
    unsafe { host::value() as u64 }
}

/// Current block timestamp in seconds since Unix epoch.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn block_time() -> i64 {
    unsafe { host::block_time() }
}

#[cfg(target_arch = "wasm32")]
static mut BLOCK_HASH_BUF: [u8; 32] = [0u8; 32];

/// Parent block hash (`[0u8; 32]` when unavailable or pre-activation).
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn block_hash() -> [u8; 32] {
    unsafe {
        host::block_hash(core::ptr::addr_of_mut!(BLOCK_HASH_BUF) as i32);
        core::ptr::read(core::ptr::addr_of!(BLOCK_HASH_BUF))
    }
}

#[cfg(target_arch = "wasm32")]
static mut CALLDATA_BUF: [u8; MAX_CALLDATA_BYTES] = [0u8; MAX_CALLDATA_BYTES];

/// Copy ABI-encoded calldata into `dest`, returning the number of bytes written.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn calldata(dest: &mut [u8]) -> usize {
    unsafe {
        let raw_len = host::calldata(core::ptr::addr_of_mut!(CALLDATA_BUF) as i32);
        if raw_len <= 0 {
            return 0;
        }
        let n = (raw_len as usize).min(dest.len()).min(MAX_CALLDATA_BYTES);
        let src = core::slice::from_raw_parts(core::ptr::addr_of!(CALLDATA_BUF) as *const u8, n);
        dest[..n].copy_from_slice(src);
        n
    }
}

/// Copy ABI-encoded calldata into `dest` without truncation.
///
/// Returns `Err(ERR_INVALID_ARGUMENT)` when raw calldata length is negative,
/// exceeds `MAX_CALLDATA_BYTES`, or exceeds `dest.len()`.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn calldata_exact(dest: &mut [u8]) -> Result<usize, i64> {
    let raw_len = unsafe { host::calldata(core::ptr::addr_of_mut!(CALLDATA_BUF) as i32) };
    let Ok(n) = usize::try_from(raw_len) else {
        return Err(ERR_INVALID_ARGUMENT);
    };
    if n > dest.len() || n > MAX_CALLDATA_BYTES {
        return Err(ERR_INVALID_ARGUMENT);
    }
    unsafe {
        let src = core::slice::from_raw_parts(core::ptr::addr_of!(CALLDATA_BUF) as *const u8, n);
        dest[..n].copy_from_slice(src);
    }
    Ok(n)
}

/// Set the contract return data buffer for the current call.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn return_data(data: &[u8]) {
    let len = i32::try_from(data.len()).unwrap_or(i32::MAX);
    unsafe { host::return_data(data.as_ptr() as i32, len) }
}

#[cfg(target_arch = "wasm32")]
static mut SHA256_BUF: [u8; 32] = [0u8; 32];

/// Compute SHA-256 digest of `data` via the host cryptographic precompile.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let len = i32::try_from(data.len()).unwrap_or(i32::MAX);
    unsafe {
        host::sha256(
            data.as_ptr() as i32,
            len,
            core::ptr::addr_of_mut!(SHA256_BUF) as i32,
        );
        core::ptr::read(core::ptr::addr_of!(SHA256_BUF))
    }
}

#[cfg(target_arch = "wasm32")]
static mut BLAKE3_BUF: [u8; 32] = [0u8; 32];

/// Compute BLAKE3 digest of `data` via the host cryptographic precompile.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let len = i32::try_from(data.len()).unwrap_or(i32::MAX);
    unsafe {
        host::blake3(
            data.as_ptr() as i32,
            len,
            core::ptr::addr_of_mut!(BLAKE3_BUF) as i32,
        );
        core::ptr::read(core::ptr::addr_of!(BLAKE3_BUF))
    }
}

/// Verify a post-quantum Falcon-512 signature via the host verifier.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn falcon512_verify(msg: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
    let Ok(mlen) = i32::try_from(msg.len()) else {
        return false;
    };
    let Ok(pklen) = i32::try_from(pubkey.len()) else {
        return false;
    };
    let Ok(siglen) = i32::try_from(signature.len()) else {
        return false;
    };
    unsafe {
        host::falcon512_verify(
            msg.as_ptr() as i32,
            mlen,
            pubkey.as_ptr() as i32,
            pklen,
            signature.as_ptr() as i32,
            siglen,
        ) != 0
    }
}

/// Enqueue an outbound actor message to `recipient` carrying `value_nano` and `payload`.
/// Returns positive 1-based message index on success, or negative error code on failure.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn send_message(recipient: &[u8; 32], value_nano: u64, payload: &[u8], bounce: bool) -> i64 {
    let Ok(val) = i64::try_from(value_nano) else {
        return -2;
    };
    unsafe {
        host::send_message(
            recipient.as_ptr() as usize as i64,
            32,
            val,
            payload.as_ptr() as usize as i64,
            payload.len() as i64,
            i64::from(bounce),
        )
    }
}

/// Recorded outbound actor message in native host mocks.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockOutboundMessage {
    pub recipient: [u8; 32],
    pub value_nano: u64,
    pub payload: Vec<u8>,
    pub bounce: bool,
}

#[cfg(not(target_arch = "wasm32"))]
mod host_mock {
    use super::{
        MockOutboundMessage, ERR_INVALID_ARGUMENT, MAX_CALLDATA_BYTES, MAX_RETURN_DATA_BYTES,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;

    const MAX_OUTBOUND_MESSAGES: usize = 64;

    thread_local! {
        static STORAGE: RefCell<HashMap<i64, i64>> = RefCell::new(HashMap::new());
        static EVENTS: RefCell<Vec<(i64, i64)>> = const { RefCell::new(Vec::new()) };
        static CALLER: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
        static ORIGIN: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
        static VALUE: RefCell<u64> = const { RefCell::new(0) };
        static BLOCK_TIME: RefCell<i64> = const { RefCell::new(0) };
        static BLOCK_HASH: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
        static CALLDATA: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static RETURN_DATA: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
        static FALCON512_VALID: RefCell<bool> = const { RefCell::new(false) };
        static OUTBOUND_MESSAGES: RefCell<Vec<MockOutboundMessage>> = const { RefCell::new(Vec::new()) };
    }

    pub fn sload(key: i64) -> i64 {
        STORAGE.with(|s| s.borrow().get(&key).copied().unwrap_or(0))
    }

    pub fn sstore(key: i64, val: i64) {
        STORAGE.with(|s| s.borrow_mut().insert(key, val));
    }

    pub fn emit(topic: i64, val: i64) {
        EVENTS.with(|e| e.borrow_mut().push((topic, val)));
    }

    pub fn reset_mock_state() {
        STORAGE.with(|s| s.borrow_mut().clear());
        EVENTS.with(|e| e.borrow_mut().clear());
        CALLER.with(|c| *c.borrow_mut() = [0u8; 32]);
        ORIGIN.with(|o| *o.borrow_mut() = [0u8; 32]);
        VALUE.with(|v| *v.borrow_mut() = 0);
        BLOCK_TIME.with(|t| *t.borrow_mut() = 0);
        BLOCK_HASH.with(|h| *h.borrow_mut() = [0u8; 32]);
        CALLDATA.with(|d| d.borrow_mut().clear());
        RETURN_DATA.with(|d| d.borrow_mut().clear());
        FALCON512_VALID.with(|v| *v.borrow_mut() = false);
        OUTBOUND_MESSAGES.with(|m| m.borrow_mut().clear());
    }

    /// Set the mock authenticated caller (test double for `host.caller`).
    pub fn set_mock_caller(caller: [u8; 32]) {
        CALLER.with(|c| *c.borrow_mut() = caller);
    }

    /// Read the mock authenticated caller.
    pub fn mock_caller() -> [u8; 32] {
        CALLER.with(|c| *c.borrow())
    }

    /// Set the mock transaction origin (test double for `host.origin`).
    pub fn set_mock_origin(origin: [u8; 32]) {
        ORIGIN.with(|o| *o.borrow_mut() = origin);
    }

    /// Read the mock transaction origin.
    pub fn mock_origin() -> [u8; 32] {
        ORIGIN.with(|o| *o.borrow())
    }

    /// Set the mock attached value (test double for `host.value`).
    pub fn set_mock_value(value: u64) {
        VALUE.with(|v| *v.borrow_mut() = value);
    }

    /// Read the mock attached value.
    pub fn mock_value() -> u64 {
        VALUE.with(|v| *v.borrow())
    }

    /// Set the mock block timestamp (test double for `host.block_time`).
    pub fn set_mock_block_time(ts: i64) {
        BLOCK_TIME.with(|t| *t.borrow_mut() = ts);
    }

    /// Read the mock block timestamp.
    pub fn mock_block_time() -> i64 {
        BLOCK_TIME.with(|t| *t.borrow())
    }

    /// Set the mock parent block hash (test double for `host.block_hash`).
    pub fn set_mock_block_hash(hash: [u8; 32]) {
        BLOCK_HASH.with(|h| *h.borrow_mut() = hash);
    }

    /// Read the mock parent block hash.
    pub fn mock_block_hash() -> [u8; 32] {
        BLOCK_HASH.with(|h| *h.borrow())
    }

    /// Set the mock ABI-encoded calldata (test double for `host.calldata`).
    pub fn set_mock_calldata(data: &[u8]) {
        let len = data.len().min(MAX_CALLDATA_BYTES);
        CALLDATA.with(|d| {
            let mut buf = d.borrow_mut();
            buf.clear();
            buf.extend_from_slice(&data[..len]);
        });
    }

    /// Copy mock calldata into `dest`, returning the number of bytes written.
    pub fn mock_calldata(dest: &mut [u8]) -> usize {
        CALLDATA.with(|d| {
            let buf = d.borrow();
            let n = buf.len().min(dest.len());
            dest[..n].copy_from_slice(&buf[..n]);
            n
        })
    }

    /// Copy mock calldata into `dest` without truncation.
    pub fn mock_calldata_exact(dest: &mut [u8]) -> Result<usize, i64> {
        CALLDATA.with(|d| {
            let buf = d.borrow();
            let n = buf.len();
            if n > dest.len() || n > MAX_CALLDATA_BYTES {
                return Err(ERR_INVALID_ARGUMENT);
            }
            dest[..n].copy_from_slice(&buf[..n]);
            Ok(n)
        })
    }

    /// Set mock return data (test double for `host.return_data`).
    pub fn mock_return_data(data: &[u8]) {
        let len = data.len().min(MAX_RETURN_DATA_BYTES);
        RETURN_DATA.with(|d| {
            let mut buf = d.borrow_mut();
            buf.clear();
            buf.extend_from_slice(&data[..len]);
        });
    }

    /// Read mock return data.
    pub fn get_mock_return_data() -> Vec<u8> {
        RETURN_DATA.with(|d| d.borrow().clone())
    }

    /// Configure mock Falcon-512 verification result (defaults to `false`, fail-closed).
    pub fn set_mock_falcon512_verify(valid: bool) {
        FALCON512_VALID.with(|v| *v.borrow_mut() = valid);
    }

    /// Mock Falcon-512 verification.
    pub fn mock_falcon512_verify(_msg: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
        if pubkey.is_empty() || signature.is_empty() {
            return false;
        }
        FALCON512_VALID.with(|v| *v.borrow())
    }

    /// Mock outbound message enqueue (mirrors `host.send_message` return codes).
    pub fn mock_send_message(
        recipient: &[u8; 32],
        value_nano: u64,
        payload: &[u8],
        bounce: bool,
    ) -> i64 {
        if payload.len() > MAX_CALLDATA_BYTES {
            return -1;
        }
        if i64::try_from(value_nano).is_err() {
            return -2;
        }
        OUTBOUND_MESSAGES.with(|m| {
            let mut msgs = m.borrow_mut();
            if msgs.len() >= MAX_OUTBOUND_MESSAGES {
                return -3;
            }
            msgs.push(MockOutboundMessage {
                recipient: *recipient,
                value_nano,
                payload: payload.to_vec(),
                bounce,
            });
            msgs.len() as i64
        })
    }

    pub fn get_mock_outbound_messages() -> Vec<MockOutboundMessage> {
        OUTBOUND_MESSAGES.with(|m| m.borrow().clone())
    }

    pub fn get_mock_events() -> Vec<(i64, i64)> {
        EVENTS.with(|e| e.borrow().clone())
    }

    /// Pure-Rust FIPS 180-4 SHA-256 for native unit tests (`host.sha256` mock).
    pub fn mock_sha256(data: &[u8]) -> [u8; 32] {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut padded = Vec::with_capacity(data.len() + 72);
        padded.extend_from_slice(data);
        padded.push(0x80);
        while (padded.len() % 64) != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in padded.chunks_exact(64) {
            let mut w = [0u32; 64];
            for (i, word) in chunk.chunks_exact(4).enumerate() {
                w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            h[0] = h[0].wrapping_add(a);
            h[1] = h[1].wrapping_add(b);
            h[2] = h[2].wrapping_add(c);
            h[3] = h[3].wrapping_add(d);
            h[4] = h[4].wrapping_add(e);
            h[5] = h[5].wrapping_add(f);
            h[6] = h[6].wrapping_add(g);
            h[7] = h[7].wrapping_add(hh);
        }
        let mut out = [0u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Pure-Rust BLAKE3 for native unit tests (`host.blake3` mock).
    pub fn mock_blake3(data: &[u8]) -> [u8; 32] {
        const IV: [u32; 8] = [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
            0x5BE0CD19,
        ];
        const MSG_PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
        const CHUNK_START: u32 = 1;
        const CHUNK_END: u32 = 2;
        const PARENT: u32 = 4;
        const ROOT: u32 = 8;
        const BLOCK_LEN: usize = 64;
        const CHUNK_LEN: usize = 1024;

        fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
            state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
            state[d] = (state[d] ^ state[a]).rotate_right(16);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] = (state[b] ^ state[c]).rotate_right(12);
            state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
            state[d] = (state[d] ^ state[a]).rotate_right(8);
            state[c] = state[c].wrapping_add(state[d]);
            state[b] = (state[b] ^ state[c]).rotate_right(7);
        }

        fn compress(
            cv: &[u32; 8],
            block_words: &[u32; 16],
            counter: u64,
            block_len: u32,
            flags: u32,
        ) -> [u32; 16] {
            let mut state = [
                cv[0],
                cv[1],
                cv[2],
                cv[3],
                cv[4],
                cv[5],
                cv[6],
                cv[7],
                IV[0],
                IV[1],
                IV[2],
                IV[3],
                counter as u32,
                (counter >> 32) as u32,
                block_len,
                flags,
            ];
            let mut m = *block_words;
            for r in 0..7 {
                g(&mut state, 0, 4, 8, 12, m[0], m[1]);
                g(&mut state, 1, 5, 9, 13, m[2], m[3]);
                g(&mut state, 2, 6, 10, 14, m[4], m[5]);
                g(&mut state, 3, 7, 11, 15, m[6], m[7]);
                g(&mut state, 0, 5, 10, 15, m[8], m[9]);
                g(&mut state, 1, 6, 11, 12, m[10], m[11]);
                g(&mut state, 2, 7, 8, 13, m[12], m[13]);
                g(&mut state, 3, 4, 9, 14, m[14], m[15]);
                if r < 6 {
                    let mut perm = [0u32; 16];
                    for i in 0..16 {
                        perm[i] = m[MSG_PERM[i]];
                    }
                    m = perm;
                }
            }
            for i in 0..8 {
                state[i] ^= state[i + 8];
                state[i + 8] ^= cv[i];
            }
            state
        }

        fn words_from_block(block: &[u8]) -> [u32; 16] {
            let mut padded = [0u8; 64];
            padded[..block.len()].copy_from_slice(block);
            let mut words = [0u32; 16];
            for (i, w) in padded.chunks_exact(4).enumerate() {
                words[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            }
            words
        }

        fn first8(s: [u32; 16]) -> [u32; 8] {
            [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]
        }

        fn parent_cv(left: &[u32; 8], right: &[u32; 8], is_root: bool) -> [u32; 8] {
            let mut words = [0u32; 16];
            words[..8].copy_from_slice(left);
            words[8..].copy_from_slice(right);
            let flags = PARENT | if is_root { ROOT } else { 0 };
            first8(compress(&IV, &words, 0, BLOCK_LEN as u32, flags))
        }

        fn compress_chunk(chunk: &[u8], chunk_idx: u64, is_single_chunk: bool) -> [u32; 8] {
            let mut cv = IV;
            if chunk.is_empty() {
                let words = words_from_block(&[]);
                let flags = CHUNK_START | CHUNK_END | if is_single_chunk { ROOT } else { 0 };
                return first8(compress(&cv, &words, chunk_idx, 0, flags));
            }
            let num_blocks = chunk.len().div_ceil(BLOCK_LEN);
            for (b_idx, block) in chunk.chunks(BLOCK_LEN).enumerate() {
                let mut flags = 0u32;
                if b_idx == 0 {
                    flags |= CHUNK_START;
                }
                if b_idx + 1 == num_blocks {
                    flags |= CHUNK_END;
                    if is_single_chunk {
                        flags |= ROOT;
                    }
                }
                let words = words_from_block(block);
                cv = first8(compress(&cv, &words, chunk_idx, block.len() as u32, flags));
            }
            cv
        }

        let root_cv = if data.len() <= CHUNK_LEN {
            compress_chunk(data, 0, true)
        } else {
            let mut stack: [[u32; 8]; 54] = [[0u32; 8]; 54];
            let mut stack_len = 0usize;
            for (idx, chunk) in data.chunks(CHUNK_LEN).enumerate() {
                let mut new_cv = compress_chunk(chunk, idx as u64, false);
                let mut total_chunks = (idx + 1) as u64;
                while total_chunks & 1 == 0 {
                    stack_len -= 1;
                    new_cv = parent_cv(&stack[stack_len], &new_cv, false);
                    total_chunks >>= 1;
                }
                stack[stack_len] = new_cv;
                stack_len += 1;
            }
            let mut acc = stack[stack_len - 1];
            for i in (0..stack_len - 1).rev() {
                acc = parent_cv(&stack[i], &acc, i == 0);
            }
            acc
        };

        let mut out = [0u8; 32];
        for (i, w) in root_cv.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn sload(key: i64) -> i64 {
    host_mock::sload(key)
}

#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn sstore(key: i64, val: i64) {
    host_mock::sstore(key, val);
}

#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn emit(topic: i64, val: i64) {
    host_mock::emit(topic, val);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn reset_mock_state() {
    host_mock::reset_mock_state();
}

/// Mock-authenticated caller (test double; on wasm32 reads `host.caller`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn caller() -> [u8; 32] {
    host_mock::mock_caller()
}

/// Mock transaction origin (test double; on wasm32 reads `host.origin`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn origin() -> [u8; 32] {
    host_mock::mock_origin()
}

/// Mock attached value (test double; on wasm32 reads `host.value`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn value() -> u64 {
    host_mock::mock_value()
}

/// Set the mock authenticated caller (tests only).
#[cfg(not(target_arch = "wasm32"))]
pub fn set_mock_caller(caller: [u8; 32]) {
    host_mock::set_mock_caller(caller)
}

/// Set the mock transaction origin (tests only).
#[cfg(not(target_arch = "wasm32"))]
pub fn set_mock_origin(origin: [u8; 32]) {
    host_mock::set_mock_origin(origin)
}

/// Set the mock attached value (tests only).
#[cfg(not(target_arch = "wasm32"))]
pub fn set_mock_value(value: u64) {
    host_mock::set_mock_value(value)
}

/// Mock block timestamp (test double; on wasm32 reads `host.block_time`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn block_time() -> i64 {
    host_mock::mock_block_time()
}

/// Set the mock block timestamp (tests only).
#[cfg(not(target_arch = "wasm32"))]
pub fn set_mock_block_time(ts: i64) {
    host_mock::set_mock_block_time(ts)
}

/// Mock parent block hash (test double; on wasm32 reads `host.block_hash`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn block_hash() -> [u8; 32] {
    host_mock::mock_block_hash()
}

/// Set the mock parent block hash (tests only).
#[cfg(not(target_arch = "wasm32"))]
pub fn set_mock_block_hash(hash: [u8; 32]) {
    host_mock::set_mock_block_hash(hash)
}

/// Copy mock calldata into `dest` (test double; on wasm32 reads `host.calldata`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn calldata(dest: &mut [u8]) -> usize {
    host_mock::mock_calldata(dest)
}

/// Copy mock calldata into `dest` without truncation (test double; on wasm32 reads `host.calldata`).
///
/// Returns `Err(ERR_INVALID_ARGUMENT)` when raw calldata length exceeds `dest.len()`.
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn calldata_exact(dest: &mut [u8]) -> Result<usize, i64> {
    host_mock::mock_calldata_exact(dest)
}

/// Set the mock ABI-encoded calldata (tests only).
#[cfg(not(target_arch = "wasm32"))]
pub fn set_mock_calldata(data: &[u8]) {
    host_mock::set_mock_calldata(data)
}

/// Set mock return data (test double; on wasm32 writes `host.return_data`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn return_data(data: &[u8]) {
    host_mock::mock_return_data(data)
}

/// Read mock return data recorded by [`return_data`] (tests only).
#[cfg(not(target_arch = "wasm32"))]
pub fn get_mock_return_data() -> Vec<u8> {
    host_mock::get_mock_return_data()
}

/// Compute SHA-256 digest of `data` (on wasm32 calls `host.sha256`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    host_mock::mock_sha256(data)
}

/// Compute BLAKE3 digest of `data` (on wasm32 calls `host.blake3`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    host_mock::mock_blake3(data)
}

/// Mock Falcon-512 verification (test double; on wasm32 calls `host.falcon512_verify`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn falcon512_verify(msg: &[u8], pubkey: &[u8], signature: &[u8]) -> bool {
    host_mock::mock_falcon512_verify(msg, pubkey, signature)
}

/// Configure mock Falcon-512 verification return value (tests only, default `false`).
#[cfg(not(target_arch = "wasm32"))]
pub fn set_mock_falcon512_verify(valid: bool) {
    host_mock::set_mock_falcon512_verify(valid)
}

/// Enqueue mock outbound actor message (test double; on wasm32 calls `host.send_message`).
#[cfg(not(target_arch = "wasm32"))]
#[inline(always)]
pub fn send_message(recipient: &[u8; 32], value_nano: u64, payload: &[u8], bounce: bool) -> i64 {
    host_mock::mock_send_message(recipient, value_nano, payload, bounce)
}

/// Read mock outbound actor messages enqueued via [`send_message`] (tests only).
#[cfg(not(target_arch = "wasm32"))]
pub fn get_mock_outbound_messages() -> Vec<MockOutboundMessage> {
    host_mock::get_mock_outbound_messages()
}

#[cfg(not(target_arch = "wasm32"))]
pub fn get_mock_events() -> Vec<(i64, i64)> {
    host_mock::get_mock_events()
}

/// Canonical 32-byte host address for a demo-scale integer account id.
///
/// Contracts route balances by small `i64` ids but MUST authenticate with the
/// 32-byte `host.caller` (audit B-CT: ids are public and replayable, the
/// caller address is not). This is the single binding between the two: `id`
/// occupies bytes `[0..8]` little-endian, bytes `[8..32]` are zero. There is
/// no registry and no fallback — an id authenticates IFF the live `caller()`
/// equals this encoding.
#[inline(always)]
pub fn id_to_caller(id: i64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let le = id.to_le_bytes();
    out[..8].copy_from_slice(&le);
    out
}

/// Fail-closed authentication for integer account ids (audit CT-P0).
///
/// Returns true IFF `id` is a valid account (`id > 0`) AND the authenticated
/// `host.caller` is the canonical address for `id`. In particular the zero
/// address (no authenticated sender on any host; also the mock default)
/// never authenticates: `caller_is(0)` and `caller_is(negative)` are false.
#[inline(always)]
pub fn caller_is(id: i64) -> bool {
    id > 0 && caller() == id_to_caller(id)
}

/// Helper macro for registering wasm panic handler in cdylib crates
#[macro_export]
macro_rules! setup_wasm_panic_handler {
    () => {
        #[cfg(target_arch = "wasm32")]
        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo) -> ! {
            core::arch::wasm32::unreachable()
        }
    };
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod caller_mock_tests {
    use super::*;

    #[test]
    fn mock_caller_value_roundtrip_and_reset() {
        reset_mock_state();
        assert_eq!(caller(), [0u8; 32]);
        assert_eq!(value(), 0);
        assert_eq!(block_time(), 0);
        set_mock_caller([0xABu8; 32]);
        set_mock_value(12345);
        set_mock_block_time(1_750_000_000);
        assert_eq!(caller(), [0xABu8; 32]);
        assert_eq!(value(), 12345);
        assert_eq!(block_time(), 1_750_000_000);
        reset_mock_state();
        assert_eq!(caller(), [0u8; 32]);
        assert_eq!(value(), 0);
        assert_eq!(block_time(), 0);
    }

    #[test]
    fn id_to_caller_encoding_is_stable() {
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(id_to_caller(1), one);
        assert_eq!(id_to_caller(0), [0u8; 32]);
        // Little-endian id in bytes [0..8], zero elsewhere.
        let mut big = [0u8; 32];
        big[..8].copy_from_slice(&99_999i64.to_le_bytes());
        assert_eq!(id_to_caller(99_999), big);
    }

    #[test]
    fn caller_is_fail_closed() {
        reset_mock_state();
        // Zero address (mock default = no authenticated sender) owns nothing.
        assert!(!caller_is(0));
        assert!(!caller_is(-5));
        assert!(!caller_is(1));
        set_mock_caller(id_to_caller(1));
        assert!(caller_is(1));
        assert!(!caller_is(2));
        assert!(!caller_is(0));
        reset_mock_state();
        assert!(!caller_is(1));
    }

    #[test]
    fn extended_host_mocks_roundtrip_and_reset() {
        reset_mock_state();
        assert_eq!(origin(), [0u8; 32]);
        assert_eq!(block_hash(), [0u8; 32]);
        let mut buf = [0u8; 16];
        assert_eq!(calldata(&mut buf), 0);
        assert!(get_mock_return_data().is_empty());
        assert!(!falcon512_verify(b"m", &[1u8; 897], &[2u8; 666]));
        assert!(get_mock_outbound_messages().is_empty());

        set_mock_origin([0x11u8; 32]);
        set_mock_block_hash([0x22u8; 32]);
        set_mock_calldata(b"hello_calldata");
        return_data(b"ret_ok");
        set_mock_falcon512_verify(true);

        assert_eq!(origin(), [0x11u8; 32]);
        assert_eq!(block_hash(), [0x22u8; 32]);
        assert_eq!(calldata(&mut buf), 14);
        assert_eq!(&buf[..14], b"hello_calldata");
        assert_eq!(get_mock_return_data(), b"ret_ok");
        assert!(falcon512_verify(b"m", &[1u8; 897], &[2u8; 666]));
        assert!(!falcon512_verify(b"m", &[], &[2u8; 666]));

        let recipient = [0x33u8; 32];
        assert_eq!(send_message(&recipient, 500, b"ping", true), 1);
        let msgs = get_mock_outbound_messages();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].recipient, recipient);
        assert_eq!(msgs[0].value_nano, 500);
        assert_eq!(msgs[0].payload, b"ping");
        assert!(msgs[0].bounce);

        reset_mock_state();
        assert_eq!(origin(), [0u8; 32]);
        assert_eq!(block_hash(), [0u8; 32]);
        assert_eq!(calldata(&mut buf), 0);
        assert!(get_mock_return_data().is_empty());
        assert!(!falcon512_verify(b"m", &[1u8; 897], &[2u8; 666]));
        assert!(get_mock_outbound_messages().is_empty());
    }

    #[test]
    fn mock_sha256_and_blake3_match_standard_vectors() {
        // SHA-256("")
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        // SHA-256("abc")
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        // BLAKE3("")
        assert_eq!(
            blake3(b""),
            [
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
                0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
                0xe4, 0x1f, 0x32, 0x62,
            ]
        );
        // BLAKE3("abc")
        assert_eq!(
            blake3(b"abc"),
            [
                0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a,
                0x8d, 0xb5, 0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c,
                0xd5, 0xbd, 0x9d, 0x85,
            ]
        );
    }

    #[test]
    fn calldata_exact_rejects_oversized_and_accepts_exact_fit() {
        reset_mock_state();
        let mut empty = [0u8; 0];
        assert_eq!(calldata_exact(&mut empty), Ok(0));

        set_mock_calldata(b"exact16bytesdata");

        // Oversized input must fail with ERR_INVALID_ARGUMENT without modifying dest.
        let mut too_small = [0xAAu8; 15];
        assert_eq!(
            calldata_exact(&mut too_small),
            Err(ERR_INVALID_ARGUMENT)
        );
        assert_eq!(too_small, [0xAAu8; 15]);

        // Exact-fit input succeeds.
        let mut exact = [0u8; 16];
        assert_eq!(calldata_exact(&mut exact), Ok(16));
        assert_eq!(&exact, b"exact16bytesdata");

        // Larger destination buffer also succeeds without truncation.
        let mut larger = [0u8; 32];
        assert_eq!(calldata_exact(&mut larger), Ok(16));
        assert_eq!(&larger[..16], b"exact16bytesdata");
    }
}
