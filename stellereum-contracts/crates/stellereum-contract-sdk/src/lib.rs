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
        /// Native value attached to the call.
        pub fn value() -> i64;
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

/// Native value attached to the current call.
#[cfg(target_arch = "wasm32")]
#[inline(always)]
pub fn value() -> u64 {
    unsafe { host::value() as u64 }
}

#[cfg(not(target_arch = "wasm32"))]
mod host_mock {
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static STORAGE: RefCell<HashMap<i64, i64>> = RefCell::new(HashMap::new());
        static EVENTS: RefCell<Vec<(i64, i64)>> = const { RefCell::new(Vec::new()) };
        static CALLER: RefCell<[u8; 32]> = const { RefCell::new([0u8; 32]) };
        static VALUE: RefCell<u64> = const { RefCell::new(0) };
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
        VALUE.with(|v| *v.borrow_mut() = 0);
    }

    /// Set the mock authenticated caller (test double for `host.caller`).
    pub fn set_mock_caller(caller: [u8; 32]) {
        CALLER.with(|c| *c.borrow_mut() = caller);
    }

    /// Read the mock authenticated caller.
    pub fn mock_caller() -> [u8; 32] {
        CALLER.with(|c| *c.borrow())
    }

    /// Set the mock attached value (test double for `host.value`).
    pub fn set_mock_value(value: u64) {
        VALUE.with(|v| *v.borrow_mut() = value);
    }

    /// Read the mock attached value.
    pub fn mock_value() -> u64 {
        VALUE.with(|v| *v.borrow())
    }

    pub fn get_mock_events() -> Vec<(i64, i64)> {
        EVENTS.with(|e| e.borrow().clone())
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

/// Set the mock attached value (tests only).
#[cfg(not(target_arch = "wasm32"))]
pub fn set_mock_value(value: u64) {
    host_mock::set_mock_value(value)
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
        set_mock_caller([0xABu8; 32]);
        set_mock_value(12345);
        assert_eq!(caller(), [0xABu8; 32]);
        assert_eq!(value(), 12345);
        reset_mock_state();
        assert_eq!(caller(), [0u8; 32]);
        assert_eq!(value(), 0);
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
}
