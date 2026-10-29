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

#[cfg(not(target_arch = "wasm32"))]
mod host_mock {
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static STORAGE: RefCell<HashMap<i64, i64>> = RefCell::new(HashMap::new());
        static EVENTS: RefCell<Vec<(i64, i64)>> = const { RefCell::new(Vec::new()) };
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

#[cfg(not(target_arch = "wasm32"))]
pub fn get_mock_events() -> Vec<(i64, i64)> {
    host_mock::get_mock_events()
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
