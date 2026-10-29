//! High-level Storage Abstractions for Stellereum Smart Contracts

use crate::{sload, sstore};

/// Single storage slot wrapper.
#[derive(Debug, Clone, Copy)]
pub struct StorageItem {
    slot: i64,
}

impl StorageItem {
    pub const fn new(slot: i64) -> Self {
        Self { slot }
    }

    #[inline(always)]
    pub fn get(&self) -> i64 {
        sload(self.slot)
    }

    #[inline(always)]
    pub fn set(&self, val: i64) {
        sstore(self.slot, val);
    }

    #[inline(always)]
    pub fn update<F: FnOnce(i64) -> i64>(&self, f: F) -> i64 {
        let current = self.get();
        let next = f(current);
        self.set(next);
        next
    }
}

/// Key-Value mapping over contract storage slots.
/// Uses 64-bit FNV-1a mixing with domain separation over `base_slot` to eliminate collisions.
#[derive(Debug, Clone, Copy)]
pub struct StorageMap {
    base_slot: i64,
}

impl StorageMap {
    pub const fn new(base_slot: i64) -> Self {
        Self { base_slot }
    }

    #[inline(always)]
    pub fn key_slot(&self, key: i64) -> i64 {
        let mut hash: u64 = 0xcbf29ce484222325;
        let b_bytes = self.base_slot.to_le_bytes();
        let k_bytes = key.to_le_bytes();
        let mut i = 0;
        while i < 8 {
            hash ^= b_bytes[i] as u64;
            hash = hash.wrapping_mul(0x100000001b3);
            i += 1;
        }
        let mut j = 0;
        while j < 8 {
            hash ^= k_bytes[j] as u64;
            hash = hash.wrapping_mul(0x100000001b3);
            j += 1;
        }
        (hash & 0x7FFFFFFFFFFFFFFF) as i64
    }

    #[inline(always)]
    pub fn get(&self, key: i64) -> i64 {
        sload(self.key_slot(key))
    }

    #[inline(always)]
    pub fn set(&self, key: i64, val: i64) {
        sstore(self.key_slot(key), val);
    }

    #[inline(always)]
    pub fn update<F: FnOnce(i64) -> i64>(&self, key: i64, f: F) -> i64 {
        let current = self.get(key);
        let next = f(current);
        self.set(key, next);
        next
    }
}
