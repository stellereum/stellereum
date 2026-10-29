// Fuzz target: Transaction bincode decode (size, opcode count, length prefixes).
// Run: cargo +nightly fuzz run transaction_decode
// Stable fallback: cargo test --test fuzz_decoder_tests transaction_
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;
#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let r: Result<stellereum::sharding::Transaction, _> = bincode::deserialize(data);
        let _ = r;
    }));
});
#[cfg(not(feature = "libfuzzer"))]
fn main() {}
