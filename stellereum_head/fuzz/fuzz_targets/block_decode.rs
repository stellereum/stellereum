// Fuzz target: Block decode incl. validator_signatures.
// Run: cargo +nightly fuzz run block_decode
// Stable fallback: cargo test --test fuzz_decoder_tests block_
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;
#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let r: Result<stellereum::sharding::Block, _> = bincode::deserialize(data);
        let _ = r;
    }));
});
#[cfg(not(feature = "libfuzzer"))]
fn main() {}
