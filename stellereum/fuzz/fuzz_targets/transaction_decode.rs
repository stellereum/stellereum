// Fuzz target: Transaction bincode decode (size, opcode count, length prefixes).
// Run: cargo +nightly fuzz run transaction_decode
// Stable fallback: cargo test --test fuzz_decoder_tests transaction_
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "libfuzzer")]
const MAX_INPUT: usize = 1 << 20;
#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let r: Result<stellereum::sharding::Transaction, _> = bincode::deserialize(data);
        let _ = r;
    }));
    // A panic (including an assertion above) is the bug this harness
    // exists to find: never let catch_unwind swallow it.
    if panicked.is_err() {
        std::process::abort();
    }
});
#[cfg(not(feature = "libfuzzer"))]
fn main() {}
