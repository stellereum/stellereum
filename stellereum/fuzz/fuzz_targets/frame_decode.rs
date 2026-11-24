// Fuzz target: infnode Frame::decode (network entry point).
// Run: cargo +nightly fuzz run frame_decode -- -max_len=132096
// Stable fallback: cargo test --test fuzz_decoder_tests frame_
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
    // Must never panic on untrusted bytes; a panic here is a remote DoS.
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = infnode::proto::Frame::decode(data);
    }));
    // A panic (including an assertion above) is the bug this harness
    // exists to find: never let catch_unwind swallow it.
    if panicked.is_err() {
        std::process::abort();
    }
});
#[cfg(not(feature = "libfuzzer"))]
fn main() {}
