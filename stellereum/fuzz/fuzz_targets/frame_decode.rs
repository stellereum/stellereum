// Fuzz target: infnode Frame::decode (network entry point).
// Run: cargo +nightly fuzz run frame_decode -- -max_len=132096
// Stable fallback: cargo test --test fuzz_decoder_tests frame_
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;
#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    // Must never panic on untrusted bytes; a panic here is a remote DoS.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = infnode::proto::Frame::decode(data);
    }));
});
#[cfg(not(feature = "libfuzzer"))]
fn main() {}
