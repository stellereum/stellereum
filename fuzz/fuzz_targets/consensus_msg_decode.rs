// Fuzz target: ConsensusMsg::decode + parse_incoming + parse_tx_incoming.
// Run: cargo +nightly fuzz run consensus_msg_decode
// Stable fallback: cargo test --test fuzz_decoder_tests consensus_ / parse_
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;
#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = stellereum::consensus_net::ConsensusMsg::decode(data);
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = stellereum::consensus_net::parse_incoming(s);
            let _ = stellereum::consensus_net::parse_tx_incoming(s);
        }
    }));
});
#[cfg(not(feature = "libfuzzer"))]
fn main() {}
