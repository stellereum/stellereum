// Fuzz target: ConsensusMsg::decode + the JSON/hex pubsub envelope.
//
// Covers:
//   * `consensus_net::ConsensusMsg::decode` (the C1-F2 nested-Batch fix);
//   * `consensus_net::parse_incoming` (the legacy `{topic,data}` envelope);
//   * `consensus_net::parse_incoming_with_peer_key` (the live inbound path,
//     which also validates the `src` peer key and the CRITICAL pre-decode
//     budget).
//
// WHAT IT ASSERTS:
//   1. no decode path PANICS on peer bytes;
//   2. a decoded batch honours the wire caps and is never nested — the exact
//      invariant C1-F2 added. A regression here means a remote peer can make
//      the decoder recurse again.
//
// Input is capped at 1 MiB (an honest message is far smaller; the production
// ceiling is 32 MiB, and this harness deliberately does not spend fuzz time
// mutating quarter-gigabyte hex envelopes).
//
// Run: cargo +nightly fuzz run consensus_msg_decode
// Stable fallback: cargo test --test fuzz_decoder_tests consensus_ / parse_
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
        let decoded = stellereum::consensus_net::ConsensusMsg::decode(data);
        if let Ok(stellereum::consensus_net::ConsensusMsg::Batch(items)) = &decoded {
            // C1-F2: the hand-written batch path refuses a count above the
            // cap and an inner Batch at any position.
            assert!(
                items.len() <= stellereum::consensus_net::MAX_BATCH_ITEMS,
                "a decoded batch must never exceed MAX_BATCH_ITEMS"
            );
            assert!(
                !items
                    .iter()
                    .any(|m| matches!(m, stellereum::consensus_net::ConsensusMsg::Batch(_))),
                "a decoded batch must never nest another batch"
            );
        }

        if let Ok(s) = std::str::from_utf8(data) {
            let _ = stellereum::consensus_net::parse_incoming(s);
            let _ = stellereum::consensus_net::parse_incoming_with_peer_key(s);
            let _ = stellereum::consensus_net::parse_tx_incoming(s);
        }
    }));
    // A panic (including an assertion above) is the bug this harness
    // exists to find: never let catch_unwind swallow it.
    if panicked.is_err() {
        std::process::abort();
    }
});

#[cfg(not(feature = "libfuzzer"))]
fn main() {}
