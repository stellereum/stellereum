// Fuzz target: the JSON-RPC request body parser.
//
// WHY THIS TARGET EXISTS (Wave 4, 2026-11):
// every unauthenticated HTTP/WS client reaches this parser before any method
// name is even looked at (`rpc::streams::rpc_handler` and `ws_handle_text` do
// `serde_json::from_str::<Value>` then `from_value::<RpcRequest>`). It is the
// widest remote input surface in the node, and it had no fuzz target. A panic
// here is a request-triggered DoS; a malformed body must produce a JSON-RPC
// error, never an abort.
//
// SCOPE: parsing only. `RpcState`/`dispatch` are async and require a live
// node, so they are deliberately out of scope for a deterministic, in-process
// harness. The transport's size caps are applied first, exactly like the
// production handlers.
//
// WHAT IT ASSERTS: no stage panics on arbitrary bytes — single object, batch
// array, or a declared-but-missing `method`.
//
// Run: cargo +nightly fuzz run rpc_json_decode
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "libfuzzer")]
const MAX_INPUT: usize = 1 << 20;

// A peer may not send more than the HTTP body cap; keep the harness cheap.
#[cfg(feature = "libfuzzer")]
const MAX_BATCH_ITEMS_REPLAYED: usize = 128;

#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Ok(text) = std::str::from_utf8(data) else {
            return;
        };
        let Ok(first) = serde_json::from_str::<serde_json::Value>(text) else {
            return;
        };

        // Single request path.
        let _ = serde_json::from_value::<stellereum::rpc::RpcRequest>(first.clone());

        // Batch path: each item is parsed independently in production.
        if let Some(items) = first.as_array() {
            for item in items.iter().take(MAX_BATCH_ITEMS_REPLAYED) {
                let _ = serde_json::from_value::<stellereum::rpc::RpcRequest>(item.clone());
            }
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
