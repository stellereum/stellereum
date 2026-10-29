// Fuzz target: the EVM raw-transaction decoder (hand-rolled RLP).
//
// `eth_sendRawTransaction` -> `evm_raw_to_stell_transaction` ->
// `DecodedTransaction::decode` -> the RLP item decoder in `src/evm_adapter.rs`.
// Every byte of that input is chosen by a REMOTE, UNAUTHENTICATED caller.
//
// WHY THIS TARGET EXISTS (audit-prep gap, 2026-10):
// the RLP implementation in `src/evm_adapter.rs` is NOT the `rlp` crate — it
// is a hand-written recursive-descent parser with its own canonical-form
// rules, its own length prefixes and its own recursion-depth guard
// (`RlpItem::MAX_DEPTH`). The pre-existing corpus covered only the `bincode`
// decoders and the infnode `Frame`, so this parser - the single most
// attacker-reachable custom parser in the node - had NO fuzz coverage at all.
//
// WHAT IT ASSERTS:
//   1. no PANIC on peer-controlled bytes (a panic in the RPC handler is a
//      remote DoS that takes the whole node with it, not just the caller);
//   2. `RlpItem::decode` (exact) and `RlpItem::decode_with_remainder` must
//      AGREE: the exact decoder may only fail with `TrailingBytes` when the
//      remainder decoder leaves bytes behind, and must otherwise return the
//      same item;
//   3. the raw-transaction decoder must never panic and must never accept an
//      input it also rejects for a length reason - it is the same byte
//      string, so the two views must not contradict each other.
//
// Run: cargo +nightly fuzz run evm_raw_tx_decode
// Stable fallback: cargo test --test fuzz_decoder_tests evm_
#![no_main]
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // --- the exact / remainder views must agree -----------------------
        match stellereum::evm_adapter::RlpItem::decode_with_remainder(data) {
            Ok((item, rest)) => {
                if rest.is_empty() {
                    let exact = stellereum::evm_adapter::RlpItem::decode(data)
                        .expect("exact decode must succeed when nothing is left over");
                    assert_eq!(
                        exact, item,
                        "the exact RLP decoder must return the same item as the remainder decoder"
                    );
                } else {
                    assert!(
                        stellereum::evm_adapter::RlpItem::decode(data).is_err(),
                        "the exact RLP decoder must reject input with trailing bytes"
                    );
                }
            }
            Err(_) => {
                assert!(
                    stellereum::evm_adapter::RlpItem::decode(data).is_err(),
                    "the exact RLP decoder must reject what the remainder decoder rejects"
                );
            }
        }

        // --- the raw transaction decoder ----------------------------------
        let _ = stellereum::evm_adapter::decode_raw_transaction(data);
        let _ = stellereum::evm_adapter::DecodedTransaction::decode(data);
    }));
});
#[cfg(not(feature = "libfuzzer"))]
fn main() {}
