// Fuzz target: Transaction bincode decode (size, opcode count, length prefixes).
// Run: cargo +nightly fuzz run transaction_decode
// Stable fallback: cargo test --test fuzz_decoder_tests transaction_
#![no_main]
#[cfg(feature = "libfuzzer")]
use bincode::Options;
#[cfg(feature = "libfuzzer")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "libfuzzer")]
const MAX_INPUT: usize = 1 << 20;

#[cfg(feature = "libfuzzer")]
const MAX_WIRE_TX_BYTES: u64 = 262_144;

#[cfg(feature = "libfuzzer")]
fn check_contract_abis(ops: &[stellereum::svm::OpCode]) {
    let mut stack = vec![ops];
    while let Some(slice) = stack.pop() {
        for op in slice {
            match op {
                stellereum::svm::OpCode::SysCallDeployContractWithAbi { abi_json, .. } => {
                    if let Ok(abi_str) = std::str::from_utf8(abi_json) {
                        if let Ok(abi) = stellereum::contract_abi::ContractAbi::from_json(abi_str) {
                            let _ = abi.validate();
                        }
                    }
                }
                stellereum::svm::OpCode::SysCallActorSend { body, .. } => {
                    stack.push(body);
                }
                _ => {}
            }
        }
    }
}

#[cfg(feature = "libfuzzer")]
fn exercise_decoded_tx(tx: &stellereum::sharding::Transaction) {
    let _ = stellereum::sharding::Transaction::split_sponsor_envelope(&tx.signature);
    // `delegation()` forwards directly to `Transaction::delegation_from_inner(self.sponsor_inner_sig())`.
    let _ = tx.delegation();
    let _ = tx.signing_message();
    let _ = tx.compute_tx_hash();
    check_contract_abis(&tx.payload);
}

#[cfg(feature = "libfuzzer")]
fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let r: Result<stellereum::sharding::Transaction, _> = bincode::deserialize(data);
        let strict: Result<stellereum::sharding::Transaction, _> = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .with_limit(MAX_WIRE_TX_BYTES)
            .deserialize(data);
        if let Ok(ref tx) = strict {
            exercise_decoded_tx(tx);
        } else if let Ok(ref tx) = r {
            exercise_decoded_tx(tx);
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
