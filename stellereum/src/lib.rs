pub mod address;
pub mod bootstrap;
pub mod bridge;
pub mod cell;
pub mod chain;
pub mod chain_binding;
pub mod client_ip;
pub mod cn_vrf;
pub mod commitment;
pub mod consensus;
pub mod consensus_net;
pub mod contract;
pub mod contract_abi;
pub mod contract_source;
pub mod cpat2;
pub mod dns_seeds;
pub mod evm_adapter;
pub mod explorer;
pub mod governance;
// GATE: HashPool apply wiring is default-OFF (`state_engine::HASH_POOL_ENABLED
// = false`, no env knob). The pool only mutates via the test-gated
// `apply_hashpool_*` / `apply_block_transition_with_hashpool` entry points;
// the standard apply path is byte-identical while the gate is off.
pub mod hashpool;
pub mod light_client;
pub mod light_client_cli;
pub mod mempool;
pub mod metrics;
pub mod mev;
pub mod mev_epoch;
pub mod mev_kem_registry;
pub mod mev_v4;
// GATE: sandbox prototype — test builds only, never production surface.
#[cfg(test)]
mod mev_pq_plan;
// GATE: silent-payment SCAN/RECEIVE wiring — READ paths only, default OFF.
//
// `SILENT_PAY_ENABLED` is a plain `const bool` (no env knob, mirroring the
// `HASH_POOL_ENABLED = false` precedent in `state_engine.rs`, not the
// `MEV_V4_ENV` env pattern): `false` in every build. Pure shapes
// (`sp_stealth_address`, `sp_send`, pool math) are public and ungated like
// `hashpool`'s (`stealth_encap`, `note_commit`); the STATEFUL receive
// ratchet is reachable only through the wallet `SilentScanner`, which is
// disarmed unless the const flips or the per-instance
// `enable_for_tests` override fires (never on the live path, grep-proof:
// only `tests/` call it). Send/spend/funds paths have no entry points and
// no callers — never add any without a spec update + audit note + full gate.
pub const SILENT_PAY_ENABLED: bool = false;

/// Whether the silent-payment stateful receive path is armed. Default OFF;
/// see [`SILENT_PAY_ENABLED`].
pub fn silent_pay_enabled() -> bool {
    SILENT_PAY_ENABLED
}

/// Silent-payment prototype shapes (read paths wired, send/spend unwired).
///
/// Public so tests exercise the REAL wiring (`stellereum::silentpay::…`,
/// no path-included copy — the `hashpool_wiring_tests.rs` precedent), exactly
/// like `pub mod hashpool`. Production calls only the read helpers below
/// and the wallet `SilentScanner`; `sp_send` / `SpPool::{spend,
/// spend_signed}` have no callers.
pub mod silentpay;

/// Derive the silent-payment stealth address for `(chain_id, chain, ss, index)`
/// — the exact `sp_stealth_address` shape
/// (`SHAKE256(SP_STEALTH_DST || chain_be64 || chain || ss || index_be64)`).
/// Pure shape (ungated, like `hashpool::stealth_encap`); the gate lives on
/// the stateful scan in the wallet `SilentScanner`.
pub fn silent_stealth_address(
    chain_id: u64,
    chain: &[u8; 32],
    ss: &[u8; 32],
    index: u64,
) -> [u8; 32] {
    silentpay::sp_stealth_address(chain_id, chain, ss, index)
}

/// Derive the stealth address and render it in branded `Stl57` text via the
/// unmodified [`address::encode_stl57_address`]. Pure shape (ungated).
pub fn silent_stealth_display(
    chain_id: u64,
    chain: &[u8; 32],
    ss: &[u8; 32],
    index: u64,
) -> String {
    address::encode_stl57_address(&silent_stealth_address(chain_id, chain, ss, index))
}
pub mod mmr;
pub mod native_api;
pub mod network;
pub mod node_keys;
pub mod oracle;
pub mod orderbook;
pub mod parallel_exec;
pub mod pmm;
pub mod post_quantum;
pub mod pq_registry;
pub mod remote_signer;
pub mod rpc;
pub mod runtime;
pub mod sharding;
pub mod simulator;
pub mod snapshot_cadence;
pub mod staking;
pub mod state_engine;
pub mod storage;
pub mod svm;
pub mod sync;
pub mod token;
pub mod tokenomics;
pub mod turnstile;
pub mod vrf;
pub mod wallet;
pub mod wallet_signing;
pub mod xshard2pc;
pub mod zkml;
pub mod zkml_attestation;
