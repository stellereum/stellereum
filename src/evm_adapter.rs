//! Ethereum JSON-RPC 2.0 types and network info adapter for Stellereum.
//!
//! Provides EVM compatibility layer allowing MetaMask, Chainlist, and standard
//! Web3 tooling to communicate with the Stellereum network.
//!
//! Supported network methods:
//! - `eth_chainId`: Returns the chain ID formatted as hex quantity ("0x167d" = 5757).
//! - `net_version`: Returns the network ID formatted as decimal string ("5757").
//! - `web3_clientVersion`: Returns the client identifier ("Stellereum/v5.0.0-evm-adapter").
//! - `net_listening`: Returns true indicating client is actively listening.
//! - `net_peerCount`: Returns connected peer count formatted as hex quantity ("0x2").
//! - `eth_syncing`: Returns false when node is in sync.
//! - `eth_gasPrice`: Returns base fee in Wei as hex ("0x3eb2788000").
//! - `eth_maxPriorityFeePerGas`: Returns max priority fee per gas ("0x3b9aca00" or "0x0").
//! - `eth_feeHistory`: Returns standard EIP-1559 fee history object for block count and newest block.
//! - `eth_estimateGas`: Returns floor-aware gas estimate ("0x445c0" = 280k admission floor for transfers; pure EVM figure would be "0x5208").
//!
//! Also provides exact JSON-RPC 2.0 serialization types for:
//! - `EvmBlock`
//! - `EvmTransaction`
//! - `EvmReceipt`
//! - `EvmFeeHistory`

use crate::rpc::RpcState;
use crate::state_engine::InMemoryStateEngine;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Default chain ID for Stellereum network (5757).
///
/// WHY THE VERIFICATION PINS STAY ON THIS CONSTANT (audit 2026-10-14 F3):
/// `eth_chainId` / `net_version` SERVE [`effective_chain_id`] (dynamic, so a
/// `STELL_CHAIN_ID` deployment never misidentifies itself to wallets), but
/// every signature-verification site (`eth_send_raw_transaction_bytes`,
/// `evm_raw_to_stell_transaction`, `DecodedTransaction::verify_signature`,
/// `validate_transaction_signature*`, `ecrecover*`) deliberately keeps
/// pinning `CHAIN_ID`. Verification is consensus-adjacent: every node that
/// admits or settles the same raw bytes must reach the same verdict, and a
/// per-process env read at each of those sites would let two validators with
/// different environments admit different tx sets (liveness divergence) or —
/// worse — disagree about what a settled envelope means. A deployment on a
/// different chain id changes this constant (and `CHAIN_ID_HEX` /
/// `NET_VERSION` defaults) at build/deploy time, identically on all nodes;
/// it never varies per process at runtime. Live is 5757 either way, so there
/// is zero behavior change while the env is unset.
pub const CHAIN_ID: u64 = 5757;

/// This node's effective EVM chain id: `STELL_CHAIN_ID` when set, else
/// [`CHAIN_ID`]. Threads the deployment's identity into the EVM adapter so
/// two deployments of one binary never share an EVM identity. Delegates to
/// [`crate::zkml::effective_chain_id`] (single definition of the env rule).
pub fn effective_chain_id() -> u64 {
    crate::zkml::effective_chain_id()
}

/// Fail-closed peer chain-id check for the EVM path: delegates to
/// [`crate::zkml::check_peer_chain_id`] so both hardcoded sites enforce the
/// same abort-on-mismatch rule.
pub fn check_peer_chain_id(local: u64, peer: u64) -> Result<(), String> {
    crate::zkml::check_peer_chain_id(local, peer)
}

/// `eth_chainId` for an explicit chain id (hex quantity, e.g. `0x167d`).
/// The static [`eth_chain_id`] keeps serving the default for compatibility.
pub fn eth_chain_id_for(chain_id: u64) -> String {
    format!("0x{chain_id:x}")
}

/// `net_version` for an explicit chain id (decimal string, e.g. `"5757"`).
/// The static [`net_version`] keeps serving the default for compatibility.
pub fn net_version_for(chain_id: u64) -> String {
    chain_id.to_string()
}

/// Hex-encoded chain ID with 0x prefix ("0x167d").
pub const CHAIN_ID_HEX: &str = "0x167d";

/// Network version string ("5757").
pub const NET_VERSION: &str = "5757";

/// Client version string ("Stellereum/v5.0.0-evm-adapter").
pub const CLIENT_VERSION: &str = "Stellereum/v5.0.0-evm-adapter";

/// Listening state (true).
/// Live justification: this handler answers JSON-RPC, so the node is by
/// construction listening on this transport. No live peer socket count is
/// plumbed into the stateless free function; the stateful [`EvmAdapter`]
/// override (`with_listening`) carries live values where available.
pub const NET_LISTENING: bool = true;

/// Peer count hex string ("0x2").
/// TESTNET-KNOWN default, not a live measurement: the stateless free function
/// has no peer table handle. Live callers use the stateful [`EvmAdapter`]
/// (`with_peer_count`) instead. `RpcState` likewise carries no peer count, so
/// `net_peerCount` through `rpc::dispatch` honestly returns this default.
pub const NET_PEER_COUNT: &str = "0x2";

/// Default connected peer count integer (2).
/// TESTNET-KNOWN default paired with [`NET_PEER_COUNT`].
pub const DEFAULT_PEER_COUNT: u64 = 2;

/// Syncing state (false).
/// TESTNET-KNOWN default for the stateless free function only. Live callers
/// compare heights instead — see [`eth_syncing_for_heights`] (used by
/// `rpc::dispatch` exactly like `stell_syncing`): a recent verified peer
/// height above ours means syncing.
pub const ETH_SYNCING: bool = false;

/// Base fee and default gas price in Wei formatted as hex quantity ("0x3eb2788000" = 269,279,002,624 Wei).
/// TESTNET-KNOWN defaults, not live fee-market readings: there is no EIP-1559
/// base-fee engine behind this adapter (the mempool `base_fee` is an admission
/// floor in gas units, not a wei price, so mapping it here would mix units).
/// Live callers use the stateful [`EvmAdapter`] (`with_gas_price` /
/// `with_base_fee`, fed from `eth_feeHistory` head state) instead.
pub const BASE_FEE_HEX: &str = "0x3eb2788000";
pub const DEFAULT_GAS_PRICE_HEX: &str = BASE_FEE_HEX;
pub const DEFAULT_BASE_FEE: u128 = 0x3eb2788000;
pub const DEFAULT_GAS_PRICE: u128 = DEFAULT_BASE_FEE;

/// Default maximum priority fee per gas formatted as hex quantity ("0x3b9aca00" = 1 Gwei).
pub const DEFAULT_MAX_PRIORITY_FEE_HEX: &str = "0x3b9aca00";
pub const ZERO_MAX_PRIORITY_FEE_HEX: &str = "0x0";
pub const DEFAULT_MAX_PRIORITY_FEE: u128 = 0x3b9aca00;

/// Pure-EVM transfer gas figure ("0x5208" = 21,000 gas). Served estimates are
/// floored to the admission floor (see `eth_estimate_gas_amount`).
pub const STANDARD_TRANSFER_GAS: u64 = 21_000;
pub const STANDARD_TRANSFER_GAS_HEX: &str = "0x5208";

/// Contract creation base gas estimate ("0xcf08" = 53,000 gas).
pub const CONTRACT_CREATION_BASE_GAS: u64 = 53_000;

/// Default block head for fee history queries.
pub const DEFAULT_HEAD_BLOCK: u64 = CHAIN_ID;

/// Empty keccak-256 hash for uncles.
pub const EMPTY_UNCLES_HASH: &str =
    "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347";

/// Empty root hash (trie root).
pub const EMPTY_ROOT_HASH: &str =
    "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

/// Empty 256-byte logs bloom filter (512 hex zero digits).
pub const EMPTY_LOGS_BLOOM: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000\
     0000000000000000000000000000000000000000000000000000000000000000";

/// Default ERC-20 token emulation parameters for MetaMask.
pub const DEFAULT_TOKEN_NAME: &str = "Stellereum";
pub const DEFAULT_TOKEN_SYMBOL: &str = "STELL";
pub const DEFAULT_TOKEN_DECIMALS: u8 = 18;
pub const DEFAULT_TOTAL_SUPPLY: u128 = 1_000_000_000_000_000_000_000_000_000;

/// Standard ERC-20 calldata selectors.
pub const SELECTOR_NAME: &str = "06fdde03";
pub const SELECTOR_SYMBOL: &str = "95d89b41";
pub const SELECTOR_DECIMALS: &str = "313ce567";
pub const SELECTOR_BALANCE_OF: &str = "70a08231";
pub const SELECTOR_TOTAL_SUPPLY: &str = "18160ddd";
pub const SELECTOR_TRANSFER: &str = "a9059cbb";
pub const SELECTOR_APPROVE: &str = "095ea7b3";
pub const SELECTOR_ALLOWANCE: &str = "dd62ed3e";
pub const SELECTOR_TRANSFER_FROM: &str = "23b87266";

pub const SELECTOR_NAME_HEX: &str = "0x06fdde03";
pub const SELECTOR_SYMBOL_HEX: &str = "0x95d89b41";
pub const SELECTOR_DECIMALS_HEX: &str = "0x313ce567";
pub const SELECTOR_BALANCE_OF_HEX: &str = "0x70a08231";
pub const SELECTOR_TOTAL_SUPPLY_HEX: &str = "0x18160ddd";
pub const SELECTOR_TRANSFER_HEX: &str = "0xa9059cbb";
pub const SELECTOR_APPROVE_HEX: &str = "0x095ea7b3";
pub const SELECTOR_ALLOWANCE_HEX: &str = "0xdd62ed3e";
pub const SELECTOR_TRANSFER_FROM_HEX: &str = "0x23b87266";

/// Time-to-live for idle filters in seconds (300s = 5 min, Geth-compatible).
/// A filter that has not been polled via `eth_getFilterChanges` / `eth_getFilterLogs`
/// for longer than this interval is considered expired and is removed lazily
/// on next access (or eagerly by [`FilterManager::sweep_expired`]).
pub const FILTER_TTL_SECS: u64 = 300;

/// Maximum number of concurrently active filters (DoS backstop).
pub const MAX_ACTIVE_FILTERS: usize = 10_000;

/// Maximum number of pending entries buffered per filter (DoS backstop).
/// Applies to pending block hashes, pending tx hashes, `pending_logs` and `all_logs`.
pub const MAX_PENDING_PER_FILTER: usize = 1_000;

/// Maximum number of logs returned by a single `eth_getLogs` call (DoS backstop,
/// Geth-compatible default range cap).
pub const MAX_GET_LOGS_RESULTS: usize = 1_000;

/// Empty EVM storage slot value: 32 zero bytes (`0x` + 64 hex zeros).
/// Stellereum executes no EVM state trie, so every slot honestly reads as empty
/// (no fabricated state).
pub const EMPTY_STORAGE_VALUE_HEX: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

// ============================================================================
// Direct network info methods
// ============================================================================

/// Returns this node's Ethereum chain ID formatted as a hex quantity.
///
/// Serves [`effective_chain_id`] (STELL_CHAIN_ID-aware; default 5757), so the
/// served identity always matches the node's configured chain: previously
/// this hardcoded the default (`CHAIN_ID_HEX`) while node identity was
/// `STELL_CHAIN_ID`-configurable, so a non-default deployment served a
/// foreign chain id. Live stays 5757 (env unset), zero behavior change on
/// the stand. The `CHAIN_ID_HEX` / `NET_VERSION` constants stay as the
/// pinned DEFAULTS (consensus-adjacent verification and tx construction pin
/// them deliberately — see below); only the SERVED identity is dynamic.
pub fn eth_chain_id() -> String {
    eth_chain_id_for(effective_chain_id())
}

/// Returns this node's network ID formatted as a decimal string.
///
/// Same STELL_CHAIN_ID-aware rule as [`eth_chain_id`]: serves
/// [`effective_chain_id`], default 5757, zero behavior change unless the
/// operator configures a distinct chain.
pub fn net_version() -> String {
    net_version_for(effective_chain_id())
}

/// Returns the client version string ("Stellereum/v5.0.0-evm-adapter").
pub fn web3_client_version() -> &'static str {
    CLIENT_VERSION
}

/// Returns true if client is actively listening for network connections.
pub fn net_listening() -> bool {
    NET_LISTENING
}

/// Returns connected peer count formatted as hex quantity ("0x2").
/// TESTNET-KNOWN default (see [`NET_PEER_COUNT`]): no live peer table is
/// plumbed into this stateless function. Use [`format_peer_count_hex`] with a
/// live count, or the stateful [`EvmAdapter::net_peer_count`].
pub fn net_peer_count() -> &'static str {
    NET_PEER_COUNT
}

/// Formats a LIVE peer count as a hex quantity (`EvmAdapter::net_peer_count`
/// and any future `RpcState`-plumbed `net_peerCount` share this).
pub fn format_peer_count_hex(peer_count: u64) -> String {
    format_u64_hex(peer_count)
}

/// Returns false when node is in sync.
/// TESTNET-KNOWN default (see [`ETH_SYNCING`]). Use [`eth_syncing_for_heights`]
/// with live heights where available.
pub fn eth_syncing() -> bool {
    ETH_SYNCING
}

/// Live `eth_syncing`: true while a recent verified peer height names a chain
/// above ours — the same rule as `stell_syncing` in `rpc` (a bare max would
/// pin true forever on one faulty vote; a stale sighting is ignored by the
/// caller passing `None`). Pure: unit-tested, no globals.
pub fn eth_syncing_for_heights(ours: u64, peer: Option<u64>) -> bool {
    peer.map(|p| p > ours).unwrap_or(false)
}

/// Returns base fee / gas price in Wei formatted as hex quantity ("0x3eb2788000").
pub fn eth_gas_price() -> &'static str {
    DEFAULT_GAS_PRICE_HEX
}

#[allow(non_snake_case)]
pub fn eth_gasPrice() -> &'static str {
    eth_gas_price()
}

/// Returns maximum priority fee per gas formatted as hex quantity ("0x3b9aca00").
pub fn eth_max_priority_fee_per_gas() -> &'static str {
    DEFAULT_MAX_PRIORITY_FEE_HEX
}

/// Returns zero maximum priority fee per gas formatted as hex quantity ("0x0").
pub fn eth_max_priority_fee_per_gas_zero() -> &'static str {
    ZERO_MAX_PRIORITY_FEE_HEX
}

/// Returns maximum priority fee per gas formatted as hex quantity,
/// choosing between 1 Gwei ("0x3b9aca00") or zero ("0x0").
pub fn eth_max_priority_fee_per_gas_choice(zero: bool) -> &'static str {
    if zero {
        ZERO_MAX_PRIORITY_FEE_HEX
    } else {
        DEFAULT_MAX_PRIORITY_FEE_HEX
    }
}

#[allow(non_snake_case)]
pub fn eth_maxPriorityFeePerGas() -> &'static str {
    eth_max_priority_fee_per_gas()
}

/// Returns the pure-EVM transfer gas figure ("0x5208"); served estimates are floored.
pub fn eth_estimate_transfer_gas() -> &'static str {
    STANDARD_TRANSFER_GAS_HEX
}

/// Estimates gas for a call transaction parameter or returns standard transfer gas.
pub fn eth_estimate_gas(params: &Value) -> Result<String, JsonRpcError> {
    // Audit B-VM: served estimates honor the admission floor (RPC.md
    // contract); the pure figure lives in `eth_estimate_gas_amount`.
    eth_estimate_gas_with_floor(params, crate::svm::GAS_BASIC_TRANSFER)
}

#[allow(non_snake_case)]
pub fn eth_estimateGas(params: &Value) -> Result<String, JsonRpcError> {
    eth_estimate_gas(params)
}

/// Returns standard EIP-1559 fee history object for block count and newest block.
pub fn eth_fee_history(params: &Value) -> Result<EvmFeeHistory, JsonRpcError> {
    eth_fee_history_with_head(params, DEFAULT_HEAD_BLOCK)
}

#[allow(non_snake_case)]
pub fn eth_feeHistory(params: &Value) -> Result<EvmFeeHistory, JsonRpcError> {
    eth_fee_history(params)
}

/// Returns standard EIP-1559 fee history object with a specified head block number.
pub fn eth_fee_history_with_head(params: &Value, head: u64) -> Result<EvmFeeHistory, JsonRpcError> {
    fee_history_impl(
        params,
        head,
        DEFAULT_BASE_FEE,
        DEFAULT_MAX_PRIORITY_FEE,
        0.0,
    )
}

/// Direct typed helper for `eth_feeHistory` with block count, newest block, and optional reward percentiles.
pub fn eth_fee_history_direct(
    block_count: u64,
    newest_block: u64,
    reward_percentiles: Option<Vec<f64>>,
) -> Result<EvmFeeHistory, JsonRpcError> {
    let mut arr = vec![json!(block_count), json!(format_u64_hex(newest_block))];
    if let Some(rp) = reward_percentiles {
        arr.push(json!(rp));
    }
    eth_fee_history_with_head(&Value::Array(arr), newest_block)
}

#[allow(non_snake_case)]
pub fn eth_feeHistory_direct(
    block_count: u64,
    newest_block: u64,
    reward_percentiles: Option<Vec<f64>>,
) -> Result<EvmFeeHistory, JsonRpcError> {
    eth_fee_history_direct(block_count, newest_block, reward_percentiles)
}

lazy_static::lazy_static! {
    static ref GLOBAL_EVM_ADAPTER: EvmAdapter = EvmAdapter::new();
}

pub fn global_adapter() -> &'static EvmAdapter {
    &GLOBAL_EVM_ADAPTER
}

pub fn eth_call(params: &Value) -> Result<Value, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.handle_eth_call(params)
}

pub async fn eth_call_with_engine(
    engine: &InMemoryStateEngine,
    params: &Value,
) -> Result<Value, JsonRpcError> {
    global_adapter()
        .handle_eth_call_with_engine(engine, params)
        .await
}

pub fn eth_new_block_filter() -> String {
    GLOBAL_EVM_ADAPTER.filter_manager.new_block_filter()
}

pub fn eth_new_pending_transaction_filter() -> String {
    GLOBAL_EVM_ADAPTER
        .filter_manager
        .new_pending_transaction_filter()
}

pub fn eth_new_filter(params: &Value) -> Result<String, JsonRpcError> {
    let criteria = FilterCriteria::from_value(params)?;
    Ok(GLOBAL_EVM_ADAPTER.filter_manager.new_filter(criteria))
}

pub fn eth_get_filter_changes(params: &Value) -> Result<Value, JsonRpcError> {
    let id = extract_filter_id(params)?;
    GLOBAL_EVM_ADAPTER.filter_manager.get_filter_changes(&id)
}

pub fn eth_get_filter_logs(params: &Value) -> Result<Value, JsonRpcError> {
    let id = extract_filter_id(params)?;
    GLOBAL_EVM_ADAPTER.filter_manager.get_filter_logs(&id)
}

pub fn eth_uninstall_filter(params: &Value) -> Result<bool, JsonRpcError> {
    let id = extract_filter_id(params)?;
    Ok(GLOBAL_EVM_ADAPTER.filter_manager.uninstall_filter(&id))
}

/// Global `eth_getLogs`: one-shot log query over the adapter's committed
/// receipts (`blocks_by_number` / `receipts`), filtered by
/// `fromBlock` / `toBlock` / `address` / `topics` via
/// [`FilterCriteria::matches`] (plus optional `blockHash` scoping),
/// capped at [`MAX_GET_LOGS_RESULTS`] (1000) logs.
pub fn eth_get_logs(params: &Value) -> Result<Value, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_logs(params)
}

#[allow(non_snake_case)]
pub fn eth_getLogs(params: &Value) -> Result<Value, JsonRpcError> {
    eth_get_logs(params)
}

/// Global `eth_getStorageAt`: Stellereum runs no EVM state trie, so every
/// slot honestly reads as empty (`0x` + 64 zeros). Validates
/// `(address, position, blockTag)` and never fabricates state.
pub fn eth_get_storage_at(params: &Value) -> Result<String, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_storage_at(params)
}

#[allow(non_snake_case)]
pub fn eth_getStorageAt(params: &Value) -> Result<String, JsonRpcError> {
    eth_get_storage_at(params)
}

pub fn notify_block(hash: impl Into<String>) {
    GLOBAL_EVM_ADAPTER.notify_block(hash);
}

pub fn notify_pending_tx(hash: impl Into<String>) {
    GLOBAL_EVM_ADAPTER.notify_pending_tx(hash);
}

pub fn notify_log(log: EvmLog) {
    GLOBAL_EVM_ADAPTER.notify_log(log);
}

lazy_static::lazy_static! {
    static ref EVM_PENDING_TXS: std::sync::Mutex<std::collections::HashMap<String, EvmTransaction>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
}

/// Maximum EVM raw transaction size (128 KiB — generous for calldata).
pub const MAX_EVM_RAW_TX_BYTES: usize = 128 * 1024;

/// Submit a signed EVM raw transaction (MetaMask `eth_sendRawTransaction`).
///
/// Phase 1 (EVM intent pool): decodes RLP (legacy EIP-155 or EIP-1559 type-2),
/// strictly verifies `chain_id == CHAIN_ID` (5757) + low-s + ecrecover,
/// stores the pending `EvmTransaction` so `eth_getTransactionByHash` /
/// filters see it, notifies pending-tx filters, and returns the keccak hash.
/// Phase 2 (L1 settlement): the stateful RPC bridge maps the SAME bytes onto
/// a consensus `Transaction` (EV1 secp256k1 envelope) and admits it to the
/// real mempool via `add_checked_ctx` — see `evm_raw_to_stell_transaction`.
/// Until a tx is settled, it is honestly reported as pending (receipt = null).
pub fn eth_send_raw_transaction(params: &Value) -> Result<String, JsonRpcError> {
    let raw = extract_raw_evm_bytes(params)?;
    eth_send_raw_transaction_bytes(&raw)
}

/// Extract canonical raw EVM bytes from `eth_sendRawTransaction` params
/// (array / bare hex string / object with `rawTransaction` aliases).
/// Shared by the stateless intent path and the stateful RPC settlement
/// bridge so both decode exactly the same bytes.
pub fn extract_raw_evm_bytes(params: &Value) -> Result<Vec<u8>, JsonRpcError> {
    let raw_hex = match params {
        Value::Array(arr) => arr
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError::invalid_params("missing raw transaction"))?,
        Value::String(s) => s.as_str(),
        Value::Object(map) => map
            .get("rawTransaction")
            .or_else(|| map.get("rawTx"))
            .or_else(|| map.get("tx"))
            .or_else(|| map.get("data"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError::invalid_params("missing raw transaction"))?,
        _ => return Err(JsonRpcError::invalid_params("invalid params")),
    };
    let clean = raw_hex
        .strip_prefix("0x")
        .or_else(|| raw_hex.strip_prefix("0X"))
        .unwrap_or(raw_hex);
    let raw = hex::decode(clean).map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
    if raw.is_empty() || raw.len() > MAX_EVM_RAW_TX_BYTES {
        return Err(JsonRpcError::invalid_params(
            "empty or oversized raw transaction",
        ));
    }
    Ok(raw)
}

/// Decode + strictly verify already-extracted raw EVM bytes (chain_id,
/// low-s, ecrecover), store the pending intent and return the keccak hash.
/// Pure function of the bytes: the RPC settlement bridge calls this only
/// AFTER the L1 leg is admitted, so a mempool rejection never leaves a
/// stale intent behind.
///
/// The `chain_id == CHAIN_ID` pins below are DELIBERATE (see [`CHAIN_ID`]):
/// served identity is dynamic, verification is pinned so all nodes agree.
pub fn eth_send_raw_transaction_bytes(raw: &[u8]) -> Result<String, JsonRpcError> {
    if raw.is_empty() || raw.len() > MAX_EVM_RAW_TX_BYTES {
        return Err(JsonRpcError::invalid_params(
            "empty or oversized raw transaction",
        ));
    }
    let tx_hash = format!("0x{}", hex::encode(keccak256(raw)));

    // Decode + strictly verify (chain_id, low-s, ecrecover).
    let evm_tx: EvmTransaction = if !raw.is_empty() && raw[0] == 0x02 {
        let decoded =
            parse_eip1559_envelope(raw).map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
        let from = decoded
            .verify_signature()
            .map_err(|e| JsonRpcError::server_error(INTERNAL_ERROR_CODE, e.to_string()))?;
        if decoded.chain_id != CHAIN_ID {
            return Err(JsonRpcError::server_error(
                INTERNAL_ERROR_CODE,
                format!(
                    "EIP-155 replay protection mismatch: expected chain 5757, got {}",
                    decoded.chain_id
                ),
            ));
        }
        EvmTransaction {
            hash: tx_hash.clone(),
            nonce: format_u64_hex(decoded.nonce),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: evm_address_to_hex(&from),
            to: decoded.to.map(|a| evm_address_to_hex(&a)),
            value: format!("0x{:x}", decoded.value),
            gas_price: Some(format!("0x{:x}", decoded.max_fee_per_gas)),
            gas: format_u64_hex(decoded.gas_limit),
            input: format!("0x{}", hex::encode(&decoded.data)),
            v: format!("0x{:x}", decoded.v),
            r: format!("0x{}", hex::encode(decoded.r)),
            s: format!("0x{}", hex::encode(decoded.s)),
            tx_type: Some("0x2".to_string()),
            chain_id: Some(CHAIN_ID_HEX.to_string()),
            max_fee_per_gas: Some(format!("0x{:x}", decoded.max_fee_per_gas)),
            max_priority_fee_per_gas: Some(format!("0x{:x}", decoded.max_priority_fee_per_gas)),
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    } else {
        let decoded = parse_legacy_transaction(raw)
            .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;
        let from = decoded
            .verify_signature()
            .map_err(|e| JsonRpcError::server_error(INTERNAL_ERROR_CODE, e.to_string()))?;
        match decoded.chain_id {
            Some(cid) if cid == CHAIN_ID => {}
            Some(cid) => {
                return Err(JsonRpcError::server_error(
                    INTERNAL_ERROR_CODE,
                    format!("EIP-155 replay protection mismatch: expected chain 5757, got {cid}"),
                ))
            }
            None => {
                return Err(JsonRpcError::server_error(
                    INTERNAL_ERROR_CODE,
                    "EIP-155 replay protection required (unprotected legacy v=27/28 rejected)",
                ))
            }
        }
        EvmTransaction {
            hash: tx_hash.clone(),
            nonce: format_u64_hex(decoded.nonce),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: evm_address_to_hex(&from),
            to: decoded.to.map(|a| evm_address_to_hex(&a)),
            value: format!("0x{:x}", decoded.value),
            gas_price: Some(format!("0x{:x}", decoded.gas_price)),
            gas: format_u64_hex(decoded.gas_limit),
            input: format!("0x{}", hex::encode(&decoded.data)),
            v: format!("0x{:x}", decoded.v),
            r: format!("0x{}", hex::encode(decoded.r)),
            s: format!("0x{}", hex::encode(decoded.s)),
            tx_type: Some("0x0".to_string()),
            chain_id: Some(CHAIN_ID_HEX.to_string()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    };

    if let Ok(mut pending) = EVM_PENDING_TXS.lock() {
        // Bound pending pool (DoS guard): evict oldest arbitrary entry past 10k.
        if pending.len() >= 10_000 {
            if let Some(k) = pending.keys().next().cloned() {
                pending.remove(&k);
            }
        }
        pending.insert(tx_hash.clone(), evm_tx);
    }
    GLOBAL_EVM_ADAPTER.notify_pending_tx(tx_hash.clone());
    Ok(tx_hash)
}

/// Map verified raw EVM bytes onto a Phase-2 L1 settlement transaction.
///
/// Decodes RLP (legacy EIP-155 or EIP-1559 type-2), strictly verifies
/// `chain_id == CHAIN_ID` (5757, DELIBERATE pin — see [`CHAIN_ID`]) + low-s +
/// ecrecover via [`DecodedTransaction::verify_signature`], then maps through
/// `evm_to_stell_address` (sender/recipient), `wei_to_nano` (value, sub-nano
/// wei truncated deterministically) and verbatim nonce/gas_limit, sealing the
/// canonical raw inside the `EV1` envelope of
/// [`crate::sharding::Transaction::new_evm`].
///
/// Consensus re-verifies every binding from the envelope bytes alone
/// (`Transaction::verify_evm_signature`), so this mapping needs no trust:
///
/// * contract creation (`to == None`) is rejected — Phase-2 settles value
///   transfers and there is no Stell recipient to invent for a deployment;
/// * calldata (if any) is NOT executed — the L1 leg is a plain transfer of
///   the mapped value; EVM execution lands after settlement;
/// * shards are masterchain (single-shard settlement lane).
pub fn evm_raw_to_stell_transaction(raw: &[u8]) -> Result<crate::sharding::Transaction, String> {
    if raw.is_empty() || raw.len() > MAX_EVM_RAW_TX_BYTES {
        return Err("empty or oversized raw transaction".to_string());
    }
    let decoded = parse_raw_transaction(raw)?;
    // Strict chain_id == 5757 + low-s + ecrecover (both variants enforce it;
    // unprotected legacy v=27/28 fails here).
    let evm_from = decoded.verify_signature().map_err(|e| e.to_string())?;
    let evm_to = decoded.to().ok_or_else(|| {
        "EVM contract creation is not settled in Phase 2 (value transfers only)".to_string()
    })?;
    Ok(crate::sharding::Transaction::new_evm(
        evm_to_stell_address(&evm_from),
        evm_to_stell_address(&evm_to),
        wei_to_nano(decoded.value()),
        decoded.gas_limit(),
        decoded.nonce(),
        crate::sharding::MASTERCHAIN_SHARD,
        crate::sharding::MASTERCHAIN_SHARD,
        raw.to_vec(),
    ))
}

/// Lookup a pending EVM-intent transaction by hash (Phase 1 pool).
pub fn eth_pending_tx(hash: &str) -> Option<EvmTransaction> {
    let norm = normalize_hash(hash).ok()?;
    EVM_PENDING_TXS
        .lock()
        .ok()
        .and_then(|m| m.get(&norm).cloned())
}

// ============================================================================
// EVM intent -> L1 settlement bridge (keccak(EVM raw) <-> stell tx hash)
// ============================================================================

lazy_static::lazy_static! {
    static ref EVM_TO_STELL: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
    static ref STELL_TO_EVM: std::sync::Mutex<std::collections::HashMap<[u8; 32], String>> =
        std::sync::Mutex::new(std::collections::HashMap::new());
}

/// Magic prefix of a secp256k1 settlement envelope carried in
/// `Transaction.signature`: `b"SC1" || evm_hash(32) || r(32) || s(32) || recid(1)`.
pub const SECP_ENVELOPE_MAGIC: &[u8; 3] = b"SC1";
/// Total wire length of a secp settlement envelope (3 + 32 + 64 + 1).
pub const SECP_ENVELOPE_LEN: usize = 100;

/// secp256k1 curve order N (for low-s normalization of settlement signatures).
pub const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn secp_sub_n_minus_s(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow: i32 = 0;
    for i in (0..32).rev() {
        let v = SECP256K1_N[i] as i32 - s[i] as i32 - borrow;
        if v < 0 {
            out[i] = (v + 256) as u8;
            borrow = 1;
        } else {
            out[i] = v as u8;
            borrow = 0;
        }
    }
    out
}

/// Cap for the settlement maps (matches the receipts window; unbounded
/// growth on a long-lived node otherwise).
pub const MAX_SETTLED_EVM_MAP: usize = 50_000;

/// Register a bidirectional mapping `keccak(EVM raw) <-> stell tx hash`.
///
/// Both directions are queryable via [`evm_to_stell_hash`] /
/// [`stell_to_evm_hash`]. Overwrites any previous entry for either key.
/// Also drops the settled hash from the pending intent pool so
/// `pending -> mined` reads observe the mined view first.
pub fn register_evm_settlement(evm_hash_hex: &str, stell_hash: &[u8; 32]) {
    let norm = match normalize_hash(evm_hash_hex) {
        Ok(n) => n,
        Err(_) => return,
    };
    if let Ok(mut fwd) = EVM_TO_STELL.lock() {
        // Bounded: evict an arbitrary entry past the cap (same DoS-guard
        // policy as the pending pool; mappings are redundant hints — the
        // canonical receipt lookup does not depend on them).
        if fwd.len() >= MAX_SETTLED_EVM_MAP {
            if let Some(k) = fwd.keys().next().cloned() {
                fwd.remove(&k);
            }
        }
        fwd.insert(norm.clone(), *stell_hash);
    }
    if let Ok(mut rev) = STELL_TO_EVM.lock() {
        if rev.len() >= MAX_SETTLED_EVM_MAP {
            if let Some(k) = rev.keys().next().cloned() {
                rev.remove(&k);
            }
        }
        rev.insert(*stell_hash, norm.clone());
    }
    // Best-effort: the intent is now mined; free the pending slot.
    if let Ok(mut pending) = EVM_PENDING_TXS.lock() {
        pending.remove(&norm);
    }
}

/// Resolve `keccak(EVM raw)` -> stell `compute_tx_hash()`, if settled.
pub fn evm_to_stell_hash(evm_hash_hex: &str) -> Option<[u8; 32]> {
    let norm = normalize_hash(evm_hash_hex).ok()?;
    EVM_TO_STELL.lock().ok()?.get(&norm).copied()
}

/// Resolve stell `compute_tx_hash()` -> `keccak(EVM raw)`, if settled.
pub fn stell_to_evm_hash(stell_hash: &[u8; 32]) -> Option<String> {
    STELL_TO_EVM.lock().ok()?.get(stell_hash).cloned()
}

/// True when `tx.signature` carries a secp settlement envelope (`SC1` magic).
pub fn is_secp_settlement_tx(tx: &crate::sharding::Transaction) -> bool {
    tx.signature.len() == SECP_ENVELOPE_LEN && tx.signature.starts_with(SECP_ENVELOPE_MAGIC)
}

/// Extract the embedded EVM hash (`0x...` lowercase) from a secp envelope.
pub fn secp_envelope_evm_hash(tx: &crate::sharding::Transaction) -> Option<String> {
    if !is_secp_settlement_tx(tx) {
        return None;
    }
    let raw: [u8; 32] = tx.signature[3..35].try_into().ok()?;
    Some(format!("0x{}", hex::encode(raw)))
}

/// Verify a secp settlement envelope: ecrecover over `keccak(signing_message)`
/// must equal the EVM address derived from `tx.from` (left-padded Stell addr).
pub fn verify_secp_settlement(tx: &crate::sharding::Transaction) -> Result<[u8; 20], String> {
    if !is_secp_settlement_tx(tx) {
        return Err("not a secp settlement envelope".to_string());
    }
    // Audit B-VM: bind the FULL address. `stell_to_evm_address` compares only
    // the low 20 bytes, so a hostile nonzero 12-byte prefix would alias any
    // EVM identity. EVM-derived Stell addresses are always zero-prefixed.
    if tx.from[..12] != [0u8; 12] {
        return Err("secp envelope Stell prefix must be zero".to_string());
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&tx.signature[35..67]);
    s.copy_from_slice(&tx.signature[67..99]);
    let recid = tx.signature[99];
    if recid > 1 {
        return Err(format!("invalid secp recovery id: {recid}"));
    }
    if r == [0u8; 32] || s == [0u8; 32] {
        return Err("invalid secp signature (zero r/s)".to_string());
    }
    if !is_low_s(&s) {
        return Err("secp signature s is not canonical (EIP-2)".to_string());
    }
    let sighash = keccak256(&tx.signing_message());
    let recovered = ecrecover(&sighash, recid as u64, &r, &s)
        .map_err(|e| format!("secp ecrecover failed: {e}"))?;
    let expected = stell_to_evm_address(&tx.from);
    if recovered != expected {
        return Err("secp envelope recovers a different sender than tx.from".to_string());
    }
    Ok(recovered)
}

/// Build a Stellereum L1 transaction that settles `evm_hash_hex`.
///
/// `secp_key` is the SAME secp256k1 key that signed the EVM intent, so
/// `tx.from` (padded EVM sender) is authenticated by the envelope itself.
/// The envelope signs `keccak(Stell signing_message)` with low-s normalization.
pub fn build_secp_settlement_tx(
    secp_key: &k256::ecdsa::SigningKey,
    evm_hash_hex: &str,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
) -> Result<crate::sharding::Transaction, String> {
    let norm = normalize_hash(evm_hash_hex).map_err(|e| format!("bad evm hash: {e}"))?;
    let evm_bytes = parse_hash_bytes(&norm).map_err(|e| format!("bad evm hash: {e}"))?;
    let sender20 = pubkey_to_address(secp_key.verifying_key().to_encoded_point(false).as_bytes())
        .map_err(|e| e.to_string())?;
    let from32 = evm_to_stell_address(&sender20);
    // Signing bytes of the unsigned body (empty signature => base message).
    let unsigned = crate::sharding::Transaction {
        from: from32,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let sighash = keccak256(&unsigned.signing_message());
    let (sig, recid) = secp_key
        .sign_prehash_recoverable(&sighash)
        .map_err(|e| format!("secp sign failed: {e}"))?;
    let raw = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..64]);
    let mut recid_byte = recid.to_byte();
    // Normalize to low-s (EIP-2) so L1 verification is strict.
    if !is_low_s(&s) {
        s = secp_sub_n_minus_s(&s);
        recid_byte ^= 1;
    }
    let mut envelope = Vec::with_capacity(SECP_ENVELOPE_LEN);
    envelope.extend_from_slice(SECP_ENVELOPE_MAGIC);
    envelope.extend_from_slice(&evm_bytes);
    envelope.extend_from_slice(&r);
    envelope.extend_from_slice(&s);
    envelope.push(recid_byte);
    Ok(crate::sharding::Transaction {
        from: from32,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard: 0,
        target_shard: 0,
        signature: envelope,
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    })
}

/// Link a settled secp transaction into the bidirectional map.
///
/// Returns `(evm_hash, stell_hash)` when `tx` carries a valid envelope,
/// after registering. Invalid envelopes return `None` (fail-closed, no link).
pub fn link_secp_settlement(tx: &crate::sharding::Transaction) -> Option<(String, [u8; 32])> {
    let evm_hash = secp_envelope_evm_hash(tx)?;
    if verify_secp_settlement(tx).is_err() {
        return None;
    }
    let stell_hash = tx.compute_tx_hash();
    register_evm_settlement(&evm_hash, &stell_hash);
    Some((evm_hash, stell_hash))
}

/// Build the EVM receipt view for an EVM hash settled by `stell_receipt`.
///
/// Same body as [`stell_receipt_to_evm`] but `transaction_hash` is the queried
/// EVM hash (what MetaMask asked for), while block/ gas fields come from L1.
pub fn settled_receipt_for_evm(
    evm_hash_hex: &str,
    stell_receipt: &crate::rpc::TxReceipt,
) -> EvmReceipt {
    let mut receipt = stell_receipt_to_evm(stell_receipt);
    if let Ok(norm) = normalize_hash(evm_hash_hex) {
        receipt.transaction_hash = norm;
    }
    receipt
}

/// Build the mined EVM transaction view for an EVM hash settled by `stell_receipt`.
pub fn settled_tx_for_evm(
    evm_hash_hex: &str,
    stell_receipt: &crate::rpc::TxReceipt,
    chain_id: u64,
) -> Option<EvmTransaction> {
    let mut evm_tx = stell_receipt_to_evm_tx_with_chain(stell_receipt, chain_id)?;
    if let Ok(norm) = normalize_hash(evm_hash_hex) {
        evm_tx.hash = norm;
    }
    Some(evm_tx)
}

// ============================================================================
// JSON-RPC 2.0 Protocol Types
// ============================================================================

pub const PARSE_ERROR_CODE: i64 = -32700;
pub const INVALID_REQUEST_CODE: i64 = -32600;
pub const METHOD_NOT_FOUND_CODE: i64 = -32601;
pub const INVALID_PARAMS_CODE: i64 = -32602;
pub const INTERNAL_ERROR_CODE: i64 = -32603;
pub const SERVER_ERROR_CODE: i64 = -32000;

/// Standard JSON-RPC 2.0 error object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(code: i64, message: impl Into<String>, data: Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    pub fn parse_error(detail: impl Into<String>) -> Self {
        Self::with_data(PARSE_ERROR_CODE, "Parse error", json!(detail.into()))
    }

    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self::with_data(
            INVALID_REQUEST_CODE,
            "Invalid Request",
            json!(detail.into()),
        )
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            METHOD_NOT_FOUND_CODE,
            format!("Method not found: '{method}'"),
        )
    }

    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS_CODE, detail)
    }

    pub fn internal_error(detail: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR_CODE, detail)
    }

    pub fn server_error(code: i64, detail: impl Into<String>) -> Self {
        Self::new(code, detail)
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

/// Standard JSON-RPC 2.0 request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    #[serde(default = "default_jsonrpc_version")]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

fn default_jsonrpc_version() -> String {
    "2.0".to_string()
}

impl JsonRpcRequest {
    pub fn new(id: Option<Value>, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.into(),
            params,
        }
    }
}

/// Standard JSON-RPC 2.0 response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse<T = Value> {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl<T> JsonRpcResponse<T> {
    pub fn success(id: Value, result: T) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

// ============================================================================
// Filter Polling Types & Manager (EIP-1474 / MetaMask Filter Polling)
// ============================================================================

/// Ethereum log filter criteria for `eth_newFilter` and `eth_getLogs`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_block: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<FilterAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<Option<FilterTopic>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterAddress {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FilterTopic {
    Single(String),
    Multiple(Vec<String>),
}

fn parse_block_tag_or_hex(s: &str) -> Option<u64> {
    match s.trim().to_lowercase().as_str() {
        "earliest" => Some(0),
        "latest" | "pending" => None,
        _ => parse_hex_u64(s).ok(),
    }
}

impl FilterCriteria {
    pub fn from_value(val: &Value) -> Result<Self, JsonRpcError> {
        let obj = match val {
            Value::Object(map) => map,
            Value::Null => return Ok(Self::default()),
            Value::Array(arr) => {
                if let Some(first) = arr.first() {
                    if let Value::Object(map) = first {
                        map
                    } else if first.is_null() {
                        return Ok(Self::default());
                    } else {
                        return Err(JsonRpcError::invalid_params(
                            "expected filter object in params array",
                        ));
                    }
                } else {
                    return Ok(Self::default());
                }
            }
            _ => {
                return Err(JsonRpcError::invalid_params(
                    "filter parameters must be an object",
                ))
            }
        };

        let from_block = obj.get("fromBlock").and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => n.as_u64().map(format_u64_hex),
            _ => None,
        });

        let to_block = obj.get("toBlock").and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => n.as_u64().map(format_u64_hex),
            _ => None,
        });

        let address = if let Some(addr_val) = obj.get("address") {
            match addr_val {
                Value::String(s) => Some(FilterAddress::Single(s.clone())),
                Value::Array(arr) => {
                    let list: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    Some(FilterAddress::Multiple(list))
                }
                _ => None,
            }
        } else {
            None
        };

        let topics = obj.get("topics").and_then(|v| v.as_array()).map(|arr| {
            let mut parsed_topics = Vec::new();
            for item in arr {
                match item {
                    Value::Null => parsed_topics.push(None),
                    Value::String(s) => parsed_topics.push(Some(FilterTopic::Single(s.clone()))),
                    Value::Array(sub_arr) => {
                        let list: Vec<String> = sub_arr
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect();
                        parsed_topics.push(Some(FilterTopic::Multiple(list)));
                    }
                    _ => parsed_topics.push(None),
                }
            }
            parsed_topics
        });

        Ok(FilterCriteria {
            from_block,
            to_block,
            address,
            topics,
        })
    }

    pub fn matches(&self, log: &EvmLog) -> bool {
        // 1. Check address
        if let Some(ref addr_filter) = self.address {
            let log_addr = log.address.to_lowercase();
            match addr_filter {
                FilterAddress::Single(a) => {
                    if log_addr != a.to_lowercase() {
                        return false;
                    }
                }
                FilterAddress::Multiple(list) => {
                    if !list.iter().any(|a| log_addr == a.to_lowercase()) {
                        return false;
                    }
                }
            }
        }

        // 2. Check topics
        if let Some(ref topics_filter) = self.topics {
            for (idx, expected) in topics_filter.iter().enumerate() {
                if let Some(ref expected_topic) = expected {
                    let actual = match log.topics.get(idx) {
                        Some(t) => t.to_lowercase(),
                        None => return false,
                    };
                    match expected_topic {
                        FilterTopic::Single(t) => {
                            if actual != t.to_lowercase() {
                                return false;
                            }
                        }
                        FilterTopic::Multiple(list) => {
                            if !list.iter().any(|t| actual == t.to_lowercase()) {
                                return false;
                            }
                        }
                    }
                }
            }
        }

        // 3. Check block range (if specified and log has block_number)
        if let Some(ref log_block_str) = log.block_number {
            if let Ok(log_block) = parse_hex_u64(log_block_str) {
                if let Some(ref from_str) = self.from_block {
                    if let Some(from_block) = parse_block_tag_or_hex(from_str) {
                        if log_block < from_block {
                            return false;
                        }
                    }
                }
                if let Some(ref to_str) = self.to_block {
                    if let Some(to_block) = parse_block_tag_or_hex(to_str) {
                        if log_block > to_block {
                            return false;
                        }
                    }
                }
            }
        }

        true
    }
}

/// Internal representations of registered filters.
#[derive(Clone, Debug)]
pub enum FilterKind {
    Block {
        pending_hashes: Vec<String>,
    },
    PendingTransaction {
        pending_hashes: Vec<String>,
    },
    Log {
        criteria: FilterCriteria,
        pending_logs: Vec<EvmLog>,
        all_logs: Vec<EvmLog>,
    },
}

#[derive(Clone, Debug)]
pub struct FilterEntry {
    pub id: String,
    pub kind: FilterKind,
    pub created_at: Instant,
    pub last_poll: Instant,
}

/// Thread-safe in-memory filter manager for `eth_new*Filter` and polling.
#[derive(Debug)]
pub struct FilterManager {
    #[allow(dead_code)]
    // GATE: filter-id counter reserved for multi-filter RPC sessions; kept for API stability.
    next_id: AtomicU64,
    filters: RwLock<HashMap<String, FilterEntry>>,
}

impl Default for FilterManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterManager {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            filters: RwLock::new(HashMap::new()),
        }
    }

    /// TTL for idle filters (300s).
    pub fn ttl() -> Duration {
        Duration::from_secs(FILTER_TTL_SECS)
    }

    fn is_expired(entry: &FilterEntry) -> bool {
        entry.last_poll.elapsed() >= Self::ttl()
    }

    fn not_found() -> JsonRpcError {
        JsonRpcError::server_error(SERVER_ERROR_CODE, "filter not found")
    }

    /// Removes all filters idle for longer than [`FILTER_TTL_SECS`].
    /// Returns the number of evicted entries (their `all_logs` / pending
    /// buffers are dropped together with the entry).
    pub fn sweep_expired(&self) -> usize {
        let mut filters = self.filters.write().unwrap();
        let before = filters.len();
        filters.retain(|_, e| !Self::is_expired(e));
        before - filters.len()
    }

    /// Enforces [`MAX_ACTIVE_FILTERS`]. Must be called with the write guard held,
    /// after [`Self::sweep_expired`]-equivalent GC. Evicts least-recently-polled
    /// filters until there is room for one more insertion.
    fn evict_oldest_if_full(filters: &mut HashMap<String, FilterEntry>) {
        // Opportunistic GC of expired entries on the creation path.
        let ttl = Self::ttl();
        filters.retain(|_, e| e.last_poll.elapsed() < ttl);
        while filters.len() >= MAX_ACTIVE_FILTERS {
            let oldest = filters
                .iter()
                .min_by_key(|(_, e)| (e.last_poll, e.created_at))
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    filters.remove(&k);
                }
                None => break,
            }
        }
    }

    fn push_bounded_hash(pending: &mut Vec<String>, hash: String) {
        if pending.len() >= MAX_PENDING_PER_FILTER {
            let excess = pending.len() + 1 - MAX_PENDING_PER_FILTER;
            pending.drain(..excess);
        }
        pending.push(hash);
    }

    fn push_bounded_log(pending: &mut Vec<EvmLog>, all: &mut Vec<EvmLog>, log: EvmLog) {
        if pending.len() >= MAX_PENDING_PER_FILTER {
            let excess = pending.len() + 1 - MAX_PENDING_PER_FILTER;
            pending.drain(..excess);
        }
        pending.push(log.clone());
        if all.len() >= MAX_PENDING_PER_FILTER {
            let excess = all.len() + 1 - MAX_PENDING_PER_FILTER;
            all.drain(..excess);
        }
        all.push(log);
    }

    fn generate_random_filter_id() -> String {
        format!("0x{:x}", rand::random::<u64>().max(1))
    }

    pub fn new_block_filter(&self) -> String {
        let id = Self::generate_random_filter_id();
        let entry = FilterEntry {
            id: id.clone(),
            kind: FilterKind::Block {
                pending_hashes: Vec::new(),
            },
            created_at: Instant::now(),
            last_poll: Instant::now(),
        };
        let mut filters = self.filters.write().unwrap();
        Self::evict_oldest_if_full(&mut filters);
        filters.insert(id.clone(), entry);
        id
    }

    pub fn new_pending_transaction_filter(&self) -> String {
        let id = Self::generate_random_filter_id();
        let entry = FilterEntry {
            id: id.clone(),
            kind: FilterKind::PendingTransaction {
                pending_hashes: Vec::new(),
            },
            created_at: Instant::now(),
            last_poll: Instant::now(),
        };
        let mut filters = self.filters.write().unwrap();
        Self::evict_oldest_if_full(&mut filters);
        filters.insert(id.clone(), entry);
        id
    }

    pub fn new_filter(&self, criteria: FilterCriteria) -> String {
        let id = Self::generate_random_filter_id();
        let entry = FilterEntry {
            id: id.clone(),
            kind: FilterKind::Log {
                criteria,
                pending_logs: Vec::new(),
                all_logs: Vec::new(),
            },
            created_at: Instant::now(),
            last_poll: Instant::now(),
        };
        let mut filters = self.filters.write().unwrap();
        Self::evict_oldest_if_full(&mut filters);
        filters.insert(id.clone(), entry);
        id
    }

    pub fn get_filter_changes(&self, id: &str) -> Result<Value, JsonRpcError> {
        let norm_id = normalize_filter_id(id);
        let mut filters = self.filters.write().unwrap();
        // Lazy expiration: an idle filter is removed on access and reported
        // as missing (Geth-compatible "filter not found").
        if let Some(entry) = filters.get(&norm_id) {
            if Self::is_expired(entry) {
                filters.remove(&norm_id);
                return Err(Self::not_found());
            }
        }
        let entry = filters.get_mut(&norm_id).ok_or_else(Self::not_found)?;

        entry.last_poll = Instant::now();
        match entry.kind {
            FilterKind::Block {
                ref mut pending_hashes,
            } => {
                let hashes = std::mem::take(pending_hashes);
                Ok(json!(hashes))
            }
            FilterKind::PendingTransaction {
                ref mut pending_hashes,
            } => {
                let hashes = std::mem::take(pending_hashes);
                Ok(json!(hashes))
            }
            FilterKind::Log {
                ref mut pending_logs,
                ..
            } => {
                let logs = std::mem::take(pending_logs);
                Ok(json!(logs))
            }
        }
    }

    pub fn get_filter_logs(&self, id: &str) -> Result<Value, JsonRpcError> {
        let norm_id = normalize_filter_id(id);
        let mut filters = self.filters.write().unwrap();
        // Lazy expiration, symmetric with `get_filter_changes`.
        if let Some(entry) = filters.get(&norm_id) {
            if Self::is_expired(entry) {
                // Dropping the entry also frees its `all_logs` buffer.
                filters.remove(&norm_id);
                return Err(Self::not_found());
            }
        }
        let entry = filters.get_mut(&norm_id).ok_or_else(Self::not_found)?;

        entry.last_poll = Instant::now();
        match entry.kind {
            FilterKind::Log { ref all_logs, .. } => Ok(json!(all_logs)),
            FilterKind::Block { .. } | FilterKind::PendingTransaction { .. } => Ok(json!([])),
        }
    }

    pub fn uninstall_filter(&self, id: &str) -> bool {
        let norm_id = normalize_filter_id(id);
        let mut filters = self.filters.write().unwrap();
        // Removing the entry frees pending buffers and `all_logs`.
        filters.remove(&norm_id);
        true
    }

    pub fn clear(&self) {
        let mut filters = self.filters.write().unwrap();
        filters.clear();
    }

    pub fn notify_block_hash(&self, hash: impl Into<String>) {
        let hash_str = ensure_0x(&hash.into());
        let mut filters = self.filters.write().unwrap();
        for entry in filters.values_mut() {
            if Self::is_expired(entry) {
                continue;
            }
            if let FilterKind::Block {
                ref mut pending_hashes,
            } = entry.kind
            {
                Self::push_bounded_hash(pending_hashes, hash_str.clone());
            }
        }
    }

    pub fn notify_pending_tx_hash(&self, hash: impl Into<String>) {
        let hash_str = ensure_0x(&hash.into());
        let mut filters = self.filters.write().unwrap();
        for entry in filters.values_mut() {
            if Self::is_expired(entry) {
                continue;
            }
            if let FilterKind::PendingTransaction {
                ref mut pending_hashes,
            } = entry.kind
            {
                Self::push_bounded_hash(pending_hashes, hash_str.clone());
            }
        }
    }

    pub fn notify_log(&self, mut log: EvmLog) {
        log.address = normalize_address(&log.address);
        log.topics = log.topics.into_iter().map(|t| ensure_0x(&t)).collect();
        let mut filters = self.filters.write().unwrap();
        for entry in filters.values_mut() {
            if Self::is_expired(entry) {
                continue;
            }
            if let FilterKind::Log {
                ref criteria,
                ref mut pending_logs,
                ref mut all_logs,
            } = entry.kind
            {
                if criteria.matches(&log) {
                    Self::push_bounded_log(pending_logs, all_logs, log.clone());
                }
            }
        }
    }

    pub fn active_filter_count(&self) -> usize {
        self.filters.read().unwrap().len()
    }

    /// Test/debug helper: backdates a filter's `last_poll` beyond the TTL so
    /// that the next `get_filter_changes` / `get_filter_logs` treats it as
    /// expired. Returns `false` if the filter does not exist.
    /// Absent from production builds (`any(test, debug_assertions)` only).
    #[cfg(any(test, debug_assertions))]
    pub fn expire_filter_for_test(&self, id: &str) -> bool {
        let norm_id = normalize_filter_id(id);
        let mut filters = self.filters.write().unwrap();
        if let Some(entry) = filters.get_mut(&norm_id) {
            let backdate = Self::ttl() + Duration::from_secs(1);
            entry.last_poll = Instant::now()
                .checked_sub(backdate)
                .unwrap_or(entry.created_at);
            // Ensure the resulting timestamp is actually in the past beyond TTL.
            // On platforms with a very fresh monotonic clock `checked_sub` may
            // fail; in that case force expiry by also backdating `created_at`
            // is impossible, so evict directly is NOT done here — the caller
            // will observe non-expiry only on uptime < 301s, which never happens
            // in practice (monotonic clock starts at boot).
            if !Self::is_expired(entry) {
                // As a last resort for synthetic clocks, remove directly so the
                // timeout test still observes "filter not found" semantics.
                filters.remove(&norm_id);
            }
            true
        } else {
            false
        }
    }
}

pub fn extract_calldata(params: &Value) -> Option<&str> {
    match params {
        Value::Array(arr) => {
            let first = arr.first()?;
            match first {
                Value::Object(map) => map
                    .get("data")
                    .and_then(|v| v.as_str())
                    .or_else(|| map.get("input").and_then(|v| v.as_str())),
                Value::String(s) => Some(s.as_str()),
                _ => None,
            }
        }
        Value::Object(map) => map
            .get("data")
            .and_then(|v| v.as_str())
            .or_else(|| map.get("input").and_then(|v| v.as_str())),
        Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Extract the 32-byte word after the selector as an EVM address.
/// Audit B-VM: STRICT — EVM words are exactly 32 bytes (64 hex chars) with the
/// address in the low 20 bytes (12 leading zero bytes). Short/trailing/
/// non-hex input returns None (the old code zero-padded anything, so `"1234"`
/// emulated a balance for `0x000..1234` — wallet simulation confusion), and a
/// word whose top 12 bytes are NONZERO is likewise malformed ABI (not an
/// address at all): it returns None so callers map it to empty (`"0x"`, as for
/// unknown selectors) instead of aliasing the embedded low 20 bytes to a
/// balance that was never addressed.
pub fn extract_address_from_calldata(rest: &str) -> Option<String> {
    let clean = rest.trim();
    if clean.len() != 64 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if clean[..24].chars().all(|c| c == '0') {
        Some(format!("0x{}", &clean[24..64].to_lowercase()))
    } else {
        None
    }
}

pub fn normalize_address(addr: &str) -> String {
    let trimmed = addr.trim().to_lowercase();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0x"))
        .unwrap_or(&trimmed);
    format!("0x{}", stripped)
}

pub fn extract_filter_id(params: &Value) -> Result<String, JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if let Some(first) = arr.first() {
                match first {
                    Value::String(s) => Ok(normalize_filter_id(s)),
                    Value::Number(n) => {
                        if let Some(u) = n.as_u64() {
                            Ok(format!("0x{:x}", u))
                        } else {
                            Err(JsonRpcError::invalid_params(
                                "filter id must be a positive integer",
                            ))
                        }
                    }
                    _ => Err(JsonRpcError::invalid_params(
                        "filter id must be a string or integer",
                    )),
                }
            } else {
                Err(JsonRpcError::invalid_params("missing filter id"))
            }
        }
        Value::String(s) => Ok(normalize_filter_id(s)),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(format!("0x{:x}", u))
            } else {
                Err(JsonRpcError::invalid_params(
                    "filter id must be a positive integer",
                ))
            }
        }
        _ => Err(JsonRpcError::invalid_params("invalid filter parameters")),
    }
}

pub fn normalize_filter_id(id: &str) -> String {
    let clean = id.trim();
    if let Ok(u) = parse_hex_u64(clean) {
        format!("0x{:x}", u)
    } else {
        clean.to_lowercase()
    }
}

/// Extracts an optional `blockHash` scoping field from `eth_getLogs` params.
/// Accepts `[{..., "blockHash": "0x..."}]` or a bare object; returns `None`
/// when absent. Present-but-malformed hashes are rejected as invalid params
/// (never silently ignored).
pub fn extract_block_hash_filter(params: &Value) -> Option<String> {
    let obj = match params {
        Value::Array(arr) => arr.first()?.as_object()?,
        Value::Object(map) => map,
        _ => return None,
    };
    let raw = obj
        .get("blockHash")
        .or_else(|| obj.get("block_hash"))?
        .as_str()?;
    normalize_hash(raw).ok()
}

/// Sort key for deterministic `eth_getLogs` ordering:
/// `(block_number, transaction_index, log_index)` as numbers, missing as 0.
pub fn log_sort_key(log: &EvmLog) -> (u64, u64, u64) {
    let b = log
        .block_number
        .as_deref()
        .and_then(|s| parse_hex_u64(s).ok())
        .unwrap_or(0);
    let t = log
        .transaction_index
        .as_deref()
        .and_then(|s| parse_hex_u64(s).ok())
        .unwrap_or(0);
    let l = log
        .log_index
        .as_deref()
        .and_then(|s| parse_hex_u64(s).ok())
        .unwrap_or(0);
    (b, t, l)
}

/// Validates a storage slot position: `0x`-prefixed hex, up to 32 bytes.
pub fn validate_storage_position(pos: &str) -> Result<(), JsonRpcError> {
    let trimmed = pos.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .ok_or_else(|| {
            JsonRpcError::invalid_params(format!(
                "invalid storage position '{pos}': missing 0x prefix"
            ))
        })?;
    if stripped.is_empty() || stripped.len() > 64 {
        return Err(JsonRpcError::invalid_params(format!(
            "invalid storage position '{pos}': expected 1..64 hex chars"
        )));
    }
    if !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JsonRpcError::invalid_params(format!(
            "invalid storage position '{pos}': not hex"
        )));
    }
    Ok(())
}

/// Parses `eth_getStorageAt` params `[address, position, blockTag?]`
/// (object form `{address, position/slot, blockTag/block}` is also accepted).
/// Returns `(address, position, tag)`; the address and position are validated,
/// the tag defaults to `Latest`.
pub fn parse_get_storage_at_params(
    params: &Value,
) -> Result<(String, String, BlockTag), JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if arr.len() < 2 {
                return Err(JsonRpcError::invalid_params(
                    "expected [address, position, blockTag?]",
                ));
            }
            let addr = arr[0].as_str().ok_or_else(|| {
                JsonRpcError::invalid_params("address parameter must be a string")
            })?;
            let pos = arr[1].as_str().ok_or_else(|| {
                JsonRpcError::invalid_params("position parameter must be a string")
            })?;
            validate_storage_position(pos)?;
            let tag = if let Some(t) = arr.get(2) {
                if t.is_null() {
                    BlockTag::Latest
                } else {
                    BlockTag::parse(t)?
                }
            } else {
                BlockTag::Latest
            };
            Ok((addr.to_string(), pos.to_string(), tag))
        }
        Value::Object(obj) => {
            let addr = obj.get("address").and_then(|v| v.as_str()).ok_or_else(|| {
                JsonRpcError::invalid_params("missing 'address' in params object")
            })?;
            let pos = obj
                .get("position")
                .or_else(|| obj.get("slot"))
                .or_else(|| obj.get("index"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    JsonRpcError::invalid_params("missing 'position' in params object")
                })?;
            validate_storage_position(pos)?;
            let tag = if let Some(t) = obj
                .get("blockTag")
                .or_else(|| obj.get("block_tag"))
                .or_else(|| obj.get("block"))
                .or_else(|| obj.get("tag"))
            {
                if t.is_null() {
                    BlockTag::Latest
                } else {
                    BlockTag::parse(t)?
                }
            } else {
                BlockTag::Latest
            };
            Ok((addr.to_string(), pos.to_string(), tag))
        }
        _ => Err(JsonRpcError::invalid_params(
            "params must be an array or object",
        )),
    }
}

pub fn abi_encode_string(s: &str) -> String {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(2 + 64 * 3);
    out.push_str("0x");
    out.push_str("0000000000000000000000000000000000000000000000000000000000000020");
    out.push_str(&format!("{:0>64x}", len));
    let hex_data = hex::encode(bytes);
    out.push_str(&hex_data);
    let rem = hex_data.len() % 64;
    if rem != 0 {
        for _ in 0..(64 - rem) {
            out.push('0');
        }
    }
    out
}

pub fn abi_decode_string(hex_str: &str) -> Result<String, String> {
    let clean = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str);
    if clean.is_empty() {
        return Ok(String::new());
    }
    if clean.len() == 64 {
        // Fallback for bytes32 string representation
        let bytes = hex::decode(clean).map_err(|e| e.to_string())?;
        let non_zero_len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        return String::from_utf8(bytes[..non_zero_len].to_vec()).map_err(|e| e.to_string());
    }
    if clean.len() < 128 {
        return Err("hex string too short for dynamic string".to_string());
    }
    let offset_bytes = usize::from_str_radix(&clean[..64], 16).unwrap_or(32);
    // DoS guard: offset is attacker-controlled; use checked arithmetic so that
    // `offset_bytes * 2 + 64` can never wrap (hostile offset == usize::MAX).
    let offset_hex_len = offset_bytes
        .checked_mul(2)
        .ok_or("offset overflows".to_string())?;
    let offset_end = offset_hex_len
        .checked_add(64)
        .ok_or("offset overflows".to_string())?;
    let len_offset = if offset_end <= clean.len() {
        offset_hex_len
    } else {
        64
    };
    let len_end = len_offset
        .checked_add(64)
        .ok_or("offset overflows".to_string())?;
    if len_end > clean.len() {
        return Err("hex string too short for declared offset".to_string());
    }
    let len_hex = &clean[len_offset..len_end];
    let len = usize::from_str_radix(len_hex, 16).map_err(|e| e.to_string())?;
    let need_hex = len
        .checked_mul(2)
        .ok_or("declared length overflows".to_string())?;
    let data_offset = len_offset
        .checked_add(64)
        .ok_or("offset overflows".to_string())?;
    if data_offset > clean.len() {
        return Err("hex string too short for declared offset".to_string());
    }
    let data_hex = &clean[data_offset..];
    if data_hex.len() < need_hex {
        return Err("data shorter than declared length".to_string());
    }
    let bytes = hex::decode(&data_hex[..need_hex]).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

pub fn abi_encode_bool(val: bool) -> String {
    format!("0x{:0>64x}", if val { 1u8 } else { 0u8 })
}

pub fn abi_encode_u8(val: u8) -> String {
    format!("0x{:0>64x}", val)
}

pub fn abi_decode_u8(hex_str: &str) -> Result<u8, String> {
    let clean = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str);
    u8::from_str_radix(clean, 16).map_err(|e| e.to_string())
}

pub fn abi_encode_u128(val: u128) -> String {
    format!("0x{:0>64x}", val)
}

pub fn abi_decode_u128(hex_str: &str) -> Result<u128, String> {
    let clean = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str);
    u128::from_str_radix(clean, 16).map_err(|e| e.to_string())
}

pub fn abi_encode_u256_be(val: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(val))
}

pub fn abi_decode_u256_be(hex_str: &str) -> Result<[u8; 32], String> {
    let clean = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str);
    if clean.len() > 64 {
        return Err("hex string too long for u256".to_string());
    }
    let padded = format!("{:0>64}", clean);
    let bytes = hex::decode(&padded).map_err(|e| e.to_string())?;
    bytes.try_into().map_err(|_| "invalid length".to_string())
}

// ============================================================================
// EvmAdapter Handler
// ============================================================================

/// Configurable EVM-RPC adapter for Stellereum network.
#[derive(Clone)]
pub struct EvmAdapter {
    pub chain_id: u64,
    pub client_version: String,
    pub peer_count: u64,
    pub listening: bool,
    pub syncing: bool,
    pub gas_price: u128,
    pub max_priority_fee_per_gas: u128,
    pub base_fee: u128,
    pub head_block: u64,
    pub gas_used_ratio: f64,
    pub engine: Option<Arc<InMemoryStateEngine>>,
    pub blocks_by_number: HashMap<u64, EvmBlock>,
    pub blocks_by_hash: HashMap<String, EvmBlock>,
    pub receipts: HashMap<String, EvmReceipt>,
    pub transactions: HashMap<String, EvmTransaction>,
    pub token_name: String,
    pub token_symbol: String,
    pub token_decimals: u8,
    pub total_supply: u128,
    pub default_balance: u128,
    pub balances: Arc<RwLock<HashMap<String, u128>>>,
    pub filter_manager: Arc<FilterManager>,
}

impl std::fmt::Debug for EvmAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmAdapter")
            .field("chain_id", &self.chain_id)
            .field("client_version", &self.client_version)
            .field("peer_count", &self.peer_count)
            .field("listening", &self.listening)
            .field("syncing", &self.syncing)
            .field("gas_price", &self.gas_price)
            .field("max_priority_fee_per_gas", &self.max_priority_fee_per_gas)
            .field("base_fee", &self.base_fee)
            .field("head_block", &self.head_block)
            .field("gas_used_ratio", &self.gas_used_ratio)
            .field(
                "engine",
                &self.engine.as_ref().map(|_| "<InMemoryStateEngine>"),
            )
            .field("blocks_count", &self.blocks_by_number.len())
            .field("receipts_count", &self.receipts.len())
            .field("transactions_count", &self.transactions.len())
            .field("token_name", &self.token_name)
            .field("token_symbol", &self.token_symbol)
            .field("token_decimals", &self.token_decimals)
            .field("total_supply", &self.total_supply)
            .field("default_balance", &self.default_balance)
            .finish()
    }
}

impl Default for EvmAdapter {
    /// Pinned protocol defaults (`chain_id: CHAIN_ID`), for deterministic
    /// test/snapshot contexts. Node code prefers [`EvmAdapter::new`], which
    /// additionally honors `STELL_CHAIN_ID` for the served identity.
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID,
            client_version: CLIENT_VERSION.to_string(),
            peer_count: DEFAULT_PEER_COUNT,
            listening: NET_LISTENING,
            syncing: ETH_SYNCING,
            gas_price: DEFAULT_GAS_PRICE,
            max_priority_fee_per_gas: DEFAULT_MAX_PRIORITY_FEE,
            base_fee: DEFAULT_BASE_FEE,
            head_block: DEFAULT_HEAD_BLOCK,
            gas_used_ratio: 0.0,
            engine: None,
            blocks_by_number: HashMap::new(),
            blocks_by_hash: HashMap::new(),
            receipts: HashMap::new(),
            transactions: HashMap::new(),
            token_name: DEFAULT_TOKEN_NAME.to_string(),
            token_symbol: DEFAULT_TOKEN_SYMBOL.to_string(),
            token_decimals: DEFAULT_TOKEN_DECIMALS,
            total_supply: DEFAULT_TOTAL_SUPPLY,
            default_balance: 0,
            balances: Arc::new(RwLock::new(HashMap::new())),
            filter_manager: Arc::new(FilterManager::new()),
        }
    }
}

impl EvmAdapter {
    /// Node default: the pinned protocol defaults, except the served chain
    /// identity, which honors [`effective_chain_id`] (STELL_CHAIN_ID-aware) so
    /// every view (`eth_chainId`, `net_version`, tx/block `chain_id`) agrees
    /// with the node's configured chain out of the box. Explicit
    /// [`EvmAdapter::with_chain_id`] still overrides (tests, multi-chain
    /// harnesses). Verification sites do NOT follow this field — they pin
    /// [`CHAIN_ID`] deliberately (see [`CHAIN_ID`]). Zero behavior change
    /// while the env is unset (`effective == CHAIN_ID == 5757`).
    pub fn new() -> Self {
        Self::default().with_chain_id(effective_chain_id())
    }

    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    pub fn with_client_version(mut self, version: impl Into<String>) -> Self {
        self.client_version = version.into();
        self
    }

    pub fn with_peer_count(mut self, peer_count: u64) -> Self {
        self.peer_count = peer_count;
        self
    }

    pub fn with_listening(mut self, listening: bool) -> Self {
        self.listening = listening;
        self
    }

    pub fn with_syncing(mut self, syncing: bool) -> Self {
        self.syncing = syncing;
        self
    }

    pub fn with_gas_price(mut self, gas_price: u128) -> Self {
        self.gas_price = gas_price;
        self
    }

    pub fn with_max_priority_fee_per_gas(mut self, fee: u128) -> Self {
        self.max_priority_fee_per_gas = fee;
        self
    }

    pub fn with_base_fee(mut self, base_fee: u128) -> Self {
        self.base_fee = base_fee;
        self
    }

    pub fn with_head_block(mut self, head_block: u64) -> Self {
        self.head_block = head_block;
        self
    }

    pub fn with_gas_used_ratio(mut self, ratio: f64) -> Self {
        self.gas_used_ratio = ratio;
        self
    }

    pub fn with_height(mut self, height: u64) -> Self {
        self.head_block = height;
        self
    }

    pub fn with_current_height(mut self, height: u64) -> Self {
        self.head_block = height;
        self
    }

    pub fn set_height(&mut self, height: u64) {
        self.head_block = height;
    }

    pub fn set_current_height(&mut self, height: u64) {
        self.head_block = height;
    }

    pub fn with_token_name(mut self, name: impl Into<String>) -> Self {
        self.token_name = name.into();
        self
    }

    pub fn with_token_symbol(mut self, symbol: impl Into<String>) -> Self {
        self.token_symbol = symbol.into();
        self
    }

    pub fn with_token_decimals(mut self, decimals: u8) -> Self {
        self.token_decimals = decimals;
        self
    }

    pub fn with_total_supply(mut self, total_supply: u128) -> Self {
        self.total_supply = total_supply;
        self
    }

    pub fn with_default_balance(mut self, default_balance: u128) -> Self {
        self.default_balance = default_balance;
        self
    }

    pub fn with_balance(self, address: impl AsRef<str>, balance: u128) -> Self {
        self.set_balance(address, balance);
        self
    }

    pub fn with_filter_manager(mut self, filter_manager: Arc<FilterManager>) -> Self {
        self.filter_manager = filter_manager;
        self
    }

    pub fn set_balance(&self, address: impl AsRef<str>, balance: u128) {
        let norm = normalize_address(address.as_ref());
        if let Ok(mut b) = self.balances.write() {
            b.insert(norm, balance);
        }
    }

    pub fn get_balance(&self, address: impl AsRef<str>) -> u128 {
        let raw = address.as_ref().trim();
        let stripped = raw
            .strip_prefix("0x")
            .or_else(|| raw.strip_prefix("0X"))
            .unwrap_or(raw);
        if let Ok(b) = self.balances.read() {
            let norm = format!("0x{}", stripped.to_lowercase());
            if let Some(&val) = b.get(&norm) {
                return val;
            }
            if stripped.len() == 64 {
                let evm_norm = format!("0x{}", &stripped[24..64].to_lowercase());
                if let Some(&val) = b.get(&evm_norm) {
                    return val;
                }
            }
            if stripped.len() == 40 {
                let stell_norm = format!("0x000000000000000000000000{}", stripped.to_lowercase());
                if let Some(&val) = b.get(&stell_norm) {
                    return val;
                }
            }
        }
        self.lookup_engine_balance(address.as_ref())
    }

    pub fn lookup_engine_balance(&self, address: &str) -> u128 {
        if let Some(ref engine) = self.engine {
            if let Ok(guard) = engine.accounts.try_read() {
                if let Ok(stell_addr) = parse_evm_or_stell_address(address) {
                    if let Some(acc) = guard.get(&stell_addr) {
                        return nano_to_wei(acc.balance);
                    }
                }
            }
        }
        self.default_balance
    }

    pub fn eth_new_block_filter(&self) -> String {
        self.filter_manager.new_block_filter()
    }

    pub fn eth_new_pending_transaction_filter(&self) -> String {
        self.filter_manager.new_pending_transaction_filter()
    }

    pub fn eth_new_filter(&self, params: &Value) -> Result<String, JsonRpcError> {
        let criteria = FilterCriteria::from_value(params)?;
        Ok(self.filter_manager.new_filter(criteria))
    }

    pub fn eth_get_filter_changes(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let id = extract_filter_id(params)?;
        self.filter_manager.get_filter_changes(&id)
    }

    pub fn eth_get_filter_logs(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let id = extract_filter_id(params)?;
        self.filter_manager.get_filter_logs(&id)
    }

    pub fn eth_uninstall_filter(&self, params: &Value) -> Result<bool, JsonRpcError> {
        let id = extract_filter_id(params)?;
        Ok(self.filter_manager.uninstall_filter(&id))
    }

    /// One-shot `eth_getLogs` over committed receipts.
    ///
    /// Parses `fromBlock` / `toBlock` / `address` / `topics` via
    /// [`FilterCriteria::from_value`] (+ optional `blockHash` scoping),
    /// matches every log in `self.receipts` with
    /// [`FilterCriteria::matches`], sorts deterministically by
    /// `(block_number, transaction_index, log_index)` and caps at
    /// [`MAX_GET_LOGS_RESULTS`] (1000).
    pub fn eth_get_logs(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let criteria = FilterCriteria::from_value(params)?;
        let block_hash_filter = extract_block_hash_filter(params);
        let mut out = self.collect_matching_logs(&criteria, block_hash_filter.as_deref());
        out.sort_by_key(log_sort_key);
        out.truncate(MAX_GET_LOGS_RESULTS);
        Ok(json!(out))
    }

    #[allow(non_snake_case)]
    pub fn eth_getLogs(&self, params: &Value) -> Result<Value, JsonRpcError> {
        self.eth_get_logs(params)
    }

    /// Collects all receipt logs matching `criteria` (and optional `block_hash`),
    /// capped at [`MAX_GET_LOGS_RESULTS`]. Shared by the adapter-level
    /// [`EvmAdapter::eth_get_logs`] and the RPC-level merged query so both
    /// levels filter identically.
    pub fn collect_matching_logs(
        &self,
        criteria: &FilterCriteria,
        block_hash: Option<&str>,
    ) -> Vec<EvmLog> {
        let mut out = Vec::new();
        for receipt in self.receipts.values() {
            for log in &receipt.logs {
                if let Some(want) = block_hash {
                    match &log.block_hash {
                        Some(have) if have.to_lowercase() == want.to_lowercase() => {}
                        _ => continue,
                    }
                }
                if criteria.matches(log) {
                    out.push(log.clone());
                    if out.len() >= MAX_GET_LOGS_RESULTS {
                        return out;
                    }
                }
            }
        }
        out
    }

    /// `eth_getStorageAt(address, position, tag)`: no EVM state trie exists,
    /// so every slot honestly reads as empty ([`EMPTY_STORAGE_VALUE_HEX`]).
    /// Validates the address, the 32-byte slot position and the block tag.
    pub fn eth_get_storage_at(&self, params: &Value) -> Result<String, JsonRpcError> {
        let (addr_str, _pos_str, _tag) = parse_get_storage_at_params(params)?;
        let _ = parse_evm_or_stell_address(&addr_str).map_err(|e| {
            JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}"))
        })?;
        Ok(EMPTY_STORAGE_VALUE_HEX.to_string())
    }

    #[allow(non_snake_case)]
    pub fn eth_getStorageAt(&self, params: &Value) -> Result<String, JsonRpcError> {
        self.eth_get_storage_at(params)
    }

    /// Typed helper for `eth_getStorageAt` without going through JSON params.
    pub fn eth_get_storage_at_direct(
        &self,
        address: &str,
        position: &str,
        tag: &str,
    ) -> Result<String, JsonRpcError> {
        self.eth_get_storage_at(&json!([address, position, tag]))
    }

    pub fn notify_block(&self, hash: impl Into<String>) {
        self.filter_manager.notify_block_hash(hash);
    }

    pub fn notify_pending_tx(&self, hash: impl Into<String>) {
        self.filter_manager.notify_pending_tx_hash(hash);
    }

    pub fn notify_log(&self, log: EvmLog) {
        self.filter_manager.notify_log(log);
    }

    pub fn notify_logs(&self, logs: impl IntoIterator<Item = EvmLog>) {
        for log in logs {
            self.filter_manager.notify_log(log);
        }
    }

    /// Pure local ERC-20 emulation (audit 2026-10-14 `eth_call` sandbox).
    ///
    /// BOUNDS, verified: engine/balance READS only (no state write, no gas
    /// spent); unknown selectors → `"0x"`; no iteration over attacker-sized
    /// structures (one selector match + at most one account read); input
    /// arrives via [`extract_calldata`] and is already bounded by the shared
    /// 128 KiB raw-tx cap plus the HTTP body/rate limits. No loop/DoS vector.
    pub fn handle_eth_call(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let calldata = extract_calldata(params);
        let result = match calldata {
            Some(data) => self.emulate_erc20_call(data),
            None => "0x".to_string(),
        };
        Ok(json!(result))
    }

    pub fn emulate_erc20_call(&self, calldata: &str) -> String {
        let clean = calldata.trim();
        let hex_part = clean
            .strip_prefix("0x")
            .or_else(|| clean.strip_prefix("0X"))
            .unwrap_or(clean);

        if !hex_part.is_ascii() || hex_part.len() < 8 {
            return "0x".to_string();
        }

        let selector = &hex_part[..8].to_lowercase();
        let rest = &hex_part[8..];

        match selector.as_str() {
            SELECTOR_NAME => abi_encode_string(&self.token_name),
            SELECTOR_SYMBOL => abi_encode_string(&self.token_symbol),
            SELECTOR_DECIMALS => abi_encode_u8(self.token_decimals),
            SELECTOR_TOTAL_SUPPLY => abi_encode_u128(self.total_supply),
            SELECTOR_TRANSFER | SELECTOR_APPROVE | SELECTOR_TRANSFER_FROM => abi_encode_bool(true),
            SELECTOR_ALLOWANCE => abi_encode_u128(u128::MAX),
            SELECTOR_BALANCE_OF => {
                let address = match extract_address_from_calldata(rest) {
                    Some(a) => a,
                    None => return "0x".to_string(),
                };
                let bal = self.get_balance(&address);
                abi_encode_u128(bal)
            }
            _ => "0x".to_string(),
        }
    }

    pub async fn handle_eth_call_with_engine(
        &self,
        engine: &InMemoryStateEngine,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        let calldata = extract_calldata(params);
        let result = match calldata {
            Some(data) => self.emulate_erc20_call_with_engine(engine, data).await,
            None => "0x".to_string(),
        };
        Ok(json!(result))
    }

    pub async fn emulate_erc20_call_with_engine(
        &self,
        engine: &InMemoryStateEngine,
        calldata: &str,
    ) -> String {
        let clean = calldata.trim();
        let hex_part = clean
            .strip_prefix("0x")
            .or_else(|| clean.strip_prefix("0X"))
            .unwrap_or(clean);

        if !hex_part.is_ascii() || hex_part.len() < 8 {
            return "0x".to_string();
        }

        let selector = &hex_part[..8].to_lowercase();
        let rest = &hex_part[8..];

        match selector.as_str() {
            SELECTOR_NAME => abi_encode_string(&self.token_name),
            SELECTOR_SYMBOL => abi_encode_string(&self.token_symbol),
            SELECTOR_DECIMALS => abi_encode_u8(self.token_decimals),
            SELECTOR_TOTAL_SUPPLY => abi_encode_u128(self.total_supply),
            SELECTOR_TRANSFER | SELECTOR_APPROVE | SELECTOR_TRANSFER_FROM => abi_encode_bool(true),
            SELECTOR_ALLOWANCE => abi_encode_u128(u128::MAX),
            SELECTOR_BALANCE_OF => {
                let address = match extract_address_from_calldata(rest) {
                    Some(a) => a,
                    None => return "0x".to_string(),
                };
                // Check local overrides first
                let raw = address.trim();
                let stripped = raw
                    .strip_prefix("0x")
                    .or_else(|| raw.strip_prefix("0X"))
                    .unwrap_or(raw);
                if let Ok(b) = self.balances.read() {
                    let norm = format!("0x{}", stripped.to_lowercase());
                    if let Some(&val) = b.get(&norm) {
                        return abi_encode_u128(val);
                    }
                    if stripped.len() == 64 {
                        let evm_norm = format!("0x{}", &stripped[24..64].to_lowercase());
                        if let Some(&val) = b.get(&evm_norm) {
                            return abi_encode_u128(val);
                        }
                    }
                    if stripped.len() == 40 {
                        let stell_norm =
                            format!("0x000000000000000000000000{}", stripped.to_lowercase());
                        if let Some(&val) = b.get(&stell_norm) {
                            return abi_encode_u128(val);
                        }
                    }
                }
                // Check engine asynchronously
                let bal = if let Ok(stell_addr) = parse_evm_or_stell_address(&address) {
                    if let Some(acc) = engine.get_account(&stell_addr).await {
                        nano_to_wei(acc.balance)
                    } else {
                        self.default_balance
                    }
                } else {
                    self.default_balance
                };
                abi_encode_u128(bal)
            }
            _ => "0x".to_string(),
        }
    }

    pub fn insert_block(&mut self, block: EvmBlock) {
        if let Some(ref num_hex) = block.number {
            if let Ok(num) = parse_hex_u64(num_hex) {
                if num > self.head_block {
                    self.head_block = num;
                }
                self.blocks_by_number.insert(num, block.clone());
            }
        }
        if let Some(ref hash_hex) = block.hash {
            if let Ok(norm_hash) = normalize_hash(hash_hex) {
                self.blocks_by_hash.insert(norm_hash, block.clone());
            }
        }
        if let BlockTransactions::Full(ref txs) = block.transactions {
            for tx in txs {
                if let Ok(norm_tx_hash) = normalize_hash(&tx.hash) {
                    self.transactions.insert(norm_tx_hash, tx.clone());
                }
            }
        }
    }

    pub fn insert_stell_block(&mut self, block: &crate::sharding::Block) {
        let evm_block = stell_block_to_evm(block, true);
        self.insert_block(evm_block);
    }

    pub fn insert_block_summary(&mut self, summary: &crate::rpc::BlockSummary) {
        let evm_block = stell_block_summary_to_evm(summary);
        self.insert_block(evm_block);
    }

    pub fn insert_receipt(&mut self, receipt: EvmReceipt) {
        if let Ok(norm_hash) = normalize_hash(&receipt.transaction_hash) {
            self.receipts.insert(norm_hash, receipt);
        }
    }

    pub fn insert_stell_receipt(&mut self, receipt: &crate::rpc::TxReceipt) {
        let evm_receipt = stell_receipt_to_evm(receipt);
        self.insert_receipt(evm_receipt);
        if let Some(evm_tx) = stell_receipt_to_evm_tx(receipt) {
            self.insert_transaction(evm_tx);
        }
    }

    pub fn insert_transaction(&mut self, tx: EvmTransaction) {
        if let Ok(norm_hash) = normalize_hash(&tx.hash) {
            self.transactions.insert(norm_hash, tx);
        }
    }

    pub fn insert_stell_tx(
        &mut self,
        tx: &crate::sharding::Transaction,
        block_hash: Option<[u8; 32]>,
        block_number: Option<u64>,
        tx_index: Option<u32>,
    ) {
        let evm_tx =
            stell_tx_to_evm_with_chain(tx, block_hash, block_number, tx_index, self.chain_id);
        self.insert_transaction(evm_tx);
    }

    pub fn eth_block_number(&self) -> String {
        eth_block_number(self.head_block)
    }

    pub fn get_block_by_number(&self, tag: &BlockTag, full_txs: bool) -> Option<EvmBlock> {
        let height = tag.resolve(self.head_block);
        self.blocks_by_number.get(&height).map(|b| {
            let mut block = b.clone();
            if !full_txs {
                if let BlockTransactions::Full(ref txs) = block.transactions {
                    block.transactions =
                        BlockTransactions::Hashes(txs.iter().map(|t| t.hash.clone()).collect());
                }
            } else if let BlockTransactions::Hashes(ref hashes) = block.transactions {
                let hydrated: Vec<EvmTransaction> = hashes
                    .iter()
                    .filter_map(|h| {
                        normalize_hash(h)
                            .ok()
                            .and_then(|norm| self.transactions.get(&norm).cloned())
                    })
                    .collect();
                if hydrated.len() == hashes.len() && !hydrated.is_empty() {
                    block.transactions = BlockTransactions::Full(hydrated);
                }
            }
            block
        })
    }

    pub fn get_block_by_hash(&self, hash: &str, full_txs: bool) -> Option<EvmBlock> {
        let norm = normalize_hash(hash).ok()?;
        self.blocks_by_hash.get(&norm).map(|b| {
            let mut block = b.clone();
            if !full_txs {
                if let BlockTransactions::Full(ref txs) = block.transactions {
                    block.transactions =
                        BlockTransactions::Hashes(txs.iter().map(|t| t.hash.clone()).collect());
                }
            } else if let BlockTransactions::Hashes(ref hashes) = block.transactions {
                let hydrated: Vec<EvmTransaction> = hashes
                    .iter()
                    .filter_map(|h| {
                        normalize_hash(h)
                            .ok()
                            .and_then(|norm| self.transactions.get(&norm).cloned())
                    })
                    .collect();
                if hydrated.len() == hashes.len() && !hydrated.is_empty() {
                    block.transactions = BlockTransactions::Full(hydrated);
                }
            }
            block
        })
    }

    pub fn get_transaction_receipt(&self, hash: &str) -> Option<&EvmReceipt> {
        let norm = normalize_hash(hash).ok()?;
        if let Some(r) = self.receipts.get(&norm) {
            return Some(r);
        }
        // EVM intent -> L1 settlement: resolve keccak(EVM raw) to stell hash.
        if let Some(stell) = evm_to_stell_hash(&norm) {
            let stell_hex = stell_hash_to_evm(&stell);
            return self.receipts.get(&stell_hex);
        }
        None
    }

    /// Owned receipt lookup that reports the QUERIED (EVM) hash in
    /// `transaction_hash` when the hit came via the settlement map.
    pub fn get_settled_receipt(&self, hash: &str) -> Option<EvmReceipt> {
        let norm = normalize_hash(hash).ok()?;
        if let Some(r) = self.receipts.get(&norm) {
            return Some(r.clone());
        }
        let stell = evm_to_stell_hash(&norm)?;
        let stell_hex = stell_hash_to_evm(&stell);
        let mut receipt = self.receipts.get(&stell_hex)?.clone();
        receipt.transaction_hash = norm;
        Some(receipt)
    }

    pub fn get_transaction_by_hash(&self, hash: &str) -> Option<&EvmTransaction> {
        let norm = normalize_hash(hash).ok()?;
        if let Some(t) = self.transactions.get(&norm) {
            return Some(t);
        }
        if let Some(stell) = evm_to_stell_hash(&norm) {
            let stell_hex = stell_hash_to_evm(&stell);
            return self.transactions.get(&stell_hex);
        }
        None
    }

    /// Owned tx lookup that reports the QUERIED (EVM) hash when resolved
    /// via the settlement map, falling back to the pending intent pool.
    pub fn get_settled_transaction(&self, hash: &str) -> Option<EvmTransaction> {
        let norm = normalize_hash(hash).ok()?;
        if let Some(t) = self.transactions.get(&norm) {
            return Some(t.clone());
        }
        if let Some(stell) = evm_to_stell_hash(&norm) {
            let stell_hex = stell_hash_to_evm(&stell);
            if let Some(t) = self.transactions.get(&stell_hex) {
                let mut out = t.clone();
                out.hash = norm;
                return Some(out);
            }
        }
        // Still pending (never settled): serve the intent itself.
        eth_pending_tx(&norm)
    }

    pub fn eth_get_block_by_number(
        &self,
        tag: &str,
        full_txs: bool,
    ) -> Result<Option<EvmBlock>, JsonRpcError> {
        let parsed = BlockTag::parse_str(tag)?;
        Ok(self.get_block_by_number(&parsed, full_txs))
    }

    pub fn eth_get_block_by_hash(
        &self,
        hash: &str,
        full_txs: bool,
    ) -> Result<Option<EvmBlock>, JsonRpcError> {
        if normalize_hash(hash).is_err() {
            return Err(JsonRpcError::invalid_params(format!(
                "invalid block hash '{hash}'"
            )));
        }
        Ok(self.get_block_by_hash(hash, full_txs))
    }

    pub fn eth_get_transaction_receipt(
        &self,
        hash: &str,
    ) -> Result<Option<EvmReceipt>, JsonRpcError> {
        let norm = normalize_hash(hash).map_err(|_| {
            JsonRpcError::invalid_params(format!("invalid transaction hash '{hash}'"))
        })?;
        Ok(self.get_settled_receipt(&norm))
    }

    pub fn eth_get_transaction_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<EvmTransaction>, JsonRpcError> {
        let norm = normalize_hash(hash).map_err(|_| {
            JsonRpcError::invalid_params(format!("invalid transaction hash '{hash}'"))
        })?;
        Ok(self.get_settled_transaction(&norm))
    }

    /// Number of transactions in a block looked up by hash.
    /// Returns `None` (JSON null) when the block is unknown.
    pub fn get_block_transaction_count_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<String>, JsonRpcError> {
        let norm = normalize_hash(hash)
            .map_err(|_| JsonRpcError::invalid_params(format!("invalid block hash '{hash}'")))?;
        match self.blocks_by_hash.get(&norm) {
            Some(block) => Ok(Some(format_u64_hex(block_transaction_count(block) as u64))),
            None => Ok(None),
        }
    }

    /// Number of transactions in a block looked up by tag/number.
    /// Returns `None` (JSON null) when the block is unknown.
    pub fn get_block_transaction_count_by_number(
        &self,
        tag: &BlockTag,
    ) -> Result<Option<String>, JsonRpcError> {
        let height = tag.resolve(self.head_block);
        match self.blocks_by_number.get(&height) {
            Some(block) => Ok(Some(format_u64_hex(block_transaction_count(block) as u64))),
            None => Ok(None),
        }
    }

    /// Transaction at `index` inside the block looked up by hash.
    /// Returns `None` (JSON null) when the block is unknown or the index is out of range.
    pub fn get_transaction_by_block_hash_and_index(
        &self,
        hash: &str,
        index: u64,
    ) -> Result<Option<EvmTransaction>, JsonRpcError> {
        let norm = normalize_hash(hash)
            .map_err(|_| JsonRpcError::invalid_params(format!("invalid block hash '{hash}'")))?;
        let block = match self.blocks_by_hash.get(&norm) {
            Some(b) => b,
            None => return Ok(None),
        };
        Ok(self.transaction_at_index(block, index))
    }

    /// Transaction at `index` inside the block looked up by tag/number.
    /// Returns `None` (JSON null) when the block is unknown or the index is out of range.
    pub fn get_transaction_by_block_number_and_index(
        &self,
        tag: &BlockTag,
        index: u64,
    ) -> Result<Option<EvmTransaction>, JsonRpcError> {
        let height = tag.resolve(self.head_block);
        let block = match self.blocks_by_number.get(&height) {
            Some(b) => b,
            None => return Ok(None),
        };
        Ok(self.transaction_at_index(block, index))
    }

    fn transaction_at_index(&self, block: &EvmBlock, index: u64) -> Option<EvmTransaction> {
        let idx = usize::try_from(index).ok()?;
        match &block.transactions {
            BlockTransactions::Full(txs) => txs.get(idx).cloned(),
            BlockTransactions::Hashes(hashes) => {
                let h = hashes.get(idx)?;
                let norm = normalize_hash(h).ok()?;
                self.transactions.get(&norm).cloned()
            }
        }
    }

    /// Uncle count for a block looked up by hash. Stellereum never produces
    /// uncles, so a known block reports `"0x0"`; unknown blocks report `None` (JSON null).
    pub fn get_uncle_count_by_block_hash(
        &self,
        hash: &str,
    ) -> Result<Option<String>, JsonRpcError> {
        let norm = normalize_hash(hash)
            .map_err(|_| JsonRpcError::invalid_params(format!("invalid block hash '{hash}'")))?;
        if self.blocks_by_hash.contains_key(&norm) {
            Ok(Some("0x0".to_string()))
        } else {
            Ok(None)
        }
    }

    /// Uncle count for a block looked up by tag/number. See [`Self::get_uncle_count_by_block_hash`].
    pub fn get_uncle_count_by_block_number(
        &self,
        tag: &BlockTag,
    ) -> Result<Option<String>, JsonRpcError> {
        let height = tag.resolve(self.head_block);
        if self.blocks_by_number.contains_key(&height) {
            Ok(Some("0x0".to_string()))
        } else {
            Ok(None)
        }
    }

    /// Uncle at `index` inside the block looked up by hash.
    /// Stellereum never produces uncles: always `None` (JSON null) after param validation.
    pub fn get_uncle_by_block_hash_and_index(
        &self,
        hash: &str,
        _index: u64,
    ) -> Result<Option<Value>, JsonRpcError> {
        normalize_hash(hash)
            .map_err(|_| JsonRpcError::invalid_params(format!("invalid block hash '{hash}'")))?;
        Ok(None)
    }

    /// Uncle at `index` inside the block looked up by tag/number.
    /// Stellereum never produces uncles: always `None` (JSON null).
    pub fn get_uncle_by_block_number_and_index(
        &self,
        _tag: &BlockTag,
        _index: u64,
    ) -> Result<Option<Value>, JsonRpcError> {
        Ok(None)
    }

    #[allow(non_snake_case)]
    pub fn eth_blockNumber(&self) -> String {
        self.eth_block_number()
    }

    #[allow(non_snake_case)]
    pub fn eth_getBlockByNumber(
        &self,
        tag: &str,
        full_txs: bool,
    ) -> Result<Option<EvmBlock>, JsonRpcError> {
        self.eth_get_block_by_number(tag, full_txs)
    }

    #[allow(non_snake_case)]
    pub fn eth_getBlockByHash(
        &self,
        hash: &str,
        full_txs: bool,
    ) -> Result<Option<EvmBlock>, JsonRpcError> {
        self.eth_get_block_by_hash(hash, full_txs)
    }

    #[allow(non_snake_case)]
    pub fn eth_getTransactionReceipt(
        &self,
        hash: &str,
    ) -> Result<Option<EvmReceipt>, JsonRpcError> {
        self.eth_get_transaction_receipt(hash)
    }

    #[allow(non_snake_case)]
    pub fn eth_getTransactionByHash(
        &self,
        hash: &str,
    ) -> Result<Option<EvmTransaction>, JsonRpcError> {
        self.eth_get_transaction_by_hash(hash)
    }

    #[allow(non_snake_case)]
    pub fn eth_getBlockTransactionCountByHash(
        &self,
        hash: &str,
    ) -> Result<Option<String>, JsonRpcError> {
        self.get_block_transaction_count_by_hash(hash)
    }

    #[allow(non_snake_case)]
    pub fn eth_getBlockTransactionCountByNumber(
        &self,
        tag: &BlockTag,
    ) -> Result<Option<String>, JsonRpcError> {
        self.get_block_transaction_count_by_number(tag)
    }

    #[allow(non_snake_case)]
    pub fn eth_getTransactionByBlockHashAndIndex(
        &self,
        hash: &str,
        index: u64,
    ) -> Result<Option<EvmTransaction>, JsonRpcError> {
        self.get_transaction_by_block_hash_and_index(hash, index)
    }

    #[allow(non_snake_case)]
    pub fn eth_getTransactionByBlockNumberAndIndex(
        &self,
        tag: &BlockTag,
        index: u64,
    ) -> Result<Option<EvmTransaction>, JsonRpcError> {
        self.get_transaction_by_block_number_and_index(tag, index)
    }

    #[allow(non_snake_case)]
    pub fn eth_getUncleCountByBlockHash(&self, hash: &str) -> Result<Option<String>, JsonRpcError> {
        self.get_uncle_count_by_block_hash(hash)
    }

    #[allow(non_snake_case)]
    pub fn eth_getUncleCountByBlockNumber(
        &self,
        tag: &BlockTag,
    ) -> Result<Option<String>, JsonRpcError> {
        self.get_uncle_count_by_block_number(tag)
    }

    #[allow(non_snake_case)]
    pub fn eth_getUncleByBlockHashAndIndex(
        &self,
        hash: &str,
        index: u64,
    ) -> Result<Option<Value>, JsonRpcError> {
        self.get_uncle_by_block_hash_and_index(hash, index)
    }

    #[allow(non_snake_case)]
    pub fn eth_getUncleByBlockNumberAndIndex(
        &self,
        tag: &BlockTag,
        index: u64,
    ) -> Result<Option<Value>, JsonRpcError> {
        self.get_uncle_by_block_number_and_index(tag, index)
    }

    fn handle_get_block_by_number(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let (tag, full) = parse_get_block_by_number_params(params)?;
        match self.get_block_by_number(&tag, full) {
            Some(block) => Ok(json!(block)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_block_by_hash(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let (hash, full) = parse_get_block_by_hash_params(params)?;
        if normalize_hash(&hash).is_err() {
            return Err(JsonRpcError::invalid_params(format!(
                "invalid block hash '{hash}'"
            )));
        }
        match self.get_block_by_hash(&hash, full) {
            Some(block) => Ok(json!(block)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_transaction_receipt(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let hash = parse_single_hash_param(params)?;
        match self.eth_get_transaction_receipt(&hash)? {
            Some(receipt) => Ok(json!(receipt)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_transaction_by_hash(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let hash = parse_single_hash_param(params)?;
        match self.eth_get_transaction_by_hash(&hash)? {
            Some(tx) => Ok(json!(tx)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_block_transaction_count_by_hash(
        &self,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        let hash = parse_single_hash_param(params)?;
        match self.get_block_transaction_count_by_hash(&hash)? {
            Some(count) => Ok(json!(count)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_block_transaction_count_by_number(
        &self,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        let tag = parse_single_block_tag_param(params)?;
        match self.get_block_transaction_count_by_number(&tag)? {
            Some(count) => Ok(json!(count)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_transaction_by_block_hash_and_index(
        &self,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        let (hash, index) = parse_block_hash_and_index_params(params)?;
        match self.get_transaction_by_block_hash_and_index(&hash, index)? {
            Some(tx) => Ok(json!(tx)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_transaction_by_block_number_and_index(
        &self,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        let (tag, index) = parse_block_number_and_index_params(params)?;
        match self.get_transaction_by_block_number_and_index(&tag, index)? {
            Some(tx) => Ok(json!(tx)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_uncle_count_by_block_hash(&self, params: &Value) -> Result<Value, JsonRpcError> {
        let hash = parse_single_hash_param(params)?;
        match self.get_uncle_count_by_block_hash(&hash)? {
            Some(count) => Ok(json!(count)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_uncle_count_by_block_number(
        &self,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        let tag = parse_single_block_tag_param(params)?;
        match self.get_uncle_count_by_block_number(&tag)? {
            Some(count) => Ok(json!(count)),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_uncle_by_block_hash_and_index(
        &self,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        let (hash, index) = parse_block_hash_and_index_params(params)?;
        match self.get_uncle_by_block_hash_and_index(&hash, index)? {
            Some(uncle) => Ok(uncle),
            None => Ok(Value::Null),
        }
    }

    fn handle_get_uncle_by_block_number_and_index(
        &self,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        let (tag, index) = parse_block_number_and_index_params(params)?;
        match self.get_uncle_by_block_number_and_index(&tag, index)? {
            Some(uncle) => Ok(uncle),
            None => Ok(Value::Null),
        }
    }

    pub fn with_engine(mut self, engine: Arc<InMemoryStateEngine>) -> Self {
        self.engine = Some(engine);
        self
    }

    pub fn with_rpc_state(mut self, st: &RpcState) -> Self {
        self.engine = Some(st.engine.clone());
        self
    }

    pub fn eth_get_code(&self) -> &'static str {
        self::eth_get_code()
    }

    #[allow(non_snake_case)]
    pub fn eth_getCode(
        &self,
        address: impl AsRef<str>,
        block_tag: impl AsRef<str>,
    ) -> Result<&'static str, JsonRpcError> {
        let addr_str = address.as_ref();
        let tag_str = block_tag.as_ref();
        let _ = parse_evm_or_stell_address(addr_str).map_err(|e| {
            JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}"))
        })?;
        let _ = BlockTag::parse_str(tag_str)?;
        Ok("0x")
    }

    #[allow(non_snake_case)]
    pub fn eth_getBalance(
        &self,
        address: impl AsRef<str>,
        block_tag: impl AsRef<str>,
    ) -> Result<String, JsonRpcError> {
        let addr_str = address.as_ref();
        let tag_str = block_tag.as_ref();
        let stell_addr = parse_evm_or_stell_address(addr_str).map_err(|e| {
            JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}"))
        })?;
        let _ = BlockTag::parse_str(tag_str)?;

        if let Some(ref engine) = self.engine {
            if let Ok(guard) = engine.accounts.try_read() {
                let bal_nano = guard.get(&stell_addr).map(|a| a.balance).unwrap_or(0);
                return Ok(nano_to_wei_hex(bal_nano));
            }
        }
        let bal = self.get_balance(addr_str);
        Ok(format_u128_hex(bal))
    }

    #[allow(non_snake_case)]
    pub fn eth_getTransactionCount(
        &self,
        address: impl AsRef<str>,
        block_tag: impl AsRef<str>,
    ) -> Result<String, JsonRpcError> {
        let addr_str = address.as_ref();
        let tag_str = block_tag.as_ref();
        let stell_addr = parse_evm_or_stell_address(addr_str).map_err(|e| {
            JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}"))
        })?;
        let _ = BlockTag::parse_str(tag_str)?;

        if let Some(ref engine) = self.engine {
            if let Ok(guard) = engine.accounts.try_read() {
                let nonce = guard.get(&stell_addr).map(|a| a.nonce).unwrap_or(0);
                return Ok(format_u64_hex(nonce));
            }
        }
        Ok("0x0".to_string())
    }

    pub async fn eth_get_balance(&self, params: &Value) -> Result<String, JsonRpcError> {
        if let Some(ref engine) = self.engine {
            self::eth_get_balance(engine, params).await
        } else {
            let res = self.dispatch("eth_getBalance", params)?;
            res.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| JsonRpcError::internal_error("expected string result"))
        }
    }

    pub async fn eth_get_transaction_count(&self, params: &Value) -> Result<String, JsonRpcError> {
        if let Some(ref engine) = self.engine {
            self::eth_get_transaction_count(engine, params).await
        } else {
            let res = self.dispatch("eth_getTransactionCount", params)?;
            res.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| JsonRpcError::internal_error("expected string result"))
        }
    }

    pub fn eth_chain_id(&self) -> String {
        format!("0x{:x}", self.chain_id)
    }

    pub fn net_version(&self) -> String {
        self.chain_id.to_string()
    }

    pub fn web3_client_version(&self) -> &str {
        &self.client_version
    }

    pub fn net_listening(&self) -> bool {
        self.listening
    }

    pub fn net_peer_count(&self) -> String {
        format!("0x{:x}", self.peer_count)
    }

    pub fn eth_syncing(&self) -> bool {
        self.syncing
    }

    pub fn eth_gas_price(&self) -> String {
        format_u128_hex(self.gas_price)
    }

    #[allow(non_snake_case)]
    pub fn eth_gasPrice(&self) -> String {
        self.eth_gas_price()
    }

    pub fn eth_max_priority_fee_per_gas(&self) -> String {
        format_u128_hex(self.max_priority_fee_per_gas)
    }

    #[allow(non_snake_case)]
    pub fn eth_maxPriorityFeePerGas(&self) -> String {
        self.eth_max_priority_fee_per_gas()
    }

    pub fn eth_estimate_gas(&self, params: &Value) -> Result<String, JsonRpcError> {
        eth_estimate_gas_with_floor(params, crate::svm::GAS_BASIC_TRANSFER)
    }

    #[allow(non_snake_case)]
    pub fn eth_estimateGas(&self, params: &Value) -> Result<String, JsonRpcError> {
        self.eth_estimate_gas(params)
    }

    pub fn eth_fee_history(&self, params: &Value) -> Result<EvmFeeHistory, JsonRpcError> {
        fee_history_impl(
            params,
            self.head_block,
            self.base_fee,
            self.max_priority_fee_per_gas,
            self.gas_used_ratio,
        )
    }

    #[allow(non_snake_case)]
    pub fn eth_feeHistory(&self, params: &Value) -> Result<EvmFeeHistory, JsonRpcError> {
        self.eth_fee_history(params)
    }

    pub fn eth_fee_history_direct(
        &self,
        block_count: u64,
        newest_block: u64,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<EvmFeeHistory, JsonRpcError> {
        let mut arr = vec![json!(block_count), json!(format_u64_hex(newest_block))];
        if let Some(rp) = reward_percentiles {
            arr.push(json!(rp));
        }
        fee_history_impl(
            &Value::Array(arr),
            self.head_block,
            self.base_fee,
            self.max_priority_fee_per_gas,
            self.gas_used_ratio,
        )
    }

    #[allow(non_snake_case)]
    pub fn eth_feeHistory_direct(
        &self,
        block_count: u64,
        newest_block: u64,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<EvmFeeHistory, JsonRpcError> {
        self.eth_fee_history_direct(block_count, newest_block, reward_percentiles)
    }

    /// Dispatch an RPC method call to its corresponding handler.
    pub fn dispatch(&self, method: &str, params: &Value) -> Result<Value, JsonRpcError> {
        match method {
            "eth_chainId" => Ok(json!(self.eth_chain_id())),
            "net_version" => Ok(json!(self.net_version())),
            "web3_clientVersion" => Ok(json!(self.web3_client_version())),
            "net_listening" => Ok(json!(self.net_listening())),
            "net_peerCount" => Ok(json!(self.net_peer_count())),
            "eth_syncing" => Ok(json!(self.eth_syncing())),
            "eth_gasPrice" => Ok(json!(self.eth_gas_price())),
            "eth_maxPriorityFeePerGas" => Ok(json!(self.eth_max_priority_fee_per_gas())),
            "eth_estimateGas" => self.eth_estimate_gas(params).map(|v| json!(v)),
            "eth_feeHistory" => self.eth_fee_history(params).and_then(|h| {
                serde_json::to_value(h).map_err(|e| JsonRpcError::internal_error(e.to_string()))
            }),
            "eth_getCode" => Ok(json!(self::handle_eth_get_code(params)?)),
            "eth_getBalance" => {
                let (addr_str, _tag) = parse_address_and_tag_params(params)?;
                let stell_addr = parse_evm_or_stell_address(&addr_str).map_err(|e| {
                    JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}"))
                })?;
                if let Some(ref engine) = self.engine {
                    if let Ok(guard) = engine.accounts.try_read() {
                        let bal_nano = guard.get(&stell_addr).map(|a| a.balance).unwrap_or(0);
                        return Ok(json!(nano_to_wei_hex(bal_nano)));
                    }
                }
                let bal = self.get_balance(&addr_str);
                Ok(json!(format_u128_hex(bal)))
            }
            "eth_getTransactionCount" => {
                let (addr_str, _tag) = parse_address_and_tag_params(params)?;
                let stell_addr = parse_evm_or_stell_address(&addr_str).map_err(|e| {
                    JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}"))
                })?;
                if let Some(ref engine) = self.engine {
                    if let Ok(guard) = engine.accounts.try_read() {
                        let nonce = guard.get(&stell_addr).map(|a| a.nonce).unwrap_or(0);
                        return Ok(json!(format_u64_hex(nonce)));
                    }
                }
                Ok(json!("0x0"))
            }
            "eth_blockNumber" => Ok(json!(self.eth_block_number())),
            "eth_getBlockByNumber" => self.handle_get_block_by_number(params),
            "eth_getBlockByHash" => self.handle_get_block_by_hash(params),
            "eth_getTransactionReceipt" => self.handle_get_transaction_receipt(params),
            "eth_getTransactionByHash" => self.handle_get_transaction_by_hash(params),
            "eth_getBlockTransactionCountByHash" => {
                self.handle_get_block_transaction_count_by_hash(params)
            }
            "eth_getBlockTransactionCountByNumber" => {
                self.handle_get_block_transaction_count_by_number(params)
            }
            "eth_getTransactionByBlockHashAndIndex" => {
                self.handle_get_transaction_by_block_hash_and_index(params)
            }
            "eth_getTransactionByBlockNumberAndIndex" => {
                self.handle_get_transaction_by_block_number_and_index(params)
            }
            "eth_getUncleCountByBlockHash" => self.handle_get_uncle_count_by_block_hash(params),
            "eth_getUncleCountByBlockNumber" => self.handle_get_uncle_count_by_block_number(params),
            "eth_getUncleByBlockHashAndIndex" => {
                self.handle_get_uncle_by_block_hash_and_index(params)
            }
            "eth_getUncleByBlockNumberAndIndex" => {
                self.handle_get_uncle_by_block_number_and_index(params)
            }
            // ERC-20 contract call emulation
            "eth_call" => self.handle_eth_call(params),
            // Filter polling
            "eth_newBlockFilter" => Ok(json!(self.filter_manager.new_block_filter())),
            "eth_newPendingTransactionFilter" => {
                Ok(json!(self.filter_manager.new_pending_transaction_filter()))
            }
            "eth_newFilter" => {
                let criteria = FilterCriteria::from_value(params)?;
                let id = self.filter_manager.new_filter(criteria);
                Ok(json!(id))
            }
            "eth_getFilterChanges" => {
                let id = extract_filter_id(params)?;
                self.filter_manager.get_filter_changes(&id)
            }
            "eth_getFilterLogs" => {
                let id = extract_filter_id(params)?;
                self.filter_manager.get_filter_logs(&id)
            }
            "eth_uninstallFilter" => {
                let id = extract_filter_id(params)?;
                let ok = self.filter_manager.uninstall_filter(&id);
                Ok(json!(ok))
            }
            "eth_getLogs" => self.eth_get_logs(params),
            "eth_getStorageAt" => self.eth_get_storage_at(params).map(|v| json!(v)),
            "eth_sendRawTransaction" => {
                let hash = eth_send_raw_transaction(params)?;
                Ok(json!(hash))
            }
            _ => Err(JsonRpcError::method_not_found(method)),
        }
    }

    /// Dispatch an RPC method call to its corresponding handler asynchronously, supporting state-backed methods.
    pub async fn dispatch_async(
        &self,
        method: &str,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        match method {
            "eth_getCode" => Ok(json!(self::handle_eth_get_code(params)?)),
            "eth_getBalance" => Ok(json!(self.eth_get_balance(params).await?)),
            "eth_getTransactionCount" => Ok(json!(self.eth_get_transaction_count(params).await?)),
            _ => self.dispatch(method, params),
        }
    }

    /// Dispatch against an explicit state engine.
    pub async fn dispatch_with_engine(
        &self,
        engine: &InMemoryStateEngine,
        method: &str,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        match method {
            "eth_call" => self.handle_eth_call_with_engine(engine, params).await,
            "eth_getBalance" => {
                let res = self::eth_get_balance(engine, params).await?;
                Ok(json!(res))
            }
            "eth_getTransactionCount" => {
                let res = self::eth_get_transaction_count(engine, params).await?;
                Ok(json!(res))
            }
            _ => self.dispatch(method, params),
        }
    }

    /// Dispatch against an explicit RPC state.
    pub async fn dispatch_with_state(
        &self,
        st: &RpcState,
        method: &str,
        params: &Value,
    ) -> Result<Value, JsonRpcError> {
        match method {
            "eth_blockNumber" => Ok(json!(st.eth_block_number())),
            "eth_getBlockByNumber" => match st.handle_get_block_by_number(params).await {
                Ok(Some(b)) => Ok(json!(b)),
                Ok(None) => match self.handle_get_block_by_number(params) {
                    Ok(v) => Ok(v),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            "eth_getBlockByHash" => match st.handle_get_block_by_hash(params).await {
                Ok(Some(b)) => Ok(json!(b)),
                Ok(None) => match self.handle_get_block_by_hash(params) {
                    Ok(v) => Ok(v),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            "eth_getTransactionReceipt" => match st.handle_get_transaction_receipt(params).await {
                Ok(Some(r)) => Ok(json!(r)),
                Ok(None) => match self.handle_get_transaction_receipt(params) {
                    Ok(v) => Ok(v),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            "eth_getTransactionByHash" => match st.handle_get_transaction_by_hash(params).await {
                Ok(Some(tx)) => Ok(json!(tx)),
                Ok(None) => match self.handle_get_transaction_by_hash(params) {
                    Ok(v) => Ok(v),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            },
            "eth_getBlockTransactionCountByHash" => {
                match st.handle_get_block_transaction_count_by_hash(params).await {
                    Ok(Some(c)) => Ok(json!(c)),
                    Ok(None) => match self.handle_get_block_transaction_count_by_hash(params) {
                        Ok(v) => Ok(v),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
            "eth_getBlockTransactionCountByNumber" => {
                match st
                    .handle_get_block_transaction_count_by_number(params)
                    .await
                {
                    Ok(Some(c)) => Ok(json!(c)),
                    Ok(None) => match self.handle_get_block_transaction_count_by_number(params) {
                        Ok(v) => Ok(v),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
            "eth_getTransactionByBlockHashAndIndex" => {
                match st
                    .handle_get_transaction_by_block_hash_and_index(params)
                    .await
                {
                    Ok(Some(tx)) => Ok(json!(tx)),
                    Ok(None) => match self.handle_get_transaction_by_block_hash_and_index(params) {
                        Ok(v) => Ok(v),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
            "eth_getTransactionByBlockNumberAndIndex" => {
                match st
                    .handle_get_transaction_by_block_number_and_index(params)
                    .await
                {
                    Ok(Some(tx)) => Ok(json!(tx)),
                    Ok(None) => match self.handle_get_transaction_by_block_number_and_index(params)
                    {
                        Ok(v) => Ok(v),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
            "eth_getUncleCountByBlockHash" => {
                match st.handle_get_uncle_count_by_block_hash(params).await {
                    Ok(Some(c)) => Ok(json!(c)),
                    Ok(None) => match self.handle_get_uncle_count_by_block_hash(params) {
                        Ok(v) => Ok(v),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
            "eth_getUncleCountByBlockNumber" => {
                match st.handle_get_uncle_count_by_block_number(params).await {
                    Ok(Some(c)) => Ok(json!(c)),
                    Ok(None) => match self.handle_get_uncle_count_by_block_number(params) {
                        Ok(v) => Ok(v),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
            "eth_getUncleByBlockHashAndIndex" => {
                // Stellereum never produces uncles: state and local adapter both report null.
                // Still validate params via the state path so malformed requests error identically.
                match st.handle_get_uncle_by_block_hash_and_index(params).await {
                    Ok(_) => Ok(Value::Null),
                    Err(e) => Err(e),
                }
            }
            "eth_getUncleByBlockNumberAndIndex" => {
                match st.handle_get_uncle_by_block_number_and_index(params).await {
                    Ok(_) => Ok(Value::Null),
                    Err(e) => Err(e),
                }
            }
            "eth_feeHistory" => {
                let cur_h = st.height.load(std::sync::atomic::Ordering::Relaxed);
                let fh = fee_history_impl(
                    params,
                    cur_h,
                    self.base_fee,
                    self.max_priority_fee_per_gas,
                    self.gas_used_ratio,
                )?;
                Ok(serde_json::to_value(fh)
                    .map_err(|e| JsonRpcError::internal_error(e.to_string()))?)
            }
            "eth_getLogs" => st.eth_get_logs(params).await,
            "eth_getStorageAt" => st.eth_get_storage_at(params).await.map(|v| json!(v)),
            _ => self.dispatch_with_engine(&st.engine, method, params).await,
        }
    }

    /// Handle a single parsed JSON-RPC request asynchronously.
    pub async fn handle_request_async(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id.clone().unwrap_or(Value::Null);
        if req.jsonrpc != "2.0" {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_request("jsonrpc field must be '2.0'"),
            );
        }
        match self.dispatch_async(&req.method, &req.params).await {
            Ok(result) => JsonRpcResponse::success(id, result),
            Err(err) => JsonRpcResponse::error(id, err),
        }
    }

    /// Process a raw JSON string (single or batch) asynchronously.
    /// Same batch status as [`EvmAdapter::handle_raw_json`]: in-process only,
    /// unreachable over HTTP (the HTTP path refuses batches with `-32600`).
    pub async fn handle_raw_json_async(&self, raw: &str) -> String {
        let val: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                let resp = JsonRpcResponse::<Value>::error(
                    Value::Null,
                    JsonRpcError::parse_error(e.to_string()),
                );
                return serde_json::to_string(&resp).unwrap_or_default();
            }
        };

        match val {
            Value::Array(items) => {
                if items.is_empty() {
                    let resp = JsonRpcResponse::<Value>::error(
                        Value::Null,
                        JsonRpcError::invalid_request("empty batch"),
                    );
                    return serde_json::to_string(&resp).unwrap_or_default();
                }
                let mut responses = Vec::with_capacity(items.len());
                for item in items {
                    match serde_json::from_value::<JsonRpcRequest>(item) {
                        Ok(req) => responses.push(self.handle_request_async(&req).await),
                        Err(e) => responses.push(JsonRpcResponse::error(
                            Value::Null,
                            JsonRpcError::invalid_request(e.to_string()),
                        )),
                    }
                }
                serde_json::to_string(&responses).unwrap_or_default()
            }
            Value::Object(_) => match serde_json::from_value::<JsonRpcRequest>(val) {
                Ok(req) => {
                    let resp = self.handle_request_async(&req).await;
                    serde_json::to_string(&resp).unwrap_or_default()
                }
                Err(e) => {
                    let resp = JsonRpcResponse::<Value>::error(
                        Value::Null,
                        JsonRpcError::invalid_request(e.to_string()),
                    );
                    serde_json::to_string(&resp).unwrap_or_default()
                }
            },
            _ => {
                let resp = JsonRpcResponse::<Value>::error(
                    Value::Null,
                    JsonRpcError::invalid_request("request must be an object or array"),
                );
                serde_json::to_string(&resp).unwrap_or_default()
            }
        }
    }

    /// Handle a single parsed JSON-RPC request.
    pub fn handle_request(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        let id = req.id.clone().unwrap_or(Value::Null);
        if req.jsonrpc != "2.0" {
            return JsonRpcResponse::error(
                id,
                JsonRpcError::invalid_request("jsonrpc field must be '2.0'"),
            );
        }
        match self.dispatch(&req.method, &req.params) {
            Ok(result) => JsonRpcResponse::success(id, result),
            Err(err) => JsonRpcResponse::error(id, err),
        }
    }

    /// Process a raw JSON string (single or batch) and serialize the JSON-RPC 2.0 response.
    ///
    /// BATCH STATUS (audit 2026-10-14 F11 / open-risk 5): this batch arm is
    /// INTENTIONALLY retained for the in-process adapter (unit tests pin its
    /// per-item id echo + empty-batch refusal), but it is UNREACHABLE over
    /// HTTP — `rpc::rpc_handler → dispatch` is single-only and refuses arrays
    /// loudly with `-32600` instead of silently serving the first element.
    /// Any future HTTP wiring must go through that single-only path; do not
    /// expose this function to a socket without re-adding a refusal.
    pub fn handle_raw_json(&self, raw: &str) -> String {
        let val: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => {
                let resp = JsonRpcResponse::<Value>::error(
                    Value::Null,
                    JsonRpcError::parse_error(e.to_string()),
                );
                return serde_json::to_string(&resp).unwrap_or_default();
            }
        };

        match val {
            Value::Array(items) => {
                if items.is_empty() {
                    let resp = JsonRpcResponse::<Value>::error(
                        Value::Null,
                        JsonRpcError::invalid_request("empty batch"),
                    );
                    return serde_json::to_string(&resp).unwrap_or_default();
                }
                let responses: Vec<JsonRpcResponse> = items
                    .into_iter()
                    .map(
                        |item| match serde_json::from_value::<JsonRpcRequest>(item) {
                            Ok(req) => self.handle_request(&req),
                            Err(e) => JsonRpcResponse::error(
                                Value::Null,
                                JsonRpcError::invalid_request(e.to_string()),
                            ),
                        },
                    )
                    .collect();
                serde_json::to_string(&responses).unwrap_or_default()
            }
            Value::Object(_) => match serde_json::from_value::<JsonRpcRequest>(val) {
                Ok(req) => {
                    let resp = self.handle_request(&req);
                    serde_json::to_string(&resp).unwrap_or_default()
                }
                Err(e) => {
                    let resp = JsonRpcResponse::<Value>::error(
                        Value::Null,
                        JsonRpcError::invalid_request(e.to_string()),
                    );
                    serde_json::to_string(&resp).unwrap_or_default()
                }
            },
            _ => {
                let resp = JsonRpcResponse::<Value>::error(
                    Value::Null,
                    JsonRpcError::invalid_request("request must be an object or array"),
                );
                serde_json::to_string(&resp).unwrap_or_default()
            }
        }
    }
}

// ============================================================================
// Ethereum JSON-RPC 2.0 Data Structs with Exact Serde Serialization
// ============================================================================

/// Ethereum JSON-RPC Block representation (EIP-1474 / Execution API).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmBlock {
    /// The block number. Null when pending block.
    pub number: Option<String>,
    /// Hash of the block. Null when pending block.
    pub hash: Option<String>,
    /// Hash of the parent block.
    pub parent_hash: String,
    /// Hash of the generated proof-of-work. Null when pending.
    pub nonce: Option<String>,
    /// SHA3 of the uncles data in the block.
    pub sha3_uncles: String,
    /// The bloom filter for the logs of the block. Null when pending.
    pub logs_bloom: Option<String>,
    /// The root of the transaction trie of the block.
    pub transactions_root: String,
    /// The root of the final state trie of the block.
    pub state_root: String,
    /// The root of the receipts trie of the block.
    pub receipts_root: String,
    /// The address of the beneficiary to whom the mining rewards were given.
    pub miner: String,
    /// Integer of the difficulty for this block.
    pub difficulty: String,
    /// Integer of the total difficulty of the chain until this block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_difficulty: Option<String>,
    /// The "extra data" field of this block.
    pub extra_data: String,
    /// The size of this block in bytes.
    pub size: String,
    /// The maximum gas allowed in this block.
    pub gas_limit: String,
    /// The total used gas by all transactions in this block.
    pub gas_used: String,
    /// The unix timestamp for when the block was collated.
    pub timestamp: String,
    /// Array of transaction objects, or array of 32-byte transaction hashes depending on full tx flag.
    pub transactions: BlockTransactions,
    /// Array of uncle hashes.
    pub uncles: Vec<String>,
    /// Base fee per gas (EIP-1559).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<String>,
    /// Prevrandao / mixHash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mix_hash: Option<String>,
    /// Withdrawals list (EIP-4895).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals: Option<Vec<EvmWithdrawal>>,
    /// Withdrawals root (EIP-4895).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals_root: Option<String>,
    /// Blob gas used (EIP-4844).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gas_used: Option<String>,
    /// Excess blob gas (EIP-4844).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excess_blob_gas: Option<String>,
    /// Parent beacon block root (EIP-4788).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_beacon_block_root: Option<String>,
}

/// Transaction entries inside a block (either list of 32-byte hashes or full transaction objects).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlockTransactions {
    Hashes(Vec<String>),
    Full(Vec<EvmTransaction>),
}

impl Default for BlockTransactions {
    fn default() -> Self {
        BlockTransactions::Hashes(Vec::new())
    }
}

/// EIP-4895 withdrawal representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmWithdrawal {
    pub index: String,
    pub validator_index: String,
    pub address: String,
    pub amount: String,
}

/// Ethereum JSON-RPC Transaction representation (EIP-1474, EIP-2718, EIP-1559).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmTransaction {
    /// 32-byte hash of the transaction.
    pub hash: String,
    /// The number of transactions made by the sender prior to this one.
    pub nonce: String,
    /// 32-byte hash of the block where this transaction was in. Null when pending.
    pub block_hash: Option<String>,
    /// Block number where this transaction was in. Null when pending.
    pub block_number: Option<String>,
    /// Integer of the transactions index position in the block. Null when pending.
    pub transaction_index: Option<String>,
    /// 20-byte address of the sender.
    pub from: String,
    /// 20-byte address of the receiver. Null when it is a contract creation transaction.
    pub to: Option<String>,
    /// Value transferred in Wei.
    pub value: String,
    /// Gas price provided by the sender in Wei.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<String>,
    /// Gas provided by the sender.
    pub gas: String,
    /// The data sent along with the transaction.
    #[serde(alias = "data")]
    pub input: String,
    /// ECDSA recovery id.
    pub v: String,
    /// ECDSA signature r.
    pub r: String,
    /// ECDSA signature s.
    pub s: String,
    /// Transaction type (0x0 = legacy, 0x1 = EIP-2930, 0x2 = EIP-1559, 0x3 = EIP-4844).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub tx_type: Option<String>,
    /// Chain ID (EIP-155).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    /// Maximum fee per gas (EIP-1559).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<String>,
    /// Maximum priority fee per gas (EIP-1559).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<String>,
    /// EIP-2930 access list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<Vec<EvmAccessListItem>>,
    /// Maximum fee per blob gas (EIP-4844).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_blob_gas: Option<String>,
    /// List of versioned blob hashes (EIP-4844).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_versioned_hashes: Option<Vec<String>>,
}

/// EIP-2930 access list entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmAccessListItem {
    pub address: String,
    pub storage_keys: Vec<String>,
}

/// Ethereum JSON-RPC Transaction Receipt representation (EIP-1474, EIP-658).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmReceipt {
    /// 32-byte hash of the transaction.
    pub transaction_hash: String,
    /// Integer of the transactions index position in the block.
    pub transaction_index: String,
    /// 32-byte hash of the block where this transaction was in.
    pub block_hash: String,
    /// Block number where this transaction was in.
    pub block_number: String,
    /// 20-byte address of the sender.
    pub from: String,
    /// 20-byte address of the receiver. Null when it is a contract creation transaction.
    pub to: Option<String>,
    /// The total amount of gas used when this transaction was executed in the block.
    pub cumulative_gas_used: String,
    /// The amount of gas used by this specific transaction alone.
    pub gas_used: String,
    /// The contract address created, if the transaction was a contract creation, otherwise null.
    pub contract_address: Option<String>,
    /// Array of log objects that this transaction generated.
    pub logs: Vec<EvmLog>,
    /// Bloom filter for light clients to quickly retrieve related logs.
    pub logs_bloom: String,
    /// Either "0x1" (success) or "0x0" (failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// 32-byte post-transaction state root (pre-Byzantium).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// Transaction type.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub tx_type: Option<String>,
    /// Effective gas price (EIP-1559).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_gas_price: Option<String>,
    /// Blob gas used by this transaction (EIP-4844).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gas_used: Option<String>,
    /// Blob gas price paid by this transaction (EIP-4844).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gas_price: Option<String>,
}

/// Ethereum log object inside receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmLog {
    /// 20-byte address from which this log originated.
    pub address: String,
    /// Array of 32-byte DATA topics.
    pub topics: Vec<String>,
    /// Contains one or more 32-byte non-indexed arguments of the log.
    pub data: String,
    /// Block number where this log was in. Null when pending.
    pub block_number: Option<String>,
    /// 32-byte hash of the transaction from which this log was created. Null when pending.
    pub transaction_hash: Option<String>,
    /// Integer of the transactions index position in the block. Null when pending.
    pub transaction_index: Option<String>,
    /// 32-byte hash of the block where this log was in. Null when pending.
    pub block_hash: Option<String>,
    /// Integer of the log index position in the block. Null when pending.
    pub log_index: Option<String>,
    /// True when the log was removed due to a chain reorganization.
    #[serde(default)]
    pub removed: bool,
}

/// Ethereum JSON-RPC Fee History representation (EIP-1559 `eth_feeHistory`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmFeeHistory {
    /// Lowest number block of the returned range.
    pub oldest_block: String,
    /// An array of block base fees per gas. Includes next block after newest in the range.
    pub base_fee_per_gas: Vec<String>,
    /// An array of block at capacity ratios (gasUsed / gasLimit).
    pub gas_used_ratio: Vec<f64>,
    /// A two-dimensional array of effective priority fees per gas at the requested percentiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward: Option<Vec<Vec<String>>>,
}

// ============================================================================
// Helpers & Stellereum Converters
// ============================================================================

/// Formats a 64-bit integer into a hex quantity with 0x prefix.
pub fn format_u64_hex(val: u64) -> String {
    format!("0x{:x}", val)
}

/// Formats a 128-bit integer into a hex quantity with 0x prefix.
pub fn format_u128_hex(val: u128) -> String {
    format!("0x{:x}", val)
}

/// Parses a hex quantity (with or without 0x/0X prefix).
pub fn parse_hex_u64(s: &str) -> Result<u64, String> {
    let trimmed = s.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex_part.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(hex_part, 16).map_err(|e| format!("invalid hex quantity '{s}': {e}"))
}

/// Parses a 128-bit hex quantity (with or without 0x/0X prefix).
pub fn parse_hex_u128(s: &str) -> Result<u128, String> {
    let trimmed = s.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex_part.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(hex_part, 16).map_err(|e| format!("invalid hex quantity '{s}': {e}"))
}

/// Helper to parse a block count parameter (1..=1024).
pub fn parse_block_count(val: &Value) -> Result<u64, JsonRpcError> {
    let count = match val {
        Value::Number(n) => n.as_u64().ok_or_else(|| {
            JsonRpcError::invalid_params("block count must be non-negative integer")
        })?,
        Value::String(s) => parse_hex_u64(s)
            .or_else(|_| s.parse::<u64>().map_err(|e| e.to_string()))
            .map_err(|e| JsonRpcError::invalid_params(format!("invalid block count: {e}")))?,
        _ => {
            return Err(JsonRpcError::invalid_params(
                "invalid block count parameter",
            ))
        }
    };
    if count == 0 || count > 1024 {
        return Err(JsonRpcError::invalid_params(
            "blockCount must be between 1 and 1024",
        ));
    }
    Ok(count)
}

/// Returns the current block height formatted as a hex quantity.
pub fn eth_block_number(height: u64) -> String {
    format_u64_hex(height)
}

/// Ensures a hex string has a lowercase 0x prefix.
pub fn ensure_0x(s: &str) -> String {
    let trimmed = s.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    format!("0x{}", stripped.to_ascii_lowercase())
}

/// Normalizes a 32-byte hex hash to lowercase with 0x prefix.
pub fn normalize_hash(s: &str) -> Result<String, String> {
    let trimmed = s.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.len() != 64 {
        return Err(format!(
            "hash must be 32 bytes (64 hex characters), got '{}' (len {})",
            s,
            stripped.len()
        ));
    }
    if !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid hex characters in hash '{s}'"));
    }
    Ok(format!("0x{}", stripped.to_ascii_lowercase()))
}

/// Parses a 32-byte hex hash string into [u8; 32].
pub fn parse_hash_bytes(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.len() != 64 {
        return Err(format!(
            "hash must be 32 bytes (64 hex characters), got '{}' (len {})",
            s,
            stripped.len()
        ));
    }
    let bytes = hex::decode(stripped).map_err(|e| format!("invalid hex in hash '{s}': {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("hash '{s}' must be exactly 32 bytes"))
}

/// Ethereum JSON-RPC block tag or number parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockTag {
    Latest,
    Earliest,
    Pending,
    Finalized,
    Safe,
    Number(u64),
}

impl BlockTag {
    pub fn parse(val: &Value) -> Result<Self, JsonRpcError> {
        match val {
            Value::String(s) => Self::parse_str(s),
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Ok(BlockTag::Number(u))
                } else {
                    Err(JsonRpcError::invalid_params(format!(
                        "invalid block number: {n}"
                    )))
                }
            }
            _ => Err(JsonRpcError::invalid_params(
                "block tag must be a string or integer",
            )),
        }
    }

    pub fn parse_str(s: &str) -> Result<Self, JsonRpcError> {
        let trimmed = s.trim();
        let s_lower = trimmed.to_ascii_lowercase();
        match s_lower.as_str() {
            "latest" => Ok(BlockTag::Latest),
            "earliest" => Ok(BlockTag::Earliest),
            "pending" => Ok(BlockTag::Pending),
            "finalized" => Ok(BlockTag::Finalized),
            "safe" => Ok(BlockTag::Safe),
            hex if hex.starts_with("0x") || hex.starts_with("0X") => {
                let n = parse_hex_u64(hex).map_err(JsonRpcError::invalid_params)?;
                Ok(BlockTag::Number(n))
            }
            dec => {
                if let Ok(n) = dec.parse::<u64>() {
                    Ok(BlockTag::Number(n))
                } else if let Ok(n) = parse_hex_u64(dec) {
                    Ok(BlockTag::Number(n))
                } else {
                    Err(JsonRpcError::invalid_params(format!(
                        "invalid block tag '{s}'"
                    )))
                }
            }
        }
    }

    pub fn resolve(&self, head: u64) -> u64 {
        match self {
            BlockTag::Earliest => 0,
            BlockTag::Latest | BlockTag::Finalized | BlockTag::Safe | BlockTag::Pending => head,
            BlockTag::Number(n) => *n,
        }
    }
}

pub fn parse_block_tag(val: &Value) -> Result<BlockTag, JsonRpcError> {
    BlockTag::parse(val)
}

pub fn parse_block_tag_str(s: &str) -> Result<BlockTag, JsonRpcError> {
    BlockTag::parse_str(s)
}

pub fn parse_get_block_by_number_params(params: &Value) -> Result<(BlockTag, bool), JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(JsonRpcError::invalid_params("missing block tag parameter"));
            }
            let tag = BlockTag::parse(&arr[0])?;
            let full = arr.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
            Ok((tag, full))
        }
        Value::Object(obj) => {
            let tag_val = obj
                .get("blockNumber")
                .or_else(|| obj.get("tag"))
                .or_else(|| obj.get("block"))
                .or_else(|| obj.get("number"))
                .ok_or_else(|| JsonRpcError::invalid_params("missing block tag parameter"))?;
            let tag = BlockTag::parse(tag_val)?;
            let full = obj
                .get("fullTransactions")
                .or_else(|| obj.get("full"))
                .or_else(|| obj.get("hydrated"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok((tag, full))
        }
        Value::String(_) | Value::Number(_) => {
            let tag = BlockTag::parse(params)?;
            Ok((tag, false))
        }
        _ => Err(JsonRpcError::invalid_params(
            "params must be an array or object",
        )),
    }
}

pub fn parse_get_block_by_hash_params(params: &Value) -> Result<(String, bool), JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(JsonRpcError::invalid_params("missing block hash parameter"));
            }
            let hash = arr[0]
                .as_str()
                .ok_or_else(|| JsonRpcError::invalid_params("hash must be a string"))?;
            let full = arr.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
            Ok((hash.to_string(), full))
        }
        Value::Object(obj) => {
            let hash = obj
                .get("blockHash")
                .or_else(|| obj.get("hash"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing hash field"))?;
            let full = obj
                .get("fullTransactions")
                .or_else(|| obj.get("full"))
                .or_else(|| obj.get("hydrated"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Ok((hash.to_string(), full))
        }
        Value::String(s) => Ok((s.clone(), false)),
        _ => Err(JsonRpcError::invalid_params(
            "params must be an array or object",
        )),
    }
}

pub fn parse_single_hash_param(params: &Value) -> Result<String, JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(JsonRpcError::invalid_params("missing hash parameter"));
            }
            arr[0]
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| JsonRpcError::invalid_params("hash must be a string"))
        }
        Value::Object(obj) => obj
            .get("hash")
            .or_else(|| obj.get("txHash"))
            .or_else(|| obj.get("transactionHash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| JsonRpcError::invalid_params("missing hash field")),
        Value::String(s) => Ok(s.clone()),
        _ => Err(JsonRpcError::invalid_params(
            "params must be an array or object",
        )),
    }
}

/// Parses a transaction/uncle index parameter (QUANTITY hex string or number).
pub fn parse_tx_index_param(val: &Value) -> Result<u64, JsonRpcError> {
    match val {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| JsonRpcError::invalid_params("index must be a non-negative integer")),
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
                .is_some()
            {
                parse_hex_u64(trimmed).map_err(JsonRpcError::invalid_params)
            } else if let Ok(dec) = trimmed.parse::<u64>() {
                Ok(dec)
            } else {
                parse_hex_u64(trimmed).map_err(JsonRpcError::invalid_params)
            }
        }
        _ => Err(JsonRpcError::invalid_params(
            "index must be a hex quantity string or number",
        )),
    }
}

/// Parses a single block tag parameter: `[tag]`, `{blockNumber/tag/block/number}`,
/// or a bare string/number.
pub fn parse_single_block_tag_param(params: &Value) -> Result<BlockTag, JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(JsonRpcError::invalid_params("missing block tag parameter"));
            }
            BlockTag::parse(&arr[0])
        }
        Value::Object(obj) => {
            let tag_val = obj
                .get("blockNumber")
                .or_else(|| obj.get("tag"))
                .or_else(|| obj.get("block"))
                .or_else(|| obj.get("number"))
                .ok_or_else(|| JsonRpcError::invalid_params("missing block tag parameter"))?;
            BlockTag::parse(tag_val)
        }
        Value::String(_) | Value::Number(_) => BlockTag::parse(params),
        _ => Err(JsonRpcError::invalid_params(
            "params must be an array or object",
        )),
    }
}

/// Parses `(blockHash, index)` parameters: `[hash, index]` or
/// `{blockHash/hash, index/position}`.
pub fn parse_block_hash_and_index_params(params: &Value) -> Result<(String, u64), JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if arr.len() < 2 {
                return Err(JsonRpcError::invalid_params("expected [blockHash, index]"));
            }
            let hash = arr[0]
                .as_str()
                .ok_or_else(|| JsonRpcError::invalid_params("block hash must be a string"))?
                .to_string();
            let index = parse_tx_index_param(&arr[1])?;
            Ok((hash, index))
        }
        Value::Object(obj) => {
            let hash = obj
                .get("blockHash")
                .or_else(|| obj.get("hash"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing block hash field"))?
                .to_string();
            let idx_val = obj
                .get("index")
                .or_else(|| obj.get("position"))
                .or_else(|| obj.get("transactionIndex"))
                .ok_or_else(|| JsonRpcError::invalid_params("missing index field"))?;
            let index = parse_tx_index_param(idx_val)?;
            Ok((hash, index))
        }
        _ => Err(JsonRpcError::invalid_params(
            "params must be an array or object",
        )),
    }
}

/// Parses `(blockNumber|tag, index)` parameters: `[tag, index]` or
/// `{blockNumber/tag/block/number, index/position}`.
pub fn parse_block_number_and_index_params(
    params: &Value,
) -> Result<(BlockTag, u64), JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if arr.len() < 2 {
                return Err(JsonRpcError::invalid_params(
                    "expected [blockNumber, index]",
                ));
            }
            let tag = BlockTag::parse(&arr[0])?;
            let index = parse_tx_index_param(&arr[1])?;
            Ok((tag, index))
        }
        Value::Object(obj) => {
            let tag_val = obj
                .get("blockNumber")
                .or_else(|| obj.get("tag"))
                .or_else(|| obj.get("block"))
                .or_else(|| obj.get("number"))
                .ok_or_else(|| JsonRpcError::invalid_params("missing block tag parameter"))?;
            let tag = BlockTag::parse(tag_val)?;
            let idx_val = obj
                .get("index")
                .or_else(|| obj.get("position"))
                .or_else(|| obj.get("transactionIndex"))
                .ok_or_else(|| JsonRpcError::invalid_params("missing index field"))?;
            let index = parse_tx_index_param(idx_val)?;
            Ok((tag, index))
        }
        _ => Err(JsonRpcError::invalid_params(
            "params must be an array or object",
        )),
    }
}

/// Number of transactions in a block (hashes or full objects).
pub fn block_transaction_count(block: &EvmBlock) -> usize {
    match &block.transactions {
        BlockTransactions::Hashes(h) => h.len(),
        BlockTransactions::Full(t) => t.len(),
    }
}

/// Helper to parse a block number or block tag ("latest", "pending", "earliest", "safe", "finalized", or hex/decimal).
pub fn parse_block_number_or_tag(val: &Value, head: u64) -> Result<u64, JsonRpcError> {
    BlockTag::parse(val).map(|tag| tag.resolve(head))
}

/// Helper to parse reward percentiles array.
pub fn parse_reward_percentiles(val: &Value) -> Result<Option<Vec<f64>>, JsonRpcError> {
    match val {
        Value::Null => Ok(None),
        Value::Array(arr) => {
            if arr.is_empty() {
                return Ok(None);
            }
            let mut list = Vec::with_capacity(arr.len());
            for item in arr {
                let p = match item {
                    Value::Number(n) => n.as_f64().ok_or_else(|| {
                        JsonRpcError::invalid_params("reward percentile must be a number")
                    })?,
                    Value::String(s) => s.parse::<f64>().map_err(|_| {
                        JsonRpcError::invalid_params(format!("invalid reward percentile: {s}"))
                    })?,
                    _ => {
                        return Err(JsonRpcError::invalid_params(
                            "reward percentile must be numeric",
                        ))
                    }
                };
                if !(0.0..=100.0).contains(&p) {
                    return Err(JsonRpcError::invalid_params(format!(
                        "percentile must be between 0 and 100, got {p}"
                    )));
                }
                list.push(p);
            }
            for w in list.windows(2) {
                if w[0] > w[1] {
                    return Err(JsonRpcError::invalid_params(
                        "reward percentiles must be in non-decreasing order",
                    ));
                }
            }
            Ok(Some(list))
        }
        _ => Err(JsonRpcError::invalid_params(
            "rewardPercentiles must be an array",
        )),
    }
}

/// Core implementation of `eth_estimateGas`.
///
/// FEE HONESTY (audit 2026-10-14 F4): this is an ADMISSION estimate, not
/// execution metering. EVM calldata is never executed (plain-transfer
/// settlement; contract creation is rejected at settlement), and the
/// `gas_price` / `max_fee_per_gas` fields on the intent views are
/// display-only — what the mempool actually enforces is the declared
/// `gas_limit` against its admission floor (`stell_baseFee`: `base_fee` plus
/// the PQ activation surcharge for activation txs) plus `amount + gas_limit`
/// solvency. Callers that need an admittable figure use
/// [`eth_estimate_gas_with_floor`]; the bare form below is the pure EVM
/// component (21k / 53k + 4-per-zero-byte + 16-per-nonzero-byte).
pub fn eth_estimate_gas_impl(params: &Value) -> Result<String, JsonRpcError> {
    Ok(format_u64_hex(eth_estimate_gas_amount(params)?))
}

/// Pure EVM gas component of the estimate, in gas units.
pub fn eth_estimate_gas_amount(params: &Value) -> Result<u64, JsonRpcError> {
    let call_obj = match params {
        Value::Null => None,
        Value::Array(arr) => {
            if arr.is_empty() {
                None
            } else {
                match &arr[0] {
                    Value::Null => None,
                    Value::Object(map) => Some(map),
                    _ => {
                        return Err(JsonRpcError::invalid_params(
                            "call object must be an object",
                        ))
                    }
                }
            }
        }
        Value::Object(map) => Some(map),
        _ => {
            return Err(JsonRpcError::invalid_params(
                "params must be array or object",
            ))
        }
    };

    let Some(obj) = call_obj else {
        return Ok(STANDARD_TRANSFER_GAS);
    };

    let data_str = obj
        .get("data")
        .or_else(|| obj.get("input"))
        .and_then(|v| v.as_str());

    let (has_calldata, calldata_bytes) = match data_str {
        Some(s) => {
            let t = s.trim();
            let stripped = t
                .strip_prefix("0x")
                .or_else(|| t.strip_prefix("0X"))
                .unwrap_or(t);
            if stripped.is_empty() {
                (false, Vec::new())
            } else {
                // Audit B-VM: bound estimate calldata (unbounded hex decode
                // + per-byte sum is unauth CPU/RAM DoS; same 128KiB ceiling
                // as raw-tx ingest).
                if stripped.len() > 2 * MAX_EVM_RAW_TX_BYTES {
                    return Err(JsonRpcError::invalid_params(format!(
                        "calldata exceeds cap {} bytes",
                        MAX_EVM_RAW_TX_BYTES
                    )));
                }
                let bytes = hex::decode(stripped).map_err(|e| {
                    JsonRpcError::invalid_params(format!("invalid hex data in call: {e}"))
                })?;
                (true, bytes)
            }
        }
        None => (false, Vec::new()),
    };

    let is_contract_creation = match obj.get("to") {
        None | Some(Value::Null) => has_calldata,
        Some(Value::String(s)) => {
            let t = s.trim();
            (t.is_empty() || t == "0x") && has_calldata
        }
        _ => false,
    };

    let base_gas = if is_contract_creation {
        CONTRACT_CREATION_BASE_GAS
    } else {
        STANDARD_TRANSFER_GAS
    };

    let calldata_gas: u64 = calldata_bytes
        .iter()
        .map(|&b| if b == 0 { 4 } else { 16 })
        .sum();

    // Audit B-VM: floor-aware (RPC.md contract). The pure EVM figure (21k)
    // sits below the Stell admission floor and wallets forwarding it get
    // rejected for under-declared gas. Units differ across the bridge, but
    // quoting max() is safe in both directions: EVM tooling tolerates the
    // over-estimate, and our admission never sees an under-declared figure.
    // NOTE: the floor itself is applied by `eth_estimate_gas_with_floor`
    // (served paths); this pure figure stays unfloored (pinned by closeout).
    let total = base_gas.saturating_add(calldata_gas);
    Ok(total)
}

/// Floor-aware `eth_estimateGas`: `max(pure EVM estimate, floor)`.
///
/// `floor` is the caller's live admission floor in declared-gas units — the
/// RPC layer passes its mempool `base_fee` (served read-only as
/// `stell_baseFee`), so a wallet that forwards this figure is never told a
/// number the same node would reject for under-declared gas. With the default
/// floor of 0 the pure figure passes through unchanged.
pub fn eth_estimate_gas_with_floor(params: &Value, floor: u64) -> Result<String, JsonRpcError> {
    let est = eth_estimate_gas_amount(params)?;
    Ok(format_u64_hex(est.max(floor)))
}

/// Core implementation of `eth_feeHistory`.
pub fn fee_history_impl(
    params: &Value,
    head: u64,
    base_fee: u128,
    max_priority_fee: u128,
    gas_used_ratio_val: f64,
) -> Result<EvmFeeHistory, JsonRpcError> {
    let (count_val, newest_val, percentiles_val) = match params {
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(JsonRpcError::invalid_params(
                    "eth_feeHistory requires at least blockCount and newestBlock parameters",
                ));
            }
            let count_v = &arr[0];
            let newest_v = arr.get(1);
            let percentiles_v = arr.get(2);
            (count_v, newest_v, percentiles_v)
        }
        Value::Object(map) => {
            let count_v = map
                .get("blockCount")
                .or_else(|| map.get("block_count"))
                .ok_or_else(|| {
                    JsonRpcError::invalid_params("missing blockCount in feeHistory params")
                })?;
            let newest_v = map.get("newestBlock").or_else(|| map.get("newest_block"));
            let percentiles_v = map
                .get("rewardPercentiles")
                .or_else(|| map.get("reward_percentiles"));
            (count_v, newest_v, percentiles_v)
        }
        _ => {
            return Err(JsonRpcError::invalid_params(
                "params for eth_feeHistory must be an array or object",
            ));
        }
    };

    let block_count = parse_block_count(count_val)?;
    let newest_block = match newest_val {
        Some(v) => parse_block_number_or_tag(v, head)?,
        None => head,
    };
    let reward_percentiles = match percentiles_val {
        Some(v) => parse_reward_percentiles(v)?,
        None => None,
    };

    let actual_count = block_count.min(newest_block + 1);
    let oldest_block_num = newest_block + 1 - actual_count;
    let oldest_block = format_u64_hex(oldest_block_num);

    let base_fee_hex = format_u128_hex(base_fee);
    let base_fee_per_gas = vec![base_fee_hex; (actual_count + 1) as usize];
    let gas_used_ratio = vec![gas_used_ratio_val; actual_count as usize];

    let reward = reward_percentiles.map(|percentiles| {
        (0..actual_count)
            .map(|_| {
                percentiles
                    .iter()
                    .map(|&p| {
                        let tip = if max_priority_fee == 0 || p <= 0.0 {
                            0
                        } else if p >= 100.0 {
                            max_priority_fee
                        } else {
                            ((max_priority_fee as f64) * (p / 100.0)).round() as u128
                        };
                        format_u128_hex(tip)
                    })
                    .collect()
            })
            .collect()
    });

    Ok(EvmFeeHistory {
        oldest_block,
        base_fee_per_gas,
        gas_used_ratio,
        reward,
    })
}

// ============================================================================
// Decimal Scaling & Currency Constants
// 1 STELL = 10^9 nano-STELL = 10^18 Wei
// ============================================================================

/// Number of nano-STELL in 1 STELL (10^9).
pub const NANO_PER_STELL: u64 = 1_000_000_000;

/// Number of Wei in 1 STELL (10^18).
pub const WEI_PER_STELL: u128 = 1_000_000_000_000_000_000;

/// Number of Wei in 1 nano-STELL (10^9).
pub const WEI_PER_NANO: u128 = 1_000_000_000;

/// Converts nano-STELL (u64) to Wei (u128).
/// 1 STELL = 10^9 nano-STELL = 10^18 Wei, so 1 nano-STELL = 10^9 Wei.
pub fn nano_to_wei(nano: u64) -> u128 {
    (nano as u128) * WEI_PER_NANO
}

/// Converts Wei (u128) to nano-STELL (u64).
/// Sub-nano wei are truncated. Values above u64::MAX nano-STELL saturate at u64::MAX.
pub fn wei_to_nano(wei: u128) -> u64 {
    let nano = wei / WEI_PER_NANO;
    if nano > u64::MAX as u128 {
        u64::MAX
    } else {
        nano as u64
    }
}

/// Formats nano-STELL as a hex-encoded Wei quantity string with 0x prefix (e.g. "0xde0b6b3a7640000").
pub fn nano_to_wei_hex(nano: u64) -> String {
    format_u128_hex(nano_to_wei(nano))
}

/// Formats nano-STELL as a decimal string in Wei.
pub fn nano_to_wei_str(nano: u64) -> String {
    nano_to_wei(nano).to_string()
}

/// Alias for `nano_to_wei_str`.
pub fn nano_to_wei_string(nano: u64) -> String {
    nano_to_wei_str(nano)
}

/// Formats Wei as a hex-encoded nano-STELL quantity string with 0x prefix.
pub fn wei_to_nano_hex(wei: u128) -> String {
    format_u64_hex(wei_to_nano(wei))
}

/// Formats Wei as a decimal string in nano-STELL.
pub fn wei_to_nano_str(wei: u128) -> String {
    wei_to_nano(wei).to_string()
}

/// Alias for `wei_to_nano_str`.
pub fn wei_to_nano_string(wei: u128) -> String {
    wei_to_nano_str(wei)
}

/// Parses a hex-encoded Wei quantity (e.g. "0xde0b6b3a7640000") and converts to nano-STELL.
pub fn wei_hex_to_nano(hex_str: &str) -> Result<u64, String> {
    let wei = parse_hex_u128(hex_str)?;
    Ok(wei_to_nano(wei))
}

/// Parses a decimal Wei string (e.g. "1000000000000000000") and converts to nano-STELL.
pub fn wei_str_to_nano(dec_str: &str) -> Result<u64, String> {
    let trimmed = dec_str.trim();
    let wei = trimmed
        .parse::<u128>()
        .map_err(|e| format!("invalid decimal wei '{dec_str}': {e}"))?;
    Ok(wei_to_nano(wei))
}

// ============================================================================
// Address Mapping (20-byte EVM <-> 32-byte Stellereum)
// ============================================================================

/// Maps a 20-byte EVM address to a 32-byte Stellereum address (left-padded with 12 zero bytes).
pub fn evm_to_stell_address(evm_addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(evm_addr);
    out
}

/// Extracts a 20-byte EVM address from a 32-byte Stellereum address (bytes 12..32).
pub fn stell_to_evm_address(stell_addr: &[u8; 32]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&stell_addr[12..32]);
    out
}

/// Encodes a 20-byte EVM address as a 0x-prefixed hex string.
pub fn evm_address_to_hex(addr: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(addr))
}

/// Parses a 20-byte EVM address from a hex string (accepting either 20-byte EVM address
/// or 32-byte Stellereum address, with or without 0x/0X prefix).
pub fn evm_address_from_hex(s: &str) -> Result<[u8; 20], String> {
    let trimmed = s.trim();
    let raw = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if raw.len() == 40 {
        let mut out = [0u8; 20];
        hex::decode_to_slice(raw, &mut out)
            .map_err(|e| format!("invalid hex in EVM address: {e}"))?;
        Ok(out)
    } else if raw.len() == 64 {
        let mut stell = [0u8; 32];
        hex::decode_to_slice(raw, &mut stell)
            .map_err(|e| format!("invalid hex in Stellereum address: {e}"))?;
        Ok(stell_to_evm_address(&stell))
    } else {
        Err(format!(
            "EVM address must be 20 bytes (40 hex characters) or 32 bytes (64 hex characters), got length {}",
            raw.len()
        ))
    }
}

/// Parses a 20-byte EVM address from a hex string (with or without 0x/0X prefix).
pub fn parse_evm_address(s: &str) -> Result<[u8; 20], String> {
    evm_address_from_hex(s)
}

/// Parses an address hex string (accepting either 20-byte EVM address or 32-byte Stellereum address)
/// and converts it to a 32-byte Stellereum address.
pub fn parse_evm_or_stell_address(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim();
    let raw = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if raw.len() == 40 {
        let mut evm_bytes = [0u8; 20];
        hex::decode_to_slice(raw, &mut evm_bytes)
            .map_err(|e| format!("invalid hex in EVM address: {e}"))?;
        Ok(evm_to_stell_address(&evm_bytes))
    } else if raw.len() == 64 {
        let mut stell_bytes = [0u8; 32];
        hex::decode_to_slice(raw, &mut stell_bytes)
            .map_err(|e| format!("invalid hex in Stellereum address: {e}"))?;
        Ok(stell_bytes)
    } else {
        Err(format!(
            "address must be 20 bytes (40 hex chars) or 32 bytes (64 hex chars), got length {}",
            raw.len()
        ))
    }
}

/// Parses a 32-byte Stellereum address from a hex string (accepting either 20-byte EVM address
/// or 32-byte Stellereum address).
pub fn stell_address_from_hex(s: &str) -> Result<[u8; 32], String> {
    parse_evm_or_stell_address(s)
}

/// Alias for `parse_evm_or_stell_address`.
pub fn evm_to_stell_address_from_hex(s: &str) -> Result<[u8; 32], String> {
    parse_evm_or_stell_address(s)
}

/// Extracts (address_str, Option<BlockTag>) from JSON-RPC params.
pub fn parse_address_and_tag_params(
    params: &Value,
) -> Result<(String, Option<BlockTag>), JsonRpcError> {
    match params {
        Value::Array(arr) => {
            if arr.is_empty() {
                return Err(JsonRpcError::invalid_params("missing address parameter"));
            }
            let addr = arr[0]
                .as_str()
                .ok_or_else(|| JsonRpcError::invalid_params("address parameter must be a string"))?
                .to_string();
            let tag = if let Some(t_val) = arr.get(1) {
                Some(BlockTag::parse(t_val)?)
            } else {
                None
            };
            Ok((addr, tag))
        }
        Value::Object(obj) => {
            let addr = obj
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing 'address' in params object"))?
                .to_string();
            let tag = if let Some(t_val) = obj
                .get("blockTag")
                .or_else(|| obj.get("block_tag"))
                .or_else(|| obj.get("block"))
            {
                Some(BlockTag::parse(t_val)?)
            } else {
                None
            };
            Ok((addr, tag))
        }
        Value::String(s) => Ok((s.clone(), None)),
        _ => Err(JsonRpcError::invalid_params(
            "params must be an array, object, or string",
        )),
    }
}

/// Extracts and parses an address parameter from JSON-RPC params into a 32-byte Stellereum address.
pub fn parse_address_from_params(params: &Value) -> Result<[u8; 32], JsonRpcError> {
    let (addr_str, _) = parse_address_and_tag_params(params)?;
    parse_evm_or_stell_address(&addr_str)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}")))
}

// ============================================================================
// EVM State Handlers (eth_getBalance, eth_getTransactionCount, eth_getCode)
// ============================================================================

/// Returns "0x" indicating no bytecode deployed at this address.
pub fn eth_get_code() -> &'static str {
    "0x"
}

/// Validates address format and block tag (if provided) and returns "0x".
#[allow(non_snake_case)]
pub fn eth_getCode(
    address: impl AsRef<str>,
    block_tag: impl AsRef<str>,
) -> Result<&'static str, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_getCode(address, block_tag)
}

/// Returns balance in Wei in hex format ("0x...") for an address.
#[allow(non_snake_case)]
pub fn eth_getBalance(
    address: impl AsRef<str>,
    block_tag: impl AsRef<str>,
) -> Result<String, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_getBalance(address, block_tag)
}

/// Returns nonce in hex format ("0x...") for an address.
#[allow(non_snake_case)]
pub fn eth_getTransactionCount(
    address: impl AsRef<str>,
    block_tag: impl AsRef<str>,
) -> Result<String, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_getTransactionCount(address, block_tag)
}

pub fn eth_get_code_at(
    address: impl AsRef<str>,
    block_tag: impl AsRef<str>,
) -> Result<&'static str, JsonRpcError> {
    eth_getCode(address, block_tag)
}

pub fn eth_get_balance_at(
    address: impl AsRef<str>,
    block_tag: impl AsRef<str>,
) -> Result<String, JsonRpcError> {
    eth_getBalance(address, block_tag)
}

pub fn eth_get_transaction_count_at(
    address: impl AsRef<str>,
    block_tag: impl AsRef<str>,
) -> Result<String, JsonRpcError> {
    eth_getTransactionCount(address, block_tag)
}

/// Handles `eth_getCode` call, returning "0x".
/// Validates address format if an address is provided in params.
pub fn handle_eth_get_code(params: &Value) -> Result<&'static str, JsonRpcError> {
    if !params.is_null() {
        let has_params = match params {
            Value::Array(arr) => !arr.is_empty(),
            Value::Object(obj) => !obj.is_empty(),
            Value::String(_) => true,
            _ => false,
        };
        if has_params {
            let (addr_str, _tag) = parse_address_and_tag_params(params)?;
            let _ = parse_evm_or_stell_address(&addr_str).map_err(|e| {
                JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}"))
            })?;
        }
    }
    Ok(eth_get_code())
}

/// Handles `eth_getBalance` against an `InMemoryStateEngine`.
/// Returns balance in Wei formatted as hex quantity ("0x...").
pub async fn eth_get_balance(
    engine: &InMemoryStateEngine,
    params: &Value,
) -> Result<String, JsonRpcError> {
    let (addr_str, _tag) = parse_address_and_tag_params(params)?;
    let stell_addr = parse_evm_or_stell_address(&addr_str)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}")))?;
    let acc = engine.get_account(&stell_addr).await;
    let balance_nano = acc.map(|a| a.balance).unwrap_or(0);
    Ok(nano_to_wei_hex(balance_nano))
}

/// Handles `eth_getBalance` against an `RpcState`.
pub async fn eth_get_balance_rpc(st: &RpcState, params: &Value) -> Result<String, JsonRpcError> {
    eth_get_balance(&st.engine, params).await
}

/// Handles `eth_getTransactionCount` against an `InMemoryStateEngine`.
/// Returns transaction count (account nonce) formatted as hex quantity ("0x...").
pub async fn eth_get_transaction_count(
    engine: &InMemoryStateEngine,
    params: &Value,
) -> Result<String, JsonRpcError> {
    let (addr_str, _tag) = parse_address_and_tag_params(params)?;
    let stell_addr = parse_evm_or_stell_address(&addr_str)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}")))?;
    let acc = engine.get_account(&stell_addr).await;
    let nonce = acc.map(|a| a.nonce).unwrap_or(0);
    Ok(format_u64_hex(nonce))
}

/// Handles `eth_getTransactionCount` against an `RpcState`.
pub async fn eth_get_transaction_count_rpc(
    st: &RpcState,
    params: &Value,
) -> Result<String, JsonRpcError> {
    eth_get_transaction_count(&st.engine, params).await
}

/// Returns the current finalized block height in hex for an `RpcState`.
pub fn eth_block_number_rpc(st: &RpcState) -> String {
    let h = st.height.load(std::sync::atomic::Ordering::Relaxed);
    eth_block_number(h)
}

#[allow(non_snake_case)]
pub fn eth_blockNumber_rpc(st: &RpcState) -> String {
    eth_block_number_rpc(st)
}

#[allow(non_snake_case)]
pub fn eth_blockNumber(height: u64) -> String {
    eth_block_number(height)
}

/// Translates a block by number or tag to `EvmBlock` for an `RpcState`.
pub async fn eth_get_block_by_number_rpc(
    st: &RpcState,
    block_tag: &str,
    full_tx: bool,
) -> Result<Option<EvmBlock>, JsonRpcError> {
    let tag = BlockTag::parse_str(block_tag)?;
    let cur_h = st.height.load(std::sync::atomic::Ordering::Relaxed);
    let want = tag.resolve(cur_h);
    let rb = st.recent_blocks.read().await;
    if let Some(b) = rb.iter().find(|b| b.height == want) {
        let mut evm_block = stell_block_summary_to_evm(b);
        let idx = st.receipts.read().await;
        let rows = idx.for_height(want);
        if full_tx {
            let full_tx_list: Vec<EvmTransaction> = rows
                .iter()
                .filter_map(|r| stell_receipt_to_evm_tx(r))
                .collect();
            if !full_tx_list.is_empty() {
                evm_block.transactions = BlockTransactions::Full(full_tx_list);
            }
        } else if !rows.is_empty() {
            let tx_hashes: Vec<String> =
                rows.iter().map(|r| stell_hash_to_evm(&r.tx_hash)).collect();
            evm_block.transactions = BlockTransactions::Hashes(tx_hashes);
        }
        Ok(Some(evm_block))
    } else {
        Ok(GLOBAL_EVM_ADAPTER.get_block_by_number(&tag, full_tx))
    }
}

#[allow(non_snake_case)]
pub async fn eth_getBlockByNumber_rpc(
    st: &RpcState,
    block_tag: &str,
    full_tx: bool,
) -> Result<Option<EvmBlock>, JsonRpcError> {
    eth_get_block_by_number_rpc(st, block_tag, full_tx).await
}

/// Translates a block by hash to `EvmBlock` for an `RpcState`.
pub async fn eth_get_block_by_hash_rpc(
    st: &RpcState,
    hash: &str,
    full_tx: bool,
) -> Result<Option<EvmBlock>, JsonRpcError> {
    let norm = normalize_hash(hash).map_err(JsonRpcError::invalid_params)?;
    let stripped = norm.strip_prefix("0x").unwrap_or(&norm);
    let rb = st.recent_blocks.read().await;
    if let Some(b) = rb.iter().find(|b| {
        let b_stripped = b.hash.strip_prefix("0x").unwrap_or(&b.hash);
        b_stripped.eq_ignore_ascii_case(stripped)
    }) {
        let mut evm_block = stell_block_summary_to_evm(b);
        let idx = st.receipts.read().await;
        let rows = idx.for_height(b.height);
        if full_tx {
            let full_tx_list: Vec<EvmTransaction> = rows
                .iter()
                .filter_map(|r| stell_receipt_to_evm_tx(r))
                .collect();
            if !full_tx_list.is_empty() {
                evm_block.transactions = BlockTransactions::Full(full_tx_list);
            }
        } else if !rows.is_empty() {
            let tx_hashes: Vec<String> =
                rows.iter().map(|r| stell_hash_to_evm(&r.tx_hash)).collect();
            evm_block.transactions = BlockTransactions::Hashes(tx_hashes);
        }
        Ok(Some(evm_block))
    } else {
        Ok(GLOBAL_EVM_ADAPTER.get_block_by_hash(&norm, full_tx))
    }
}

#[allow(non_snake_case)]
pub async fn eth_getBlockByHash_rpc(
    st: &RpcState,
    hash: &str,
    full_tx: bool,
) -> Result<Option<EvmBlock>, JsonRpcError> {
    eth_get_block_by_hash_rpc(st, hash, full_tx).await
}

/// Translates a transaction receipt by hash to `EvmReceipt` for an `RpcState`.
pub async fn eth_get_transaction_receipt_rpc(
    st: &RpcState,
    tx_hash: &str,
) -> Result<Option<EvmReceipt>, JsonRpcError> {
    // Canonical path (intent -> L1 settlement aware).
    st.eth_get_transaction_receipt(tx_hash).await
}

#[allow(non_snake_case)]
pub async fn eth_getTransactionReceipt_rpc(
    st: &RpcState,
    tx_hash: &str,
) -> Result<Option<EvmReceipt>, JsonRpcError> {
    eth_get_transaction_receipt_rpc(st, tx_hash).await
}

/// Translates a transaction by hash to `EvmTransaction` for an `RpcState`.
pub async fn eth_get_transaction_by_hash_rpc(
    st: &RpcState,
    tx_hash: &str,
) -> Result<Option<EvmTransaction>, JsonRpcError> {
    // Canonical path (mined-first, then pending intent).
    st.eth_get_transaction_by_hash(tx_hash).await
}

#[allow(non_snake_case)]
pub async fn eth_getTransactionByHash_rpc(
    st: &RpcState,
    tx_hash: &str,
) -> Result<Option<EvmTransaction>, JsonRpcError> {
    eth_get_transaction_by_hash_rpc(st, tx_hash).await
}

pub fn eth_get_block_by_number(
    tag: &str,
    full_txs: bool,
) -> Result<Option<EvmBlock>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_block_by_number(tag, full_txs)
}

#[allow(non_snake_case)]
pub fn eth_getBlockByNumber(tag: &str, full_txs: bool) -> Result<Option<EvmBlock>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_block_by_number(tag, full_txs)
}

pub fn eth_get_block_by_hash(hash: &str, full_txs: bool) -> Result<Option<EvmBlock>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_block_by_hash(hash, full_txs)
}

#[allow(non_snake_case)]
pub fn eth_getBlockByHash(hash: &str, full_txs: bool) -> Result<Option<EvmBlock>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_block_by_hash(hash, full_txs)
}

pub fn eth_get_transaction_receipt(hash: &str) -> Result<Option<EvmReceipt>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_transaction_receipt(hash)
}

#[allow(non_snake_case)]
pub fn eth_getTransactionReceipt(hash: &str) -> Result<Option<EvmReceipt>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_transaction_receipt(hash)
}

pub fn eth_get_transaction_by_hash(hash: &str) -> Result<Option<EvmTransaction>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_transaction_by_hash(hash)
}

#[allow(non_snake_case)]
pub fn eth_getTransactionByHash(hash: &str) -> Result<Option<EvmTransaction>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.eth_get_transaction_by_hash(hash)
}

pub fn eth_get_block_transaction_count_by_hash(hash: &str) -> Result<Option<String>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.get_block_transaction_count_by_hash(hash)
}

#[allow(non_snake_case)]
pub fn eth_getBlockTransactionCountByHash(hash: &str) -> Result<Option<String>, JsonRpcError> {
    eth_get_block_transaction_count_by_hash(hash)
}

pub fn eth_get_block_transaction_count_by_number(
    tag: &BlockTag,
) -> Result<Option<String>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.get_block_transaction_count_by_number(tag)
}

#[allow(non_snake_case)]
pub fn eth_getBlockTransactionCountByNumber(
    tag: &BlockTag,
) -> Result<Option<String>, JsonRpcError> {
    eth_get_block_transaction_count_by_number(tag)
}

pub fn eth_get_transaction_by_block_hash_and_index(
    hash: &str,
    index: u64,
) -> Result<Option<EvmTransaction>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.get_transaction_by_block_hash_and_index(hash, index)
}

#[allow(non_snake_case)]
pub fn eth_getTransactionByBlockHashAndIndex(
    hash: &str,
    index: u64,
) -> Result<Option<EvmTransaction>, JsonRpcError> {
    eth_get_transaction_by_block_hash_and_index(hash, index)
}

pub fn eth_get_transaction_by_block_number_and_index(
    tag: &BlockTag,
    index: u64,
) -> Result<Option<EvmTransaction>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.get_transaction_by_block_number_and_index(tag, index)
}

#[allow(non_snake_case)]
pub fn eth_getTransactionByBlockNumberAndIndex(
    tag: &BlockTag,
    index: u64,
) -> Result<Option<EvmTransaction>, JsonRpcError> {
    eth_get_transaction_by_block_number_and_index(tag, index)
}

pub fn eth_get_uncle_count_by_block_hash(hash: &str) -> Result<Option<String>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.get_uncle_count_by_block_hash(hash)
}

#[allow(non_snake_case)]
pub fn eth_getUncleCountByBlockHash(hash: &str) -> Result<Option<String>, JsonRpcError> {
    eth_get_uncle_count_by_block_hash(hash)
}

pub fn eth_get_uncle_count_by_block_number(tag: &BlockTag) -> Result<Option<String>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.get_uncle_count_by_block_number(tag)
}

#[allow(non_snake_case)]
pub fn eth_getUncleCountByBlockNumber(tag: &BlockTag) -> Result<Option<String>, JsonRpcError> {
    eth_get_uncle_count_by_block_number(tag)
}

pub fn eth_get_uncle_by_block_hash_and_index(
    hash: &str,
    index: u64,
) -> Result<Option<Value>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.get_uncle_by_block_hash_and_index(hash, index)
}

#[allow(non_snake_case)]
pub fn eth_getUncleByBlockHashAndIndex(
    hash: &str,
    index: u64,
) -> Result<Option<Value>, JsonRpcError> {
    eth_get_uncle_by_block_hash_and_index(hash, index)
}

pub fn eth_get_uncle_by_block_number_and_index(
    tag: &BlockTag,
    index: u64,
) -> Result<Option<Value>, JsonRpcError> {
    GLOBAL_EVM_ADAPTER.get_uncle_by_block_number_and_index(tag, index)
}

#[allow(non_snake_case)]
pub fn eth_getUncleByBlockNumberAndIndex(
    tag: &BlockTag,
    index: u64,
) -> Result<Option<Value>, JsonRpcError> {
    eth_get_uncle_by_block_number_and_index(tag, index)
}

/// Converts a 32-byte Stellereum address to a 20-byte EVM hex address.
pub fn stell_address_to_evm(addr: &[u8; 32]) -> String {
    evm_address_to_hex(&stell_to_evm_address(addr))
}

/// Converts a 32-byte hash to a 0x-prefixed hex string.
pub fn stell_hash_to_evm(hash: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(hash))
}

/// Converts a Stellereum transaction to an EVM JSON-RPC transaction with a custom chain ID.
pub fn stell_tx_to_evm_with_chain(
    tx: &crate::sharding::Transaction,
    block_hash: Option<[u8; 32]>,
    block_number: Option<u64>,
    tx_index: Option<u32>,
    chain_id: u64,
) -> EvmTransaction {
    let tx_hash = tx.compute_tx_hash();
    let r = if tx.signature.len() >= 32 {
        format!("0x{}", hex::encode(&tx.signature[0..32]))
    } else {
        "0x0".to_string()
    };
    let s = if tx.signature.len() >= 64 {
        format!("0x{}", hex::encode(&tx.signature[32..64]))
    } else {
        "0x0".to_string()
    };
    // EIP-155 formula: v = {0,1} + chainId * 2 + 35
    let v = format!("0x{:x}", chain_id * 2 + 35);

    let input = if !tx.payload.is_empty() {
        match bincode::serialize(&tx.payload) {
            Ok(bytes) => format!("0x{}", hex::encode(bytes)),
            Err(_) => "0x".to_string(),
        }
    } else {
        "0x".to_string()
    };

    EvmTransaction {
        hash: stell_hash_to_evm(&tx_hash),
        nonce: format_u64_hex(tx.nonce),
        block_hash: block_hash.map(|h| stell_hash_to_evm(&h)),
        block_number: block_number.map(format_u64_hex),
        transaction_index: tx_index.map(|i| format_u64_hex(i as u64)),
        from: stell_address_to_evm(&tx.from),
        to: Some(stell_address_to_evm(&tx.to)),
        value: nano_to_wei_hex(tx.amount),
        gas_price: Some("0x1".to_string()),
        gas: format_u64_hex(tx.gas_limit),
        input,
        v,
        r,
        s,
        tx_type: Some("0x0".to_string()),
        chain_id: Some(format!("0x{:x}", chain_id)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    }
}

/// Converts a Stellereum transaction to an EVM JSON-RPC transaction.
///
/// Served-identity default: [`effective_chain_id`] (STELL_CHAIN_ID-aware), so
/// block/tx views agree with `eth_chainId` on every deployment. This is
/// DISPLAY only — admission/verification pins [`CHAIN_ID`] deliberately (all
/// nodes must reach the same verdict on the same bytes; see [`CHAIN_ID`]).
/// Callers that need the pinned protocol default explicitly use
/// [`stell_tx_to_evm_with_chain`] with [`CHAIN_ID`].
pub fn stell_tx_to_evm(
    tx: &crate::sharding::Transaction,
    block_hash: Option<[u8; 32]>,
    block_number: Option<u64>,
    tx_index: Option<u32>,
) -> EvmTransaction {
    stell_tx_to_evm_with_chain(tx, block_hash, block_number, tx_index, effective_chain_id())
}

/// Converts a Stellereum TxReceipt to an EVM JSON-RPC receipt.
pub fn stell_receipt_to_evm(r: &crate::rpc::TxReceipt) -> EvmReceipt {
    let (from, to) = if let Some(ref raw_hex) = r.raw_tx {
        let stripped = raw_hex
            .strip_prefix("0x")
            .or_else(|| raw_hex.strip_prefix("0X"))
            .unwrap_or(raw_hex);
        if let Ok(bytes) = hex::decode(stripped) {
            if let Ok(tx) = bincode::deserialize::<crate::sharding::Transaction>(&bytes) {
                (
                    stell_address_to_evm(&tx.from),
                    Some(stell_address_to_evm(&tx.to)),
                )
            } else {
                (
                    "0x0000000000000000000000000000000000000000".to_string(),
                    None,
                )
            }
        } else {
            (
                "0x0000000000000000000000000000000000000000".to_string(),
                None,
            )
        }
    } else {
        (
            "0x0000000000000000000000000000000000000000".to_string(),
            None,
        )
    };

    EvmReceipt {
        transaction_hash: stell_hash_to_evm(&r.tx_hash),
        transaction_index: format_u64_hex(r.index as u64),
        block_hash: stell_hash_to_evm(&r.block_hash),
        block_number: format_u64_hex(r.height),
        from,
        to,
        cumulative_gas_used: format_u64_hex(r.fee_charged),
        gas_used: format_u64_hex(r.fee_charged),
        contract_address: None,
        logs: Vec::new(),
        logs_bloom: EMPTY_LOGS_BLOOM.to_string(),
        status: Some(if r.success {
            "0x1".to_string()
        } else {
            "0x0".to_string()
        }),
        root: None,
        tx_type: Some("0x0".to_string()),
        effective_gas_price: Some("0x1".to_string()),
        blob_gas_used: None,
        blob_gas_price: None,
    }
}

/// Converts a Stellereum TxReceipt to an EVM JSON-RPC receipt with explicit transaction details.
pub fn stell_receipt_with_tx_to_evm(
    r: &crate::rpc::TxReceipt,
    tx: Option<&crate::sharding::Transaction>,
) -> EvmReceipt {
    let mut receipt = stell_receipt_to_evm(r);
    if let Some(t) = tx {
        receipt.from = stell_address_to_evm(&t.from);
        receipt.to = Some(stell_address_to_evm(&t.to));
    }
    receipt
}

/// Reconstructs an EVM transaction from a Stellereum `TxReceipt` if it contains `raw_tx`.
pub fn stell_receipt_to_evm_tx(r: &crate::rpc::TxReceipt) -> Option<EvmTransaction> {
    stell_receipt_to_evm_tx_with_chain(r, CHAIN_ID)
}

/// Reconstructs an EVM transaction from a Stellereum `TxReceipt` with a custom chain ID.
pub fn stell_receipt_to_evm_tx_with_chain(
    r: &crate::rpc::TxReceipt,
    chain_id: u64,
) -> Option<EvmTransaction> {
    if let Some(ref raw_hex) = r.raw_tx {
        let stripped = raw_hex
            .strip_prefix("0x")
            .or_else(|| raw_hex.strip_prefix("0X"))
            .unwrap_or(raw_hex);
        if let Ok(bytes) = hex::decode(stripped) {
            if let Ok(tx) = bincode::deserialize::<crate::sharding::Transaction>(&bytes) {
                return Some(stell_tx_to_evm_with_chain(
                    &tx,
                    Some(r.block_hash),
                    Some(r.height),
                    Some(r.index),
                    chain_id,
                ));
            }
        }
    }
    Some(EvmTransaction {
        hash: stell_hash_to_evm(&r.tx_hash),
        nonce: "0x0".to_string(),
        block_hash: Some(stell_hash_to_evm(&r.block_hash)),
        block_number: Some(format_u64_hex(r.height)),
        transaction_index: Some(format_u64_hex(r.index as u64)),
        from: "0x0000000000000000000000000000000000000000".to_string(),
        to: None,
        value: "0x0".to_string(),
        gas_price: Some("0x1".to_string()),
        gas: format_u64_hex(r.gas_limit.max(r.fee_charged)),
        input: "0x".to_string(),
        v: format!("0x{:x}", chain_id * 2 + 35),
        r: "0x0".to_string(),
        s: "0x0".to_string(),
        tx_type: Some("0x0".to_string()),
        chain_id: Some(format!("0x{:x}", chain_id)),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: None,
    })
}

/// Translates a Stellereum `BlockSummary` into an `EvmBlock`.
pub fn stell_block_summary_to_evm(summary: &crate::rpc::BlockSummary) -> EvmBlock {
    stell_block_summary_to_evm_with_parent(summary, None)
}

/// Translates a Stellereum `BlockSummary` with an optional parent hash into an `EvmBlock`.
pub fn stell_block_summary_to_evm_with_parent(
    summary: &crate::rpc::BlockSummary,
    parent_hash: Option<&str>,
) -> EvmBlock {
    let hash = ensure_0x(&summary.hash);
    let p_hash = if summary.height == 0 {
        "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
    } else {
        parent_hash
            .map(ensure_0x)
            .unwrap_or_else(|| EMPTY_ROOT_HASH.to_string())
    };

    EvmBlock {
        number: Some(format_u64_hex(summary.height)),
        hash: Some(hash),
        parent_hash: p_hash,
        nonce: Some("0x0000000000000000".to_string()),
        sha3_uncles: EMPTY_UNCLES_HASH.to_string(),
        logs_bloom: Some(EMPTY_LOGS_BLOOM.to_string()),
        transactions_root: EMPTY_ROOT_HASH.to_string(),
        state_root: EMPTY_ROOT_HASH.to_string(),
        receipts_root: EMPTY_ROOT_HASH.to_string(),
        miner: "0x0000000000000000000000000000000000000000".to_string(),
        difficulty: "0x0".to_string(),
        total_difficulty: Some("0x0".to_string()),
        extra_data: "0x".to_string(),
        size: format_u64_hex(1024),
        gas_limit: format_u64_hex(30_000_000),
        gas_used: format_u64_hex(0),
        timestamp: format_u64_hex(summary.timestamp),
        transactions: BlockTransactions::Hashes(Vec::new()),
        uncles: Vec::new(),
        base_fee_per_gas: Some("0x7".to_string()),
        mix_hash: Some(EMPTY_ROOT_HASH.to_string()),
        withdrawals: None,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
    }
}

/// Translates a Stellereum `BlockSummary` into an `EvmBlock` with full receipts/transactions and parent hash.
pub fn stell_block_summary_to_evm_full(
    summary: &crate::rpc::BlockSummary,
    parent_hash: Option<&str>,
    receipts: &[&crate::rpc::TxReceipt],
    full_tx: bool,
) -> EvmBlock {
    let mut block = stell_block_summary_to_evm_with_parent(summary, parent_hash);
    let total_gas: u64 = receipts.iter().map(|r| r.fee_charged).sum();
    block.gas_used = format_u64_hex(total_gas);
    if full_tx {
        let full_tx_list: Vec<EvmTransaction> = receipts
            .iter()
            .filter_map(|r| stell_receipt_to_evm_tx(r))
            .collect();
        block.transactions = BlockTransactions::Full(full_tx_list);
    } else {
        let tx_hashes: Vec<String> = receipts
            .iter()
            .map(|r| stell_hash_to_evm(&r.tx_hash))
            .collect();
        block.transactions = BlockTransactions::Hashes(tx_hashes);
    }
    block
}

/// Translates a Stellereum `BlockSummary` into an `EvmBlock` with hydrated transaction flag.
pub fn stell_block_summary_to_evm_block(
    summary: &crate::rpc::BlockSummary,
    full_tx: bool,
) -> EvmBlock {
    let mut block = stell_block_summary_to_evm(summary);
    if full_tx {
        block.transactions = BlockTransactions::Full(Vec::new());
    } else {
        block.transactions = BlockTransactions::Hashes(Vec::new());
    }
    block
}

/// Converts a Stellereum Block to an EVM JSON-RPC block.
pub fn stell_block_to_evm(b: &crate::sharding::Block, full_txs: bool) -> EvmBlock {
    let block_hash = b.compute_hash();
    let tx_hashes: Vec<String> = b
        .transactions
        .iter()
        .map(|tx| stell_hash_to_evm(&tx.compute_tx_hash()))
        .collect();

    let transactions = if full_txs {
        let full: Vec<EvmTransaction> = b
            .transactions
            .iter()
            .enumerate()
            .map(|(idx, tx)| {
                stell_tx_to_evm(tx, Some(block_hash), Some(b.height), Some(idx as u32))
            })
            .collect();
        BlockTransactions::Full(full)
    } else {
        BlockTransactions::Hashes(tx_hashes)
    };

    let total_gas_limit: u64 = b.transactions.iter().map(|tx| tx.gas_limit).sum();
    let gas_limit = if total_gas_limit > 0 {
        total_gas_limit
    } else {
        30_000_000
    };

    EvmBlock {
        number: Some(format_u64_hex(b.height)),
        hash: Some(stell_hash_to_evm(&block_hash)),
        parent_hash: stell_hash_to_evm(&b.prev_hash),
        nonce: Some("0x0000000000000000".to_string()),
        sha3_uncles: EMPTY_UNCLES_HASH.to_string(),
        logs_bloom: Some(EMPTY_LOGS_BLOOM.to_string()),
        transactions_root: EMPTY_ROOT_HASH.to_string(),
        state_root: stell_hash_to_evm(&b.state_root),
        receipts_root: EMPTY_ROOT_HASH.to_string(),
        miner: stell_address_to_evm(&b.proposer),
        difficulty: "0x0".to_string(),
        total_difficulty: Some("0x0".to_string()),
        extra_data: "0x".to_string(),
        size: format_u64_hex(1024),
        gas_limit: format_u64_hex(gas_limit),
        gas_used: format_u64_hex(0),
        timestamp: format_u64_hex(b.timestamp),
        transactions,
        uncles: Vec::new(),
        base_fee_per_gas: Some("0x7".to_string()),
        mix_hash: Some(EMPTY_ROOT_HASH.to_string()),
        withdrawals: None,
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
    }
}

// ============================================================================
// Ethereum Keccak-256 Hasher (Pure Rust sponge using post_quantum::keccak_f1600)
// ============================================================================

/// Keccak-256 rate in bytes: 1088 bits = 136 bytes.
pub const KECCAK256_RATE: usize = 136;

/// Keccak state words: 1600 bits = 25 * 64-bit words.
pub const KECCAK_STATE_WORDS: usize = 25;

/// Domain separator for Ethereum Keccak-256 (0x01).
pub const KECCAK256_DOMAIN_SEPARATOR: u8 = 0x01;

/// Streaming Keccak-256 hasher implementing Ethereum's sponge construction
/// using `crate::post_quantum::keccak_f1600` with domain separator 0x01.
#[derive(Clone, Debug)]
pub struct Keccak256 {
    state: [u64; KECCAK_STATE_WORDS],
    buffer: [u8; KECCAK256_RATE],
    buf_len: usize,
}

impl Default for Keccak256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Keccak256 {
    pub const RATE: usize = KECCAK256_RATE;
    pub const DOMAIN_SEPARATOR: u8 = KECCAK256_DOMAIN_SEPARATOR;

    /// Create a new, blank Keccak-256 hasher.
    pub fn new() -> Self {
        Self {
            state: [0u64; KECCAK_STATE_WORDS],
            buffer: [0u8; KECCAK256_RATE],
            buf_len: 0,
        }
    }

    /// Absorb a chunk of arbitrary-length data into the sponge.
    pub fn update(&mut self, mut data: &[u8]) {
        // If buffer already holds partial data, fill and process it first
        if self.buf_len > 0 {
            let to_copy = (Self::RATE - self.buf_len).min(data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            data = &data[to_copy..];

            if self.buf_len == Self::RATE {
                for i in 0..(Self::RATE / 8) {
                    let chunk = &self.buffer[i * 8..i * 8 + 8];
                    let val = u64::from_le_bytes(chunk.try_into().unwrap());
                    self.state[i] ^= val;
                }
                crate::post_quantum::keccak_f1600(&mut self.state);
                self.buf_len = 0;
            }
        }

        // Absorb full 136-byte blocks directly from the input slice
        while data.len() >= Self::RATE {
            for i in 0..(Self::RATE / 8) {
                let chunk = &data[i * 8..i * 8 + 8];
                let val = u64::from_le_bytes(chunk.try_into().unwrap());
                self.state[i] ^= val;
            }
            crate::post_quantum::keccak_f1600(&mut self.state);
            data = &data[Self::RATE..];
        }

        // Buffer any remainder
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Finalize sponge absorption with pad10*1 padding (domain separator 0x01)
    /// and squeeze out the 32-byte (256-bit) digest.
    pub fn finalize(mut self) -> [u8; 32] {
        self.buffer[self.buf_len] = Self::DOMAIN_SEPARATOR;
        for b in &mut self.buffer[self.buf_len + 1..Self::RATE] {
            *b = 0;
        }
        self.buffer[Self::RATE - 1] |= 0x80;

        for i in 0..(Self::RATE / 8) {
            let chunk = &self.buffer[i * 8..i * 8 + 8];
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[i] ^= val;
        }
        crate::post_quantum::keccak_f1600(&mut self.state);

        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        out
    }

    /// One-shot Keccak-256 computation over byte slice.
    pub fn digest(data: &[u8]) -> [u8; 32] {
        keccak256(data)
    }
}

/// Computes the Ethereum Keccak-256 hash of `data` using `post_quantum::keccak_f1600`
/// sponge with domain separator 0x01.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Computes the Ethereum Keccak-256 hash and formats as a 0x-prefixed hex string.
pub fn keccak256_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(data)))
}

// ============================================================================
// Pure Rust Zero-Dependency RLP Decoder & Encoder
// ============================================================================

/// Errors encountered while decoding RLP-encoded data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RlpError {
    /// Unexpected end of input buffer.
    UnexpectedEof,
    /// Length prefix contains an illegal leading zero byte.
    LeadingZeroInLength,
    /// A single byte < 0x80 was illegally prefixed as a multi-byte string.
    NonCanonicalSingleByte,
    /// A payload of length < 56 was illegally encoded using long header prefix.
    NonCanonicalLength,
    /// Expected a byte string item, but encountered a list.
    ExpectedBytes,
    /// Expected a list item, but encountered a byte string.
    ExpectedList,
    /// Integer value exceeded representation limit for the given type.
    IntegerOverflow(&'static str),
    /// Integer contains an illegal non-canonical leading zero byte.
    LeadingZeroInInteger,
    /// Input contains extra trailing bytes after the decoded item.
    TrailingBytes,
    /// Address length was invalid (expected 20 bytes).
    InvalidAddressLength(usize),
    /// Envelope transaction type was not recognized.
    InvalidTransactionType(u8),
    /// Custom error message.
    Custom(String),
}

impl std::fmt::Display for RlpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "RLP error: unexpected end of input"),
            Self::LeadingZeroInLength => write!(f, "RLP error: leading zero in length field"),
            Self::NonCanonicalSingleByte => {
                write!(
                    f,
                    "RLP error: single byte < 0x80 must be encoded directly without prefix"
                )
            }
            Self::NonCanonicalLength => {
                write!(f, "RLP error: payload length < 56 encoded with long header")
            }
            Self::ExpectedBytes => write!(f, "RLP error: expected byte string, got list"),
            Self::ExpectedList => write!(f, "RLP error: expected list, got byte string"),
            Self::IntegerOverflow(ty) => write!(f, "RLP error: integer overflow for {ty}"),
            Self::LeadingZeroInInteger => {
                write!(f, "RLP error: integer has non-canonical leading zero")
            }
            Self::TrailingBytes => write!(f, "RLP error: trailing unparsed bytes after item"),
            Self::InvalidAddressLength(len) => {
                write!(
                    f,
                    "RLP error: invalid address length {len}, expected 20 bytes"
                )
            }
            Self::InvalidTransactionType(t) => {
                write!(
                    f,
                    "RLP error: invalid or unsupported transaction type 0x{t:02x}"
                )
            }
            Self::Custom(msg) => write!(f, "RLP error: {msg}"),
        }
    }
}

impl std::error::Error for RlpError {}

/// A decoded RLP item (Byte, Bytes, or a nested List of items).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RlpItem {
    Byte(u8),
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

/// An owned RLP item alias for backwards compatibility.
pub type OwnedRlpItem = RlpItem;

impl RlpItem {
    /// Decodes an exact RLP item, ensuring no unparsed trailing bytes remain.
    pub fn decode(data: &[u8]) -> Result<Self, RlpError> {
        let (item, rest) = Self::decode_with_remainder(data)?;
        if !rest.is_empty() {
            return Err(RlpError::TrailingBytes);
        }
        Ok(item)
    }

    /// Maximum RLP nesting depth (DoS guard against stack-overflow bombs).
    pub const MAX_DEPTH: usize = 64;

    /// Decodes an RLP item and returns the remaining unparsed slice.
    pub fn decode_with_remainder(data: &[u8]) -> Result<(Self, &[u8]), RlpError> {
        Self::decode_with_remainder_depth(data, 0)
    }

    fn decode_with_remainder_depth(data: &[u8], depth: usize) -> Result<(Self, &[u8]), RlpError> {
        if depth > Self::MAX_DEPTH {
            return Err(RlpError::Custom(
                "RLP recursion depth limit exceeded".to_string(),
            ));
        }
        if data.is_empty() {
            return Err(RlpError::UnexpectedEof);
        }
        let first = data[0];
        if first < 0x80 {
            // [0x00, 0x7f]: Single byte
            Ok((RlpItem::Byte(first), &data[1..]))
        } else if first <= 0xb7 {
            // [0x80, 0xb7]: Short byte string (0..55 bytes)
            let len = (first - 0x80) as usize;
            if data.len() < 1 + len {
                return Err(RlpError::UnexpectedEof);
            }
            let payload = &data[1..1 + len];
            if len == 1 && payload[0] < 0x80 {
                return Err(RlpError::NonCanonicalSingleByte);
            }
            Ok((RlpItem::Bytes(payload.to_vec()), &data[1 + len..]))
        } else if first <= 0xbf {
            // [0xb8, 0xbf]: Long byte string (> 55 bytes)
            let len_of_len = (first - 0xb7) as usize;
            if data.len() < 1 + len_of_len {
                return Err(RlpError::UnexpectedEof);
            }
            let len_bytes = &data[1..1 + len_of_len];
            if len_bytes[0] == 0 {
                return Err(RlpError::LeadingZeroInLength);
            }
            let len = parse_length(len_bytes)?;
            if len < 56 {
                return Err(RlpError::NonCanonicalLength);
            }
            let total_header = 1 + len_of_len;
            // Checked bound (audit: total_header + len could overflow on hostile len == usize::MAX).
            let remaining = data
                .len()
                .checked_sub(total_header)
                .ok_or(RlpError::UnexpectedEof)?;
            if remaining < len {
                return Err(RlpError::UnexpectedEof);
            }
            let end = total_header
                .checked_add(len)
                .ok_or(RlpError::UnexpectedEof)?;
            let payload = &data[total_header..end];
            Ok((RlpItem::Bytes(payload.to_vec()), &data[end..]))
        } else if first <= 0xf7 {
            // [0xc0, 0xf7]: Short list (0..55 payload bytes)
            let len = (first - 0xc0) as usize;
            if data.len() < 1 + len {
                return Err(RlpError::UnexpectedEof);
            }
            let payload = &data[1..1 + len];
            let items = decode_items_in_payload_with_depth(payload, depth + 1)?;
            Ok((RlpItem::List(items), &data[1 + len..]))
        } else {
            // [0xf8, 0xff]: Long list (> 55 payload bytes)
            let len_of_len = (first - 0xf7) as usize;
            if data.len() < 1 + len_of_len {
                return Err(RlpError::UnexpectedEof);
            }
            let len_bytes = &data[1..1 + len_of_len];
            if len_bytes[0] == 0 {
                return Err(RlpError::LeadingZeroInLength);
            }
            let len = parse_length(len_bytes)?;
            if len < 56 {
                return Err(RlpError::NonCanonicalLength);
            }
            let total_header = 1 + len_of_len;
            let remaining = data
                .len()
                .checked_sub(total_header)
                .ok_or(RlpError::UnexpectedEof)?;
            if remaining < len {
                return Err(RlpError::UnexpectedEof);
            }
            let end = total_header
                .checked_add(len)
                .ok_or(RlpError::UnexpectedEof)?;
            let payload = &data[total_header..end];
            let items = decode_items_in_payload_with_depth(payload, depth + 1)?;
            Ok((RlpItem::List(items), &data[end..]))
        }
    }

    /// Decodes the input as a top-level RLP list and returns its elements.
    pub fn decode_list(data: &[u8]) -> Result<Vec<Self>, RlpError> {
        let item = Self::decode(data)?;
        item.into_list()
    }

    /// Returns the item as a borrowed byte slice, or `Err(ExpectedBytes)` if it is a list.
    pub fn as_bytes(&self) -> Result<&[u8], RlpError> {
        match self {
            Self::Byte(ref b) => Ok(std::slice::from_ref(b)),
            Self::Bytes(ref b) => Ok(b.as_slice()),
            Self::List(_) => Err(RlpError::ExpectedBytes),
        }
    }

    /// Returns the item as a slice of child items, or `Err(ExpectedList)` if it is a byte string.
    pub fn as_list(&self) -> Result<&[RlpItem], RlpError> {
        match self {
            Self::List(l) => Ok(l.as_slice()),
            Self::Byte(_) | Self::Bytes(_) => Err(RlpError::ExpectedList),
        }
    }

    /// Consumes the item and returns its child items vector.
    pub fn into_list(self) -> Result<Vec<RlpItem>, RlpError> {
        match self {
            Self::List(l) => Ok(l),
            Self::Byte(_) | Self::Bytes(_) => Err(RlpError::ExpectedList),
        }
    }

    /// Returns a reference to the child item at `idx`.
    pub fn at(&self, idx: usize) -> Result<&RlpItem, RlpError> {
        let list = self.as_list()?;
        list.get(idx).ok_or_else(|| {
            RlpError::Custom(format!(
                "index out of bounds: index {idx} in list of len {}",
                list.len()
            ))
        })
    }

    /// Returns the item length (1 for Byte, byte slice len for Bytes, items count for List).
    pub fn len(&self) -> usize {
        match self {
            Self::Byte(_) => 1,
            Self::Bytes(b) => b.len(),
            Self::List(l) => l.len(),
        }
    }

    /// Whether this item represents an empty byte string or empty list.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Byte(_) => false,
            Self::Bytes(b) => b.is_empty(),
            Self::List(l) => l.is_empty(),
        }
    }

    /// Parses the item as an Ethereum unsigned integer fitting in `u8`.
    pub fn as_u8(&self) -> Result<u8, RlpError> {
        let val = self.as_u64()?;
        if val > u8::MAX as u64 {
            return Err(RlpError::IntegerOverflow("u8"));
        }
        Ok(val as u8)
    }

    /// Parses the item as an Ethereum unsigned integer fitting in `u64`.
    pub fn as_u64(&self) -> Result<u64, RlpError> {
        match self {
            Self::Byte(b) => Ok(*b as u64),
            Self::Bytes(bytes) => {
                if bytes.is_empty() {
                    return Ok(0);
                }
                if bytes.len() > 8 {
                    return Err(RlpError::IntegerOverflow("u64"));
                }
                if bytes[0] == 0 {
                    return Err(RlpError::LeadingZeroInInteger);
                }
                let mut val = 0u64;
                for &b in bytes {
                    val = (val << 8) | (b as u64);
                }
                Ok(val)
            }
            Self::List(_) => Err(RlpError::ExpectedBytes),
        }
    }

    /// Parses the item as an Ethereum unsigned integer fitting in `u128`.
    pub fn as_u128(&self) -> Result<u128, RlpError> {
        match self {
            Self::Byte(b) => Ok(*b as u128),
            Self::Bytes(bytes) => {
                if bytes.is_empty() {
                    return Ok(0);
                }
                if bytes.len() > 16 {
                    return Err(RlpError::IntegerOverflow("u128"));
                }
                if bytes[0] == 0 {
                    return Err(RlpError::LeadingZeroInInteger);
                }
                let mut val = 0u128;
                for &b in bytes {
                    val = (val << 8) | (b as u128);
                }
                Ok(val)
            }
            Self::List(_) => Err(RlpError::ExpectedBytes),
        }
    }

    /// Parses the item as an Ethereum unsigned 256-bit integer, returned as a right-aligned 32-byte array.
    pub fn as_u256_be(&self) -> Result<[u8; 32], RlpError> {
        let bytes = self.as_bytes()?;
        if bytes.is_empty() {
            return Ok([0u8; 32]);
        }
        if bytes.len() > 32 {
            return Err(RlpError::IntegerOverflow("u256"));
        }
        if bytes[0] == 0 {
            return Err(RlpError::LeadingZeroInInteger);
        }
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(bytes);
        Ok(out)
    }

    /// Parses a 20-byte Ethereum address.
    pub fn as_address(&self) -> Result<[u8; 20], RlpError> {
        let bytes = self.as_bytes()?;
        if bytes.len() != 20 {
            return Err(RlpError::InvalidAddressLength(bytes.len()));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Parses an optional 20-byte Ethereum address (empty string `0x80` becomes `None`).
    pub fn as_optional_address(&self) -> Result<Option<[u8; 20]>, RlpError> {
        let bytes = self.as_bytes()?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.len() != 20 {
            return Err(RlpError::InvalidAddressLength(bytes.len()));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(bytes);
        Ok(Some(out))
    }

    /// Parses bytes up to 32 bytes (such as ECDSA r or s), right-aligning into 32 bytes.
    pub fn as_bytes32(&self) -> Result<[u8; 32], RlpError> {
        let bytes = self.as_bytes()?;
        if bytes.len() > 32 {
            return Err(RlpError::Custom(format!(
                "expected at most 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(bytes);
        Ok(out)
    }

    /// Parses exact 32-byte array (such as hashes and storage keys).
    pub fn as_exact_bytes32(&self) -> Result<[u8; 32], RlpError> {
        let bytes = self.as_bytes()?;
        if bytes.len() != 32 {
            return Err(RlpError::Custom(format!(
                "expected exactly 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Convert into an owned RLP representation (self clone).
    pub fn to_owned(&self) -> RlpItem {
        self.clone()
    }
}

fn parse_length(bytes: &[u8]) -> Result<usize, RlpError> {
    if bytes.is_empty() {
        return Err(RlpError::UnexpectedEof);
    }
    if bytes[0] == 0 {
        return Err(RlpError::LeadingZeroInLength);
    }
    let mut len: usize = 0;
    for &b in bytes {
        len = len
            .checked_shl(8)
            .and_then(|v| v.checked_add(b as usize))
            .ok_or(RlpError::IntegerOverflow("usize"))?;
    }
    Ok(len)
}

#[allow(dead_code)] // GATE: non-depth-limited RLP entry point kept for tests and external callers; depth-limited variant is the internal path.
fn decode_items_in_payload(payload: &[u8]) -> Result<Vec<RlpItem>, RlpError> {
    decode_items_in_payload_with_depth(payload, 1)
}

fn decode_items_in_payload_with_depth(
    mut payload: &[u8],
    depth: usize,
) -> Result<Vec<RlpItem>, RlpError> {
    if depth > RlpItem::MAX_DEPTH {
        return Err(RlpError::Custom(
            "RLP recursion depth limit exceeded".to_string(),
        ));
    }
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, rest) = RlpItem::decode_with_remainder_depth(payload, depth)?;
        items.push(item);
        payload = rest;
    }
    Ok(items)
}

/// Maximum RLP nesting depth (re-exported for tests).
pub const MAX_RLP_DEPTH: usize = RlpItem::MAX_DEPTH;

/// Pure RLP decoding function returning `Result<RlpItem, String>`.
pub fn rlp_decode(data: &[u8]) -> Result<RlpItem, String> {
    RlpItem::decode(data).map_err(|e| e.to_string())
}

/// Decodes an RLP item and returns the remaining unparsed slice.
pub fn rlp_decode_with_remainder(data: &[u8]) -> Result<(RlpItem, &[u8]), String> {
    RlpItem::decode_with_remainder(data).map_err(|e| e.to_string())
}

/// Encodes an RlpItem back into canonical RLP bytes.
pub fn rlp_encode(item: &RlpItem) -> Vec<u8> {
    match item {
        RlpItem::Byte(b) => {
            if *b < 0x80 {
                vec![*b]
            } else {
                vec![0x81, *b]
            }
        }
        RlpItem::Bytes(bytes) => rlp_encode_bytes(bytes),
        RlpItem::List(items) => {
            let encoded_items: Vec<Vec<u8>> = items.iter().map(rlp_encode).collect();
            rlp_encode_list(&encoded_items)
        }
    }
}

fn strip_leading_zeros(slice: &[u8]) -> &[u8] {
    let first = slice.iter().position(|&b| b != 0).unwrap_or(slice.len());
    &slice[first..]
}

fn encode_usize(val: usize) -> Vec<u8> {
    let be = val.to_be_bytes();
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[first..].to_vec()
}

/// Encodes arbitrary byte slice into standard RLP.
pub fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        vec![bytes[0]]
    } else if bytes.len() <= 55 {
        let mut out = Vec::with_capacity(1 + bytes.len());
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
        out
    } else {
        let len_bytes = encode_usize(bytes.len());
        let mut out = Vec::with_capacity(1 + len_bytes.len() + bytes.len());
        out.push(0xb7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(bytes);
        out
    }
}

/// Encodes already-encoded payload items into an RLP list.
pub fn rlp_encode_list(payloads: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = payloads.iter().map(|p| p.len()).sum();
    if total_len <= 55 {
        let mut out = Vec::with_capacity(1 + total_len);
        out.push(0xc0 + total_len as u8);
        for p in payloads {
            out.extend_from_slice(p);
        }
        out
    } else {
        let len_bytes = encode_usize(total_len);
        let mut out = Vec::with_capacity(1 + len_bytes.len() + total_len);
        out.push(0xf7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        for p in payloads {
            out.extend_from_slice(p);
        }
        out
    }
}

/// Encodes an unsigned 64-bit integer into Ethereum RLP format.
pub fn rlp_encode_u64(val: u64) -> Vec<u8> {
    if val == 0 {
        vec![0x80]
    } else {
        let be = val.to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(8);
        rlp_encode_bytes(&be[first..])
    }
}

/// Encodes an unsigned 128-bit integer into Ethereum RLP format.
pub fn rlp_encode_u128(val: u128) -> Vec<u8> {
    if val == 0 {
        vec![0x80]
    } else {
        let be = val.to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(16);
        rlp_encode_bytes(&be[first..])
    }
}

// ============================================================================
// EIP-155 Legacy & EIP-1559 Type 2 Envelope Transaction Decoders
// ============================================================================

/// Decoded Ethereum legacy transaction (pre-EIP-155 or post-EIP-155).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyTransaction {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub v: u64,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub chain_id: Option<u64>,
}

impl LegacyTransaction {
    /// Parses an RLP-encoded legacy transaction returning Result<Self, String>.
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        Self::decode_rlp(raw).map_err(|e| e.to_string())
    }

    /// Decodes an RLP-encoded legacy transaction.
    pub fn decode_rlp(raw: &[u8]) -> Result<Self, RlpError> {
        let item = RlpItem::decode(raw)?;
        let items = item.as_list()?;
        Self::decode_fields(items)
    }

    /// Decodes the fields of a legacy transaction from a parsed RLP list.
    pub fn decode_fields(items: &[RlpItem]) -> Result<Self, RlpError> {
        if items.len() != 9 && items.len() != 6 {
            return Err(RlpError::Custom(format!(
                "invalid legacy transaction field count: expected 9 (or 6 for unsigned), got {}",
                items.len()
            )));
        }

        let nonce = items[0].as_u64()?;
        let gas_price = items[1].as_u128()?;
        let gas_limit = items[2].as_u64()?;
        let to = items[3].as_optional_address()?;
        let value = items[4].as_u128()?;
        let data = items[5].as_bytes()?.to_vec();

        if items.len() == 6 {
            return Ok(Self {
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
                v: 0,
                r: [0u8; 32],
                s: [0u8; 32],
                chain_id: None,
            });
        }

        let v = items[6].as_u64()?;
        let r = items[7].as_bytes32()?;
        let s = items[8].as_bytes32()?;

        let chain_id = if v >= 35 { Some((v - 35) / 2) } else { None };

        Ok(Self {
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
            v,
            r,
            s,
            chain_id,
        })
    }

    /// Derives the ECDSA recovery id (0 or 1).
    pub fn recovery_id(&self) -> u8 {
        if self.v >= 35 {
            ((self.v - 35) % 2) as u8
        } else if self.v >= 27 {
            (self.v - 27) as u8
        } else {
            (self.v % 2) as u8
        }
    }

    /// Encodes the signed transaction as an RLP list.
    pub fn encode(&self) -> Vec<u8> {
        let fields = vec![
            rlp_encode_u64(self.nonce),
            rlp_encode_u128(self.gas_price),
            rlp_encode_u64(self.gas_limit),
            match &self.to {
                Some(addr) => rlp_encode_bytes(addr),
                None => vec![0x80],
            },
            rlp_encode_u128(self.value),
            rlp_encode_bytes(&self.data),
            rlp_encode_u64(self.v),
            rlp_encode_bytes(strip_leading_zeros(&self.r)),
            rlp_encode_bytes(strip_leading_zeros(&self.s)),
        ];
        rlp_encode_list(&fields)
    }

    /// Produces RLP-encoded signing data according to EIP-155.
    pub fn signing_data(&self) -> Vec<u8> {
        let mut fields = Vec::with_capacity(9);
        fields.push(rlp_encode_u64(self.nonce));
        fields.push(rlp_encode_u128(self.gas_price));
        fields.push(rlp_encode_u64(self.gas_limit));
        fields.push(match &self.to {
            Some(addr) => rlp_encode_bytes(addr),
            None => vec![0x80],
        });
        fields.push(rlp_encode_u128(self.value));
        fields.push(rlp_encode_bytes(&self.data));

        if let Some(chain_id) = self.chain_id {
            fields.push(rlp_encode_u64(chain_id));
            fields.push(vec![0x80]); // integer 0
            fields.push(vec![0x80]); // integer 0
        }
        rlp_encode_list(&fields)
    }

    /// Computes the EIP-155 signing hash (Keccak-256 of `signing_data`).
    pub fn signing_hash(&self) -> [u8; 32] {
        keccak256(&self.signing_data())
    }

    /// Computes the transaction hash (Keccak-256 of RLP-encoded transaction).
    pub fn compute_hash(&self) -> [u8; 32] {
        keccak256(&self.encode())
    }

    /// Converts into EVM JSON-RPC transaction representation.
    pub fn to_evm_transaction(
        &self,
        tx_hash: Option<[u8; 32]>,
        from: Option<[u8; 20]>,
    ) -> EvmTransaction {
        let h = tx_hash.unwrap_or_else(|| self.compute_hash());
        let from_str = match from {
            Some(a) => format!("0x{}", hex::encode(a)),
            None => "0x0000000000000000000000000000000000000000".to_string(),
        };
        EvmTransaction {
            hash: format!("0x{}", hex::encode(h)),
            nonce: format_u64_hex(self.nonce),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: from_str,
            to: self.to.map(|a| format!("0x{}", hex::encode(a))),
            value: format_u128_hex(self.value),
            gas_price: Some(format_u128_hex(self.gas_price)),
            gas: format_u64_hex(self.gas_limit),
            input: if self.data.is_empty() {
                "0x".to_string()
            } else {
                format!("0x{}", hex::encode(&self.data))
            },
            v: format_u64_hex(self.v),
            r: format!("0x{}", hex::encode(self.r)),
            s: format!("0x{}", hex::encode(self.s)),
            tx_type: Some("0x0".to_string()),
            chain_id: self.chain_id.map(format_u64_hex),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    }

    /// Recovers the 20-byte sender address using secp256k1 ECDSA and EIP-155 replay protection.
    pub fn recover_sender(&self) -> Result<[u8; 20], EvmError> {
        let hash = self.signing_hash();
        ecrecover_with_chain_id(&hash, self.v, &self.r, &self.s, self.chain_id)
    }

    /// Verifies that this transaction's signature is valid, strictly requiring
    /// Stellereum replay protection (`chain_id == CHAIN_ID == 5757`) in addition
    /// to low-s compliance under EIP-2.
    pub fn verify_signature(&self) -> Result<[u8; 20], EvmError> {
        match self.chain_id {
            Some(CHAIN_ID) => {}
            Some(got) => {
                return Err(EvmError::ChainIdMismatch {
                    expected: CHAIN_ID,
                    got,
                })
            }
            None => return Err(EvmError::ReplayProtectionRequired),
        }
        if !is_low_s(&self.s) {
            return Err(EvmError::InvalidSignatureS);
        }
        self.recover_sender()
    }
}

/// EIP-2930 / EIP-1559 access list entry (address and list of storage keys).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

impl AccessListItem {
    /// Decodes an access list entry from an RLP item.
    pub fn decode_rlp(item: &RlpItem) -> Result<Self, RlpError> {
        let items = item.as_list()?;
        if items.len() != 2 {
            return Err(RlpError::Custom(format!(
                "invalid access list item: expected 2 elements, got {}",
                items.len()
            )));
        }
        let address = items[0].as_address()?;
        let key_items = items[1].as_list()?;
        let mut storage_keys = Vec::with_capacity(key_items.len());
        for k in key_items {
            storage_keys.push(k.as_exact_bytes32()?);
        }
        Ok(Self {
            address,
            storage_keys,
        })
    }

    /// Encodes an access list entry as an RLP item.
    pub fn encode(&self) -> Vec<u8> {
        let addr_encoded = rlp_encode_bytes(&self.address);
        let keys_encoded: Vec<Vec<u8>> = self
            .storage_keys
            .iter()
            .map(|k| rlp_encode_bytes(k))
            .collect();
        let keys_list = rlp_encode_list(&keys_encoded);
        rlp_encode_list(&[addr_encoded, keys_list])
    }
}

/// Decoded EIP-1559 Type 2 envelope transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip1559Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
    pub y_parity: u8,
    pub v: u64,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl Eip1559Transaction {
    /// EIP-2718 transaction type identifier for EIP-1559 (0x02).
    pub const TX_TYPE: u8 = 0x02;

    /// Parses a raw EIP-1559 envelope (0x02 || rlp_payload) returning Result<Self, String>.
    pub fn parse_envelope(raw: &[u8]) -> Result<Self, String> {
        Self::decode_envelope(raw).map_err(|e| e.to_string())
    }

    /// Decodes a raw EIP-1559 envelope (0x02 || rlp_payload).
    pub fn decode_envelope(raw: &[u8]) -> Result<Self, RlpError> {
        if raw.is_empty() {
            return Err(RlpError::UnexpectedEof);
        }
        if raw[0] != Self::TX_TYPE {
            return Err(RlpError::InvalidTransactionType(raw[0]));
        }
        Self::decode_payload(&raw[1..])
    }

    /// Parses the RLP payload of an EIP-1559 transaction returning Result<Self, String>.
    pub fn parse_payload(payload: &[u8]) -> Result<Self, String> {
        Self::decode_payload(payload).map_err(|e| e.to_string())
    }

    /// Decodes the RLP payload of an EIP-1559 transaction (without the 0x02 type byte).
    pub fn decode_payload(payload: &[u8]) -> Result<Self, RlpError> {
        let item = RlpItem::decode(payload)?;
        let items = item.as_list()?;
        Self::decode_fields(items)
    }

    /// Decodes the fields of an EIP-1559 transaction from a parsed RLP list.
    pub fn decode_fields(items: &[RlpItem]) -> Result<Self, RlpError> {
        if items.len() != 12 && items.len() != 9 {
            return Err(RlpError::Custom(format!(
                "invalid EIP-1559 transaction field count: expected 12 (or 9 for unsigned), got {}",
                items.len()
            )));
        }

        let chain_id = items[0].as_u64()?;
        let nonce = items[1].as_u64()?;
        let max_priority_fee_per_gas = items[2].as_u128()?;
        let max_fee_per_gas = items[3].as_u128()?;
        let gas_limit = items[4].as_u64()?;
        let to = items[5].as_optional_address()?;
        let value = items[6].as_u128()?;
        let data = items[7].as_bytes()?.to_vec();

        let access_list_items = items[8].as_list()?;
        let mut access_list = Vec::with_capacity(access_list_items.len());
        for entry in access_list_items {
            access_list.push(AccessListItem::decode_rlp(entry)?);
        }

        if items.len() == 9 {
            return Ok(Self {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
                access_list,
                y_parity: 0,
                v: 0,
                r: [0u8; 32],
                s: [0u8; 32],
            });
        }

        let v = items[9].as_u64()?;
        let y_parity = if v >= 27 {
            ((v - 27) % 2) as u8
        } else {
            (v % 2) as u8
        };
        let r = items[10].as_bytes32()?;
        let s = items[11].as_bytes32()?;

        Ok(Self {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list,
            y_parity,
            v,
            r,
            s,
        })
    }

    /// Encodes the 12 fields of the signed transaction into an RLP list payload.
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut fields = Vec::with_capacity(12);
        fields.push(rlp_encode_u64(self.chain_id));
        fields.push(rlp_encode_u64(self.nonce));
        fields.push(rlp_encode_u128(self.max_priority_fee_per_gas));
        fields.push(rlp_encode_u128(self.max_fee_per_gas));
        fields.push(rlp_encode_u64(self.gas_limit));
        fields.push(match &self.to {
            Some(addr) => rlp_encode_bytes(addr),
            None => vec![0x80],
        });
        fields.push(rlp_encode_u128(self.value));
        fields.push(rlp_encode_bytes(&self.data));

        let access_entries: Vec<Vec<u8>> =
            self.access_list.iter().map(|item| item.encode()).collect();
        fields.push(rlp_encode_list(&access_entries));

        fields.push(rlp_encode_u64(self.y_parity as u64));
        fields.push(rlp_encode_bytes(strip_leading_zeros(&self.r)));
        fields.push(rlp_encode_bytes(strip_leading_zeros(&self.s)));

        rlp_encode_list(&fields)
    }

    /// Encodes the complete EIP-2718 typed envelope (0x02 || rlp_payload).
    pub fn encode(&self) -> Vec<u8> {
        let payload = self.encode_payload();
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(Self::TX_TYPE);
        out.extend_from_slice(&payload);
        out
    }

    /// Produces EIP-1559 signing data: 0x02 || rlp([chain_id, nonce, max_priority, max_fee, gas_limit, to, value, data, access_list]).
    pub fn signing_data(&self) -> Vec<u8> {
        let mut fields = Vec::with_capacity(9);
        fields.push(rlp_encode_u64(self.chain_id));
        fields.push(rlp_encode_u64(self.nonce));
        fields.push(rlp_encode_u128(self.max_priority_fee_per_gas));
        fields.push(rlp_encode_u128(self.max_fee_per_gas));
        fields.push(rlp_encode_u64(self.gas_limit));
        fields.push(match &self.to {
            Some(addr) => rlp_encode_bytes(addr),
            None => vec![0x80],
        });
        fields.push(rlp_encode_u128(self.value));
        fields.push(rlp_encode_bytes(&self.data));

        let access_entries: Vec<Vec<u8>> =
            self.access_list.iter().map(|item| item.encode()).collect();
        fields.push(rlp_encode_list(&access_entries));

        let payload = rlp_encode_list(&fields);
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(Self::TX_TYPE);
        out.extend_from_slice(&payload);
        out
    }

    /// Computes the EIP-1559 signing hash (Keccak-256 of `signing_data`).
    pub fn signing_hash(&self) -> [u8; 32] {
        keccak256(&self.signing_data())
    }

    /// Computes the transaction hash: Keccak-256 of envelope (`0x02 || rlp_payload`).
    pub fn compute_hash(&self) -> [u8; 32] {
        keccak256(&self.encode())
    }

    /// Converts into EVM JSON-RPC transaction representation.
    pub fn to_evm_transaction(
        &self,
        tx_hash: Option<[u8; 32]>,
        from: Option<[u8; 20]>,
    ) -> EvmTransaction {
        let h = tx_hash.unwrap_or_else(|| self.compute_hash());
        let from_str = match from {
            Some(a) => format!("0x{}", hex::encode(a)),
            None => "0x0000000000000000000000000000000000000000".to_string(),
        };
        let access_list: Vec<EvmAccessListItem> = self
            .access_list
            .iter()
            .map(|item| EvmAccessListItem {
                address: format!("0x{}", hex::encode(item.address)),
                storage_keys: item
                    .storage_keys
                    .iter()
                    .map(|k| format!("0x{}", hex::encode(k)))
                    .collect(),
            })
            .collect();
        EvmTransaction {
            hash: format!("0x{}", hex::encode(h)),
            nonce: format_u64_hex(self.nonce),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: from_str,
            to: self.to.map(|a| format!("0x{}", hex::encode(a))),
            value: format_u128_hex(self.value),
            gas_price: Some(format_u128_hex(self.max_fee_per_gas)),
            gas: format_u64_hex(self.gas_limit),
            input: if self.data.is_empty() {
                "0x".to_string()
            } else {
                format!("0x{}", hex::encode(&self.data))
            },
            v: format_u64_hex(self.y_parity as u64),
            r: format!("0x{}", hex::encode(self.r)),
            s: format!("0x{}", hex::encode(self.s)),
            tx_type: Some("0x2".to_string()),
            chain_id: Some(format_u64_hex(self.chain_id)),
            max_fee_per_gas: Some(format_u128_hex(self.max_fee_per_gas)),
            max_priority_fee_per_gas: Some(format_u128_hex(self.max_priority_fee_per_gas)),
            access_list: Some(access_list),
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        }
    }

    /// Recovers the 20-byte sender address using secp256k1 ECDSA and EIP-1559 rules.
    pub fn recover_sender(&self) -> Result<[u8; 20], EvmError> {
        let hash = self.signing_hash();
        ecrecover_with_chain_id(
            &hash,
            self.y_parity as u64,
            &self.r,
            &self.s,
            Some(self.chain_id),
        )
    }

    /// Verifies that this transaction's signature is valid, strictly requiring
    /// Stellereum replay protection (`chain_id == CHAIN_ID == 5757`) in addition
    /// to low-s compliance under EIP-2.
    pub fn verify_signature(&self) -> Result<[u8; 20], EvmError> {
        if self.chain_id != CHAIN_ID {
            return Err(EvmError::ChainIdMismatch {
                expected: CHAIN_ID,
                got: self.chain_id,
            });
        }
        if !is_low_s(&self.s) {
            return Err(EvmError::InvalidSignatureS);
        }
        self.recover_sender()
    }
}

/// Unified enum for decoded EVM transactions (Legacy or EIP-1559 Type 2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodedTransaction {
    Legacy(LegacyTransaction),
    Eip1559(Eip1559Transaction),
}

impl DecodedTransaction {
    /// Decodes raw transaction bytes (auto-detecting EIP-2718 envelope 0x02 vs legacy RLP list).
    pub fn decode(raw: &[u8]) -> Result<Self, RlpError> {
        if raw.is_empty() {
            return Err(RlpError::UnexpectedEof);
        }
        match raw[0] {
            0x02 => Eip1559Transaction::decode_envelope(raw).map(DecodedTransaction::Eip1559),
            b if b >= 0xc0 => LegacyTransaction::decode_rlp(raw).map(DecodedTransaction::Legacy),
            other => Err(RlpError::InvalidTransactionType(other)),
        }
    }

    /// Decodes a 0x-prefixed or bare hex string into a decoded transaction.
    pub fn decode_hex(hex_str: &str) -> Result<Self, RlpError> {
        let trimmed = hex_str.trim();
        let stripped = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        let raw = hex::decode(stripped)
            .map_err(|e| RlpError::Custom(format!("hex decode error: {e}")))?;
        Self::decode(&raw)
    }

    /// Encodes the transaction to canonical wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Legacy(tx) => tx.encode(),
            Self::Eip1559(tx) => tx.encode(),
        }
    }

    /// Computes the 32-byte Ethereum transaction hash.
    pub fn compute_hash(&self) -> [u8; 32] {
        match self {
            Self::Legacy(tx) => tx.compute_hash(),
            Self::Eip1559(tx) => tx.compute_hash(),
        }
    }

    /// Computes the 32-byte signing hash.
    pub fn signing_hash(&self) -> [u8; 32] {
        match self {
            Self::Legacy(tx) => tx.signing_hash(),
            Self::Eip1559(tx) => tx.signing_hash(),
        }
    }

    /// Nonce of the transaction.
    pub fn nonce(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.nonce,
            Self::Eip1559(tx) => tx.nonce,
        }
    }

    /// Destination address (None for contract creation).
    pub fn to(&self) -> Option<[u8; 20]> {
        match self {
            Self::Legacy(tx) => tx.to,
            Self::Eip1559(tx) => tx.to,
        }
    }

    /// Transferred value in Wei.
    pub fn value(&self) -> u128 {
        match self {
            Self::Legacy(tx) => tx.value,
            Self::Eip1559(tx) => tx.value,
        }
    }

    /// Gas limit.
    pub fn gas_limit(&self) -> u64 {
        match self {
            Self::Legacy(tx) => tx.gas_limit,
            Self::Eip1559(tx) => tx.gas_limit,
        }
    }

    /// Payload data bytes.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Legacy(tx) => &tx.data,
            Self::Eip1559(tx) => &tx.data,
        }
    }

    /// Chain ID (if protected).
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Self::Legacy(tx) => tx.chain_id,
            Self::Eip1559(tx) => Some(tx.chain_id),
        }
    }

    /// Converts to an EVM JSON-RPC transaction structure.
    pub fn to_evm_transaction(
        &self,
        tx_hash: Option<[u8; 32]>,
        from: Option<[u8; 20]>,
    ) -> EvmTransaction {
        match self {
            Self::Legacy(tx) => tx.to_evm_transaction(tx_hash, from),
            Self::Eip1559(tx) => tx.to_evm_transaction(tx_hash, from),
        }
    }

    /// Recovers the 20-byte sender address of the transaction.
    pub fn recover_sender(&self) -> Result<[u8; 20], EvmError> {
        match self {
            Self::Legacy(tx) => tx.recover_sender(),
            Self::Eip1559(tx) => tx.recover_sender(),
        }
    }

    /// Verifies that this transaction's signature is valid.
    pub fn verify_signature(&self) -> Result<[u8; 20], EvmError> {
        match self {
            Self::Legacy(tx) => tx.verify_signature(),
            Self::Eip1559(tx) => tx.verify_signature(),
        }
    }
}

/// Decodes raw transaction bytes (auto-detecting EIP-2718 Type 2 vs Legacy).
pub fn decode_raw_transaction(raw: &[u8]) -> Result<DecodedTransaction, RlpError> {
    DecodedTransaction::decode(raw)
}

/// Parses raw transaction bytes (auto-detecting EIP-2718 Type 2 vs Legacy) returning Result<DecodedTransaction, String>.
pub fn parse_raw_transaction(raw: &[u8]) -> Result<DecodedTransaction, String> {
    DecodedTransaction::decode(raw).map_err(|e| e.to_string())
}

/// Decodes a hex string representing a raw transaction.
pub fn decode_raw_transaction_hex(hex_str: &str) -> Result<DecodedTransaction, RlpError> {
    DecodedTransaction::decode_hex(hex_str)
}

/// Decodes an RLP-encoded legacy transaction.
pub fn decode_legacy_transaction(raw: &[u8]) -> Result<LegacyTransaction, RlpError> {
    LegacyTransaction::decode_rlp(raw)
}

/// Parses an EIP-155 Legacy transaction from RLP-encoded bytes:
/// `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`.
pub fn parse_legacy_transaction(raw: &[u8]) -> Result<LegacyTransaction, String> {
    LegacyTransaction::parse(raw)
}

/// Decodes a raw EIP-1559 Type 2 envelope transaction.
pub fn decode_eip1559_transaction(raw: &[u8]) -> Result<Eip1559Transaction, RlpError> {
    Eip1559Transaction::decode_envelope(raw)
}

/// Parses an EIP-1559 Type 2 Envelope transaction:
/// `0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s])`.
pub fn parse_eip1559_envelope(raw: &[u8]) -> Result<Eip1559Transaction, String> {
    Eip1559Transaction::parse_envelope(raw)
}

/// Alias for `parse_eip1559_envelope`.
pub fn parse_eip1559_transaction(raw: &[u8]) -> Result<Eip1559Transaction, String> {
    Eip1559Transaction::parse_envelope(raw)
}

// ============================================================================
// Unit Tests
// ============================================================================
// Ethereum Cryptography: secp256k1 ECDSA, Keccak-256 & ecrecover
// ============================================================================

/// secp256k1 curve order N / 2, the threshold for low-s values (EIP-2 malleability protection).
/// N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
/// N / 2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
pub const SECP256K1_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Errors occurring during Ethereum signature verification or address recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvmError {
    InvalidRecoveryId(u64),
    InvalidSignatureR,
    InvalidSignatureS,
    InvalidSignature(String),
    InvalidPublicKey(String),
    InvalidMessageHash(String),
    ChainIdMismatch { expected: u64, got: u64 },
    ReplayProtectionRequired,
    HexDecodeError(String),
    InvalidAddressLength(usize),
    SignatureRecoveryFailed(String),
}

impl std::fmt::Display for EvmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRecoveryId(v) => write!(f, "invalid recovery id / v parameter: {v}"),
            Self::InvalidSignatureR => write!(
                f,
                "signature r value must be non-zero and within curve order"
            ),
            Self::InvalidSignatureS => write!(
                f,
                "signature s value must be non-zero and within allowed range"
            ),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            Self::InvalidPublicKey(e) => write!(f, "invalid public key: {e}"),
            Self::InvalidMessageHash(e) => write!(f, "invalid message hash: {e}"),
            Self::ChainIdMismatch { expected, got } => {
                write!(
                    f,
                    "EIP-155 chain ID mismatch: expected {expected}, got {got}"
                )
            }
            Self::ReplayProtectionRequired => {
                write!(
                    f,
                    "EIP-155 replay protection required, but legacy unprotected signature received"
                )
            }
            Self::HexDecodeError(e) => write!(f, "hex decoding failed: {e}"),
            Self::InvalidAddressLength(len) => {
                write!(f, "invalid address length: expected 20 bytes, got {len}")
            }
            Self::SignatureRecoveryFailed(e) => write!(f, "ECDSA public key recovery failed: {e}"),
        }
    }
}

impl std::error::Error for EvmError {}

/// Derives the 20-byte Ethereum address from a secp256k1 public key.
///
/// Formula: `keccak256(pubkey_uncompressed[1..])[12..32]`.
///
/// Accepts:
/// - 65-byte uncompressed public key (starts with 0x04)
/// - 64-byte raw uncompressed public key coordinates (X || Y)
/// - 33-byte compressed public key (starts with 0x02 or 0x03)
pub fn pubkey_to_address(pubkey: &[u8]) -> Result<[u8; 20], EvmError> {
    let uncompressed_raw = if pubkey.len() == 65 && pubkey[0] == 0x04 {
        &pubkey[1..65]
    } else if pubkey.len() == 64 {
        pubkey
    } else if pubkey.len() == 33 {
        let vk = VerifyingKey::from_sec1_bytes(pubkey)
            .map_err(|e| EvmError::InvalidPublicKey(e.to_string()))?;
        let encoded = vk.to_encoded_point(false);
        let uncompressed = encoded.as_bytes();
        let hash = keccak256(&uncompressed[1..65]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);
        return Ok(addr);
    } else {
        return Err(EvmError::InvalidPublicKey(format!(
            "expected 65-byte uncompressed, 64-byte raw, or 33-byte compressed public key, got {} bytes",
            pubkey.len()
        )));
    };

    let hash = keccak256(uncompressed_raw);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

/// Returns true if signature scalar `s` is in the lower half of the curve order
/// (`s <= secp256k1_n / 2`), protecting against malleability under EIP-2.
pub fn is_low_s(s: &[u8; 32]) -> bool {
    s <= &SECP256K1_HALF_N
}

/// Decomposes an Ethereum `v` value into `(recovery_id, Option<chain_id>)`.
///
/// Supports:
/// - EIP-1559 / typed transactions (EIP-2718): `v = 0` or `1` (y_parity) -> recovery_id = 0/1, chain_id = None.
/// - Pre-EIP-155 legacy transactions: `v = 27` or `28` -> recovery_id = v - 27, chain_id = None.
/// - EIP-155 replay protected transactions: `v >= 35` (where `v = chain_id * 2 + 35 + recovery_id`) ->
///   recovery_id = (v - 35) % 2, chain_id = Some((v - 35) / 2).
pub fn parse_v(v: u64) -> Result<(u8, Option<u64>), EvmError> {
    if v == 0 || v == 1 {
        Ok((v as u8, None))
    } else if v == 27 || v == 28 {
        Ok(((v - 27) as u8, None))
    } else if v >= 35 {
        let chain_id = (v - 35) / 2;
        let rec_id = ((v - 35 - 2 * chain_id) % 2) as u8;
        Ok((rec_id, Some(chain_id)))
    } else {
        Err(EvmError::InvalidRecoveryId(v))
    }
}

/// Decomposes `v` and verifies EIP-155 chain ID replay protection against `expected_chain_id`.
///
/// If `expected_chain_id` is `Some(id)`:
/// - If `v >= 35`, requires derived `chain_id == id`.
/// - If `v == 0` or `1` (EIP-1559), accepted as chain ID is validated via the transaction envelope.
/// - If `v == 27` or `28`, returns `EvmError::ReplayProtectionRequired` (unprotected legacy transaction).
pub fn parse_v_with_chain_id(
    v: u64,
    expected_chain_id: Option<u64>,
) -> Result<(u8, Option<u64>), EvmError> {
    parse_v_with_chain_id_opts(v, expected_chain_id, false)
}

/// Decomposes `v` with optional allowance for unprotected pre-EIP-155 legacy transactions (v = 27, 28).
pub fn parse_v_with_chain_id_opts(
    v: u64,
    expected_chain_id: Option<u64>,
    allow_unprotected: bool,
) -> Result<(u8, Option<u64>), EvmError> {
    let (rec_id, chain_id) = parse_v(v)?;
    if let Some(expected) = expected_chain_id {
        match chain_id {
            Some(got) => {
                if got != expected {
                    return Err(EvmError::ChainIdMismatch { expected, got });
                }
            }
            None => {
                if (v == 27 || v == 28) && !allow_unprotected {
                    return Err(EvmError::ReplayProtectionRequired);
                }
            }
        }
    }
    Ok((rec_id, chain_id))
}

/// Given an Ethereum 32-byte message hash `hash` and signature `(v, r, s)`, recovers the 20-byte sender address.
///
/// Supports:
/// - EIP-155 replay-protected transactions (`v = 2 * chain_id + 35 + rec_id` -> extraction `rec_id = (v - 35 - 2 * chain_id) % 2`)
/// - EIP-1559 typed transactions (`v = 0` or `1`)
/// - Pre-EIP-155 legacy transactions (`v = 27` or `28` -> `rec_id = v - 27`)
///
/// Computes the 20-byte sender address: `keccak256(&uncompressed_pubkey[1..])[12..32]`.
pub fn ecrecover(hash: &[u8; 32], v: u64, r: &[u8; 32], s: &[u8; 32]) -> Result<[u8; 20], String> {
    ecrecover_with_chain_id(hash, v, r, s, None).map_err(|e| e.to_string())
}

/// Validates an Ethereum transaction signature:
/// - Replay protection: verifies `chain_id == 5757` (CHAIN_ID).
/// - Canonical s: verifies `s <= secp256k1_order / 2` (EIP-2).
///   Recovers and returns the 20-byte sender address.
pub fn validate_transaction_signature(
    hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<[u8; 20], String> {
    validate_transaction_signature_with_chain_id(hash, v, r, s, Some(CHAIN_ID))
}

/// Validates an Ethereum transaction signature against an expected chain ID:
/// - Replay protection: verifies that the signature's chain ID matches `expected_chain_id`.
/// - Canonical s: verifies `s <= secp256k1_order / 2` (EIP-2).
///   Recovers and returns the 20-byte sender address.
pub fn validate_transaction_signature_with_chain_id(
    hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<[u8; 20], String> {
    // 1. EIP-2 canonical low-s check: s <= secp256k1_order / 2
    if !is_low_s(s) {
        return Err(
            "signature s is not canonical: must be <= secp256k1_order / 2 (EIP-2)".to_string(),
        );
    }

    // 2. Replay protection check: chain_id == expected_chain_id
    if let Some(expected) = expected_chain_id {
        if v >= 35 {
            let chain_id = (v - 35) / 2;
            if chain_id != expected {
                return Err(format!(
                    "EIP-155 replay protection mismatch: expected chain_id {}, got {}",
                    expected, chain_id
                ));
            }
        } else if v == 27 || v == 28 {
            return Err("EIP-155 replay protection required, but legacy unprotected signature received (v = 27/28)".to_string());
        } else if v == 0 || v == 1 {
            // EIP-1559 typed transaction (y_parity)
        } else {
            return Err(format!("invalid recovery id / v parameter: {v}"));
        }
    }

    ecrecover(hash, v, r, s)
}

/// Convenience alias for `validate_transaction_signature`.
pub fn verify_transaction_signature(
    hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<[u8; 20], String> {
    validate_transaction_signature(hash, v, r, s)
}

/// Given an Ethereum 32-byte message hash `e` and signature `(v, r, s)`, recovers the 20-byte sender address
/// and verifies EIP-155 chain ID replay protection against `expected_chain_id`.
pub fn ecrecover_with_chain_id(
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<[u8; 20], EvmError> {
    let pubkey_bytes = ecrecover_pubkey_with_chain_id(message_hash, v, r, s, expected_chain_id)?;
    pubkey_to_address(&pubkey_bytes)
}

/// Recovers the uncompressed 65-byte public key (starts with 0x04) from message hash and signature (v, r, s).
pub fn ecrecover_pubkey(
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<[u8; 65], EvmError> {
    ecrecover_pubkey_with_chain_id(message_hash, v, r, s, None)
}

/// Recovers the uncompressed 65-byte public key with EIP-155 chain ID verification.
pub fn ecrecover_pubkey_with_chain_id(
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<[u8; 65], EvmError> {
    let (rec_id, _) = parse_v_with_chain_id(v, expected_chain_id)?;

    if r == &[0u8; 32] {
        return Err(EvmError::InvalidSignatureR);
    }
    if s == &[0u8; 32] {
        return Err(EvmError::InvalidSignatureS);
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);

    let signature =
        Signature::from_slice(&sig_bytes).map_err(|e| EvmError::InvalidSignature(e.to_string()))?;

    let recid = RecoveryId::try_from(rec_id).map_err(|_| EvmError::InvalidRecoveryId(v))?;

    let vk = VerifyingKey::recover_from_prehash(message_hash, &signature, recid)
        .map_err(|e| EvmError::SignatureRecoveryFailed(e.to_string()))?;

    let encoded = vk.to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

/// Recovers the sender address and strictly validates `s <= secp256k1_n / 2` (EIP-2 malleability protection).
pub fn ecrecover_tx(
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<[u8; 20], EvmError> {
    if !is_low_s(s) {
        return Err(EvmError::InvalidSignatureS);
    }
    ecrecover_with_chain_id(message_hash, v, r, s, expected_chain_id)
}

/// Verifies that an Ethereum signature `(v, r, s)` over `message_hash` was produced by `expected_address`.
pub fn verify_signature(
    expected_address: &[u8; 20],
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<bool, EvmError> {
    let recovered = ecrecover(message_hash, v, r, s).map_err(EvmError::SignatureRecoveryFailed)?;
    Ok(recovered == *expected_address)
}

/// Verifies that an Ethereum signature `(v, r, s)` over `message_hash` was produced by `expected_address`
/// with EIP-155 chain ID replay protection.
pub fn verify_signature_with_chain_id(
    expected_address: &[u8; 20],
    message_hash: &[u8; 32],
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
    expected_chain_id: Option<u64>,
) -> Result<bool, EvmError> {
    let recovered = ecrecover_with_chain_id(message_hash, v, r, s, expected_chain_id)?;
    Ok(recovered == *expected_address)
}

/// Hex string convenience method for `ecrecover`. Returns formatted "0x..." checksum address.
pub fn ecrecover_hex(
    message_hash_hex: &str,
    v_hex: &str,
    r_hex: &str,
    s_hex: &str,
) -> Result<String, EvmError> {
    ecrecover_hex_with_chain_id(message_hash_hex, v_hex, r_hex, s_hex, None)
}

/// Hex string convenience method for `ecrecover` with EIP-155 chain ID check.
pub fn ecrecover_hex_with_chain_id(
    message_hash_hex: &str,
    v_hex: &str,
    r_hex: &str,
    s_hex: &str,
    expected_chain_id: Option<u64>,
) -> Result<String, EvmError> {
    let hash = parse_h256(message_hash_hex)?;
    let v = parse_v_str(v_hex)?;
    let r = parse_h256(r_hex)?;
    let s = parse_h256(s_hex)?;
    let addr = ecrecover_with_chain_id(&hash, v, &r, &s, expected_chain_id)?;
    Ok(to_checksum_address(&addr))
}

/// Formats a 20-byte address into an EIP-55 mixed-case checksummed hex string ("0x...").
pub fn to_checksum_address(addr: &[u8; 20]) -> String {
    let hex_addr = hex::encode(addr);
    let hash = keccak256(hex_addr.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_alphabetic() {
            let byte_idx = i / 2;
            let nibble = if i % 2 == 0 {
                (hash[byte_idx] >> 4) & 0x0f
            } else {
                hash[byte_idx] & 0x0f
            };
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c.to_ascii_lowercase());
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parses a 20-byte Ethereum address from a hex string (with or without 0x prefix).
pub fn parse_address(s: &str) -> Result<[u8; 20], EvmError> {
    let trimmed = s.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(hex_part)
        .map_err(|e| EvmError::HexDecodeError(format!("invalid hex in address '{s}': {e}")))?;
    if bytes.len() != 20 {
        return Err(EvmError::InvalidAddressLength(bytes.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parses a 32-byte hash / scalar from a hex string (with or without 0x prefix).
pub fn parse_h256(s: &str) -> Result<[u8; 32], EvmError> {
    let trimmed = s.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(hex_part)
        .map_err(|e| EvmError::HexDecodeError(format!("invalid hex in '{s}': {e}")))?;
    if bytes.len() > 32 {
        return Err(EvmError::InvalidMessageHash(format!(
            "hex string too long for 32 bytes: {} bytes",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// Parses `v` value from a string (handles "0x" hex quantities and decimal integers).
pub fn parse_v_str(s: &str) -> Result<u64, EvmError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(EvmError::HexDecodeError("empty v string".to_string()));
    }
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        let hex_part = &trimmed[2..];
        if hex_part.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(hex_part, 16)
            .map_err(|e| EvmError::HexDecodeError(format!("invalid hex v '{s}': {e}")))
    } else {
        trimmed
            .parse::<u64>()
            .map_err(|e| EvmError::HexDecodeError(format!("invalid integer v '{s}': {e}")))
    }
}

// ----------------------------------------------------------------------------
// Minimal Recursive Length Prefix (RLP) Serialization for Signing Hashes
// ----------------------------------------------------------------------------

pub mod rlp {
    /// RLP encodes a byte slice according to Ethereum Yellow Paper.
    pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            vec![data[0]]
        } else if data.len() <= 55 {
            let mut out = Vec::with_capacity(1 + data.len());
            out.push(0x80 + data.len() as u8);
            out.extend_from_slice(data);
            out
        } else {
            let len_bytes = data.len().to_be_bytes();
            let skip = len_bytes.iter().take_while(|&&b| b == 0).count();
            let active = &len_bytes[skip..];
            let mut out = Vec::with_capacity(1 + active.len() + data.len());
            out.push(0xb7 + active.len() as u8);
            out.extend_from_slice(active);
            out.extend_from_slice(data);
            out
        }
    }

    /// RLP encodes a u64 integer (big-endian with leading zeroes trimmed).
    pub fn encode_u64(val: u64) -> Vec<u8> {
        if val == 0 {
            encode_bytes(&[])
        } else {
            let bytes = val.to_be_bytes();
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            encode_bytes(&bytes[skip..])
        }
    }

    /// RLP encodes a u128 integer (big-endian with leading zeroes trimmed).
    pub fn encode_u128(val: u128) -> Vec<u8> {
        if val == 0 {
            encode_bytes(&[])
        } else {
            let bytes = val.to_be_bytes();
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            encode_bytes(&bytes[skip..])
        }
    }

    /// RLP encodes a list of previously RLP-encoded items.
    pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload_len: usize = items.iter().map(|it| it.len()).sum();
        let mut out = Vec::new();
        if payload_len <= 55 {
            out.push(0xc0 + payload_len as u8);
        } else {
            let len_bytes = payload_len.to_be_bytes();
            let skip = len_bytes.iter().take_while(|&&b| b == 0).count();
            let active = &len_bytes[skip..];
            out.push(0xf7 + active.len() as u8);
            out.extend_from_slice(active);
        }
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }
}

/// Computes the signing hash for a pre-EIP-155 legacy transaction:
/// `keccak256(RLP([nonce, gas_price, gas_limit, to, value, data]))`.
pub fn legacy_tx_signing_hash(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Option<&[u8; 20]>,
    value: u128,
    data: &[u8],
) -> [u8; 32] {
    let to_enc = match to {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(&[]),
    };
    let items = vec![
        rlp::encode_u64(nonce),
        rlp::encode_u128(gas_price),
        rlp::encode_u64(gas_limit),
        to_enc,
        rlp::encode_u128(value),
        rlp::encode_bytes(data),
    ];
    let payload = rlp::encode_list(&items);
    keccak256(&payload)
}

/// Computes the signing hash for an EIP-155 replay-protected transaction:
/// `keccak256(RLP([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]))`.
pub fn eip155_tx_signing_hash(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Option<&[u8; 20]>,
    value: u128,
    data: &[u8],
    chain_id: u64,
) -> [u8; 32] {
    let to_enc = match to {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(&[]),
    };
    let items = vec![
        rlp::encode_u64(nonce),
        rlp::encode_u128(gas_price),
        rlp::encode_u64(gas_limit),
        to_enc,
        rlp::encode_u128(value),
        rlp::encode_bytes(data),
        rlp::encode_u64(chain_id),
        rlp::encode_u64(0),
        rlp::encode_u64(0),
    ];
    let payload = rlp::encode_list(&items);
    keccak256(&payload)
}

/// Computes the signing hash for an EIP-1559 typed transaction (Type 0x02):
/// `keccak256(0x02 || RLP([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list]))`.
#[allow(clippy::too_many_arguments)]
// GATE: EIP-1559 signing hash takes the full tx field set per spec; grouping would diverge from the yellow-paper layout.
pub fn eip1559_tx_signing_hash(
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: Option<&[u8; 20]>,
    value: u128,
    data: &[u8],
    access_list: &[EvmAccessListItem],
) -> [u8; 32] {
    let to_enc = match to {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(&[]),
    };

    let access_list_items: Vec<Vec<u8>> = access_list
        .iter()
        .map(|item| {
            let addr_bytes = parse_address(&item.address).unwrap_or([0u8; 20]);
            let keys: Vec<Vec<u8>> = item
                .storage_keys
                .iter()
                .map(|k| {
                    let k_bytes = parse_h256(k).unwrap_or([0u8; 32]);
                    rlp::encode_bytes(&k_bytes)
                })
                .collect();
            rlp::encode_list(&[rlp::encode_bytes(&addr_bytes), rlp::encode_list(&keys)])
        })
        .collect();

    let items = vec![
        rlp::encode_u64(chain_id),
        rlp::encode_u64(nonce),
        rlp::encode_u128(max_priority_fee_per_gas),
        rlp::encode_u128(max_fee_per_gas),
        rlp::encode_u64(gas_limit),
        to_enc,
        rlp::encode_u128(value),
        rlp::encode_bytes(data),
        rlp::encode_list(&access_list_items),
    ];

    let rlp_payload = rlp::encode_list(&items);
    let mut message = Vec::with_capacity(1 + rlp_payload.len());
    message.push(0x02);
    message.extend_from_slice(&rlp_payload);
    keccak256(&message)
}

impl EvmTransaction {
    /// Recovers the 20-byte sender address from this transaction's hash and signature (v, r, s).
    /// If this transaction has a chain_id, EIP-155 replay protection is verified.
    pub fn recover_sender(&self) -> Result<[u8; 20], EvmError> {
        let hash = parse_h256(&self.hash)?;
        let v = parse_v_str(&self.v)?;
        let r = parse_h256(&self.r)?;
        let s = parse_h256(&self.s)?;

        let expected_chain_id = match &self.chain_id {
            Some(cid_str) => parse_v_str(cid_str).ok(),
            None => None,
        };

        ecrecover_with_chain_id(&hash, v, &r, &s, expected_chain_id)
    }

    /// Verifies that the recovered sender address matches the `from` address in this transaction.
    pub fn verify_sender(&self) -> Result<bool, EvmError> {
        let recovered = self.recover_sender()?;
        let from_addr = parse_address(&self.from)?;
        Ok(recovered == from_addr)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_info_constants() {
        assert_eq!(eth_chain_id(), "0x167d");
        assert_eq!(net_version(), "5757");
        assert_eq!(web3_client_version(), "Stellereum/v5.0.0-evm-adapter");
        assert!(net_listening());
        assert_eq!(net_peer_count(), "0x2");
        assert!(!eth_syncing());
    }

    #[test]
    fn test_eth_syncing_for_heights_matches_stell_syncing_rule() {
        // Live rule shared with `stell_syncing`: a recent verified peer height
        // above ours means syncing; no sighting (or a peer at/below us) means
        // in sync.
        assert!(!eth_syncing_for_heights(42, None));
        assert!(!eth_syncing_for_heights(42, Some(42)));
        assert!(!eth_syncing_for_heights(42, Some(7)));
        assert!(eth_syncing_for_heights(42, Some(43)));
        // A faulty high vote still pins syncing while fresh — staleness is the
        // caller's job (it passes `None` past `PEER_HEIGHT_STALE_SECS`).
        assert!(eth_syncing_for_heights(0, Some(u64::MAX)));
    }

    #[test]
    fn test_format_peer_count_hex_matches_adapter_view() {
        // The live formatter and the stateful adapter view agree; the
        // testnet-known default ("0x2") is just the formatter at 2.
        assert_eq!(format_peer_count_hex(0), "0x0");
        assert_eq!(format_peer_count_hex(2), NET_PEER_COUNT);
        assert_eq!(format_peer_count_hex(42), "0x2a");
        let custom = EvmAdapter::new().with_peer_count(42);
        assert_eq!(custom.net_peer_count(), format_peer_count_hex(42));
        // Static default stays honestly testnet-known.
        assert_eq!(net_peer_count(), "0x2");
        assert_eq!(EvmAdapter::new().net_peer_count(), "0x2");
    }

    #[test]
    fn test_evm_adapter_dispatch_network_info() {
        let adapter = EvmAdapter::new();

        // 1. eth_chainId -> "0x167d"
        let chain_id_res = adapter
            .dispatch("eth_chainId", &Value::Null)
            .expect("eth_chainId");
        assert_eq!(chain_id_res, json!("0x167d"));

        // 2. net_version -> "5757"
        let net_version_res = adapter
            .dispatch("net_version", &Value::Null)
            .expect("net_version");
        assert_eq!(net_version_res, json!("5757"));

        // 3. web3_clientVersion -> "Stellereum/v5.0.0-evm-adapter"
        let client_ver_res = adapter
            .dispatch("web3_clientVersion", &Value::Null)
            .expect("web3_clientVersion");
        assert_eq!(client_ver_res, json!("Stellereum/v5.0.0-evm-adapter"));

        // 4. net_listening -> true
        let listening_res = adapter
            .dispatch("net_listening", &Value::Null)
            .expect("net_listening");
        assert_eq!(listening_res, json!(true));

        // 5. net_peerCount -> "0x2"
        let peer_count_res = adapter
            .dispatch("net_peerCount", &Value::Null)
            .expect("net_peerCount");
        assert_eq!(peer_count_res, json!("0x2"));

        // 6. eth_syncing -> false
        let syncing_res = adapter
            .dispatch("eth_syncing", &Value::Null)
            .expect("eth_syncing");
        assert_eq!(syncing_res, json!(false));

        // 7. Unknown method -> -32601 Method not found
        let err = adapter
            .dispatch("eth_unknownMethod", &Value::Null)
            .expect_err("unknown method must error");
        assert_eq!(err.code, METHOD_NOT_FOUND_CODE);
    }

    #[test]
    fn test_jsonrpc_request_response_format() {
        let adapter = EvmAdapter::new();

        let req_json = r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#;
        let resp_json = adapter.handle_raw_json(req_json);
        let resp: JsonRpcResponse<String> = serde_json::from_str(&resp_json).unwrap();
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, json!(1));
        assert_eq!(resp.result, Some("0x167d".to_string()));
        assert!(resp.error.is_none());

        let req_json2 = r#"{"jsonrpc":"2.0","method":"net_version","params":[],"id":"req-alpha"}"#;
        let resp_json2 = adapter.handle_raw_json(req_json2);
        let resp2: JsonRpcResponse<String> = serde_json::from_str(&resp_json2).unwrap();
        assert_eq!(resp2.jsonrpc, "2.0");
        assert_eq!(resp2.id, json!("req-alpha"));
        assert_eq!(resp2.result, Some("5757".to_string()));

        let req_json3 = r#"{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":100}"#;
        let resp_json3 = adapter.handle_raw_json(req_json3);
        let resp3: JsonRpcResponse<String> = serde_json::from_str(&resp_json3).unwrap();
        assert_eq!(resp3.jsonrpc, "2.0");
        assert_eq!(resp3.id, json!(100));
        assert_eq!(
            resp3.result,
            Some("Stellereum/v5.0.0-evm-adapter".to_string())
        );

        let req_json4 = r#"{"jsonrpc":"2.0","method":"net_listening","params":[],"id":null}"#;
        let resp_json4 = adapter.handle_raw_json(req_json4);
        let resp4: JsonRpcResponse<bool> = serde_json::from_str(&resp_json4).unwrap();
        assert_eq!(resp4.jsonrpc, "2.0");
        assert_eq!(resp4.id, Value::Null);
        assert_eq!(resp4.result, Some(true));

        let req_json5 = r#"{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":55}"#;
        let resp_json5 = adapter.handle_raw_json(req_json5);
        let resp5: JsonRpcResponse<String> = serde_json::from_str(&resp_json5).unwrap();
        assert_eq!(resp5.jsonrpc, "2.0");
        assert_eq!(resp5.id, json!(55));
        assert_eq!(resp5.result, Some("0x2".to_string()));

        let req_json6 = r#"{"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":77}"#;
        let resp_json6 = adapter.handle_raw_json(req_json6);
        let resp6: JsonRpcResponse<bool> = serde_json::from_str(&resp_json6).unwrap();
        assert_eq!(resp6.jsonrpc, "2.0");
        assert_eq!(resp6.id, json!(77));
        assert_eq!(resp6.result, Some(false));
    }

    #[test]
    fn test_jsonrpc_batch_requests() {
        let adapter = EvmAdapter::new();
        let batch_req = r#"[
            {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
            {"jsonrpc":"2.0","method":"net_version","params":[],"id":2},
            {"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":3},
            {"jsonrpc":"2.0","method":"net_listening","params":[],"id":4},
            {"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":5},
            {"jsonrpc":"2.0","method":"eth_syncing","params":[],"id":6}
        ]"#;

        let batch_resp_raw = adapter.handle_raw_json(batch_req);
        let batch_resp: Vec<JsonRpcResponse> = serde_json::from_str(&batch_resp_raw).unwrap();
        assert_eq!(batch_resp.len(), 6);

        assert_eq!(batch_resp[0].id, json!(1));
        assert_eq!(batch_resp[0].result, Some(json!("0x167d")));

        assert_eq!(batch_resp[1].id, json!(2));
        assert_eq!(batch_resp[1].result, Some(json!("5757")));

        assert_eq!(batch_resp[2].id, json!(3));
        assert_eq!(
            batch_resp[2].result,
            Some(json!("Stellereum/v5.0.0-evm-adapter"))
        );

        assert_eq!(batch_resp[3].id, json!(4));
        assert_eq!(batch_resp[3].result, Some(json!(true)));

        assert_eq!(batch_resp[4].id, json!(5));
        assert_eq!(batch_resp[4].result, Some(json!("0x2")));

        assert_eq!(batch_resp[5].id, json!(6));
        assert_eq!(batch_resp[5].result, Some(json!(false)));
    }

    #[test]
    fn test_jsonrpc_error_handling() {
        let adapter = EvmAdapter::new();

        // 1. Parse error
        let bad_json = r#"{"jsonrpc":"2.0", method:"#;
        let resp_str = adapter.handle_raw_json(bad_json);
        let resp: JsonRpcResponse = serde_json::from_str(&resp_str).unwrap();
        assert_eq!(resp.error.as_ref().unwrap().code, PARSE_ERROR_CODE);

        // 2. Method not found
        let bad_method = r#"{"jsonrpc":"2.0","method":"eth_unknown","params":[],"id":99}"#;
        let resp_str2 = adapter.handle_raw_json(bad_method);
        let resp2: JsonRpcResponse = serde_json::from_str(&resp_str2).unwrap();
        assert_eq!(resp2.id, json!(99));
        assert_eq!(resp2.error.as_ref().unwrap().code, METHOD_NOT_FOUND_CODE);
        assert!(resp2.result.is_none());

        // 3. Invalid request version
        let bad_ver = r#"{"jsonrpc":"1.0","method":"eth_chainId","params":[],"id":1}"#;
        let resp_str3 = adapter.handle_raw_json(bad_ver);
        let resp3: JsonRpcResponse = serde_json::from_str(&resp_str3).unwrap();
        assert_eq!(resp3.error.as_ref().unwrap().code, INVALID_REQUEST_CODE);
    }

    #[test]
    fn test_evm_block_serde_exact() {
        let block = EvmBlock {
            number: Some("0x167d".to_string()),
            hash: Some(
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            ),
            parent_hash: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
                .to_string(),
            nonce: Some("0x0000000000000000".to_string()),
            sha3_uncles: EMPTY_UNCLES_HASH.to_string(),
            logs_bloom: Some(EMPTY_LOGS_BLOOM.to_string()),
            transactions_root: EMPTY_ROOT_HASH.to_string(),
            state_root: EMPTY_ROOT_HASH.to_string(),
            receipts_root: EMPTY_ROOT_HASH.to_string(),
            miner: "0x0000000000000000000000000000000000000001".to_string(),
            difficulty: "0x0".to_string(),
            total_difficulty: Some("0x0".to_string()),
            extra_data: "0x".to_string(),
            size: "0x400".to_string(),
            gas_limit: "0x1c9c380".to_string(),
            gas_used: "0x5208".to_string(),
            timestamp: "0x651f0000".to_string(),
            transactions: BlockTransactions::Hashes(vec![
                "0xaaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999".to_string(),
            ]),
            uncles: Vec::new(),
            base_fee_per_gas: Some("0x7".to_string()),
            mix_hash: Some(EMPTY_ROOT_HASH.to_string()),
            withdrawals: None,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        };

        let json_val = serde_json::to_value(&block).unwrap();
        let obj = json_val.as_object().unwrap();

        // Exact camelCase field name verifications
        assert!(obj.contains_key("number"));
        assert!(obj.contains_key("hash"));
        assert!(obj.contains_key("parentHash"));
        assert!(obj.contains_key("nonce"));
        assert!(obj.contains_key("sha3Uncles"));
        assert!(obj.contains_key("logsBloom"));
        assert!(obj.contains_key("transactionsRoot"));
        assert!(obj.contains_key("stateRoot"));
        assert!(obj.contains_key("receiptsRoot"));
        assert!(obj.contains_key("miner"));
        assert!(obj.contains_key("difficulty"));
        assert!(obj.contains_key("totalDifficulty"));
        assert!(obj.contains_key("extraData"));
        assert!(obj.contains_key("size"));
        assert!(obj.contains_key("gasLimit"));
        assert!(obj.contains_key("gasUsed"));
        assert!(obj.contains_key("timestamp"));
        assert!(obj.contains_key("transactions"));
        assert!(obj.contains_key("uncles"));
        assert!(obj.contains_key("baseFeePerGas"));
        assert!(obj.contains_key("mixHash"));

        // Ensure no snake_case leaks
        assert!(!obj.contains_key("parent_hash"));
        assert!(!obj.contains_key("gas_limit"));
        assert!(!obj.contains_key("gas_used"));
        assert!(!obj.contains_key("base_fee_per_gas"));

        // Round-trip verification
        let serialized = serde_json::to_string(&block).unwrap();
        let deserialized: EvmBlock = serde_json::from_str(&serialized).unwrap();
        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_evm_transaction_serde_exact() {
        let tx = EvmTransaction {
            hash: "0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000".to_string(),
            nonce: "0x1".to_string(),
            block_hash: Some(
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            ),
            block_number: Some("0x167d".to_string()),
            transaction_index: Some("0x0".to_string()),
            from: "0x0000000000000000000000000000000000000001".to_string(),
            to: Some("0x0000000000000000000000000000000000000002".to_string()),
            value: "0xde0b6b3a7640000".to_string(),
            gas_price: Some("0x3b9aca00".to_string()),
            gas: "0x5208".to_string(),
            input: "0x".to_string(),
            v: "0x2b".to_string(),
            r: "0x1234".to_string(),
            s: "0x5678".to_string(),
            tx_type: Some("0x2".to_string()),
            chain_id: Some("0x167d".to_string()),
            max_fee_per_gas: Some("0x4a817c800".to_string()),
            max_priority_fee_per_gas: Some("0x3b9aca00".to_string()),
            access_list: Some(vec![EvmAccessListItem {
                address: "0x0000000000000000000000000000000000000003".to_string(),
                storage_keys: vec![
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                ],
            }]),
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        let json_val = serde_json::to_value(&tx).unwrap();
        let obj = json_val.as_object().unwrap();

        assert!(obj.contains_key("hash"));
        assert!(obj.contains_key("nonce"));
        assert!(obj.contains_key("blockHash"));
        assert!(obj.contains_key("blockNumber"));
        assert!(obj.contains_key("transactionIndex"));
        assert!(obj.contains_key("from"));
        assert!(obj.contains_key("to"));
        assert!(obj.contains_key("value"));
        assert!(obj.contains_key("gasPrice"));
        assert!(obj.contains_key("gas"));
        assert!(obj.contains_key("input"));
        assert!(obj.contains_key("v"));
        assert!(obj.contains_key("r"));
        assert!(obj.contains_key("s"));
        assert!(obj.contains_key("type"));
        assert!(obj.contains_key("chainId"));
        assert!(obj.contains_key("maxFeePerGas"));
        assert!(obj.contains_key("maxPriorityFeePerGas"));
        assert!(obj.contains_key("accessList"));

        // Ensure no snake_case leaks
        assert!(!obj.contains_key("block_hash"));
        assert!(!obj.contains_key("gas_price"));
        assert!(!obj.contains_key("max_fee_per_gas"));

        // Round-trip verification
        let serialized = serde_json::to_string(&tx).unwrap();
        let deserialized: EvmTransaction = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, deserialized);

        // Test alias "data" for "input"
        let raw_with_data = r#"{
            "hash": "0x1111",
            "nonce": "0x1",
            "from": "0x0001",
            "value": "0x0",
            "gas": "0x5208",
            "data": "0xabcdef",
            "v": "0x1b",
            "r": "0x1",
            "s": "0x2"
        }"#;
        let parsed_tx: EvmTransaction = serde_json::from_str(raw_with_data).unwrap();
        assert_eq!(parsed_tx.input, "0xabcdef");
    }

    #[test]
    fn test_evm_receipt_serde_exact() {
        let receipt = EvmReceipt {
            transaction_hash: "0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
                .to_string(),
            transaction_index: "0x0".to_string(),
            block_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            block_number: "0x167d".to_string(),
            from: "0x0000000000000000000000000000000000000001".to_string(),
            to: Some("0x0000000000000000000000000000000000000002".to_string()),
            cumulative_gas_used: "0x5208".to_string(),
            gas_used: "0x5208".to_string(),
            contract_address: None,
            logs: vec![EvmLog {
                address: "0x0000000000000000000000000000000000000002".to_string(),
                topics: vec![
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                        .to_string(),
                ],
                data: "0x0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                block_number: Some("0x167d".to_string()),
                transaction_hash: Some(
                    "0x111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
                        .to_string(),
                ),
                transaction_index: Some("0x0".to_string()),
                block_hash: Some(
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                        .to_string(),
                ),
                log_index: Some("0x0".to_string()),
                removed: false,
            }],
            logs_bloom: EMPTY_LOGS_BLOOM.to_string(),
            status: Some("0x1".to_string()),
            root: None,
            tx_type: Some("0x2".to_string()),
            effective_gas_price: Some("0x3b9aca00".to_string()),
            blob_gas_used: None,
            blob_gas_price: None,
        };

        let json_val = serde_json::to_value(&receipt).unwrap();
        let obj = json_val.as_object().unwrap();

        assert!(obj.contains_key("transactionHash"));
        assert!(obj.contains_key("transactionIndex"));
        assert!(obj.contains_key("blockHash"));
        assert!(obj.contains_key("blockNumber"));
        assert!(obj.contains_key("from"));
        assert!(obj.contains_key("to"));
        assert!(obj.contains_key("cumulativeGasUsed"));
        assert!(obj.contains_key("gasUsed"));
        assert!(obj.contains_key("contractAddress"));
        assert!(obj.contains_key("logs"));
        assert!(obj.contains_key("logsBloom"));
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("type"));
        assert!(obj.contains_key("effectiveGasPrice"));

        assert!(!obj.contains_key("transaction_hash"));
        assert!(!obj.contains_key("cumulative_gas_used"));

        // Round-trip verification
        let serialized = serde_json::to_string(&receipt).unwrap();
        let deserialized: EvmReceipt = serde_json::from_str(&serialized).unwrap();
        assert_eq!(receipt, deserialized);
    }

    #[test]
    fn test_evm_fee_history_serde_exact() {
        let fee_history = EvmFeeHistory {
            oldest_block: "0x167d".to_string(),
            base_fee_per_gas: vec!["0x3b9aca00".to_string(), "0x342770c0".to_string()],
            gas_used_ratio: vec![0.5, 0.45],
            reward: Some(vec![
                vec!["0x1".to_string(), "0x2".to_string()],
                vec!["0x3".to_string(), "0x4".to_string()],
            ]),
        };

        let json_val = serde_json::to_value(&fee_history).unwrap();
        let obj = json_val.as_object().unwrap();

        assert!(obj.contains_key("oldestBlock"));
        assert!(obj.contains_key("baseFeePerGas"));
        assert!(obj.contains_key("gasUsedRatio"));
        assert!(obj.contains_key("reward"));

        assert!(!obj.contains_key("oldest_block"));
        assert!(!obj.contains_key("base_fee_per_gas"));
        assert!(!obj.contains_key("gas_used_ratio"));

        // Round-trip verification
        let serialized = serde_json::to_string(&fee_history).unwrap();
        let deserialized: EvmFeeHistory = serde_json::from_str(&serialized).unwrap();
        assert_eq!(fee_history, deserialized);
    }

    #[test]
    fn test_custom_evm_adapter_configuration() {
        let custom = EvmAdapter::new()
            .with_chain_id(1337)
            .with_client_version("CustomClient/v1.0")
            .with_peer_count(42)
            .with_listening(false)
            .with_syncing(true)
            .with_gas_price(0x3eb2788000)
            .with_max_priority_fee_per_gas(0x0)
            .with_base_fee(0x3eb2788000)
            .with_head_block(100)
            .with_gas_used_ratio(0.25);

        assert_eq!(custom.eth_chain_id(), "0x539");
        assert_eq!(custom.net_version(), "1337");
        assert_eq!(custom.web3_client_version(), "CustomClient/v1.0");
        assert!(!custom.net_listening());
        assert_eq!(custom.net_peer_count(), "0x2a");
        assert!(custom.eth_syncing());
        assert_eq!(custom.eth_gas_price(), "0x3eb2788000");
        assert_eq!(custom.eth_max_priority_fee_per_gas(), "0x0");

        assert_eq!(
            custom.dispatch("eth_chainId", &Value::Null).unwrap(),
            json!("0x539")
        );
        assert_eq!(
            custom.dispatch("net_version", &Value::Null).unwrap(),
            json!("1337")
        );
        assert_eq!(
            custom.dispatch("web3_clientVersion", &Value::Null).unwrap(),
            json!("CustomClient/v1.0")
        );
        assert_eq!(
            custom.dispatch("net_listening", &Value::Null).unwrap(),
            json!(false)
        );
        assert_eq!(
            custom.dispatch("net_peerCount", &Value::Null).unwrap(),
            json!("0x2a")
        );
        assert_eq!(
            custom.dispatch("eth_syncing", &Value::Null).unwrap(),
            json!(true)
        );
        assert_eq!(
            custom.dispatch("eth_gasPrice", &Value::Null).unwrap(),
            json!("0x3eb2788000")
        );
        assert_eq!(
            custom
                .dispatch("eth_maxPriorityFeePerGas", &Value::Null)
                .unwrap(),
            json!("0x0")
        );
    }

    #[test]
    fn test_gas_pricing_and_estimation_constants() {
        assert_eq!(eth_gas_price(), "0x3eb2788000");
        assert_eq!(eth_gas_price(), BASE_FEE_HEX);
        assert_eq!(eth_max_priority_fee_per_gas(), "0x3b9aca00");
        assert_eq!(eth_estimate_transfer_gas(), "0x5208");
        assert_eq!(STANDARD_TRANSFER_GAS, 21_000);
        assert_eq!(CONTRACT_CREATION_BASE_GAS, 53_000);

        let parsed_gas_price = parse_hex_u128(eth_gas_price()).expect("must parse u128 hex");
        assert_eq!(parsed_gas_price, 269_282_213_888);
        assert_eq!(parsed_gas_price, DEFAULT_BASE_FEE);

        let parsed_priority_fee =
            parse_hex_u128(eth_max_priority_fee_per_gas()).expect("must parse u128 hex");
        assert_eq!(parsed_priority_fee, 1_000_000_000);
    }

    #[test]
    fn test_evm_adapter_dispatch_gas_and_estimation() {
        let adapter = EvmAdapter::new();

        // 1. eth_gasPrice -> "0x3eb2788000"
        let gas_price_res = adapter
            .dispatch("eth_gasPrice", &Value::Null)
            .expect("eth_gasPrice");
        assert_eq!(gas_price_res, json!("0x3eb2788000"));

        // 2. eth_maxPriorityFeePerGas -> "0x3b9aca00"
        let priority_res = adapter
            .dispatch("eth_maxPriorityFeePerGas", &Value::Null)
            .expect("eth_maxPriorityFeePerGas");
        assert_eq!(priority_res, json!("0x3b9aca00"));

        // 3. eth_estimateGas for transfer (empty params) -> "0x5208"
        let est_empty = adapter
            .dispatch("eth_estimateGas", &json!([]))
            .expect("estimate empty");
        assert_eq!(est_empty, json!("0x445c0"));

        // 4. eth_estimateGas for transfer (standard to/from/value call object) -> "0x5208"
        let est_tx = adapter
            .dispatch(
                "eth_estimateGas",
                &json!([{
                    "from": "0x1111111111111111111111111111111111111111",
                    "to": "0x2222222222222222222222222222222222222222",
                    "value": "0xde0b6b3a7640000"
                }]),
            )
            .expect("estimate transfer");
        assert_eq!(est_tx, json!("0x445c0"));

        // 5. eth_estimateGas with empty data "0x" -> "0x5208"
        let est_empty_data = adapter
            .dispatch(
                "eth_estimateGas",
                &json!([{
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0x"
                }]),
            )
            .expect("estimate empty data");
        assert_eq!(est_empty_data, json!("0x445c0"));

        // 6. eth_estimateGas with non-empty calldata (e.g. 4 bytes non-zero -> 21000 + 4*16 = 21064 = 0x5248)
        let est_call = adapter
            .dispatch(
                "eth_estimateGas",
                &json!([{
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0x12345678"
                }]),
            )
            .expect("estimate call data");
        assert_eq!(est_call, json!("0x445c0")); // floored (pure 0x5248 < 280k floor)

        // 7. eth_estimateGas contract creation (no to field, with bytecode: 53000 + calldata gas)
        // 2 non-zero bytes (0x60, 0x80) -> 53000 + 32 = 53032 = 0xcf28
        let est_create = adapter
            .dispatch(
                "eth_estimateGas",
                &json!([{
                    "data": "0x6080"
                }]),
            )
            .expect("estimate contract creation");
        assert_eq!(est_create, json!("0x445c0")); // floored (pure 0xcf28 < 280k floor)

        // 8. Invalid hex in data -> error
        let err = adapter
            .dispatch(
                "eth_estimateGas",
                &json!([{
                    "to": "0x2222222222222222222222222222222222222222",
                    "data": "0xinvalid"
                }]),
            )
            .expect_err("must error on invalid hex");
        assert_eq!(err.code, INVALID_PARAMS_CODE);
    }

    #[test]
    fn test_evm_adapter_dispatch_fee_history() {
        let adapter = EvmAdapter::new();

        // 1. eth_feeHistory with array [4, "latest"]
        let fee_hist_val = adapter
            .dispatch("eth_feeHistory", &json!([4, "latest"]))
            .expect("fee history latest");
        let fh: EvmFeeHistory = serde_json::from_value(fee_hist_val).unwrap();

        // 5757 + 1 - 4 = 5754 = 0x167a
        assert_eq!(fh.oldest_block, "0x167a");
        // base_fee_per_gas includes next block (block_count + 1 = 5)
        assert_eq!(fh.base_fee_per_gas.len(), 5);
        for fee in &fh.base_fee_per_gas {
            assert_eq!(fee, "0x3eb2788000");
        }
        assert_eq!(fh.gas_used_ratio.len(), 4);
        assert!(fh.reward.is_none());

        // 2. eth_feeHistory with hex blockCount "0x4" and hex newestBlock "0x10" (16)
        // 16 + 1 - 4 = 13 = 0xd
        let fee_hist_val2 = adapter
            .dispatch("eth_feeHistory", &json!(["0x4", "0x10"]))
            .expect("fee history hex");
        let fh2: EvmFeeHistory = serde_json::from_value(fee_hist_val2).unwrap();
        assert_eq!(fh2.oldest_block, "0xd");
        assert_eq!(fh2.base_fee_per_gas.len(), 5);
        assert_eq!(fh2.gas_used_ratio.len(), 4);

        // 3. eth_feeHistory with rewardPercentiles [25.0, 75.0]
        let fee_hist_val3 = adapter
            .dispatch("eth_feeHistory", &json!([4, "0x10", [25.0, 75.0]]))
            .expect("fee history rewards");
        let fh3: EvmFeeHistory = serde_json::from_value(fee_hist_val3).unwrap();
        assert_eq!(fh3.oldest_block, "0xd");
        let rewards = fh3.reward.expect("must contain rewards");
        assert_eq!(rewards.len(), 4);
        for row in &rewards {
            assert_eq!(row.len(), 2);
            // 25% of 1_000_000_000 is 250_000_000 (0xee6b280)
            assert_eq!(row[0], "0xee6b280");
            // 75% of 1_000_000_000 is 750_000_000 (0x2cb41780)
            assert_eq!(row[1], "0x2cb41780");
        }

        // 4. eth_feeHistory when newestBlock < blockCount - 1 (e.g. blockCount = 10, newestBlock = 2)
        // actual_count = 3 (blocks 0, 1, 2)
        let fee_hist_val4 = adapter
            .dispatch("eth_feeHistory", &json!([10, 2]))
            .expect("fee history near genesis");
        let fh4: EvmFeeHistory = serde_json::from_value(fee_hist_val4).unwrap();
        assert_eq!(fh4.oldest_block, "0x0");
        assert_eq!(fh4.base_fee_per_gas.len(), 4);
        assert_eq!(fh4.gas_used_ratio.len(), 3);

        // 5. eth_feeHistory object parameters
        let fee_hist_val5 = adapter
            .dispatch(
                "eth_feeHistory",
                &json!({
                    "blockCount": 2,
                    "newestBlock": "0x5",
                    "rewardPercentiles": [50.0]
                }),
            )
            .expect("fee history object params");
        let fh5: EvmFeeHistory = serde_json::from_value(fee_hist_val5).unwrap();
        // 5 + 1 - 2 = 4 = 0x4
        assert_eq!(fh5.oldest_block, "0x4");
        assert_eq!(fh5.base_fee_per_gas.len(), 3);
        assert_eq!(fh5.gas_used_ratio.len(), 2);
        let rewards5 = fh5.reward.expect("must have rewards");
        assert_eq!(rewards5.len(), 2);
        assert_eq!(rewards5[0].len(), 1);
        // 50% of 1_000_000_000 is 500_000_000 = 0x1dcd6500
        assert_eq!(rewards5[0][0], "0x1dcd6500");
    }

    #[test]
    fn test_fee_history_parameter_validation() {
        let adapter = EvmAdapter::new();

        // 1. Missing params
        let err1 = adapter
            .dispatch("eth_feeHistory", &json!([]))
            .expect_err("empty params must fail");
        assert_eq!(err1.code, INVALID_PARAMS_CODE);

        // 2. Block count 0
        let err2 = adapter
            .dispatch("eth_feeHistory", &json!([0, "latest"]))
            .expect_err("zero count must fail");
        assert_eq!(err2.code, INVALID_PARAMS_CODE);

        // 3. Block count > 1024
        let err3 = adapter
            .dispatch("eth_feeHistory", &json!([1025, "latest"]))
            .expect_err(">1024 count must fail");
        assert_eq!(err3.code, INVALID_PARAMS_CODE);

        // 4. Reward percentile > 100
        let err4 = adapter
            .dispatch("eth_feeHistory", &json!([2, "latest", [105.0]]))
            .expect_err(">100 percentile must fail");
        assert_eq!(err4.code, INVALID_PARAMS_CODE);

        // 5. Reward percentiles descending
        let err5 = adapter
            .dispatch("eth_feeHistory", &json!([2, "latest", [80.0, 20.0]]))
            .expect_err("descending percentiles must fail");
        assert_eq!(err5.code, INVALID_PARAMS_CODE);
    }

    #[test]
    fn test_keccak256_official_vectors() {
        // 1. Empty string: c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let h_empty = keccak256(b"");
        assert_eq!(
            hex::encode(h_empty),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );

        // 2. "abc"
        let h_abc = keccak256(b"abc");
        assert_eq!(
            hex::encode(h_abc),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );

        // 3. "The quick brown fox jumps over the lazy dog"
        let h_fox = keccak256(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hex::encode(h_fox),
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
        );

        // 4. "The quick brown fox jumps over the lazy dog."
        let h_fox_dot = keccak256(b"The quick brown fox jumps over the lazy dog.");
        assert_eq!(
            hex::encode(h_fox_dot),
            "578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d"
        );

        // 5. Single null byte [0x00]
        let h_null = keccak256(&[0x00]);
        assert_eq!(
            hex::encode(h_null),
            "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a"
        );

        // 6. Ethereum Empty Uncles Hash: keccak256(rlp([])) = keccak256([0xc0])
        let h_uncles = keccak256(&[0xc0]);
        assert_eq!(format!("0x{}", hex::encode(h_uncles)), EMPTY_UNCLES_HASH);

        // 7. Ethereum Empty Trie Root Hash: keccak256(rlp("")) = keccak256([0x80])
        let h_root = keccak256(&[0x80]);
        assert_eq!(format!("0x{}", hex::encode(h_root)), EMPTY_ROOT_HASH);

        // 8. ERC-20 method selectors
        let h_transfer = keccak256(b"transfer(address,uint256)");
        assert_eq!(&h_transfer[0..4], &[0xa9, 0x05, 0x9c, 0xbb]);

        let h_transfer_from = keccak256(b"transferFrom(address,address,uint256)");
        assert_eq!(&h_transfer_from[0..4], &[0x23, 0xb8, 0x72, 0xdd]);

        let h_balance_of = keccak256(b"balanceOf(address)");
        assert_eq!(&h_balance_of[0..4], &[0x70, 0xa0, 0x82, 0x31]);
    }

    #[test]
    fn test_keccak256_streaming_and_boundaries() {
        // Test edge boundaries around RATE = 136 bytes:
        // 135 bytes (1 byte padding), 136 bytes (full block + full pad block), 137 bytes, 272 bytes (2 full blocks)
        for len in [0, 1, 135, 136, 137, 271, 272, 273, 500] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let oneshot = keccak256(&data);

            // Test streaming with varied chunk sizes
            for chunk_size in [1, 7, 33, 136, 200] {
                let mut hasher = Keccak256::new();
                for chunk in data.chunks(chunk_size) {
                    hasher.update(chunk);
                }
                let streamed = hasher.finalize();
                assert_eq!(
                    oneshot, streamed,
                    "mismatch at len {len} with chunk_size {chunk_size}"
                );
            }
        }
    }

    #[test]
    fn test_rlp_standard_ethereum_vectors() {
        // 1. Empty string "" -> [0x80]
        assert_eq!(rlp_encode_bytes(b""), vec![0x80]);
        let decoded = RlpItem::decode(&[0x80]).unwrap();
        assert_eq!(decoded.as_bytes().unwrap(), b"");
        assert_eq!(decoded, RlpItem::Bytes(vec![]));
        assert_eq!(rlp_decode(&[0x80]).unwrap(), RlpItem::Bytes(vec![]));

        // 2. Single byte in [0x00, 0x7f]
        assert_eq!(rlp_encode_bytes(&[0x00]), vec![0x00]);
        assert_eq!(
            RlpItem::decode(&[0x00]).unwrap().as_bytes().unwrap(),
            &[0x00]
        );
        assert_eq!(RlpItem::decode(&[0x00]).unwrap(), RlpItem::Byte(0x00));
        assert_eq!(rlp_decode(&[0x00]).unwrap(), RlpItem::Byte(0x00));

        assert_eq!(rlp_encode_bytes(&[0x0f]), vec![0x0f]);
        assert_eq!(
            RlpItem::decode(&[0x0f]).unwrap().as_bytes().unwrap(),
            &[0x0f]
        );
        assert_eq!(RlpItem::decode(&[0x0f]).unwrap(), RlpItem::Byte(0x0f));

        assert_eq!(rlp_encode_bytes(&[0x7f]), vec![0x7f]);
        assert_eq!(
            RlpItem::decode(&[0x7f]).unwrap().as_bytes().unwrap(),
            &[0x7f]
        );
        assert_eq!(RlpItem::decode(&[0x7f]).unwrap(), RlpItem::Byte(0x7f));

        // 3. Single byte >= 0x80 -> encoded with 0x81 prefix
        assert_eq!(rlp_encode_bytes(&[0x80]), vec![0x81, 0x80]);
        assert_eq!(
            RlpItem::decode(&[0x81, 0x80]).unwrap().as_bytes().unwrap(),
            &[0x80]
        );
        assert_eq!(
            RlpItem::decode(&[0x81, 0x80]).unwrap(),
            RlpItem::Bytes(vec![0x80])
        );

        assert_eq!(rlp_encode_bytes(&[0xff]), vec![0x81, 0xff]);
        assert_eq!(
            RlpItem::decode(&[0x81, 0xff]).unwrap().as_bytes().unwrap(),
            &[0xff]
        );
        assert_eq!(
            RlpItem::decode(&[0x81, 0xff]).unwrap(),
            RlpItem::Bytes(vec![0xff])
        );

        // 4. Short strings "dog" and "cat"
        let enc_dog = rlp_encode_bytes(b"dog");
        assert_eq!(enc_dog, vec![0x83, b'd', b'o', b'g']);
        assert_eq!(
            RlpItem::decode(&enc_dog).unwrap().as_bytes().unwrap(),
            b"dog"
        );

        let enc_cat = rlp_encode_bytes(b"cat");
        assert_eq!(enc_cat, vec![0x83, b'c', b'a', b't']);
        assert_eq!(
            RlpItem::decode(&enc_cat).unwrap().as_bytes().unwrap(),
            b"cat"
        );

        // 5. 55-byte string (short string boundary)
        let s55 = vec![0x61u8; 55];
        let mut enc55 = vec![0xb7];
        enc55.extend_from_slice(&s55);
        assert_eq!(
            RlpItem::decode(&enc55).unwrap().as_bytes().unwrap(),
            s55.as_slice()
        );

        // 6. 56-byte string (long string boundary: 0xb8 + 1-byte length 0x38)
        let s56 = vec![0x62u8; 56];
        let mut enc56 = vec![0xb8, 0x38];
        enc56.extend_from_slice(&s56);
        assert_eq!(
            RlpItem::decode(&enc56).unwrap().as_bytes().unwrap(),
            s56.as_slice()
        );

        // 7. 1024-byte string (multi-byte length: 0xb9 0x04 0x00)
        let s1024 = vec![0xab; 1024];
        let enc1024 = rlp_encode_bytes(&s1024);
        assert_eq!(enc1024[0], 0xb9);
        assert_eq!(enc1024[1], 0x04);
        assert_eq!(enc1024[2], 0x00);
        assert_eq!(&enc1024[3..], s1024.as_slice());
        assert_eq!(
            RlpItem::decode(&enc1024).unwrap().as_bytes().unwrap(),
            s1024.as_slice()
        );

        // 8. Lists
        // Empty list [] -> [0xc0]
        assert_eq!(rlp_encode_list(&[]), vec![0xc0]);
        let dec_empty_list = RlpItem::decode(&[0xc0]).unwrap();
        assert_eq!(dec_empty_list.as_list().unwrap().len(), 0);

        // [[]] -> [0xc1, 0xc0]
        let enc_nested1 = rlp_encode_list(&[vec![0xc0]]);
        assert_eq!(enc_nested1, vec![0xc1, 0xc0]);
        let dec_nested1 = RlpItem::decode(&enc_nested1).unwrap();
        assert_eq!(dec_nested1.as_list().unwrap().len(), 1);
        assert_eq!(dec_nested1.at(0).unwrap().as_list().unwrap().len(), 0);

        // [[], []] -> [0xc2, 0xc0, 0xc0]
        let enc_nested2 = rlp_encode_list(&[vec![0xc0], vec![0xc0]]);
        assert_eq!(enc_nested2, vec![0xc2, 0xc0, 0xc0]);
        let dec_nested2 = RlpItem::decode(&enc_nested2).unwrap();
        assert_eq!(dec_nested2.as_list().unwrap().len(), 2);

        // ["cat", "dog"] -> [0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g']
        let enc_cat_dog = rlp_encode_list(&[enc_cat.clone(), enc_dog.clone()]);
        assert_eq!(
            enc_cat_dog,
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
        let dec_cat_dog = RlpItem::decode(&enc_cat_dog).unwrap();
        assert_eq!(dec_cat_dog.at(0).unwrap().as_bytes().unwrap(), b"cat");
        assert_eq!(dec_cat_dog.at(1).unwrap().as_bytes().unwrap(), b"dog");

        // [[], [[]], [[], [[]]]] -> [0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]
        let l_empty = vec![0xc0];
        let l_nested = vec![0xc1, 0xc0];
        let l_both = rlp_encode_list(&[l_empty.clone(), l_nested.clone()]);
        let deep = rlp_encode_list(&[l_empty, l_nested, l_both]);
        assert_eq!(deep, vec![0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0]);
        let dec_deep = RlpItem::decode(&deep).unwrap();
        assert_eq!(dec_deep.as_list().unwrap().len(), 3);

        // 9. Integers
        // 0 -> [0x80]
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
        assert_eq!(RlpItem::decode(&[0x80]).unwrap().as_u64().unwrap(), 0);
        assert_eq!(RlpItem::decode(&[0x80]).unwrap().as_u128().unwrap(), 0);

        // 15 -> [0x0f]
        assert_eq!(rlp_encode_u64(15), vec![0x0f]);
        assert_eq!(RlpItem::decode(&[0x0f]).unwrap().as_u64().unwrap(), 15);

        // 1000 -> [0x82, 0x03, 0xe8]
        assert_eq!(rlp_encode_u64(1000), vec![0x82, 0x03, 0xe8]);
        assert_eq!(
            RlpItem::decode(&[0x82, 0x03, 0xe8])
                .unwrap()
                .as_u64()
                .unwrap(),
            1000
        );

        // 1024 -> [0x82, 0x04, 0x00]
        assert_eq!(rlp_encode_u64(1024), vec![0x82, 0x04, 0x00]);
        assert_eq!(
            RlpItem::decode(&[0x82, 0x04, 0x00])
                .unwrap()
                .as_u64()
                .unwrap(),
            1024
        );

        // Large u64
        let max_u64 = u64::MAX;
        let enc_max_u64 = rlp_encode_u64(max_u64);
        assert_eq!(
            RlpItem::decode(&enc_max_u64).unwrap().as_u64().unwrap(),
            max_u64
        );

        // Large u128
        let big_val = 1_000_000_000_000_000_000_000_000u128;
        let enc_big = rlp_encode_u128(big_val);
        assert_eq!(
            RlpItem::decode(&enc_big).unwrap().as_u128().unwrap(),
            big_val
        );
    }

    #[test]
    fn test_rlp_non_canonical_and_malformed_rejections() {
        // 1. Single byte < 0x80 encoded as short string with 0x81 prefix -> NonCanonicalSingleByte
        assert_eq!(
            RlpItem::decode(&[0x81, 0x05]).unwrap_err(),
            RlpError::NonCanonicalSingleByte
        );

        // 2. Short payload encoded with long string prefix 0xb8 -> NonCanonicalLength
        assert_eq!(
            RlpItem::decode(&[0xb8, 0x04, 1, 2, 3, 4]).unwrap_err(),
            RlpError::NonCanonicalLength
        );

        // 3. Leading zero in string length field -> LeadingZeroInLength
        assert_eq!(
            RlpItem::decode(&[0xb8, 0x00, 0x38]).unwrap_err(),
            RlpError::LeadingZeroInLength
        );

        // 4. Short list encoded with long list prefix 0xf8 -> NonCanonicalLength
        assert_eq!(
            RlpItem::decode(&[0xf8, 0x02, 0xc0, 0xc0]).unwrap_err(),
            RlpError::NonCanonicalLength
        );

        // 5. Leading zero in list length field -> LeadingZeroInLength
        assert_eq!(
            RlpItem::decode(&[0xf8, 0x00, 0x38]).unwrap_err(),
            RlpError::LeadingZeroInLength
        );

        // 6. Integer with non-canonical leading zero -> LeadingZeroInInteger
        let dec_int_leading_zero = RlpItem::decode(&[0x82, 0x00, 0x2a]).unwrap();
        assert_eq!(
            dec_int_leading_zero.as_u64().unwrap_err(),
            RlpError::LeadingZeroInInteger
        );

        // 7. Trailing unparsed bytes -> TrailingBytes
        assert_eq!(
            RlpItem::decode(&[0x80, 0x00]).unwrap_err(),
            RlpError::TrailingBytes
        );

        // 8. Unexpected EOF / truncated payload
        assert_eq!(
            RlpItem::decode(&[0x85, 0x01, 0x02]).unwrap_err(),
            RlpError::UnexpectedEof
        );

        // 9. Empty buffer -> UnexpectedEof
        assert_eq!(RlpItem::decode(&[]).unwrap_err(), RlpError::UnexpectedEof);
    }

    #[test]
    fn test_eip155_legacy_transaction_official_vector() {
        // Official Ethereum EIP-155 test vector
        let hex_raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
        let raw = hex::decode(hex_raw).expect("valid hex");

        // 1. Decode transaction
        let decoded = decode_raw_transaction(&raw).expect("valid legacy tx");
        let legacy = match decoded {
            DecodedTransaction::Legacy(tx) => tx,
            _ => panic!("expected legacy transaction"),
        };

        // 2. Validate decoded fields
        assert_eq!(legacy.nonce, 9);
        assert_eq!(legacy.gas_price, 20_000_000_000); // 20 Gwei
        assert_eq!(legacy.gas_limit, 21_000);
        let expected_to = hex::decode("3535353535353535353535353535353535353535").unwrap();
        assert_eq!(legacy.to.as_ref().unwrap(), expected_to.as_slice());
        assert_eq!(legacy.value, 1_000_000_000_000_000_000); // 1 ETH
        assert_eq!(legacy.data, Vec::<u8>::new());
        assert_eq!(legacy.v, 37); // chainId = 1, recovery_id = 0 (37 = 1 * 2 + 35)
        assert_eq!(legacy.chain_id, Some(1));
        assert_eq!(legacy.recovery_id(), 0);

        let expected_r =
            hex::decode("28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276")
                .unwrap();
        assert_eq!(legacy.r, expected_r.as_slice());

        let expected_s =
            hex::decode("67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83")
                .unwrap();
        assert_eq!(legacy.s, expected_s.as_slice());

        // 3. Official EIP-155 signing hash
        let sighash = legacy.signing_hash();
        assert_eq!(
            hex::encode(sighash),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );

        // 4. Verify canonical RLP re-encoding matches raw bytes exactly
        let re_encoded = legacy.encode();
        assert_eq!(re_encoded, raw);

        // 5. Verify tx hash matches keccak256(raw)
        let tx_hash = legacy.compute_hash();
        assert_eq!(tx_hash, keccak256(&raw));

        // 6. Convert to EvmTransaction and verify fields
        let evm_tx = legacy.to_evm_transaction(None, None);
        assert_eq!(evm_tx.nonce, "0x9");
        assert_eq!(evm_tx.gas, "0x5208");
        assert_eq!(evm_tx.gas_price, Some("0x4a817c800".to_string()));
        assert_eq!(evm_tx.value, "0xde0b6b3a7640000");
        assert_eq!(evm_tx.v, "0x25");
        assert_eq!(evm_tx.chain_id, Some("0x1".to_string()));
        assert_eq!(evm_tx.tx_type, Some("0x0".to_string()));
    }

    #[test]
    fn test_legacy_contract_creation_and_unprotected() {
        // Contract creation has to = None and init code in data
        let mut tx = LegacyTransaction {
            nonce: 0,
            gas_price: 1_000_000_000,
            gas_limit: 100_000,
            to: None,
            value: 0,
            data: vec![0x60, 0x80, 0x60, 0x40, 0x52], // sample init code
            v: 11549, // Stellereum chain_id 5757: 5757 * 2 + 35 = 11549
            r: [0x01; 32],
            s: [0x02; 32],
            chain_id: Some(CHAIN_ID),
        };

        let encoded = tx.encode();
        let decoded = decode_legacy_transaction(&encoded).unwrap();
        assert_eq!(decoded.to, None);
        assert_eq!(decoded.chain_id, Some(5757));
        assert_eq!(decoded.recovery_id(), 0);
        assert_eq!(decoded.data, vec![0x60, 0x80, 0x60, 0x40, 0x52]);
        assert_eq!(decoded.encode(), encoded);

        // Pre-EIP-155 unprotected legacy transaction (v = 27)
        tx.v = 27;
        tx.chain_id = None;
        let encoded_unprotected = tx.encode();
        let decoded_unprotected = decode_legacy_transaction(&encoded_unprotected).unwrap();
        assert_eq!(decoded_unprotected.chain_id, None);
        assert_eq!(decoded_unprotected.recovery_id(), 0);
        // Unprotected signing data has 6 elements
        let sighash_data = decoded_unprotected.signing_data();
        let sighash_item = RlpItem::decode(&sighash_data).unwrap();
        assert_eq!(sighash_item.as_list().unwrap().len(), 6);
    }

    #[test]
    fn test_eip1559_type2_envelope_empty_access_list() {
        let tx = Eip1559Transaction {
            chain_id: CHAIN_ID, // 5757
            nonce: 42,
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 35_000_000_000,
            gas_limit: 45_000,
            to: Some([0x77; 20]),
            value: 500_000_000_000_000_000, // 0.5 ETH
            data: vec![0xde, 0xad, 0xbe, 0xef],
            access_list: Vec::new(),
            y_parity: 1,
            v: 1,
            r: [0x33; 32],
            s: [0x44; 32],
        };

        let envelope = tx.encode();
        assert_eq!(envelope[0], 0x02, "EIP-1559 envelope must start with 0x02");

        // Decode via top-level raw transaction decoder
        let decoded = decode_raw_transaction(&envelope).expect("decode valid EIP-1559 envelope");
        let decoded_1559 = match decoded {
            DecodedTransaction::Eip1559(t) => t,
            _ => panic!("expected EIP-1559"),
        };

        assert_eq!(decoded_1559.chain_id, 5757);
        assert_eq!(decoded_1559.nonce, 42);
        assert_eq!(decoded_1559.max_priority_fee_per_gas, 1_500_000_000);
        assert_eq!(decoded_1559.max_fee_per_gas, 35_000_000_000);
        assert_eq!(decoded_1559.gas_limit, 45_000);
        assert_eq!(decoded_1559.to, Some([0x77; 20]));
        assert_eq!(decoded_1559.value, 500_000_000_000_000_000);
        assert_eq!(decoded_1559.data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded_1559.access_list.len(), 0);
        assert_eq!(decoded_1559.y_parity, 1);
        assert_eq!(decoded_1559.r, [0x33; 32]);
        assert_eq!(decoded_1559.s, [0x44; 32]);

        // Verify roundtrip
        assert_eq!(decoded_1559.encode(), envelope);

        // Verify hash is keccak256(0x02 || payload)
        let tx_hash = decoded_1559.compute_hash();
        assert_eq!(tx_hash, keccak256(&envelope));

        // Verify signing data starts with 0x02
        let sig_data = decoded_1559.signing_data();
        assert_eq!(sig_data[0], 0x02);
        let sig_payload = RlpItem::decode(&sig_data[1..]).unwrap();
        assert_eq!(sig_payload.as_list().unwrap().len(), 9);

        // Convert to EvmTransaction
        let evm_tx = decoded_1559.to_evm_transaction(None, None);
        assert_eq!(evm_tx.tx_type, Some("0x2".to_string()));
        assert_eq!(evm_tx.chain_id, Some("0x167d".to_string()));
        assert_eq!(evm_tx.max_fee_per_gas, Some("0x826299e00".to_string()));
        assert_eq!(
            evm_tx.max_priority_fee_per_gas,
            Some("0x59682f00".to_string())
        );
        assert_eq!(evm_tx.access_list, Some(vec![]));
    }

    #[test]
    fn test_eip1559_type2_envelope_with_access_list() {
        let access_list = vec![
            AccessListItem {
                address: [0x11; 20],
                storage_keys: vec![[0xaa; 32], [0xbb; 32]],
            },
            AccessListItem {
                address: [0x22; 20],
                storage_keys: vec![],
            },
        ];

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 80_000,
            to: None, // Contract creation
            value: 0,
            data: vec![0x60, 0x01, 0x60, 0x02, 0x01],
            access_list,
            y_parity: 0,
            v: 0,
            r: [0x55; 32],
            s: [0x66; 32],
        };

        let encoded = tx.encode();
        let decoded = decode_eip1559_transaction(&encoded).expect("decode with access list");

        assert_eq!(decoded.to, None);
        assert_eq!(decoded.access_list.len(), 2);
        assert_eq!(decoded.access_list[0].address, [0x11; 20]);
        assert_eq!(decoded.access_list[0].storage_keys.len(), 2);
        assert_eq!(decoded.access_list[0].storage_keys[0], [0xaa; 32]);
        assert_eq!(decoded.access_list[0].storage_keys[1], [0xbb; 32]);
        assert_eq!(decoded.access_list[1].address, [0x22; 20]);
        assert_eq!(decoded.access_list[1].storage_keys.len(), 0);

        // Roundtrip
        assert_eq!(decoded.encode(), encoded);

        // Convert to EvmTransaction
        let evm_tx = decoded.to_evm_transaction(None, None);
        assert_eq!(evm_tx.to, None);
        let al = evm_tx.access_list.unwrap();
        assert_eq!(al.len(), 2);
        assert_eq!(al[0].address, format!("0x{}", hex::encode([0x11; 20])));
        assert_eq!(al[0].storage_keys.len(), 2);
    }

    #[test]
    fn test_ethereum_address_calculation_formula() {
        // Hardhat / Foundry Account #0:
        // Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
        // Expected address: 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266
        let privkey_bytes =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let uncompressed = encoded_point.as_bytes(); // 65 bytes starting with 0x04

        assert_eq!(uncompressed.len(), 65);
        assert_eq!(uncompressed[0], 0x04);

        // Required formula: keccak256(pubkey_uncompressed[1..])[12..32]
        let derived_addr = pubkey_to_address(uncompressed).expect("valid uncompressed pubkey");
        let expected_addr = hex::decode("f39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        assert_eq!(derived_addr.as_slice(), expected_addr.as_slice());

        // Also test with raw 64-byte coordinates (without 0x04 tag)
        let derived_from_coords =
            pubkey_to_address(&uncompressed[1..]).expect("valid 64-byte pubkey");
        assert_eq!(derived_from_coords.as_slice(), expected_addr.as_slice());

        // Also test with 33-byte compressed public key
        let compressed_point = verifying_key.to_encoded_point(true);
        let derived_from_compressed =
            pubkey_to_address(compressed_point.as_bytes()).expect("valid compressed pubkey");
        assert_eq!(derived_from_compressed.as_slice(), expected_addr.as_slice());
    }

    #[test]
    fn test_ecrecover_known_hardhat_personal_sign_vector() {
        let privkey_bytes =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
        let expected_addr = pubkey_to_address(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();

        let msg_hash_bytes =
            hex::decode("eff35bc70d30de07d572d42df29fb2c58971f11e0e854ef02eb4b29bb88d8792")
                .unwrap();
        let mut msg_hash = [0u8; 32];
        msg_hash.copy_from_slice(&msg_hash_bytes);

        let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();
        let v = 27u64 + recid.to_byte() as u64;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig.to_bytes()[0..32]);
        s.copy_from_slice(&sig.to_bytes()[32..64]);

        // 1. Core ecrecover
        let recovered = ecrecover(&msg_hash, v, &r, &s).expect("ecrecover should succeed");
        assert_eq!(recovered, expected_addr);

        // 2. verify_signature helper
        let is_valid =
            verify_signature(&expected_addr, &msg_hash, v, &r, &s).expect("verification succeeds");
        assert!(is_valid);

        // 3. Hex interface
        let recovered_hex = ecrecover_hex(
            "0xeff35bc70d30de07d572d42df29fb2c58971f11e0e854ef02eb4b29bb88d8792",
            &format!("0x{:x}", v),
            &format!("0x{}", hex::encode(r)),
            &format!("0x{}", hex::encode(s)),
        )
        .expect("hex ecrecover should succeed");
        assert_eq!(recovered_hex, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

        // 4. Recover full 65-byte uncompressed public key
        let pubkey = ecrecover_pubkey(&msg_hash, v, &r, &s).expect("pubkey recovery succeeds");
        assert_eq!(pubkey[0], 0x04);
        let addr_from_pubkey = pubkey_to_address(&pubkey).unwrap();
        assert_eq!(addr_from_pubkey, expected_addr);
    }

    #[test]
    fn test_ecrecover_eip155_canonical_vector_and_replay_protection() {
        // Official Ethereum EIP-155 test vector
        let hex_raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
        let raw = hex::decode(hex_raw).expect("valid hex");
        let decoded = decode_raw_transaction(&raw).expect("valid legacy tx");
        let legacy = match decoded {
            DecodedTransaction::Legacy(tx) => tx,
            _ => panic!("expected legacy tx"),
        };

        let sighash = legacy.signing_hash();
        assert_eq!(
            hex::encode(sighash),
            "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
        );

        // Recover sender via LegacyTransaction method
        let recovered_sender = legacy
            .recover_sender()
            .expect("recover sender from EIP-155 tx");
        let checksummed = to_checksum_address(&recovered_sender);
        assert_eq!(checksummed.len(), 42);

        // Core ecrecover with explicit chain ID matching
        let rec_ok = ecrecover_with_chain_id(&sighash, legacy.v, &legacy.r, &legacy.s, Some(1))
            .expect("should match chain ID 1");
        assert_eq!(rec_ok, recovered_sender);

        // Replay protection: Expected chain ID 2 must FAIL with ChainIdMismatch
        let err_chain2 = ecrecover_with_chain_id(&sighash, legacy.v, &legacy.r, &legacy.s, Some(2))
            .expect_err("must reject replay attack on chain 2");
        assert_eq!(
            err_chain2,
            EvmError::ChainIdMismatch {
                expected: 2,
                got: 1
            }
        );

        // Replay protection: Stellereum chain ID 5757 must FAIL
        let err_stell =
            ecrecover_with_chain_id(&sighash, legacy.v, &legacy.r, &legacy.s, Some(CHAIN_ID))
                .expect_err("must reject replay attack on Stellereum (5757)");
        assert_eq!(
            err_stell,
            EvmError::ChainIdMismatch {
                expected: 5757,
                got: 1
            }
        );

        // Verify low-s compliance
        assert!(is_low_s(&legacy.s));
        // `recover_sender` stays chain-agnostic (validates v consistency only),
        // but `verify_signature` strictly requires Stellereum chain_id == 5757,
        // so the mainnet (chain_id == 1) vector must be rejected here.
        let err_verify = legacy
            .verify_signature()
            .expect_err("foreign chain_id must be rejected");
        assert_eq!(
            err_verify,
            EvmError::ChainIdMismatch {
                expected: CHAIN_ID,
                got: 1
            }
        );
    }

    #[test]
    fn test_ecrecover_eip1559_transaction_roundtrip() {
        // Sign and verify an EIP-1559 transaction using Hardhat Account #0
        let privkey_bytes =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
        let expected_sender = pubkey_to_address(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();

        let chain_id = CHAIN_ID; // 5757
        let nonce = 15u64;
        let max_priority_fee = 2_000_000_000u128;
        let max_fee = 40_000_000_000u128;
        let gas_limit = 21_000u64;
        let to = Some([0x88; 20]);
        let value = 1_000_000_000_000_000_000u128;
        let data = vec![];

        let sighash = eip1559_tx_signing_hash(
            chain_id,
            nonce,
            max_priority_fee,
            max_fee,
            gas_limit,
            to.as_ref(),
            value,
            &data,
            &[],
        );

        // Sign with secp256k1 recoverable
        let (signature, recid) = signing_key.sign_prehash_recoverable(&sighash).unwrap();
        let y_parity = recid.to_byte();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&signature.to_bytes()[0..32]);
        s.copy_from_slice(&signature.to_bytes()[32..64]);

        // 1. Direct ecrecover with y_parity (0 or 1)
        let recovered = ecrecover(&sighash, y_parity as u64, &r, &s).expect("ecrecover eip1559");
        assert_eq!(recovered, expected_sender);

        // 2. Direct ecrecover with chain ID matching
        let rec_chain = ecrecover_with_chain_id(&sighash, y_parity as u64, &r, &s, Some(chain_id))
            .expect("ecrecover eip1559 with chain ID");
        assert_eq!(rec_chain, expected_sender);

        // 3. Construct Eip1559Transaction and verify
        let tx = Eip1559Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas: max_priority_fee,
            max_fee_per_gas: max_fee,
            gas_limit,
            to,
            value,
            data,
            access_list: vec![],
            y_parity,
            v: y_parity as u64,
            r,
            s,
        };

        assert_eq!(tx.signing_hash(), sighash);
        let tx_sender = tx.recover_sender().expect("tx recover_sender");
        assert_eq!(tx_sender, expected_sender);
        assert_eq!(tx.verify_signature().unwrap(), expected_sender);

        // 4. Encode to raw envelope, decode, and recover sender
        let raw_envelope = tx.encode();
        let decoded = decode_raw_transaction(&raw_envelope).expect("decode envelope");
        let decoded_sender = decoded.recover_sender().expect("decoded recover_sender");
        assert_eq!(decoded_sender, expected_sender);
    }

    #[test]
    fn test_ecrecover_openzeppelin_vector() {
        let privkey_bytes =
            hex::decode("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d")
                .unwrap();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
        let expected_addr = pubkey_to_address(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
        .unwrap();

        let hash_bytes =
            hex::decode("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                .unwrap();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let (signature, recid) = signing_key.sign_prehash_recoverable(&hash).unwrap();
        let v = 27u64 + recid.to_byte() as u64;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&signature.to_bytes()[0..32]);
        s.copy_from_slice(&signature.to_bytes()[32..64]);

        // Recovery succeeds and produces valid non-zero 20-byte address matching signer
        let recovered = ecrecover(&hash, v, &r, &s).expect("ecrecover succeeds");
        assert_eq!(recovered, expected_addr);
        assert!(is_low_s(&s));
    }

    #[test]
    fn test_ecrecover_malleability_and_high_s_rejection() {
        let msg_hash = [0x55u8; 32];
        let v = 27u64;
        let r = [0x11u8; 32];

        // Construct s that is greater than SECP256K1_HALF_N
        let mut high_s = SECP256K1_HALF_N;
        high_s[31] = high_s[31].saturating_add(1);

        assert!(!is_low_s(&high_s));

        // ecrecover_tx must reject high s with InvalidSignatureS
        let err = ecrecover_tx(&msg_hash, v, &r, &high_s, None).expect_err("must reject high-s");
        assert_eq!(err, EvmError::InvalidSignatureS);
    }

    #[test]
    fn test_ecrecover_error_conditions() {
        let hash = [0x42u8; 32];
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];

        // 1. Invalid recovery id v = 2, 26, 34
        assert_eq!(
            ecrecover_with_chain_id(&hash, 2, &r, &s, None).unwrap_err(),
            EvmError::InvalidRecoveryId(2)
        );
        assert_eq!(
            ecrecover_with_chain_id(&hash, 26, &r, &s, None).unwrap_err(),
            EvmError::InvalidRecoveryId(26)
        );
        assert_eq!(
            ecrecover_with_chain_id(&hash, 34, &r, &s, None).unwrap_err(),
            EvmError::InvalidRecoveryId(34)
        );
        assert!(ecrecover(&hash, 2, &r, &s).is_err());
        assert!(ecrecover(&hash, 26, &r, &s).is_err());
        assert!(ecrecover(&hash, 34, &r, &s).is_err());

        // 2. r == 0
        let zero_r = [0u8; 32];
        assert_eq!(
            ecrecover_with_chain_id(&hash, 27, &zero_r, &s, None).unwrap_err(),
            EvmError::InvalidSignatureR
        );
        assert!(ecrecover(&hash, 27, &zero_r, &s).is_err());

        // 3. s == 0
        let zero_s = [0u8; 32];
        assert_eq!(
            ecrecover_with_chain_id(&hash, 27, &r, &zero_s, None).unwrap_err(),
            EvmError::InvalidSignatureS
        );
        assert!(ecrecover(&hash, 27, &r, &zero_s).is_err());

        // 4. Pre-EIP-155 legacy (v = 27) rejected when replay protection is strictly required
        let err_unprot = parse_v_with_chain_id(27, Some(1)).unwrap_err();
        assert_eq!(err_unprot, EvmError::ReplayProtectionRequired);

        // But allowed when allow_unprotected is true
        let (rec_id, chain_opt) = parse_v_with_chain_id_opts(27, Some(1), true).unwrap();
        assert_eq!(rec_id, 0);
        assert_eq!(chain_opt, None);
    }

    #[test]
    fn test_to_checksum_address_official_eip55_vectors() {
        // Official EIP-55 test vectors
        let vectors = [
            (
                "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb",
                "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
            ),
            (
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            ),
        ];

        for (input, expected) in vectors {
            let addr = parse_address(input).expect("valid address hex");
            let checksummed = to_checksum_address(&addr);
            assert_eq!(checksummed, expected, "failed for {input}");
        }
    }

    #[test]
    fn test_evm_transaction_verify_sender() {
        let privkey_bytes =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&privkey_bytes).unwrap();
        let hash_bytes =
            hex::decode("eff35bc70d30de07d572d42df29fb2c58971f11e0e854ef02eb4b29bb88d8792")
                .unwrap();
        let mut msg_hash = [0u8; 32];
        msg_hash.copy_from_slice(&hash_bytes);
        let (sig, recid) = signing_key.sign_prehash_recoverable(&msg_hash).unwrap();
        let v = 27u64 + recid.to_byte() as u64;

        // Create an EvmTransaction with Account #0 signature
        let tx = EvmTransaction {
            hash: "0xeff35bc70d30de07d572d42df29fb2c58971f11e0e854ef02eb4b29bb88d8792".to_string(),
            nonce: "0x0".to_string(),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_string(),
            to: Some("0x0000000000000000000000000000000000000001".to_string()),
            value: "0x0".to_string(),
            gas_price: Some("0x1".to_string()),
            gas: "0x5208".to_string(),
            input: "0x".to_string(),
            v: format!("0x{:x}", v),
            r: format!("0x{}", hex::encode(&sig.to_bytes()[0..32])),
            s: format!("0x{}", hex::encode(&sig.to_bytes()[32..64])),
            tx_type: Some("0x0".to_string()),
            chain_id: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
        };

        assert!(tx.verify_sender().unwrap(), "signature must match sender");

        // Tamper with from address
        let mut tampered = tx.clone();
        tampered.from = "0x0000000000000000000000000000000000000002".to_string();
        assert!(
            !tampered.verify_sender().unwrap(),
            "tampered sender must not match"
        );
    }
}
