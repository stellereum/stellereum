use super::*;
use crate::rpc::RpcState;
use crate::state_engine::InMemoryStateEngine;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

/// Maximum number of blocks, receipts, or transactions retained in
/// `EvmAdapter`'s in-memory lookup caches (oldest entries evicted FIFO).
pub const MAX_EVM_ADAPTER_CACHE: usize = 50_000;

// ============================================================================
// Direct network info methods
// ============================================================================

/// Returns this node's Ethereum chain ID formatted as a hex quantity.
///
/// Serves [`effective_chain_id`] (STELL_CHAIN_ID-aware; default 5757), so the
/// served identity always matches the node's configured chain. Live stays
/// 5757 (env unset), zero behavior change on the stand. The `CHAIN_ID_HEX`
/// / `NET_VERSION` constants stay as the pinned DEFAULT renderings.
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

/// Extract the `to` target of an `eth_call` parameter object, if one is named.
///
/// Accepts every shape `eth_call` accepts: `[{to, data}, tag]`, `{to, data}`.
/// A bare calldata string names no target; a missing, null, or empty `to` is
/// "no target" (contract-creation emulation), not an address.
fn extract_call_target(params: &Value) -> Option<&str> {
    let obj = match params {
        Value::Array(arr) => arr.first()?.as_object()?,
        Value::Object(map) => map,
        _ => return None,
    };
    obj.get("to")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Code status of an `eth_call` target: `Some(true)` = committed code,
/// `Some(false)` = address with no code, `None` = the request names no target.
///
/// Delegates to [`eth_get_code_with_engine`] so `eth_call` and `eth_getCode`
/// use ONE rule for "does this address have code". An invalid `to` is refused
/// with the same `invalid params` error `eth_getCode` produces.
async fn eth_call_target_code_status(
    engine: &InMemoryStateEngine,
    params: &Value,
) -> Result<Option<bool>, JsonRpcError> {
    let Some(target) = extract_call_target(params) else {
        return Ok(None);
    };
    let code = eth_get_code_with_engine(engine, &json!([target])).await?;
    Ok(Some(code != "0x"))
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
    max_cache: usize,
    block_order: VecDeque<u64>,
    block_hash_order: VecDeque<String>,
    receipt_order: VecDeque<String>,
    tx_order: VecDeque<String>,
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
            max_cache: MAX_EVM_ADAPTER_CACHE,
            block_order: VecDeque::new(),
            block_hash_order: VecDeque::new(),
            receipt_order: VecDeque::new(),
            tx_order: VecDeque::new(),
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
    /// harnesses). Verification also follows [`effective_chain_id`]
    /// (single source, M-02). Zero behavior change while the env is unset
    /// (`effective == CHAIN_ID == 5757`).
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

    pub fn with_max_cache(mut self, max_cache: usize) -> Self {
        self.max_cache = max_cache;
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
            if stripped.len() == 64 && stripped.is_ascii() {
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
        let block_hash_filter = extract_block_hash_filter(params)?;
        let out = self.collect_matching_logs(&criteria, block_hash_filter.as_deref());
        Ok(json!(out))
    }

    #[allow(non_snake_case)]
    pub fn eth_getLogs(&self, params: &Value) -> Result<Value, JsonRpcError> {
        self.eth_get_logs(params)
    }

    /// Collects all receipt logs matching `criteria` (and optional `block_hash`),
    /// sorted deterministically before truncating at [`MAX_GET_LOGS_RESULTS`].
    /// Shared by the adapter-level [`EvmAdapter::eth_get_logs`] and the
    /// RPC-level merged query so both levels filter identically.
    pub fn collect_matching_logs(
        &self,
        criteria: &FilterCriteria,
        block_hash: Option<&str>,
    ) -> Vec<EvmLog> {
        fn cmp_log_deterministic(a: &EvmLog, b: &EvmLog) -> std::cmp::Ordering {
            log_sort_key(a)
                .cmp(&log_sort_key(b))
                .then_with(|| a.block_hash.cmp(&b.block_hash))
                .then_with(|| a.transaction_hash.cmp(&b.transaction_hash))
                .then_with(|| a.address.cmp(&b.address))
        }

        const COMPACT_THRESHOLD: usize = MAX_GET_LOGS_RESULTS * 8;
        let mut out = Vec::new();
        for receipt in self.receipts.values() {
            for log in &receipt.logs {
                if let Some(want) = block_hash {
                    match &log.block_hash {
                        Some(have) if have.eq_ignore_ascii_case(want) => {}
                        _ => continue,
                    }
                }
                if criteria.matches(log) {
                    out.push(log.clone());
                    if out.len() >= COMPACT_THRESHOLD {
                        out.sort_by(cmp_log_deterministic);
                        out.truncate(MAX_GET_LOGS_RESULTS);
                    }
                }
            }
        }
        out.sort_by(cmp_log_deterministic);
        out.truncate(MAX_GET_LOGS_RESULTS);
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
    ///
    /// HONESTY (F2/F2b): only READ-ONLY views are answered, and every answer
    /// is either a committed account read (`balanceOf`) or a documented
    /// constant of the native-token adapter (`name`/`symbol`/`decimals`/
    /// `totalSupply`). State-changing selectors — `transfer`, `approve`,
    /// `transferFrom` — and `allowance` return EMPTY (`"0x"`): this node
    /// cannot execute EVM code and holds no approvals, so a preflight of a
    /// call that would revert must never be answered `true`, and a claim of
    /// an infinite allowance is never invented. `0x` is exactly what a node
    /// returns for a call at an address with no code (`eth_getCode` is `0x`
    /// here by design).
    ///
    /// TARGET RULE (audit 2026-11-18): a call that NAMES a `to` target is
    /// answered `0x` by this stateless entry point, because no engine exists
    /// here to show that the target holds code — the exact `eth_getCode`
    /// contract above. The stateful path
    /// ([`Self::handle_eth_call_with_engine`]) omits the metadata answer only
    /// when the committed lookup proves the target is codeless; a target-less
    /// call keeps the native-token view.
    pub fn handle_eth_call(&self, params: &Value) -> Result<Value, JsonRpcError> {
        // STATELESS: this adapter has no state engine, so no target can be
        // shown to hold code. That is the same rule as `eth_getCode` here
        // (`handle_eth_get_code` answers `0x` for every address): a call with
        // a `to` target is answered `0x`, never with token metadata invented
        // for an address that may not be a token at all. Only a target-less
        // call keeps the legacy native-token view (see
        // `eth_call_target_code_status` for the stateful rule).
        if let Some(target) = extract_call_target(params) {
            // Validate exactly as the stateless `eth_getCode` does, so a
            // malformed target is `invalid params` in both methods.
            parse_evm_or_stell_address(target).map_err(|e| {
                JsonRpcError::invalid_params(format!("invalid address '{target}': {e}"))
            })?;
            return Ok(json!("0x"));
        }
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
            // State-changing / approval selectors: no EVM interpreter, no
            // approvals, no token state → honest empty, never `true`.
            SELECTOR_TRANSFER | SELECTOR_APPROVE | SELECTOR_TRANSFER_FROM | SELECTOR_ALLOWANCE => {
                "0x".to_string()
            }
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
        // A call at an address with NO committed code answers `0x`, exactly as
        // `eth_getCode` answers for that address (same lookup, so the two can
        // never disagree). This used to answer native-token metadata for ANY
        // `to`, including addresses with no code at all (audit 2026-11-18).
        // Target-less calls keep the legacy native-token view: `{data}` with
        // no `to` names no address to check.
        if matches!(
            eth_call_target_code_status(engine, params).await?,
            Some(false)
        ) {
            return Ok(json!("0x"));
        }
        let calldata = extract_calldata(params);
        let result = match calldata {
            Some(data) => self.emulate_erc20_call_with_engine(engine, data).await,
            None => "0x".to_string(),
        };
        Ok(json!(result))
    }

    /// Engine-backed variant of [`EvmAdapter::emulate_erc20_call`]: identical
    /// honesty contract — read-only views only; `transfer`/`approve`/
    /// `transferFrom`/`allowance` answer empty (`"0x"`) because this node has
    /// no EVM interpreter and no approvals to report (F2/F2b).
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
            // No EVM execution: a state-changing call or an allowance query
            // cannot be answered, so it is answered EMPTY (never `true`,
            // never `u128::MAX`).
            SELECTOR_TRANSFER | SELECTOR_APPROVE | SELECTOR_TRANSFER_FROM | SELECTOR_ALLOWANCE => {
                "0x".to_string()
            }
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
                    if stripped.len() == 64 && stripped.is_ascii() {
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
        let cap = self.max_cache;
        if let Some(ref num_hex) = block.number {
            if let Ok(num) = parse_hex_u64(num_hex) {
                if num > self.head_block {
                    self.head_block = num;
                }
                insert_bounded_u64(
                    &mut self.blocks_by_number,
                    &mut self.block_order,
                    num,
                    block.clone(),
                    cap,
                );
            }
        }
        if let Some(ref hash_hex) = block.hash {
            if let Ok(norm_hash) = normalize_hash(hash_hex) {
                insert_bounded_str(
                    &mut self.blocks_by_hash,
                    &mut self.block_hash_order,
                    norm_hash,
                    block.clone(),
                    cap,
                );
            }
        }
        if let BlockTransactions::Full(ref txs) = block.transactions {
            for tx in txs {
                self.insert_transaction(tx.clone());
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
            insert_bounded_str(
                &mut self.receipts,
                &mut self.receipt_order,
                norm_hash,
                receipt,
                self.max_cache,
            );
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
            insert_bounded_str(
                &mut self.transactions,
                &mut self.tx_order,
                norm_hash,
                tx,
                self.max_cache,
            );
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
                // FULL-PQ: the stateless adapter cannot admit anything into a
                // consensus mempool, and a secp256k1 signature is never an
                // admission credential. Same honest refusal as the node RPC.
                Err(evm_send_refusal_from_params(params))
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
            "eth_call" => match &self.engine {
                Some(engine) => self.handle_eth_call_with_engine(engine, params).await,
                None => self.handle_eth_call(params),
            },
            "eth_getCode" => match &self.engine {
                Some(engine) => Ok(json!(self::eth_get_code_with_engine(engine, params).await?)),
                None => Ok(json!(self::handle_eth_get_code(params)?)),
            },
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
            "eth_getCode" => Ok(json!(self::eth_get_code_with_engine(engine, params).await?)),
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
            "eth_getCode" => Ok(json!(self::eth_get_code_rpc(st, params).await?)),
            "eth_getProof" => self::eth_get_proof_rpc(st, params).await,
            "eth_subscribe" => Err(eth_subscribe_refusal(params)),
            "eth_unsubscribe" => Err(eth_unsubscribe_refusal()),
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

fn insert_bounded_u64<V>(
    map: &mut HashMap<u64, V>,
    order: &mut VecDeque<u64>,
    key: u64,
    val: V,
    cap: usize,
) {
    if cap == 0 {
        return;
    }
    if !map.contains_key(&key) {
        while map.len() >= cap {
            if let Some(oldest) = order.pop_front() {
                map.remove(&oldest);
            } else if let Some(k) = map.keys().next().copied() {
                map.remove(&k);
            } else {
                break;
            }
        }
        order.push_back(key);
    }
    map.insert(key, val);
}

fn insert_bounded_str<V>(
    map: &mut HashMap<String, V>,
    order: &mut VecDeque<String>,
    key: String,
    val: V,
    cap: usize,
) {
    if cap == 0 {
        return;
    }
    if !map.contains_key(&key) {
        while map.len() >= cap {
            if let Some(oldest) = order.pop_front() {
                map.remove(&oldest);
            } else if let Some(k) = map.keys().next().cloned() {
                map.remove(&k);
            } else {
                break;
            }
        }
        order.push_back(key.clone());
    }
    map.insert(key, val);
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

/// Converts a reward percentile in `[0, 100]` into integer millionths
/// (`p_micro = round(p * 10_000)`).
///
/// This is the ONLY place `eth_feeHistory` converts a percentile to/from
/// `f64`; every returned Wei value is then computed with integer arithmetic.
/// Non-finite (`NaN`, `±inf`) and out-of-range input is refused, never
/// coerced.
fn reward_percentile_micro(p: f64) -> Result<u128, JsonRpcError> {
    if !p.is_finite() || !(0.0..=100.0).contains(&p) {
        return Err(JsonRpcError::invalid_params(format!(
            "percentile must be a finite number between 0 and 100, got {p}"
        )));
    }
    Ok((p * 10_000.0).round() as u128)
}

/// Integer `(value * p_micro + 500_000) / 1_000_000` (round half up) without
/// `f64` and without overflowing `u128`.
///
/// Splits `value` into whole and remainder millionths, so `whole * p_micro`
/// never exceeds `value` (as `p_micro <= 1_000_000`) and only the small
/// remainder product is scaled. Mathematically identical to the naive formula.
fn percent_of_u128_round(value: u128, p_micro: u128) -> u128 {
    let whole = value / 1_000_000;
    let rem = value % 1_000_000;
    whole
        .saturating_mul(p_micro)
        .saturating_add((rem.saturating_mul(p_micro).saturating_add(500_000)) / 1_000_000)
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
    // Convert every percentile to integer millionths ONCE, fail-closed. From
    // here on no `f64` touches a returned value (W4 §2.3 п.5).
    let percentile_micros = match reward_percentiles {
        Some(percentiles) => Some(
            percentiles
                .into_iter()
                .map(reward_percentile_micro)
                .collect::<Result<Vec<u128>, JsonRpcError>>()?,
        ),
        None => None,
    };

    let available_blocks = u128::from(newest_block) + 1;
    let actual_count = u128::from(block_count).min(available_blocks) as u64;
    let oldest_block_num = (available_blocks - u128::from(actual_count)) as u64;
    let oldest_block = format_u64_hex(oldest_block_num);

    let base_fee_hex = format_u128_hex(base_fee);
    let base_fee_per_gas = vec![base_fee_hex; actual_count.saturating_add(1) as usize];
    let gas_used_ratio = vec![gas_used_ratio_val; actual_count as usize];

    let reward = percentile_micros.map(|percentiles| {
        (0..actual_count)
            .map(|_| {
                percentiles
                    .iter()
                    .map(|&p_micro| {
                        let tip = if max_priority_fee == 0 || p_micro == 0 {
                            0
                        } else if p_micro >= 1_000_000 {
                            max_priority_fee
                        } else {
                            percent_of_u128_round(max_priority_fee, p_micro)
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
///
/// STATELESS: this helper has no state engine, so it cannot know whether a
/// deployed contract exists. It is kept for the embedded/stateless adapter and
/// its long-standing "no code visible" contract. The JSON-RPC server uses
/// [`eth_get_code_with_engine`], which returns the REAL committed code.
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

/// `eth_getCode` against a live engine: the REAL committed bytecode, or `0x`.
///
/// Lookup order (each read-only, no fabricated bytes):
/// 1. the account's own `code` field;
/// 2. the contract registry entry (code + ABI manifest deployments);
/// 3. the state trie's raw-address entry when it is NOT the account leaf for
///    that address (a plain account stores balance/nonce there, which must
///    never be reported as bytecode).
///
/// `0x` is served only when all three sources hold no code for the address.
pub async fn eth_get_code_with_engine(
    engine: &InMemoryStateEngine,
    params: &Value,
) -> Result<String, JsonRpcError> {
    let (addr_str, _tag) = parse_address_and_tag_params(params)?;
    let address = parse_evm_or_stell_address(&addr_str)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}")))?;

    let account = engine.get_account(&address).await;
    if let Some(acc) = &account {
        if !acc.code.is_empty() {
            return Ok(format!("0x{}", hex::encode(&acc.code)));
        }
    }
    let contract_code = engine
        .get_contract(&address)
        .await
        .map(|c| c.code)
        .unwrap_or_default();
    if !contract_code.is_empty() {
        return Ok(format!("0x{}", hex::encode(&contract_code)));
    }
    // Trie fallback: the raw value at an address is contract code only when
    // it is NOT that address's account leaf (a plain account stores
    // balance/nonce there, which must never be reported as bytecode).
    if let Some(value) = engine.get_contract_code_from_trie(&address).await {
        let is_account_leaf = account
            .as_ref()
            .map(|acc| acc.to_trie_bytes() == value)
            .unwrap_or(false);
        if !is_account_leaf && !value.is_empty() {
            return Ok(format!("0x{}", hex::encode(&value)));
        }
    }
    Ok("0x".to_string())
}

/// `eth_getCode` against an `RpcState` (stateful JSON-RPC path).
pub async fn eth_get_code_rpc(st: &RpcState, params: &Value) -> Result<String, JsonRpcError> {
    eth_get_code_with_engine(&st.engine, params).await
}

/// Maximum storage keys accepted by the `eth_getProof` parameter parser.
/// Non-empty lists are refused anyway (no EVM storage trie), so this only
/// bounds parse work.
const MAX_ETH_GET_PROOF_STORAGE_KEYS: usize = 64;

/// Parse `eth_getProof(address, storageKeys, blockTag)` in both array and
/// object shapes. Storage keys are validated as 32-byte hex even though a
/// non-empty list is refused below.
fn parse_eth_get_proof_params(
    params: &Value,
) -> Result<(String, Vec<[u8; 32]>, BlockTag), JsonRpcError> {
    fn keys_from(val: Option<&Value>) -> Result<Vec<[u8; 32]>, JsonRpcError> {
        let Some(val) = val else {
            return Ok(Vec::new());
        };
        if val.is_null() {
            return Ok(Vec::new());
        }
        let items = val.as_array().ok_or_else(|| {
            JsonRpcError::invalid_params("storageKeys must be an array of 32-byte hex strings")
        })?;
        if items.len() > MAX_ETH_GET_PROOF_STORAGE_KEYS {
            return Err(JsonRpcError::invalid_params(format!(
                "too many storage keys: at most {MAX_ETH_GET_PROOF_STORAGE_KEYS} per request"
            )));
        }
        let mut out = Vec::with_capacity(items.len());
        for it in items {
            let s = it
                .as_str()
                .ok_or_else(|| JsonRpcError::invalid_params("storage key must be a hex string"))?;
            let clean = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            let bytes = hex::decode(clean).map_err(|e| {
                JsonRpcError::invalid_params(format!("invalid storage key '{s}': {e}"))
            })?;
            let key: [u8; 32] = bytes.try_into().map_err(|_| {
                JsonRpcError::invalid_params(format!("storage key '{s}' must be exactly 32 bytes"))
            })?;
            out.push(key);
        }
        Ok(out)
    }

    match params {
        Value::Array(arr) => {
            let addr = arr
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing address parameter"))?
                .to_string();
            let keys = keys_from(arr.get(1))?;
            let tag = match arr.get(2) {
                Some(v) => BlockTag::parse(v)?,
                None => BlockTag::Latest,
            };
            Ok((addr, keys, tag))
        }
        Value::Object(obj) => {
            let addr = obj
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("missing 'address' in params object"))?
                .to_string();
            let keys = keys_from(
                obj.get("storageKeys")
                    .or_else(|| obj.get("storage_keys"))
                    .or_else(|| obj.get("storageProof")),
            )?;
            let tag = match obj
                .get("blockTag")
                .or_else(|| obj.get("block_tag"))
                .or_else(|| obj.get("block"))
            {
                Some(v) => BlockTag::parse(v)?,
                None => BlockTag::Latest,
            };
            Ok((addr, keys, tag))
        }
        Value::String(s) => Ok((s.clone(), Vec::new(), BlockTag::Latest)),
        _ => Err(JsonRpcError::invalid_params(
            "params must be an array, object, or address string",
        )),
    }
}

/// `eth_getProof` (EIP-1186 account half) anchored at the committed state trie.
///
/// WHAT IS SERVED (real, verifiable):
/// * `accountProof` — a cpat2 inclusion proof (or an exclusion proof when the
///   address has no state entry) over the address's leaf in
///   `engine.state_trie`, with `stateRoot` the root the proof folds to.
///   Before returning, the node
///   re-verifies the proof itself; a proof it cannot verify is an internal
///   error, never a served answer.
/// * `balance` (wei), `nonce`, and `codeHash = keccak256(eth_getCode(addr))`.
///
/// WHAT IS NOT SERVED: `storageProof` / `storageHash`. This chain has ONE
/// account/contract Patricia trie, not a per-account EVM storage trie, so no
/// EVM slot proof exists. A non-empty `storageKeys` request is refused with
/// `-32000` naming that missing capability; `storageHash` is `null` and
/// `storageProof` is `[]` for that same reason (never a fabricated Ethereum
/// empty-trie root).
///
/// HISTORICAL STATE: the node keeps only the live trie, so a block tag that
/// resolves to a height other than the current head is refused. `latest`
/// (and the current height) is served.
pub async fn eth_get_proof_with_engine(
    engine: &InMemoryStateEngine,
    head: u64,
    params: &Value,
) -> Result<Value, JsonRpcError> {
    let (addr_str, storage_keys, tag) = parse_eth_get_proof_params(params)?;
    let address = parse_evm_or_stell_address(&addr_str)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid address '{addr_str}': {e}")))?;
    let want = tag.resolve(head);
    if want != head {
        return Err(JsonRpcError::new(
            -32000,
            format!(
                "eth_getProof serves only the current state: this node is at height {head}, \
                 not {want} (historical state is not retained; use stell_getArchiveProof with \
                 an attached archive store)"
            ),
        ));
    }
    if !storage_keys.is_empty() {
        return Err(JsonRpcError::with_data(
            -32000,
            "eth_getProof storageProof is not served: this chain has one account/contract \
             Patricia trie, not a per-account EVM storage trie, so no EVM storage-slot proof \
             exists. Request storageKeys: [] for the account proof; raw state-trie keys are \
             available through stell_getProof."
                .to_string(),
            serde_json::json!({
                "reason": "no-evm-storage-trie",
                "missing": "per-account EVM storage trie (Verkle/MPT slot proofs)",
                "accountProofAvailable": true,
            }),
        ));
    }

    let account = engine.get_account(&address).await;
    let contract = engine.get_contract(&address).await;
    let mut code = account.as_ref().map(|a| a.code.clone()).unwrap_or_default();
    if code.is_empty() {
        if let Some(c) = &contract {
            code = c.code.clone();
        }
    }
    if code.is_empty() {
        if let Some(value) = engine.get_contract_code_from_trie(&address).await {
            let is_account_leaf = account
                .as_ref()
                .map(|acc| acc.to_trie_bytes() == value)
                .unwrap_or(false);
            if !is_account_leaf {
                code = value;
            }
        }
    }

    // Fold the consensus-domain digest first so the root served is the
    // canonical committed root (same discipline as `stell_getProof`).
    let _ = engine.get_state_root().await;
    let (nodes, trie_has_entry, root) = {
        let trie = engine.state_trie.read().await;
        let root = trie.root_hash();
        match trie.compressed().generate_proof(&address) {
            Some(p) => {
                if !crate::cpat2::verify_proof(&root, &address, &p.value, &p) {
                    return Err(JsonRpcError::new(
                        -32000,
                        "internal error: generated account proof does not verify",
                    ));
                }
                (p.to_nodes(), true, root)
            }
            None => match trie.compressed().generate_exclusion_proof(&address) {
                Some(p) => {
                    if !crate::cpat2::verify_exclusion_proof(&root, &address, &p) {
                        return Err(JsonRpcError::new(
                            -32000,
                            "internal error: generated account exclusion proof does not verify",
                        ));
                    }
                    (p.to_nodes(), false, root)
                }
                // Empty trie: nothing to prove against. The answer is an
                // honest empty proof, never a manufactured leaf.
                None => (Vec::new(), false, root),
            },
        }
    };
    if account.is_some() && !trie_has_entry {
        return Err(JsonRpcError::new(
            -32000,
            "internal error: account exists in the engine but has no state-trie leaf",
        ));
    }

    let proof_nodes: Vec<String> = nodes.iter().map(|n| format!("0x{n}")).collect();
    let address_json = if address[..12] == [0u8; 12] {
        format!("0x{}", hex::encode(&address[12..]))
    } else {
        format!("0x{}", hex::encode(address))
    };
    Ok(serde_json::json!({
        "address": address_json,
        "stellAddress": format!("0x{}", hex::encode(address)),
        "accountProof": proof_nodes,
        "balance": account
            .as_ref()
            .map(|a| nano_to_wei_hex(a.balance))
            .unwrap_or_else(|| "0x0".to_string()),
        "nonce": account
            .as_ref()
            .map(|a| format_u64_hex(a.nonce))
            .unwrap_or_else(|| "0x0".to_string()),
        "codeHash": format!("0x{}", hex::encode(keccak256(&code))),
        // No per-account EVM storage trie exists; `null` is the honest answer
        // (an Ethereum empty-trie root would describe a trie this chain lacks).
        "storageHash": Value::Null,
        "storageProof": Vec::<Value>::new(),
        "stateRoot": format!("0x{}", hex::encode(root)),
        "height": head,
        "exists": account.is_some() || contract.is_some() || trie_has_entry,
        "proofModel": "stell-cpat2-state-trie-v1",
    }))
}

/// `eth_getProof` against an `RpcState` (stateful JSON-RPC path).
pub async fn eth_get_proof_rpc(st: &RpcState, params: &Value) -> Result<Value, JsonRpcError> {
    let head = st.height.load(std::sync::atomic::Ordering::Relaxed);
    eth_get_proof_with_engine(&st.engine, head, params).await
}

/// Honest `eth_subscribe` refusal.
///
/// The node HAS a subscription registry and a WebSocket fan-out
/// (`crate::rpc::streams`), but that transport only understands
/// `stell_subscribe` topics and frames every notification as
/// `{"subscription": <id>, "result": <stell payload>}`. It has no EIP-1193
/// `eth_subscription` envelope and no EVM header/log materialiser, so an
/// `eth_subscribe` id would never receive a correctly shaped notification.
/// Refusing names the exact gap instead of issuing a dead id.
pub fn eth_subscribe_refusal(params: &Value) -> JsonRpcError {
    let kind = params
        .get(0)
        .and_then(|v| v.as_str())
        .or_else(|| params.get("type").and_then(|v| v.as_str()))
        .or_else(|| params.get("subscription").and_then(|v| v.as_str()))
        .unwrap_or("subscription");
    JsonRpcError::with_data(
        -32000,
        format!(
            "eth_subscribe(\"{kind}\") is not served: this node's WebSocket transport \
             (src/rpc/streams.rs::ws_handle_text) tracks only stell_subscribe and frames \
             notifications as {{\"subscription\",\"result\"}}; it emits no EIP-1193 \
             `eth_subscription` envelope and has no EVM newHeads/log payload materialiser. \
             Use stell_subscribe [\"newHeads\"] / [\"events\", {{...}}] on /ws (or /events \
             SSE), or poll eth_getBlockByNumber(\"latest\") / eth_getLogs. No subscription \
             id was issued and no notification will be pushed for this call."
        ),
        serde_json::json!({
            "reason": "no-evm-subscription-transport",
            "missing": "EIP-1193 eth_subscription framing + EVM newHeads/log payloads in rpc/streams.rs",
            "use": ["stell_subscribe", "eth_getLogs", "eth_getBlockByNumber"],
            "kind": kind,
        }),
    )
}

/// Honest `eth_unsubscribe` refusal: no `eth_subscribe` id is ever issued, so
/// there is nothing to remove. `stell_unsubscribe` removes stell ids.
pub fn eth_unsubscribe_refusal() -> JsonRpcError {
    JsonRpcError::with_data(
        -32000,
        "eth_unsubscribe is not served: this node issues no eth_subscribe ids (see \
         eth_subscribe). Stell subscription ids are removed with stell_unsubscribe."
            .to_string(),
        serde_json::json!({
            "reason": "no-evm-subscription-transport",
            "use": ["stell_unsubscribe"],
        }),
    )
}

/// Resolve an address parameter to the account whose balance / nonce it means.
///
/// A 32-byte (or hex-64) address is taken literally. A 20-byte EVM address is
/// resolved through the on-chain PQ binding when this node knows one, because
/// that is the account which can actually spend the funds: the bare 20-byte
/// projection (`evm_to_stell_address`) is where ETH-shaped clients would look,
/// but no Falcon-512 key derives it, so reporting that account would show a
/// wallet `0` while its money sits in the bound PQ account.
///
/// No binding => the historical projection (unchanged behaviour, and the
/// honest answer: nothing is bound, so nothing else can be claimed).
pub async fn resolve_evm_account(
    engine: &InMemoryStateEngine,
    addr: &str,
) -> Result<[u8; 32], JsonRpcError> {
    let trimmed = addr.trim();
    let bare = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if bare.len() == 40 {
        let evm = evm_address_from_hex(bare)
            .map_err(|e| JsonRpcError::invalid_params(format!("invalid address '{addr}': {e}")))?;
        if let Some(pq) = engine.evm_binding_pq(&evm).await {
            return Ok(pq);
        }
    }
    parse_evm_or_stell_address(addr)
        .map_err(|e| JsonRpcError::invalid_params(format!("invalid address '{addr}': {e}")))
}

/// Handles `eth_getBalance` against an `InMemoryStateEngine`.
/// Returns balance in Wei formatted as hex quantity ("0x...").
pub async fn eth_get_balance(
    engine: &InMemoryStateEngine,
    params: &Value,
) -> Result<String, JsonRpcError> {
    let (addr_str, _tag) = parse_address_and_tag_params(params)?;
    let stell_addr = resolve_evm_account(engine, &addr_str).await?;
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
    let stell_addr = resolve_evm_account(engine, &addr_str).await?;
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

#[cfg(test)]
mod fee_history_percentile_tests {
    use super::*;

    #[test]
    fn percentiles_on_boundaries_are_integer_exact() {
        let hist = fee_history_impl(
            &json!([1, 0, [0.0, 50.0, 100.0]]),
            0,
            DEFAULT_BASE_FEE,
            DEFAULT_MAX_PRIORITY_FEE,
            0.5,
        )
        .expect("fee history");
        let reward = hist.reward.expect("rewards");
        assert_eq!(reward.len(), 1);
        // 0% -> 0, 50% of 1 Gwei -> 500_000_000, 100% -> 1_000_000_000.
        assert_eq!(
            reward[0],
            vec![
                "0x0".to_string(),
                "0x1dcd6500".to_string(),
                "0x3b9aca00".to_string()
            ]
        );
    }

    #[test]
    fn fractional_percentile_rounds_to_integer_micros() {
        // 12.3456% of 1 Gwei = 123_456_000 wei exactly (p_micro = 123_456).
        let hist = fee_history_impl(
            &json!([1, 0, [12.3456]]),
            0,
            DEFAULT_BASE_FEE,
            DEFAULT_MAX_PRIORITY_FEE,
            0.5,
        )
        .expect("fee history");
        assert_eq!(hist.reward.unwrap()[0][0], "0x75bca00");
    }

    #[test]
    fn percentile_round_half_up_without_float_result() {
        // 1 wei * 50% = 0.5 wei -> rounds to 1 wei.
        assert_eq!(percent_of_u128_round(1, 500_000), 1);
        // 1 wei * 25% = 0.25 wei -> rounds to 0.
        assert_eq!(percent_of_u128_round(1, 250_000), 0);
        // u128::MAX at 100% must not overflow or panic.
        assert_eq!(percent_of_u128_round(u128::MAX, 1_000_000), u128::MAX);
    }

    #[test]
    fn non_finite_percentiles_are_refused_without_panic() {
        for raw in [json!([1, 0, ["NaN"]]), json!([1, 0, ["inf"]])] {
            let err = fee_history_impl(&raw, 0, DEFAULT_BASE_FEE, DEFAULT_MAX_PRIORITY_FEE, 0.5)
                .expect_err("non-finite percentile must be refused");
            assert_eq!(err.code, INVALID_PARAMS_CODE);
        }
        assert!(reward_percentile_micro(f64::NAN).is_err());
        assert!(reward_percentile_micro(f64::INFINITY).is_err());
        assert!(reward_percentile_micro(-0.5).is_err());
        assert!(reward_percentile_micro(100.5).is_err());
    }

    #[test]
    fn fee_history_at_u64_max_does_not_overflow_or_panic() {
        let hist = fee_history_impl(
            &json!([1, "0xffffffffffffffff"]),
            u64::MAX,
            DEFAULT_BASE_FEE,
            DEFAULT_MAX_PRIORITY_FEE,
            0.5,
        )
        .expect("eth_feeHistory at u64::MAX must succeed");
        assert_eq!(hist.oldest_block, "0xffffffffffffffff");
        assert_eq!(hist.base_fee_per_gas.len(), 2);
        assert_eq!(hist.gas_used_ratio.len(), 1);

        let hist_multi = fee_history_impl(
            &json!([5, "0xffffffffffffffff"]),
            u64::MAX,
            DEFAULT_BASE_FEE,
            DEFAULT_MAX_PRIORITY_FEE,
            0.25,
        )
        .expect("eth_feeHistory multi-block at u64::MAX must succeed");
        assert_eq!(hist_multi.oldest_block, format_u64_hex(u64::MAX - 4));
        assert_eq!(hist_multi.base_fee_per_gas.len(), 6);
        assert_eq!(hist_multi.gas_used_ratio.len(), 5);
    }

    #[test]
    fn get_balance_non_ascii_64_bytes_does_not_panic() {
        let adapter = EvmAdapter::new().with_default_balance(77);
        // 32 two-byte UTF-8 chars = 64 bytes, byte 24 is mid-character.
        let non_ascii_64 = format!("0x{}", "é".repeat(32));
        assert_eq!(non_ascii_64.strip_prefix("0x").unwrap().len(), 64);
        assert_eq!(adapter.get_balance(&non_ascii_64), 77);
    }

    #[test]
    fn eth_get_logs_rejects_malformed_block_hash_and_sorts_deterministically() {
        let mut adapter = EvmAdapter::new();
        let err = adapter
            .eth_get_logs(&json!([{ "blockHash": "0xbad" }]))
            .expect_err("malformed blockHash must return invalid_params");
        assert_eq!(err.code, INVALID_PARAMS_CODE);

        // Insert > MAX_GET_LOGS_RESULTS logs in reverse block order across receipts.
        let total = MAX_GET_LOGS_RESULTS + 50;
        for i in (0..total).rev() {
            let tx_hash = format!("0x{:064x}", i + 1);
            let block_hash = format!("0x{:064x}", i + 10_000);
            let log = EvmLog {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                topics: vec![],
                data: "0x".to_string(),
                block_number: Some(format_u64_hex(i as u64)),
                transaction_hash: Some(tx_hash.clone()),
                transaction_index: Some("0x0".to_string()),
                block_hash: Some(block_hash.clone()),
                log_index: Some("0x0".to_string()),
                removed: false,
            };
            adapter.insert_receipt(EvmReceipt {
                transaction_hash: tx_hash,
                transaction_index: "0x0".to_string(),
                block_hash,
                block_number: format_u64_hex(i as u64),
                from: "0x1111111111111111111111111111111111111111".to_string(),
                to: None,
                cumulative_gas_used: "0x5208".to_string(),
                gas_used: "0x5208".to_string(),
                contract_address: None,
                logs: vec![log],
                logs_bloom: EMPTY_LOGS_BLOOM.to_string(),
                status: Some("0x1".to_string()),
                root: None,
                tx_type: Some("0x0".to_string()),
                effective_gas_price: Some("0x1".to_string()),
                blob_gas_used: None,
                blob_gas_price: None,
            });
        }

        let val = adapter.eth_get_logs(&json!([{}])).expect("eth_getLogs");
        let logs = val.as_array().expect("array of logs");
        assert_eq!(logs.len(), MAX_GET_LOGS_RESULTS);
        assert_eq!(logs[0]["blockNumber"], json!("0x0"));
        assert_eq!(
            logs[MAX_GET_LOGS_RESULTS - 1]["blockNumber"],
            json!(format_u64_hex((MAX_GET_LOGS_RESULTS - 1) as u64))
        );
    }

    #[test]
    fn evm_adapter_cache_evicts_oldest_entries() {
        let mut adapter = EvmAdapter::new().with_max_cache(3);
        for i in 0u64..5 {
            let block_hash = format!("0x{:064x}", i + 1);
            let tx_hash = format!("0x{:064x}", i + 100);
            let tx = EvmTransaction {
                hash: tx_hash.clone(),
                nonce: format_u64_hex(i),
                block_hash: Some(block_hash.clone()),
                block_number: Some(format_u64_hex(i)),
                transaction_index: Some("0x0".to_string()),
                from: "0x1111111111111111111111111111111111111111".to_string(),
                to: None,
                value: "0x0".to_string(),
                gas_price: Some("0x1".to_string()),
                gas: "0x5208".to_string(),
                input: "0x".to_string(),
                v: "0x0".to_string(),
                r: "0x0".to_string(),
                s: "0x0".to_string(),
                tx_type: Some("0x0".to_string()),
                chain_id: Some("0x167d".to_string()),
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                access_list: None,
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: None,
            };
            let block = EvmBlock {
                number: Some(format_u64_hex(i)),
                hash: Some(block_hash.clone()),
                parent_hash: EMPTY_ROOT_HASH.to_string(),
                nonce: None,
                sha3_uncles: EMPTY_UNCLES_HASH.to_string(),
                logs_bloom: None,
                transactions_root: EMPTY_ROOT_HASH.to_string(),
                state_root: EMPTY_ROOT_HASH.to_string(),
                receipts_root: EMPTY_ROOT_HASH.to_string(),
                miner: "0x0000000000000000000000000000000000000000".to_string(),
                difficulty: "0x0".to_string(),
                total_difficulty: None,
                extra_data: "0x".to_string(),
                size: "0x0".to_string(),
                gas_limit: "0x1".to_string(),
                gas_used: "0x0".to_string(),
                timestamp: "0x0".to_string(),
                transactions: BlockTransactions::Full(vec![tx]),
                uncles: vec![],
                base_fee_per_gas: None,
                mix_hash: None,
                withdrawals: None,
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
            };
            adapter.insert_block(block);
            adapter.insert_receipt(EvmReceipt {
                transaction_hash: tx_hash,
                transaction_index: "0x0".to_string(),
                block_hash,
                block_number: format_u64_hex(i),
                from: "0x1111111111111111111111111111111111111111".to_string(),
                to: None,
                cumulative_gas_used: "0x5208".to_string(),
                gas_used: "0x5208".to_string(),
                contract_address: None,
                logs: vec![],
                logs_bloom: EMPTY_LOGS_BLOOM.to_string(),
                status: Some("0x1".to_string()),
                root: None,
                tx_type: Some("0x0".to_string()),
                effective_gas_price: Some("0x1".to_string()),
                blob_gas_used: None,
                blob_gas_price: None,
            });
        }
        assert_eq!(adapter.blocks_by_number.len(), 3);
        assert_eq!(adapter.blocks_by_hash.len(), 3);
        assert_eq!(adapter.receipts.len(), 3);
        assert_eq!(adapter.transactions.len(), 3);
        assert!(!adapter.blocks_by_number.contains_key(&0));
        assert!(!adapter.blocks_by_number.contains_key(&1));
        assert!(adapter.blocks_by_number.contains_key(&2));
        assert!(adapter.blocks_by_number.contains_key(&3));
        assert!(adapter.blocks_by_number.contains_key(&4));
    }
}
