use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Default chain ID for Stellereum network (5757).
///
/// SINGLE SOURCE (M-02): served identity AND verification both resolve the
/// deployment's chain through [`effective_chain_id`] (`STELL_CHAIN_ID`, else
/// this default). Every signature-verification site
/// (`eth_send_raw_transaction_bytes`, `evm_raw_to_stell_transaction`,
/// `DecodedTransaction::verify_signature`,
/// `validate_transaction_signature*`) compares against
/// [`effective_chain_id`], so one binary serves any number of networks and
/// every node of one deployment (same `STELL_CHAIN_ID`) reaches the same
/// verdict on the same bytes. Live is 5757 either way (env unset), so there
/// is zero behavior change on the stand. `CHAIN_ID` remains only as the
/// compile-time default seed (and `CHAIN_ID_HEX` / `NET_VERSION` as its
/// default rendering); never compare against it directly in new code.
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
/// [`eth_chain_id`] serves this for [`effective_chain_id`].
pub fn eth_chain_id_for(chain_id: u64) -> String {
    format!("0x{chain_id:x}")
}

/// `net_version` for an explicit chain id (decimal string, e.g. `"5757"`).
/// [`net_version`] serves this for [`effective_chain_id`].
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
/// (`with_peer_count`) or the process-wide observed count
/// (`rpc::note_peer_count` / `rpc::observed_peer_count`) instead — the
/// `rpc::dispatch` arm serves THAT, never this default (F8).
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
/// EIP-20 `transferFrom(address,address,uint256)`.
pub const SELECTOR_TRANSFER_FROM: &str = "23b872dd";

pub const SELECTOR_NAME_HEX: &str = "0x06fdde03";
pub const SELECTOR_SYMBOL_HEX: &str = "0x95d89b41";
pub const SELECTOR_DECIMALS_HEX: &str = "0x313ce567";
pub const SELECTOR_BALANCE_OF_HEX: &str = "0x70a08231";
pub const SELECTOR_TOTAL_SUPPLY_HEX: &str = "0x18160ddd";
pub const SELECTOR_TRANSFER_HEX: &str = "0xa9059cbb";
pub const SELECTOR_APPROVE_HEX: &str = "0x095ea7b3";
pub const SELECTOR_ALLOWANCE_HEX: &str = "0xdd62ed3e";
/// EIP-20 `transferFrom(address,address,uint256)`.
pub const SELECTOR_TRANSFER_FROM_HEX: &str = "0x23b872dd";

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

/// Maximum EVM raw transaction size (128 KiB — generous for calldata).
pub const MAX_EVM_RAW_TX_BYTES: usize = 128 * 1024;

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

/// Converts Wei (u128) to nano-STELL (u64) EXACTLY, refusing every lossy case.
///
/// Contract (W4 §2.3 п.1): a Wei amount is a valid nano-STELL amount only when
/// it is an integer multiple of [`WEI_PER_NANO`], and the quotient must fit in
/// `u64`. Nothing is truncated and nothing saturates:
/// * `wei % WEI_PER_NANO != 0` → `Err("sub-nano wei remainder ...")`;
/// * `wei / WEI_PER_NANO > u64::MAX` → `Err("wei amount overflows ...")`.
///
/// This is the fail-closed boundary new value-moving code must use; the legacy
/// [`wei_to_nano`] stays for read-only `EV1` simulation and historical tests.
pub fn wei_to_nano_exact(wei: u128) -> Result<u64, String> {
    let remainder = wei % WEI_PER_NANO;
    if remainder != 0 {
        return Err(format!(
            "sub-nano wei remainder {remainder}: value must be a multiple of 1_000_000_000 wei"
        ));
    }
    let nano = wei / WEI_PER_NANO;
    if nano > u64::MAX as u128 {
        return Err("wei amount overflows u64 nano-STELL".to_string());
    }
    Ok(nano as u64)
}

/// Converts Wei (u128) to nano-STELL (u64).
///
/// WARNING (W4 §2.3, LEGACY lossy boundary): sub-nano wei are TRUNCATED and
/// values above `u64::MAX` nano-STELL SATURATE at `u64::MAX`. Kept only for
/// read-only `EV1` simulation and historical tests; never add a value-moving
/// caller. New code must use [`wei_to_nano_exact`] (fail-closed).
///
/// Deliberately NOT annotated `#[deprecated]`: it is still called from
/// `sharding::transaction`, `rpc::tests` and the legacy adapters, and a
/// `-D warnings` gate would fail on those out-of-scope call sites.
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
    /// Stellereum replay protection (`chain_id == effective_chain_id()`) in
    /// addition to low-s compliance under EIP-2.
    pub fn verify_signature(&self) -> Result<[u8; 20], EvmError> {
        let expected = effective_chain_id();
        match self.chain_id {
            Some(got) if got == expected => {}
            Some(got) => return Err(EvmError::ChainIdMismatch { expected, got }),
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
        if v > 1 {
            return Err(RlpError::Custom(format!(
                "invalid EIP-1559 y_parity: expected 0 or 1, got {v}"
            )));
        }
        let y_parity = v as u8;
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
    /// Stellereum replay protection (`chain_id == effective_chain_id()`) in
    /// addition to low-s compliance under EIP-2.
    pub fn verify_signature(&self) -> Result<[u8; 20], EvmError> {
        let expected = effective_chain_id();
        if self.chain_id != expected {
            return Err(EvmError::ChainIdMismatch {
                expected,
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

#[cfg(test)]
mod sub_nano_exact_tests {
    use super::*;

    #[test]
    fn rejects_sub_nano_remainder() {
        let err = wei_to_nano_exact(1_500_000_000).expect_err("sub-nano must be refused");
        assert_eq!(
            err,
            "sub-nano wei remainder 500000000: value must be a multiple of 1_000_000_000 wei"
        );
    }

    #[test]
    fn accepts_exact_nano_multiple() {
        assert_eq!(wei_to_nano_exact(2_000_000_000).unwrap(), 2);
        assert_eq!(wei_to_nano_exact(0).unwrap(), 0);
    }

    #[test]
    fn rejects_u64_overflow() {
        let wei = (u64::MAX as u128 + 1) * WEI_PER_NANO;
        let err = wei_to_nano_exact(wei).expect_err("overflow must be refused");
        assert_eq!(err, "wei amount overflows u64 nano-STELL");
    }

    #[test]
    fn accepts_u64_max_boundary() {
        let wei = (u64::MAX as u128) * WEI_PER_NANO;
        assert_eq!(wei_to_nano_exact(wei).unwrap(), u64::MAX);
    }

    #[test]
    fn legacy_helper_keeps_lossy_contract() {
        // The legacy helper stays byte-compatible: truncation + saturation.
        assert_eq!(wei_to_nano(1_500_000_000), 1);
        assert_eq!(wei_to_nano((u64::MAX as u128 + 1) * WEI_PER_NANO), u64::MAX);
    }
}

#[cfg(test)]
mod eip1559_y_parity_tests {
    use super::*;

    fn encode_raw_eip1559_with_v(v: u64) -> Vec<u8> {
        let fields = vec![
            rlp_encode_u64(CHAIN_ID),
            rlp_encode_u64(1),
            rlp_encode_u128(1_000_000_000),
            rlp_encode_u128(20_000_000_000),
            rlp_encode_u64(21_000),
            rlp_encode_bytes(&[0x11; 20]),
            rlp_encode_u128(1_000),
            rlp_encode_bytes(&[]),
            rlp_encode_list(&[]),
            rlp_encode_u64(v),
            rlp_encode_bytes(&[0x22; 32]),
            rlp_encode_bytes(&[0x33; 32]),
        ];
        let payload = rlp_encode_list(&fields);
        let mut raw = Vec::with_capacity(1 + payload.len());
        raw.push(0x02);
        raw.extend_from_slice(&payload);
        raw
    }

    #[test]
    fn accepts_canonical_y_parity_0_and_1() {
        for v in [0u64, 1u64] {
            let raw = encode_raw_eip1559_with_v(v);
            let decoded = Eip1559Transaction::decode_envelope(&raw).expect("valid y_parity");
            assert_eq!(decoded.y_parity, v as u8);
            assert_eq!(decoded.v, v);
            assert_eq!(decoded.compute_hash(), keccak256(&raw));
        }
    }

    #[test]
    fn rejects_non_canonical_y_parity_gt_1() {
        for bad_v in [2u64, 27u64, 28u64, 35u64, u64::MAX] {
            let raw = encode_raw_eip1559_with_v(bad_v);
            let err = Eip1559Transaction::decode_envelope(&raw)
                .expect_err("non-canonical y_parity > 1 must be rejected");
            match err {
                RlpError::Custom(msg) => assert!(msg.contains("y_parity"), "unexpected msg: {msg}"),
                other => panic!("expected RlpError::Custom, got {other:?}"),
            }
        }
    }
}
