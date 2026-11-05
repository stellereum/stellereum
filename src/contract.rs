//! On-chain WASM smart contracts (deterministic, metered).
//!
//! Contracts are deployed as validated WebAssembly modules and executed by the
//! `wasmi` interpreter with strict, consensus-safe settings:
//!   - `consume_fuel` fuel metering bounds every call (no infinite loops);
//!   - `deterministic` float semantics so every node computes identical results;
//!   - module validation on deploy (rejects malformed/invalid wasm up front);
//!   - no host imports are linked, so a contract cannot reach the network, the
//!     clock, or host memory — it is a pure (i64) -> i64 function;
//!   - memory/tables/instances are capped by `StoreLimits` (memory-bomb proof).
//!
//! The ABI is intentionally tiny and integer-only: a contract exports named
//! functions with the signature `(i64) -> i64`. This keeps execution fully
//! deterministic across architectures (no floating-point, no imports).
//!
//! Determinism is non-negotiable on a consensus chain: two validators that run
//! the same contract on the same state MUST get the same result, so this module
//! forbids everything that could differ between machines.
//!
//! # Multi-argument methods and the ABI manifest
//!
//! A contract may export methods with several parameters:
//! `() -> i64`, `(i64) -> i64`, `(i64, i64) -> i64`, `(i64, i64, i64) -> i64`
//! and up to [`MAX_CONTRACT_CALL_ARGS`] parameters. Dispatch is by *exact*
//! arity, so a two-parameter method can never be called with one parameter
//! (an argument is never silently dropped).
//!
//! A contract may additionally carry a typed **ABI manifest**
//! ([`crate::contract_abi::ContractAbi`]) describing every method and event.
//! The manifest is stored alongside the code hash, lets clients encode/decode
//! arguments in a canonical, length-prefixed format (instead of hand-packing
//! `from * 100_000_000 + to * 100_000 + amount`) and lets the RPC layer
//! validate calls before they touch consensus state.

use crate::contract_abi::{AbiError, AbiValue, ContractAbi};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use wasmi::{
    Config, Engine, Extern, ExternType, Instance, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder,
};

/// Maximum deployed contract code size (2 MiB / 2,097,152 bytes).
pub const MAX_CONTRACT_CODE_SIZE: usize = 2 * 1024 * 1024;
/// Backward-compatible alias for `MAX_CONTRACT_CODE_SIZE`.
pub const MAX_CONTRACT_CODE: usize = MAX_CONTRACT_CODE_SIZE;

/// Maximum number of `i64` parameters a single contract call may pass.
pub const MAX_CONTRACT_CALL_ARGS: usize = 8;

/// Maximum wasmi fuel a single contract call may consume (anti-DoS).
pub const MAX_CONTRACT_FUEL: u64 = 50_000_000;
/// Bounded safety fuel limit for read-only get method execution (anti-DoS / infinite loops).
pub const GET_METHOD_SAFETY_FUEL_LIMIT: u64 = 5_000_000;

/// WASM standard memory page size in bytes (64 KiB = 65,536 bytes).
pub const WASM_PAGE_SIZE: usize = 64 * 1024;
/// Maximum WASM memory pages allowed per contract during validation and execution.
/// Set to 128 pages (8 MiB), permitting contracts up to 64 pages (4 MiB) or 128 pages.
pub const MAX_CONTRACT_PAGES: u32 = 128;
/// Alias for `MAX_CONTRACT_PAGES`.
pub const MAX_CONTRACT_MEMORY_PAGES: u32 = MAX_CONTRACT_PAGES;
pub const MAX_CONTRACT_PAGES_64: u32 = 64;
pub const MAX_CONTRACT_PAGES_128: u32 = 128;
/// Maximum linear memory a contract may allocate (128 pages * 64 KiB = 8 MiB).
pub const MAX_CONTRACT_MEMORY: usize = (MAX_CONTRACT_PAGES as usize) * WASM_PAGE_SIZE;

/// Base gas charged for contract deployment and validation.
pub const GAS_DEPLOY_BASE: u64 = 2_000;
/// Gas charged per byte of contract bytecode.
pub const GAS_PER_BYTE: u64 = 2;

/// Calculate deploy gas / validation costs scaled with bytecode size:
/// `GAS_DEPLOY_BASE + bytes * GAS_PER_BYTE`.
#[inline(always)]
pub fn contract_deploy_gas(code_len: usize) -> u64 {
    GAS_DEPLOY_BASE.saturating_add((code_len as u64).saturating_mul(GAS_PER_BYTE))
}

#[inline(always)]
pub fn deploy_gas(code_len: usize) -> u64 {
    contract_deploy_gas(code_len)
}

/// Hard cap on the number of persistent storage slots one contract may own.
///
/// Host functions run outside the fuel meter, so without this a contract could
/// write millions of distinct keys inside one call and permanently bloat the
/// consensus state of every node.
pub const MAX_CONTRACT_STORAGE_KEYS: usize = 4_096;
/// Hard cap on events a single call may emit (same reasoning as storage).
pub const MAX_CONTRACT_EVENTS: usize = 256;
/// Hard cap on outbound messages a single contract call may produce.
pub const MAX_CONTRACT_OUTBOUND_MESSAGES: usize = 64;
/// Maximum return data size a contract may set (64 KiB).
pub const MAX_RETURN_DATA: usize = 64 * 1024;

/// Fuel charged for a host storage read.
pub const FUEL_SLOAD: u64 = 10;
/// Fuel charged for a host storage write.
pub const FUEL_SSTORE: u64 = 100;
/// Fuel charged per emitted event.
pub const FUEL_EMIT: u64 = 50;
/// Fuel charged per outbound contract message sent.
pub const FUEL_SEND_MESSAGE: u64 = 100;
/// Fuel charged for reading caller address into WASM memory.
pub const FUEL_CALLER: u64 = 10;
/// Fuel charged for reading call value.
pub const FUEL_VALUE: u64 = 5;
/// Fuel charged for copying the ABI-encoded call arguments into WASM memory.
pub const FUEL_CALLDATA: u64 = 20;
/// Fuel charged per byte of call arguments copied into WASM memory.
pub const FUEL_CALLDATA_PER_BYTE: u64 = 1;
/// Fuel charged for reading block timestamp.
pub const FUEL_BLOCK_TIME: u64 = 5;
/// Fuel charged for writing block hash into WASM memory.
pub const FUEL_BLOCK_HASH: u64 = 10;
/// Base fuel charged for SHA-256 computation.
pub const FUEL_SHA256_BASE: u64 = 30;
/// Fuel charged per byte hashed with SHA-256.
pub const FUEL_SHA256_PER_BYTE: u64 = 1;
/// Base fuel charged for BLAKE3 computation.
pub const FUEL_BLAKE3_BASE: u64 = 20;
/// Fuel charged per byte hashed with BLAKE3.
pub const FUEL_BLAKE3_PER_BYTE: u64 = 1;
/// Fuel charged for Ed25519 signature verification.
pub const FUEL_ED25519_VERIFY: u64 = 500;
/// Base fuel charged for setting return data.
pub const FUEL_RETURN_DATA_BASE: u64 = 10;
/// Fuel charged per byte of return data.
pub const FUEL_RETURN_DATA_PER_BYTE: u64 = 1;

/// Context passed into a contract call execution.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallContext {
    pub caller: [u8; 32],
    pub value: u64,
    pub block_time: u64,
    pub block_hash: [u8; 32],
}

/// Full execution outcome of a contract call.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractOutcome {
    pub result: i64,
    pub fuel_used: u64,
    pub events: Vec<ContractEvent>,
    pub outbound_messages: Vec<ContractMessage>,
    pub return_data: Vec<u8>,
}

impl ContractOutcome {
    /// Decode the outcome's return value with the contract's ABI manifest.
    ///
    /// Scalar returns come from the `i64` result, blob returns (`bytes`,
    /// `address`, `string`) from the contract's return data.
    pub fn typed_return(&self, abi: &ContractAbi, method: &str) -> Result<AbiValue, AbiError> {
        abi.decode_runtime_return(method, self.result, &self.return_data)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractError {
    EmptyCode,
    CodeTooLarge,
    InvalidWasm,
    AlreadyExists,
    NotFound,
    Paused,
    NoSuchMethod,
    OutOfFuel,
    Trapped,
    Overflow,
    UnresolvableImports,
    /// The attached ABI manifest is malformed.
    InvalidAbi(String),
    /// The call does not match the attached ABI manifest.
    AbiMismatch(String),
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ContractError::EmptyCode => "contract code must not be empty",
            ContractError::CodeTooLarge => "contract code exceeds the maximum size",
            ContractError::InvalidWasm => "contract code is not a valid wasm module",
            ContractError::AlreadyExists => "contract already exists",
            ContractError::NotFound => "contract not found",
            ContractError::Paused => "contract is paused",
            ContractError::NoSuchMethod => "contract does not export the requested method",
            ContractError::OutOfFuel => "contract ran out of fuel",
            ContractError::Trapped => "contract trapped during execution",
            ContractError::Overflow => "contract id space exhausted",
            ContractError::UnresolvableImports => {
                "contract imports something the host does not provide"
            }
            ContractError::InvalidAbi(m) => return write!(f, "invalid contract ABI manifest: {m}"),
            ContractError::AbiMismatch(m) => {
                return write!(f, "call does not match the contract ABI: {m}")
            }
        };
        write!(f, "{s}")
    }
}

/// Deterministic contract address: sha256("STELL_CONTRACT" || creator || nonce).
pub fn contract_address(creator: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELL_CONTRACT");
    h.update(creator);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// A deployed contract actor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contract {
    pub address: [u8; 32],
    pub creator: [u8; 32],
    pub code_hash: [u8; 32],
    pub code: Vec<u8>,
    /// On-chain persistent key-value storage (modified via host.sload / host.sstore)
    pub storage: HashMap<i64, i64>,
    pub created_at: u64,
    pub paused: bool,
    #[serde(default)]
    pub balance: u64,
    /// Optional typed ABI manifest describing the exported methods and events.
    ///
    /// Stored with the contract (and committed next to the code hash) so that
    /// clients can encode/decode calls and the RPC layer can validate them.
    #[serde(default)]
    pub abi: Option<ContractAbi>,
    /// Optional deterministic build fingerprint of the verified source:
    /// `BLAKE3(source_text)` (see `crate::contract_source`).
    ///
    /// Committed to the state digest alongside the code hash when present;
    /// absent (`None`) means UNVERIFIED and contributes nothing to the digest,
    /// so chains that never registered a source keep byte-identical roots
    /// (backward-compatible). Set only by an explicit, creator-signed
    /// registration — verification itself is read-only and never sets it.
    #[serde(default)]
    pub source_hash: Option<[u8; 32]>,
}

/// An outbound contract message produced during execution via `host.send_message`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractMessage {
    pub msg_id: [u8; 32],
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub value: u64,
    pub payload: Vec<u8>,
    pub bounce: bool,
}

/// An on-chain contract event emitted during execution via `host.emit`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEvent {
    pub contract: [u8; 32],
    pub topic: i64,
    pub value: i64,
}

/// JSON-friendly event representation returned in read-only get method responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEventJson {
    pub contract: String,
    pub topic: i64,
    pub value: i64,
}

impl From<ContractEvent> for ContractEventJson {
    fn from(e: ContractEvent) -> Self {
        Self {
            contract: hex::encode(e.contract),
            topic: e.topic,
            value: e.value,
        }
    }
}

/// Result format of a read-only getter call (`stell_runGetMethod`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetMethodResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_bytes: Option<String>,
    /// Typed return value decoded with the contract's ABI manifest, when one
    /// is attached (JSON form: number / bool / `0x…` hex string).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_typed: Option<AbiValue>,
    pub fuel_used: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<ContractEventJson>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl GetMethodResponse {
    pub fn success(return_value: i64, fuel_used: u64, events: Vec<ContractEvent>) -> Self {
        Self {
            success: true,
            return_value: Some(return_value),
            return_bytes: Some(hex::encode(return_value.to_be_bytes())),
            return_typed: None,
            fuel_used,
            events: Some(events.into_iter().map(ContractEventJson::from).collect()),
            error: None,
        }
    }

    /// Same as [`GetMethodResponse::success`] but carrying a typed return value
    /// decoded through the contract's ABI manifest.
    pub fn success_typed(
        return_value: i64,
        typed: AbiValue,
        fuel_used: u64,
        events: Vec<ContractEvent>,
    ) -> Self {
        let mut resp = Self::success(return_value, fuel_used, events);
        resp.return_typed = Some(typed);
        resp
    }

    pub fn error(error: impl Into<String>, fuel_used: u64) -> Self {
        Self {
            success: false,
            return_value: None,
            return_bytes: None,
            return_typed: None,
            fuel_used,
            events: None,
            error: Some(error.into()),
        }
    }
}

/// Read an unsigned LEB128 integer from a byte slice, returning (value, bytes_read).
fn read_leb128_u32(bytes: &[u8]) -> Result<(u32, usize), ContractError> {
    let mut result = 0u32;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if i >= 5 {
            return Err(ContractError::InvalidWasm);
        }
        result |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(ContractError::InvalidWasm)
}

/// Validate that WASM module memory declarations do not exceed `MAX_CONTRACT_PAGES`.
fn validate_memory_limits(code: &[u8]) -> Result<(), ContractError> {
    if code.len() < 8 || &code[0..4] != b"\0asm" {
        return Ok(()); // Defer to wasmi::Module::new
    }
    let mut pos = 8;
    while pos < code.len() {
        let sec_id = code[pos];
        pos += 1;
        let (sec_len, n) = read_leb128_u32(&code[pos..])?;
        pos += n;
        let sec_len = sec_len as usize;
        if pos + sec_len > code.len() {
            return Err(ContractError::InvalidWasm);
        }
        let sec_bytes = &code[pos..pos + sec_len];
        pos += sec_len;

        if sec_id == 5 {
            // Memory section: [count, (limits)...]
            let mut sec_pos = 0;
            let (count, n) = read_leb128_u32(&sec_bytes[sec_pos..])?;
            sec_pos += n;
            for _ in 0..count {
                if sec_pos >= sec_bytes.len() {
                    return Err(ContractError::InvalidWasm);
                }
                let (flags, n) = read_leb128_u32(&sec_bytes[sec_pos..])?;
                sec_pos += n;
                if sec_pos >= sec_bytes.len() {
                    return Err(ContractError::InvalidWasm);
                }
                let (min_pages, n) = read_leb128_u32(&sec_bytes[sec_pos..])?;
                sec_pos += n;
                if min_pages > MAX_CONTRACT_PAGES {
                    return Err(ContractError::InvalidWasm);
                }
                if flags & 1 != 0 {
                    if sec_pos >= sec_bytes.len() {
                        return Err(ContractError::InvalidWasm);
                    }
                    let (max_pages, n) = read_leb128_u32(&sec_bytes[sec_pos..])?;
                    sec_pos += n;
                    if max_pages > MAX_CONTRACT_PAGES {
                        return Err(ContractError::InvalidWasm);
                    }
                }
            }
        }
    }
    Ok(())
}

/// Registry of all deployed contracts (part of consensus state).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ContractRegistry {
    pub contracts: HashMap<[u8; 32], Contract>,
    pub next_nonce: u64,
    #[serde(default)]
    pub last_return_data: Vec<u8>,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate deploy gas / validation costs scaling with bytecode size:
    /// `GAS_DEPLOY_BASE + bytes * GAS_PER_BYTE`.
    #[inline(always)]
    pub fn deploy_gas(code_len: usize) -> u64 {
        deploy_gas(code_len)
    }

    /// Validate wasm code without deploying it (used by deploy and tests).
    ///
    /// Besides syntactic validation this performs a *dry-run instantiation*, so
    /// a module whose imports the host cannot satisfy is rejected up front
    /// instead of becoming a permanently uncallable contract that still cost
    /// the creator their deployment gas.
    pub fn validate_code(code: &[u8]) -> Result<(), ContractError> {
        if code.is_empty() {
            return Err(ContractError::EmptyCode);
        }
        if code.len() > MAX_CONTRACT_CODE_SIZE {
            return Err(ContractError::CodeTooLarge);
        }
        validate_memory_limits(code)?;
        let engine = contract_engine();
        let module = Module::new(&engine, code).map_err(|_| ContractError::InvalidWasm)?;
        for export in module.exports() {
            if let ExternType::Memory(mem_ty) = export.ty() {
                if mem_ty.minimum() > MAX_CONTRACT_PAGES as u64 {
                    return Err(ContractError::InvalidWasm);
                }
                if let Some(max) = mem_ty.maximum() {
                    if max > MAX_CONTRACT_PAGES as u64 {
                        return Err(ContractError::InvalidWasm);
                    }
                }
            }
        }
        let host = HostState {
            limits: store_limits(),
            contract_addr: [0u8; 32],
            balance: 0,
            storage: HashMap::new(),
            events: Vec::new(),
            outbound_messages: Vec::new(),
            caller: [0u8; 32],
            value: 0,
            block_time: 0,
            block_hash: [0u8; 32],
            return_data: Vec::new(),
            calldata: Vec::new(),
        };
        let mut store = Store::new(&engine, host);
        store.limiter(|s| &mut s.limits);
        let linker = host_linker(&engine);
        // A missing import, or a start function that traps, is a deploy-time error.
        linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|e| {
                let msg = format!("{e}");
                if msg.contains("import") {
                    ContractError::UnresolvableImports
                } else {
                    ContractError::InvalidWasm
                }
            })?;
        Ok(())
    }

    /// Deploy a new contract. Returns its deterministic address.
    pub fn deploy(
        &mut self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
    ) -> Result<[u8; 32], ContractError> {
        self.deploy_with_balance(creator, code, now, 0)
    }

    /// Deploy a new contract with an initial balance. Returns its deterministic address.
    pub fn deploy_with_balance(
        &mut self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
        balance: u64,
    ) -> Result<[u8; 32], ContractError> {
        self.deploy_inner(creator, code, now, balance, None)
    }

    /// Deploy a new contract with a typed ABI manifest attached.
    ///
    /// The manifest is stored with the contract (and committed next to the
    /// code hash) so clients can encode/decode calls and the RPC layer can
    /// validate them before they touch consensus state.
    pub fn deploy_with_abi(
        &mut self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
        abi: ContractAbi,
    ) -> Result<[u8; 32], ContractError> {
        self.deploy_inner(creator, code, now, 0, Some(abi))
    }

    /// Deploy a new contract with an initial balance and an ABI manifest.
    pub fn deploy_with_balance_and_abi(
        &mut self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
        balance: u64,
        abi: ContractAbi,
    ) -> Result<[u8; 32], ContractError> {
        self.deploy_inner(creator, code, now, balance, Some(abi))
    }

    fn deploy_inner(
        &mut self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
        balance: u64,
        abi: Option<ContractAbi>,
    ) -> Result<[u8; 32], ContractError> {
        Self::validate_code(&code)?;
        if let Some(a) = &abi {
            a.validate()
                .map_err(|e| ContractError::InvalidAbi(e.to_string()))?;
        }
        let address = contract_address(&creator, self.next_nonce);
        if self.contracts.contains_key(&address) {
            return Err(ContractError::AlreadyExists);
        }
        self.next_nonce = self.next_nonce.saturating_add(1);
        let code_hash: [u8; 32] = Sha256::digest(&code).into();
        self.contracts.insert(
            address,
            Contract {
                address,
                creator,
                code_hash,
                code,
                storage: HashMap::new(),
                created_at: now,
                paused: false,
                balance,
                abi,
                source_hash: None,
            },
        );
        Ok(address)
    }

    /// Register the verified-source fingerprint of a deployed contract.
    ///
    /// Explicit and authorised: only the contract CREATOR may register, and
    /// the RPC layer additionally requires the creator's ed25519 signature
    /// over the registration message (see
    /// `crate::contract_source::verify_register_signature`). Verification
    /// itself never calls this — a `verified: true` answer alone pins
    /// nothing; the label is set only by this signed action.
    pub fn register_source(
        &mut self,
        address: &[u8; 32],
        source_hash: [u8; 32],
        caller: [u8; 32],
    ) -> Result<(), ContractError> {
        let c = self
            .contracts
            .get_mut(address)
            .ok_or(ContractError::NotFound)?;
        if c.creator != caller {
            return Err(ContractError::NotFound); // only creator may register
        }
        c.source_hash = Some(source_hash);
        Ok(())
    }

    /// The registered source fingerprint of a contract, if one was registered.
    pub fn source_hash(&self, address: &[u8; 32]) -> Option<[u8; 32]> {
        self.contracts.get(address).and_then(|c| c.source_hash)
    }

    /// True when a source fingerprint is registered (the contract is labelled
    /// verified). The label is meaningful only together with a
    /// `stell_verifyContractSource` rebuild check against `code_hash`.
    pub fn is_source_registered(&self, address: &[u8; 32]) -> bool {
        self.source_hash(address).is_some()
    }

    /// Attach (or replace) the ABI manifest of a deployed contract.
    pub fn set_abi(&mut self, address: &[u8; 32], abi: ContractAbi) -> Result<(), ContractError> {
        abi.validate()
            .map_err(|e| ContractError::InvalidAbi(e.to_string()))?;
        let c = self
            .contracts
            .get_mut(address)
            .ok_or(ContractError::NotFound)?;
        c.abi = Some(abi);
        Ok(())
    }

    /// The ABI manifest of a contract, if one is attached.
    pub fn abi(&self, address: &[u8; 32]) -> Option<&ContractAbi> {
        self.contracts.get(address).and_then(|c| c.abi.as_ref())
    }

    /// The JSON ABI manifest of a contract, if one is attached.
    pub fn abi_json(&self, address: &[u8; 32]) -> Option<String> {
        self.abi(address).map(|a| a.to_json())
    }

    pub fn set_balance(&mut self, address: &[u8; 32], balance: u64) -> Result<(), ContractError> {
        let c = self
            .contracts
            .get_mut(address)
            .ok_or(ContractError::NotFound)?;
        c.balance = balance;
        Ok(())
    }

    pub fn deposit(&mut self, address: &[u8; 32], amount: u64) -> Result<(), ContractError> {
        let c = self
            .contracts
            .get_mut(address)
            .ok_or(ContractError::NotFound)?;
        c.balance = c.balance.saturating_add(amount);
        Ok(())
    }

    pub fn get_balance(&self, address: &[u8; 32]) -> u64 {
        self.contracts.get(address).map(|c| c.balance).unwrap_or(0)
    }

    pub fn get(&self, address: &[u8; 32]) -> Option<&Contract> {
        self.contracts.get(address)
    }

    pub fn exists(&self, address: &[u8; 32]) -> bool {
        self.contracts.contains_key(address)
    }

    pub fn pause(&mut self, address: &[u8; 32], caller: [u8; 32]) -> Result<(), ContractError> {
        let c = self
            .contracts
            .get_mut(address)
            .ok_or(ContractError::NotFound)?;
        if c.creator != caller {
            return Err(ContractError::NotFound); // only creator may pause
        }
        c.paused = true;
        Ok(())
    }

    /// Call an exported `(i64) -> i64` method with persistent storage, events, and outbound messages.
    /// Returns (result, fuel_used, events, outbound_messages).
    pub fn call(
        &mut self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> Result<(i64, u64, Vec<ContractEvent>, Vec<ContractMessage>), ContractError> {
        let outcome =
            self.call_with_context(address, method, arg, fuel, &ContractCallContext::default())?;
        Ok((
            outcome.result,
            outcome.fuel_used,
            outcome.events,
            outcome.outbound_messages,
        ))
    }

    /// Call an exported method that takes several `i64` parameters.
    ///
    /// Dispatch is by exact arity: the contract decides how many parameters a
    /// method takes, and the caller must supply exactly that many — an
    /// argument is never silently dropped.
    ///
    /// Returns (result, fuel_used, events, outbound_messages).
    pub fn call_args(
        &mut self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel: u64,
    ) -> Result<(i64, u64, Vec<ContractEvent>, Vec<ContractMessage>), ContractError> {
        let outcome = self.call_with_context_args(
            address,
            method,
            args,
            fuel,
            &ContractCallContext::default(),
        )?;
        Ok((
            outcome.result,
            outcome.fuel_used,
            outcome.events,
            outcome.outbound_messages,
        ))
    }

    /// Call an exported `(i64) -> i64` method with full execution context and return outcome.
    pub fn call_with_context(
        &mut self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
        ctx: &ContractCallContext,
    ) -> Result<ContractOutcome, ContractError> {
        self.call_with_context_args(address, method, &[arg], fuel, ctx)
    }

    /// Call an exported method with several `i64` parameters and full context.
    pub fn call_with_context_args(
        &mut self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel: u64,
        ctx: &ContractCallContext,
    ) -> Result<ContractOutcome, ContractError> {
        self.call_with_context_args_inner(address, method, args, &[], fuel, ctx)
    }

    /// Call an exported method with several `i64` parameters, the canonical
    /// ABI-encoded argument blob and full context.
    ///
    /// The blob is handed to the contract through `host.calldata`, so a
    /// contract can read blob parameters (addresses, bytes, strings) that do
    /// not fit the `i64` calling convention.
    pub fn call_with_context_args_calldata(
        &mut self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        calldata: &[u8],
        fuel: u64,
        ctx: &ContractCallContext,
    ) -> Result<ContractOutcome, ContractError> {
        self.call_with_context_args_inner(address, method, args, calldata, fuel, ctx)
    }

    fn call_with_context_args_inner(
        &mut self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        calldata: &[u8],
        fuel: u64,
        ctx: &ContractCallContext,
    ) -> Result<ContractOutcome, ContractError> {
        let contract = self
            .contracts
            .get_mut(address)
            .ok_or(ContractError::NotFound)?;
        if contract.paused {
            return Err(ContractError::Paused);
        }
        let fuel = fuel.min(MAX_CONTRACT_FUEL);
        let (out, used, new_storage, new_balance, events, outbound_messages, return_data) =
            run_contract(
                *address,
                &contract.code,
                &contract.storage,
                contract.balance,
                method,
                args,
                calldata,
                fuel,
                ctx,
            )?;
        contract.storage = new_storage;
        contract.balance = new_balance;
        self.last_return_data = return_data.clone();
        Ok(ContractOutcome {
            result: out,
            fuel_used: used,
            events,
            outbound_messages,
            return_data,
        })
    }

    /// Call a method with typed ABI arguments.
    ///
    /// The contract's ABI manifest is authoritative: the method must be
    /// declared, the arguments must match the declaration exactly and are
    /// encoded with the canonical ABI encoding. The scalar parameters are
    /// passed to the wasm export (one `i64` per declared parameter, in order)
    /// and the full encoded argument blob is handed to the contract through
    /// `host.calldata` so blob parameters (addresses, bytes, strings) are
    /// readable from the contract's memory.
    pub fn call_abi(
        &mut self,
        address: &[u8; 32],
        method: &str,
        args: &[AbiValue],
        fuel: u64,
    ) -> Result<ContractOutcome, ContractError> {
        self.call_abi_with_context(address, method, args, fuel, &ContractCallContext::default())
    }

    /// Call a method with typed ABI arguments and full execution context.
    pub fn call_abi_with_context(
        &mut self,
        address: &[u8; 32],
        method: &str,
        args: &[AbiValue],
        fuel: u64,
        ctx: &ContractCallContext,
    ) -> Result<ContractOutcome, ContractError> {
        let (scalars, calldata) = self.encode_abi_call(address, method, args)?;
        self.call_with_context_args_inner(address, method, &scalars, &calldata, fuel, ctx)
    }

    /// Validate a call against the contract's ABI and produce the wasm
    /// arguments plus the canonical encoded argument blob.
    fn encode_abi_call(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[AbiValue],
    ) -> Result<(Vec<i64>, Vec<u8>), ContractError> {
        let contract = self.contracts.get(address).ok_or(ContractError::NotFound)?;
        let abi = contract.abi.as_ref().ok_or_else(|| {
            ContractError::AbiMismatch("contract has no ABI manifest".to_string())
        })?;
        let m = abi
            .method(method)
            .ok_or_else(|| ContractError::AbiMismatch(format!("unknown method: {method}")))?;
        abi.validate_args(method, args)
            .map_err(|e| ContractError::AbiMismatch(e.to_string()))?;
        let encoded = abi
            .encode_args(method, args)
            .map_err(|e| ContractError::AbiMismatch(e.to_string()))?;
        let mut scalars = Vec::with_capacity(m.params.len());
        for v in args.iter() {
            // Blob parameters do not fit the i64 calling convention: they are
            // passed as 0 and read from the calldata blob.
            let scalar = v.as_i64().unwrap_or(0);
            scalars.push(scalar);
        }
        Ok((scalars, encoded))
    }

    /// Call an exported `(i64) -> i64` method with default context and return outcome.
    pub fn call_outcome(
        &mut self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> Result<ContractOutcome, ContractError> {
        self.call_with_context(address, method, arg, fuel, &ContractCallContext::default())
    }

    /// Call an exported method with several `i64` parameters, default context.
    pub fn call_outcome_args(
        &mut self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel: u64,
    ) -> Result<ContractOutcome, ContractError> {
        self.call_with_context_args(address, method, args, fuel, &ContractCallContext::default())
    }

    /// Read-only getter execution against a cloned working state of the contract.
    ///
    /// - Zero state changes: mutations to storage or balances are immediately discarded.
    /// - Zero gas fee charged: read-only execution.
    /// - Bounded by `GET_METHOD_SAFETY_FUEL_LIMIT` (5,000,000 fuel) to prevent infinite loops.
    pub fn run_get_method(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        fuel_limit: Option<u64>,
    ) -> GetMethodResponse {
        self.run_get_method_inner(address, method, args, &[], fuel_limit)
            .0
    }

    /// Same as [`ContractRegistry::run_get_method`] but also returns the raw
    /// return data the contract produced (`host.return_data`).
    fn run_get_method_inner(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[i64],
        calldata: &[u8],
        fuel_limit: Option<u64>,
    ) -> (GetMethodResponse, Vec<u8>) {
        let contract = match self.contracts.get(address) {
            Some(c) => c,
            None => {
                return (
                    GetMethodResponse::error("contract not found", 0),
                    Vec::new(),
                )
            }
        };
        if contract.paused {
            return (
                GetMethodResponse::error("contract is paused", 0),
                Vec::new(),
            );
        }

        let fuel = fuel_limit
            .unwrap_or(GET_METHOD_SAFETY_FUEL_LIMIT)
            .min(GET_METHOD_SAFETY_FUEL_LIMIT);

        // ARITY BOUND (audit W6.7): the state-changing path refuses more
        // than `MAX_CONTRACT_CALL_ARGS` arguments, but the READ-ONLY getter
        // path did not — and its "legacy tolerance" fallback walks the WHOLE
        // argument list looking for a matching export, so a caller could
        // hand it a 1 MiB argument array (the RPC body limit) and make every
        // request do hundreds of thousands of export lookups. The getter
        // refuses the same arity the call path does.
        if args.len() > MAX_CONTRACT_CALL_ARGS {
            return (
                GetMethodResponse::error(
                    format!("too many arguments: at most {MAX_CONTRACT_CALL_ARGS}"),
                    0,
                ),
                Vec::new(),
            );
        }

        let engine = contract_engine();
        let module = match Module::new(&engine, &contract.code) {
            Ok(m) => m,
            Err(_) => {
                return (
                    GetMethodResponse::error("contract code is not a valid wasm module", 0),
                    Vec::new(),
                )
            }
        };

        let host = HostState {
            limits: store_limits(),
            contract_addr: *address,
            balance: contract.balance,
            storage: contract.storage.clone(),
            events: Vec::new(),
            outbound_messages: Vec::new(),
            caller: [0u8; 32],
            value: 0,
            block_time: 0,
            block_hash: [0u8; 32],
            return_data: Vec::new(),
            calldata: calldata.to_vec(),
        };
        let mut store = Store::new(&engine, host);
        store.limiter(|s| &mut s.limits);
        if store.set_fuel(fuel).is_err() {
            return (
                GetMethodResponse::error("contract ran out of fuel", 0),
                Vec::new(),
            );
        }

        let linker = host_linker(&engine);
        let instance = match linker.instantiate_and_start(&mut store, &module) {
            Ok(inst) => inst,
            Err(e) => {
                let remaining = store.get_fuel().unwrap_or(0);
                let used = fuel.saturating_sub(remaining);
                let msg = format!("{e}");
                let err_str = if msg.contains("fuel") {
                    "contract ran out of fuel"
                } else {
                    "contract instantiation failed"
                };
                return (GetMethodResponse::error(err_str, used), Vec::new());
            }
        };

        let call_res = match call_export(&mut store, &instance, method, args, true) {
            Some(res) => res,
            None => {
                return (
                    GetMethodResponse::error("contract does not export the requested method", 0),
                    Vec::new(),
                )
            }
        };

        let remaining = store.get_fuel().unwrap_or(0);
        let used = fuel.saturating_sub(remaining);
        let host = store.into_data();
        let events = host.events;
        let return_data = host.return_data;

        let resp = match call_res {
            Ok(ret_val) => GetMethodResponse::success(ret_val, used, events),
            Err(e) => {
                let msg = format!("{e}");
                let err_str = if msg.contains("fuel") {
                    "contract ran out of fuel"
                } else {
                    "contract trapped during execution"
                };
                GetMethodResponse::error(err_str, used)
            }
        };
        (resp, return_data)
    }

    /// Read-only getter execution validated against the contract's ABI
    /// manifest.
    ///
    /// The manifest is authoritative: the method must exist, the argument
    /// count must match the declaration and every argument must have the
    /// declared type. The typed return value is decoded from the outcome and
    /// returned in [`GetMethodResponse::return_typed`].
    pub fn run_get_method_typed(
        &self,
        address: &[u8; 32],
        method: &str,
        args: &[AbiValue],
        fuel_limit: Option<u64>,
    ) -> GetMethodResponse {
        let contract = match self.contracts.get(address) {
            Some(c) => c,
            None => return GetMethodResponse::error("contract not found", 0),
        };
        let abi = match &contract.abi {
            Some(a) => a,
            None => return GetMethodResponse::error("contract has no ABI manifest attached", 0),
        };
        if let Err(e) = abi.validate_args(method, args) {
            return GetMethodResponse::error(format!("ABI validation failed: {e}"), 0);
        }
        // The canonical encoding travels to the contract as calldata; the
        // scalar parameters are passed as `i64` parameters.
        let (scalars, calldata) = match self.encode_abi_call(address, method, args) {
            Ok(v) => v,
            Err(e) => return GetMethodResponse::error(e.to_string(), 0),
        };
        let (resp, return_data) =
            self.run_get_method_inner(address, method, &scalars, &calldata, fuel_limit);
        if !resp.success {
            return resp;
        }
        let raw = resp.return_value.unwrap_or(0);
        match abi.decode_runtime_return(method, raw, &return_data) {
            Ok(typed) => {
                let mut out = resp;
                out.return_typed = Some(typed);
                out
            }
            Err(e) => GetMethodResponse::error(format!("ABI decoding failed: {e}"), resp.fuel_used),
        }
    }
}

/// Build the deterministic wasmi engine used for every contract execution.
fn contract_engine() -> Engine {
    let mut config = Config::default();
    // Bound execution: every instruction consumes fuel; a call cannot loop forever.
    config.consume_fuel(true);
    // Keep the feature surface tight. Float determinism is enforced by the
    // `deterministic` crate feature (canonical NaN semantics) enabled in
    // Cargo.toml, so results match on every CPU/architecture.
    config.wasm_multi_memory(false);
    config.wasm_mutable_global(true);
    Engine::new(&config)
}

struct HostState {
    limits: StoreLimits,
    contract_addr: [u8; 32],
    balance: u64,
    storage: HashMap<i64, i64>,
    events: Vec<ContractEvent>,
    outbound_messages: Vec<ContractMessage>,
    caller: [u8; 32],
    value: u64,
    block_time: u64,
    block_hash: [u8; 32],
    return_data: Vec<u8>,
    /// ABI-encoded arguments of the current call (see `host.calldata`).
    calldata: Vec<u8>,
}

impl HostState {
    /// Charge `fuel` to the caller's budget, trapping when it is exhausted.
    fn charge(caller: &mut wasmi::Caller<'_, HostState>, fuel: u64) -> Result<(), wasmi::Error> {
        let left = caller.get_fuel()?;
        let left = left
            .checked_sub(fuel)
            .ok_or_else(|| wasmi::Error::new("host operation out of fuel"))?;
        caller.set_fuel(left)
    }
}

/// The resource limits every contract store runs under.
fn store_limits() -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(MAX_CONTRACT_MEMORY)
        .memories(4)
        .tables(4)
        .instances(16)
        .build()
}

fn get_memory(caller: &mut wasmi::Caller<'_, HostState>) -> Result<Memory, wasmi::Error> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| wasmi::Error::new("contract memory not exported"))
}

fn read_wasm_memory(
    caller: &mut wasmi::Caller<'_, HostState>,
    ptr: i32,
    len: usize,
) -> Result<Vec<u8>, wasmi::Error> {
    if ptr < 0 {
        return Err(wasmi::Error::new(
            "memory pointer out of bounds: negative pointer",
        ));
    }
    let offset = ptr as usize;
    let mem = get_memory(caller)?;
    let end = offset
        .checked_add(len)
        .ok_or_else(|| wasmi::Error::new("memory pointer overflow"))?;
    if end > mem.data(&*caller).len() {
        return Err(wasmi::Error::new("memory access out of bounds"));
    }
    let mut buf = vec![0u8; len];
    mem.read(&*caller, offset, &mut buf)?;
    Ok(buf)
}

fn write_wasm_memory(
    caller: &mut wasmi::Caller<'_, HostState>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), wasmi::Error> {
    if ptr < 0 {
        return Err(wasmi::Error::new(
            "memory pointer out of bounds: negative pointer",
        ));
    }
    let offset = ptr as usize;
    let mem = get_memory(caller)?;
    let end = offset
        .checked_add(bytes.len())
        .ok_or_else(|| wasmi::Error::new("memory pointer overflow"))?;
    if end > mem.data(&*caller).len() {
        return Err(wasmi::Error::new("memory access out of bounds"));
    }
    mem.write(&mut *caller, offset, bytes)?;
    Ok(())
}

/// The complete set of host functions a contract may import.
///
/// Anything outside this list is unresolvable, which is what makes the sandbox
/// closed: no clock, no network, no filesystem, no host memory.
fn host_linker(engine: &Engine) -> Linker<HostState> {
    let mut linker = <Linker<HostState>>::new(engine);
    let _ = linker.func_wrap(
        "host",
        "sload",
        |mut caller: wasmi::Caller<'_, HostState>, key: i64| -> Result<i64, wasmi::Error> {
            HostState::charge(&mut caller, FUEL_SLOAD)?;
            Ok(caller.data().storage.get(&key).copied().unwrap_or(0))
        },
    );
    let _ = linker.func_wrap(
        "host",
        "sstore",
        |mut caller: wasmi::Caller<'_, HostState>,
         key: i64,
         val: i64|
         -> Result<(), wasmi::Error> {
            HostState::charge(&mut caller, FUEL_SSTORE)?;
            let state = caller.data_mut();
            // Writing a *new* key grows the permanent consensus state, so it is
            // capped; overwriting an existing slot is always allowed.
            if !state.storage.contains_key(&key) && state.storage.len() >= MAX_CONTRACT_STORAGE_KEYS
            {
                return Err(wasmi::Error::new("contract storage limit exceeded"));
            }
            state.storage.insert(key, val);
            Ok(())
        },
    );
    let _ = linker.func_wrap(
        "host",
        "emit",
        |mut caller: wasmi::Caller<'_, HostState>,
         topic: i64,
         val: i64|
         -> Result<(), wasmi::Error> {
            HostState::charge(&mut caller, FUEL_EMIT)?;
            let state = caller.data_mut();
            if state.events.len() >= MAX_CONTRACT_EVENTS {
                return Err(wasmi::Error::new("contract event limit exceeded"));
            }
            let contract = state.contract_addr;
            state.events.push(ContractEvent {
                contract,
                topic,
                value: val,
            });
            Ok(())
        },
    );
    let _ = linker.func_wrap(
        "host",
        "caller",
        |mut caller: wasmi::Caller<'_, HostState>, dest_ptr: i32| -> Result<(), wasmi::Error> {
            HostState::charge(&mut caller, FUEL_CALLER)?;
            let caller_addr = caller.data().caller;
            write_wasm_memory(&mut caller, dest_ptr, &caller_addr)?;
            Ok(())
        },
    );
    let _ = linker.func_wrap(
        "host",
        "value",
        |mut caller: wasmi::Caller<'_, HostState>| -> Result<i64, wasmi::Error> {
            HostState::charge(&mut caller, FUEL_VALUE)?;
            Ok(caller.data().value as i64)
        },
    );
    let _ = linker.func_wrap(
        "host",
        "block_time",
        |mut caller: wasmi::Caller<'_, HostState>| -> Result<i64, wasmi::Error> {
            HostState::charge(&mut caller, FUEL_BLOCK_TIME)?;
            Ok(caller.data().block_time as i64)
        },
    );
    let _ = linker.func_wrap(
        "host",
        "block_hash",
        |mut caller: wasmi::Caller<'_, HostState>, dest_ptr: i32| -> Result<(), wasmi::Error> {
            HostState::charge(&mut caller, FUEL_BLOCK_HASH)?;
            let b_hash = caller.data().block_hash;
            write_wasm_memory(&mut caller, dest_ptr, &b_hash)?;
            Ok(())
        },
    );
    let _ = linker.func_wrap(
        "host",
        "calldata",
        |mut caller: wasmi::Caller<'_, HostState>, dest_ptr: i32| -> Result<i64, wasmi::Error> {
            // The ABI-encoded arguments of the current call are copied into
            // the contract's memory so a contract can read blob parameters
            // (addresses, bytes, strings) that do not fit the i64 calling
            // convention.
            let data = caller.data().calldata.clone();
            let fuel = FUEL_CALLDATA
                .saturating_add((data.len() as u64).saturating_mul(FUEL_CALLDATA_PER_BYTE));
            HostState::charge(&mut caller, fuel)?;
            if data.is_empty() {
                return Ok(0);
            }
            write_wasm_memory(&mut caller, dest_ptr, &data)?;
            Ok(data.len() as i64)
        },
    );
    let _ = linker.func_wrap(
        "host",
        "sha256",
        |mut caller: wasmi::Caller<'_, HostState>,
         src_ptr: i32,
         src_len: i32,
         dest_ptr: i32|
         -> Result<(), wasmi::Error> {
            if src_len < 0 {
                return Err(wasmi::Error::new("negative input length for sha256"));
            }
            let len = src_len as usize;
            if len > MAX_CONTRACT_MEMORY {
                return Err(wasmi::Error::new("sha256 input exceeds maximum memory"));
            }
            let fuel = FUEL_SHA256_BASE
                .saturating_add((len as u64).saturating_mul(FUEL_SHA256_PER_BYTE))
                .saturating_add(32);
            HostState::charge(&mut caller, fuel)?;
            let input = read_wasm_memory(&mut caller, src_ptr, len)?;
            let digest: [u8; 32] = Sha256::digest(&input).into();
            write_wasm_memory(&mut caller, dest_ptr, &digest)?;
            Ok(())
        },
    );
    let _ = linker.func_wrap(
        "host",
        "blake3",
        |mut caller: wasmi::Caller<'_, HostState>,
         src_ptr: i32,
         src_len: i32,
         dest_ptr: i32|
         -> Result<(), wasmi::Error> {
            if src_len < 0 {
                return Err(wasmi::Error::new("negative input length for blake3"));
            }
            let len = src_len as usize;
            if len > MAX_CONTRACT_MEMORY {
                return Err(wasmi::Error::new("blake3 input exceeds maximum memory"));
            }
            let fuel = FUEL_BLAKE3_BASE
                .saturating_add((len as u64).saturating_mul(FUEL_BLAKE3_PER_BYTE))
                .saturating_add(32);
            HostState::charge(&mut caller, fuel)?;
            let input = read_wasm_memory(&mut caller, src_ptr, len)?;
            let digest: [u8; 32] = *blake3::hash(&input).as_bytes();
            write_wasm_memory(&mut caller, dest_ptr, &digest)?;
            Ok(())
        },
    );
    let _ = linker.func_wrap(
        "host",
        "ed25519_verify",
        |mut caller: wasmi::Caller<'_, HostState>,
         pubkey_ptr: i32,
         msg_ptr: i32,
         msg_len: i32,
         sig_ptr: i32|
         -> Result<i32, wasmi::Error> {
            if msg_len < 0 {
                return Err(wasmi::Error::new(
                    "negative message length for ed25519_verify",
                ));
            }
            let mlen = msg_len as usize;
            if mlen > MAX_CONTRACT_MEMORY {
                return Err(wasmi::Error::new("message length exceeds maximum memory"));
            }
            let fuel = FUEL_ED25519_VERIFY
                .saturating_add(32)
                .saturating_add(mlen as u64)
                .saturating_add(64);
            HostState::charge(&mut caller, fuel)?;
            let _pk_bytes = read_wasm_memory(&mut caller, pubkey_ptr, 32)?;
            let _msg_bytes = read_wasm_memory(&mut caller, msg_ptr, mlen)?;
            let _sig_bytes = read_wasm_memory(&mut caller, sig_ptr, 64)?;
            // FULL-PQ: classical ed25519 host verification is REMOVED.
            // Fuel + memory effects above stay identical (no free-call
            // oracle); the cryptographic verdict is always false.
            Ok(0)
        },
    );
    let _ = linker.func_wrap(
        "host",
        "return_data",
        |mut caller: wasmi::Caller<'_, HostState>,
         ptr: i32,
         len: i32|
         -> Result<(), wasmi::Error> {
            if len < 0 {
                return Err(wasmi::Error::new("negative length for return_data"));
            }
            let dlen = len as usize;
            if dlen > MAX_RETURN_DATA {
                return Err(wasmi::Error::new("return data exceeds maximum limit"));
            }
            let fuel = FUEL_RETURN_DATA_BASE
                .saturating_add((dlen as u64).saturating_mul(FUEL_RETURN_DATA_PER_BYTE));
            HostState::charge(&mut caller, fuel)?;
            let data = read_wasm_memory(&mut caller, ptr, dlen)?;
            caller.data_mut().return_data = data;
            Ok(())
        },
    );
    let _ = linker.func_wrap(
        "host",
        "send_message",
        |mut caller: wasmi::Caller<'_, HostState>,
         recipient_ptr: i64,
         recipient_len: i64,
         value_nano: i64,
         payload_ptr: i64,
         payload_len: i64,
         bounce_flag: i64|
         -> Result<i64, wasmi::Error> {
            HostState::charge(&mut caller, FUEL_SEND_MESSAGE)?;

            if recipient_len != 32 {
                return Ok(-1);
            }
            if recipient_ptr < 0 || payload_ptr < 0 || payload_len < 0 {
                return Ok(-1);
            }
            if payload_len > 64 * 1024 {
                return Ok(-1);
            }
            if value_nano < 0 {
                return Ok(-2);
            }

            let memory = match caller.get_export("memory").and_then(Extern::into_memory) {
                Some(m) => m,
                None => return Ok(-1),
            };

            let mut recipient = [0u8; 32];
            if memory
                .read(&caller, recipient_ptr as usize, &mut recipient)
                .is_err()
            {
                return Ok(-1);
            }

            let mut payload = vec![0u8; payload_len as usize];
            if payload_len > 0
                && memory
                    .read(&caller, payload_ptr as usize, &mut payload)
                    .is_err()
            {
                return Ok(-1);
            }

            let state = caller.data_mut();
            if (value_nano as u64) > state.balance {
                return Ok(-2);
            }
            if state.outbound_messages.len() >= MAX_CONTRACT_OUTBOUND_MESSAGES {
                return Ok(-3);
            }

            state.balance -= value_nano as u64;

            let sender = state.contract_addr;
            let bounce = bounce_flag != 0;

            let mut hasher = Sha256::new();
            hasher.update(sender);
            hasher.update(recipient);
            hasher.update((value_nano as u64).to_be_bytes());
            hasher.update(&payload);
            hasher.update((state.outbound_messages.len() as u64).to_be_bytes());
            let msg_id: [u8; 32] = hasher.finalize().into();

            let msg_num = (state.outbound_messages.len() + 1) as i64;
            state.outbound_messages.push(ContractMessage {
                msg_id,
                sender,
                recipient,
                value: value_nano as u64,
                payload,
                bounce,
            });

            Ok(msg_num)
        },
    );
    linker
}

/// Invoke an exported wasm function with `args` `i64` parameters.
///
/// The export is resolved by *exact* arity, so a contract that exports
/// `(i64, i64) -> i64` is called with two arguments, `(i64, i64, i64) -> i64`
/// with three, and so on up to [`MAX_CONTRACT_CALL_ARGS`].
///
/// `allow_fallback` enables the legacy tolerance of the read-only getter path:
/// when no export matches the requested arity, a lower-arity export of the
/// same name is tried with the extra arguments dropped. The state-changing
/// path never does this — dropping an argument could move the wrong amount of
/// value.
///
/// Returns `None` when the contract does not export the method at all.
fn call_export(
    store: &mut Store<HostState>,
    instance: &Instance,
    method: &str,
    args: &[i64],
    allow_fallback: bool,
) -> Option<Result<i64, wasmi::Error>> {
    if let Some(res) = call_export_exact(store, instance, method, args) {
        return Some(res);
    }

    if allow_fallback {
        // Legacy tolerance of the read-only getter path: a contract that
        // exports a lower-arity function is still callable and the extra
        // arguments are dropped. A zero-argument export is only reachable
        // from a zero- or one-argument call (as before the ABI existed).
        let start = if args.len() <= 1 { 0 } else { 1 };
        for n in start..args.len() {
            if let Some(res) = call_export_exact(store, instance, method, &args[..n]) {
                return Some(res);
            }
        }
    } else if args.len() == 1 {
        // Legacy tolerance of the state-changing path: a one-argument call
        // may still reach a zero-argument export (the pre-ABI runtime allowed
        // `call(addr, "get", 0)` on a `() -> i64` export). Multi-argument
        // calls stay strict: an argument is never dropped.
        if let Ok(f) = instance.get_typed_func::<(), i64>(&*store, method) {
            return Some(f.call(&mut *store, ()));
        }
    }

    None
}

/// Call an exported function whose arity matches `args` exactly.
///
/// Returns `None` when the contract does not export a function of that name
/// and arity.
fn call_export_exact(
    store: &mut Store<HostState>,
    instance: &Instance,
    method: &str,
    args: &[i64],
) -> Option<Result<i64, wasmi::Error>> {
    macro_rules! try_arity {
        ($ty:ty, $val:expr) => {{
            match instance.get_typed_func::<$ty, i64>(&*store, method) {
                Ok(f) => return Some(f.call(&mut *store, $val)),
                Err(_) => {}
            }
        }};
    }

    match args.len() {
        0 => {
            if let Ok(f) = instance.get_typed_func::<(), i64>(&*store, method) {
                return Some(f.call(&mut *store, ()));
            }
        }
        1 => try_arity!(i64, args[0]),
        2 => try_arity!((i64, i64), (args[0], args[1])),
        3 => try_arity!((i64, i64, i64), (args[0], args[1], args[2])),
        4 => try_arity!((i64, i64, i64, i64), (args[0], args[1], args[2], args[3])),
        5 => try_arity!(
            (i64, i64, i64, i64, i64),
            (args[0], args[1], args[2], args[3], args[4])
        ),
        6 => try_arity!(
            (i64, i64, i64, i64, i64, i64),
            (args[0], args[1], args[2], args[3], args[4], args[5])
        ),
        7 => try_arity!(
            (i64, i64, i64, i64, i64, i64, i64),
            (args[0], args[1], args[2], args[3], args[4], args[5], args[6])
        ),
        8 => try_arity!(
            (i64, i64, i64, i64, i64, i64, i64, i64),
            (args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7])
        ),
        _ => return None,
    }

    // Exports that return nothing.
    match args.len() {
        0 => {
            if let Ok(f) = instance.get_typed_func::<(), ()>(&*store, method) {
                return Some(f.call(&mut *store, ()).map(|_| 0i64));
            }
        }
        1 => {
            if let Ok(f) = instance.get_typed_func::<i64, ()>(&*store, method) {
                return Some(f.call(&mut *store, args[0]).map(|_| 0i64));
            }
        }
        2 => {
            if let Ok(f) = instance.get_typed_func::<(i64, i64), ()>(&*store, method) {
                return Some(f.call(&mut *store, (args[0], args[1])).map(|_| 0i64));
            }
        }
        3 => {
            if let Ok(f) = instance.get_typed_func::<(i64, i64, i64), ()>(&*store, method) {
                return Some(
                    f.call(&mut *store, (args[0], args[1], args[2]))
                        .map(|_| 0i64),
                );
            }
        }
        _ => {}
    }

    None
}

/// Execute an exported method in a fully sandboxed, metered store with
/// host storage (sload/sstore), event emission (emit), outbound messages (send_message),
/// and contextual/crypto host functions (caller, value, block_time, block_hash, sha256, blake3, ed25519_verify, return_data).
///
/// The method may take up to [`MAX_CONTRACT_CALL_ARGS`] `i64` parameters.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
// GATE: contract-call plumbing takes the full execution context (9 params) and returns the full outcome tuple; splitting it would churn every caller.
fn run_contract(
    contract_addr: [u8; 32],
    code: &[u8],
    initial_storage: &HashMap<i64, i64>,
    initial_balance: u64,
    method: &str,
    args: &[i64],
    calldata: &[u8],
    fuel: u64,
    ctx: &ContractCallContext,
) -> Result<
    (
        i64,
        u64,
        HashMap<i64, i64>,
        u64,
        Vec<ContractEvent>,
        Vec<ContractMessage>,
        Vec<u8>,
    ),
    ContractError,
> {
    if args.len() > MAX_CONTRACT_CALL_ARGS {
        return Err(ContractError::AbiMismatch(format!(
            "a call may take at most {MAX_CONTRACT_CALL_ARGS} arguments, got {}",
            args.len()
        )));
    }
    let engine = contract_engine();
    let module = Module::new(&engine, code).map_err(|_| ContractError::InvalidWasm)?;

    let host = HostState {
        limits: store_limits(),
        contract_addr,
        balance: initial_balance,
        storage: initial_storage.clone(),
        events: Vec::new(),
        outbound_messages: Vec::new(),
        caller: ctx.caller,
        value: ctx.value,
        block_time: ctx.block_time,
        block_hash: ctx.block_hash,
        return_data: Vec::new(),
        calldata: calldata.to_vec(),
    };
    let mut store = Store::new(&engine, host);
    store.limiter(|s| &mut s.limits);
    store.set_fuel(fuel).map_err(|_| ContractError::OutOfFuel)?;

    let linker = host_linker(&engine);
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|_| ContractError::InvalidWasm)?;
    let call_res = match call_export(&mut store, &instance, method, args, false) {
        Some(res) => res,
        None => return Err(ContractError::NoSuchMethod),
    };

    let out = match call_res {
        Ok(v) => v,
        Err(e) => {
            // Distinguish "out of fuel" from a generic trap so callers can price it.
            let msg = format!("{e}");
            if msg.contains("fuel") {
                return Err(ContractError::OutOfFuel);
            }
            return Err(ContractError::Trapped);
        }
    };
    let remaining = store.get_fuel().unwrap_or(0);
    let used = fuel.saturating_sub(remaining);
    let final_host = store.into_data();
    Ok((
        out,
        used,
        final_host.storage,
        final_host.balance,
        final_host.events,
        final_host.outbound_messages,
        final_host.return_data,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-assembled wasm for `(func (export "double") (param i64) (result i64)
    /// local.get 0; i64.const 2; i64.mul)` and `answer` ignoring its arg.
    const DOUBLE_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7e, 0x01, 0x7e, // type: (i64)->i64
        0x03, 0x02, 0x01, 0x00, // function section: 1 func, type 0
        0x07, 0x0a, 0x01, 0x06, 0x64, 0x6f, 0x75, 0x62, 0x6c, 0x65, 0x00,
        0x00, // export "double"
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x42, 0x02, 0x7e, 0x0b, // code
    ];

    const ANSWER_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7e, 0x01, 0x7e, // type: (i64)->i64
        0x03, 0x02, 0x01, 0x00, // function section
        0x07, 0x0a, 0x01, 0x06, 0x61, 0x6e, 0x73, 0x77, 0x65, 0x72, 0x00,
        0x00, // export "answer"
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x42, 0x2a, 0x0b, // code: i64.const 42; end
    ];

    #[test]
    fn deploy_validates_and_rejects_bad_code() {
        let mut reg = ContractRegistry::new();
        assert_eq!(
            reg.deploy([1u8; 32], vec![], 0),
            Err(ContractError::EmptyCode)
        );
        assert_eq!(
            reg.deploy([1u8; 32], vec![0, 1, 2, 3], 0),
            Err(ContractError::InvalidWasm)
        );
        let addr = reg.deploy([1u8; 32], DOUBLE_WASM.to_vec(), 0).unwrap();
        assert!(reg.exists(&addr));
        assert_eq!(reg.get(&addr).unwrap().creator, [1u8; 32]);
    }

    #[test]
    fn call_double_works_and_is_deterministic() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], DOUBLE_WASM.to_vec(), 0).unwrap();
        let (a, used, ..) = reg.call(&addr, "double", 21, 10_000).unwrap();
        assert_eq!(a, 42);
        assert!(used > 0, "fuel must be consumed");
        let (b, ..) = reg.call(&addr, "double", 21, 10_000).unwrap();
        assert_eq!(a, b, "deterministic");
    }

    #[test]
    fn call_unknown_method_fails() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], DOUBLE_WASM.to_vec(), 0).unwrap();
        assert_eq!(
            reg.call(&addr, "nope", 1, 10_000),
            Err(ContractError::NoSuchMethod)
        );
    }

    #[test]
    fn out_of_fuel_is_bounded() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], DOUBLE_WASM.to_vec(), 0).unwrap();
        // One fuel unit is not enough to run anything.
        assert_eq!(
            reg.call(&addr, "double", 1, 1),
            Err(ContractError::OutOfFuel)
        );
    }

    #[test]
    fn p5_event_cap_and_oob_host_args_are_fail_closed() {
        // P5 ATTACK (contract escape): a contract looping `host.emit` must
        // stop at MAX_CONTRACT_EVENTS (256) — the 257th emit traps instead of
        // bloating consensus state on every node — and host fns taking
        // wasm-memory pointers must refuse out-of-bounds addresses instead of
        // reading/writing host memory. Fuel is charged BEFORE the effect in
        // every host fn, so a failed call still pays.
        let spam_wat = r#"(module
          (import "host" "emit" (func $emit (param i64 i64)))
          (func (export "spam") (param i64) (result i64)
            (local $i i64)
            (loop $l
              (call $emit (local.get $i) (local.get $i))
              (local.set $i (i64.add (local.get $i) (i64.const 1)))
              (br_if $l (i64.lt_u (local.get $i) (i64.const 300))))
            (i64.const 0)))"#;
        let spam = wat::parse_str(spam_wat).expect("spam wat compiles");
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], spam, 0).unwrap();
        let res = reg.call(&addr, "spam", 0, crate::contract::MAX_CONTRACT_FUEL);
        assert!(
            res.is_err(),
            "the 257th emit must trap, not bloat state: {res:?}"
        );
        assert!(
            reg.get(&addr).unwrap().storage.is_empty(),
            "a trapped spam call must not persist partial effects"
        );

        // OOB pointer confusion: host.caller(dest_ptr) with a wild pointer.
        let oob_wat = r#"(module
          (import "host" "caller" (func $caller (param i32)))
          (memory 1)
          (func (export "evil") (param i64) (result i64)
            (call $caller (i32.const 1000000000))
            (i64.const 0)))"#;
        let oob = wat::parse_str(oob_wat).expect("oob wat compiles");
        let addr2 = reg.deploy([2u8; 32], oob, 0).unwrap();
        assert!(
            reg.call(&addr2, "evil", 0, crate::contract::MAX_CONTRACT_FUEL)
                .is_err(),
            "wild host-fn pointer must trap, never touch host memory"
        );

        // Self-recipient send_message is NOT reentrancy: the message is queued
        // (capped at MAX_CONTRACT_OUTBOUND_MESSAGES), never executed inline.
        // Pinned by the host linker shape: `send_message` only pushes.
        assert_eq!(crate::contract::MAX_CONTRACT_OUTBOUND_MESSAGES, 64);
        assert_eq!(crate::contract::MAX_CONTRACT_EVENTS, 256);
    }

    #[test]
    fn paused_contract_cannot_be_called() {
        let mut reg = ContractRegistry::new();
        let creator = [1u8; 32];
        let addr = reg.deploy(creator, ANSWER_WASM.to_vec(), 0).unwrap();
        assert_eq!(reg.call(&addr, "answer", 0, 10_000).unwrap().0, 42);
        reg.pause(&addr, creator).unwrap();
        assert_eq!(
            reg.call(&addr, "answer", 0, 10_000),
            Err(ContractError::Paused)
        );
        // a non-creator cannot pause
        let addr2 = reg.deploy(creator, ANSWER_WASM.to_vec(), 0).unwrap();
        assert_eq!(reg.pause(&addr2, [9u8; 32]), Err(ContractError::NotFound));
    }

    #[test]
    fn persistent_storage_sload_sstore_counter_works() {
        // Wasm module that imports host.sload and host.sstore and implements a counter:
        // `inc(key) -> sstore(key, sload(key) + 1); sload(key)`
        const COUNTER_WASM: &[u8] = &[
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0b, 0x02, 0x60, 0x01, 0x7e,
            0x01, 0x7e, 0x60, 0x02, 0x7e, 0x7e, 0x00, 0x02, 0x1c, 0x02, 0x04, 0x68, 0x6f, 0x73,
            0x74, 0x05, 0x73, 0x6c, 0x6f, 0x61, 0x64, 0x00, 0x00, 0x04, 0x68, 0x6f, 0x73, 0x74,
            0x06, 0x73, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x00, 0x01, 0x03, 0x02, 0x01, 0x00, 0x07,
            0x07, 0x01, 0x03, 0x69, 0x6e, 0x63, 0x00, 0x02, 0x0a, 0x13, 0x01, 0x11, 0x00, 0x20,
            0x00, 0x20, 0x00, 0x10, 0x00, 0x42, 0x01, 0x7c, 0x10, 0x01, 0x20, 0x00, 0x10, 0x00,
            0x0b,
        ];

        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([2u8; 32], COUNTER_WASM.to_vec(), 0).unwrap();

        // Call 1: key 42 -> was 0 -> now 1:
        let (v1, ..) = reg.call(&addr, "inc", 42, 50_000).unwrap();
        assert_eq!(v1, 1, "first call must increment 0 -> 1");

        // Call 2: key 42 -> was 1 -> now 2:
        let (v2, ..) = reg.call(&addr, "inc", 42, 50_000).unwrap();
        assert_eq!(
            v2, 2,
            "second call must increment 1 -> 2 (persistent storage)"
        );

        // Storage is persisted in contract:
        assert_eq!(reg.get(&addr).unwrap().storage.get(&42), Some(&2));
    }

    #[test]
    fn addresses_are_deterministic_and_unique() {
        let mut reg = ContractRegistry::new();
        let a1 = reg.deploy([1u8; 32], ANSWER_WASM.to_vec(), 0).unwrap();
        let a2 = reg.deploy([1u8; 32], ANSWER_WASM.to_vec(), 0).unwrap();
        assert_ne!(a1, a2);
        assert_eq!(a1, contract_address(&[1u8; 32], 0));
    }

    /// Writes `n` distinct storage keys in a loop: the state-bloat vector.
    fn storage_filler_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (import "host" "sstore" (func $sstore (param i64 i64)))
                 (func (export "fill") (param $n i64) (result i64)
                   (local $i i64)
                   (block $done
                     (loop $again
                       (br_if $done (i64.ge_s (local.get $i) (local.get $n)))
                       (call $sstore (local.get $i) (local.get $i))
                       (local.set $i (i64.add (local.get $i) (i64.const 1)))
                       (br $again)))
                   (i64.const 0)))"#,
        )
        .unwrap()
    }

    /// Emits `n` events in a loop.
    fn event_filler_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (import "host" "emit" (func $emit (param i64 i64)))
                 (func (export "fill") (param $n i64) (result i64)
                   (local $i i64)
                   (block $done
                     (loop $again
                       (br_if $done (i64.ge_s (local.get $i) (local.get $n)))
                       (call $emit (local.get $i) (local.get $i))
                       (local.set $i (i64.add (local.get $i) (i64.const 1)))
                       (br $again)))
                   (i64.const 0)))"#,
        )
        .unwrap()
    }

    #[test]
    fn storage_growth_is_capped() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], storage_filler_wasm(), 0).unwrap();

        // Filling exactly to the cap is allowed.
        let (out, ..) = reg
            .call(&addr, "fill", MAX_CONTRACT_STORAGE_KEYS as i64, 10_000_000)
            .unwrap();
        assert_eq!(out, 0);
        assert_eq!(
            reg.get(&addr).unwrap().storage.len(),
            MAX_CONTRACT_STORAGE_KEYS
        );

        // One more *new* key must trap instead of silently growing consensus state.
        let err = reg
            .call(
                &addr,
                "fill",
                (MAX_CONTRACT_STORAGE_KEYS + 1) as i64,
                10_000_000,
            )
            .unwrap_err();
        assert!(
            matches!(err, ContractError::Trapped),
            "expected trap, got {err:?}"
        );
        assert_eq!(
            reg.get(&addr).unwrap().storage.len(),
            MAX_CONTRACT_STORAGE_KEYS,
            "a trapped call must not leave a partial write behind"
        );
    }

    #[test]
    fn overwriting_existing_slots_is_never_capped() {
        let mut reg = ContractRegistry::new();
        let code = wat::parse_str(
            r#"(module
                 (import "host" "sstore" (func $sstore (param i64 i64)))
                 (func (export "set") (param $v i64) (result i64)
                   (call $sstore (i64.const 7) (local.get $v))
                   (i64.const 1)))"#,
        )
        .unwrap();
        let addr = reg.deploy([1u8; 32], code, 0).unwrap();
        for _ in 0..(MAX_CONTRACT_STORAGE_KEYS * 2) {
            reg.call(&addr, "set", 9, 1_000_000).unwrap();
        }
        assert_eq!(
            reg.get(&addr).unwrap().storage.len(),
            1,
            "rewriting key 7 must not add slots"
        );
    }

    #[test]
    fn event_emission_is_capped() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], event_filler_wasm(), 0).unwrap();
        let (_, _, events, ..) = reg
            .call(&addr, "fill", MAX_CONTRACT_EVENTS as i64, 10_000_000)
            .unwrap();
        assert_eq!(events.len(), MAX_CONTRACT_EVENTS);
        assert!(events.iter().all(|e| e.contract == addr));

        let err = reg
            .call(&addr, "fill", (MAX_CONTRACT_EVENTS + 1) as i64, 10_000_000)
            .unwrap_err();
        assert!(
            matches!(err, ContractError::Trapped),
            "expected trap, got {err:?}"
        );
    }

    #[test]
    fn host_operations_are_fuel_metered() {
        // A loop of host writes must run out of fuel long before it can write
        // an unbounded number of slots, even with a huge declared budget.
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], storage_filler_wasm(), 0).unwrap();
        let err = reg.call(&addr, "fill", 1_000_000, 5_000).unwrap_err();
        assert!(
            matches!(err, ContractError::OutOfFuel),
            "expected out of fuel, got {err:?}"
        );
        assert!(
            reg.get(&addr).unwrap().storage.is_empty(),
            "a fuel-starved call must not persist writes"
        );
    }

    #[test]
    fn deep_loops_cannot_overflow_the_native_stack() {
        // Regression: wasmi's default dispatch backend relies on the compiler
        // emitting tail calls. Without them (debug builds, or targets without
        // guaranteed TCO) every wasm back-edge recursed in Rust and a contract
        // loop aborted the whole node process with a stack overflow — a remote
        // kill of every validator. `portable-dispatch` in Cargo.toml forces the
        // bounded loop backend; this test fails loudly if that is ever dropped.
        //
        // It runs on a deliberately small 1 MiB stack, the size a tokio worker
        // task gets, which is where consensus actually executes contracts.
        let handle = std::thread::Builder::new()
            .stack_size(1024 * 1024)
            .spawn(|| {
                let mut reg = ContractRegistry::new();
                let addr = reg.deploy([1u8; 32], storage_filler_wasm(), 0).unwrap();
                // Far past the point where the recursive backend died.
                let outcome = reg.call(&addr, "fill", 300_000, 50_000_000);
                // Either it ran out of fuel or hit the storage cap; what matters
                // is that we got a value back instead of aborting the process.
                assert!(outcome.is_ok() || outcome.is_err());
            })
            .expect("spawn contract thread");
        handle
            .join()
            .expect("contract execution must not abort the process");
    }

    /// WASM module that writes a recipient address and payload into memory,
    /// then calls host.send_message.
    fn send_message_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (import "host" "send_message" (func $send_message
                   (param i64 i64 i64 i64 i64 i64) (result i64)))
                 (memory (export "memory") 1)
                 (func (export "init_and_send") (param $val i64) (result i64)
                   ;; Write 32 bytes of recipient address at offset 0
                   (i64.store (i32.const 0) (i64.const 0x0102030405060708))
                   (i64.store (i32.const 8) (i64.const 0x090a0b0c0d0e0f10))
                   (i64.store (i32.const 16) (i64.const 0x1112131415161718))
                   (i64.store (i32.const 24) (i64.const 0x191a1b1c1d1e1f20))

                   ;; Write 4 bytes payload "PING" at offset 64
                   (i32.store (i32.const 64) (i32.const 0x474e4950))

                   ;; Call send_message(recipient_ptr=0, recipient_len=32, value_nano=$val, payload_ptr=64, payload_len=4, bounce=1)
                   (call $send_message
                     (i64.const 0)
                     (i64.const 32)
                     (local.get $val)
                     (i64.const 64)
                     (i64.const 4)
                     (i64.const 1))))"#,
        )
        .unwrap()
    }

    #[test]
    fn contract_send_message_works_and_deducts_balance() {
        let mut reg = ContractRegistry::new();
        let creator = [5u8; 32];
        let code = send_message_wasm();
        let addr = reg.deploy_with_balance(creator, code, 0, 500_000).unwrap();
        assert_eq!(reg.get_balance(&addr), 500_000);

        // Call method with value = 200_000
        let (msg_id, used, events, msgs) =
            reg.call(&addr, "init_and_send", 200_000, 100_000).unwrap();
        assert_eq!(msg_id, 1, "first message id must be 1");
        assert!(used > 0);
        assert_eq!(events.len(), 0);
        assert_eq!(msgs.len(), 1, "must produce 1 outbound message");

        let msg = &msgs[0];
        assert_eq!(msg.sender, addr);
        assert_eq!(msg.value, 200_000);
        assert!(msg.bounce);
        assert_eq!(msg.payload, b"PING".to_vec());
        assert_eq!(msg.recipient[0..8], 0x0102030405060708u64.to_le_bytes());

        // Contract balance must be debited by 200_000: 500_000 - 200_000 = 300_000
        assert_eq!(reg.get_balance(&addr), 300_000);
    }

    #[test]
    fn contract_send_message_rejects_insufficient_balance() {
        let mut reg = ContractRegistry::new();
        let creator = [5u8; 32];
        let code = send_message_wasm();
        let addr = reg.deploy_with_balance(creator, code, 0, 100_000).unwrap();

        // Call method requesting 200_000 value with only 100_000 balance
        let (res, _, _, msgs) = reg.call(&addr, "init_and_send", 200_000, 100_000).unwrap();
        assert_eq!(res, -2, "insufficient balance must return error code -2");
        assert_eq!(msgs.len(), 0, "no message should be queued on error");
        assert_eq!(reg.get_balance(&addr), 100_000, "balance must be unchanged");
    }

    #[tokio::test]
    async fn test_contract_send_message_routes_to_local_actor_inbox() {
        use crate::state_engine::{AccountState, InMemoryStateEngine};
        let engine = InMemoryStateEngine::new();
        let creator = [0x11u8; 32];
        let code = send_message_wasm();
        let contract_addr = engine.deploy_contract(creator, code, 0).await.unwrap();

        // Give the contract a balance
        engine
            .update_account(AccountState::new(contract_addr, 1_000_000))
            .await;

        // Recipient address matching the one written by send_message_wasm:
        let mut recipient = [0u8; 32];
        recipient[0..8].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        recipient[8..16].copy_from_slice(&0x090a0b0c0d0e0f10u64.to_le_bytes());
        recipient[16..24].copy_from_slice(&0x1112131415161718u64.to_le_bytes());
        recipient[24..32].copy_from_slice(&0x191a1b1c1d1e1f20u64.to_le_bytes());

        // Initialize recipient account with 0 balance
        engine.update_account(AccountState::new(recipient, 0)).await;

        // Call the contract to send 250_000 nano-STELL
        let (val, _) = engine
            .call_contract(&contract_addr, "init_and_send", 250_000, 100_000)
            .await
            .unwrap();
        assert_eq!(val, 1, "send_message must return message id 1");

        // Verify recipient's inbox received the message
        let rec_acc = engine.get_account(&recipient).await.unwrap();
        assert_eq!(
            rec_acc.inbox.len(),
            1,
            "recipient inbox must have 1 message"
        );
        let msg = &rec_acc.inbox[0];
        assert_eq!(msg.sender, contract_addr);
        assert_eq!(msg.recipient, recipient);
        assert_eq!(msg.value, 250_000);
        assert_eq!(msg.body, b"PING");
        assert!(msg.bounce);
        assert!(!msg.bounced);

        // Contract balance in accounts must be debited: 1_000_000 - 250_000 = 750_000
        let c_acc = engine.get_account(&contract_addr).await.unwrap();
        assert_eq!(c_acc.balance, 750_000);
    }

    #[tokio::test]
    async fn test_contract_send_message_routes_to_cross_shard_out() {
        use crate::state_engine::{AccountState, InMemoryStateEngine};
        let engine = InMemoryStateEngine::new();
        engine.enable_cross_shard();
        // Set engine local shard to 0 (masterchain)
        engine.set_shard_id(0);

        let creator = [0x22u8; 32];
        let code = send_message_wasm();
        let contract_addr = engine.deploy_contract(creator, code, 0).await.unwrap();
        engine
            .update_account(AccountState::new(contract_addr, 1_000_000))
            .await;

        // Recipient address routes to shard 1 (workchain)
        let mut recipient = [0u8; 32];
        recipient[0..8].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        recipient[8..16].copy_from_slice(&0x090a0b0c0d0e0f10u64.to_le_bytes());
        recipient[16..24].copy_from_slice(&0x1112131415161718u64.to_le_bytes());
        recipient[24..32].copy_from_slice(&0x191a1b1c1d1e1f20u64.to_le_bytes());

        // Call the contract to send 350_000 nano-STELL
        let (val, _) = engine
            .call_contract(&contract_addr, "init_and_send", 350_000, 100_000)
            .await
            .unwrap();
        assert_eq!(val, 1, "send_message must return message id 1");

        // Verify message was routed to cross_shard_out
        let xout = engine.get_cross_shard_out().await;
        assert_eq!(xout.len(), 1, "must route 1 message to cross_shard_out");
        let xmsg = &xout[0];
        assert_eq!(xmsg.source_shard, 0);
        assert_eq!(xmsg.target_shard, 1);
        assert_eq!(xmsg.tx.from, contract_addr);
        assert_eq!(xmsg.tx.to, recipient);
        assert_eq!(xmsg.tx.amount, 350_000);
        assert!(xmsg.bounce);
        assert!(!xmsg.bounced);
    }

    #[test]
    fn contract_code_size_cap_enforced() {
        assert_eq!(MAX_CONTRACT_CODE_SIZE, 2 * 1024 * 1024);
        assert_eq!(MAX_CONTRACT_CODE, MAX_CONTRACT_CODE_SIZE);

        // Code exceeding MAX_CONTRACT_CODE_SIZE must be rejected immediately with CodeTooLarge
        let oversized = vec![0u8; MAX_CONTRACT_CODE_SIZE + 1];
        assert_eq!(
            ContractRegistry::validate_code(&oversized),
            Err(ContractError::CodeTooLarge)
        );

        // Code up to 2 MiB: construct a valid WASM binary with a custom section padding it out to ~1.5 MiB
        let base_wasm = ANSWER_WASM.to_vec();
        let custom_name = b"pad";
        let target_payload_len = 1_500_000;
        let mut padded_wasm = base_wasm.clone();
        padded_wasm.push(0x00); // custom section id
        let payload_len = 1 + custom_name.len() + target_payload_len;
        let mut len_val = payload_len;
        while len_val >= 0x80 {
            padded_wasm.push((len_val as u8 & 0x7f) | 0x80);
            len_val >>= 7;
        }
        padded_wasm.push(len_val as u8);
        padded_wasm.push(custom_name.len() as u8);
        padded_wasm.extend_from_slice(custom_name);
        padded_wasm.resize(padded_wasm.len() + target_payload_len, 0);

        assert!(padded_wasm.len() > 1_500_000);
        assert!(padded_wasm.len() <= MAX_CONTRACT_CODE_SIZE);

        let mut reg = ContractRegistry::new();
        let addr = reg
            .deploy([7u8; 32], padded_wasm, 0)
            .expect("1.5 MiB contract must deploy");
        assert_eq!(reg.call(&addr, "answer", 0, 10_000).unwrap().0, 42);
    }

    #[test]
    fn wasm_memory_page_limits_validation() {
        let mut reg = ContractRegistry::new();
        let creator = [8u8; 32];

        // 1 page (64 KiB) memory declaration: succeeds
        let wasm_1p = wat::parse_str(
            r#"(module (memory 1) (func (export "f") (param i64) (result i64) local.get 0))"#,
        )
        .unwrap();
        assert!(reg.deploy(creator, wasm_1p, 0).is_ok());

        // 64 pages (4 MiB) memory declaration: succeeds
        let wasm_64p = wat::parse_str(
            r#"(module (memory 64) (func (export "f") (param i64) (result i64) local.get 0))"#,
        )
        .unwrap();
        assert!(reg.deploy(creator, wasm_64p, 0).is_ok());

        // 128 pages (8 MiB) memory declaration: succeeds
        let wasm_128p = wat::parse_str(
            r#"(module (memory 128) (func (export "f") (param i64) (result i64) local.get 0))"#,
        )
        .unwrap();
        assert!(reg.deploy(creator, wasm_128p, 0).is_ok());

        // 129 pages (> 128 pages limit) memory declaration: fails validation with InvalidWasm
        let wasm_129p = wat::parse_str(
            r#"(module (memory 129) (func (export "f") (param i64) (result i64) local.get 0))"#,
        )
        .unwrap();
        assert_eq!(
            ContractRegistry::validate_code(&wasm_129p),
            Err(ContractError::InvalidWasm)
        );

        // Memory with explicit max exceeding limit: fails validation with InvalidWasm
        let wasm_max_over = wat::parse_str(
            r#"(module (memory 1 129) (func (export "f") (param i64) (result i64) local.get 0))"#,
        )
        .unwrap();
        assert_eq!(
            ContractRegistry::validate_code(&wasm_max_over),
            Err(ContractError::InvalidWasm)
        );
    }

    #[test]
    fn deploy_gas_scales_with_bytecode_size() {
        assert_eq!(GAS_DEPLOY_BASE, 2_000);
        assert_eq!(GAS_PER_BYTE, 2);

        assert_eq!(contract_deploy_gas(0), 2_000);
        assert_eq!(contract_deploy_gas(100), 2_000 + 100 * 2);
        assert_eq!(contract_deploy_gas(1_000), 2_000 + 1_000 * 2);
        assert_eq!(
            contract_deploy_gas(MAX_CONTRACT_CODE_SIZE),
            GAS_DEPLOY_BASE + (MAX_CONTRACT_CODE_SIZE as u64) * GAS_PER_BYTE
        );
        assert_eq!(deploy_gas(500), contract_deploy_gas(500));
        assert_eq!(ContractRegistry::deploy_gas(500), deploy_gas(500));
    }

    fn escape_wat_bytes(bytes: &[u8]) -> String {
        let mut s = String::new();
        for &b in bytes {
            use std::fmt::Write;
            write!(s, "\\{:02x}", b).unwrap();
        }
        s
    }

    #[test]
    fn test_host_caller_and_bounds_checking() {
        let wasm = wat::parse_str(
            r#"(module
                 (import "host" "caller" (func $caller (param i32)))
                 (memory (export "memory") 1)
                 (func (export "read_caller") (param $ptr i64) (result i64)
                   (call $caller (i32.wrap_i64 (local.get $ptr)))
                   (i64.load (i32.wrap_i64 (local.get $ptr)))))"#,
        )
        .unwrap();

        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], wasm, 0).unwrap();

        let caller_addr = [0x42u8; 32];
        let ctx = ContractCallContext {
            caller: caller_addr,
            ..Default::default()
        };
        let outcome = reg
            .call_with_context(&addr, "read_caller", 0, 100_000, &ctx)
            .unwrap();
        let expected_word = i64::from_le_bytes(caller_addr[0..8].try_into().unwrap());
        assert_eq!(outcome.result, expected_word);

        // Bounds checks
        let oob_err = reg
            .call_with_context(&addr, "read_caller", 65530, 100_000, &ctx)
            .unwrap_err();
        assert!(matches!(oob_err, ContractError::Trapped));

        let neg_err = reg
            .call_with_context(&addr, "read_caller", -1, 100_000, &ctx)
            .unwrap_err();
        assert!(matches!(neg_err, ContractError::Trapped));

        // Fuel check
        let fuel_err = reg
            .call_with_context(&addr, "read_caller", 0, 1, &ctx)
            .unwrap_err();
        assert!(matches!(fuel_err, ContractError::OutOfFuel));
    }

    #[test]
    fn test_host_value_returns_amount() {
        let wasm = wat::parse_str(
            r#"(module
                 (import "host" "value" (func $value (result i64)))
                 (func (export "read_value") (param $dummy i64) (result i64)
                   (call $value)))"#,
        )
        .unwrap();

        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], wasm, 0).unwrap();

        let ctx = ContractCallContext {
            value: 9876543210,
            ..Default::default()
        };
        let outcome = reg
            .call_with_context(&addr, "read_value", 0, 100_000, &ctx)
            .unwrap();
        assert_eq!(outcome.result, 9876543210i64);

        let fuel_err = reg
            .call_with_context(&addr, "read_value", 0, 1, &ctx)
            .unwrap_err();
        assert!(matches!(fuel_err, ContractError::OutOfFuel));
    }

    #[test]
    fn test_host_block_time_returns_timestamp() {
        let wasm = wat::parse_str(
            r#"(module
                 (import "host" "block_time" (func $block_time (result i64)))
                 (func (export "read_block_time") (param $dummy i64) (result i64)
                   (call $block_time)))"#,
        )
        .unwrap();

        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], wasm, 0).unwrap();

        let ctx = ContractCallContext {
            block_time: 1729000000,
            ..Default::default()
        };
        let outcome = reg
            .call_with_context(&addr, "read_block_time", 0, 100_000, &ctx)
            .unwrap();
        assert_eq!(outcome.result, 1729000000i64);

        let fuel_err = reg
            .call_with_context(&addr, "read_block_time", 0, 1, &ctx)
            .unwrap_err();
        assert!(matches!(fuel_err, ContractError::OutOfFuel));
    }

    #[test]
    fn test_host_block_hash_and_bounds_checking() {
        let wasm = wat::parse_str(
            r#"(module
                 (import "host" "block_hash" (func $block_hash (param i32)))
                 (memory (export "memory") 1)
                 (func (export "read_block_hash") (param $ptr i64) (result i64)
                   (call $block_hash (i32.wrap_i64 (local.get $ptr)))
                   (i64.load (i32.wrap_i64 (local.get $ptr)))))"#,
        )
        .unwrap();

        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], wasm, 0).unwrap();

        let hash = [0x5au8; 32];
        let ctx = ContractCallContext {
            block_hash: hash,
            ..Default::default()
        };
        let outcome = reg
            .call_with_context(&addr, "read_block_hash", 0, 100_000, &ctx)
            .unwrap();
        let expected_word = i64::from_le_bytes(hash[0..8].try_into().unwrap());
        assert_eq!(outcome.result, expected_word);

        // Bounds checks
        let oob_err = reg
            .call_with_context(&addr, "read_block_hash", 65530, 100_000, &ctx)
            .unwrap_err();
        assert!(matches!(oob_err, ContractError::Trapped));

        let neg_err = reg
            .call_with_context(&addr, "read_block_hash", -5, 100_000, &ctx)
            .unwrap_err();
        assert!(matches!(neg_err, ContractError::Trapped));

        // Fuel check
        let fuel_err = reg
            .call_with_context(&addr, "read_block_hash", 0, 1, &ctx)
            .unwrap_err();
        assert!(matches!(fuel_err, ContractError::OutOfFuel));
    }

    #[test]
    fn test_host_sha256_and_bounds_and_fuel() {
        let wasm = wat::parse_str(
            r#"(module
                 (import "host" "sha256" (func $sha256 (param i32 i32 i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "hello world")
                 (func (export "compute_sha256") (param $src_len i64) (result i64)
                   (call $sha256 (i32.const 0) (i32.wrap_i64 (local.get $src_len)) (i32.const 100))
                   (i64.load (i32.const 100)))
                 (func (export "sha256_oob_dest") (param $dummy i64) (result i64)
                   (call $sha256 (i32.const 0) (i32.const 11) (i32.const 65530))
                   (i64.const 0))
                 (func (export "sha256_oob_src") (param $dummy i64) (result i64)
                   (call $sha256 (i32.const 65530) (i32.const 11) (i32.const 100))
                   (i64.const 0)))"#,
        )
        .unwrap();

        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], wasm, 0).unwrap();

        let expected = Sha256::digest(b"hello world");
        let expected_first_word = i64::from_le_bytes(expected[0..8].try_into().unwrap());
        let res = reg.call(&addr, "compute_sha256", 11, 100_000).unwrap();
        assert_eq!(res.0, expected_first_word);

        // Empty input buffer
        let empty_expected = Sha256::digest(b"");
        let empty_first_word = i64::from_le_bytes(empty_expected[0..8].try_into().unwrap());
        let res_empty = reg.call(&addr, "compute_sha256", 0, 100_000).unwrap();
        assert_eq!(res_empty.0, empty_first_word);

        // Bounds checking
        let oob_dest = reg.call(&addr, "sha256_oob_dest", 0, 100_000).unwrap_err();
        assert!(matches!(oob_dest, ContractError::Trapped));

        let oob_src = reg.call(&addr, "sha256_oob_src", 0, 100_000).unwrap_err();
        assert!(matches!(oob_src, ContractError::Trapped));

        // Fuel metering
        let fuel_err = reg.call(&addr, "compute_sha256", 11, 1).unwrap_err();
        assert!(matches!(fuel_err, ContractError::OutOfFuel));
    }

    #[test]
    fn test_host_blake3_and_bounds_and_fuel() {
        let wasm = wat::parse_str(
            r#"(module
                 (import "host" "blake3" (func $blake3 (param i32 i32 i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "stellereum blake3")
                 (func (export "compute_blake3") (param $src_len i64) (result i64)
                   (call $blake3 (i32.const 0) (i32.wrap_i64 (local.get $src_len)) (i32.const 100))
                   (i64.load (i32.const 100)))
                 (func (export "blake3_oob_dest") (param $dummy i64) (result i64)
                   (call $blake3 (i32.const 0) (i32.const 17) (i32.const 65530))
                   (i64.const 0))
                 (func (export "blake3_oob_src") (param $dummy i64) (result i64)
                   (call $blake3 (i32.const 65530) (i32.const 17) (i32.const 100))
                   (i64.const 0)))"#,
        )
        .unwrap();

        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], wasm, 0).unwrap();

        let expected = blake3::hash(b"stellereum blake3");
        let expected_first_word = i64::from_le_bytes(expected.as_bytes()[0..8].try_into().unwrap());
        let res = reg.call(&addr, "compute_blake3", 17, 100_000).unwrap();
        assert_eq!(res.0, expected_first_word);

        // Empty input buffer
        let empty_expected = blake3::hash(b"");
        let empty_first_word =
            i64::from_le_bytes(empty_expected.as_bytes()[0..8].try_into().unwrap());
        let res_empty = reg.call(&addr, "compute_blake3", 0, 100_000).unwrap();
        assert_eq!(res_empty.0, empty_first_word);

        // Bounds checking
        let oob_dest = reg.call(&addr, "blake3_oob_dest", 0, 100_000).unwrap_err();
        assert!(matches!(oob_dest, ContractError::Trapped));

        let oob_src = reg.call(&addr, "blake3_oob_src", 0, 100_000).unwrap_err();
        assert!(matches!(oob_src, ContractError::Trapped));

        // Fuel metering
        let fuel_err = reg.call(&addr, "compute_blake3", 17, 1).unwrap_err();
        assert!(matches!(fuel_err, ContractError::OutOfFuel));
    }

    #[test]
    fn test_host_ed25519_verify_valid_and_invalid() {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();
        let msg = b"contract payload verification";
        let sig = sk.sign(msg).to_bytes();

        let wat_src = format!(
            r#"(module
                 (import "host" "ed25519_verify" (func $ed25519_verify (param i32 i32 i32 i32) (result i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "{}")
                 (data (i32.const 32) "{}")
                 (data (i32.const 64) "{}")
                 (func (export "verify_sig") (param $corrupt i64) (result i64)
                   (if (i64.ne (local.get $corrupt) (i64.const 0))
                     (then
                       (i32.store8 (i32.const 64) (i32.xor (i32.load8_u (i32.const 64)) (i32.const 0xff)))))
                   (i64.extend_i32_u
                     (call $ed25519_verify (i32.const 0) (i32.const 32) (i32.const {}) (i32.const 64))))
                 (func (export "verify_oob") (param $dummy i64) (result i64)
                   (i64.extend_i32_u
                     (call $ed25519_verify (i32.const 0) (i32.const 32) (i32.const 4) (i32.const 70000)))))"#,
            escape_wat_bytes(&pk),
            escape_wat_bytes(msg),
            escape_wat_bytes(&sig),
            msg.len()
        );

        let wasm = wat::parse_str(&wat_src).unwrap();
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], wasm, 0).unwrap();

        // FULL-PQ: even a VALID classical signature is refused (0).
        // Valid signature -> returns 0 (classical host removed)
        let (valid_res, ..) = reg.call(&addr, "verify_sig", 0, 100_000).unwrap();
        assert_eq!(valid_res, 0);

        // Corrupted signature -> returns 0
        let (corrupt_res, ..) = reg.call(&addr, "verify_sig", 1, 100_000).unwrap();
        assert_eq!(corrupt_res, 0);

        // Out-of-bounds pointer -> traps
        let oob_err = reg.call(&addr, "verify_oob", 0, 100_000).unwrap_err();
        assert!(matches!(oob_err, ContractError::Trapped));

        // Fuel check
        let fuel_err = reg.call(&addr, "verify_sig", 0, 10).unwrap_err();
        assert!(matches!(fuel_err, ContractError::OutOfFuel));
    }

    /// FULL-PQ: classical `ed25519_verify` host is REMOVED — a VALID ed25519
    /// signature is always refused (0). Fuel/memory effects still apply.
    #[test]
    fn test_host_ed25519_verify_refused_under_pure_pq() {
        use ed25519_dalek::Signer;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let pk = sk.verifying_key().to_bytes();
        let msg = b"contract pq gate pin";
        let sig = sk.sign(msg).to_bytes();

        let wat_src = format!(
            r#"(module
                 (import "host" "ed25519_verify" (func $ed25519_verify (param i32 i32 i32 i32) (result i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "{}")
                 (data (i32.const 32) "{}")
                 (data (i32.const 64) "{}")
                 (func (export "verify_sig") (param $dummy i64) (result i64)
                   (i64.extend_i32_u
                     (call $ed25519_verify (i32.const 0) (i32.const 32) (i32.const {}) (i32.const 64)))))"#,
            escape_wat_bytes(&pk),
            escape_wat_bytes(msg),
            escape_wat_bytes(&sig),
            msg.len()
        );
        let wasm = wat::parse_str(&wat_src).unwrap();

        // FULL-PQ always-on: the SAME valid sig is refused (fail-closed 0).
        {
            crate::post_quantum::set_pure_pq_override(Some(true));
            let mut reg = ContractRegistry::new();
            let addr = reg.deploy([3u8; 32], wasm.clone(), 0).unwrap();
            let (res, ..) = reg.call(&addr, "verify_sig", 0, 100_000).unwrap();
            assert_eq!(res, 0, "valid ed sig must be refused under FULL-PQ");
        }
        // Still refused without the override (always-on).
        {
            let mut reg = ContractRegistry::new();
            let addr = reg.deploy([3u8; 32], wasm, 0).unwrap();
            let (res, ..) = reg.call(&addr, "verify_sig", 0, 100_000).unwrap();
            assert_eq!(res, 0, "FULL-PQ always-on: valid ed sig refused");
        }
    }

    #[test]
    fn test_host_return_data_and_bounds_checking() {
        let wasm = wat::parse_str(
            r#"(module
                 (import "host" "return_data" (func $return_data (param i32 i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 10) "STELL_RETURN_BYTES")
                 (func (export "set_ret") (param $len i64) (result i64)
                   (call $return_data (i32.const 10) (i32.wrap_i64 (local.get $len)))
                   (i64.const 42))
                 (func (export "set_ret_oob") (param $dummy i64) (result i64)
                   (call $return_data (i32.const 65530) (i32.const 20))
                   (i64.const 0)))"#,
        )
        .unwrap();

        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], wasm, 0).unwrap();

        let outcome = reg
            .call_with_context(
                &addr,
                "set_ret",
                18,
                100_000,
                &ContractCallContext::default(),
            )
            .unwrap();
        assert_eq!(outcome.result, 42);
        assert_eq!(outcome.return_data, b"STELL_RETURN_BYTES");
        assert_eq!(reg.last_return_data, b"STELL_RETURN_BYTES");

        // Bounds check (pointer out of bounds)
        let oob_err = reg.call(&addr, "set_ret_oob", 0, 100_000).unwrap_err();
        assert!(matches!(oob_err, ContractError::Trapped));

        // Length limit (> MAX_RETURN_DATA)
        let limit_err = reg.call(&addr, "set_ret", 100_000, 100_000).unwrap_err();
        assert!(matches!(limit_err, ContractError::Trapped));

        // Fuel check
        let fuel_err = reg.call(&addr, "set_ret", 18, 1).unwrap_err();
        assert!(matches!(fuel_err, ContractError::OutOfFuel));
    }

    #[test]
    fn test_contract_imports_all_new_host_functions() {
        let wasm = wat::parse_str(
            r#"(module
                 (import "host" "sload" (func $sload (param i64) (result i64)))
                 (import "host" "sstore" (func $sstore (param i64 i64)))
                 (import "host" "emit" (func $emit (param i64 i64)))
                 (import "host" "send_message" (func $send_message (param i64 i64 i64 i64 i64 i64) (result i64)))
                 (import "host" "caller" (func $caller (param i32)))
                 (import "host" "value" (func $value (result i64)))
                 (import "host" "block_time" (func $block_time (result i64)))
                 (import "host" "block_hash" (func $block_hash (param i32)))
                 (import "host" "sha256" (func $sha256 (param i32 i32 i32)))
                 (import "host" "blake3" (func $blake3 (param i32 i32 i32)))
                 (import "host" "ed25519_verify" (func $ed25519_verify (param i32 i32 i32 i32) (result i32)))
                 (import "host" "return_data" (func $return_data (param i32 i32)))
                 (memory (export "memory") 1)
                 (func (export "run_all") (param $arg i64) (result i64)
                   (call $sstore (i64.const 1) (local.get $arg))
                   (call $emit (i64.const 2) (call $sload (i64.const 1)))
                   (call $caller (i32.const 0))
                   (call $block_hash (i32.const 32))
                   (call $sha256 (i32.const 0) (i32.const 32) (i32.const 64))
                   (call $blake3 (i32.const 0) (i32.const 32) (i32.const 96))
                   (call $return_data (i32.const 64) (i32.const 32))
                   (drop (call $value))
                   (drop (call $block_time))
                   (drop (call $ed25519_verify (i32.const 0) (i32.const 32) (i32.const 10) (i32.const 64)))
                   (i64.const 123)))"#,
        )
        .unwrap();

        assert!(ContractRegistry::validate_code(&wasm).is_ok());
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([9u8; 32], wasm, 0).unwrap();
        let (res, ..) = reg.call(&addr, "run_all", 777, 100_000).unwrap();
        assert_eq!(res, 123);
        assert_eq!(reg.last_return_data.len(), 32);
    }

    // -----------------------------------------------------------------
    // Multi-argument methods and the ABI manifest
    // -----------------------------------------------------------------

    /// A contract exporting methods with 0, 1, 2, 3 and 4 parameters.
    ///
    /// * `zero()`      -> 7
    /// * `one(a)`     -> a + 1
    /// * `two(a, b)`  -> a * 10 + b
    /// * `three(a,b,c)` -> a + b + c
    /// * `four(a,b,c,d)` -> a + b + c + d
    fn multi_arg_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                 (func (export "zero") (result i64)
                   (i64.const 7))
                 (func (export "one") (param $a i64) (result i64)
                   (i64.add (local.get $a) (i64.const 1)))
                 (func (export "two") (param $a i64) (param $b i64) (result i64)
                   (i64.add (i64.mul (local.get $a) (i64.const 10)) (local.get $b)))
                 (func (export "three") (param $a i64) (param $b i64) (param $c i64) (result i64)
                   (i64.add (i64.add (local.get $a) (local.get $b)) (local.get $c)))
                 (func (export "four") (param $a i64) (param $b i64) (param $c i64) (param $d i64) (result i64)
                   (i64.add (i64.add (i64.add (local.get $a) (local.get $b)) (local.get $c)) (local.get $d))))"#,
        )
        .unwrap()
    }

    #[test]
    fn multi_argument_methods_are_callable() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], multi_arg_wasm(), 0).unwrap();

        // 0 arguments
        let (v, ..) = reg.call_args(&addr, "zero", &[], 100_000).unwrap();
        assert_eq!(v, 7);

        // 1 argument
        let (v, ..) = reg.call_args(&addr, "one", &[41], 100_000).unwrap();
        assert_eq!(v, 42);

        // 2 arguments
        let (v, ..) = reg.call_args(&addr, "two", &[4, 2], 100_000).unwrap();
        assert_eq!(v, 42);

        // 3 arguments
        let (v, ..) = reg
            .call_args(&addr, "three", &[10, 20, 12], 100_000)
            .unwrap();
        assert_eq!(v, 42);

        // 4 arguments
        let (v, ..) = reg
            .call_args(&addr, "four", &[1, 2, 3, 36], 100_000)
            .unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn multi_argument_dispatch_is_strict_about_arity() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], multi_arg_wasm(), 0).unwrap();

        // A two-parameter method must not be reachable with one argument:
        // dropping an argument could move the wrong amount of value.
        assert_eq!(
            reg.call_args(&addr, "two", &[4], 100_000),
            Err(ContractError::NoSuchMethod)
        );
        assert_eq!(
            reg.call_args(&addr, "two", &[4, 2, 9], 100_000),
            Err(ContractError::NoSuchMethod)
        );
        assert_eq!(
            reg.call_args(&addr, "nope", &[1], 100_000),
            Err(ContractError::NoSuchMethod)
        );
    }

    #[test]
    fn multi_argument_getter_executes_read_only() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], multi_arg_wasm(), 0).unwrap();

        let resp = reg.run_get_method(&addr, "two", &[4, 2], None);
        assert!(resp.success);
        assert_eq!(resp.return_value, Some(42));

        let resp = reg.run_get_method(&addr, "three", &[10, 20, 12], None);
        assert!(resp.success);
        assert_eq!(resp.return_value, Some(42));
    }

    #[test]
    fn abi_manifest_can_be_attached_and_is_validated() {
        use crate::contract_abi::{AbiMethod, AbiParam, AbiType, AbiValue, ContractAbi};

        let abi = ContractAbi {
            methods: vec![
                AbiMethod::view(
                    "two",
                    vec![
                        AbiParam::new("a", AbiType::I64),
                        AbiParam::new("b", AbiType::I64),
                    ],
                    AbiType::I64,
                ),
                AbiMethod::mutating(
                    "three",
                    vec![
                        AbiParam::new("a", AbiType::I64),
                        AbiParam::new("b", AbiType::I64),
                        AbiParam::new("c", AbiType::I64),
                    ],
                    AbiType::I64,
                ),
            ],
            events: vec![],
        };

        let mut reg = ContractRegistry::new();
        let addr = reg
            .deploy_with_abi([1u8; 32], multi_arg_wasm(), 0, abi.clone())
            .unwrap();

        // The manifest travels with the contract.
        let stored = reg.abi(&addr).unwrap().clone();
        assert_eq!(stored.methods.len(), 2);
        assert_eq!(stored.method("two").unwrap().params.len(), 2);
        assert_eq!(reg.abi_json(&addr).unwrap(), abi.to_json());

        // A typed call runs the contract and decodes the typed return.
        let outcome = reg
            .call_abi(&addr, "two", &[AbiValue::I64(4), AbiValue::I64(2)], 100_000)
            .unwrap();
        assert_eq!(outcome.result, 42);
        let typed = outcome.typed_return(&stored, "two").unwrap();
        assert_eq!(typed, AbiValue::I64(42));

        let outcome = reg
            .call_abi(
                &addr,
                "three",
                &[AbiValue::I64(10), AbiValue::I64(20), AbiValue::I64(12)],
                100_000,
            )
            .unwrap();
        assert_eq!(outcome.result, 42);

        // A call that does not match the manifest is rejected before it
        // touches consensus state.
        let err = reg
            .call_abi(&addr, "two", &[AbiValue::I64(4)], 100_000)
            .unwrap_err();
        assert!(matches!(err, ContractError::AbiMismatch(_)));

        let err = reg.call_abi(&addr, "nope", &[], 100_000).unwrap_err();
        assert!(matches!(err, ContractError::AbiMismatch(_)));
    }

    #[test]
    fn abi_typed_getter_returns_a_typed_value() {
        use crate::contract_abi::{AbiMethod, AbiParam, AbiType, AbiValue, ContractAbi};

        let abi = ContractAbi {
            methods: vec![AbiMethod::view(
                "two",
                vec![
                    AbiParam::new("a", AbiType::I64),
                    AbiParam::new("b", AbiType::I64),
                ],
                AbiType::U64,
            )],
            events: vec![],
        };
        let mut reg = ContractRegistry::new();
        let addr = reg
            .deploy_with_abi([1u8; 32], multi_arg_wasm(), 0, abi)
            .unwrap();

        let resp =
            reg.run_get_method_typed(&addr, "two", &[AbiValue::I64(4), AbiValue::I64(2)], None);
        assert!(resp.success);
        assert_eq!(resp.return_value, Some(42));
        assert_eq!(resp.return_typed, Some(AbiValue::U64(42)));

        // Wrong arity -> the manifest rejects the call.
        let resp = reg.run_get_method_typed(&addr, "two", &[AbiValue::I64(4)], None);
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("ABI validation failed"));
    }

    #[test]
    fn abi_calldata_is_readable_by_the_contract() {
        use crate::contract_abi::{AbiMethod, AbiParam, AbiType, AbiValue, ContractAbi};

        // The contract reads the ABI-encoded arguments from its memory
        // through `host.calldata` and returns the number of bytes it got.
        let wasm = wat::parse_str(
            r#"(module
                 (import "host" "calldata" (func $calldata (param i32) (result i64)))
                 (memory (export "memory") 1)
                 (func (export "read_calldata") (param $a i64) (result i64)
                   (call $calldata (i32.const 0))))"#,
        )
        .unwrap();

        let abi = ContractAbi {
            methods: vec![AbiMethod::view(
                "read_calldata",
                vec![AbiParam::new("a", AbiType::I64)],
                AbiType::I64,
            )],
            events: vec![],
        };
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy_with_abi([1u8; 32], wasm, 0, abi).unwrap();

        let outcome = reg
            .call_abi(&addr, "read_calldata", &[AbiValue::I64(7)], 100_000)
            .unwrap();
        // u32_le(count=1) + tag + 8 bytes = 13 bytes
        assert_eq!(outcome.result, 13);
    }
}
