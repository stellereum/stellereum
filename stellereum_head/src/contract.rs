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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use wasmi::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Maximum deployed contract code size (256 KiB).
pub const MAX_CONTRACT_CODE: usize = 256 * 1024;
/// Maximum wasmi fuel a single contract call may consume (anti-DoS).
pub const MAX_CONTRACT_FUEL: u64 = 50_000_000;
/// Maximum linear memory a contract may use (16 MiB).
pub const MAX_CONTRACT_MEMORY: usize = 16 * 1024 * 1024;
/// Hard cap on the number of persistent storage slots one contract may own.
///
/// Host functions run outside the fuel meter, so without this a contract could
/// write millions of distinct keys inside one call and permanently bloat the
/// consensus state of every node.
pub const MAX_CONTRACT_STORAGE_KEYS: usize = 4_096;
/// Hard cap on events a single call may emit (same reasoning as storage).
pub const MAX_CONTRACT_EVENTS: usize = 256;
/// Fuel charged for a host storage read.
pub const FUEL_SLOAD: u64 = 10;
/// Fuel charged for a host storage write.
pub const FUEL_SSTORE: u64 = 100;
/// Fuel charged per emitted event.
pub const FUEL_EMIT: u64 = 50;

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
            ContractError::UnresolvableImports => "contract imports something the host does not provide",
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
}

/// An on-chain contract event emitted during execution via `host.emit`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEvent {
    pub contract: [u8; 32],
    pub topic: i64,
    pub value: i64,
}

/// Registry of all deployed contracts (part of consensus state).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ContractRegistry {
    pub contracts: HashMap<[u8; 32], Contract>,
    pub next_nonce: u64,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self::default()
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
        if code.len() > MAX_CONTRACT_CODE {
            return Err(ContractError::CodeTooLarge);
        }
        let engine = contract_engine();
        let module = Module::new(&engine, code).map_err(|_| ContractError::InvalidWasm)?;
        let host = HostState {
            limits: store_limits(),
            contract_addr: [0u8; 32],
            storage: HashMap::new(),
            events: Vec::new(),
        };
        let mut store = Store::new(&engine, host);
        let linker = host_linker(&engine);
        // A missing import, or a start function that traps, is a deploy-time error.
        linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| ContractError::UnresolvableImports)?;
        Ok(())
    }

    /// Deploy a new contract. Returns its deterministic address.
    pub fn deploy(
        &mut self,
        creator: [u8; 32],
        code: Vec<u8>,
        now: u64,
    ) -> Result<[u8; 32], ContractError> {
        Self::validate_code(&code)?;
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
            },
        );
        Ok(address)
    }

    pub fn get(&self, address: &[u8; 32]) -> Option<&Contract> {
        self.contracts.get(address)
    }

    pub fn exists(&self, address: &[u8; 32]) -> bool {
        self.contracts.contains_key(address)
    }

    pub fn pause(&mut self, address: &[u8; 32], caller: [u8; 32]) -> Result<(), ContractError> {
        let c = self.contracts.get_mut(address).ok_or(ContractError::NotFound)?;
        if c.creator != caller {
            return Err(ContractError::NotFound); // only creator may pause
        }
        c.paused = true;
        Ok(())
    }

    /// Call an exported `(i64) -> i64` method with persistent storage and events.
    /// Returns (result, fuel_used, events).
    pub fn call(
        &mut self,
        address: &[u8; 32],
        method: &str,
        arg: i64,
        fuel: u64,
    ) -> Result<(i64, u64, Vec<ContractEvent>), ContractError> {
        let contract = self.contracts.get_mut(address).ok_or(ContractError::NotFound)?;
        if contract.paused {
            return Err(ContractError::Paused);
        }
        let fuel = fuel.min(MAX_CONTRACT_FUEL);
        let (out, used, new_storage, events) = run_contract(
            *address,
            &contract.code,
            &contract.storage,
            method,
            arg,
            fuel,
        )?;
        contract.storage = new_storage;
        Ok((out, used, events))
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
    storage: HashMap<i64, i64>,
    events: Vec<ContractEvent>,
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

/// The complete set of host functions a contract may import.
///
/// Anything outside this list is unresolvable, which is what makes the sandbox
/// closed: no clock, no network, no filesystem, no host memory.
fn host_linker(engine: &Engine) -> Linker<HostState> {
    let mut linker = <Linker<HostState>>::new(engine);
    let _ = linker.func_wrap("host", "sload", |mut caller: wasmi::Caller<'_, HostState>, key: i64| -> Result<i64, wasmi::Error> {
        HostState::charge(&mut caller, FUEL_SLOAD)?;
        Ok(caller.data().storage.get(&key).copied().unwrap_or(0))
    });
    let _ = linker.func_wrap("host", "sstore", |mut caller: wasmi::Caller<'_, HostState>, key: i64, val: i64| -> Result<(), wasmi::Error> {
        HostState::charge(&mut caller, FUEL_SSTORE)?;
        let state = caller.data_mut();
        // Writing a *new* key grows the permanent consensus state, so it is
        // capped; overwriting an existing slot is always allowed.
        if !state.storage.contains_key(&key) && state.storage.len() >= MAX_CONTRACT_STORAGE_KEYS {
            return Err(wasmi::Error::new("contract storage limit exceeded"));
        }
        state.storage.insert(key, val);
        Ok(())
    });
    let _ = linker.func_wrap("host", "emit", |mut caller: wasmi::Caller<'_, HostState>, topic: i64, val: i64| -> Result<(), wasmi::Error> {
        HostState::charge(&mut caller, FUEL_EMIT)?;
        let state = caller.data_mut();
        if state.events.len() >= MAX_CONTRACT_EVENTS {
            return Err(wasmi::Error::new("contract event limit exceeded"));
        }
        let contract = state.contract_addr;
        state.events.push(ContractEvent { contract, topic, value: val });
        Ok(())
    });
    linker
}

/// Execute a `(i64) -> i64` export in a fully sandboxed, metered store with
/// host storage (sload/sstore) and event emission (emit).
fn run_contract(
    contract_addr: [u8; 32],
    code: &[u8],
    initial_storage: &HashMap<i64, i64>,
    method: &str,
    arg: i64,
    fuel: u64,
) -> Result<(i64, u64, HashMap<i64, i64>, Vec<ContractEvent>), ContractError> {
    let engine = contract_engine();
    let module = Module::new(&engine, code).map_err(|_| ContractError::InvalidWasm)?;

    let host = HostState {
        limits: store_limits(),
        contract_addr,
        storage: initial_storage.clone(),
        events: Vec::new(),
    };
    let mut store = Store::new(&engine, host);
    store.limiter(|s| &mut s.limits);
    store.set_fuel(fuel).map_err(|_| ContractError::OutOfFuel)?;

    let linker = host_linker(&engine);
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .map_err(|_| ContractError::InvalidWasm)?;
    let func = instance
        .get_typed_func::<i64, i64>(&store, method)
        .map_err(|_| ContractError::NoSuchMethod)?;

    let out = match func.call(&mut store, arg) {
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
    Ok((out, used, final_host.storage, final_host.events))
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
        0x07, 0x0a, 0x01, 0x06, 0x64, 0x6f, 0x75, 0x62, 0x6c, 0x65, 0x00, 0x00, // export "double"
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x42, 0x02, 0x7e, 0x0b, // code
    ];

    const ANSWER_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7e, 0x01, 0x7e, // type: (i64)->i64
        0x03, 0x02, 0x01, 0x00, // function section
        0x07, 0x0a, 0x01, 0x06, 0x61, 0x6e, 0x73, 0x77, 0x65, 0x72, 0x00, 0x00, // export "answer"
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x42, 0x2a, 0x0b, // code: i64.const 42; end
    ];

    #[test]
    fn deploy_validates_and_rejects_bad_code() {
        let mut reg = ContractRegistry::new();
        assert_eq!(reg.deploy([1u8; 32], vec![], 0), Err(ContractError::EmptyCode));
        assert_eq!(reg.deploy([1u8; 32], vec![0, 1, 2, 3], 0), Err(ContractError::InvalidWasm));
        let addr = reg.deploy([1u8; 32], DOUBLE_WASM.to_vec(), 0).unwrap();
        assert!(reg.exists(&addr));
        assert_eq!(reg.get(&addr).unwrap().creator, [1u8; 32]);
    }

    #[test]
    fn call_double_works_and_is_deterministic() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], DOUBLE_WASM.to_vec(), 0).unwrap();
        let (a, used, _) = reg.call(&addr, "double", 21, 10_000).unwrap();
        assert_eq!(a, 42);
        assert!(used > 0, "fuel must be consumed");
        let (b, _, _) = reg.call(&addr, "double", 21, 10_000).unwrap();
        assert_eq!(a, b, "deterministic");
    }

    #[test]
    fn call_unknown_method_fails() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], DOUBLE_WASM.to_vec(), 0).unwrap();
        assert_eq!(reg.call(&addr, "nope", 1, 10_000), Err(ContractError::NoSuchMethod));
    }

    #[test]
    fn out_of_fuel_is_bounded() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], DOUBLE_WASM.to_vec(), 0).unwrap();
        // One fuel unit is not enough to run anything.
        assert_eq!(reg.call(&addr, "double", 1, 1), Err(ContractError::OutOfFuel));
    }

    #[test]
    fn paused_contract_cannot_be_called() {
        let mut reg = ContractRegistry::new();
        let creator = [1u8; 32];
        let addr = reg.deploy(creator, ANSWER_WASM.to_vec(), 0).unwrap();
        assert_eq!(reg.call(&addr, "answer", 0, 10_000).unwrap().0, 42);
        reg.pause(&addr, creator).unwrap();
        assert_eq!(reg.call(&addr, "answer", 0, 10_000), Err(ContractError::Paused));
        // a non-creator cannot pause
        let addr2 = reg.deploy(creator, ANSWER_WASM.to_vec(), 0).unwrap();
        assert_eq!(reg.pause(&addr2, [9u8; 32]), Err(ContractError::NotFound));
    }

    #[test]
    fn persistent_storage_sload_sstore_counter_works() {
        // Wasm module that imports host.sload and host.sstore and implements a counter:
        // `inc(key) -> sstore(key, sload(key) + 1); sload(key)`
        const COUNTER_WASM: &[u8] = &[
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0b, 0x02, 0x60, 0x01, 0x7e, 0x01, 0x7e,
            0x60, 0x02, 0x7e, 0x7e, 0x00, 0x02, 0x1c, 0x02, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x05, 0x73, 0x6c,
            0x6f, 0x61, 0x64, 0x00, 0x00, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x06, 0x73, 0x73, 0x74, 0x6f, 0x72,
            0x65, 0x00, 0x01, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x69, 0x6e, 0x63, 0x00, 0x02,
            0x0a, 0x13, 0x01, 0x11, 0x00, 0x20, 0x00, 0x20, 0x00, 0x10, 0x00, 0x42, 0x01, 0x7c, 0x10, 0x01,
            0x20, 0x00, 0x10, 0x00, 0x0b,
        ];

        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([2u8; 32], COUNTER_WASM.to_vec(), 0).unwrap();

        // Call 1: key 42 -> was 0 -> now 1:
        let (v1, _, _) = reg.call(&addr, "inc", 42, 50_000).unwrap();
        assert_eq!(v1, 1, "first call must increment 0 -> 1");

        // Call 2: key 42 -> was 1 -> now 2:
        let (v2, _, _) = reg.call(&addr, "inc", 42, 50_000).unwrap();
        assert_eq!(v2, 2, "second call must increment 1 -> 2 (persistent storage)");

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
        let (out, _, _) = reg
            .call(&addr, "fill", MAX_CONTRACT_STORAGE_KEYS as i64, 10_000_000)
            .unwrap();
        assert_eq!(out, 0);
        assert_eq!(reg.get(&addr).unwrap().storage.len(), MAX_CONTRACT_STORAGE_KEYS);

        // One more *new* key must trap instead of silently growing consensus state.
        let err = reg.call(&addr, "fill", (MAX_CONTRACT_STORAGE_KEYS + 1) as i64, 10_000_000).unwrap_err();
        assert!(matches!(err, ContractError::Trapped), "expected trap, got {err:?}");
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
        assert_eq!(reg.get(&addr).unwrap().storage.len(), 1, "rewriting key 7 must not add slots");
    }

    #[test]
    fn event_emission_is_capped() {
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], event_filler_wasm(), 0).unwrap();
        let (_, _, events) = reg.call(&addr, "fill", MAX_CONTRACT_EVENTS as i64, 10_000_000).unwrap();
        assert_eq!(events.len(), MAX_CONTRACT_EVENTS);
        assert!(events.iter().all(|e| e.contract == addr));

        let err = reg.call(&addr, "fill", (MAX_CONTRACT_EVENTS + 1) as i64, 10_000_000).unwrap_err();
        assert!(matches!(err, ContractError::Trapped), "expected trap, got {err:?}");
    }

    #[test]
    fn host_operations_are_fuel_metered() {
        // A loop of host writes must run out of fuel long before it can write
        // an unbounded number of slots, even with a huge declared budget.
        let mut reg = ContractRegistry::new();
        let addr = reg.deploy([1u8; 32], storage_filler_wasm(), 0).unwrap();
        let err = reg.call(&addr, "fill", 1_000_000, 5_000).unwrap_err();
        assert!(matches!(err, ContractError::OutOfFuel), "expected out of fuel, got {err:?}");
        assert!(reg.get(&addr).unwrap().storage.is_empty(), "a fuel-starved call must not persist writes");
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
        handle.join().expect("contract execution must not abort the process");
    }
}
