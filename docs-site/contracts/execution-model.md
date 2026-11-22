---
title: Execution model
description: How the wasmi engine executes Stellereum contracts, what fuel and limits apply, and exactly when state is kept or discarded.
---

# Execution model

Every contract call runs in a fresh `wasmi` store with a fresh linear memory, a cloned storage map, and a fuel budget derived from the transaction's remaining gas. Nothing survives between calls except the contract's persistent storage and balance, and every node must reach the same result. This page defines the fuel model, hard limits and revert rules that make that possible.

## The engine

`stellereum/src/contract.rs` builds the engine with a deliberately narrow configuration:

| Setting | Value | Why |
| --- | --- | --- |
| Interpreter | `wasmi` 2.0 | Deterministic, sandboxed, no JIT-dependent behavior |
| Fuel | `consume_fuel(true)` | Every instruction is metered; no infinite loops |
| Compilation (shared engine) | `CompilationMode::Eager` | Cold and hot module reads burn identical fuel |
| Multi-memory | disabled | One linear memory per instance |
| Mutable globals | enabled | Normal Rust codegen needs them |
| Dispatch | `portable-dispatch` | Bounded loop backend; a deep contract loop cannot overflow the host stack |
| Floats | `deterministic` crate feature | Canonical NaN semantics if float instructions ever appear |

There are two engine paths, selected by the chain's hardening flag:

- **Hardened path** (`>= H`, and `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT = 0` on the current
  chain, so it is always active): shared eager engine + a bounded FIFO module cache
  (`CONTRACT_MODULE_CACHE_CAP = 1024`, keyed by `blake3(code)`), distinct `caller`/`origin`, and
  per-byte `send_message` fuel.
- **Legacy path** (`< H` only): a per-call lazy-translation engine and flat `send_message` fuel.
  This path exists for pre-activation replay compatibility; new contracts never use it.

Module compilation is cached process-wide on the hardened path. A cached module is only an
optimization: each call still gets its own `Store`, `Linker` and `Instance`.

## Fuel is charged before the effect

Contract code consumes fuel per executed instruction. Host functions run *outside* the
instruction meter, so each one charges an explicit amount **first** and only then touches storage,
memory or the event log:

```rust
fn charge(caller: &mut Caller<'_, HostState>, fuel: u64) -> Result<(), wasmi::Error> {
    let left = caller.get_fuel()?;
    let left = left.checked_sub(fuel).ok_or_else(|| wasmi::Error::new("host operation out of fuel"))?;
    caller.set_fuel(left)
}
```

This ordering is a security property, not an implementation detail:

- a host call that performs an effect always pays for it;
- a state-dependent limit (storage/event/message caps) is checked after the charge, so a rejected
  effect still costs fuel;
- fuel exhaustion is detected before a write, so a fuel-starved call leaves no partial state.

Some pure argument checks (negative lengths, oversized hash input) trap before charging; that is
the narrow exception, not a way to get host work for free.

Host price formulas use saturating arithmetic; the subtraction itself is checked, and an
underflow traps with `host operation out of fuel`. The per-call budget is
`min(requested_gas, MAX_CONTRACT_FUEL)`, and in the block path it is simply the transaction's
remaining gas (`state.gas_remaining`), so a contract can never consume more compute than the
sender paid for.

::: tip Fuel ≠ gas
**Gas** is the transaction-level resource priced by the fee market. **Fuel** is the `wasmi`
budget. The block path passes `min(remaining_gas, 50,000,000)` as the fuel budget, but the two are
not interchangeable in client code: `stell_estimateFee` reports gas, while
`stell_runGetMethod` reports `fuel_used`.
:::

## Hard limits

All values below are constants in `stellereum/src/contract.rs` and
`stellereum/src/svm.rs`; none are configurable per chain at runtime.

### Code and memory

| Limit | Value | Constant |
| --- | --- | --- |
| Maximum code size | 2 MiB (2,097,152 bytes) | `MAX_CONTRACT_CODE_SIZE` |
| Maximum memory pages | 128 pages = 8 MiB | `MAX_CONTRACT_PAGES` / `MAX_CONTRACT_MEMORY` |
| Memory declarations validated | min **and** max pages ≤ 128 | `validate_memory_limits` |
| Store memory cap | 8 MiB | `StoreLimitsBuilder::memory_size` |
| Memories per store | 4 | `store_limits()` |
| Tables per store | 4 | `store_limits()` |
| Instances per store | 16 | `store_limits()` |

### Call shape and output

| Limit | Value | Constant |
| --- | --- | --- |
| `i64` parameters per call | 8 | `MAX_CONTRACT_CALL_ARGS` |
| Method-name bytes (SVM) | 256 | `MAX_CONTRACT_METHOD_LEN` |
| Calldata bytes (SVM) | 64 KiB | `MAX_CONTRACT_CALLDATA_BYTES` |
| Return data bytes (`host.return_data`) | 64 KiB | `MAX_RETURN_DATA` |
| Events per call | 256 | `MAX_CONTRACT_EVENTS` |
| Outbound messages per call | 64 | `MAX_CONTRACT_OUTBOUND_MESSAGES` |
| Persistent storage keys per contract | 4,096 | `MAX_CONTRACT_STORAGE_KEYS` |
| Nested sub-call depth (engine API) | 8 | `MAX_CALL_DEPTH` |

The storage cap applies to **new keys only**. Overwriting an existing slot is always allowed, so a
counter can update forever without growing state. The 4,096th new key succeeds; the 4,097th traps
with `contract storage limit exceeded` and the whole call is discarded.

### Fuel budgets

| Budget | Value | Constant |
| --- | --- | --- |
| Maximum call fuel | 50,000,000 | `MAX_CONTRACT_FUEL` |
| Read-only getter cap | 5,000,000 | `GET_METHOD_SAFETY_FUEL_LIMIT` |
| `(start)` validation budget | 5,000,000 | `VALIDATE_CODE_START_FUEL_LIMIT` |
| Module cache entries | 1,024 | `CONTRACT_MODULE_CACHE_CAP` |

A getter's requested `fuel` is clamped to 5,000,000, never raised. `stell_estimateFee` has its own
fixed simulation ceiling of 5,000,000 gas, which is a separate bound (see
[`/contracts/deploy-and-call`](/contracts/deploy-and-call)).

### Gas prices (transaction layer)

| Operation | Formula | Constant |
| --- | --- | --- |
| Deploy | `2,000 + 2 × code_len` | `GAS_DEPLOY_BASE`, `GAS_PER_BYTE` |
| Call | `1,000 + 10 × arg_count + 2 × (method_len + calldata_len)` | `contract_call_gas` |

The deploy and call charges are the opcode price. `wasmi` fuel is charged **on top** of that price
and is bounded by the remaining gas.

## Revert semantics

A call has exactly two outcomes: it returns an `i64`, or it fails with a `ContractError`. There is
no "return false means reverted" rule.

```rust
// call_with_options: the assignment happens only on Ok
let (out, used, new_storage, new_balance, events, outbound_messages, return_data) =
    run_contract(...)?;              // any Err returns immediately
contract.storage = new_storage;      // committed only on success
contract.balance = new_balance;
```

Consequences:

- **A trap reverts everything.** Storage writes, balance debits, emitted events, outbound messages
  and return data produced before the trap are all discarded.
- **A negative return value does not revert.** `SUCCESS = 0` and `ERR_* = -1 … -7` are an
  application-level convention used by the SDK. The runtime records them as a successful call with
  a negative result. Receipts show `status: "success"` and `return_value: -1`.
- **Events and messages are effects of the call, not of the return code.** If the call succeeds,
  they are kept even when the returned integer is an error code.
- **Fuel is consumed on failure.** `OutOfFuel` reports `gas_used = gas_limit` in previews and in the
  structured engine outcome; every other error reports `0` `gas_used` there, even though fuel was
  burned before the trap. Treat `gas_used: 0` on a failure as "not reported", not "free".
- **Sub-calls are isolated.** The engine's `execute_subcall_hardened` takes a `SubCallSnapshot` and
  rolls back storage, balance, `last_return_data`, events and outbound messages if the sub-call
  fails or exceeds depth 8. This API exists for the engine; **contracts cannot invoke it** because
  there is no synchronous `call` host import.

::: warning No revert reason on chain
A wasm trap has no payload. `ContractError::Trapped` displays as
`contract trapped during execution`, and a Rust `panic!` message is not preserved (the panic
handler lowers it to `unreachable`). If callers need a reason, return an `ERR_*` code instead of
panicking.
:::

## Panics

The SDK installs a wasm panic handler:

```rust
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
```

So a `panic!`, an out-of-bounds slice index, an `unwrap()` on `None`, or an arithmetic overflow in
a build with `overflow-checks = true` becomes a wasm trap:

| Where | Observed result |
| --- | --- |
| `ContractRegistry::call*` | `Err(ContractError::Trapped)` |
| `stell_runGetMethod` | `{"success": false, "error": "contract trapped during execution", "fuel_used": N}` |
| Receipt (`stell_getContractReceipt`) | `status: "failed"`, `gas_used`, empty events, no return value |

State is still all-or-nothing: the trap discards the call's writes.

The reference contracts use both styles deliberately: STS-20 returns `ERR_*` for expected business
failures and panics on impossible/invalid states; Account Object panics on unauthorized access so a
native test harness can observe the refusal via `catch_unwind` (its entry points are
`extern "C-unwind"`; wasm behavior is identical).

## Paused contracts

`ContractRegistry::pause(address, caller)` sets `paused = true`, and only the contract's **creator**
may call it. A different caller gets `ContractError::NotFound` — the runtime does not reveal that
the contract exists.

| Path | Behavior when paused |
| --- | --- |
| `call`, `call_args`, `call_abi` | `Err(ContractError::Paused)` before any wasm runs |
| `stell_callContract` preview | failed outcome with `contract is paused`, `gas_used: 0` |
| `stell_runGetMethod` | `{"success": false, "error": "contract is paused", "fuel_used": 0}` |
| Deploy of the same address | irrelevant; the address is taken |

::: danger Pause exists in the engine, but no public setter does
`ContractRegistry::pause` is creator-only and there is **no `unpause`**. Worse for operators: no
`stell_*` RPC method and no `SysCall*` opcode calls `pause` today — it is an engine-level method
used by tests and available to a node implementation, not a user-facing switch. Treat the paused
behavior above as the semantics if the flag is set, not as a maintenance tool you can invoke over
RPC. Pausing, when available at all, is effectively permanent; plan upgrades around "deploy the new
contract, migrate, retire the old one", not around a temporary stop.
:::

## Deterministic state root

Two validators that execute the same block must derive the same root. The contract domain of the
consensus commitment is built deterministically:

1. contracts are sorted by 32-byte address;
2. `next_nonce`, the contract count, and then per contract: address, creator, code hash,
   `created_at`, `paused`, ABI manifest JSON (or a `has_abi = false` marker), optional source hash;
3. storage slots are sorted by **signed** `i64` key (not `HashMap` iteration order) and written as
   `(key, value)` pairs.

The Patricia trie additionally commits:

```text
sha256("STELL_CONTRACT_CODE"   || address) -> code_hash
sha256("STELL_CONTRACT_ABI"    || address) -> abi_json      (when present)
sha256("STELL_CONTRACT_SOURCE" || address) -> source_hash   (when registered)
```

Storage slots are **not** individual trie leaves. They are folded into the consensus-commitment
digest, so an archive proof can prove the digest and the code/ABI/source leaves, but not a single
storage slot. The RPC states this explicitly: `stell_getProgramAccounts` with
`program: "contract"` returns slots with `"proof": null` and a note pointing at the contract digest.

::: tip Practical consequence for clients
You can verify a contract's code hash and ABI against a state root. You cannot verify "slot 7 is
42" with a Merkle proof today; read it from a node you trust, or recompute it from the contract's
event history.
:::

## Why no floats

Determinism is the whole reason for the integer-only ABI:

- IEEE-754 results can differ across architectures, compilers and optimization levels;
- NaN payloads and signed zero are classic consensus-split bugs;
- the ABI has no float type, so a float could never cross the contract boundary anyway.

The engine enables `wasmi`'s `deterministic` feature (canonical NaN semantics) as defense in depth,
but that is not a license to use floats. Do not use `f32`/`f64` in contract logic; represent
amounts as integers in the smallest unit (nano-STELL, basis points, fixed-point scaled integers).

## The call context is supplied, not read from the host

Contracts observe their environment only through host functions. The block path supplies:

| Field | Block application | `stell_runGetMethod` |
| --- | --- | --- |
| `caller` | `tx.from` | `[0u8; 32]` |
| `origin` (hardened) | `tx.from` | `[0u8; 32]` |
| `value` | `0` — the value leg is a separate debit/credit | `0` |
| `block_time` | the block timestamp | `0` |
| `block_hash` | `[0u8; 32]` | `[0u8; 32]` |

Two consequences deserve their own warning:

::: danger Getters run with a zero context
`stell_runGetMethod` does not authenticate anyone and does not carry a timestamp. A view method
that branches on `caller()` or `block_time()` will see zeros. Keep views context-free; do not use
them to answer "what would this caller be allowed to do?".
:::

::: warning `block_hash` is currently always zero
The SVM call context sets `block_hash = [0u8; 32]` for both deploy and call paths, and the preview
uses the same shape. Do not build randomness, commit-reveal schemes or cross-chain assertions on
`host.block_hash` today. Use `host.block_time` for coarse time and an explicit stored commitment
for anything stronger.
:::

The preview deliberately uses the **head block's committed timestamp**, not wall-clock time, so a
preview of a time-dependent call matches what the next block would see closely enough to be useful.
An owner-guarded call previewed with an explicit `caller` executes with that caller; the RPC
refuses to invent a zero or random caller (see
[`/contracts/deploy-and-call`](/contracts/deploy-and-call)).

## Next

Continue with [Writing contracts in Rust](/contracts/rust) or [Host functions](/contracts/host-functions). [Deploying and calling contracts](/contracts/deploy-and-call) turns a module into a signed transaction.
