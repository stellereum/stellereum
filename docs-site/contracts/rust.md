---
title: Writing contracts in Rust
description: Build a no_std Stellereum contract with stellereum-contract-sdk, export i64 methods, use StorageItem/StorageMap, and authenticate callers correctly.
---

# Writing contracts in Rust

Rust is the recommended way to write a Stellereum contract: `#![no_std]`, a small SDK, and the
standard `wasm32-unknown-unknown` target. The ABI is plain C:

```rust
#[no_mangle]
pub extern "C" fn method(a: i64, b: i64) -> i64 { /* ... */ }
```

Each exported Rust function becomes a wasm export with the same name and an `(i64, …) -> i64`
signature. The runtime dispatches by name **and exact arity**.

## Project layout

The SDK lives at `stellereum-contracts/crates/stellereum-contract-sdk`. A contract crate inside the
same workspace looks like this:

```text
stellereum-contracts/
├── Cargo.toml                    # workspace
├── crates/stellereum-contract-sdk/
└── contracts/
    └── my-contract/
        ├── Cargo.toml
        └── src/lib.rs
```

```toml
# contracts/my-contract/Cargo.toml
[package]
name = "my-contract"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
stellereum-contract-sdk = { path = "../../crates/stellereum-contract-sdk" }

# Profiles are workspace-wide: set these in the workspace root Cargo.toml,
# not in a member (Cargo ignores member profiles with a warning).
[profile.release]
panic = "abort"
opt-level = "s"
lto = true
overflow-checks = true
```

`overflow-checks = true` is not cosmetic. With checks off, an overflowing `+` silently wraps in
release builds and can mint or destroy balances. Keep the checks and write explicit
`checked_*`/`saturating_*` arithmetic for values supplied by callers.

The workspace builds every contract for the wasm target:

```sh
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
```

The artifact is `target/wasm32-unknown-unknown/release/my_contract.wasm`. Check its size before
deploying — the chain rejects anything above **2 MiB**:

```sh
ls -l target/wasm32-unknown-unknown/release/my_contract.wasm
```

## The SDK surface

`stellereum-contract-sdk` is `no_std` on wasm and provides a native mock for `cargo test`:

| Item | Purpose |
| --- | --- |
| `sload(key) -> i64` / `sstore(key, value)` | raw persistent slot access |
| `StorageItem::new(slot)` | typed single-slot wrapper with `get`/`set`/`update` |
| `StorageMap::new(base_slot)` | keyed map with FNV-1a domain-separated slot derivation |
| `emit(topic, value)` | append an event |
| `caller() -> [u8; 32]` | **authenticated** transaction sender |
| `caller_is(id) -> bool` | fail-closed binding of an integer id to `caller()` |
| `value() -> u64` | native value attached to the call |
| `setup_wasm_panic_handler!()` | lowers panics to a wasm trap |
| `SUCCESS`, `ERR_*` | conventional return codes |

::: warning `value()` is almost always zero
On the block path the native value leg is settled as a separate debit/credit and is **not** exposed
as `host.value`. Do not implement payable logic that depends on `value()` today; transfer value
explicitly and account for it in your own storage model.
:::

### `StorageItem` and `StorageMap`

`StorageItem` is a single slot:

```rust
use stellereum_contract_sdk::storage::StorageItem;

const COUNTER: StorageItem = StorageItem::new(10);

let current = COUNTER.get();
COUNTER.set(current + 1);
let next = COUNTER.update(|v| v.saturating_add(1)); // returns the new value
```

`StorageMap` hashes `(base_slot, key)` with 64-bit FNV-1a and masks the sign bit, so keys map to
deterministic positive `i64` slots:

```rust
use stellereum_contract_sdk::storage::StorageMap;

const BALANCES: StorageMap = StorageMap::new(1_000);

BALANCES.set(7, 500);
let bal = BALANCES.get(7);
```

Both helpers are thin wrappers over `sload`/`sstore`; they do not add fuel beyond the host charge.
Collisions are possible in principle (the slot space is 63 bits, the map is not a cryptographic
hash), so keep key spaces domain-separated with distinct `base_slot` values.

## Authentication: the one rule that matters

::: danger Never authorize with a caller-supplied id
Integer account ids are **public**. If `transfer(packed)` trusts the `from` field inside `packed`,
anyone can move anyone's tokens. Every value-moving entry point must bind the claimed id to the
authenticated `host.caller`.
:::

The SDK gives you two primitives:

```rust
pub fn caller() -> [u8; 32];

pub fn caller_is(id: i64) -> bool {
    id > 0 && caller() == id_to_caller(id)
}
```

`id_to_caller(id)` is the canonical encoding: the `i64` little-endian in bytes `[0..8]`, zeros in
bytes `[8..32]`. `caller_is(0)` and `caller_is(negative)` are **always false**, because the zero
address is "no authenticated sender" and must never own anything.

```rust
if !caller_is(from) {
    return ERR_UNAUTHORIZED;
}
```

For a contract that stores 32-byte identities directly (four `i64` slots), compare `caller()`
against the stored words. Do not accept a 32-byte `owner` argument and compare it to `caller()` —
that is just as forgeable as an integer id, because the attacker supplies both sides of the
comparison.

On native targets the SDK substitutes a mock caller:

```rust
use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller};

reset_mock_state();
set_mock_caller(id_to_caller(1));
assert!(caller_is(1));
```

## A complete contract: counter + guarded token transfer

The following crate compiles as-is. It demonstrates both storage helpers, both caller primitives,
events, error codes and the panic handler.

```rust
// contracts/my-contract/src/lib.rs
#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use stellereum_contract_sdk::storage::{StorageItem, StorageMap};
use stellereum_contract_sdk::{
    caller, caller_is, emit, setup_wasm_panic_handler, sload, sstore, ERR_INSUFFICIENT_BALANCE,
    ERR_INVALID_ARGUMENT, ERR_OVERFLOW, ERR_UNAUTHORIZED, SUCCESS,
};

setup_wasm_panic_handler!();

// ---- storage layout -------------------------------------------------------
const SLOT_INITIALIZED: i64 = 0;
const SLOT_TOTAL_SUPPLY: i64 = 1;
const SLOT_ADMIN: i64 = 2;

/// A single-slot counter at slot 10.
const COUNTER: StorageItem = StorageItem::new(10);
/// id -> balance, hashed from base slot 20.
const BALANCES: StorageMap = StorageMap::new(20);

// ---- events ---------------------------------------------------------------
const TOPIC_TRANSFER: i64 = 1;
const TOPIC_MINT: i64 = 2;

/// Initialize once. `supply` is minted to account id 1.
#[no_mangle]
pub extern "C" fn init(supply: i64) -> i64 {
    if supply <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    if sload(SLOT_INITIALIZED) != 0 {
        panic!("already initialized");
    }

    let admin = 1i64;
    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_ADMIN, admin);
    sstore(SLOT_TOTAL_SUPPLY, supply);
    BALANCES.set(admin, supply);

    emit(TOPIC_MINT, supply);
    SUCCESS
}

/// `increment(0)` -> new counter value.
#[no_mangle]
pub extern "C" fn increment(_arg: i64) -> i64 {
    COUNTER.update(|v| v.saturating_add(1))
}

#[no_mangle]
pub extern "C" fn count(_arg: i64) -> i64 {
    COUNTER.get()
}

#[no_mangle]
pub extern "C" fn total_supply(_arg: i64) -> i64 {
    sload(SLOT_TOTAL_SUPPLY)
}

#[no_mangle]
pub extern "C" fn balance_of(id: i64) -> i64 {
    if id <= 0 {
        return 0;
    }
    BALANCES.get(id)
}

/// First 8 bytes of the authenticated caller, little-endian.
///
/// Useful for debugging and for clients that key on a small id.
#[no_mangle]
pub extern "C" fn caller_word(_arg: i64) -> i64 {
    let who = caller();
    i64::from_le_bytes([
        who[0], who[1], who[2], who[3], who[4], who[5], who[6], who[7],
    ])
}

/// transfer(packed): packed = from * 10_000_000_000 + to * 100_000 + amount
///
/// `amount` must be in `1..=99_999`; `from`/`to` are account ids, not
/// addresses. `from` is only a claim — authorization comes from `caller_is`.
#[no_mangle]
pub extern "C" fn transfer(packed: i64) -> i64 {
    if packed <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let from = packed / 10_000_000_000;
    let to = (packed % 10_000_000_000) / 100_000;
    let amount = packed % 100_000;

    if from <= 0 || to <= 0 || amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    if !caller_is(from) {
        return ERR_UNAUTHORIZED;
    }

    let from_balance = BALANCES.get(from);
    if from_balance < amount {
        return ERR_INSUFFICIENT_BALANCE;
    }

    let to_balance = BALANCES.get(to);
    let new_to_balance = match to_balance.checked_add(amount) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    BALANCES.set(from, from_balance - amount);
    BALANCES.set(to, new_to_balance);

    emit(TOPIC_TRANSFER, amount);
    SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller};

    fn pack(from: i64, to: i64, amount: i64) -> i64 {
        from * 10_000_000_000 + to * 100_000 + amount
    }

    #[test]
    fn counter_survives_between_calls() {
        reset_mock_state();
        assert_eq!(increment(0), 1);
        assert_eq!(increment(0), 2);
        assert_eq!(count(0), 2);
    }

    #[test]
    fn transfer_requires_the_authenticated_owner() {
        reset_mock_state();
        assert_eq!(init(1_000), SUCCESS);

        // A stranger claims to be account 1: refused, nothing moves.
        set_mock_caller(id_to_caller(2));
        assert_eq!(transfer(pack(1, 2, 10)), ERR_UNAUTHORIZED);
        assert_eq!(balance_of(1), 1_000);

        // The real owner succeeds.
        set_mock_caller(id_to_caller(1));
        assert_eq!(transfer(pack(1, 2, 10)), SUCCESS);
        assert_eq!(balance_of(1), 990);
        assert_eq!(balance_of(2), 10);
    }
}
```

Run the native tests with the mock host:

```sh
cargo test -p my-contract
```

::: warning Packed arguments have a range
`from * 10_000_000_000` overflows `i64` once `from` exceeds roughly 922 million, and `to`/`amount`
must stay below 100,000. Packing is a legacy convenience; new contracts should use
`SysCallCallContractArgs` and a typed ABI manifest instead
(see [`/contracts/abi`](/contracts/abi)). Validate every field before arithmetic.
:::

## Exports: names, arity, and zero-argument methods

| Rust export | Wasm signature | Callable with |
| --- | --- | --- |
| `fn f() -> i64` | `() -> i64` | `[]` (and one ignored argument on legacy paths) |
| `fn f(a: i64) -> i64` | `(i64) -> i64` | `[a]` |
| `fn f(a: i64, b: i64) -> i64` | `(i64, i64) -> i64` | `[a, b]` |
| `fn f(a: i64) -> ()` | `(i64) -> ()` | `[a]`, runtime records `0` |

- Export names are case-sensitive and must be valid UTF-8 (the SVM method-name field is bytes and
  is decoded as UTF-8).
- A multi-parameter export is **never** reachable with fewer or more arguments on the
  state-changing path. A two-argument method called with one argument is `NoSuchMethod`.
- Keep method names short: the SVM charges 2 gas per byte of method name and caps it at 256 bytes.
- Do not export `memory` unless you use pointer-taking host functions. When you do, the runtime
  looks up the export named exactly `"memory"`.

`#[no_mangle]` is correct for edition 2021. On edition 2024 use `#[unsafe(no_mangle)]`.

## Error codes

The SDK defines a small, stable convention. These are ordinary `i64` return values; they do **not**
revert the call by themselves.

| Constant | Value | Meaning |
| --- | --- | --- |
| `SUCCESS` | `0` | success |
| `ERR_UNAUTHORIZED` | `-1` | caller is not the owner/spender/admin |
| `ERR_INSUFFICIENT_BALANCE` | `-2` | balance too low |
| `ERR_INVALID_ARGUMENT` | `-3` | malformed packing or out-of-range field |
| `ERR_EXPIRED` | `-4` | deadline passed |
| `ERR_ALREADY_EXISTS` | `-5` | duplicate id / re-initialization |
| `ERR_NOT_FOUND` | `-6` | unknown record |
| `ERR_OVERFLOW` | `-7` | checked arithmetic failed |

Reserve panics for states that must never happen (re-initialization, impossible slot math,
unauthorized admin operations in the reference contracts). A panic is a trap: the call reverts,
but the reason is not preserved on chain.

## Determinism checklist

Before deploying, confirm:

- no `f32`/`f64`, no `std::time`, no randomness, no environment access;
- no iteration over a `HashMap` whose order affects a stored value or event order — iterate sorted
  keys;
- arithmetic on caller-supplied values is `checked_*` or explicitly bounded;
- every state-changing entry point authenticates with `caller()` / `caller_is()`;
- every loop has a bound independent of caller input, or relies on fuel (and then still respects
  the storage/event/message caps);
- the crate builds with `panic = "abort"`, `overflow-checks = true`, and no allocator unless you
  really need one (8 MiB of linear memory is the ceiling).

## Next

Read [Writing contracts in WAT](/contracts/wat) to see the canonical instruction-level form, then [Deploying and calling contracts](/contracts/deploy-and-call) to ship the `.wasm` artifact.
