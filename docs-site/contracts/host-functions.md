---
title: Host functions
description: Exact signatures, fuel prices and failure behavior for every host.* import available to a Stellereum contract.
---

# Host functions

A contract can import exactly the functions registered in `host_linker`
(`stellereum/src/contract.rs`). The list is closed: no clock, network, filesystem, allocator or
host memory is reachable through any other name. Unknown imports fail deployment with
`ContractError::UnresolvableImports`.

Fuel is charged **before** the effect in every function, so a limit that is checked after the
charge (a storage, event or message cap) still costs fuel. Argument-shape checks that happen before
the charge — negative lengths, oversized hash inputs, an oversized return blob — trap without
charging. A call that reaches the effect never does so for free.

## The complete table

| # | Import | WAT signature | Returns | Fuel |
| --- | --- | --- | --- | --- |
| 1 | `host.sload` | `(param i64) (result i64)` | slot value, `0` if unset | **10** |
| 2 | `host.sstore` | `(param i64 i64)` | — | **100** |
| 3 | `host.emit` | `(param i64 i64)` | — | **50** |
| 4 | `host.caller` | `(param i32)` | — (writes 32 bytes) | **10** |
| 5 | `host.origin` | `(param i32)` | — (writes 32 bytes) | **10** |
| 6 | `host.value` | `(result i64)` | attached value as `i64` | **5** |
| 7 | `host.block_time` | `(result i64)` | block timestamp (seconds) | **5** |
| 8 | `host.block_hash` | `(param i32)` | — (writes 32 bytes) | **10** |
| 9 | `host.calldata` | `(param i32) (result i64)` | byte length copied | **20 + 1/byte** |
| 10 | `host.sha256` | `(param i32 i32 i32)` | — (writes 32 bytes) | **30 + 1/byte + 32** |
| 11 | `host.blake3` | `(param i32 i32 i32)` | — (writes 32 bytes) | **20 + 1/byte + 32** |
| 12 | `host.falcon512_verify` | `(param i32 i32 i32 i32 i32 i32) (result i32)` | `1` valid / `0` invalid | **2,000 + msg + pk + sig bytes** |
| 13 | `host.return_data` | `(param i32 i32)` | — | **10 + 1/byte** |
| 14 | `host.send_message` | `(param i64 i64 i64 i64 i64 i64) (result i64)` | message ordinal, or negative code | **100** (hardened: **+1/byte**) |

All arithmetic in the charges is saturating. Fuel constants live in `stellereum/src/contract.rs`
(`FUEL_SLOAD`, `FUEL_SSTORE`, `FUEL_EMIT`, `FUEL_CALLER`, `FUEL_VALUE`, `FUEL_BLOCK_TIME`,
`FUEL_BLOCK_HASH`, `FUEL_CALLDATA`/`_PER_BYTE`, `FUEL_SHA256_BASE`/`_PER_BYTE`,
`FUEL_BLAKE3_BASE`/`_PER_BYTE`, `FUEL_FALCON512_VERIFY`, `FUEL_RETURN_DATA_BASE`/`_PER_BYTE`,
`FUEL_SEND_MESSAGE`/`_PER_BYTE`).

::: warning The count is 14, not 13
Older notes list 13 imports and omit `host.origin`. The linker registers `origin` on every path;
it is the 14th function. See [`/contracts/wat`](/contracts/wat#the-import-surface).
:::

## Storage

### `sload(key: i64) -> i64`

Reads one persistent slot. Missing keys return `0` — there is no "unset" distinction, so do not use
zero as a sentinel unless your schema reserves it.

### `sstore(key: i64, value: i64)`

Writes one slot. Two rules apply:

- **New keys are capped.** A contract may own at most **4,096 distinct keys**
  (`MAX_CONTRACT_STORAGE_KEYS`). Writing a key that does not exist when the map is full traps with
  `contract storage limit exceeded`.
- **Overwrites are uncapped.** Re-writing an existing key is always allowed, so counters and
  balances can live forever in a handful of slots.

Storage is keyed by signed `i64`. Two contracts never share a namespace; each has its own map.

::: tip Slot layout is your responsibility
The runtime does not allocate slots or protect against collisions. Reserve low slots for globals,
use distinct offsets or a `StorageMap` base per logical map, and document the layout. The reference
contracts do exactly this (see [`/contracts/standards`](/contracts/standards)).
:::

## Events

### `emit(topic: i64, value: i64)`

Appends `ContractEvent { contract, topic, value }`. The emitting contract is filled in by the host;
a contract cannot forge another contract's address.

- At most **256 events per call** (`MAX_CONTRACT_EVENTS`). The 257th traps with
  `contract event limit exceeded`.
- Events survive only if the call succeeds. A later trap discards the whole list.
- The runtime stores `(topic, value)` as integers. The optional ABI manifest gives them names and
  types off-chain; it does not change the on-chain bytes.

RPC surfaces events as:

```json
{ "contract": "<64 hex>", "contract_stl57": "Stl57…", "topic": 2001, "value": 1000 }
```

## Call context

### `caller(dest_ptr: i32)`

Writes the **authenticated** sender's 32-byte address at `dest_ptr`. On the block path this is
`tx.from`; on a call preview it is the `caller` the request named; on `stell_runGetMethod` it is
all zeros.

This is the only trustworthy identity in the runtime.

### `origin(dest_ptr: i32)`

Writes the transaction origin (`tx.from`) at `dest_ptr`. On the hardened path `origin` and `caller`
are both `tx.from` today, because contracts cannot synchronously call each other. On the legacy
path `origin` falls back to `caller`. Use `caller` for authorization; use `origin` only for
accounting/diagnostics that must survive a future meta-transaction layer.

### `value() -> i64`

Returns the native value attached to the call. **On the block path this is always `0`**: the
transaction's value leg is settled as a separate debit/credit and is not exposed as `host.value`.
Do not implement payable behavior on top of it.

### `block_time() -> i64`

Returns the supplied block timestamp in seconds. Block application passes the block timestamp;
`stell_runGetMethod` passes `0`; a preview passes the head block's committed timestamp.

### `block_hash(dest_ptr: i32)`

Writes a 32-byte block hash. **The current call path supplies `[0u8; 32]`**, so this function
currently writes zeros. Do not build randomness or commit-reveal schemes on it. It remains in the
ABI for forward compatibility.

## Calldata and return data

### `calldata(dest_ptr: i32) -> i64`

Copies the current call's ABI-encoded argument blob into the contract's memory and returns its
length. If there is no calldata, it returns `0` **without touching `dest_ptr`**.

What exactly is copied matters, and it is easy to get wrong:

- The blob is the **arguments payload** (`u32_le(arg_count) || arg_0 || …`), exactly what
  `ContractAbi::encode_args` produces and what `stellereum-sdk`'s `encode_calldata` produces.
- It does **not** include the 4-byte method selector. The selector exists in
  `ContractAbi::encode_call` for tooling, but the runtime passes only the arguments payload.
- The method name is dispatched from the opcode's `method` field, not from calldata.

A one-`i64` call therefore yields `4 + 1 + 8 = 13` bytes. This is pinned by a runtime test.

Fuel: `20 + len`. A contract cannot use `calldata` to read more than the SVM allowed into the
transaction (`MAX_CONTRACT_CALLDATA_BYTES` = 64 KiB).

### `return_data(ptr: i32, len: i32)`

Sets the call's return blob, readable by clients and by `ContractOutcome::return_data`. It is
separate from the `i64` return value:

- `i64` result → scalar returns (`i64`, `u64`, `i32`, `bool`);
- `return_data` → blob returns (`bytes`, `address`, `string`).

Limits and fuel:

- `len > 64 KiB` (`MAX_RETURN_DATA`) traps with `return data exceeds maximum limit`;
- negative `len` traps;
- fuel is `10 + len`.

Calling `return_data` twice replaces the blob; only the last value survives.

## Hashing

Both hashes write 32 raw bytes to `dest_ptr` and charge for input length plus the fixed 32-byte
output.

### `sha256(src_ptr: i32, src_len: i32, dest_ptr: i32)`

Fuel: `30 + src_len + 32`. Input length above `MAX_CONTRACT_MEMORY` (8 MiB) traps.

### `blake3(src_ptr: i32, src_len: i32, dest_ptr: i32)`

Fuel: `20 + src_len + 32`. Same input bound.

Use `sha256` when you need to match the chain's address/code-hash conventions; use `blake3` when
you need the chain's build-fingerprint convention (`source_hash = BLAKE3(source_text)`).

## Signature verification

### `falcon512_verify(msg_ptr, msg_len, pk_ptr, pk_len, sig_ptr, sig_len) -> i32`

Verifies a Falcon-512 post-quantum signature over `msg` with public key `pk`.

- Returns `1` for a valid signature, `0` for an invalid one. A wrong key length is simply invalid
  (`0`), not a trap.
- Fuel: `2,000 + msg_len + pk_len + sig_len`.
- Any negative length traps (`negative length for falcon512_verify`).
- Any single length above `MAX_CONTRACT_MEMORY` traps.
- Out-of-bounds pointers trap.

`ed25519_verify` is **not** available. A module importing it fails deployment.

## Outbound messages

### `send_message(recipient_ptr, recipient_len, value, payload_ptr, payload_len, bounce) -> i64`

Queues an asynchronous message to another address. The host debits the contract's balance
immediately; delivery happens after the call succeeds.

Arguments are declared as `i64` even though the two pointers are memory offsets:

| Argument | Meaning |
| --- | --- |
| `recipient_ptr` | memory offset of 32 raw address bytes |
| `recipient_len` | must be exactly `32` |
| `value` | nano-STELL to send (must be ≥ 0 and ≤ contract balance) |
| `payload_ptr` | memory offset of the payload |
| `payload_len` | `0 … 65,536` bytes |
| `bounce` | non-zero ⇒ bounce enabled |

Return codes:

| Code | Meaning |
| --- | --- |
| `1, 2, 3, …` | 1-based ordinal of the queued message in this call |
| `-1` | bad recipient length, negative pointer, unreadable memory, or payload too large |
| `-2` | negative value, or insufficient contract balance |
| `-3` | outbound message cap reached (64 per call) |

Fuel is **100** flat on the legacy path and `100 + payload_len` on the hardened path
(`FUEL_SEND_MESSAGE_PER_BYTE = 1`). A rejected message still costs 100 fuel: the hardened path
charges the base price before returning `-1`, and the legacy path charges before validating.

::: warning A queued message is not a synchronous call
`send_message` only appends to the call's outbound list. There is no reentrancy: a contract cannot
observe the recipient's state or return value, and a self-addressed message is not executed inline.
If the call later traps, the queued messages are discarded along with the balance debit.
:::

Messages are routed by the state engine after a successful call, including cross-shard routing.
The message id is `sha256(sender || recipient || value_be || payload || ordinal_be)`.

## Pointer safety: fail closed

Every pointer-taking host function validates memory access before reading or writing:

```rust
if ptr < 0 { return Err("memory pointer out of bounds: negative pointer"); }
let end = offset.checked_add(len).ok_or("memory pointer overflow")?;
if end > mem.data(&*caller).len() { return Err("memory access out of bounds"); }
```

Therefore:

| Situation | Result |
| --- | --- |
| Negative pointer (`i32` interpreted as signed) | trap |
| `ptr + len` overflows `usize` | trap |
| Range extends past linear memory | trap |
| Exported memory missing | trap (`contract memory not exported`) |
| Length exceeds a hard cap (hash input, return data, falcon leg) | trap |

`send_message` is the deliberate exception: because it returns an error code instead of trapping,
its pointer/length problems return `-1`. This lets a contract handle a bad message gracefully
without reverting the whole call. The trade-off is that a contract must check the return value.

::: danger Out-of-bounds is never "read something else"
The host never clamps, wraps or reads host memory. A wild pointer traps (or returns `-1` for
`send_message`). There is no way to escape the sandbox through a pointer bug, only to fail the
call.
:::

## Fuel accounting example

A call that does one `sload`, one `sstore`, one `emit`, one `sha256` over 64 bytes and one
`caller` costs at least:

```text
sload      10
sstore    100
emit       50
caller     10
sha256     30 + 64 + 32 = 126
--------------------------
host total 296 fuel
```

Per-instruction wasm fuel is charged on top of these host prices. The sender pays the opcode gas (`1,000 + 10/arg + 2/byte`), and the wasm fuel is bounded by the remaining gas; see [Execution model](/contracts/execution-model) for the full budget model.

## Next

Read [ABI manifest and wire format](/contracts/abi) for typed calls, then [Deploying and calling contracts](/contracts/deploy-and-call) for the transaction path.
