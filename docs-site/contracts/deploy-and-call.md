---
title: Deploying and calling contracts
description: The difference between the deploy/call previews and a real signed transaction, the exact opcode payloads, and the read/query/receipt RPCs.
---

# Deploying and calling contracts

Deploying and calling a contract has two paths that look similar and behave differently: the preview RPCs validate and simulate on a clone, while a signed transaction is what actually changes state. This page separates the two, gives the exact opcode payloads, and shows how to read the result back.

::: danger Previews do not change state
`stell_deployContract` and `stell_callContract` are **previews**. They validate code, simulate
execution on a clone of the contract registry, and return a result. They **never** enter the
mempool, never gossip, never write a receipt, and never touch live state. A successful preview is
not a deployment and not an inclusion.

State changes only when a block applies a signed transaction submitted through
`stell_sendRawTransaction`:

| Want to… | Submit |
| --- | --- |
| deploy | a signed transaction whose payload contains `SysCallDeployContract { code }` |
| call, one argument | `SysCallCallContract { contract, method, arg }` |
| call, several args + blobs | `SysCallCallContractArgs { contract, method, args, calldata }` |
:::

The previews are still useful: they are the cheapest way to catch invalid wasm, unresolvable
imports, bad ABI arguments, owner-guard mistakes and insufficient value before spending gas. Use
them as a dry run, then submit the real transaction.

## Choosing a path

| Goal | Method | State change | Token required |
| --- | --- | --- | --- |
| Validate wasm + predict address | `stell_deployContract` | no | **yes** |
| Simulate a call | `stell_callContract` | no | **yes** |
| Read a view method | `stell_runGetMethod` | no | no |
| Read events | `stell_getEvents` | no | no |
| Read a contract receipt | `stell_getContractReceipt` | no | no |
| Read ABI / source | `stell_getContractAbi`, `stell_getContractSource` | no | no |
| Estimate gas | `stell_estimateFee` | no | no |
| Deploy for real | `stell_sendRawTransaction` + `SysCallDeployContract` | **yes** | no (signature) |
| Call for real | `stell_sendRawTransaction` + `SysCallCallContract*` | **yes** | no (signature) |

The token gate on the two previews is the node's write-auth token
(`STELL_RPC_AUTH_TOKEN`, checked by `require_gov_write_auth`). It is a spam control, not a
consensus rule: it is enforced even on loopback, and a node with no token configured refuses the
previews entirely.

## Deploy: the preview

### Direct form

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "stell_deployContract",
  "params": {
    "sender": "0x<32-byte creator>",
    "code": "0x<hex wasm>",
    "abi": { "methods": [], "events": [] }
  }
}
```

- `code` — hex of the module, optional `0x`, at most 2 MiB.
- `sender` — the account whose `(address, nonce)` derives the predicted address. Without it the
  preview validates the code but returns `predicted: false` and a `null` address.
- `nonce` — optional; defaults to the sender's current account nonce.
- `abi` — optional manifest, validated and then discarded (see the warning below).

The arm does not execute the module or charge gas, so a `gas_limit` in this request is ignored.

`private_key` and `from` are **refused** with `-32602`. The node never signs as a user and never
accepts key material over RPC.

Response (abridged):

```json
{
  "contract_address": "<64 hex>",
  "contract_address_stl57": "Stl57…",
  "code_hash": "<64 hex>",
  "sender": "<64 hex>",
  "nonce": 7,
  "gas_estimate": "<2000 + 2 × code_len>",
  "predicted": true,
  "deployed": false,
  "preview_only": true,
  "tx_hash": null,
  "address_derivation": "contract_address(tx.from, tx.nonce)",
  "note": "prediction only: the contract exists once a block applies a signed SysCallDeployContract transaction from `sender` at `nonce`"
}
```

`gas_estimate` is the opcode price `2,000 + 2 × code_len`, not the full fee (the base fee and any
priority bid are separate).

### Signed-transaction form

If you already built and signed the deploy transaction, pass it to the preview for a full check:

```json
{ "method": "stell_deployContract", "params": { "tx": "0x<hex bincode(Transaction)>" } }
```

The arm verifies the transaction exactly like `stell_sendRawTransaction` (PQ envelope required,
signature checked), extracts `SysCallDeployContract`, validates the code, and predicts
`contract_address(tx.from, tx.nonce)`. It then **drops the transaction** — it is not admitted and
not gossiped. You must submit the same bytes yourself.

::: warning No deploy builder exists today
`stellereum-sdk` has `TxBuilder::contract_call` but **no** `TxBuilder::contract_deploy`, and its
`Op` enum has no deploy variant. The node's RPC comments mention a `TxBuilder::contract_deploy`
that does not exist in the SDK. To deploy today you must build the opcode payload yourself (see
below) or add the builder.

Also note the ABI gap: `SysCallDeployContract` carries **code only**, so an `abi` submitted to the
preview is not committed by block application. See [`/contracts/abi`](/contracts/abi).
:::

## Deploy: the real transaction

### Address derivation

```text
address = sha256("STELL_CONTRACT" || creator[32] || nonce_be_u64)
```

On the current chain the hardening activation height is **0**, so `nonce` is the **transaction
nonce** (`tx.nonce`) and the derivation is stable across nodes. On a pre-activation chain the
legacy path used the registry-global `contracts.next_nonce` instead; the preview still returns
`legacy_contract_address` and `legacy_next_nonce` in that case, but you should not target it for new
work.

The address depends only on creator and nonce, **not on the code**. Re-deploying different code at
the same `(creator, nonce)` is impossible because the nonce advances; the address is consumed once.

### Opcode shape

```rust
// stellereum/src/svm.rs
SysCallDeployContract {
    code: Vec<u8>,
}
```

Bincode encoding (the node uses bincode 1.3):

```text
Vec<T>      := u64_le(element_count) || elements
enum OpCode := u32_le(variant_ordinal) || fields
Vec<u8>     := u64_le(byte_len) || bytes
```

`SysCallDeployContract` is the 20th variant, ordinal **19** (`Nop = 0`, … , `SysCallStake = 21`,
which the SDK pins as `OP_STAKE`). So one deploy op is:

```text
19 00 00 00                 u32_le(19)
<len> 00 00 00 00 00 00 00   u64_le(code.len())
<code bytes>
```

A transaction payload is a `Vec<OpCode>`:

```text
01 00 00 00 00 00 00 00     one op
19 00 00 00                 SysCallDeployContract
<len> 00 00 00 00 00 00 00
<code>
```

### Transaction fields

`stell_sendRawTransaction` takes the bincode serialization of the node's `Transaction`, in this
field order:

```text
from           [u8; 32]
to             [u8; 32]
amount         u64
gas_limit      u64
nonce          u64
source_shard   u32
target_shard   u32
signature      Vec<u8>        (PQ1 envelope; priority bid travels inside it)
payload        Vec<OpCode>
```

For a deploy:

- `from` = creator (the signing key's address);
- `to` = creator (self-addressed; deploy ignores the recipient, so do not send value elsewhere);
- `amount` = 0;
- `nonce` = the account nonce the transaction will apply at;
- `gas_limit` ≥ deploy gas **and** the mempool's base-fee requirement;
- `payload` = the single `SysCallDeployContract` op.

The signature must be a post-quantum envelope. Classical 64-byte Ed25519 envelopes are refused at
intake. The signature covers the payload, so it cannot be swapped after signing.

::: tip Practical workflow
1. Build the transaction bytes with the exact layout above.
2. Call `stell_deployContract` with `{"tx": "<hex>"}` — it verifies the signature and code without
   touching state.
3. Submit the **same** bytes with `stell_sendRawTransaction`.
4. Watch `stell_getContractReceipt` / `stell_getTransactionStatus` until mined.
:::

## Call: the preview

### Direct form

```json
{
  "method": "stell_callContract",
  "params": {
    "contract": "0x<32-byte address>",
    "method": "transfer",
    "args": [2, 1000],
    "caller": "0x<32-byte caller>",
    "value": 0,
    "gas_limit": 50000000
  }
}
```

- `contract` (alias `address`), `method`, `args` (alias `arg`).
- `args` is a scalar or an array with one element per parameter. Missing `args` means the legacy
  single `0` argument.
- `caller` is **required** in the direct form. The node refuses to invent a zero or random caller,
  because a zero caller inverts every owner-guarded contract: owner checks would fail (false
  revert) and `caller == 0` checks would succeed (false success).
- `value` is simulated against a clone, including `insufficient funds to transfer value: …`.
- `private_key` and `from` are refused with `-32602`.

Response:

```json
{
  "tx_hash": null,
  "status": "success",
  "return_value": 1000,
  "gas_used": 1200,
  "events": [
    { "contract": "<64 hex>", "contract_stl57": "Stl57…", "topic": 2001, "value": 1000 }
  ],
  "preview_only": true,
  "mined": false,
  "outcome": {
    "status": "success",
    "return_value": 1000,
    "gas_used": 1200,
    "events": [ … ],
    "error": null
  }
}
```

`tx_hash` is `null` for the direct form because there is no transaction. `preview_only: true` and
`mined: false` are always present: a preview is never an inclusion.

### Signed-transaction form

```json
{ "method": "stell_callContract", "params": { "tx": "0x<hex>" } }
```

The arm verifies the transaction, extracts the first `SysCallCallContract` /
`SysCallCallContractArgs`, previews it with `tx.from` as the caller and `tx.amount` as the value
leg, and returns the outcome plus the transaction's real hash. It still does **not** admit it.

Status values are preview verdicts, not receipts. `"success"` means the clone executed without an
error; a negative `return_value` is still `"success"` because `ERR_*` codes are application-level
results, not reverts. A trap is `"failed"` with the `ContractError` string and empty events.

## Call: the real transaction

The SDK makes this straightforward. `TxBuilder::contract_call` builds
`SysCallCallContractArgs` with typed arguments, including the canonical ABI calldata:

```rust
use stellereum_sdk::prelude::{CallArg, FalconKeypair, TxBuilder};
use stellereum_sdk::rpc::RetryPolicy;
use stellereum_sdk::Wallet;

let key = FalconKeypair::generate()?;            // load your real key in production
let mut wallet = Wallet::connect(key, "http://127.0.0.1:8545");

let signed = wallet.contract_call(
    contract,
    "transfer",
    &[
        CallArg::Address(to_address),
        CallArg::U64(1_000),
    ],
    0,                                            // native value in nano-STELL
)?;

wallet.submit(&signed, &RetryPolicy::default())?;
```

`wallet.contract_call` fills the nonce, chain id, base fee and gas limit, then signs. The node CLI
offers `sign-typed-data` for a human-readable structured signature over
`{contract, method, args, value, nonce, chain_id}`, but that is a signing aid, not a transaction
builder: there is no CLI subcommand that assembles a deploy or call payload today.

For manual control:

```rust
let signed = TxBuilder::contract_call(contract, "transfer", &args, 0)?
    .nonce(nonce)
    .gas_limit(5_000_000)
    .sign(&key)?;

let hex = signed.to_hex();      // pass to stell_sendRawTransaction as {"tx": hex}
```

On-chain, the SDK builds:

```rust
SysCallCallContractArgs {
    contract: [u8; 32],
    method:   Vec<u8>,      // UTF-8, max 256 bytes
    args:     Vec<i64>,     // one per parameter, max 8
    calldata: Vec<u8>,      // ABI args payload, max 64 KiB
}
```

`Op::call` fills `args` by projecting each typed `CallArg` to `i64` (blobs become `0`) and
`calldata` with `encode_calldata(args)`. Block application forwards that `calldata` to the contract
unchanged; it does not re-encode from the manifest. The direct `stell_callContract` preview does
encode from the manifest when one is attached, and for the same values both encodings are
byte-identical.

In the **signed-transaction** preview form the manifest is not consulted at all: the arm executes
the exact `args`/`calldata` in the payload. A manifest is a client-side contract, not a consensus
check (see [`/contracts/abi`](/contracts/abi)).

For legacy single-integer calls there is `SysCallCallContract { contract, method, arg: i64 }`
(ordinal 20). `SysCallCallContractArgs` is ordinal 50, pinned by the SDK's parity tests.

::: warning Value semantics
`tx.amount` is credited to `tx.to` by block application. For a call, set `to = contract` if you
want the contract to receive the value. The contract does **not** see that amount through
`host.value()` — it is always `0` on the block path. Design your accounting accordingly.
:::

## Handling failures

| Failure | Where it appears |
| --- | --- |
| Bad signature / classical envelope | `stell_sendRawTransaction` → `-32000`, never enters the pool |
| Nonce gap / insufficient funds | `stell_sendRawTransaction` → `-32000 "rejected: …"` |
| Invalid wasm / unresolvable import | block application reverts the deploy; preview returns `deploy contract failed: …` |
| Contract traps | receipt `status: "failed"`, gas consumed, no state change |
| Out of fuel | receipt `status: "failed"`, gas consumed (a preview reports `gas_used = gas_limit`) |
| Paused contract | receipt `status: "failed"` with `contract is paused` |
| Negative `ERR_*` return | receipt `status: "success"` with a negative `return_value` |

Admission is not finality. A stale nonce can be accepted into the mempool and then skipped by the
producer. Poll `stell_getTransactionStatus` or `stell_getContractReceipt` rather than assuming that
a successful submission means inclusion.

## Reads

### `stell_runGetMethod`

The only read-only execution path. No token, no gas, no state change.

```json
{
  "method": "stell_runGetMethod",
  "params": {
    "address": "0x<32-byte contract>",
    "method": "balance_of",
    "args": [7],
    "fuel": 1000000,
    "height": 12345
  }
}
```

```json
{
  "success": true,
  "return_value": 42,
  "return_bytes": "000000000000002a",
  "return_typed": 42,
  "fuel_used": 1200,
  "events": [],
  "error": null,
  "shard": 1,
  "local_shard": 0,
  "shard_is_local": false
}
```

- Executes against a cloned working state; storage writes and balance changes are discarded.
- `fuel` is clamped to **5,000,000** (`GET_METHOD_SAFETY_FUEL_LIMIT`); the default is the same.
- `height` above the node's finalized height is refused. A height at or below the tip is served
  from current state (the node keeps no historical state).
- With a manifest, `return_typed` carries the declared return type; without one, only
  `return_value` + `return_bytes`.
- The call context is zeroed: `caller = 0`, `value = 0`, `block_time = 0`, `block_hash = 0`. Do not
  use getters for caller-dependent authorization questions.
- **Failures are answers**: `{"success": false, "error": "…", "fuel_used": N}` with HTTP 200. Only
  malformed JSON is an RPC-level error.

### `stell_getEvents`

Two forms.

By transaction:

```json
{ "method": "stell_getEvents", "params": { "tx_hash": "0x<64 hex>" } }
```

By contract and range:

```json
{
  "method": "stell_getEvents",
  "params": {
    "contract": "0x<address>",
    "from_block": 100,
    "to_block": 200,
    "topic": 2001,
    "limit": 100
  }
}
```

The answer is always an array of:

```json
{ "contract": "<64 hex>", "contract_stl57": "Stl57…", "topic": 2001, "value": 1000 }
```

`topic` and `value` are **integers**. An unknown transaction is an empty array, not an error. The
answer cap is **1,000** events (`MAX_EVENTS_RETURNED`); the array is truncated rather than returning
an error. There is no name decoding here — map topic constants to names with your ABI manifest.

### `stell_getContractReceipt`

```json
{ "method": "stell_getContractReceipt", "params": { "hash": "0x<64 hex>" } }
```

```json
{
  "status": "success",
  "return_value": 1000,
  "gas_used": 1200,
  "events": [ { "contract": "<64 hex>", "contract_stl57": "Stl57…", "topic": 2001, "value": 1000 } ],
  "tx_hash": "<64 hex>"
}
```

The contract-shaped receipt deliberately omits block height/index fields. An unknown hash answers
`{"status": "pending"}` if it is in the mempool, otherwise `{"status": "unknown"}`. Receipts exist
only for block-applied transactions; previews never file one.

For the full transaction receipt (block hash, height, index, fee fields), use
`stell_getTransactionReceipt`.

## `stell_estimateFee`

A read-only simulation with its own tight budget. It is the most expensive read on the node.

```json
{
  "method": "stell_estimateFee",
  "params": {
    "from": "0x<sender>",
    "to": "0x<contract>",
    "amount": 0,
    "method": "transfer",
    "args": [2, 1000]
  }
}
```

For a deploy, put the op in `payload`:

```json
{
  "params": {
    "from": "0x<creator>",
    "to": "0x<creator>",
    "amount": 0,
    "payload": [{ "SysCallDeployContract": { "code": "0x<hex>" } }]
  }
}
```

Or estimate a fully built transaction with `{"tx": "0x<hex>"}`.

Response fields include `gas_limit`, `estimated_fee`, `base_fee`, `source_shard`, `target_shard`,
`is_cross_shard`, `gas_budget` and `gas_ceiling`.

Bounds:

| Bound | Value |
| --- | --- |
| Simulation gas ceiling | **5,000,000** (`ESTIMATE_FEE_GAS_CEILING`), fixed |
| Minimum `max_gas` | **280,000** (`GAS_BASIC_TRANSFER`) |
| Per-IP rate limit | **5 req/s** by default |
| Request body | 1 MiB |

`max_gas` may only lower the budget; a value above the ceiling is refused with `-32602`, never
silently clamped. The simulation always runs at 5,000,000 unless you ask for less, regardless of a
transaction's declared `gas_limit`.

::: warning Estimate is approximate for multi-argument calls
When you pass `method` + `args`, the estimator builds a **single-argument**
`SysCallCallContract` using the first argument. That covers the common case but undercounts the
`10 gas/argument` and calldata legs of a multi-argument call. For an exact estimate, pass the fully
built transaction with `{"tx": …}` or an explicit `SysCallCallContractArgs` payload.
:::

## Fee arithmetic

| Component | Formula |
| --- | --- |
| Deploy opcode | `2,000 + 2 × code_len` |
| Call opcode | `1,000 + 10 × args_len + 2 × (method_len + calldata_len)` |
| Base fee floor | the node's current `stell_baseFee` (frozen floor 280,000) |
| Priority bid | optional, signed, must be covered by `gas_limit` |

The opcode price is charged at execution. `wasmi` fuel is bounded by the transaction's remaining
gas, so a contract cannot exceed the compute the sender paid for.

## Reading contract storage

`stell_getProgramAccounts` with `program: "contract"` returns a contract's slots:

```json
{
  "method": "stell_getProgramAccounts",
  "params": {
    "program": "contract",
    "contract": "0x<address>",
    "slot_from": 0,
    "slot_to": 100,
    "limit": 50
  }
}
```

Items are `{"program":"contract","contract":"…","slot":"…","value":"…"}` with slots sorted
numerically and a keyset `cursor`. This is the practical tool for **state migration** before an
upgrade. With `with_proof: true`, `proof` is `null` and a note explains that storage slots are
committed by the contract digest, not as individual trie leaves.

## Next

Read [Reference standards](/contracts/standards) for complete example contracts, then [Verification and upgrade](/contracts/verification-and-upgrade) for the migration path.
