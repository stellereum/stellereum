---
title: ABI manifest and wire format
description: The STELL-ABI v1 JSON manifest, its typed values, the canonical binary encoding, and how the runtime maps typed arguments onto i64 wasm parameters.
---

# ABI manifest and wire format

A contract does not need an ABI manifest to be callable. Without one, every method is a name plus
zero to eight `i64` parameters, and clients pack values by hand. With a manifest, a contract
publishes a typed interface: method names, parameter names and types, return types, whether a
method mutates state, and event shapes. Clients can then validate and encode calls instead of
guessing.

::: warning Read this before relying on the manifest
The ABI **format** is stable, but the **deployment plumbing is incomplete**:

- `SysCallDeployContract { code }` carries **code only**. It has no ABI field, and block
  application calls `deploy_with_nonce(creator, code, nonce, now)` without a manifest.
- The `abi` parameter of `stell_deployContract` is parsed and validated by the preview, then
  discarded — the preview does not deploy and cannot persist it.
- The engine exposes `set_contract_abi`, but no RPC calls it.

Consequently, a contract deployed through the normal signed-transaction path has **no on-chain
manifest**, and `stell_getContractAbi` answers `abi: null`. The manifest still works in-process
(engine API, tests) and as a client-side schema you ship with your dApp. Treat this page as the
format specification plus a precise statement of what is wired today.
:::

## The manifest

```json
{
  "methods": [
    {
      "name": "balance_of",
      "params": [{ "name": "owner", "type": "address" }],
      "returns": "u64",
      "mutates_state": false
    },
    {
      "name": "transfer",
      "params": [
        { "name": "to", "type": "address" },
        { "name": "amount", "type": "u64" },
        { "name": "memo", "type": "string" }
      ],
      "returns": "bool",
      "mutates_state": true
    },
    {
      "name": "total_supply",
      "params": [],
      "returns": "i64",
      "mutates_state": false
    }
  ],
  "events": [
    {
      "name": "Transfer",
      "topics": [{ "name": "from", "type": "address" }],
      "data": [{ "name": "amount", "type": "u64" }]
    }
  ]
}
```

### Field reference

| Field | Required | Default | Notes |
| --- | --- | --- | --- |
| `methods[].name` | yes | — | Must be unique; matched exactly against the wasm export |
| `methods[].params[]` | no | `[]` | Ordered; at most **8** declared |
| `params[].name` | yes | — | Informational, used in RPC error messages |
| `params[].type` | yes | — | One of the seven type names; `ty` is accepted as an alias |
| `methods[].returns` | no | `i64` | A method returning nothing is modelled as `i64` + `0` |
| `methods[].mutates_state` | no | `false` | Metadata for clients/indexers; not enforced by the runtime |
| `events[].name` | yes | — | Must be unique |
| `events[].topics[]` | no | `[]` | Indexed fields, in order |
| `events[].data[]` | no | `[]` | Non-indexed fields, in order |

`type` is the serialized field name. The parser also accepts `ty` (the `AbiParam` deserializer has
`#[serde(rename = "type", alias = "ty")]`), which is why older examples use `"ty": "Address"`.
Both spellings parse; the node re-serializes as `"type"`.

The JSON may be a bare manifest or wrapped as `{"abi": { … }}`; both are accepted. Type names are
parsed case-insensitively and accept aliases (`int64`, `uint`, `boolean`, `byte[]`, `blob`, `hex`,
`addr`, `account`, `public_key`, `str`, `text`, …).

::: warning `mutates_state` is not a security boundary
A method declared `mutates_state: false` is still executed by `stell_runGetMethod` on a throwaway
clone — any writes it performs are discarded. A real transaction can still call it and persist
those writes. The flag tells clients what to expect; it does not restrict the contract.
:::

## Types

| Type | Tag | Wire payload | JSON form | Fits an `i64` wasm param? |
| --- | --- | --- | --- | --- |
| `i64` | `0x01` | 8 bytes, big-endian two's complement | number | yes |
| `u64` | `0x02` | 8 bytes, big-endian | number | yes (bit pattern) |
| `i32` | `0x03` | 4 bytes, big-endian two's complement | number | yes |
| `bool` | `0x04` | 1 byte, `0x00` / `0x01` | `true` / `false` | yes (`0`/`1`) |
| `bytes` | `0x05` | `u32_le(len) ‖ raw bytes` | `0x…` hex string or byte array | **no** — blob |
| `address` | `0x06` | 32 raw bytes | `0x…` 64-hex (Stl57 also accepted by RPC) | **no** — blob |
| `string` | `0x07` | `u32_le(len) ‖ UTF-8 bytes` | string | **no** — blob |

Type tags are **frozen forever**. New types would get new tags; existing tags are never
renumbered. Fixed-width integers are big-endian so the encoding never depends on the host
architecture.

A 32-byte `0x…` value in JSON is interpreted as an `address` by the generic `AbiValue` parser; a
shorter/longer hex blob is interpreted as `bytes`. The RPC typed path does **not** use that
heuristic — it converts according to the **declared** parameter type, so a 32-byte hex value for a
`bytes` parameter stays bytes. A JSON array of `0..=255` integers is also accepted as `bytes`.

## STELL-ABI v1 binary encoding

### Arguments

```text
args_payload := u32_le(arg_count) ‖ arg_0 ‖ arg_1 ‖ …
arg_i        := u8(type_tag) ‖ value_payload
```

Example — one `i64` argument `42`:

```text
01 00 00 00        arg_count = 1
01                 type tag I64
00 00 00 00 00 00 00 2a
```

That is 13 bytes. A method with two `i64` arguments yields `4 + 9 + 9 = 22` bytes.

### Calls and selectors

`ContractAbi::encode_call` prepends a selector:

```text
calldata := sha256(method_name)[0..4] ‖ args_payload
```

The selector is the **first four bytes of the SHA-256 digest in digest order**, also interpreted as
a `u32_le` when convenient. `decode_call` looks up a method by comparing those four bytes.

::: danger `host.calldata` does not contain the selector
The runtime hands the contract `args_payload` only — the output of `encode_args`, not
`encode_call`. This is intentional: the method is already a separate field in
`SysCallCallContractArgs`, so repeating a selector would waste calldata. The SDK's
`encode_calldata` also emits only `args_payload`. A contract that expects a leading selector will
misparse every call.

If a one-`i64` method reads `host.calldata` and returns the length, it must get **13**, not 17.
:::

### Return values

```text
return_value := u8(type_tag) ‖ value_payload
```

The runtime splits returns in two:

- scalar returns (`i64`, `u64`, `i32`, `bool`) come from the wasm `i64` result;
- blob returns (`bytes`, `address`, `string`) come from `host.return_data`.

`ContractAbi::decode_runtime_return` applies that rule. It does **not** expect a type tag on the
blob, and it does **not** expect a length prefix: `host.return_data` is the raw value.
`bytes` returns the whole blob, `string` is UTF-8-decoded from the whole blob, and `address` takes
the first 32 bytes.

The separate `ContractAbi::decode_return` utility is more forgiving: it accepts the canonical
tagged encoding, or a bare fixed-width scalar, or a length-prefixed `bytes`/`string`. That is a
client-side helper, not what the runtime does.

::: tip Rule of thumb
Write exactly the bytes you want the client to receive to `host.return_data`:
`return_data(ptr, 32)` for an address, raw UTF-8 for a string, raw bytes otherwise. Do not prepend
a tag or a length unless your off-chain decoder expects it.
:::

### Events

```text
event_payload := u32_le(topic_count) ‖ tagged topics
              ‖ u32_le(data_count)  ‖ tagged data
```

::: warning Events on chain are `(topic, value)` pairs
`host.emit` carries exactly two integers. The runtime does not call `encode_event`, and it does not
consult the manifest when emitting. `ContractAbi::encode_event` / `decode_event` are library
utilities for clients and indexers that want a richer off-chain representation; they are not the
on-chain event format today.

In practice an event's `topic` is a numeric constant chosen by the contract (for example STS-20
uses `2001` for `Transfer`), and `value` is a single packed or scalar amount. Declaring richer
`topics`/`data` in the manifest does not make the node emit them.
:::

::: danger The manifest is not enforced by consensus
ABI validation happens in the RPC/preview layer (`stell_callContract` direct form,
`stell_runGetMethod`, and the engine's `call_abi` methods). Block application of
`SysCallCallContract` / `SysCallCallContractArgs` passes the raw `args` and `calldata` straight to
the wasm export without consulting the manifest. A caller who builds a transaction by hand is not
stopped by the ABI, and the signed-tx preview form deliberately executes the exact payload.

Therefore: the manifest is a **client contract**, not a consensus rule. A contract must still
validate its own calldata (arity, lengths, tags, bounds) if malformed input could hurt it.
:::

## How typed arguments reach wasm

On the engine's typed-call path (`call_abi`, `run_get_method_typed`, and the direct
`stell_callContract` form), the runtime bridges the typed world to the integer calling convention
as follows:

1. Validate the call against the manifest: method exists, argument count matches, every argument
   has the declared type.
2. Encode the full `args_payload`.
3. For each declared parameter, produce one `i64` scalar:
   - scalar types use their numeric value;
   - blob types (`bytes`, `address`, `string`) become `0`.
4. Call the wasm export with those scalars, exact arity.
5. The contract reads blobs from `host.calldata` using the same `args_payload`.

A Rust entry point for the `transfer` example therefore looks like:

```rust
#[no_mangle]
pub extern "C" fn transfer(_to: i64, amount: i64, _memo: i64) -> i64 {
    // `_to` and `_memo` are 0 placeholders; the real values are in calldata.
    // Parse them with a small cursor over the blob returned by host.calldata.
    // ...
    amount
}
```

::: tip The manifest limit matches the VM
`MAX_ABI_ARGS` and `MAX_CONTRACT_CALL_ARGS` are both **8**. A manifest that declares a ninth
parameter is refused during validation, before any call is built. Keep callable methods at eight
parameters or fewer.
:::

## Call validation errors

`ContractRegistry::call_abi` / `run_get_method_typed` wrap ABI failures in
`ContractError::AbiMismatch`. The direct `stell_callContract` form reports them as
`-32602 "ABI validation failed: …"` (or `"ABI encoding failed: …"` for an encode error); the
getter returns the same text in its `error` field.

| Condition | Message |
| --- | --- |
| No manifest attached | `contract has no ABI manifest` |
| Method not declared | `unknown method: <name>` |
| Wrong argument count | `argument count mismatch for <m>: expected N, got M` |
| Wrong argument type | `type mismatch for <m> at index I: expected T, got U` |
| Value does not fit target type | `value does not fit into <type>` |
| Unknown tag on the wire | `unknown ABI type tag: 0x..` |
| Short buffer | `buffer too short: needed N bytes, got M` |
| Extra bytes | `N unexpected trailing bytes` |
| Invalid boolean byte | `invalid boolean byte: 0x..` |
| Invalid UTF-8 | `string payload is not valid UTF-8` |
| Blob too large | `blob length N exceeds the maximum` |
| Duplicate method/event, >8 params | `invalid ABI manifest: …` |

The same errors are available as `AbiError` variants for library users.

## Size limits

| Limit | Value | Where |
| --- | --- | --- |
| Declared parameters per method | 8 | `MAX_ABI_ARGS` |
| Single blob (`bytes`/`string`) | 1 MiB | `MAX_ABI_BLOB_LEN` |
| Calldata in one transaction | 64 KiB | `MAX_CONTRACT_CALLDATA_BYTES` (SVM) |
| Return blob | 64 KiB | `MAX_RETURN_DATA` |
| Method name | 256 bytes | `MAX_CONTRACT_METHOD_LEN` |

::: warning The blob limit is not the transaction limit
The encoder will happily build a 1 MiB blob, but `SysCallCallContractArgs` refuses calldata over
**64 KiB** before execution. A single blob parameter therefore cannot exceed 64 KiB minus the
4-byte count and tags. Design large payloads as multiple calls or as hashes plus off-chain data.
:::

## Discovery

If a manifest is attached in-process, `stell_getContractAbi` returns both a parsed object and the
raw committed JSON:

```json
{
  "contract": "<64 hex>",
  "contract_stl57": "Stl57…",
  "abi": { "methods": [], "events": [] },
  "abi_json": "{\"methods\":[],\"events\":[]}"
}
```

When no manifest exists, `abi` is `null` and `abi_json` is absent. Given the deployment gap above,
this is the expected answer for contracts deployed through the normal transaction path.

## Next

Continue with [Deploying and calling contracts](/contracts/deploy-and-call) for the signed-transaction path, or [Writing contracts in Rust](/contracts/rust) for calldata handling in the contract.
