---
title: Writing contracts in WAT
description: A minimal WebAssembly text contract, the host imports it may use, how to compile and hex-encode it, and what the deploy preview validates.
---

# Writing contracts in WAT

WAT (WebAssembly Text) is the canonical source form for Stellereum contracts. It is what
`stell_verifyContractSource` rebuilds, and it is the easiest way to see exactly what the runtime
executes. A contract is an ordinary wasm module with exported `(i64, …) -> i64` functions.

## A minimal contract

```text
(module
  ;; Persistent storage: 10 fuel per read, 100 per write.
  (import "host" "sload"  (func $sload  (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit"   (func $emit   (param i64 i64)))

  ;; Exported so pointer-taking host functions can write into it.
  (memory (export "memory") 1)

  ;; answer() -> 42
  (func (export "answer") (result i64)
    (i64.const 42))

  ;; double(x) -> x * 2
  (func (export "double") (param $x i64) (result i64)
    (i64.mul (local.get $x) (i64.const 2)))

  ;; inc(key) -> sstore(key, sload(key) + 1); return the new value
  (func (export "inc") (param $key i64) (result i64)
    (local $next i64)
    (local.set $next
      (i64.add (call $sload (local.get $key)) (i64.const 1)))
    (call $sstore (local.get $key) (local.get $next))
    (call $emit (i64.const 1) (local.get $next))
    (local.get $next)))
```

That module uses three imports, exports one memory and three methods, and costs 10 fuel to read,
100 to write and 50 to emit, plus instruction fuel.

::: tip Export names are the API
`(export "inc")` is the method name clients pass to `stell_callContract` /
`SysCallCallContractArgs`. There is no selector-based dispatch for wasm exports; the name is
matched exactly, and the arity must match exactly.
:::

## Reading the caller

Pointer-taking host functions write into linear memory. A guarded transfer needs the authenticated
caller:

```text
(module
  (import "host" "caller" (func $caller (param i32)))
  (import "host" "sload"  (func $sload  (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (memory (export "memory") 1)

  ;; owner_word() -> first 8 bytes of host.caller, little-endian
  (func (export "owner_word") (result i64)
    (call $caller (i32.const 0))
    (i64.load (i32.const 0))))
```

`host.caller` writes 32 bytes and charges 10 fuel. It never fails for a valid 32-byte destination;
an out-of-bounds or negative pointer traps. There is no "who am I" argument you can trust from the
client — only this import is authenticated.

For the semantics of every import see [`/contracts/host-functions`](/contracts/host-functions).

## The import surface

Only imports from the module name `host` resolve. Anything else fails validation at deploy time
with `contract imports something the host does not provide`
(`ContractError::UnresolvableImports`). The host module exposes **14** functions:

| Import | WAT signature |
| --- | --- |
| `host.sload` | `(param i64) (result i64)` |
| `host.sstore` | `(param i64 i64)` |
| `host.emit` | `(param i64 i64)` |
| `host.caller` | `(param i32)` |
| `host.origin` | `(param i32)` |
| `host.value` | `(result i64)` |
| `host.block_time` | `(result i64)` |
| `host.block_hash` | `(param i32)` |
| `host.calldata` | `(param i32) (result i64)` |
| `host.sha256` | `(param i32 i32 i32)` |
| `host.blake3` | `(param i32 i32 i32)` |
| `host.falcon512_verify` | `(param i32 i32 i32 i32 i32 i32) (result i32)` |
| `host.return_data` | `(param i32 i32)` |
| `host.send_message` | `(param i64 i64 i64 i64 i64 i64) (result i64)` |

::: warning `ed25519_verify` no longer exists
It was removed, not stubbed. A module that imports it fails to deploy exactly like any other
unknown import, even if the signature bytes would have verified under the old host. Use
`falcon512_verify`.
:::

::: warning Older material says "13 imports"
That count predates `host.origin`, which was added with the hardened `>= H` execution path. The
linker registers 14 functions today. `origin` returns the transaction origin on the hardened path
and the immediate caller on the legacy path.
:::

## Bundled WAT examples

The node tree ships four hand-written modules in `stellereum/contracts/`:

| File | Shape |
| --- | --- |
| `sts20_token.wat` | token with `init`, `total_supply`, `balance_of`, `set_tax`, `transfer_direct(from, to, amount)`, `transfer(packed)`, `mint`, `burn` |
| `liquidity_pool.wat` | pool accounting methods |
| `account_object.wat` | account/session methods |
| `stl_domain_registry.wat` | name/auction methods |

They are useful for seeing multi-argument exports (`transfer_direct` takes three `i64`s) and
integer packing without the typed ABI. They are **not** the same source as the Rust reference
contracts in `stellereum-contracts/contracts/`; method sets differ. Verify whichever one you deploy
against its own hash.

## Compile

With [WABT](https://github.com/WebAssembly/wabt):

```sh
wat2wasm counter.wat -o counter.wasm
```

Validate and inspect:

```sh
wasm-validate counter.wasm
wasm-objdump -x counter.wasm | head -40
```

Hex-encode the bytes for the JSON-RPC `code` field:

```sh
# GNU coreutils / BSD xxd
xxd -p counter.wasm | tr -d '\n' > counter.hex

# or, without xxd
od -An -tx1 -v counter.wasm | tr -d ' \n' > counter.hex

wc -c counter.wasm
```

The deploy preview accepts an optional `0x` prefix.

::: danger WABT output is not necessarily the node's rebuild
Deploy accepts any valid wasm module, but source verification recompiles the submitted `.wat` with
the **Rust `wat` crate** (`wat::parse_str`), not with your local `wat2wasm`. Different encoders can
emit different (still semantically equivalent) binaries: section ordering, LEB128 widths, name
sections, custom sections. If the rebuilt bytes differ, `stell_verifyContractSource` answers
`verified: false` even though the source is honest.

Two safe options:

1. deploy the bytes produced by the same pipeline the node uses (the Rust `wat` crate), or
2. verify against the exact deployed binary and treat a mismatch as expected until the build
   pipeline is pinned.

The accepted `compiler` strings (`wat-1.0`, `wat2wasm-1.0`, `wat`, `wat2wasm`, `wast-1.0`) are
**labels for the node's pipeline**, not a promise to reproduce WABT's output.
:::

## Encode a 32-byte address in memory

Addresses are raw 32 bytes, not a string. To pass one to `send_message` or return one via
`return_data`, store it in eight `i64` words (or four `i64.store` pairs per 16 bytes) in
little-endian order:

```text
(i64.store (i32.const 0)  (i64.const 0x0102030405060708))
(i64.store (i32.const 8)  (i64.const 0x090a0b0c0d0e0f10))
(i64.store (i32.const 16) (i64.const 0x1112131415161718))
(i64.store (i32.const 24) (i64.const 0x191a1b1c1d1e1f20))
```

This is exactly what the runtime test module does before calling `host.send_message`. Remember that
RPC JSON displays addresses as `0x…` hex or Stl57, but the wasm side always sees bytes.

## Deploy preview

`stell_deployContract` validates and predicts; it never deploys. The direct form takes the code,
the sender whose nonce derives the address, and an optional ABI:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "stell_deployContract",
  "params": {
    "sender": "0x<32-byte-creator-address>",
    "code": "0x<hex of counter.wasm>"
  }
}
```

```json
{
  "result": {
    "contract_address": "<64 hex>",
    "contract_address_stl57": "Stl57…",
    "code_hash": "<64 hex>",
    "sender": "<64 hex>",
    "nonce": 7,
    "gas_estimate": 2000,
    "predicted": true,
    "deployed": false,
    "preview_only": true,
    "tx_hash": null,
    "address_derivation": "contract_address(tx.from, tx.nonce)",
    "note": "prediction only: the contract exists once a block applies a signed SysCallDeployContract transaction from `sender` at `nonce`"
  }
}
```

::: warning The preview is token-gated
`stell_deployContract` and `stell_callContract` require the node's write-auth token
(`STELL_RPC_AUTH_TOKEN`) on every bind. A node with no token configured refuses them. This is a
spam/abuse gate on the *preview*, not on consensus: real transactions are accepted through
`stell_sendRawTransaction`, which authenticates them by signature.
:::

### What the preview actually checks

In order, before answering:

1. **Presence and hex** of `code`.
2. **Non-empty code** (`EmptyCode`).
3. **Size** ≤ `MAX_CONTRACT_CODE_SIZE` = 2 MiB (`CodeTooLarge`).
4. **Memory declarations** — every declared memory minimum and maximum must be ≤ 128 pages; the
   parser walks the wasm memory section (`validate_memory_limits`).
5. **Module validity** — `wasmi::Module::new` must parse it (`InvalidWasm`).
6. **Import resolvability and `(start)` execution** — the module is instantiated against
   `host_linker` on a throwaway store. A missing import is `UnresolvableImports`; a trapping or
   runaway `(start)` section fails (hardened path gives it 5,000,000 fuel).
7. **Optional ABI** — `parse_abi_manifest_param` parses and validates the manifest; duplicate
   method/event names or more than 8 declared parameters are `-32602`.
8. **Address prediction** — `sha256("STELL_CONTRACT" || sender || nonce)`, with `nonce` taken from
   the request or the sender's current account nonce.
9. **Duplicate check** — if a contract already exists at the predicted address, the preview refuses
   with `deploy contract failed: contract already exists`.

It does **not** charge gas, write the trie, create a receipt, enter the mempool, or gossip
anything. The response says `deployed: false` and `preview_only: true` precisely because a preview
is not an inclusion.

To make it real, sign a `SysCallDeployContract` transaction and submit it with
`stell_sendRawTransaction`. The full recipe is in
[`/contracts/deploy-and-call`](/contracts/deploy-and-call).

## WAT contract checklist

- Imports only from `"host"`; unknown names fail deploy.
- Export `"memory"` if (and only if) you pass pointers to host functions.
- Every exported method returns `i64`; use `() -> i64` for constants.
- Bound loops; fuel will stop them, but a trapped call wastes the sender's gas.
- Stay under 128 memory pages (8 MiB), 4,096 storage keys, 256 events, 64 outbound messages and
  64 KiB of return data.
- Do not use floats. There is no float ABI type and no need for one.

## Next

Continue with [Host functions](/contracts/host-functions) for the exact import semantics, then [Deploying and calling contracts](/contracts/deploy-and-call) for the signed-transaction path.
