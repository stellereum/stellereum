# Contracts

Lifecycle: `WAT → compile → deploy → call → query → events →
verify-source → upgrade (redeploy)`. Engine: `wasmi`, pure `(i64)→i64`
functions, no float, no imports outside the host list (`src/contract.rs`
header). Limits: ≤ 8 call args, 4 096 storage keys, 256 events, 64
outbound messages, 64 KiB return data, 5 M fuel cap on reads
(`src/contract.rs:50,91–97`, `GET_METHOD_SAFETY_FUEL_LIMIT`).

## Minimal WAT

Only the 13 `host.*` imports below resolve; anything else fails deploy
with `contract imports something the host does not provide`. Full working
example: `contracts/sts20_token.wat` (slots for supply/tax/treasury,
topics 1/2/3 = Transfer/Mint/Burn):

```wat
(module
  (import "host" "sload"  (func $sload  (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit"   (func $emit   (param i64 i64)))
  (func (export "total_supply") (param $d i64) (result i64)
    (call $sload (i64.const 0))))
```

Compile with `wat2wasm`, hex-encode the wasm, deploy:

```sh
rpc stell_deployContract '{"from":"<hex>","code":"<hex>","abi":{…}}'
```

- TODO: pin the exact `wat2wasm` version and a live deploy receipt.
  Verify: `which wat2wasm; rpc stell_deployContract …` then
  `rpc stell_getTransactionReceipt …`.

## Calls, queries, events

- **Call (writes):** `stell_callContract
  {"contract":"<hex>","method":"<name>","args":[…],"value":…}` —
  `contract`/`address`, `args`/`arg` aliases; missing `args` = legacy
  single `0`. Auth-token gated when configured; executes inline and
  admits a tx (`src/rpc.rs`).
- **Query (reads):** `stell_runGetMethod {"contract":…,"method":…,
  "args":…}` — same rule as fees/topology for shard reporting
  (`shard`, `local_shard`, `shard_is_local`); never fabricates another
  shard's state.
- **Events:** `stell_getEvents {"tx_hash":"…"}` or `{"contract":"…"}`;
  items `{contract, contract_stl57, topic, value}`. Receipts also carry
  `events`, `return_value`, `gas_used`, `contract_address(+_stl57)`.
- **Verify source:** `stell_verifyContractSource` recompiles claimed
  `.wat` (`source`/`source_hex`/`source_hash`) and compares;
  `stell_registerContractSource` records it (signed action);
  `stell_getContractSource`, `stell_getContractAbi`,
  `stell_getContractReceipt` read back (`src/rpc.rs`).
- **Upgrade = redeploy.** No in-place upgrade opcode exists; ship a new
  contract (new address), migrate state explicitly, pause the old one
  (`ContractError::Paused` exists for that path).

## ABI manifest

Optional `abi` param on deploy (`parse_abi_manifest_param`, `src/rpc.rs`);
typed in `src/contract_abi.rs` (`ContractAbi{methods,events}`). Full example:

```json
{"methods":[
  {"name":"transfer","params":[
    {"name":"to","ty":"Address"},{"name":"amount","ty":"U64"}],
   "returns":"U64","mutates_state":true},
  {"name":"balance_of","params":[
    {"name":"who","ty":"Address"}],
   "returns":"U64","mutates_state":false}],
 "events":[
  {"name":"Transfer","fields":[
    {"name":"amount","ty":"U64"}]}]}
```

A call whose args do not match the manifest fails with
`call does not match the contract ABI: …`. View methods must not mutate.

## Host functions (all 13) and fuel

From `host_linker` (`src/contract.rs:1152+`) and `FUEL_*` consts (`:99–132`):

| Import | Signature | Fuel |
| --- | --- | --- |
| `host.sload` | `(key:i64)→i64` | 10 |
| `host.sstore` | `(key,val)` | 100 |
| `host.emit` | `(topic,val)` | 50 |
| `host.caller` | `(dest_ptr)` writes 32 B | 10 |
| `host.value` | `()→i64` | 5 |
| `host.block_time` | `()→i64` (block's clock) | 5 |
| `host.block_hash` | `(dest_ptr)` writes 32 B | 10 |
| `host.calldata` | `(dest_ptr)→len` | 20 + 1/byte |
| `host.sha256` | `(src,len,dst)` | 30 + 1/byte + 32 |
| `host.blake3` | `(src,len,dst)` | 20 + 1/byte + 32 |
| `host.ed25519_verify` | `(pk,msg,mlen,sig)→0/1` | 500 + 32 + mlen + 64 |
| `host.return_data` | `(ptr,len)` | 10 + 1/byte |
| `host.send_message` | `(rcpt_ptr,32,val,payload_ptr,len,bounce)→id/neg` | 100 |

Fuel is charged **before** the effect; `send_message` returns negative
codes (not traps) on bad recipient/funds/caps. OOB pointers are
fail-closed (P5 regression test in `src/contract.rs`).

## Error registry

There is **no stable numeric error-code registry** — contract failures are
`ContractError` display strings (`src/contract.rs:164–196`) plus RPC
envelope codes (`-32602` bad params, `-32000` chain/mempool,
`-32003` refused-by-state, `-32004` not-available; `docs/RPC.md` §1):

`contract code must not be empty` · `contract code exceeds the maximum
size` · `contract code is not a valid wasm module` · `contract already
exists` · `contract not found` · `contract is paused` · `contract does
not export the requested method` · `contract ran out of fuel` ·
`contract trapped during execution` · `contract id space exhausted` ·
`contract imports something the host does not provide` ·
`invalid contract ABI manifest: …` · `call does not match the contract
ABI: …` · `contract storage limit exceeded` · `contract event limit
exceeded`.

Proposal: if a registry is wanted, assign `STELL_Cxxxx` numbers to exactly
these strings and serve them in receipts — TODO, no code does this today.
Verify: `rg -n "ContractError" src/contract.rs`.
