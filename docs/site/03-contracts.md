# Contracts

Lifecycle: `WAT → compile → deploy → call → query → events →
verify-source → upgrade (redeploy)`. Engine: `wasmi`, pure `(i64)→i64`
functions, no float, no imports outside the host list (`src/contract.rs`
header). Limits: ≤ 8 call args, 4 096 storage keys, 256 events, 64
outbound messages, 64 KiB return data, 5 M fuel cap on reads
(`src/contract.rs:50,91–97`, `GET_METHOD_SAFETY_FUEL_LIMIT`).

## Minimal WAT

Only the 14 `host.*` imports below resolve; anything else fails deploy
with `contract imports something the host does not provide`. Full working
example: `stellereum/contracts/sts20_token.wat` (slots for supply/tax/treasury,
topics 1/2/3 = Transfer/Mint/Burn):

```wat
(module
  (import "host" "sload"  (func $sload  (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit"   (func $emit   (param i64 i64)))
  (func (export "total_supply") (param $d i64) (result i64)
    (call $sload (i64.const 0))))
```

Compile with `wat2wasm`, hex-encode the wasm, and get a deploy **preview**
(address prediction + code validation) with:

```sh
rpc stell_deployContract '{"sender":"<hex>","code":"<hex>","abi":{…}}'
```

`stell_deployContract` is a **preview**: it validates the code and predicts
`contract_address(tx.from, tx.nonce)` from the explicit `sender` (with an
optional `nonce`; without `sender` it answers `predicted:false` and a null
address). It deploys nothing, files no receipt and never enters the mempool
(`src/rpc/contracts.rs`). A contract exists only after a block applies a signed
`SysCallDeployContract` transaction submitted via `stell_sendRawTransaction`.

The SDK now has deploy builders: `TxBuilder::contract_deploy(code)` mints
`SysCallDeployContract` (discriminant 19) and
`TxBuilder::contract_deploy_with_abi(code, abi_json)` mints
`SysCallDeployContractWithAbi` (discriminant 65); both are self-addressed with
`amount == 0`. The CLI equivalent is `stellereum contract deploy --wasm-file
<path> --falcon-seed-file <seed> --rpc $RPC` (plain opcode only — there is no
`--abi` flag). See the Rust SDK README for the wire layout and gas.

- TODO: pin the exact `wat2wasm` version and a live deploy receipt.
  Verify: `which wat2wasm; rpc stell_sendRawTransaction …` then
  `rpc stell_getTransactionReceipt …`.

## Calls, queries, events

- **Call preview (not a write):** `stell_callContract
  {"contract":"<hex>","method":"<name>","args":[…],"caller":"<hex>","value":…}`
  — `contract`/`address`, `args`/`arg` aliases; missing `args` = legacy
  single `0`. `caller` is **required** on the direct form; `from` and
  `private_key` are refused with `-32602` (the node cannot sign as the caller).
  Auth-token gated. It executes on a **clone** of the registry, returns the
  result, and DROPS the tx: it never enters the mempool and never changes live
  state (`src/rpc/contracts.rs`). To persist a call, sign the same payload
  locally and submit it via `stell_sendRawTransaction`.
- **Query (reads):** `stell_runGetMethod {"contract":…,"method":…,
  "args":…}` — same rule as fees/topology for shard reporting
  (`shard`, `local_shard`, `shard_is_local`); never fabricates another
  shard's state.
- **Events:** `stell_getEvents {"tx_hash":"…"}` or `{"contract":"…"}`;
  items `{contract, contract_stl57, topic, value}`, where `topic` and `value`
  are **numeric `i64`** values (event topics are integers, not strings).
  Receipts also carry `events`, `return_value`, `gas_used`,
  `contract_address(+_stl57)`.
- **Verify source:** `stell_verifyContractSource` recompiles claimed
  `.wat` (`source`/`source_hex`/`source_hash`) and compares;
  `stell_registerContractSource` records it and requires the creator's
  **Falcon-512 (PQ1)** signature (64-byte classical/Ed25519 signatures are
  refused); `stell_getContractSource`, `stell_getContractAbi`,
  `stell_getContractReceipt` read back (`src/rpc/`).
- **Upgrade = redeploy.** No in-place upgrade opcode exists; ship a new
  contract (new address) and migrate state explicitly. There is no pause
  RPC/opcode either: `ContractRegistry::pause` exists at the engine level but
  nothing reachable from RPC or a transaction calls it (and there is no
  unpause), so `ContractError::Paused` is not reachable on a live contract.

## ABI manifest

The `stell_deployContract` **preview** accepts an optional `abi` param
(`parse_abi_manifest_param`, `src/rpc/`), and the same manifest can travel
on-chain through the gated `SysCallDeployContractWithAbi` opcode below. The
manifest type lives in `src/contract_abi.rs` (`ContractAbi{methods,events}`).
Full example:

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

A previewed call whose args do not match the manifest fails with
`call does not match the contract ABI: …`. View methods must not mutate.

**ABI: preview plus a gated consensus opcode, INERT today.**
`SysCallDeployContract { code }` has no ABI field: block application calls
`deploy_with_nonce(creator, code, nonce, now)` and commits no manifest.
`SysCallDeployContractWithAbi { code, abi_json }` (discriminant 65) does
persist the parsed `ContractAbi` in the registry, but only when
`chain_spec::contract_abi_onchain_active_at(height)` is true. The compiled
`CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT` is `u64::MAX`, and that helper returns
`false` for **every** height — including `u64::MAX` — when the gate is
`u64::MAX` (`GatedOff`). On today's chain the opcode therefore reverts at
apply with `SysCallDeployContractWithAbi inactive at height <h>`. A plain
`SysCallDeployContract` deploy commits no manifest, so `stell_getContractAbi`
answers `abi: null` (no RPC sets an ABI out-of-band either:
`ContractRegistry::set_contract_abi` has no caller).

`stell_deployContract` accepts a signed `tx` carrying either opcode. For the
ABI variant it checks `abi_json.len() <= svm::MAX_CONTRACT_ABI_BYTES` (64 KiB),
that the bytes are UTF-8, and that `ContractAbi::from_json` validates; the
preview response reports `has_abi: true`/`false`. That check is read-only: the
preview deploys nothing, files no receipt, and does not consult the activation
gate, so it can report success for a transaction that would revert at apply.

Deploy gas (`svm.rs`): `contract_deploy_gas(n) = 2_000 + 2n` and
`contract_deploy_with_abi_gas(c, a) = contract_deploy_gas(c) + 2 *
min(a, 65_536)`.

On the signed path `SysCallCallContract` / `SysCallCallContractArgs` pass raw
calldata to wasm — the manifest is **not** enforced. Only the previews
(`stell_callContract` direct form, `stell_runGetMethod`) consult the engine
ABI, so a preview can reject a call that a hand-built signed transaction would
still execute.

The manifest validator (`MAX_ABI_ARGS`) accepts at most **8** declared
parameters, matching the VM's `MAX_CONTRACT_CALL_ARGS` (8 `i64`). A 9-parameter
method is refused at manifest validation instead of validating and then
failing at execution. Each `bytes`/`string` blob is capped at 1 MiB in the
codec, but signed-path call calldata is capped at 64 KiB
(`MAX_CONTRACT_CALLDATA_BYTES`), so 64 KiB is the practical limit.

## Host functions (all 14) and fuel

From `host_linker` (`stellereum/src/contract.rs:2391–2729`) and the `FUEL_*` consts:

| Import | Signature | Fuel |
| --- | --- | --- |
| `host.sload` | `(key:i64)→i64` | 10 (`FUEL_SLOAD`) |
| `host.sstore` | `(key,val)` | 100 (`FUEL_SSTORE`) |
| `host.emit` | `(topic,val)` | 50 (`FUEL_EMIT`) |
| `host.caller` | `(dest_ptr)` writes 32 B | 10 (`FUEL_CALLER`) |
| `host.origin` | `(dest_ptr)` writes 32 B; `tx.from` on the hardened path, falls back to `caller` on the legacy path | 10 (`FUEL_CALLER`) |
| `host.value` | `()→i64` | 5 (`FUEL_VALUE`) |
| `host.block_time` | `()→i64` (block's clock) | 5 (`FUEL_BLOCK_TIME`) |
| `host.block_hash` | `(dest_ptr)` writes 32 B (`block.prev_hash` when `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT` is active, else `[0; 32]`) | 10 (`FUEL_BLOCK_HASH`) |
| `host.calldata` | `(dest_ptr)→len` | 20 + 1/byte (`FUEL_CALLDATA`) |
| `host.return_data` | `(ptr,len)` (max 64 KiB) | 10 + 1/byte (`FUEL_RETURN_DATA_BASE`) |
| `host.sha256` | `(src,len,dst)` | 30 + 1/byte + 32 (`FUEL_SHA256_BASE`) |
| `host.blake3` | `(src,len,dst)` | 20 + 1/byte + 32 (`FUEL_BLAKE3_BASE`) |
| `host.falcon512_verify` | `(msg,mlen,pk,pklen,sig,siglen)→0/1` | 2000 + mlen + pklen + siglen (`FUEL_FALCON512_VERIFY`, or 150 000 base under `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT`) |
| `host.send_message` | `(rcpt_ptr,32,val,payload_ptr,len,bounce)→id/neg` (`-1` bad ptr/len/mem, `-2` insufficient balance, `-3` >64 msgs) | 100 (`FUEL_SEND_MESSAGE`, +1/byte payload on hardened path) |

Fuel is charged **before** the effect; `send_message` returns negative
codes (not traps) on bad recipient/funds/caps. OOB pointers are
fail-closed (P5 regression test in `src/contract.rs`).

**`stellereum-contract-sdk` wrappers (`stellereum-contracts/crates/stellereum-contract-sdk/`):**
provides safe `no_std` Rust bindings (`sload`, `sstore`, `emit`, `caller`,
`value`, `block_time`), storage helpers (`StorageItem`, `StorageMap`), demo id
auth helpers (`id_to_caller`, `caller_is`), and `setup_wasm_panic_handler!()`.
The remaining 8 host imports (`origin`, `block_hash`, `calldata`, `return_data`,
`sha256`, `blake3`, `falcon512_verify`, `send_message`) can be imported
directly from `"host"` via `extern "C"` or WAT when needed.

## Reference contracts: legacy and PQ entrypoints

All four crates in `stellereum-contracts/contracts/` (`sts20-token`,
`liquidity-pool`, `account-object`, `stl-dns`) keep their original
packed-`i64` entrypoints (still **DEMO-GRADE**, integer account ids bound to
`host.caller` through `caller_is`) and add production-shape `*_pq`
entrypoints. The `*_pq` ones:

- authorize the mover through the real 32-byte transaction sender
  (`host.caller()`); a caller-supplied `from`/`owner` field is data, never a
  substitute for that check, and integer ids are gone;
- read typed parameters from `host.calldata()` and require an exact byte
  length (`ERR_INVALID_ARGUMENT` otherwise) wherever parameters exist;
- write typed results through `host.return_data()` (max 64 KiB) where a result
  is returned.

`calldata` is the verbatim `SysCallCallContractArgs.calldata` blob. The typed
call helpers elsewhere in the tree (`TxBuilder::contract_call`,
`client.contractCall`, `stellereum contract call --args`) ABI-encode their
arguments as `u32 LE count || (tag || payload)*`, so they do **not** produce the
raw layouts below. A `*_pq` call must carry these bytes raw in
`SysCallCallContractArgs.calldata`; there is no raw-calldata flag on
`stellereum contract call` and no raw-calldata helper in the JS SDK today.

All multi-byte integers below are unsigned little-endian (`8B LE u64`) unless
stated otherwise.

### `sts20-token`

Legacy (DEMO-GRADE): `init(initial_supply)`, `decimals`, `total_supply`,
`balance_of(account)`, `allowance(owner*1_000_000 + spender)`,
`approve(owner*10_000_000_000 + spender*100_000 + amount)`,
`transfer(from*100_000_000 + to*100_000 + amount)`,
`transfer_from(spender*100_000_000_000 + from*10_000_000 + to*100_000 + amount)`,
`mint(arg)` / `burn(arg)` (raw amount or `admin*10_000_000_000 + amount`).

| PQ method | `calldata()` | `return_data` | Notes |
| --- | --- | --- | --- |
| `init_pq` | `initial_supply` (8B) | `initial_supply` (8B) | `caller()` becomes admin and treasury; once only (`ERR_ALREADY_EXISTS`). |
| `balance_of_pq` | `account` (32B) | `balance` (8B) | zero address reads 0. |
| `allowance_pq` | `owner` (32B) `\|\|` `spender` (32B) | `allowance` (8B) | 64-byte blob. |
| `approve_pq` | `spender` (32B) `\|\|` `amount` (8B) | `amount` (8B) | 40 bytes; owner is `caller()`. |
| `transfer_pq` | `to` (32B) `\|\|` `amount` (8B) | `net` (8B); burn-to-`[0;32]`: `amount` (8B) | 40 bytes; 50 bps ceiling fee to treasury. |
| `transfer_from_pq` | `from` (32B) `\|\|` `to` (32B) `\|\|` `amount` (8B) | same as `transfer_pq` | 72 bytes; spender is `caller()`; allowance spent only on success. |
| `mint_pq` | `amount` (8B) | `new_balance` (8B) | admin `caller()` only. |
| `burn_pq` | `amount` (8B) | `new_balance` (8B) | burns the caller's own balance. |

### `liquidity-pool`

Legacy (DEMO-GRADE): `init(fee_bps)`, `get_reserve_a`, `get_reserve_b`,
`get_total_shares`, `shares_of(user_id)`,
`deposit(user*10_000_000_000 + amount_a*100_000 + amount_b)`,
`withdraw(user*1_000_000 + shares)`, `swap_quote`, `swap_quote_b_for_a`,
`swap_a_for_b`, `swap_b_for_a`.

| PQ method | `calldata()` | `return_data` | Notes |
| --- | --- | --- | --- |
| `shares_of_pq` | `owner` (32B) | `shares` (8B) | zero address reads 0. |
| `deposit_pq` | `amount_a` (8B) `\|\|` `amount_b` (8B) | `minted_shares` (8B) | 16 bytes; LP is `caller()`. |
| `withdraw_pq` | `shares` (8B) | `payout_a` (8B) `\|\|` `payout_b` (8B) | 8-byte calldata; the `i64` return is `payout_a`. |

### `account-object`

Legacy (DEMO-GRADE): `init(owner_id)`, `get_owner`, `get_guardian`,
`get_pending_owner`, `transfer_ownership`, `rotate_guardian`,
`initiate_recovery`, `cancel_recovery`, `finalize_recovery`, `set_tenant`,
`revoke_rental`, `get_active_tenant`, `is_rental_active`, `create_session`,
`update_session_budget`, `spend_with_session`, `revoke_session`,
`is_session_active`, `get_session_budget`.

| PQ method | `calldata()` | `return_data` | Notes |
| --- | --- | --- | --- |
| `init_pq` | empty | `owner` (32B) | `caller()` becomes the 32-byte owner; once only. |
| `get_owner_pq` | empty | `owner` (32B) | returns `1` if set, `0` otherwise. |
| `create_session_pq` | `session_id` (8B) `\|\|` `delegate` (32B) `\|\|` `budget` (8B) | `session_id` (8B) | 48 bytes; owner `caller()` only. |
| `spend_with_session_pq` | `session_id` (8B) `\|\|` `amount` (8B) | `remaining` (8B) | 16 bytes; `caller()` must be the session delegate or the owner. |
| `revoke_session_pq` | `session_id` (8B) | — (empty) | 8 bytes; delegate or owner `caller()`; terminal tombstone. |
| `get_session_budget_pq` | `session_id` (8B) | `remaining` (8B) | 8 bytes. |
| `is_session_active_pq` | `session_id` (8B) | — (empty) | 8 bytes; returns `1`/`0`. |

### `stl-dns`

Legacy (DEMO-GRADE): `init(treasury_account)`, `get_min_bid(name_len)`,
`get_hue(domain_id)`, `start_auction(...)`, `place_bid(...)`,
`finalize_auction(domain_id)`, `resolve(domain_id)`, `set_target(...)`,
`transfer(...)`.

| PQ method | `calldata()` | `return_data` | Notes |
| --- | --- | --- | --- |
| `init_pq` | empty | `treasury` (32B) | `caller()` becomes the PQ treasury; once only. |
| `start_auction_pq` | `domain_id` (8B) `\|\|` `name_len` (8B) | `end_time` (8B) | 16 bytes; `name_len` must be 4..=126; duration is `AUCTION_DURATION_SECS = 3600`; returns `domain_id`. |
| `place_bid_pq` | `domain_id` (8B) **or** `domain_id` (8B) `\|\|` `bid_amount` (8B) | `new_bid` (8B) | 8 or 16 bytes; 10% minimum raise; `ERR_EXPIRED` at/after `end_time`. |
| `finalize_auction_pq` | `domain_id` (8B) | `winner` (32B) | 8 bytes; only at/after `end_time`; permissionless. |
| `resolve_pq` | `domain_id` (8B) | resolved target (32B) or 32 zero bytes | 8 bytes; returns `1`/`0`. |
| `set_target_pq` | `domain_id` (8B) `\|\|` `new_target` (32B) | `new_target` (32B) | 40 bytes; owner or protocol treasury `caller()`. |
| `transfer_pq` | `domain_id` (8B) `\|\|` `new_owner` (32B) | `new_owner` (32B) | 40 bytes; owner or protocol treasury `caller()`. |

The cross-contract end-to-end proof for these entrypoints is
`stellereum-contracts/crates/e2e-tests/tests/w9_pq_contract_auth_tests.rs`; it
deploys each crate, drives the same human wallet through owner/delegate/stranger
roles, and asserts the exact `ERR_*` codes on forged calls.

## Error registry

There is **no stable numeric error-code registry** — contract failures are
`ContractError` display strings (`stellereum/src/contract.rs:327–368`) plus RPC
envelope codes (`-32602` bad params, `-32000` chain/mempool,
`-32003` refused-by-state, `-32004` not-available; `docs/RPC.md` §1):

`contract code must not be empty` · `contract code exceeds the maximum
size` · `contract code is not a valid wasm module` · `contract already
exists` · `contract not found` · `contract is paused` · `contract does
not export the requested method` · `contract ran out of fuel` ·
`contract trapped during execution` · `contract id space exhausted` ·
`contract imports something the host does not provide` ·
`invalid contract ABI manifest: …` · `call does not match the contract
ABI: …`.

(Host traps on storage/event caps — `"contract storage limit exceeded"` at
4,096 keys and `"contract event limit exceeded"` at 256 events — are internal
`wasmi::Error` traps inside `host_linker` that surface to callers as
`ContractError::Trapped` / `"contract trapped during execution"`, not separate
`ContractError` variants.)

Proposal: if a registry is wanted, assign `STELL_Cxxxx` numbers to exactly
these strings and serve them in receipts — TODO, no code does this today.
Verify: `rg -n "ContractError" stellereum/src/contract.rs`.
