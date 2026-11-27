# 60-minute developer loop

Goal: install → wallet → faucet drip → transfer → deploy preview →
call preview → query → events, against a local node. Every command below names the
binary/flag it was read from (`stellereum --help`, `wallet send --help`,
`docs/RPC.md`). Live-network outputs are marked TODO — verify with the
command given.

Helper used throughout (`docs/VALIDATOR_ONBOARDING.md` §0):

```sh
RPC=http://127.0.0.1:8545
# Optional: set TOKEN="$STELL_FAUCET_TOKEN" for stell_faucet, or
# TOKEN="$STELL_RPC_AUTH_TOKEN" for token-gated methods
# (e.g. stell_deployContract / stell_callContract).
rpc() {
  if [ -n "${TOKEN:-}" ]; then
    curl -s -X POST "$RPC" -H 'content-type: application/json' \
      -H "Authorization: Bearer $TOKEN" \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-\{\}}}"
  else
    curl -s -X POST "$RPC" -H 'content-type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-\{\}}}"
  fi
}
```

## 0. Install (5 min)

```sh
git clone https://github.com/immtes/stellereum.git
cd stellereum
cargo build --bin stellereum   # binary: target/debug/stellereum
./target/debug/stellereum --help
```

Expected: subcommands include `run sim devnet wallet contract orderbook oracle
bridge genesis pmm light-client network keys remote-signer` (`--help` lists
the rest). **If it fails:** needs Rust 1.75+; a bare
`cargo test` fails compiling examples (pre-existing) — use
`cargo test --lib --tests` (`README.md` Quick Start).

## 1. Wallet (5 min)

```sh
./target/debug/stellereum wallet generate
```

Prints two lines — a Falcon-512 address and the 32-byte hex private seed
(spendable directly by `wallet send` and `wallet send-pq`):

```text
• Address (Public Key):   <64 hex>
• Private Key:            <64 hex>
```

Save the private seed offline. **If it fails:** none known — it is pure local
keygen, no network. Other `stellereum wallet` subcommands (`wallet --help`):
`generate`, `balance`, `address`, `send`, `send-pq`, `unjail`,
`delegate-session`, `sign`, `verify`, `sign-typed-data`, `verify-typed-data`.

**`stellereum` vs `stell`:** `stellereum` is the node + operator/developer CLI
(running nodes, keys, governance, validator ops, and stateless `wallet` helpers).
`stell` is the separate user wallet & SPV light-client binary built from
`stell-wallet/` (`cargo build -p stell-wallet --bin stell`), providing encrypted
keystores (`~/.stellereum/wallet.json`), SPV balance verification, staking,
tokens, and interactive REPL mode.

## 2. Start a node (10 min)

Single-shard local node (flags from `run --help`: `--config`, `--shard`,
`--parallel-exec`, `--pure-pq`):

```sh
./target/debug/stellereum run --config config.yaml --shard 0
```

For a throwaway chain the in-process simulator is faster (no network):

```sh
./target/debug/stellereum sim --blocks 3
```

Expected: `Cluster initialized with 3 Validators`, per-block CLOB/MEV/zkML
lines, `Finalized in …ms` (`README.md` sample). **If the node exits with
`genesis state root mismatch`:** the data dir was created with different
`validators:`/`STELL_FAUCET_KEY`/binary — wipe `./data` on all nodes or
restore the original config (`OPERATIONS.md` §3). **If `Could not acquire
lock`:** an old process still holds `./data/store/db` — kill, wait ~20 s,
verify `pgrep -f "stellereum run"` is empty, restart (§7.2).

## 3. Faucet drip (5 min)

```sh
TOKEN="$STELL_FAUCET_TOKEN" rpc stell_faucet '{"address":"-1:<64-hex>"}'
```

Documented result shape (`docs/RPC.md` §4):
`{"credited_nano":"…","recipient":"…","tx_hash":"…","shard":…}`. Defaults:
**2 STELL drip** (`STELL_FAUCET_DRIP_STELL`), **50 STELL lifetime cap** per
address, 20 requests/hour/IP, gated by `STELL_FAUCET_TOKEN` (fail-closed).
The public (tokenless) widget route (`POST /api/faucet-public/:address`) also
drips **2 STELL** per **45-minute** per-address cooldown (same **50 STELL**
lifetime cap). Fund the **`-1:<hex>` masterchain form** for gas; a bare address
is a workchain address and never routes to shard 0. The faucet **cannot fund a
validator**: 50 STELL is the lifetime ceiling while a new bond needs 1,100
STELL, which comes from the Foundation on request or an operator transfer.

- TODO (live output): run the command against a faucet-enabled node and
  paste the real JSON. Verify: `curl … stell_faucet` above.
- **If `-32601 faucet is disabled`:** node lacks `STELL_FAUCET=1`.
- **If `-32000 faucet limit reached`:** the 50 STELL cap is spent.
- **If `-32000 … cannot serve an address on shard T`:** sharded faucet
  serves only its own shard — drip from that shard's faucet. Burns no nonce.

## 4. Transfer (10 min)

```sh
./target/debug/stellereum wallet send --from-key <hex-seed> \
  --to <64-hex> --amount 25000000000 --rpc $RPC
# Or using --falcon-seed / --falcon-seed-file / STELL_FALCON_SEED:
./target/debug/stellereum wallet send-pq --falcon-seed <hex-seed> \
  --to <64-hex> --amount 25000000000 --rpc $RPC
rpc stell_getBalance '{"address":"<64-hex>"}'
# → {"result":{"balance":"…","nonce":…}}  (decimal-string balance)
```

`--amount` is nano-STELL (1 STELL = 10⁹). Both `wallet send` and
`wallet send-pq` sign a Falcon-512 `PQ1` explicit-envelope transfer from the
32-byte hex seed (`--target-shard 0` by default). Watch inclusion, not just
submission:

```sh
rpc stell_getTransactionStatus '{"hash":"<64-hex>"}'
# → {"status":"success|failed|pending|unknown","height":…}
```

- TODO (live output): capture a real `success` receipt. Verify: commands above.
- **If `-32000 rejected: offered fee is below the base fee`:** raise
  `gas_limit` above `stell_baseFee`. **If `pending` forever:** the tx sits
  only in *this* node's mempool, or a nonce gap — check `stell_mempoolSize`.

## 5. Deploy a contract (10 min)

Write WAT using only the 14 `host.*` imports ([03-contracts](03-contracts.md));
minimal example is `stellereum/contracts/sts20_token.wat` (imports `host.sload`,
`host.sstore`, `host.emit`, `host.caller`). `stell_deployContract` is a
token-gated **preview** (address prediction + code validation using `"sender"`,
since `"from"` and `"private_key"` are refused with `-32602`); a real deploy is
a signed `SysCallDeployContract` tx submitted through `stell_sendRawTransaction`
or `stellereum contract deploy`:

```sh
# Preview only (requires STELL_RPC_AUTH_TOKEN on every bind, loopback included):
TOKEN="$STELL_RPC_AUTH_TOKEN" rpc stell_deployContract \
  '{"sender":"<hex>","code":"<hex-of-wasm>","abi":{…}}'

# Real deployment via CLI (signs SysCallDeployContract locally and submits;
# the flag is --wasm-file, and there is no --abi flag):
./target/debug/stellereum contract deploy \
  --wasm-file <path/to/contract.wasm> --falcon-seed-file <seed-file> --rpc $RPC

# Or submit a locally built & signed SysCallDeployContract transaction directly:
rpc stell_sendRawTransaction '{"tx":"<hex of signed bincode(Transaction)>"}'
```

- TODO (live output + minimal WAT→wasm toolchain): `wat2wasm` binary name
  and exact success JSON unverified. Verify: `which wat2wasm; rpc
  stell_sendRawTransaction …`.
- **If `-32602 missing 'code'`:** the field name is `code`, hex-encoded.
- **If `-32001 unauthorized`:** `stell_deployContract` requires `TOKEN="$STELL_RPC_AUTH_TOKEN"` even on loopback.
- **If `contract imports something the host does not provide`:** you
  imported outside the 14 host functions. **If `contract code exceeds the
  maximum size`:** shrink the module (limit in `src/contract.rs`).

**Deploy with an ABI (INERT on today's chain).** `SysCallDeployContractWithAbi`
(discriminant 65) is available through the SDKs —
`TxBuilder::contract_deploy_with_abi(code, abi_json)` in
[`stellereum-sdk`](../../stellereum-sdk/README.md#contract-deployment) and
`client.contractDeployWithAbi(code, abi)` in
[`sdk-js`](../../sdk-js/README.md#contract-deployment) — but
`CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT = u64::MAX`, which means gated off for
every height. The transaction signs and can be submitted like any other (subject
to the normal payload caps), then reverts at apply with
`SysCallDeployContractWithAbi inactive at height <h>`. The
`stellereum contract deploy` command has no `--abi` flag; use the plain opcode
and expect `stell_getContractAbi` to answer `null` (see
[03-contracts](03-contracts.md#abi-manifest)).

**Browser signing without a Node/CLI process.** Load `stellereum-wasm`
(`wasm32-unknown-unknown`) with `WasmFalconSigner` from `@stellereum/sdk`; it
needs `crypto.getRandomValues` for entropy and rewrites the Falcon signature
header to `0x29`. See
[sdk-js → Browser signing](../../sdk-js/README.md#browser-signing-wasmfalconsigner).
`SubprocessFalconSigner` / `HttpFalconSigner` remain the Node/CLI paths.

## 6. Call → query → events (10 min)

```sh
# Preview only (requires STELL_RPC_AUTH_TOKEN and explicit "caller"):
TOKEN="$STELL_RPC_AUTH_TOKEN" rpc stell_callContract \
  '{"contract":"<hex>","caller":"<hex>","method":"transfer","args":[1,2,500]}'

# Real state-changing call via CLI (signs a SysCallCallContract /
# SysCallCallContractArgs payload locally and submits). --args accepts one i64
# or a JSON array:
./target/debug/stellereum contract call \
  --contract <hex> --method transfer --args '[1,2,500]' \
  --falcon-seed-file <seed-file> --rpc $RPC

# Read-only getter (no auth token, 5M fuel cap):
rpc stell_runGetMethod '{"contract":"<hex>","method":"balance_of","args":[2]}'
rpc stell_getEvents '{"tx_hash":"<64-hex>"}'
# → [{"contract":"…","contract_stl57":"…","topic":…,"value":…}]
# events exist only for a tx a block applied; a call PREVIEW emits none
rpc stell_getTransactionReceipt '{"hash":"<64-hex>"}'
# after you submit a signed tx (not after a preview)
# → {"status":"success","height":…,"fee_charged":"…","return_value":…,"events":[…]}
```

`stell_callContract` is a **preview** (`STELL_RPC_AUTH_TOKEN`-gated on every
bind): it runs on a clone with `caller` and drops the tx, so no state changes.
`stell_runGetMethod` is the read-only path (5M fuel cap). To write, use
`stellereum contract call` or sign the same payload locally and submit via
`stell_sendRawTransaction`. Events are also queryable per contract:
`stell_getEvents '{"contract":"<hex>"}'`.

- TODO (live outputs): capture real call/query/events JSON. Verify: commands above.
- **If receipt is `{"status":"pending"}`:** still in this node's mempool
  only. **If `unknown`:** evicted or never seen here (receipt window:
  50 000 entries, oldest-first).

## 7. Next steps

Concepts ([02-concepts](02-concepts.md)) → contracts in depth
([03-contracts](03-contracts.md)) → staking ([04-validators](04-validators.md)).
