# 60-minute developer loop

Goal: install → wallet → faucet drip → transfer → deploy → call →
query → events, against a local node. Every command below names the
binary/flag it was read from (`stellereum --help`, `wallet send --help`,
`docs/RPC.md`). Live-network outputs are marked TODO — verify with the
command given.

Helper used throughout (`docs/VALIDATOR_ONBOARDING.md` §0):

```sh
RPC=http://127.0.0.1:8545
rpc() { curl -s -X POST "$RPC" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-\{\}}}"; }
```

## 0. Install (5 min)

```sh
git clone https://github.com/immtes/stellereum.git
cd stellereum
cargo build --bin stellereum   # binary: target/debug/stellereum
./target/debug/stellereum --help
```

Expected: subcommands `run sim wallet orderbook oracle bridge genesis pmm
light-client network keys`. **If it fails:** needs Rust 1.75+; a bare
`cargo test` fails compiling examples (pre-existing) — use
`cargo test --lib --tests` (`README.md` Quick Start).

## 1. Wallet (5 min)

```sh
./target/debug/stellereum wallet generate
```

Real shape (values differ per run; verified by executing it):

```text
• Address (Public Key):   <64 hex>
• Private Key:            <64 hex>
• Viewing Public Key:     <64 hex>
• Viewing Private Key:    <64 hex>
• Stealth One-Time Pub:   <64 hex>
```

Save both keys offline. **If it fails:** none known — it is pure local
keygen, no network. Other wallet commands
(`balance --address`, `address --from-key`, `send`, `delegate-session`,
`sign/verify`, `sign-typed-data`): `wallet --help` lists them; there is no
separate `stell` binary (`README.md` wallet section).

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
rpc stell_faucet '{"address":"<64-hex>"}'
```

Documented result shape (`docs/RPC.md` §4):
`{"credited_nano":"…","recipient":"…","tx_hash":"…","shard":…}`. Defaults:
**10 STELL drip** (`STELL_FAUCET_DRIP_STELL`), **1000 STELL lifetime cap**
per address, 20 drips/hour/IP, gated by `STELL_FAUCET_TOKEN` (fail-closed).
Fund the **`-1:<hex>` masterchain form** if you will stake; a bare address
is a workchain address and never routes to shard 0.

- TODO (live output): run the command against a faucet-enabled node and
  paste the real JSON. Verify: `curl … stell_faucet` above.
- **If `-32601 faucet is disabled`:** node lacks `STELL_FAUCET=1`.
- **If `-32000 faucet limit reached`:** the 1000 STELL cap is spent.
- **If `-32000 … cannot serve an address on shard T`:** sharded faucet
  serves only its own shard — drip from that shard's faucet. Burns no nonce.

## 4. Transfer (10 min)

```sh
./target/debug/stellereum wallet send --from-key <hex-seed> \
  --to <64-hex> --amount 25000000000 --rpc $RPC
rpc stell_getBalance '{"address":"<64-hex>"}'
# → {"result":{"balance":"…","nonce":…}}  (decimal-string balance)
```

`--amount` is nano-STELL (1 STELL = 10⁹). Note `send --help`: default
`--target-shard 0`. Watch inclusion, not just submission:

```sh
rpc stell_getTransactionStatus '{"hash":"<64-hex>"}'
# → {"status":"success|failed|pending|unknown","height":…}
```

- TODO (live output): capture a real `success` receipt. Verify: commands above.
- **If `-32000 rejected: offered fee is below the base fee`:** raise
  `gas_limit` above `stell_baseFee`. **If `pending` forever:** the tx sits
  only in *this* node's mempool, or a nonce gap — check `stell_mempoolSize`.

## 5. Deploy a contract (10 min)

Write WAT using only the 13 `host.*` imports ([03-contracts](03-contracts.md));
minimal example is `contracts/sts20_token.wat` (imports `host.sload`,
`host.sstore`, `host.emit`). Deploy over RPC:

```sh
rpc stell_deployContract '{"from":"<hex>","code":"<hex-of-wasm>","abi":{…}}'
# optional wrapper: {"tx":"<hex of bincode(Transaction)>"} with a
# SysCallDeployContract payload (src/rpc.rs stell_deployContract)
```

- TODO (live output + minimal WAT→wasm toolchain): `wat2wasm` binary name
  and exact success JSON unverified. Verify: `which wat2wasm; rpc
  stell_deployContract …`.
- **If `-32602 missing 'code'`:** the field name is `code`, hex-encoded.
- **If `contract imports something the host does not provide`:** you
  imported outside the 13 host functions. **If `contract code exceeds the
  maximum size`:** shrink the module (limit in `src/contract.rs`).

## 6. Call → query → events (10 min)

```sh
rpc stell_callContract '{"contract":"<hex>","method":"transfer","args":[1,2,500]}'
rpc stell_runGetMethod '{"contract":"<hex>","method":"balance_of","args":[2]}'
rpc stell_getEvents '{"tx_hash":"<64-hex>"}'
# → [{"contract":"…","contract_stl57":"…","topic":…,"value":…}]
rpc stell_getTransactionReceipt '{"hash":"<64-hex>"}'
# → {"status":"success","height":…,"fee_charged":"…","return_value":…,"events":[…]}
```

`stell_callContract` writes state (auth-token gated when configured);
`stell_runGetMethod` is the read-only path (5M fuel cap). Events are also
queryable per contract: `stell_getEvents '{"contract":"<hex>"}'`.

- TODO (live outputs): capture real call/query/events JSON. Verify: commands above.
- **If receipt is `{"status":"pending"}`:** still in this node's mempool
  only. **If `unknown`:** evicted or never seen here (receipt window:
  50 000 entries, oldest-first).

## 7. Next steps

Concepts ([02-concepts](02-concepts.md)) → contracts in depth
([03-contracts](03-contracts.md)) → staking ([04-validators](04-validators.md)).
