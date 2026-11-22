# local-cluster.sh — local N-validator testnet on one machine

`scripts/local-cluster.sh` boots **N validators on ONE host** (each in
`run/cluster/node<i>/` as its own cwd, since `run` uses relative
`./data`/`./keys`). For legit dev tests — finality, stalls, chaos —
without multiple VPS servers. Read-only toward everything live:
never touches `multinode/`, live configs, or `/root/*`.

## Commands

| Command | Effect |
|---|---|
| `up [N]` (default 3) | Two-phase keygen+config, fresh boot all, wait ≤120s for first `FINALIZED` everywhere, assert identical epoch + common heights, print status (single-shard unless `--shards` given) |
| `up [N] --shards 0,1` | Same as `up`, but 2-shard XPC demo mode (see below): `STELL_SHARDS=0,1` + `STELL_XPC_ACTIVATION_HEIGHT=5`, one process/node drives both shards |
| `up2 [N]` (default 3) | Shortcut for `up N --shards 0,1` |
| `status` | Per node: alive?/finals-count/height/epoch + RPC `eth_blockNumber` (in 2-shard mode also prints `STELL_SHARDS`; FINALIZED counts cover BOTH shards — lines carry no shard id) |
| `stop [i]` / `start [i]` / `restart [i]` | One node (no arg to `stop` = all) |
| `down` | Stop all |
| `reset` | Stop all, wipe `data/` (keys/configs kept), fresh boot with `STELL_NEW_CHAIN=1` |
| `chaos` | Stop node3 (or last node if N<3) for 60s, then restart; checks survivors log round movement + returnee finalizes NEW blocks post-restart (≤180s; baseline-counted since the log is kept) |

Logs: `run/cluster/node<i>/live.log`. PIDs: `node.pid` next to them.
Ports: P2P `19410+i`, RPC `18645+i`, explorer `18080+i` on 127.0.0.1
(RPC base is **not** 18545: that port is taken on this dev box by an ssh
tunnel — the script `ss`-checks every port before binding and fails loudly).
Binary: `stellereum/target/{debug,release}/stellereum` (debug preferred),
else `PATH`. The script **never builds** — build first if missing.

## Env reference (written to `run/cluster/node<i>/env.i`, identical shape)

| Var | Value | Why |
|---|---|---|
| `STELL_KEY_PLAINTEXT=1` | 1 | Local throwaway keys; avoids passphrase plumbing (`node_keys.rs` refuses plaintext writes otherwise) |
| `STELL_NEW_CHAIN=1` | 1 | Authorizes founding on fresh data with peers configured (`bootstrap.rs` guard) |
| `STELL_FAUCET_KEY` | `1111…1` (32 bytes `0x11`) | Shared faucet seed → identical genesis state root |
| `STELL_DEV_UNSAFE_TESTKEY=1` | 1 | Required to accept the public test key (fail-closed otherwise) |
| `STELL_LEGACY_GENESIS_ROOT=1` | 1 | Falcon derivation path must match on all nodes (`post_quantum.rs`) |
| `STELL_PURE_PQ=1` | 1 | Same PQ verification policy everywhere |
| `STELL_PEER_PQ_KEYS` | `ed:pq,…` all members | PQ vote verification needs every validator's Falcon pub |
| `STELL_ROUND_TIMEOUT_MS` | 10000 | Generous: tight timeouts + slow links = stale-vote stall (pinned by `tests/unanimity3_slow_voter_tests.rs`) |
| `STELL_BROADCAST_JOIN_MS` | 2000 | Flush join budget (default 500) |
| `STELL_CATCHUP_BUDGET_MS` | 8000 | Catch-up pass budget (code default 250ms; WAN heals needed minutes) |
| `STELL_RPC_LISTEN` | `127.0.0.1:18645+i` | Per-node RPC (default 8545 would clash) |
| `STELL_EXPLORER_LISTEN` | `127.0.0.1:18080+i` | Per-node gateway (default 8080 would clash) |
| NOT set: `STELL_SHARDS` | — | Single-shard = plain topics, no workchain/masterchain split (2-shard mode sets `0,1`, see below) |
| NOT set: `STELL_XPC_ACTIVATION_HEIGHT` | — | Single-shard: 2PC `Disabled` (legacy flow). 2-shard mode sets `5` |
| NOT set: `STELL_OBSERVER` | — | All local nodes are validators |
| NOT set: `STELL_CHAIN_ID` | — | Same default (5757) everywhere = same network |

## The 5 genesis pitfalls and how the script avoids each

1. **Faucet seed divergence** (`main.rs` funds genesis from the faucet
   seed): same `STELL_FAUCET_KEY` + `STELL_DEV_UNSAFE_TESTKEY=1` in every
   `env.i`.
2. **Falcon derivation divergence** (`generate_from_seed_bytes`): same
   `STELL_LEGACY_GENESIS_ROOT=1` everywhere.
3. **Validator-set divergence** (`build_validator_set` is a pure function
   of the config): `validators:` lists **all** member ids on every node
   (the all-listed convention), peers pin the matching `ed-pub`
   (blake3-bound, F6), so every node derives the same set → same genesis.
4. **Workchain topic split**: no `STELL_SHARDS` (script also `unset`s it
   at boot in case the caller exported it), all nodes `--shard 0`.
5. **Fresh-join fork trap** (`guard_fresh_data_dir`: fresh data + peers =
   refuse unless founding is explicit): every boot carries
   `STELL_NEW_CHAIN=1`; `reset` wipes `data/` so a re-boot is founding again,
   never a dirty-restart on a foreign chain.

## Chaos expectations

- **N=3** = unanimous quorum (3/3, see `log_quorum_safety` "урок ночи C"):
  killing any node **stalls** finality. The script asserts only that
  survivor logs keep moving (rounds/timeouts) and that the returnee
  catches up via the blind-QC-probe path — **never liveness under kill**.
- **N≥4**: the survivors keep finalizing through the kill; the returnee
  still has to catch up on restart.

## 2-shard mode (opt-in XPC/2PC demo: `up --shards 0,1` / `up2`)

Same 3 validators, but each node runs **one process driving both shards**
(`STELL_SHARDS=0,1` preserved at boot — `boot_node` only `unset`s it when
`env.i` does not set it; cf. `scripts/run-observer.sh` which already sets
`STELL_SHARDS=0,1` with `run --shard 0`). Main flow stays pinned to the
masterchain (`run --config node.yaml --shard 0` in both modes;
`block_shard_for` + `start_workchain_shard` in `main.rs`); workchain 1 spawns
as an in-process extra over the **same** infnode node.

- **Ports: shared, no extras.** Shard traffic is separated by pubsub topic
  (`consensus_topic_for_shard`: `stellereum/consensus/v1/<epoch>/shard/<id>`;
  `cross_shard_topic`: `stell/cross_shard/<epoch>/<target>` in
  `network.rs`), not by socket. P2P stays `19410+i`, RPC `18645+i`,
  explorer `18080+i` — `ports_free_for` unchanged.
- **Env deltas vs single-shard** (written to `env.i` only in this mode):
  `STELL_SHARDS=0,1`, `STELL_XPC_ACTIVATION_HEIGHT=5` (low so 2PC is active
  from height 5, reachable in minutes). Everything else identical —
  notably the funded-workchain genesis reuses the **same** shared faucet
  seed `STELL_FAUCET_KEY=1111…1` + `STELL_DEV_UNSAFE_TESTKEY=1` pattern the
  live network uses (`start_workchain_shard` → `fund_shard_genesis` funds
  ONLY the dev/faucet account on shard 1; validator set comes from the
  masterchain staking ledger, so no double-count).
- **What `up2` asserts:** generic `wait_finalized` (identical epoch +
  non-empty common FINALIZED heights) **plus** `wait_sharded_ready`: every
  node logs `[shard 1] workchain genesis` + `[shard 0/1] cross-shard 2PC
  ACTIVE from height 5`, and `data/store-shard1` exists. Per-shard stores:
  masterchain keeps `./data/store` (+ `./data/mempool.bin`); workchain 1
  gets `./data/store-shard1` (+ `./data/mempool-shard1.bin`) — see
  `store_path_for_shard` / `mempool_path_for_shard` in `main.rs`. `reset`
  preserves the mode (keys/configs kept, `data/` wiped, same `env.i`
  re-booted).
- **What 2PC needs (and what is still missing 2026-11-01):** `STELL_SHARDS`
  + `STELL_XPC_ACTIVATION_HEIGHT` + funded workchain are now present, and
  the wallet CLI already takes `--target-shard 1` (source is always the
  masterchain). **Blocked:** `wallet send` builds legacy ed25519-signed
  txs, which `verify_signature` **refuses** when `STELL_PURE_PQ=1` (the
  mode live + local-cluster both use) — even same-shard sends fail with
  `invalid transaction signature`, so no PREPARE can reach admission.
  Missing: a PQ-capable transfer-signing path (`wallet sign --scheme
  falcon/hybrid` covers messages, not transfers), an RPC view of shard-1
  balances (`stell_getBalance` serves the masterchain engine only), and
  per-shard `FINALIZED` tagging (today both shards log identically, so
  per-shard height must be inferred from paired hashes + `store-shard1`).
  In-process 2PC contract remains green via `cargo test -p stellereum
  --test xshard_2pc_tests` (11/11).
