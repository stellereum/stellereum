# Two-shard (`{0,1}`) deployment runbook

Status: **supported public configuration** (masterchain + base workchain). The
boot guard accepts exactly `{0}` and `{0,1}` without the experimental hatch;
any other multi-shard set still refuses startup (`STELL_EXPERIMENTAL_SHARDS=1`
is local-soak/test-only and is **not** part of this deployment).

The cross-shard value path is the §9 **two-phase commit (2PC)**. It is armed by
the compiled chain-spec constant, not by an operator variable.

## 1. What ships

| Item | Value |
|---|---|
| Registry | one process runs both shards: `STELL_SHARDS=0,1` |
| Cross-shard value protocol | 2PC: `PREPARE -> PREPARE-ACK -> COMMIT` |
| Activation | `xshard2pc::XPC_ACTIVATION_HEIGHT = 0` (`active_from_genesis`) |
| Chain-spec gate | `chain_spec::current_activation_schedule()` → `XPC_ACTIVATION_HEIGHT [stellereum::xshard2pc]: active_from_genesis (0)` |
| Transport | shared in-process infnode node-local KV (`CrossShardTransport::from_node`) |
| Credit accounting | a target-side `COMMIT` counts as **one** inbound credit in the `cross-shard inbound credited N` log/counter (duplicate COMMITs are no-ops); consumed mailbox records are pruned by `msg_id` on apply (idempotent, node-local KV hygiene) |
| Validator set of shard 1 | **the masterchain staking ledger** (one registry, no second opinion) |
| Boot guard | `{0,1}` is accepted **without** `STELL_EXPERIMENTAL_SHARDS` |

### Why height 0

`XPC_ACTIVATION_HEIGHT = 0` means every cross-shard transfer produced at
height `0` or later runs PREPARE/vote/COMMIT.

* A fresh chain must use 2PC from block 0. The legacy one-way transfer is
  refused at the target's credit gate (XSHARD-01: one message cannot prove the
  source-side escrow), so a nonzero activation would create a window in which
  cross-shard value is stuck until the boundary.
* `0` is already passed on every existing chain, so upgrading the binary
  switches **new** transfers immediately and uniformly — there is no
  chain-height coordination between operators.
* The value is deterministic: it is a compiled `const`; every node derives
  `XpcActivation::FromHeight(0)` from the same source.
* The legacy code path is not deleted, but there is no reachable height below
  `0` on an upgraded chain: every in-flight legacy transfer is re-read as
  "produced at height >= 0". It is still refused by the target's XSHARD-01
  credit gate and can time out/refund on the source, so a chain with in-flight
  legacy transfers must drain them **before** running this binary. (A fresh
  chain has no pre-0 history and is unaffected.)

`STELL_XPC_ACTIVATION_HEIGHT` is **deprecated and ignored**. The node logs a
warning if it is set. Do not use it: two nodes with different local values
would classify the same transfer differently and split the shard.

## 2. Prerequisites

* The release binary built from this commit (`stellereum`), same build on every
  node.
* One process per **node**, running both shards. Do **not** run one process per
  shard: the cross-shard transport is node-local, so two processes on one host
  (or different hosts) cannot exchange PREPARE/ACK/COMMIT records.
* A genesis plan. On a fresh network every node's `node.yaml` must list the
  same validator set (same ids / ed / pq / falcon keys) and the same shared
  faucet seed; otherwise each node derives a different genesis and splits.
* A shared, genesis-funded **faucet** seed (`STELL_FAUCET_KEY_FILE`, preferred,
  mode `0600`; or `STELL_FAUCET_KEY`). It funds the deterministic faucet
  account on the masterchain and the workchain genesis.
* Open the P2P port (`listen`/`advertise`) and bind JSON-RPC to loopback or set
  `STELL_RPC_AUTH_TOKEN`. P2P is one port per node; both shards share it
  (topics are shard-scoped).

## 3. Directory and key layout

Run the node from its own directory. The binary reads `./keys`, `./data`,
`./node.yaml` relative to the working directory.

```text
/opt/stell/node1/
├── node.yaml                 # validators + peers (see below)
├── keys/                     # node validator keys, 0700 dir / 0600 files
│   ├── validator.key         # consensus Ed25519 key
│   ├── e2e.key               # ML-KEM KEM key (FULL-PQ)
│   ├── pq-identity.key
│   └── falcon.key            # Falcon-512 validator key
├── data/
│   ├── store/                # masterchain (shard 0) store
│   ├── store-shard1/         # workchain (shard 1) store
│   ├── mempool-shard0.bin
│   └── mempool-shard1.bin
└── env                       # environment (sourced by the supervisor)
```

Generate keys **once per node** (idempotent — existing keys are loaded, never
overwritten):

```bash
cd /opt/stell/node1
STELL_KEY_PLAINTEXT=1 /usr/local/bin/stellereum keys init --keys-dir ./keys
```

`keys init` prints one `NODE IDENTITY: id=… kem_ek=… pq_pub=… falcon=…`
line. Collect `pq_pub` and `falcon` from **every** node. The `id=` value is
the PQ **transport** id; it is not the consensus validator id (see below).

Key distribution rules:

* Each node keeps its **own** validator keys. Never copy one node's
  `validator.key` / `falcon.key` to another validator.
* `validators:` is the frozen **consensus** id list:
  `inf1:` + the first 20 bytes of `blake3(consensus Ed25519 public key)`
  (`build_validator_set`). It is not the transport `id=` from
  `NODE IDENTITY`. For a single-node dev chain the supported shorthand is an
  empty list (`validators: []`), which makes the node its own sole validator
  (quorum 1). For a multi-validator network, derive each node's consensus id
  with your genesis/cluster tooling and confirm the boot log reports
  `Consensus: N validator(s)` with `N` equal to the expected set size.
* Every node's `node.yaml` lists **all** consensus ids and all other nodes as
  peers. Each peer carries its `pq-pub` (transport, 897-byte Falcon key) and
  its `consensus-pub` / legacy `ed-pub` (32-byte Ed25519 consensus key):
  ```yaml
  name: node1
  listen: "0.0.0.0:9410"
  advertise: "203.0.113.10:9410"
  validators:
    - "inf1:<consensus-id-node1>"
    - "inf1:<consensus-id-node2>"
  peers:
    - name: node2
      pq-pub: "<node2-897-byte-falcon-hex>"
      consensus-pub: "<node2-ed25519-hex>"
      endpoints: ["203.0.113.11:9410"]
      allow: ["*"]
  ```
* `STELL_PEER_PQ_KEYS` maps each peer's **32-byte Ed25519 consensus id** to
  its **897-byte Falcon-512 public key**, identically on every node
  (`<ed_pub>:<falcon_pub>` per peer; this is the format
  `node/consensus_driver.rs` parses and `add-peer.sh` validates against the
  peer's `ed-pub`):
  ```bash
  STELL_PEER_PQ_KEYS="<ed_pub1>:<falcon_pub1>,<ed_pub2>:<falcon_pub2>"
  ```
* The faucet seed is **shared** (it is a genesis account), not per-node.

## 4. Environment

Put these in each node's `env` file and let the supervisor source it
(`set -a; . ./env; set +a`). Values are examples; use your ports/paths.

```bash
# --- the supported two-shard registry -------------------------------------
STELL_SHARDS=0,1

# --- keys / files ---------------------------------------------------------
STELL_KEY_PLAINTEXT=1            # only where the key directory is protected
STELL_FAUCET_KEY_FILE=/etc/stell/faucet.key   # 0600, preferred
# STELL_FAUCET_KEY=<64-hex>      # alternative; avoid in world-readable units
STELL_PEER_PQ_KEYS="<ed_pub1>:<falcon_pub1>,<ed_pub2>:<falcon_pub2>"

# --- fresh genesis (ONLY on a brand-new network) --------------------------
STELL_NEW_CHAIN=1

# --- networking / RPC -----------------------------------------------------
STELL_RPC_LISTEN=127.0.0.1:8545
STELL_EXPLORER_LISTEN=127.0.0.1:8080
STELL_ROUND_TIMEOUT_MS=10000
STELL_BROADCAST_JOIN_MS=2000
STELL_CATCHUP_BUDGET_MS=8000
# STELL_DNS_SEEDS=...            # opt-in only; empty/unset disables discovery

# --- 2PC ------------------------------------------------------------------
# Nothing to set. XPC_ACTIVATION_HEIGHT is compiled in (0 = from genesis).
# STELL_XPC_ACTIVATION_HEIGHT is DEPRECATED and IGNORED (warns if present).
```

Notes:

* `STELL_PURE_PQ` / `--pure-pq` are compatibility knobs: the production binary
  enforces Pure PQ unconditionally. Cross-shard transfers must therefore be
  signed PQ transfers (`wallet send-pq`), not classical Ed25519 transfers.
* `STELL_DEV_UNSAFE_TESTKEY=1` is local/dev only. It is required to use the
  public test faucet key; never enable it on a live network.
* Do not set `STELL_EXPERIMENTAL_SHARDS` for this deployment.

## 5. Startup order

1. Start the **masterchain/main flow** and the in-process workchain together:
   one `run` command per node.
   ```bash
   cd /opt/stell/node1
   set -a; . ./env; set +a
   exec /usr/local/bin/stellereum run --config node.yaml --shard 0
   ```
   The process starts shard 0 as the main flow and spawns shard 1 as an
   in-process extra; it publishes shard 1's genesis block and opens
   `./data/store-shard1`.
2. Start every node with the same command. There is no separate shard-1 start
   step and no "shard 1 first" ordering: the masterchain publishes/commits
   shard heads, and shard 1 reads the masterchain staking ledger.
3. Wait for each node to log all three:
   ```text
   workchain genesis ...
   [shard 1] cross-shard 2PC ACTIVE from height 0 (new transfers use prepare/vote/commit)
   FINALIZED block #...
   ```
   and for `./data/store` plus `./data/store-shard1` to exist.
4. Only after both shards finalize on every node, open the network to wallets
   and start the soak.

## 6. Verification commands

Set `RPC=http://127.0.0.1:8545` (one node; repeat on each node).

```bash
# Node identity / chain
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":[]}' "$RPC" | jq
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}' "$RPC" | jq

# Both shards: id, type, tip height, state root (local = applied by this node)
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_getShards","params":[]}' "$RPC" \
  | jq '{total_shards, shards: [.result.shards[] | {shard_id, shard_type, tip_height, tip_hash, state_root, local}]}'

# Local (masterchain) state root and a quorum-anchored historical root
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_getStateRoot","params":[]}' "$RPC" | jq
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_getHistoricalRoot","params":{"height":100}}' "$RPC" | jq

# Boot/activation evidence in the log
grep -E 'workchain genesis|2PC ACTIVE from height|shard 1.*FINALIZED' /opt/stell/node1/live.log | tail -20

# Both shard stores exist
ls -d /opt/stell/node1/data/store /opt/stell/node1/data/store-shard1
```

A cross-shard probe (faucet account is genesis-funded; recipient is any
32-byte address):

```bash
/usr/local/bin/stellereum wallet send-pq \
  --falcon-seed "$(cat /etc/stell/faucet.key)" \
  --to 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a \
  --amount 1000000 \
  --target-shard 1 \
  --rpc "$RPC"
```

Then watch the source receipt and the target credit:

```bash
# terminal 1: source included success + raw transaction bytes
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_getTransactionReceipt","params":{"hash":"<tx-hash>"}}' "$RPC" | jq

# terminal 2: exactly one workchain credit per transfer
grep 'cross-shard inbound credited' /opt/stell/node1/live.log | tail
```

Expected: one debit `amount + fee_charged` on shard 0, one
`cross-shard inbound credited 1 message(s) on shard 1` line, and repeating the
same raw transaction does not credit again.

## 7. Live soak

`scripts/soak_two_shard.sh` starts real two-shard processes and soaks them for
30 minutes by default. It exits non-zero on the first divergence: a stalled
shard, an alpha/beta state-root mismatch at a common height, a duplicate target
credit, or a source debit that is not exactly `amount + fee_charged`.

```bash
# Local/dev throwaway chain (public DEV faucet key):
scripts/soak_two_shard.sh --dev --duration 300

# Real soak: the seed must be the genesis-funded faucet seed the nodes use.
STELL_FAUCET_KEY_FILE=/etc/stell/faucet.key \
  scripts/soak_two_shard.sh --duration 1800
```

The script writes its clusters under `run/soak_two_shard/<timestamp>/`
(`alpha`, `beta`, `xpc`) with a log and PID per role. It stops them on exit;
`SOAK_KEEP=1` keeps them for inspection. It runs two sequential phases so a
busy host never starves the in-process shard-1 task of one of three concurrent
full nodes. Tunables (env or flags): `--interval`, `--amount`, `--replays`,
`--base-dir`, `--bin`, `SOAK_READY_TIMEOUT`, `SOAK_TX_TIMEOUT`, port bases
`SOAK_P2P_BASE`, `SOAK_RPC_BASE`, `SOAK_EXPLORER_BASE`.

What the roles mean:

* `alpha`, `beta` — phase 1, two independently built clusters with the same
  genesis. They receive the **same signed same-shard transfer bytes** and must
  serve the same shard-0 state root at the same historical height, and the
  same shard-1 root. Cross-shard traffic is not sent to this pair because a 2PC
  record commits its prepared/decided heights into the digest; the same
  transfer included at different heights is expected to differ.
* `xpc` — phase 2, the cross-shard probe. One real PQ transfer shard 0 →
  shard 1 per interval, then checked for exactly one debit and exactly one
  target credit. `--replays N` additionally re-submits the same raw bytes N
  times for an adversarial idempotency run (default 0).

## 8. Upgrade and rollback

The activation is a **protocol change compiled into the binary**. All nodes
must run the same build.

* Upgrade: stop the cluster, replace the binary on **every** node, restart with
  the same data directories and `STELL_SHARDS=0,1`. The chain spec now reports
  `active_from_genesis (0)`; newly produced transfers use 2PC immediately.
* Mixed versions are unsafe. A pre-activation binary reports the gate off and
  ignores `XPC_*` records; a new source producing PREPARE against an old target
  stalls the transfer (liveness loss, not a double spend). Roll out together.
* In-flight legacy transfers from before the upgrade: after the switch every
  transfer is classified as produced at height `>= 0`, so the new binary does
  not continue their old lifecycle. The XSHARD-01 target gate still refuses the
  one-step credit, so they time out and refund on the source. Drain them before
  upgrading if a clean legacy completion is required.
* Rollback to an older binary has the same mixed-version hazard in reverse:
  2PC records already committed stay in state, but the old binary will not
  process new XPC records. Roll forward is the safe direction.

## 9. Troubleshooting the soak

The soak fails closed; read the first `[soak] FAIL` line and the role logs it
prints.

* `shard1 stalled` / `did not advance BOTH shards` while the log still shows
  `FINALIZED block #…` for the workchain: the node's in-memory finalized-header
  registry (the source of the published shard head and of cross-shard anchors)
  is lagging behind the workchain. This is a node/runtime condition, not a
  configuration error; the soak's log-derived fallback keeps checking, and the
  cross-shard phase will fail if the anchor never becomes available. Capture
  the role log and report it with the binary version.
* `did not reach N shard-1 credits`: the target did not consume/credit the
  COMMIT. Check that both shard heads are published (`stell_getShards`), that
  the target log has no `credit refused` line, and that both shards are in the
  same process (`STELL_SHARDS=0,1`).
* `2PC is not armed`: the running binary predates the activation. Rebuild from
  the release that carries `XPC_ACTIVATION_HEIGHT = 0`; the log must say
  `cross-shard 2PC ACTIVE from height 0`.

## 10. Honest limits

* The soak script exercises real processes and real JSON-RPC on one host; it is
  not a multi-host partition/chaos test.
* The two-shard pair is fixed (`{0,1}`). Dynamic split/merge is implemented and
  tested in-process but has never been performed on a live network; it remains
  parked behind the experimental hatch.
* A 2PC transfer whose target shard is unreachable stays ESCROWED until the
  target answers. That is the liveness price of not letting the source decide
  unilaterally; it is not a safety failure.
