# LIVE_DEMOS_RUNBOOK — chain split, xshard 2PC, DKG (EpochDkg)

> 2026-11-04 changelog: dropped removed legacy-genesis env knob from genesis-identity (§0) and send-pq (§2); keygen is strict-only/env-independent (citations in text).

Push-button runbook for the three unclosed-structural live demos.
Live chain is DOWN, so nothing here touches live nodes/configs.
Local proof is against `scripts/local-cluster.sh` (3 local validators
finalizing) where possible; everything NOT locally verified is marked
**UNVERIFIED** with the reason.

Code refs are to files actually read for this runbook — commands are
derived from them, not guessed.

## 0. Shared prerequisites (all demos)

- Repo root: `/home/imm/stellereum-project` (all commands assume it).
- Binary: `stellereum/target/debug/stellereum` (preferred) or
  `stellereum/target/release/stellereum`, else `PATH` (`local-cluster.sh`
  `resolve_bin`; the script **never builds** — build first if missing).
- Cluster state dir: `run/cluster/` (gitignored). Ports per node `i`
  (`scripts/local-cluster.md`): P2P `19410+i`, RPC `18645+i`,
  explorer `18080+i` on 127.0.0.1. (RPC base is NOT 18545: taken by an
  ssh tunnel on this dev box; the script `ss`-checks every port and
  fails loudly.)
- Genesis identity: every node gets `STELL_FAUCET_KEY=1111…1` (32 bytes
  `0x11`) + `STELL_DEV_UNSAFE_TESTKEY=1`
  + `STELL_PURE_PQ=1` (`local-cluster.sh` `write_configs`). Same seed +
  same flags on all nodes = identical genesis state root; `up` asserts
  identical epoch + non-empty intersection of FINALIZED heights.
  (Removed legacy-genesis env knob omitted: it is removed/inert — Falcon
  keygen is strict-only `stellereum/src/post_quantum.rs:1598-1600`, the toggle
  changes nothing `stellereum/tests/a_crypto_audit_poc.rs:147-174`.)
- Chain id default 5757 (`STELL_CHAIN_ID` unset everywhere).
- Timeouts: `STELL_ROUND_TIMEOUT_MS=10000`,
  `STELL_BROADCAST_JOIN_MS=2000`, `STELL_CATCHUP_BUDGET_MS=8000`.
- Read-only recon rule: never touch `multinode/`, live configs,
  `/root/*`. `down`/`reset` only affect `run/cluster/`.

### 0.1 What the test files prove (local, in-process — NOT live)

| Demo | Test file | Feature-matrix row |
|---|---|---|
| split | `stellereum/tests/hunt_finalize_split.rs` (4 tests) | `split`: `cargo test -- --test hunt_finalize_split` |
| xshard 2PC | `stellereum/tests/xshard_2pc_tests.rs` (11 tests) | `xshard-2pc`: `cargo test -- --test xshard_2pc_tests` |
| DKG / mev_epoch | `stellereum/tests/mev_epoch_seal_tests.rs` (DKG via `EpochSealManager::sync_epoch`/`ingest_contribution`) | `mev-seal`: `cargo test -- --test mev_epoch_seal_tests` (no dedicated DKG row) |

- `hunt_finalize_split.rs`: Finding 2 (phantom-block finalize now
  REFUSED — test is PARKED by design, asserts `try_finalize() == None`
  + `applied_txs == 0` for a block the node never received); Finding 3
  (two-height form: height 1 no evidence, height 2 carries height-1 QC
  as canonical evidence; `try_finalize` path vs `adopt_committed` path
  must mark the same silent validator `missed == 1`, same burn, same
  root); Finding 4 (`adopt_committed` refuses fabricated `state_root`,
  error must contain "parent state root"); Finding 5
  (`adopt_committed` takes NO validator set — uses `self.validators`;
  one-key forged cert refused with "validator quorum").
- `xshard_2pc_tests.rs` (2-shard `ShardedCluster`, `SHARD0=0`,
  `SHARD1=1`, `XpcActivation::FromHeight(0)`): happy-path exactly-once
  credit; source-crash-resumes-to-COMMIT; target-crash-resumes-to-same;
  Byzantine source CANNOT bounce after prepare (bare bounce not
  `xpc_admissible`, forged abort-ack refused, `source_on_abort_ack ==
  Refused("transfer already committed")`, proposer never emits bounce
  for `XPC_PREPARE_TIMEOUT_HEIGHTS + 4` heights); Byzantine target
  ack-then-no-credit burns, never double-spends; replay refused (phase
  monotone); 2-validator shard accepts 2PC records (regression for the
  admission rule); lost-PREPARE re-published (new `msg_id`); refused
  escrow (stale nonce) leaves NO PREPARED record; activation boundary
  (legacy flow before, 2PC at/after); 2PC state in digest + replay blob.
- `mev_epoch_seal_tests.rs`: `run_dkg` helper (derived contributor set
  contributes, all ingest all, one epoch key, distinct shares);
  ciphertext-only gossip (`is_sealed_payload`, mempool holds no
  plaintext); order-commit gate (`release_partial` refused before
  commitment); threshold unseals (3-of-4; 2 → `NotEnoughShares`, never
  stall); epoch binding (epoch-7 ciphertext never opens under epoch 8);
  stale-epoch refused at admission; malformed seal fail-closed;
  `epoch_key_commitment` in block hash; diverged key stops release;
  plain path coexists; contributor set derived/deterministic;
  announcement quorum; height-commitment idempotence; sealed pool prune
  + per-sender quota; wallet end-to-end (fetch `stell_epochKey` →
  seal → submit hex → admit → commit → threshold release → unseal).
  Constants: `EPOCH_BLOCKS = 128` (`mev_epoch.rs:81`;
  `epoch_of_height(h) = h / 128`).

### 0.2 Spec sections that govern the demos

- `docs/specs/03_VM_AND_EXECUTION.md`: mempool rule 3 — 2PC-gated
  flows stay out until `STELL_XPC_ACTIVATION_HEIGHT` (currently OFF
  everywhere); cross-shard txs gated; workchain Parked (see below).
- `docs/specs/04_NETWORK_AND_CONSENSUS.md`: BFT V5 (live N=4,
  quorum 2f+1; leader = parent-hash sortition); `adopt_committed`
  uniformity; `DIVERGENCE their_root=… our_root=…` = the fork alarm
  (watchdog pattern `DIVERGENCE|their_root.*our_root`); shard routing
  by tx prefix, **workchain shard-1 PARKED (empty, no user txs — unpark
  needs funded demo + serving RPC)**; P2P topic
  `stellereum/consensus/v1/<chain-id>/shard/1`; single-shard = plain
  topics, no workchain/masterchain split.

### 0.3 CLI / RPC surface (from `stellereum/src/main.rs`, `rpc.rs`, `stelops`)

- Node: `stellereum keys init --keys-dir <dir>` (prints `NODE IDENTITY:
  id=… ed=… x=… falcon=…`); `stellereum run --config node.yaml
  --shard 0`.
- Wallet: `stellereum wallet send --from-key <hex-seed> --to <hex-addr>
  --amount <nano> [--target-shard 0|1, default 0] --rpc
  http://127.0.0.1:<port> [--nonce N] [--dry-run] [--verbose]`
  (submits via `stell_sendRawTransaction`; source is always the
  masterchain). `wallet balance --address <hex>`,
  `wallet address --from-key <hex>` (address = pubkey, NOT seed).
- RPC (POST JSON): `eth_blockNumber` (no auth, used by
  `local-cluster.sh status`); `stell_sendRawTransaction {"tx": <hex>}`;
  `stell_getBalance {"address": <hex>}` (returns balance+nonce);
  `stell_epochKey` → `{epoch, epoch_blocks: 128, public_key,
  committee_hash, threshold, commitment, committed_by_chain, diverged,
  announcement_signatures, …}` or error `-32010 "no epoch key is
  available yet"`; `stell_faucet` (see §0.4 — DISABLED locally).
- `stelops` (`scripts/tools/stelops/src/main.rs`): OFFLINE store tool
  only — `checkpoint|genesis-root|meta|doctor|diverge <dataA> <dataB>`
  (+ mutating `clear-lock --force`). **Requires the node STOPPED**
  (sled exclusive lock); never run against a live store.

### 0.4 Funding / tx-submission path on local-cluster (read from code)

- `local-cluster.sh` `env.i` sets `STELL_FAUCET_KEY` +
  `STELL_DEV_UNSAFE_TESTKEY=1` but does **NOT** set `STELL_FAUCET=1` or
  `STELL_FAUCET_TOKEN`. In `main.rs` the `stell_faucet` RPC arm exists
  only if `STELL_FAUCET=1/true`, and then still refuses without
  `STELL_FAUCET_TOKEN`. Consequence: **`stell_faucet` RPC is DISABLED
  on a stock local-cluster** (expected error: `faucet is disabled on
  this node`). **UNVERIFIED** (never called it; derived from
  `main.rs:7503` + `rpc.rs:4420-4433`).
- Working funding path (code-derived): the faucet/dev account IS funded
  at genesis (`GENESIS_FAUCET_BALANCE`, `fund_shard_genesis` /
  masterchain genesis credit). Sign with the faucet seed directly:
  `FROM_KEY=1111…1` (64 hex chars, i.e. the `STELL_FAUCET_KEY` value)
  → `wallet address --from-key` to get its address → `wallet send
  --from-key <seed> … --rpc http://127.0.0.1:18646`. For a second
  hop, fund a fresh keypair once from the faucet seed, then send from
  it (nonce auto-queried via `stell_getBalance`).
- Drip amounts: default 10 STELL (`Faucet::default_drip_nano`;
  `STELL_FAUCET_DRIP_STELL` override). Balances are u64 nano-STELL.

---

## Demo 1 — chain split handling

### Goal

Show (a) the cluster survives / correctly stalls under a network
partition (kill one node), (b) the returnee catches up via the
blind-QC-probe path, and (c) IF a state-root divergence ever occurs,
the `DIVERGENCE` alarm fires and `stelops diverge` diffs the two
stores offline for a resync decision.

### Prerequisites

- Fresh or running local-cluster (`up` green: identical epoch +
  common FINALIZED heights).
- `curl` + `jq` for RPC checks. No funds needed (no txs required).
- For (c): two STOPPED node data dirs. There is no live divergence
  available while the live chain is down.

### Steps — local-cluster (ports 18646/18647/18648 for N=3)

**1a. Partition drill (N=3 — stall is CORRECT, liveness is NOT asserted):**

```bash
./scripts/local-cluster.sh status
./scripts/local-cluster.sh chaos
```

What `chaos` does (`local-cluster.sh:345-394`): stops node3 (or last
node if N<3) for 60s, notes survivor log growth, restarts node3, waits
≤180s for NEW `FINALIZED` post-restart (baseline-counted, since the
log is kept), prints `status`.

**1b. Observe + verify:**

```bash
grep -c 'FINALIZED block #' run/cluster/node1/live.log run/cluster/node2/live.log run/cluster/node3/live.log
grep -E 'FINALIZED block #|DIVERGENCE|their_root.*our_root' run/cluster/node3/live.log | tail -20
for i in 1 2 3; do echo -n "node$i: "; curl -s -m 5 -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
  http://127.0.0.1:1864$((5+i)) ; echo; done
./scripts/local-cluster.sh status
```

Expected (from `local-cluster.md` "Chaos expectations" + script
comments): with N=3 (unanimous quorum 3/3) killing any node STALLS
finality — survivor logs keep moving (rounds/timeouts) but NO new
`FINALIZED` while node3 is down; after restart node3 finalizes NEW
blocks (count grows past pre-restart baseline) and `status` heights
converge. With N≥4 (`up 4`): survivors keep finalizing through the
kill. **UNVERIFIED** end-to-end (read-only recon; never executed here).

**1c. True-split forensics drill (only if a divergence exists):**

```bash
./scripts/local-cluster.sh stop
# build once if needed: cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml
./scripts/tools/stelops/target/release/stelops diverge run/cluster/node1/data run/cluster/node2/data
```

Expected: exit 0 + matching finalized height/hash/epoch when healthy;
`DIVERGENCE` line + exit 1 on any difference (offline counterpart of
the live `DIVERGENCE` log; `stelops` refuses to open a RUNNING node's
store — "could not acquire lock" is by design, stop first).

### What changes on the live VPS chain

- N=4, quorum 2f+1: a single-node kill must NOT stall (survivors keep
  finalizing) — the N≥4 branch, not the N=3 branch.
- Live nodes use `STELL_SHARDS=0,1` (doctor `EXPECT_STELL_SHARDS`);
  pubsub topic includes chain-id + shard; check the topic first if
  nodes look isolated (`scripts/doctor.sh` covers this).
- Never restart/clear-lock live without explicit human order
  (AGENTS.md §6). Forensics = `stelops diverge` on COPIES of stopped
  stores, or `stelops checkpoint/genesis-root/doctor` on a stopped
  node only.

### Pass / fail criteria

- PASS (partition): pre-kill `status` green; during kill, survivors
  alive, returnee rejoins, post-restart NEW `FINALIZED` count > 0
  within 180s, heights converge across nodes, identical epoch.
- PASS (forensics): `stelops diverge` exit 0 on healthy pair.
- FAIL: epoch mismatch (`genesis diverged`); disjoint FINALIZED sets;
  returnee finalizes nothing new within 180s (WARN in script);
  `DIVERGENCE` lines in any live log (page, do not auto-heal).

### Rollback / cleanup

- `chaos` self-restarts the killed node. If stuck:
  `./scripts/local-cluster.sh restart 3 && ./scripts/local-cluster.sh status`.
- Full reset (wipes data, keeps keys/configs):
  `./scripts/local-cluster.sh reset`. Full stop:
  `./scripts/local-cluster.sh down`.

---

## Demo 2 — xshard 2PC (cross-shard two-phase commit)

### Goal

A cross-shard transfer runs PREPARE → PREPARE-ACK → COMMIT (no bare
`is_transfer` credit-before-vote), credits the target EXACTLY ONCE,
survives source/target crash between phases, and a Byzantine
bounce-after-prepare is refused (no double spend).

### Prerequisites

- What the TESTS need (in-process, available NOW): two shards
  (`SHARD0=0`, `SHARD1=1`), `XpcActivation::FromHeight(h)`, funded
   sender on shard 0. Covered by `xshard_2pc_tests.rs` (11 tests, §0.1).
- What a LIVE/LOCAL demo needs (NOT present on stock local-cluster):
  a **2-shard process** (`STELL_SHARDS=0,1` over one `Node` — the
  cross-shard KV helpers in `network.rs` are node-local, so both
  consensus instances must share one process; `sharding.rs:389-392`),
  `STELL_XPC_ACTIVATION_HEIGHT=<h>` set identically on all validators
  (`main.rs:2589-2612`, `xpc_activation_from_env`; unset/parse-fail =
  `Disabled`, logged), and a funded account on the workchain
  (`fund_shard_genesis` funds ONLY the dev/faucet account;
  `STELL_FAUCET_KEY` seed).
- Spec note: workchain shard-1 is PARKED on live (no user txs);
  `STELL_XPC_ACTIVATION_HEIGHT` is OFF everywhere
  (`docs/specs/03_VM_AND_EXECUTION.md` rule 3).

### Steps — local-cluster: BLOCKED (do not attempt stock)

`local-cluster.sh` is single-shard ON PURPOSE: `env.i` documents "NO
STELL_SHARDS", `boot_node` runs `stellereum run --config node.yaml
--shard 0` and explicitly `unset STELL_SHARDS …` at boot
(`local-cluster.sh:149,185-186`), and all nodes use plain topics (no
workchain/masterchain split, `local-cluster.md` pitfalls §4). A 2PC
transfer needs shard 1 to exist in-process; on a stock cluster the
target shard never runs, so PREPARE has no counterparty. **Do not
hack env files around the script** — that bypasses the genesis guards.

Requirement to unblock (for the lead): a 2-shard local-cluster mode
(script change, NOT this runbook — no code changes allowed here):
boot each node with `STELL_SHARDS=0,1` preserved (stop unsetting it),
one process driving both shards per node (cf.
`scripts/run-observer.sh` which already sets `STELL_SHARDS=0,1`),
`--shard` handling per shard instance, `STELL_XPC_ACTIVATION_HEIGHT`
in `env.i`, faucet-funded workchain genesis, and an RPC that can
route `--target-shard 1` sends. Then the demo is:

```bash
# UNVERIFIED sketch (blocked on the above — commands follow wallet/RPC code, never executed):
BIN=stellereum/target/debug/stellereum
$BIN wallet address --from-key <FAUCET_SEED_HEX>          # faucet/dev account addr
$BIN wallet send --from-key <FAUCET_SEED_HEX> --to <RECIPIENT_HEX> --amount 1000000000 \
  --target-shard 1 --rpc http://127.0.0.1:18646           # cross-shard tx, source shard 0
# watch PREPARE / PREPARE-ACK / COMMIT on both shards' logs + RPC; assert exactly-once credit:
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_getBalance","params":{"address":"<RECIPIENT_HEX>"}}' \
  http://127.0.0.1:18646
```

Expected observable (mirroring `xshard_2pc_tests.rs` assertions, mapped
to live surfaces — **UNVERIFIED**): source block carries a `PREPARE`
record (never a bare `is_transfer`); target prepares WITHOUT crediting;
target publishes `PREPARE-ACK`; source commits; source publishes
`COMMIT`; target credits exactly once; further heights never re-credit;
`xpc` phase readable as `Prepared → Committed` (terminal/monotone).

### Local proof available NOW (no cluster needed)

```bash
cargo test -p stellereum --test xshard_2pc_tests
```

11 tests (§0.1). This is the push-button proof until the 2-shard local
mode exists. Matrix row: `xshard-2pc` in `scripts/feature_matrix.sh:80`.

### What changes on the live VPS chain

- Set the SAME `STELL_XPC_ACTIVATION_HEIGHT` on all 4 validators
  (a mismatch splits the protocol: pre-boundary legacy flow vs 2PC).
  Requires unparking shard 1 (funded demo + serving RPC per spec §04).
- Live topics are sharded (`…/shard/1`); cross-shard transport is P2P,
  not node-local — watch for dropped/lost PREPARE (the re-publish
  path covers it: source re-sends PREPARE with a new `msg_id`).

### Pass / fail criteria

- PASS (tests): all 11 `xshard_2pc_tests` green.
- PASS (live, when unblocked): recipient credited EXACTLY once;
  sender debited amount+fee (escrow released, NOT refunded); no
  `is_bounce` for the transfer within timeout window; replayed
  COMMIT never re-credits.
- FAIL: any bare-transfer credit before the vote; any bounce/refund
  of a `Committed` transfer; credit count ≠ 1.

### Rollback / cleanup

- Tests: no state (in-process engines). Live/local-cluster: no refund
  path exists for committed transfers BY DESIGN (burn on Byzantine
  target, never double-spend) — cleanup = fresh `reset`, not a bounce.

### Unblocked 2026-11-01 — `wallet send-pq` (EXECUTED, local 2-shard cluster)

`wallet send` builds legacy ed25519 txs, refused under `STELL_PURE_PQ=1`
(`sharding.rs:3472-75`). New command (no verifier change — the tx shape is
byte-identical to a faucet drip):

```bash
BIN=stellereum/target/debug/stellereum
# NOTE: removed legacy-genesis env knob is inert (no-op) — do NOT export it.
# Keygen is strict-only (stellereum/src/post_quantum.rs:1598-1600) and the
# toggle changes nothing (stellereum/tests/a_crypto_audit_poc.rs:147-174).
$BIN wallet send-pq --falcon-seed <hex-seed> --to <hex-addr> --amount <nano> \
  [--target-shard 0|1, default 0] --rpc http://127.0.0.1:<port> \
  [--nonce N] [--dry-run] [--verbose]
```

Design: Falcon-512 keypair derived with the SAME raw derivation
`Faucet::new` uses (`generate_from_seed_bytes`, no wallet KDF), so the
shared faucet seed (`1111…1`) spends the genesis-funded faucet PQ account;
shape = `rpc::sign_pq_explicit_transfer` (unbound, always-explicit PQ1
envelope, base fee + activation surcharge). Fail-closed: bad seed refused
before signing, never ed/unsigned fallback; a client-side self-check
refuses to submit a non-verifying tx.

PQ ACTIVATION RULE (measured, `verify_inclusion_untrusted` +
`commit_native` pin): a fresh PQ account holds a 16-byte trie leaf; its
FIRST spend must be same-shard (pins the 49-byte PQ leaf at apply). A
cross-shard first spend's opening PREPARE is refused at target admission
(16-byte proof vs 49-byte metadata skew); cross-shard works from the
second spend on. The demo below follows the rule.

EXECUTED 2026-11-01 ~06:05–06:15 UTC on `./scripts/local-cluster.sh up2 3`
(epoch `b76feefadaf33c5a`, XPC active from height 5). Faucet PQ address
`eff75acfeb416b7e7c48f0c2db79462073e20f86bbd34d2fba03158d80443ea3`
(matches the genesis log line; `wallet sign --scheme falcon
--falcon-seed 1111…1` prints the same address):

1. pin+fund, same-shard, faucet nonce 0 → `e31ad48e…` admitted; R1
   (`a26766…b06e`) credited **exactly** `10000000000`; faucet
   `1000000000000000` → `999989999630000` (amount + 370000 fee = 325000
   gas + 45000 surcharge), nonce 0 → 1.
2. cross-shard first leg, faucet nonce 1, `--target-shard 1` → `4e9ac3c4…`
   admitted, applied height 29, receipt `success` (`fee_charged 370000`,
   `gas_limit 325000`); faucet → `999988499260000`, nonce 2 (exact escrow
   debit: 1500000000 + 370000); opening PREPARE published
   (`cross-shard outbound published 0d357781… shard 0 -> 1` at the
   block-29 adopt). Target-side credit is NOT RPC-visible
   (`stell_getBalance` serves the masterchain engine only — pre-existing
   limitation): **UNVERIFIED** live; source re-PREPARE cadence (every 8
   heights) observed afterwards, target completion not confirmed on this
   run.
3. second hop, R1 (`5555…55` seed) → R3, same-shard, R1 nonce 0 →
   `b420b8a7…`, receipt `success` height 49 (`fee_charged 370000`); R3
   credited **exactly** `1000000000`; R1 → `8999630000`, nonce 1 (exact).

Full-2PC proof (both legs, exactly-once credit, same tx shape):
`cargo test -p stellereum --test pq_wallet_2pc_tests` 4/4 green (fund
leg, funded spend, cross-shard PREPARE → PREPARE-ACK → COMMIT exactly-once
with escrow released-not-refunded, ed refusal) + `xshard_2pc_tests` 11/11
green + `rpc.rs` unit pins (shape verifies under PURE_PQ, ed refused,
tampered-sig/amount/recipient refused, mempool admits PQ / refuses ed).
`down` PASS afterwards (only live `multinode/nodeB/stellereum` in `pgrep`,
all cluster ports free).

---

## Demo 3 — DKG (distributed key generation, mev_epoch EpochDkg)

### Goal

Show the committee running the DKG for an epoch: contributions
published as `MevFrame::Dkg`, one agreed epoch key, `stell_epochKey`
serving it, key committed in blocks (`epoch_key_commitment`), key
rotation at the epoch boundary (every 128 blocks).

### Prerequisites

- Fresh or running local-cluster (any N≥3). No funds/txs needed.
- `curl` for `stell_epochKey`; log access to `run/cluster/node<i>/live.log`.
- Mechanism (from `runtime.rs:2922-2991`): on tick, `sync_mev_epoch`
  computes `epoch = height / 128`, `sync_epoch(epoch, ids, our_id,
  seed)` publishes our `DkgContribution` via
  `gossip_mev_frame(MevFrame::Dkg(...)))` (log line `[mev-seal] epoch
  {epoch}: published our dkg contribution`), re-publishes every
  `DKG_REPUBLISH_INTERVAL` (5s) until the key is ready, then publishes
  the epoch announcement. Ingested gossip contributions go through
  `ingest_contribution` (same path the tests drive).

### Steps — local-cluster (ready in attenuated form)

```bash
./scripts/local-cluster.sh status
grep -h 'mev-seal' run/cluster/node1/live.log | tail -20
for i in 1 2 3; do echo "== node$i"; curl -s -m 5 -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_epochKey","params":[]}' \
  http://127.0.0.1:1864$((5+i)) | head -c 600; echo; done
```

Expected (code-derived, **UNVERIFIED** end-to-end): `[mev-seal] epoch
0: published our dkg contribution` lines in each `live.log` shortly
after boot; once all contributions are ingested, `stell_epochKey`
returns `{epoch: 0, epoch_blocks: 128, public_key, committee_hash,
threshold, commitment, …}` identically (same `public_key` +
`commitment`) on all nodes. Before completion it returns `-32010 "no
epoch key is available yet"` — that error is NORMAL pre-DKG, not a
failure. Cross-check the served key against the chain: `commitment`
must equal the block's `epoch_key_commitment` (the block commits the
key; `mev_epoch_seal_tests.rs::the_epoch_key_is_committed_to_the_block`).

Epoch-boundary rotation (full demo): boundary every 128 heights
(`EPOCH_BLOCKS`). At ~2–3 s/block this is ~4–6 min per epoch on a
healthy cluster — wait for height ≥ 128, then expect new-epoch
`published our dkg contribution` lines, `stell_epochKey` serving
`epoch: 1` with a DIFFERENT `public_key`/`commitment`
(`the_epoch_key_rotates`), and old-epoch ciphertexts refusing to open
under the new key. **UNVERIFIED** (timing + rotation never observed
here; read-only recon only).

### Local proof available NOW (no cluster needed)

```bash
cargo test -p stellereum --test mev_epoch_seal_tests
```

Covers the DKG contract end-to-end in-process: one-key agreement,
distinct shares, derived contributor set, rotation, announcement
quorum, foreign/non-contributor refusal (§0.1). Matrix row: `mev-seal`
(`scripts/feature_matrix.sh:85`). There is NO `dkg`-named matrix row.

### What changes on the live VPS chain

- Same trigger (epoch boundary at multiples of 128) and same RPC;
  committee = the 4 live validators. A member whose remote signer
  withholds the long-term secret simply has no epoch key and keeps
  serving plain txs (plain path untouched by design).
- Divergence alarm: a node whose key differs from the chain-committed
  key sets `diverged` and REFUSES `release_partial`
  (`a_diverged_epoch_key_stops_the_release`) — check `"diverged":true`
  / `committed_by_chain` mismatch in `stell_epochKey` output.

### Pass / fail criteria

- PASS: all nodes log DKG publish; `stell_epochKey` converges to one
  `public_key`+`commitment` per epoch; `epoch` advances at height 128;
  `commitment` matches block header; `the_committee_agrees…`,
  `the_epoch_key_rotates` tests green.
- FAIL: nodes stuck on `-32010` past the first epoch with no
  `[mev-seal]` publish lines (gossip/DKG stall); `diverged: true` on
  any node; two nodes serving different keys for the same epoch.

### Rollback / cleanup

- Nothing to roll back: DKG is deterministic per epoch and re-runs at
  each boundary; `reset` restarts from epoch 0. No restarts needed —
  observation is RPC + logs only.

---

## Appendix — exact 3-command sequences (lead decides when; do NOT pre-run clusters)

Clusters take minutes + CPU. Do NOT start anything yourself — hand
these to the lead. (Per task constraints: read-only recon; no
long-running processes were started for this runbook.)

**Split (ready-now against a fresh local cluster):**

```bash
./scripts/local-cluster.sh up 3
./scripts/local-cluster.sh chaos
./scripts/local-cluster.sh status
```

**2PC (blocked — local proof only, no cluster needed):**

```bash
cargo test -p stellereum --test xshard_2pc_tests
# live/local demo blocked on: 2-shard local-cluster mode (STELL_SHARDS=0,1 + STELL_XPC_ACTIVATION_HEIGHT)
./scripts/feature_matrix.sh   # optional: full matrix incl. xshard-2pc + split rows
```

**DKG (ready-now attenuated: epoch-0 DKG observation):**

```bash
./scripts/local-cluster.sh up 3
curl -s -X POST -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"stell_epochKey","params":[]}' http://127.0.0.1:18646
cargo test -p stellereum --test mev_epoch_seal_tests
```

## Feasibility verdicts

| Demo | Verdict | Blocker / note |
|---|---|---|
| split | **READY-NOW** (partition-recovery half) + **BLOCKED** (true state-root split forensics) | `chaos` + `status` + log/RPC checks runnable today. True-split half needs a real divergence (none exists while live is down); `stelops diverge` path documented but **UNVERIFIED** live. In-process divergence proofs green (`hunt_finalize_split`, matrix row `split`). |
| xshard 2PC | **BLOCKED-ON-X** | X = 2-shard local-cluster mode: script unsets `STELL_SHARDS`, boots `--shard 0` only; needs `STELL_SHARDS=0,1` multi-shard process + `STELL_XPC_ACTIVATION_HEIGHT` + funded workchain. Also live-blocked (shard-1 PARKED, activation OFF). Local proof = `xshard_2pc_tests` (11 tests) + matrix row `xshard-2pc`. |
| DKG (EpochDkg) | **READY-NOW** (attenuated) | Epoch-0 DKG observable via `[mev-seal]` logs + `stell_epochKey` on any fresh cluster; full rotation needs height ≥ 128 (**UNVERIFIED** timing). In-process proofs green (`mev_epoch_seal_tests`, matrix row `mev-seal`; no dedicated DKG row). |

All `UNVERIFIED` marks above mean: derived from code actually read
(file:line cited), but never executed against a running cluster in
this session (read-only recon, no processes started).

---

## Execution log — 2026-10-31 (local cluster N=3, EXECUTED)

Executed on the LOCAL simulator only (`scripts/local-cluster.sh`; debug
binary, ports P2P 19411-19413 / RPC 18646-18648). Nothing touched live
nodes/configs. Times UTC. Rest of this file left byte-identical.

### 1. `up 3` + finalizing (PASS)

```bash
./scripts/local-cluster.sh up 3
```

```
[local-cluster] OK: epoch b76feefadaf33c5a identical on all 3 nodes; 1 common FINALIZED height(s), max #1.
node1   yes(3970978) 1   #1   b76feefadaf33c5a   1   127.0.0.1:18646
node2   yes(3971009) 1   #1   b76feefadaf33c5a   1   127.0.0.1:18647
node3   yes(3971039) 1   #1   b76feefadaf33c5a   1   127.0.0.1:18648
```

Same-epoch + finalizing re-confirmed ~1 min later; one matching
FINALIZED line per node (block #4, identical hash + root on all 3):

- node1: `[consensus] FINALIZED block #4 bd037e0ac54d (state root 96db47e0919d)`
- node2: `[consensus] FINALIZED block #4 bd037e0ac54d (state root 96db47e0919d)`
- node3: `[consensus] FINALIZED block #4 bd037e0ac54d (state root 96db47e0919d)`

### 2. Split drill — partition half + returnee catch-up (EXECUTED, PASS)

Pre-kill tip (21:06:18): node2/node3 at
`FINALIZED block #21 68976cce93cb (state root 7e12eea8bce4)`;
baselines node1=18, node2=18, node3=20 finals in `live.log`.

```bash
./scripts/local-cluster.sh chaos
```

```
[local-cluster] chaos: stopping node3 for 60s.
[local-cluster] node3 stopped (was pid 3971039).
[local-cluster] node3 down; sleeping 60s...
[local-cluster] node3 booted (pid 3982078, ...).
[local-cluster] OK: node3 finalized 1 new block(s) post-restart.
node1   yes(3970978) 19  #23  b76feefadaf33c5a  23  127.0.0.1:18646
node2   yes(3971009) 20  #23  b76feefadaf33c5a  23  127.0.0.1:18647
node3   yes(3982078) 22  #23  b76feefadaf33c5a  23  127.0.0.1:18648
```

Stall evidence (N=3 unanimous quorum ⇒ stall is CORRECT, liveness not
asserted): last pre-kill FINALIZED was #22 at 21:06:31 (node2/node3);
next FINALIZED anywhere was #23 at 21:07:40 (~69 s gap covering the
60 s kill). Survivors kept moving rounds without finalizing:

- node1 21:06:57: `[consensus] RX Prevote from b0939b21b597 #23 r0 target 410a5f6f`
- node1 21:06:57: `[consensus] view change -> height 23 round 1`
- node2 21:06:56: `[consensus] view change -> height 23 round 1`

Post-restart convergence (same tip hash + root on all 3, ~2 min after
restart at ~21:07:3x):

- `#36 3cb4d5eb70c5 (state root 8a584a035c46)` — node1 21:09:15.45,
  node2 21:09:15.42, node3 21:09:15.45
- `#37 75e86c471a6f (state root 42cd95a81ed1)` — node1 21:09:15.64,
  node2 21:09:15.68, node3 21:09:15.66
- `status`: #38/#38/#37, RPC_BLOCK 38 on all 3, epoch
  `b76feefadaf33c5a` identical; `DIVERGENCE` count 0 on all 3 logs.

`status` run before (pre-kill, heights #19/#21/#21) and after (above);
heights converge, no divergence alarm. True state-root-split
forensics (`stelops diverge`) still BLOCKED — no divergence exists to
diff.

### 3. DKG observation — epoch-0 (OBSERVED, attenuated — partial)

Fresh-cluster `mev-seal` publish lines present (epoch 0):

- node1: `[mev-seal] epoch 0: published our dkg contribution (index 1)`
  then `[mev-seal] epoch 0 key ready (threshold 2)`
- node3: `[mev-seal] epoch 0: published our dkg contribution (index 2)`
- node2: **zero** `mev-seal`/`dkg` lines in `live.log` (grep -ci = 0).

`stell_epochKey` (code-derived expectation: `-32010` pre-completion is
normal, not a failure):

- node1 (18646): serves epoch 0 —
  `epoch=0, epoch_blocks=128, threshold=2, diverged=false`,
  `public_key=74b802ff0daaef5…`, `commitment == committed_by_chain ==
  067192d9968cd480…`, `announcement_quorum=false`,
  `announcement_signatures=0`; committee shows 2/3 contributors true.
- node2/node3 (18647/18648): `-32010 "no epoch key is available yet:
  the committee's key generation has not completed"` — still pending
  at observation time (pre- and post-chaos), consistent with node2
  never logging a publish and threshold-2 key ready only on node1.

What is ABSENT and why: no epoch-1 rotation lines (needs height ≥ 128;
cluster only reached #46), no `announcement_quorum=true`, no
cross-node key convergence yet. Rotation timing therefore stays
UNVERIFIED; in-process DKG contract remains covered by
`mev_epoch_seal_tests` (not re-run in this session).

### 4. 2PC (blocked-on-X re-confirmed + in-process proof green)

No live/cluster execution attempted (unchanged blocker: stock
local-cluster is single-shard by design — script unsets
`STELL_SHARDS`, boots `--shard 0`; live shard-1 still PARKED,
activation height OFF). In-process proof re-run from
`stellereum/` (test-only build, no source changes):

```bash
cargo test --test xshard_2pc_tests
```

```
running 11 tests
test result: ok. 11 passed; 0 failed; 0 ignored; finished in 0.07s
```

(all 11 named tests green, incl. exactly-once credit,
Byzantine-bounce refusal, replay rejection, activation boundary).

### 5. `down` (PASS)

```
[local-cluster] node1 stopped (was pid 3970978).
[local-cluster] node2 stopped (was pid 3971009).
[local-cluster] node3 stopped (was pid 3982078).
node1  no  41  #46  b76feefadaf33c5a  n/a
node2  no  42  #46  b76feefadaf33c5a  n/a
node3  no  39  #46  b76feefadaf33c5a  n/a
```

Zero `stellereum` processes (`pgrep` clean) and all cluster ports
(19411-13/18646-48/18080-82) free per `ss`. Final agreed height #46,
same epoch on all 3 at shutdown.

### What remains for live demos on the VPS chain

- Split: re-run `chaos`-equivalent single-node kill on the N=4 live
  chain — expectation flips to the N≥4 branch (survivors keep
  finalizing through the kill); `stelops diverge` forensics needs a
  real divergence (none exists).
- 2PC: still blocked-on-X (2-shard local-cluster mode +
  `STELL_XPC_ACTIVATION_HEIGHT` + funded workchain; live additionally
  needs shard-1 unparked). In-process suite green (11/11, this log).
- DKG: needs a live observation of `stell_epochKey` convergence across
  the 4 validators + epoch-boundary rotation at height multiple of
  128; local observation here was partial (1/3 nodes serving).

---

## Execution log — 2026-11-01 (local 2-shard XPC mode, EXECUTED; 2PC transfer BLOCKED with reason)

Executed on the LOCAL simulator only (`scripts/local-cluster.sh up2`,
2-shard opt-in added this date; debug binary, ports P2P 19411-13 / RPC
18646-48 shared by both shards — shard traffic is topic-scoped
(`consensus_topic_for_shard`, `cross_shard_topic`), no extra ports).
Nothing touched live nodes/configs. Times UTC. Rest of this file left
byte-identical.

### 1. `up2 3` + BOTH shards finalizing (PASS)

```bash
./scripts/local-cluster.sh up2 3
```

```
[local-cluster] mode: 2-shard (STELL_SHARDS=0,1, XPC_HEIGHT=5, same P2P 19410+i, topics shard-scoped)
[local-cluster] OK: epoch b76feefadaf33c5a identical on all 3 nodes; 4 common FINALIZED height(s), max #4.
[local-cluster] OK: 2-shard mode live on all 3 nodes (masterchain store + store-shard1, XPC ACTIVE, shared P2P 19410+i, topics shard-scoped).
node1   yes(902828) 8          #4       b76feefadaf33c5a   4            127.0.0.1:18646
node2   yes(902844) 8          #4       b76feefadaf33c5a   4            127.0.0.1:18647
node3   yes(902860) 8          #4       b76feefadaf33c5a   4            127.0.0.1:18648
```

Production wiring reconfirmed read-only (no live touch): one process runs
`STELL_SHARDS=0,1` over one infnode `Node` (`sharding.rs:389-392`,
`main.rs:7212-7217`); cross-shard KV helpers are node-local so both
consensus instances must share the process (`network.rs:2282,2460`);
`--shard` handling: main flow pinned to masterchain, workchain 1 spawns as
in-process extra (`main.rs:7861-7913`, `block_shard_for`); live
`multinode/nodeB/env.B` sets `STELL_SHARDS=0,1` + `start-nodeB.sh` runs
`run --config node.yaml --shard 1` (read-only); `run-observer.sh` already
uses `STELL_SHARDS=0,1` with `run --shard 0`. Activation switch
`STELL_XPC_ACTIVATION_HEIGHT` read in `main.rs:2686-2703`
(`xpc_activation_from_env`; unset/parse-fail = `Disabled`), wired per
shard in `run_consensus_node` (`main.rs:2950-2969`). Funded workchain
genesis: `start_workchain_shard` → `fund_shard_genesis` funds ONLY the
dev/faucet account (`main.rs:384-411`, `runtime.rs:187-191`), same
`STELL_FAUCET_KEY=1111…1` + `STELL_DEV_UNSAFE_TESTKEY=1` pattern as the
masterchain genesis.

Both-shards evidence (same `live.log` carries both instances; FINALIZED
lines carry no shard id so pairs are the proof):

- `env.i`: `STELL_SHARDS=0,1`, `STELL_XPC_ACTIVATION_HEIGHT=5` (+ shared
  faucet seed + `DEV_UNSAFE=1`, identical on all 3).
- Each node: `[shard 1] workchain genesis e0a92e3fc0a7` identical on all 3
  (funded, deterministic); `[shard 0/1] cross-shard 2PC ACTIVE from height
  5`; `data/store` + `data/store-shard1` exist on all 3.
- Paired FINALIZED per height with distinct hashes/roots on all 3, e.g.
  `#1 f7d5fc62abe5` + `#1 be1149b51939`, `#3 c79d79d2d2fc` +
  `#3 c144edcd574f` — identical pairs on node1/node2/node3.
- Heights advancing: `status` `#23/#23/#23` (RPC 19) → 10 s later
  `#33/#34/#33`; later `#48/#47/#48` (RPC 25). Epoch `b76feefadaf33c5a`
  identical throughout (same faucet seed + flags as the 2026-10-31
  single-shard run, as designed).

### 2. Minimal cross-shard transfer (BLOCKED with precise reason + evidence)

Per-runbook attempt (validator-funded account, source = masterchain):

```bash
BIN=stellereum/target/debug/stellereum
FROM=$(cat run/cluster/node1/keys/identity.key)   # validator seed, balance 1e17 (ed addr 1d61a1…)
RECIPIENT=$($BIN wallet address --from-key 2222…22) # a09aa5…
$BIN wallet send --from-key $FROM --to $RECIPIENT --amount 1000000000 \
  --target-shard 1 --rpc http://127.0.0.1:18646
```

Result: `Error: rejected by node:
{"code":-32000,"message":"invalid transaction signature"}` (tx hash
`36bf5a7e…`, nonce 0). Same failure for a same-shard control
(`--target-shard 0`, `invalid transaction signature`). Sender balance
unchanged (`100000000000000000`, nonce 0); recipient `0`. No PREPARE /
PREPARE-ACK / COMMIT beyond the activation lines in any `live.log`.

Root cause (read from code, reproduced): `local-cluster.sh` sets
`STELL_PURE_PQ=1` (like live). `Transaction::verify_signature`
(`sharding.rs:3472-3475`) returns `false` for every legacy ed25519-signed
tx when pure-PQ is enforced; `wallet send` builds ONLY legacy ed
transactions (`main.rs:8451-8459` → `Transaction::sign`). The faucet's own
PQ path (`rpc.rs:797-820`) builds Falcon envelopes, but the faucet RPC is
disabled locally (no `STELL_FAUCET=1`, runbook §0.4) and only serves
same-shard drips anyway. Hence **no wallet-submitted transfer can pass
admission on this cluster**, single- or cross-shard — the documented §0.4
funding path is UNVERIFIED and, in PURE_PQ mode, inoperative as written.

What is missing to unblock the demo (no Rust changes made here):

- a PQ-capable transfer-signing CLI (`wallet sign --scheme falcon/hybrid`
  covers messages, not transfers);
- an RPC view of shard-1 balances (`stell_getBalance` serves the
  masterchain engine only; workchain credit is invisible);
- per-shard FINALIZED tagging (today both shards log identically; pairs +
  `store-shard1` are the only shard-liveness proof).

What works: 2-shard local finality (above) + in-process 2PC contract
(`xshard_2pc_tests`, re-confirmed green in the prior log, 11/11).

### 3. `down` (PASS)

```bash
./scripts/local-cluster.sh down
```

```
[local-cluster] node1 stopped (was pid 902828).
[local-cluster] node2 stopped (was pid 902844).
[local-cluster] node3 stopped (was pid 902860).
node1   no      83         #59      b76feefadaf33c5a   n/a          127.0.0.1:18646
node2   no      87         #60      b76feefadaf33c5a   n/a          127.0.0.1:18647
node3   no      81         #60      b76feefadaf33c5a   n/a          127.0.0.1:18648
```

Only `multinode/nodeB/stellereum` remains in `pgrep` (live, untouched);
all cluster ports (19411-13/18646-48/18081-83) free per `ss`. Final agreed
heights ~#59-60, same epoch on all 3 at shutdown.
