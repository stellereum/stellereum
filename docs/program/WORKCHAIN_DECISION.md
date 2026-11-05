# Workchain / Shard-1: CUT vs UNPARK decision record

Scope: `stellereum/` crate, default boot path (`Run`, CLI `--shard 0`,
`STELL_SHARDS` unset). Every claim carries `file:line`. No code changed.

## 1. Reference map (pattern `workchain|shard_1|shard-1|SHARD1|shard 1`, `*.rs`)

291 matching lines / 305 total matches across 10 files (`stellereum/src`):

| File (`stellereum/src/…`) | Lines w/ match | File size (lines) | What the matches are |
|---|---|---|---|
| `sharding.rs` | 70 | 8606 | `MASTERCHAIN_SHARD` (`sharding.rs:373`), `BASE_WORKCHAIN_SHARD_INITIAL` (`sharding.rs:374`), `SHARD_REGISTRY_ENV="STELL_SHARDS"` (`sharding.rs:379`), `from_env_or` (`sharding.rs:424`), `is_sharded` (`sharding.rs:439`), routing/topology/commitments/registry |
| `main.rs` | 41 | 11908 | `start_workchain_shard` (`main.rs:389`), per-shard store/mempool paths (`main.rs:350`, `main.rs:364`), boot registry (`main.rs:7454`), extras loop (`main.rs:8108`), `STELL_WORKCHAIN_OBSERVER` (`main.rs:8118`), `xpc_activation_from_env` (`main.rs:2723`) |
| `runtime.rs` | 143 | 11230 | `master_staking` shared ledger (`runtime.rs:585`), `with_shard` gate (`runtime.rs:1114`), `with_master_staking` (`runtime.rs:1137`), `collect_shard_header_commitments` (`runtime.rs:1361`), `check_shard_header_commitments` (`runtime.rs:1450`), `refresh_workchain_set_from_master` (`runtime.rs:7484`) |
| `rpc.rs` | 28 | 15156 | shard-type helpers (`rpc.rs:3640`), `collect_shard_heads` (`rpc.rs:3696`), workchain faucet tests (`rpc.rs:9970`), `get_shards` tests (`rpc.rs:11457`) |
| `network.rs` | 2 | 4897 | cross-shard gossip topic comment (`network.rs:2461`), gossip path (`network.rs:3100`) |
| `sync.rs` | 1 | 2940 | shard-binding test comment (`sync.rs:2213`) |
| `state_engine.rs` | 2 | 14479 | bridge-intents masterchain-only gate (`state_engine.rs:2879`), `route_address` workchain rule (`state_engine.rs:8633`) |
| `svm.rs` | 1 | 4175 | default-topology comment, base workchain holds every workchain address (`svm.rs:3326`) |
| `contract.rs` | 1 | 2921 | test comment, recipient routes to shard 1 (`contract.rs:2188`) |
| `bridge.rs` | 2 | 2675 | `workchain: i32` field (`bridge.rs:1770`), test value (`bridge.rs:2317`) |

Broader `shard_id|ShardId|shard_registry|ShardRegistry` footprint:
`sharding.rs` 225, `runtime.rs` 107, `network.rs` 103, `rpc.rs` 53,
`main.rs` 35, `state_engine.rs` 17, `mempool.rs` 12, `consensus_net.rs` 7,
`sync.rs` 9, others small.

### PARK flag / gate (exact)

1. `SHARD_REGISTRY_ENV = "STELL_SHARDS"` — `sharding.rs:379`.
2. `ShardRegistry::from_env_or(cli_shard)`: `STELL_SHARDS` unset/empty →
   `{cli_shard}` — `sharding.rs:424`.
3. `is_sharded() = len > 1` — the single gate for every shard-aware check —
   `sharding.rs:439` (documented `sharding.rs:385`, `sharding.rs:565`).
4. CLI default `shard = 0` for `Run` and `NodeBootstrap` — `main.rs:6614`,
   `main.rs:6638`.
5. Boot: `let registry = ShardRegistry::from_env_or(shard)` —
   `main.rs:7454`; `let sharded = registry.is_sharded()` — `main.rs:7457`.
6. Extras loop spawns workchains ONLY if sharded:
   `registry.is_sharded() && *s != MASTERCHAIN_SHARD` — `main.rs:8111`
   (loop at `main.rs:8108`, spawn at `main.rs:8133`).
7. Secondary gates: `STELL_WORKCHAIN_OBSERVER` observer mode —
   `main.rs:8118`; `STELL_XPC_ACTIVATION_HEIGHT` → `XpcActivation::Disabled`
   default — `main.rs:2723`, `xshard2pc.rs:242`.

### Tests covering workchain paths

Integration (`stellereum/tests/`, `#[test]`/`#[tokio::test]` counts via `rg -c`):

| File | Tests | Covers |
|---|---|---|
| `sharding_m1_tests.rs` | 4 | two shards in one process, shard-stamped blocks, wrong-shard rejection |
| `sharding_m2_tests.rs` | 5 | cross-shard transfer debit/credit/supply conservation |
| `sharding_m3_tests.rs` | 6 | ack/bounce atomicity over `cross_shard_out` |
| `sharding_topology_tests.rs` | 6 | split/merge, caps, migration abort |
| `xshard_2pc_tests.rs` | 11 | 2PC prepare/vote/commit |
| `xshard_replay_tests.rs` | 5 | cross-shard replay protection |
| `cross_shard_anchor_tests.rs` | 4 | header-anchored verification, registry mirror |
| `cross_shard_persistence_tests.rs` | 4 | cross-shard persistence |
| `cross_shard_e2e_pq_tests.rs` | 3 | cross-shard PQ end-to-end |
| `multi_shard_stress_bench_tests.rs` | 1 | multi-shard stress/bench |
| `sequencer_m3_tests.rs` | 5 | sequencer M3 |
| **Integration total** | **54** | |

Unit tests in `src` (totals: `main.rs` 51, `runtime.rs` 44, `sharding.rs` 45,
`rpc.rs` 122): shard-pinned examples include registry default/single tests
(`sharding.rs:5981`), `--shard 1` regression (`sharding.rs:6008`),
`registry_publishes_the_latest_workchain_head` (`sharding.rs:8498`),
workchain faucet tests (`rpc.rs:9970`, `rpc.rs:10026`, `rpc.rs:10075`),
`get_shards` topology tests (`rpc.rs:11457`, `rpc.rs:11499`),
`refresh_workchain_set_from_master` tests (`runtime.rs:10476`–`runtime.rs:10545`),
cross-shard transport tests (`network.rs:3055`–`network.rs:3175`),
shard-binding sync test (`sync.rs:2213`).
Simulator (`simulator.rs`) has **no** 2-shard mode — it is a single-shard
deterministic devnet (`simulator.rs:1`–`simulator.rs:80`); multi-shard
coverage lives in `Cluster::new_sharded` test helpers (`runtime.rs:7859`)
and the files above.

## 2. Assessment

**(a) Reachable on the default boot path? NO.**
Default = CLI `--shard 0` (`main.rs:6614`) + `STELL_SHARDS` unset →
`from_env_or` returns `{0}` (`sharding.rs:424`) → `is_sharded() == false`
(`sharding.rs:439`) → extras loop filter (`main.rs:8111`) yields zero
iterations → `start_workchain_shard` (`main.rs:389`) never runs. All runtime
shard-aware checks are gated on `is_sharded()` (`runtime.rs:1119`,
`runtime.rs:2699`, `runtime.rs:3699`, `runtime.rs:4892`, `runtime.rs:6211`;
`consensus_net.rs:948`; `mempool.rs:262`). Workchain code is live but
unreachable without explicitly setting `STELL_SHARDS=0,1`.

**(b) Shared state / commitment domains? YES — three shared, one separated.**

- Shared 1 — finalized-header registry: one `FinalizedHeaderRegistry` per
  process, masterchain + workchain extras share it (`main.rs:7459`, passed at
  `main.rs:8143`); masterchain block commits latest workchain heads via
  `collect_shard_header_commitments` (`runtime.rs:1361`) reading
  `workchain_headers` (`sharding.rs:4734`); proposals checked by
  `check_shard_header_commitments` (`runtime.rs:1450`).
- Shared 2 — staking/validator set: workchain keeps its own ledger EMPTY and
  reads the master's via `master_staking` alias (`runtime.rs:568`,
  `runtime.rs:1137`); rotations converge via
  `refresh_workchain_set_from_master` (`runtime.rs:7484`, repaired periodically
  `main.rs:4305`).
- Shared 3 — transport/process: one infnode `Node` shared by all shards in
  the process (`main.rs:8098` comment); cross-shard KV is node-local
  (`network.rs:2282`); topics are shard-scoped only when sharded
  (`consensus_net.rs:948`).
- Separated: per-shard store (`main.rs:364` → `./data/store-shardN`), per-shard
  mempool file (`main.rs:350`), per-shard state engine; bridge intents settle
  masterchain-only, workchain settlement fails closed (`state_engine.rs:2879`).

**(c) How many tests pin it? ~54 integration + ~20–30 shard-named unit tests.**
Cutting requires deleting/rewriting 11 integration files plus unit tests in
`sharding.rs` (45), `runtime.rs` (44), `rpc.rs` (122), `main.rs` (51),
`network.rs`, `sync.rs`.

**(d) Blast-radius estimate.**

- CUT (delete): touches ≥10 `src` files and the 11 test files above. The
  dangerous part is not the workchain-only code (`start_workchain_shard`,
  `xshard2pc.rs` full file, topology split/merge) but the **shared seams**:
  `ShardRegistry`/`is_sharded` gating used by the single-shard path,
  `collect/check_shard_header_commitments` in every masterchain proposal,
  `Faucet`/address-routing shard rules in `rpc.rs`, mempool pin
  (`main.rs:531`), topic construction (`consensus_net.rs:948`), sync shard
  binding (`sync.rs:2213`), bridge gate (`state_engine.rs:2879`), SVM routing
  (`svm.rs:3326`). A bad cut regresses the live single-shard consensus path.
- UNPARK (serve + fund + test live): touches **0 code files** — it is
  config/ops: set `STELL_SHARDS=0,1`, provision `./data/store-shard1` +
  `./data/mempool-shard1.bin` (`main.rs:350`, `main.rs:364`), fund faucet via
  `STELL_FAUCET_KEY_FILE` (`main.rs:405`), decide `STELL_WORKCHAIN_OBSERVER`
  (`main.rs:8118`) and `STELL_XPC_ACTIVATION_HEIGHT` (`main.rs:2723`,
  default `Disabled` = legacy outbox flow), then soak on testnet.

## 3. CUT plan (file-by-file, if chosen)

1. `main.rs`: delete `start_workchain_shard` (`main.rs:389`–`~main.rs:640`),
   `store/mempool_path_for_shard` sharded branches (`main.rs:350`,
   `main.rs:364`), extras loop (`main.rs:8108`–`main.rs:8150`),
   `xpc_activation_from_env` wiring if 2PC goes too (`main.rs:2711`).
2. `sharding.rs`: delete `ShardRegistry` env parsing / multi-shard topology /
   `workchain_headers` + `ShardHeaderCommitment` plumbing, keep single-shard
   routing constants; highest regression risk (225 `ShardId` sites).
3. `runtime.rs`: delete `master_staking`, `with_shard` sharded branch
   (`runtime.rs:1119`), header-commitment collect/check (`runtime.rs:1361`,
   `runtime.rs:1450`), `refresh_workchain_set_from_master`
   (`runtime.rs:7484`), `Cluster::new_sharded` helpers (`runtime.rs:7859`).
4. `xshard2pc.rs`: delete whole module + activation enum (`xshard2pc.rs:242`)
   if 2PC is cut with it; else keep `Disabled` only.
5. `network.rs`: delete `CrossShardTransport`, cross-shard KV, topic helpers
   (`network.rs:134`, `network.rs:1753`–`network.rs:1852`).
6. `rpc.rs`: delete shard-type/routing/faucet-shard branches
   (`rpc.rs:3640`, `rpc.rs:3696`, `rpc.rs:2608`), keep shard-0 behavior.
7. `mempool.rs`, `consensus_net.rs`, `sync.rs`, `state_engine.rs`, `svm.rs`:
   delete sharded branches, keep single-shard defaults
   (`mempool.rs:262`, `consensus_net.rs:948`, `sync.rs:2213`,
   `state_engine.rs:2879`, `svm.rs:3326`).
8. Tests: delete the 11 integration files (§1 table) + shard unit tests;
   re-pin single-shard-only coverage (registry, faucet, `get_shards`).

## 4. UNPARK plan (if chosen)

1. Serve: `STELL_SHARDS=0,1`, single process (cross-shard KV is node-local).
2. Fund: workchain genesis funds ONLY dev/faucet account (`main.rs:402`);
   provide `STELL_FAUCET_KEY_FILE`; confirm `GENESIS_FAUCET_BALANCE`.
3. Observe-first: start with `STELL_WORKCHAIN_OBSERVER=1` (`main.rs:8118`)
   to dodge N=3 equal-power quorum deadlock, then promote to validating.
4. Protocol: leave `STELL_XPC_ACTIVATION_HEIGHT` unset (legacy outbox flow,
   the tested mode) until 2PC (`xshard2pc.rs`) passes testnet soak.
5. Test live: run the 54 integration tests + a 2-shard testnet soak
   (finality on both shards, one cross-shard transfer, one masterchain
   rotation propagating via `refresh_workchain_set_from_master`).
6. Mainnet: monitor per-shard stores, header-registry lag
   (`workchain_headers`), XPC activation boundary agreement across operators.

## 5. RECOMMENDATION

**UNPARK (staged: testnet observer → validating → XPC), do not CUT.**

Numbers: reachable-on-default = NO (gate = 1 env var + `is_sharded()`,
`sharding.rs:379` + `sharding.rs:439` + `main.rs:8111`); shared domains = 3
(header registry, staking ledger, transport) vs separated stores;
tests pinning = 54 integration + ~20–30 unit; CUT blast radius ≈ 10 src
files + 11 test files + 291 narrow-match lines (+225 `ShardId` sites in
`sharding.rs` alone) with direct regression risk to the live single-shard
proposal path; UNPARK code diff = 0 files (env/config + soak only).

Why: the code is parked behind a clean, single-predicate gate that leaves
the default path byte-identical (`sharding.rs:385`); deletion surgery on
shared commitment/validator-set seams risks the working single-shard chain
to remove code that 54+ tests already cover. Unparking costs ops effort,
not code risk.

## 6. Risks of each

- CUT risks: breaking single-shard proposal validation (header-commitment
  collect/check), address routing, faucet, sync binding; losing 54 tests of
  coverage; re-adding sharding later costs far more than keeping the gate.
- UNPARK risks: workchain liveness/quorum ops (N=3 deadlock note,
  `main.rs:8116`); faucet key management; storage doubling (second store);
  XPC 2PC still default-off so cross-shard value runs legacy flow until
  activation; needs testnet proof before mainnet — never enable
  `STELL_SHARDS=0,1` on mainnet without the §4 soak.
