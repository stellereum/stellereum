# SHARD2 SOAK — in-process 2-shard proof (UNPARK §4, no live touch)

Scope: `stellereum/tests/shard2_soak_tests.rs` (4 tests, NEW FILE ONLY).
Harness: existing `ShardedCluster` / `Cluster::new_sharded_with_transport`
(`src/runtime.rs:7880`, `:7968`); M2 transfer idiom (`tests/sharding_m2_tests.rs`);
repair path `refresh_workchain_set_from_master` (`src/runtime.rs:7484`).
No existing file modified. Each test < 1 s (limit 180 s).

## Proven (measured `cargo test --test shard2_soak_tests -- --nocapture`)

| # | Test | Numbers |
|---|---|---|
| a | `shard2_soak_both_shards_finalize` | shard0=10 finals, shard1=10 finals, 10 heights each, 13 ms wall (~1437 heights/s in-process) |
| b | `shard2_soak_cross_shard_transfer_conserves_supply` | warmup 3H/side → xfer 10_000 + gas 50 → 3H/side soak; sender 989_950, recipient 10_000, supply 1_000_000 → 1_000_000 conserved; finals0=7 finals1=7 |
| c | `shard2_soak_rotation_propagates_to_workchain` | bond floor 1_100_000_000_000 staged=true at activation=4 (pending power replaces 1); masterchain repair call = false (no-op); installed after next boundary, finals1=3 height1=4 |
| d | `shard2_soak_freeze_and_heal` | freeze: finals0 3→7, finals1 pinned 3→3 (no deadlock); heal: finals1 3→7; post-heal xfer 5_000 credited; finals0=8 finals1=8 |

Suite: 4 passed, 0 failed. Target clippy:
`cargo clippy --test shard2_soak_tests -- -D warnings` → clean.

## Human 2-shard soak recipe (commands only — NOT run here)

```bash
cargo build -p stellereum                      # binary first (script never builds)
./scripts/local-cluster.sh up2 3               # = up 3 --shards 0,1; STELL_SHARDS=0,1, XPC height 5
./scripts/local-cluster.sh status              # expect store-shard1 + XPC ACTIVE on all nodes
# soak: leave running; watch per-shard FINALIZED + workchain genesis lines
grep -c 'FINALIZED block #' run/cluster/node1/live.log
curl -s -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
  http://127.0.0.1:18646
./scripts/local-cluster.sh chaos               # N=3 stall expected (unanimous quorum); N>=4 keeps finalizing
./scripts/local-cluster.sh down                # stop all (data kept)
./scripts/local-cluster.sh reset               # wipe data, fresh boot (keys kept)
```

## Gaps (honest)

1. **Single validator per shard in-harness.** No N=3 unanimous-quorum dynamics
   (the `main.rs:8116` deadlock note); multi-node quorum soak needs the recipe above.
2. **Freeze is cooperative** (heights just not driven) — not a crashed/stalled
   live process; no real P2P, ports, or timers in-harness.
3. **Rotation asserted via direct repair call** (the same function `main.rs:4305`
   runs on timer), not via the timed loop itself.
4. **Legacy outbox flow only** — XPC 2PC activation path covered by
   `xshard_2pc_tests`, not soaked here.
5. **No wall-clock latency/tempo claims** — in-process rounds have no network.
6. **Gate limits (out of scope, not modified):** `cargo clippy --all-targets`
   and `cargo test --lib` currently fail on a pre-existing unclosed delimiter
   in another worker's in-flight edit to `src/bridge.rs` (`mod tests`, 2191→2686);
   lib proper + this suite compile and lint clean.
