# STELLEREUM deterministic consensus simulator

Two ways to run a multi-node chain on one machine. They answer different
questions — use the right one.

## 1. What runs where

| | `scripts/local-cluster.sh` | `stellereum/tests/sim_*.rs` (this doc) |
|---|---|---|
| What runs | REAL `stellereum` binaries, one process per node, real P2P + RPC on 127.0.0.1 | REAL `ValidatorRuntime` / `HeightConsensus` / `VoteSet` code paths, N runtimes in ONE process |
| Time | Wall clock (minutes per scenario; `chaos` stops node3 for 60s) | VIRTUAL clock (a 10-minute WAN scenario runs in milliseconds) |
| Determinism | No (scheduler, network jitter) | Yes — fixed seed, seeded xorshift64* PRNG, fixed broadcast order. Same seed ⇒ same fingerprint |
| Fast-forward | No | Yes — virtual hours in seconds via `run_until` / `run_for` budgets |
| Scenario DSL | Bash (`up`, `chaos`, `stop i`) | Rust profiles: `NodeProfile` per member (`power`, `round_timeout_factor`, `late_by`, `down`, loss permilles, delays, `byzantine`) + pre/post-phase orchestration (`set_down`) |
| Best for | Ops realism: ports, keys, peering, RPC, restarts, log inspection | Liveness/safety regression: quorum arithmetic, stalls, skew, equivocation — with assertions |

Rule of thumb: reproduce the CONSENSUS SHAPE in the simulator (seconds,
deterministic, asserted); validate the OPS SHAPE on `local-cluster.sh`
(real binaries, real sockets).

## 2. Scenario catalog

All scenarios live in `stellereum/tests/sim_*.rs`, share the harness in
`stellereum/tests/support/consensus_cluster.rs`, and print a
`[sim][name] seed=… virtual_ms=… best=… common=…` line per run.

| File | One-line semantics |
|---|---|
| `sim_happy3.rs` | Sanity baseline: 3 honest equal-power validators finalize steadily (5 heights / 3300 virtual ms); replay test demands identical fingerprints |
| `sim_slow_voter_unanimity.rs` | One slow voter (5x timeout, 250ms link) under unanimity: finals flow AND every vote is fresh (zero NIL prevotes, post-transient heights decided in round 0) |
| `sim_dead_member_4node.rs` | Kill node 3 at T after liveness: 3/4 (a quorum) keeps finalizing, dead head frozen; then 3-node unanimity kill at T: nothing new finalizes while rounds advance to 60 (why C-death + unanimity = halt) |
| `sim_round_skew_converge.rs` | Staggered starts (6 and 12 rounds late on 4 nodes): all reconverge, late nodes consume future-rule jumps (`sync_jumps` 3, 4) |
| `sim_byzantine_evict.rs` | Equivocating PROPOSER (conflicting re-signed body per slot): honest nodes refuse the second body (12 refusals), no fork, liveness preserved, zero vote-equivocations |

Prior art these files reuse — not duplicate — is listed per-file in each
file's header: static-DOWN cases (`consensus_liveness_harness.rs` 3a/3b/4),
vote-equivocation (`nil_veto_stall_tests.rs`, harness scenario 7),
timeout-vs-link discriminator (`unanimity3_slow_voter_tests.rs`),
message pump / tempo profiles (`consensus_liveness_repro.rs`,
`block_tempo_lan.rs`, `zz_vel_measure.rs`).

## 3. How to add a scenario

Copy-paste template (see `sim_happy3.rs` for the full working example):

```rust
#[path = "support/consensus_cluster.rs"]
mod consensus_cluster;
use consensus_cluster::{ConsensusCluster, NodeProfile};

const SEED: u64 = 0xC10C_0007; // next free CLOC-series seed; document it
const TICK_MS: u64 = 100;
const ROUND_TIMEOUT_MS: u64 = 1_000;

#[tokio::test]
async fn my_scenario() {
    let profiles = vec![NodeProfile::default(), /* … */];
    let mut c = ConsensusCluster::build(4, profiles, SEED, TICK_MS, ROUND_TIMEOUT_MS);
    c.seed_transactions(3).await; // real tx content so state roots evolve
    let report = c.run_until(3, 240_000).await; // budget is ABSOLUTE virtual ms
    println!("[sim][mine] seed=0x{:x} virtual_ms={} best={} common={}",
        SEED, report.virtual_ms, report.best_height, report.common_height);
    println!("{}", report.diagnostics()); // one-line per node: heights, rounds, QCs
    assert!(report.common_height >= 3, "…\n{}", report.diagnostics());
    // …safety half: no fork, no double-votes, roots agree (see template)…
}
```

Conventions (enforced by review, not by code):

1. ONE new file per scenario, `sim_<name>.rs`; one-line semantics added to
   the table above.
2. FIXED seed (`0xC10C_*` CLOC series), documented in the file header. Any
   seed change moves every number — that is the point.
3. VIRTUAL budget sized to the shape: seconds for happy paths, 60s+ for
   stall shapes (a stall must REPORT, not hang). `run_until` budgets are
   absolute virtual ms — for phased scenarios use `c.now_ms() + delta`.
4. PASTE the `[sim]` numbers into the task/PR: heights finalized, rounds
   used (`decide_rounds`), kill times, refusal counts.
5. Pin the MECHANISM, not just the outcome: `sync_jumps > 0` (jumps
   really ran), `proposals_refused > 0` (the attack really ran),
   frozen `decide_rounds` + growing `prevotes_cast` (stall = voting
   without deciding), zero NIL prevotes (freshness).
6. If the scenario needs a harness primitive that does not exist, extend
   `support/consensus_cluster.rs` MINIMALLY (see §4) and say what the
   extension was in the file header.

## 4. Expressiveness limits (what the harness CANNOT do today)

CAN: N real runtimes; equal/unequal power; per-node timeout factor;
initial round offsets (`late_by`); static `down`; vote/precommit loss
(permille, seeded); per-node inbound delay + proposer build delay;
`Byzantine::{DoublePrevote, NilPrevote, DoubleProposal}`; mid-run kill
(`set_down`); QC/round/vote/fingerprint reporting.

CANNOT (with what each would need):

- **Network partitions / healing.** Only the `down` flag + loss permilles;
  no split-brain with a heal step. Would need a delivery matrix
  (allow-list per ordered pair + mid-run rewiring) in `broadcast`.
- **Asymmetric / reordered links.** Delay is per receiving node
  (`inbound_delay_ms`) plus per-sender propose delay; no per-link matrix,
  no reordering beyond delay ties, no jitter distribution. Would need a
  `(from, to)` delay table in `Pending`.
- **Restart mid-scenario.** `set_down(i, false)` flips the flag and resets
  the round timer, but replay/restart fidelity (mempool, lock state vs. a
  real reboot) is UNTESTED — only the kill path is pinned.
- **Evidence / downtime / slashing.** Votes are counted, equivocations
  recorded, but nothing slashes, jails, or rotates power. Would need the
  staking/downtime rules wired into the report loop.
- **Workchains / shards.** Single chain, masterchain-shard bodies only;
  no cross-shard messages, no `shard_headers` divergence.
- **Production timeout ladder.** The harness uses a FLAT per-node timeout
  (+ the 650ms round-0 cap), not the production backoff ladder + view-
  change hold — a stuck height spins FASTER here, so verdicts arrive
  sooner, but per-round timing is not production-faithful.
- **Dynamic sets.** No mid-run power changes, validator joins/leaves, or
  key rotation.
- **Richer Byzantine.** Only double-prevote, nil-prevote, double-proposal:
  no selective equivocation (different votes to different halves), no
  lock-timing games, no proposal withholding.

## 5. Gate

```text
cargo clippy -p stellereum --all-targets -- -D warnings   # 0 warnings, 0 errors
cargo test --test sim_happy3 --test sim_slow_voter_unanimity \
  --test sim_dead_member_4node --test sim_round_skew_converge \
  --test sim_byzantine_evict
```

All green, then update the numbers in §2 from the `[sim]` output lines.
