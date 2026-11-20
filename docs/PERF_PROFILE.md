# PERF_PROFILE — node hot-path CPU, offline (2026-11-02)

Measurement + analysis ONLY. No live nodes touched, nothing restarted,
no src/tests/benches changes (a temporary probe test was used for two
runs, then **deleted** — see §1; final diff of this task = this file).

Companion: `stellereum/docs/program/TEMPO_PROFILE.md` (wall-clock/tempo verdict — code is
≤~1% of live 60–300s/block). This doc goes one level deeper on **CPU**:
which per-height stage and which functions own the milliseconds.

> **Snapshot note (2026-11-20):** the numbers below were measured on the
> 2026-11-02 tree, before the module split and the FULL-PQ wipe. The values
> are the recorded measurements; `file:line` references such as
> `runtime.rs:5147` / `state_engine.rs:4470` now live under `runtime/` and
> `state_engine/` and should be re-grepped before use. The "live
> 60–300s/block" context predates the ruleset-v6 liveness fix; do not quote it
> as the current tempo without a fresh measurement.

## 1. Setup

- Repo: `/home/imm/stellereum-project`, crate `stellereum/`.
- `[[bench]]` check: **no `[[bench]]` sections** in
  `stellereum/Cargo.toml` — benches are `#[test]` fns inside
  `stellereum/benches/{packing,tempo_probe,svm_hot_path,
  zkml_attestation}.rs`, run via `cargo test --release --bench <name>`.
- New code: **none retained**. A temporary
  `stellereum/tests/perf_profile_probe.rs` (correctness asserts only, no
  timing gates) supplied the vote/QC/apply-20 rows in §3; it was run twice
  in release mode, then `rm`'d. `git status` after removal shows no new or
  modified source files from this task.
- Reuse-first: mempool-select, apply-100/428/1000, tx-batch-verify,
  commitment-assembly rows come from the **existing** `packing` /
  `tempo_probe` benches (headers in those files state REPORTS-not-gates,
  median-of-repeats). Existing `[perf]`/`[subtiming]` instrumentation was
  reviewed (`stellereum/src/consensus_net.rs:121` `log_stage`,
  WARN >200ms / DEBUG below) — it covers broadcast sub-stages only, not
  the 5 consensus stages, so direct function timing was used instead.
- Harness shape (for stage mapping): `stellereum/tests/sim_happy3.rs`
  drives real `ValidatorRuntime::{propose, on_proposal, on_prevote,
  on_precommit, try_finalize}` on a virtual clock, tick order
  `propose → prevote → drain → precommit → finalize`
  (`stellereum/tests/support/consensus_cluster.rs`).
- All numbers below: release mode, single dev box, pasted from tool output.
  Rows marked ESTIMATE are arithmetic scalings, not measurements.

## 2. Raw numbers — existing benches (pasted, release)

`cargo test --release --bench tempo_probe -- --nocapture`:

```text
[tempo][staking] 50 vals preimage=15835 bytes time=0.006 ms (median-of-10)
[tempo][contracts] 50 contracts preimage=95711 bytes cold=0.142 ms (misses=50) warm=0.054 ms abi_hits=600 abi_misses=0
[tempo][tokens] 200tok/8bal preimage=274655 bytes time=0.136 ms (median-of-10)
[tempo][assemble] preimage_total=387719 bytes streaming=0.465 ms hot(all-hit,14 clones)=0.211 ms speedup=2.21x hits=168 misses=0
[tempo][validate] batch_verify_20tx=0.476 ms ok=true (0.024 ms/tx)
[tempo][trie] 5k inserts total=10.348 ms (2.1 us/op) root_hash alone=0.000 ms root=1105c6a5
```

`cargo test --release --bench packing -- --nocapture`:

```text
[bench][packing][apply_mixed] n=  100 wall=4.721 ms (21182 tx/s)
[bench][packing][select_multi_plain] pool=  428 packed= 428 time=55.575 us/op total
[bench][packing][select_multi_plain] pool= 1000 packed=1000 time=137.069 us/op total
[bench][packing][transfer2_verify_1in1out_32bit] time=10.271 ms/op per verify
[bench][packing][apply_mixed] n=  428 wall=12.604 ms (33958 tx/s)
[bench][packing][apply_mixed] n= 1000 wall=20.348 ms (49145 tx/s)
[bench][packing][transfer2_verify_1in1out_64bit] time=15.287 ms/op per verify
[bench][packing][select_multi_plain] pool=10000 packed=1785 time=555.879 us/op total
```

## 3. Raw numbers — temporary stage probe (pasted, release, file removed)

`cargo test --release --test perf_profile_probe -- --nocapture`
(3 validators, power 1 each → `total=3 quorum=3`; real `Vote::sign`,
real `VoteSet`/`QuorumCertificate`, 20 mixed txs = 3/4 plain + 1/4
`Transfer`-syscall on a fresh funded engine):

```text
[perfprobe][quorum] total=3 quorum=3
[perfprobe][vote-verify][single] time=0.063 ms
[perfprobe][mempool-select][pool20] time=0.001 ms
[perfprobe][vote-verify][batch4] time=0.106 ms
[perfprobe][propose-build][sign] time=0.018 ms
[perfprobe][vote-verify][voteset_ingest3] time=0.128 ms
[perfprobe][qc-assemble][3of3] time=0.137 ms
[perfprobe][apply][mixed20] wall=0.544 ms (36753 tx/s)
[perfprobe][qc-verify][3sigs] time=0.090 ms
```

Caveat (honest): the `qc-assemble` timer rebuilds the `VoteSet` (3×`add`)
per iteration, so it **includes** ingest. Pure assembly delta ≈
0.137 − 0.128 = **0.009 ms** (ESTIMATE by subtraction); assembly itself
(`VoteSet::certificate_with_parent_vrf`,
`stellereum/src/consensus.rs:2598`) is Vec-push/power-sum bookkeeping —
no crypto when PQ/BLS envelopes are absent.

## 4. Per-height CPU budget (stages as tasked)

### 4a. Sim scale — 20tx block, 3-node (all measured, per node)

| stage | composition | ms |
|---|---|---|
| propose-build (proposer) | select 0.001 + ed25519 sign 0.018 (+ block hash, µs, unmeasured) | ≈0.02 |
| vote-verify | proposal tx-batch 0.476 + ingest 3 prevotes 0.128 + ingest 3 precommits 0.128 + 2× QC-verify 0.180 | ≈0.91 |
| apply | `apply_block_parallel_fees` 0.544 (incl. internal parallel tx-verify) | 0.544 |
| QC-assemble | 2 × pure assemble ≈0.009 | ≈0.02 |
| mempool-select | pool20 | 0.001 |
| (+ finalize sub-row) commitment assembly hot 0.211 / streaming 0.465 — counted iff digest recomputed per height | 0.21–0.47 |
| **total** | | **≈1.7–2.0** |

**Hottest stage at sim scale: vote-verify (~0.91 ms, ≈50% of per-height CPU)** —
dominated by the serial 20-tx signature batch on proposal intake, not by vote crypto.

### 4b. Realistic scale — 428tx mixed block (measured + ESTIMATE)

| stage | composition | ms |
|---|---|---|
| apply | measured `apply_mixed_428` | **12.604** |
| vote-verify | proposal tx-batch: 428 × 0.024 linear from §2 (ESTIMATE) ≈10.2 + vote/QC constant 0.44 | ≈10.6 |
| mempool-select | measured, 428-pool | 0.056 |
| QC-assemble | pure, block-size independent | ≈0.02 |
| propose-build | select + sign, block-size independent | ≈0.07 |
| (+ finalize sub-row) commitment assembly | 0.21–0.47 (block-size dependent via preimage bytes; small snapshot here) | 0.21–0.47 |
| **total** | | **≈23.6** |

**Hottest stage at realistic scale: apply (~12.6 ms, ≈53%), vote-verify
close second (~45%).** Note the crossover: apply scales sublinearly
(47µs/tx @100 → 29µs/tx @428 → 20µs/tx @1000 — rayon helps), while the
serial proposal-intake batch scales linearly, so at very large blocks
(~1785tx: serial verify ≈43ms ESTIMATE vs apply ≈30ms ESTIMATE) the
proposal re-verification would take the lead.

### 4c. Wall context (why this changes nothing in TEMPO)

Happy-path intra-height wall is 130–260ms (TEMPO §2.3) while total per-height
CPU here is ~2ms (sim scale) – ~24ms (428tx): wall is tick/network
scheduling, e.g. DECIDED→FINALIZED 66ms wall vs 0.5ms CPU apply. Against
live 60–300s blocks, even the 428tx budget is ~0.004–0.04%.

## 5. Hotspot ranking — top-3 functions by wall share (428tx mixed)

1. `InMemoryStateEngine::apply_block_parallel_fees`
   (`stellereum/src/state_engine.rs:4470`) — **12.604 ms measured**.
   Includes parallel tx-sig verify (`:4557`
   `verify_signatures_batch_parallel`), SVM execution, state writes.
2. `Transaction::verify_signatures_batch`
   (`stellereum/src/sharding.rs:4024`) via proposal intake
   (`stellereum/src/runtime.rs:5147`, verify-once cache `:5138–5156`) —
   **≈10 ms ESTIMATE** @428tx (0.476 ms measured @20tx, linear scale).
   Same ed25519 work apply already does at `:4557`: every tx signature is
   verified **twice per height per node** (once serial at intake, once
   parallel inside apply).
3. Commitment assembly `assemble_cached_digest`
   (`stellereum/src/commitment.rs:1751`; streaming digest `:1804`) —
   **0.211 ms hot / 0.465 ms streaming measured** (388 KB snapshot) and
   `Mempool::select_for_block_multi`
   (`stellereum/src/mempool.rs:2488`) — **0.056 ms @428-pool …
   0.556 ms @10k-pool measured**. Whichever is #3 depends on snapshot/pool
   size; both are ≤2% of the §4b budget.
   Vote crypto for reference (constant in block size):
   `Vote::verify` (`consensus.rs:1642`) 0.063 ms,
   `Vote::verify_batch` (`:1704`) 0.106 ms/4,
   `VoteSet::add` (`:2330`) path 0.128 ms/3,
   `QuorumCertificate::verify_unified_with_pq_keys` (`:2830`) 0.090 ms/3.

## 6. Ranked optimization proposals (measure-only — no implementation)

1. **Verify-once across proposal intake + apply** (kill the double verify).
   Thread the intake batch verdict (or its cache entry,
   `runtime.rs:5138–5156`) into `apply_block_parallel_fees`
   (`state_engine.rs:4470`) so the second verification at `:4557` is
   skipped on a cache hit. Expected gain: up to **~40% off per-height CPU
   at 428tx** (≈10 ms removed, ESTIMATE). Risk: **medium** — the cache key
   must commit to the exact tx bytes/order; any bypass must stay
   fail-closed; signature-domain code is frozen core (AGENTS.md §7:
   spec + audit note required).
2. **Parallelize the intake batch** (`sharding.rs:4024` →
   `verify_signatures_batch_parallel` at `:4119`, the same primitive apply
   uses). Expected gain: **~3–4× off the serial intake leg on multi-core**
   (≈10 ms → ≈3 ms @428tx, ESTIMATE); subsumed by #1 if both land — do #1
   first. Risk: **low-medium** — identical verdict semantics, rayon already
   a dependency; needs a determinism/correctness diff test, no behavior
   change intended.
3. **Batch the vote-ingest path** (`Vote::verify_batch` at
   `consensus.rs:1704` + `VoteSet::add_verified` at `:2351`, instead of
   per-vote `VoteSet::add` at `:2330` on the RX path — usage to be
   confirmed by reading the RX call sites first). Expected gain:
   **≈2× off vote crypto constant** (≈0.26 ms → ≈0.13 ms/height,
   ESTIMATE) — small in absolute terms, matters only for tiny-block
   regimes where §4a shows vote-verify leading. Risk: **low** —
   all-or-nothing verdict plus existing scalar fallback; confirm fallback
   accounting identical before touching.
4. **Explicit non-levers (do not touch for CPU):** `select_for_block_multi`
   (≤0.56 ms), QC assembly (~0.02 ms), proposal signing (0.018 ms),
   `root_hash` (~0.000 ms). Each <2% alone.
5. **Watch-item (not hot today):** confidential `transfer2_verify`
   10.271 ms (32-bit) / 15.287 ms (64-bit) **per tx** (§2). If
   confidential txs ever dominate blocks, this single predicate becomes the
   hottest function by 100× — track confidential-tx share before any
   block-size growth.

## 7. Gate + constraints compliance

- Files: **new `docs/PERF_PROFILE.md` only**. No behavior changes; no live
  ops; no local-cluster runs (offline benches + deterministic sim-scale
  probe only, dev box, nothing to take down).
- `cargo clippy -p stellereum --all-targets -- -D warnings`: **not re-run
  — pure measurement, zero code touched** (probe test deleted; `git status`
  shows no source modifications from this task). Per task §GATE this
  satisfies the gate conditionally ("if pure measurement, say so").
- Repro: `cargo test --release --bench tempo_probe -- --nocapture` and
  `cargo test --release --bench packing -- --nocapture` from
  `stellereum/`; probe rows reproducible by recreating the deleted probe
  as described in §1/§3.
