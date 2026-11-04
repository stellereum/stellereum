# The 1k-TPS recipe: composition × pace × hardware

Measured, not modeled. Every number below comes from a bench or test in
this branch — re-run them to refresh the table (`cargo test --release
--bench packing -- --nocapture`, `cargo test --release --test packing_1k_tests`).

Reference host: 6-core AMD Ryzen 5 3600, 16 GB RAM, bench profile
(release-optimized). Absolute ms move with hardware; the RATIOS (gas math,
apply share of budget, verify cost per proof) travel.

> **DRIFT NOTE (2026-10-20 hygiene pass).** The block gas cap was raised from
> 120M to **500M** in commit `27b1bfb` ("500M block gas cap"), together with a
> 1.75x gas-price hike for confidential ops. This document was measured at the
> old 120M cap and was never updated, so the "428 plain transfers per block"
> figure was stale. This pass recomputes **cap-derived** arithmetic for 500M
> (block composition, TPS, cadence) and labels every **measured** row with the
> size it was actually measured at. Nothing was re-measured here: the bench
> rows in §2 still carry the old 120M numbers, and any figure derived from
> them is marked as an extrapolation.
>
> **PQ SCOPE NOTE (M-01 fallback + M-06, 2026-11-04).** Pure-PQ mode is
> OPT-IN (`STELL_PURE_PQ=1`); every number in §2 was measured on the
> classical (Ed25519) path. PQ figures below are DERIVED from wire
> constants (`src/post_quantum.rs`: Falcon-512 pubkey 897 B / sig 666 B;
> explicit envelope = 9 + 897 + 666 = **1572 B** per tx sig vs 64 B
> Ed25519, ~24.6x; registry-implicit = **675 B**, ~10.5x; µQC at N=100 =
> 64 seats × 666 B ≈ **42.6 KB**) — NOT measured end-to-end. A PQ-enforced
> default was tried and reverted (155/1104 lib failures; suite, sim,
> wallet and genesis assume the dual-stack default), so no PQ-path block
> time or PQ TPS is claimed here. Do not quote this recipe as PQ
> performance.

## 1. The recipe (headline)

| Ingredient | Value | Source |
|---|---|---|
| Block composition | **1785 plain transfers** = 1 full gas-cap block (1785 × 280k = 499.8M ≤ 500M; the 1786th needs 500.08M > cap) | `tests/packing_1k_tests.rs` (`packing_plain_transfers_fit_max_gas`) |
| Pace | **1 full block every ~400 ms** (the `STELL_MIN_BLOCK_MS` floor): 1785 / 0.4 ≈ 4462 TPS | math below |
| Hardware | any host that applies 1785 mixed txs in ≪ 400 ms (reference: 8.4 ms measured at n=428 → ≈ 35 ms extrapolated at n=1785; NOT re-measured) | `benches/packing.rs` `apply_mixed_428` |

**TPS = (txs per block) / (seconds per block) = 1785 / 0.4 ≈ 4462**
(the 1k-TPS target is now cleared by the gas cap alone, see §3).

There is no fourth ingredient: selection costs 35–550 µs
(`select_multi_plain`: 35.0 µs at pool 428, 60.2 µs at 1 000, 550.5 µs at
10 000 — `benches/packing.rs`, measured at the 120M cap), and signature
batching is inside the 8.4 ms apply. The entire 400 ms budget outside ~9 ms of
execution belongs to consensus + gossip.

## 2. Where the numbers come from (this branch, this host)

| Bench row | Measured (at the 120M cap, unless noted) |
|---|---|
| `select_multi_plain` pool=428 / 1000 / 10000 | packed **428 / 428 / 428** (35.0 / 60.2 / 550.5 µs total) — measured at the 120M cap. Under the 500M cap the same pools pack **428 / 1000 / 1785**; the timings were not re-measured |
| `apply_mixed` n=100 / 428 / 1000 | 3.94 / **8.45** / 13.16 ms wall → 25.4k / 50.7k / 76.0k tx/s in-process |
| `transfer2_verify_1in1out_32bit` / `_64bit` | **8.94 ms** / **12.89 ms** per verify (live-path predicate `verify_balanced_with_ranges`) |
| `packing_plain_transfers_fit_max_gas` | 500M / 280k = **1785**; pool of 1800 selects exactly 1785; the 1786th provably unfits |

Read: execution clears a full 1785-block in **≈ 9% of the 400 ms interval**
(35 ms extrapolated from the measured 8.45 ms at n=428; linear in tx count,
NOT re-measured). In-process apply runs at 50k+ tx/s — **execution is not the
bottleneck and never was** (the old bottleneck read in
`scripts/tps_load.py` agrees: Token ~613k tx/s, Native ~26k tx/s).

## 3. Pace: what the chain must actually do

1000 TPS now needs 0.56 full (1785-tx) blocks per second, i.e. a sustained
**~1.79 s block interval** — the gas cap is no longer the binding constraint.
Against today's consensus knobs:

- `STELL_MIN_BLOCK_MS` floor = 50 ms, round timeout default = 3 s
  (`STELL_ROUND_TIMEOUT_MS`; see the TPS summary in `scripts/tps_load.py`).
  The 400 ms floor was cut to 50 ms by the R-tempo re-measurement (2026-10-26):
  the live fleet already ran 50 ms via env with ~1 s loaded bursts.
- At an 800 ms cadence (for comparison), full 1785-blocks yield **~2231 TPS**.
- At the 400 ms floor (empty-round fast path, back-to-back full blocks),
  1785-blocks yield **~4462 TPS** — the 1k-TPS recipe closes with 4× headroom.

So the path to 1000 TPS is a pacing/network change, not an execution change
and not a gas-cap change. Any ONE of these closes the gap (pick by
operational taste):

1. **Sustain ~400 ms intervals** — keep the floor at 400 ms and let full
   mempools propose back-to-back (no code change; needs the load harness
   below to prove the network keeps up).
2. **Mix** — 600-tx blocks (~168M gas) at 600 ms cadence = 1000 TPS.
   (The old "raise `MAX_BLOCK_GAS`" option is DONE: the cap is 500M since
   `27b1bfb`. Raising it further still needs a fat-block sync measurement —
   the constant's own doc comment says the same.)

What does NOT work: more threads on execution (50× headroom already),
bigger mempools (selection is sub-ms at 10k), or faster proofs for plain
TPS (plain transfers verify no proofs).

## 4. The confidential caveat (mixed blocks)

Each shielded 1-in/1-out `Transfer2` costs **~9 ms (32-bit) / ~13 ms
(64-bit)** of serial verify on the apply worker, and proof units cap a
block at 2048 units (~1024 1-in/1-out transfers). The gas cap no longer binds
here (1024 × 6 658 gas ≈ 6.8M « 500M). A full 1785-block carrying a
Transfer2 fraction `f` needs roughly `8.5 ms + f·1785·11 ms` of apply:

- `f` = 0% (plain): ~35 ms at n=1785 (extrapolated) — fits any cadence.
- `f` = 10%: ~2.0 s — exceeds a 400 ms interval; the margin is gone.
- `f` = 100%: ~20 s — verify-bound; shielded-full blocks pace at
  ~90 TPS, not 1000.

(Parallel `batch_verify` across cores recovers part of this on hosts with
spare cores — the 8.94/12.89 ms above are the per-transfer predicate, the
unit the cap math is stated in.) **The 1k recipe is plain-dominated
blocks; shielded throughput is separately proof-bound.** Prefer 32-bit
proofs wherever values fit (`prove_auto` already does this): 1.44× cheaper
to verify per the bench above.

## 5. Proving it end-to-end (load harness)

In-process numbers are necessary, not sufficient. The end-to-end proof is
`scripts/tps_load.py --run -N <accts> -M <txs>`:

- **Fund → wait finality → blast.** Funding precedes submission and the
  harness waits for balances/nonces to be visible before blasting.
- **Sequential per account, parallel across accounts.** Each account's
  nonces submit in order (k only after k−1 returns) so mempool arrival
  order IS nonce order — chains of any depth pass the
  `NONCE_FUTURE_WINDOW = 16` admission gate that killed the old
  concurrent blaster with `NonceGap` rejects.
- **Rejection breakdown by message** is printed per wave and in the
  summary (`rejections: Nx <message>`), so a failed run says WHY.
- Validate without a chain: `--plan` (dry-run math, exit 0 offline),
  `--check-only` (offline harness checks + RPC probes when a node is up;
  offline checks alone gate the exit code with no chain),
  `--self-test` (sign/encode round-trip + harness math, fully offline).
