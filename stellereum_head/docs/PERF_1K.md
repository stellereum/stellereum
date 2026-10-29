# The 1k-TPS recipe: composition × pace × hardware

Measured, not modeled. Every number below comes from a bench or test in
this branch — re-run them to refresh the table (`cargo test --release
--bench packing -- --nocapture`, `cargo test --release --test packing_1k_tests`).

Reference host: 6-core AMD Ryzen 5 3600, 16 GB RAM, bench profile
(release-optimized). Absolute ms move with hardware; the RATIOS (gas math,
apply share of budget, verify cost per proof) travel.

## 1. The recipe (headline)

| Ingredient | Value | Source |
|---|---|---|
| Block composition | **428 plain transfers** = 1 full gas-cap block (428 × 280k = 119.84M ≤ 120M; the 429th needs 120.12M > cap) | `tests/packing_1k_tests.rs:28` |
| Pace | **1 full block every ~427 ms** (428 / 0.427 ≈ 1002 TPS) | math below |
| Hardware | any host that applies 428 mixed txs in ≪ 427 ms (reference: 8.4 ms; 50× headroom) | `benches/packing.rs` `apply_mixed_428` |

**TPS = (txs per block) / (seconds per block) = 428 / 0.427 ≈ 1000.**

There is no fourth ingredient: selection costs 35–550 µs
(`select_multi_plain`: 35.0 µs at pool 428, 60.2 µs at 1 000, 550.5 µs at
10 000 — `benches/packing.rs`), and signature batching is inside the 8.4 ms
apply. The entire 427 ms budget outside ~9 ms of execution belongs to
consensus + gossip.

## 2. Where the numbers come from (this branch, this host)

| Bench row | Measured |
|---|---|
| `select_multi_plain` pool=428 / 1000 / 10000 | packed **428 / 428 / 428**; 35.0 / 60.2 / 550.5 µs total |
| `apply_mixed` n=100 / 428 / 1000 | 3.94 / **8.45** / 13.16 ms wall → 25.4k / 50.7k / 76.0k tx/s in-process |
| `transfer2_verify_1in1out_32bit` / `_64bit` | **8.94 ms** / **12.89 ms** per verify (live-path predicate `verify_balanced_with_ranges`) |
| `packing_428_plain_transfers_fit_120m_gas` | 120M / 280k = 428; pool of 500 selects exactly 428; 429th provably unfits |

Read: execution clears a full 428-block in **~2% of the 427 ms interval**
(8.45 / 427). In-process apply runs at 50k+ tx/s — **execution is not the
bottleneck and never was** (the old bottleneck read in
`scripts/tps_load.py` agrees: Token ~613k tx/s, Native ~26k tx/s).

## 3. Pace: what the chain must actually do

1000 TPS needs 2.34 full (428-tx) blocks per second, i.e. a sustained
**~427 ms block interval**. Against today's consensus knobs:

- `STELL_MIN_BLOCK_MS` floor = 400 ms, round timeout default = 3 s
  (`STELL_ROUND_TIMEOUT_MS`; see the TPS summary in `scripts/tps_load.py`).
- At an 800 ms cadence (for comparison), full 428-blocks yield **535 TPS** — halfway there.
- At the 400 ms floor (empty-round fast path, back-to-back full blocks),
  428-blocks yield **1070 TPS** — the recipe closes.

So the path to 1000 TPS is a pacing change, not an execution change.
Any ONE of these closes the gap (pick by operational taste):

1. **Sustain ~427 ms intervals** — keep the floor at 400 ms and let full
   mempools propose back-to-back (no code change; needs the load harness
   below to prove the network keeps up).
2. **Raise `MAX_BLOCK_GAS`** — e.g. 280M gas → 1000 plain/block → 1000 TPS
   at a relaxed 1.0 s cadence. Costs: fatter gossip (~115 KB minimal —
   still far under the 24 MB wire cap), ~20 ms applies (linear from §2:
   13.2 ms at 1000 mixed). Raise only with a fat-block sync measurement
   (the constant's own doc comment says the same).
3. **Mix** — 600-tx blocks (~168M gas) at 600 ms cadence = 1000 TPS.

What does NOT work: more threads on execution (50× headroom already),
bigger mempools (selection is sub-ms at 10k), or faster proofs for plain
TPS (plain transfers verify no proofs).

## 4. The confidential caveat (mixed blocks)

Each shielded 1-in/1-out `Transfer2` costs **~9 ms (32-bit) / ~13 ms
(64-bit)** of serial verify on the apply worker, and proof units cap a
block at 2048 units (~1024 1-in/1-out transfers). A 428-block carrying a
Transfer2 fraction `f` needs roughly `8.5 ms + f·428·11 ms` of apply:

- `f` = 0% (plain): 8.5 ms — fits any cadence.
- `f` = 10%: ~55 ms — still fits 427 ms, but eats the margin.
- `f` = 100%: ~4.7 s — verify-bound; shielded-full blocks pace at
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
