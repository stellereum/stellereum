# FUZZING — deterministic economics battery

Battery: `stellereum/tests/fuzz_economics_ext.rs` (3 tests, fixed seeds,
bounded iters, no wall clock, no new deps). Run:

```sh
cd stellereum && cargo test --test fuzz_economics_ext --no-fail-fast
```

Nightly: `./scripts/nightly_gate.sh` runs clippy `-D warnings`, full lib
tests, this battery, then `./scripts/feature_matrix.sh` (no flags) and
`stellereum/scripts/audit-repro.sh --quick` (root has no
`scripts/audit-repro.sh`; root has no `.github/workflows`, so no nightly.yml).

## What it covers

1. **Staking ops** (`fuzz_staking_ops_conserve_stake_every_n`, 600 ops):
   delegations / undelegations / unbonds / slashes (incl. downtime path) /
   redelegations / rewards / claims / withdrawals interleaved via xorshift.
   Every 25 ops it pins: stake conservation
   (`active + unbonding + withdrawable + burned == bonded_in − withdrawn`,
   via `StakingLedger::ledger_stake_supply` + burn/withdraw ledgers),
   `total_burned` counter exactness, rewards `pool + claimed == minted`,
   and delegations-map == delegated-aggregate. A deterministic tail then
   forces a full lifecycle (delegate → slash → exit → mature past
   `UNBONDING_PERIOD_SECS` → withdraw both legs) plus fail-closed probes.
2. **Mempool orderings** (`fuzz_mempool_admission_orderings_...`, 120 funded
   txs, 8 senders, cap 64): the same multiset admitted in identity /
   shuffled / reversed order. Every ordering must hold: `len <= cap`,
   per-sender quota, reservation == sum of pooled `tx_cost` (F-03), and
   `select()` non-increasing `(priority, fee)` order. Replaying the shuffled
   order must reproduce the identical pool bit-for-bit (determinism pin).
3. **Churn linearity** (`fuzz_mempool_full_pool_churn_stays_linear`, 60 bids
   into a full 16-slot pool): each displacement must pay at least
   `Mempool::eviction_premium` over the displaced floor, the floor ratchets
   monotonically, and the final floor stays within the bids actually paid
   (rules out the old exponential 2x ratchet).

## How to extend

- New staking op: add an arm to the `match rng.below(100)` in test 1 AND
  update the two external ledgers in the same arm (`bonded_in` on inflow,
  `withdrawn_out` on outflow, `burned_expected` on slash, `claimed_out` on
  claim). Every other transition must leave `ledger_stake_supply` unchanged.
- New mempool invariant: add it to `assert_pool_invariants` so all three
  orderings check it. New admission pressure: extend `build_candidates`
  (keep nonces sequential per sender, keep `gas >= priority` so bids stay
  funded, keep balances covering).
- Keep every test under ~30s; the battery must finish well under 120s.

## Seed policy

- Seeds are `*_SEED` constants at the top of the file. Fixed forever unless
  the covered logic changes; a seed change is a review-visible event, never
  a drive-by tweak.
- Never use wall time, thread RNG, or OS randomness in this file. Clocks in
  tests are `AdmissionCtx::new(fixed)` / monotone counters only.
- If a seed stops finding failures it is still load-bearing as a
  regression pin: add a new test with a new seed, do not mutate the old one.
