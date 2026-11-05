# 03 — VM & Execution (HDAE Phase-2, code truth)

Sources: `stellereum/src/contract.rs`, `svm.rs`, `evm_adapter.rs`,
`state_engine.rs`, `runtime.rs`, `mempool.rs`, `native_api.rs`, `orderbook.rs`,
`pmm.rs`, `oracle.rs`, `bridge.rs`, `xshard2pc.rs`, `governance.rs`,
`staking.rs`, `zkml.rs`.

## 1. SVM vs EVM adapter

- SVM: gas table `svm.rs:38` (`GAS_BASIC_TRANSFER 280000`), cancel 100 (`:40`),
  place 1200 (`:41`), zkML-verify 5000 (`:42`), patricia lookup 50 (`:43`);
  session-grant publish 1500 (`:113`).
- Contract caps: 2 MiB code (`contract.rs:45`), 8 call args (`:50`), 50M fuel
  (`:53`); 13 `linker.func_wrap("host", …)` registrations
  (`contract.rs:1193-1413`): `sload` `:1193`, `sstore` `:1201`, `emit` `:1220`,
  `caller` `:1241`, `value` `:1251`, `block_time` `:1259`, `block_hash` `:1267`,
  `calldata` `:1277`, `sha256` `:1296`, `blake3` `:1321`,
  `ed25519_verify` `:1346`, `return_data` `:1390`, `send_message` `:1412`.
- EVM adapter: `CHAIN_ID 5757` (`evm_adapter.rs:51`, hex `0x167d` `:81`);
  serves dynamic `effective_chain_id` (`:57-58` → `zkml.rs:234-235`).
  Gas-model/EIP-1559: NO base-fee engine behind the adapter — static defaults
  `BASE_FEE_HEX`/`DEFAULT_BASE_FEE` (`evm_adapter.rs:115-123`); `eth_feeHistory`
  surface at `:328-368` (typed `:329-340`, direct helper `:350-368`).

## 2. Apply order

- Entry: `runtime.rs:8184` (`apply_block`), advance `:6894`
  (`apply_and_advance`), fees/rewards `:6884` (`apply_block_fees_rewards`);
  decided-block path `:6123` (`apply_decided`); equivocation slashes `:2188`,
  downtime slashes `:5983`.
- Documented order inside transition: fees/rewards → unbonding → downtime slash
  (comment `runtime.rs:6737`); exact interleave: txs → actor mailbox → fees →
  reward → unbonding → downtime slash (`state_engine.rs:6437`, transition fn
  `:6480`, runtime wrapper `:6872-6899`, order restated `:6898`) — the linear
  "fees first, then txs" phrasing is corrected (txs run first).
- Failure-fee (F-01): `failure_fee_state` (`state_engine.rs:1153`), mirrors at
  `:862,:1132-1220,:1314-1322`; invariant: failed txs still debit floor-or-0.

## 3. Mempool admission gates

- Caps: `MAX_ACTIVATION_BUFFER_NONCES_PER_ACCOUNT 4` (`mempool.rs:20`),
  `PQ_ACTIVATION_SURCHARGE_GAS 45000` (`:24`), `MAX_GLOBAL_BUFFERED_TXS 2048`
  (`:50`), sender-penalty floor `FAILED_SENDER_PENALTY` (`:648`) /
  `MAX_FAILED_SENDER_PENALTY` (`:653`); journal magic `MP03` (`:710`),
  legacy `MP02` (`:713`).
- Chain-id: cross-network barrier fail-closed always-on (`:1829-1843`);
  unbound-activation gate from committed height (`:1810-1828`,
  `consensus_chain_id()` `:1823`).
- Replay: refused cheap pre-crypto (comment `:1817-1818`); nonce mechanics live
  in `failure_fee_state`/sender-nonce paths (`state_engine.rs:1153+`) — no
  `NONCE_WINDOW` const exists in tree (grep zero hits); window behavior = the
  `MAX_*_NONCES_PER_ACCOUNT` caps above (`mempool.rs:20,45`).
- Fee gate: priority ordering + wire/proof-unit caps before crypto (`mempool.rs:1861-1869`);
  pure-PQ scheme gate (`:1844-1859`).

## 4. Faucet / paymaster-sponsor / sessions (one-liners)

- Faucet: `Faucet` drip `STELL_FAUCET_DRIP_STELL`, default 10 STELL
  (`rpc.rs:274-275`, default `default_drip_nano` `:693-700`); public drip
  `PUBLIC_DRIP_NANO` 5 STELL (`:599-602`) + 45-min cooldown
  `PUBLIC_DRIP_COOLDOWN_SECS` (`:604-607`); genesis funding (`runtime.rs:179`),
  test funding (`:3588`).
- Paymaster/sponsor: rejection census tracks `rej_sponsor` (`runtime.rs:892`);
  policy = `check_sponsor_policy` (`sharding.rs:3892-3916`: 64 B ed25519 inner,
  expiry, allowed-targets, max-fee cap); sponsored path
  `runtime.rs:2694-2697,2787-2819` (no `PAYMASTER` const in `svm.rs` — policy
  lives in `sharding.rs`, accounting in `runtime.rs`).
- Sessions: `GAS_PUBLISH_SESSION_GRANT 1500` (`svm.rs:113`); domain
  `STELL_SESSKEY_V1` (`zkml.rs:209`); native API `stell_sessionKeyRegister`
  + `stell_sessionBudget` (`native_api.rs:329-333`, `native_api.rs:9`).

## 5. DeFi / gov / staking one-liners

- CLOB: pairs 1/2/3 STELL-USDT/TON/GRAM (`orderbook.rs:9-11`); actor
  `OrderbookActor` (`:83`), `submit_order` (`:142`).
- PMM: base 250000 micro-USD (`pmm.rs:30`), depth cap (`:33`), redemption
  buffer 2000 bps (`:35`).
- Oracle: staleness 15 min (`oracle.rs:10`), deviation 1000 bps (`:11`),
  USDT peg floor 950000 (`:33`), TWAP 3600 s (`:34`), `check_freshness` (`:64`).
- Bridge: truth-gated relay per module docs (`bridge.rs:14-23`); withdrawal
  50k threshold (`:34`), 1 h timelock (`:35`), 500k/h rate+deposit limits
  (`:36,:42`), 100M mint cap (`:47`), 24 h refund grace (`:49`).
- 2PC: state tags + codes (`xshard2pc.rs:77-95`), prepare timeout 64 heights
  (`:105`), activation-height switch (`:232-259`), pre-activation transfers
  grandfathered (`:64`).
- Gov: quorum 6666 bps (`governance.rs:30`), floor 3333 (`:34`), 3-day vote
  (`:36`), 10k-STELL proposal stake (`:38`), bond cap (`:46`), reward cap (`:50`).
- Staking: bond floor (`staking.rs:59`), buffer (`:72`), 250 max / 150 target
  validators (`:199,:204`), slash 500/10 bps (`:231,:235`), commission delay
  7200 (`:294`), emission cap (`:225`), F1 accumulator (`:636-668`).

## 6. Fee-batching parity harness (no static ns/tx in tree)

- Harness: `stellereum/benches/fee_path.rs:10-24` (428-tx fixtures isolating
  per-tx FEE overhead: `fee_plain_seq` / `fee_mixed_seq` / `fee_oom_seq` /
  `apply_plain_wave` parallel) prints
  `[bench][fee][<name>] n=428 wall=<ms> (<ns>/tx)` (`:168`) via
  `Instant` samples (`:158-161`); engine funding (`:24`).
- Parity tests (correctness, not speed):
  `stellereum/tests/fee_batching_parity_tests.rs:5-12` —
  `plain_block_matches_sequential_singles` (`:68-114`, N=64, all-success
  plain block == sequential `apply_transaction`), `mixed_fee_vectors_are_pinned`
  (`:201+`) + `mixed_fee_vectors_parallel_waves` (`:234+`) over
  `mixed_fixture` (`:158-186`: success/failure/sponsored/nonce-gap rows,
  `FLOOR 500_000` `:35` vs `GAS_BASIC_TRANSFER`).
- No before/after ns/tx values are pinned in files; measured walls are
  runtime-only (UNVERIFIED static count added: 0).

## 7. Shard-2 soak (2-shard live cluster)

- Suite: `stellereum/tests/shard2_soak_tests.rs:7-14` (running 2-shard
  cluster, `SOAK_HEIGHTS 10` `:33`, `SHARD0/1` `:31-32` via `ShardRegistry`).
- Pins: both-shards-finalize (`:83-103`, every height finalized, height ==
  `SOAK_HEIGHTS+1`); cross-shard conserves supply end-to-end
  (`:110-179`, consumption record `:148`, post-soak accounting `:167-179`);
  rotation propagates to workchain (`:187-243`, staged `:231`, installed
  `:237-243`); freeze-and-heal (`:252-293`, frozen shard finalizes nothing
  `:276`, healed catches up `:283`, post-heal credit `:290-293`).
- Activation gate (not soak): `xpc_activation_from_env`
  (`main.rs:2723-2736`, `XpcActivation::Disabled` default / `FromHeight(h)`).

## 8. Breaker bounds (virtual-clock pins)

- Nil-breaker: `NIL_CIRCUIT_BREAKER_K 3` (`consensus.rs:3826`, applied
  `:4677-4679`); bound fn `breaker_fire_bound_ms = K*2*BASE_MS`
  (`liveness_breaker_tests.rs:64-65`, `BASE_MS 1000` `:55`, `TICK_MS 100`
  `:53`); pin `full_stall_trips_nil_breaker_within_bound_and_heals`
  (`:135-212`, asserts K==3 `:137`, no-fire before K `:140-145`,
  `measured_ms <= bound_ms` `:206-212`); `flapping_proposer_never_commits_nil`
  (`:252+`, `consecutive_nil_rounds < K` `:354`); healthy path
  `healthy_fast_rounds_never_fire_breaker` (`:473+`).
- Deadlock/timeout: `deadlock_timeout_defaults_to_300s`
  (`deadlock_breaker_tests.rs:118`), `MAX_DEADLOCK_JUMP 65536` bound +
  `cap_hold_to_two_x_bound` (`liveness_breaker_tests.rs:16-22`);
  `straggler_hold_extends_exactly_per_cap` (`:366+`, cap-formula bound
  `:431-442`); `ROUND_LOOKBACK 8` (`:10`).

## 9. Staking model — ops + checks (code truth)

- Consts: `MIN_VALIDATOR_BOND` (`staking.rs:59`), `STELL_MIN_BOND_BUFFER`
  (`:72`, floor fn `:75`), `MAX_ACTIVE_VALIDATORS 250` (`:199`),
  `TARGET_MIN_VALIDATORS 150` (`:204`), pools `STAKING_POOL [0x53;32]`
  (`:211`) / `REWARDS_POOL [0x52;32]` (`:220`),
  `REWARDS_EMISSION_CAP` (`:225`), `MIN_DELEGATION` (`:227`),
  `UNBONDING_PERIOD_SECS` (`:229`), slashes `EQUIVOCATION 500` (`:231`) /
  `MICRO_COMMITTEE 10000` (`:233`) / `DOWNTIME 10` (`:235`),
  `DOWNTIME_MISS_THRESHOLD 10` (`:237`), commission
  `DEFAULT 1000 BPS` (`:265`) / `MAX_DELTA 500` (`:285`) /
  `EFFECT_DELAY 7200` (`:294`) / `COOLDOWN 7200` (`:300`),
  `JAIL_RELEASE_DELAY 1000` (`:278`).
- Ops: `bond` (`:1051`, refuses `BondBelowMinimum` `:1061`,
  `AlreadyValidator` `:1067`), `bond_genesis` (`:1098`), `unbond` (`:1502`,
  governance-lock check `:1520`, jail check `:1575`),
  `delegate` (`:1542`), `slash` (`:2058`), `slash_equivocation` (`:2244`),
  `slash_equivocation_verified` (`:2292`), `slash_proposal_equivocation_verified`
  (`:2407`), `slash_pq_equivocation` (`:2712`), `slash_downtime` (`:2822`);
  `validator_set_gains` (`:830`), `reentry_liveness_risk` (`:858`).
- Checks (fail-closed): `CooldownNotElapsed` (`:310`/`1031`/`1196`/`1729`),
  `LockedInGovernanceVote` (`:337`/`1390`/`1520`/`1627`/`1724`),
  `Jailed`/`NotJailed` (`:370-372`/`1169-1194`/`1737`/`2995`),
  `BondBelowMinimum/DelegationBelowMinimum/InsufficientBond` (`:394-410`),
  `BadSlashBps/BadCommission/CommissionDeltaExceeded/CommissionNotDue`
  (`:284-299`/`425-434`), vesting floor `check_vesting_balance_floor`
  (`:3246`).
