# 03 — VM & Execution (HDAE Phase-2, code truth)

Verified on the 2026-11-18 tree (base HEAD `0fdf1eefc` plus the day's in-flight
edits; line numbers match that tree), after the module split. The
old sources `evm_adapter.rs`, `state_engine.rs` and `runtime.rs` are now
directories; `main.rs` is 35 lines. Every `file:line` below was re-grepped;
sections that cannot be re-verified are marked `STALE — see <module dir>`.

> **Ruleset snapshot — historical for consensus values.** Verified under
> ruleset **v2**. Height windows quoted here (e.g. commission delay 7 200) were
> rescaled by v2 (now 30 000) and ruleset v6 is current
> (`FORK_ID = 0x0f584a46`); see `docs/RULESET_V2.md`, `docs/RULESET_V5.md` and
> `docs/RULESET_V6.md`.

Sources: `stellereum/src/contract.rs`, `svm.rs`, `evm_adapter/`,
`state_engine/`, `runtime/`, `sharding/`, `mempool.rs`, `native_api.rs`,
`orderbook.rs`, `pmm.rs`, `oracle.rs`, `bridge.rs`, `xshard2pc.rs`,
`governance.rs`, `staking.rs`.

## 1. SVM vs EVM adapter

- SVM gas table: `GAS_BASIC_TRANSFER 280_000` (`svm.rs:38`), cancel 100
  (`:40`), place 1 200 (`:41`), zkML-verify 5 000 (`:42`), patricia lookup 50
  (`:43`).
- Contract caps: 2 MiB code (`MAX_CONTRACT_CODE_SIZE`, `contract.rs:45`),
  8 call args (`MAX_CONTRACT_CALL_ARGS`, `:50`), 50M fuel
  (`MAX_CONTRACT_FUEL`, `:53`); 13 `linker.func_wrap("host", …)`
  registrations (`contract.rs:1193-1410`): `sload` `:1195`, `sstore` `:1203`,
  `emit` `:1222`, `caller` `:1243`, `value` `:1253`, `block_time` `:1261`,
  `block_hash` `:1269`, `calldata` `:1279`, `sha256` `:1298`, `blake3`
  `:1323`, `falcon512_verify` `:1348` (the former `ed25519_verify` host is
  deleted), `return_data` `:1390`, `send_message` `:1412`.
- EVM adapter: `CHAIN_ID 5757` (`evm_adapter/types.rs:19`), hex `0x167d`;
  serves dynamic `effective_chain_id` (`:25` → `zkml.rs:205`).
  Gas-model/EIP-1559: NO base-fee engine behind the adapter — static defaults
  (`DEFAULT_BASE_FEE`, `evm_adapter/types.rs:91`); `eth_feeHistory` surface at
  `adapter.rs:123,128,144` (snake/camel + direct forms).

## 2. Apply order

- Entry points: `apply_decided` (`runtime/apply.rs:202`),
  `apply_block_fees_rewards` (`:1115`), `apply_and_advance` (`:1125`), block
  transition `state_engine/apply.rs:2584` (`apply_block_transition`);
  cluster path `runtime/cluster.rs:382` (`apply_block`).
- Documented order inside the transition (comment `state_engine/apply.rs:2541`):
  txs → actor mailbox → fees → reward → unbonding → downtime slash; the
  linear "fees first, then txs" phrasing is wrong (txs run first).
- Failure-fee (F-01): `failure_fee_state` (`state_engine/parallel.rs:96`),
  used by the block path; invariant: failed txs still debit floor-or-0.

## 3. Mempool admission gates

- Caps: `MAX_ACTIVATION_BUFFER_NONCES_PER_ACCOUNT 4` (`mempool.rs:20`),
  `PQ_ACTIVATION_SURCHARGE_GAS 45000` (`:24`),
  `MAX_GLOBAL_BUFFERED_TXS 2048` (`:65`), sender-penalty floor
  `FAILED_SENDER_PENALTY` (`:676`) / `MAX_FAILED_SENDER_PENALTY` (`:681`).
- Chain-id: cross-network barrier fail-closed always-on (`chain_binding.rs`;
  error prefix `chain_binding.rs:161`), unbound-activation gate from the
  committed height (`mempool.rs`).
- Replay: refused cheap pre-crypto; nonce mechanics live in
  `failure_fee_state`/sender-nonce paths (`state_engine/parallel.rs:96+`) — no
  `NONCE_WINDOW` const exists in the tree; window behavior is the
  `MAX_*_NONCES_PER_ACCOUNT` caps above.
- Fee gate: priority ordering + wire/proof-unit caps before crypto; pure-PQ
  scheme gate in the same admission path.

## 4. Faucet / paymaster-sponsor / sessions (one-liners)

- Faucet: token drip default 10 STELL (`rpc/faucet.rs:456-460`); public drip
  5 STELL (`PUBLIC_DRIP_NANO`, `:364`) + 45-min cooldown
  (`PUBLIC_DRIP_COOLDOWN_SECS`, `:369`); per-IP cap and lifetime cap live in
  `rpc/faucet.rs`; genesis funding is in `node/bootstrap.rs`.
- Paymaster/sponsor: policy = `check_sponsor_policy`
  (`sharding/transaction.rs:1708`: 64 B ed25519 inner, expiry,
  allowed-targets, max-fee cap). There is no `PAYMASTER` const in `svm.rs`;
  accounting is in the runtime apply path.
- Sessions: `GAS_PUBLISH_SESSION_GRANT` (`svm.rs`); domain
  `STELL_SESSKEY_V1` (`zkml.rs`); native API `stell_sessionKeyRegister` +
  `stell_sessionBudget` (`native_api.rs`).

## 5. DeFi / gov / staking one-liners

- CLOB: pairs 1/2/3 STELL-USDT/TON/GRAM (`orderbook.rs:9-11`); actor
  `OrderbookActor` (`:83`), `submit_order` (`:142`).
- PMM: base 250 000 micro-USD (`pmm.rs:34`), redemption buffer 2 000 bps
  (`:39`).
- Oracle: staleness 15 min (`oracle.rs:11`), deviation 1 000 bps (`:12`),
  USDT peg floor 950 000 (`:34`), TWAP window **91 s** (`:56`; the old
  "3600 s" claim is STALE).
- Bridge: withdrawal 50k threshold (`bridge.rs:33`), 1 h timelock (`:34`),
  500k/h rate limit (`:35`), 100M mint cap (`:46`), 24 h refund grace (`:48`).
- 2PC: prepare timeout 64 heights (`XPC_PREPARE_TIMEOUT_HEIGHTS`,
  `xshard2pc.rs`), activation `XPC_ACTIVATION_HEIGHT = 0` (active from genesis;
  `xshard2pc.rs:146`, `XpcActivation` `:301`), pre-activation transfers
  grandfathered.
- Gov: quorum 6 666 bps (`governance.rs:30`).
- Staking: bond floor (`staking.rs:62`), active/target validators
  (`:209,:214`), slashes 500/10 000/10 bps (`:265,:270,:275`), commission
  delay 7 200 (`:355`), emission cap (`:235`), unbonding period (`:260`).
  Detailed op/check line numbers are STALE — see `stellereum/src/staking.rs`.

## 6. Fee-batching parity harness (no static ns/tx in tree)

- Harness: `stellereum/benches/fee_path.rs` (the old `:10-24` cite is STALE —
  read the file); it prints wall/ns metrics from `Instant` samples.
- Parity tests: `stellereum/tests/fee_batching_parity_tests.rs` — sequential
  vs parallel block equivalence and pinned mixed fee vectors. Line numbers
  from the pre-split pass are STALE; the tests exist and are the proof.
- No before/after ns/tx values are pinned in files; measured walls are
  runtime-only (UNVERIFIED static count: 0).

## 7. Shard-2 soak (2-shard live cluster)

- Suite: `stellereum/tests/shard2_soak_tests.rs` (running 2-shard cluster,
  `SOAK_HEIGHTS`, `SHARD0/1` via `ShardRegistry`).
- Pins: both-shards-finalize, cross-shard supply conservation, rotation
  propagation to the workchain, freeze-and-heal.
- Activation gate: `XpcActivation::from_chain_spec()` (`xshard2pc.rs:301-345`),
  which is `FromHeight(0)` because `XPC_ACTIVATION_HEIGHT = 0`
  (`xshard2pc.rs:146`). `Disabled` remains only the `u64::MAX` sentinel; the
  old env/`main.rs:2723` pointer is STALE.
- Boot topology: `{0}` and the fixed public pair `{0,1}` are the only
  registries accepted without `STELL_EXPERIMENTAL_SHARDS`
  (`sharding/topology.rs:89-124`).

## 8. Breaker bounds (virtual-clock pins)

- Nil-breaker: `NIL_CIRCUIT_BREAKER_K 3` (`consensus/engine.rs:1270`, applied
  `:2109`); bound helpers live in `tests/liveness_breaker_tests.rs` (see
  `breaker_fire_bound_ms`, `TICK_MS`, `BASE_MS` in that file — the old
  `consensus.rs:3826` pointer is STALE).
- Deadlock/timeout: `tests/deadlock_breaker_tests.rs` (deadlock defaults to
  300 s), `MAX_DEADLOCK_JUMP` + cap hold in `liveness_breaker_tests.rs`,
  `ROUND_LOOKBACK` in the same file. Read the tests for exact lines.

## 9. Staking model — ops + checks (code truth)

- Consts: `MIN_VALIDATOR_BOND` (`staking.rs:62`), active/target validators
  (`:209,:214`), pools `STAKING_POOL [0x53;32]` (`:221`) /
  `REWARDS_POOL [0x52;32]` (`:230`), `REWARDS_EMISSION_CAP` (`:235`),
  `UNBONDING_PERIOD_SECS` (`:260`), slashes `EQUIVOCATION 500` (`:265`) /
  `MICRO_COMMITTEE 10 000` (`:270`) / `DOWNTIME 10` (`:275`),
  `DOWNTIME_MISS_THRESHOLD 10` (`:280`), commission
  `COMMISSION_EFFECT_DELAY_HEIGHTS 7 200` (`:355`).
- Ops/checks: the function-level list in the pre-split spec is STALE — see
  `stellereum/src/staking.rs` (`bond`, `unbond`, `delegate`, `slash*`,
  `validator_set_gains`, `reentry_liveness_risk`, and the fail-closed error
  variants). No behaviour claim in this section should be relied on without
  reading the module.
