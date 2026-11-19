# Internal Review — State Engine, Supply Economics, Staking & Settlement

**Date:** 2026-11-18
**Tree:** `/home/imm/stellereum-project` (read-only review; no source or test file was modified)
**Reviewer:** autonomous subagent (state/economics/staking wave)
**Method:** targeted source reading with `file:line` anchors, plus one permitted test run:
`cargo test --lib state_engine` → **44 passed, 0 failed** (1294 filtered out, 26.7 s).
No full-suite run, no `cargo fmt`, no git operations.

**Scope reviewed**

| Area | Files (lines) |
|---|---|
| Engine core | `stellereum/src/state_engine/{mod,accounts,apply,types,settlement,xshard,verify_once,memory_bounds,contracts}.rs` (~14k) |
| Staking | `stellereum/src/staking.rs` (7,053) |
| Value subsystems | `bridge.rs` (2,912), `pmm.rs` (792), `tokenomics.rs` (862), `commitment.rs` (3,457) |
| VM value opcodes | `svm.rs` (Transfer, Stake/Unbond/Delegate/Undelegate, Rotate, PmmBuy/PmmSell, Bridge, ActorSend, ReportEquivocation, token ops) |

---

## Verdict

**Not ready for mainnet, but materially stronger than the public gap analysis implies.** The global supply invariant is real: one atomic counter, reserved before every credit, fail-closed on overflow and cap, folded into the committed root, persisted in the snapshot, and rebased on reorg. Cross-shard and 2PC credits use the *uncapped* transfer primitive with an atomic claim, which is the correct shape. The block-path CLOB/PMM/bridge legs validate-then-apply under one snapshot with rollback, and the staking ledger keeps pool/ledger 1:1 in the claim paths.

Three things block launch, in order:

1. **The block path still charges the declared `gas_limit` and refunds nothing** (the known P0 from `docs/COMPLETENESS_GAP_ANALYSIS.md` §6/§P0). Every block-applied transaction overpays by `declared_limit − gas_used`, with no refund path. This is live on the consensus path, not a latent edge case.
2. **The legacy cross-shard credit is not backed by a source-side debit.** It proves only that the sender *could afford* the amount at a finalized source root. On any multi-shard chain, a colluding target proposer plus one funded source-shard account can mint on the target without ever being debited on the source. The 2PC path fixes this; the legacy path (still live whenever `cross_shard_enabled`) does not.
3. **Validator key rotation is a slashing escape hatch.** Slashing is membership-gated on the accused id, the downtime oracle attributes against the pre-transition set, and the block-path rotate does not migrate CN-VRF abort debt. A validator that rotates its key each height never accrues a downtime deficit, and equivocation evidence naming the retired key becomes permanently unactionable.

Everything else below is P1–P3: per-engine (not chain-wide) supply cap, slashed-pool debits that ignore failure, mature-but-unclaimed stake outside the slashable base, and a handful of latent fail-open helpers in dead code.

---

## Findings

| ID | Finding | Severity | Location | Blocks mainnet? |
|---|---|---|---|---|
| **FEE-01** | Block path charges declared `gas_limit`, no gas-used refund | **P0** | `apply.rs:1824-1840`, `apply.rs:1922`, `parallel.rs:1228`, `:1458` | **Yes** |
| **XSHARD-01** | Legacy inbound credit proves affordability, not a source debit | **P0** (multi-shard) | `xshard.rs:587`, `sharding/xshard.rs:213-220` | No today (single-shard); **Yes before sharding** |
| **STAKE-01** | Key rotation escapes downtime attribution, equivocation slash, and CN-VRF debt | **P1** | `svm.rs:2211`, `staking.rs:1723`, `:2751`, `apply.rs:3726` | **Yes** (validator economy) |
| **SUPPLY-01** | `TOTAL_SUPPLY_CAP` is per-engine, not chain-wide; workchain genesis uncounted | **P1** | `accounts.rs:1845-1900`, `bootstrap.rs:100-124` | No today; **Yes before sharding** |
| **SLASH-01** | Matured-but-unwithdrawn stake is outside the slashable base | **P1** | `staking.rs:2494-2508`, `:2200-2226` | No |
| **SLASH-02** | Slash/abort pool debits are `let _ = …` (fail-open → pool/ledger drift) | **P1** | `apply.rs:3734`, `:3838`, `:3888`, `:2980-2989` | No |
| **SUPPLY-02** | Value-conserving moves routed through the *capped mint* in latent helpers | **P2** | `runtime/anchors.rs:2183`, `contracts.rs:397`, `settlement.rs:1392` | No (no production callers) |
| **DET-01** | Block reward resolved from local governance state, not block bytes | **P1** (now reachable) | `runtime/apply.rs:213`, `runtime/cluster.rs:383`, `runtime/lanes.rs:125-126` | **Yes** — governance is active from genesis (`GOV_OPS_ACTIVATION_HEIGHT = 0`); a `SetBlockReward` can change the reward between pipeline points |
| **SNAP-01** | Empty chunk list accepted as a valid snapshot → mint headroom reset; `unwrap_or_default` snapshots | **P2** | `accounts.rs:2525-2531`, `memory_bounds.rs:522-543`, `accounts.rs:2261` | No (latent, no production caller) |
| **DET-02** | Node-local switches (`cross_shard_enabled`, `STELL_PARALLEL_EXEC`) select committed behaviour | **P2** (latent) | `apply.rs:1981`, `xshard.rs:414`, `accounts.rs:457-465` | No |
| **COMMIT-01** | Minted counter joins the digest with no activation height / version gate | **P3** | `commitment.rs:2046-2060`, `accounts.rs:916` | No (rollout hazard) |
| **DOC-01** | Stale doc-comments claim the counter is *not* committed / not persisted | **P3** | `accounts.rs:1756-1763`, `mod.rs:304-309` | No |
| **PMM-01** | `pmm_op` is not taken by the block path; safe only by a wider lock | **P3** | `settlement.rs:1256`, `:1345`, `apply.rs:501` | No |
| **RECOV-01** | `restore_checkpoint` discards the restore error | **P3** | `runtime/cluster.rs:505-510` | No |

---

## 1. FEE-01 — block path charges the declared gas limit (P0, blocks mainnet)

`stellereum/src/state_engine/apply.rs:1824-1840`

```rust
/// `gas_charged` is what execution consumed; the fee actually taken is
/// `max(min(gas_charged, tx.gas_limit), floor_base) + surcharge` …
///  * EVERY block application passes the DECLARED `tx.gas_limit`, because
///    admission reserved exactly `amount + gas_limit` and `fees_collected`
///    … is defined as the sum of declared limits.
```

`stellereum/src/state_engine/apply.rs:1922`

```rust
let fee = gas_charged.min(tx.gas_limit).max(floor_base);
```

`stellereum/src/state_engine/parallel.rs:1228` and `:1458` (both block-apply paths):

```rust
self.commit_native_with_floor(tx, tx.gas_limit, &transfers, &payouts, &burns, …)
```

**Explanation.** On the block path `gas_charged == tx.gas_limit`, so `min(gas_charged, gas_limit)` is a no-op and the fee is exactly the declared limit (or the consensus floor, whichever is higher). The VM returns `gas_used` (it is stored for the session budget and receipts), but it is never fed to the fee. The single-transaction API (`apply_transaction`, `apply.rs:1441`) does pass the used gas — so the two paths deliberately charge different amounts for the same transaction, and the consensus path is the overcharging one. The failure fee has the same shape (`parallel.rs:997`: `tx.gas_limit.max(floor_base) + surcharge`).

**Economic impact.** A transfer that consumes ~4 gas but declares 10,000 is charged 10,000. There is no refund, no unused-gas credit, and no way for a wallet to know the exact post-execution gas in advance, so rational users either overpay systematically or under-declare and risk OOG (and an OOG transaction still pays the full declared limit as the failure fee). Fee revenue is therefore inflated relative to real resource consumption, and the fee has no relationship to the gas the block actually used. It also makes `fee_charged` in receipts inconsistent with `gas_used`, which any external fee estimator will misread.

**Fix.** Charge `max(min(gas_used, gas_limit), floor) + surcharge` on the block path too, and make `fees_collected` the sum of those (the proposer credit already uses the returned `fee`, `apply.rs:2607`). This is a consensus change: gate it behind the same kind of activation height used elsewhere, and add a golden test that a 10 000-limit transfer with `gas_used = 4` debits 4 + floor.

---

## 2. XSHARD-01 — legacy inbound credit is not bound to a source debit (P0 for multi-shard)

The credit itself is correctly uncapped and atomic (`xshard.rs:587`):

```rust
// Audit F2: an inbound cross-shard credit moves value that the source
// already escrowed, so it is a TRANSFER, never a mint.
if let Err(e) = self.credit_native_transfer(&msg.tx.to, msg.tx.amount).await {
```

The comment's premise — "the value already existed … it was debited/burned when the source block applied" — is **not proven** by anything the receiver checks. The strongest inbound check for a legacy `Transfer` is `sharding/xshard.rs:213-220`:

```rust
// The proven balance must actually cover the transfer, so an attacker
// cannot inflate `amount` and keep an old proof for a smaller balance.
if self.source_balance < self.tx.amount {
    return false;
}
// Prove the SENDER ACCOUNT LEAF (balance || nonce) at the source state root
```

plus the anchor (`finalized_in_block` names a locally finalized source header whose `state_root` matches). The proposal-side gate is the same one (`runtime/consensus_step.rs:426-433` → `verify_cross_shard_anchored`).

**Explanation.** That is a proof of *affordability*, not of *debit*. Nothing proves the transaction was included in a source-shard block, or that the source applied it and removed the coins. `msg_id` binds `(source_shard, target_shard, tx_hash, finalized_in_block)` and the block hash binds the source block's `cross_shard_out` list, but no verifier checks that the message is a member of that list or that the source's account leaf changed. The 2PC path fixes exactly this by requiring a PREPARED/COMMITTED leaf (`apply_xpc_record`, `xshard.rs:729+`); the legacy path (selected whenever a transfer is not `is_xpc()`) retains the weaker rule.

**Attack.** On a sharded deployment, an attacker funds an account on shard S, signs a `tx {from: self, to: self_on_T, amount: X, source_shard: S, target_shard: T}`, and never has it applied on S. A colluding proposer of shard T includes a `CrossShardMessage` carrying that signed tx plus a Merkle proof of the sender's unchanged S-leaf (balance ≥ X) at a finalized S header. `verify_msg_id`, `verify_signature`, the anchor and `verify_inclusion_strict` all pass, the consumed-claim inserts, and T credits X to the attacker. The attacker keeps the S balance. Repeating drains the target shard's value into the attacker's hands — an uncapped, unbacked mint on T.

**Economic impact.** Cross-shard value conservation is the load-bearing assumption of the whole sharding story. This breaks it with one colluding proposer and one funded account, without breaking any signature or Merkle proof.

**Status.** Not reachable while `cross_shard_enabled` is false (single-shard, the shipped default). It becomes reachable the moment a second shard is booted, so it blocks sharding, not today's launch.

**Fix.** Route every legacy transfer through the 2PC state machine (PREPARE/COMMIT), or require the credit to be accompanied by a proof that the sender leaf was *decremented* (a source-shard `produced` commitment included in a header the target anchors to). At minimum, refuse a legacy credit unless the source header commits to a `cross_shard_out` membership proof for that `msg_id`.

---

## 3. STAKE-01 — key rotation is a slashing escape hatch (P1, blocks a validator economy)

Rotation is live on the block path (`svm.rs:2211`):

```rust
if let Err(e) = ledger.rotate_key(*old_validator, *new_validator) {
    return VmExecutionResult::Reverted(format!("rotate failed: {e}"));
}
```

`rotate_key` (`staking.rs:1723-1840`) moves every keyed map — delegations, rewards, unbonding, withdrawable, gov locks, **jail**, commission, redelegation locks — to the new id. It has **no cooldown, no height gate, and no "recently active" check**.

Two consequences:

**(a) Downtime attribution is dropped for the rotation block.** `apply_downtime_slash_with_set` builds the eligible list from the *pre-transition* validator set (`apply.rs:3726`), then looks the id up in the *post-transaction* ledger:

```rust
let eligible: Vec<[u8; 32]> = val_set.validators.keys().copied().collect();
…
for v in eligible {
    let Some(rec) = self.validators.get_mut(v) else { continue; };   // staking.rs:3409
```

After a same-block rotation the old id is gone from `validators`, so the miss is silently forgiven. `missed` travels with the record, but the *evidence for that height* does not, so a validator that rotates every height is attributed zero misses and never reaches `DOWNTIME_MISS_THRESHOLD`.

**(b) Equivocation evidence becomes permanently unactionable.** `slash_equivocation_verified` is membership-gated (`staking.rs:2750-2753`):

```rust
// 3. Membership.
if !self.validators.contains_key(&voter) {
    return Err(StakingError::NotValidator);
}
```

The evidence names the old id and has no age bound; once the stake has rotated, the slash returns `NotValidator` and the block path logs-and-skips it (`apply.rs:3821-3829`), burning 0. The offense dedup key is keyed by voter, so the offense is never consumed either — but the stake now sits under a key the evidence does not name.

**(c) The block path does not migrate CN-VRF abort debt.** `staking.rs:3643` exists for exactly this:

```rust
pub fn rotate_key_with_cnvrf_abort(&mut self, old, new, abort_state) -> Result<(), StakingError> {
    self.rotate_key(old, new)?;
    abort_state.migrate_validator(&old, &new);
```

but the opcode calls plain `rotate_key`, and `abort_state` is owned by the apply step, not the VM. The old id's abort counters stay behind on a record that no longer exists, and the new id starts at zero — another evidence reset.

**Economic impact.** The only live penalties are downtime and block-carried equivocation. Both are evadable by a cheap, self-signed rotation. A Byzantine validator can double-sign and immediately rotate, keeping 100 % of its 5 % slashable stake; a flaky one can rotate instead of fixing its uptime. Severity is P1 rather than P0 only because the offender must already be a bonded validator; the capital at risk (self + delegators) is exactly what the mechanism exists to protect.

**Fix.** (1) Add a rotation cooldown (`ROTATION_COOLDOWN_HEIGHTS`) and refuse rotation while the validator has an unpunished `missed` deficit or an open jail. (2) Attribute downtime against the post-transaction ledger *or* map old→new within the same block (a `rotation_alias` map that `note_missed_heights` and `slash_*` consult). (3) Carry equivocation evidence age/id-independence: key the offense on the *stake record identity* rather than the address, or keep the retired id resolvable for one unbonding period. (4) Call `rotate_key_with_cnvrf_abort` from a block-path apply step (the VM cannot, so the scan must do it like `apply_staking_unjail_ops`).

---

## 4. SUPPLY-01 — the cap is per-engine, so it is not a global cap (P1)

The invariant is implemented exactly as documented, in one counter:

`accounts.rs:1857-1892`

```rust
pub(super) fn reserve_mint_nano(&self, amount: u64, genesis_nano: u64) -> Result<(), String> {
    let cap = crate::tokenomics::TOTAL_SUPPLY_CAP;
    …
    if next > cap { return Err(format!("global supply cap exceeded: …")); }
    match self.total_minted_nano.compare_exchange_weak(current, next, …)
```

`accounts.rs:1815-1830` documents the intended invariant as `genesis_allocation + post_genesis_minted <= TOTAL_SUPPLY_CAP`.

**Explanation.** The counter is a field of `InMemoryStateEngine`, and each shard runs its own engine with its own counter and its own snapshot. Nothing aggregates them. With N shards the enforced ceiling is N × 1e18 nano, plus N genesis allocations, plus whatever the lazy-baseline fold treats as "genesis":

- `fund_shard_genesis` (`runtime/lanes.rs:76-82`) writes the faucet balance with `update_account`, i.e. outside the counter; that shard's first mint folds it in — consistent per shard, but not part of any chain-wide sum.
- The workchain genesis path (`bootstrap.rs:100-124`) has **no** cap check, unlike the masterchain path (`bootstrap.rs:725-744`).
- An inbound cross-shard credit (`credit_native_transfer`) arrives as a balance without a counter entry, so the target shard's lazy baseline treats it as pre-mined genesis and permanently reduces that shard's headroom by the credited amount — headroom is not even conserved across shards.

**Economic impact.** The "1 B STELL hard cap" — the headline tokenomics claim — is single-shard-only. On a sharded chain the cap is per shard and the total is unbounded in the number of shards. Today (single shard) the invariant holds; the moment a second shard exists, it does not.

**Fix.** Make the minted counter a cross-shard committed value (e.g., a masterchain supply registry that shard mints reserve against, the way the bridge is masterchain-only), or make the cap explicitly per-shard in the spec and in `tokenomics.rs` docs. Add the cap assertion to the workchain genesis path regardless.

---

## 5. SLASH-01 — matured-but-unclaimed stake escapes slashing (P1)

The slashable base (`staking.rs:2494-2508`):

```rust
let unbonding_self  = self.unbonding.iter().filter(...owner.is_none()...).fold(...);
let unbonding_deleg = self.unbonding.iter().filter(...owner.is_some()...).fold(...);
let total = self_bond
    .saturating_add(delegated_now)
    .saturating_add(unbonding_self)
    .saturating_add(unbonding_deleg);
```

`withdrawable` is **not** in the sum. `process_unbonding` (`staking.rs:2200-2226`) drains mature entries out of `unbonding` into `withdrawable` at `release_at`:

```rust
let entry = self.withdrawable.entry(key).or_insert(0);
*entry = entry.checked_add(e.amount)…
```

**Explanation.** Evidence-based slashing has no age bound (`slash_equivocation_verified` checks shape, signatures, membership and dedup — nothing about the offense height). So a validator's flow is: equivocate at height H → begin unbonding → wait `UNBONDING_PERIOD_SECS` so the entry matures into `withdrawable` → the evidence for H is included afterwards and misses that amount entirely. In-flight (`unbonding`) stake is correctly included (audit P1); matured-but-unclaimed stake is the remaining gap in the same logic.

**Economic impact.** Up to 100 % of the offender's stake can be moved out of reach by waiting one cooldown. The slash still burns whatever remains, so the victim set (delegators/inflation) absorbs an under-penalised offense.

**Fix.** Add `withdrawable` for that validator/owner to the `total` (and to the consumption order, after the in-flight delegator haircut). The amount is already owner-keyed in the same map.

---

## 6. SLASH-02 — slash pool debits ignore failure (P1)

Four call sites mutate the ledger (decrementing `self_bond`/`delegated`/`unbonding` and incrementing `total_burned`) and then debit the pool with the result discarded:

`apply.rs:3734-3737` (downtime), `apply.rs:3838-3841` (vote equivocation), `apply.rs:3888-3891` (proposal equivocation), `apply.rs:2980-2989` (CN-VRF abort):

```rust
if burned > 0 {
    // The coins are real: take them out of the staking pool, exactly like
    // the downtime path above.
    let _ = self
        .debit_native(&crate::staking::STAKING_POOL, burned)
        .await;
}
```

**Explanation.** Contrast with the VM-driven PQ burn, which is correctly fail-closed as a `burns` entry checked against the pool balance inside `commit_native` (`apply.rs:2244-2264` → "a burn the payer cannot cover REFUSES the transaction"). The engine-side slashes have no such check: if `STAKING_POOL` holds less than `burned`, the debit returns `Err("Insufficient …")`, the error is dropped, and the ledger has already removed the stake and raised `total_burned`. The ledger then says "X was burned" while the pool still holds the coins — the exact pool/ledger drift the doc comment at `staking.rs:2651-2668` warns about ("…or pool/ledger drift by `burned`").

**Economic impact.** The drifted surplus stays in the pool forever (it is not payable to anyone: claims are bounded by `rewards_pool`, withdrawals by `withdrawable`). The visible symptom is under-funded staking capacity later: `withdraw` pays from `STAKING_POOL`, so a pool shortfall makes a legitimate unbond fail. It is not directly exploitable, but it silently breaks the accounting invariant that every slashing test relies on.

**Fix.** Fail the *step* closed: read the pool balance first, cap `burned` at it (recording the shortfall loudly), or turn the debit into a hard error that leaves the ledger untouched. Better: compute `burned` from the pool's actual balance so the two can never disagree.

---

## 7. SUPPLY-02 — value-conserving moves still funnel through the capped mint (P2, latent)

Three helpers move existing value but call the *mint* primitive, which both consumes global headroom and can silently swallow the value at the cap:

- `runtime/anchors.rs:2183` — bond:
  ```rust
  self.state.debit_native(&validator, amount).await…
  let _ = self.state.credit_native(&crate::staking::STAKING_POOL, amount).await;
  ```
- `state_engine/contracts.rs:397` — contract call value:
  ```rust
  let _ = self.credit_native(address, value).await;
  ```
- `state_engine/settlement.rs:1392` — PMM sell refund:
  ```rust
  let _ = self.credit_native(&seller, stell_nano).await;
  ```

**Explanation.** These are transfers (the debit already happened), yet each one reserves against `TOTAL_SUPPLY_CAP`. Every bond/unbond cycle therefore permanently consumes headroom that was never emitted, and a contract call with value does the same. At the cap, the credit is refused, the error is dropped, and the debit stands — the coins vanish (burned) with no compensating credit. `anchors.rs` also credits the pool *before* checking whether the ledger accepted the bond, and repairs with `debit_native`/`credit_native` on failure, which makes the accounting fragile.

**Status.** Grep confirms **no production callers** today: `pmm_buy`/`pmm_sell` are referenced only by `tests/pmm_onchain_tests.rs`, `tests/pentest_state_wave.rs`; `call_contract_structured_with_value` has only its definition; `ValidatorRuntime::stake_bond` is not called from `src`. So this is latent — but it is the shape the live path must never drift into, and the file already has the right primitive (`credit_native_transfer`) one line away.

**Fix.** Replace each with `credit_native_transfer` and propagate the error (`?` / `if let Err` → roll back the debit). Add a lint-style test that `credit_native` is only reachable from allowed call sites.

---

## 8. DET-01 — the block reward is resolved from local state, not block bytes (P1, now reachable)

`runtime/apply.rs:213` and `runtime/cluster.rs:383`:

```rust
let reward = block_reward_for(self.governance.as_ref(), self.block_reward);
```

`runtime/lanes.rs:125-127`:

```rust
pub fn block_reward_for(gov: Option<&crate::governance::Governance>, default: u64) -> u64 {
    gov.and_then(|g| g.applied.block_reward).unwrap_or(default)
}
```

`runtime/lanes.rs:306` then applies `job.reward`, captured at submit time.

**Explanation.** `apply_block_transition(block, block_reward)` takes the mint amount as a *parameter*, and that parameter is derived from the node's own governance state at submit time (`block_reward_for` reads `gov.applied.block_reward`). The correct deterministic source is the block (a committed field) or the committed pre-state at the applied height. Governance is now **active from genesis** (`GOV_OPS_ACTIVATION_HEIGHT = 0`, `governance.rs:151`), so this is no longer a latent issue: a node that applies a `SetBlockReward` at a slightly different pipeline point — or that missed it — can mint a different reward for the same block and fork the root. This is a code finding, not a doc-only drift; do not mark it safe because an old doc said governance was inert.

**Economic impact.** Inflation rate becomes node-local at the moment governance becomes useful — precisely when the reward parameter starts to move.

**Fix.** Commit the reward (or a hash of the applied params it depends on) into the block header, or derive it inside `apply_block_transition` from the committed ledger/governance pre-state at `block.height`, never from a caller-supplied parameter.

---

## 9. SNAP-01 — empty chunk list is a valid snapshot; serialization failures become empty snapshots (P2, latent)

`accounts.rs:2525-2531`:

```rust
pub(super) fn decode_snapshot_chunks(chunks: &[Vec<u8>]) -> Result<(…), String> {
    let mut decoded = Vec::with_capacity(chunks.len());
    let mut penalty = HashMap::new();
    let mut total_minted_nano = 0u64;
    for (i, raw) in chunks.iter().enumerate() { … }
    Ok((decoded, penalty, total_minted_nano))
```

With `chunks == []` this returns `Ok((vec![], {}, 0))`, and `memory_bounds.rs:573` then calls

```rust
self.set_total_minted_from_snapshot(total_minted_nano);
```

which stores 0 — i.e. **full mint headroom restored** — and clears the accounts and penalty map. The producer side has the matching hole (`memory_bounds.rs:522-543`): `addrs.chunks(per)` yields no chunks for an empty account map, so the chunk-0 envelope carrying `total_minted_nano` is never emitted, and each `bincode::serialize(...).unwrap_or_default()` turns a serialization failure into an empty chunk.

The monolithic path has the same `unwrap_or_default` (`accounts.rs:2261`), though `parse_account_snapshot` then fails closed on empty bytes.

**Status.** No production caller of the chunked pair exists (only `tests/audit_state_sync_closeout_tests.rs`, `tests/memory_bounds_tests.rs`, `tests/pentest_state_wave.rs`, `tests/xshard_replay_tests.rs`, `state_engine/tests/parallel_waves.rs`); the node uses `create_snapshot`/`restore_snapshot`. So this is latent, but it is exactly the "reset headroom" failure the prompt asks about, and it is one wiring change away.

**Fix.** Reject an empty chunk list (`if chunks.is_empty() { return Err(…) }`), always emit chunk 0 even when the account map is empty, and make `create_snapshot_chunked` propagate a serialization error instead of `unwrap_or_default`.

---

## 10. DET-02 — node-local switches in a committed transition (P2, latent)

`apply.rs:1981`:

```rust
let burn_for_cross_shard = self.cross_shard_enabled() && tx.source_shard != tx.target_shard;
```

`xshard.rs:414` returns 0 unless `cross_shard_enabled()`, and `accounts.rs:457-465`:

```rust
pub fn is_parallel_exec_enabled(&self) -> bool {
    self.parallel_exec.load(Ordering::Acquire)
        || std::env::var("STELL_PARALLEL_EXEC").map(|v| v == "1" … ).unwrap_or(false)
}
```

**Explanation.** `cross_shard_enabled` decides whether an outbound transaction credits locally or burns (the difference is committed state), and it is process configuration set from shard topology, not from the block. `STELL_PARALLEL_EXEC` selects between the sequential and wave paths; both are claimed byte-identical (`parallel.rs:16-22`) and pinned by tests, but the switch itself is an env var inside a consensus transition. There is no protocol-version field in `Block` (see `docs/COMPLETENESS_GAP_ANALYSIS.md` §2) to detect a misconfigured peer.

**Economic impact.** A node with the wrong shard topology or an env var set forks silently and only notices at the post-state-root comparison (`runtime/consensus_step.rs:478+`), which parks finality rather than naming the cause.

**Fix.** Derive the sharding mode from the block/shard header rather than process config, and either remove `STELL_PARALLEL_EXEC` from the consensus path or include it in the chain spec so it cannot differ between nodes applying the same block.

---

## 11. Lower-severity and informational

- **COMMIT-01** — `commitment.rs:2046-2060` appends the counter only when non-zero:
  ```rust
  if total_minted_nano != 0 { put_u64(&mut h, b"total_minted_nano", total_minted_nano); }
  ```
  The genesis root stays pinned (good), but the preimage gains a field with **no `COMMITMENT_VERSION` bump and no activation height** (`COMMITMENT_VERSION` is 5, `commitment.rs:100`). A mixed-binary network diverges at the first mint. Not a bug in this tree, but it must be coordinated with the upgrade gate. Also: because the field is conditional, a counter that has been reset to 0 is *indistinguishable* from "never minted" in the root, so an operator cannot detect a lost counter from state alone.
- **DOC-01** — `accounts.rs:1756-1763` still says "WIRING REQUIRED … this value is NOT yet folded into the consensus commitment", and `mod.rs:304-309` says "NOT YET IN THE STATE ROOT", while `accounts.rs:916` passes `self.total_minted_nano()` into `assemble_cached_digest_with_cnvrf_and_minted` and `accounts.rs:2248` persists it. Stale comments on the single most important invariant invite an auditor to "fix" a non-problem or, worse, to trust a claim that the code no longer matches.
- **PMM-01** — `pmm_buy`/`pmm_sell` take `self.pmm_op` (`settlement.rs:1256`, `:1345`), but the block path does not: it holds the `pmm` **write guard** across the whole payload (`apply.rs:501`). The ordering is therefore safe today, but the mutex alone would not be — if that guard were ever narrowed, the RPC path's read-clone-write would overwrite the block's curve advance (the class of bug the comment cites). Keep the invariant documented at `apply.rs:501` or take `pmm_op` in the block path too.
- **RECOV-01** — `runtime/cluster.rs:505-510`:
  ```rust
  pub async fn restore_checkpoint(&self) {
      if !self.checkpoint.is_empty() { let _ = self.state.restore_snapshot(&self.checkpoint).await; }
  }
  ```
  A corrupt checkpoint leaves the engine un-restored and `reorg` then replays the new branch on top of the old state — a double-apply with no signal. Fail loud and refuse to reorg.
- **Fee payout** — `apply.rs:2607` `let _ = self.credit_native_transfer(&block.proposer, fees)`: a credit failure (overflow) silently destroys collected fees. Only reachable at absurd balances, but the same pattern as SLASH-02.
- **`missed = 0` on a zero-burn slash** — `note_missed_heights` resets the deficit even when `slash` returns `Ok(0)` (zero stake), so a fully drained validator never re-accumulates a deficit. Harmless for a zero-stake validator but worth a `burned > 0` guard for clarity.

---

## Coverage — what was reviewed and found clean

Explicitly checked, no finding:

**Supply counter mechanics**
- `reserve_mint_nano` is a CAS loop, reserves *before* any credit, folds the genesis baseline in the single `0 → x` CAS, refuses `u64` overflow and `> cap`, and `release_mint_nano` gives headroom back only on a failed credit (`accounts.rs:1857-1905`). Concurrent mints cannot both see the same headroom.
- Burns do not restore headroom (`accounts.rs:2041-2050`); transfers never touch the counter (`transfer_native`, `credit_native_transfer`).
- Every *live* value-creating path is routed through it: block reward reserves first and defers the ledger write until the reservation succeeds (`apply.rs:2626-2641`); bridge deposits reserve both quorum and adapter-evidence arms (`settlement.rs:1677-1714`, `bridge.rs:1398-1420`); PMM block buys reserve gross buy-side volume before any balance write (`settlement.rs:1458-1500`); `mint_native`/`credit_native` are the only engine mint entry points.
- Snapshot persistence: `StateSnapshotV2 { accounts, penalty, total_minted_nano }` (`types.rs:696-710`), captured at `accounts.rs:2248`, validated-before-commit on restore (`accounts.rs:2265-2270`, `memory_bounds.rs:565-575`), and the reorg checkpoint path rebases it (`restore_checkpoint` → `restore_snapshot`). A replay after a restore re-counts from the restored value exactly once.
- `clone_for_simulation` deep-copies the counter (`accounts.rs:161-169`), so an RPC simulation (`rpc/reads.rs:430`) cannot consume live headroom.
- Genesis: `fund_genesis` moves validator bonds into `STAKING_POOL` with `credit_native_transfer` (not a mint), and the masterchain bootstrap now asserts `N × GENESIS_VALIDATOR_BALANCE + GENESIS_FAUCET_BALANCE ≤ TOTAL_SUPPLY_CAP` and refuses to boot otherwise (`bootstrap.rs:725-744`). The values are 1e15 nano each (1 M STELL), not the 100 M the gap analysis states — the check is real, the doc figure is not.
- The faucet is a **funded account**, not a mint: `bootstrap.rs:813` credits `GENESIS_FAUCET_BALANCE` with `credit_native_transfer`, and drips are ordinary signed transfers. No mint path there.

**Atomicity**
- `settle_clob_effects` (block path) plans on clones of the escrow map and token registry with a native projection, validates balances/minter/paused/max-supply, and only then applies (`settlement.rs:838-1210`). The older `place_order_settled` in-loop mutation has **no callers**.
- `settle_pmm_native` / `settle_bridge_native` take one accounts write lock, snapshot pre-state, validate, reserve, apply, then mirror into the trie; every caller restores the snapshot and releases `pmm_minted_nano` / `minted_nano` on a later leg's failure (`apply.rs:398-401`, `settlement.rs:1768-1790`). The bridge domain is restored with the accounts, so no replay-set residue survives a refused payload.
- Cross-shard consume is an atomic `HashSet::insert` before the credit, removed on credit failure (`xshard.rs:588-611`); the 2PC COMMIT credit and ABORT-ACK refund use the same claim via `cross_shard_completed` (`xshard.rs:862-905`, `:944-975`). The ABORT-ACK cannot fire after a COMMIT because the transition is refused.
- `apply_xpc_source_prepares` writes a PREPARED record only for transactions whose `status[i]` is true (`xshard.rs:683-700`) — the correct fail-closed rule.
- Parallel plain-tx waves plan on one consistent snapshot and merge with a compare-and-swap that aborts and re-runs sequentially (`parallel.rs:391-560`); independent tests confirmed order independence and sequential parity.

**Determinism**
- Every committed domain sorts its hash-map iteration: staking (`commitment.rs:951-999`), bridge (`BTreeSet`/`BTreeMap` by construction, `bridge.rs:1038-1080`, digest at `:1460+`), cross-shard keys sorted both in the snapshot and in the digest (`xshard.rs:87-95`, `commitment.rs:1686-1706`), escrow/orderbooks sorted (`commitment.rs:1869-1877`).
- No wall clock in a committed transition: the only `SystemTime::now` in `state_engine/` is the log-throttle in `memory_bounds.rs:27`; bridge rate windows, unbonding maturity, order gates and governance all take `block.timestamp`, and `apply_gov_ops` documents and enforces that (`apply.rs:3979-3984`).
- Staking consensus floors are consts, not env: `required_bond_floor_nano() = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER` (`staking.rs:62-84`). The two env vars in `staking.rs` (`STELL_SLASH_EJECT_WARN_GAP`, `STELL_MIN_BOND_BUFFER`) feed **log warnings only** and cannot change accept/refuse.
- `verify_once` is node-local, binds tx hash + signer + full signature + signing-message digest + both chain ids + pure-PQ mode, and evicts by whole-map clear; it can only cost re-verification, never a bypass (`verify_once.rs:1-60`).

**Staking lifecycle**
- In-flight (`unbonding`) self and delegated stake are in the slashable base, and `unbond` cannot dip below `MIN + buffer` unless it exits fully (`staking.rs:1846-1878`). `unbond` correctly checks the governance lock.
- The per-validator delegation cap is enforced on **both** entry paths (`delegate` `staking.rs:1970-1975`, `redelegate` `:2160-2165`), and the zero-delegator key is reserved for the validator's own matured bond.
- Jail travels with a rotation and is installed only on a positive-burn downtime penalty (`staking.rs:3430-3446`); unjail is block-carried, sender-checked, height-gated and bond-gated (`apply.rs:3660-3695`).
- The downtime deficit is a leaky bucket that converges (+1 per miss, −1 per vote, floor 0), and re-applying an older QC cannot re-penalise because of the `height >= last_downtime_penalty` guard (`staking.rs:3418-3435`).
- `distribute_reward` refuses jailed/zero-stake validators and the 350 M local cap before any credit, and the block applies it *after* the global reservation, so a cap refusal leaves no per-validator `pending_rewards` to unwind (`staking.rs:3706-3749`, `apply.rs:2626-2641`).
- Reward claims are bounded by the ledger's `rewards_pool` (`staking.rs:3862-3900`), and every claim pays from the native `REWARDS_POOL`, so principal in `STAKING_POOL` is never touched.

**Failure modes (spot-checked)**
- Zero amount: `mint_native`, `credit_native_transfer`, `transfer_native` return `Ok` without touching state; `SysCallStake`/`Delegate`/PMM reject zero with a revert.
- Self-transfer: `transfer_native` short-circuits on `from == to`; the CLOB self-trade branch consumes the escrow without moving net value.
- Missing account: debits return `Err("account does not exist")`, credits create the account with `AccountState::new(addr, amount)`; both paths write the trie leaf.
- Paused / renounced token: the CLOB settlement pre-validates minter and pause state and refuses the whole settlement rather than leaving a half-released escrow (`settlement.rs:270-295`).
- Duplicate opcode / replay: consumed-set claims are atomic and removed only on credit failure; 2PC transitions are pure functions of the committed record (phase monotone), so a replay is a no-op.
- Overflow: `checked_add`/`checked_mul` on balances, nonces, supply, and reward accumulators; `saturating_add` only where the value is later `min`-clamped (documented).
- Panics: `cargo test --lib state_engine` → 44/44 passed on this tree.

---

## Prioritised fix list

| # | Fix | Addresses | Effort |
|---|---|---|---|
| 1 | Charge `gas_used` (floored) on the block path and refund the difference; make `fees_collected` the sum of charged fees | FEE-01 | M — consensus change behind an activation height |
| 2 | Bind legacy cross-shard credits to a source-side debit (require 2PC, or a `produced`-set membership proof in the anchored header) before enabling a second shard | XSHARD-01 | L |
| 3 | Rotation cooldown + old→new attribution map for downtime/equivocation + migrate CN-VRF abort debt on the block path | STAKE-01 | M |
| 4 | Make the supply cap chain-wide (or spec it as per-shard) and add the cap assertion to workchain genesis | SUPPLY-01 | M–L |
| 5 | Include `withdrawable` in the slashable base and the consumption order | SLASH-01 | S |
| 6 | Make every slash/abort pool debit fail-closed (cap at the pool balance or refuse the step) | SLASH-02 | S |
| 7 | Replace `credit_native` with `credit_native_transfer` in `anchors.rs`, `contracts.rs`, `pmm_sell` refund; propagate errors | SUPPLY-02 | S |
| 8 | Derive the block reward from block bytes / committed pre-state, not from local `Governance::applied` | DET-01 | M — must precede governance activation |
| 9 | Reject empty chunk lists; always emit chunk 0; propagate snapshot serialization errors | SNAP-01 | S |
| 10 | Derive sharding mode from the block/shard header; remove or spec-bind `STELL_PARALLEL_EXEC` | DET-02 | M |
| 11 | Correct the stale "not in the state root" comments; add a counter-committed assertion test | DOC-01, COMMIT-01 | S |
| 12 | Fail loud in `restore_checkpoint`; keep `pmm_op` (or its guard invariant) explicit | RECOV-01, PMM-01 | S |

---

## UNVERIFIED / out of this review

- Whether `SysCallRotateValidatorKey` is reachable from the shipped wallet/SDK (the on-wire opcode is reachable by any hand-built transaction; the wallet surface was not audited).
- The runtime/P2P side of cross-shard message admission beyond `runtime/consensus_step.rs:409-440` — i.e. whether a node-level filter could reject a forged inbound message before proposal. The engine and proposal checks reviewed here do not.
- The cryptographic soundness of `bridge_adapters::verify_evidence` (SPV/receipt proofs for TON/Ethereum/Arbitrum/Solana) — only the *policy wiring* around it was reviewed.
- Live network configuration (validator count, shard count, `STELL_*` env vars on real hosts) and therefore the real genesis allocation and headroom.
- Consensus/liveness behaviour of a mixed-binary network after the minted-counter digest change.
- The `eth_*` / EVM adapter surface (out of scope).
