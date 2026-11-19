# Chain-wide `TOTAL_SUPPLY_CAP`

Status: ruleset v5 (design + implementation). Supersedes the per-engine note in
`src/node/bootstrap.rs` and the `SUPPLY-01` known gap.

## 1. The invariant

```text
sum over every committed shard S of minted_total(S)  <=  TOTAL_SUPPLY_CAP
```

where `minted_total(S)` is the shard's CUMULATIVE gross native issuance,
INCLUDING its genesis pre-mine, in nano-STELL. Transfers and burns never change
it (it is gross lifetime minting, so burn-then-mint cannot create a second cap).

`TOTAL_SUPPLY_CAP = 1_000_000_000 * 10^9` nano-STELL (1 B STELL).

Before v5 the only enforcement was `InMemoryStateEngine::total_minted_nano`:
one counter per ENGINE. With N shard engines the real ceiling was `N x cap`
plus N genesis allocations. The cap is now chain-wide.

## 2. Model: static share + committed aggregate

Two independent mechanisms, both deterministic:

### 2.1 Static per-shard share (the hard bound)

`tokenomics::SupplyPartition` splits the cap over the committed shard set:

* shards sorted ascending, integer division, remainder to the lowest ids;
* `sum(quota_i) <= TOTAL_SUPPLY_CAP` by construction;
* `ValidatorRuntime::with_shard` installs `quota_i` on that shard's engine
  (`InMemoryStateEngine::set_chain_mint_limit_nano`);
* every mint path goes through `reserve_mint_nano`, which now enforces
  `min(TOTAL_SUPPLY_CAP, quota_i)`.

Because `minted_total(i) <= quota_i` for every shard and the quotas sum to at
most the cap:

```text
sum(minted_total(i)) <= sum(quota_i) <= TOTAL_SUPPLY_CAP
```

This holds under EVERY interleaving of shard execution, with or without any
cross-shard communication, and at every lag. It is the primary invariant.

### 2.2 Committed aggregate on the masterchain (accounting + refusal)

`ShardHeaderCommitment` (inside the signed `Block::shard_headers` of a
masterchain block) gained `minted_total_nano`: the shard's cumulative total at
that head, including genesis. `Block::compute_hash` covers the commitment set,
so the masterchain quorum signs it. The field is zero-skipped in
`commitment_bytes`, so a head with no minted supply keeps its pre-v5 hash.

`FinalizedHeaderRegistry::committed_minted_total_nano()` is the aggregate:

```text
sum of latest committed head.minted_total_nano, for every shard
(masterchain included)
```

It is a PURE function of the committed header set — no env, clock, peer or
local counter input — and it is recomputed on demand rather than stored as a
second ledger that could drift.

`ValidatorRuntime::check_chain_supply_commitment` (called from
`check_shard_header_commitments` on the masterchain proposal path):

1. refuses a proposed head above `TOTAL_SUPPLY_CAP`;
2. refuses a proposed head above its static share (when the shard is in this
   node's partition);
3. refuses a proposed head that DECREASES a shard's committed total
   (monotonicity: a rollback would hide supply);
4. rebuilds the aggregate as
   `masterchain own committed total + proposed heads + unchanged committed
   heads`, and refuses it above the cap.

## 3. Why not dynamic sharing of the remaining headroom?

The intuitive design — each shard may mint `cap - aggregate` (or a fair
`(cap - aggregate) / N`) — is NOT safe under asynchronous interleaving. Two
shards that both observe the same stale aggregate `A` may each mint
`(cap - A) / N`; with different/stale views the increments do not compose, and
a third observation can hand out the same headroom twice. The counterexample
is in the `SupplyPartition` docs: after one shard's head commits, a second
shard that has not committed its own head sees the freed room and mints it
again.

Safe dynamic reallocation needs a two-phase quota handoff (grant committed at
height H, old quota unusable after H, every shard acknowledges). That is a new
cross-shard protocol, not a counter change, and is deliberately out of scope
here. The static partition is the strongest scheme that is safe without it.

## 4. Lag bound and honest under-mint

A workchain knows only the aggregate its node has committed. It does not need
the live aggregate to be safe: its hard bound is its static share, which is
committed with the genesis shard set and never grows. That static share IS the
last committed view the shard relies on; it is deliberately not recomputed
from a live registry because two nodes with different registry lags would then
apply the same block with different mint limits and diverge.

`SupplyPartition::bounded_limit_nano` exposes the additional honest tightening
a caller may apply when it does hold a committed aggregate:

```text
min(static_share, cap - committed_others)
```

with `committed_others = committed_aggregate - committed_own`, or
`static_share` when no committed aggregate is known.

* A lagging view can only make `committed_others` SMALLER, so the expression
  approaches the static share; it can never exceed it.
* With no view at all the shard still mints at most its static share:
  fail-closed under-mint, never over-mint.
* Worst-case lag: UNBOUNDED in wall-clock (a stalled masterchain or a shard
  that never sees a masterchain head). The consequence is stranded headroom,
  not extra supply: other shards cannot borrow the lagging shard's unused
  quota, so the sum of static shares remains the ceiling. In the limit the
  chain under-uses the cap; it never exceeds it.

Why production does not wire the aggregate view into the engine limit: the
limit affects `apply_block_transition` (the block reward reserve). A node whose
registry lags would then mint a reward a better-synced node refuses, and the
two would commit different roots for the same signed block. The static share
avoids that by being a pure function of the genesis shard set. Wiring a live
aggregate into consensus state requires the two-phase quota handoff described
in §3; until then the aggregate is a masterchain refusal and an advisory
under-mint rule only.

This is the honest trade: the cost of a chain-wide hard cap without a quota
handoff is that idle shards strand their share. `SupplyPartition::uniform`
makes the stranding symmetric and predictable instead of first-come-first-served.

## 5. Genesis accounting

Genesis funding uses the uncapped transfer primitive (`update_account` /
`credit_native_transfer`), so it does not advance the engine counter. The
chain-wide accounting must still see it:

* `InMemoryStateEngine::committed_minted_nano()` returns the counter once the
  first post-genesis mint folded in the baseline, and the committed native
  balance sum (the same baseline) before that;
* `note_finalized_header` writes that value into the shard head, so the genesis
  head of a workchain already counts its pre-mine;
* bootstrap refuses a genesis allocation above the shard's static share
  (masterchain and workchain).

## 6. Failure modes and what fails closed

| Failure | Result |
| --- | --- |
| Shard engine reaches its share | Mints (rewards, bridge, PMM) are refused; transfers still work. Existing behaviour, now per-share. |
| Masterchain proposal declares a head above the cap / above its share | `check_chain_supply_commitment` refuses the proposal. |
| Proposed head rolls a shard's minted total back | Refused (monotonicity). |
| Node has no committed aggregate view | Shard uses its static share: under-mint, never over-mint. |
| Registry snapshot from before v5 | Refused by the version bump; registry starts empty (fail closed) and re-anchors as the node re-syncs. |
| Masterchain stalled | Workchains keep minting up to their static shares; stranded headroom, no cap breach. |
| An inbound transfer lands BEFORE the shard's first post-genesis mint | The engine's lazy genesis baseline sums all committed balances at that instant, so the transfer is counted as pre-mined supply for THAT shard. The chain aggregate then OVER-counts (never under-counts): it can strand headroom or make the masterchain refuse a head early, but it cannot let the chain mint past the cap. |
| A node is configured with a different shard set | It is a different chain configuration; the fork id must cover the ruleset, and mixed fleets refuse consensus at handshake. The partition is a pure function of the committed set. |
| Upgrading a chain that already minted under the old per-engine rule | The share cannot retroactively remove already-created supply. v5 is a HARD FORK with a new genesis (fork id change): a state migrated from a pre-v5 chain must be audited, not assumed under the new cap. |

## 7. Test list

* `stellereum/tests/supply_chain_wide_tests.rs`
  * `two_shards_cannot_jointly_mint_past_the_chain_cap` — each shard gets
    `cap/2`; both filling their share reaches exactly the cap and the next mint
    is refused on both sides. Fails before: each engine accepted a full cap.
  * `genesis_premine_on_two_workchains_counts_toward_the_aggregate` — the
    committed aggregate includes both workchains' genesis allocations.
  * `masterchain_refuses_a_workchain_head_above_the_chain_cap` — a declared
    total above the cap/share is refused, and the aggregate sum is refused even
    when each term is plausible.
  * `committed_aggregate_is_identical_after_restart_and_replay` — registry
    snapshot/restore and delta replay derive the same total.
  * `lagging_aggregate_view_tightens_but_never_loosens_the_static_share` — the
    honest lag bound: stale views and `None` cannot widen a share.
  * `per_engine_guard_still_holds_after_the_partition` — defence in depth.
* `stellereum/tests/supply_cap_tests.rs`
  * `chain_partition_closes_the_per_engine_gap` (replaces the old
    `per_engine_cap_is_not_a_chain_wide_cap_known_gap` proof-of-gap) — two
    shards sum to exactly the cap, not twice it.
  * the existing mint/transfer/reward/snapshot/monotonicity tests still pin the
    per-engine primitive.
* `stellereum/tests/sharding_m2_tests.rs`
  * `inbound_credit_at_the_supply_cap_still_credits_on_the_live_target` — now
    fills the target's chain-wide SHARE; inbound value still credits at zero
    headroom because it is a transfer, not a mint.

## 8. Protocol / fork-id rule (reported, not edited here)

`src/protocol.rs` is owned by the protocol change. To move the fork id for
ruleset v5, append to `FORK_ID_RULES`:

```text
crate::tokenomics::CHAIN_SUPPLY_PARTITION_VERSION   // value 1
crate::tokenomics::TOTAL_SUPPLY_CAP                 // value 1_000_000_000_000_000_000
```

and bump `CONSENSUS_RULESET_VERSION` from 4 to 5 (the rule logic — a new
consensus refusal and a new signed shard-head field — is more than a constant
change). A mixed v4/v5 fleet must refuse consensus at handshake instead of
accepting a masterchain block whose supply accounting it cannot interpret.
