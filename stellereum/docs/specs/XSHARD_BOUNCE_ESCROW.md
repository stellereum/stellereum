# XSHARD bounce escrow (S6-2) — activation gate and invariants

Status: implemented behind `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT`
(compiled default `u64::MAX`, i.e. disabled).
Owner surface: `src/chain_spec.rs`, `src/runtime/{apply,consensus_step,anchors,mev_sync}.rs`,
`src/state_engine/xshard.rs`.

## 1. Defect

The legacy cross-shard timeout bounce trusted a "produced" record and a height
timeout, but nothing tied either to a real source debit:

1. `ValidatorRuntime::record_apply_outcome` (`runtime/apply.rs`) recorded
   `produced_cross_shard` for **every** outbound legacy `Transfer` in the block,
   regardless of the transaction's apply `status[i]`.
2. `control_linkage_ok` (`runtime/anchors.rs`) accepted a bounce when the tx
   hash was produced, the 64-height timeout had elapsed, and the lifecycle was
   not completed. It never asked whether the source escrowed anything.
3. `validate_proposal` (`runtime/consensus_step.rs`) checked only that the
   outbound record's transaction was **present in the block** — not that it
   applied, and not that its debit was committed.
4. The refund paid `tx.amount` through `credit_native_transfer`, the uncapped
   transfer primitive. That is correct for redeeming escrowed value, but it
   mints if the value was never debited.

Two exploits follow.

**(a) Failed-apply mint.** A validly signed transaction that fails at apply
(saturated nonce, a reverting payload, a short balance after admission) debits
nobody. Its outbound transfer record is still in `cross_shard_out`, so it is
recorded as produced; at `produce_height + 64` the source commits a bounce and
credits `tx.amount` to the sender. Repeatable — free money.

**(b) 2PC double spend.** A §9 2PC PREPARE exists for tx `T` (the source will
escrow and the target will credit on COMMIT), and a legacy transfer record for
the same `T` also exists. A hand-crafted bounce for `T` passes linkage
(produced + timeout + not completed), so the source refunds while the target's
COMMIT credits the recipient. The same value is spent twice.

## 2. Gate

`chain_spec::XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT`:

* compiled value `u64::MAX` → `xshard_bounce_escrow_required_active_at(h)` is
  `false` at **every** height (including `u64::MAX`), so the live single-shard
  chain `{0}` is byte-identical to the previous build;
* test/debug-only thread-local override
  `set_xshard_bounce_escrow_override(Option<u64>)`;
* registered as `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` in
  `current_activation_schedule()` so operators see it in
  `ChainActivationSchedule`.

## 3. Invariants at/above the gate

Let `L(T) = (xshard_escrow_state_key(T.compute_tx_hash()), xshard_escrow_state_value(T))`
be the XSHARD-01 source escrow/debit leaf, written by the source's apply path
only for an outbound legacy transfer whose transaction **applied**.

1. **Produced implies debit.** `produced_cross_shard` contains `T` only if
   `status[idx(T)] == true` **and** `L(T)` is committed. This holds in both
   mirrors:
   * runtime: `record_apply_outcome` (`runtime/apply.rs`);
   * engine: `record_legacy_escrow_receipts_with_index`
     (`state_engine/xshard.rs`) — `apply_cross_shard_consumptions` no longer
     writes the gate-active produced set.

   Both use the same predicate and the same leaf helpers, so
   `cross_shard_replay_covers` and the persisted `CrossShardReplaySnapshot`
   cannot diverge across a restart.
2. **Outbound legacy proof.** An outbound legacy record on this chain is valid
   only if `verify_cross_shard_escrow_anchored(record)` holds: the same
   anchored XSHARD-01 escrow proof the inbound legacy credit requires. The
   "transaction is present in the block" shortcut is gone. Consequence: a
   one-step legacy producer cannot satisfy this (it anchors to the parent root,
   which predates its own escrow), so legacy cross-shard **value** is disabled
   while the gate is active; §9 2PC is the delivery path.
3. **Bounce requires escrow.** Before a bounce refund is paid, the engine/trie
   must hold `L(T)` (`InMemoryStateEngine::has_legacy_escrow_leaf`); the
   proposer also filters derived bounces on the same predicate. A produced entry
   inherited from a below-gate block that never escrowed therefore cannot pay.
4. **2PC precedence.** Any tx hash with a §9 2PC record — PREPARE, COMMIT or
   ABORT, committed or in the same block — is refused by the control path
   (`control_linkage_ok`, apply, engine apply, proposer admission). A bounce or
   ack for such a hash never claims the replay key and never moves value.
5. **Ordering.** All gate checks happen **before** the consumed/completed
   inserts, so a refused bounce stays replayable for a later height and the
   replay sets never claim a completion that paid nothing.
6. **History cleanse at the gate (restart lockstep).** Entries inherited from
   below the gate were recorded unconditionally, so a failed apply can be in
   the produced set. The first gated block (and every gated block after it)
   removes every produced entry WITHOUT a committed escrow leaf
   (`legacy_escrow_leaf_committed`, a pure function of the committed trie), in
   both the engine and the runtime mirror. The digest moves identically on
   every node holding the same pre-state. After that block the produced set
   contains only real debits, so a snapshot taken at/after the gate re-derives
   exactly the leaves the committed root contains and `cross_shard_replay_covers`
   matches across restart. A snapshot taken BELOW the gate keeps the historical
   restore behaviour byte-for-byte; a pre-gate failed-apply record makes that
   snapshot's re-derived leaf disagree with its committed root, which the
   existing `verify_restored_root` refuses (fail closed, never a mint) — take
   the first post-gate snapshot after `H`.

Below the gate every one of the above is skipped and the historical code path
runs unchanged (pinned by `x8_bounce_below_gate_unchanged`).

## 4. Exact code touchpoints

| Place | Gate-active behaviour |
| --- | --- |
| `chain_spec::xshard_bounce_escrow_required_active_at` | single source of truth |
| `runtime/apply.rs` `record_apply_outcome` | produced needs `status[i] && L(T)`; control records need `L(T)` and no 2PC (same block or mirror) |
| `runtime/anchors.rs` `control_linkage_ok` | refuses a hash present in the 2PC mirror |
| `runtime/consensus_step.rs` `validate_proposal_unaligned_with_hash` | outbound legacy record needs `verify_cross_shard_escrow_anchored`; ack/bounce refused if the block also carries a 2PC record for its hash |
| `runtime/mev_sync.rs` `propose` | derived bounces filtered on `L(T)` and on 2PC ownership; mailbox bounces filtered the same way; outbound legacy transfers are not selected when the 2PC is not the configured flow |
| `state_engine/xshard.rs` `apply_cross_shard_consumptions` | produced skipped; control records need `L(T)` and no 2PC (block set or map) |
| `state_engine/xshard.rs` `record_legacy_escrow_receipts_with_index` | writes the gate-active produced entry together with `L(T)` |
| `state_engine/xshard.rs` `has_legacy_escrow_leaf` | local, proof-free leaf predicate used by every apply-time check |
| `state_engine/xshard.rs` `legacy_escrow_leaf_committed` | key-only leaf predicate used by the gated produced prune |
| `state_engine/xshard.rs` `apply_cross_shard_consumptions` (head) | prunes produced entries with no committed escrow leaf on every gated block |
| `runtime/apply.rs` `record_apply_outcome` (head) | mirrors the same prune before inserting this block's produced entries |

No wire format, transaction format, block format, msg-id domain, quorum value
or signature domain changes. The only new consensus-visible rule is the gated
predicate above.

## 5. Prerequisites for enabling (multi-shard `{0,1}`)

Before any chain sets `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` to a real height:

1. The shard set is genuinely sharded (`ShardRegistry::is_sharded()`), so the
   runtime and engine cross-shard paths are active on every node.
2. `XPC_ACTIVATION_HEIGHT` is active from genesis (it is `0` in the compiled
   chain spec) and every node runs `XpcActivation::from_chain_spec()`, so new
   cross-shard value moves through PREPARE → PREPARE-ACK → COMMIT. The gate
   disables new legacy value delivery by design.
3. Every node runs a build that includes this rule. The gate height is
   consensus-visible (it changes which blocks validate), so it must be a
   coordinated chain-spec value, never a local env knob.
4. Any reorg/`ChainState::apply_block` mirror (`runtime/cluster.rs`) must be
   updated to the same produced predicate before the gate opens; it is a
   replay mirror, not the live apply, and must not re-derive a produced entry
   the live path would refuse.
5. The live `{0}` chain keeps `u64::MAX`. Changing it on a single-shard chain is
   a no-op at reachable heights but is not how `{0,1}` should be activated:
   `{0,1}` sets one shared height for the shard set.

## 6. Activation sequencing

1. Ship the build with the gate disabled (`u64::MAX`). Verify the below-gate
   tests and the full suite.
2. Configure the `{0,1}` genesis chain spec with the 2PC active from genesis.
3. Choose a bounce-gate height `H` strictly greater than the last height at
   which a legacy transfer may be produced. Transfers produced below `H` remain
   bounce-eligible after `H` **only if** their escrow leaf exists (an honest,
   applied legacy transfer always has one while the process has not been
   replay-restored). Prefer draining below-gate legacy transfers (ack or
   timeout bounce) before `H`: a replay-restore at/after `H` deliberately does
   not re-synthesize pre-gate leaves, so an unfinished one then fails closed.
4. Set `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT = H` in the coordinated
   chain-spec/genesis identity and restart/upgrade all nodes together.
5. Do not lower `H` afterwards: blocks below it were validated under the old
   rule.

## 7. Tests

`tests/x8_bounce_escrow_gate.rs`:

* `x8_bounce_failed_apply_outbound_record_cannot_mint` — exploit (a); fails on
  the ungated code, passes with the gate active at the test height.
* `x8_bounce_2pc_transfer_bounce_cannot_double_spend` — exploit (b); the target
  COMMIT credits once, the source bounce refunds nothing.
* `x8_bounce_escrow_proven_transfer_refunds_exactly_once` — the happy path:
  a genuinely debited, escrow-proven legacy transfer still bounces after the
  timeout and refunds exactly once.
* `x8_bounce_below_gate_unchanged` — the compiled default (`u64::MAX` /
  overridden off) keeps the historical produced record and the historical
  refund.
* `x8_bounce_gate_prunes_unproven_produced_records` — the first gated block
  (even empty) deterministically prunes produced entries with no committed
  escrow leaf, in the engine and in the runtime mirror; an escrow-proven entry
  survives, so a post-gate snapshot restores exactly the committed leaves.
