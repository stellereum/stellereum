# RULESET V6 — locks compare the round-free value id; rescues re-stamp

Ruleset 6 is a consensus-logic hard fork. It changes which signed body a
locked validator will prevote and which body a proposer serves on rescue. No
wire field, domain string, quorum value or constant value changed; the
ruleset version itself is the activation marker, so the fork id moves and
mixed fleets fail closed at handshake.

| Field | Value |
|---|---|
| `PROTOCOL_VERSION` | 1.0 (unchanged) |
| `CONSENSUS_RULESET_VERSION` | **6** |
| `DOMAIN_SET_VERSION` | **3** (unchanged) |
| `FORK_ID` | **`0x0f584a46`** |
| Rules folded into the fork id | **23** (unchanged list) |
| Genesis | new (a v5 data directory is refused) |

## The defect ruleset 6 closes

Under ruleset v4/v5 the BFT round is part of the signed block hash. Lock
rescue re-served the locked body **verbatim**, so the body kept the round it
was originally signed under while the network moved on:

```
A at r+3 re-serves body B signed at r
B, C accept B (block.round = r <= their round)
prevote round = B.round = r        <-- older than the network
```

Votes are watermark-gated: a validator that signed **any** vote at round `q`
(a nil prevote is enough) must never sign at `r <= q`. In the live shape the
floor was already above the body's signed round, so the value vote was
refused, no polka formed, and the height stayed parked forever even though all
three validators held and wanted the same value. This is the
`LIVE-STALL` / `SIGNED-ROUND-LIVENESS` shape in `docs/OPEN_DEFECTS.md`; the
mechanism analysis is `docs/LIVENESS_ROUND_SYNC_AUDIT.md` (R-B, T3, T10).

## The two rules

1. **Value identity is round-free.** `Block::value_id()` is the block hash
   with the signed `round` forced to `0`. The existing block-hash preimage
   zero-skips round 0, so this is the canonical body identity. Lock/unlock,
   precommit-vote guards, decision checks, the demanded-body (lock-hint)
   lookup and every "is this the same value?" comparison use `value_id`.
   Votes, proposer signatures, QCs, the compact body index and finality keep
   the **signed** hash (`compute_hash`), which still commits the real round.

2. **A rescued body is re-stamped at the proposer's current round.** When
   `propose` serves a locked or demanded body, it rebuilds the identical
   value with `round = hc.round`, clears the signatures and re-signs the new
   hash. It never re-serves the stale signed round. The original body stays
   in the store for body serving and hint resolution. A body authored by
   another validator is served unmodified (only its author can sign it, and
   rewriting `proposer` would change the value identity); the demanded rescue
   only ever stores the node's own bodies.

`accepts_block_round(block)` remains `block.round <= hc.round`: after
re-stamping the equality path is the normal one, and the earlier-signed-round
tolerance is preserved for a body already held.

## Why it is safe

* **No double finality.** Two hashes of one value commit to the same height,
  shard, parent, state root, timestamp, transaction order and commitments;
  they differ only in the round tag. A QC for either certifies the same state
  transition and a height decides at most once (`try_finalize`,
  `adopt_committed`).
* **No vote below the watermark.** Every value vote is stamped with the body's
  signed round, which is now `hc.round` — strictly above the fsynced floor.
  The write-ahead watermark, one vote per `(height, round, kind)` and the
  no-rewind rule are unchanged.
* **No future signed round.** `accepts_block_round` still refuses
  `block.round > hc.round`.
* **Locks keep their strength.** `same_value(a, b)` is true for equal hashes,
  and for different hashes only when BOTH registered round-free ids are known
  and equal. An unknown hash falls back to plain equality, so a node cannot
  unlock or decide on identity it does not hold.
* **Proposal-slash evidence is unchanged.** Evidence still requires the SAME
  signed round with two different bodies. A re-stamp has a different signed
  round and is never evidence (`value_id_lock_tests`).

## Test pins

* `tests/live_stall_repro_tests.rs::restamped_locked_body_is_voted_above_a_nil_watermark_and_finalises`
  — the exact live shape: a nil prevote at `r+2`, a locked value re-proposed
  at `r+3`, the value vote at `r+3` (strictly above the floor), finality.
* `tests/value_id_lock_tests.rs` — `value_id` stability/value sensitivity, a
  re-stamped body accepted by a peer that never held the old hash, and a
  re-stamp never accepted as proposal-equivocation evidence.
* `tests/signed_round_liveness_tests.rs`, `tests/live_stall_repro_tests.rs`,
  `tests/chase_livelock_tests.rs`, `tests/lock_rules_audit_tests.rs`,
  `tests/bft_lock_safety_tests.rs` — re-pinned lock/round behaviour.
* `tests/protocol_negotiation_tests.rs::fork_id_v6_is_pinned_and_matches_the_sdk_guard`
  — `FORK_ID = 0x0f584a46`, 23 rules, ruleset version 6; the Rust SDK
  (`stellereum-sdk/tests/parity.rs`) and the TS SDK test pin the same value.

## Upgrade note

New genesis. The repair path (`propose` re-stamp) and the lock comparison are
consensus behaviour, so a v5 binary and a v6 binary must not share a chain:
the handshake refuses the fork-id mismatch. The stopped cluster can adopt v6
directly with a fresh data directory (`docs/FRESH_GENESIS_RUNBOOK.md`).
