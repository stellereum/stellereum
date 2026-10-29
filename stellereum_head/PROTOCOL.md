# Stellereum Protocol Specification

Status: draft, tracking `main`. Written after the state-root audit (commit
`398e900`) so that every invariant here has a test that fails when it is
violated. Where this document and the code disagree, the code is the bug.

Scope: consensus state, the state transition, and the invariants that make the
chain safe. Transport, gossip and the RPC surface are out of scope except where
they touch consensus.

---

## 1. Consensus state

All consensus-visible state lives in `InMemoryStateEngine`. It is split into two
groups, and the split is not stylistic - it is the definition of what the state
root means.

### 1.1 In the Patricia trie

Committed directly, key by key:

| Domain | Key | Value |
| --- | --- | --- |
| Native account | `address` | `balance_be ‖ nonce_be` |
| STS balance | `sha256("STS_BAL" ‖ token_id ‖ account)` | `balance_be` |
| STS supply | `sha256("STS_SUPPLY" ‖ token_id)` | `total_supply_be` |
| Contract code | `sha256("STELL_CONTRACT_CODE" ‖ addr)` | `code_hash` |
| Consensus commitment | `sha256("STELL_CONSENSUS_COMMITMENT_V1")` | digest, see 1.2 |

The state root is the trie root. Keeping these identical is deliberate: Merkle
proofs and block sync are both defined against the trie root, and a light client
verifying an account proof must not need a second, separately sourced root.

### 1.2 Outside the trie, folded in as a digest

These lived in memory and were never committed. They are hashed by
`commitment::commitment_digest` and written under the single key above.

- **Staking ledger** - `validators` (self_bond, delegated, commission_bps,
  pending_rewards, total_slashed, missed, last_downtime_penalty), `delegations`,
  `delegator_rewards`, `unbonding`, `withdrawable`, `total_burned`.
- **Order books** - per pair: `next_order_id`, `bids`, `asks`, `max_depth`, and
  every order's full field set.
- **Order escrow** - `(pair, order) -> (trader, locked_base, locked_quote)`.
- **PMM** - `minted_nano`, `reserve_micro`, `redemption_buffer_micro`,
  `depth_cap_nano`, `base_price_micro`, plus the quote asset id and treasury.
- **Contracts** - per contract: creator, code_hash, created_at, paused, and the
  full `storage` map.
- **Governance** - `proposals` and each proposal's `voters` (both `HashMap`s,
  normalised through a `BTreeMap`), the applied parameter set and counters. Joined
  the digest in `COMMITMENT_VERSION` 3 (commit `9a93ef0`).
- **Oracle** - `OracleState`: the publisher set, the committed price feeds and the
  circuit-breaker latch. Joined the digest in `COMMITMENT_VERSION` 4 (commit
  `95df70c`).
- **On-chain session keys** - `SessionKeyRegistry`: registration, cumulative gas
  spend and revocation. **Conditional:** hashed only when the registry is
  non-empty, so a chain that never registered a session key commits identically to
  a pre-phase-2 one.
- **Bridge domain** - `BridgeState`: the source-tx replay set
  (`processed_source_txs`), the parked withdrawal queue (`pending_withdrawals`,
  `next_withdrawal_id`), the hourly rate-limit window (`hourly_withdrawn`,
  `last_rate_limit_reset`) and the escrow mirror, on top of the bridge's escrow
  account (an ordinary trie account). **Conditional:** hashed only when the
  domain is non-empty, so a chain that has never bridged commits identically to
  a pre-bridge one. Joined the digest WITHOUT a `COMMITMENT_VERSION` bump, the
  same trick the session keys used (the oracle, by contrast, re-rooted genesis
  when it forced v4).

**I1 - Completeness.** Every field above appears in `commitment_digest`.
`tests/state_root_completeness_tests.rs` mutates each subsystem and requires the
root to move. Adding a field to consensus state without adding it to the digest
fails that test.

**I2 - Determinism.** Every map is sorted by key before hashing, and every
length is written explicitly. `HashMap` iteration order differs between
processes, so a naive walk would give two nodes with identical state different
roots: a consensus split with no attacker involved.

**I3 - The digest is written on read.** `get_state_root()` recomputes the digest
and writes it if it changed. The alternative - committing at each mutation site -
is how the gap opened: dozens of sites, each of which had to remember. The write
is skipped when the digest is unchanged, so repeated reads do not churn the trie.

---

## 2. State transition

```
        Propose ──▶ Prevote ──▶ Precommit ──▶ Commit ──┐
           ▲                                             │
           └───────────── next height ◀──────────────────┘
```

`HeightConsensus` is per height. `ValidatorRuntime::try_finalize` runs on a
precommit quorum, and applies effects in a fixed order:

1. `try_precommit_quorum()` - require 2f+1 precommits for one block
2. `apply_block_fees_rewards` - apply transactions, credit fees to proposer,
   pay block reward, prune the mempool
3. `apply_equivocation_slashes` - punish double-voting
4. `apply_downtime_slashes` - punish absence from this block's certificate
5. record the finalized `(height, hash)`
6. `refresh_validator_set_from_staking` - rotate the set for height+1
7. `HeightConsensus::new(height + 1, ...)` - all votes discarded

A peer that already decided a block is caught up by `adopt_committed`, which
verifies the certificate against the local validator set and then runs the same
step 2. A block reaches the state engine identically no matter which path
decided it.

**I4 - Order matters.** Fees and rewards are applied before slashes, and slashes
before the validator-set rotation, so the reward for height N is computed from
the stake as of height N and the set for N+1 reflects the slashes of N.

---

## 3. Economic security

Both penalties are driven by block evidence, never by local observation. A local
timer would slash honest peers for being partitioned, and two nodes would reach
different verdicts.

**I5 - Downtime evidence is the quorum certificate.** A validator that did not
sign the precommit certificate of a finalized block counts as missed, derived
from that block, so all nodes count identically. A validator that signs again
is forgiven; 10 consecutive misses trigger a 0.1% burn with a 100-height
cooldown between penalties, so one long outage costs a bounded amount rather
than the whole bond. The cooldown deliberately does not apply to a first
offence - on a chain younger than 100 blocks nobody would ever be punished.

**I6 - Slashing burns real stake.** The burn is debited from the staking pool,
not recorded in a counter, so total supply and the pool balance cannot drift
from the sum of individual slashes.

**I7 - The validator set has one source of truth.** It is derived from the
staking ledger inside the state engine at every height boundary. It is not a
node-local value fed over RPC: two nodes that disagreed about the set could not
agree on a proposer, and nothing would have detected it.

---

## 4. Transaction application

`apply_block_parallel_fees` returns `(applied, failed, fees, Vec<bool>)`. The
per-transaction flags are recorded at the commit point inside block application.

**I8 - Verdicts are recorded, never recomputed.** After a transaction applies,
the sender's nonce has moved on, so re-deriving the verdict from post-state
reports every successful transaction as failed. `receipt_status_and_block_are_consistent`
pins this, and also pins that value moves exactly once.

**I9 - Admission is checked before payload execution.** Transactions are
pre-validated in deterministic per-sender nonce order. A transaction that fails
signature, nonce or balance must not execute its SVM payload, because payloads
mutate shared token and orderbook state - otherwise an unfunded or replayed
transaction could still place orders while being reported as failed.

**I10 - Payload execution is deterministic.** Payloads run sequentially in
block order, and the VM uses clone-commit, so a reverting or out-of-gas payload
leaves no partial effect.

**I11 - A payload's value movement is applied, not merely executed.** The SVM
returns the value its program moved (`transfers`, `payouts`); both
`apply_transaction` and `apply_block_parallel_fees` commit it through one shared
commit point (`state_engine::commit_native`), in one order - sender debit,
recipient credit, payload transfers, payload payouts - with the fee and everything
the payload moved re-checked against the sender's balance under the lock. A
Transfer, a `SysCallStake` bond into the pool or a `SysCallClaimRewards` payout
therefore moves the same coins whichever path applies it.
`tests/live_block_path_tests.rs` drives those payloads through the block path,
which is the path every finalized block takes.

**I12 - The VM's clock is the block's clock.** `execute_payload` takes
`block.timestamp` and hands it to the VM as `VmContext.timestamp`, so
`SysCallUnbond` matures at `block.timestamp + UNBONDING_PERIOD_SECS`, contracts
carry the deployment time of their block and orders are stamped with it. It used
to be a hardcoded `0`, which was identical on every node (so nothing split) and
wrong on every node.

*Documented divergence, preserved deliberately:* the fee each path CHARGES.
`apply_transaction` charges the gas actually consumed; `apply_block_parallel_fees`
charges the declared `gas_limit`, which is what admission reserved and what
`fees_collected` credits to the proposer. Both rules are pinned by tests
(`bonding_moves_real_funds_and_grants_validator_power` vs
`block_execution_runs_payloads_and_conserves_native_value`); unifying them would
change what a payload transaction costs on chain. What is shared, and must be:
a payload can never spend the fee, and an unaffordable transaction is refused on
both paths without moving value.

---

## 5. Known gaps

These are real and deliberately not yet addressed. They are listed so an auditor
does not have to rediscover them.

- **Archive state is not committed per key.** The non-trie subsystems are
  committed as a digest, so a light client can prove a balance but not a single
  staking entry or orderbook level. Per-entry keys would be needed for that.
- **Restoring from a snapshot does not rebuild the commitment.** A restored
  engine commits on the next root read, but a snapshot taken before this change
  carries no commitment key and the first read folds the in-memory state in.
- **No light client.** The completeness of I1 is what makes one possible; it does
  not exist yet.
- **Ed25519 votes, not BLS.** 100+ validators means 100+ signatures per
  certificate.
- **The commitment is recomputed per root read.** O(state) per block. Correct
  first, optimisable later.

## Security posture (updated 2026-09-25)

### Closed and regression-tested

| Finding | Fix | Regression |
| --- | --- | --- |
| Sync accepted chains signed by non-validators | `Block::verify_validator_quorum(&ValidatorSet)`, power-weighted; `validate_sync_chain` takes the real set | `hunt_sync_quorum.rs`, `hunt_consensus_core.rs` |
| `try_finalize` finalised a block body the node never had | refuses to advance unless the block is present | `hunt_finalize_split.rs` |
| `SysCallUnbond` / `SysCallClaimRewards` / `SysCallCancelOrder` had no owner check | owner-only | `hunt_staking_grief.rs`, `hunt_staking_theft.rs`, `hunt_svm_steal.rs`, `hunt_clob_orphan.rs` |
| A block decided on precommits alone, or on a prevote/hash mismatch | `try_precommit_quorum` requires a **prevote quorum for the same block** and refuses to contradict the lock | `consensus::a_block_cannot_be_decided_on_precommits_alone`, `a_locked_validator_will_not_decide_a_different_block`, `hunt_slashing.rs` |
| One peer message bought 1000 rounds, wedging the pair | a message advances the round by at most 1; rounds move on our OWN timeout (`next_round`) and never on a peer's claim | `consensus::repeated_peer_messages_*`, `hunt_round_dos.rs`, `hunt_consensus_core::hunt7` |
| Block sync could never fire: the head pointer was node-local | head published as a replicated DHT blob (`stell_head`), catch-up runs inside the loop and re-anchors `hc` | `catch_up_tests.rs` |
| `adopt_committed` accepted a prevote quorum, ignored cert height/round, the proposer slot, the state root, and a caller-supplied validator set | requires a precommit QC bound to this height and round, the scheduled proposer, our own state root, and uses `self.validators` | `hunt_qc_kind.rs`, `hunt_consensus_core.rs`, `hunt_finalize_split.rs`, `hunt_consensus_round3.rs` |
| Equivocation evidence was never deduplicated -- one signed pair replayed N times slashed 5% x N | evidence keyed by the conflicting pair, recorded once | `consensus` + `hunt_` regressions |
| `note_missed_heights` decremented the aggregate without the delegation map, never incremented `total_burned`, never debited the pool, and had no cap on the delegated leg | routes through `slash()`; replay-idempotent | `hunt_amplify.rs`, `hunt_ledger_desync.rs`, `hunt_sweep_final.rs` |
| `stell_faucet` was ungated on a publicly bound port with a key that is a published constant | own `STELL_FAUCET_TOKEN`, fail-closed; RPC bound to loopback; scoped firewall | `rpc::faucet_refuses_without_a_token`, `enabled_faucet_without_a_configured_token_fails_closed` |
| The genesis root could move silently when the commitment changed | `tests/genesis_root_known_answer_tests.rs` pins it against fixed inputs | that file |

A refused syscall rolls the whole transaction back: no gas is charged and no ledger
field is mutated, so a rejected theft costs the attacker nothing.

### Open, documented

- **No observer role.** `build_validator_set` always includes the local key, so every
  node is a validator. The config convention is "`validators:` lists the others";
  running N validators means each node lists the other N-1. An observer cannot be
  expressed, and a node with a key outside the intended set will derive its own chain.
- **A restarted node resumes a stale round.** The persisted `ConsensusCheckpoint.round`
  is restored, so two nodes that were deadlocked at different rounds and restarted
  resume at different rounds and stay deadlocked. Recovery is a coordinated wipe of
  both data directories (documented in OPERATIONS.md).
- **Full block bodies are only published on a best-effort cadence.** `broadcast_block`
  is called at genesis and the head pointer on every finalize, but bodies rely on the
  retro-publish pass (bounded, every 30 s, 128 per pass, 4096 deep). A node further
  behind than that depth cannot catch up from this node.
- **Governance, the oracle AND the bridge are in the state commitment.**
  `commitment.rs` (`COMMITMENT_VERSION = 4`) folds governance in (proposals and
  voters normalised through a `BTreeMap`; commit `9a93ef0`, version 2 -> 3),
  the oracle feed (`OracleState`: publishers, committed
  feeds, breaker latch; commit `95df70c`, version 3 -> 4), and the bridge domain
  (`BridgeState`: source-tx replay set, withdrawal queue, rate-limit window,
  escrow mirror; commit `1f973ff`, WITHOUT a version bump - conditional, so an
  unbridged chain commits identically to a pre-bridge one; see §1.2). Committed
  domains are now tokens,
  staking, orderbooks, escrow, PMM, contracts, governance, oracle and the bridge
  domain. This supersedes the earlier claim that the bridge (and, before it,
  governance and the oracle) were not folded in.
- **BLS is now real pairing-based BLS.** `src/bls.rs` was a Schnorr-style
  multi-signature at the time of the state-root audit, but commit `9a93ef0`
  (P1-c) replaced it with genuine BLS12-381 (`bls12_381` crate, pure Rust):
  48-byte G1 public keys, 96-byte G2 signatures, single-signature verification by
  `e(sig, G1) == e(H(m), pk)` and same-message aggregation by
  `e(agg_sig, G1) == e(H(m), agg_pk)`. The signer bitvector is mandatory (a bare
  aggregate does not prove *which* keys signed) and is what downtime slashing
  consumes; `HybridCertificate`/`is_bls_active` model the soft-fork activation.
  The `src/consensus.rs` QC path still produces Ed25519 signatures by default
  (`qc_bls_enabled()`), so the deployed chain uses the Ed25519 certificate while
  the BLS path is opt-in.
- **The commitment is recomputed per root read.** O(state) per block.
- P3 (performance and per-entry archive proofs) is deliberately not started. The
  BLS pairing library portion of P3 is done (see the BLS entry above).

`cargo test`: 618 passed, 0 failed (count at the time of this revision; the
suite has since grown - see the total at the end of this document).

## Security posture (updated, wave 5 + faucet durability)

### Newly closed since the last revision

| Finding | Fix | Regression |
| --- | --- | --- |
| Finalized blocks carried only the proposer's signature, so sync could verify nothing | `Block.precommit_qc` attached at finalize; `validate_sync_chain` verifies the QC (kind, height, hash, quorum) | `catch_up_tests.rs`, `partition_heal_tests.rs`, `sync` unit tests |
| Equivocation evidence never deduplicated (one pair replayed N× slashed 5%×N) | evidence keyed by conflicting pair, recorded once | `consensus` unit tests |
| Downtime path skipped on catch-up (fresh `HeightConsensus` has no QC) | adopt installs the verified cert as the height's QC first | `hunt_finalize_split.rs` finding 3 (now asserts equal roots) |
| Faucet lifetime caps + nonce in-memory only (1000 STELL/address/restart, unbounded) | persisted to a `faucet_state_v1` meta key on every mutation, loaded at startup, corrupt record fails closed to empty | `rpc::faucet_caps_survive_a_restart`, `adversarial_economic_tests.rs` |
| Governed params decorative (block_reward, min_bond, commission never read) | block production prefers `AppliedParams`; `VmContext` carries governed min/commission resolved once per tx | `governance_applied_tests.rs` |

### Adversarial re-verification (wave 5)

`tests/adversarial_regression_tests.rs` (20 tests) re-runs every closed finding's
original attack literally: all blocked, no bypass. `tests/adversarial_4node_tests.rs`
(5 tests): equivocating proposer heals, round inflation capped, withheld QC inert at
new heights, nil-grind doesn't stop the honest three, amnesia replay out of scope.
`tests/adversarial_economic_tests.rs` (6 tests): double-dip, commission front-run,
dust, fee games and self-dealing all hold.

Known residual, stated plainly: equivocation evidence is votes a node observed, and a
catching-up node observed nothing -- full parity there needs evidence shipped with
the commit certificate (wire change), not a stricter local check.

`cargo test`: 760 passed, 0 failed (count at this revision; measured total
across all test binaries on the current `wip/passport-agents` HEAD is **915
passed, 0 failed** - verify with `cargo test --no-fail-fast 2>&1 | grep -E '^test
result:'` and sum the `passed` numbers).

`cargo test`: 999 passed, 0 failed (verified 2026-10-04 on HEAD `1d595c1` with
that same pipeline against a clean worktree - all `test result:` lines `ok`,
zero failures. The working tree at the time carried uncommitted wave edits
(`src/state_engine.rs`, `src/svm.rs`, `src/zkml.rs`) that did not compile, so
999/0 is the last full green anchor, not a claim about the dirty tree).
