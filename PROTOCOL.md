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

### 1.3 The commitment domains

`commitment_digest` is a sequence of **domains**. A domain is either
*unconditional* - it always contributes bytes - or *conditional*: it contributes
**zero bytes** when its own state is empty. A conditional domain is what lets a
feature be added without re-rooting the chain: an unused feature hashes
byte-for-byte identically to a chain that predates it, so the pinned genesis
known-answer vectors stay valid and `COMMITMENT_VERSION` does not have to move.

The rules a domain must obey:

- it is **domain-separated** by a tag (`put_bytes(h, b"<tag>", b"<TAG>_V1")`);
- it is **appended** after every pre-existing domain, so an older preimage
  stays a prefix of a newer one;
- **nothing inside a domain is conditional**: once the domain is present, every
  field that decides a future outcome is committed;
- a conditional domain must contribute **nothing at all** when empty - not even
  a zero length prefix (that is why the emptiness test is outside the
  `put_bytes` call).

`COMMITMENT_VERSION` is currently **5**. It moved 4 → 5 when the oracle joined
the digest (a deliberate re-root: every data directory needs a wipe and
`tests/genesis_root_known_answer_tests.rs` needs a new pinned root).

| domain | tag | conditional on | what it commits |
| --- | --- | --- | --- |
| Staking core | — | no | validators, delegations, delegator rewards, unbonding, withdrawable, `total_burned` |
| Staking rewards pool | `STAKING_REWARDS_V1` | `rewards_pool != 0 \|\| rewards_minted != 0` | the minted pool and the total ever minted |
| Governance locks | `STAKING_GOV_LOCKS_V1` | the governance-lock map is non-empty | the per-voter stake locked behind an open vote |
| Equivocation dedup | `STAKING_EQUIV_DEDUP_V1` | the dedup set is non-empty | the conflicting-vote pairs already punished (replay-idempotence) |
| PQ key registry | `STAKING_PQ_KEYS_V1` | the PQ key map is non-empty | the pinned post-quantum public keys |
| Team vesting | `STAKING_VESTING_V1` | the vesting schedule map is non-empty | allocation, start, cliff, duration, claimed |
| **Lazy (F1) reward accumulator** | `STAKING_REWARD_ACC_V1` | the accumulator map **or** the checkpoint map is non-empty | the delegator payout formula (see §1.4) |
| Governance | — | no | proposals, voters, weights, applied parameters |
| Oracle | — | no | the publisher set, the committed feeds, the breaker latch |
| Order books + escrow | — | no | the books, their depth and every order's fields; the escrow |
| PMM | — | no | minted, reserve, buffer, depth cap, base price, quote asset, treasury |
| Contracts | — | no | per contract: creator, code hash, creation time, paused, storage, **ABI manifest** |
| Tokens | — | no | name, symbol, description, decimals of every token |
| Session keys | — | the registry is non-empty | registrations, cumulative gas spend, revocations |
| Bridge | — | the bridge state is non-empty | the source-tx replay set, the withdrawal queue, the rate-limit window, the escrow mirror |
| Confidential state | `STELL_CONFIDENTIAL_STATE_V1` | the registry is non-empty | the confidential account state (balances, spent set, total fees, ownership map) |
| zkML models | `ZKML_MODELS_V1` | the model registry is non-empty | the registered models and their hashes |
| zkML verifying keys | `ZKML_VKS_V1` | the VK registry is non-empty | the verifying keys and their attestations |
| **Cross-shard replay** | `XSHARD_REPLAY_V1` | all three replay sets are empty | the consumed-message set, the produced-outbound log, the completed-lifecycle set |

### 1.4 The lazy (F1) delegator-reward accumulator

The delegator payout is computed from a **reward-per-token accumulator** rather
than by re-walking the history. The accumulator is consensus state and it is
committed, because an uncommitted field is a silent fork:

- two nodes holding different `reward_per_token` values compute **different**
  entitlements for the same delegator under the same state root — and the
  payout is a transfer of real coins;
- a stale checkpoint pays a delegator **twice** (or not at all) for the same
  accrual.

Everything that decides a future payout is therefore committed, in the
`STAKING_REWARD_ACC_V1` domain:

| field | meaning |
| --- | --- |
| `reward_acc_per_token` | the accumulator rate |
| `reward_acc_historical` | the rewards already distributed out of the pool |
| `reward_acc_remaining` | the pool still to distribute |
| `reward_acc_remainder` | the carried division remainder |
| `reward_acc_remainder_den` | the delegated total the remainder was carried from |
| `reward_cp_value` | the per-`(validator, delegator)` checkpoint |

The remainder is committed **together with its denominator**: a remainder only
means something against the delegated total it was carried from, so committing
one without the other would be worse than committing neither.

The domain is **conditional**: a ledger that never distributed a delegator
reward has an empty accumulator map and an empty checkpoint map, writes zero
bytes, and hashes byte-for-byte identically to a pre-F1 chain.

**I1a - The accumulator is part of the root.** `tests/state_root_completeness_tests.rs`
mutates the accumulator and requires the root to move; a second test requires
the digest to be insertion-order independent (the maps are `HashMap`s, so the
digest re-sorts them into `BTreeMap`s first — the same rule as I2).

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

## 2a. Chain-id binding (cross-chain replay protection)

Every consensus signature and every block hash is bound to the **chain id**.

The chain id is `STELL_CHAIN_ID` (default **5757**,
`zkml::DEFAULT_CHAIN_ID`), read once and **frozen** for the lifetime of the
process (`consensus::FROZEN_CHAIN_ID`). The freeze matters because a
disagreement here is a **chain split**, not a nuisance: two nodes on the same
host that read the environment at different moments would derive different vote
preimages and different block hashes, and would then never agree on anything.
Reading it once also makes the read a constant-time atomic instead of an
environment lookup on every vote.

| preimage | layout | domain tag |
| --- | --- | --- |
| vote | `chain_id(8 BE) ‖ height(8 BE) ‖ round(4 BE) ‖ kind(1) ‖ has_hash(1) ‖ hash(32)` | `STELLEREUM_BFT_VOTE_V2` |
| block | `chain_id(8 BE) ‖ shard_id(4 BE) ‖ height(8 BE) ‖ prev_hash(32) ‖ state_root(32) ‖ …` | `STELLEREUM_BLOCK_V3` |
| transaction | `chain_id(8 BE)` is appended to the signing preimage when the transaction is bound to one (`sharding::Transaction::sign_with_chain_id`) | — |

The vote tag was bumped `V1 → V2` and the block tag `V2 → V3` when the chain id
entered the preimage: the layout changed, so the old bytes must not verify.

**I13 - A signature is bound to one deployment.** A vote or a block signed on
one deployment has a different preimage - and therefore a different signature -
than the same object on another. A testnet vote or block can never verify on
mainnet **even with the very same validator key**, and a transaction signed for
one chain id cannot be replayed on another.

Two consequences worth stating:

- The chain id is a **deployment-wide constant**. Every node of one deployment
  reads the same `STELL_CHAIN_ID`, so they derive the same vote preimages, the
  same block hashes and the same sortition committees.
- The chain id used for **signature verification** in the EVM adapter pins the
  5757 constant (`CHAIN_ID` in `src/evm_adapter.rs`) rather than reading the
  environment: every node that admits the same raw bytes must reach the same
  verdict, and a per-process env read at each verification site would let
  validators with different environments admit different transaction sets.

---

## 3. Economic security

Both penalties are driven by block evidence, never by local observation. A local
timer would slash honest peers for being partitioned, and two nodes would reach
different verdicts.

**I5 - Downtime evidence is the proposer-chosen parent QC, not the local
finality QC (W10.5).** Every block embeds `last_qc` — the precommit
certificate that decided height H-1 — covered by the block hash and verified
by every validator against the set in force at H-1. The transition attributes
height H-1's misses from that ONE certificate, so two nodes that finalized the
same block with different quorate finality-QC subsets (e.g. {A,C} vs {A,B,C},
both passing the same quorum — live 2026-10-23 #292786) still bump identical
counters and commit identical state roots. Attributing from the locally
assembled finality QC forked the chain permanently: the subsets differ by vote
arrival timing while the evidence must be byte-identical everywhere. A
validator that did not sign the embedded certificate counts as missed; a
validator that signs again is forgiven; 10 consecutive misses trigger a 0.1%
burn with a 100-height cooldown between penalties, so one long outage costs a
bounded amount rather than the whole bond. The cooldown deliberately does not
apply to a first offence - on a chain younger than 100 blocks nobody would
ever be punished. The finality QC (`precommit_qc`) stays as the finality
proof (checkpoints, light clients, sync) but is no longer slash evidence.

**I6 - Slashing burns real stake.** The burn is debited from the staking pool,
not recorded in a counter, so total supply and the pool balance cannot drift
from the sum of individual slashes.

**I7 - The validator set has one source of truth.** It is derived from the
staking ledger inside the state engine at every height boundary. It is not a
node-local value fed over RPC: two nodes that disagreed about the set could not
agree on a proposer, and nothing would have detected it.

**I7b - Set changes take effect at the clean H+1 boundary, and every quorum
check uses the set in force at the certificate's height (W10.5).** A set
derived from the ledger at ledger-height L is STAGED and becomes in-force
exactly when the node advances to L+1 — never mid-flight — so the quorum
threshold for a height in progress can never jump under a running round, and
every node that applied the same prefix switches at the same agreed height.
Local decide, adopt, sync-chain verify, light-client anchor, proposal
evidence checks and replay all resolve the set by height
(`validator_set_for_height`, backed by the activation history), never the
live set. A node must never finalize with only its own vote when the set
requires more: every decision/adoption helper asserts the certificate's
signed power reaches the in-force quorum and refuses loudly otherwise
(`stell_weak_qc_refused_total`). Regression: `tests/w10_5_activation_race.rs`
replays the 2026-10-23 join-at-H scenario (agreement on H+1's quorum,
unilateral refusal, subset-convergence).

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

## 4b. Sharding: the address→shard rule

The full specification — the exact rule, the prefix length, how the rule
changes on a split and a merge, the masterchain form, the published
thresholds, and the trie migration plan — is in
[`docs/SHARDING.md`](docs/SHARDING.md). In short:

- The **masterchain is shard 0** and is addressed **explicitly**, in the TON
  style `-1:<addr>` (or `0:<addr>`). A **bare 32-byte address never routes
  to the masterchain** — it is a workchain address.
- A **workchain address routes to the shard whose routing prefix is the
  longest prefix of the address's leading bits**, ties broken by the smallest
  shard id. The routing prefix is the top `prefix_len` bits of the address's
  first 8 bytes — the same definition TON uses.
- A **split** grows the prefix by exactly one bit (the address's bit at the
  new depth decides the child); a **merge** removes the deepest bit and
  restores the parent prefix. The rule changes only at a transition.
- **Published thresholds**: `MIN_ACCOUNTS_PER_SHARD = 100`,
  `MAX_SHARDS = 16` (the shipped cap), `MAX_PREFIX_BITS = 60`,
  `SHARD_SPLIT_LOAD_THRESHOLD = 500`, `SHARD_MERGE_LOAD_THRESHOLD = 50`.
  The advertised shard space is 2^60; the **shipped** cap is 16 — the
  distinction is stated explicitly in `docs/SHARDING.md` and in the
  `stell_getShards` response, because the advertised number is not a
  capacity.
- One rule, one source of truth (`sharding::route_shard`): the RPC layer
  (`stell_estimateFee`, `stell_runGetMethod`), the SVM's cross-shard routing
  and the topology itself all resolve addresses through it.

**Honesty note.** The split/merge state machine, the trie migration and the
routing rule are exercised by an **integration test over a synthetic account
set** (`tests/sharding_topology_tests.rs`). A **live-network split has not
been performed**, and shipping migrated state between nodes is not
implemented. See `docs/SHARDING.md` §0 for the full demonstrated-vs-designed
table.

---

## 4c. The failure fee (F-01)

A failed transaction is **not free**. The fee policy is a three-case rule, and
it is the same on the single-transaction path and on the block path
(`state_engine::failure_fee_state` and `apply_failure_fee_to_map`):

| case | pays | nonce |
| --- | --- | --- |
| **Refused at admission** (bad signature, wrong nonce, cannot cover `amount + gas_limit`) | nothing — it never ran | unchanged |
| **Replay or nonce gap** (the nonce does not match the account) | nothing — **not attributable** | unchanged |
| **Attributable failure the sender CAN cover** (a reverting payload, a live session-gate refusal, an unaffordable amount) | the **failure fee**: `max(gas_limit, consensus floor) + surcharge` | **advanced by one** |
| **Attributable failure the sender CANNOT cover** | **nothing moves at all** — no fee, no nonce, no state change | unchanged |

**I14 - A failed transaction pays and advances its nonce.** The failure is
recorded by the D2 mirror (the status flag), which is what prices the sender's
next attempt. Advancing the nonce is what makes the failure non-replayable: a
transaction that failed and was refunded can be resubmitted with the same nonce
and fail again, and a payload that mutates shared state before failing could
be replayed for free.

**I15 - The grief rule: no pay, no state change.** A partial charge ("pay what
you can") would consume the sender's remaining dust for a transaction they
could not have known would fail — and it would do so free of any
consideration, because a transaction whose fee they cannot cover was never going
to run. A burned nonce on a failure the sender could not have prevented is a
way to make their **next** transaction impossible. So the atomic rule holds:
an unaffordable failure moves **nothing**.

The floor is the **consensus** floor, not a node-local one: `consensus_floor_parts`
returns the governed base plus the engine's D2 penalty snapshot, and admission
(`Mempool::effective_floor_for_tx`) uses the same helper, so the two cannot
drift. The proposal validator refuses a block whose transactions declare less
than the floor (`check_consensus_fee_floor`), so a Byzantine proposer cannot
build a block of underpriced work.

The receipts file both numbers: `gas_limit` (what was offered) and
`fee_charged` (what was actually debited — 0 for a failure that is not
attributable).

---

## 4d. Cross-shard atomic commit: the two-phase commit (2PC)

The full specification — the state diagram, the failure and recovery rules,
the activation switch and the residual gap — is in
[`docs/SHARDING.md` §6](docs/SHARDING.md). In short:

- The legacy cross-shard flow (outbox → inbox → ack → timeout bounce) is a
  **one-way** pipeline whose DECISION is taken unilaterally by the source
  shard. The target credits the recipient *before* the source learns that it
  did, and the source may bounce the same transfer after
  `CROSS_SHARD_TIMEOUT_HEIGHTS = 64`. A malicious source shard could
  therefore observe the credit and then bounce: **a cross-shard double
  spend**. The design was safe only while the source shard was honest.
- From the activation height on, a NEW transfer runs a **genuine two-phase
  commit**:

```text
  SOURCE S                                   TARGET T
  ─────────────────────────────────────────────────────────────────
  commit PREPARE  (the value is ESCROWED)  ──▶  validate the source's
                                                 inclusion proof, record
                                                 PREPARED, vote YES
                              ◀── PREPARE-ACK  (the target's vote, proven
                                                against the target's
                                                committed state)
  commit COMMIT   (the escrow is RELEASED) ──▶  record COMMITTED and
                                                CREDIT the recipient
```

  and the abort path is **two-sided**:

```text
  commit ABORT-REQUEST (after the prepare window) ──▶  the target has NOT
                                                         prepared -> record
                                                         ABORTED (no credit)
                              ◀── ABORT-ACK  (the target's authorisation,
                                                proven against the target's
                                                committed state)
  commit ABORTED   (the escrow is REFUNDED)
```

- The **PREPARE is re-published while the source waits** for the vote (one
  height after the prepare, then every `XPC_REPREPARE_INTERVAL = 8` heights).
  The opening PREPARE travels with the block that escrows the value and
  proves the SENDER's account leaf; the re-published one proves the source's
  own PREPARED leaf (the escrow). A transfer whose opening PREPARE never
  arrived therefore still completes instead of waiting for the whole prepare
  window.
- The **validators check every 2PC record before they vote**: the opening
  PREPARE must name a transaction that is in the block and prove the
  sender's leaf; the re-published PREPARE must be backed by this shard's
  PREPARED record and prove that leaf; the vote, the decision and the abort
  authorisation must each prove the peer's committed 2PC state, anchored to
  a finalized header of the peer shard. A proposer that invents a vote the
  shard never made is refused.
- The `trusted` shortcut (a locally-produced message that skips the
  inclusion proof) is **ignored** for every 2PC record, exactly like the
  legacy transfer's strict inclusion check does: a 2PC control record moves
  value, so its proof is always checked.

- **The decision is atomic and unambiguous** because the state machine is
  monotone (`Prepared → Committed | Aborted`, decided once, by the shard
  that owns the record) and because the two sides cannot contradict each
  other:
  - the target **never credits on a bare transfer** — it credits only on a
    COMMIT that is proven against the source's committed state, and only if
    the target is itself already PREPARED;
  - the target **never aborts a transfer it has prepared** (a 2PC
    participant that voted YES must commit), so its ABORTED record *proves*
    it never prepared;
  - the source **may only abort with the target's authorisation**, and the
    target can never give one for a transfer it prepared. **This is the
    block on the audit's double spend.**
- The **peer's vote is unforgeable**: every 2PC control record carries a
  Merkle inclusion proof of the peer's 2PC state leaf
  (`sha256("XSHARD2PC" ‖ tx_hash)` → `phase ‖ tx_hash`) at the peer's
  committed state root, and that root is anchored (C1) to a **locally
  finalized header of the peer's shard**. A malicious source shard cannot
  forge a target's ABORT-ACK: it would need the target's quorum to have
  committed an ABORTED record that the target - having voted YES - never
  writes.
- The state machine is **recoverable**: the intermediate states are committed
  (the `XSHARD_2PC_V1` commitment domain, the state trie leaves and the
  persisted replay snapshot - the 2PC records travel in the cross-shard
  replay blob, so a restart restores the record AND its state-trie leaf),
  so a node that crashes mid-2PC resumes from the committed record and
  reaches the **same** decision. The outbound records (the vote, the
  decision, the abort request, the re-published PREPARE) are **derived from
  the committed state**, not from an in-memory message, so they are
  re-emitted after a crash.
- The **activation switch** is a chain-height boundary:
  `STELL_XPC_ACTIVATION_HEIGHT=<h>` (or
  `xshard2pc::XpcActivation::FromHeight(h)`) makes every transfer PRODUCED
  at height `h` or later run the 2PC. Transfers produced before `h` keep
  running the legacy flow to completion, so the two protocols never
  interleave on one transfer and the already-deployed chain state keeps
  working. The default is **off** (legacy), because the height is
  consensus-visible: every node of a shard must be configured with the same
  value.
- **The liveness cost is deliberate**: a transfer whose target shard is
  unreachable stays ESCROWED (neither credited nor refunded) until the target
  answers. That is the price of not letting the source decide unilaterally,
  and it is the same trade-off every 2PC makes.

---

## 5. Consensus-visible block commitments

Two commitments ride **inside the block body**, so they are covered by
`Block::compute_hash` and therefore signed by the BFT quorum that decides the
block. Both are **conditional** (mixed in only when non-empty), so every block
hash that predates them stays byte-for-byte identical.

### 5.1 The shard-header commitment (TON `shard_hashes`)

A **masterchain** block commits to the latest finalized header of every
**workchain** shard: which shard, at which height, which block hash, which
state root and when.

```text
ShardHeaderCommitment {
    shard_id   : u32   BE   // never the masterchain itself
    height     : u64   BE
    block_hash : [u8; 32]
    state_root : [u8; 32]
    timestamp  : u64   BE
}
```

The set is mixed into the block hash under the tag **`SHARDHDR`**, length
prefixed, in **ascending shard-id order**. Every field is fixed-width and
big-endian, so the field boundaries are unambiguous and no two different heads
can produce the same preimage.

Why it matters: a validator can prove *"shard 1 was at height 42 with THIS
state root"* from a single masterchain block, without ever having seen the
source shard's chain. That is what makes cross-shard proofs possible — an
inbound message's `source_state_root` is checked against the **committed** shard
head instead of against a locally trusted root.

**I16 - Only a masterchain block publishes shard heads, and the set is
canonical.** A workchain block that carries shard heads is refused; the set must
have strictly ascending shard ids, no duplicates, and no entry for the
masterchain itself (a block cannot commit to its own head). The order matters
because the set is hashed as a **sequence**: two byte orders of the same set
would be two different block hashes, and a proposer could equivocate with them.

**I17 - The commitment must not contradict this node's own finalized headers.**
If we finalized shard S at height H with hash X, a proposal committing shard S
at height H with a different hash or root is refused — that is a shard-chain
equivocation dressed up as a commitment. A node that has not finalized that
shard yet has nothing to contradict, so the proposal is accepted; the commitment
is still checked by the quorum that signs the block.

### 5.2 The transaction-order commitment

A block carries the **order Merkle root** over its own transaction list, in
execution order (`mev::compute_order_merkle_root`: the transaction hashes in
order, folded into a Merkle root; the all-zero root for an empty block).

The root is mixed into the block hash under the tag **`ORDROOT1`**, so the BFT
quorum that votes for the block hash votes for the **ordering** too. A
proposer that reorders the body after the votes changes the hash, and every
validator re-computes the root from the proposed body and **refuses** the
proposal when it does not match.

**I18 - The order commitment is enforced, not advisory.** `check_order_commitment`
is a pure function of the block body alone (no state, no clock, no node-local
key), so the proposer and every validator derive the SAME verdict from the SAME
body. It is a hard rule: a block whose order root does not match its body is
**refused, not warned about**, and every validator must run it before it votes
(coordinated rollout).

The node-local `order_commits` map (`commit_block_order` / `verify_block_order`)
is kept as an **optimisation and extra evidence** — the consensus check is the
authority. Mutating a pooled transaction between admission and build, or
executing an order this node never committed, is refused.

*What is still open:* the ORDER commitment does not hide the transaction
CONTENT. That is the job of the epoch seal (§5.3).

### 5.3 The epoch-key commitment (the MEV epoch key)

A block carries the **commitment to the MEV epoch key** of its epoch:

```text
epoch_key_commitment = BLAKE3(
    "STELL_MEV_EPOCH_KEY_COM_V1" ‖
    epoch (u64 BE) ‖ epoch public key (32B) ‖ committee hash (32B) ‖
    threshold (u64 BE)
)
```

It is mixed into the block hash under the tag **`EPKEYC01`**, and only when
it is non-zero (a block whose epoch has no key, and every block that
predates the field, keep their pre-existing hash byte-for-byte).

**I19 - The chain decides which epoch key the network uses.** The epoch key
is the aggregate of the epoch committee's DKG contributions. A wallet (or a
light client) takes the key from a full node and checks the commitment
against the chain: a node that hands out a key the chain never committed to
is caught. A node whose OWN key differs from the committed one has DIVERGED
(a different validator view at the epoch boundary) and then stops releasing
decryption partials — its shares would reconstruct a different shared point,
and the ciphertext would not authenticate for anybody.

The epoch seal itself (the asymmetric sealing, the sealed gossip, the share
release, the timeout path) is specified in `docs/MEV.md`, together with the
honest statement of what it does and does not protect against.

---

### 5.4 Archive proofs and historical roots

`stell_getProof` answers for the CURRENT state only. Two arms answer for
HISTORY:

```text
stell_getArchiveProof   { address, key?, height }  -> { height, state_root,
                                                         key, value|null,
                                                         proof, proof_type }
stell_getHistoricalRoot { height }                 -> { height, state_root,
                                                       anchor_height, anchor_hash,
                                                       prev_hash, cert,
                                                       finalized: true }
```

An archive proof is `{ height, state_root, key, value_or_absence,
proof_nodes }` where `proof_nodes` is the canonical `cpat2` hex-node list
(leaf first) and `value_or_absence` is the proven leaf value (`None` for an
exclusion proof). It verifies with `cpat2::ArchiveProof::verify` against
the HISTORICAL root — a root the node no longer holds in memory. The root
itself is authenticated by `stell_getHistoricalRoot`: the post-`height`
state root together with the precommit QC on the anchoring block
(`height + 1`; a header commits to the state BEFORE its own block). The
client verifies the QC against its OWN validator set
(`Checkpoint::from_historical_root_json` + `Checkpoint::verify`,
then `LightClient::advance_to_checkpoint` and `verify_archive_proof`).
A proof against an untrusted root proves nothing, so the two arms are one
unit: the proof and its anchor.

The archive node serves the proof from its PERSISTED SNAPSHOT HISTORY
(the `state` / `domains` / aux-domain trees), never from the live trie:
the live trie has moved on and rewinding it would fork a validating node.
The rebuild runs in a throwaway engine, the recomputed root is checked
against the finalized header anchoring it, and only then is the proof
generated (`Storage::serve_archive_proof`, `Storage::historical_root`).
The live trie is untouched.

**Proof granularity ("slots").** Directly provable, inclusion AND
exclusion, one trie leaf each: the native account leaf (`address`), the
STS balance cell (`sha256("STS_BAL" ‖ token_id ‖ account)`), the STS
supply cell (`sha256("STS_SUPPLY" ‖ token_id)`), the contract code hash
(`sha256("STELL_CONTRACT_CODE" ‖ addr)`), the contract ABI manifest
(`sha256("STELL_CONTRACT_ABI" ‖ addr)`), and the consensus-commitment
digest leaf (which proves the digest, never a single entry inside it).
Everything folded into that digest — the staking ledger, order books and
escrow, the PMM state, contract STORAGE, governance, oracle feeds,
session keys, the bridge queue, the shielded ledger, zkML registries,
cross-shard replay — has NO per-key proof. Making those provable means
committing each entry under its own namespaced trie key instead of one
digest: a consensus format change, deliberately not done here.

**Retention rule (explicit and bounded).** Snapshots are taken every
`STELL_SNAPSHOT_INTERVAL` heights (default 1000, minimum 50). ARCHIVE mode (`STELL_ARCHIVE=1`, the default) never prunes block
bodies, state snapshots, domain snapshots or aux-domain snapshots: it
serves archive proofs and historical roots for EVERY snapshot height it
ever took, at the explicit, unbounded cost of roughly one full state +
domain snapshot per interval, forever. PRUNE mode (`STELL_ARCHIVE=0` +
`STELL_KEEP_BLOCKS=<n>`, default 50 000) keeps the last `keep_blocks`
bodies, all header records, the last three snapshot intervals of
state/domain/aux snapshots, and the last 512 quorum-certified headers in
memory: it serves archive proofs ONLY for retained snapshot heights and
historical roots ONLY while the anchoring body's QC is retained. Anything
older — and any unknown height, any height above the tip, any height the
node cannot anchor — is refused with a `-32004` error, never fabricated,
never an empty answer. Serving history costs MORE retained data in
archive mode and an honest refusal in prune mode; pruning itself is not
weakened either way.

---

## 6. Sortition, the µQC and the network-anchored quorum

The **µQC** (post-quantum micro-certificate) is the fast finality path: a
small, stake-weighted sample of the validator set signs a block, so a block
finalises in milliseconds instead of waiting for a full 100-signature Ed25519
certificate.

### 6.1 The committee

`derive_sortition_committee(validators, height, round, committee_size, prev_block_hash)`
picks the committee: a subset weighted **proportionally to voting power**,
drawn without replacement, returned in canonical sorted order.

The committee size is `min(N, MICRO_COMMITTEE_MAX_SIZE)` with
**`MICRO_COMMITTEE_MAX_SIZE = 64`**. It is deliberately *not* a constant
smaller than the cap: with a fixed 16-seat committee and N = 100 uniformly
staked validators, the committee holds only ~16 % of the network's stake, so a
µQC could be forged by an attacker holding ~11 % — a ~6× weakening of the
network's own 2/3 threshold. At 64 seats and N = 100 the committee holds ~64 %
of the stake, and the network-anchored quorum (§6.3) then demands a strict
majority of the *network's* stake.

### 6.2 The parent-hash-seeded draw

The draw is seeded with the **parent block hash** — the hash of the block at
`height - 1`, i.e. the `prev_hash` committed in the header of the block at
`height`:

```text
seed   = BLAKE3("STELL_SORTITION_V5" ‖ prev_block_hash ‖ height ‖ round)
ticket = BLAKE3("STELL_SORTITION_V5" ‖ seed ‖ step)          // step = 0, 1, 2, …
```

The domain was bumped `STELL_SORTITION_V4` → `STELL_SORTITION_V5` when the
parent hash entered the preimage, so a v5 draw can never be confused with a v4
one.

Without the parent hash the ticket for `(height, round, step)` was a pure
function of the height and the round, so anybody could compute the committee
for every future height ahead of time and aim a DDoS (or a collusion) at a
chosen round. With the parent hash in the preimage the committee of a height is
only knowable once its parent exists, and it changes completely if the parent
changes — **a fork re-elects a different committee**.

**I19 - Every validator of a height must pass the SAME parent hash**, the one
committed in the block header, or they elect different committees and cannot
agree on a certificate. The parent hash therefore travels **with the
certificate** (`PqMicroCertificate::sortition_parent`), so a verifier
re-derives exactly the committee the builders used.

**Residual risk, stated plainly: the parent hash is not unforgeable.** The
proposer of the parent block chooses the parent's bytes, hence its hash, hence
the committee of the next height. A proposer that can vary the parent hash (a
nonce, a timestamp, the tx set) can **search** for a favourable committee: each
candidate parent hash is a fresh 16-draw sortition, and BLAKE3 is cheap enough
(10⁹+ draws/s on a GPU) that a capture is a matter of minutes for an attacker
who controls a meaningful share of the set.

Grinding can only pick **which** honest validators are asked to sign; it cannot
manufacture the stake the certificate needs — that is what the network-anchored
quorum is for. A VRF-based (ungrindable) selection would remove the grinding
surface entirely; that is the structural fix and is out of scope here.

### 6.3 The network-anchored quorum

```text
required = max( floor(2 × W_committee / 3) + 1,      // the committee's own 2/3
                 floor(W_network  / 2) + 1 )          // a STRICT MAJORITY of the network
```

`pq_micro_required_power(committee_total_power, network_total_power)`.

- The **first** term is the committee's own two-thirds, the classical BFT
  accounting applied to the sample.
- The **second** term is what makes a µQC safe to accept as a **finality**
  certificate on its own: `floor(W_network/2) + 1` is a strict majority of the
  WHOLE network's stake, so any two conflicting certificates (µQC or full QC)
  must share at least one signer — the classic quorum-intersection property
  that a 16-seat committee's `2/3 of the committee` does **not** have (2/3 of a
  16 %-of-the-network sample is ~11 % of the network: no intersection, and an
  attacker with 11 % of the stake can finalise a conflicting block).
- A committee that cannot reach the network anchor (a small committee of a large
  network) is **refused outright** rather than silently accepted at a weakened
  threshold. The µQC is only an *accelerator*: the full Ed25519 QC path stays
  authoritative, so refusing a µQC costs bandwidth, never liveness.

**I20 - A µQC must carry a strict majority of the whole network's stake.** The
verifier sums the powers of the committee members with valid signatures and
requires `>= required`. An empty committee or a zero-power committee is
`false` (fail-closed), mirroring `ValidatorSet::quorum_power`'s `u64::MAX`
guard for the empty set.

**Compatibility:** while `N <= MICRO_COMMITTEE_MAX_SIZE` the committee **is**
the whole validator set (the live N = 4 configuration), so the two terms
coincide with the old `floor(2W/3)+1` rule and historic certificates verify
byte-for-byte unchanged. The two-tier finality is then indistinguishable from a
single-tier one.

### 6.4 The epoch-MMR root (V5 Tier-2, shipped)

The V5 spec promises a Merkle-Mountain-Range epoch root every 128 blocks
("Tier 2: the full validator set signs the MMR epoch root"). That structure
now exists (`src/mmr.rs`); Tier-2 finality itself still runs on precommit-QC
checkpoints, exactly as before.

```text
epoch e covers heights [e*128, e*128+127]
first masterchain block of epoch E (height E*128, E > 0)
    commits mmr_epoch_root = MMR(block_hash[e*128-128 .. e*128-1])
```

*What it proves.* Inclusion of a finalized block hash under the epoch root:
"height H of epoch E is part of the finalized chain". A bridge or a
cross-chain transfer anchors on ONE 32-byte root per epoch instead of 128
individual checkpoints (`stell_getEpochRoot { epoch | height }` serves
`{epoch, start_height, end_height, mmr_root, peaks}`; `light_client` verifies
inclusion proofs against the answer). Committing the *previous* epoch keeps
the commitment non-circular: a block never commits to a root that includes
its own hash.

*What still relies on QC checkpoints.* Everything about finality: the MMR
root is an inclusion commitment *under* finality, not a finality mechanism.
A root is only as trustworthy as the quorum signatures over the block hash
that carries it — a light client must recompute the boundary block's hash,
verify its QC against an OUT-OF-BAND validator set, check the committed root
against the RPC answer, and only then verify proofs. Finality evidence stays
the precommit QC (`precommit_qc`, `stell_getFinalizedCheckpoint`, sync).

*Consensus rules.* Only the first masterchain block of an epoch may carry a
non-zero root (a workchain block or a non-boundary height with one is
refused); a zero root ("not committed") is always valid — a proposer that
does not know the epoch's 128 bodies (pruned, freshly restarted) commits to
nothing rather than to a root it cannot prove. A validator that knows the
epoch recomputes the root and refuses a mismatch; a validator that does not
know it yet accepts (the quorum that signs the block is the backstop) —
the same contradict-if-able rule as the shard-head commitments (§5.1).

*Compatibility.* The field is the LAST one of the block, decoded tolerantly
on the store path, and mixed into the block hash ONLY when non-zero — every
pre-existing block keeps its hash byte-for-byte, and a boundary block with a
zero root hashes exactly like a legacy block. Mixed-version gossip fails
closed (the wire path is strict), so non-zero roots begin only after a
coordinated all-validators upgrade — the same rollout rule as the order
commitment and the sortition schedule. See `Block::mmr_epoch_root` for the
full argument.

---

## 7. Known gaps

These are real and deliberately not yet addressed. They are listed so an auditor
does not have to rediscover them.

- **Archive state is committed per key for trie-resident slots, served from
  snapshots.** `stell_getArchiveProof` proves what a trie key held at a
  historical height from the persisted snapshot history (§5.4), and
  `stell_getHistoricalRoot` authenticates that height's root with the
  anchoring block's QC. What is still digest-only: every domain folded
  into the consensus commitment (staking entries, orderbook levels, ...).
  Per-entry keys for those would be needed for that — see §5.4.
- **Restoring from a snapshot does not rebuild the commitment.** A restored
  engine commits on the next root read, but a snapshot taken before this change
  carries no commitment key and the first read folds the in-memory state in.
- **The light client does not fetch the chain itself.** Since audit wave
  W8.3 the light client is LIVE and WIRED IN: the node keeps one anchored at
  its own quorum-certified finalized head and checks every peer-supplied
  block against it (`sync::verify_synced_blocks_against_anchor`), the node
  serves its quorum-certified headers (`stell_getFinalizedHeader`,
  `stell_getFinalizedCheckpoint`), and `stellereum light-client --from <rpc>
  --verify <account> --validators <file>` is an external verifier that checks
  a proof against a root a QUORUM committed to. What it still does NOT do is
  fetch the chain by itself: the transport is the caller's problem, the
  validator set is the entire trust anchor, and there is no validator-set
  rotation story (a client that cannot update its set cannot follow a
  rotation).
- **Ed25519 votes, not BLS.** 100+ validators means 100+ signatures per
  certificate. (The BLS12-381 envelope exists and is opt-in; the deployed chain
  still uses the Ed25519 certificate — see the security posture below.)
- **The commitment is recomputed per root read.** O(state) per block. Correct
  first, optimisable later.
- **The sortition is grindable.** The parent hash makes the committee
  *unknowable in advance* but not *unforgeable*: a proposer can search for a
  favourable parent hash (§6.2). The network-anchored quorum is what keeps the
  bar high; a VRF-based selection is the structural fix and is out of scope.
- **No live-network shard split.** The split/merge state machine, the trie
  migration and the address→shard rule are exercised over a synthetic
  account set in-process, but no split has been driven by a live consensus
  event, and shipping migrated state between nodes is not implemented. See
  `docs/SHARDING.md` §0.
- **The cross-shard commitment is not per-shard.** The `XSHARD_REPLAY_V1`
  domain commits the replay sets of the whole process, so two shards of one
  process share one root rather than one root each.

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
| **No atomic cross-shard commit**: the source shard decided alone (ack/bounce), so a Byzantine source could observe the target's credit and then bounce the same transfer — a cross-shard double spend | §4d: a genuine two-phase commit (prepare / vote / commit) with a monotone, committed state machine, a proof-carrying vote anchored to the peer's finalized header, and a two-sided abort (the target must authorise it, and never does for a transfer it prepared) | `tests/xshard_2pc_tests.rs` (`a_byzantine_source_cannot_bounce_after_a_successful_prepare`, `a_byzantine_target_that_acks_and_then_refuses_to_credit_does_not_double_spend`, the two crash-recovery tests, the replay test, `a_two_validator_shard_accepts_the_2pc_records`, `a_lost_prepare_is_re_published_and_the_transfer_still_completes`, `the_activation_boundary_switches_the_protocol`, `the_2pc_state_is_committed_in_the_digest_and_the_snapshot`), `xshard2pc` unit tests |
| A cross-shard transfer produced after a state-changing parent block could never be anchored, so the target silently never consumed it | the anchor map holds the POST-APPLY root of a finalized block (the root a message's proof is made against), not the block's declared pre-state root | `cross_shard_anchor_tests`, the height-2 transfer in `xshard_2pc_tests` |

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

## Security posture (updated, the large remediation wave)

### Newly closed

| Finding | Fix | Where |
| --- | --- | --- |
| A vote or a block signed on one deployment verified on another | the chain id is in both preimages (`STELLEREUM_BFT_VOTE_V2`, `STELLEREUM_BLOCK_V3`) and frozen once per process | §2a, `consensus::consensus_chain_id` |
| The sortition committee of a future height was computable in advance | the draw is seeded with the parent block hash (`STELL_SORTITION_V5`) | §6.2, `consensus::sortition_seed` |
| A 16-seat µQC could be forged with ~11 % of the network's stake | the committee cap is 64 (`MICRO_COMMITTEE_MAX_SIZE`) and the threshold is **network-anchored**: `max(2/3 of the committee, a strict majority of the network)` | §6.1, §6.3, `consensus::pq_micro_required_power` |
| A masterchain block did not commit to the workchain shard heads | `Block::shard_headers`, mixed into the block hash under `SHARDHDR`; only a masterchain block may publish them, and the set must be canonical | §5.1 |
| A proposer could reorder a block after the votes | `Block::order_merkle_root`, mixed into the block hash under `ORDROOT1`; every validator re-computes and refuses a mismatch | §5.2 |
| The delegator payout formula was not committed | the lazy (F1) reward accumulator and the per-pair checkpoints are committed under `STAKING_REWARD_ACC_V1` | §1.4 |
| A failed transaction was free and replayable | the F-01 failure fee: an attributable failure pays the floor and advances the nonce; an unaffordable failure moves nothing | §4c |
| `stell_executeProposal` applied a passed proposal (including a binary upgrade) with no token | the same constant-time token gate as `stell_submitProposal` / `stell_vote` | `docs/RPC.md` §6 |
| `stell_estimateFee` could burn the whole contract fuel ceiling on an unauthenticated read | its own per-IP budget (5/s, `STELL_ESTIMATE_FEE_RATE_LIMIT`) and a 5,000,000 gas ceiling | `docs/RPC.md` §8 |
| `stell_getEvents` could answer with millions of events | the answer is capped at 1000 (`MAX_EVENTS_RETURNED`) | `docs/RPC.md` §8 |
| One client could take the whole subscription registry | a per-client cap of 64 (`MAX_SUBSCRIPTIONS_PER_CLIENT`) next to the global 4096 | `docs/RPC.md` §11 |
| A governance upgrade plan could point the exec at an arbitrary path | the plan's `name` must be a safe path segment; the binary is staged and hashed before the exec | `docs/OPERATIONS.md` §12 |
| Node private keys were written in plaintext | encrypted at rest by default (`enc2:` Argon2id + XChaCha20-Poly1305) | `docs/OPERATIONS.md` §11 |
| A pre-FIPS-206 Falcon key was an incomplete NTRU key | legacy keys still load and the address is unchanged; `stellereum keys rotate-falcon` mints a complete FN-DSA key | `docs/OPERATIONS.md` §11.1 |

### Open, documented

- The **examples and benches build** (`cargo build --examples --benches`
  exits 0, re-verified this run; only warnings). The earlier note that they
  did not compile against the current `Block` is stale: the struct-literal
  sites were completed with the neutral defaults.
- There are **no pre-existing failures**: the library suite and every
  integration binary are green (see Test counts below). The earlier 65
  bridge-dispute / reward-split failures were resolved by the F1
  lazy-reward-accumulator test updates of the previous wave.

### Test counts (measured on this tree)

| suite | command | result |
| --- | --- | --- |
| library | `cargo test --lib` | **970 passed, 0 failed** (2026-10-25, re-verified this run) |
| integration | `cargo test --tests --no-fail-fast` | **2801 passed, 0 failed across 213 binaries** (2026-10-25 — the tree had moved since the 2762/0 pass: a new `Block::mmr_epoch_root` field left 39 struct literals uncompilable, completed here with the neutral `[0u8; 32]` that preserves the legacy hash byte-for-byte, plus one ordering fix in the new MMR `prove()` so the sibling path is leaf-first as the module docs and `verify` require; no consensus/execution/storage semantics changed) |

Verify with
`cargo test --lib --tests --no-fail-fast 2>&1 | grep -E '^test result:'` and
sum the `passed` numbers.
