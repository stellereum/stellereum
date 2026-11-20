# Gov Block-Carried Design (C-01 full fix)

Status: **IMPLEMENTED and ACTIVE from genesis**
(`GOV_OPS_ACTIVATION_HEIGHT = 0`, `stellereum/src/governance.rs:151`). This
document retains the original design rationale; the implementation differs in
two places: only **two** carrier opcodes exist (`SysCallGovPropose` /
`SysCallGovVote`), and finalize/execute run in the deterministic block sweep
(`apply_governance_transition`), not as separate opcodes. `SoftwareUpgrade` /
`CancelUpgrade` execution still requires the separate
`UPGRADE_EXEC_ACTIVATION_HEIGHT` gate (`governance.rs:80`, `u64::MAX`).

All section references were verified against
`stellereum/src/{governance,svm,mempool,state_engine,staking,pq_registry,rpc,consensus_net}.rs`.

## 0. Problem

`stell_submitProposal` / `stell_vote` / `stell_executeProposal` mutate
`Governance` + `StakingLedger` via RPC-direct writes (`rpc.rs:6085-6206`,
`gov_write`). On multi-node chains each node's RPC mutates only local state:
same quorum decision lands differently per node → state-root fork (C-01).
Single-node dev never sees it. Fix: gov operations ride block bodies as SVM
`OpCode`s; the RPC path becomes a tx-builder and is sunset.

Precedent checked: `OpCode` is APPEND-only (bincode discriminant pinning;
comment on every variant since `SysCallSubmitPriceFeed`, `svm.rs:570-574`).
Next free variants append after `SysCallStakeWithCommission` (`svm.rs:1107`).
Old nodes fail closed on unknown discriminants. Enum IS extensible.

Precedent checked (carrier shape): `SysCallReportEquivocation`
(`svm.rs:995`) is a PURE CARRIER + block-step scan at
`apply_block_transition` step 5b (`state_engine.rs:6758-6766`); the PQ twin
slashes in-VM on a clone-committed ledger (`svm.rs:1007-1015`). Gov follows
the in-VM clone-commit shape (like `SysCallStake`), NOT a new block step —
see §3 for why.

Precedent checked (hooks): `pq_registry.rs:27-40` chose staking-hook calls
over a new tx type FOR THE REGISTRY MATH ONLY, with auth left to the future
opcode handler (`rotate_key` precedent: handler authenticates
`ctx.sender`, hook takes the id as authenticated caller). Gov is the
inverse case: the state machine already exists (`governance.rs`), what is
missing is the authenticated transport. So: NEW opcodes whose handlers
authenticate (`ctx.sender`) and call the existing `Governance` methods —
no new hook layer, no `Governance` API change.

## 1. New OpCodes (append after `SysCallStakeWithCommission`, never insert)

Byte layout: bincode enum discriminant (next sequential u32, assigned at
implementation; do NOT hand-pick numbers in this doc) + bincode fields.
`GovAction` and `VoteChoice` reuse their existing serde shapes (already the
committed forms; `GovAction` append-only per `governance.rs:156-159`).
Domain separation: (a) tx signature preimage already covers
`Transaction.payload` (existing rule, `svm.rs:692-699`); (b) chain-id
binding gate covers replay across chains (`chain_binding`, enforced in
mempool + apply); (c) tx nonce covers replay within chain; (d) sender is
`ctx.sender` (tx signer), NEVER an opcode field — no `proposer`/`voter`
address field exists to forge. Gov-level idempotence (`AlreadyVoted`,
proposer stake gate, execute-once) is the second layer, not the first.

Implemented carrier opcodes (SVM dispatch only charges gas and pushes; the
authoritative apply is the block scan — see §3):

- `SysCallGovPropose { proposal_id: u64, title: String, action: Box<GovAction>, height_observed: u64 }` — apply requires `proposal_id == governance.next_id` and `height_observed == block.height`, then runs `gov.propose(ledger, tx.from, title, action, block.timestamp)`.
- `SysCallGovVote { proposal_id: u64, choice: VoteChoice, height_observed: u64 }` — apply requires `height_observed == block.height`, then runs `gov.vote(ledger, tx.from, proposal_id, choice, block.timestamp)` (same one-vote/idempotent-replay semantics as the direct path).

There are **no** `SysCallGovFinalize` / `SysCallGovExecute` opcodes in the
shipped implementation. Finalize and execute are deterministic block steps:

- `Governance::finalize_due_at_height(ledger, block.timestamp, block.height)` finalizes every `Open` proposal whose voting window closed, in ascending id order.
- `Governance::execute_due_governance_at_height(block.height, chain_id, oracle)` executes every `Passed`, matured action in ascending id order, re-deriving authority from the committed tally. All 13 action types go through this sweep; `SoftwareUpgrade` / `CancelUpgrade` are included only when `upgrade_exec_active_at(height)` is also true.

Gas (new consts in `svm.rs`, anchored to existing table): propose =
`GAS_STAKE_BOND` scale (ledger scan + snapshot write, the most expensive);
vote/finalize/execute = `GAS_STAKE_CLAIM` scale (single map insert/update).
Exact numbers at implementation; rule: propose ≥ vote, all ≥ `GAS_BASIC_TRANSFER`.

`now`/`height` source: BOTH from the block (`block.timestamp`,
`block.height`), never wall-clock — the RPC path's `SystemTime::now`
(`rpc.rs:6116`) is the determinism bug being removed.

## 2. Mempool admission (no new mempool code path, two bounds added)

Unchanged (already sufficient): signature verify, chain-binding gate,
nonce-gap (`NONCE_FUTURE_WINDOW=4`), per-sender quota (1024), pool cap +
2×-bid auction eviction, balance `amount+gas_limit` coverage, base-fee
floor `max(frozen, governed)`, `TxTooLarge`/`TxTooManyProofs` wire caps,
D2 `failed_penalty` escalation, gossip ingress re-admission
(`main.rs:4326-4398`). Gov txs are ordinary txs here.

Added: (a) `Malformed` refusal when `title.len()>256` / `Signal>1024` /
upgrade-name unsafe (cheap static pre-check, mirrors propose-time rules so
junk never occupies pool slots); (b) per-proposer OPEN-proposal cap
(`MAX_OPEN_PROPOSALS_PER_PROPOSER=4`, counted over pooled + committed-open):
admission refuses the 5th concurrent open proposal with `TooManyFromSender`.

SPAM RULE (one line): keep the 10k-STELL stake gate, cap 4 open proposals
per proposer enforced at admission AND apply, require ≥ base-fee gas on
every gov tx, and explicitly impose NO slash-on-rejected deposit (rejected ≠
spam; slashing losers chills dissent and disagrees on no objective predicate).

Why this bounds the malicious-operator flood: each proposal needs 10k
staked (locked for the vote lifetime via G2 `lock_governance`, so flood
capital is encumbered, not free); pool quota + 2× eviction + wire caps bound
pool occupancy; D2 penalty makes failing-vote spam increasingly expensive;
the open-cap bounds committed-state growth (4×(256B+1KB) per proposer).
A slash deposit was considered and REJECTED: no deterministic spam predicate
exists (quorum-fail is not spam), and a slash needs a new fund-flow with its
own consensus risk for zero added bound over the cap+lock.

## 3. Block-apply order (deterministic, no new step)

No new step in `apply_block_transition` (`state_engine.rs:6611-6777`).
Gov ops apply INSIDE step 1 (tx payloads, block tx order, VM handlers on
clone-committed `Governance` + `StakingLedger` + oracle working copies;
commit iff the whole tx succeeds — the `SysCallStake` discipline). Order
within the transition is therefore: txs (incl. gov) → 1a XPC → 1b mailbox →
fees → reward → unbonding maturation → downtime slash → 5b equivocation.
Rejected alternative (dedicated finalize/execute sweep step): needs
iteration-order rules over `HashMap` proposals, auto-pays no gas, and fires
without a caller — tx-triggered permissionless finalize/execute is strictly
more deterministic and already matches `finalize_at_height`/`execute_at_height`
semantics.

Determinism notes (every step specified, no "then consensus happens"):
tx order is block bytes; `ctx.timestamp=block.timestamp`,
height=`block.height` for every gov handler; vote weights come from the
PROPOSE-time snapshot (`electorate_weights`, G1), so intra-block
bond/unbond/vote interleavings cannot move any tally or the quorum
denominator; finalize releases locks exactly once on the terminal transition
(existing `finalize_inner` idempotence: non-Open early-returns without
touching `timelocks`); execute checks `timelocks[id]` against the SAME
`block.height`; handler `Err` reverts ONLY its tx (fail-closed, fee still
collected in step 2 — same as every reverting syscall); reorg/replay
re-applies the same block bytes through the same function
(`apply_block_transition` is the shared core, `state_engine.rs:6552-6558).

## 4. Gossip transport: REUSE `stellereum/tx/v1/{epoch}`, no new topic

Gov ops are transactions; they ride the existing `TxGossip` path
(`consensus_net.rs:1844`, topic `tx_topic`, `TX_TOPIC_BASE`) with its
sig-check → mempool authoritative admission → per-sender quota → rate-limit
chain. Consensus-vote gossip (`stellereum/consensus/v1/{epoch}`) is a
DIFFERENT domain (prevote/precommit, not gov `VoteChoice`) and must not be
conflated. Justification: a new topic doubles subscribe/join/health code
paths and re-risks the observed 18-day wrong-topic isolation outage
(`main.rs:5297`, `liveness_alarm.rs:4`); epoch-scoping already namespaces
replays. No code change needed beyond gov txs being submittable via
`stell_sendRawTransaction` (already open, self-authenticating).

## 5. Migration (shipped)

The shipped activation is `GOV_OPS_ACTIVATION_HEIGHT = 0` (active from
genesis), not a delayed `GOV_BLOCK_CARRIED_ACTIVATION`; there is no
`STELL_GOV_DIRECT_OK`. The block form is primary:
`stell_submitProposal` / `stell_vote` accept a signed transaction carrying
`SysCallGovPropose` / `SysCallGovVote` and only admit it to the mempool. The
legacy direct-parameter RPC form still exists for single-node dev but is
refused on `validator_set.len() > 1`; `STELL_GOV_ALLOW_MULTINODE_WRITES=1`
remains the documented fork switch and should not be used on a real network.
Pre-activation committed state (open/passed proposals, locks, `timelocks`)
needs no migration — handlers operate on the same structs.

## 6. Lock/finalize/timelock state machine (exact, unchanged semantics, new callers)

States: `Open → Passed | Rejected` (deterministic finalize sweep), `Passed →
Executed` (deterministic execute sweep). Transitions: `propose` tx
(stake≥10k, title≤256B, `action.validate()`, freezes
`electorate`+`electorate_weights`, locks proposer own-stake via
`lock_governance`) → `Open`; `vote` tx (`now < voting_end`, one vote, weight
from snapshot, `lock_governance(weight)`) → tallies; `finalize_due_at_height`
(`now ≥ voting_end`; `turnout ≥ electorate*Q/10000 && yes>no && yes+no>0` →
`Passed` + `timelocks[id]=finalize_height+90_000`, else `Rejected`; BOTH
release proposer+voter locks exactly once) → terminal-pending;
`execute_due_governance_at_height` (`status==Passed && height ≥ maturity`, or
unscheduled-legacy `None`→immediate one-time migration; applies action
bounds again, oracle half atomically for oracle actions; sets `Executed`
only after all domain writes) → `Executed`. `rotate_key` refused while
`locked_governance>0` (existing). Finalize of non-Open / execute of
non-Passed are deterministic no-ops/failures that move nothing.

## 7. Test plan

- Unit (`governance.rs` + new opcode tests): every `GovAction` reachable via
propose-tx builder; title/signal/upgrade-name/quorum-floor bounds at BOTH
admission-precheck and handler; double-vote, zero-weight, early-finalize,
immature-execute, double-execute, unknown-proposal — all revert with the
exact current `GovError`.
- Snapshot/digest: `governance_digest` byte-identical for block-carried vs
legacy-direct final states (migration equivalence); electorate freeze +
G1 zero-weight-late-bond + G2 lock/release pinned through tx path.
- Mempool: 5th open proposal refused; oversize title refused `Malformed`;
D2 penalty escalation on failing gov spam; nonce-gap enforcement.
- Determinism: same block applied via finalize path AND reorg path
(`apply_block_transition` both callers) → identical roots; intra-block
bond→vote→finalize ordering test asserting tally invariance (G1 snapshot).
- Multi-node harness: proposal→vote→finalize→90_000-height wait→execute on a
3-node testnet incl. one node down mid-vote + resync; all roots equal;
equivocation-5b step unaffected (gov txs present in same blocks).
- Gate: `cargo clippy --all-targets -- -D warnings` + full `cargo test`
+ `consensus_liveness_harness` per AGENTS.md §4.

## REPORT

- `SysCallGovPropose { proposal_id, title, action, height_observed }` — sender-is-proposer, snapshot+lock at apply; id and height pinned.
- `SysCallGovVote { proposal_id, choice, height_observed }` — snapshot-weighted, one-vote, lock backing stake; height pinned.
- Deterministic finalize sweep — block timestamp/height, schedules `+90_000`, releases locks once, ascending id.
- Deterministic execute sweep — maturity-gated, oracle-atomic, exactly-once, ascending id; all 13 actions, with `SoftwareUpgrade`/`CancelUpgrade` gated by `UPGRADE_EXEC_ACTIVATION_HEIGHT`.
- SPAM RULE: 10k stake gate (locked, not slashed) + base-fee gas + D2 escalation; no slash-on-rejected. (The proposed per-proposer 4-open cap is not implemented in this wave.)
- MIGRATION: `GOV_OPS_ACTIVATION_HEIGHT = 0` from genesis; RPC direct form
stays solo-only; block form is the supported multi-node transport.
- OPEN QUESTIONS: (1) ratify `UPGRADE_EXEC_ACTIVATION_HEIGHT` and wire it
into `chain_spec`; (2) decide whether to add the per-proposer open-proposal
cap; (3) RPC tx-builder signing UX (server-side key vs client-signed
`sendRawTransaction` — latter preferred, needs wallet support); (4) oracle
actions already execute through the oracle working copy in
`execute_due_governance_at_height`; confirm that remains the only writer.
