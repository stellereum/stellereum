//! Consensus runtime: wires the BFT engine to block production, the mempool and
//! the state engine, and provides an in-process multi-validator Cluster.
//!
//! This is the integration layer between `consensus` (pure state machine) and
//! the rest of the node. The P2P transport that carries proposals/votes between
//! real nodes is layered on top of this (next stage).

use crate::consensus::{
    FalconKeypair, Height, HeightConsensus, Round, Step, ValidatorId, ValidatorSet, Vote, VoteKind,
};
#[cfg(any(test, debug_assertions))]
use crate::consensus::FalconKeypairExt;
use futures::FutureExt as _;
use crate::mempool::Mempool;
use crate::sharding::{
    Block, CrossShardKey, CrossShardMessage, ShardId, ShardRegistry, Transaction,
    MASTERCHAIN_SHARD,
};
use crate::state_engine::InMemoryStateEngine;
use ed25519_dalek::{Signer as _, SigningKey};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub type BlockHash = [u8; 32];

/// Hard cap on transactions per block (anti-DoS: a malicious proposer must not
/// be able to craft an unbounded block).
pub const MAX_BLOCK_TXS: usize = 10_000;
/// Upper bound on signers in a peer-supplied commit certificate. The validator
/// set is far smaller than this; anything larger is an attempt to make us run an
/// unbounded signature-verification loop.
pub const MAX_COMMIT_CERT_SIGNERS: usize = 4_096;

/// Gas cap per block (A11). Bounds block work independently of tx count.
///
/// Calibrated post fee-x500 (audit: blocks troubles): every tx declares at
/// least GAS_BASIC_TRANSFER (280k), so the old 30M fit ~107 plain transfers —
/// the pre-hike 1900-tx figure needed 532M and is retired. 120M fits ~428
/// plain transfers (or fewer heavy ones); serial apply (~26k native tx/s
/// in-process) clears that in ~16ms, and 428 minimal txs are ~49KB on the
/// wire (fat shielded blocks stay far under the 32MB proposal cap thanks to
/// the per-tx IO caps). Raise only with a fat-block sync measurement.
pub const MAX_BLOCK_GAS: u64 = 500_000_000;

/// Deterministic ceiling for a block timestamp ahead of its parent (seconds).
///
/// Bounds proposer clock skew WITHOUT any wall-clock read: the verdict is a
/// pure function of (parent, child), so two validators with different local
/// times derive the same answer from the same two blocks. One hour is generous
/// on purpose — honest proposers stamp seconds apart, and operational gaps and
/// catch-up produce ~1000s single-step jumps in this repo's own suites — while
/// still refusing absurd far-future stamps that would poison every
/// timestamp-driven rule (session expiry, unbonding maturity) for years.
pub const MAX_TIMESTAMP_JUMP_SECS: u64 = 3_600;

/// Near-future proposal phase-alignment window (rounds).
///
/// When a GENUINE proposal for this height arrives early for a near-future
/// round owned by the same proposer, we align to the earliest such round and
/// accept it there instead of rejecting it as "wrong proposer" (the vote that
/// would have synced us often arrives after the proposal it should precede).
/// Widened +4 -> +8 (audit MED 2026-10-14: the hash-slot schedule rejects
/// ~20% of genuine early proposals at +4; a wider scan strictly widens local
/// acceptance, never consensus — the body is signature-authenticated before
/// the scan, only the slot owner can pull us to their own slots, and the jump
/// still runs through `sync_round_to`'s caps/budget). Pinned by test below.
pub const PROPOSAL_ALIGN_WINDOW_ROUNDS: u32 = 8;

/// Deterministic genesis: credit EVERY validator in `validators` the same fixed
/// balance. The validator set is a `BTreeMap` (sorted), so every node with the
/// same config credits the same accounts in the same order and derives an
/// identical genesis state root.
pub async fn fund_genesis(
    engine: &InMemoryStateEngine,
    validators: &ValidatorSet,
    balance: u64,
) {
    for v in validators.validators.keys() {
        engine
            .update_account(crate::state_engine::AccountState::new(*v, balance))
            .await;
    }

    // Bond them in the staking ledger too, not just fund them.
    //
    // The validator set is re-derived from this ledger at every height
    // boundary, so funding an account without bonding it leaves the set empty.
    // An empty set has zero total power, and a zero-power set can reach quorum
    // with a single vote, so the node would finalise every block by itself and
    // the chain would look healthy while having no consensus in it at all.
    //
    // Both nodes must derive an identical ledger, so the bond amount and
    // commission are fixed constants rather than derived from anything local.
    let bond = GENESIS_VALIDATOR_BOND.min(balance);
    let mut ledger = engine.staking_write().await;
    for v in validators.validators.keys() {
        // A genesis validator can only appear once; a repeated id is a config
        // error and must not silently double-bond.
        if ledger.validators.contains_key(v) {
            continue;
        }
        // Never silent: a failed genesis bond leaves a funded-but-unbonded
        // validator and a thin/empty set (Finding-8 class). Loud on both
        // channels; control flow unchanged (tests intentionally probe thin
        // sets with tiny balances).
        if let Err(e) = ledger.bond_genesis(*v, bond, 0) {
            let msg = format!(
                "[genesis] WARN bond failed for {} (bond {bond}): {e} — validator funded but NOT bonded",
                hex::encode(&v[..6])
            );
            eprintln!("{msg}");
            tracing::error!("{msg}");
        } else {
            // SEC-ECON-01: Transfer bond from validator account to STAKING_POOL
            // so genesis stake is fully backed and STAKING_POOL is solvent.
            if std::env::var("STELL_LEGACY_GENESIS_ROOT").as_deref() != Ok("1") {
                let _ = engine.debit_native(v, bond).await;
                let _ = engine.credit_native(&crate::staking::STAKING_POOL, bond).await;
            }
        }
    }
}

/// Bond amount for a genesis validator: bare MIN (v1 genesis bytes —
/// `bond_genesis` reproduces the pinned root `61336779...` exactly).
/// The runtime MIN+buffer floor applies to NEW stakes, not to founding.
pub const GENESIS_VALIDATOR_BOND: u64 = crate::staking::MIN_VALIDATOR_BOND;

/// Genesis funding for a NON-masterchain shard.
///
/// Deliberately different from [`fund_genesis`]: it credits ONLY the supplied
/// dev/faucet account and never the validators. `fund_genesis` both funds and
/// bonds the validator set, and running it again on a second shard would
/// double-count validator balances and give that shard its own staking ledger.
/// A workchain instead keeps its staking ledger EMPTY, so
/// `ValidatorRuntime::refresh_validator_set_from_staking` falls back to the
/// config-defined validator set and both shards agree on one P2P namespace and
/// one validator schedule. Only the dev account may move value on that shard in
/// M1; cross-shard value flow is a later milestone.
pub async fn fund_shard_genesis(
    engine: &InMemoryStateEngine,
    dev_account: [u8; 32],
    balance: u64,
) {
    engine
        .update_account(crate::state_engine::AccountState::new(dev_account, balance))
        .await;
}

/// Build the height-0 block for a shard. Every shard roots its own chain at
/// `prev_hash == [0u8; 32]` with its own `state_root`; `shard_id` fixes the
/// block's identity so a shard-1 block can never validate as a shard-0 block.
pub fn shard_genesis_block(
    shard_id: ShardId,
    state_root: [u8; 32],
    proposer: [u8; 32],
    timestamp: u64,
) -> Block {
    Block {
        shard_id,
        height: 0,
        prev_hash: [0u8; 32],
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp,
        proposer,
        validator_signatures: vec![],
        precommit_qc: None,
    }
}

/// The reward a block pays its proposer: the governed value when governance
/// has set one, else the node's configured default.
///
/// The governed value wins when set: a passed `SetBlockReward` proposal must
/// actually change what the next produced block pays, or governance is
/// decorative and the commitment records a parameter nothing reads.
///
/// SHARED by both block-apply paths - `ValidatorRuntime::apply_block_fees_rewards`
/// (live consensus) and `ChainState::apply_block` (reorg) - so a re-applied
/// block cannot pay a different reward than the node that produced it did.
pub fn block_reward_for(gov: Option<&crate::governance::Governance>, default: u64) -> u64 {
    gov.and_then(|g| g.applied.block_reward).unwrap_or(default)
}

/// Static actor-mailbox load of one block: every `SysCallActorSend` its
/// transactions carry, counting nested bodies transitively.
///
/// A top-level send enqueues one message; when that message is delivered its
/// body runs, and every send inside THAT body enqueues another — so the total
/// number of messages this block's content can ever generate is the recursive
/// count, not just the top-level one. This is an UPPER bound on what delivery
/// will do (a reverted payload or a failed body delivers less, never more),
/// which is exactly what a fail-closed validation check needs: it never
/// executes, it only counts bytes already committed in the block.
///
/// Pure function of the block alone — no clock, no state — so the proposer
/// and every validator derive the same number.
pub fn count_block_actor_sends(block: &Block) -> usize {
    block
        .transactions
        .iter()
        .map(|t| count_program_sends(&t.payload))
        .fold(0usize, |acc, n| acc.saturating_add(n))
}

/// Recursive half of [`count_block_actor_sends`]: sends in one program plus
/// every send inside the bodies those sends carry.
fn count_program_sends(program: &[crate::svm::OpCode]) -> usize {
    program
        .iter()
        .map(|op| match op {
            crate::svm::OpCode::SysCallActorSend { body, .. } => {
                1usize.saturating_add(count_program_sends(body))
            }
            _ => 0,
        })
        .fold(0usize, |acc, n| acc.saturating_add(n))
}

/// Senders present in the live pool but missing from a snapshot taken
/// earlier: they were admitted while the snapshot's account reads were in
/// flight. Pure helper for the r0-fullness refresh in [`ValidatorRuntime::propose`].
pub fn missing_sender_accounts(
    snapshot: &std::collections::HashMap<[u8; 32], (u64, u64)>,
    pool_senders: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    pool_senders
        .iter()
        .copied()
        .filter(|s| !snapshot.contains_key(s))
        .collect()
}

/// Static half of the actor-mailbox cap check: a block whose OWN sends already
/// exceed the cap is rejected without reading any state. The backlog-inclusive
/// check lives in [`ValidatorRuntime::check_actor_cap`] (async, reads the
/// engine); both agree whenever the backlog is empty, which honest operation
/// maintains at every boundary.
fn block_actor_sends_exceed_cap(block: &Block) -> bool {
    count_block_actor_sends(block) > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
}

// ==================== §7 Phase 2: sequenced execution lane ====================
//
// `try_finalize` used to execute the decided block INLINE: the consensus tick
// awaited `apply_block_fees_rewards` → `apply_block_transition` to completion,
// so one slow apply stalled round timers, gossip handling and the next
// proposal. Phase 2 moves the WAITING off the tick without moving the work,
// the order or the bytes:
//
//   * `apply_decided` is the exact current finalize-apply sequence (reward
//     resolution → the shared `apply_block_transition` → the node-local
//     bookkeeping that cannot move the root). Every route that applies a
//     decided block — local finalize, sequenced submit, adopt/walk, replay —
//     funnels through the same transition and the same bookkeeping.
//   * Execution itself runs on ONE long-lived ordered worker ([`ApplyLane`]:
//     a single task, FIFO, never parallel, strictly in submission order).
//     Callers submit strictly height-ordered (enforced by the
//     `apply_in_flight` gates below), so the worker applies H before H+1.
//   * While the worker runs, the loop keeps draining inbound messages (votes
//     still count; they never read post-H state). Anything that WOULD read
//     post-H state — `propose` for the next height, the `on_proposal` root
//     check, `adopt_committed`, a second submit — refuses while
//     `apply_in_flight` is set. Nothing observing consensus (the `finalized`
//     list, the height advance, the commit broadcast, receipts) moves until
//     the worker reports back and the outcome is installed.
//
// What was deliberately NOT built (design P2a/P2b rejected, P2c skipped):
// speculative pre-execution of un-decided blocks (executing a proposal before
// its QC exists would make state a function of gossip order, and every node
// would certify a different root), and a side-effect-free staging cache keyed
// by block hash. The cache has no safe consumer: redelivery paths already
// short-circuit on height before executing, while reorg/replay MUST re-execute
// (restoring from a checkpoint or healing), so serving a cached outcome there
// would hide a divergence instead of reproducing it. No cache was added.

/// One execution job for the sequenced worker: the decided block plus the
/// already-resolved reward, so the worker never reads governance or consensus
/// state — only the engine it was spawned with and the bytes it was sent.
struct ApplyJob {
    block: Block,
    reward: u64,
    done: tokio::sync::oneshot::Sender<(
        crate::state_engine::BlockTransitionOutcome,
        [u8; 32],
    )>,
}

/// A quiescent state capture: every root-committed domain cloned at a FIFO
/// idle point (after the previous apply installed, before the next starts),
/// so the bytes can never mix heights. Cross-shard RUNTIME mirrors are NOT
/// included (they are transport-driven and deliberately uncommitted — their
/// raciness cannot move the root); the tick captures those separately.
pub struct SnapBundle {
    pub height: u64,
    pub accounts: Vec<crate::state_engine::AccountState>,
    pub domains: crate::storage::DomainSnapshot,
    pub session_keys: Vec<u8>,
    pub bridge: Vec<u8>,
    pub confidential: Vec<u8>,
    pub zkml_models: Vec<u8>,
}

/// Snapshot request/response on the sequenced lane (see `SnapBundle`).
/// `expected_root` is the worker-certified post-`height` root: the worker
/// captures ONLY if the live engine still roots there, so a snapshot labeled
/// H can never carry H+1 state no matter the queue order (mislabel is
/// impossible by construction, not by timing).
struct SnapshotJob {
    height: u64,
    expected_root: [u8; 32],
    done: tokio::sync::oneshot::Sender<Option<SnapBundle>>,
}

enum LaneJob {
    Apply(ApplyJob),
    Snapshot(SnapshotJob),
}

/// The sequenced execution lane: one FIFO channel feeding one task.
///
/// Cloning the lane clones the sender only — every clone feeds the SAME queue
/// and therefore the same order (same contract as `ConsensusSender`).
#[derive(Clone)]
struct ApplyLane {
    tx: tokio::sync::mpsc::UnboundedSender<LaneJob>,
}

impl ApplyLane {
    /// Spawn the single worker for `state`. One task, one loop: take the next
    /// job, run the shared transition to completion, report the outcome plus
    /// the post-apply root, repeat. Two jobs can never overlap (the next
    /// `recv` happens only after the previous outcome is sent), and order is
    /// exactly submission order.
    fn spawn(state: &Arc<InMemoryStateEngine>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<LaneJob>();
        let state = Arc::clone(state);
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                match job {
                    LaneJob::Apply(job) => {
                // Panic guard (audit follow-up): a DETERMINISTIC panic (same
                // block bytes => same panic on every node) bricks finality
                // identically everywhere across restarts. Never synthesize an
                // outcome and never advance past an unapplied block — park
                // LOUDLY (the Closed branch below already parks on worker
                // death; this covers the panic itself). No outcome is
                // reported, so `try_poll_apply` sees Closed and parks.
                let outcome = std::panic::AssertUnwindSafe(async {
                    let outcome = state.apply_block_transition(&job.block, job.reward).await;
                    // Captured HERE, on the worker, so the submitter learns the
                    // certified post-H root without recomputing the commitment a
                    // second time on the tick.
                    let root = state.get_state_root().await;
                    (outcome, root)
                });
                let result = outcome.catch_unwind().await;
                match result {
                    Ok((outcome, root)) => {
                        let _ = job.done.send((outcome, root));
                    }
                    Err(_) => {
                        tracing::error!(
                            height = job.block.height,
                            "apply worker PANICKED — parking height, never advancing past an unapplied block"
                        );
                        // `done` is dropped unsent: `try_recv` sees Closed and
                        // parks (fail-closed, same as worker death).
                    }
                }
                    }
                    LaneJob::Snapshot(job) => {
                        // Quiescent capture (audit 2026-10-06, chain-down
                        // incident): FIFO order usually lands this between two
                        // applies, but queue order alone cannot prove it (an
                        // H+1 apply submitted earlier this tick would run
                        // first). The ROOT check makes it airtight: capture
                        // only if the engine still roots at the certified
                        // post-`height` root; otherwise skip loudly and let a
                        // later height snapshot instead (labels stay exact —
                        // a skipped height simply snapshots later).
                        if state.get_state_root().await != job.expected_root {
                            tracing::warn!(
                                height = job.height,
                                "snapshot skipped: engine moved past the certified root (concurrent apply won the race)"
                            );
                            let _ = job.done.send(None);
                            continue;
                        }
                        // Quiescent capture (audit 2026-10-06, chain-down
                        // incident): FIFO order guarantees the previous apply
                        // installed and the next has not started, so these
                        // clones can never mix heights — unlike tick-side
                        // cloning, where the worker could slip an apply
                        // between the separate clone calls. Read locks only;
                        // uncontended (nothing else mutates mid-capture).
                        let accounts =
                            crate::storage::clone_account_snapshot(&state).await;
                        let ledger = state.staking_read().await.clone();
                        let gov = state.governance_read().await.clone();
                        let domains =
                            crate::storage::DomainSnapshot::capture(&state, &ledger, &gov)
                                .await;
                        let session_keys = state.session_keys_snapshot().await;
                        let bridge = state.bridge_snapshot().await;
                        let confidential = state.confidential_snapshot().await;
                        let zkml_models = state.zkml_models_snapshot().await;
                        let _ = job.done.send(Some(SnapBundle {
                            height: job.height,
                            accounts,
                            domains,
                            session_keys,
                            bridge,
                            confidential,
                            zkml_models,
                        }));
                    }
                }
            }
        });
        Self { tx }
    }
}

/// A decided block whose execution is still on the worker: the decision is
/// final (QC attached, proof stashed) but NOTHING observable has moved yet —
/// no `finalized` entry, no height advance, no receipts. The outcome is
/// installed by `try_poll_apply` / `await_apply_completion`.
struct ApplyInflight {
    height: Height,
    hash: BlockHash,
    block: Block,
    done: tokio::sync::oneshot::Receiver<(
        crate::state_engine::BlockTransitionOutcome,
        [u8; 32],
    )>,
}

/// What the worker reported back once its outcome is installed: the executed
/// height, its hash and the certified post-apply root (no recompute needed by
/// the caller).
pub struct ApplyCompleted {
    pub height: Height,
    pub hash: BlockHash,
    pub root: [u8; 32],
}
pub struct ValidatorRuntime {
    pub key: SigningKey,
    /// Optional out-of-process signer (HSM / KMS / remote service). When present it
    /// signs votes and proposals INSTEAD of `key`; there is no fallback, so a signer
    /// that is present but failing produces no vote at all rather than a locally
    /// signed one. See `src/remote_signer.rs` rule 1.
    pub remote_signer: Option<Arc<dyn crate::remote_signer::Signer>>,
    pub id: ValidatorId,
    pub validators: ValidatorSet,
    pub hc: HeightConsensus,
    pub state: Arc<InMemoryStateEngine>,
    pub mempool: Arc<tokio::sync::RwLock<Mempool>>,
    pub blocks: HashMap<BlockHash, Block>,
    /// Bodies our locked peers are stuck on (learned from nil-vote lock hints).
    /// Scoped to `demanded_height` (a finalize moves on, old demands die with
    /// it); capped so hint spam cannot grow memory. Served one-shot per hint
    /// batch: re-proposing re-validates, and a still-stuck peer re-hints.
    demanded: HashSet<BlockHash>,
    demanded_height: Height,
    /// Best-known peer head `(height, hash)` from structurally-valid proposals:
    /// a proposal at height H proves its author finalized H-1 (hash = prev_hash),
    /// REGARDLESS of whether we accept it (wrong height/round rejections carry
    /// true information too). Updated after authentication, before slot checks,
    /// so a lagging node learns where the network is even from proposals it
    /// must refuse. try_catch_up prefers it over the flaky DHT read.
    pub peer_hint: Option<(Height, BlockHash)>,
    pub finalized: Vec<(Height, BlockHash)>,
    pub applied_txs: u64,
    /// Per-transaction success flags from the last applied block, kept for
    /// receipts. Must not be recomputed by re-applying the block.
    pub applied_statuses: Vec<bool>,
    /// Per-transaction fee actually charged by the last applied block, in the
    /// same order as `applied_statuses` (0 for failed transactions). Filed
    /// into receipts alongside the flags.
    pub applied_fees: Vec<u64>,
    /// Optional staking ledger. When present, equivocation evidence is slashed
    /// on finalization and voting power is derived from bonded stake.
    /// Shared on-chain staking ledger. This is an ALIAS of the ledger inside the
    /// state engine, not a second copy: consensus derives the validator set from
    /// it, so two copies could disagree about who the validators are.
    pub staking: Arc<tokio::sync::RwLock<crate::staking::StakingLedger>>,
    /// Optional governance engine. When present, proposals/votes can be driven
    /// through the node (and later applied to parameters).
    pub governance: Option<crate::governance::Governance>,
    /// Block reward (nano-STELL) paid to the proposer on each finalized block.
    /// Zero disables rewards.
    pub block_reward: u64,
    /// The last decision proof, stashed by `try_finalize` before it resets
    /// `hc`. The main loop consumes it for the commit broadcast that lets
    /// lagging peers catch up in place.
    pub last_decision: Option<(Height, Block, crate::consensus::QuorumCertificate)>,
    /// Which shard this runtime produces and validates blocks for. Defaults to
    /// `MASTERCHAIN_SHARD` so existing single-shard call sites are unchanged.
    pub shard_id: ShardId,
    /// The shards this process runs. Defaults to the single masterchain, so
    /// `is_sharded()` is false and every shard-aware check below is skipped.
    pub shard_registry: ShardRegistry,
    /// Node-local cross-shard transport (in-process mailbox or the shared
    /// infnode KV). `None` disables cross-shard flow entirely, which is the
    /// single-shard default and leaves every pre-sharding call site untouched.
    pub cross_shard: Option<Arc<crate::network::CrossShardTransport>>,
    /// Process-shared finalized-header registry (C1 anchor). `None` (unit
    /// tests, single-shard nodes) fails anchored verification CLOSED.
    /// Set once via [`Self::with_finalized_headers`]; shared (same `Arc`)
    /// with every shard runtime AND state engine in the process, so a header
    /// finalized on any shard anchors consumption on all of them.
    pub finalized_headers: Option<Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>>,
    /// Inbound cross-shard messages this runtime has already committed and
    /// credited. A pure function of the applied chain (rebuilt block by block on
    /// replay), used to reject a replayed inbound message at proposal time
    /// synchronously. Not part of the state root; the state engine keeps its own
    /// copy so a direct apply is safe too.
    consumed_cross_shard: HashSet<CrossShardKey>,
    /// §5 M3: outbound transfers this chain committed, by transaction hash to
    /// (transaction, producing height). Rebuilt block by block in
    /// `record_apply_outcome` (every apply path funnels through it), so ack /
    /// bounce linkage checks and the height-based timeout rule are pure
    /// functions of the applied chain on every node.
    produced_cross_shard: HashMap<[u8; 32], (Transaction, u64)>,
    /// §5 M3: transaction hashes whose cross-shard lifecycle completed on this
    /// chain (an ack OR a bounce was committed). At most one completion per
    /// transaction, even across differing carrier hashes — the guard that
    /// keeps a late duplicate (or a bounce after an ack) from minting twice.
    completed_cross_shard: HashSet<[u8; 32]>,
    /// §7 Phase 2: the single ordered execution worker (spawned lazily on the
    /// first submit, so construction never needs a tokio context) and the one
    /// in-flight apply, if any. At most one decided block is ever queued or
    /// executing: a second submit while this is set is refused, and every
    /// reader of post-H state checks this first.
    apply_lane: Option<ApplyLane>,
    apply_in_flight: Option<ApplyInflight>,
    /// Snapshot capture in flight (see `SnapBundle`): at most one queued or
    /// executing. A second submit while set is refused; the caller retries on
    /// a later height (labels stay exact — a skipped height simply snapshots
    /// later).
    snapshot_in_flight: Option<tokio::sync::oneshot::Receiver<Option<SnapBundle>>>,
    /// Parallel block execution enabled flag.
    pub parallel_exec: bool,
    /// Fail-closed stale-ledger gate (node C): when the staking ledger the
    /// validator set would be derived from lags the state beyond
    /// [`crate::storage::validator_set_freshness_max_lag`], the set is
    /// REFUSED for quorum use and the node runs as observer (no votes) with
    /// a loud log, instead of silently voting/verifying with a foreign set.
    /// Set by the checked refresh paths below; cleared by any fresh refresh.
    pub validator_set_stale: bool,
    /// Human-readable reason for [`Self::validator_set_stale`], for logs/RPC.
    pub validator_set_stale_reason: Option<String>,
    /// Heights the stale verdict was derived from (state, ledger).
    pub validator_set_state_height: Option<u64>,
    /// Heights the stale verdict was derived from (state, ledger).
    pub validator_set_ledger_height: Option<u64>,
    /// Node-local count of validator-set re-entry WARNs ever emitted by the
    /// refresh paths below (metric/counter, visibility only — never consensus).
    pub validator_reentry_warns_total: u64,
    /// Re-entrants under liveness watch: member -> height it rejoined the set.
    /// Fed by [`Self::note_validator_set_gains`] on every refresh; entries
    /// leave when the member votes again (ledger `missed` streak forgiven) or
    /// drops out of the derived set. Local policy + visibility ONLY: the
    /// derived set itself is never altered.
    pub reentry_watch: HashMap<ValidatorId, u64>,
    /// Optional Falcon-512 keypair for post-quantum consensus vote signing.
    pub falcon_key: Option<FalconKeypair>,
    /// Last wall-clock instant finalization made progress (deadlock breaker).
    /// Stamped at construction and on every finalize/adopt; the breaker only
    /// fires after `STELL_DEADLOCK_TIMEOUT_SECS` (default 300) without it.
    pub last_progress_at: std::time::Instant,
    /// Last wall-clock instant the deadlock breaker jumped (rate limit: at
    /// most one jump per timeout window).
    pub last_breaker_at: Option<std::time::Instant>,
}

impl ValidatorRuntime {
    pub fn new(
        key: SigningKey,
        validators: ValidatorSet,
        state: Arc<InMemoryStateEngine>,
        start_height: Height,
    ) -> Self {
        let id = key.verifying_key().to_bytes();
        let hc = HeightConsensus::new(start_height, validators.clone());
        // The ledger is shared with the state engine, never copied out of it.
        let staking = state.staking_handle();
        // Same for the session-key registry (phase 2): the default pool gets
        // the engine's lock so admission can see revocations. A pool swapped in
        // via `with_mempool` carries its own handle (the node wires both).
        let mempool = Arc::new(tokio::sync::RwLock::new(
            Mempool::default().with_session_registry(state.session_keys_handle()),
        ));
        Self {
            key,
            remote_signer: None,
            id,
            validators,
            hc,
            state: state.clone(),
            mempool,
            blocks: HashMap::new(),
            demanded: HashSet::new(),
            demanded_height: start_height,
            peer_hint: None,
            finalized: Vec::new(),
            applied_txs: 0,
            applied_statuses: Vec::new(),
            applied_fees: Vec::new(),
            staking,
            governance: None,
            block_reward: 0,
            last_decision: None,
            shard_id: MASTERCHAIN_SHARD,
            shard_registry: ShardRegistry::single(),
            cross_shard: None,
            finalized_headers: None,
            consumed_cross_shard: HashSet::new(),
            produced_cross_shard: HashMap::new(),
            completed_cross_shard: HashSet::new(),
            apply_lane: None,
            apply_in_flight: None,
            snapshot_in_flight: None,
            parallel_exec: state.is_parallel_exec_enabled(),
            validator_set_stale: false,
            validator_set_stale_reason: None,
            validator_set_state_height: None,
            validator_set_ledger_height: None,
            validator_reentry_warns_total: 0,
            reentry_watch: HashMap::new(),
            falcon_key: None,
            last_progress_at: std::time::Instant::now(),
            last_breaker_at: None,
        }
    }

    /// Configure a Falcon-512 keypair for post-quantum consensus voting and proposal signing.
    pub fn with_falcon_key(mut self, key: FalconKeypair) -> Self {
        crate::consensus::register_validator_pq_key(
            self.id,
            crate::post_quantum::PqScheme::Falcon512,
            key.public_key.clone(),
        );
        let falcon_id = key.validator_id();
        if falcon_id != self.id {
            crate::consensus::register_validator_pq_key(
                falcon_id,
                crate::post_quantum::PqScheme::Falcon512,
                key.public_key.clone(),
            );
        }
        self.falcon_key = Some(key);
        self
    }

    /// Falcon keypair to sign a proposal or vote with, or `None` when signing
    /// must be REFUSED.
    ///
    /// Under Pure PQ a missing keypair is a hard stop, never a derivation
    /// fallback. The old fallback did
    /// `FalconKeypair::generate_from_seed(self.id[0])`, i.e. derived a PRIVATE
    /// key from a single byte of the PUBLIC validator id: 256 candidate
    /// keypairs total, so anyone who reads the validator's id out of
    /// `node.yaml` could reproduce its private key and forge its proposals and
    /// votes. That is exactly the failure `main.rs` warns about on the real key
    /// path ("deriving a PRIVATE key deterministically from a PUBLIC validator
    /// id would let anyone forge any validator's votes").
    ///
    /// Production always installs a persisted key via
    /// [`ValidatorRuntime::with_falcon_key`] before consensus starts, so this
    /// only fires for a misconfigured runtime - where not signing is the safe
    /// outcome: the set refuses to accept a vote it cannot attribute.
    fn falcon_signing_key(&self) -> Option<&FalconKeypair> {
        if let Some(k) = &self.falcon_key {
            return Some(k);
        }
        if crate::post_quantum::is_pure_pq_enforced() {
            tracing::error!(
                "[post-quantum] Pure PQ requires a persisted Falcon-512 keypair and this \
                 validator has none; refusing to sign proposals/votes (a derived key would \
                 be forgeable from the public validator id)"
            );
        }
        None
    }

    /// Run this runtime as a specific shard of a multi-shard process.
    ///
    /// With the default registry (`is_sharded() == false`) this only sets the
    /// block's `shard_id`; the shard-aware proposal checks and the mempool
    /// target filter stay off, so single-shard behaviour is unchanged.
    pub fn with_shard(mut self, shard_id: ShardId, registry: ShardRegistry) -> Self {
        self.shard_id = shard_id;
        // A genuine multi-shard process turns on cross-shard execution on the
        // engine. A single-shard registry leaves it off, so the historical
        // "always credit `to`" semantics (and every pre-sharding test) hold.
        if registry.is_sharded() {
            self.state.enable_cross_shard();
        }
        self.shard_registry = registry;
        self
    }

    /// Attach the node-local cross-shard transport (shared with the process's
    /// other shard runtimes). Without one, a sharded runtime produces and
    /// consumes no cross-shard messages.
    pub fn with_cross_shard(
        mut self,
        transport: Arc<crate::network::CrossShardTransport>,
    ) -> Self {
        self.cross_shard = Some(transport);
        self
    }

    /// Attach the process-shared finalized-header registry (C1 anchor).
    /// Same `Arc` for every shard runtime and engine in the process.
    pub fn with_finalized_headers(
        mut self,
        registry: Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>>,
    ) -> Self {
        self.finalized_headers = Some(registry);
        self
    }

    /// Record a finalized block's header for cross-shard anchoring. Called
    /// on every finalize path (live, adopt, walk); idempotent.
    pub fn note_finalized_header(&self, block: &Block) {
        if let Some(reg) = self.finalized_headers.as_ref() {
            if let Ok(mut r) = reg.write() {
                r.note_finalized(block.shard_id, block.compute_hash(), block.state_root);
            }
        }
    }

    /// Anchored inclusion check for one inbound message (C1): proof AND a
    /// locally-finalized source header with the claimed root. `false` covers
    /// both "forged" and "not finalized here yet" — callers treat it as
    /// not-ready (skip/refuse + retry after catching up), never as verified.
    pub fn verify_cross_shard_anchored(&self, msg: &CrossShardMessage) -> bool {
        let guard = self
            .finalized_headers
            .as_ref()
            .and_then(|r| r.read().ok());
        let Some(reg) = guard.as_deref() else {
            return false;
        };
        msg.verify_anchored(Some(reg))
    }

    /// §5 M3: linkage rule for ack/bounce control records, checked at a given
    /// chain height (the proposed block's height at propose/validate time, the
    /// applied block's height at apply time).
    ///
    /// A control record is valid iff ALL hold:
    ///  * it carries NO Merkle proof and is NOT locally trusted. The engine
    ///    credits any proof-carrying inbound to `tx.to`, so a proof-carrying
    ///    reversed-direction record would mint on the source shard; refusing
    ///    it here (and skipping proof-less records in the engine) is what
    ///    makes the refund path safe without a state-engine change;
    ///  * its transaction's outbound transfer was committed on THIS chain
    ///    (`produced_cross_shard`, rebuilt from applied blocks);
    ///  * the transaction has not already completed (no ack/bounce committed);
    ///  * for a bounce, the height timeout has elapsed
    ///    (`bounce_eligible(produce_height, at_height)` — heights, not seconds).
    /// Unknown kinds fail closed (false).
    fn control_linkage_ok(&self, msg: &CrossShardMessage, at_height: u64) -> bool {
        if !msg.is_ack() && !msg.is_bounce() {
            return false;
        }
        if msg.merkle_inclusion_proof.is_some() || msg.trusted {
            return false;
        }
        let tx_hash = msg.tx.compute_tx_hash();
        if self.completed_cross_shard.contains(&tx_hash) {
            return false;
        }
        let Some((_, produce_height)) = self.produced_cross_shard.get(&tx_hash) else {
            return false;
        };
        if msg.is_bounce() {
            return crate::sharding::bounce_eligible(*produce_height, at_height);
        }
        true
    }

    /// Producing height of a committed outbound transfer on this chain, if any
    /// (§5 M3; test/debug introspection over `produced_cross_shard`).
    pub fn produced_cross_shard_height(&self, tx_hash: &[u8; 32]) -> Option<u64> {
        self.produced_cross_shard.get(tx_hash).map(|(_, h)| *h)
    }

    /// True once an ack or bounce for `tx_hash` committed on this chain (§5 M3).
    pub fn is_transfer_completed(&self, tx_hash: &[u8; 32]) -> bool {
        self.completed_cross_shard.contains(tx_hash)
    }

    /// Snapshot the whole cross-shard replay state for persistence (audit
    /// F-I): the engine credit gate plus the three runtime mirrors, sorted
    /// for deterministic bytes. Called where the runtime is alive (periodic
    /// snapshot block); a fresh runtime snapshots empty sets, which is correct
    /// (nothing committed yet to protect).
    pub async fn cross_shard_replay_snapshot(
        &self,
    ) -> crate::sharding::CrossShardReplaySnapshot {
        let mut engine_consumed = self.state.cross_shard_consumed_snapshot().await;
        engine_consumed.sort();
        let mut runtime_consumed: Vec<crate::sharding::CrossShardKey> =
            self.consumed_cross_shard.iter().copied().collect();
        runtime_consumed.sort();
        let mut produced: Vec<([u8; 32], Transaction, u64)> = self
            .produced_cross_shard
            .iter()
            .map(|(h, (tx, height))| (*h, tx.clone(), *height))
            .collect();
        produced.sort_by_key(|(h, _, _)| *h);
        let mut completed: Vec<[u8; 32]> =
            self.completed_cross_shard.iter().copied().collect();
        completed.sort();
        crate::sharding::CrossShardReplaySnapshot {
            engine_consumed,
            runtime_consumed,
            produced,
            completed,
        }
    }

    /// Install persisted replay state (startup restore). Extends (never
    /// replaces: live sets may already hold entries committed after the
    /// snapshot was taken). The engine half travels separately through the
    /// load paths (`restore_cross_shard_consumed`); calling both with the
    /// same blob is idempotent.
    pub fn restore_cross_shard_sets(
        &mut self,
        snap: &crate::sharding::CrossShardReplaySnapshot,
    ) {
        self.consumed_cross_shard
            .extend(snap.runtime_consumed.iter().copied());
        for (h, tx, height) in &snap.produced {
            self.produced_cross_shard.insert(*h, (tx.clone(), *height));
        }
        self.completed_cross_shard
            .extend(snap.completed.iter().copied());
    }

    /// Seed the staking ledger (tests / genesis). The ledger lives in the state
    /// engine, so this writes there; there is deliberately no second copy on the
    /// runtime, because a second copy is a second opinion about who the
    /// validators are - and the validator set decides who proposes.
    pub fn with_staking(self, _ledger: crate::staking::StakingLedger) -> Self {
        // The ledger now lives in the state engine; this setter is kept so
        // existing call sites keep compiling, and seeds the engine if it can take
        // the lock synchronously.
        if let Some(mut guard) = self.state.try_staking_write() {
            *guard = _ledger;
        }
        self
    }

    /// Attach a governance engine (on-chain parameter control).
    pub fn with_governance(mut self, g: crate::governance::Governance) -> Self {
        self.governance = Some(g);
        self
    }

    /// Set the per-block proposer reward (nano-STELL). Requires a staking ledger
    /// to have any effect.
    /// Use a mempool that is shared with the RPC layer, so a transaction
    /// submitted over RPC is the very same one the proposer selects.
    pub fn with_mempool(mut self, mempool: Arc<tokio::sync::RwLock<Mempool>>) -> Self {
        self.mempool = mempool;
        self
    }

    pub fn with_block_reward(mut self, reward: u64) -> Self {
        self.block_reward = reward;
        self
    }

    /// Configure disjoint wave parallel block execution for this runtime.
    pub fn with_parallel_exec(mut self, enabled: bool) -> Self {
        self.parallel_exec = enabled;
        self.state.set_parallel_exec(enabled);
        self
    }

    /// Set parallel block execution flag on this runtime and its state engine.
    pub fn set_parallel_exec(&mut self, enabled: bool) {
        self.parallel_exec = enabled;
        self.state.set_parallel_exec(enabled);
    }

    /// Check whether disjoint wave parallel execution is enabled.
    pub fn is_parallel_exec_enabled(&self) -> bool {
        self.parallel_exec || self.state.is_parallel_exec_enabled()
    }

    /// Slash the offenders named by THIS NODE'S local equivocation observations.
    /// Returns the total burned.
    ///
    /// SECURITY / F4: this is deliberately NOT called from any state-transition
    /// path (`try_finalize`, `apply_and_advance`, `replay_historical_block`).
    /// The evidence comes from `self.hc.equivocations()`, i.e. from whichever
    /// conflicting votes this node happened to receive over best-effort gossip.
    /// Two nodes that decide the SAME block by different routes (local finalize
    /// vs adopt vs walk vs replay) therefore observe different evidence, burn
    /// different stake, and commit different state roots — a chain split that a
    /// single Byzantine double-voter triggers at will by choosing gossip
    /// delivery (audit finding F4).
    ///
    /// Equivocation slashing therefore travels inside the block as verifiable
    /// content (approach "carry evidence in the block"): no new `Block` field
    /// was needed — the evidence rides the block BODY as
    /// `OpCode::SysCallReportEquivocation` payloads (appended terminal
    /// variant; old nodes fail closed on the unknown discriminant instead of
    /// misreading the block). Gossip-direct slashing stays DEAD: determinism
    /// is preserved by slashing ONLY from block bytes. Direct callers in
    /// tests exercise the primitive; production code must not call this from
    /// a transition.
    ///
    /// PRODUCT DECISION (audit O1 — gossip-direct equivocation stays
    /// unwired, stated without ambiguity): THIS function (local-observation
    /// slash) must never run in a state transition — double-signing observed
    /// only over gossip is still FREE by design, and only downtime slashing
    /// plus BLOCK-CARRIED equivocation slashing are live. The wired path is
    /// `InMemoryStateEngine::apply_block_transition` (step 5b), which meets
    /// all three preconditions together with fail-closed tests:
    ///   (1) block-carried, signature-verifiable equivocation evidence
    ///       (`SysCallReportEquivocation` payloads, both votes fully
    ///       included, re-verified from block bytes on every node);
    ///   (2) the live call site debits `STAKING_POOL` by `burned` (the
    ///       primitive mutates ledger fields only; without the debit
    ///       pool/ledger drift by `burned` per slash);
    ///   (3) per-offense (`BLAKE3(voter‖height‖round‖kind‖targets)`) dedup
    ///       in the ledger, so one offense slashes exactly once on every
    ///       node. Wire gossip evidence instead and nodes slash different
    ///       stake from the same height (audit finding F4).
    pub async fn apply_equivocation_slashes(&mut self) -> u64 {
        let mut guard = self.state.staking_write().await;
        let ledger = &mut *guard;
        let mut burned = 0u64;
        for ev in self.hc.equivocations() {
            if let Ok(b) = ledger.slash_equivocation(&ev) {
                burned = burned.saturating_add(b);
            }
        }
        burned
    }

    /// Block-carried equivocation feed: deterministic envelopes for the NEXT
    /// block this node helps build.
    ///
    /// Converts THIS node's local double-vote observations
    /// (`HeightConsensus::equivocations()` — which transactions may never
    /// read, audit F4) into canonical, verified
    /// [`crate::consensus::EquivocationEvidence`] envelopes ready to embed
    /// as `OpCode::SysCallReportEquivocation` payloads (permissionless: any
    /// funded account may report, like the price-feed path). Verified
    /// against the consensus validator set, sorted by offense key, in-block
    /// duplicates dropped, capped at
    /// [`crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES`] — so every
    /// caller feeds the same bytes for the same observations.
    ///
    /// This feeds PROPOSAL content only. The slash itself fires at apply
    /// (`InMemoryStateEngine::apply_block_transition`, step 5b), which
    /// re-verifies every envelope from block bytes and dedupes per offense
    /// in the staking ledger — so a re-included (already-slashed) offense
    /// burns 0 and the feed needs no ledger access. Fail-closed: anything
    /// unverifiable never leaves this function.
    pub fn equivocation_feed_evidence(
        &self,
    ) -> Vec<crate::consensus::EquivocationEvidence> {
        let pairs = self.hc.equivocations();
        if pairs.is_empty() {
            return Vec::new();
        }
        let items: Vec<crate::consensus::EquivocationEvidence> = pairs
            .into_iter()
            .map(|(voter, a, b)| crate::consensus::EquivocationEvidence::new(voter, a, b))
            .collect();
        let mut out = crate::consensus::canonicalize_equivocation_evidence(items, &|v| {
            self.validators.validators.contains_key(v)
        });
        out.truncate(crate::consensus::MAX_BLOCK_EQUIVOCATION_EVIDENCES);
        out
    }

    // ==================== Staking lifecycle (on-chain) ====================

    /// Register a validator self-bond through the node.
    ///
    /// A8: the bonded STELL is actually DEBITED from the validator's account, so
    /// voting power is backed by real funds (previously the ledger was updated
    /// without moving any balance, letting a validator stake funds it never had).
    pub async fn stake_bond(
        &mut self,
        validator: ValidatorId,
        amount: u64,
        commission_bps: u64,
    ) -> Result<(), crate::staking::StakingError> {
        use crate::staking::StakingError;
        // The ledger lives in the state engine, so a bond through this helper
        // lands in exactly the place a SysCallStake bond does.
        self.state
            .debit_native(&validator, amount)
            .await
            .map_err(|_| StakingError::InsufficientBond)?;
        let _ = self
            .state
            .credit_native(&crate::staking::STAKING_POOL, amount)
            .await;
        let res = self
            .state
            .staking_write()
            .await
            .bond(validator, amount, commission_bps);
        if let Err(e) = res {
            // M2: the ledger refused AFTER the pool was credited — remove the
            // pool credit symmetrically (fail-closed) before refunding the
            // validator, or the pool keeps coins no ledger entry backs (mint).
            let _ = self.state.debit_native(&crate::staking::STAKING_POOL, amount).await;
            let _ = self.state.credit_native(&validator, amount).await;
            return Err(e);
        }
        Ok(())
    }

    /// Begin unbonding self-bond (subject to cooldown). Funds are already held by
    /// the ledger from `stake_bond`, so nothing moves until withdrawal.
    pub async fn stake_unbond(
        &mut self,
        validator: ValidatorId,
        amount: u64,
        now: u64,
    ) -> Result<(), crate::staking::StakingError> {
        let mut engine = self.state.staking_write().await;
        let l = &mut *engine;
        l.unbond(validator, amount, now)
    }

    /// Delegate stake to a validator. The STELL is actually DEBITED from the
    /// delegator's account.
    ///
    /// M2: the debit is escrowed into [`crate::staking::STAKING_POOL`] exactly
    /// like `stake_bond`, so the delegated ledger entry is always pool-backed
    /// and a later `stake_withdraw_delegator` can debit the pool instead of
    /// minting. Every native leg unwinds symmetrically on failure.
    pub async fn stake_delegate(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
        amount: u64,
    ) -> Result<(), crate::staking::StakingError> {
        // L2: the zero delegator would collide with the validator's own
        // matured self-bond key — refuse before moving any coins.
        if delegator == [0u8; 32] {
            return Err(crate::staking::StakingError::ZeroAddress);
        }
        use crate::staking::StakingError;
        self.state
            .debit_native(&delegator, amount)
            .await
            .map_err(|_| StakingError::InsufficientDelegation)?;
        if self
            .state
            .credit_native(&crate::staking::STAKING_POOL, amount)
            .await
            .is_err()
        {
            let _ = self.state.credit_native(&delegator, amount).await;
            return Err(StakingError::InsufficientDelegation);
        }
        let res = self
            .state
            .staking_write()
            .await
            .delegate(delegator, validator, amount);
        if let Err(e) = res {
            let _ = self.state.debit_native(&crate::staking::STAKING_POOL, amount).await;
            let _ = self.state.credit_native(&delegator, amount).await;
            return Err(e);
        }
        Ok(())
    }

    /// Begin undelegating (subject to cooldown).
    pub async fn stake_undelegate(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
        amount: u64,
        now: u64,
    ) -> Result<(), crate::staking::StakingError> {
        self.state
            .staking_write()
            .await
            .undelegate(delegator, validator, amount, now)
    }

    /// Mature any unbonding entries whose cooldown has elapsed (called on
    /// finalization so funds become withdrawable without an external trigger).
    pub async fn process_unbonding(&mut self, now: u64) {
        self.state.staking_write().await.process_unbonding(now);
    }

    /// Withdraw matured self-bond funds (credited back to the validator).
    ///
    /// M2: withdrawals are paid OUT OF [`crate::staking::STAKING_POOL`], never
    /// minted. The pool is debited FIRST (fail-closed on shortfall: the
    /// consumed ledger entry is restored and nothing is paid); if the final
    /// credit then fails, the pool debit is refunded AND the ledger entry is
    /// restored, so a failed withdrawal moves no coins anywhere.
    pub async fn stake_withdraw(&mut self, validator: ValidatorId) -> Result<u64, crate::staking::StakingError> {
        use crate::staking::StakingError;
        let amount = self.state.staking_write().await.withdraw(validator)?;
        if self
            .state
            .debit_native(&crate::staking::STAKING_POOL, amount)
            .await
            .is_err()
        {
            let mut l = self.state.staking_write().await;
            let key = (validator, [0u8; 32]);
            let back = l.withdrawable.get(&key).copied().unwrap_or(0).saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        if self.state.credit_native(&validator, amount).await.is_err() {
            let _ = self
                .state
                .credit_native(&crate::staking::STAKING_POOL, amount)
                .await;
            let mut l = self.state.staking_write().await;
            let key = (validator, [0u8; 32]);
            let back = l.withdrawable.get(&key).copied().unwrap_or(0).saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        Ok(amount)
    }

    /// Withdraw matured undelegated funds as a delegator (credited to delegator).
    ///
    /// M2: same pool-backed discipline as [`Self::stake_withdraw`] — the pool
    /// is debited first (fail-closed on shortfall, ledger entry restored) and
    /// both legs unwind on a failed credit.
    pub async fn stake_withdraw_delegator(
        &mut self,
        delegator: [u8; 32],
        validator: ValidatorId,
    ) -> Result<u64, crate::staking::StakingError> {
        use crate::staking::StakingError;
        let amount = self
            .state
            .staking_write()
            .await
            .withdraw_delegator(delegator, validator)?;
        if self
            .state
            .debit_native(&crate::staking::STAKING_POOL, amount)
            .await
            .is_err()
        {
            let mut l = self.state.staking_write().await;
            let key = (validator, delegator);
            let back = l.withdrawable.get(&key).copied().unwrap_or(0).saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        if self.state.credit_native(&delegator, amount).await.is_err() {
            let _ = self
                .state
                .credit_native(&crate::staking::STAKING_POOL, amount)
                .await;
            let mut l = self.state.staking_write().await;
            let key = (validator, delegator);
            let back = l.withdrawable.get(&key).copied().unwrap_or(0).saturating_add(amount);
            l.withdrawable.insert(key, back);
            return Err(StakingError::NothingToWithdraw);
        }
        Ok(amount)
    }

    /// Claim accrued validator rewards (credited to the validator).
    ///
    /// E2: paid out of the minted [`crate::staking::REWARDS_POOL`], never out
    /// of bonded principal and never minted from thin air. The ledger claim
    /// already consumed the pool backing; the native leg debits the pool
    /// first (fail-closed on shortfall) and restores the ledger entry if
    /// either native leg fails.
    pub async fn stake_claim_rewards(&mut self, validator: ValidatorId) -> Result<u64, crate::staking::StakingError> {
        let amount = self
            .state
            .staking_write()
            .await
            .claim_validator_rewards(validator)?;
        if amount > 0 {
            if self
                .state
                .debit_native(&crate::staking::REWARDS_POOL, amount)
                .await
                .is_err()
            {
                // Restore pool backing + pending rewards: nothing was paid.
                let mut l = self.state.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_add(amount);
                if let Some(v) = l.validators.get_mut(&validator) {
                    v.pending_rewards = v.pending_rewards.saturating_add(amount);
                }
                return Err(crate::staking::StakingError::RewardCreditFailed);
            }
            if let Err(_e) = self.state.credit_native(&validator, amount).await {
                // Refund the pool debit and restore the ledger entry.
                let _ = self
                    .state
                    .credit_native(&crate::staking::REWARDS_POOL, amount)
                    .await;
                let mut l = self.state.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_add(amount);
                if let Some(v) = l.validators.get_mut(&validator) {
                    v.pending_rewards = v.pending_rewards.saturating_add(amount);
                }
                return Err(crate::staking::StakingError::RewardCreditFailed);
            }
        }
        Ok(amount)
    }

    /// Claim accrued delegator rewards (credited to the delegator).
    ///
    /// E2: same funding discipline as [`Self::stake_claim_rewards`] — the
    /// native leg debits [`crate::staking::REWARDS_POOL`], never principal.
    pub async fn stake_claim_delegator_rewards(&mut self, delegator: [u8; 32], validator: ValidatorId) -> u64 {
        let amount = self
            .state
            .staking_write()
            .await
            .claim_delegator_rewards(delegator, validator);
        if amount > 0 {
            if self
                .state
                .debit_native(&crate::staking::REWARDS_POOL, amount)
                .await
                .is_err()
            {
                // Restore pool backing + the consumed entry: nothing was paid.
                let mut l = self.state.staking_write().await;
                l.rewards_pool = l.rewards_pool.saturating_add(amount);
                *l.delegator_rewards.entry((validator, delegator)).or_insert(0) =
                    l.delegator_rewards
                        .get(&(validator, delegator))
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(amount);
                return 0;
            }
            if self.state.credit_native(&delegator, amount).await.is_err() {
                // Refund the pool debit and restore the ledger entry.
                let _ = self
                    .state
                    .credit_native(&crate::staking::REWARDS_POOL, amount)
                    .await;
                {
                    let mut l = self.state.staking_write().await;
                    l.rewards_pool = l.rewards_pool.saturating_add(amount);
                    *l.delegator_rewards.entry((validator, delegator)).or_insert(0) =
                        l.delegator_rewards
                            .get(&(validator, delegator))
                            .copied()
                            .unwrap_or(0)
                            .saturating_add(amount);
                }
                return 0;
            }
        }
        amount
    }

    // ==================== Governance (on-chain) ====================

    /// Submit a governance proposal.
    pub fn gov_propose(
        &mut self,
        proposer: ValidatorId,
        title: String,
        action: crate::governance::GovAction,
        now: u64,
    ) -> Result<u64, crate::governance::GovError> {
        let ledger = self.staking.try_read().map_err(|_| crate::governance::GovError::NotStaker)?;
        let g = self.governance.as_mut().ok_or(crate::governance::GovError::NotStaker)?;
        g.propose(&ledger, proposer, title, action, now)
    }

    /// Cast a governance vote.
    pub fn gov_vote(
        &mut self,
        voter: [u8; 32],
        proposal_id: u64,
        choice: crate::governance::VoteChoice,
        now: u64,
    ) -> Result<u128, crate::governance::GovError> {
        // E7: `Governance::vote` locks the voter's stake in the ledger, so it
        // needs a write guard (via the state engine, which also bumps the
        // commitment generation — a bare handle write would leave the root
        // cache stale). Same underlying lock as `self.staking`.
        let mut ledger = self
            .state
            .try_staking_write()
            .ok_or(crate::governance::GovError::NotStaker)?;
        let g = self.governance.as_mut().ok_or(crate::governance::GovError::NotStaker)?;
        g.vote(&mut ledger, voter, proposal_id, choice, now)
    }

    /// Finalize a proposal after its voting window.
    pub fn gov_finalize(
        &mut self,
        proposal_id: u64,
        now: u64,
    ) -> Result<crate::governance::ProposalStatus, crate::governance::GovError> {
        // E7: `Governance::finalize` releases voters' staking locks (see
        // `gov_vote` for why this goes through the state engine).
        let mut ledger = self
            .state
            .try_staking_write()
            .ok_or(crate::governance::GovError::NotStaker)?;
        let g = self.governance.as_mut().ok_or(crate::governance::GovError::NotStaker)?;
        g.finalize(&mut ledger, proposal_id, now)
    }

    /// Execute a passed proposal's action.
    pub fn gov_execute(
        &mut self,
        executor: [u8; 32],
        proposal_id: u64,
    ) -> Result<crate::governance::AppliedParams, crate::governance::GovError> {
        let g = self.governance.as_mut().ok_or(crate::governance::GovError::NotStaker)?;
        g.execute(executor, proposal_id).cloned()
    }

    pub fn height(&self) -> Height {
        self.hc.height
    }

    pub fn is_proposer(&self) -> bool {
        self.hc.proposer() == Some(self.id)
    }

    pub async fn add_tx(&mut self, tx: Transaction) {
        // Check the sender's balance so an unfunded tx can never occupy queue
        // space or evict a funded one at the mempool.
        let acct = self.state.get_account(&tx.from).await;
        let balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
        // F-02: carry the on-chain head so `insert` enforces the nonce-gap
        // fail-fast at the choke point itself (not just at the RPC/gossip
        // pre-checks). `None`-head callers keep legacy behavior; here the
        // head is already in hand, so enforce unconditionally. Node-local
        // admission only — never consensus.
        let onchain = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
        let _ = self
            .mempool
            .write()
            .await
            .add_checked_ctx(
                tx,
                balance,
                crate::mempool::AdmissionCtx::wall_now().with_onchain_nonce(onchain),
            );
    }

    /// If we are the proposer, build a block from the mempool and sign it.
    pub async fn propose(&mut self, timestamp: u64) -> Option<Block> {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        if !self.is_proposer() || self.hc.step != Step::Propose {
            return None;
        }
        // §7 Phase 2 gate: while a decided block is still executing on the
        // sequenced worker, our state root is PRE-H and every read below
        // (account snapshots for the filter, `state_root` for the header,
        // cross-shard proofs) would build on it. Building now produces a block
        // for the wrong parent state, so there is nothing to propose until the
        // worker reports back. ("Propose while apply pending" must stay None.)
        if self.apply_in_flight.is_some() {
            return None;
        }
        // Liveness: a locked proposer re-proposes its locked value. Building a
        // fresh block while locked is voted nil by every node locked on the old
        // value (including ourselves) while unlocked nodes vote the fresh one
        // -- no quorum either way, forever. Re-proposing the locked body lets
        // the network converge on it: unlocked nodes vote it, nodes locked on
        // it vote it, a QC forms, finalize. The lock is per-height (a new
        // height constructs a fresh HeightConsensus), bodies are retained, and
        // we only ever lock values we voted for, so the body is present; if it
        // is somehow gone, fall through to a fresh block rather than forfeit
        // our proposer rounds entirely.
        // C1 genesis anchor: first messages reference the zero-hash parent
        // with the current (genesis) root, which no finalize event ever
        // records. Note it here (idempotent, overwritten by real finals):
        // without this, height-1 cross-shard transfers can never anchor.
        // Root read FIRST, lock second: the guard must never be held across
        // the await (std guards are !Send).
        if self.finalized.is_empty() {
            if let Some(reg) = self.finalized_headers.clone() {
                let root = self.state.get_state_root().await;
                if let Ok(mut r) = reg.write() {
                    r.note_finalized(self.shard_id, [0u8; 32], root);
                }
            }
        }
        if let Some((locked_hash, _)) = self.hc.locked {
            if let Some(body) = self.blocks.get(&locked_hash).cloned() {
                // Info when bypassing a non-empty pool (audit: blocks
                // troubles): locked re-proposals skip fresh selection, so an
                // empty locked body with a full mempool looks identical to an
                // empty chain without this line.
                let pool_len = self.mempool.read().await.len();
                if pool_len > 0 {
                    tracing::info!(
                        "propose h={} r={}: path=locked txs={} mempool={} (bypasses fresh selection)",
                        self.hc.height,
                        self.hc.round,
                        body.transactions.len(),
                        pool_len,
                    );
                } else {
                    tracing::debug!(
                        "propose h={} r={}: path=locked txs={} mempool=0",
                        self.hc.height,
                        self.hc.round,
                        body.transactions.len(),
                    );
                }
                // Self-record like the fresh path: without this the section-1
                // gate (`!has_live_proposal`) refires every 100ms tick and
                // rebroadcasts the identical hash all round (refire spam).
                self.hc.receive_proposal(self.id, locked_hash).ok()?;
                return Some(body);
            }
        }
        // Rescue: a peer is locked on one of OUR bodies (learned via nil-vote
        // lock hints). Re-propose it verbatim at our own slot: receivers
        // validate it normally, the locked peer votes it (it matches its
        // lock), unlocked peers vote it, QC forms, finalize. One shot per
        // hint batch -- a still-stuck peer re-hints and we serve again.
        if self.demanded_height != self.hc.height {
            self.demanded.clear();
            self.demanded_height = self.hc.height;
        }
        if let Some(h) = self.demanded.iter().next().copied() {
            let demanded_body = self
                .blocks
                .get(&h)
                .filter(|b| b.height == self.hc.height)
                .cloned();
            match demanded_body {
                None => {
                    // Unknown or stale body (never seen, or a previous
                    // height): drop it and fall through to fresh selection
                    // below; a still-stuck peer re-hints on its next nil
                    // prevote.
                    self.demanded.remove(&h);
                }
                Some(body) => {
                    let root = self.state.get_state_root().await;
                    if self.validate_proposal_unaligned(&body, root).is_ok()
                        && self.check_actor_cap(&body).await.is_ok()
                    {
                    let pool_len = self.mempool.read().await.len();
                    if pool_len > 0 {
                        tracing::info!(
                            "propose h={} r={}: path=demanded txs={} mempool={} (bypasses fresh selection)",
                            self.hc.height,
                            self.hc.round,
                            body.transactions.len(),
                            pool_len,
                        );
                    } else {
                        tracing::debug!(
                            "propose h={} r={}: path=demanded txs={} mempool=0",
                            self.hc.height,
                            self.hc.round,
                            body.transactions.len(),
                        );
                    }
                    // Self-record like the fresh path (see the locked path).
                    let bh = body.compute_hash();
                    self.blocks.insert(bh, body.clone());
                    self.hc.receive_proposal(self.id, bh).ok()?;
                        // Served: consume one-shot (a still-stuck peer re-hints).
                        self.demanded.remove(&h);
                        return Some(body);
                    }
                    // Re-validation failed (transient state/backlog read):
                    // KEEP the demand so the next tick retries instead of
                    // waiting a full hint round-trip. The set stays bounded
                    // (MAX_DEMANDED) and height-scoped, so this cannot pile up.
                }
            }
        }
        let state_root = self.state.get_state_root().await;
        // Anti-DoS: bound the block by BOTH tx count and total gas.
        // Both caps plus the admission filter, so a flood of transactions that
        // cannot execute (spent nonce, drained balance) cannot occupy the block
        // and be paid for like real work. `evict_unexecutable` cleans these up
        // each round; this stops them costing anything in the meantime.
        //
        // Sender state is gathered first because the filter itself is
        // synchronous: it walks the fee-ordered index once and must not await
        // inside the loop.
        let senders: Vec<[u8; 32]> = self
            .mempool
            .read()
            .await
            .senders()
            .into_iter()
            .collect();
        let mut accounts: std::collections::HashMap<[u8; 32], (u64, u64)> =
            std::collections::HashMap::with_capacity(senders.len());
        for a in senders {
            if let Some(acct) = self.state.get_account(&a).await {
                accounts.insert(a, (acct.nonce, acct.balance));
            }
        }
        // R0-fullness refresh (packing mechanics, no consensus change): the
        // sender snapshot above is taken BEFORE the per-sender account reads,
        // and each read awaits. The RPC layer shares this mempool, so
        // transactions admitted DURING those reads have senders missing from
        // the map and the filter below rejects them as account-less — the
        // live shape was r0 carrying 52tx while r2 carried 200tx from the same
        // pool. One bounded refresh pass fetches exactly the senders that
        // arrived mid-build, so selection sees the pool as of select time.
        // No waiting is added (no artificial delay): this only stops using a
        // stale snapshot of what is ALREADY available.
        {
            let fresh: Vec<[u8; 32]> = self
                .mempool
                .read()
                .await
                .senders()
                .into_iter()
                .collect();
            for s in missing_sender_accounts(&accounts, &fresh) {
                if let Some(acct) = self.state.get_account(&s).await {
                    accounts.insert(s, (acct.nonce, acct.balance));
                }
            }
        }
        // A block must carry a CONTIGUOUS nonce sequence per sender, so the
        // expected nonce advances as transactions are accepted. Comparing
        // against the account's nonce alone would admit a gap - a transaction
        // whose nonce is ahead of the next expected one cannot execute, and
        // would be included, fail at application, and still be paid for.
        let next_nonce = std::cell::RefCell::new(accounts.clone());
        // PHASE 2: the on-chain session-key registry, cloned out BEFORE the
        // filter runs because the closure is synchronous (it must not await).
        // The filter therefore evaluates exactly what execution will: terminal
        // revocation, the registered record's ceilings, and the CUMULATIVE
        // spend across the transactions it has already selected for THIS
        // block - in `SessionSpendSim`, so two transactions of one grant can
        // never both be selected against the same remaining budget.
        let session_keys = self.state.session_keys_read().await.clone();
        let session_sim = std::cell::RefCell::new(crate::zkml::SessionSpendSim::default());
        // Rejection census for the empty-block hunt (temporary diagnostics):
        // counts WHY the filter refuses, so a live empty-with-mempool names
        // its reason instead of staying silent.
        let rej_noacct = std::cell::Cell::new(0u32);
        let rej_nonce = std::cell::Cell::new(0u32);
        let rej_funds = std::cell::Cell::new(0u32);
        let rej_session = std::cell::Cell::new(0u32);
        let rej_shard = std::cell::Cell::new(0u32);
        let rej_basefee = std::cell::Cell::new(0u32);
        // Admission floor, mirrored in the proposer filter: the mempool
        // refuses `gas_limit < effective_floor(sender)` on every admission
        // path, so a proposer must not pack such a transaction either.
        // SKIP-only like every other filter condition (never a hard reject):
        // selection stays a pure function of the same inputs on every node,
        // so proposers cannot diverge over it. The snapshot carries the D2
        // failure penalties: a sender whose transactions keep failing at
        // apply (paying nothing) is skipped until it over-posts.
        let (base_fee, penalty_floors) = {
            let pool = self.mempool.read().await;
            (pool.base_fee, pool.penalty_snapshot())
        };
        // SHARD SCOPE: a transaction belongs to the shard it is SOURCED from.
        // That includes outbound cross-shard transfers (source == this shard,
        // target != this shard): the source shard is the one that debits the
        // sender, emits the committed CrossShardMessage and burns the value off
        // this shard; the target credits the recipient from that message. Gated
        // on `is_sharded()`, so the single-shard path (where txs carry the
        // legacy source=1/target=1 tags while the chain's block shard is 0) is
        // untouched and keeps including exactly what it always did.
        let sharded = self.shard_registry.is_sharded();
        let my_shard = self.shard_id;
        // A sender may contribute at most ONE outbound cross-shard transfer per
        // block, and it must be its first accepted transaction. The inclusion
        // proof is generated against the PRE-block account leaf, so a second
        // cross-shard transfer from the same sender (at a later nonce) could
        // not be proven against the same root. Later sends wait for the next
        // block; nothing is lost, the mempool keeps them.
        let used_senders: std::cell::RefCell<std::collections::HashSet<[u8; 32]>> =
            std::cell::RefCell::new(std::collections::HashSet::new());
        let txs = self
            .mempool
            .read()
            .await
            .select_for_block_multi(MAX_BLOCK_TXS, MAX_BLOCK_GAS, |t| {
                if sharded && !crate::sharding::tx_belongs_to_shard(t, my_shard) {
                    rej_shard.set(rej_shard.get() + 1);
                    return false;
                }
                let is_cross = sharded && crate::sharding::tx_is_outbound_cross_shard(t, my_shard);
                if is_cross && used_senders.borrow().contains(&t.from) {
                    rej_shard.set(rej_shard.get() + 1);
                    return false;
                }
                // Session-key delegation policy against THIS block's
                // timestamp (the deterministic clock): expiry, scope, value
                // cap and remaining budget. The exact same predicate the
                // apply path re-checks, so a proposer never selects a
                // transaction execution would refuse — and a plain (legacy)
                // transaction passes unconditionally.
                if t.check_session_policy(timestamp).is_err() {
                    rej_session.set(rej_session.get() + 1);
                    return false;
                }
                // ...joined by the registry: a revoked key is refused here
                // exactly as it is refused at admission and at execution, and
                // this block's own in-flight session spend counts against the
                // budget the same way the apply path's simulation does.
                if let Some(d) = t.delegation() {
                    // Same single definition the apply path uses (including
                    // the actor-mailbox scope), so a proposer can never select
                    // a transaction execution would refuse for scope.
                    let required_scope = t.required_scope();
                    if session_keys
                        .check(
                            &d,
                            t.amount,
                            t.gas_limit,
                            required_scope,
                            timestamp,
                            &mut session_sim.borrow_mut(),
                        )
                        .is_err()
                    {
                        rej_session.set(rej_session.get() + 1);
                        return false;
                    }
                }
                let Some(&(expected, balance)) = next_nonce.borrow().get(&t.from) else {
                    // No account means no balance, so it cannot pay.
                    rej_noacct.set(rej_noacct.get() + 1);
                    return false;
                };
                if t.nonce != expected {
                    rej_nonce.set(rej_nonce.get() + 1);
                    return false;
                }
                // Failure-penalized floor (D2): below-floor transactions never
                // clear admission, so packing one only wastes block space.
                // Skipped, not rejected, like every other filter condition.
                // PQ activation surcharge: admission (`effective_floor_for_tx`,
                // mempool.rs) refuses activation txs below base + penalty +
                // PQ_ACTIVATION_SURCHARGE_GAS, so the pack filter must mirror
                // it or the proposer packs txs that price differently at
                // apply (wasted space feeding the D2 free-failure loop).
                // SKIP-only like the floor itself: selection stays a pure
                // function of the same inputs on every node, and block
                // validity rules are untouched (no consensus change).
                let floor = base_fee
                    .saturating_add(penalty_floors.get(&t.from).copied().unwrap_or(0))
                    .saturating_add(if t.is_pq_activation() {
                        crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                    } else {
                        0
                    });
                if t.gas_limit < floor {
                    rej_basefee.set(rej_basefee.get() + 1);
                    return false;
                }
                // F-07: the pack balance check mirrors admission execution
                // (amount + gas_limit + PQ surcharge for activation txs), or
                // the proposer packs txs execution must refuse (wasted space).
                let cost = t.amount.saturating_add(t.gas_limit).saturating_add(if t.is_pq_activation() {
                    crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                } else {
                    0
                });
                if balance < cost {
                    rej_funds.set(rej_funds.get() + 1);
                    return false;
                }
                // Accepting it advances this sender's nonce and debits its budget.
                next_nonce.borrow_mut().insert(t.from, (expected + 1, balance - cost));
                used_senders.borrow_mut().insert(t.from);
                true
            });
        let mempool_len = self.mempool.read().await.len();
        // Empty block with a non-empty mempool is the shape to watch (usually
        // a per-sender nonce gap: filter needs exact nonces, evict keeps
        // future ones by design): log it at info, the rest at debug.
        if txs.is_empty() && mempool_len > 0 {
            tracing::info!(
                "propose h={} r={} shard={}: path=fresh selected=0 mempool={} (noacct={} nonce={} funds={} session={} shardfilter={} basefee={})",
                self.hc.height,
                self.hc.round,
                self.shard_id,
                mempool_len,
                rej_noacct.get(),
                rej_nonce.get(),
                rej_funds.get(),
                rej_session.get(),
                rej_shard.get(),
                rej_basefee.get(),
            );
        } else {
            tracing::debug!(
                "propose h={} r={} shard={}: path=fresh selected={} mempool={}",
                self.hc.height,
                self.hc.round,
                self.shard_id,
                txs.len(),
                mempool_len,
            );
        }
        // MEV blind-round unseal gate: a transaction sealed at admission must
        // unseal to EXACTLY the bytes we are about to execute. Anything whose
        // envelope fails to open or whose pool copy no longer matches the
        // ciphertext is dropped here — fail closed, before it can waste block
        // space on a body every validator would reject. Transactions admitted
        // without an envelope (restored pools) pass through unchanged.
        let txs = {
            let pool = self.mempool.read().await;
            // The unseal check is a pure function of (envelope, transaction):
            // decrypt plus a byte-compare, with no shared mutation. Large
            // blocks therefore verify it across cores while the kept set, its
            // order and every verdict stay exactly the sequential ones (the
            // parallel pass returns verdicts in input order; filtering and the
            // drop warnings below run sequentially). Small blocks skip the
            // thread-pool round trip and run the original loop.
            const PARALLEL_UNSEAL_MIN_TXS: usize = 512;
            let selected_n: usize;
            let kept = if txs.len() >= PARALLEL_UNSEAL_MIN_TXS {
                use rayon::prelude::*;
                let checked: Vec<(Transaction, crate::mev::SealVerdict)> = txs
                    .into_par_iter()
                    .map(|tx| {
                        let verdict = pool.mev.verify_pool_tx(&tx);
                        (tx, verdict)
                    })
                    .collect();
                selected_n = checked.len();
                let mut kept = Vec::with_capacity(checked.len());
                for (tx, verdict) in checked {
                    match verdict {
                        crate::mev::SealVerdict::Match | crate::mev::SealVerdict::NotSealed => {
                            kept.push(tx)
                        }
                        _ => {
                            tracing::warn!(
                                tx = %hex::encode(tx.compute_tx_hash()),
                                ?verdict,
                                "propose: dropping transaction that failed the blind-round unseal gate"
                            );
                        }
                    }
                }
                kept
            } else {
                selected_n = txs.len();
                let mut kept = Vec::with_capacity(txs.len());
                for tx in txs {
                    match pool.mev.verify_pool_tx(&tx) {
                        crate::mev::SealVerdict::Match | crate::mev::SealVerdict::NotSealed => {
                            kept.push(tx)
                        }
                        verdict => {
                            tracing::warn!(
                                tx = %hex::encode(tx.compute_tx_hash()),
                                ?verdict,
                                "propose: dropping transaction that failed the blind-round unseal gate"
                            );
                        }
                    }
                }
                kept
            };
            // Post-unseal recount (audit: blocks troubles): the census above
            // counts SELECTED, but the gate can only shrink. Without this line
            // an emptied-by-unseal block looked identical to an empty mempool.
            if kept.len() != selected_n {
                tracing::info!(
                    "propose h={} r={} shard={}: unseal gate dropped {} of {} selected",
                    self.hc.height,
                    self.hc.round,
                    self.shard_id,
                    selected_n - kept.len(),
                    selected_n
                );
            }
            kept
        };
        let prev_hash = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        // Validation-layer close of the actor-mailbox gap (propose side): the
        // engine's mailbox pass is a defensive clamp — whatever is still
        // queued when `MAX_ACTOR_MSGS_PER_BLOCK` (or the round bound) runs out
        // stays for a later block, but inboxes are NOT trie state, so that
        // leftover is invisible to the state root and two nodes can queue
        // different leftovers behind the same root. An over-cap block is
        // therefore never built: the backlog this block would add to what is
        // already queued must fit the cap, or there is no proposal this round
        // (fail closed; every validator rejects such a block below, so no
        // honest node can be split by one).
        {
            let backlog = self.pending_actor_backlog().await;
            let sends: usize = txs
                .iter()
                .map(|t| count_program_sends(&t.payload))
                .fold(0usize, |acc, n| acc.saturating_add(n));
            if backlog.saturating_add(sends) > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK {
                tracing::warn!(
                    "propose h={}: refusing to build an over-cap actor block ({} queued + {} in block)",
                    self.hc.height,
                    backlog,
                    sends,
                );
                return None;
            }
        }
        // Cross-shard commit records for this block. In a sharded process a
        // block carries BOTH directions in the one existing `cross_shard_out`
        // field:
        //   * OUTBOUND (source == this shard): one record per outbound
        //     transfer selected above, with a Merkle proof of the sender's
        //     pre-block leaf and the pre-block balance. Applying the block
        //     debits the sender here; the record is what lets the target mint.
        //   * INBOUND (target == this shard): messages pulled from the
        //     node-local KV, filtered against what this chain already
        //     consumed, each carrying its source inclusion proof. Applying the
        //     block credits each recipient exactly once.
        let mut cross_shard_out: Vec<CrossShardMessage> = Vec::new();
        if sharded {
            for tx in &txs {
                if !crate::sharding::tx_is_outbound_cross_shard(tx, my_shard) {
                    continue;
                }
                let balance = self
                    .state
                    .get_account(&tx.from)
                    .await
                    .map(|a| a.balance)
                    .unwrap_or(0);
                let proof = self.state.get_account_proof(&tx.from).await;
                let msg = CrossShardMessage::new(
                    my_shard,
                    tx.target_shard,
                    tx.clone(),
                    state_root,
                    prev_hash,
                    proof,
                )
                .with_source_balance(balance);
                cross_shard_out.push(msg);
            }
                if let Some(transport) = &self.cross_shard {
                let mut inbound = transport.fetch_cross_shard_inbound(my_shard).await;
                // Deterministic order, independent of KV enumeration order.
                inbound.sort_by_key(CrossShardKey::of);
                let mut engine_hit_ids: Vec<[u8; 32]> = Vec::new();
                for msg in inbound {
                    if !msg.is_inbound_for(my_shard) {
                        continue;
                    }
                    let key = CrossShardKey::of(&msg);
                    if self.consumed_cross_shard.contains(&key) {
                        continue;
                    }
                    // Belt beyond the runtime mirrors: the PERSISTED engine
                    // set survives restarts (audit F-I) while the mirrors may
                    // be empty (fresh process). If the engine already credited
                    // this key, prune it from the mailbox so no future propose
                    // wastes a round on it, and skip it now. Without the prune
                    // a restarted proposer would re-propose it forever (its
                    // mirrors are empty) while every apply refuses it.
                    if self.state.is_cross_shard_consumed(&key).await {
                        engine_hit_ids.push(msg.msg_id);
                        continue;
                    }
                    // §5 M3 kind-dispatched admission: transfers prove
                    // inclusion against the source root; acks/bounces prove
                    // linkage to a committed outbound on this chain (plus the
                    // height timeout for bounces). Anything else fails closed.
                    if msg.is_ack() || msg.is_bounce() {
                        if !self.control_linkage_ok(&msg, self.hc.height) {
                            continue;
                        }
                    } else if msg.is_transfer() {
                        // C1 anchored (not just proof-checked): the root must
                        // be a locally-finalized source header, or the message
                        // waits for a later block (NOT-READY, not verified).
                        if !self.verify_cross_shard_anchored(&msg) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    // Stale after completion: the transaction already acked or
                    // bounced (e.g. a late duplicate lingering in the KV).
                    if self.completed_cross_shard.contains(&msg.tx.compute_tx_hash()) {
                        continue;
                    }
                    if cross_shard_out.iter().any(|m| m.msg_id == msg.msg_id) {
                        continue;
                    }
                    cross_shard_out.push(msg);
                }
                if !engine_hit_ids.is_empty() {
                    transport.prune_consumed(my_shard, &engine_hit_ids).await;
                }
                // §5 M3 timeout bounces: outbounds this chain produced that
                // never completed and aged past the height timeout are
                // refunded by committing a bounce-back record. Deterministic
                // in (tx hash, height): every node builds the same record for
                // the same chain, and `validate_proposal` re-checks the rule.
                let mut expired: Vec<([u8; 32], Transaction)> = self
                    .produced_cross_shard
                    .iter()
                    .filter(|(tx_hash, (_, hp))| {
                        !self.completed_cross_shard.contains(*tx_hash)
                            && crate::sharding::bounce_eligible(*hp, self.hc.height)
                    })
                    .map(|(tx_hash, (tx, _))| (*tx_hash, tx.clone()))
                    .collect();
                expired.sort_by_key(|(tx_hash, _)| *tx_hash);
                for (tx_hash, tx) in expired {
                    if cross_shard_out
                        .iter()
                        .any(|m| m.tx.compute_tx_hash() == tx_hash)
                    {
                        continue;
                    }
                    cross_shard_out.push(CrossShardMessage::new_bounce(tx, prev_hash));
                }
            }
        }
        let timestamp = if let Some(parent_ts) = self
            .blocks
            .get(&prev_hash)
            .map(|b| b.timestamp)
            .or_else(|| {
                self.last_decision.as_ref().and_then(|(h, b, _)| {
                    if *h + 1 == self.hc.height && b.compute_hash() == prev_hash {
                        Some(b.timestamp)
                    } else {
                        None
                    }
                })
            })
        {
            timestamp
                .min(parent_ts.saturating_add(MAX_TIMESTAMP_JUMP_SECS))
                .max(parent_ts)
        } else {
            timestamp
        };
        let mut block = Block {
            shard_id: self.shard_id,
            height: self.hc.height,
            prev_hash,
            state_root,
            transactions: txs,
            cross_shard_out,
            timestamp,
            proposer: self.id,
            validator_signatures: vec![],
            precommit_qc: None,
        };
        // Sign the proposer slot with whichever signer is configured. `sign_block`
        // signs with an in-process key, so when a remote signer is present the
        // signature is produced out of process and pushed directly.
        // One hash for both the proposer signature and the order-commit /
        // block-store keys below: `compute_hash` intentionally excludes
        // `validator_signatures` (and `precommit_qc`), so pushing our own
        // signature cannot move it. Recomputing it would re-hash all 10k
        // transaction hashes (~25ms at MAX_BLOCK_TXS) for an identical value.
        let proposal_msg = block.compute_hash();
        if let Some(sig) = self.sign_bytes(&proposal_msg) {
            block.validator_signatures.push((self.id, sig));
        } else {
            return None; // no signer, no proposal
        }
        let fk_ref = self.falcon_signing_key();
        if let Some(fk) = fk_ref {
            let falcon_sig = fk.sign(&proposal_msg);
            let falcon_id = fk.validator_id();
            block.validator_signatures.push((falcon_id, falcon_sig));
        }
        // Proposer-side pre-gossip size check (packing/visibility only, no
        // consensus change): the `select_multi` wire estimate (~24MB) leaves
        // headroom under `MAX_CONSENSUS_MSG` (32MB), but it is an ESTIMATE, so
        // a block can still encode oversize and die in `broadcast_singles`
        // (silently dropped, height stalls with a full mempool). Check the
        // EXACT `ConsensusMsg::Proposal` encoding here and fall back to a
        // smaller block — drop fattest txs first — instead of proposing
        // un-sendable bytes. Trimming only shrinks `transactions` (and the
        // outbound cross-shard records that name dropped txs); it never
        // reorders, never touches apply/consensus logic.
        {
            let cap = crate::consensus_net::MAX_CONSENSUS_MSG;
            let mut encoded_len = crate::consensus_net::ConsensusMsg::Proposal {
                height: self.hc.height,
                round: self.hc.round,
                block: block.clone(),
            }
            .encode()
            .map(|b| b.len())
            .unwrap_or(usize::MAX);
            if encoded_len > cap {
                let orig_txs = block.transactions.len();
                // Fattest-first: indices by descending estimated wire bytes.
                let mut order: Vec<usize> = (0..block.transactions.len()).collect();
                order.sort_by_key(|&i| {
                    std::cmp::Reverse(Mempool::estimate_tx_wire_bytes(&block.transactions[i]))
                });
                let mut drop: Vec<bool> = vec![false; block.transactions.len()];
                let mut dropped = 0usize;
                for &i in &order {
                    if encoded_len <= cap {
                        break;
                    }
                    drop[i] = true;
                    dropped += 1;
                    // Re-encode the candidate survivor set each drop. O(drops)
                    // encodes, but this path only runs when the estimate
                    // already failed, i.e. essentially never on healthy blocks.
                    let kept: Vec<crate::sharding::Transaction> = block
                        .transactions
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| !drop[*j])
                        .map(|(_, t)| t.clone())
                        .collect();
                    let probe = Block {
                        transactions: kept,
                        ..block.clone()
                    };
                    encoded_len = crate::consensus_net::ConsensusMsg::Proposal {
                        height: self.hc.height,
                        round: self.hc.round,
                        block: probe,
                    }
                    .encode()
                    .map(|b| b.len())
                    .unwrap_or(usize::MAX);
                }
                if encoded_len > cap {
                    // Even empty-of-txs is un-sendable (giant inbound
                    // cross-shard section). Fail closed: no proposal this
                    // round rather than bytes no peer can receive.
                    tracing::error!(
                        "propose h={} r={}: pre-gossip fallback FAILED ({} txs, {} bytes > {} cap even empty); proposing nothing",
                        self.hc.height,
                        self.hc.round,
                        orig_txs,
                        encoded_len,
                        cap,
                    );
                    return None;
                }
                let dropped_hashes: std::collections::HashSet<[u8; 32]> = block
                    .transactions
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| drop[*j])
                    .map(|(_, t)| t.compute_tx_hash())
                    .collect();
                let mut kept_txs = Vec::with_capacity(orig_txs - dropped);
                for (j, t) in block.transactions.into_iter().enumerate() {
                    if !drop[j] {
                        kept_txs.push(t);
                    }
                }
                block.transactions = kept_txs;
                // Outbound records naming a dropped tx would burn value with
                // nobody able to claim it (validate rejects tx-without-record
                // only in the outbound direction; the reverse — record without
                // tx — is equally unclaimable). Prune them with the txs.
                block.cross_shard_out.retain(|m| {
                    !dropped_hashes.contains(&m.tx.compute_tx_hash())
                });
                // The body changed, so the proposer signature must be remade
                // over the new hash (same rule as the fresh path above).
                block.validator_signatures.clear();
                let new_msg = block.compute_hash();
                if let Some(sig) = self.sign_bytes(&new_msg) {
                    block.validator_signatures.push((self.id, sig));
                } else {
                    return None;
                }
                let fk_ref = self.falcon_signing_key();
                if let Some(fk) = fk_ref {
                    let falcon_sig = fk.sign(&new_msg);
                    let falcon_id = fk.validator_id();
                    block.validator_signatures.push((falcon_id, falcon_sig));
                }
                let final_len = crate::consensus_net::ConsensusMsg::Proposal {
                    height: self.hc.height,
                    round: self.hc.round,
                    block: block.clone(),
                }
                .encode()
                .map(|b| b.len())
                .unwrap_or(usize::MAX);
                tracing::error!(
                    "propose h={} r={}: pre-gossip fallback SHRANK block {} -> {} txs ({} bytes now, cap {}); dropped fattest first, survivors kept in order",
                    self.hc.height,
                    self.hc.round,
                    orig_txs,
                    block.transactions.len(),
                    final_len,
                    cap,
                );
            }
        }
        // MEV order commitment at build: record (and sign) the exact execution
        // order BEFORE the block is proposed or voted on. `try_finalize`
        // re-verifies this commitment against the block it is about to apply,
        // so this node never executes an order it did not commit to build.
        // NOTE: recomputed AFTER the pre-gossip fallback above (which may have
        // shrunk the body and re-signed it); `compute_hash` excludes the
        // signatures, so this equals `proposal_msg` on the untrimmed path.
        let bh = block.compute_hash();
        {
            let mut pool = self.mempool.write().await;
            pool.mev.commit_block_order(
                self.hc.height,
                bh,
                &block.transactions,
                &[self.key.clone()],
            );
        }
        self.blocks.insert(bh, block.clone());
        self.hc.receive_proposal(self.id, bh).ok()?;
        Some(block)
    }

    /// Validate a proposed block before accepting/prevoting it.
    /// SECURITY: rejects wrong height/proposer/prev_hash, oversized blocks and
    /// transactions with bad signatures.
    ///
    /// `expected_state_root` is OUR current root. The block header commits to the
    /// state it builds on - the root after the previous block, which is the
    /// standard convention and is what lets a chain be walked without replaying
    /// it - so that value is checkable, and it was not being checked at all. A
    /// proposer could put any root in the header and every validator accepted the
    /// block, which left the whole state commitment decorative on the live path.
    /// Fail-closed block-timestamp gate (A3): refuse on a bad or missing
    /// timestamp using deterministic rules only.
    ///
    /// The parent timestamp resolves from, in order: (1) the stored parent
    /// body (`blocks[prev_hash]`, the common live case); (2) `last_decision`
    /// when it names exactly this parent (hash AND height match, so a stale
    /// decision from an older height can never vouch for a new parent);
    /// (3) the zero parent of a height-1 block (`prev_hash == [0; 32]`
    /// anchors at 0). Anything else — a parent this node never saw — is
    /// refused rather than skipped: accepting first and hoping the parent
    /// turns up is the fail-open this closes.
    ///
    /// Pure function of (`self.blocks`, `self.last_decision`, `block`): no
    /// wall clock, so every validator derives the same verdict. Called on the
    /// proposal path AND the adopt path, so a Byzantine commit cannot smuggle
    /// past the decision boundary a timestamp no proposer could publish.
    fn check_block_timestamp(&self, block: &Block) -> Result<(), String> {
        if block.height == 0 {
            return Ok(()); // genesis carries no parent; nothing to be monotone against
        }
        if block.timestamp == 0 {
            return Err("proposal: missing block timestamp".to_string());
        }
        // Whether the parent resolved to the zero-genesis anchor rather than a
        // seen body: the first block after genesis legitimately jumps from the
        // anchor to the proposer's wall clock (billions of seconds), so the
        // forward jump bound below cannot apply to it. Monotonicity still
        // holds (any non-zero timestamp is past the anchor).
        let mut from_genesis_anchor = false;
        let parent_ts = self
            .blocks
            .get(&block.prev_hash)
            .map(|b| b.timestamp)
            .or_else(|| {
                self.last_decision.as_ref().and_then(|(h, b, _)| {
                    if *h + 1 == block.height && b.compute_hash() == block.prev_hash {
                        Some(b.timestamp)
                    } else {
                        None
                    }
                })
            })
            .or_else(|| {
                if block.prev_hash == [0u8; 32] {
                    from_genesis_anchor = true;
                    Some(0)
                } else {
                    None
                }
            });
        let Some(parent_ts) = parent_ts else {
            return Err("proposal: unknown parent timestamp (fail-closed)".to_string());
        };
        if block.timestamp < parent_ts {
            return Err("proposal: timestamp moved backwards".to_string());
        }
        if !from_genesis_anchor
            && block.timestamp > parent_ts.saturating_add(MAX_TIMESTAMP_JUMP_SECS)
        {
            return Err("proposal: timestamp too far ahead of parent".to_string());
        }
        Ok(())
    }

    /// Round-INDEPENDENT proposal checks: everything `validate_proposal` verifies
    /// except which round's proposer slot the block claims. Used by `on_proposal`
    /// to prove a block is genuine (signed by its declared proposer, building on
    /// our state) BEFORE any round alignment happens: aligning first and asking
    /// questions later would let a forged envelope shove us +64 rounds per
    /// message, wiping our live proposal each time -- a round-DoS.
    fn validate_proposal_unaligned(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
    ) -> Result<(), String> {
        if block.height != self.hc.height {
            return Err("proposal: wrong height".to_string());
        }
        // TIMESTAMP VALIDITY (A3, fail-closed): the proposer timestamp is
        // hashed into the block and used as the VM's "now" (session expiry,
        // unbonding, order stamps) — an unbounded proposer could skew all of
        // them. Both bounds are deterministic functions of (parent, child):
        // (a) monotone vs the parent block's timestamp (agreed state, no
        // clock involved); (b) at most MAX_TIMESTAMP_JUMP_SECS ahead of the
        // parent. There is deliberately NO wall-clock read here: a
        // `now_secs()` bound makes the verdict node-local (two validators
        // with skewed clocks disagree about the same block), and there is no
        // grace or skip path — a bad or unresolvable timestamp is refused.
        self.check_block_timestamp(block)?;
        // SHARD SCOPE (gated): in a multi-shard process each consensus instance
        // only accepts blocks for its own shard, and only transactions it OWNS
        // (`source_shard == this shard`). That covers same-shard transfers and
        // OUTBOUND cross-shard transfers; the destination receives value through
        // a committed consumption record, never through `transactions`.
        // Single-shard mode skips all of this, so the historical masterchain
        // blocks that carry source=1/target=1 txs still validate.
        if self.shard_registry.is_sharded() {
            if block.shard_id != self.shard_id {
                return Err(format!(
                    "proposal: wrong shard {} (expected {})",
                    block.shard_id, self.shard_id
                ));
            }
            if let Some(bad) = block
                .transactions
                .iter()
                .find(|t| !crate::sharding::tx_belongs_to_shard(t, self.shard_id))
            {
                return Err(format!(
                    "proposal: transaction targets shard {} not {}",
                    bad.source_shard, self.shard_id
                ));
            }
            // Cross-shard commit consistency: every OUTBOUND message must name a
            // transaction actually in this block (so the debit happens), and
            // every INBOUND consumption record must prove inclusion against the
            // source root and must not be a replay of a message already
            // credited on this chain.
            for msg in &block.cross_shard_out {
                if msg.is_outbound_for(self.shard_id) {
                    let tx_present = block
                        .transactions
                        .iter()
                        .any(|t| t.compute_tx_hash() == msg.tx.compute_tx_hash());
                    if !tx_present {
                        return Err(
                            "proposal: outbound cross-shard message has no transaction in the block"
                                .to_string(),
                        );
                    }
                    continue;
                }
                if msg.is_inbound_for(self.shard_id) {
                    let key = CrossShardKey::of(msg);
                    if self.consumed_cross_shard.contains(&key) {
                        return Err(format!(
                            "proposal: replayed cross-shard message {}",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                    // §5 M3 kind-dispatched validation (mirrors `propose`):
                    // transfers prove inclusion; acks/bounces prove linkage
                    // to a committed outbound (+ timeout for bounces); a
                    // record for an already-completed transaction is stale.
                    if msg.is_ack() || msg.is_bounce() {
                        if !self.control_linkage_ok(msg, block.height) {
                            return Err(format!(
                                "proposal: cross-shard ack/bounce {} fails linkage/timeout",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                    } else if msg.is_transfer() {
                        if !self.verify_cross_shard_anchored(msg) {
                            return Err(format!(
                                "proposal: cross-shard message {} fails anchored inclusion (uncommitted source root or unfinalized source block)",
                                hex::encode(&msg.msg_id[..8])
                            ));
                        }
                    } else {
                        return Err(format!(
                            "proposal: cross-shard message {} has an unknown kind",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                    if self.completed_cross_shard.contains(&msg.tx.compute_tx_hash()) {
                        return Err(format!(
                            "proposal: cross-shard message {} is for a completed transfer",
                            hex::encode(&msg.msg_id[..8])
                        ));
                    }
                }
            }
            // The reverse direction too: an outbound cross-shard transaction
            // with no committed message would burn the value with nobody able
            // to claim it. Require the pair.
            for tx in &block.transactions {
                if !crate::sharding::tx_is_outbound_cross_shard(tx, self.shard_id) {
                    continue;
                }
                let committed = block.cross_shard_out.iter().any(|m| {
                    m.is_outbound_for(self.shard_id)
                        && m.tx.compute_tx_hash() == tx.compute_tx_hash()
                });
                if !committed {
                    return Err(
                        "proposal: outbound cross-shard transaction has no committed message"
                            .to_string(),
                    );
                }
            }
        }
        if block.state_root != expected_state_root {
            return Err(format!(
                "proposal: state root {} does not match our state {}",
                hex::encode(block.state_root),
                hex::encode(expected_state_root)
            ));
        }
        // Authenticity: the block must actually be signed by its declared
        // proposer, otherwise a peer could propose on another validator's behalf.
        if !crate::consensus::verify_proposer_signature(block) {
            return Err("proposal: invalid or missing proposer signature".to_string());
        }
        let expected_prev = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        if block.prev_hash != expected_prev {
            return Err("proposal: wrong prev_hash (not chained to finalized head)".to_string());
        }
        if block.transactions.len() > MAX_BLOCK_TXS {
            return Err("proposal: block too large".to_string());
        }
        // Actor-mailbox cap, block-static half (no state read, so it stays in
        // the synchronous validator): a block whose OWN sends already exceed
        // `MAX_ACTOR_MSGS_PER_BLOCK` can never drain-to-empty and is rejected
        // here. The backlog-inclusive half is checked by the async callers
        // (`on_proposal`, `adopt_committed`, `propose`), which agree with this
        // whenever the backlog is empty.
        if block_actor_sends_exceed_cap(block) {
            return Err(format!(
                "proposal: actor mailbox over cap ({} sends in block > {})",
                count_block_actor_sends(block),
                crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
            ));
        }
        let total_gas = block
            .transactions
            .iter()
            .fold(0u64, |acc, t| acc.saturating_add(t.gas_limit));
        if total_gas > MAX_BLOCK_GAS {
            return Err("proposal: block gas limit exceeded".to_string());
        }
        // Batched Ed25519 verification: much faster than one-by-one for a full block.
        if !Transaction::verify_signatures_batch(&block.transactions) {
            return Err("proposal: bad transaction signature".to_string());
        }
        // F-01 CONSENSUS FEE FLOOR (fail-closed, cheap, before execution):
        // admission (`Mempool::insert`) and the honest proposer filter both
        // refuse `gas_limit` below the effective floor, but neither binds a
        // Byzantine proposer — and until now neither did this function, so a
        // custom-built block of valid-signature underpriced (or zero-fee)
        // transactions was accepted and executed by every honest validator,
        // with failures paying nothing. Refuse such blocks here.
        //
        // The verdict is THE single admission helper
        // (`Mempool::effective_floor_for_tx`: base + D2 failure penalty + PQ
        // activation surcharge where applicable), so the formula cannot drift
        // from admission. It reads this validator's mempool floor state via a
        // non-blocking lock: a contended pool fails CLOSED (the block is
        // refused, not skipped) rather than executing underpriced work. An
        // empty block passes vacuously.
        //
        // CONSENSUS NOTE: the base here is the admission base (`max(env,
        // governed)`, synced every finalize); the apply path charges the
        // governed base (see `consensus_floor_parts`) — the env half is
        // node-local config and cannot move consensus. Validate is therefore
        // never looser than apply: anything apply would up-charge is either
        // refused here or arrives declaring at least the floor. The penalty
        // half converges across honest nodes that finalized the same chain
        // (identical verdict feeds in identical order); a node whose mempool
        // missed feedback (reorg/sync paths feed nothing) holds a LOWER floor
        // and may accept what peers refuse — fail-open for that node only,
        // never a network split, and closed the moment its live path
        // re-feeds. Coordinated rollout: all validators run the identical
        // floor config, exactly like admission today.
        {
            let pool = self
                .mempool
                .try_read()
                .map_err(|_| "proposal: fee floor unavailable (fail-closed)".to_string())?;
            // Snapshot once for the diagnostic breakdown below; the verdict
            // itself comes from the single helper (cannot drift).
            let penalty_snapshot = pool.penalty_snapshot();
            for tx in &block.transactions {
                let floor = pool.effective_floor_for_tx(tx);
                if tx.gas_limit < floor {
                    let surcharge = if tx.is_pq_activation() {
                        crate::mempool::PQ_ACTIVATION_SURCHARGE_GAS
                    } else {
                        0
                    };
                    return Err(format!(
                        "proposal: tx {} from {} below fee floor (gas_limit {} < floor {} = base {} + penalty {} + pq_surcharge {})",
                        hex::encode(tx.compute_tx_hash()),
                        hex::encode(&tx.from[..6]),
                        tx.gas_limit,
                        floor,
                        pool.base_fee,
                        penalty_snapshot.get(&tx.from).copied().unwrap_or(0),
                        surcharge,
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn validate_proposal(
        &self,
        block: &Block,
        expected_state_root: [u8; 32],
    ) -> Result<(), String> {
        self.validate_proposal_unaligned(block, expected_state_root)?;
        if Some(block.proposer) != self.hc.proposer() {
            return Err("proposal: wrong proposer".to_string());
        }
        Ok(())
    }

    /// Record a peer's lock hint from a nil prevote: "I am stuck on the block
    /// `hint`, which you authored -- re-propose it". Only nil prevotes at our
    /// height qualify, and only hints naming OUR bodies for THIS height are
    /// kept (anything else is another author's turn, or junk). Bounded and
    /// height-scoped; serving is one-shot per hint (see `propose`).
    pub fn note_lock_hint(
        &mut self,
        vote_height: Height,
        kind: VoteKind,
        target: Option<BlockHash>,
        hint: Option<BlockHash>,
    ) {
        if vote_height != self.hc.height || kind != VoteKind::Prevote || target.is_some() {
            return;
        }
        let Some(h) = hint else { return };
        if self.demanded_height != self.hc.height {
            self.demanded.clear();
            self.demanded_height = self.hc.height;
        }
        let ours = self
            .blocks
            .get(&h)
            .is_some_and(|b| b.proposer == self.id && b.height == self.hc.height);
        if !ours {
            return;
        }
        const MAX_DEMANDED: usize = 8;
        if self.demanded.len() >= MAX_DEMANDED && !self.demanded.contains(&h) {
            return;
        }
        self.demanded.insert(h);
    }

    /// Record a peer's SIGNED round. Returns true when we moved.
    ///
    /// Syncs ONLY when the peer is FAR ahead (more than 3 rounds): bounded
    /// catch-up for a node that fell behind. A peer within 3 rounds is normal
    /// operation -- our own timeout steps us there within seconds, and jumping
    /// early gains nothing: each near jump wipes the accepted proposal (or
    /// abandons the round), and at message rates the +1..+3 nudges compound
    /// into a round-number explosion (observed live: r9700 with zero QCs,
    /// both nodes leapfrogging past every proposal). The view-change hold
    /// separately keeps near nodes in phase, and proposal-acceptance carries
    /// its own atomic align (a sync that brings its proposal can never strand
    /// us proposalless). Far jumps are self-limiting: landing near stops
    /// further syncing.
    pub fn note_peer_vote_round(&mut self, vote_height: Height, vote_round: Round) -> bool {
        // Any verified lead pulls us up -- including 1 round. Callers invoke this
        // only AFTER `Vote::verify` + membership (see the F2 fix in the drain),
        // and `sync_round_to` is capped at ROUND_LOOKBACK=8, so this cannot be
        // used for the round explosion we saw from unverified votes with a +64
        // cap. Suppressing near (1-3 round) sync instead left a PERSISTENT
        // one-round offset between two honest nodes: they prevoted the SAME
        // value at r15 and r16, so no same-round QC could ever form and each
        // height burned ~10 rounds (30s+). The behind node must follow.
        //
        // (A sit-while-armed variant was tried for 3-member WAN liveness and
        // reverted: refusing near jumps while holding a proposal deadlocks two
        // armed nodes on different rounds AND breaks the pinned
        // `round_nudge_reopens_gate_once_not_per_tick` convergence. The
        // 3-racer leapfrog cascade stays a known open issue for ≥3 WAN-skewed
        // equal-power members; the fix there is quorum-gated jumps (≥2
        // distinct voters), not unilateral sitting.)
        if vote_height != self.hc.height || vote_round <= self.hc.round {
            return false;
        }
        let before = self.hc.round;
        self.hc.sync_round_to(vote_round);
        self.hc.round != before
    }

    /// Feed a (possibly stale/absurd) peer vote into round-sync WITHOUT voting
    /// (deadlock fix 2026-10-14).
    ///
    /// Verifies the vote (signature + validator membership) and requires
    /// `vote.height == hc.height`; on success records the peer's round via
    /// `HeightConsensus::observe_peer_round` (counter only, bounded
    /// `sync_round_to` chase). Returns true when our round moved. A vote for
    /// a stale round or beyond `MAX_ROUND_AHEAD` — both rejected by
    /// `on_prevote`/`on_precommit` — still teaches us the peer's round here,
    /// so a 1200-round desync collapses instead of being dropped both ways.
    pub fn observe_peer_vote(&mut self, vote: &Vote) -> bool {
        if vote.height != self.hc.height {
            return false;
        }
        if !vote.verify() {
            return false;
        }
        if self.validators.power_of(&vote.voter) == 0 {
            return false;
        }
        self.hc.observe_peer_round(vote.voter, vote.round)
    }

    /// Stamp finalization progress (call on every finalize/adopt).
    pub fn record_progress(&mut self) {
        self.last_progress_at = std::time::Instant::now();
    }

    /// Breaker timeout (`STELL_DEADLOCK_TIMEOUT_SECS`, default 300s).
    pub fn deadlock_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(crate::consensus::HeightConsensus::deadlock_timeout_secs())
    }

    /// Deadlock circuit breaker (live 2026-10-14: A r1550 vs B r318 at h92078).
    ///
    /// Fires only when ALL hold (fail-safe):
    ///  * no finalization progress for the timeout window,
    ///  * a verified peer round ahead of us exists (`max_peer_round`),
    ///  * the jump is forward-only, and at most once per timeout window.
    /// On fire, performs the bounded jump to `max(peer rounds)`, stamps the
    /// rate limit, logs LOUDLY (tracing + stderr), and returns the new round.
    /// The caller must reset its round timer so it does not view-change past
    /// the peer it just joined.
    pub fn check_deadlock_breaker(&mut self) -> Option<Round> {
        let timeout = Self::deadlock_timeout();
        if self.last_progress_at.elapsed() < timeout {
            return None;
        }
        if let Some(last) = self.last_breaker_at {
            if last.elapsed() < timeout {
                return None;
            }
        }
        let no_progress_secs = self.last_progress_at.elapsed().as_secs();
        let timeout_secs = timeout.as_secs().max(1);
        let target = self.hc.deadlock_breaker_target(no_progress_secs, timeout_secs)?;
        let from = self.hc.round;
        if !self.hc.apply_deadlock_jump(target) {
            return None;
        }
        self.last_breaker_at = Some(std::time::Instant::now());
        tracing::error!(
            height = self.hc.height,
            from_round = from,
            to_round = target,
            no_progress_secs,
            "DEADLOCK-BREAKER: no finalization, jumping round forward to max(peer rounds)"
        );
        eprintln!(
            "[consensus][DEADLOCK-BREAKER] h={} r{} -> r{} after {}s without finalization (timeout {}s)",
            self.hc.height, from, target, no_progress_secs, timeout_secs
        );
        Some(target)
    }

    /// Receive a proposal from the (correct) proposer for the current round.
    pub async fn on_proposal(
        &mut self,
        proposer: ValidatorId,
        block: Block,
        envelope_round: Round,
    ) -> Result<BlockHash, String> {
        // §7 Phase 2 gate: the header's root check below reads OUR root, which
        // is PRE-H while a decided block is still executing. Checking now
        // would compare the proposal against the wrong parent state (a valid
        // H+1 proposal looks corrupt, a stale one looks fine), so the
        // proposal is deferred, not validated, until the worker reports back.
        // No state is read and none moves.
        if self.apply_in_flight.is_some() {
            return Err("proposal deferred: apply in flight".to_string());
        }
        // Read our root BEFORE accepting, so the header is checked against the
        // state the block would actually extend.
        let our_root = self.state.get_state_root().await;
        // Authenticity FIRST, before height/state checks: only the declared
        // proposer could have signed this, so a verified signature makes the
        // header's claims (height, prev_hash) attributable -- and worth
        // learning from even when we must refuse the block itself.
        if !crate::consensus::verify_proposer_signature(&block) {
            return Err("proposal: invalid or missing proposer signature".to_string());
        }
        // Record the peer head BEFORE any refusal below: a genuine proposal at
        // height H proves finalized H-1 even when it is not for us (wrong
        // height or round). Refused proposals previously taught us nothing, so
        // a node exactly one height behind never learned the head and spun in
        // view changes at its own height forever. Forgery is impossible here
        // (signature just verified); a Byzantine proposer advertising false
        // heads only triggers loudly-failing walks, bounded by caps.
        if block.height > 0 {
            let h = (block.height - 1, block.prev_hash);
            if self.peer_hint.map(|(ph, _)| ph < h.0).unwrap_or(true) {
                self.peer_hint = Some(h);
            }
        }
        // Prove the block genuine BEFORE any round alignment: a forged envelope
        // must never move our round (see `validate_proposal_unaligned`).
        self.validate_proposal_unaligned(&block, our_root)?;
        // Actor-mailbox cap, backlog-inclusive half (async: reads the engine).
        // The static half already ran inside `validate_proposal_unaligned`;
        // this adds what is already queued, so a block that fits on its own
        // but overflows on top of leftovers is still rejected deterministically
        // instead of carried over.
        self.check_actor_cap(&block).await?;
        // Freshness: the envelope round is the sender's claimed round. A
        // genuine body arriving LATE (delayed in transit) must not be adopted
        // as the current round's value: the proposer has moved on, the rest of
        // the network votes something else, and voting the stale body spends
        // our one vote on a quorum that can never form -- observed live as two
        // nodes voting different bodies at the same round for hundreds of
        // rounds. The envelope is only a freshness hint (it is unsigned), and
        // it is consulted strictly AFTER authentication: a forged envelope on
        // garbage dies above without moving anything; a forged envelope on a
        // genuine body is indistinguishable from network delay, which is
        // harmless (idempotent at worst).
        if envelope_round < self.hc.round {
            return Err("proposal: stale round".to_string());
        }
        // Phase-align: if the block is genuinely this height's proposer's work
        // but for a NEAR-FUTURE round, we are simply behind -- jump to the
        // earliest round this proposer owns and accept it there instead of
        // rejecting it as "wrong proposer" and then missing it forever (the
        // vote that would have synced us arrives after the proposal it should
        // have preceded). Bounded to near rounds: a far claim is answered by
        // the vote path, not by an unsigned envelope.
        if Some(block.proposer) != self.hc.proposer() {
            // Near-future phase alignment (widened +4 -> +8, see
            // `PROPOSAL_ALIGN_WINDOW_ROUNDS`: early delivery of a
            // GENUINE future proposal must align, not reject — the scan is
            // deliberate, pinned by test. Abuse is bounded elsewhere: the
            // jump runs through `sync_round_to`, which caps each jump at
            // ROUND_LOOKBACK and budgets 4 jumps/sec (audit 2026-10-06), and
            // the body is signature-authenticated before this point, so only
            // the slot owner can pull us to their own slots.
            let mut target = None;
            for r in (self.hc.round.saturating_add(1))..=(self.hc.round.saturating_add(PROPOSAL_ALIGN_WINDOW_ROUNDS)) {
                if self.validators.proposer_for(self.hc.height, r) == Some(block.proposer) {
                    target = Some(r);
                    break;
                }
            }
            match target {
                Some(r) => self.hc.sync_round_to(r),
                None => return Err("proposal: wrong proposer".to_string()),
            }
        }
        self.validate_proposal(&block, our_root)?;
        if block.proposer != proposer {
            return Err("proposal: proposer field mismatch".to_string());
        }
        let bh = block.compute_hash();
        self.hc.receive_proposal(proposer, bh)?;
        self.blocks.insert(bh, block);
        Ok(bh)
    }

    /// Our prevote for the current round (applies the safety lock).
    /// Read the staking ledger through the state engine. Same lock the engine
    /// commits, so reads always see committed state.
    pub async fn staking_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, crate::staking::StakingLedger> {
        self.state.staking_read().await
    }

    /// Write the staking ledger through the state engine, bumping the commitment
    /// generation so the state root cannot go stale.
    pub async fn staking_write(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, crate::staking::StakingLedger> {
        self.state.staking_write().await
    }

    /// Attach an out-of-process signer. Kept as a builder so every existing
    /// construction site (tests, simulator) is unaffected.
    ///
    /// Refuses a signer whose public key is not this node's identity. `self.id` is
    /// fixed at construction from `key` and is what the validator set and every vote's
    /// `voter` field are keyed on; a remote signer for a DIFFERENT key would produce
    /// signatures that verify against nothing (or worse, attribute a signature to the
    /// wrong validator), so it is rejected here rather than at vote time.
    pub fn with_remote_signer(
        mut self,
        signer: Arc<dyn crate::remote_signer::Signer>,
    ) -> Result<Self, String> {
        let remote_pk = signer.public_key();
        if remote_pk != self.id {
            return Err(format!(
                "remote signer key {} does not match this node's validator identity {}",
                hex::encode(&remote_pk[..8]),
                hex::encode(&self.id[..8])
            ));
        }
        self.remote_signer = Some(signer);
        Ok(self)
    }

    /// The public key this node votes with. For a remote signer this is the key the
    /// signer pinned at construction, so it is the same value `id` was set from.
    pub fn signer_public_key(&self) -> [u8; 32] {
        match &self.remote_signer {
            Some(s) => s.public_key(),
            None => self.key.verifying_key().to_bytes(),
        }
    }

    /// Produce a signature over `bytes`, via the remote signer when one is configured.
    ///
    /// Returns `None` on any signer failure. Deliberately NOT `unwrap_or`-style
    /// fallback to `self.key`: a node that believes its key is in an HSM while it
    /// quietly signs from a plaintext seed in its own heap is the exact failure this
    /// exists to prevent, so the caller must skip the vote instead.
    fn sign_bytes(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        match &self.remote_signer {
            Some(s) => match s.sign(bytes) {
                Ok(sig) => Some(sig.to_vec()),
                Err(e) => {
                    eprintln!("[signer] refusing to vote, remote signer failed: {e}");
                    None
                }
            },
            None => Some(self.key.sign(bytes).to_vec()),
        }
    }

    /// Build a vote signed by whichever signer is configured.
    fn make_vote(&self, kind: VoteKind, target: Option<BlockHash>) -> Option<Vote> {
        self.make_vote_at(kind, target, self.hc.round)
    }

    /// Build a vote stamped with an explicit round. Precommits use the round
    /// of the POLKA they follow, not the local round: the decision needs the
    /// prevote QC and the precommit QC in the SAME bucket, and the two nodes
    /// are routinely one round apart (60% of sampled time on the live stand).
    fn make_vote_at(
        &self,
        kind: VoteKind,
        target: Option<BlockHash>,
        round: Round,
    ) -> Option<Vote> {
        let msg = crate::consensus::vote_sign_bytes(self.hc.height, round, kind, &target);
        let sig = self.sign_bytes(&msg)?;
        let mut vote = Vote::signed_with(self.id, self.hc.height, round, kind, target, sig);

        let fk_ref = self.falcon_signing_key();
        if let Some(fk) = fk_ref {
            crate::consensus::attach_vote_falcon(fk, &msg, &mut vote.signature);
        }

        Some(vote)
    }

    pub fn make_prevote(&self) -> Option<Vote> {
        if self.hc.step != Step::Propose && self.hc.step != Step::Prevote {
            return None;
        }
        let target = self.hc.decide_prevote();
        self.make_vote(VoteKind::Prevote, target)
    }

    pub fn on_prevote(&mut self, v: Vote) -> Result<(), String> {
        let res = self.hc.add_prevote(v.clone());
        if res.is_err() {
            // Stale/absurd votes never vote, but a VERIFIED same-height vote
            // still feeds the peer-round counter so the desync collapses.
            self.observe_peer_vote(&v);
        }
        res
    }

    /// Once a prevote quorum exists, lock and produce our precommit.
    ///
    /// Audit F10: `try_prevote_quorum` scans back a window of rounds (so a late
    /// quorum still decides), but a precommit must be cast for the round we are
    /// actually in. Casting a precommit at the CURRENT round off a prevote QC
    /// that formed in an OLDER round would vote a round in which we never
    /// prevoted, and lock us at the wrong round -- a validator only precommits
    /// after prevoting in that same round. So require a prevote QC recorded for
    /// `self.hc.round` whose target is the quorum target we are about to
    /// precommit. Finalization of an older round is unaffected: `try_finalize`
    /// inspects the same lookback window and can still commit it.
    pub fn make_precommit(&mut self) -> Option<Vote> {
        // Cast at the polka's OWN round (Tendermint), not at `hc.round`.
        // The old rule ("the QC must be in my current round") meant that a
        // one-round skew -- the normal state of the two-node stand -- made BOTH
        // nodes refuse to precommit: each saw the QC one round behind, so a
        // full prevote QC never decided (31 of 180 wasted rounds, measured
        // live: prevote QC present, no precommit ever cast).
        let (qc_round, target) = self.hc.try_prevote_quorum_at()?;
        let qc = self.hc.prevote_qc.get(&qc_round)?;
        if qc.block_hash != target {
            return None;
        }
        if let Some(bh) = target {
            // Lock at the polka round too: the lock round is what the safety
            // check in `try_precommit_quorum` compares against.
            self.hc.locked = Some((bh, qc_round));
        }
        self.make_vote_at(VoteKind::Precommit, target, qc_round)
    }

    pub fn on_precommit(&mut self, v: Vote) -> Result<(), String> {
        let res = self.hc.add_precommit(v.clone());
        if res.is_err() {
            self.observe_peer_vote(&v);
        }
        res
    }

    /// Downtime slash for the certificate this runtime currently holds in `hc`:
    /// punish validators that did not contribute to it and burn the slashed
    /// stake from the staking pool. The evidence is the certificate itself, so
    /// every node reaches the same verdict; a local timeout would be neither
    /// sound nor deterministic.
    ///
    /// The production state transition no longer comes here: it runs inside
    /// `InMemoryStateEngine::apply_block_transition`, from the BLOCK's own
    /// `precommit_qc` and `height`, so every route that applies a block -
    /// local finalize, adopt, walk, replay and a reorg re-apply - derives one
    /// verdict from one piece of block content and cannot fork. This entry
    /// point is kept for the consensus-view primitive: tests that build an
    /// `hc` by hand and want to observe what the certificate they hold burns.
    pub async fn apply_downtime_slashes(&mut self) -> u64 {
        // Snapshot the certificate and height BEFORE anything resets them.
        let Some(cert) = self.hc.precommit_qc.clone() else {
            return 0;
        };
        let height = self.hc.height;
        self.state.apply_downtime_slash(height, Some(&cert)).await
    }

    // ==================== §7 Phase 2: lane plumbing ====================

    /// True while a decided block's execution is still on the worker. Stage 1
    /// of the consensus loop and every reader of post-H state check this
    /// first: while set, our observable consensus state (height, `finalized`,
    /// the root a new proposal is checked against) is still PRE-H.
    pub fn has_pending_apply(&self) -> bool {
        self.apply_in_flight.is_some()
    }

    /// Messages currently queued in every inbox: defensive leftovers plus
    /// anything queued since. Honest operation keeps this at zero at every
    /// block boundary (drain-to-empty plus the cap check below refuses any
    /// block that would break it), so a non-zero value here is either a test
    /// setup or evidence of pre-fix history.
    pub async fn pending_actor_backlog(&self) -> usize {
        self.state
            .accounts
            .read()
            .await
            .values()
            .map(|a| a.inbox.len())
            .sum()
    }

    /// Backlog-inclusive half of the actor-mailbox cap check: whatever is
    /// already queued plus whatever this block statically carries must fit
    /// `MAX_ACTOR_MSGS_PER_BLOCK`, or the block is rejected deterministically
    /// instead of carried over. Called on the propose path (fresh and
    /// demanded bodies), the proposal path and the adopt path, so every
    /// decision boundary refuses the same blocks for the same reason.
    pub async fn check_actor_cap(&self, block: &Block) -> Result<(), String> {
        let sends = count_block_actor_sends(block);
        // Static half first, WITHOUT touching state: an over-cap block dies on
        // block bytes alone. Previously the full inbox scan ran first, so even
        // a self-evidently over-cap commit paid a whole-state read-lock on a
        // weak node before being refused.
        if sends > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK {
            return Err(format!(
                "actor mailbox over cap: 0 queued + {sends} in block > {} (rejected; leftovers never carry over)",
                crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
            ));
        }
        // Backlog scan with early exit: stop the moment the cap is exceeded
        // instead of summing every inbox on a doomed block. Same verdict as
        // `pending_actor_backlog() + sends > cap`, one lock, bounded work on
        // the refuse path; the accept path still proves the total.
        let limit = crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK.saturating_sub(sends);
        let guard = self.state.accounts.read().await;
        let mut backlog: usize = 0;
        for a in guard.values() {
            backlog = backlog.saturating_add(a.inbox.len());
            if backlog > limit {
                return Err(format!(
                    "actor mailbox over cap: {backlog} queued + {sends} in block > {} (rejected; leftovers never carry over)",
                    crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
                ));
            }
        }
        Ok(())
    }

    /// Spawn-once accessor for the single ordered worker. Lazy so that
    /// construction never needs a tokio context; every apply below funnels
    /// through here, so there is exactly one worker per runtime — never a
    /// pool, never parallel.
    fn ensure_apply_lane(&mut self) -> ApplyLane {
        if self.apply_lane.is_none() {
            self.apply_lane = Some(ApplyLane::spawn(&self.state));
        }
        self.apply_lane.clone().expect("lane just spawned")
    }

    /// Run one decided block's state transition on the worker and wait for
    /// it. The worker runs one job at a time strictly in submission order,
    /// so even concurrent submitters can never interleave two applies: the
    /// second simply waits behind the first on the channel.
    async fn run_on_apply_lane(
        &mut self,
        block: &Block,
        reward: u64,
    ) -> (
        crate::state_engine::BlockTransitionOutcome,
        [u8; 32],
    ) {
        let lane = self.ensure_apply_lane();
        let (tx, rx) = tokio::sync::oneshot::channel();
        lane.tx
            .send(LaneJob::Apply(ApplyJob {
                block: block.clone(),
                reward,
                done: tx,
            }))
            .expect("apply worker lives as long as the runtime holds its lane sender");
        rx.await.expect("apply worker answers every job it takes")
    }

    /// `apply_decided`: the exact current finalize-apply sequence — reward
    /// resolution, the shared `apply_block_transition` on the worker,
    /// then the node-local bookkeeping that cannot move the root (via
    /// [`Self::record_apply_outcome`]). Awaited inline: the caller blocks,
    /// but the execution still serializes on the single ordered lane, so it
    /// can never overlap a sequenced submit. Returns the transition outcome
    /// with the certified post-apply root.
    async fn apply_decided(
        &mut self,
        block: &Block,
    ) -> (
        crate::state_engine::BlockTransitionOutcome,
        [u8; 32],
    ) {
        // `block.timestamp` is the VM's "now" for every payload in this block:
        // unbonding maturity, contract creation time, order stamps. Every node
        // applying this block passes the SAME value, so the resulting state is
        // deterministic.
        //
        // The reward is the governed value when governance set one, else the
        // node default - resolved by the SAME helper the reorg path uses.
        let reward = block_reward_for(self.governance.as_ref(), self.block_reward);
        let (outcome, root) = self.run_on_apply_lane(block, reward).await;
        self.record_apply_outcome(block, &outcome).await;
        (outcome, root)
    }

    /// Node-local half of the finalize-apply sequence: everything the old
    /// inline `apply_block_fees_rewards` did AFTER `apply_block_transition`
    /// (receipts / applied counters, mempool pruning, cross-shard
    /// bookkeeping). None of it can move the state root, and the reorg path
    /// mirrors it field by field — see `ChainState::apply_block`.
    async fn record_apply_outcome(
        &mut self,
        block: &Block,
        outcome: &crate::state_engine::BlockTransitionOutcome,
    ) {
        self.applied_statuses = outcome.status.clone();
        self.applied_fees = outcome.tx_fees.clone();
        self.applied_txs += outcome.applied as u64;
        // Node-local: remove included txs from our mempool so they are never
        // re-proposed. The mempool is not consensus state and is not part of
        // the state root, so the reorg path (which has no mempool) diverges
        // here without forking - see `ChainState::apply_block`.
        let included: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.compute_tx_hash()).collect();
        self.mempool.write().await.prune_confirmed(&included);
        // D2 free-failure gate: an included transaction that FAILED at apply
        // paid nothing (the native commit is atomic) while its bytes occupied
        // block wire/gas and burned verifier CPU. Feed the verdicts back so a
        // repeatedly-failing sender must over-post (bond in fee form) to
        // re-enter the pool or a future block; one success clears the sender.
        {
            let mut failed: Vec<[u8; 32]> = Vec::new();
            let mut succeeded: Vec<[u8; 32]> = Vec::new();
            for (i, tx) in block.transactions.iter().enumerate() {
                if outcome.status.get(i).copied().unwrap_or(false) {
                    succeeded.push(tx.from);
                } else {
                    failed.push(tx.from);
                }
            }
            self.mempool.write().await.note_apply_feedback(&failed, &succeeded);
        }
        // M2 cross-shard bookkeeping, all a pure function of the block:
        //   * remember every INBOUND message this block credited, so a replay
        //     is refused by `validate_proposal` and skipped at proposal time;
        //   * publish every OUTBOUND message this block produced to the local
        //     transport, so the destination shard can consume it. Publishing is
        //     idempotent (keyed by msg_id) and is a no-op without a transport.
        // §5 M3 extends the same discipline to acks/bounces (all still riding
        // `cross_shard_out`, no new Block/Transaction fields):
        //   * outbound TRANSFERS are recorded in `produced_cross_shard`
        //     (tx hash -> (tx, height)) for linkage + timeout checks;
        //   * a newly consumed transfer publishes an ack to the transport, so
        //     the source shard can commit the completion;
        //   * a newly committed ack marks its transaction complete (no value
        //     movement — the value already moved on the target);
        //   * a newly committed bounce marks its transaction complete AND
        //     refunds `tx.amount` to `tx.from` on this (source) shard, exactly
        //     once (guarded by the consumed set, in deterministic key order);
        //   * every inbound record consumed here is pruned from the transport
        //     KV, so consumed entries cannot accumulate.
        // The engine itself skips proof-less control records (it only credits
        // proof-carrying inbound to `tx.to`), which is why the refund below is
        // the ONLY credit a bounce performs — and validation refuses
        // proof-carrying control records, closing the source-side mint.
        if self.shard_registry.is_sharded() {
            for msg in &block.cross_shard_out {
                if msg.is_transfer() && msg.is_outbound_for(self.shard_id) {
                    let tx_hash = msg.tx.compute_tx_hash();
                    self.produced_cross_shard
                        .entry(tx_hash)
                        .or_insert((msg.tx.clone(), block.height));
                }
            }
            let mut inbound_sorted: Vec<&CrossShardMessage> = block
                .cross_shard_out
                .iter()
                .filter(|m| m.is_inbound_for(self.shard_id))
                .collect();
            inbound_sorted.sort_by_key(|m| CrossShardKey::of(m));
            let mut pruned_ids: Vec<[u8; 32]> = Vec::new();
            for msg in inbound_sorted {
                let key = CrossShardKey::of(msg);
                if msg.is_transfer() {
                    // C4: mirror ONLY what the engine actually credited (its
                    // gate verifies + inserts on success). Recording a
                    // proof-less/invalid transfer here used to poison the
                    // mirror: the later VALID retry shared the replay key and
                    // was refused as already-consumed, burning the sender's
                    // funds until a timeout bounce. Engine-first, mirror
                    // second — never the reverse.
                    if !self.state.is_cross_shard_consumed(&key).await {
                        continue;
                    }
                    if self.consumed_cross_shard.insert(key) {
                        pruned_ids.push(msg.msg_id);
                        // Newly consumed: tell the source shard with an ack.
                        // Transport-local only; the committed form is the ack
                        // record the source includes in its own block.
                        let ack = CrossShardMessage::new_ack(
                            msg.tx.clone(),
                            block.compute_hash(),
                        );
                        if let Some(transport) = &self.cross_shard {
                            if let Err(e) = transport.broadcast_cross_shard(&ack).await {
                                tracing::warn!(
                                    "cross-shard ack publish failed for {}: {e}",
                                    hex::encode(&msg.msg_id[..8])
                                );
                            }
                        }
                    }
                } else if msg.is_ack() || msg.is_bounce() {
                    // Re-check linkage at apply height (same rule validation
                    // used): an apply must never complete what validation
                    // would refuse, no matter which path (finalize / adopt /
                    // walk / replay) brought the block here.
                    if !self.control_linkage_ok(msg, block.height) {
                        continue;
                    }
                    if !self.consumed_cross_shard.insert(key) {
                        continue;
                    }
                    let tx_hash = msg.tx.compute_tx_hash();
                    // Same-block ack+bounce for one transaction: the first in
                    // key order completes it; the second finds it completed.
                    if !self.completed_cross_shard.insert(tx_hash) {
                        continue;
                    }
                    pruned_ids.push(msg.msg_id);
                    if msg.is_bounce() {
                        // The refund: exactly `tx.amount` back to the sender.
                        // Gas went to the source proposer at produce time and
                        // is not refunded. `credit_native` creates the account
                        // if it vanished, and commits to the trie, so every
                        // node applying this block derives the same root.
                        if let Err(e) = self.state.credit_native(&msg.tx.from, msg.tx.amount).await {
                            tracing::warn!(
                                "cross-shard bounce refund failed for {}: {e}",
                                hex::encode(&msg.msg_id[..8])
                            );
                        }
                    }
                }
            }
            if let Some(transport) = &self.cross_shard {
                if !pruned_ids.is_empty() {
                    transport.prune_consumed(self.shard_id, &pruned_ids).await;
                }
                for msg in &block.cross_shard_out {
                    if msg.is_transfer() && msg.is_outbound_for(self.shard_id) {
                        if let Err(e) = transport.broadcast_cross_shard(msg).await {
                            tracing::warn!(
                                "cross-shard publish failed for {}: {e}",
                                hex::encode(&msg.msg_id[..8])
                            );
                        } else {
                            tracing::info!(
                                "cross-shard outbound published {} shard {} -> {}",
                                hex::encode(&msg.msg_id[..8]),
                                self.shard_id,
                                msg.target_shard,
                            );
                        }
                    }
                }
            }
        }
    }

    /// Install a worker-reported outcome: the node-local bookkeeping above,
    /// then the consensus advance the old inline path did (finalized entry,
    /// validator-set rotation, next height). Runs exactly once per decided
    /// block, whether the decision was awaited inline or collected later.
    async fn install_apply_outcome(
        &mut self,
        height: Height,
        bh: BlockHash,
        block: &Block,
        outcome: &crate::state_engine::BlockTransitionOutcome,
    ) {
        self.record_apply_outcome(block, outcome).await;
        self.finalized.push((height, bh));
        // Any finalize is progress: the deadlock breaker measures silence.
        self.last_progress_at = std::time::Instant::now();
        // C1 anchor: every finalized block (live, replayed, adopted) feeds
        // the process-shared header registry its own and sibling shards read.
        self.note_finalized_header(&block);
        // Rotate the consensus validator set from bonded stake at the height
        // boundary. Deterministic: every node derives it from the same consensus
        // ledger, so all nodes agree on the new set/power for height+1.
        self.refresh_validator_set_from_staking().await;
        self.hc = HeightConsensus::new(height + 1, self.validators.clone());
    }

    /// Shared DECISION half of finalization: quorum, presence, order and cap
    /// gates, QC attachment and decision-proof stash. Both `try_finalize`
    /// (await inline) and `try_finalize_submit` (queue on the worker) decide
    /// through here, so the two can never disagree about what is decidable.
    /// Returns the decided height, hash and block (QC attached).
    async fn prepare_decided_block(&mut self) -> Option<(Height, BlockHash, Block)> {
        // One apply at a time, strictly height-ordered: while a decided block
        // is still on the worker our height has not advanced, so deciding
        // again now would queue the SAME height twice. Refuse; the next poll
        // collects the pending outcome and this retries then.
        if self.apply_in_flight.is_some() {
            return None;
        }
        let bh = self.hc.try_precommit_quorum()?;
        let height = self.hc.height;
        // The block must actually be here.
        //
        // This used to be `if let Some(block) = ... { apply }` followed by
        // committing to the height unconditionally. A peer could therefore send
        // three precommits for a hash of its choosing and never send the block:
        // the node skipped every check, skipped applying anything, still pushed
        // the height, still rotated the validator set from the ledger, and still
        // slashed - all on the strength of a block it had never received or
        // validated. It is a quorum of honest validators, so this is not a
        // byzantine scenario, it is what happens whenever a block is lost in
        // transit.
        let Some(block) = self.blocks.get(&bh).cloned() else {
            tracing::warn!(
                height,
                "quorum reached for a block this node does not have; refusing to finalize"
            );
            return None;
        };
        // Body integrity re-check (audit 2026-10-06): the map is keyed by hash
        // but the STORED bytes may have been corrupted/reordered after
        // insertion — executing a body whose hash no longer matches the voted
        // `bh` would finalize a DIFFERENT state than the quorum (a split).
        // Refuse, like the missing-body case above. (A mere ORDER-COMMITMENT
        // mismatch below is different: the body is byte-identical to what the
        // quorum voted, so execution converges everywhere.)
        if block.compute_hash() != bh {
            tracing::warn!(
                height,
                "stored body hash does not match the decided hash; refusing to finalize"
            );
            return None;
        }
        // MEV build-order gate: if THIS NODE built the block being decided, the
        // order about to execute is compared against the build-time commitment
        // (`commit_block_order`). A mismatch is logged LOUDLY (tamper evidence
        // or mempool drift between build and finalize) but NO LONGER refuses
        // finalization: execution is deterministic from the voted body, so
        // every node reaches the same root either way, while refusing stalled
        // ONLY the builder at H as everyone else moved on — a forced catch-up
        // every height under mempool divergence (audit 2026-10-06).
        if block.proposer == self.id {
            let pool = self.mempool.read().await;
            match pool.mev.verify_block_order(block.height, bh, &block.transactions) {
                crate::mev::OrderVerdict::NoCommit
                | crate::mev::OrderVerdict::Match => {}
                verdict => {
                    tracing::warn!(
                        height,
                        ?verdict,
                        "block order differs from build-time commitment; finalizing anyway (deterministic execution converges)"
                    );
                }
            }
        }
        // Actor-mailbox cap (finalize side): an over-cap block is never
        // executed, so the defensive clamp in the engine can never leave a
        // root-invisible leftover behind on this path either.
        if let Err(e) = self.check_actor_cap(&block).await {
            tracing::warn!(height, "{e}; refusing to finalize");
            return None;
        }
        // Attach the precommit QC that decided this block, so the decision travels
        // with the block. A block otherwise carries only the PROPOSER's signature,
        // and every other validator's agreement exists only as a vote -- which is over
        // `vote_sign_bytes`, a different message from the block hash, so those
        // signatures can never verify as block signatures and grafting them was
        // wrong. Block sync verifies the attached QC (kind, height, quorum) instead.
        let mut finalized_block = block;
        finalized_block.precommit_qc = self.hc.precommit_qc.clone();
        // Replace the proposal-only version so what we serve and republish carries
        // the decision proof and can be verified by anyone.
        self.blocks.insert(bh, finalized_block.clone());
        // Stash the decision proof for the commit broadcast: `try_finalize`
        // resets `hc` below, so reading `hc.precommit_qc` afterwards (as the
        // main loop once did) always finds None and the broadcast silently
        // never fires -- lagging peers then never learn outcomes.
        if let Some(qc) = self.hc.precommit_qc.clone() {
            self.last_decision = Some((height, finalized_block.clone(), qc));
        }
        let block = finalized_block;
        Some((height, bh, block))
    }

    pub async fn try_finalize(&mut self) -> Option<BlockHash> {
        let (height, bh, block) = self.prepare_decided_block().await?;
        // Economic security from block content: the transition runs the
        // downtime slash from `block.precommit_qc` AND the equivocation
        // slash from the block's `SysCallReportEquivocation` payloads
        // (re-verified from block bytes, pool-debited, per-offense deduped)
        // inside `apply_block_transition` - the same core the reorg path
        // uses, so both burn the same coins.
        //
        // F4: LOCAL-observation equivocation is intentionally NOT slashed
        // here. Its evidence is a pair of conflicting votes this node
        // happened to observe on the local gossip path, not block content,
        // so a node that finalized locally and a node that
        // adopted/walked/replayed the same height would burn different
        // stake and commit different state roots. See
        // `apply_equivocation_slashes` for the full rationale; the WIRED
        // path is block-carried evidence via `apply_block_transition`.
        self.apply_block_fees_rewards(&block).await;
        self.finalized.push((height, bh));
        self.last_progress_at = std::time::Instant::now();
        self.note_finalized_header(&block);
        // Rotate the consensus validator set from bonded stake at the height
        // boundary. Deterministic: every node derives it from the same consensus
        // ledger, so all nodes agree on the new set/power for height+1.
        self.refresh_validator_set_from_staking().await;
        self.hc = HeightConsensus::new(height + 1, self.validators.clone());
        Some(bh)
    }

    /// §7 Phase 2 sequenced submit: decide through the same
    /// [`Self::prepare_decided_block`] as [`Self::try_finalize`], then queue
    /// the execution on the single ordered worker WITHOUT awaiting it and
    /// return the decided hash immediately.
    ///
    /// Nothing observable moves here: no `finalized` entry, no height
    /// advance, no receipts. The caller keeps draining inbound messages and
    /// collects the outcome with [`Self::try_poll_apply`] (or
    /// [`Self::await_apply_completion`]), which installs it and advances.
    /// Returns `None` when there is nothing to decide (no quorum, missing
    /// body, failed order/cap gate) or when an apply is already in flight —
    /// at most one decided block is ever queued or executing.
    pub async fn try_finalize_submit(&mut self) -> Option<BlockHash> {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        let (height, bh, block) = self.prepare_decided_block().await?;
        // The reward is resolved NOW, from the same helper the inline path
        // uses, so the worker executes byte-identically with no governance
        // read of its own.
        let reward = block_reward_for(self.governance.as_ref(), self.block_reward);
        let lane = self.ensure_apply_lane();
        let (tx, rx) = tokio::sync::oneshot::channel();
        if lane
            .tx
            .send(LaneJob::Apply(ApplyJob {
                block: block.clone(),
                reward,
                done: tx,
            }))
            .is_err()
        {
            return None;
        }
        self.apply_in_flight = Some(ApplyInflight {
            height,
            hash: bh,
            block,
            done: rx,
        });
        Some(bh)
    }

    /// Non-blocking collect of the sequenced apply: when the worker has
    /// reported back, install the outcome (bookkeeping + height advance) and
    /// return it; when it is still executing, leave everything untouched and
    /// return `None` so the loop keeps draining. Safe to call every tick.
    pub async fn try_poll_apply(&mut self) -> Option<ApplyCompleted> {
        let mut inflight = self.apply_in_flight.take()?;
        match inflight.done.try_recv() {
            Ok((outcome, root)) => {
                self.install_apply_outcome(
                    inflight.height,
                    inflight.hash,
                    &inflight.block,
                    &outcome,
                )
                .await;
                Some(ApplyCompleted {
                    height: inflight.height,
                    hash: inflight.hash,
                    root,
                })
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                self.apply_in_flight = Some(inflight);
                None
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                // The worker only ends when every lane sender is gone, and one
                // lives in `self`, so this is unreachable without a worker
                // panic. Re-queueing blindly could double-apply; park the
                // height (loudly) instead of advancing past an unapplied block.
                tracing::error!(
                    "apply worker vanished mid-block at height {}; height stuck until restart",
                    inflight.height
                );
                self.apply_in_flight = Some(inflight);
                None
            }
        }
    }

    /// Blocking collect of the sequenced apply, for tests and startup paths
    /// that have nothing else to drain while they wait. Installs the outcome
    /// exactly like [`Self::try_poll_apply`] and returns it with the
    /// certified post-apply root.
    pub async fn await_apply_completion(&mut self) -> Option<ApplyCompleted> {
        let inflight = self.apply_in_flight.take()?;
        let (outcome, root) = inflight.done.await.ok()?;
        self.install_apply_outcome(inflight.height, inflight.hash, &inflight.block, &outcome)
            .await;
        Some(ApplyCompleted {
            height: inflight.height,
            hash: inflight.hash,
            root,
        })
    }

    /// Submit a quiescent snapshot capture to the sequenced lane (see
    /// `SnapBundle`). `expected_root` is the worker-certified post-`height`
    /// root: the worker captures only if the engine still roots there, so a
    /// mislabeled capture is impossible no matter the queue order.
    /// Non-blocking; at most one in flight (a second submit is refused).
    pub fn submit_snapshot(&mut self, height: u64, expected_root: [u8; 32]) -> bool {
        if self.snapshot_in_flight.is_some() {
            return false;
        }
        let lane = self.ensure_apply_lane();
        let (tx, rx) = tokio::sync::oneshot::channel();
        if lane.tx.send(LaneJob::Snapshot(SnapshotJob { height, expected_root, done: tx })).is_err() {
            return false;
        }
        self.snapshot_in_flight = Some(rx);
        true
    }

    /// Non-blocking collect of a submitted snapshot capture. `None` while the
    /// worker has not reached it yet — or when the worker SKIPPED it (engine
    /// moved past the certified root); either way the caller retries on a
    /// later height and labels stay exact.
    pub fn poll_snapshot(&mut self) -> Option<SnapBundle> {
        let mut rx = self.snapshot_in_flight.take()?;
        match rx.try_recv() {
            Ok(Some(bundle)) => Some(bundle),
            Ok(None) => None,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                self.snapshot_in_flight = Some(rx);
                None
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                // Worker died mid-capture: fail LOUD (fail-closed) so the gap
                // in snapshots is visible instead of silently missing.
                tracing::error!("snapshot capture lost: apply worker died mid-capture");
                None
            }
        }
    }

    /// Re-apply a HISTORICAL block during startup healing (engine behind head).
    ///
    /// Same effects as finalization minus consensus: the full block transition
    /// (`apply_block_transition`: fees/rewards, unbonding, downtime slash),
    /// validator-set rotation. Does NOT touch `finalized` (the head is already
    /// seeded from metadata) and does NOT reset `hc` (the caller owns height/round
    /// bookkeeping during replay).
    ///
    /// Every applied block must carry a verifiable precommit QC, and its header must
    /// commit to the engine state as it stands (F3.2). Blocks from before blocks
    /// carried QCs cannot be replayed and are an error -- that history predates
    /// verifiable sync and the node must be wiped, not guessed forward.
    pub async fn replay_historical_block(&mut self, block: &Block) -> Result<(), String> {
        let bh = block.compute_hash();
        let Some(qc) = &block.precommit_qc else {
            return Err(format!(
                "block {} carries no decision proof (predates verifiable history)",
                block.height
            ));
        };
        if qc.kind != crate::consensus::VoteKind::Precommit {
            return Err(format!("block {} decision proof is not a precommit quorum", block.height));
        }
        if qc.height != block.height {
            return Err(format!(
                "block {} decision proof is for height {}",
                block.height, qc.height
            ));
        }
        if qc.block_hash != Some(bh) {
            return Err(format!(
                "block {} decision proof commits to a different block",
                block.height
            ));
        }
        let root_before = self.state.get_state_root().await;
        if block.state_root != root_before {
            return Err(format!(
                "block {} commits to parent state root {} but engine is at {} (gap in replay range?)",
                block.height,
                hex::encode(block.state_root),
                hex::encode(root_before)
            ));
        }
        // F5: verify the historical QC against the set that was in force AT THIS
        // HEIGHT, not the current one. There is no height-indexed validator-set
        // snapshot, but replay gives us the next best thing for free: the engine
        // is already at this block's committed PRE-state, and the set in force
        // for height H is derived from the staking ledger at the end of H-1 --
        // i.e. exactly that pre-state. So derive it here instead of trusting the
        // live `self.validators` (which, after a restart, starts from the config
        // set rather than the ledger at the replay anchor).
        //
        // Fall back to `self.validators` when staking is empty: a network that
        // never bonded uses its config-defined set, and `to_validator_set` would
        // be empty there.
        //
        // TODO(F5): `validate_sync_chain` cannot do this because it is a pure
        // function with no state engine; it still verifies against the current
        // set (conservative: a rotated-away signer is dropped, and quorum must
        // still be met by the current set). Threading per-height sets through it
        // requires the ledger to advance per block, which means replaying
        // staking effects -- a larger change than this fix.
        let historical_vs = {
            let ledger = self.state.staking_read().await;
            ledger.to_validator_set()
        };
        let verify_set = if historical_vs.is_empty() {
            self.validators.clone()
        } else {
            historical_vs
        };
        if !qc.verify(&verify_set) {
            return Err(format!(
                "block {} decision proof lacks a validator quorum at its height",
                block.height
            ));
        }
        // The certificate IS the block's downtime evidence: the transition
        // reads `block.precommit_qc`, and installing the same QC into `hc`
        // keeps the consensus bookkeeping in step with it.
        //
        // F4: LOCAL-observation equivocation slashing is deliberately
        // skipped on EVERY path now, not just this one. It was never
        // replayable (votes are not persisted, and the block carries no
        // gossip evidence), so replaying it here while the local-finalize
        // path slashed it split the chain. See
        // `apply_equivocation_slashes`. The WIRED path is block-carried
        // evidence (`SysCallReportEquivocation` scanned from the decided
        // block in `apply_block_transition`), which every path applies
        // identically.
        self.hc.precommit_qc = Some(qc.clone());
        self.blocks.insert(bh, block.clone());
        self.apply_block_fees_rewards(block).await;
        self.refresh_validator_set_from_staking().await;
        Ok(())
    }

    /// Apply a finalized block's transactions and distribute its fees/rewards.
    /// Shared by `try_finalize`, `apply_and_advance` and
    /// `replay_historical_block` so a block reaches the state engine identically
    /// no matter how it was decided.
    ///
    /// ALL of the state work now lives in one place:
    /// `InMemoryStateEngine::apply_block_transition`, the same function
    /// `ChainState::apply_block` (the reorg path) calls — executed here via
    /// [`Self::apply_decided`] (same sequence the sequenced submit runs, only
    /// awaited inline). This wrapper only adds the node-local bookkeeping
    /// that cannot move the state root: receipts / applied counters and
    /// mempool pruning.
    async fn apply_block_fees_rewards(&mut self, block: &Block) {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        let (_outcome, _root) = self.apply_decided(block).await;
    }

    /// Apply an adopted block and move to the next height, exactly as a locally
    /// finalized block would be handled. Also used by live catch-up, which must
    /// reproduce the identical transition (not just transaction effects).
    pub async fn apply_and_advance(&mut self, bh: BlockHash, block: &Block) {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        // The full transition (txs, fees, reward, unbonding, downtime slash)
        // runs inside `apply_block_fees_rewards` from the block's own content,
        // so adopting/walking a block is byte-identical to finalizing it and to
        // a reorg re-applying it.
        //
        // F4: no LOCAL-observation equivocation slash on the adopt/walk path
        // (or any other). It would read local vote observations, which are
        // not block content, and split the chain against the local-finalize
        // path. See `apply_equivocation_slashes`. Block-carried evidence
        // (`SysCallReportEquivocation`) slashes uniformly on every path via
        // `apply_block_transition`. Downtime evidence travels with the
        // block (`precommit_qc`), which the caller installs/verifies.
        self.apply_block_fees_rewards(block).await;
        let height = self.hc.height;
        self.finalized.push((height, bh));
        self.last_progress_at = std::time::Instant::now();
        self.note_finalized_header(&block);
        self.refresh_validator_set_from_staking().await;
        self.hc = HeightConsensus::new(height + 1, self.validators.clone());
    }

    /// Whether the validator set is currently refused as STALE (fail-closed
    /// observer mode: the node follows and validates but must NOT vote).
    pub fn is_validator_set_stale(&self) -> bool {
        self.validator_set_stale
    }

    /// Human-readable stale reason, if any (see [`Self::is_validator_set_stale`]).
    pub fn validator_set_stale_reason(&self) -> Option<&str> {
        self.validator_set_stale_reason.as_deref()
    }

    /// Effective franchise: the static config flag AND ledger membership, MINUS
    /// the stale gate. A node with a stale ledger is an observer even if its
    /// key is in the (foreign) set — voting with a foreign set is exactly the
    /// node-C failure (silent wrong quorums instead of an honest observer).
    pub fn effective_can_vote(&self, config_is_validator: bool) -> bool {
        if self.validator_set_stale {
            return false;
        }
        config_is_validator || self.validators.validators.contains_key(&self.id)
    }

    /// Mark the set STALE (fail-closed to observer). LOUD on both channels;
    /// records both heights so the operator sees how far the ledger lags.
    pub fn mark_validator_set_stale(&mut self, state_height: u64, ledger_height: u64, reason: String) {
        self.validator_set_stale = true;
        self.validator_set_stale_reason = Some(reason.clone());
        self.validator_set_state_height = Some(state_height);
        self.validator_set_ledger_height = Some(ledger_height);
        tracing::warn!(
            "[validator-set] WARN stale validator set at state {state_height} (ledger {ledger_height}): {reason} — fail-closed to observer (no votes) until a fresh ledger arrives"
        );
        eprintln!(
            "[validator-set] WARN stale validator set at state {state_height} (ledger {ledger_height}): {reason} — fail-closed to observer (no votes) until a fresh ledger arrives"
        );
    }

    /// Clear the stale gate after a FRESH set was installed or verified.
    pub fn clear_validator_set_stale(&mut self) {
        self.validator_set_stale = false;
        self.validator_set_stale_reason = None;
    }

    /// Re-entry hysteresis sweep: LOUD-warn every member the derived set
    /// GAINS over the previous set, count it, watch it for liveness, and
    /// re-WARN watched re-entrants that still show no votes after N heights.
    ///
    /// ADDITIVE LOGGING ONLY — no logic change: the derived set the caller
    /// installs is never filtered, reordered or refused here. Both channels
    /// (tracing + stderr) because an offline re-entrant in a micro-quorum is
    /// a chain-halt precursor and must be unmissable.
    ///
    /// Liveness signal: the ledger's QC-derived `missed` streak (same
    /// evidence the downtime slasher uses — block content, identical on every
    /// node), via [`crate::staking::reentry_liveness_risk`]. A watched member
    /// leaves the watch when it drops out of the derived set again or its
    /// streak is forgiven (`missed == 0`, i.e. it signed a certificate).
    fn note_validator_set_gains(
        &mut self,
        derived: &crate::consensus::ValidatorSet,
        ledger: &crate::staking::StakingLedger,
    ) {
        let height = self.hc.height;
        // Snapshot the pre-existing watch BEFORE inserting this refresh's
        // gains: a member gained right now has a clean `missed` streak (it
        // could not miss certificates while unelected), so sweeping it in the
        // same pass would instantly unwatch it and the liveness watch would
        // never hold a fresh re-entrant.
        let watched: Vec<(ValidatorId, u64)> =
            self.reentry_watch.iter().map(|(m, h)| (*m, *h)).collect();
        for (member, power) in crate::staking::validator_set_gains(&self.validators, derived) {
            let msg = crate::staking::reentry_warn_message_for(&member, power, height);
            tracing::warn!("{msg}");
            eprintln!("{msg}");
            self.validator_reentry_warns_total =
                self.validator_reentry_warns_total.saturating_add(1);
            self.reentry_watch.insert(member, height);
        }
        let mut unwatched: Vec<ValidatorId> = Vec::new();
        for (member, rejoined_at) in &watched {
            let power = derived.validators.get(member).copied().unwrap_or(0);
            if power == 0 {
                // Re-ejected (or never installed): stop watching silently.
                unwatched.push(*member);
                continue;
            }
            let missed = ledger.validators.get(member).map(|v| v.missed).unwrap_or(0);
            if missed == 0 {
                // Signed a certificate since rejoining: healthy, stop watching.
                unwatched.push(*member);
                continue;
            }
            if crate::staking::reentry_liveness_risk(*rejoined_at, height, missed)
                && height.saturating_sub(*rejoined_at) % 10 == 0
            {
                let msg = crate::staking::reentry_liveness_warn_message_for(
                    member,
                    power,
                    *rejoined_at,
                    height,
                    missed,
                );
                tracing::warn!("{msg}");
                eprintln!("{msg}");
            }
        }
        for m in unwatched {
            self.reentry_watch.remove(&m);
        }
    }

    /// Core installer used by every refresh path: freshness-gated set install
    /// from an explicit ledger with explicit heights.
    ///
    /// * STALE (`ledger_height` lags `state_height` beyond
    ///   [`crate::storage::validator_set_freshness_max_lag`]): LOUD warn,
    ///   stale flag set, set NOT installed, returns `false`. The caller keeps
    ///   its old set for READS but must not vote (see
    ///   [`Self::effective_can_vote`]).
    /// * FRESH: derives the set from `ledger`; installs on change (with the
    ///   usual before/after warn), clears the stale flag, returns whether the
    ///   set changed. Empty stays a no-op (pre-bond network keeps its config
    ///   set), exactly like [`Self::refresh_validator_set_from_staking`].
    pub async fn refresh_validator_set_from_ledger(
        &mut self,
        ledger: &crate::staking::StakingLedger,
        state_height: u64,
        ledger_height: u64,
    ) -> bool {
        if let Err(reason) =
            crate::storage::check_validator_set_freshness(state_height, ledger_height)
        {
            self.mark_validator_set_stale(state_height, ledger_height, reason);
            return false;
        }
        let vs = ledger.to_validator_set();
        // Re-entry hysteresis (local policy + visibility ONLY — the derived
        // set `vs` below is installed or compared verbatim, never filtered).
        // урок валидатора C: an ejected-then-topped-up validator silently
        // rejoined while offline and halted a micro-quorum. Every gain gets a
        // LOUD warn + counter + liveness watch; watched re-entrants with no
        // votes for N heights get a repeating liveness-risk WARN.
        self.note_validator_set_gains(&vs, ledger);
        if vs.is_empty() || vs.validators == self.validators.validators {
            // Fresh ledger that changes nothing proves we are NOT stale.
            self.clear_validator_set_stale();
            self.validator_set_state_height = Some(state_height);
            self.validator_set_ledger_height = Some(ledger_height);
            return false;
        }
        let fmt = |m: &std::collections::BTreeMap<ValidatorId, u64>| {
            m.iter()
                .map(|(k, p)| format!("{}:{}", hex::encode(&k[..4]), p))
                .collect::<Vec<_>>()
                .join(",")
        };
        tracing::warn!(
            "validator set refreshed at height {}: [{}] -> [{}]",
            self.hc.height,
            fmt(&self.validators.validators),
            fmt(&vs.validators),
        );
        self.validators = vs.clone();
        self.hc.validators = vs;
        self.clear_validator_set_stale();
        self.validator_set_state_height = Some(state_height);
        self.validator_set_ledger_height = Some(ledger_height);
        true
    }

    /// Checked refresh from the live engine ledger with explicit heights.
    ///
    /// Restore / snapshot-refresh paths MUST call this (not the unchecked
    /// [`Self::refresh_validator_set_from_staking`]): it compares the ledger
    /// height against the state height and fail-closes to observer on
    /// staleness instead of silently installing a foreign set.
    pub async fn refresh_validator_set_from_staking_checked(
        &mut self,
        state_height: u64,
        ledger_height: u64,
    ) -> bool {
        let ledger = self.state.staking_read().await.clone();
        self.refresh_validator_set_from_ledger(&ledger, state_height, ledger_height)
            .await
    }

    /// Refresh the set from FRESH domain-snapshot bytes fetched separately
    /// from blocks (the lagging-node repair path).
    ///
    /// Decodes `domain_bytes` (V0/V1 via
    /// [`crate::storage::decode_domain_snapshot`]) and installs its staking
    /// ledger through [`Self::refresh_validator_set_from_ledger`] with the
    /// snapshot's height as `ledger_height` and the node's current state
    /// height as `state_height`. Undecodable bytes are a loud `Err` and never
    /// touch the set. This is how a node whose bond predates every walkable
    /// body pulls the CURRENT set without replaying ancient history.
    pub async fn refresh_validator_set_from_domain_bytes(
        &mut self,
        domain_bytes: &[u8],
        state_height: u64,
        ledger_height: u64,
    ) -> Result<bool, String> {
        let snap = crate::storage::decode_domain_snapshot(domain_bytes)
            .map_err(|e| format!("validator-set refresh: domain snapshot at {ledger_height} undecodable: {e}"))?;
        Ok(self
            .refresh_validator_set_from_ledger(&snap.staking, state_height, ledger_height)
            .await)
    }

    /// Recompute the validator set (and voting power) from the staking ledger.
    ///
    /// Reads the ledger out of the **state engine**, not from a node-local copy:
    /// consensus has to be a function of the block, otherwise two nodes that
    /// heard different bond transactions over RPC would derive different
    /// validators and deadlock on disagreeing about who proposes.
    ///
    /// No-op when nobody meets the minimum self-bond, so a network that has
    /// never been bonded keeps using its config-defined set.
    ///
    /// Apply-path wrapper: the ledger just came out of the transition at the
    /// current height, so state and ledger heights coincide (always fresh).
    /// Restore / snapshot paths must use
    /// [`Self::refresh_validator_set_from_staking_checked`] with real heights
    /// instead, or a stale ledger installs silently (node C).
    pub async fn refresh_validator_set_from_staking(&mut self) -> bool {
        let h = self.hc.height;
        self.refresh_validator_set_from_staking_checked(h, h).await
    }

    /// View change: move to the next round.
    pub fn next_round(&mut self) {
        self.hc.next_round();
    }

    /// Adopt a block a peer reports as committed, once its certificate proves a
    /// real quorum of our own validators signed it.
    ///
    /// This is the catch-up path for a node that fell a round behind: the
    /// certificate is checked against the *local* validator set, so a peer can
    /// only make us apply a block that the network genuinely finalized. A peer
    /// cannot invent one.
    pub async fn adopt_committed(
        &mut self,
        height: u64,
        mut block: Block,
        certificate: crate::consensus::QuorumCertificate,
    ) -> Result<crate::cell::CellHash, String> {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        // §7 Phase 2 gate: adopting means executing, and execution is still
        // running for the decided height. The checks below read our root
        // (PRE-H until the worker reports back) and `apply_and_advance` would
        // queue a second apply behind it — for a height we have not advanced
        // past. Deferred, not validated; the peer rebroadcasts (and catch-up
        // re-walks) until we are ready.
        if self.apply_in_flight.is_some() {
            return Err("committed block deferred: apply in flight".to_string());
        }
        // Always the LOCAL set. This used to take it as a parameter, which meant
        // the "the certificate is checked against your own validators" guarantee
        // held only because of the single call site -- a property the doc comment
        // and OPERATIONS.md both asserted as intrinsic.
        let validators = self.validators.clone();
        if height != self.hc.height {
            return Err(format!("height mismatch (ours {}, peer {height})", self.hc.height));
        }
        if block.height != height {
            return Err("block height does not match the commit".to_string());
        }
        // SECURITY: the certificate must be a COMMIT certificate. `certificate.kind`
        // was never read, and `QuorumCertificate::verify` signs over the
        // certificate's own fields, so a PREVOTE quorum verified just as well.
        // Prevotes are broadcast in the clear for every round, including rounds
        // that never finalize, so a passive peer could harvest one off the wire,
        // relabel the kind and ship it as proof of finality -- with zero stake of
        // its own. "2/3 saw this block" is not "2/3 committed to it".
        if certificate.kind != crate::consensus::VoteKind::Precommit {
            return Err("commit certificate is not a precommit quorum".to_string());
        }
        // SECURITY: bind the certificate to this height AND round. Both fields are
        // signed, so without this check a quorum harvested at any height or round
        // replayed as a commit for our current height. `height` is already pinned
        // to `self.hc.height` above, so this makes the certificate describe the
        // height it is being used to prove.
        if certificate.height != height {
            return Err(format!(
                "certificate is for height {} not {height}",
                certificate.height
            ));
        }
        if certificate.round != self.hc.round {
            // Liveness window (audit 2026-10-06): a commit that landed while
            // we already timed out into a later round is still a valid quorum
            // for THIS height — refusing it forced a full catch-up for a
            // one-round skew ("60% of time 1 round apart"). Accept anything
            // within the same lookback the finalizer itself uses, so adoption
            // and finalization agree on what "recent" means. Future rounds are
            // still refused (forward sync owns them, not adoption).
            let behind = self.hc.round.saturating_sub(certificate.round);
            let lookback = crate::consensus::ROUND_LOOKBACK as u64;
            if certificate.round > self.hc.round || behind as u64 > lookback {
                return Err(format!(
                    "certificate is for round {} not {} (lookback {lookback})",
                    certificate.round, self.hc.round
                ));
            }
        }
        let bh = block.compute_hash();
        // Cheap binding check BEFORE the signature loop: `verify` runs one
        // Ed25519 verification per entry and the list is attacker-supplied and
        // uncapped, so checking the cheap thing first avoids an unbounded
        // signature-verification loop driven by one message.
        if certificate.block_hash != Some(bh) {
            return Err("certificate commits to a different block".to_string());
        }
        // Lock guard (audit 2026-10-06): the lookback window above accepts
        // STALE commits, but must never override our lock for a conflicting
        // block — we precommitted another value, so adopting this one would
        // finalize against our own vote. Tendermint unlocks only on a NEWER
        // polka, never on an older QC. Same-block certs pass (locked == bh).
        if let Some((locked_bh, _)) = self.hc.locked {
            if locked_bh != bh {
                return Err("certificate conflicts with our locked block".to_string());
            }
        }
        if certificate.signatures.len() > MAX_COMMIT_CERT_SIGNERS {
            return Err("commit certificate has an implausible number of signers".to_string());
        }
        // HOT-PATH ORDER (observer C, 2026-10-13): every check below is fail-closed,
        // so order changes cost, not safety. The expensive one is `certificate.verify`
        // (one Ed25519 + one Falcon-512 verify per signer on Pure PQ) — run ALL cheap
        // header checks first so a forked/misaddressed commit dies before burning
        // weak-CPU verifier time. Previously the QC verify ran before the linkage
        // checks and every stale commit paid full crypto cost.
        //
        // SECURITY: the proposer must be the one the schedule names for this
        // height/round, not merely a key that signed. Otherwise a peer names an
        // address it controls, and `apply_block_fees_rewards` credits the fees to
        // it with no membership test.
        if Some(block.proposer) != validators.proposer_for(height, certificate.round) {
            return Err("committed block's proposer is not the expected proposer".to_string());
        }
        // The block must still be a valid extension of what we finalized.
        // Checked here (before any signature loop) so a commit for a forked head
        // is refused on two hash comparisons, not on quorum verification.
        let expected_prev = self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
        if block.prev_hash != expected_prev {
            return Err("committed block does not extend our finalized head".to_string());
        }
        if block.transactions.len() > MAX_BLOCK_TXS {
            return Err("committed block is oversized".to_string());
        }
        let total_gas = block
            .transactions
            .iter()
            .fold(0u64, |acc, t| acc.saturating_add(t.gas_limit));
        if total_gas > MAX_BLOCK_GAS {
            return Err("committed block exceeds the gas limit".to_string());
        }
        // Single proposer signature before the quorum loop: one Ed25519 verify
        // filters forged bodies before paying per-signer QC cost.
        if !crate::consensus::verify_proposer_signature(&block) {
            return Err("committed block has no valid proposer signature".to_string());
        }
        if !certificate.verify(&validators) {
            return Err("commit certificate does not carry a validator quorum".to_string());
        }
        // SECURITY: do not let the adopt path decide a block that contradicts a lock
        // we already took, and do not skip the prevote requirement. Locally
        // `try_precommit_quorum` (consensus.rs) enforces both: a prevote quorum
        // for the SAME block plus lock-consistency
        // (`locked_round <= round && locked_block != block` refuses). Adopting
        // bypasses the state machine entirely, so without these two checks a
        // node that precommitted and locked block A would happily adopt and
        // finalize a conflicting B.
        if let Some((locked_block, locked_round)) = self.hc.locked {
            if locked_round <= certificate.round && locked_block != bh {
                return Err("refusing to adopt a block that contradicts our lock".to_string());
            }
        }
        // PREVOTE-QUORUM CONSISTENCY (parity with `try_precommit_quorum`):
        // the local path refuses to decide a block unless a prevote quorum for
        // the SAME block exists in the same round. The adopt path receives only
        // the precommit QC on the wire, so full parity is IMPOSSIBLE without a
        // wire change: the peer would have to ship a prevote QC for
        // (height, round, block) alongside the commit certificate (new param or
        // envelope field), and we would `verify` it against `self.validators`
        // exactly like the precommit QC above. The signature is deliberately
        // unchanged (main.rs + tests call `adopt_committed(height, block,
        // certificate)`), so what we CAN do soundly is consult `self.hc`'s
        // recorded prevotes for `certificate.round`: if we observed a quorum
        // for a DIFFERENT target (another block, or nil), adopting this block
        // contradicts evidence we already hold and is refused. If we observed
        // nothing -- the normal catching-up node -- the check is VACUOUS and
        // the precommit QC is trusted transitively (honest validators only
        // precommit after a prevote quorum, so 2/3 precommits imply one
        // existed). Residual gap, stated plainly: a Byzantine quorum (or key
        // compromise reaching quorum power) can fabricate precommits for a
        // block nobody prevoted, and a lagging node with empty prevote sets
        // cannot tell; closing it requires the wire change above, not a
        // stricter local check (refusing on empty local prevotes would make
        // catch-up impossible by construction).
        if let Some(set) = self.hc.prevote_set(certificate.round) {
            if let Some(local_target) = set.quorum_target(&validators) {
                if local_target != Some(bh) {
                    return Err("refusing to adopt: our prevote quorum for this round is for a different block".to_string());
                }
            }
        }
        // SECURITY: bind the block to the state it builds on. A block header commits
        // to the state root BEFORE it is applied, and the linkage check above already
        // forces the block to extend our own finalized head -- so the parent state IS
        // ours and our live root is the right thing to compare against. Without this
        // the adopt path applied blocks to a state the network never committed to,
        // and computed a root nobody else had.
        // (Linkage, size/gas and proposer-signature checks ran above, before the QC
        // verify — not repeated here: the hot path verifies each once.)
        let root_before = self.state.get_state_root().await;
        if block.state_root != root_before {
            return Err(format!(
                "committed block claims parent state root {} but our state is {}",
                hex::encode(block.state_root),
                hex::encode(root_before)
            ));
        }
        if !crate::sharding::Transaction::verify_signatures_batch(&block.transactions) {
            return Err("committed block contains a bad transaction signature".to_string());
        }
        // Actor-mailbox cap (adopt side): the same deterministic refusal as
        // propose/finalize, so a Byzantine commit carrying an over-cap block
        // cannot smuggle a root-invisible leftover past the decision boundary.
        self.check_actor_cap(&block).await?;
        // Timestamp gate (adopt side, A3): the same fail-closed parent check
        // the proposal path runs, so a commit cannot smuggle a timestamp no
        // proposer could publish. Runs BEFORE the body is stored: the check
        // reads the parent out of `blocks`/`last_decision`, and storing first
        // would let a block vouch for itself.
        self.check_block_timestamp(&block)?;

        // DOWNTIME PARITY with the local path: the transition reads its slash
        // evidence from `block.precommit_qc`, and this body never ran the
        // height's rounds locally, so the body may arrive without a certificate
        // while the commit message carries the verified one. Attach the
        // just-verified certificate to the body BEFORE it is stored and applied:
        // the slash then sees the identical signer set a locally-finalizing node
        // attached to the same block, and a later reorg re-apply of this very
        // body reproduces the same burn instead of finding no evidence at all.
        // `Block::compute_hash` deliberately excludes the QC (it commits to the
        // header + transactions), so attaching it cannot change `bh`.
        // Without this, a node catching up skipped the burn (and the pool
        // debit) while a node that finalized locally applied it, and the two
        // reached different state roots from the same block.
        self.hc.precommit_qc = Some(certificate.clone());
        block.precommit_qc = Some(certificate);
        self.blocks.insert(bh, block.clone());
        self.apply_and_advance(bh, &block).await;
        Ok(bh)
    }

    pub async fn state_root(&self) -> [u8; 32] {
        self.state.get_state_root().await
    }
}

/// In-process multi-validator cluster used for tests and the local simulator.
pub struct Cluster {
    pub nodes: Vec<ValidatorRuntime>,
}

impl Cluster {
    /// Build a cluster from (key, own state) pairs. Each validator must get its
    /// OWN state engine (nodes do not share mutable state in reality).
    pub fn new(nodes: Vec<(SigningKey, Arc<InMemoryStateEngine>)>) -> Self {
        let validators = ValidatorSet::from_list(
            nodes
                .iter()
                .map(|(k, _)| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let runtimes = nodes
            .into_iter()
            .map(|(k, st)| ValidatorRuntime::new(k, validators.clone(), st, 1))
            .collect();
        Self { nodes: runtimes }
    }

    /// Build a cluster whose runtimes all produce/validate blocks for one shard
    /// of a multi-shard process. With the default (`single`) registry this is
    /// indistinguishable from [`Cluster::new`] except for the block `shard_id`.
    pub fn new_sharded(
        nodes: Vec<(SigningKey, Arc<InMemoryStateEngine>)>,
        shard_id: ShardId,
        registry: ShardRegistry,
    ) -> Self {
        let validators = ValidatorSet::from_list(
            nodes
                .iter()
                .map(|(k, _)| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let runtimes = nodes
            .into_iter()
            .map(|(k, st)| {
                ValidatorRuntime::new(k, validators.clone(), st, 1)
                    .with_shard(shard_id, registry.clone())
            })
            .collect();
        Self { nodes: runtimes }
    }

    /// Like [`Cluster::new_sharded`] but wires every runtime to the shared
    /// node-local cross-shard transport, so this shard can publish outbound
    /// messages and consume inbound ones.
    pub fn new_sharded_with_transport(
        nodes: Vec<(SigningKey, Arc<InMemoryStateEngine>)>,
        shard_id: ShardId,
        registry: ShardRegistry,
        transport: Arc<crate::network::CrossShardTransport>,
    ) -> Self {
        let mut c = Self::new_sharded(nodes, shard_id, registry);
        // C1 anchor: one registry per CLUSTER (not per process): every shard
        // in this process shares it (like production), but independent test
        // clusters never collide (a process-global would mix their geneses).
        let hdrs: Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>> =
            Arc::new(std::sync::RwLock::new(
                crate::sharding::FinalizedHeaderRegistry::default(),
            ));
        for n in &mut c.nodes {
            n.cross_shard = Some(transport.clone());
            n.finalized_headers = Some(hdrs.clone());
            n.state.with_finalized_headers(hdrs.clone());
        }
        c
    }

    pub fn height(&self) -> Height {
        self.nodes.first().map(|n| n.height()).unwrap_or(0)
    }

    /// Seed every node's mempool with the same transaction.
    pub async fn broadcast_tx(&mut self, tx: Transaction) {
        for n in &mut self.nodes {
            n.add_tx(tx.clone()).await;
        }
    }

    /// Run one full consensus round at the current height and return the block hash.
    pub async fn run_height(&mut self, timestamp: u64) -> BlockHash {
        // 1. proposer builds and signs a block
        let proposer_idx = self
            .nodes
            .iter()
            .position(|n| n.is_proposer())
            .expect("no proposer for this height");
        let block = self.nodes[proposer_idx]
            .propose(timestamp)
            .await
            .expect("proposer failed to propose");
        let bh = block.compute_hash();
        let proposer_id = self.nodes[proposer_idx].id;

        // 2. distribute the proposal
        for (i, n) in self.nodes.iter_mut().enumerate() {
            if i != proposer_idx {
                let r = n.hc.round;
                n.on_proposal(proposer_id, block.clone(), r)
                    .await
                    .expect("proposal rejected");
            }
        }

        // 3. collect and distribute prevotes
        let prevotes: Vec<Vote> = self.nodes.iter().filter_map(|n| n.make_prevote()).collect();
        for v in &prevotes {
            for n in self.nodes.iter_mut() {
                let _ = n.on_prevote(v.clone());
            }
        }

        // 4. collect and distribute precommits (locking happens here)
        let precommits: Vec<Vote> = self.nodes.iter_mut().filter_map(|n| n.make_precommit()).collect();
        for v in &precommits {
            for n in self.nodes.iter_mut() {
                let _ = n.on_precommit(v.clone());
            }
        }

        // 5. finalize + apply + advance
        for n in self.nodes.iter_mut() {
            let _ = n.try_finalize().await;
        }
        bh
    }
}

/// An in-process multi-shard harness: one [`Cluster`] per shard, all sharing a
/// single node-local [`crate::network::CrossShardTransport`].
///
/// This is the M2 analogue of [`Cluster`]: it proves a source shard and a
/// destination shard, running as two consensus instances in one process, can
/// move value atomically through committed cross-shard messages. It is also the
/// shape the production loop uses (`STELL_SHARDS=0,1` over one infnode `Node`).
pub struct ShardedCluster {
    pub shards: std::collections::BTreeMap<ShardId, Cluster>,
    pub transport: Arc<crate::network::CrossShardTransport>,
    pub registry: ShardRegistry,
}

impl ShardedCluster {
    pub fn new(
        registry: ShardRegistry,
        shards: Vec<(ShardId, Vec<(SigningKey, Arc<InMemoryStateEngine>)>)>,
        transport: Arc<crate::network::CrossShardTransport>,
    ) -> Self {
        let mut map = std::collections::BTreeMap::new();
        for (shard_id, nodes) in shards {
            map.insert(
                shard_id,
                Cluster::new_sharded_with_transport(
                    nodes,
                    shard_id,
                    registry.clone(),
                    transport.clone(),
                ),
            );
        }
        // C1 anchor: ONE registry for the whole multi-shard process (both
        // shards read what either finalized). Per-Cluster registries from the
        // constructor above are replaced by the shared one.
        let hdrs: Arc<std::sync::RwLock<crate::sharding::FinalizedHeaderRegistry>> =
            Arc::new(std::sync::RwLock::new(
                crate::sharding::FinalizedHeaderRegistry::default(),
            ));
        for c in map.values_mut() {
            for n in &mut c.nodes {
                n.finalized_headers = Some(hdrs.clone());
                n.state.with_finalized_headers(hdrs.clone());
            }
        }
        Self {
            shards: map,
            transport,
            registry,
        }
    }

    pub fn shard(&self, shard_id: ShardId) -> &Cluster {
        self.shards.get(&shard_id).expect("unknown shard")
    }

    pub fn shard_mut(&mut self, shard_id: ShardId) -> &mut Cluster {
        self.shards.get_mut(&shard_id).expect("unknown shard")
    }

    /// Seed every shard's mempool; the per-shard filter keeps the transaction
    /// only on its source shard.
    pub async fn broadcast_tx(&mut self, tx: Transaction) {
        for c in self.shards.values_mut() {
            c.broadcast_tx(tx.clone()).await;
        }
    }

    /// Run one consensus height for a single shard.
    pub async fn run_height(&mut self, shard_id: ShardId, timestamp: u64) -> BlockHash {
        // C1 genesis anchoring for sim clusters: note the zero-hash genesis
        // parent for EVERY shard (not just the running one) from each
        // engine's current root. Test engines are funded before first use,
        // so these roots are the exact pre-roots height-1 messages reference.
        // Idempotent (real finals overwrite nothing: different keys).
        for (sid, cluster) in self.shards.iter() {
            if let Some(n) = cluster.nodes.first() {
                if n.finalized.is_empty() {
                    if let Some(reg) = n.finalized_headers.as_ref() {
                        let root = n.state.get_state_root().await;
                        if let Ok(mut r) = reg.write() {
                            r.note_finalized(*sid, [0u8; 32], root);
                        }
                    }
                }
            }
        }
        self.shard_mut(shard_id).run_height(timestamp).await
    }
}

/// State manager with checkpointing, to support deterministic reorgs.
///
/// A checkpoint is a full state snapshot taken at the last finalized height.
/// On a reorg we restore that checkpoint and re-apply the new canonical blocks,
/// which is correct and simple (reorgs only ever touch non-finalized blocks).
///
/// REORG PARITY: `apply_block` delegates to the SAME core the live consensus
/// path uses (`InMemoryStateEngine::apply_block_transition`), fed with the SAME
/// inputs (the block itself, plus a reward resolved by `block_reward_for`), so
/// a re-applied block produces byte-identical state - state root, receipts and
/// applied counters - to the node that finalized it. It used to loop
/// `apply_transaction` over the transactions instead, which charged a different
/// fee (gas actually consumed rather than the declared limit) and skipped the
/// proposer fee credit, the block reward, unbonding maturity and the downtime
/// slash entirely: a reorg then silently forked a second chain under the same
/// height. Anything genuinely node-local (mempool, consensus bookkeeping) is
/// mirrored here field by field rather than dropped, and is documented on the
/// field it mirrors.
pub struct ChainState {
    pub state: Arc<InMemoryStateEngine>,
    pub checkpoint: Vec<u8>,
    /// Per-block proposer reward, mirroring `ValidatorRuntime::block_reward`.
    pub block_reward: u64,
    /// Governance copy used to resolve the reward, mirroring
    /// `ValidatorRuntime::governance`.
    pub governance: Option<crate::governance::Governance>,
    /// Transactions applied so far - mirrors `ValidatorRuntime::applied_txs`.
    pub applied_txs: u64,
    /// Receipts (per-transaction success flags) of the last applied block -
    /// mirrors `ValidatorRuntime::applied_statuses`.
    pub applied_statuses: Vec<bool>,
    /// Per-transaction fee actually charged by the last applied block -
    /// mirrors `ValidatorRuntime::applied_fees`.
    pub applied_fees: Vec<u64>,
    /// Optional node-local mempool. The live path prunes included txs from its
    /// mempool on every apply; attach the same pool here to reproduce that.
    /// The mempool is NOT consensus state and is not committed, so leaving it
    /// unset cannot move the state root - it only decides whether an
    /// already-included transaction stays queued for re-proposal.
    mempool: Option<Arc<tokio::sync::RwLock<crate::mempool::Mempool>>>,
    /// §5 M3: mirrors of the live runtime's cross-shard sets, so a reorg
    /// re-apply derives the same linkage/timeout/completion verdicts — and
    /// the same bounce refunds — as the node that finalized the blocks.
    /// (No transport here: publishing and KV pruning are node-local effects
    /// of the live path, not state.)
    consumed_cross_shard: HashSet<CrossShardKey>,
    produced_cross_shard: HashMap<[u8; 32], (Transaction, u64)>,
    completed_cross_shard: HashSet<[u8; 32]>,
}

impl ChainState {
    pub fn new(state: Arc<InMemoryStateEngine>) -> Self {
        Self {
            state: state.clone(),
            checkpoint: Vec::new(),
            block_reward: 0,
            governance: None,
            applied_txs: 0,
            applied_statuses: Vec::new(),
            applied_fees: Vec::new(),
            mempool: None,
            consumed_cross_shard: HashSet::new(),
            produced_cross_shard: HashMap::new(),
            completed_cross_shard: HashSet::new(),
        }
    }

    /// Pay the governed/default block reward, exactly as the live path does.
    pub fn with_block_reward(mut self, reward: u64) -> Self {
        self.block_reward = reward;
        self
    }

    /// Use this governance copy when resolving the block reward (mirrors
    /// `ValidatorRuntime::with_governance`).
    pub fn with_governance(mut self, g: crate::governance::Governance) -> Self {
        self.governance = Some(g);
        self
    }

    /// Prune included transactions from this pool on apply, exactly as
    /// `apply_block_fees_rewards` does for the live path.
    pub fn with_mempool(mut self, mempool: Arc<tokio::sync::RwLock<crate::mempool::Mempool>>) -> Self {
        self.mempool = Some(mempool);
        self
    }

    /// Configure disjoint wave parallel block execution for historical replay / reorg.
    pub fn with_parallel_exec(self, enabled: bool) -> Self {
        self.state.set_parallel_exec(enabled);
        self
    }

    /// Apply a block to the state through the SHARED block transition - the
    /// same `InMemoryStateEngine::apply_block_transition` the live consensus
    /// path runs on finalize, adopt, walk and replay. Returns nothing; the
    /// per-block outcome is recorded in `applied_statuses` / `applied_txs`,
    /// the same bookkeeping `ValidatorRuntime` keeps for receipts.
    pub async fn apply_block(&mut self, block: &Block) {
        let reward = block_reward_for(self.governance.as_ref(), self.block_reward);
        let out = self.state.apply_block_transition(block, reward).await;
        self.applied_statuses = out.status;
        self.applied_fees = out.tx_fees;
        self.applied_txs += out.applied as u64;
        // §5 M3 parity with `ValidatorRuntime::record_apply_outcome` (same
        // block -> same verdicts -> same refunds, in the same deterministic
        // key order). Transport effects (ack publish, KV prune) are live-path
        // node-local effects and are deliberately NOT mirrored: they cannot
        // move the state root.
        for msg in &block.cross_shard_out {
            if msg.is_transfer() && msg.is_outbound_for(block.shard_id) {
                let tx_hash = msg.tx.compute_tx_hash();
                self.produced_cross_shard
                    .entry(tx_hash)
                    .or_insert((msg.tx.clone(), block.height));
            }
        }
        let mut inbound_sorted: Vec<&CrossShardMessage> = block
            .cross_shard_out
            .iter()
            .filter(|m| m.is_inbound_for(block.shard_id))
            .collect();
        inbound_sorted.sort_by_key(|m| CrossShardKey::of(m));
        for msg in inbound_sorted {
            let key = CrossShardKey::of(msg);
            if msg.is_transfer() {
                self.consumed_cross_shard.insert(key);
            } else if msg.is_ack() || msg.is_bounce() {
                if msg.merkle_inclusion_proof.is_some() || msg.trusted {
                    continue;
                }
                if self.completed_cross_shard.contains(&msg.tx.compute_tx_hash()) {
                    continue;
                }
                let linked = self
                    .produced_cross_shard
                    .get(&msg.tx.compute_tx_hash())
                    .is_some();
                if !linked {
                    continue;
                }
                if msg.is_bounce() {
                    let hp = self.produced_cross_shard[&msg.tx.compute_tx_hash()].1;
                    if !crate::sharding::bounce_eligible(hp, block.height) {
                        continue;
                    }
                }
                if !self.consumed_cross_shard.insert(key) {
                    continue;
                }
                if !self.completed_cross_shard.insert(msg.tx.compute_tx_hash()) {
                    continue;
                }
                if msg.is_bounce() {
                    let _ = self.state.credit_native(&msg.tx.from, msg.tx.amount).await;
                }
            }
        }
        if let Some(mp) = &self.mempool {
            let included: Vec<[u8; 32]> =
                block.transactions.iter().map(|t| t.compute_tx_hash()).collect();
            mp.write().await.prune_confirmed(&included);
        }
    }

    /// The validator set this state implies: the same read-only derivation
    /// `ValidatorRuntime::refresh_validator_set_from_staking` performs after
    /// every live apply. `ChainState` holds no consensus view of its own (the
    /// proposer schedule and quorum live in `HeightConsensus`), so the caller
    /// re-derives from here after a reorg. Because the staking ledger is
    /// engine state committed by the shared transition, the derivation input is
    /// byte-identical on both paths.
    pub async fn validator_set(&self) -> crate::consensus::ValidatorSet {
        self.state.staking_read().await.to_validator_set()
    }

    /// Snapshot the current state (call at each finalized height).
    pub async fn save_checkpoint(&mut self) {
        self.checkpoint = self.state.create_snapshot().await;
    }

    /// Restore the last checkpoint (finalized state).
    pub async fn restore_checkpoint(&self) {
        if !self.checkpoint.is_empty() {
            let _ = self.state.restore_snapshot(&self.checkpoint).await;
        }
    }

    /// Perform a reorg: restore the finalized checkpoint, then re-apply the new
    /// canonical blocks from the reorg plan (ancestor-first).
    pub async fn reorg(&mut self, tree: &crate::chain::BlockTree, plan: &crate::chain::ReorgPlan) {
        self.restore_checkpoint().await;
        for h in &plan.apply {
            if let Some(b) = tree.get(h) {
                self.apply_block(b).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_engine::AccountState;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    async fn funded_state(owner: [u8; 32]) -> Arc<InMemoryStateEngine> {
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(owner, 10_000_000)).await;
        st
    }

    /// Regression: the RPC layer and the consensus loop once had SEPARATE
    /// mempools, so a transaction submitted over RPC was never selected by the
    /// proposer (it was only ever filled from the P2P overlay) and on a
    /// single-validator node it was never included at all. A shared mempool
    /// makes a submitted transaction the same object the proposer picks up.
    #[tokio::test]
    async fn rpc_mempool_is_the_mempool_the_proposer_uses() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let state = funded_state(me).await;
        let validators = ValidatorSet::from_list(vec![(me, 1)]);

        // This is the handle the RPC layer writes to.
        let shared = Arc::new(tokio::sync::RwLock::new(crate::mempool::Mempool::default()));
        let mut rt = ValidatorRuntime::new(key.clone(), validators, state, 1)
            .with_mempool(shared.clone());

        let tx = crate::sharding::Transaction::sign(&key, [1u8; 32], 10, 1_000, 0, 1, 1);
        let balance = rt.state.get_account(&me).await.map(|a| a.balance).unwrap_or(0);

        // Submit exactly the way the RPC handler does...
        shared.write().await.add_checked(tx.clone(), balance).unwrap();
        assert_eq!(shared.read().await.len(), 1, "the RPC's mempool must hold it");

        // ...and the proposer must select that very same transaction.
        let selected = rt.mempool.read().await.select_bounded(100, 30_000_000);
        assert_eq!(selected.len(), 1, "proposer must see the transaction submitted over RPC");
        assert_eq!(selected[0].compute_tx_hash(), tx.compute_tx_hash());

        // And a confirmed transaction leaves both views empty.
        rt.mempool.write().await.prune_confirmed(&[tx.compute_tx_hash()]);
        assert!(rt.mempool.read().await.is_empty());
        assert!(shared.read().await.is_empty(), "RPC view must not keep a confirmed tx");
    }

    #[test]
    fn missing_sender_accounts_names_exactly_the_race_arrivals() {
        // Pure helper for the r0-fullness refresh: only senders the snapshot
        // missed are returned, in pool order, deterministically.
        let mut snap = std::collections::HashMap::new();
        snap.insert([1u8; 32], (0u64, 100u64));
        let pool = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        assert_eq!(missing_sender_accounts(&snap, &pool), vec![[2u8; 32], [3u8; 32]]);
        assert!(missing_sender_accounts(&snap, &[[1u8; 32]]).is_empty());
        assert!(missing_sender_accounts(&std::collections::HashMap::new(), &[]).is_empty());
    }

    #[tokio::test]
    async fn demanded_demand_survives_transient_revalidation_failure() {
        // Lock-hint rescue liveness: a demand must be consumed exactly once —
        // on successful serve — never on a failed re-validation. Dropping it
        // on a transient failure costs a full hint round-trip (the peer only
        // re-hints on its next nil prevote) while the round keeps timing out.
        let valkey = SigningKey::generate(&mut OsRng);
        let me = valkey.verifying_key().to_bytes();
        let peer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1), (peer, 1)]);
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(me, 100_000_000)).await;
        let mut rt = ValidatorRuntime::new(valkey.clone(), validators, st, 1);
        while rt.hc.proposer() != Some(me) {
            rt.next_round();
        }
        let body = rt.propose(1_000).await.expect("proposer must propose");
        let h = body.compute_hash();
        // Reopen the propose gate (the fresh path self-recorded a proposal).
        rt.hc.proposal = None;
        // The peer is stuck on our body and says so with a nil prevote hint.
        rt.note_lock_hint(rt.hc.height, VoteKind::Prevote, None, Some(h));
        assert!(rt.demanded.contains(&h), "hint must record the demand");
        // Corrupt the stored copy so the serve-time re-validation fails.
        rt.blocks.get_mut(&h).expect("body must be stored").state_root = [9u8; 32];
        rt.hc.proposal = None;
        let _ = rt.propose(1_000).await;
        assert!(
            rt.demanded.contains(&h),
            "transient re-validation failure must not consume the demand"
        );
        // Repair the stored copy: the still-queued demand serves exactly once.
        let root = rt.state.get_state_root().await;
        rt.blocks.get_mut(&h).expect("body must be stored").state_root = root;
        rt.hc.proposal = None;
        let served = rt.propose(1_000).await.expect("repaired demand must serve");
        assert_eq!(served.compute_hash(), h, "must re-propose the demanded body verbatim");
        assert!(rt.demanded.is_empty(), "successful serve consumes the demand one-shot");
    }

    #[tokio::test]
    async fn r0_proposal_packs_the_full_available_mempool_deterministically() {
        // Regression for the live partial-then-retry shape (r0 52tx, r2 200tx
        // from the same pool): the proposer must pack everything available at
        // select time, and rebuilding must yield the identical set.
        //
        // NOTE on scale: sequences are 10 deep per sender; the pass budget
        // lives in mempool.rs (`select_for_block_multi`, 64 passes) — an
        // adversarial fee-hash order completes one nonce per pass per sender,
        // so only chains deeper than 64 per sender select partially. This test
        // pins the proposer-side contract.
        let valkey = SigningKey::generate(&mut OsRng);
        let me = valkey.verifying_key().to_bytes();
        let st = Arc::new(InMemoryStateEngine::new());
        st.update_account(AccountState::new(me, 100_000_000)).await;
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let mut rt = ValidatorRuntime::new(valkey.clone(), validators, st, 1);
        assert!(rt.is_proposer());

        // 5 senders x 10 contiguous nonces = 50 executable txs.
        let mut senders = Vec::new();
        for _ in 0..5 {
            let sk = SigningKey::generate(&mut OsRng);
            let from = sk.verifying_key().to_bytes();
            rt.state.update_account(AccountState::new(from, 100_000_000)).await;
            senders.push(sk);
        }
        for sk in &senders {
            for i in 0..10u64 {
                rt.add_tx(Transaction::sign(sk, [1u8; 32], 10, 100, i, 1, 1)).await;
            }
        }
        assert_eq!(rt.mempool.read().await.len(), 50);

        let first = rt.propose(1_000).await.expect("sole proposer must propose");
        assert_eq!(
            first.transactions.len(),
            50,
            "r0 must carry the full available mempool, not a partial prefix"
        );
        // Deterministic rebuild: the same pool yields the same ordered set.
        let second = rt.propose(1_000).await.expect("rebuild must also propose");
        let h1: Vec<[u8; 32]> =
            first.transactions.iter().map(|t| t.compute_tx_hash()).collect();
        let h2: Vec<[u8; 32]> =
            second.transactions.iter().map(|t| t.compute_tx_hash()).collect();
        assert_eq!(h1, h2, "packing snapshot must be deterministic");
    }

    fn signer_keys(n: usize) -> Vec<SigningKey> {
        (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
    }

    #[tokio::test]
    async fn cluster_finalizes_blocks_and_applies_state() {
        let val_keys = signer_keys(4);
        let user = SigningKey::generate(&mut OsRng);
        let from = user.verifying_key().to_bytes();
        let to = [9u8; 32];

        // Each validator gets its OWN identical state
        let mut nodes = Vec::new();
        for k in &val_keys {
            nodes.push((k.clone(), funded_state(from).await));
        }
        let mut cluster = Cluster::new(nodes);

        // 3 heights, one tx each
        for h in 0..3u64 {
            let tx = Transaction::sign(&user, to, 1_000, 0, h, 1, 1);
            cluster.broadcast_tx(tx).await;
            let bh = cluster.run_height(1_000 + h).await;

            // every node finalized the same block at this height
            for n in &cluster.nodes {
                assert_eq!(n.finalized.last().unwrap().1, bh);
                assert_eq!(n.finalized.last().unwrap().0, h + 1);
            }
        }

        // all nodes converged to the same state root and balances
        let roots: Vec<[u8; 32]> = {
            let mut v = Vec::new();
            for n in &cluster.nodes {
                v.push(n.state_root().await);
            }
            v
        };
        assert!(roots.windows(2).all(|w| w[0] == w[1]), "nodes diverged on state root");

        for n in &cluster.nodes {
            assert_eq!(n.applied_txs, 3, "each node applied 3 txs");
            let sender = n.state.get_account(&from).await.unwrap();
            let recipient = n.state.get_account(&to).await.unwrap();
            assert_eq!(sender.balance, 10_000_000 - 3_000);
            assert_eq!(recipient.balance, 3_000);
        }
    }

    #[tokio::test]
    async fn cluster_survives_one_byzantine_validator() {
        // 4 validators, quorum = 3. Simulate one validator going silent.
        let val_keys = signer_keys(4);
        let user = SigningKey::generate(&mut OsRng);
        let from = user.verifying_key().to_bytes();
        let to = [9u8; 32];

        let mut nodes = Vec::new();
        for k in &val_keys {
            nodes.push((k.clone(), funded_state(from).await));
        }
        let mut cluster = Cluster::new(nodes);

        let tx = Transaction::sign(&user, to, 500, 0, 0, 1, 1);
        cluster.broadcast_tx(tx).await;

        // Silence the LAST validator: it never contributes prevotes/precommits.
        // We emulate this by running the round manually with only 3 voters.
        let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
        let block = cluster.nodes[proposer_idx].propose(1_000).await.unwrap();
        let bh = block.compute_hash();
        let proposer_id = cluster.nodes[proposer_idx].id;
        for (i, n) in cluster.nodes.iter_mut().enumerate() {
            if i != proposer_idx {
                let r = n.hc.round;
                n.on_proposal(proposer_id, block.clone(), r).await.unwrap();
            }
        }

        // only the first 3 (a quorum) vote
        let prevotes: Vec<Vote> = cluster.nodes.iter().take(3).filter_map(|n| n.make_prevote()).collect();
        assert_eq!(prevotes.len(), 3);
        for v in &prevotes {
            for n in cluster.nodes.iter_mut() {
                let _ = n.on_prevote(v.clone());
            }
        }
        let precommits: Vec<Vote> = cluster.nodes.iter_mut().take(3).filter_map(|n| n.make_precommit()).collect();
        assert_eq!(precommits.len(), 3);
        for v in &precommits {
            for n in cluster.nodes.iter_mut() {
                let _ = n.on_precommit(v.clone());
            }
        }
        // 3-of-4 is a quorum -> the first 3 nodes finalize despite the 4th being silent
        let mut finalized_count = 0;
        for n in cluster.nodes.iter_mut().take(3) {
            if n.try_finalize().await == Some(bh) {
                finalized_count += 1;
            }
        }
        assert_eq!(finalized_count, 3, "quorum must finalize with 1/4 offline");
    }

    #[tokio::test]
    async fn no_finality_without_quorum() {
        let val_keys = signer_keys(4);
        let user = SigningKey::generate(&mut OsRng);
        let from = user.verifying_key().to_bytes();
        let mut nodes = Vec::new();
        for k in &val_keys {
            nodes.push((k.clone(), funded_state(from).await));
        }
        let mut cluster = Cluster::new(nodes);

        let tx = Transaction::sign(&user, [9u8; 32], 1, 0, 0, 1, 1);
        cluster.broadcast_tx(tx).await;

        let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
        let block = cluster.nodes[proposer_idx].propose(1_000).await.unwrap();
        let proposer_id = cluster.nodes[proposer_idx].id;
        for (i, n) in cluster.nodes.iter_mut().enumerate() {
            if i != proposer_idx {
                let r = n.hc.round;
                n.on_proposal(proposer_id, block.clone(), r).await.unwrap();
            }
        }
        // only 2 of 4 vote -> below quorum 3
        let prevotes: Vec<Vote> = cluster.nodes.iter().take(2).filter_map(|n| n.make_prevote()).collect();
        for v in &prevotes {
            for n in cluster.nodes.iter_mut() {
                let _ = n.on_prevote(v.clone());
            }
        }
        let precommits: Vec<Vote> = cluster.nodes.iter_mut().take(2).filter_map(|n| n.make_precommit()).collect();
        for v in &precommits {
            for n in cluster.nodes.iter_mut() {
                let _ = n.on_precommit(v.clone());
            }
        }
        for n in cluster.nodes.iter_mut() {
            assert_eq!(n.try_finalize().await, None, "must not finalize without quorum");
        }
    }

    #[tokio::test]
    async fn proposal_validation_rejects_tampering() {
        let val_keys = signer_keys(4);
        let user = SigningKey::generate(&mut OsRng);
        let from = user.verifying_key().to_bytes();
        let mut nodes = Vec::new();
        for k in &val_keys {
            nodes.push((k.clone(), funded_state(from).await));
        }
        let mut cluster = Cluster::new(nodes);
        let tx = Transaction::sign(&user, [9u8; 32], 100, 0, 0, 1, 1);
        cluster.broadcast_tx(tx).await;

        let proposer_idx = cluster.nodes.iter().position(|n| n.is_proposer()).unwrap();
        let block = cluster.nodes[proposer_idx].propose(1).await.unwrap();
        let receiver_idx = (proposer_idx + 1) % cluster.nodes.len();
        let receiver = &cluster.nodes[receiver_idx];

        // The expected root is the state the block builds on: ours, right now.
        // Using the block's own value here would make the check vacuous, which is
        // exactly how it went unchecked in the first place.
        let root = receiver.state.get_state_root().await;
        assert_eq!(
            block.state_root, root,
            "a genuine block from the proposer must carry the shared state root"
        );

        // genuine block passes
        assert!(receiver.validate_proposal(&block, root).is_ok());

        // wrong height
        let mut b1 = block.clone();
        b1.height = 999;
        assert!(receiver.validate_proposal(&b1, root).is_err(), "wrong height must be rejected");

        // wrong proposer
        let mut b2 = block.clone();
        b2.proposer = [0xEE; 32];
        assert!(receiver.validate_proposal(&b2, root).is_err(), "wrong proposer must be rejected");

        // tampered tx signature
        let mut b3 = block.clone();
        if let Some(t) = b3.transactions.first_mut() {
            t.signature[0] ^= 0xFF;
        }
        assert!(receiver.validate_proposal(&b3, root).is_err(), "bad tx signature must be rejected");

        // oversized block (count check happens before signatures)
        let mut b4 = block.clone();
        b4.transactions = (0..MAX_BLOCK_TXS + 1)
            .map(|i| Transaction {
                from: [0u8; 32],
                to: [0u8; 32],
                amount: 0,
                gas_limit: 0,
                nonce: i as u64,
                source_shard: 1,
                target_shard: 1,
                signature: vec![],
                payload: vec![],
            })
            .collect();
        assert!(receiver.validate_proposal(&b4, root).is_err(), "oversized block must be rejected");

        // forged proposer signature: correct proposer FIELD, but the block is
        // signed by an attacker key -> authenticity check must reject it.
        use ed25519_dalek::Signer;
        let attacker = SigningKey::generate(&mut OsRng);
        let mut b5 = block.clone();
        let h = b5.compute_hash();
        let forged_sig = attacker.sign(&h).to_vec();
        b5.validator_signatures = vec![(attacker.verifying_key().to_bytes(), forged_sig)];
        assert!(
            receiver.validate_proposal(&b5, root).is_err(),
            "forged proposer signature must be rejected"
        );
    }

    #[tokio::test]
    async fn reorg_restores_state_and_applies_new_chain() {
        use crate::chain::ChainManager;
        use crate::sharding::MASTERCHAIN_SHARD;

        let user = SigningKey::generate(&mut OsRng);
        let from = user.verifying_key().to_bytes();
        let b_addr = [0xB0u8; 32];
        let c_addr = [0xC0u8; 32];

        let state = Arc::new(InMemoryStateEngine::new());
        state.update_account(AccountState::new(from, 1_000_000)).await;

        let mk = |height: u64, prev: [u8; 32], txs: Vec<Transaction>, sk: &SigningKey| {
            let mut blk = Block {
                shard_id: MASTERCHAIN_SHARD,
                height,
                prev_hash: prev,
                state_root: [0u8; 32],
                transactions: txs,
                cross_shard_out: vec![],
                timestamp: height,
                proposer: sk.verifying_key().to_bytes(),
                validator_signatures: vec![],
                precommit_qc: None,
            };
            blk.sign_block(sk);
            blk
        };

        let genesis = mk(0, [0u8; 32], vec![], &user);
        let mut cm = ChainManager::new(genesis);
        let g = cm.best_head();

        // Checkpoint = finalized (genesis) state.
        let cs = ChainState::new(state.clone());
        let mut cs = cs;
        cs.save_checkpoint().await;

        // Canonical chain A: two transfers of 100 to B.
        let blk1 = mk(1, g, vec![Transaction::sign(&user, b_addr, 100, 0, 0, 1, 1)], &user);
        let b1 = cm.insert(blk1.clone());
        let blk2 = mk(2, b1, vec![Transaction::sign(&user, b_addr, 100, 0, 1, 1, 1)], &user);
        let b2 = cm.insert(blk2.clone());
        cm.recompute_canonical();
        assert_eq!(cm.best_head(), b2);
        cs.apply_block(&blk1).await;
        cs.apply_block(&blk2).await;
        assert_eq!(state.get_account(&from).await.unwrap().balance, 999_800);
        assert_eq!(state.get_account(&b_addr).await.unwrap().balance, 200);

        // Longer fork B: three transfers of 50 to C.
        let f1 = mk(1, g, vec![Transaction::sign(&user, c_addr, 50, 0, 0, 1, 1)], &user);
        let fb1 = cm.insert(f1.clone());
        let f2 = mk(2, fb1, vec![Transaction::sign(&user, c_addr, 50, 0, 1, 1, 1)], &user);
        let fb2 = cm.insert(f2.clone());
        let f3 = mk(3, fb2, vec![Transaction::sign(&user, c_addr, 50, 0, 2, 1, 1)], &user);
        let fb3 = cm.insert(f3.clone());

        // Plan from canonical (b2) to the longer fork head (fb3).
        let plan = cm.reorg_plan(&fb3).unwrap().unwrap();
        assert_eq!(plan.rollback.len(), 2);
        assert_eq!(plan.apply.len(), 3);

        // Apply the reorg: state must reflect the new chain, not the old one.
        cs.reorg(&cm.tree, &plan).await;
        assert_eq!(state.get_account(&from).await.unwrap().balance, 999_850, "from: -150 only");
        assert_eq!(state.get_account(&c_addr).await.unwrap().balance, 150, "C has the new transfers");
        assert!(
            state.get_account(&b_addr).await.is_none(),
            "B's rolled-back transfers must be gone"
        );
    }

    /// Audit F5: `replay_historical_block` must verify a historical precommit QC
    /// against the validator set in force AT THAT HEIGHT, not the node's current
    /// (post-rotation / config) set. During replay the engine is already at the
    /// block's committed pre-state, so the staking ledger there IS the height's
    /// set -- this test proves replay consults it by making the two sets disjoint.
    #[tokio::test]
    async fn replay_verifies_qc_against_the_height_set_not_the_current_set() {
        use crate::consensus::{QuorumCertificate, VoteKind};
        use crate::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};

        // The set in force at the replayed height: bonded in the engine ledger.
        let historical = signer_keys(3);
        let engine = Arc::new(InMemoryStateEngine::new());
        {
            let mut ledger = engine.staking_write().await;
            for k in &historical {
                ledger
                    .bond(k.verifying_key().to_bytes(), MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
                    .unwrap();
            }
        }
        let historical_vs = engine.staking_read().await.to_validator_set();
        assert_eq!(historical_vs.len(), 3, "precondition: ledger holds the height's set");

        // The runtime's current set is DIFFERENT. If replay verified against this
        // one it would reject a genuine historical certificate.
        let decoy = signer_keys(3);
        let decoy_vs = ValidatorSet::from_list(
            decoy
                .iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let mut rt = ValidatorRuntime::new(historical[0].clone(), decoy_vs, engine.clone(), 1);

        let root = engine.get_state_root().await;
        let mut block = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1,
            proposer: historical[0].verifying_key().to_bytes(),
            validator_signatures: vec![],
            precommit_qc: None,
        };
        block.sign_block(&historical[0]);
        let bh = block.compute_hash();
        let sigs = historical
            .iter()
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect();
        block.precommit_qc = Some(QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: sigs,
        });

        rt.replay_historical_block(&block)
            .await
            .expect("replay must verify the QC against the height's ledger-derived set");
        // And the rotation afterwards installs that same set.
        assert_eq!(rt.validators.len(), 3);
    }

    /// Audit F10: a prevote quorum from an OLDER round must not be turned into a
    /// precommit at the current round. `try_prevote_quorum` still inspects the
    /// lookback window (so a late quorum can decide), but `make_precommit` must
    /// only act on a QC formed in the round we are actually in.
    #[tokio::test]
    async fn make_precommit_stamps_the_polka_round_not_the_local_round() {
        let ks = signer_keys(2);
        let vs = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let me = ks[0].verifying_key().to_bytes();
        let state = funded_state(me).await;
        let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state, 1);
        let h = rt.hc.height;
        let target = [0x42u8; 32];

        // A full prevote quorum for `target` at round 0.
        for k in &ks {
            rt.on_prevote(Vote::sign(k, h, 0, VoteKind::Prevote, Some(target)))
                .unwrap();
        }
        // Move on to round 1 BEFORE precommitting: the round-0 QC is now
        // BEHIND us. We still precommit -- but stamped with round 0, the round
        // the polka formed in (Tendermint). Casting at our own round 1 would
        // file the vote into a different bucket than the peer's, and with the
        // two nodes routinely one round apart neither side's precommit ever
        // matched (31 of 180 wasted rounds on the live stand: a full prevote
        // QC whose precommit leg never landed).
        rt.next_round();
        assert_eq!(rt.hc.round, 1);
        let pc_old = rt
            .make_precommit()
            .expect("a polka behind us must still be precommitted");
        assert_eq!(pc_old.round, 0, "precommit is stamped with the POLKA's round");
        assert_eq!(pc_old.block_hash, Some(target));
        assert_eq!(
            rt.hc.locked,
            Some((target, 0)),
            "the lock records the polka round, not the local round"
        );
        // Recasting for the same polka round is a duplicate, not a new vote:
        // main.rs dedups on (height, vote.round), and here we simply observe
        // that the same bytes come back (idempotent for the receiver).
        let again = rt.make_precommit().expect("idempotent re-cast");
        assert_eq!(again.round, 0);
        assert_eq!(again.block_hash, Some(target));

        // A polka in a NEWER round supersedes: we now precommit at round 1.
        for k in &ks {
            rt.on_prevote(Vote::sign(k, h, 1, VoteKind::Prevote, Some(target)))
                .unwrap();
        }
        let pc = rt.make_precommit().expect("current-round QC must precommit");
        assert_eq!(pc.round, 1);
        assert_eq!(pc.block_hash, Some(target));
    }

    #[tokio::test]
    async fn parallel_exec_configuration_and_preservation() {
        let ks = signer_keys(1);
        let me = ks[0].verifying_key().to_bytes();
        let vs = ValidatorSet::from_list(vec![(me, 1)]);
        let state = funded_state(me).await;

        let mut rt = ValidatorRuntime::new(ks[0].clone(), vs, state.clone(), 1);
        assert!(!rt.parallel_exec, "default parallel_exec is false");
        assert!(!rt.is_parallel_exec_enabled(), "default is disabled");
        assert!(!rt.state.is_parallel_exec_enabled(), "state default is disabled");

        // Enable parallel execution
        rt = rt.with_parallel_exec(true);
        assert!(rt.parallel_exec);
        assert!(rt.is_parallel_exec_enabled());
        assert!(rt.state.is_parallel_exec_enabled());

        // Temporarily clear on state directly; runtime preserves / restores it on propose
        rt.state.set_parallel_exec(false);
        assert!(!rt.state.parallel_exec.load(std::sync::atomic::Ordering::Acquire));
        let _ = rt.propose(1_000_000).await;
        assert!(rt.state.is_parallel_exec_enabled(), "propose preserves parallel exec on state");

        // Set to false via runtime
        rt.set_parallel_exec(false);
        assert!(!rt.parallel_exec);
        assert!(!rt.is_parallel_exec_enabled());
        assert!(!rt.state.is_parallel_exec_enabled());

        // Re-enable and verify apply_and_advance preserves it
        rt = rt.with_parallel_exec(true);
        rt.state.set_parallel_exec(false);
        let blk = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: rt.state.get_state_root().await,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_000_000,
            proposer: me,
            validator_signatures: vec![],
            precommit_qc: None,
        };
        rt.apply_and_advance(blk.compute_hash(), &blk).await;
        assert!(rt.state.is_parallel_exec_enabled(), "apply_and_advance preserves parallel exec on state");
    }

    #[tokio::test]
    async fn validator_runtime_with_falcon_key_produces_falcon_votes_and_proposals() {
        let key = SigningKey::generate(&mut OsRng);
        let me = key.verifying_key().to_bytes();
        let vs = ValidatorSet::from_list(vec![(me, 1)]);
        let state = funded_state(me).await;

        let fk = FalconKeypair::generate_from_seed(0x42);
        let mut rt = ValidatorRuntime::new(key.clone(), vs.clone(), state.clone(), 1)
            .with_falcon_key(fk.clone());

        assert!(rt.falcon_key.is_some());
        assert_eq!(rt.falcon_key.as_ref().unwrap().public_key, fk.public_key);

        // 1. make_prevote produces vote with Falcon signature
        let prevote = rt.make_prevote().expect("prevote must be produced");
        let falcon_sig = prevote.falcon_signature().expect("vote must carry Falcon signature");
        assert_eq!(falcon_sig.len(), crate::post_quantum::FALCON512_SIG_LEN);

        let msg = crate::consensus::vote_sign_bytes(1, 0, VoteKind::Prevote, &prevote.block_hash);
        assert!(crate::post_quantum::verify_pq_signature(
            crate::post_quantum::PqScheme::Falcon512,
            &fk.public_key,
            &msg,
            falcon_sig,
        ));
        assert!(prevote.verify(), "vote with Falcon signature must verify");

        // 2. propose signs proposal with Falcon key
        let block = rt.propose(1_000_000).await.expect("propose must succeed");
        let falcon_id = fk.validator_id();
        let proposal_msg = block.compute_hash();

        let falcon_prop_sig = block
            .validator_signatures
            .iter()
            .find(|(id, _)| *id == falcon_id)
            .map(|(_, sig)| sig)
            .expect("block validator signatures must contain Falcon signature");

        assert!(crate::post_quantum::verify_pq_signature(
            crate::post_quantum::PqScheme::Falcon512,
            &fk.public_key,
            &proposal_msg,
            falcon_prop_sig,
        ));

        // 3. make_precommit with polka produces precommit with Falcon signature
        assert!(rt.on_prevote(prevote).is_ok());
        let precommit = rt.make_precommit().expect("precommit must be produced");
        let pc_falcon_sig = precommit.falcon_signature().expect("precommit must carry Falcon signature");
        let pc_msg = crate::consensus::vote_sign_bytes(1, 0, VoteKind::Precommit, &precommit.block_hash);
        assert!(crate::post_quantum::verify_pq_signature(
            crate::post_quantum::PqScheme::Falcon512,
            &fk.public_key,
            &pc_msg,
            pc_falcon_sig,
        ));
        assert!(precommit.verify());
    }

    #[tokio::test]
    async fn validator_runtime_falcon_votes_form_uqc_and_verify_unified() {
        let val_keys = signer_keys(4);
        let user = SigningKey::generate(&mut OsRng);
        let from = user.verifying_key().to_bytes();
        let to = [9u8; 32];

        let mut nodes = Vec::new();
        for k in &val_keys {
            nodes.push((k.clone(), funded_state(from).await));
        }

        let validators = ValidatorSet::from_list(
            nodes
                .iter()
                .map(|(k, _)| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );

        let mut runtimes: Vec<ValidatorRuntime> = nodes
            .into_iter()
            .enumerate()
            .map(|(i, (k, st))| {
                let fk = FalconKeypair::generate_from_seed((i + 1) as u8);
                ValidatorRuntime::new(k, validators.clone(), st, 1)
                    .with_falcon_key(fk)
            })
            .collect();

        let tx = Transaction::sign(&user, to, 1_000, 0, 0, 1, 1);
        for rt in &runtimes {
            rt.mempool.write().await.add_checked(tx.clone(), 10_000_000).unwrap();
        }

        // 1. Propose from designated proposer
        let proposer_idx = runtimes.iter().position(|rt| rt.is_proposer()).expect("must have proposer");
        let block = runtimes[proposer_idx].propose(1_000).await.expect("propose must succeed");
        let bh = block.compute_hash();

        // Ingest proposal on all nodes
        let proposer_id = runtimes[proposer_idx].id;
        for rt in &mut runtimes {
            assert!(rt.on_proposal(proposer_id, block.clone(), 0).await.is_ok());
        }

        // 2. Prevote
        let mut prevotes = Vec::new();
        for rt in &runtimes {
            let v = rt.make_prevote().expect("make_prevote");
            assert!(v.falcon_signature().is_some());
            prevotes.push(v);
        }

        for rt in &mut runtimes {
            for v in &prevotes {
                assert!(rt.on_prevote(v.clone()).is_ok());
            }
            let (polka_round, target) = rt.hc.try_prevote_quorum_at().expect("polka must form");
            assert_eq!(target, Some(bh));
            let prevote_qc = rt.hc.prevote_qc.get(&polka_round).expect("prevote QC must exist");
            assert!(
                prevote_qc.signatures.iter().any(|(voter, _)| *voter == crate::consensus::PQ_UQC_MARKER_ID),
                "prevote QC must contain PQ_UQC_MARKER_ID"
            );
            assert!(prevote_qc.verify_unified(&validators));
        }

        // 3. Precommit
        let mut precommits = Vec::new();
        for rt in &mut runtimes {
            let v = rt.make_precommit().expect("make_precommit");
            assert!(v.falcon_signature().is_some());
            precommits.push(v);
        }

        for rt in &mut runtimes {
            for v in &precommits {
                assert!(rt.on_precommit(v.clone()).is_ok());
            }
            let decided = rt.hc.try_precommit_quorum().expect("precommit quorum must decide");
            assert_eq!(decided, bh);
            let precommit_qc = rt.hc.precommit_qc.as_ref().expect("precommit QC must exist");
            assert!(
                precommit_qc.signatures.iter().any(|(voter, _)| *voter == crate::consensus::PQ_UQC_MARKER_ID),
                "precommit QC must contain PQ_UQC_MARKER_ID"
            );
            assert!(precommit_qc.verify_unified(&validators));
            assert!(precommit_qc.verify(&validators));
        }

        // 4. Finalize the block across all nodes
        for rt in &mut runtimes {
            let finalized = rt.try_finalize().await.expect("finalization must succeed");
            assert_eq!(finalized, bh);
            assert!(rt.finalized.contains(&(1, bh)));
        }
    }
}
