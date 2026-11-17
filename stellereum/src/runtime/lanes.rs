use super::{BlockHash, GENESIS_VALIDATOR_BOND};
use crate::consensus::{Height, ValidatorSet};
use crate::sharding::{Block, ShardId, Transaction};
use crate::state_engine::InMemoryStateEngine;
use futures::FutureExt as _;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Deterministic genesis: credit EVERY validator in `validators` the same fixed
/// balance. The validator set is a `BTreeMap` (sorted), so every node with the
/// same config credits the same accounts in the same order and derives an
/// identical genesis state root.
pub async fn fund_genesis(engine: &InMemoryStateEngine, validators: &ValidatorSet, balance: u64) {
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
            // Strict-only (LEAD: no legacy branch): every genesis takes this
            // path unconditionally.
            let _ = engine.debit_native(v, bond).await;
            let _ = engine
                .credit_native(&crate::staking::STAKING_POOL, bond)
                .await;
        }
    }
}

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
pub async fn fund_shard_genesis(engine: &InMemoryStateEngine, dev_account: [u8; 32], balance: u64) {
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
        shard_headers: vec![],
        precommit_qc: None,
        // Genesis (height 0) predates canonical downtime evidence: there is
        // no parent height to attest. `None` is also what every pre-upgrade
        // block decodes to — see `de_last_qc`.
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        // Genesis is never an epoch-committing boundary (see
        // `crate::mmr::commits_epoch_root`): it commits to no epoch root.
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
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
pub(super) fn count_program_sends(program: &[crate::svm::OpCode]) -> usize {
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
pub(super) fn block_actor_sends_exceed_cap(block: &Block) -> bool {
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
pub(super) struct ApplyJob {
    pub(super) block: Block,
    pub(super) reward: u64,
    pub(super) done:
        tokio::sync::oneshot::Sender<(crate::state_engine::BlockTransitionOutcome, [u8; 32])>,
}

/// A quiescent state capture: every root-committed domain cloned at a FIFO
/// idle point (after the previous apply installed, before the next starts),
/// so the bytes can never mix heights. The cross-shard replay set is NOT
/// captured here even though its engine halves ARE root-committed (see
/// `commitment::write_cross_shard_domain`): the tick captures it at submit
/// quiescence (the same post-`height` instant) and the poll site reuses those
/// bytes verbatim — a fresh read at poll would be newer state under this
/// height's label and brick the next boot in `verify_restored_root` (see the
/// snapshot block in main.rs).
pub struct SnapBundle {
    pub height: u64,
    /// The canonical state capture: the accounts (address-sorted) AND the D2
    /// consensus penalty map. The penalty is consensus-critical (it enters
    /// the charged fee), so it MUST travel with the accounts — a snapshot
    /// without it would restore a node that charges a different fee than a
    /// node that applied the blocks (audit W6.6). Serialized with the same
    /// shape `InMemoryStateEngine::create_snapshot` produces, so the bytes
    /// this bundle publishes are the bytes the restore path reads.
    pub accounts: crate::state_engine::StateSnapshotV2,
    pub domains: crate::storage::DomainSnapshot,
    pub session_keys: Vec<u8>,
    pub bridge: Vec<u8>,
    pub zkml_models: Vec<u8>,
    pub cnvrf_v3: Vec<u8>,
}

/// Snapshot request/response on the sequenced lane (see `SnapBundle`).
/// `expected_root` is the worker-certified post-`height` root: the worker
/// captures ONLY if the live engine still roots there, so a snapshot labeled
/// H can never carry H+1 state no matter the queue order (mislabel is
/// impossible by construction, not by timing).
pub(super) struct SnapshotJob {
    pub(super) height: u64,
    pub(super) expected_root: [u8; 32],
    pub(super) done: tokio::sync::oneshot::Sender<Option<SnapBundle>>,
}

#[allow(clippy::large_enum_variant)]
// GATE: boxing ApplyJob would change memory layout without benefit; sizes are bounded and local-only.
pub(super) enum LaneJob {
    Apply(ApplyJob),
    Snapshot(SnapshotJob),
}

/// The sequenced execution lane: one FIFO channel feeding one task.
///
/// Cloning the lane clones the sender only — every clone feeds the SAME queue
/// and therefore the same order (same contract as `ConsensusSender`).
#[derive(Clone)]
pub(super) struct ApplyLane {
    pub(super) tx: tokio::sync::mpsc::UnboundedSender<LaneJob>,
}

impl ApplyLane {
    /// Spawn the single worker for `state`. One task, one loop: take the next
    /// job, run the shared transition to completion, report the outcome plus
    /// the post-apply root, repeat. Two jobs can never overlap (the next
    /// `recv` happens only after the previous outcome is sent), and order is
    /// exactly submission order.
    pub(super) fn spawn(state: &Arc<InMemoryStateEngine>) -> Self {
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
                            let outcome =
                                state.apply_block_transition(&job.block, job.reward).await;
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
                        let accounts = crate::storage::clone_account_snapshot(&state).await;
                        let ledger = state.staking_read().await.clone();
                        let gov = state.governance_read().await.clone();
                        let domains =
                            crate::storage::DomainSnapshot::capture(&state, &ledger, &gov).await;
                        let session_keys = state.session_keys_snapshot().await;
                        let bridge = state.bridge_snapshot().await;
                        let zkml_models = state.zkml_models_snapshot().await;
                        let cnvrf_v3 = bincode::serialize(&state.cnvrf_v3_snapshot().await)
                            .unwrap_or_default();
                        let _ = job.done.send(Some(SnapBundle {
                            height: job.height,
                            accounts,
                            domains,
                            session_keys,
                            bridge,
                            zkml_models,
                            cnvrf_v3,
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
pub(super) struct ApplyInflight {
    pub(super) height: Height,
    pub(super) hash: BlockHash,
    pub(super) block: Block,
    pub(super) done:
        tokio::sync::oneshot::Receiver<(crate::state_engine::BlockTransitionOutcome, [u8; 32])>,
}

/// What the worker reported back once its outcome is installed: the executed
/// height, its hash and the certified post-apply root (no recompute needed by
/// the caller).
pub struct ApplyCompleted {
    pub height: Height,
    pub hash: BlockHash,
    pub root: [u8; 32],
}

// ============================================================================
// VEL-1 bounded proposer-prebuild (local only, never on the wire)
// ============================================================================

/// A prebuilt plain-transaction selection, cached for one height.
///
/// Produced ONLY by [`ValidatorRuntime::prebuild_next_proposal`] during an
/// idle window (`propose` itself never writes, so a round retry at the
/// current height can never evict a future-height prebuild), consumed by
/// `propose` after per-tx revalidation against live state. Single slot:
/// overwritten, never grown; `txs.len() <= MAX_BLOCK_TXS` by construction
/// (it came out of the capped selector). `None`/height-mismatch ⇒ build
/// fresh — the propose path is then byte-identical to before this cache.
#[derive(Clone, Debug)]
pub struct PrebuiltSelection {
    /// The height this selection was built for. Reused only when it equals
    /// the proposing height; anything else is discarded (stale parent).
    pub for_height: Height,
    /// Candidate transactions in selection order.
    pub txs: Vec<Transaction>,
}

/// Mutable filter state threaded through the pack admissibility predicate.
///
/// The predicate ([`ValidatorRuntime::pack_filter_accept`]) is a pure
/// function of (tx, this state): the same inputs always admit the same set
/// in the same order, whether it runs inside `propose`, inside the prebuild,
/// or during revalidation. Fresh `propose` builds this state from live
/// reads; reuse only ever REPLAYS the same predicate against fresh state —
/// so a reused selection is validity-identical to a fresh one, and any
/// composition difference is liveness-only (every kept tx passes the exact
/// checks a fresh build would apply, and receivers re-verify everything).
pub struct PackFilterCtx {
    /// Block timestamp the policy checks evaluate against.
    pub timestamp: u64,
    /// Shard scope of the proposing chain.
    pub sharded: bool,
    /// This chain's shard.
    pub my_shard: ShardId,
    /// Base fee leg of the admission floor.
    pub base_fee: u64,
    /// Per-sender D2 failure penalties.
    pub penalty_floors: HashMap<[u8; 32], u64>,
    /// Session-key registry snapshot (revocation + ceilings as of build).
    pub session_keys: crate::zkml::SessionKeyRegistry,
    /// Expected nonce + spendable balance per sender (live snapshot).
    pub next_nonce: std::cell::RefCell<HashMap<[u8; 32], (u64, u64)>>,
    /// Cumulative in-block session spend simulation.
    pub session_sim: std::cell::RefCell<crate::zkml::SessionSpendSim>,
    /// Senders already carrying an outbound cross-shard transfer in this block.
    pub used_senders: std::cell::RefCell<HashSet<[u8; 32]>>,
    /// Rejection census (diagnostics only, same counters as the inline path).
    pub rej_noacct: std::cell::Cell<u32>,
    /// Rejection census: nonce gap.
    pub rej_nonce: std::cell::Cell<u32>,
    /// Rejection census: insufficient funds.
    pub rej_funds: std::cell::Cell<u32>,
    /// Rejection census: session policy.
    pub rej_session: std::cell::Cell<u32>,
    /// Rejection census: shard scope.
    pub rej_shard: std::cell::Cell<u32>,
    /// Rejection census: fee floor.
    pub rej_basefee: std::cell::Cell<u32>,
    /// Rejection census: sponsor policy.
    pub rej_sponsor: std::cell::Cell<u32>,
}

impl PackFilterCtx {
    /// Fresh filter state over live inputs (what `propose` builds per block).
    ///
    /// `next_nonce`/`session_sim`/`used_senders` are the filter's starting
    /// point: a clean build passes the live snapshot and empty extras, while
    /// `propose` passes the post-sealed-loop state so plain selection
    /// continues exactly where the sealed path left off (byte-identical to
    /// the pre-factoring inline closure, which shared those same cells).
    #[allow(clippy::too_many_arguments)]
    // GATE: 9 filter inputs are required together; grouping would change call sites and packing semantics.
    pub fn new(
        timestamp: u64,
        sharded: bool,
        my_shard: ShardId,
        base_fee: u64,
        penalty_floors: HashMap<[u8; 32], u64>,
        session_keys: crate::zkml::SessionKeyRegistry,
        next_nonce: HashMap<[u8; 32], (u64, u64)>,
        session_sim: crate::zkml::SessionSpendSim,
        used_senders: HashSet<[u8; 32]>,
    ) -> Self {
        Self {
            timestamp,
            sharded,
            my_shard,
            base_fee,
            penalty_floors,
            session_keys,
            next_nonce: std::cell::RefCell::new(next_nonce),
            session_sim: std::cell::RefCell::new(session_sim),
            used_senders: std::cell::RefCell::new(used_senders),
            rej_noacct: std::cell::Cell::new(0),
            rej_nonce: std::cell::Cell::new(0),
            rej_funds: std::cell::Cell::new(0),
            rej_session: std::cell::Cell::new(0),
            rej_shard: std::cell::Cell::new(0),
            rej_basefee: std::cell::Cell::new(0),
            rej_sponsor: std::cell::Cell::new(0),
        }
    }
}

// ============================================================================
// CN-VRF v3 off-tick MinRoot VDF lane (local only, never on the wire)
// ============================================================================

/// Completed MinRoot VDF evaluation returned by [`VdfLane`].
#[allow(dead_code)]
// GATE: VdfLane is scoped to lanes.rs here and wired into runtime/mod.rs in a follow-up integration step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdfJobOutput {
    /// Epoch this VDF proof was evaluated for.
    pub epoch: u64,
    /// 48-byte raw seed passed into `minroot_vdf::eval`.
    pub raw_seed: [u8; 48],
    /// Checkpointed MinRoot VDF proof.
    pub proof: crate::minroot_vdf::MinRootProof,
    /// Canonical 48-byte VDF beacon output derived from `(raw_seed, proof)`.
    pub output: [u8; 48],
}

/// One queued MinRoot VDF evaluation request for [`VdfLane`].
#[allow(dead_code)]
// GATE: VdfLane is scoped to lanes.rs here and wired into runtime/mod.rs in a follow-up integration step.
pub struct VdfJob {
    /// Epoch associated with this VDF evaluation.
    pub epoch: u64,
    /// 48-byte raw seed for `minroot_vdf::eval`.
    pub raw_seed: [u8; 48],
    /// Number of sequential MinRoot forward steps (`> 0`).
    pub steps: u64,
    /// Number of intermediate checkpoints to record in the proof.
    pub checkpoints: usize,
    /// One-shot completion channel (`None` if superseded or on panic).
    pub done: tokio::sync::oneshot::Sender<Option<VdfJobOutput>>,
}

/// Dedicated off-tick sequential worker for `MinRoot` PQ-VDF evaluation.
///
/// Cloning the lane clones the sender and epoch-cancellation handle only —
/// every clone feeds the SAME FIFO worker task. Each job executes inside
/// `tokio::task::spawn_blocking` wrapped in `AssertUnwindSafe` + `catch_unwind`
/// so CPU-bound VDF evaluation never stalls async consensus ticks and a panic
/// returns `None` without crashing the consensus process.
#[allow(dead_code)]
// GATE: VdfLane is scoped to lanes.rs here and wired into runtime/mod.rs in a follow-up integration step.
#[derive(Clone)]
pub struct VdfLane {
    tx: tokio::sync::mpsc::UnboundedSender<VdfJob>,
    latest_epoch: Arc<std::sync::atomic::AtomicU64>,
}

#[allow(dead_code)]
// GATE: VdfLane is scoped to lanes.rs here and wired into runtime/mod.rs in a follow-up integration step.
impl VdfLane {
    /// Spawn the single sequential off-tick VDF worker task.
    pub fn spawn() -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<VdfJob>();
        let latest_epoch = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let worker_latest_epoch = Arc::clone(&latest_epoch);

        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                if job.epoch < worker_latest_epoch.load(std::sync::atomic::Ordering::Acquire) {
                    tracing::debug!(
                        epoch = job.epoch,
                        "vdf job skipped: superseded by newer epoch"
                    );
                    let _ = job.done.send(None);
                    continue;
                }

                let epoch = job.epoch;
                let raw_seed = job.raw_seed;
                let steps = job.steps;
                let checkpoints = job.checkpoints;
                let blocking_latest_epoch = Arc::clone(&worker_latest_epoch);

                let join_res = tokio::task::spawn_blocking(move || {
                    std::thread::yield_now();
                    if epoch < blocking_latest_epoch.load(std::sync::atomic::Ordering::Acquire) {
                        return Ok(None);
                    }
                    let eval_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let proof = crate::minroot_vdf::eval(&raw_seed, steps, checkpoints);
                        std::thread::yield_now();
                        let output = crate::minroot_vdf::derive_vdf_output(&raw_seed, &proof);
                        VdfJobOutput {
                            epoch,
                            raw_seed,
                            proof,
                            output,
                        }
                    }));
                    match eval_res {
                        Ok(out) => {
                            if epoch
                                < blocking_latest_epoch.load(std::sync::atomic::Ordering::Acquire)
                            {
                                Ok(None)
                            } else {
                                Ok(Some(out))
                            }
                        }
                        Err(_) => Err(()),
                    }
                })
                .await;

                match join_res {
                    Ok(Ok(maybe_out)) => {
                        let _ = job.done.send(maybe_out);
                    }
                    Ok(Err(())) => {
                        tracing::error!(
                            epoch,
                            steps,
                            "vdf worker PANICKED during MinRoot evaluation — returning None"
                        );
                        let _ = job.done.send(None);
                    }
                    Err(join_err) => {
                        tracing::error!(
                            epoch,
                            steps,
                            error = %join_err,
                            "vdf blocking task aborted — returning None"
                        );
                        let _ = job.done.send(None);
                    }
                }
            }
        });

        Self { tx, latest_epoch }
    }

    /// Enqueue a `MinRoot` VDF evaluation job and return a one-shot receiver
    /// for its result (`None` if superseded by a newer epoch or on panic).
    pub fn submit(
        &self,
        epoch: u64,
        raw_seed: [u8; 48],
        steps: u64,
        checkpoints: usize,
    ) -> tokio::sync::oneshot::Receiver<Option<VdfJobOutput>> {
        self.latest_epoch
            .fetch_max(epoch, std::sync::atomic::Ordering::AcqRel);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let job = VdfJob {
            epoch,
            raw_seed,
            steps,
            checkpoints,
            done: done_tx,
        };
        if let Err(err) = self.tx.send(job) {
            let _ = err.0.done.send(None);
        }
        done_rx
    }

    /// Mark any queued or in-flight VDF jobs for epochs strictly below `epoch`
    /// as stale so they are skipped or dropped cleanly.
    pub fn cancel_below(&self, epoch: u64) {
        self.latest_epoch
            .fetch_max(epoch, std::sync::atomic::Ordering::AcqRel);
    }

    /// Return the highest epoch seen by this lane so far.
    pub fn latest_epoch(&self) -> u64 {
        self.latest_epoch.load(std::sync::atomic::Ordering::Acquire)
    }
}

#[cfg(test)]
mod vdf_lane_tests {
    use super::*;
    use crate::minroot_vdf::{verify, TEST_VDF_STEPS};

    #[tokio::test]
    async fn vdf_lane_computes_and_verifies_minroot_proof() {
        let lane = VdfLane::spawn();
        let seed = [0x42u8; 48];
        let out = lane
            .submit(1, seed, TEST_VDF_STEPS, 4)
            .await
            .expect("vdf worker channel open")
            .expect("vdf job should produce proof");

        assert_eq!(out.epoch, 1);
        assert_eq!(out.raw_seed, seed);
        assert_eq!(out.proof.steps, TEST_VDF_STEPS);
        assert_eq!(out.proof.checkpoints.len(), 4);

        let verified_output = verify(&seed, TEST_VDF_STEPS, &out.proof)
            .expect("minroot_vdf::verify must accept VdfLane proof");
        assert_eq!(verified_output, out.output);
    }

    #[tokio::test]
    async fn vdf_lane_sequential_multiple_epochs_and_panic_recovery() {
        let lane = VdfLane::spawn();

        // Multiple sequential epochs complete cleanly in order.
        for epoch in 0..=3u64 {
            let mut seed = [0u8; 48];
            seed[0] = epoch as u8;
            seed[47] = 0xA5;
            let out = lane
                .submit(epoch, seed, TEST_VDF_STEPS, 4)
                .await
                .expect("vdf worker channel open")
                .expect("vdf job should succeed");
            assert_eq!(out.epoch, epoch);
            let verified = verify(&seed, TEST_VDF_STEPS, &out.proof)
                .expect("sequential epoch proof must verify");
            assert_eq!(verified, out.output);
        }

        // Submitting an invalid 0-step job triggers minroot_vdf::eval's assert! panic,
        // which must be caught by AssertUnwindSafe + catch_unwind and return None
        // without crashing the worker or subsequent jobs.
        let panic_res = lane
            .submit(4, [0x11u8; 48], 0, 4)
            .await
            .expect("vdf worker channel open after panic");
        assert!(panic_res.is_none(), "panicking VDF job must return None");

        // Worker remains alive for epoch 5.
        let post_panic = lane
            .submit(5, [0x22u8; 48], TEST_VDF_STEPS, 4)
            .await
            .expect("vdf worker channel open")
            .expect("subsequent VDF job must still succeed");
        assert_eq!(post_panic.epoch, 5);
        assert_eq!(
            verify(&[0x22u8; 48], TEST_VDF_STEPS, &post_panic.proof),
            Some(post_panic.output)
        );
    }

    #[tokio::test]
    async fn vdf_lane_supersedes_stale_epoch_jobs() {
        let lane = VdfLane::spawn();
        let rx_stale = lane.submit(10, [0x01u8; 48], TEST_VDF_STEPS, 4);
        let rx_newer = lane.submit(11, [0x02u8; 48], TEST_VDF_STEPS, 4);

        let stale_out = rx_stale.await.expect("stale receiver open");
        assert!(
            stale_out.is_none(),
            "superseded epoch 10 job must be skipped/dropped"
        );

        let newer_out = rx_newer
            .await
            .expect("newer receiver open")
            .expect("latest epoch 11 job must complete");
        assert_eq!(newer_out.epoch, 11);
        assert_eq!(
            verify(&[0x02u8; 48], TEST_VDF_STEPS, &newer_out.proof),
            Some(newer_out.output)
        );
    }
}
