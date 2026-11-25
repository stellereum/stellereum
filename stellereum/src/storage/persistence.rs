use super::{BlockHash, ConsensusCheckpoint, DomainSnapshot, Storage};
use crate::sharding::{Block, FinalizedHeaderSink};
use crate::state_engine::InMemoryStateEngine;
use serde::Serialize;
use std::sync::Arc;

/// A background flusher that decouples the consensus hot path from disk I/O.
///
/// Finalized blocks and periodic state snapshots are pushed into an unbounded
/// channel; a spawned task writes them. The hot path never waits on `sled`.
/// Max pending persist jobs. Bounds memory so a slow disk cannot grow the queue
/// without limit (anti-DoS).
pub const PERSIST_QUEUE_CAP: usize = 8192;

pub struct AsyncPersistence {
    pub(super) tx: tokio::sync::mpsc::Sender<PersistJob>,
    pub(super) storage: Arc<Storage>,
    /// Jobs pushed but not yet dequeued by the background writer. Drives the
    /// `stell_persist_queue_depth` gauge (F2: previously declared but unwired
    /// — the queue existed, the producer did not). Atomic: `push` (hot path)
    /// and the writer task update it without locking.
    pub(super) queue_depth: Arc<std::sync::atomic::AtomicU64>,
}

/// Persist work items. `pub` so the drop-policy classifier
/// ([`persist_push_policy`]) can name the type it matches on; constructed
/// only inside this module.
#[allow(clippy::large_enum_variant)]
// GATE: Block variant dominates by design; jobs are short-lived queue items, boxing would add alloc overhead.
pub enum PersistJob {
    Block(Block),
    State {
        height: u64,
        snapshot: Vec<u8>,
    },
    /// Domain + session-key + bridge snapshots of the SAME height, carried in
    /// one job so they are enqueued (and therefore ordered/dropped) together:
    /// two jobs could be split by a full queue or a crash, leaving a registry
    /// from a different height than the domains it must restore alongside - or
    /// a bridge replay set paired with accounts that already credited it.
    Domains {
        height: u64,
        bytes: Vec<u8>,
        session_keys: Vec<u8>,
        bridge: Vec<u8>,
        zkml_models: Vec<u8>,
        cross_shard: Vec<u8>,
    },
    CnVrfV3 {
        height: u64,
        bytes: Vec<u8>,
    },
    EvmBindingsState {
        height: u64,
        bytes: Vec<u8>,
    },
    PqRegistry {
        height: u64,
        bytes: Vec<u8>,
    },
    /// Complete cross-shard finalized-header registry snapshot (latest shard
    /// heads + bounded anchor window). Latest-state, so a later job replaces an
    /// earlier one; enqueued from the registry's finalize path, never read from
    /// the network.
    XshardHeaders {
        bytes: Vec<u8>,
    },
    ValidatorSetHistory(Vec<(u64, crate::consensus::ValidatorSet)>),
    Consensus(Box<ConsensusCheckpoint>),
    Finalized {
        height: u64,
        hash: BlockHash,
    },
    Prune {
        keep_from: u64,
    },
    /// Durable receipts for one applied block. Carries the tx hashes + statuses
    /// from the single real application (never wire data); the worker persists
    /// them alongside the body so an adopter serves receipts after a restart.
    /// One job per height, bounded by the block's own tx count.
    Receipts {
        height: u64,
        hash: BlockHash,
        txs: Vec<crate::sharding::Transaction>,
        statuses: Vec<bool>,
        fees: Vec<u64>,
        events: Vec<Vec<crate::contract::ContractEvent>>,
    },
    Flush,
}

/// How [`AsyncPersistence::push`] treats a job when the bounded queue is full
/// (audit F2 drop-policy by job class).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistPushPolicy {
    /// Drop immediately (logged + counted): re-runnable work whose loss is
    /// a no-op — the prune pass is re-scheduled from the regular snapshot
    /// cadence.
    DropFirst,
    /// Wait (bounded) for the writer to drain before dropping: every job
    /// class carrying consensus-relevant data (see `push`'s loss assessment).
    BoundedWait,
    /// Consensus-critical class (`Consensus` safety checkpoint / `Finalized`
    /// tip pointer): ALWAYS attempt the bounded drain, including on a
    /// current-thread runtime where the synchronous producer cannot hand the
    /// thread to the writer. The wait is deferred to a spawned task instead
    /// of dropping immediately. A drop is still possible after the budget
    /// expires (wedged disk) but is LOUD, counted, and names the recovery
    /// consequence — never silent.
    CriticalWait,
}

/// Pure classifier for the push drop-policy: which job classes may be
/// dropped outright when the persist queue is full, and which must wait out
/// a bounded drain first. Pure so the policy is test-pinned without timing.
///
/// Audit F2 (mainnet blocker): `Consensus` carries the per-height BFT safety
/// checkpoint and `Finalized` the durable tip pointer. Neither may be
/// dropped just because the producer happens to run on a current-thread
/// runtime, so both are `CriticalWait` (deferred drain) rather than the
/// generic `BoundedWait`.
pub fn persist_push_policy(job: &PersistJob) -> PersistPushPolicy {
    match job {
        PersistJob::Prune { .. } => PersistPushPolicy::DropFirst,
        PersistJob::Consensus(_) | PersistJob::Finalized { .. } => PersistPushPolicy::CriticalWait,
        _ => PersistPushPolicy::BoundedWait,
    }
}

/// Human label for a job class, used by the drop log so an operator can name
/// exactly what was lost without decoding an enum.
pub fn persist_job_label(job: &PersistJob) -> &'static str {
    match job {
        PersistJob::Block(_) => "Block (finalized body)",
        PersistJob::State { .. } => "State snapshot",
        PersistJob::Domains { .. } => "Domains snapshot",
        PersistJob::CnVrfV3 { .. } => "CN-VRF v3 snapshot",
        PersistJob::EvmBindingsState { .. } => "EVM bindings state snapshot",
        PersistJob::PqRegistry { .. } => "PQ registry snapshot",
        PersistJob::XshardHeaders { .. } => "cross-shard header registry",
        PersistJob::ValidatorSetHistory(_) => "Validator-set activation history",
        PersistJob::Consensus(_) => "Consensus safety checkpoint",
        PersistJob::Finalized { .. } => "Finalized tip pointer",
        PersistJob::Prune { .. } => "Prune pass",
        PersistJob::Receipts { .. } => "Receipts",
        PersistJob::Flush => "Flush barrier",
    }
}

/// Documented recovery consequence of losing one job of this class. Shown
/// verbatim in the LOUD drop path: a critical drop must never be a bare
/// counter bump that leaves the operator guessing whether finality is safe.
pub fn persist_drop_consequence(job: &PersistJob) -> &'static str {
    match job {
        PersistJob::Prune { .. } => {
            "nothing durable is lost; the next snapshot cadence re-schedules the prune"
        }
        PersistJob::State { .. } | PersistJob::Domains { .. } => {
            "one periodic snapshot is lost; the next cadence captures a newer height, widening the crash-recovery gap by at most one interval (half-pairs are refused loudly on restore)"
        }
        PersistJob::Block(_) => {
            "one finalized body is missing until adopter replication re-fetches it by hash"
        }
        PersistJob::Finalized { .. } => {
            "the durable tip pointer lags; the next boot re-walks from the last persisted finalized height (safe, slower). Finality itself is unaffected"
        }
        PersistJob::Consensus(_) => {
            "this height's BFT safety checkpoint is not durable; the node re-locks/re-derives it on restart and finality remains protected by the consensus certificate"
        }
        PersistJob::Receipts { .. } => {
            "receipts for this height are re-derivable by re-application; RPC serves no receipt until then"
        }
        PersistJob::CnVrfV3 { .. }
        | PersistJob::EvmBindingsState { .. }
        | PersistJob::PqRegistry { .. }
        | PersistJob::XshardHeaders { .. }
        | PersistJob::ValidatorSetHistory(_)
        | PersistJob::Flush => {
            "recoverable auxiliary state; the next cadence/finalize refreshes it"
        }
    }
}

/// Total time a `BoundedWait` push waits for queue space before dropping
/// (audit F2 bounded-blocking): 200ms. Long enough for the writer to drain
/// several sled batches on a slow disk, short enough that a wedged disk
/// costs the tick a bounded delay, never a hang.
pub const PERSIST_BLOCKING_WAIT_MS: u64 = 200;

/// Pace between queue-space retries inside the bounded wait: 5ms (up to ~40
/// retries per wait). Yields the thread instead of spinning.
pub const PERSIST_RETRY_PACE_MS: u64 = 5;

/// Record one persist-job drop: always counted, always LOUD, and — for a
/// consensus-critical class — names the exact recovery consequence. Kept in
/// one place so the synchronous and deferred (current-thread) drop paths can
/// never diverge in either metric or message.
fn record_persist_drop(policy: PersistPushPolicy, label: &'static str, consequence: &'static str) {
    match policy {
        PersistPushPolicy::CriticalWait => {
            tracing::error!(
                "[storage] CRITICAL persist job DROPPED after {PERSIST_BLOCKING_WAIT_MS}ms \
                 of bounded drain: {label}. Consequence: {consequence}. Counted in \
                 stell_persist_queue_dropped_total — a repeating drop means the disk is too \
                 slow or wedged; recover by restoring from a verified snapshot and fixing I/O."
            );
            eprintln!(
                "[storage] CRITICAL persist job DROPPED ({label}) after \
                 {PERSIST_BLOCKING_WAIT_MS}ms; consequence: {consequence} \
                 (counted: stell_persist_queue_dropped_total)"
            );
        }
        _ => {
            eprintln!(
                "[storage] persist queue full; dropping {label} (disk too slow? — counted, \
                 alert on stell_persist_queue_dropped_total; consequence: {consequence})"
            );
        }
    }
    crate::metrics::global().inc_persist_queue_dropped();
}

/// Decrement the live queue-depth gauge exactly once, saturating at zero.
/// Used by the writer on dequeue and by the deferred current-thread send when
/// a reservation is abandoned (drop or closed writer), so `pending()` never
/// leaks a phantom job — or hides a real one.
fn decrement_queue_depth(depth: &std::sync::atomic::AtomicU64) -> u64 {
    let mut prev = depth.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let next = prev.saturating_sub(1);
        match depth.compare_exchange_weak(
            prev,
            next,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => prev = actual,
        }
    }
    let now_depth = prev.saturating_sub(1);
    crate::metrics::global().set_persist_queue_depth(now_depth);
    now_depth
}

impl AsyncPersistence {
    /// Start the background writer. Returns a handle for enqueuing jobs and the
    /// shared storage for reads.
    pub fn start(storage: Arc<Storage>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<PersistJob>(PERSIST_QUEUE_CAP);
        let st = storage.clone();
        let depth = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let depth_worker = depth.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                // Dequeued: one fewer job waiting, even before the write
                // lands. `saturating` — a missed count must never wrap the
                // gauge to u64::MAX.
                // L-04: `fetch_update` is deprecated on newer toolchains; the
                // explicit CAS loop in `decrement_queue_depth` is exactly its
                // body for an always-Some closure (same race-safety:
                // concurrent dequeues serialize on the compare-exchange, the
                // counter saturates at 0 instead of wrapping).
                decrement_queue_depth(&depth_worker);
                let res = match job {
                    PersistJob::Block(b) => st.put_block(&b).map(|_| ()),
                    PersistJob::State { height, snapshot } => st.put_state(height, &snapshot),
                    // Audit F1(c): `cross_shard` is written FIRST. The old
                    // order wrote it LAST (domains→session→bridge→
                    // zkml→cross_shard), so an I/O error anywhere
                    // in the chain silently skipped the replay set while
                    // keeping the rest — the exact partial write that
                    // re-opens consumed inbounds. Replay-first inverts the
                    // failure shape: a later error now leaves replay state
                    // WITHOUT its domains, which the paired-snapshot loader
                    // REFUSES loudly (unpaired/half snapshot) instead of
                    // installing a double-mint. Replay data without domains
                    // is fail-closed; domains without replay data was the
                    // corruption.
                    PersistJob::Domains {
                        height,
                        bytes,
                        session_keys,
                        bridge,
                        zkml_models,
                        cross_shard,
                    } => st
                        .put_cross_shard(height, &cross_shard)
                        .and_then(|()| st.put_domains(height, &bytes))
                        .and_then(|()| st.put_session_keys(height, &session_keys))
                        .and_then(|()| st.put_bridge(height, &bridge))
                        .and_then(|()| st.put_zkml_models(height, &zkml_models)),
                    PersistJob::CnVrfV3 { height, bytes } => st.put_cnvrf_v3(height, &bytes),
                    PersistJob::EvmBindingsState { height, bytes } => {
                        st.put_evm_bindings_state(height, &bytes)
                    }
                    PersistJob::PqRegistry { height, bytes } => st.put_pq_registry(height, &bytes),
                    PersistJob::XshardHeaders { bytes } => st.put_xshard_headers(&bytes),
                    PersistJob::ValidatorSetHistory(history) => {
                        st.put_validator_set_history(&history)
                    }
                    PersistJob::Consensus(cp) => st.set_consensus(&cp),
                    PersistJob::Finalized { height, hash } => st.set_finalized(height, &hash),
                    PersistJob::Receipts {
                        height,
                        hash,
                        txs,
                        statuses,
                        fees,
                        events,
                    } => st
                        .put_receipts_for_block_with_events(
                            height, &hash, &txs, &statuses, &fees, &events,
                        )
                        .map(|_| ()),
                    // Bounded per job: the flusher is the only writer, so an
                    // unbounded scan here would stall every other write.
                    // Receipts ride the same retention window (audit 2026-10-06).
                    PersistJob::Prune { keep_from } => st
                        .prune_blocks_below(keep_from)
                        .and_then(|_| st.prune_receipts_below(keep_from))
                        .map(|_| ()),
                    PersistJob::Flush => st.flush(),
                };
                if let Err(e) = res {
                    eprintln!("[storage] persist error: {e}");
                }
            }
        });
        Self {
            tx,
            storage,
            queue_depth: depth,
        }
    }

    pub fn storage(&self) -> Arc<Storage> {
        self.storage.clone()
    }

    /// Non-blocking enqueue. Never grows memory without bound: if the bounded
    /// queue is full the job is either waited out (bounded) or dropped
    /// (logged AND counted) according to its class — see
    /// [`persist_push_policy`]. F2: the drop path increments
    /// `stell_persist_queue_dropped_total` and every push/dequeue refreshes
    /// the `stell_persist_queue_depth` gauge, so the declared metrics finally
    /// have a producer.
    ///
    /// What a drop LOSES, per class (assessed audit F2):
    /// * `Prune`: nothing durable — the next snapshot cadence re-schedules
    ///   it. Always droppable, dropped first.
    /// * `State` / `Domains`: one periodic snapshot (every ~100 heights).
    ///   The next cadence re-captures a NEWER height, so a drop only widens
    ///   the crash-recovery gap by one interval; the paired-snapshot loader
    ///   refuses half-pairs loudly rather than installing them.
    /// * `Block`: one finalized body. Healable via adopter replication
    ///   (`put_verified_block` re-fetches by hash), but a missing body is
    ///   serving-visible until healed — hence bounded-wait, not drop-first.
    /// * `Finalized`: the tip pointer. Loss forces a full re-walk at next
    ///   boot (safe but slow) — CRITICAL, so it is always granted a bounded
    ///   drain (deferred on a current-thread runtime) before any drop.
    /// * `Consensus`: the per-height BFT safety checkpoint. Re-derivable by
    ///   re-locking, but consensus-critical — same deferred bounded drain as
    ///   `Finalized`.
    /// * `Receipts`: per-height durable indexes. Re-derivable by
    ///   re-application — hence bounded-wait.
    /// * `Flush`: a durability barrier with no data — dropping it only
    ///   widens the fsync window; still bounded-waited (cheap) for uniformity.
    fn push(&self, job: PersistJob) {
        let policy = persist_push_policy(&job);
        let label = persist_job_label(&job);
        let consequence = persist_drop_consequence(&job);
        match self.tx.try_send(job) {
            Ok(()) => {
                self.bump_queue_depth();
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(job)) => {
                if policy == PersistPushPolicy::DropFirst {
                    record_persist_drop(policy, label, consequence);
                    return;
                }
                // Bounded blocking for consensus-relevant jobs (audit F2):
                // wait up to `PERSIST_BLOCKING_WAIT_MS` for the writer to
                // drain, then drop loudly with a metric. The wait is BOUNDED
                // (never indefinite), so a wedged disk delays the tick by at
                // most this budget instead of growing memory without limit.
                //
                // NO-DEADLOCK PROOF: the only waiter here is the producer
                // (consensus tick / RPC), and the only drain is the background
                // writer task, which performs PURE sled I/O (`put_*`,
                // `prune_*`, `flush`) and never sends on this channel, never
                // awaits a consensus lock, and never awaits the producer.
                // The wait-for graph is therefore producer → writer → disk,
                // with no edge back to the producer: no cycle, no deadlock.
                // Worst case is a bounded tick delay followed by a counted
                // drop (whose loss class is documented above), never a hang
                // and never silent loss.
                //
                // `block_in_place` is what lets the WRITER task drain the
                // queue while this thread waits - but it PANICS on a
                // current-thread runtime ("can call blocking only when
                // running on the multi-threaded runtime"), and a panic in the
                // persistence path is a node-killer, not a hiccup. So the
                // runtime FLAVOUR decides:
                //
                //   * MultiThread: `block_in_place` hands the thread to the
                //     scheduler, the writer drains in parallel, and the
                //     bounded wait can actually succeed.
                //   * CurrentThread: the writer runs ONLY when the producer
                //     awaits, and this is a SYNCHRONOUS push - so the writer
                //     cannot drain while we wait. For a CRITICAL job the wait
                //     is DEFERRED to a spawned task (which the runtime polls
                //     as soon as the producer yields) instead of dropping
                //     immediately; a non-critical BoundedWait job keeps the
                //     historical immediate counted drop.
                //   * No runtime at all: nothing can drain either; keep the
                //     historical bounded wait.
                let flavor = tokio::runtime::Handle::try_current()
                    .ok()
                    .map(|h| h.runtime_flavor());
                match flavor {
                    Some(tokio::runtime::RuntimeFlavor::MultiThread) => {
                        if !tokio::task::block_in_place(|| self.bounded_wait_send(job)) {
                            record_persist_drop(policy, label, consequence);
                        }
                    }
                    Some(tokio::runtime::RuntimeFlavor::CurrentThread) => {
                        if policy == PersistPushPolicy::CriticalWait {
                            // Deferred bounded drain: the current-thread
                            // writer cannot run while the producer blocks on
                            // this synchronous call, but it WILL run at the
                            // producer's next await. The spawned send waits
                            // for capacity under the same bounded budget and
                            // only then records a drop — never an immediate,
                            // silent loss of the safety checkpoint/tip.
                            let tx = self.tx.clone();
                            let depth = self.queue_depth.clone();
                            // Reserve the gauge slot NOW: `pending()` drives
                            // graceful shutdown, and a deferred job that is
                            // not yet in the channel must still keep the drain
                            // waiting. The writer removes this reservation
                            // when it dequeues; an abandoned send removes it
                            // here.
                            self.bump_queue_depth();
                            tokio::spawn(async move {
                                match tokio::time::timeout(
                                    std::time::Duration::from_millis(PERSIST_BLOCKING_WAIT_MS),
                                    tx.send(job),
                                )
                                .await
                                {
                                    // Accepted: the writer owns the
                                    // reservation and decrements on dequeue.
                                    Ok(Ok(())) => {}
                                    // Writer gone: shutdown, no persistence
                                    // target left to lose.
                                    Ok(Err(_)) => {
                                        decrement_queue_depth(&depth);
                                    }
                                    Err(_) => {
                                        decrement_queue_depth(&depth);
                                        record_persist_drop(policy, label, consequence);
                                    }
                                }
                            });
                        } else {
                            record_persist_drop(policy, label, consequence);
                        }
                    }
                    // `RuntimeFlavor` is `#[non_exhaustive]`: a future tokio
                    // could add a flavour whose drain semantics we do not
                    // know. Fail SAFE (counted drop, never a silent loss) and
                    // never call `block_in_place` on it.
                    Some(_) => {
                        record_persist_drop(policy, label, consequence);
                    }
                    None => {
                        if !self.bounded_wait_send(job) {
                            record_persist_drop(policy, label, consequence);
                        }
                    }
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Bump the live queue-depth gauge after a successful push.
    fn bump_queue_depth(&self) -> u64 {
        let d = self
            .queue_depth
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1);
        crate::metrics::global().set_persist_queue_depth(d);
        d
    }

    /// Retry `try_send` until the bounded budget expires. Returns `true` when
    /// the job was accepted (or the writer is gone, so there is nothing left
    /// to persist), `false` when the budget expired with the queue still full.
    fn bounded_wait_send(&self, mut job: PersistJob) -> bool {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(PERSIST_BLOCKING_WAIT_MS);
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(PERSIST_RETRY_PACE_MS));
            match self.tx.try_send(job) {
                Ok(()) => {
                    self.bump_queue_depth();
                    return true;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(j)) => {
                    job = j;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return true,
            }
        }
        false
    }

    /// Non-blocking: enqueue a finalized block for writing.
    pub fn enqueue_block(&self, block: Block) {
        self.push(PersistJob::Block(block));
    }

    /// Non-blocking: enqueue a state snapshot.
    pub fn enqueue_state(&self, height: u64, snapshot: Vec<u8>) {
        self.push(PersistJob::State { height, snapshot });
    }

    /// Non-blocking: enqueue a domain snapshot (tokens/contracts/...), together
    /// with the session-key registry, the bridge domain,
    /// the zkML registry and the cross-shard replay snapshot of the same
    /// height.
    #[allow(clippy::too_many_arguments)]
    // GATE: domain-enqueue batches all same-height snapshots in one call; a params struct would churn storage callers.
    pub fn enqueue_domains(
        &self,
        height: u64,
        bytes: Vec<u8>,
        session_keys: Vec<u8>,
        bridge: Vec<u8>,
        zkml_models: Vec<u8>,
        cross_shard: Vec<u8>,
    ) {
        self.push(PersistJob::Domains {
            height,
            bytes,
            session_keys,
            bridge,
            zkml_models,
            cross_shard,
        });
    }

    /// Non-blocking: enqueue a CN-VRF v3 subsystem snapshot for `height`
    /// (`BoundedWait` policy, matching `Domains`/`Bridge`).
    pub fn enqueue_cnvrf_v3(&self, height: u64, bytes: Vec<u8>) {
        self.push(PersistJob::CnVrfV3 { height, bytes });
    }

    /// Non-blocking: enqueue a canonical `Domain::EvmBindings` snapshot for `height`.
    pub fn enqueue_evm_bindings_state(&self, height: u64, bytes: Vec<u8>) {
        self.push(PersistJob::EvmBindingsState { height, bytes });
    }

    /// Non-blocking: enqueue a canonical `Domain::PqRegistry` snapshot for `height`.
    pub fn enqueue_pq_registry(&self, height: u64, bytes: Vec<u8>) {
        self.push(PersistJob::PqRegistry { height, bytes });
    }

    /// Non-blocking: enqueue a complete cross-shard finalized-header registry
    /// snapshot. Latest-state (a later job replaces an earlier one), so the
    /// queue-under-pressure drop of one snapshot is recovered by the next
    /// finalize; `BoundedWait` keeps that window as small as the disk allows.
    pub fn enqueue_xshard_headers(&self, bytes: Vec<u8>) {
        self.push(PersistJob::XshardHeaders { bytes });
    }

    /// Non-blocking: enqueue the ordered `(activation_height, ValidatorSet)`
    /// history snapshot (`BoundedWait` policy).
    pub fn enqueue_validator_set_history(
        &self,
        history: Vec<(u64, crate::consensus::ValidatorSet)>,
    ) {
        self.push(PersistJob::ValidatorSetHistory(history));
    }

    /// Capture + enqueue the full domain snapshot (A9), plus the session-key
    /// registry AND the committed bridge domain captured from the SAME engine
    /// in the SAME job.
    ///
    /// The capture (clone under the read locks) happens before this returns --
    /// that is the snapshot instant -- while the bincode serialization runs on
    /// the BLOCKING POOL via [`serialize_off_tick`], so a consensus tick that
    /// calls this pays only for the clones and never for the encode.
    ///
    /// The registry and the bridge domain deliberately do NOT become fields of
    /// `DomainSnapshot`: that struct is bincode with a hard-erroring restore
    /// path, so a new field would stop every pre-session-key (and every
    /// pre-bridge) domain snapshot from decoding. Their own trees keep old
    /// snapshots loadable while still pairing with the height they were
    /// written at - and make a restored node keep refusing replayed source
    /// transactions, which is the whole point of committing the replay set.
    pub async fn snapshot_domains(
        &self,
        engine: &InMemoryStateEngine,
        staking: &crate::staking::StakingLedger,
        governance: &crate::governance::Governance,
        height: u64,
    ) {
        let snap = DomainSnapshot::capture(engine, staking, governance).await;
        let session_keys = engine.session_keys_snapshot().await;
        let bridge = engine.bridge_snapshot().await;
        let zkml_models = engine.zkml_models_snapshot().await;
        let cnvrf_v3 = bincode::serialize(&engine.cnvrf_v3_snapshot().await).unwrap_or_default();
        let evm_bindings = engine.evm_bindings_snapshot().await;
        let pq_registry = engine.pq_registry_snapshot().await;
        // Cross-shard replay, engine half (audit F-I): the runtime mirrors are
        // empty wherever this runs (startup healing with a fresh runtime, or
        // tests) - and that is CORRECT here, because there is nothing live to
        // protect yet. The periodic path (main.rs) snapshots the full struct
        // including the live runtime mirrors. Either way the engine credit
        // gate - the part that stops a double mint - always travels.
        //
        // §9 2PC: the engine's COMMITTED two-phase-commit records travel with
        // it too. They are the decision state of every cross-shard transfer
        // (PREPARED / COMMITTED / ABORTED), and they are part of the
        // commitment digest - so a blob without them would (a) re-open a
        // decided transfer on the next restart (the phase decides where the
        // value is) and (b) move the digest of a restarted node away from the
        // digest of a node that did not restart. The engine's completed set
        // travels for the same reason (it is what refuses a second
        // completion).
        let cross_shard = {
            use crate::sharding::CrossShardReplaySnapshot;
            let mut engine_consumed = engine.cross_shard_consumed_snapshot().await;
            engine_consumed.sort();
            let mut completed = engine.cross_shard_completed_snapshot().await;
            completed.sort();
            let xpc = engine.xpc_snapshot().await;
            bincode::serialize(&CrossShardReplaySnapshot {
                engine_consumed,
                completed,
                xpc,
                ..Default::default()
            })
            .unwrap_or_default()
        };
        // Serialize OFF the executor (bincode of every domain is real CPU work);
        // skip on error exactly like the old inline `if let Ok(bytes)` did.
        if let Some(bytes) = serialize_off_tick(snap).await {
            self.enqueue_cnvrf_v3(height, cnvrf_v3);
            self.enqueue_evm_bindings_state(height, evm_bindings);
            self.enqueue_pq_registry(height, pq_registry);
            self.enqueue_domains(
                height,
                bytes,
                session_keys,
                bridge,
                zkml_models,
                cross_shard,
            );
        }
    }

    /// Non-blocking: persist the consensus safety checkpoint.
    pub fn enqueue_consensus(&self, cp: ConsensusCheckpoint) {
        self.push(PersistJob::Consensus(Box::new(cp)));
    }

    /// Non-blocking: record finality.
    pub fn enqueue_finalized(&self, height: u64, hash: BlockHash) {
        self.push(PersistJob::Finalized { height, hash });
    }

    /// Non-blocking: durably file the receipt set for one APPLIED block.
    ///
    /// `statuses` must be the outcome of the single real application of `txs`
    /// (the adopter's `apply_and_advance` / the proposer's finalize worker),
    /// never re-execution output or wire data. Fire-and-forget like every
    /// other enqueue: consensus never waits on disk.
    pub fn enqueue_receipts(
        &self,
        height: u64,
        hash: BlockHash,
        txs: Vec<crate::sharding::Transaction>,
        statuses: Vec<bool>,
        fees: Vec<u64>,
    ) {
        self.enqueue_receipts_with_events(height, hash, txs, statuses, fees, Vec::new());
    }

    pub fn enqueue_receipts_with_events(
        &self,
        height: u64,
        hash: BlockHash,
        txs: Vec<crate::sharding::Transaction>,
        statuses: Vec<bool>,
        fees: Vec<u64>,
        events: Vec<Vec<crate::contract::ContractEvent>>,
    ) {
        self.push(PersistJob::Receipts {
            height,
            hash,
            txs,
            statuses,
            fees,
            events,
        });
    }

    /// Ask the background writer to drop block bodies below `keep_from`.
    ///
    /// Fire-and-forget: consensus must never wait on disk.
    pub fn enqueue_prune(&self, keep_from: u64) {
        self.push(PersistJob::Prune { keep_from });
    }

    /// Request a durability barrier (processed after queued jobs).
    pub fn request_flush(&self) {
        self.push(PersistJob::Flush);
    }

    /// Jobs pushed but not yet dequeued by the background writer.
    ///
    /// Shutdown-path seam: the graceful-shutdown handler polls this until it
    /// reads empty (see [`wait_for_persist_drain`]). Reads zero at DEQUEUE —
    /// the dequeued job's own sled write (in particular the trailing `Flush`
    /// barrier's fsync) is still in flight at that instant, which is why the
    /// drain wait adds a bounded settle grace after observing zero rather
    /// than exiting immediately.
    pub fn pending(&self) -> u64 {
        self.queue_depth.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Snapshot the current state of an engine and enqueue it (convenience).
    ///
    /// Byte-identical to `engine.create_snapshot()`: the capture is the SAME
    /// canonical one (`InMemoryStateEngine::capture_state_snapshot` - the
    /// accounts PLUS the D2 consensus penalty map, address-sorted), so the
    /// bytes this path writes are the bytes `create_snapshot` produces and the
    /// bytes `restore_snapshot` reads back. Only the encode moves to the
    /// blocking pool (see [`serialize_off_tick`]).
    pub async fn snapshot_state(&self, engine: &InMemoryStateEngine, height: u64) {
        let accounts = clone_account_snapshot(engine).await;
        let snap = serialize_off_tick(accounts).await.unwrap_or_default();
        self.enqueue_state(height, snap);
    }
}

/// Durability sink for the process-shared cross-shard finalized-header
/// registry: the registry hands us one complete snapshot per mutation and we
/// only ENQUEUE it, so the finalize path never touches disk.
impl FinalizedHeaderSink for AsyncPersistence {
    fn persist_finalized_headers(&self, bytes: Vec<u8>) {
        self.enqueue_xshard_headers(bytes);
    }
}

/// Graceful-shutdown drain budget: overall cap on waiting for the persist
/// queue to empty (shutdown path only).
///
/// The units carry `TimeoutStopSec=300s`: the process must be gone well
/// inside it, or systemd SIGKILLs it mid-write — the torn-sled brick this
/// replaces (fixed 15s sleep, then `exit(0)` mid-flush). Worst case below is
/// `SHUTDOWN_DRAIN_CAP_SECS + SHUTDOWN_SETTLE_GRACE_SECS` = 250s < 300s.
pub const SHUTDOWN_DRAIN_CAP_SECS: u64 = 240;
/// Poll cadence while waiting for the queue to drain. The query is one
/// atomic load, so sub-second polling costs nothing and exits promptly on
/// drain instead of sleeping past it.
pub const SHUTDOWN_DRAIN_POLL_MS: u64 = 500;
/// Operator-visible progress cadence while waiting for the drain.
pub const SHUTDOWN_DRAIN_LOG_EVERY_SECS: u64 = 15;
/// Extra grace AFTER the queue reads empty. [`AsyncPersistence::pending`]
/// hits zero at DEQUEUE — the trailing `Flush` barrier's own sled fsync is
/// still in flight at that instant — and the runtime snapshot worker
/// (`submit_snapshot`/`poll_snapshot`) is not queryable from the shutdown
/// path (no runtime handle is captured there), so a bounded settle covers
/// both without refactoring unrelated code.
pub const SHUTDOWN_SETTLE_GRACE_SECS: u64 = 10;

/// Tuning for [`wait_for_persist_drain`]. `Default` is the production
/// shutdown budget above; the struct (not loose args) exists so tests can
/// shrink every knob to milliseconds without touching production values.
#[derive(Clone, Copy, Debug)]
pub struct ShutdownDrainConfig {
    /// Give up and report `drained: false` after this long.
    pub cap: std::time::Duration,
    /// Delay between queue-depth polls.
    pub poll: std::time::Duration,
    /// Minimum gap between `[storage] shutdown drain` progress lines.
    pub log_every: std::time::Duration,
    /// Extra wait after the queue first reads empty (see
    /// [`SHUTDOWN_SETTLE_GRACE_SECS`]).
    pub settle_grace: std::time::Duration,
}

impl Default for ShutdownDrainConfig {
    fn default() -> Self {
        Self {
            cap: std::time::Duration::from_secs(SHUTDOWN_DRAIN_CAP_SECS),
            poll: std::time::Duration::from_millis(SHUTDOWN_DRAIN_POLL_MS),
            log_every: std::time::Duration::from_secs(SHUTDOWN_DRAIN_LOG_EVERY_SECS),
            settle_grace: std::time::Duration::from_secs(SHUTDOWN_SETTLE_GRACE_SECS),
        }
    }
}

/// Outcome of [`wait_for_persist_drain`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShutdownDrainOutcome {
    /// True when the queue read empty before the cap (settle grace included
    /// in the wait); false when the cap fired first — e.g. consensus kept
    /// finalizing (and enqueueing) during the wait, or the disk is wedged.
    /// The caller still exits: the cap is the bounded worst case inside the
    /// systemd stop timeout.
    pub drained: bool,
    /// Queue depth observed when the wait ended (0 when drained).
    pub last_pending: u64,
}

/// Wait until `pending` reports an empty persist queue, then observe the
/// settle grace and report. `pending` is any queue-depth query — in
/// production `|| ap.pending()`, in tests a fake counter.
///
/// Evidence contract for operators: while waiting, one
/// `[storage] shutdown drain: N blocks pending...` line every `log_every`.
pub async fn wait_for_persist_drain_with(
    pending: impl Fn() -> u64,
    cfg: ShutdownDrainConfig,
) -> ShutdownDrainOutcome {
    let start = std::time::Instant::now();
    let mut last_log = start;
    loop {
        let n = pending();
        if n == 0 {
            tokio::time::sleep(cfg.settle_grace).await;
            return ShutdownDrainOutcome {
                drained: true,
                last_pending: 0,
            };
        }
        if start.elapsed() >= cfg.cap {
            return ShutdownDrainOutcome {
                drained: false,
                last_pending: n,
            };
        }
        if last_log.elapsed() >= cfg.log_every {
            eprintln!("[storage] shutdown drain: {n} blocks pending...");
            last_log = std::time::Instant::now();
        }
        tokio::time::sleep(cfg.poll).await;
    }
}

/// Production-budget [`wait_for_persist_drain_with`]: the shared shutdown
/// helper every graceful-shutdown site calls after `request_flush()`.
/// Keeps `exit(0)` semantics at the call site; worst case
/// cap + settle grace, comfortably inside the 300s stop timeout.
pub async fn wait_for_persist_drain(pending: impl Fn() -> u64) -> ShutdownDrainOutcome {
    wait_for_persist_drain_with(pending, ShutdownDrainConfig::default()).await
}

/// The engine's consensus state, cloned under the read lock and NOT serialized.
///
/// This clone IS the snapshot instant: every byte that follows (bincode, the
/// disk queue, the DHT publish) happens after it, off the caller's await point,
/// so a snapshot labeled `height` still holds exactly the state `height`
/// finalized even if `height+1` is applied before the encode runs.
///
/// It is the CANONICAL capture (`InMemoryStateEngine::capture_state_snapshot`):
/// the accounts (address-sorted) AND the D2 consensus penalty map. The
/// penalty is consensus-critical (it enters the charged fee), so a snapshot
/// that dropped it would restore a node that charges a DIFFERENT fee than a
/// node that applied the blocks - a different state root, i.e. a consensus
/// split (audit W6.6). The same function backs
/// `InMemoryStateEngine::create_snapshot`, so the off-tick bytes and the
/// inline bytes are identical by construction, not by coincidence.
pub async fn clone_account_snapshot(
    engine: &InMemoryStateEngine,
) -> crate::state_engine::StateSnapshotV2 {
    engine.capture_state_snapshot().await
}

/// bincode-serialize `value` on the BLOCKING POOL (never on a consensus tick).
///
/// §7 Phase 1: a full account or domain snapshot is thousands of allocations
/// plus one large buffer, and doing that inline kept a non-transport millisecond
/// cost on the very loop that drives consensus (and, in `create_snapshot`, under
/// the engine's read lock, which then blocked writers). Returns `None` when
/// bincode refuses the value, so callers keep whatever skip/fallback behaviour
/// they had with an inline `bincode::serialize`.
pub async fn serialize_off_tick<T: Serialize + Send + 'static>(value: T) -> Option<Vec<u8>> {
    tokio::task::spawn_blocking(move || bincode::serialize(&value).ok())
        .await
        .unwrap_or(None)
}
