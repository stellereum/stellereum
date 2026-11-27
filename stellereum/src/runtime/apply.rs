use super::lanes::{
    count_block_actor_sends, ApplyInflight, ApplyJob, ApplyLane, LaneJob, SnapshotJob,
};
use super::{
    ApplyCompleted, BlockHash, DecidedParentVotes, SnapBundle, ValidatorRuntime,
    MAX_APPLY_IN_FLIGHT_DEPTH, POST_STATE_HISTORY_CAP, RUNTIME_BLOCK_CACHE_WINDOW,
    RUNTIME_FINALIZED_CACHE_WINDOW,
};
use crate::consensus::{Height, HeightConsensus};
use crate::sharding::{Block, CrossShardKey, CrossShardMessage};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Prune a height-keyed ring to its newest [`POST_STATE_HISTORY_CAP`] entries.
/// `BTreeMap` iterates ascending, so the first keys are the oldest heights.
fn prune_post_state_history<V>(ring: &mut BTreeMap<u64, V>) {
    while ring.len() > POST_STATE_HISTORY_CAP {
        let Some(oldest) = ring.keys().next().copied() else {
            break;
        };
        ring.remove(&oldest);
    }
}

/// Height-driven governance finalization on the live path (neural audit
/// 2026-11-04 C-02, P0: `gov_finalize` was never called on the live path, so
/// voter/proposer staking locks were held forever).
///
/// After each decided block, finalizes every still-Open proposal whose voting
/// window closed (block time is `now`) via `finalize_at_height` at the decided
/// height: Passed proposals get their `GOV_TIMELOCK_HEIGHTS` (7200) maturity
/// scheduled, and every terminal transition releases its staking locks.
/// Inputs are pure block content (`height`, `timestamp`) plus the committed
/// pre-state, swept in proposal-id order, so every node finalizing the same
/// block derives the same transition and the same root — the mutation is a
/// deterministic function of the block, not an off-block RPC write (C-01
/// direction). Returns the finalized ids (logging/tests).
///
/// Lock order is governance-then-staking, matching the RPC handlers, so no
/// lock cycle is introduced. // GATE: C-02 live-path wiring.
pub(super) async fn sweep_gov_finalize(
    state: &crate::state_engine::InMemoryStateEngine,
    cur_height: u64,
    now: u64,
) -> Vec<u64> {
    let due: Vec<u64> = {
        let g = state.governance_read().await;
        let mut ids: Vec<u64> = g
            .proposals
            .iter()
            .filter(|(_, p)| {
                p.status == crate::governance::ProposalStatus::Open && now >= p.voting_end
            })
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    };
    if due.is_empty() {
        return Vec::new();
    }
    let mut g = state.governance_write().await;
    let mut ledger = state.staking_write().await;
    let mut done = Vec::with_capacity(due.len());
    for pid in due {
        match g.finalize_at_height(&mut ledger, pid, now, cur_height) {
            Ok(_) => done.push(pid),
            Err(_) => {
                // Unreachable with the filter above (same `now`, and no other
                // finalizer exists on this path); skip fail-safe so one id can
                // never wedge the height — the next height retries with the
                // same deterministic inputs.
            }
        }
    }
    if !done.is_empty() {
        tracing::info!(
            "[gov] finalized {} proposal(s) at height {cur_height}: {done:?}",
            done.len()
        );
    }
    done
}

impl ValidatorRuntime {
    // ==================== §7 Phase 2: lane plumbing ====================

    /// True while a decided block's execution is still on the worker. Stage 1
    /// of the consensus loop and every reader of post-H state check this
    /// first: while set, our observable consensus state (height, `finalized`,
    /// the root a new proposal is checked against) is still PRE-H.
    pub fn has_pending_apply(&self) -> bool {
        !self.apply_in_flight.is_empty()
    }

    /// Depth of the decided-but-uninstalled apply queue (diagnostics/tests).
    pub fn apply_in_flight_depth(&self) -> usize {
        self.apply_in_flight.len()
    }

    /// Blueprint predicate for "may this node accept a consensus decision at
    /// `height` right now?".
    ///
    /// * Below [`crate::chain_spec::execution_pipeline_v1_active_at`] this is
    ///   exactly [`Self::has_pending_apply`] inverted: at most one apply in
    ///   flight and no post-state history is required (today's rule,
    ///   byte-identical behaviour).
    /// * At/above the gate the queue may hold up to
    ///   [`MAX_APPLY_IN_FLIGHT_DEPTH`] decided blocks, but only once the
    ///   committed post-state the new decision builds on
    ///   ([`crate::chain_spec::committed_state_height_at`]) has a recorded
    ///   worker-certified root. That is the lag-2 binding: a decision is
    ///   admitted only when its parent state is already committed, not merely
    ///   queued.
    ///
    /// Seed `post_state_roots[0]` from the current genesis state root when
    /// running at genesis (`finalized.is_empty()` and `apply_in_flight.is_empty()`)
    /// and height `0` is not yet recorded.
    pub async fn ensure_genesis_root_seeded(&mut self) {
        if self.finalized.is_empty()
            && self.apply_in_flight.is_empty()
            && !self.post_state_roots.contains_key(&0)
        {
            let root = self.state.get_state_root().await;
            self.note_post_state_root(0, root);
        }
    }

    pub fn can_accept_consensus_height(&mut self, height: u64) -> bool {
        if !crate::chain_spec::execution_pipeline_v1_active_at(height) {
            return self.apply_in_flight.is_empty();
        }
        let committed_h = crate::chain_spec::committed_state_height_at(height);
        let has_committed = self.post_state_roots.contains_key(&committed_h)
            || (committed_h == 0 && self.finalized.is_empty() && self.apply_in_flight.is_empty());
        self.apply_in_flight.len() < MAX_APPLY_IN_FLIGHT_DEPTH && has_committed
    }

    /// Record a worker-certified post-state root at `height` and prune the
    /// bounded history to its newest [`POST_STATE_HISTORY_CAP`] entries.
    pub fn note_post_state_root(&mut self, height: u64, root: [u8; 32]) {
        self.post_state_roots.insert(height, root);
        prune_post_state_history(&mut self.post_state_roots);
    }

    /// Prune bounded in-memory block and finalized-history caches after
    /// committing `committed_height`.
    ///
    /// * Keeps the newest [`RUNTIME_FINALIZED_CACHE_WINDOW`] entries in
    ///   `self.finalized`, preserving monotonic order and the finalized tip.
    /// * When `self.blocks.len() > RUNTIME_BLOCK_CACHE_WINDOW`, evicts entries
    ///   strictly below `committed_height.saturating_sub(RUNTIME_BLOCK_CACHE_WINDOW as u64)`
    ///   while never evicting any block whose height or hash is still
    ///   referenced by `apply_in_flight`, `parked_commit`, `parked_proposal`,
    ///   `post_state_roots`, `last_decision`, `decided_parent_votes`, `hc`, or
    ///   the retained `finalized` tip.
    pub fn prune_runtime_history(&mut self, committed_height: u64) {
        if self.finalized.len() > RUNTIME_FINALIZED_CACHE_WINDOW {
            let excess = self.finalized.len() - RUNTIME_FINALIZED_CACHE_WINDOW;
            self.finalized.drain(..excess);
        }
        if self.blocks.len() > RUNTIME_BLOCK_CACHE_WINDOW {
            let min_keep_height =
                committed_height.saturating_sub(RUNTIME_BLOCK_CACHE_WINDOW as u64);
            let mut protected_hashes: HashSet<BlockHash> = HashSet::new();
            let mut protected_heights: HashSet<u64> = HashSet::new();

            for inflight in &self.apply_in_flight {
                protected_hashes.insert(inflight.hash);
                protected_hashes.insert(inflight.block.prev_hash);
                protected_heights.insert(inflight.height);
            }
            if let Some(pc) = &self.parked_commit {
                protected_hashes.insert(pc.block.prev_hash);
                protected_hashes.insert(pc.block.compute_hash());
                protected_heights.insert(pc.height);
            }
            if let Some(pp) = &self.parked_proposal {
                protected_hashes.insert(pp.block.prev_hash);
                protected_hashes.insert(pp.block.compute_hash());
                protected_heights.insert(pp.block.height);
            }
            for &h in self.post_state_roots.keys() {
                protected_heights.insert(h);
            }
            if let Some((h, blk, _)) = &self.last_decision {
                protected_heights.insert(*h);
                protected_hashes.insert(blk.compute_hash());
            }
            if let Some(dpv) = &self.decided_parent_votes {
                protected_heights.insert(dpv.height);
                protected_hashes.insert(dpv.block_hash);
                protected_hashes.insert(dpv.decision_block_hash);
            }
            if let Some((h, _)) = self.hc.locked {
                protected_hashes.insert(h);
            }
            if let Some((_, h)) = self.hc.proposal {
                protected_hashes.insert(h);
            }
            if let Some(h) = self.hc.sortition_parent() {
                protected_hashes.insert(*h);
            }
            if let Some((tip_h, tip_hash)) = self.finalized.last().copied() {
                protected_heights.insert(tip_h);
                protected_hashes.insert(tip_hash);
            }
            protected_heights.insert(self.hc.height);

            self.blocks.retain(|hash, block| {
                block.height >= min_keep_height
                    || protected_hashes.contains(hash)
                    || protected_heights.contains(&block.height)
            });
        }
    }

    /// Whether this node may build/propose a block at `height` right now.
    ///
    /// * Below [`crate::chain_spec::execution_pipeline_v1_active_at`]: identical
    ///   to `self.apply_in_flight.is_empty()`.
    /// * At/above the gate: up to [`MAX_APPLY_IN_FLIGHT_DEPTH`] applies may be
    ///   in flight (lag-2 overlap allows 1 in flight while proposing the next),
    ///   provided the committed post-state root for
    ///   [`crate::chain_spec::committed_state_height_at`] is already recorded.
    pub fn can_propose_at_height(&self, height: u64) -> bool {
        if !crate::chain_spec::execution_pipeline_v1_active_at(height) {
            return self.apply_in_flight.is_empty();
        }
        let committed_h = crate::chain_spec::committed_state_height_at(height);
        let has_committed = self.post_state_roots.contains_key(&committed_h)
            || (committed_h == 0 && self.finalized.is_empty() && self.apply_in_flight.is_empty());
        self.apply_in_flight.len() < MAX_APPLY_IN_FLIGHT_DEPTH && has_committed
    }

    /// Worker-certified post-state root for the state height committed by a
    /// block at `height` (`committed_state_height_at(height)`).
    pub fn state_root_for_committed_height(&self, height: u64) -> Option<[u8; 32]> {
        self.post_state_roots
            .get(&crate::chain_spec::committed_state_height_at(height))
            .copied()
    }

    /// Whether this node holds the committed post-state required to validate
    /// a proposal (or commit) at `height` right now.
    ///
    /// * Below [`crate::chain_spec::execution_pipeline_v1_active_at`]: identical
    ///   to `self.apply_in_flight.is_empty()`.
    /// * At/above the gate: requires the worker-certified root for
    ///   [`crate::chain_spec::committed_state_height_at`] to be recorded in
    ///   [`Self::post_state_roots`].
    pub fn can_validate_proposal_at_height(&self, height: u64) -> bool {
        if !crate::chain_spec::execution_pipeline_v1_active_at(height) {
            return self.apply_in_flight.is_empty();
        }
        let committed_h = crate::chain_spec::committed_state_height_at(height);
        self.post_state_roots.contains_key(&committed_h)
            || (committed_h == 0 && self.finalized.is_empty() && self.apply_in_flight.is_empty())
    }

    /// Decided parent tip height for `height`:
    /// * Below the gate (or when `apply_in_flight` does not hold `height - 1`):
    ///   the last installed entry in `self.finalized` (`0` at genesis).
    /// * At/above the gate when `height - 1` is already decided in
    ///   `self.apply_in_flight`: that queued parent's height.
    pub fn decided_tip_height_for_height(&self, height: u64) -> u64 {
        if crate::chain_spec::execution_pipeline_v1_active_at(height) {
            if let Some(inflight) = self
                .apply_in_flight
                .back()
                .filter(|a| a.height.checked_add(1) == Some(height))
            {
                return inflight.height;
            }
        }
        self.finalized.last().map(|(h, _)| *h).unwrap_or(0)
    }

    /// Expected `prev_hash` for a block at `height`:
    /// * Below the gate (or when `apply_in_flight` does not hold `height - 1`):
    ///   the last installed entry in `self.finalized` (`[0u8; 32]` at genesis).
    /// * At/above the gate when `height - 1` was already decided and queued in
    ///   `self.apply_in_flight`: that queued parent's hash, so lag-2 consensus
    ///   for `height` chains onto `height - 1` while `height - 1` executes.
    pub fn expected_parent_hash_for_height(&self, height: u64) -> BlockHash {
        if crate::chain_spec::execution_pipeline_v1_active_at(height) {
            if let Some(inflight) = self
                .apply_in_flight
                .back()
                .filter(|a| a.height.checked_add(1) == Some(height))
            {
                return inflight.hash;
            }
        }
        self.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32])
    }

    /// TEST/DEBUG-ONLY: seed the bounded in-flight queue with a synthetic entry
    /// (no worker behind it) so integration tests can exercise the depth gates
    /// without a live consensus round. The completion channel is already
    /// closed, so the entry can only ever observe a depth predicate — it is
    /// never production-reachable and is compiled out of release builds.
    #[cfg(any(test, debug_assertions))]
    #[doc(hidden)]
    pub fn debug_try_enqueue_apply_inflight(&mut self, height: u64, hash: BlockHash) -> bool {
        // Mirror the production admission rule exactly: depth 1 below the
        // gate, MAX_APPLY_IN_FLIGHT_DEPTH at/above it.
        let limit = if crate::chain_spec::execution_pipeline_v1_active_at(height) {
            MAX_APPLY_IN_FLIGHT_DEPTH
        } else {
            1
        };
        if self.apply_in_flight.len() >= limit {
            return false;
        }
        let mut block = super::lanes::shard_genesis_block(self.shard_id, [0u8; 32], self.id, 0);
        block.height = height;
        let (_tx, rx) = tokio::sync::oneshot::channel();
        self.apply_in_flight.push_back(ApplyInflight {
            height,
            hash,
            block,
            done: rx,
        });
        true
    }

    /// Messages currently queued in every inbox: defensive leftovers plus
    /// anything queued since. Honest operation keeps this at zero at every
    /// block boundary (drain-to-empty plus the cap check below refuses any
    /// block that would break it), so a non-zero value here is either a test
    /// setup or evidence of pre-fix history.
    pub async fn pending_actor_backlog(&self) -> usize {
        self.cached_actor_backlog().await
    }

    /// The inbox total with a per-(height, state-root) cache (R-tempo).
    ///
    /// SOUNDNESS: the inbox sum is a pure function of committed state. The
    /// scan runs under ONE read guard (mutually consistent entries) bracketed
    /// by two root reads; the total is stored only when both roots match the
    /// key (no mutation mid-scan — any mutation moves the root). A later hit
    /// re-checks the CURRENT root against the key, so it returns exactly what
    /// a fresh full-map scan would prove. The scan keeps the early exit of
    /// `check_actor_cap` (proving "over cap" needs no full sum), and an
    /// over-cap total is NOT stored (only exact totals are cached).
    pub(super) async fn cached_actor_backlog(&self) -> usize {
        let height = self.hc.height;
        let root0 = self.state.get_state_root().await;
        if let Some(total) = self.actor_backlog_cache.lock().ok().and_then(|g| {
            g.as_ref()
                .filter(|(h, r, _)| *h == height && *r == root0)
                .map(|(_, _, t)| *t)
        }) {
            return total;
        }
        let guard = self.state.accounts.read().await;
        let mut total: usize = 0;
        for a in guard.values() {
            total = total.saturating_add(a.inbox.len());
            // Same bound as the cap check: proving "over cap" needs no full sum.
            if total > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK {
                break;
            }
        }
        drop(guard);
        let root1 = self.state.get_state_root().await;
        // Store only a PROVEN total: the scan saw one consistent state, and
        // both bracketing roots match it. Anything else is used once (it is
        // still a consistent snapshot) but never cached.
        if root0 == root1 {
            if let Ok(mut g) = self.actor_backlog_cache.lock() {
                *g = Some((height, root1, total));
            }
        }
        total
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
        // Backlog via the shared (height, root) cache: a hit returns exactly
        // what the scan below would prove (R-tempo). Same verdict as
        // `pending_actor_backlog() + sends > cap`, O(1) on repeat visits.
        let backlog = self.cached_actor_backlog().await;
        if backlog.saturating_add(sends) > crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK {
            return Err(format!(
                "actor mailbox over cap: {backlog} queued + {sends} in block > {} (rejected; leftovers never carry over)",
                crate::state_engine::MAX_ACTOR_MSGS_PER_BLOCK
            ));
        }
        Ok(())
    }

    /// Spawn-once accessor for the single ordered worker. Lazy so that
    /// construction never needs a tokio context; every apply below funnels
    /// through here, so there is exactly one worker per runtime — never a
    /// pool, never parallel.
    pub(super) fn ensure_apply_lane(&mut self) -> ApplyLane {
        if self.apply_lane.is_none() {
            self.apply_lane = Some(ApplyLane::spawn(&self.state));
        }
        self.apply_lane.clone().expect("lane just spawned")
    }

    /// Run one decided block's state transition on the worker and wait for
    /// it. The worker runs one job at a time strictly in submission order,
    /// so even concurrent submitters can never interleave two applies: the
    /// second simply waits behind the first on the channel.
    pub(super) async fn run_on_apply_lane(
        &mut self,
        block: &Block,
        reward: u64,
    ) -> super::lanes::ApplyJobResult {
        let lane = self.ensure_apply_lane();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sweep_gov_in_worker = crate::chain_spec::execution_pipeline_v1_active_at(block.height);
        lane.tx
            .send(LaneJob::Apply(ApplyJob {
                block: block.clone(),
                reward,
                sweep_gov_in_worker,
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
    pub(super) async fn apply_decided(
        &mut self,
        block: &Block,
    ) -> (crate::state_engine::BlockTransitionOutcome, [u8; 32]) {
        // `block.timestamp` is the VM's "now" for every payload in this block:
        // unbonding maturity, contract creation time, order stamps. Every node
        // applying this block passes the SAME value, so the resulting state is
        // deterministic.
        //
        // R1/DET-01: pass only the STATIC default. The transition resolves the
        // governed value itself from the committed pre-state (its own
        // governance read), so no caller-held copy can make this path mint a
        // different amount than the catch-up/walk path for the same block.
        let (outcome, root, penalties) = self.run_on_apply_lane(block, self.block_reward).await;
        self.record_apply_outcome(block, &outcome).await;
        self.note_post_state_root(block.height, root);
        self.consensus_penalties_at.insert(block.height, penalties);
        prune_post_state_history(&mut self.consensus_penalties_at);
        (outcome, root)
    }

    /// Node-local half of the finalize-apply sequence: everything the old
    /// inline `apply_block_fees_rewards` did AFTER `apply_block_transition`
    /// (receipts / applied counters, mempool pruning, cross-shard
    /// bookkeeping). None of it can move the state root, and the reorg path
    /// mirrors it field by field — see `ChainState::apply_block`.
    pub(super) async fn record_apply_outcome(
        &mut self,
        block: &Block,
        outcome: &crate::state_engine::BlockTransitionOutcome,
    ) {
        self.applied_statuses = outcome.status.clone();
        self.applied_fees = outcome.tx_fees.clone();
        self.applied_events = outcome.events.clone();
        self.applied_txs += outcome.applied as u64;
        // Node-local: remove included txs from our mempool so they are never
        // re-proposed. The mempool is not consensus state and is not part of
        // the state root, so the reorg path (which has no mempool) diverges
        // here without forking - see `ChainState::apply_block`.
        let included: Vec<[u8; 32]> = block
            .transactions
            .iter()
            .map(|t| t.compute_tx_hash())
            .collect();
        self.mempool.write().await.prune_confirmed(&included);
        // CometBFT-style RECHECK after each commit: the commit advanced
        // on-chain nonces, drained balances and may have moved the fee floor,
        // so queued txs valid at admission can now be permanently
        // unexecutable. `recheck` drops exactly those (spent nonce / drained
        // balance / fee below floor) against post-commit state; honest pools
        // come back with 0. Snapshot-then-recheck under SEPARATE short locks
        // (never nested): the accounts read drops before the mempool write is
        // taken, so no lock order is introduced.
        {
            let payers: Vec<[u8; 32]> =
                self.mempool.read().await.fee_payers().into_iter().collect();
            let guard = self.state.accounts.read().await;
            let mut snap: HashMap<[u8; 32], (u64, u64)> = HashMap::with_capacity(payers.len());
            for a in &payers {
                if let Some(acct) = guard.get(a) {
                    snap.insert(*a, (acct.nonce, acct.balance));
                }
            }
            drop(guard);
            let dropped = self
                .mempool
                .write()
                .await
                .recheck(crate::zkml::now_secs(), |a| snap.get(a).copied());
            if dropped > 0 {
                tracing::info!(
                    "[mempool] recheck after commit at height {}: dropped {dropped} stale tx(s)",
                    block.height,
                );
            }
        }
        // D2 free-failure gate: an included transaction that FAILED at apply
        // paid nothing (the native commit is atomic) while its bytes occupied
        // block wire/gas and burned verifier CPU. Feed the verdicts back so a
        // repeatedly-failing sender must over-post (bond in fee form) to
        // re-enter the pool or a future block; one success clears the sender.
        // PAYMASTER: the penalty stays keyed on the USER (whose nonce
        // advanced and whose failure history it prices) even when the
        // sponsor paid the failure fee — the sponsor is protected by their
        // explicit per-tx cap, not by the penalty.
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
            self.mempool
                .write()
                .await
                .note_apply_feedback(&failed, &succeeded);
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
            // XSHARD bounce-escrow gate: at/above the gate an outbound
            // transfer enters the produced mirror ONLY when its transaction
            // APPLIED (`status[i]`) and the committed XSHARD-01 escrow leaf
            // proves the source debit. Recording a refused transaction is the
            // mint side of the S6-2 defect: its outbound record exists, it
            // debited nobody, and the timeout bounce would refund an amount
            // the sender still holds. Below the gate the historical
            // unconditional record is kept byte-identical.
            let bounce_escrow_gate =
                crate::chain_spec::xshard_bounce_escrow_required_active_at(block.height);
            // XSHARD bounce-escrow gate, HISTORY CLEANSE (runtime mirror): the
            // engine pruned every produced entry without a committed escrow
            // leaf at the start of this apply; mirror that verdict here so the
            // two sets (and therefore `cross_shard_replay_covers`) stay in
            // lockstep across a restart. Post-apply leaves are exactly the
            // engine's pre-apply leaves for previous blocks (no step deletes
            // an escrow leaf), so the victim set is identical.
            if bounce_escrow_gate {
                let hashes: Vec<[u8; 32]> = self.produced_cross_shard.keys().copied().collect();
                for tx_hash in hashes {
                    if !self.state.legacy_escrow_leaf_committed(&tx_hash).await {
                        self.produced_cross_shard.remove(&tx_hash);
                    }
                }
            }
            // §9 2PC: refresh the runtime's mirror of the committed 2PC
            // records from the engine (the authority). The mirror is what
            // the SYNCHRONOUS proposal-validation path reads.
            self.xpc_records = self
                .state
                .xpc_snapshot()
                .await
                .into_iter()
                .map(|r| (r.tx_hash, r))
                .collect();
            // XSHARD bounce-escrow gate: every 2PC record in THIS block also
            // refuses a control record for the same hash, even before the
            // engine snapshot below was taken (the mirror refresh above runs
            // after the block's own records are committed, but a same-block
            // PREPARE + bounce must never be able to pay).
            let xpc_in_block: HashSet<[u8; 32]> = block
                .cross_shard_out
                .iter()
                .filter(|m| m.is_xpc())
                .map(|m| m.tx.compute_tx_hash())
                .collect();
            for msg in &block.cross_shard_out {
                if msg.is_transfer() && msg.is_outbound_for(self.shard_id) {
                    let tx_hash = msg.tx.compute_tx_hash();
                    if bounce_escrow_gate {
                        let applied = block
                            .transactions
                            .iter()
                            .position(|t| t.compute_tx_hash() == tx_hash)
                            .and_then(|idx| outcome.status.get(idx).copied())
                            .unwrap_or(false);
                        if !applied || !self.state.has_legacy_escrow_leaf(&msg.tx).await {
                            continue;
                        }
                    }
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
                if msg.is_xpc() {
                    // §9 2PC: the ENGINE applied the record (it owns the
                    // phase transitions, value movements, and replay sets), so
                    // the runtime MUST keep exact parity with the engine's
                    // `cross_shard_consumed` and `cross_shard_completed` sets
                    // (otherwise `CrossShardReplaySnapshot` diverges on
                    // restart and `verify_restored_root` fails). The engine
                    // never adds XPC keys to `cross_shard_consumed`, and adds
                    // `tx_hash` to `cross_shard_completed` on terminal commits
                    // (`PrepareAck`, `Commit`, `AbortAck`).
                    if self.state.is_cross_shard_consumed(&key).await {
                        self.consumed_cross_shard.insert(key);
                    }
                    let tx_hash = msg.tx.compute_tx_hash();
                    if self.state.is_cross_shard_completed(&tx_hash).await {
                        self.completed_cross_shard.insert(tx_hash);
                    }
                    pruned_ids.push(msg.msg_id);
                    continue;
                }
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
                        let ack = CrossShardMessage::new_ack(msg.tx.clone(), block.compute_hash());
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
                    let tx_hash = msg.tx.compute_tx_hash();
                    // XSHARD bounce-escrow gate: refuse BEFORE the replay
                    // claim (so the record stays replayable and the sets never
                    // claim a completion that paid nothing). A bounce must be
                    // backed by the committed source escrow leaf, and NO
                    // control record may complete a transaction that owns a
                    // §9 2PC record (in this block OR committed earlier).
                    // Without this a hand-crafted bounce refunds the source
                    // while the target's COMMIT credits the recipient — the
                    // S6-2 double spend.
                    if bounce_escrow_gate {
                        if xpc_in_block.contains(&tx_hash)
                            || self.xpc_records.contains_key(&tx_hash)
                        {
                            tracing::warn!(
                                "cross-shard bounce/ack refused at the escrow gate: tx {} owns a 2PC record",
                                hex::encode(&tx_hash[..8])
                            );
                            continue;
                        }
                        if msg.is_bounce() && !self.state.has_legacy_escrow_leaf(&msg.tx).await {
                            tracing::warn!(
                                "cross-shard bounce refused at the escrow gate: tx {} has no committed source escrow leaf",
                                hex::encode(&tx_hash[..8])
                            );
                            continue;
                        }
                    }
                    if !self.consumed_cross_shard.insert(key) {
                        continue;
                    }
                    // Same-block ack+bounce for one transaction: the first in
                    // key order completes it; the second finds it completed.
                    if !self.completed_cross_shard.insert(tx_hash) {
                        continue;
                    }
                    pruned_ids.push(msg.msg_id);
                    if msg.is_bounce() {
                        // The refund: exactly `tx.amount` back to the sender.
                        // Gas went to the source proposer at produce time and
                        // is not refunded. This is a REDEEM of value that was
                        // already debited on the source shard, not new minting:
                        // `credit_native` is the CAPPED mint path, so at the
                        // global supply cap the refund would be silently
                        // dropped and the sender's money lost. The transfer
                        // primitive creates the account if it vanished and
                        // commits to the trie, so every node applying this
                        // block still derives the same root.
                        if let Err(e) = self
                            .state
                            .credit_native_transfer(&msg.tx.from, msg.tx.amount)
                            .await
                        {
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
                let mut tx_succeeded: HashMap<[u8; 32], bool> =
                    HashMap::with_capacity(block.transactions.len());
                for (idx, tx) in block.transactions.iter().enumerate() {
                    let ok = outcome.status.get(idx).copied().unwrap_or(false);
                    tx_succeeded
                        .entry(tx.compute_tx_hash())
                        .and_modify(|prev| *prev |= ok)
                        .or_insert(ok);
                }
                for msg in &block.cross_shard_out {
                    let outbound = if msg.is_transfer() {
                        msg.is_outbound_for(self.shard_id)
                    } else {
                        // §9 2PC: the outbound 2PC records (the vote, the
                        // decision, the abort request) are published the same
                        // way the legacy transfer is.
                        msg.is_xpc() && msg.is_outbound_for(self.shard_id)
                    };
                    if !outbound {
                        continue;
                    }
                    // SECURITY (mint-without-source): only broadcast
                    // tx-originated outbound `Transfer` / `Prepare` messages
                    // when the matching transaction in `block.transactions`
                    // actually succeeded. A failed tx debits nobody on the
                    // source shard, so publishing its pre-block inclusion proof
                    // would let the target shard credit without a source
                    // debit. XPC messages derived from `xpc_records`
                    // (re-published `Prepare`, `Commit`, `PrepareAck`,
                    // `AbortRequest`, `AbortAck`) have no tx in
                    // `block.transactions` and continue to broadcast as before.
                    if msg.is_transfer() || msg.is_prepare() {
                        let tx_hash = msg.tx.compute_tx_hash();
                        if matches!(tx_succeeded.get(&tx_hash), Some(false)) {
                            tracing::warn!(
                                "cross-shard outbound suppressed for failed tx {} (msg {})",
                                hex::encode(&tx_hash[..8]),
                                hex::encode(&msg.msg_id[..8]),
                            );
                            continue;
                        }
                    }
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

    /// Install a worker-reported outcome when the caller does NOT have the
    /// worker-certified root (direct/inline callers that applied on this
    /// runtime, e.g. unit tests). The current engine root IS that post-state in
    /// this case, so it is recorded verbatim.
    #[allow(dead_code)] // GATE: direct/inline (unit-test) callers have no completion channel.
    pub(super) async fn install_apply_outcome(
        &mut self,
        height: Height,
        bh: BlockHash,
        block: &Block,
        outcome: &crate::state_engine::BlockTransitionOutcome,
    ) {
        let root = self.state.get_state_root().await;
        let penalties = self.state.consensus_floor_snapshot().await.1;
        self.install_apply_outcome_with_root(height, bh, block, outcome, root, penalties)
            .await;
    }

    /// Install a worker-reported outcome: the node-local bookkeeping above,
    /// then the consensus advance the old inline path did (finalized entry,
    /// validator-set rotation, next height). Runs exactly once per decided
    /// block, whether the decision was awaited inline or collected later.
    ///
    /// `root` and `penalties` are captured by the WORKER immediately after
    /// executing this block and reported over the completion channel, so they
    /// never race a newer height already running on `ApplyLane`.
    pub(super) async fn install_apply_outcome_with_root(
        &mut self,
        height: Height,
        bh: BlockHash,
        block: &Block,
        outcome: &crate::state_engine::BlockTransitionOutcome,
        root: [u8; 32],
        penalties: HashMap<[u8; 32], u64>,
    ) {
        // Bounded post-state history: record this height's certified post-state
        // (and the worker-captured consensus-penalty map that travels with it),
        // pruning to the newest POST_STATE_HISTORY_CAP entries. Below the gate
        // nothing reads these rings, so this is unobservable bookkeeping there.
        self.note_post_state_root(height, root);
        self.consensus_penalties_at.insert(height, penalties);
        prune_post_state_history(&mut self.consensus_penalties_at);
        self.record_apply_outcome(block, outcome).await;
        // C-02: height-driven gov finalization (locks release, 7200-height
        // timelocks schedule). Deterministic in (height, block.timestamp).
        // At/above EXECUTION_PIPELINE_V1, `ApplyLane` already swept this inside
        // the worker BEFORE certifying `root`, so re-running here is skipped.
        if !crate::chain_spec::execution_pipeline_v1_active_at(height) {
            sweep_gov_finalize(&self.state, height, block.timestamp).await;
        }
        self.finalized.push((height, bh));
        // The block is final: it anchors the fork-choice tree, and every
        // candidate branch it superseded is pruned (and signalled).
        self.note_finalized_block(block);
        // Any finalize is progress: the deadlock breaker measures silence.
        // EMISSION ONLY (calibration feed, FIXES.md §2.12 block-interval
        // series): wall-clock seconds since the previous finalization
        // progress stamp — the sequenced worker path's live-commit cadence
        // (mirrors the inline `try_finalize` emission; exactly one of the two
        // fires per commit). Read BEFORE the stamp below is reset; on the
        // process-global registry; never feeds back into any decision.
        crate::metrics::global()
            .observe_block_interval(self.last_progress_at.elapsed().as_secs_f64());
        self.last_progress_at = std::time::Instant::now();
        // C1 anchor: every finalized block (live, replayed, adopted) feeds
        // the process-shared header registry its own and sibling shards read.
        self.note_finalized_header(block).await;
        self.note_light_anchor(block);
        // Rotate the consensus validator set from bonded stake at the applied
        // height (`height`, never `self.hc.height` which may already have
        // advanced under EXECUTION_PIPELINE_V1). At/above the gate this stages
        // for `height + 2`, so `height + 1` is never mutated mid-flight.
        self.refresh_validator_set_from_staking_at(height).await;
        // At/above EXECUTION_PIPELINE_V1, `submit_prepared_block` already advanced
        // `safety` and `hc` to `height + 1` on decide (`advance_consensus_pipeline_on_decide`)
        // so consensus could overlap for `height + 1`. Re-advancing `safety` or
        // resetting `hc` here would fail `HeightMismatch` or clobber live
        // `height + 1` consensus state. Direct `install_apply_outcome` test
        // callers (where `hc.height == height`) still take the full advance path.
        let already_advanced_on_decide =
            crate::chain_spec::execution_pipeline_v1_active_at(height) && self.hc.height > height;
        if !already_advanced_on_decide {
            if let Err(e) = self.safety.advance_height(height + 1, height, bh) {
                tracing::error!(height, error = %e, "[safety] advance_height failed; quarantining");
                self.safety.quarantine(format!(
                    "advance_height({} -> {}): {e}",
                    height,
                    height + 1
                ));
            }
            self.hc = HeightConsensus::new(height + 1, self.validators.clone());
            self.install_due_validator_set();
            self.hc.validators = self.validators.clone();
            // The sortition committee of height+1 is elected from the PARENT
            // block hash — the block we just finalized. Every node of the network
            // must use the same parent, or they elect different committees.
            self.hc.set_parent_hash(bh);
            // CN-VRF v3: install the new height's committee schedule (review F2).
            self.install_committee_schedule();
        }
        // PARITY with `try_finalize` and `apply_and_advance`: this is the
        // SEQUENCED/live finalize install (the node loop collects it with
        // `try_poll_apply`), and the epoch hooks are part of "every finalized
        // block advance" — refresh the mirrors, prepare next epoch's commit
        // before H_freeze, and dispatch the VDF at H_freeze. Omitting it here
        // meant the production path never dispatched an epoch VDF: at
        // activation the boundary block would have no beacon and the
        // fail-closed committee schedule would carry no proposer.
        self.prepare_cnvrf_v3_epoch_hooks(height, bh).await;
        // The committed state has advanced to `height`; re-project the view
        // over it plus whatever decided blocks are still queued (FIFO). With
        // an empty queue below the gate this simply clears the view.
        self.rebuild_pending_exec_view().await;
        self.prune_runtime_history(height);
    }

    /// Rebuild [`PendingExecView`] from the committed accounts plus every
    /// decided block still queued, in FIFO order.
    ///
    /// Only the senders/sponsors of the queued blocks are read from the committed
    /// state (one short read lock, released before the view is touched), so the
    /// cost is proportional to the queued transactions, not to the whole state.
    async fn rebuild_pending_exec_view(&mut self) {
        let blocks_in_flight: Vec<Block> = self
            .apply_in_flight
            .iter()
            .map(|inflight| inflight.block.clone())
            .collect();
        let mut senders: BTreeSet<[u8; 32]> = BTreeSet::new();
        for block in &blocks_in_flight {
            for tx in &block.transactions {
                senders.insert(tx.from);
                if let Some(auth) = tx.sponsored_grant() {
                    senders.insert(auth.sponsor);
                }
            }
        }
        let mut applied: BTreeMap<[u8; 32], (u64, u64)> = BTreeMap::new();
        if !senders.is_empty() {
            let guard = self.state.accounts.read().await;
            for addr in &senders {
                if let Some(acct) = guard.get(addr) {
                    applied.insert(*addr, (acct.nonce, acct.balance));
                }
            }
        }
        self.pending_exec_view.rebuild(&applied, &blocks_in_flight);
    }

    /// Shared DECISION half of finalization: quorum, presence, order and cap
    /// gates, QC attachment and decision-proof stash. Both `try_finalize`
    /// (await inline) and `try_finalize_submit` (queue on the worker) decide
    /// through here, so the two can never disagree about what is decidable.
    /// Returns the decided height, hash and block (QC attached).
    pub async fn prepare_decided_block(&mut self) -> Option<(Height, BlockHash, Block)> {
        if crate::chain_spec::execution_pipeline_v1_active_at(self.hc.height) {
            self.ensure_genesis_root_seeded().await;
        }
        // One apply at a time below the pipeline gate, bounded FIFO at/above
        // it (also requiring the committed post-state root for
        // `committed_state_height_at(self.hc.height)`). Guard against
        // double-queuing the same height in `apply_in_flight`.
        if !self.can_accept_consensus_height(self.hc.height) {
            return None;
        }
        if self
            .apply_in_flight
            .iter()
            .any(|inflight| inflight.height == self.hc.height)
        {
            return None;
        }
        // The decision certificate this height produces must be drawn from the
        // schedule its own finalize gate attributes it with. The engine is also
        // re-anchored by startup/sync code outside this crate's runtime, so the
        // schedule is (re)installed here, right before the producer runs
        // (review F2).
        self.install_committee_schedule();
        // Probe on a clone first so missing-body or validation refusals never
        // mutate `self.hc.step = Step::Commit` / `self.hc.decided` / `self.hc.locked`
        // (W6-A1-6).
        let mut hc_probe = self.hc.clone();
        let bh = hc_probe.try_precommit_quorum()?;
        let height = hc_probe.height;
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
        // MEV ORDER COMMITMENT (consensus-enforced): the block carries the
        // order Merkle root over its transaction list and the root is inside
        // the signed block hash, so the quorum that decided this block voted
        // for its ORDER as well. Re-compute the root from the body about to
        // execute and REFUSE to finalize a block that does not match.
        //
        // This used to be a warning: the commitment was node-local evidence
        // only (it was never in the block), so refusing would have stalled
        // ONLY the builder while the rest of the network moved on. Now the
        // commitment is on the wire and signed by the quorum, a mismatch is
        // real tamper evidence, and every node derives the same verdict — so
        // it is a hard refusal, not a log line.
        if let Err(e) = self.check_order_commitment_with_hash(&block, &bh) {
            tracing::error!(height, "{e}; refusing to finalize");
            return None;
        }
        // The node-local build-time commitment stays as an OPTIMIZATION and
        // as a second, independent witness: if THIS NODE built the block
        // being decided, the order about to execute is compared against the
        // commitment it made at build time.
        //
        // It is a WARNING, never a refusal (policy change, audit 2026-10-06):
        // the body about to execute is byte-identical to the one the quorum
        // voted (the hash check above), so the ORDER is what the network
        // committed — and the consensus-level check above (`check_order_
        // commitment`, the root INSIDE the signed hash) has already proved
        // it. A stale LOCAL witness therefore says nothing about the chain,
        // and refusing on it stalls ONLY the builder at that height while
        // every other node moves on (the exact regression this policy
        // change fixed).
        if block.proposer == self.id {
            let pool = self.mempool.read().await;
            match pool
                .mev
                .verify_block_order(block.height, bh, &block.transactions)
            {
                crate::mev::OrderVerdict::NoCommit | crate::mev::OrderVerdict::Match => {}
                verdict => {
                    tracing::warn!(
                        height,
                        ?verdict,
                        "block order differs from this node's build-time commitment; \
                         finalizing anyway (the quorum-voted body is authoritative)"
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
        // W10.5 HARDENING (fail LOUD, never finalize unilaterally): validate the
        // deciding QC against the set IN FORCE AT THIS HEIGHT before committing
        // `hc_probe`, `blocks`, or `last_decision`.
        let in_force = self.validator_set_for_height(height);
        let Some(qc) = hc_probe.precommit_qc.clone() else {
            tracing::error!(
                height,
                "REFUSING to finalize: decided without a precommit QC (unilateral finalization is never allowed)"
            );
            eprintln!(
                "[quorum] REFUSING to finalize height {height}: decided without a precommit QC — unilateral finalization is never allowed"
            );
            crate::metrics::global().inc_weak_qc_refused();
            return None;
        };
        let signed = self.qc_signed_power_for_height(&in_force, &qc);
        let required = in_force.quorum_power();
        if signed < required {
            tracing::error!(
                height,
                signed,
                required,
                total = in_force.total_power(),
                "REFUSING to finalize: deciding QC carries {signed} of {required} required power (total {}) — unilateral/weak finalization is never allowed",
                in_force.total_power(),
            );
            eprintln!(
                "[quorum] REFUSING to finalize height {height}: deciding QC carries {signed} of {required} required power — unilateral/weak finalization is never allowed"
            );
            crate::metrics::global().inc_weak_qc_refused();
            return None;
        }
        // All checks passed: commit the probed consensus state and attach the
        // precommit QC that decided this block.
        self.hc = hc_probe;
        let mut finalized_block = block;
        finalized_block.precommit_qc = Some(qc.clone());
        self.blocks.insert(bh, finalized_block.clone());
        self.last_decision = Some((height, finalized_block.clone(), qc.clone()));
        self.parent_evidence_missing = false;
        let votes = self.hc.precommit_set(qc.round).cloned().unwrap_or_default();
        self.decided_parent_votes = Some(DecidedParentVotes {
            height,
            round: qc.round,
            block_hash: bh,
            shard_id: qc.shard_id,
            validators: in_force,
            parent_hash: self.hc.sortition_parent().copied(),
            schedule: self.hc.committee_schedule,
            votes,
            decision_block_hash: bh,
        });
        let block = finalized_block;
        Some((height, bh, block))
    }

    pub async fn try_finalize(&mut self) -> Option<BlockHash> {
        let (height, bh, block) = self.prepare_decided_block().await?;
        // Economic security from block content: the transition runs the
        // downtime slash from `block.last_qc` (canonical proposer-chosen
        // evidence for height-1) AND the equivocation slash from the block's
        // `SysCallReportEquivocation` payloads (re-verified from block bytes,
        // pool-debited, per-offense deduped) inside `apply_block_transition` -
        // the same core the reorg path uses, so both burn the same coins.
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
        // C-02: height-driven gov finalization (locks release, 7200-height
        // timelocks schedule). Deterministic in (height, block.timestamp).
        // At/above EXECUTION_PIPELINE_V1, `ApplyLane` already swept this inside
        // the worker BEFORE certifying `root`.
        if !crate::chain_spec::execution_pipeline_v1_active_at(height) {
            sweep_gov_finalize(&self.state, height, block.timestamp).await;
        }
        self.finalized.push((height, bh));
        // The block is final: it anchors the fork-choice tree, and every
        // candidate branch it superseded is pruned (and signalled).
        self.note_finalized_block(&block);
        // EMISSION ONLY (calibration feed, FIXES.md §2.12 block-interval
        // series): wall-clock seconds since the previous finalization
        // progress stamp — the node's observed live-commit cadence. Read
        // BEFORE the stamp below is reset; on the process-global registry;
        // never feeds back into any finalize/apply decision.
        crate::metrics::global()
            .observe_block_interval(self.last_progress_at.elapsed().as_secs_f64());
        self.last_progress_at = std::time::Instant::now();
        self.note_finalized_header(&block).await;
        self.note_light_anchor(&block);
        // Rotate the consensus validator set from bonded stake at the height
        // boundary. Deterministic: every node derives it from the same consensus
        // ledger, so all nodes agree on the new set/power for height+1.
        // W10.5: the refresh only STAGES the change (activation height+1);
        // it becomes in-force below, exactly when this node moves to the new
        // height — never mid-flight.
        if crate::chain_spec::execution_pipeline_v1_active_at(height) {
            if let Err(e) = self.safety.advance_height(height + 1, height, bh) {
                tracing::error!(height, error = %e, "[safety] advance_height failed; quarantining");
                self.safety.quarantine(format!(
                    "advance_height({} -> {}): {e}",
                    height,
                    height + 1
                ));
            }
            self.hc = HeightConsensus::new(height + 1, self.validators.clone());
            self.install_due_validator_set();
            self.refresh_validator_set_from_staking_at(height).await;
            self.hc.validators = self.validators.clone();
        } else {
            self.refresh_validator_set_from_staking_at(height).await;
            if let Err(e) = self.safety.advance_height(height + 1, height, bh) {
                tracing::error!(height, error = %e, "[safety] advance_height failed; quarantining");
                self.safety.quarantine(format!(
                    "advance_height({} -> {}): {e}",
                    height,
                    height + 1
                ));
            }
            self.hc = HeightConsensus::new(height + 1, self.validators.clone());
            self.install_due_validator_set();
            self.hc.validators = self.validators.clone();
        }
        // The sortition committee of height+1 is elected from the PARENT
        // block hash — the block we just finalized. Every node of the network
        // must use the same parent, or they elect different committees.
        self.hc.set_parent_hash(bh);
        // CN-VRF v3: the new height produces/verifies under the epoch-beacon
        // schedule at/after activation (parent-hash draw below it), so this
        // height's own decision certificate is drawn from the same committee
        // its verifier attributes it with (review F2).
        self.install_committee_schedule();
        self.prepare_cnvrf_v3_epoch_hooks(height, bh).await;
        self.prune_runtime_history(height);
        Some(bh)
    }

    /// Advance the consensus state machine to `height + 1` immediately when
    /// `height` is decided and queued on `ApplyLane` at/above
    /// `EXECUTION_PIPELINE_V1`.
    ///
    /// Preserves all consensus invariants while `height` executes asynchronously:
    /// * `safety.advance_height(height + 1, height, bh)` moves durable safety
    ///   state to `height + 1` so the validator can sign proposals/votes for
    ///   `height + 1` without `HeightMismatch`, and
    ///   `install_apply_outcome_with_root` skips repeating `advance_height` /
    ///   `hc` reset when `hc.height > height`.
    /// * `hc` resets to `HeightConsensus::new(height + 1, ...)` with
    ///   `set_parent_hash(bh)` and `install_committee_schedule()` so sortition
    ///   for `height + 1` uses the decided parent `bh`.
    /// * `finalized` and `post_state_roots` are NOT touched here — they remain
    ///   strictly worker-certified on `try_poll_apply` ->
    ///   `install_apply_outcome_with_root`.
    fn advance_consensus_pipeline_on_decide(&mut self, height: Height, bh: BlockHash) {
        if let Err(e) = self.safety.advance_height(height + 1, height, bh) {
            tracing::error!(height, error = %e, "[safety] pipelined advance_height failed; quarantining");
            self.safety
                .quarantine(format!("advance_height({} -> {}): {e}", height, height + 1));
        }
        self.hc = HeightConsensus::new(height + 1, self.validators.clone());
        self.install_due_validator_set();
        self.hc.validators = self.validators.clone();
        self.hc.set_parent_hash(bh);
        self.install_committee_schedule();
    }

    /// Enqueue a block already decided by [`Self::prepare_decided_block`] on the
    /// sequenced worker and advance consensus immediately when pipelined.
    ///
    /// Separating decision from submission lets the node driver persist the
    /// write-ahead finalized block + pointer BEFORE `safety.advance_height`
    /// flushes sled (`W6-A2-4`).
    pub async fn submit_prepared_block(
        &mut self,
        height: Height,
        bh: BlockHash,
        block: Block,
    ) -> Option<BlockHash> {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        // R1/DET-01: only the STATIC default travels to the worker; the
        // governed reward is derived inside `apply_block_transition` from the
        // committed pre-state, identically on every path.
        let reward = self.block_reward;
        let lane = self.ensure_apply_lane();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sweep_gov_in_worker = crate::chain_spec::execution_pipeline_v1_active_at(height);
        if lane
            .tx
            .send(LaneJob::Apply(ApplyJob {
                block: block.clone(),
                reward,
                sweep_gov_in_worker,
                done: tx,
            }))
            .is_err()
        {
            return None;
        }
        if self.apply_in_flight.is_empty() {
            self.pending_exec_view.clear();
        }
        if !block.transactions.is_empty() {
            let mut to_seed: BTreeSet<[u8; 32]> = BTreeSet::new();
            for t in &block.transactions {
                if self.pending_exec_view.predicted_nonce(&t.from).is_none() {
                    to_seed.insert(t.from);
                }
                if let Some(auth) = t.sponsored_grant() {
                    if self
                        .pending_exec_view
                        .predicted_nonce(&auth.sponsor)
                        .is_none()
                    {
                        to_seed.insert(auth.sponsor);
                    }
                }
            }
            if !to_seed.is_empty() {
                let guard = self.state.accounts.read().await;
                for addr in to_seed {
                    if let Some(acct) = guard.get(&addr) {
                        self.pending_exec_view
                            .seed_account(addr, acct.nonce, acct.balance);
                    }
                }
            }
        }
        // Fold the newly decided block into the optimistic projection (FIFO:
        // it is appended behind any older queued height). The view is
        // authoritative only until the next install rebuilds it from committed
        // state.
        self.pending_exec_view.note_decided(height, &block);
        self.apply_in_flight.push_back(ApplyInflight {
            height,
            hash: bh,
            block,
            done: rx,
        });
        if crate::chain_spec::execution_pipeline_v1_active_at(height) {
            self.advance_consensus_pipeline_on_decide(height, bh);
        }
        Some(bh)
    }

    /// §7 Phase 2 sequenced submit: decide through the same
    /// [`Self::prepare_decided_block`] as [`Self::try_finalize`], then queue
    /// the execution on the single ordered worker WITHOUT awaiting it and
    /// return the decided hash immediately.
    ///
    /// Below the gate, nothing observable moves here: no `finalized` entry,
    /// no height advance, no receipts. At/above `EXECUTION_PIPELINE_V1`,
    /// [`Self::advance_consensus_pipeline_on_decide`] moves `safety` and `hc`
    /// to `height + 1` so consensus can overlap lag-2 execution while
    /// `finalized` and `post_state_roots` still advance only when
    /// [`Self::try_poll_apply`] installs the worker-certified outcome.
    /// Returns `None` when there is nothing to decide (no quorum, missing
    /// body, failed order/cap gate) or when the in-flight depth limit /
    /// committed-root gate is not satisfied.
    pub async fn try_finalize_submit(&mut self) -> Option<BlockHash> {
        if self.parallel_exec {
            self.state.set_parallel_exec(true);
        }
        let (height, bh, block) = self.prepare_decided_block().await?;
        self.submit_prepared_block(height, bh, block).await
    }

    /// Pipelined consensus step: poll any completed apply at the FIFO front
    /// (freeing queue depth and recording its certified post-state root) and
    /// submit the next decided block if consensus is ready to decide.
    pub async fn try_finalize_pipelined_step(&mut self) -> Option<BlockHash> {
        let _ = self.try_poll_apply().await;
        self.try_finalize_submit().await
    }

    /// Non-blocking collect of the sequenced apply: when the worker has
    /// reported back, install the outcome (bookkeeping + height advance) and
    /// return it; when it is still executing, leave everything untouched and
    /// return `None` so the loop keeps draining. Safe to call every tick.
    ///
    /// Collects the FIFO FRONT only: the worker applies strictly in submission
    /// order, so an earlier height must install before a later one can.
    pub async fn try_poll_apply(&mut self) -> Option<ApplyCompleted> {
        let mut inflight = self.apply_in_flight.pop_front()?;
        match inflight.done.try_recv() {
            Ok((outcome, root, penalties)) => {
                self.install_apply_outcome_with_root(
                    inflight.height,
                    inflight.hash,
                    &inflight.block,
                    &outcome,
                    root,
                    penalties,
                )
                .await;
                Some(ApplyCompleted {
                    height: inflight.height,
                    hash: inflight.hash,
                    root,
                })
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                // Still executing: put it back at the FRONT (its FIFO slot).
                self.apply_in_flight.push_front(inflight);
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
                self.apply_in_flight.push_front(inflight);
                None
            }
        }
    }

    /// Blocking collect of the sequenced apply, for tests and startup paths
    /// that have nothing else to drain while they wait. Installs the outcome
    /// exactly like [`Self::try_poll_apply`] and returns it with the
    /// certified post-apply root.
    pub async fn await_apply_completion(&mut self) -> Option<ApplyCompleted> {
        let inflight = self.apply_in_flight.pop_front()?;
        let (outcome, root, penalties) = inflight.done.await.ok()?;
        self.install_apply_outcome_with_root(
            inflight.height,
            inflight.hash,
            &inflight.block,
            &outcome,
            root,
            penalties,
        )
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
        if lane
            .tx
            .send(LaneJob::Snapshot(SnapshotJob {
                height,
                expected_root,
                done: tx,
            }))
            .is_err()
        {
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
        // NOTE: the TRANSACTION-ORDER commitment is deliberately NOT re-checked
        // here. This path replays ALREADY-DECIDED history: the block's hash
        // commits to the transaction order (the tx hashes are hashed in
        // execution order), and the decision proof below binds that hash, so
        // the order of a historical block is as committed as the rest of its
        // body. Blocks decided BEFORE the order commitment existed carry no
        // root at all, and re-deriving one here would refuse the very history
        // the node is catching up on. The order root is enforced where it
        // matters: on the LIVE paths (proposal, finalize, adopt).
        let bh = block.compute_hash();
        let Some(qc) = block.precommit_qc.clone() else {
            return Err(format!(
                "block {} carries no decision proof (predates verifiable history)",
                block.height
            ));
        };
        if qc.kind != crate::consensus::VoteKind::Precommit {
            return Err(format!(
                "block {} decision proof is not a precommit quorum",
                block.height
            ));
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
        // W10.5: verify the historical QC against the set that was in force
        // AT THIS HEIGHT, not the current one. Replay gives us the exact
        // oracle for free: the engine is already at this block's committed
        // PRE-state, and the set in force for height H is derived from the
        // staking ledger at the end of H-1 -- i.e. exactly that pre-state. So
        // derive it here instead of trusting the live `self.validators`
        // (which, after a restart, starts from the config set rather than
        // the ledger at the replay anchor). The pure sync path
        // (`validate_sync_chain_with_sets`) cannot do this -- it has no state
        // engine -- so it threads per-height sets from the caller's
        // `validator_set_for_height` history instead (see the old F5 note it
        // resolves).
        //
        // Fall back to `self.validators` when staking is empty: a network that
        // never bonded uses its config-defined set, and `to_validator_set` would
        // be empty there.
        let historical_vs = {
            let ledger = self.state.staking_read().await;
            ledger.to_validator_set()
        };
        let verify_set = if historical_vs.is_empty() {
            self.validators.clone()
        } else {
            historical_vs
        };
        if !qc.binds_to_parent(&block.prev_hash) {
            return Err(format!(
                "block {} decision proof was elected with a different parent block",
                block.height
            ));
        }
        if self.cnvrf_v3_is_active_at(block.height) {
            self.validate_cnvrf_v3_payload(block)?;
            if block.height.is_multiple_of(crate::cn_vrf::EPOCH_LEN)
                && block.height >= crate::cn_vrf::EPOCH_LEN
            {
                if let Some(vdf) = block.cnvrf_v3.as_ref().and_then(|p| p.epoch_vdf.as_ref()) {
                    self.ready_vdf_beacons
                        .entry(vdf.epoch)
                        .or_insert_with(|| vdf.clone());
                }
            }
        }
        if !self.verify_qc_for_height(&qc, &verify_set) {
            return Err(format!(
                "block {} decision proof lacks a validator quorum at its height",
                block.height
            ));
        }
        // The verified certificate is installed into `hc` to keep the
        // consensus bookkeeping in step with the replay. NOTE (W10.5): it is
        // NOT downtime evidence anymore — the transition attributes from the
        // block's embedded `last_qc` (canonical, proposer-chosen), so a
        // replayed block converges with the live-applied one even when the
        // locally observed finality QC was a different quorate subset.
        //
        // `None` evidence skips attribution HERE exactly as on the live
        // path (`apply_block_transition` skips `None`; live
        // `try_finalize`/`apply_and_advance` add nothing further). The
        // replay path MUST NOT apply a legacy slash from the attached
        // finality QC for `None` blocks: post-upgrade proposers that knew
        // no parent decision (restored/healed nodes) emit `None`, the live
        // path skips those heights, and a replay that burned them anyway
        // landed on a different post-state root for identical block bytes
        // — the same-hash fork observed live (masterchain #304133 /
        // #304395). Pinned by `tests/none_evidence_parity_tests.rs`.
        //
        // Pre-upgrade history (blocks decided by a binary that attributed
        // from the finality QC) is NOT replayable across this boundary:
        // replaying it would reproduce the old subset-dependent
        // attribution the upgrade removed. Catch those heights up with a
        // verified snapshot, never with a walk (the same rule as blocks
        // that predate verifiable QCs entirely, above).
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
        // C-02: same deterministic gov-finalization sweep as the live path,
        // so a replayed catch-up converges with live-finalized nodes.
        // At/above EXECUTION_PIPELINE_V1, `ApplyLane` already swept this inside
        // the worker BEFORE certifying `root`.
        if !crate::chain_spec::execution_pipeline_v1_active_at(block.height) {
            sweep_gov_finalize(&self.state, block.height, block.timestamp).await;
        }
        // The replayed block is canonical, finalized history: the
        // fork-choice tree follows it, so the candidates seen afterwards
        // are compared against the right chain.
        self.note_finalized_block(block);
        // The ledger now sits at THIS block's height, not at `hc.height`
        // (replay never advances `hc`): label the derivation with the real
        // height so a set change decided inside the healed range activates at
        // `block.height + 1` (already due) instead of one past the resumed
        // height. Using `hc.height` left the post-jail set staged for the
        // height AFTER the head while the network already voted it.
        self.refresh_validator_set_from_staking_checked(block.height, block.height)
            .await;
        if self.cnvrf_v3_is_active_at(block.height) {
            self.finalized_epoch_beacons = self.state.epoch_vdf_beacons_read().await.clone();
            self.cnvrf_v3_mirror = self.state.cnvrf_v3_read().await.clone();
            if block.height >= crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS {
                if let Some(boundary) = block
                    .height
                    .checked_add(crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS)
                {
                    if boundary.is_multiple_of(crate::cn_vrf::EPOCH_LEN) {
                        let target_epoch = boundary / crate::cn_vrf::EPOCH_LEN;
                        let prev_epoch = target_epoch.saturating_sub(1);
                        let freeze_mix = self.cnvrf_v3_mirror.rolling_mix_for_epoch(prev_epoch);
                        self.cnvrf_freeze_inputs
                            .insert(target_epoch, (bh, freeze_mix));
                    }
                }
            }
        }
        self.prune_runtime_history(block.height);
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
    pub(super) async fn apply_block_fees_rewards(&mut self, block: &Block) {
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
        // block as `last_qc` (canonical, proposer-chosen, in the block
        // hash) — never the attached finality `precommit_qc`, whose signer
        // subset differs per observer. `None` evidence skips attribution
        // on this path exactly as on finalize and replay.
        self.apply_block_fees_rewards(block).await;
        let height = self.hc.height;
        // C-02: height-driven gov finalization (locks release, 7200-height
        // timelocks schedule). Deterministic in (height, block.timestamp).
        // At/above EXECUTION_PIPELINE_V1, `ApplyLane` already swept this inside
        // the worker BEFORE certifying `root`.
        if !crate::chain_spec::execution_pipeline_v1_active_at(height) {
            sweep_gov_finalize(&self.state, height, block.timestamp).await;
        }
        self.finalized.push((height, bh));
        // The block is final: it anchors the fork-choice tree, and every
        // candidate branch it superseded is pruned (and signalled).
        self.note_finalized_block(block);
        self.last_progress_at = std::time::Instant::now();
        self.note_finalized_header(block).await;
        self.note_light_anchor(block);
        if crate::chain_spec::execution_pipeline_v1_active_at(height) {
            if let Err(e) = self.safety.advance_height(height + 1, height, bh) {
                tracing::error!(height, error = %e, "[safety] advance_height failed; quarantining");
                self.safety.quarantine(format!(
                    "advance_height({} -> {}): {e}",
                    height,
                    height + 1
                ));
            }
            self.hc = HeightConsensus::new(height + 1, self.validators.clone());
            // W10.5: activate any set staged for `height + 1` before staging
            // `height`'s rotation for `height + 2`.
            self.install_due_validator_set();
            self.refresh_validator_set_from_staking_at(height).await;
            self.hc.validators = self.validators.clone();
        } else {
            self.refresh_validator_set_from_staking_at(height).await;
            if let Err(e) = self.safety.advance_height(height + 1, height, bh) {
                tracing::error!(height, error = %e, "[safety] advance_height failed; quarantining");
                self.safety.quarantine(format!(
                    "advance_height({} -> {}): {e}",
                    height,
                    height + 1
                ));
            }
            self.hc = HeightConsensus::new(height + 1, self.validators.clone());
            // W10.5: activate the set staged for the new height (never mid-flight).
            self.install_due_validator_set();
            self.hc.validators = self.validators.clone();
        }
        // The sortition committee of height+1 is elected from the PARENT
        // block hash — the block we just finalized. Every node of the network
        // must use the same parent, or they elect different committees.
        self.hc.set_parent_hash(bh);
        // CN-VRF v3: the new height produces/verifies under the epoch-beacon
        // schedule at/after activation (parent-hash draw below it), so this
        // height's own decision certificate is drawn from the same committee
        // its verifier attributes it with (review F2).
        self.install_committee_schedule();
        self.prepare_cnvrf_v3_epoch_hooks(height, bh).await;
        self.prune_runtime_history(height);
    }
}

#[cfg(test)]
mod tests {
    use crate::consensus::{FalconKeypair, ValidatorSet};
    use crate::network::CrossShardTransport;
    use crate::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN};
    use crate::runtime::{ShardedCluster, ValidatorRuntime};
    use crate::sharding::{
        Block, CrossShardMessage, ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL,
        MASTERCHAIN_SHARD,
    };
    use crate::state_engine::{AccountState, BlockTransitionOutcome, InMemoryStateEngine};
    use crate::xshard2pc::{XpcActivation, XpcPhase, XPC_COMMIT, XPC_PREPARE};
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    fn sign_pq_xshard_tx(
        sender: &FalconKeypair,
        to: [u8; 32],
        amount: u64,
        gas_limit: u64,
        nonce: u64,
        source_shard: u32,
        target_shard: u32,
    ) -> Transaction {
        let probe = Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            sender.public_key.clone(),
            vec![0u8; FALCON512_SIG_LEN],
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            Vec::new(),
            &DEFAULT_SALT,
        );
        let sig = sender.sign(&probe.signing_message());
        Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            sender.public_key.clone(),
            sig,
            to,
            amount,
            gas_limit,
            nonce,
            source_shard,
            target_shard,
            Vec::new(),
            &DEFAULT_SALT,
        )
    }

    #[tokio::test]
    async fn record_apply_outcome_suppresses_failed_tx_outbound_and_keeps_xpc_outbounds() {
        let s0 = MASTERCHAIN_SHARD;
        let s1 = BASE_WORKCHAIN_SHARD_INITIAL;
        let validator = SigningKey::from_bytes(&[1u8; 32]);
        let me = validator.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(me, 1)]);
        let registry = ShardRegistry::from_ids([s0, s1]);
        let transport = CrossShardTransport::local();
        let state = Arc::new(InMemoryStateEngine::new());

        let mut rt = ValidatorRuntime::new(validator, validators, state, 1)
            .with_shard(s0, registry)
            .with_cross_shard(transport.clone());

        let sender = FalconKeypair::generate_from_seed(11);
        let recipient = [0x42u8; 32];

        let tx_fail = sign_pq_xshard_tx(&sender, recipient, 1_000, 280_000, 0, s0, s1);
        let tx_ok = sign_pq_xshard_tx(&sender, recipient, 2_000, 280_000, 1, s0, s1);
        let tx_prepare_fail = sign_pq_xshard_tx(&sender, recipient, 3_000, 280_000, 2, s0, s1);
        let tx_commit_from_record =
            sign_pq_xshard_tx(&sender, recipient, 4_000, 280_000, 3, s0, s1);

        let msg_fail =
            CrossShardMessage::new(s0, s1, tx_fail.clone(), [0xA1; 32], [0xB1; 32], None);
        let msg_ok = CrossShardMessage::new(s0, s1, tx_ok.clone(), [0xA2; 32], [0xB2; 32], None);
        let msg_prepare_fail = CrossShardMessage::new_xpc(
            XPC_PREPARE,
            s0,
            s1,
            tx_prepare_fail.clone(),
            [0xA3; 32],
            [0xB3; 32],
            None,
        );
        let msg_commit_xpc = CrossShardMessage::new_xpc(
            XPC_COMMIT,
            s0,
            s1,
            tx_commit_from_record.clone(),
            [0xA4; 32],
            [0xB4; 32],
            None,
        );

        let block = Block {
            shard_id: s0,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![tx_fail, tx_ok, tx_prepare_fail],
            cross_shard_out: vec![
                msg_fail.clone(),
                msg_ok.clone(),
                msg_prepare_fail.clone(),
                msg_commit_xpc.clone(),
            ],
            timestamp: 1_770_000_001,
            proposer: me,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            round: 0,
        };
        let outcome = BlockTransitionOutcome {
            applied: 1,
            failed: 2,
            fees_collected: 0,
            status: vec![false, true, false],
            tx_fees: vec![0, 280_000, 0],
            slashed: 0,
            events: vec![vec![], vec![], vec![]],
        };

        rt.record_apply_outcome(&block, &outcome).await;

        let inbound = transport.fetch_cross_shard_inbound(s1).await;
        let ids: Vec<[u8; 32]> = inbound.iter().map(|m| m.msg_id).collect();
        assert!(
            !ids.contains(&msg_fail.msg_id),
            "failed legacy transfer outbound must NOT be broadcast"
        );
        assert!(
            !ids.contains(&msg_prepare_fail.msg_id),
            "failed 2PC PREPARE outbound must NOT be broadcast"
        );
        assert!(
            ids.contains(&msg_ok.msg_id),
            "succeeded legacy transfer outbound must be broadcast"
        );
        assert!(
            ids.contains(&msg_commit_xpc.msg_id),
            "xpc_records-derived COMMIT outbound without block tx must still broadcast"
        );
    }

    #[tokio::test]
    async fn record_apply_outcome_preserves_2pc_replay_snapshot_parity_on_restart() {
        let s0 = MASTERCHAIN_SHARD;
        let s1 = BASE_WORKCHAIN_SHARD_INITIAL;
        let validator = SigningKey::from_bytes(&[7u8; 32]);
        let sender = FalconKeypair::generate_from_seed(12);
        let sender_addr = derive_pq_address(PqScheme::Falcon512, &sender.public_key, &DEFAULT_SALT);
        let recipient_addr = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();

        let e0 = Arc::new(InMemoryStateEngine::new());
        e0.update_account(AccountState::new(sender_addr, 5_000_000_000))
            .await;
        let e1 = Arc::new(InMemoryStateEngine::new());

        let mut cluster = ShardedCluster::new(
            ShardRegistry::from_ids([s0, s1]),
            vec![
                (s0, vec![(validator.clone(), e0)]),
                (s1, vec![(validator, e1)]),
            ],
            CrossShardTransport::local(),
        );
        cluster.with_xpc_activation(XpcActivation::FromHeight(0));

        let tx = sign_pq_xshard_tx(&sender, recipient_addr, 1_000_000_000, 280_000, 0, s0, s1);
        let tx_hash = tx.compute_tx_hash();
        cluster.broadcast_tx(tx).await;

        let ts = 1_770_000_000u64;
        // Drive full 2PC to completion across both shards.
        cluster.run_height(s0, ts).await;
        cluster.run_height(s1, ts + 1).await;
        cluster.run_height(s1, ts + 2).await;
        cluster.run_height(s0, ts + 3).await;
        cluster.run_height(s0, ts + 4).await;
        cluster.run_height(s1, ts + 5).await;

        for shard in [s0, s1] {
            let node = &cluster.shard(shard).nodes[0];
            assert_eq!(
                node.state.xpc_record(&tx_hash).await.map(|r| r.phase),
                Some(XpcPhase::Committed)
            );
            let replay = node.cross_shard_replay_snapshot().await;
            assert_eq!(
                replay.runtime_consumed, replay.engine_consumed,
                "shard {shard} runtime_consumed must match engine_consumed (no XPC key pollution)"
            );
            assert!(
                replay.completed.contains(&tx_hash),
                "shard {shard} CrossShardReplaySnapshot.completed must include completed 2PC tx"
            );

            let snap_bytes = node.state.create_snapshot().await;
            let live_root = node.state.get_state_root().await;

            let restored = InMemoryStateEngine::new();
            restored.enable_cross_shard();
            restored
                .restore_snapshot_preserve_replay_sets(&snap_bytes)
                .await
                .unwrap();
            restored.restore_cross_shard_replay(&replay).await;
            assert_eq!(
                restored.get_state_root().await,
                live_root,
                "shard {shard} restored root must match live root after 2PC"
            );
        }
    }

    #[tokio::test]
    async fn prune_runtime_history_bounds_caches_and_preserves_active_refs() {
        use crate::consensus::{QuorumCertificate, VoteKind};
        use crate::runtime::{
            ParkedCommit, RUNTIME_BLOCK_CACHE_WINDOW, RUNTIME_FINALIZED_CACHE_WINDOW,
        };

        let key = SigningKey::from_bytes(&[0x33u8; 32]);
        let id = key.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(id, 1)]);
        let state = Arc::new(InMemoryStateEngine::new());
        let committed_height = (RUNTIME_FINALIZED_CACHE_WINDOW as u64) + 500;
        let mut rt = ValidatorRuntime::new(key, validators, state, committed_height + 1);

        let make_block = |height: u64, tag: u8| {
            let mut prev = [0u8; 32];
            prev[0] = tag;
            prev[1..9].copy_from_slice(&height.to_le_bytes());
            Block {
                shard_id: MASTERCHAIN_SHARD,
                height,
                prev_hash: prev,
                timestamp: 1_700_000_000 + height,
                proposer: id,
                ..Default::default()
            }
        };

        let mut old_hashes: Vec<(u64, [u8; 32])> = Vec::new();
        for h in 1..=committed_height {
            let blk = make_block(h, 0x10);
            let bh = blk.compute_hash();
            rt.finalized.push((h, bh));
            if h <= 100 || h >= committed_height - (RUNTIME_BLOCK_CACHE_WINDOW as u64) - 50 {
                rt.blocks.insert(bh, blk);
                old_hashes.push((h, bh));
            }
        }

        // Pin three distinct old heights below the window via active runtime structures:
        // 1) apply_in_flight, 2) parked_commit, 3) post_state_roots.
        let inflight_h = 5u64;
        let inflight_bh = old_hashes
            .iter()
            .find(|(h, _)| *h == inflight_h)
            .map(|(_, bh)| *bh)
            .expect("inflight block seeded");
        assert!(rt.debug_try_enqueue_apply_inflight(inflight_h, inflight_bh));

        let parked_h = 12u64;
        let parked_blk = make_block(parked_h, 0x10);
        let parked_bh = parked_blk.compute_hash();
        assert!(rt.blocks.contains_key(&parked_bh));
        rt.parked_commit = Some(ParkedCommit {
            height: parked_h,
            block: parked_blk,
            certificate: QuorumCertificate {
                height: parked_h,
                round: 0,
                kind: VoteKind::Precommit,
                block_hash: Some(parked_bh),
                signatures: Vec::new(),
                shard_id: MASTERCHAIN_SHARD,
            },
            parked_at: (committed_height + 1, 0),
        });

        let root_pinned_h = 20u64;
        let root_pinned_bh = old_hashes
            .iter()
            .find(|(h, _)| *h == root_pinned_h)
            .map(|(_, bh)| *bh)
            .expect("root-pinned block seeded");
        rt.post_state_roots.insert(root_pinned_h, [0xAAu8; 32]);

        let unreferenced_old_h = 30u64;
        let unreferenced_old_bh = old_hashes
            .iter()
            .find(|(h, _)| *h == unreferenced_old_h)
            .map(|(_, bh)| *bh)
            .expect("unreferenced old block seeded");

        let min_keep_h = committed_height.saturating_sub(RUNTIME_BLOCK_CACHE_WINDOW as u64);
        let boundary_bh = old_hashes
            .iter()
            .find(|(h, _)| *h == min_keep_h)
            .map(|(_, bh)| *bh)
            .expect("boundary block seeded");
        let tip = rt.finalized.last().copied().expect("tip present");

        assert!(rt.blocks.len() > RUNTIME_BLOCK_CACHE_WINDOW);
        assert!(rt.finalized.len() > RUNTIME_FINALIZED_CACHE_WINDOW);

        rt.prune_runtime_history(committed_height);

        // finalized is bounded, monotonic, and keeps the tip intact.
        assert_eq!(rt.finalized.len(), RUNTIME_FINALIZED_CACHE_WINDOW);
        assert_eq!(rt.finalized.last().copied(), Some(tip));
        assert!(rt.finalized.windows(2).all(|w| w[0].0 < w[1].0));

        // Unreferenced blocks below min_keep_h are evicted, while the safety
        // window and all active references are preserved.
        assert!(!rt.blocks.contains_key(&unreferenced_old_bh));
        assert!(rt.blocks.contains_key(&boundary_bh));
        assert!(rt.blocks.contains_key(&tip.1));
        assert!(rt.blocks.contains_key(&inflight_bh));
        assert!(rt.blocks.contains_key(&parked_bh));
        assert!(rt.blocks.contains_key(&root_pinned_bh));
        // Only the recent window (min_keep_h..=committed_height) + 3 pinned old blocks remain.
        assert_eq!(rt.blocks.len(), RUNTIME_BLOCK_CACHE_WINDOW + 1 + 3);
    }
}
