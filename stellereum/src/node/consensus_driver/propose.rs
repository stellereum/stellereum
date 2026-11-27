use std::time::Duration;
use tracing::info;

use super::{
    advance_vote_floor, round_at_or_below_vote_floor, DriverConfig, DriverState, TickStep,
};
use crate::node::policy::*;
use stellereum::consensus_net::ConsensusMsg;

/// True when this node may build a proposal at `hc_height`.
///
/// A block's `prev_hash` is always our finalized tip, so proposing is only
/// meaningful at exactly `finalized_tip + 1` (height 1 at genesis). Any other
/// combination builds a block that skips heights or reuses a decided parent;
/// peers refuse it as a stale/wrong height, and the node burns rounds on a
/// proposal nobody can vote. This is the propose-side half of HEIGHT-SPLIT.
pub(super) fn proposal_parent_is_finalized(finalized_tip: u64, hc_height: u64) -> bool {
    finalized_tip.checked_add(1) == Some(hc_height)
}

/// Admit a gossiped or overlay-polled transaction into `mempool`.
///
/// Lock order (`accounts.rs:953`): reads `state` (`get_account` and
/// `sponsor_balance_of`) BEFORE acquiring `mempool.write()`, never holding the
/// pool write guard across an `accounts` read.
async fn admit_tx_from_ingress(
    state: &stellereum::state_engine::InMemoryStateEngine,
    mempool: &tokio::sync::RwLock<stellereum::mempool::Mempool>,
    is_sharded: bool,
    shard_id: u32,
    ingress_height: u64,
    tx: stellereum::sharding::Transaction,
    log_refusals: bool,
) {
    let from = tx.from;
    let nonce = tx.nonce;
    let acct = state.get_account(&from).await;
    let bal = acct.as_ref().map(|a| a.balance).unwrap_or(0);
    let onchain = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
    // PAYMASTER: pre-fetch sponsor balance BEFORE acquiring `mempool.write()`
    // (engine read before pool write guard, see `accounts.rs:953`).
    let sponsor_bal = state.sponsor_balance_of(&tx).await;
    let mut pool = mempool.write().await;
    // Same nonce-gap fail-fast as the RPC path (audit: blocks troubles):
    // gossiped far-future nonces clogged both pools behind unreachable heads.
    if let Some(gap) = pool.check_nonce_gap(&from, nonce, onchain) {
        if log_refusals {
            tracing::debug!(
                "[mempool] gossip tx gapped from {}: {gap}",
                hex::encode(&from[..6])
            );
        }
        return;
    }
    // P2 shard gate + F-02 nonce head, carried into the choke point (not just
    // pre-checked above): foreign-shard gossip can no longer squat in this
    // shard's pool. The pool-level pin is the backstop; this is the explicit
    // first line.
    let mut ctx = stellereum::mempool::AdmissionCtx::wall_now()
        .with_onchain_nonce(onchain)
        .with_chain_height(ingress_height);
    if let Some(sbal) = sponsor_bal {
        ctx = ctx.with_sponsor_balance(sbal);
    }
    if is_sharded {
        ctx = ctx.with_shard(shard_id);
    }
    if let Err(e) = pool.add_checked_ctx(tx, bal, ctx) {
        if log_refusals {
            tracing::debug!(
                "[mempool] gossip admission refused from {} nonce={}: {e}",
                hex::encode(&from[..6]),
                nonce
            );
        }
    }
}

/// Ingest gossiped & overlay mempool transactions, evaluate `can_vote`, run
/// the propose gate (1), and cast value prevote (2) or timeout nil prevote (2b).
pub(super) async fn run_mempool_and_propose_and_prevote(
    cfg: &DriverConfig,
    st: &mut DriverState,
    step: &mut TickStep,
) {
    let height = step.height;
    let round = step.round;

    // Ingest gossiped transactions into the fee-priority mempool.
    // A14 phase 3 (chain binding): ingress height + one-shot activation
    // drain.
    // GATE: `ingress_height` is finalized-tip+1 — the earliest height a
    // newly admitted tx could be included at — derived from COMMITTED
    // `rt.finalized`, never gossip-supplied. The drain runs ONCE, on the
    // first tick at/after activation (a node starting post-activation
    // with unbound txs in its restored pool drains on its first tick,
    // before the propose section below); `insert` already refuses new
    // unbound arrivals while armed, so re-draining would only rescan.
    // Default-off: `refusal_active` is always false, so this whole block
    // is a no-op and every context below behaves byte-identically.
    let binding_activation = stellereum::chain_binding::ChainBindingActivation::from_chain_spec();
    let ingress_height = st
        .rt
        .finalized
        .last()
        .map(|(h, _)| (*h).saturating_add(1))
        .unwrap_or(0);
    if !st.chain_binding_drained && binding_activation.refusal_active(ingress_height) {
        let dropped = st
            .rt
            .mempool
            .write()
            .await
            .drop_unbound_at_activation(ingress_height, &binding_activation);
        if dropped > 0 {
            tracing::warn!(
                "[binding] activation drain at height {ingress_height}: dropped {dropped} unbound tx(s) from the mempool (see docs/PLAN-BINDING.md)"
            );
        }
        st.chain_binding_drained = true;
    }
    for _ in 0..MAX_TX_RX_PER_TICK {
        let Ok(raw) = st.tx_rx.try_recv() else {
            break;
        };
        // The epoch-seal frames share the transaction-gossip channel:
        // the sealed ciphertext, the DKG contribution, the order
        // commitment and the share release.
        match stellereum::consensus_net::parse_tx_gossip_payload(&raw) {
            Some(stellereum::consensus_net::TxGossipPayload::Mev(frame)) => {
                st.rt.on_mev_frame(frame).await;
            }
            Some(stellereum::consensus_net::TxGossipPayload::Plain(tx)) => {
                admit_tx_from_ingress(
                    &st.rt.state,
                    &st.rt.mempool,
                    st.rt.shard_registry.is_sharded(),
                    st.rt.shard_id,
                    ingress_height,
                    tx,
                    true,
                )
                .await;
            }
            None => {}
        }
    }

    // 0. pull mempool txs from the infnode overlay into our mempool (throttled
    //    to `MEMPOOL_KV_POLL_INTERVAL_MS` rather than every 50ms tick).
    if st.last_mempool_kv_poll.elapsed() >= Duration::from_millis(MEMPOOL_KV_POLL_INTERVAL_MS) {
        st.last_mempool_kv_poll = std::time::Instant::now();
        for tx in cfg.adapter.fetch_mempool_transactions(cfg.shard).await {
            admit_tx_from_ingress(
                &st.rt.state,
                &st.rt.mempool,
                st.rt.shard_registry.is_sharded(),
                st.rt.shard_id,
                ingress_height,
                tx,
                false,
            )
            .await;
        }
    }

    // 1. propose if we are the proposer for this (height, round)
    //
    // Pacing guard: with a small validator set consensus completes instantly,
    // so without a floor the chain ran at ~5000 empty blocks/second and ate
    // the disk. Proposing later is always allowed (a block's validity does
    // not depend on when it was made), so this is local policy, not a
    // consensus rule — every validator still accepts whatever arrives.
    //
    // Dynamic franchise (see the longer note at the prevote gate below):
    // `is_validator` is the static config flag, but the LEDGER is
    // consensus truth — a node whose key entered the committed staking
    // set on-chain proposes and votes even as a config observer.
    // Without this, the first on-chain-added validator can never
    // participate and any quorum requiring it halts the chain.
    // STALE-LEDGER GATE (node C): a refused (stale) set must never vote,
    // even if the config flag or the foreign set names us. Fail-closed to
    // observer with an honest log instead of a silent foreign quorum.
    // `effective_can_vote` encodes exactly this (config-or-ledger minus
    // stale); the throttled line below keeps the observer state visible
    // without spamming every 100ms tick.
    let can_vote = st.rt.effective_can_vote(cfg.is_validator);
    step.can_vote = can_vote;
    if st.rt.is_validator_set_stale() {
        static STALE_VOTE_N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = STALE_VOTE_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n.is_multiple_of(300) {
            eprintln!(
                "[validator-set] WARN observer mode (stale set: {}); votes disabled until a fresh domain snapshot arrives",
                st.rt.validator_set_stale_reason().unwrap_or("unknown reason")
            );
        }
    }
    //
    // §7 Phase 2 gate (stage 1): while the execution worker is still
    // applying the decided block, our state root is PRE-H and every read
    // in this section (the eviction snapshot, the filter's account map,
    // the header's `state_root`) would build on it. The section is
    // skipped — but the gossip drains above and the message drain below
    // still run every tick, so the loop never blocks on execution.
    // (`ValidatorRuntime::propose` enforces the same gate itself; this
    // keeps even the mempool-eviction reads off the pre-H state.)
    // Dynamic franchise (see can_vote above): a ledger-member newcomer
    // proposes in its own slots too, or every third round dies empty
    // while the network waits for a proposer that will never come
    // (observed live: 1/3 dead rounds + WAN skew = no QC for an hour).
    // Liveness diagnostic (once per round): expose WHY the propose gate
    // does or does not fire. A silent proposer is indistinguishable from
    // a dead network without this; it separates gate-blocked (values
    // below) from send-blocked (gate passes but nothing arrives).
    {
        let pending = st.rt.has_pending_apply();
        match (pending, st.apply_in_flight_since) {
            (true, None) => st.apply_in_flight_since = Some(std::time::Instant::now()),
            (false, Some(started)) => {
                st.apply_in_flight_since = None;
                stellereum::metrics::global().observe_apply(started.elapsed().as_secs_f64());
            }
            _ => {}
        }
    }
    if stellereum::chain_spec::execution_pipeline_v1_active_at(st.rt.hc.height) {
        st.rt.ensure_genesis_root_seeded().await;
    }
    let decided_tip = st.rt.decided_tip_height_for_height(st.rt.hc.height);
    let can_propose_now = st.rt.can_propose_at_height(st.rt.hc.height);
    if st.last_gate_diag != Some((height, round)) {
        st.last_gate_diag = Some((height, round));
        // Enterprise KPI: one "expected" opportunity per HEIGHT+ROUND-0
        // slot this node OWNS. This is the same once-per-round guard as
        // the gate diagnostic below, so it cannot double-count a tick.
        // Counting only: it never feeds the gate decision.
        // An opportunity the node could not legally fill (not in the
        // active set, stale validator set, quarantined) is not a miss, so
        // it is not counted as expected: `can_vote` keeps the ratio honest
        // instead of dragging it down while the node is an observer.
        if round == 0 && st.rt.is_proposer() && can_vote {
            stellereum::metrics::global().inc_validator_proposal_expected();
        }
        // One increment per round we OWE a proposal and cannot emit it:
        // `nil_rounds` says the round was lost, this says why.
        if st.rt.is_proposer() && !st.rt.hc.has_live_proposal() {
            let reason = if !can_vote {
                Some("not_can_vote")
            } else if !proposal_parent_is_finalized(decided_tip, st.rt.hc.height) {
                Some("parent_not_finalized")
            } else if !can_propose_now {
                Some(if st.rt.has_pending_apply() {
                    "pending_apply"
                } else {
                    "missing_committed_root"
                })
            } else if st.last_block_at.elapsed() < cfg.min_block_time {
                Some("min_block_time")
            } else {
                None
            };
            if let Some(reason) = reason {
                stellereum::metrics::global().inc_propose_gate_blocked(reason);
            }
        }
        tracing::debug!(
            "[consensus] propose-gate h={} r={} can_vote={} can_propose={} pending_apply={} is_proposer={} live_proposal={} min_time_ok={} parent_ready={} scheduled={}",
            height,
            round,
            can_vote,
            can_propose_now,
            st.rt.has_pending_apply(),
            st.rt.is_proposer(),
            st.rt.hc.has_live_proposal(),
            st.last_block_at.elapsed() >= cfg.min_block_time,
            proposal_parent_is_finalized(decided_tip, st.rt.hc.height),
            st.rt
                .hc
                .proposer()
                .map(|p| hex::encode(&p[..6]))
                .unwrap_or_else(|| "none".into())
        );
    }
    // VEL-1 bounded proposer-prebuild: move the next build out of the
    // proposal critical path into this tick's idle window (before the
    // propose gate). `prebuild_next_proposal` is a bounded no-op unless
    // this node owns its imminent proposal (current round waiting out
    // `min_block_time`, or round 0 of the next height) and the cache
    // does not cover it yet: at most one selection run per height, local
    // only, no wire/quorum/state-transition effect. Staleness (parent
    // changed under the prebuild) is handled inside `propose` by
    // per-tx revalidation + top-up, so the worst case is one bounded
    // O(block) revalidation before a fresh-equivalent build.
    // PARENT-BOUND PROPOSAL GATE (HEIGHT-SPLIT, propose half): a block's
    // `prev_hash` is always our decided parent (`finalized` below the gate,
    // or the queued `height - 1` parent in `apply_in_flight` at/above it),
    // so the only height we may build at is `decided_tip + 1` (height 1 at
    // genesis). Proposing at any other height emits a block that either skips
    // heights or reuses a decided parent — peers refuse it as a stale/wrong
    // height and ours burns the round. This is also the backstop for a
    // restored head that could not be reconciled: fail closed (no proposal)
    // rather than fork.
    let parent_is_finalized = proposal_parent_is_finalized(decided_tip, st.rt.hc.height);
    if can_vote && can_propose_now && parent_is_finalized {
        st.rt.prebuild_next_proposal(now_secs()).await;
    }
    if can_vote
        && parent_is_finalized
        && can_propose_now
        && st.rt.is_proposer()
        && !st.rt.hc.has_live_proposal()
        && st.last_block_at.elapsed() >= cfg.min_block_time
    {
        // Drop transactions that can never execute (consumed nonce, or the
        // sender can no longer afford them). Otherwise a stale-nonce tx sits
        // in the mempool forever and blocks that account's later
        // transactions indefinitely.
        //
        // The clock is passed explicitly so the sweep can also reclaim
        // AGED FUTURE nonces (a transaction waiting behind a gap that
        // never filled — the sender controls that gap, so it is pool
        // pollution, not a pending payment; audit: nonce-stuffing
        // lockup).
        {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let payers = st.rt.mempool.read().await.fee_payers();
            let mut accounts: std::collections::HashMap<[u8; 32], (u64, u64)> =
                std::collections::HashMap::with_capacity(payers.len());
            {
                let guard = st.rt.state.accounts.read().await;
                for s in payers {
                    if let Some(a) = guard.get(&s) {
                        accounts.insert(s, (a.nonce, a.balance));
                    }
                }
            }
            let dropped = st
                .rt
                .mempool
                .write()
                .await
                .evict_unexecutable_at(now_secs, |s| {
                    // Unknown senders are skipped, never assumed broke: the
                    // snapshot may be partial or pre-height, and deleting a
                    // funded transaction here is irreversible (audit 2026-10-06).
                    accounts.get(s).copied()
                });
            if dropped > 0 {
                info!("[mempool] evicted {dropped} unexecutable transaction(s)");
            }
            // TTL sweep for stuck-gapped suffixes (audit: blocks troubles):
            // unexecutable AND old goes; executable stays whatever its age.
            // Same snapshot (no extra engine reads); wall clock is local
            // policy, never consensus.
            {
                let swept = st
                    .rt
                    .mempool
                    .write()
                    .await
                    .sweep_expired(now_secs, |s| accounts.get(s).copied());
                if swept > 0 {
                    info!("[mempool] swept {swept} stuck transaction(s) past TTL");
                }
            }
        }
        // EPOCH SEAL: keep the epoch key in step with the chain
        // (the DKG starts when the chain crosses an epoch boundary).
        // Cheap: the manager only does work when the epoch changed.
        st.rt.sync_mev_epoch().await;
        // Off-tick CN-VRF v3 VDF completion (cheap `try_recv`; the lane
        // itself runs on a blocking worker, never on this tick).
        st.rt.poll_vdf_lane();
        let phase_t = std::time::Instant::now();
        let proposed = st.rt.propose(now_secs()).await;
        stellereum::metrics::global().observe_phase("propose", phase_t.elapsed().as_secs_f64());
        if let Some(block) = proposed {
            // Enterprise KPI numerator: the normal propose gate above
            // actually emitted a proposal. (The same-tick VEL-1
            // fast-forward path further below uses the same `propose`
            // call but is deliberately not counted here; see the note
            // there. One counter, never a protocol input.)
            stellereum::metrics::global().inc_validator_proposal_produced();
            let bh = block.compute_hash();
            let ntx = block.transactions.len();
            // P3-H4: enqueue; proposals carry bodies so they flush at once.
            // COMPACT GOSSIP: announce the compact header; the announced
            // block stays servable for bounded body pulls AND for the
            // full-proposal fallback (same-height round-trip).
            // The block is stamped with `rt.hc.round` INSIDE `propose()`;
            // a view change earlier in this tick would leave the tick-local
            // `round` stale, so the envelope would name an older round and
            // every peer would refuse the frame as `stale round` while the
            // signed block was current. Always take the envelope round from
            // the block we just signed.
            st.compact_server.remember(&block, block.round);
            let msg = stellereum::consensus_net::proposal_gossip_msg(&block, block.round);
            let large = msg.is_large();
            enqueue_outbox(&mut st.outbox, msg);
            if large {
                flush_outbox(
                    &cfg.net_sender,
                    &mut st.outbox,
                    st.rt.hc.height,
                    st.rt.hc.round,
                );
                step.outbox_flushes += 1;
                st.last_flush = std::time::Instant::now();
            }
            st.last_block_at = std::time::Instant::now();
            info!(
                "[consensus] proposed block #{} r{} {} txs={}",
                height,
                round,
                hex::encode(&bh[..6]),
                ntx
            );
        }
    }

    // An observer follows and validates but never proposes or votes. It still
    // drains incoming messages and applies finalized blocks, so it stays in sync
    // and can answer RPC/SPV queries.
    //
    // Dynamic franchise: see the note at the propose gate above (`can_vote`
    // is computed once per tick there). Proposing stays equally gated: a
    // newcomer that never proposes leaves every third round empty.
    // 2. prevote once we have a proposal.
    //
    // The vote round is the PROPOSAL's SIGNED round. Under ruleset v6 a
    // lock-rescue/demanded re-proposal is RE-STAMPED at the proposer's
    // current round (`restamp_for_round`), so the signed round IS the
    // round the network is voting the value in — not the old round it was
    // first signed under. The fsynced watermark is still checked against
    // the vote's own round: a node that already voted in a later round
    // stays silent rather than voting below its floor.
    let prevote_round = st.rt.prevote_round();
    if can_vote
        && st.rt.hc.has_live_proposal()
        && st.last_prevoted != Some((height, prevote_round))
        && !round_at_or_below_vote_floor(st.vote_floor, height, prevote_round)
    {
        if let Some(v) = st.rt.make_prevote() {
            advance_vote_floor(&mut st.vote_floor, v.height, v.round);
            if let Err(e) = st.rt.on_prevote(v.clone()) {
                tracing::warn!(
                    height = v.height,
                    round = v.round,
                    error = %e,
                    "[consensus] own value prevote admission failed"
                );
            }
            // P3-H4: guards are set at ENQUEUE time, so the vote is cast
            // exactly once even though the wire flush happens later.
            enqueue_outbox(
                &mut st.outbox,
                ConsensusMsg::Vote {
                    vote: v.clone(),
                    locked: lock_hint(&st.rt, &v),
                },
            );
            flush_outbox(
                &cfg.net_sender,
                &mut st.outbox,
                st.rt.hc.height,
                st.rt.hc.round,
            );
            step.outbox_flushes += 1;
            st.last_flush = std::time::Instant::now();
            let cast_round = v.round;
            st.cast_prevote = Some(v);
            st.last_prevoted = Some((height, cast_round));
        }
    }
    // 2b. nil prevote on proposal-timeout (Tendermint liveness): a
    // validator with no proposal still speaks once per round. Without
    // this, a behind node is radio-silent: tip nodes never observe it,
    // their behind-peer trackers never stamp, and retro/catch-up help
    // never flows to it — a silent follower can never be rescued
    // (observed live: C ~200 heights behind voted for nothing while A/B
    // suppressed retro for "no behind peer"). Fires at 2x the base round
    // timeout (past even the view-change hold bound): a proposal arriving
    // before that still gets our value vote via (2) above. Nil votes
    // finalize nothing (a nil QC decides no block) and locked nodes
    // attach their lock hint, feeding the rescue path. Rate: once per
    // round via last_prevoted, shared with (2).
    //
    // PER-ROUND "WAIT FOR A PEER" (WAN liveness, live 2026-10-21): a
    // nil prevote SPENDS this node's one vote for the round, and a round
    // with a nil vote from a third of the power can never carry a polka
    // for the block the rest of the network is voting for. So a node must
    // not spend that vote while a peer is demonstrably ALIVE in this
    // round: the peer's proposal may be a second away, and the round is
    // decided by the value vote, not by our nil.
    //
    // The rule is LOCAL (it never moves our round) and it is the SAME
    // signal the view change uses (`peer_alive_recently`, below), so the
    // two agree: the node holds the round AND keeps its vote while a peer
    // is talking, and it gives up (nil vote + view change) when the peer
    // goes silent. NO 2-SUPPORTER GATE: the quorum-gated jump was tried
    // and reverted because in a 3-validator set the two nodes BEHIND
    // could never gather two supporters and never caught up - a
    // different deadlock. One live peer is enough.
    //
    // SAFETY: a nil prevote decides nothing, so withholding it can only
    // cost a nil quorum (liveness), never a fork: the value vote path (2)
    // is untouched.
    let peer_alive_in_round = matches!(
        st.peer_round_seen,
        Some((ph, pr, at))
            if ph == height
                && pr + 1 >= round
                && at.elapsed() < cfg.round_timeout
    );
    // Straggler grace on the nil wait (docs/PROPOSER_REWORK.md §2c): the
    // same bounded hold — don't nil a round whose scheduled value may
    // still be in flight. Default-off (grace 0 → zero added, the deadline
    // below is byte-identical to today).
    let nil_grace = {
        let g = straggler_grace_ms();
        if g == 0 {
            Duration::from_millis(0)
        } else {
            let seen = st.peer_round_seen.map(|(ph, pr, at)| {
                let age_ms: u64 = at.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                (ph, pr, age_ms)
            });
            Duration::from_millis(straggler_hold_ms(
                height,
                round,
                st.rt.hc.has_live_proposal(),
                seen,
                g,
                straggler_grace_cap_ms(),
                straggler_freshness_ms(cfg.round_timeout.as_millis() as u64),
            ))
        }
    };
    if can_vote
        && !st.rt.hc.has_live_proposal()
        && st.last_prevoted != Some((height, round))
        && st.round_started.elapsed() >= 2 * cfg.round_timeout + nil_grace
        && !peer_alive_in_round
        && !round_at_or_below_vote_floor(st.vote_floor, height, round)
    {
        if let Some(v) = st.rt.make_prevote() {
            debug_assert!(
                v.block_hash.is_none(),
                "no live proposal must prevote nil, never a value"
            );
            advance_vote_floor(&mut st.vote_floor, v.height, v.round);
            if let Err(e) = st.rt.on_prevote(v.clone()) {
                tracing::warn!(
                    height = v.height,
                    round = v.round,
                    error = %e,
                    "[consensus] own timeout nil prevote admission failed"
                );
            }
            enqueue_outbox(
                &mut st.outbox,
                ConsensusMsg::Vote {
                    vote: v.clone(),
                    locked: lock_hint(&st.rt, &v),
                },
            );
            st.cast_prevote = Some(v);
            st.last_prevoted = Some((height, round));
            tracing::debug!(
                "[consensus] prevoted nil at #{} r{} (no proposal after {:?})",
                height,
                round,
                2 * cfg.round_timeout
            );
        }
    }
}

/// VEL-1 same-tick proposal fast-forward after `poll_apply` completes (prebuild hit).
pub(super) async fn fast_forward_propose(
    cfg: &DriverConfig,
    st: &mut DriverState,
    step: &mut TickStep,
) {
    // SPD proposal-fast-forward (empty-block fast path): the next
    // VEL-1 proposal-fast-forward (prebuild hit): the next proposer
    // pre-broadcasts its proposal IN THE SAME TICK as finalize
    // instead of waiting for the next tick's propose gate. Saves one
    // tick (TICK_MS) per height and, for a slow 1-vCPU proposer whose
    // build + schedule would otherwise miss the round-zero proposal
    // window (650ms), keeps the proposal under the window and avoids
    // a full timeout-ladder round (~3.5s waste).
    // SAFE (liveness-only, no wire/quorum change): same gates as the
    // top-of-tick propose (can_vote, !has_pending_apply, is_proposer,
    // !has_live_proposal, min_block_time), same parent (finalized head)
    // and same post-apply state root (poll_apply completed, so
    // has_pending_apply is false), same Proposal bytes, idempotent via
    // the propose gate (`has_live_proposal` set by self-record refuses
    // a second build for the same (height, round)). Gated on the
    // prebuild cache (`has_prebuild_for`): the selection was packed
    // during the prevote idle window and `propose` revalidates it
    // against live state + tops up, so a same-tick build stays cheap
    // (O(block) revalidation + bounded top-up) instead of paying a
    // full multi-pass scan inside the finalize tick; on a cache miss
    // the height falls back to the normal next-tick path. Empty
    // blocks hit trivially (empty selection revalidates vacuously).
    // Timeouts never move safety (lock rules untouched); earlier
    // proposals only improve liveness.
    if stellereum::chain_spec::execution_pipeline_v1_active_at(st.rt.hc.height) {
        st.rt.ensure_genesis_root_seeded().await;
    }
    let decided_tip = st.rt.decided_tip_height_for_height(st.rt.hc.height);
    if step.can_vote
        && proposal_parent_is_finalized(decided_tip, st.rt.hc.height)
        && st.rt.can_propose_at_height(st.rt.hc.height)
        && st.rt.is_proposer()
        && !st.rt.hc.has_live_proposal()
        && st.last_block_at.elapsed() >= cfg.min_block_time
        && st.rt.has_prebuild_for(st.rt.hc.height)
    {
        st.rt.poll_vdf_lane();
        let phase_t = std::time::Instant::now();
        let proposed = st.rt.propose(now_secs()).await;
        stellereum::metrics::global().observe_phase("propose", phase_t.elapsed().as_secs_f64());
        if let Some(block) = proposed {
            // Validator-efficiency KPI: the fast-forward path fills a
            // slot exactly like the normal gate, so it must count as
            // produced. Leaving it out made the ratio read low for
            // every prebuild-hit height (the blind spot recorded in
            // the Wave 1 handoff).
            stellereum::metrics::global().inc_validator_proposal_produced();
            let height = st.rt.hc.height;
            let round = st.rt.hc.round;
            let bh = block.compute_hash();
            let ntx = block.transactions.len();
            st.compact_server.remember(&block, round);
            let msg = stellereum::consensus_net::proposal_gossip_msg(&block, round);
            let large = msg.is_large();
            enqueue_outbox(&mut st.outbox, msg);
            if large {
                flush_outbox(
                    &cfg.net_sender,
                    &mut st.outbox,
                    st.rt.hc.height,
                    st.rt.hc.round,
                );
                step.outbox_flushes += 1;
                st.last_flush = std::time::Instant::now();
            }
            st.last_block_at = std::time::Instant::now();
            info!(
                "[consensus][ff] fast-forward proposed block #{} r{} {} txs={} (same-tick after finalize, prebuild hit)",
                height,
                round,
                hex::encode(&bh[..6]),
                ntx
            );
        }
    }
}

#[cfg(test)]
mod wave23b_propose_tests {
    use super::*;
    use std::sync::Arc;
    use stellereum::mempool::Mempool;
    use stellereum::sharding::Transaction;
    use stellereum::state_engine::InMemoryStateEngine;

    #[tokio::test]
    async fn admit_tx_from_ingress_does_not_hold_mempool_write_across_accounts_read() {
        let state = Arc::new(InMemoryStateEngine::new());
        let mempool = Arc::new(tokio::sync::RwLock::new(Mempool::default()));
        let tx = Transaction {
            from: [0x11u8; 32],
            to: [0x22u8; 32],
            amount: 10,
            gas_limit: 280_000,
            nonce: 0,
            source_shard: 0,
            target_shard: 0,
            signature: vec![],
            payload: vec![],
            priority_fee_per_gas: 0,
        };

        // Hold `state.accounts.write()` so `get_account` / `sponsor_balance_of`
        // must wait inside `admit_tx_from_ingress`.
        let acct_write = state.accounts.write().await;
        let state_bg = Arc::clone(&state);
        let mempool_bg = Arc::clone(&mempool);
        let handle = tokio::spawn(async move {
            admit_tx_from_ingress(&state_bg, &mempool_bg, false, 0, 1, tx, false).await;
        });

        tokio::task::yield_now().await;

        // `mempool.write()` must remain immediately acquirable while the
        // spawned task is blocked on `state.accounts` (proving lock order
        // `accounts` before `mempool.write()` with no nested hold).
        let pool_guard = tokio::time::timeout(Duration::from_millis(500), mempool.write())
            .await
            .expect("mempool.write() must not be held while awaiting state.accounts");
        drop(pool_guard);
        drop(acct_write);

        handle.await.expect("ingress task must finish cleanly");
    }

    #[test]
    fn tx_rx_cap_leaves_excess_for_next_tick() {
        assert_eq!(MAX_TX_RX_PER_TICK, 256);
        assert_eq!(MEMPOOL_KV_POLL_INTERVAL_MS, 2_000);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
        for i in 0..(MAX_TX_RX_PER_TICK + 17) {
            tx.send(i).unwrap();
        }
        let mut drained = 0usize;
        for _ in 0..MAX_TX_RX_PER_TICK {
            let Ok(_item) = rx.try_recv() else {
                break;
            };
            drained += 1;
        }
        assert_eq!(drained, MAX_TX_RX_PER_TICK);
        let mut remaining = 0usize;
        while rx.try_recv().is_ok() {
            remaining += 1;
        }
        assert_eq!(remaining, 17);
    }
}
