use std::time::{Duration, Instant};
use tracing::info;

use super::{
    adopt, advance_vote_floor, catchup, governance_equal, process_cpu_seconds, propose,
    round_at_or_below_vote_floor, should_publish_body_now, should_publish_header_now,
    write_ahead_finalized_block, DriverConfig, DriverState, TickStep,
};
use crate::node::policy::*;
use crate::node::sync::*;
use stellereum::consensus_net::ConsensusMsg;
use stellereum::runtime::ValidatorRuntime;

/// Main consensus tick loop.
pub(super) async fn run_tick_loop(cfg: &DriverConfig, st: &mut DriverState) {
    loop {
        st.tick_no += 1;
        // P0-READINESS-DEAD: /readyz and stell_ready had no producer at all, so
        // a load balancer would have dropped a healthy node. Peer count is
        // cheap (mesh length) and refreshed periodically, not every tick.
        if st.tick_no.is_multiple_of(20) {
            stellereum::explorer::set_readiness_peers(cfg.adapter.validator_mesh().len());
        }
        // Per-peer compact-work budgets are per TICK (C2/F-8/H1): a peer can
        // force at most a bounded number of index lookups/pull replies each
        // tick, no matter how many envelopes its bucket admits.
        st.compact_peer_frames.clear();
        st.compact_peer_pulls.clear();
        st.compact_index_builds_tick = 0;

        // Height-scoped vote sightings reset (down-proposer fast timeout): a
        // new height means a new proposer schedule, so last height's
        // sightings must not leak into this height's "no vote observed" test.
        if st.rt.hc.height != st.votes_seen_height {
            st.votes_seen_height = st.rt.hc.height;
            st.votes_seen_voters.clear();
        }
        // Reactive evidence latched by the previous tick's drain: a VERIFIED
        // Committed/Proposal/Vote named a height above ours, or a peer head
        // pointer did. Consumed here so the attempt runs on THIS tick — never
        // waiting out the backstop interval.
        let reactive_catchup_due = std::mem::take(&mut st.catchup_pending);
        let mut step = TickStep {
            tick_t0: Instant::now(),
            height: st.rt.hc.height,
            round: st.rt.hc.round,
            reactive_catchup_due,
            net_budget: Duration::from_millis(0),
            catchup_ran: false,
            retro_ran: false,
            probe_ran: false,
            join_ran: false,
            outbox_flushes: 0,
            catchup_ms: 0,
            retro_ms: 0,
            probe_ms: 0,
            join_ms: 0,
            can_vote: false,
        };

        if catchup::run_catchup_step(cfg, st, &mut step).await {
            st.split_ticks += 1;
            st.split_tick_ms += step.tick_t0.elapsed().as_millis() as u64;
            continue;
        }

        catchup::run_retro_publish_step(cfg, st, &mut step).await;

        step_periodic_maintenance(cfg, st, &mut step).await;

        propose::run_mempool_and_propose_and_prevote(cfg, st, &mut step).await;

        adopt::drain_inbound_messages(cfg, st, &mut step).await;

        check_liveness_alarm(cfg, st, step.can_vote);

        catchup::update_catchup_latch(st);

        step_precommit(cfg, st, &mut step).await;

        if step_finalize_and_apply(cfg, st, &mut step).await {
            continue;
        }

        step_view_change(cfg, st, &mut step).await;

        step_deadlock_breaker(st);

        step_retransmit_and_flush(cfg, st, &mut step);

        // NO governance write-back here. It was copying a clone of the shared
        // governance object back into the SAME lock it was cloned from, which
        // (a) did nothing useful -- RPC mutations already land in that lock --
        // and (b) worse, `governance_write` bumps the commitment generation, so
        // every tick forced `get_state_root` to recompute the FULL commitment
        // (clone every domain + SHA-256 + trie insert). That was the dominant
        // CPU cost on the single-core stand (both nodes together at ~83% CPU
        // on an otherwise idle chain) and made every proposal pay it too. It
        // could also clobber a newer RPC mutation with a stale clone.

        // Name the slow tick instead of guessing: report how long the tick
        // took and which network blocks fired inside it. Rounds looked ~10x
        // slower than ROUND_TIMEOUT for hours because the tick -- not the
        // timer -- was the clock, and nothing logged it.
        let tick_dt = step.tick_t0.elapsed();
        if tick_dt >= Duration::from_millis(400) {
            tracing::info!(
                "[perf] tick h={} r={} took {:?} (catchup={} retro={} probe={} join={} flushes={} catchup_ms={} retro_ms={} probe_ms={} join_ms={})",
                st.rt.hc.height,
                st.rt.hc.round,
                tick_dt,
                step.catchup_ran,
                step.retro_ran,
                step.probe_ran,
                step.join_ran,
                step.outbox_flushes,
                step.catchup_ms,
                step.retro_ms,
                step.probe_ms,
                step.join_ms,
            );
        }
        // Windowed tick-split report (see the HOW TO READ note where the
        // counters are declared): one line per 300 ticks (~30s at TICK_MS),
        // never per tick. Resets after each report so every line describes
        // exactly its own window.
        st.split_ticks += 1;
        st.split_tick_ms += tick_dt.as_millis() as u64;
        if st.split_ticks >= 300 {
            tracing::info!(
                "[perf][tick-split] ticks={} tick_avg_ms={} catchup_avg_ms={} (n={}) retro_avg_ms={} (n={}) probe_avg_ms={} (n={}) join_avg_ms={} (n={})",
                st.split_ticks,
                st.split_tick_ms / st.split_ticks.max(1),
                st.split_catchup_ms / st.split_ticks.max(1),
                st.split_catchup_n,
                st.split_retro_ms / st.split_ticks.max(1),
                st.split_retro_n,
                st.split_probe_ms / st.split_ticks.max(1),
                st.split_probe_n,
                st.split_join_ms / st.split_ticks.max(1),
                st.split_join_n,
            );
            st.split_ticks = 0;
            st.split_tick_ms = 0;
            st.split_catchup_ms = 0;
            st.split_retro_ms = 0;
            st.split_probe_ms = 0;
            st.split_join_ms = 0;
            st.split_catchup_n = 0;
            st.split_retro_n = 0;
            st.split_probe_n = 0;
            st.split_join_n = 0;
        }
        tokio::time::sleep(Duration::from_millis(cfg.tick_ms)).await;
    }
}

/// Sync governance, periodic join/probe/mempool-save, and workchain validator-set repair.
async fn step_periodic_maintenance(cfg: &DriverConfig, st: &mut DriverState, step: &mut TickStep) {
    // Sync the shared staking ledger + governance into the runtime before
    // each iteration, so RPC-driven changes (bonds, votes, proposals) take
    // effect. The staking ledger is NOT copied here: it lives in the state
    // engine and is shared by reference, so a bond applied in a block is
    // visible to consensus without a node-local mirror.
    {
        let gov_guard = cfg.shared_gov.read().await;
        let changed = st
            .rt
            .governance
            .as_ref()
            .is_none_or(|cur| !governance_equal(&gov_guard, cur));
        if changed {
            st.rt.governance = Some(gov_guard.clone());
        }
    }

    // Re-register as a network subscriber periodically (until peers connect).
    // Re-subscription is idempotent plumbing for the case where peers
    // connected after we subscribed; it does not need to run every 5s.
    // Two join calls capped at 2s each made this a 4s tax on every tick
    // once peers answered slowly, and [perf] showed ticks of 8-11s with
    // join=true. Once connected it is pure overhead, so check rarely.
    //
    // Join backoff (local policy only): a join dial is a full request_to
    // round trip (handshake timeout ~1.7s to a dead endpoint), so dialing
    // a cooldown-skipped peer on every window re-creates the storm the
    // cooldown exists to suppress. Each dial below is gated by
    // `join_should_dial` over that network's `has_nonskipped_peers()`
    // (section-level equivalent: all-cooldown => skip the dial entirely,
    // join_ms stays 0). A returning peer re-announces via DHT/probe,
    // whose success clears its cooldown entry, so the next window
    // re-dials automatically. Never consensus, never wire.
    if st.last_join.elapsed() > Duration::from_secs(60) {
        let net_dial = stellereum::consensus_net::join_should_dial(!cfg.net.has_nonskipped_peers());
        let gossip_dial =
            stellereum::consensus_net::join_should_dial(!cfg.gossip.has_nonskipped_peers());
        if net_dial || gossip_dial {
            step.join_ran = true;
            let n_join = cfg.net.clone();
            let g_join = cfg.gossip.clone();
            tokio::spawn(async move {
                if net_dial {
                    let _ = tokio::time::timeout(Duration::from_secs(2), n_join.join()).await;
                }
                if gossip_dial {
                    let _ = tokio::time::timeout(Duration::from_secs(2), g_join.join()).await;
                }
            });
            st.last_join = std::time::Instant::now();
            st.split_join_n += 1;
        } else {
            tracing::debug!(
                "[net] join skipped (all peers in failure cooldown, no dial on either network)"
            );
            st.last_join = std::time::Instant::now();
        }
    }
    // Liveness probe (visible outcome per peer) runs non-blocking off the tick.
    if st.last_probe.elapsed() > Duration::from_secs(30) {
        step.probe_ran = true;
        let n_probe = cfg.net.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(2), n_probe.probe_peers()).await;
        });
        // F8: `net_peerCount` follows the live peer table. One read per
        // probe window, off the tick — the RPC then serves the observed
        // count (honest `0x0` when nothing was seen), never a constant.
        let a_peers = cfg.adapter.clone();
        tokio::spawn(async move {
            let _ = a_peers.publish_live_peer_count().await;
        });
        if let Some((fh, fhash)) = st.rt.finalized.last().copied() {
            let a = cfg.adapter.clone();
            let shard_id = cfg.block_shard;
            cfg.publish_lane.submit(async move {
                a.publish_head(shard_id, fh, fhash).await;
            });
        }
        st.last_probe = std::time::Instant::now();
        st.split_probe_n += 1;
    }
    // Persist the mempool periodically (crash-safe pending transactions):
    // the pool is memory-only, so without this every restart silently
    // drops users' valid transactions (observed live: funded-but-never-
    // visible drips across every restart). Loaded back at startup above.
    // Every 15s bounds the loss window below the watchdog's stall
    // threshold, so a stall-restart cycle cannot eat a fresh blast.
    //
    // §7 Phase 1: fire-and-forget. The blocking bincode + fs::write (and
    // the read lock it used to hold across both) now run on the blocking
    // pool; this call only claims the single-flight guard, so an overdue
    // save can never overlap a still-running one.
    if st.last_mempool_save.elapsed() > Duration::from_secs(15) {
        let _ = schedule_mempool_save(&st.rt.mempool, &cfg.mempool_path, &cfg.mempool_save_guard);
        st.last_mempool_save = std::time::Instant::now();
    }

    // Periodic workchain validator-set repair (R3 CODE-TAILS sweep, see
    // the method docs): re-read the masterchain registry and stage/install
    // whatever is due, even when this shard has not finalized for a while.
    // Interval-gated (30s) and internally workchain-gated; a no-op for
    // the masterchain and single-shard nodes. Bounded: one shared-ledger
    // read plus a compare per interval, silent unless the set changes.
    if st.last_workchain_set_repair.elapsed() > Duration::from_secs(30) {
        st.last_workchain_set_repair = std::time::Instant::now();
        if st.rt.refresh_workchain_set_from_master().await {
            info!(
                "[shard {}] workchain validator set converged from the masterchain registry (periodic repair)",
                cfg.block_shard
            );
        }
        // Consensus-copy resync (post-restart wedge repair): a refresh can
        // move the runtime's in-force set without moving heights (restore
        // from a lagging domains snapshot, then a live-ledger refresh),
        // stranding the consensus copy on the older set. The node then
        // computes a different proposer schedule from converged peers and
        // the wedge never heals (no height advances to rebuild the copy).
        // The runtime set is agreed with peers (same live-ledger
        // derivation everywhere); aligning the copy completes the
        // transition instead of reverting one.
        if st.rt.resync_consensus_set_to_runtime() {
            info!(
                "[shard {}] consensus validator set resynced to the runtime in-force set (periodic repair)",
                cfg.block_shard
            );
        }
    }
}

/// FAIL-LOUD LIVENESS ALARM (audit note: a production validator sat isolated
/// 18 days on the wrong pubsub topic — zero votes/proposals, nothing in any log).
fn check_liveness_alarm(cfg: &DriverConfig, st: &mut DriverState, can_vote: bool) {
    // A validator with configured peers that consumes no Proposal/Vote for
    // the silence threshold screams on stderr (throttled to one line per
    // minute) instead of churning silently. Liveness-only: reads
    // clocks/counters, never touches consensus, the wire, or quorum
    // accounting. `can_vote` is the exact franchise the propose/prevote
    // gates above used — reused, not reinvented — so observers and
    // stale-set nodes stay silent by construction, as do solo stands (no
    // configured peers).
    let peer_count = cfg.adapter.node.cfg.peers.len();
    let now_ms = stellereum::liveness_alarm::now_ms();
    if stellereum::liveness_alarm::should_liveness_alarm(
        st.last_consensus_rx_ms,
        now_ms,
        can_vote,
        peer_count,
        stellereum::liveness_alarm::liveness_alarm_silence_ms(),
    ) && stellereum::liveness_alarm::liveness_alarm_due(st.last_liveness_emit_ms, now_ms)
    {
        st.last_liveness_emit_ms = Some(now_ms);
        stellereum::liveness_alarm::note_liveness_alarm();
        let n = stellereum::liveness_alarm::liveness_alarm_count();
        let silent_s = now_ms.saturating_sub(st.last_consensus_rx_ms) / 1000;
        eprintln!(
            "[liveness] ALARM #{n}: validator with {peer_count} configured peer(s) received no consensus Proposal/Vote for {silent_s}s; possible pubsub-topic isolation (e.g. wrong single-shard vs sharded topic) — check network/topic config"
        );
    }
}

/// 4. precommit once a prevote quorum exists.
async fn step_precommit(cfg: &DriverConfig, st: &mut DriverState, step: &mut TickStep) {
    let height = step.height;

    // The vote is stamped with the POLKA's round (which may be behind our
    // local round when the two nodes are skewed), so the dedup key is
    // (height, v.round): casting per LOCAL round either skipped the cast
    // entirely when the QC sat one round back (the "prevote QC but no
    // precommit" case that cost 31 of 180 rounds live) or duplicated it.
    if step.can_vote {
        if let Some(v) = st.rt.make_precommit() {
            // FLOOR: a precommit is stamped with the POLKA's round, which
            // may be older than the local round — and after a crash the
            // node must not re-enter a round it already PRECOMMITTED in.
            // Compare the PRECOMMIT floor, not the prevote/union floor:
            // a late polka's round can be below a nil prevote this node
            // already signed, and precommitting it is a different
            // (height, round, kind) statement. See `precommit_floor`.
            if st.last_precommitted != Some((height, v.round))
                && !round_at_or_below_vote_floor(st.precommit_floor, height, v.round)
            {
                advance_vote_floor(&mut st.vote_floor, v.height, v.round);
                advance_vote_floor(&mut st.precommit_floor, v.height, v.round);
                if let Err(e) = st.rt.on_precommit(v.clone()) {
                    tracing::warn!(
                        height = v.height,
                        round = v.round,
                        error = %e,
                        "[consensus] own precommit admission failed"
                    );
                }
                // P3-H4: guards are set at ENQUEUE time (same reason as prevotes).
                enqueue_outbox(
                    &mut st.outbox,
                    ConsensusMsg::Vote {
                        vote: v.clone(),
                        locked: None,
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
                st.cast_precommit = Some(v.clone());
                st.last_precommitted = Some((height, v.round));
                // Persist the lock so a restart cannot double-vote this height.
                if let (Some(ap), Some((lh, lr))) = (&cfg.persistence, st.rt.hc.locked) {
                    // Persist the locked BODY as well. A lock without its
                    // body is unusable after a restart: `same_value` needs
                    // the body's round-free identity to recognise the
                    // re-stamp, and `propose` needs the body to re-serve
                    // it. The lock is set before the height is finalized,
                    // so the normal finalized-block persistence has not
                    // covered it yet (RESTART-SPLIT).
                    if let Some(body) = st.rt.blocks.get(&lh).cloned() {
                        ap.enqueue_block(body);
                    }
                    let (fh, fhash) = st.rt.finalized.last().copied().unwrap_or((0, [0u8; 32]));
                    ap.enqueue_consensus(stellereum::storage::ConsensusCheckpoint {
                        height,
                        round: step.round,
                        locked_hash: Some(lh),
                        locked_round: lr,
                        finalized_height: fh,
                        finalized_hash: fhash,
                    });
                }
            }
        }
    }
}

/// 5. finalize on a precommit quorum — §7 Phase 2 sequenced lane.
///
/// Returns `true` when `try_poll_apply` completed a block and the tick loop
/// should `continue` immediately (preserving the exact skip of view-change,
/// deadlock-breaker, retransmit, split_ticks, and sleep).
async fn step_finalize_and_apply(
    cfg: &DriverConfig,
    st: &mut DriverState,
    step: &mut TickStep,
) -> bool {
    let height = step.height;
    let round = step.round;

    // `try_finalize_submit` DECIDES (quorum + body + order + actor-cap
    // gates, QC attach, decision-proof stash) and queues the execution on
    // the single ordered worker WITHOUT awaiting it, so this loop keeps
    // draining inbound messages while the block applies. `try_poll_apply`
    // below installs the outcome the moment the worker reports back —
    // that is the only place post-H state becomes observable — and runs
    // the publishes, records and persistence that used to follow the
    // inline apply. `propose` for the next height, the proposal root
    // check and the commit broadcast all wait for it (stage-1 gate,
    // `apply_in_flight` checks in the runtime).
    if st.rt.parallel_exec {
        st.rt.state.set_parallel_exec(true);
    }
    let phase_t = std::time::Instant::now();
    let decided_out = if let Some((decided_height, decided_bh, decided_block)) =
        st.rt.prepare_decided_block().await
    {
        // P0-SAFETY-BOOT-ONE-BLOCK / W6-A2-4: write-ahead the QC-carrying
        // decided block and finalized tip pointer BEFORE `submit_prepared_block`
        // -> `safety.advance_height` fsyncs `safety_record_v1` (at/above
        // `EXECUTION_PIPELINE_V1`) or `try_poll_apply` -> `safety.advance_height`
        // fsyncs it (below the gate). Sled's `db.flush()` inside `advance_height`
        // then makes both durable together, closing the hard-SIGKILL 1-block gap
        // on the live finalize path.
        if let Some(ap) = &cfg.persistence {
            if let Err(e) = write_ahead_finalized_block(
                ap,
                decided_height,
                decided_bh,
                decided_block.clone(),
                false,
            )
            .await
            {
                tracing::error!(
                    height = decided_height,
                    error = %e,
                    "[storage] write-ahead put_block/set_finalized failed before safety advance"
                );
                eprintln!(
                    "[storage] write-ahead put_block/set_finalized failed at #{decided_height}: {e}"
                );
            }
        }
        st.rt
            .submit_prepared_block(decided_height, decided_bh, decided_block)
            .await
    } else {
        None
    };
    stellereum::metrics::global().observe_phase("finalize_submit", phase_t.elapsed().as_secs_f64());
    if let Some(decided) = decided_out {
        let decided_height = st
            .rt
            .last_decision
            .as_ref()
            .filter(|(_, b, _)| b.compute_hash() == decided)
            .map(|(dh, _, _)| *dh)
            .unwrap_or(st.rt.hc.height);
        info!(
            "[consensus] DECIDED block #{} {} (execution queued on the sequenced worker)",
            decided_height,
            hex::encode(&decided[..6]),
        );
        // EARLY `_hq_` QC SIDECAR (liveness, incident #21508): the QC is
        // already in hand (`prepare_decided_block` stashed it), so publish it
        // NOW — before the body persist / apply completion path — instead
        // of waiting for the header publish that rides after the apply.
        //
        // ORDERING INVARIANT (kept explicitly): the sidecar is never the
        // only blob present for a height. The job publishes the
        // header/index (and v2 record) FIRST via `persist_block_header`,
        // then the QC, matching the "header first, then QC: a crash
        // between writes yields missing-QC -> skip, never a half-trusted
        // header" contract. `claim_hq_publish` makes the later
        // header-completion publish a no-op duplicate.
        //
        // Amplification guard: only nodes that already publish this
        // height's header (proposer / small set / 8-boundary) take this
        // path; on other nodes a lone QC write would violate the ordering
        // invariant, and their sidecar rides the header publish as before.
        if let Some((dh, block, qc)) = st.rt.last_decision.clone() {
            let is_proposer = block.proposer == cfg.self_vote_id;
            let publish_header =
                should_publish_header_now(st.rt.validators.len(), is_proposer, decided_height);
            if dh == decided_height && block.compute_hash() == decided && publish_header {
                let a = cfg.adapter.clone();
                let shard_id = cfg.block_shard;
                let decided_for_job = decided;
                cfg.publish_lane.submit(async move {
                    a.persist_block_header(shard_id, &block).await;
                    a.publish_block_qc(shard_id, dh, decided_for_job, &qc).await;
                });
            }
        }
        // At/above EXECUTION_PIPELINE_V1, `submit_prepared_block` advances `hc`
        // to `decided_height + 1` immediately on decide; reset per-height vote
        // caches, cast votes, checkpoint, and round timers here so `decided_height + 1`
        // starts clean.
        if stellereum::chain_spec::execution_pipeline_v1_active_at(decided_height)
            && st.rt.hc.height > decided_height
        {
            st.last_prevoted = None;
            st.last_precommitted = None;
            st.cast_prevote = None;
            st.cast_precommit = None;
            if let Some(ap) = &cfg.persistence {
                ap.enqueue_consensus(stellereum::storage::ConsensusCheckpoint {
                    height: decided_height + 1,
                    round: 0,
                    locked_hash: None,
                    locked_round: 0,
                    finalized_height: decided_height,
                    finalized_hash: decided,
                });
            }
            let elapsed_round = st.round_started.elapsed();
            st.round_started = std::time::Instant::now();
            st.last_block_at = std::time::Instant::now()
                .checked_sub(elapsed_round.min(cfg.min_block_time))
                .unwrap_or_else(std::time::Instant::now);
        }
    }
    let mut any_polled = false;
    let max_polls = if stellereum::chain_spec::execution_pipeline_v1_active_at(step.height) {
        stellereum::runtime::MAX_APPLY_IN_FLIGHT_DEPTH
    } else {
        1
    };
    for _ in 0..max_polls {
        let phase_t = std::time::Instant::now();
        let polled = st.rt.try_poll_apply().await;
        stellereum::metrics::global().observe_phase("poll_apply", phase_t.elapsed().as_secs_f64());
        let Some(completed) = polled else {
            break;
        };
        any_polled = true;
        if let Some(now_cpu) = process_cpu_seconds() {
            if let Some(prev_cpu) = st.cpu_at_last_block {
                if now_cpu >= prev_cpu {
                    stellereum::metrics::global().observe_cpu_per_block(now_cpu - prev_cpu);
                }
            }
            st.cpu_at_last_block = Some(now_cpu);
        }
        // PARK-AND-REPLAY HOOK (liveness, incident #21508): this is the
        // exact point where the sequenced apply worker's completion is
        // observed (`apply_in_flight` just transitioned Some -> None and
        // `install_apply_outcome` installed H). Anything that arrived
        // during the execute window was parked, not dropped; replay it
        // through the normal validating entry points. The replay is placed
        // at the END of this block (just before the same-tick fast-forward
        // propose) on purpose: a replayed H+1 commit enters the ordinary
        // drain (which adopts it with ALL side effects), and the
        // completed-height publish/record/persist work above must still
        // see ITS height (`last_decision`, `applied_statuses`, the durable
        // finalized pointer). `take_parked` clears both one-slot buffers,
        // so replay is at-most-once and cannot grow the runtime.
        // The executed height: the tick-top `height` cannot have moved
        // past it (the height advance happens right here), but naming it
        // keeps every line below honest about what it publishes.
        let height = completed.height;
        // P0-READINESS-DEAD: a block was just installed, so the gateway can
        // honestly report readiness (finality freshness + height).
        stellereum::explorer::note_readiness_finalized(height);
        let bh = completed.hash;
        let root = completed.root;
        {
            let pq_reg = st.rt.state.pq_registry_read().await;
            let active = stellereum::pq_registry::pq_lifecycle_active_at(height);
            if active || !pq_reg.is_empty() {
                stellereum::consensus::sync_committed_pq_registry(&pq_reg, active);
            }
        }
        // Governed fee floor (audit follow-up): admission floor =
        // max(frozen, governed), refreshed every finalized height so a passed
        // SetMinGasLimit takes effect network-wide without restarts.
        // Frozen floor stays the boot default; governance can only raise.
        {
            let gov_floor = st
                .rt
                .state
                .governance_read()
                .await
                .applied
                .min_gas_limit
                .unwrap_or(0);
            let env_floor = stellereum::mempool::Mempool::frozen_base_fee_floor();
            let want = env_floor.max(gov_floor);
            let mut mp = cfg.rpc.mempool.write().await;
            if mp.base_fee != want {
                info!(
                    "[config] admission base_fee floor {0} -> {want} (frozen={env_floor} governed={gov_floor})",
                    mp.base_fee
                );
                mp.base_fee = want;
            }
        }
        info!(
            "[consensus] FINALIZED block #{} {} (state root {})",
            height,
            hex::encode(&bh[..6]),
            hex::encode(&root[..6])
        );
        // Local finalization proves live chain progress just as much as
        // `adopt_committed`: refreshing `last_live_adopt` prevents
        // synchronous `try_catch_up` DHT probes from stalling active rounds.
        st.last_live_adopt = std::time::Instant::now();
        // Republish the head pointer on every finalize, so a peer that is
        // behind can discover where we are. The local KV head is useless to
        // peers (see P2pNetworkAdapter::publish_head), this is the one they
        // can read.
        //
        // §7 Phase 1: these three used to be awaited `request_to`/DHT round
        // trips ON the tick (hundreds of ms each, and `store_blob` can wait
        // for a replica). They are submitted to `publish_lane` instead,
        // which runs them one at a time in submission order -- head, then
        // body, then header, exactly the order awaiting gave them.
        // Publish the fresh body and header immediately for the block's
        // proposer (and on small sets / boundary heights), avoiding a
        // cluster-wide dht.store storm on every single height while keeping
        // every height's head/body/header available immediately.
        if let Some(block) = st.rt.blocks.get(&bh).cloned() {
            let is_proposer = block.proposer == cfg.self_vote_id;
            let validator_count = st.rt.validators.len();
            let publish_body = should_publish_body_now(validator_count, is_proposer, height);
            // NEVER suppress this store just because the early decision-time
            // job already published the same header. `persist_block_header`
            // returns `()` and the early job runs on `publish_lane`, where
            // `paced_store_blob_in_lane` can SHED/DROP under backpressure or
            // a lane cooldown; if that write was shed, suppression would
            // mean this node NEVER re-stores the header/index for the height
            // (catch-up readers then see "body present, header missing").
            // The store is idempotent and content-addressed, so publishing
            // twice is safe; publishing zero times is not. Header before QC
            // ordering is preserved in both jobs.
            let publish_header = should_publish_header_now(validator_count, is_proposer, height);
            if publish_body {
                let a = cfg.adapter.clone();
                let shard_id = cfg.block_shard;
                cfg.publish_lane.submit(async move {
                    a.publish_head(shard_id, height, bh).await;
                });
            }
            let h = block.height;
            if publish_body || publish_header {
                let a = cfg.adapter.clone();
                let shard_id = cfg.block_shard;
                cfg.publish_lane.submit(async move {
                    if publish_body {
                        let _ = a.retro_publish_blocks([&block], 1).await;
                    }
                    if publish_header {
                        // Publish the HEADER at every height too (by the
                        // proposer, and reinforced on 8-height boundaries).
                        // The snapshot anchor (F1) walks headers from our
                        // finalized head to the snapshot's successor.
                        a.persist_block_header(shard_id, &block).await;
                    }
                });
            }
            // Retention prune rides its OWN lane (audit 2026-10-06, own lane
            // since the live-adopt tempo fix): on publish_lane it queued
            // behind replica-waiting store_blob jobs (seconds each), and on
            // record_lane its fetch_blob fan-out held every receipt behind
            // it — so one slow peer starved either lane with no
            // throttle-vs-starve distinction. prune_lane carries only this
            // pass; the pass itself is throttled (100 heights) and capped
            // inside maybe_prune_retained, and the guard keeps passes from
            // piling up.
            if let Some(reset_guard) =
                AtomicFlagResetGuard::try_acquire(std::sync::Arc::clone(&cfg.prune_lane_guard))
            {
                let a = cfg.adapter.clone();
                let shard_id = cfg.block_shard;
                cfg.prune_lane.submit(async move {
                    let _reset_guard = reset_guard;
                    a.maybe_prune_retained(shard_id, h).await;
                });
            }
        } else {
            let a = cfg.adapter.clone();
            let shard_id = cfg.block_shard;
            cfg.publish_lane.submit(async move {
                a.publish_head(shard_id, height, bh).await;
            });
        }
        // Tell peers what we committed. A node that missed the deciding
        // vote would otherwise never learn the outcome and would stall
        // behind us at this height forever. Reads the stashed decision
        // proof (`try_finalize` resets `hc`, so the proof must be read
        // from the stash, never from `hc.precommit_qc` afterwards).
        //
        // IMPORTANT (W10.5): NEVER clear `rt.last_decision` here — `propose()`
        // (`decided_parent_qc(&prev_hash)`) and `check_last_qc_evidence()` depend on
        // `last_decision` holding `(height, block, qc)` for height + 1; clearing
        // it caused the next proposer to emit `last_qc: None` and trigger
        // `omits the downtime evidence` view-change stalls.
        if let Some((dh, block, certificate)) = st.rt.last_decision.clone() {
            if dh == height {
                // PUSH-BASED PROPAGATION (Task 1): the commit goes to
                // EVERY directly connected validator peer NOW, on its own
                // detached task — not through the batched outbox FIFO,
                // where it could queue behind votes/proposals behind a
                // slow peer, and not via the DHT, where a lagging peer
                // would only see it on its next poll. `ConsensusNetwork`
                // delivers `pubsub.msg` per peer concurrently and logs
                // every outcome; the DHT publication below (head pointer,
                // body, header) is unchanged and remains the slow path.
                spawn_committed_push(&cfg.net, height, block, certificate);
            } else if stellereum::chain_spec::execution_pipeline_v1_active_at(height) {
                if let Some(block) = st.rt.blocks.get(&bh).cloned() {
                    if let Some(certificate) = block.precommit_qc.clone() {
                        spawn_committed_push(&cfg.net, height, block, certificate);
                    }
                }
            }
        }
        // Publish the finalized block to the RPC/explorer height + feed, and
        // file a receipt per transaction so wallets can confirm.
        //
        // §7 Phase 1: submitted to `record_lane`, a FIFO lane of its own.
        // Both records are LOCAL (a lock and a vec push -- no `request_to`;
        // the round trips on this path are the publishes above), but they
        // still leave the tick, and the lane's FIFO is what preserves the
        // ordering RPC readers depend on: receipts for height H are filed
        // before `record_block(H)` publishes H, and the whole batch for H
        // runs before the batch for H+1, so the moment a reader sees
        // height H+1 every earlier receipt is already in the index.
        let block_ts = now_secs();
        if let Some(block) = st.rt.blocks.get(&bh).cloned() {
            let tx_count = block.transactions.len();
            // Use the statuses captured when the block was ACTUALLY applied;
            // re-applying here would execute every transaction a second time.
            let statuses = std::mem::take(&mut st.rt.applied_statuses);
            let fees = std::mem::take(&mut st.rt.applied_fees);
            let events = std::mem::take(&mut st.rt.applied_events);
            let r = cfg.rpc.clone();
            let persist_store = cfg.persistence.as_ref().map(|ap| ap.storage());
            let is_mc = cfg.block_shard == stellereum::sharding::MASTERCHAIN_SHARD;
            let block_shard = cfg.block_shard;
            cfg.record_lane.submit(async move {
                // LIGHT CLIENT (audit W8.3): publish the finalized header
                // with its quorum certificate, so an external verifier can
                // check a served proof against a root a QUORUM committed
                // to.
                r.record_finalized_header(&block).await;
                r.record_receipts_with_events(
                    height,
                    bh,
                    &block.transactions,
                    &statuses,
                    &fees,
                    &events,
                )
                .await;
                r.record_block(height, bh, tx_count, block_ts).await;
                // GEYSER-LITE DELTAS (Zero Consensus Blocking): publish the
                // accounts this block actually changed and the token
                // transfers it included. Both `record_receipts_with_events`
                // and `record_block` have released their write locks above,
                // and this fan-out is a non-blocking broadcast — a stalled
                // subscriber cannot delay the record lane (or consensus).
                stellereum::rpc::publish_block_deltas(
                    height,
                    bh,
                    block_shard,
                    &block.transactions,
                    &statuses,
                );
                if let Some(store) = persist_store {
                    let _ = store.put_finalized_post_root(height, root);
                    if is_mc {
                        let exec_hardening =
                            stellereum::chain_spec::exec_hardening_v1_active_at(height);
                        for (i, tx) in block.transactions.iter().enumerate() {
                            if !statuses.get(i).copied().unwrap_or(false) {
                                continue;
                            }
                            if let Some((evm, pq)) =
                                stellereum::evm_adapter::verified_binding_from_tx_at(
                                    tx,
                                    exec_hardening,
                                )
                            {
                                let _ = store.put_evm_binding_if_absent(&evm, &pq);
                            }
                        }
                        if store
                            .evm_bindings_cursor()
                            .ok()
                            .flatten()
                            .map(|c| height > c)
                            .unwrap_or(true)
                        {
                            let _ = store.set_evm_bindings_cursor(height);
                        }
                    }
                }
            });
        } else {
            let r = cfg.rpc.clone();
            let persist_store = cfg.persistence.as_ref().map(|ap| ap.storage());
            cfg.record_lane.submit(async move {
                r.record_block(height, bh, 0, block_ts).await;
                if let Some(store) = persist_store {
                    let _ = store.put_finalized_post_root(height, root);
                }
            });
        }
        // Write-ahead at `try_finalize_submit` already wrote the QC-carrying
        // block and finalized pointer before `safety.advance_height` flushed
        // sled. Verify and repair synchronously if write-ahead missed/failed,
        // instead of enqueueing an async `Finalized` job that could race
        // backwards with a later height.
        if let Some(ap) = &cfg.persistence {
            let already_persisted = ap.storage().finalized().ok().flatten() == Some((height, bh))
                && ap.storage().get_block(&bh).ok().flatten().is_some();
            if !already_persisted {
                if let Some(block) = st.rt.blocks.get(&bh).cloned() {
                    if let Err(e) = write_ahead_finalized_block(ap, height, bh, block, true).await {
                        tracing::error!(
                            height,
                            error = %e,
                            "[storage] post-apply finalized persist fallback failed"
                        );
                    }
                } else {
                    let store = ap.storage();
                    let _ = tokio::task::spawn_blocking(move || {
                        store.set_finalized(height, &bh).and_then(|_| store.flush())
                    })
                    .await;
                }
            }
            // Periodic durability barrier (async, no consensus stall):
            // bounds the loss window on kill for queued consensus checkpoints.
            if height % 25 == 0 {
                ap.enqueue_validator_set_history(st.rt.export_validator_set_history());
                ap.request_flush();
            }
            // Clear the lock for the next height in the checkpoint, only when
            // `hc` is still at `height + 1` without a newer live lock.
            if st.rt.hc.height == height + 1 && st.rt.hc.locked.is_none() {
                ap.enqueue_consensus(stellereum::storage::ConsensusCheckpoint {
                    height: height + 1,
                    round: 0,
                    locked_hash: None,
                    locked_round: 0,
                    finalized_height: height,
                    finalized_hash: bh,
                });
            }
            // Check if an on-chain governed software upgrade is scheduled for this height.
            let upgrade_plan = st
                .rt
                .state
                .governance_read()
                .await
                .applied
                .upgrade_plan
                .clone();
            if let Some(plan) = upgrade_plan {
                // MISSED-EVENT SAFETY: `==` made the halt an EVENT — a node
                // that was offline at the plan height, or that restarted
                // past it, never fired and kept running the pre-upgrade
                // rules while reporting healthy (the silent straggler,
                // `docs/UPGRADE_AND_RECOVERY.md` §1.2.3). The predicate is
                // `height >= plan.height`: the first block this node
                // finalizes at/after the halt height halts it, and a late
                // fire is LOUD because it means the node ran past the
                // coordinated halt height.
                if plan.height <= height {
                    if plan.height < height {
                        tracing::warn!(
                            "[upgrade] LATE halt at height {}: plan '{}' was scheduled at \
                             height {} and this node finalized past it (offline at the halt, \
                             or restarted after it). Halting now instead of continuing on the \
                             pre-upgrade rules.",
                            height,
                            plan.name,
                            plan.height
                        );
                    }
                    info!(
                        "[upgrade] UPGRADE TRIGGERED at height {}: plan name='{}', target sha256={}",
                        height,
                        plan.name,
                        hex::encode(plan.sha256)
                    );
                    if let Some(ap) = &cfg.persistence {
                        ap.request_flush();
                        ap.snapshot_state(&st.rt.state, height).await;
                        let ledger = st.rt.staking_read().await.clone();
                        let gov = match &st.rt.governance {
                            Some(g) => g.clone(),
                            None => st.rt.state.governance_read().await.clone(),
                        };
                        ap.snapshot_domains(&st.rt.state, &ledger, &gov, height)
                            .await;
                    }

                    // DRAIN BEFORE EXIT (docs/UPGRADE_AND_RECOVERY.md
                    // §1.2.4): `request_flush` + the snapshot calls only
                    // ENQUEUE jobs, and `std::process::exit(42)` skips the
                    // SIGTERM drain, so the writer could still be holding
                    // the final blocks/snapshots when the process dies.
                    // Await the same bounded helper the SIGTERM path uses
                    // (240 s cap + 10 s settle) — BOUNDED, so a dead disk
                    // delays the halt but can never hang it.
                    if let Some(ap) = &cfg.persistence {
                        let outcome = crate::node::bootstrap::upgrade_halt::drain_for_halt(
                            || ap.pending(),
                            stellereum::storage::ShutdownDrainConfig::default(),
                        )
                        .await;
                        if outcome.drained {
                            info!(
                                "[upgrade] persistence drained (queue empty) before the \
                                 upgrade halt at height {height}"
                            );
                        } else {
                            tracing::error!(
                                "[upgrade] halt drain CAP reached with {} persist job(s) still \
                                 queued (wedged writer or dead disk); halting anyway — the \
                                 drain is bounded and the loss window is the pre-upgrade queue",
                                outcome.last_pending
                            );
                        }
                    }

                    // DURABLE HALT MARKER (closes the missed-event hole):
                    // a node that is offline at the halt height (or that
                    // restarts past it) never runs the finalize lane at
                    // `plan.height`, so the halt itself must be a
                    // PREDICATE on disk, not only an event. Written after
                    // the drain (so it is never the only thing that
                    // survived a torn flush) and BEFORE any `execve`, so
                    // the NEW image's startup guard can validate and clear
                    // it. `target_version` is the plan's name: the upgraded
                    // binary proves it by matching the plan sha256 or by
                    // declaring STELL_UPGRADE_VERSION=<plan name>.
                    {
                        let marker_path = crate::node::bootstrap::upgrade_halt::marker_path();
                        let marker = crate::node::bootstrap::upgrade_halt::UpgradeHaltMarker {
                            height: plan.height,
                            halted_at_height: height,
                            plan_name: plan.name.clone(),
                            plan_sha256: plan.sha256,
                            target_version: plan.name.clone(),
                            running_version: crate::node::bootstrap::upgrade_halt::running_version(
                            ),
                            halted_unix: now_secs(),
                        };
                        let marker_written = crate::node::bootstrap::upgrade_halt::write_marker(
                            &marker_path,
                            &marker,
                        );
                        if let Err(e) = marker_written {
                            tracing::error!(
                                "[upgrade] FAILED to write the halt marker {:?}: {e} — the \
                                 node still halts, but a restart cannot prove it is halted; \
                                 the finalize-lane predicate fires again on the next height",
                                marker_path
                            );
                        } else {
                            info!(
                                "[upgrade] halt marker written to {:?} (plan '{}' at height \
                                 {}, target version '{}'): a restarted node refuses to join \
                                 consensus until the upgraded binary is running",
                                marker_path, marker.plan_name, marker.height, marker.target_version
                            );
                        }
                    }

                    // LIVE MIGRATION ARMING (audit W8.3 / production
                    // blocker A8): the live `execve` of a new binary is
                    // DISARMED unless the operator explicitly set
                    // `STELL_AUTO_UPGRADE=1` on THIS node. The old
                    // default was "armed unless told otherwise", which
                    // turned a quorum decision about the chain's RULES
                    // into a decision to replace the running binary on
                    // the operator's box. Unarmed, the node still halts
                    // at the upgrade height with exit code 42
                    // (Cosmovisor-compatible) and the supervisor restarts
                    // it — the graceful path is unchanged, only the
                    // in-place `execve` is now opt-in.
                    let auto_upgrade = stellereum::governance::auto_upgrade_armed();

                    // PATH SAFETY (audit W6.7): the plan's name is used to
                    // build the candidate path, so it must be a SAFE single
                    // path segment. A name carrying a separator (or a
                    // `..`) would resolve OUTSIDE `data/upgrades/` — a
                    // governance proposal could then point the upgrade at
                    // an arbitrary path on the box. `upgrade_candidate_paths`
                    // returns an EMPTY list for such a name, so the exec
                    // is skipped and the node exits 42 as usual.
                    let upgrade_candidates = stellereum::governance::upgrade_candidate_paths(&plan);

                    if auto_upgrade {
                        if upgrade_candidates.is_empty() {
                            tracing::error!(
                                "[upgrade] REFUSING upgrade plan '{}': the name is not a safe path segment",
                                plan.name
                            );
                        }
                        for cand in &upgrade_candidates {
                            if !cand.exists() {
                                continue;
                            }
                            // TOCTOU CLOSED (audit W6.7): the bytes that
                            // were HASHED are staged into a private
                            // directory, and THAT copy is executed. The
                            // old path read+hash'd the file and then
                            // exec'd it BY PATH, so the file could be
                            // swapped between the check and the exec.
                            // The staging also refuses a SYMLINKED
                            // candidate (and no longer chmod-s the
                            // candidate, which used to chmod the TARGET
                            // of a planted symlink).
                            match stellereum::governance::stage_verified_upgrade_binary(
                                cand,
                                &plan.sha256,
                            ) {
                                Ok(staged) => {
                                    info!(
                                        "[upgrade] found verified new binary at {:?} (sha256 matches) — executing live zero-downtime swap!",
                                        cand
                                    );
                                    use std::os::unix::process::CommandExt;
                                    // `args_os` (not `args`): `args` PANICS
                                    // on a non-UTF-8 argv element, which
                                    // would kill the node instead of
                                    // exec'ing the new binary.
                                    let err = std::process::Command::new(&staged)
                                        .args(std::env::args_os().skip(1))
                                        .exec();
                                    eprintln!("[upgrade] live exec failed: {err}");
                                }
                                Err(e) => {
                                    tracing::error!("[upgrade] candidate {:?} refused: {e}", cand);
                                }
                            }
                        }
                    }

                    info!(
                        "[upgrade] halting node gracefully at height {} for upgrade plan '{}'. Exit code 42.",
                        height, plan.name
                    );
                    std::process::exit(42);
                }
            }
            // Snapshot state every 100 heights (bounded disk growth).
            //
            // SYNC TRAP N5 (R3 CODE-TAILS sweep, P2P snapshot publication
            // gap): captures ride the FINALIZE path, so a shard that
            // stops finalizing publishes nothing new — a node that falls
            // behind the last published snapshot + the pruned
            // header/body windows has no in-band recovery (the wedge-side
            // half of the gap; the publish-side half — shed Bulk stores
            // holding the pointer fail-closed — is already handled in
            // `P2pNetworkAdapter::persist_state_snapshot`). There is no
            // code fix that publishes what was never finalized; the
            // repair is operational (restore finalization first) plus N3:
            // keep at least one GOOD snapshot per 100-height boundary
            // reachable (forever TTL) so catchers never depend on the
            // freshest one. If `try_snapshot_sync` probes every boundary
            // down the window and finds no state blob, the shard stopped
            // publishing — check finalization, not the fetcher.
            // CAPTURE rides the sequenced apply lane (see `SnapBundle` in
            // runtime.rs): the worker clones between two applies, so the
            // bytes can never mix heights — unlike the old tick-side
            // cloning, where the worker could slip an apply between the
            // separate clone calls (chain-down incident: every snapshot
            // in the window torn, both nodes refusing to restart). The
            // worker ALSO verifies the engine still roots at the
            // worker-certified post-`height` root before cloning, so a
            // mislabeled capture is impossible no matter the queue order;
            // a skipped capture simply snapshots a later height (labels
            // stay exact — `last_snapshot_height` advances only when a
            // bundle ARRIVES, never on submit).
            // Snapshots land on exact multiples of `snap_int` (plus the
            // 100-grid catch-up multiples), and `try_snapshot_sync` now
            // walks interval-spaced boundaries derived from the same
            // cadence, so probes find them without guessing offsets
            // (audit F4).
            let snap_int = snapshot_interval();
            // Adaptive cadence (`stellereum::snapshot_cadence`): the
            // candidate rule below is byte-identical to the old trigger;
            // the gate additionally skips a candidate that provably
            // brought no state change (certified post-`height` root equals
            // the previous height's root — asserted on real roots, never
            // assumed from tx count) unless the interval floor is due
            // (gap beyond one full `snap_int`, so the worst-case restore
            // distance never exceeds today's). On an active chain
            // `state_changed` is always true and this submits exactly as
            // before.
            let state_changed = st.prev_finalized_root != Some(root);
            let candidate = stellereum::snapshot_cadence::snapshot_candidate(
                height,
                st.last_snapshot_height,
                snap_int,
            );
            if !st.rt.has_pending_apply()
                && stellereum::snapshot_cadence::should_submit_snapshot(
                    height,
                    st.last_snapshot_height,
                    snap_int,
                    state_changed,
                )
            {
                // Submit-time cross-shard binding: the worker bundle holds
                // accounts/domains/aux at post-`height` (root-gated), but
                // the replay set is captured HERE, on the tick, at the
                // same quiescent instant (this height just installed, the
                // next apply is not submitted yet, so the worker is idle
                // and nothing mutates the engine under the clone).
                // Capturing at POLL time instead read a replay set
                // advanced by later heights and persisted it under this
                // height's label: the restored engine then rooted
                // differently from `header(height+1)` and the next boot
                // died in `verify_restored_root` (restore root mismatch
                // crash-loop). The bytes travel with the submit
                // (single-flight) and are never re-read at poll.
                // A failed OR EMPTY cross-shard replay encode must never
                // be published beside a snapshot (audit 2.6): the paired
                // restore would then reject the whole snapshot loudly, but
                // the height would burn and a good snapshot could be
                // pruned. Treat empty as failure and SKIP this capture;
                // the cadence retries at a later height.
                let xshard = match bincode::serialize(&st.rt.cross_shard_replay_snapshot().await) {
                    Ok(bytes) if !bytes.is_empty() => Some(bytes),
                    Ok(_) => {
                        tracing::error!(
                            "[snapshot] height {height}: cross-shard replay encode \
                             produced EMPTY bytes — SKIPPING this capture (an empty replay \
                             set must never be published; restore would fail closed)"
                        );
                        None
                    }
                    Err(e) => {
                        tracing::error!(
                            "[snapshot] height {height}: cross-shard replay encode FAILED: \
                             {e} — SKIPPING this capture (publishing an empty replay set \
                             would fail every restore)"
                        );
                        None
                    }
                };
                if let Some(xshard) = xshard {
                    if st.rt.submit_snapshot(height, root) {
                        st.pending_snapshot_xshard = Some((height, xshard));
                        info!(
                            "[snapshot] submitted capture for height {height} \
                             (last_snapshot_height={})",
                            st.last_snapshot_height
                        );
                    } else {
                        // By design at most one capture is in flight (a
                        // refused submit snapshots a later height instead)
                        // — but a refusal on EVERY height means the worker
                        // never answers, so it stays LOUD, never silent.
                        tracing::warn!(
                            "[snapshot] submit REFUSED for height {height} \
                             (a capture is still in flight; \
                             last_snapshot_height={})",
                            st.last_snapshot_height
                        );
                    }
                }
            } else if candidate {
                // Adaptive cadence skip: a candidate that provably brought
                // no state change (certified root equals the previous
                // height's) while the interval floor is not due. Stays
                // LOUD (never silent): every skip names the height, the
                // last snapshot, and the unchanged root.
                info!(
                    "[snapshot] SKIPPED idle capture for height {height} \
                     (last_snapshot_height={} \
                     root={} snap_int={snap_int})",
                    st.last_snapshot_height,
                    hex::encode(&root[..6])
                );
            }
            // Advance the idleness clock: the NEXT height compares against
            // this height's certified root.
            st.prev_finalized_root = Some(root);
            // Collect a ready capture (non-blocking): serialize + enqueue
            // + publish exactly like before, sourced from the bundle.
            // Cross-shard runtime mirrors + tip header are captured here
            // (tick): they are transport-driven and deliberately
            // uncommitted, so their raciness cannot move the root.
            if let Some(bundle) = st.rt.poll_snapshot() {
                info!(
                    "[snapshot] capture ready for height {} \
                     (accounts={}, last_snapshot_height={})",
                    bundle.height,
                    bundle.accounts.accounts.len(),
                    st.last_snapshot_height,
                );
                st.last_snapshot_height = bundle.height;
                // Submit-time bytes (see above): never a fresh read — a
                // fresh read here is post-`bundle.height` state under an
                // older label. A missing/mismatched stash is impossible
                // (single-flight: the submit stashes before its poll
                // reads); fall fail-closed (empty bytes fail the restore
                // loudly) rather than substituting newer state.
                let cross_shard = match st.pending_snapshot_xshard.take() {
                    Some((h, bytes)) if h == bundle.height => bytes,
                    Some((h, _)) => {
                        tracing::error!(
                            "[snapshot] height {}: cross-shard stash mismatch (stashed for {h}); persisting empty so the restore fails closed instead of mixing heights",
                            bundle.height,
                        );
                        Vec::new()
                    }
                    None => {
                        tracing::error!(
                            "[snapshot] height {}: no submit-time cross-shard stash (submit/poll desync?); persisting empty so the restore fails closed instead of mixing heights",
                            bundle.height,
                        );
                        Vec::new()
                    }
                };
                let tip_header = st
                    .rt
                    .finalized
                    .iter()
                    .rev()
                    .find(|(h, _)| *h == bundle.height)
                    .and_then(|(_, hash)| st.rt.blocks.get(hash).cloned())
                    .or_else(|| {
                        ap.storage()
                            .hashes_at_height(bundle.height)
                            .ok()
                            .and_then(|hashes| hashes.into_iter().next())
                            .and_then(|hash| ap.storage().get_block(&hash).ok().flatten())
                    });
                let ap2 = ap.clone();
                let adapter2 = cfg.adapter.clone();
                let shard_id = cfg.block_shard;
                let lane = cfg.backfill_lane.clone();
                tokio::spawn(async move {
                    let stellereum::runtime::SnapBundle {
                        height,
                        accounts,
                        domains,
                        session_keys,
                        bridge,
                        zkml_models,
                        cnvrf_v3,
                        evm_bindings,
                        pq_registry,
                    } = bundle;
                    // Serialize on the blocking pool. Bytes are identical to
                    // the old inline `create_snapshot`/`bincode::serialize`
                    // (same cloned values, same order) -- pinned by
                    // tests/tick_offload_tests.rs.
                    let bytes = stellereum::storage::serialize_off_tick(accounts)
                        .await
                        .unwrap_or_default();
                    if bytes.is_empty() {
                        // bincode of even an empty account vec is 8 bytes
                        // (the length prefix), so empty here means the
                        // blocking encode FAILED — loud, not a silent
                        // empty publish (fetchers would reject it loudly
                        // at the root check, but the height still burns).
                        tracing::error!(
                            "[snapshot] height {height}: account serialize \
                             FAILED (publishing empty bytes; see [snapshot-publish] \
                             outcome below)"
                        );
                    }
                    ap2.enqueue_state(height, bytes.clone());
                    info!(
                        "[snapshot] height {height}: local persist enqueued \
                         (state {} bytes); handing to backfill_lane",
                        bytes.len()
                    );
                    // A9: persist every non-account domain too.
                    if let Some(domain_bytes) =
                        stellereum::storage::serialize_off_tick(domains).await
                    {
                        ap2.enqueue_cnvrf_v3(height, cnvrf_v3.clone());
                        ap2.enqueue_evm_bindings_state(height, evm_bindings.clone());
                        ap2.enqueue_pq_registry(height, pq_registry.clone());
                        ap2.enqueue_domains(
                            height,
                            domain_bytes.clone(),
                            session_keys.clone(),
                            bridge.clone(),
                            zkml_models.clone(),
                            cross_shard.clone(),
                        );
                        // Publish the SAME domain blobs beside the state
                        // snapshot (audit follow-up F-J): without them a
                        // far-behind node restores accounts only and fails
                        // the trusted-root check on any live chain. One job
                        // per the shared kind list
                        // (`network::SNAPSHOT_PUBLISH_DOMAIN_KINDS`), so the
                        // publish set cannot drift from what
                        // `sync::SYNC_DOMAIN_KINDS` fetches without failing
                        // the parity test in
                        // tests/observer_and_recovery_tests.rs.
                        // Separate adapter clone: the state publish below
                        // moves its own.
                        let adapter3 = adapter2.clone();
                        // Every blob beside the state snapshot carries the
                        // effectively-non-expiring TTL (see
                        // `persist_domain_snapshot`): snapshots must stay
                        // FOREVER (one per 100 heights), because a node
                        // thousands of blocks behind anchors on a recent
                        // one long after every body/header window elapsed.
                        let pq_keys = ap2.storage().export_pq_keys_blob().unwrap_or_default();
                        let by_kind: Vec<(&'static str, Vec<u8>)> = vec![
                            ("domains", domain_bytes.clone()),
                            ("session", session_keys.clone()),
                            ("bridge", bridge.clone()),
                            ("zkml", zkml_models.clone()),
                            ("cross_shard", cross_shard.clone()),
                            ("cnvrf_v3", cnvrf_v3.clone()),
                            ("pq_keys", pq_keys),
                            ("evm_bindings", evm_bindings.clone()),
                            ("pq_registry", pq_registry.clone()),
                        ];
                        debug_assert!(
                            {
                                let mut got: Vec<&str> = by_kind.iter().map(|(k, _)| *k).collect();
                                got.sort_unstable();
                                let mut want: Vec<&str> =
                                    stellereum::network::SNAPSHOT_PUBLISH_DOMAIN_KINDS.to_vec();
                                want.sort_unstable();
                                got == want
                            },
                            "snapshot domain publish set drifted from SNAPSHOT_PUBLISH_DOMAIN_KINDS"
                        );
                        if !lane.submit(async move {
                            for (kind, data) in &by_kind {
                                if !adapter3
                                    .persist_domain_snapshot(shard_id, height, kind, data)
                                    .await
                                {
                                    // The persist fn already logged LOUDLY;
                                    // this caller-side line ties the
                                    // failure to the snapshot height.
                                    tracing::error!(
                                        "[snapshot] height {height}: domain \
                                         blob kind={kind} did NOT land \
                                         (fetchers will miss it; pointer \
                                         unaffected — domains carry no pointer)"
                                    );
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                            }
                        }) {
                            // `TickLane::submit` is false only when the
                            // lane task is gone: every later publish on
                            // this lane dies the same way, so this is a
                            // node-restart-class alarm, not a retryable miss.
                            tracing::error!(
                                "[snapshot] height {height}: domain \
                                 backfill_lane submit FAILED (lane dead? \
                                 domain blobs unpublished)"
                            );
                        }
                    } else {
                        // The state snapshot below still publishes, but a
                        // far-behind node restoring accounts-only fails
                        // the trusted-root check on any live chain — one
                        // LOUD line per occurrence (1 per 100 heights max).
                        tracing::error!(
                            "[snapshot] height {height}: domain serialize \
                             FAILED (no local domain persist, no domain \
                             publish; state snapshot still publishes)"
                        );
                    }
                    if !lane.submit(async move {
                        // Publish the SAME snapshots to the network. This is what makes
                        // catching up independent of how far back the block-retro-publish
                        // window reaches: a node thousands of blocks behind can take the
                        // state at this height and the block headers above it, instead of
                        // walking every body from genesis. The snapshot is verified
                        // against the trusted state root before it is applied
                        // (`sync::fast_sync_state`), so a poisoned snapshot is rejected
                        // rather than committed.
                        if !adapter2
                            .persist_state_snapshot(shard_id, height, &bytes)
                            .await
                        {
                            // The persist fn already logged LOUDLY (and
                            // held the pointer fail-closed); this
                            // caller-side line ties it to the height.
                            tracing::error!(
                                "[snapshot] height {height}: state snapshot \
                                 did NOT land (pointer held; catchers will \
                                 keep probing older boundaries)"
                            );
                        }
                        // The HEADER at the same height. A cold node uses the snapshot
                        // to skip execution but still has to chain headers from the
                        // snapshot up to the head to be convinced it is on the right
                        // chain, and headers carry the statthat binding.
                        if let Some(b) = tip_header {
                            adapter2.persist_block_header(shard_id, &b).await;
                        }
                    }) {
                        // `TickLane::submit` is false only when the lane
                        // task is gone: every later publish on this lane
                        // dies the same way — node-restart-class alarm.
                        tracing::error!(
                            "[snapshot] height {height}: state \
                             backfill_lane submit FAILED (lane dead? \
                             snapshot + header unpublished)"
                        );
                    }
                });
            }
            // Retention has its OWN cadence guard (audit follow-up): it
            // used to ride inside the snapshot block, so a continuously
            // busy apply worker starved sled pruning together with
            // snapshots — bodies/receipts growing unbounded. Prune is
            // safe on a busy chain (height-keyed deletes below the
            // retention window), only the snapshot capture needs
            // quiescence.
            if !cfg.retention.archive && height >= st.last_prune_height + 100 {
                st.last_prune_height = height;
                {
                    let keep_from = height.saturating_sub(cfg.retention.keep_blocks);
                    ap.enqueue_prune(keep_from);
                    // Older state/domain snapshots only help a reorg, and
                    // `load_state_into` reads only the newest, so a small
                    // ring is plenty.
                    //
                    // §7 Phase 1: these two were synchronous sled scans
                    // INLINE in the consensus loop. Same functions, same
                    // arguments, same ignored errors -- only the thread
                    // moves (blocking pool), with a single-flight guard so
                    // a slow pass can never be joined by a second one.
                    let keep_states = height.saturating_sub(snap_int * 3);
                    let store = ap.storage();
                    spawn_guarded_blocking(&cfg.prune_guard, move || {
                        let _ = store.prune_state_below(keep_states);
                        let _ = store.prune_domains_below(keep_states);
                    });
                }
            }
        }
    }
    if any_polled {
        if st.last_prevoted.is_some_and(|(vh, _)| vh < st.rt.hc.height) {
            st.last_prevoted = None;
        }
        if st
            .last_precommitted
            .is_some_and(|(vh, _)| vh < st.rt.hc.height)
        {
            st.last_precommitted = None;
        }
        if st
            .cast_prevote
            .as_ref()
            .is_some_and(|v| v.height < st.rt.hc.height)
        {
            st.cast_prevote = None;
        }
        if st
            .cast_precommit
            .as_ref()
            .is_some_and(|v| v.height < st.rt.hc.height)
        {
            st.cast_precommit = None;
        }
        if !stellereum::chain_spec::execution_pipeline_v1_active_at(step.height) {
            let elapsed_round = st.round_started.elapsed();
            st.round_started = std::time::Instant::now();
            st.last_block_at = std::time::Instant::now()
                .checked_sub(elapsed_round.min(cfg.min_block_time))
                .unwrap_or_else(std::time::Instant::now);
        }
        // PARK-AND-REPLAY (see the note at `try_poll_apply` above). Runs
        // after this height's publish/record/persist work so the commit
        // re-injection cannot rewrite the H bookkeeping, and before the
        // same-tick fast-forward so a replayed H+1 proposal is live here.
        // A parked commit enters the ordinary drain on the next tick.
        adopt::replay_parked_apply_window(
            &mut st.rt,
            &mut st.loopback_queue,
            &mut st.loopback_dropped,
        )
        .await;
        propose::fast_forward_propose(cfg, st, step).await;
        return true;
    } else if !st.rt.has_pending_apply() && st.last_blockers_log != Some((height, round)) {
        // try_finalize found nothing. Say WHY (throttled: once per round)
        // instead of failing silently: precommit activity without finality
        // is exactly the stuck shape, and the reason (missing prevote QC
        // with per-side presence, lock refusal, missing body) tells which
        // layer to fix. Quiet when nobody precommits at all (healthy wait).
        if let Some(msg) = st.rt.hc.finalize_blockers() {
            tracing::warn!("[consensus] FINALIZE-BLOCKED {msg}");
            st.last_blockers_log = Some((height, round));
        }
    }

    false
}

/// 6. view change on timeout (liveness).
async fn step_view_change(cfg: &DriverConfig, st: &mut DriverState, step: &mut TickStep) {
    // Hold the view change while a peer is demonstrably active within one round of
    // us. Without this, two nodes time out in lockstep, stay one round apart, and
    // with an even validator count sit in opposite proposer phases forever. The
    // hold is bounded by the same timeout, so a silent peer still lets us advance.
    // Hold ONLY if we are the AHEAD one. A node that is BEHIND must be free to
    // time out and advance toward its peer -- holding it too was a bug: a node
    // resuming on round 8 (from its checkpoint) faced a peer on round 0, the peer
    // held its own view change waiting for us, and neither ever moved.
    //
    // So: wait only when the peer is at or behind us but still active (it is about
    // to propose or vote where we are), which is exactly when leaving would abandon
    // a live round. If the peer is clearly ahead, advancing is the right move.
    // The hold window is deliberately TWICE the round timeout. With a window equal
    // to the timeout, two nodes leapfrog: each times out just as the peer's last
    // vote ages out, so the hold never engages and the pair advances in lockstep
    // one round apart forever. A 2x window means a live peer's votes always hold
    // us; a truly dead peer releases us after two timeouts, which only costs one
    // extra round of waiting.
    // STRICTLY ahead only (`pr < our round`). At equal rounds both nodes
    // held each other: neither timer ran, a proposal that never arrived
    // (one transport timeout) was never re-made, and the pair sat frozen
    // until the watchdog restarted it -- observed live as a 180s stall at
    // identical heights with every check green. With near-round vote sync
    // restored (verified votes pull us to the peer's round) an offset is
    // fixed by following, not by holding, so the hold only needs to keep
    // the genuinely-ahead node from abandoning a live near-behind peer.
    // The hold covers BOTH cases now -- peer BEHIND us (wait for it) and
    // peer IN OUR ROUND (wait for the exchange to finish instead of
    // leaping out from under it) -- but it is BOUNDED: after
    // 2 * round_timeout from our round start we advance no matter what.
    // The upper bound is what makes holding at equal rounds safe: the
    // 600ms retransmit gets several attempts to deliver the proposal and
    // the votes, and if nothing does (dead peer, wedged transport) the
    // round still expires instead of freezing the pair forever.
    let peer_is_active_nearby = matches!(
        st.peer_round_seen,
        Some((ph, pr, at))
            if ph == st.rt.hc.height
                && at.elapsed() < 2 * cfg.round_timeout
                && pr <= st.rt.hc.round
                // Tightened +3 -> +1 (audit 2026-10-06): "nearby" must mean
                // nearby — a peer 2-3 rounds behind is not keeping phase
                // with us, it is behind, and waiting for it only extends
                // a remotely-triggerable hold. One-round skew (the normal
                // two-node state) still holds.
                && pr + 1 >= st.rt.hc.round
    );
    // PER-ROUND "WAIT FOR A PEER" (WAN liveness, live 2026-10-21): a
    // SINGLE peer that is demonstrably alive - we heard a verified vote
    // from it inside this round's timeout window - is enough reason to
    // hold the view change for one more round. That peer may be exactly
    // one vote short of the quorum that would decide this height, and
    // abandoning the round is what strands it.
    //
    // NO 2-SUPPORTER GATE: the quorum-gated jump was tried and reverted
    // because in a 3-validator set the two nodes BEHIND could never
    // gather two supporters and never caught up - a different deadlock.
    // This rule is LOCAL (it never moves our round, so it cannot drag the
    // node off the network) and BOUNDED (at most 2x the timeout, so it
    // cannot freeze the node either). It only ever delays a round we were
    // about to abandon, and the peer it waits for is a peer we have
    // actually heard from.
    let peer_alive_recently = matches!(
        st.peer_round_seen,
        Some((ph, _, at)) if ph == st.rt.hc.height && at.elapsed() < cfg.round_timeout
    );
    let hold_bounded = (peer_is_active_nearby || peer_alive_recently)
        && st.round_started.elapsed() < 2 * cfg.round_timeout;
    // C2 DETERMINISTIC ROUND TIMING: the timeout VALUE for (height, round)
    // is a pure function of (base env, round, proposer ledger-missed) —
    // see `deterministic_timeout_for`. Two honest nodes at the same
    // (height, round) compute the SAME duration even with different wall
    // clocks. The old input `hc.timeouts` (a LOCAL failure count that
    // diverges: following a peer does not increment it, timing out does)
    // made two honest nodes compute different timeouts for the same
    // round — removed here. The peer-active HOLD below stays, but it is
    // EXECUTION (delaying the firing), never part of the timeout value.
    let scheduled = st.rt.hc.proposer();
    let missed_streak = match scheduled {
        Some(p) => st
            .rt
            .staking_read()
            .await
            .validators
            .get(&p)
            .map(|s| s.missed)
            .unwrap_or(0),
        None => 0,
    };
    let backoff_ms = deterministic_timeout_for(
        cfg.round_timeout.as_millis() as u64,
        st.rt.hc.round,
        missed_streak,
    );
    // C-SLOT FAST TIMEOUT (local policy only — timeouts are never
    // consensus): when the scheduled proposer for the CURRENT round is
    // proven down (ledger missed-streak >= DOWNTIME_MISS_THRESHOLD) the
    // full backoff ladder is pure dead air — cap this round's timeout at
    // STELL_DOWN_PROPOSER_TIMEOUT_MS (default 800ms). DETERMINISTIC gate:
    // ledger evidence ONLY (no `vote_seen` — a local observation flag
    // that diverges across honest nodes and made the timeout value
    // node-local). Skipped while we hold a live proposal for this round:
    // a merely-slow proposer's proposal still arrives first and seats it,
    // so the race resolves toward waiting (normal backoff), never toward
    // a fork — a timeout can only move OUR round, never the chain.
    let fast_down_proposer = !st.rt.hc.has_live_proposal()
        && scheduled.is_some()
        && should_use_down_proposer_timeout_deterministic(missed_streak);
    if fast_down_proposer && st.last_fast_timeout_logged != Some((st.rt.hc.height, st.rt.hc.round))
    {
        st.last_fast_timeout_logged = Some((st.rt.hc.height, st.rt.hc.round));
        eprintln!(
            "[consensus] DOWN-PROPOSER fast timeout h={} r{} proposer={} missed={} (cap {}ms, no backoff)",
            st.rt.hc.height,
            st.rt.hc.round,
            scheduled
                .map(|p| hex::encode(&p[..6]))
                .unwrap_or_else(|| "none".into()),
            missed_streak,
            down_proposer_timeout_ms(),
        );
        tracing::warn!(
            "[consensus] DOWN-PROPOSER fast timeout h={} r={} missed={}",
            st.rt.hc.height,
            st.rt.hc.round,
            missed_streak,
        );
    }
    let effective_timeout = Duration::from_millis(if fast_down_proposer {
        backoff_ms.min(down_proposer_timeout_ms())
    } else if !st.rt.hc.has_live_proposal() && st.rt.hc.round == 0 {
        // In round 0, online proposers deliver within 50ms. Cap round 0 wait at
        // STELL_ROUND_ZERO_TIMEOUT_MS (default 650ms) to eliminate 1.5s dead air spikes.
        backoff_ms.min(round_zero_timeout_ms())
    } else {
        backoff_ms
    });
    // Straggler grace (docs/PROPOSER_REWORK.md §2c): bounded ADDITIVE hold
    // past the deterministic deadline while fresh evidence shows a live
    // straggler (behind peer vote, or no live proposal with a peer live
    // at our height). The deterministic core above stays byte-identical
    // (same-on-all-nodes); this only ever WIDENS honest-round overlap, so
    // heterogeneous holds cannot fork (safety is time-free). Default-off
    // (grace 0 → zero added, the gate below is byte-identical to today).
    // Dead peers age out of the freshness window, so they cannot park us.
    let straggler_hold = {
        let g = straggler_grace_ms();
        if g == 0 {
            Duration::from_millis(0)
        } else {
            let seen = st.peer_round_seen.map(|(ph, pr, at)| {
                let age_ms: u64 = at.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
                (ph, pr, age_ms)
            });
            Duration::from_millis(straggler_hold_ms(
                st.rt.hc.height,
                st.rt.hc.round,
                st.rt.hc.has_live_proposal(),
                seen,
                g,
                straggler_grace_cap_ms(),
                straggler_freshness_ms(cfg.round_timeout.as_millis() as u64),
            ))
        }
    };
    // ROUND-TIMER ACCOUNTING (docs/TEMPO_PROFILE.md §5.3 root cause): the
    // gate below fires at `max(effective_timeout, 2 * round_timeout)`
    // while a peer is active, so an unsubsumed grace stacks PAST the 2×
    // bound (`effective + grace`) instead of filling it. Cap the hold to
    // the slack between the deterministic deadline and that bound — the
    // hold still holds (peer-active wait, grace-while-evidence-fresh),
    // the timeout still times out, and with grace unset the hold is
    // already zero so this `min` is a no-op (default behavior
    // byte-identical). The nil wait is NOT a dwell term (it spends the
    // vote but never gates the view change), so it is untouched.
    let hold_slack = (2 * cfg.round_timeout)
        .checked_sub(effective_timeout)
        .unwrap_or_default();
    let straggler_hold = straggler_hold.min(hold_slack);
    if !straggler_hold.is_zero() && st.round_started.elapsed() > effective_timeout {
        stellereum::metrics::global().inc_straggler_grace_extends();
    }
    if st.round_started.elapsed() > effective_timeout + straggler_hold && !hold_bounded {
        // infnode pubsub is best-effort: a vote can be dropped in transit.
        // Broadcasting each vote exactly once means a single lost message
        // leaves the peer one signature short forever, and since the two
        // sides then sit in different rounds neither can ever finalize —
        // the chain stalls at that height permanently. Re-send this round's
        // votes before moving on so a peer that missed them can still
        // reach quorum (the same reason Tendermint re-propagates on timeout).
        // P3-H4: timeout re-sends RE-ENQUEUE rebuilt votes (fresh
        // lock_hint: the node may have locked since casting) and force
        // flushes. Never a direct broadcast from this path.
        let mut requeued = false;
        for v in [st.cast_prevote.clone(), st.cast_precommit.clone()]
            .into_iter()
            .flatten()
        {
            requeued |= enqueue_outbox(
                &mut st.outbox,
                ConsensusMsg::Vote {
                    vote: v.clone(),
                    locked: lock_hint(&st.rt, &v),
                },
            );
        }
        // Re-send OUR proposal for this round as well. If that one message
        // was lost, the peer never votes it, the proposal gate stays shut
        // (has_live_proposal) for the whole round, and nothing retries it
        // until the round changes -- one dropped datagram cost a full round.
        // Same bytes, idempotent on the receiver.
        if st.rt.hc.has_live_proposal() {
            if let Some((_, ph)) = st.rt.hc.proposal {
                if let Some(b) = st.rt.blocks.get(&ph).cloned() {
                    // The envelope is a freshness hint for the BODY, so it
                    // must name the body's OWN signed round. Using the
                    // current local round re-advertised a stale body as
                    // "the proposal for r" (RESTART-SPLIT).
                    st.compact_server.remember(&b, b.round);
                    requeued |= enqueue_outbox(
                        &mut st.outbox,
                        stellereum::consensus_net::proposal_gossip_msg(&b, b.round),
                    );
                }
            }
        }
        // Flush only when something NEW was actually queued. The old
        // force-flush re-emitted the same bytes on EVERY view change even
        // when dedup collapsed both requeues, so a wedged round (one view
        // change per `round_timeout`) amplified into a retry storm on top
        // of the 2s TIMEOUTs. Loss recovery stays on the periodic
        // retransmit below, which backs off while stuck instead.
        if requeued {
            flush_outbox(
                &cfg.net_sender,
                &mut st.outbox,
                st.rt.hc.height,
                st.rt.hc.round,
            );
            step.outbox_flushes += 1;
            st.last_flush = std::time::Instant::now();
        }
        st.rt.next_round();
        st.last_prevoted = None;
        st.last_precommitted = None;
        st.cast_prevote = None;
        st.cast_precommit = None;
        st.round_started = std::time::Instant::now();
        info!(
            "[consensus] view change -> height {} round {}",
            st.rt.hc.height, st.rt.hc.round
        );
        // C2 NIL-STORM CIRCUIT BREAKER (one-shot per streak, K=3): after K
        // consecutive nil-rounds, (a) re-broadcast the highest-QC-backed
        // proposal body we hold (same bytes, idempotent), (b) widen the
        // vote-collection window ONCE (inside `apply_nil_convergence`),
        // (c) resume normal timing. SAFE: casts no vote (never
        // double-votes), moves no round (never rewinds); only the window
        // widens, once. The node that already holds the network's polka
        // body re-shares it; nodes that don't hold it only widen.
        if st.rt.hc.nil_breaker_due() {
            let target = st.rt.hc.apply_nil_convergence();
            let have_body = target.and_then(|h| st.rt.blocks.get(&h).cloned());
            if let Some(body) = have_body {
                let h = body.compute_hash();
                // Envelope = the body's signed round, never the local
                // round: the other nodes must not adopt a stale body as
                // the current round's proposal (RESTART-SPLIT).
                st.compact_server.remember(&body, body.round);
                enqueue_outbox(
                    &mut st.outbox,
                    stellereum::consensus_net::proposal_gossip_msg(&body, body.round),
                );
                flush_outbox(
                    &cfg.net_sender,
                    &mut st.outbox,
                    st.rt.hc.height,
                    st.rt.hc.round,
                );
                step.outbox_flushes += 1;
                st.last_flush = std::time::Instant::now();
                eprintln!(
                    "[consensus][nil-breaker] h={} r{} K={} re-broadcast QC-backed {} (window widened once)",
                    st.rt.hc.height,
                    st.rt.hc.round,
                    stellereum::consensus::NIL_CIRCUIT_BREAKER_K,
                    hex::encode(&h[..6]),
                );
                tracing::warn!(
                    "[consensus][nil-breaker] h={} r{} re-broadcast QC-backed proposal",
                    st.rt.hc.height,
                    st.rt.hc.round,
                );
            } else {
                eprintln!(
                    "[consensus][nil-breaker] h={} r{} K={} no QC-backed body held (window widened once, waiting for votes)",
                    st.rt.hc.height,
                    st.rt.hc.round,
                    stellereum::consensus::NIL_CIRCUIT_BREAKER_K,
                );
                tracing::warn!(
                    "[consensus][nil-breaker] h={} r{} widened vote-collection window (no body to re-share)",
                    st.rt.hc.height,
                    st.rt.hc.round,
                );
            }
        }
    }
}

/// Deadlock circuit breaker + pure no-progress local re-phase fallback.
fn step_deadlock_breaker(st: &mut DriverState) {
    // Deadlock circuit breaker (live 2026-10-14: A r1550 vs B r318 at
    // h92078, `sync_round_to` +8/4s + `MAX_ROUND_AHEAD` made convergence
    // impossible). Fires only after `STELL_DEADLOCK_TIMEOUT_SECS`
    // (default 300) without finalization while verified peer rounds are
    // ahead: one bounded forward-only jump to max(peer rounds), at most
    // once per timeout window. `check_deadlock_breaker` owns the
    // fail-safe + loud log; here we only reset per-round bookkeeping so
    // the fresh round is not view-changed instantly.
    //
    // Follow-up (live: A r1595 vs B r412, EMPTY peer rounds, mutually deaf
    // forever): when NO verified peer is ahead (empty/default peer rounds)
    // the jump path above can never fire. The `else` below is the pure
    // no-progress fallback: same timeout + same once-per-window rate limit,
    // but a bounded LOCAL RE-PHASE — advance the round (never rewind: a
    // re-vote in an already-used round is a self-equivocation), widen the
    // quorum-scan window so the round the network is actually in becomes
    // committable, and drop only a bodyless lock. Local policy only, no
    // wire-protocol change.
    if let Some(new_round) = st.rt.check_deadlock_breaker() {
        info!(
            "[consensus] DEADLOCK-BREAKER jumped to round {} at height {}",
            new_round, st.rt.hc.height
        );
        st.round_started = std::time::Instant::now();
        st.last_prevoted = None;
        st.last_precommitted = None;
        st.cast_prevote = None;
        st.cast_precommit = None;
    } else {
        let timeout = ValidatorRuntime::deadlock_timeout();
        let timeout_secs = timeout.as_secs().max(1);
        let no_progress_secs = st.rt.last_progress_at.elapsed().as_secs();
        let rate_ok = st
            .rt
            .last_breaker_at
            .map(|t| t.elapsed() >= timeout)
            .unwrap_or(true);
        if rate_ok
            && st
                .rt
                .hc
                .deadlock_local_reset_due(no_progress_secs, timeout_secs)
        {
            let height_before = st.rt.hc.height;
            let from_round = st.rt.hc.round;
            // HOLD-SET LOOKUP BY VALUE (ruleset v6, site 8): the lock may
            // name a signed hash we have since re-stamped away from. The
            // body is present when ANY held body has the lock's
            // round-free value id, not only when the exact hash is in
            // the store — otherwise a re-proposal would look "bodyless"
            // and the re-phase would drop a lock it still holds.
            let locked_body_present =
                st.rt
                    .hc
                    .locked
                    .map(|(h, _)| {
                        st.rt.blocks.contains_key(&h)
                            || st.rt.hc.value_id_of(&h).is_some_and(|vid| {
                                st.rt.blocks.values().any(|b| b.value_id() == vid)
                            })
                    })
                    .unwrap_or(true);
            if st.rt.hc.apply_deadlock_local_reset(locked_body_present) {
                st.rt.last_breaker_at = Some(std::time::Instant::now());
                debug_assert_eq!(
                    st.rt.hc.height, height_before,
                    "breaker must never move height"
                );
                debug_assert!(
                    st.rt.hc.round > from_round,
                    "re-phase must never rewind the round (self-equivocation)"
                );
                tracing::warn!(
                    height = st.rt.hc.height,
                    from_round,
                    to_round = st.rt.hc.round,
                    scan_lookback = st.rt.hc.scan_lookback,
                    no_progress_secs,
                    "DEADLOCK-BREAKER (local re-phase): no finalization and no peer ahead, \
                     advancing the round and widening the quorum-scan window"
                );
                eprintln!(
                    "[consensus][DEADLOCK-BREAKER][local-rephase] h={} r{} -> r{} (scan window {} rounds) after {}s without finalization (timeout {}s)",
                    height_before,
                    from_round,
                    st.rt.hc.round,
                    st.rt.hc.scan_lookback,
                    no_progress_secs,
                    timeout_secs
                );
                info!(
                    "[consensus] DEADLOCK-BREAKER local re-phase to round {} at height {}",
                    st.rt.hc.round, st.rt.hc.height
                );
                st.round_started = std::time::Instant::now();
                st.last_prevoted = None;
                st.last_precommitted = None;
                st.cast_prevote = None;
                st.cast_precommit = None;
            }
        }
    }
}

/// Periodic retransmit of already-cast votes/thin proposals, plus P3-H4 timer flush.
fn step_retransmit_and_flush(cfg: &DriverConfig, st: &mut DriverState, step: &mut TickStep) {
    // Periodic retransmit of what we already cast. pubsub is best-effort:
    // measurements on the live stand attributed 26.7% of wasted rounds to
    // a message that simply never arrived (18.8% of proposals, 31 rounds
    // with a full prevote QC whose precommit leg was lost). Re-enqueueing
    // is idempotent -- `enqueue_outbox` dedups votes still pending, and
    // re-sent bytes are identical, so the receiver's VoteSet treats them
    // as the same vote (never as equivocation).
    //
    // The cadence BACKS OFF the longer a round is stuck (fast while
    // fresh for loss recovery, relaxing toward 2x timeout): a fixed
    // cadence re-sent at full rate forever, and each wedged round added
    // its own storm on top of the 2s TIMEOUTs. `round_started` resets on
    // every round change, so a new round automatically retries fast.
    let rexmit_every = Duration::from_millis(stellereum::consensus_net::retransmit_interval_ms(
        cfg.round_timeout.as_millis() as u64,
        st.round_started.elapsed().as_millis() as u64,
    ));
    if st.last_rexmit.elapsed() >= rexmit_every {
        st.last_rexmit = std::time::Instant::now();
        let mut resent = false;
        for v in [st.cast_prevote.clone(), st.cast_precommit.clone()]
            .into_iter()
            .flatten()
        {
            resent |= enqueue_outbox(
                &mut st.outbox,
                ConsensusMsg::Vote {
                    vote: v.clone(),
                    locked: lock_hint(&st.rt, &v),
                },
            );
        }
        // Thin blocks only (<=32 txs): re-sending a full block every window
        // would amplify traffic, while a large block that is lost simply
        // gets re-proposed by the next round's gate anyway. Guarded
        // against pushing the identical body twice: the outbox already
        // holding this round's proposal means the wire copy is queued.
        if st.rt.hc.has_live_proposal() {
            if let Some((_, ph)) = st.rt.hc.proposal {
                if let Some(b) = st.rt.blocks.get(&ph).cloned() {
                    if b.transactions.len() <= 32
                        && !outbox_has_proposal(&st.outbox, b.height, b.round)
                    {
                        // Same rule everywhere: re-share under the body's
                        // signed round, not the local one (RESTART-SPLIT).
                        st.compact_server.remember(&b, b.round);
                        resent |= enqueue_outbox(
                            &mut st.outbox,
                            stellereum::consensus_net::proposal_gossip_msg(&b, b.round),
                        );
                    }
                }
            }
        }
        if resent {
            flush_outbox(
                &cfg.net_sender,
                &mut st.outbox,
                st.rt.hc.height,
                st.rt.hc.round,
            );
            step.outbox_flushes += 1;
            st.last_flush = std::time::Instant::now();
        }
    }

    // P3-H4 timer flush: pack this tick's votes into one Batch.
    if !st.outbox.is_empty() && st.last_flush.elapsed() >= Duration::from_millis(BATCH_MS) {
        flush_outbox(
            &cfg.net_sender,
            &mut st.outbox,
            st.rt.hc.height,
            st.rt.hc.round,
        );
        step.outbox_flushes += 1;
        st.last_flush = std::time::Instant::now();
    }
}
