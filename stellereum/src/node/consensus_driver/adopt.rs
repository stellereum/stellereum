use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

use super::{
    advance_vote_floor, round_at_or_below_vote_floor, should_publish_body_now,
    should_publish_header_now, write_ahead_finalized_block, DriverConfig, DriverState, TickStep,
};
use crate::node::policy::*;
use stellereum::consensus::VoteKind;
use stellereum::consensus_net::{parse_incoming_with_peer_key, ConsensusMsg};
use stellereum::runtime::ValidatorRuntime;

/// Re-enter the inbound drain as a FULL proposal.
///
/// A compact proposal resolves into a complete `Block`. Handing it straight to
/// `on_proposal` would duplicate the attribution, H+1 deferral, hint and vote
/// machinery of the plain-Proposal arm. Instead the resolved block is encoded
/// exactly like a wire `Proposal` and pushed back into the bounded deferred
/// queue, so it is parsed, verified and handled by the ONE existing path —
/// there is no second implementation to drift.
pub(super) fn encode_full_proposal_loopback(
    block: &stellereum::sharding::Block,
    round: u32,
    src: &str,
) -> Option<String> {
    let msg = ConsensusMsg::Proposal {
        height: block.height,
        round,
        block: block.clone(),
    };
    let bytes = msg.encode().ok()?;
    // Carry the originating peer id so admission/accounting can attribute the
    // re-injected frame instead of charging a shared "broadcast" bucket. Local
    // loopbacks ride their own bounded queue and are not re-charged to the
    // bulk limiter (the compact frame already paid); attribution still lets
    // scoring/rate decisions see who caused the work.
    Some(serde_json::json!({ "data": hex::encode(bytes), "src": src }).to_string())
}

/// Encode a parked commit back into the local loopback queue.
///
/// Re-entering the normal inbound drain (rather than calling
/// `adopt_committed` from the tick tail) is deliberate: the drain's
/// `Committed` arm is the ONE place that performs the full adopt side effects
/// — persistence (`enqueue_block` / `enqueue_finalized`), the QC sidecar
/// clear, explorer/receipt records and replication. Adopting from the tail
/// would advance consensus while silently skipping all of them.
pub(super) fn encode_committed_loopback(
    height: u64,
    block: &stellereum::sharding::Block,
    certificate: &stellereum::consensus::QuorumCertificate,
    src: &str,
) -> Option<String> {
    let msg = ConsensusMsg::Committed {
        height,
        block: block.clone(),
        certificate: certificate.clone(),
    };
    let bytes = msg.encode().ok()?;
    Some(serde_json::json!({ "data": hex::encode(bytes), "src": src }).to_string())
}

/// Replay the bounded park slots once the apply worker has released post-H
/// state (`apply_in_flight` Some -> None).
///
/// The proposal goes through the same public entry point as live traffic
/// ([`ValidatorRuntime::on_proposal`]) and the commit is re-injected into the
/// local loopback queue so the next drain runs the normal `Committed` arm
/// (which validates it through [`ValidatorRuntime::adopt_committed`] AND
/// performs the persistence/publication/receipt side effects). Nothing is
/// applied from the parked copy directly; a refusal is logged and dropped
/// (the peer/gossip retry remains the backstop).
///
/// Order: the commit is queued first, then the proposal is replayed (it
/// typically targets the newly installed H+1).
pub(super) async fn replay_parked_apply_window(
    rt: &mut ValidatorRuntime,
    loopback_queue: &mut std::collections::VecDeque<String>,
    loopback_dropped: &mut u64,
) {
    let (proposal, commit) = rt.take_parked();
    if let Some(c) = commit {
        let height = c.height;
        match encode_committed_loopback(height, &c.block, &c.certificate, "local-replay") {
            Some(raw) => {
                if push_bounded_loopback(loopback_queue, raw, LOOPBACK_QUEUE_CAP) {
                    *loopback_dropped += 1;
                }
                info!(
                    "[consensus] parked commit #{} re-injected into the drain (full adopt path on the next tick)",
                    height
                );
            }
            None => tracing::warn!(
                height,
                "[consensus] parked commit could not be re-encoded for replay; dropped (peer retry remains the backstop)"
            ),
        }
    }
    if let Some(p) = proposal {
        let h = p.block.height;
        match rt.on_proposal(p.proposer, p.block, p.round).await {
            Ok(bh) => info!(
                "[consensus] replayed parked proposal #{} r{} {} (accepted)",
                h,
                p.round,
                hex::encode(&bh[..6])
            ),
            Err(e) => tracing::debug!(
                height = h,
                round = p.round,
                error = %e,
                "[consensus] parked proposal refused on replay (fail-closed)"
            ),
        }
    }
}

/// 3. drain incoming consensus messages, capped per tick (audit 2026-10-06).
pub(super) async fn drain_inbound_messages(
    cfg: &DriverConfig,
    st: &mut DriverState,
    step: &mut TickStep,
) {
    let can_vote = step.can_vote;

    // One settle path for a compact resolution (proposal AND body): every
    // outcome is handled identically, so the two receive arms cannot drift.
    // `$src` is the peer id that produced the compact frame (attribution).
    macro_rules! settle_compact {
        ($inbound:expr, $src:expr) => {{
            match $inbound {
                stellereum::consensus_net::CompactInbound::Ready { round, block } => {
                    // Re-enter the SAME drain as a full proposal: attribution,
                    // H+1 deferral, hints, `on_proposal` and the vote all run
                    // once, in the one place they are already correct.
                    match encode_full_proposal_loopback(&block, round, $src) {
                        Some(raw) => {
                            // Bounded + priority-drained (F-1/H5): on overflow
                            // the oldest loopback goes (counted loudly), never
                            // unbounded memory.
                            if push_bounded_loopback(
                                &mut st.loopback_queue,
                                raw,
                                LOOPBACK_QUEUE_CAP,
                            ) {
                                st.loopback_dropped += 1;
                                if st.loopback_dropped == 1 || st.loopback_dropped.is_multiple_of(50)
                                {
                                    tracing::warn!(
                                        "[consensus] compact loopback queue full ({} entries); dropped the oldest resolved proposal ({} dropped)",
                                        LOOPBACK_QUEUE_CAP,
                                        st.loopback_dropped
                                    );
                                }
                            }
                            st.compact_looped += 1;
                            if st.compact_looped == 1 {
                                info!(
                                    "[consensus] compact gossip LIVE: first proposal resolved from the local mempool and re-entered the drain as a full proposal"
                                );
                            }
                        }
                        None => tracing::warn!(
                            "[consensus] compact gossip: resolved block #{} r{} could not be re-encoded for loopback",
                            block.height,
                            round,
                        ),
                    }
                }
                stellereum::consensus_net::CompactInbound::Pull(pull) => {
                    // H1: a pull is consensus traffic to EVERY peer. Cap the
                    // number one peer can force per tick, and never let a
                    // pull-born flood share the ordered vote/proposal queue
                    // without bound.
                    let budget = st.compact_peer_pulls.entry($src.to_string()).or_insert(0);
                    if compact_frame_within_peer_budget(budget, COMPACT_PULLS_PER_PEER_PER_TICK) {
                        enqueue_outbox(&mut st.outbox, ConsensusMsg::BodyPull { pull });
                        flush_outbox(&cfg.net_sender, &mut st.outbox, st.rt.hc.height, st.rt.hc.round);
                        step.outbox_flushes += 1;
                        st.last_flush = std::time::Instant::now();
                    } else {
                        st.compact_budget_dropped += 1;
                    }
                }
                stellereum::consensus_net::CompactInbound::FetchFull {
                    height,
                    round,
                    block_hash,
                    reason,
                } => {
                    // NEVER prevote a partial body. An UNRESOLVABLE compact
                    // announcement is not evidence: neither the block nor
                    // its proposer signature was ever checked, so this arm
                    // must not plant `peer_hint`/`peer_named_height` or
                    // re-arm catch-up (pentest-2 F-2/C1). It only asks the
                    // proposer for the full body through the existing
                    // pull frame; the normal Proposal arm authenticates it
                    // and only THEN may evidence be recorded.
                    tracing::warn!(
                        "[consensus] compact gossip fell back to the full proposal #{} r{} ({reason:?})",
                        height,
                        round,
                    );
                    st.compact_full_requests += 1;
                    if st.compact_full_requests == 1 {
                        info!(
                            "[consensus] compact gossip LIVE: first full-proposal fallback requested (the unresolved announcement is not treated as evidence)"
                        );
                    }
                    if full_proposal_request_is_relevant(st.rt.hc.height, height) {
                        let pull = stellereum::consensus_net::compact_prop::BodyPull::full_request(
                            height, round, block_hash,
                        );
                        enqueue_outbox(&mut st.outbox, ConsensusMsg::BodyPull { pull });
                        flush_outbox(&cfg.net_sender, &mut st.outbox, st.rt.hc.height, st.rt.hc.round);
                        step.outbox_flushes += 1;
                        st.last_flush = std::time::Instant::now();
                    } else {
                        tracing::debug!(
                            "[sync] compact full-proposal request at #{height} ignored (local hc #{}, outside the live window); catch-up owns far-ahead announcements",
                            st.rt.hc.height
                        );
                    }
                }
                stellereum::consensus_net::CompactInbound::Refused(why) => {
                    st.inbound_compact_refused += 1;
                    if st.inbound_compact_refused % 20 == 1 {
                        tracing::warn!(
                            "[consensus] refused compact frame ({} refused): {why}",
                            st.inbound_compact_refused
                        );
                    }
                }
            }
        }};
    }

    // 3. drain incoming consensus messages, capped per tick (audit
    // 2026-10-06): an unbounded drain lets a flood of max-size batches
    // stretch signature verification past the round timeout — the tick IS
    // the clock. TWO caps: at most MAX_INBOUND_PER_TICK envelopes are
    // CONSUMED per tick (the rest wait in the channel — deferred, never
    // dropped), and at most INNER_BUDGET flattened messages are VERIFIED
    // (a Batch fans out to 32 votes; counting envelopes alone let the
    // exact blowup through that the cap claims to stop). Past the inner
    // budget the flood tail is dropped loudly — honest traffic (tens/tick)
    // never reaches either cap (weak-node principle).
    let mut inner_verified = 0u32;
    let mut committed_admitted = 0u32;
    const INNER_BUDGET_PER_TICK: u32 = MAX_INBOUND_PER_TICK * 4;
    // SEC-06: prioritize draining live messages from rx.try_recv().
    // Deferred bulk messages wait in `inbound_deferred` until their scheduled
    // `wake_at` time and are only popped when `rx` has no immediate messages,
    // preventing bulk deferrals from starving real-time consensus votes.
    'drain: for _ in 0..MAX_INBOUND_PER_TICK {
        // LOCAL LOOPBACKS FIRST: a resolved compact proposal re-enters the
        // drain here, ahead of peer traffic, so an honest block is never
        // starved behind future-dated deferrals or a flood (F-1/H5). These
        // entries are local-only, bounded, and already accounted to the
        // compact frame that produced them; they skip the per-peer bulk
        // limiter (no double charge) but still pay the inner verify budget.
        let (raw, from_loopback): (String, bool) = if let Some(raw) = st.loopback_queue.pop_front()
        {
            (raw, true)
        } else {
            match st.rx.try_recv() {
                Ok(r) => (r, false),
                Err(_) => {
                    let now = Instant::now();
                    if st
                        .inbound_deferred
                        .front()
                        .map(|(wake_at, _)| now >= *wake_at)
                        .unwrap_or(false)
                    {
                        (st.inbound_deferred.pop_front().unwrap().1, false)
                    } else {
                        break;
                    }
                }
            }
        };
        let Some((msg, peer_key)) = parse_incoming_with_peer_key(&raw) else {
            // Unparseable payloads on our own topic are a delivery-layer
            // bug (or garbage from a peer); silent drops here once hid a
            // one-directional blackout for hours. Count them loudly.
            st.parse_fail_count += 1;
            if st.parse_fail_count % 50 == 1 {
                tracing::warn!(
                    "[consensus] dropped {} unparseable inbound message(s); last len {} head {:?}",
                    st.parse_fail_count,
                    raw.len(),
                    &raw[..raw.len().min(120)],
                );
            }
            continue;
        };
        // Inbound bulk guard (audit-network F1 + pentest F2): EVERY
        // envelope is budget-checked against the SENDER's per-peer bucket
        // (`src`: infnode adds it — it is the only place that knows the
        // connection's peer id; `from` is the legacy spelling). Without a
        // sender every peer's bulk traffic shared ONE token bucket and one
        // noisy neighbour could defer everybody else's batches.
        //
        // Only Committed bypasses inside `admit_inbound` (the catch-up
        // proof must never wait). Votes and proposals are budget-checked
        // too: exempting every non-Batch message let an attacker trickle
        // singleton votes — never a Batch — and burn an Ed25519 verify
        // per message while the limiter saw nothing (pentest F2). A
        // deferred message is REQUEUED (bounded wait hint honored by
        // re-parking for a later tick), never dropped; per-peer buckets
        // mean an honest peer's votes still pass while the flooder's own
        // bucket is empty. The envelope already counted as liveness
        // evidence below even when deferred.
        //
        // A LOCAL LOOPBACK is already budgeted (it is the resolved block
        // for a compact frame that paid admission) and is bounded by
        // `LOOPBACK_QUEUE_CAP`, so it is not re-charged to the shared bulk
        // limiter. It still carries the originating `src` for attribution.
        if !from_loopback {
            match cfg.net.admit_inbound(&peer_key, &msg, raw.len()) {
                stellereum::consensus_net::InboundDecision::Allow => {}
                stellereum::consensus_net::InboundDecision::Defer { wait_ms } => {
                    st.inbound_defer_count += 1;
                    if st.inbound_defer_count % 20 == 1 {
                        tracing::warn!(
                            "[consensus] inbound bulk over budget; deferring message ({raw_len} bytes, retry in ~{wait_ms}ms) {} time(s) — catch-up Committed unaffected",
                            st.inbound_defer_count,
                            raw_len = raw.len(),
                        );
                    }
                    if st.inbound_deferred.len() < INBOUND_DEFERRED_CAP {
                        // SEC-06: Store deferred messages in time-gated queue with scheduled wake_at time.
                        let wake_at = Instant::now() + Duration::from_millis(wait_ms);
                        let pos = st
                            .inbound_deferred
                            .iter()
                            .position(|(w, _)| *w > wake_at)
                            .unwrap_or(st.inbound_deferred.len());
                        st.inbound_deferred.insert(pos, (wake_at, raw));
                        continue;
                    }
                    // Park full: handle inline LOUDLY rather than drop
                    // or grow memory without bound. Only under a
                    // sustained bulk flood past 1024 parked messages.
                    tracing::warn!(
                        "[consensus] deferred park full ({INBOUND_DEFERRED_CAP}); handling an over-budget message inline (never dropped)"
                    );
                }
            }
        }
        // Inbound liveness clock (dead-peer retro gate): ANY parseable
        // consensus message proves somebody is talking to us right now.
        // Stamped per envelope (before flattening): one Batch from a live
        // peer is liveness evidence even if every inner is later dropped.
        st.last_inbound_msg = std::time::Instant::now();
        {
            // P3-H4: a Batch flattens to its inners in sender order. Each
            // inner is isolated (one bad inner never drops its siblings)
            // and runs the full per-vote bookkeeping below.
            //
            // Audit-network F2 priority lane: `Committed` is the live
            // catch-up path (full block + QC, no DHT work) and must not
            // starve behind bulk junk. Flattened inners are reordered so
            // `Committed` verifies first, and `Committed` neither counts
            // against the verification budget nor is dropped as flood
            // tail — only Batch-carried votes/proposals burn the budget.
            // Scheduling only: validation below is untouched.
            for msg in
                stellereum::consensus_net::prioritize_inbound_for_verify(flatten_incoming(msg))
            {
                // Liveness-alarm RX clock: ANY consumed Proposal/Vote —
                // accepted or refused, Batch-carried or singleton — proves
                // the transport delivers our topic right now. Stamped
                // BEFORE any verification/refusal below (a refusal still
                // proves receipt); Committed is deliberately excluded (it
                // is catch-up proof, and the alarm watches live traffic).
                if matches!(
                    msg,
                    ConsensusMsg::Proposal { .. }
                        | ConsensusMsg::CompactProposal { .. }
                        | ConsensusMsg::Vote { .. }
                ) {
                    st.last_consensus_rx_ms = stellereum::liveness_alarm::now_ms();
                }
                // At-tip silence clock: every consensus frame counts,
                // including `Committed` (catch-up evidence also proves the
                // inbound stream delivers). Stamped on receipt, before any
                // verification/refusal, so only true transport silence
                // arms the bounded head/QC probe.
                if matches!(
                    msg,
                    ConsensusMsg::Proposal { .. }
                        | ConsensusMsg::CompactProposal { .. }
                        | ConsensusMsg::Vote { .. }
                        | ConsensusMsg::Committed { .. }
                ) {
                    st.last_consensus_frame_ms = stellereum::liveness_alarm::now_ms();
                }
                // Event-driven catch-up: a message that NAMES a height above
                // ours is potential "peer is ahead" evidence. It is acted on
                // only AFTER the arm's own verification (QC / proposer
                // signature / vote signature) — never on the raw claim.
                let named_ahead = inbound_names_ahead(st.rt.hc.height, &msg);
                let is_catchup = matches!(msg, ConsensusMsg::Committed { .. });
                if is_catchup {
                    // VERIFICATION F2-hardening: Committed bypasses the
                    // byte limiter by design, so a single peer can emit
                    // unbounded fake proofs. The per-tick proof cap is
                    // the bound: excess proofs are dropped LOUDLY (not
                    // deferred — a deferred fake would just burn the next
                    // tick too), the rest of the drain continues, and the
                    // sender's rebroadcast + the DHT walk cover honest
                    // catch-up (which needs ~1 proof per finalize).
                    if !stellereum::consensus_net::committed_admit_this_tick(committed_admitted) {
                        st.inbound_overcap_count += 1;
                        tracing::warn!(
                            "[consensus] dropping Committed proof over per-tick cap ({} proves/tick); flood tail, catch-up falls back to rebroadcast/DHT walk",
                            stellereum::consensus_net::COMMITTED_INNER_BUDGET_PER_TICK,
                        );
                        continue;
                    }
                    committed_admitted += 1;
                } else {
                    inner_verified += 1;
                    if inner_verified > INNER_BUDGET_PER_TICK {
                        st.inbound_overcap_count += 1;
                        if st.inbound_overcap_count % 20 == 1 {
                            tracing::warn!(
                                "[consensus] inbound verification over budget {INNER_BUDGET_PER_TICK}/tick {} time(s); dropping flood tail (Committed catch-up still admitted)",
                                st.inbound_overcap_count
                            );
                        }
                        break 'drain;
                    }
                }
                match msg {
                    ConsensusMsg::Batch(_) => {}
                    // Compact proposal gossip (`CompactProposal` / `BodyPull`
                    // / `Body`): activation is frozen OFF at
                    // `COMPACT_GOSSIP_ACTIVATION_HEIGHT = u64::MAX`, and the
                    // receiver wiring lands with the lead's gate flip. Below
                    // the gate these frames MUST be refused loudly and
                    // dropped — never reinterpreted as a full proposal, never
                    // a panic. `ConsensusMsg::decode` already rejects them
                    // pre-activation; these arms are defense in depth for a
                    // frame that decoded while the gate says off.
                    // COMPACT GOSSIP is ACTIVE. Resolve against the local
                    // mempool; a complete resolution re-enters the drain as
                    // a FULL proposal (one code path for every check); a
                    // miss emits a BOUNDED pull; an unresolvable proposal
                    // falls back to the plain full fetch.
                    ConsensusMsg::CompactProposal { proposal } => {
                        // C2/F-8: authenticate/structurally pre-filter and
                        // budget BEFORE any mempool clone or index build.
                        // Far/stale heights and over-budget peers are
                        // dropped loudly without touching the pool.
                        let over = {
                            let count = st.compact_peer_frames.entry(peer_key.clone()).or_insert(0);
                            !compact_frame_within_peer_budget(
                                count,
                                COMPACT_FRAMES_PER_PEER_PER_TICK,
                            )
                        };
                        if over {
                            st.compact_budget_dropped += 1;
                            st.inbound_compact_refused += 1;
                            if st.compact_budget_dropped == 1
                                || st.compact_budget_dropped.is_multiple_of(50)
                            {
                                tracing::warn!(
                                    "[consensus] compact frame budget exceeded for peer {} ({} dropped): per-tick cap {}",
                                    peer_key,
                                    st.compact_budget_dropped,
                                    COMPACT_FRAMES_PER_PEER_PER_TICK,
                                );
                            }
                            continue;
                        }
                        if !compact_proposal_height_is_relevant(st.rt.hc.height, proposal.height) {
                            st.inbound_compact_refused += 1;
                            tracing::debug!(
                                "[consensus] compact proposal #{} r{} outside live window (hc #{}) — catch-up owns it",
                                proposal.height,
                                proposal.round,
                                st.rt.hc.height,
                            );
                            continue;
                        }
                        // STRUCTURAL VALIDATION FIRST (C2/F-8): a malformed
                        // frame must not be able to trigger an index build.
                        if let Err(why) = proposal.validate() {
                            st.inbound_compact_refused += 1;
                            if st.inbound_compact_refused % 20 == 1 {
                                tracing::warn!(
                                    "[consensus] refused compact frame before mempool work ({} refused): {why}",
                                    st.inbound_compact_refused
                                );
                            }
                            continue;
                        }
                        // Parent plausibility: at OUR height the header must
                        // build on our finalized tip, so a peer cannot mint
                        // unlimited distinct salts with random prev_hashes.
                        let (tip_h, tip_hash) =
                            st.rt.finalized.last().copied().unwrap_or((0, [0u8; 32]));
                        if !compact_parent_is_plausible(
                            proposal.height,
                            proposal.header.prev_hash,
                            st.rt.hc.height,
                            tip_hash,
                        ) {
                            st.inbound_compact_refused += 1;
                            tracing::debug!(
                                "[consensus] compact proposal #{} does not build on our tip #{tip_h} (prev {}); dropped before mempool work",
                                proposal.height,
                                hex::encode(&proposal.header.prev_hash[..6]),
                            );
                            continue;
                        }
                        let inbound = if proposal.short_ids.is_empty() {
                            // Zero-id block: no index work at all.
                            st.compact_rx.on_proposal(proposal, std::iter::empty())
                        } else {
                            let now = Instant::now();
                            let cached = st.compact_index.get(&proposal.header, now).is_some();
                            let index = if cached {
                                st.compact_index
                                    .get(&proposal.header, now)
                                    .expect("just checked")
                            } else {
                                // Whole-node per-tick build budget: the
                                // cache key is the salt, and a peer can
                                // vary it; this is the hard bound on
                                // whole-mempool work per tick.
                                if st.compact_index_builds_tick >= COMPACT_INDEX_BUILDS_PER_TICK {
                                    st.compact_budget_dropped += 1;
                                    continue;
                                }
                                st.compact_index_builds_tick += 1;
                                let txs = st.rt.mempool.read().await.all();
                                st.compact_index.insert(&proposal.header, txs, now)
                            };
                            st.compact_rx.on_proposal_indexed(proposal, index)
                        };
                        settle_compact!(inbound, &peer_key);
                    }
                    // Serve missing txs for a block WE announced, from the
                    // cached announced body (bounded), never from arbitrary
                    // storage and never by cloning the whole mempool.
                    ConsensusMsg::BodyPull { pull } => {
                        let over = {
                            let count = st.compact_peer_frames.entry(peer_key.clone()).or_insert(0);
                            !compact_frame_within_peer_budget(
                                count,
                                COMPACT_FRAMES_PER_PEER_PER_TICK,
                            )
                        };
                        if over {
                            st.compact_budget_dropped += 1;
                            continue;
                        }
                        let now_ms = stellereum::liveness_alarm::now_ms();
                        if pull.is_full_request() {
                            match st.compact_server.serve_full_for(&peer_key, &pull, now_ms) {
                                Ok(Some(block)) => {
                                    let round = pull.round;
                                    enqueue_outbox(
                                        &mut st.outbox,
                                        ConsensusMsg::Proposal {
                                            height: block.height,
                                            round,
                                            block,
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
                                    st.compact_served += 1;
                                    if st.compact_served == 1 {
                                        info!(
                                            "[consensus] compact gossip LIVE: first full-proposal fallback served from the announced body"
                                        );
                                    }
                                }
                                Ok(None) => {}
                                Err(why) => {
                                    st.inbound_compact_refused += 1;
                                    if st.inbound_compact_refused % 20 == 1 {
                                        tracing::warn!(
                                            "[consensus] refused compact full-proposal request #{} r{}: {why}",
                                            pull.height,
                                            pull.round,
                                        );
                                    }
                                }
                            }
                            continue;
                        }
                        match st.compact_server.serve_for(&peer_key, &pull, now_ms) {
                            Ok(Some(body)) => {
                                // UNICAST REPLY (no broadcast amplification):
                                // the requester is the inbound envelope's
                                // peer id (`peer_key`, derived at the top of
                                // this drain from `inbound_peer_key`), which
                                // `serve_for` already used for the
                                // served-once set and rate cap. A 40-hex id
                                // gets one addressed send; an unknown key
                                // (shared `broadcast` bucket, legacy short
                                // src) keeps the bounded outbox broadcast.
                                let counters = cfg.net.compact_reply_counters();
                                let net_unicast = Arc::clone(&cfg.net);
                                let hc_height = st.rt.hc.height;
                                let hc_round = st.rt.hc.round;
                                let route = stellereum::consensus_net::dispatch_compact_body_reply(
                                    &peer_key,
                                    ConsensusMsg::Body { body },
                                    &counters,
                                    |peer, msg| async move {
                                        match net_unicast.send_to_peer(peer, &msg).await {
                                            Ok(()) => Ok(()),
                                            Err(e) => Err((msg, e)),
                                        }
                                    },
                                    |msg| {
                                        enqueue_outbox(&mut st.outbox, msg);
                                        flush_outbox(
                                            &cfg.net_sender,
                                            &mut st.outbox,
                                            hc_height,
                                            hc_round,
                                        );
                                        step.outbox_flushes += 1;
                                        st.last_flush = std::time::Instant::now();
                                    },
                                )
                                .await;
                                if let stellereum::consensus_net::BodyReplyRoute::BoundedBroadcast(
                                    why,
                                ) = route
                                {
                                    tracing::debug!(
                                        "[consensus] compact body reply #{} r{} used the bounded broadcast ({why:?})",
                                        pull.height,
                                        pull.round,
                                    );
                                }
                                st.compact_served += 1;
                                if st.compact_served == 1 {
                                    info!(
                                        "[consensus] compact gossip LIVE: first body pull served from the announced block"
                                    );
                                }
                            }
                            // We did not announce that block, or this
                            // (peer, pull) was already answered: silence.
                            Ok(None) => {}
                            Err(why) => {
                                st.inbound_compact_refused += 1;
                                if st.inbound_compact_refused % 20 == 1 {
                                    tracing::warn!(
                                        "[consensus] refused compact body pull #{} r{}: {why}",
                                        pull.height,
                                        pull.round,
                                    );
                                }
                            }
                        }
                    }
                    // Complete a parked resolution with the served body.
                    ConsensusMsg::Body { body } => {
                        let over = {
                            let count = st.compact_peer_frames.entry(peer_key.clone()).or_insert(0);
                            !compact_frame_within_peer_budget(
                                count,
                                COMPACT_FRAMES_PER_PEER_PER_TICK,
                            )
                        };
                        if over {
                            st.compact_budget_dropped += 1;
                            continue;
                        }
                        // Cheap first: no parked proposal => no mempool
                        // clone and no index build (C2/F-8).
                        let Some(header) = st.compact_rx.parked_header(&body.block_hash).cloned()
                        else {
                            st.inbound_compact_refused += 1;
                            tracing::debug!(
                                "[consensus] compact body for an un-parked proposal {} (ignored before mempool work)",
                                hex::encode(&body.block_hash[..6]),
                            );
                            continue;
                        };
                        let now = Instant::now();
                        let cached = st.compact_index.get(&header, now).is_some();
                        let index = if cached {
                            st.compact_index.get(&header, now).expect("just checked")
                        } else {
                            let txs = st.rt.mempool.read().await.all();
                            st.compact_index.insert(&header, txs, now)
                        };
                        let inbound = st.compact_rx.on_body_indexed(&body, index);
                        settle_compact!(inbound, &peer_key);
                    }
                    ConsensusMsg::Proposal {
                        round: r, block, ..
                    } => {
                        info!(
                            "[consensus] RX proposal from {} #{} r{}",
                            hex::encode(&block.proposer[..6]),
                            block.height,
                            r
                        );
                        // Deliberately NOT advancing our round to match a peer's
                        // claim. A node advances rounds on its own 3s timeout
                        // (next_round), and nothing else. Syncing to a peer's
                        // claimed round sounds harmless but is what wedged the
                        // two-machine stand: one node timed out a round before the
                        // other, the follower adopted the leader's round, the
                        // leader then timed out again, and they drifted apart by
                        // one round permanently. At an offset of one, each
                        // expects the other to propose, every proposal is refused
                        // as "wrong proposer", the follower prevotes nil, and no
                        // prevote+precommit quorum for the same block ever forms.
                        // Local timeouts are the single source of round changes.
                        let proposer = block.proposer;
                        let height = block.height;
                        let round_of_block = r;
                        // Signature + membership check, computed ONLY when a
                        // consumer below needs it (a future proposal, the
                        // H+1 parent hint, or a behind peer). A proposal at
                        // OUR height is verified inside `on_proposal`, so
                        // the normal path pays no extra Falcon verification.
                        let needs_attribution = named_ahead.is_some()
                            || height < st.rt.hc.height
                            || (height == st.rt.hc.height + 1 && !st.rt.has_pending_apply());
                        let proposal_admissible = !needs_attribution
                            || stellereum::consensus_net::proposal_hint_admissible(
                                &block,
                                &st.rt.validators,
                            );
                        // Height-ahead deferral: peer finalized and proposed for H+1 while
                        // we are still applying H (or in tick transition). Defer instead of
                        // dropping, so H+1 proposals execute immediately on the next tick!
                        if height == st.rt.hc.height + 1 {
                            if st.rt.has_pending_apply() {
                                if st.inbound_deferred.len() < INBOUND_DEFERRED_CAP {
                                    let wake_at = Instant::now() + Duration::from_millis(10);
                                    let pos = st
                                        .inbound_deferred
                                        .iter()
                                        .position(|(w, _)| *w > wake_at)
                                        .unwrap_or(st.inbound_deferred.len());
                                    st.inbound_deferred.insert(pos, (wake_at, raw));
                                }
                                continue 'drain;
                            } else if block.height > 0 {
                                // We are not applying H: we missed block H! Record peer hint immediately
                                // so try_catch_up can pull block H without waiting.
                                //
                                // VERIFICATION G1: the hint forces the
                                // catch-up machine to run, so it must be
                                // attributable — only a proposal with a valid
                                // proposer signature from a staked member
                                // plants it. A forged H+1 proposal previously
                                // set this before any verification, keeping
                                // the node on loudly-failing DHT walks.
                                if proposal_admissible {
                                    let h = (block.height - 1, block.prev_hash);
                                    if st.rt.peer_hint.map(|(ph, _)| ph < h.0).unwrap_or(true) {
                                        st.rt.peer_hint = Some(h);
                                        st.peer_hint_at = Some(std::time::Instant::now());
                                    }
                                }
                            }
                        }
                        // REACTIVE CATCH-UP TRIGGER (proposal): a VERIFIED
                        // proposal for a height above ours proves its author
                        // advanced ahead of us (it is building where we have
                        // not arrived). Same admissibility verdict as the
                        // parent hint above, so a forged far-ahead proposal
                        // can never drive DHT work. The latch is consumed at
                        // the NEXT tick top, not on the backstop timer.
                        if named_ahead.is_some() && proposal_admissible {
                            // A proposal AT height H says the author's
                            // FINALIZED tip is at least H-1 (the parent it
                            // builds on) — that is the at-tip evidence.
                            let tip = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                            st.peer_named_height = clamp_peer_evidence_height(
                                tip,
                                st.peer_named_height.max(height.saturating_sub(1)),
                            );
                            st.catchup_pending = true;
                            stellereum::rpc::note_peer_height(height);
                        }
                        // Behind-peer retro gate: a VERIFIED proposal
                        // (signature + membership) from below our height
                        // proves a lagging peer is talking — the only
                        // consumer a retro push can serve.
                        if height < st.rt.hc.height && proposal_admissible {
                            st.last_behind_peer_seen = Some(std::time::Instant::now());
                        }
                        let round_before_proposal = st.rt.hc.round;
                        match st.rt.on_proposal(proposer, block, round_of_block).await {
                            Ok(_) => {
                                // VEL-2 vote-fan-in pipeline: vote in the SAME
                                // drain instead of waiting for the next tick's
                                // prevote step, overlapping the r-prevote
                                // fan-in with the proposal processing that
                                // triggered it. Timing-only: the vote content
                                // is identical to what the next-tick step
                                // would cast (same round — no timeout fires
                                // mid-drain — same live proposal, same lock,
                                // same `make_prevote`), the once-per-round
                                // dedup (`last_prevoted`) is shared with that
                                // step so no double vote is possible, and QCs
                                // stay strictly per-round, so quorum
                                // intersection is untouched: earlier arrival
                                // can only form the same QC sooner, never a
                                // different one. Refused proposals (the Err
                                // arm) never vote.
                                let cast_round = st.rt.prevote_round();
                                if can_vote
                                    && st.rt.hc.has_live_proposal()
                                    && st.last_prevoted != Some((st.rt.hc.height, cast_round))
                                    && !round_at_or_below_vote_floor(
                                        st.vote_floor,
                                        st.rt.hc.height,
                                        cast_round,
                                    )
                                {
                                    if let Some(v) = st.rt.make_prevote() {
                                        advance_vote_floor(&mut st.vote_floor, v.height, v.round);
                                        if let Err(e) = st.rt.on_prevote(v.clone()) {
                                            tracing::warn!(
                                                height = v.height,
                                                round = v.round,
                                                error = %e,
                                                "[consensus] own fast-path prevote admission failed"
                                            );
                                        }
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
                                        let voted_round = v.round;
                                        st.cast_prevote = Some(v);
                                        st.last_prevoted = Some((st.rt.hc.height, voted_round));
                                    }
                                }
                            }
                            Err(e) => {
                                // Never swallow this: a rejected proposal is the
                                // difference between liveness and a silent stall.
                                tracing::warn!(
                                    "[consensus] rejected proposal from {} at #{} r{}: {}",
                                    hex::encode(&proposer[..6]),
                                    height,
                                    round_of_block,
                                    e
                                );
                            }
                        }
                        // NEAR-FUTURE ALIGNMENT IS A ROUND CHANGE: a genuine
                        // body signed at a later round carries us there
                        // inside `on_proposal` (`sync_round_to`). Without
                        // restarting the timer the next tick's elapsed-time
                        // check can fire immediately and view-change past the
                        // proposal we just voted. Same rule as the vote
                        // chase above, accepted or refused (the round moved
                        // either way).
                        if round_timer_should_restart(round_before_proposal, st.rt.hc.round, false)
                        {
                            st.round_started = std::time::Instant::now();
                        }
                    }
                    ConsensusMsg::Vote { vote: v, locked } => {
                        info!(
                            "[consensus] RX {:?} from {} #{} r{} target {}",
                            v.kind,
                            hex::encode(&v.voter[..6]),
                            v.height,
                            v.round,
                            v.block_hash
                                .map(|h| hex::encode(&h[..4]))
                                .unwrap_or_else(|| "nil".into())
                        );
                        // Audit F2/F9: authenticate FIRST. `on_prevote` /
                        // `on_precommit` run `Vote::verify` plus the
                        // membership/scope checks inside `VoteSet::add`. An
                        // unauthenticated (height, round) or lock hint must
                        // NEVER reach the round counter: a Batch of 32 junk
                        // votes previously moved our round up to 2048 rounds
                        // (MAX_SYNC_JUMP=64 each) with zero signatures, and a
                        // forged nil prevote could plant a lock hint.
                        let (vh, vk, vr, vbh, voter) =
                            (v.height, v.kind, v.round, v.block_hash, v.voter);
                        // Height-ahead deferral: peer cast a vote for H+1 while
                        // we are still finishing H. Defer so it applies immediately on H+1!
                        if vh == st.rt.hc.height + 1 && st.rt.has_pending_apply() {
                            if st.inbound_deferred.len() < INBOUND_DEFERRED_CAP {
                                let wake_at = Instant::now() + Duration::from_millis(10);
                                let pos = st
                                    .inbound_deferred
                                    .iter()
                                    .position(|(w, _)| *w > wake_at)
                                    .unwrap_or(st.inbound_deferred.len());
                                st.inbound_deferred.insert(pos, (wake_at, raw));
                            }
                            continue 'drain;
                        }
                        let round_before = st.rt.hc.round;
                        let vcopy = v.clone();
                        let accepted = match vk {
                            VoteKind::Prevote => st.rt.on_prevote(v).is_ok(),
                            VoteKind::Precommit => st.rt.on_precommit(v).is_ok(),
                        };
                        // Falcon verification is the expensive part and the
                        // refusal branches below only need the VERDICT:
                        // signature plus staked membership. ACCEPTED votes
                        // were already verified inside
                        // `on_prevote`/`on_precommit`, so this runs on the
                        // refusal path only (unchanged cost profile).
                        if !accepted {
                            let late_recorded = vk == VoteKind::Precommit
                                && vh.checked_add(1) == Some(st.rt.hc.height)
                                && st.rt.record_late_parent_precommit(&vcopy);
                            let vote_verified = late_recorded
                                || (vcopy.verify() && st.rt.validators.power_of(&vcopy.voter) != 0);
                            // Scope/signature failure: the vote does NOT count
                            // toward any quorum. BUT a verified same-height
                            // vote still feeds the peer-round counter
                            // (`ValidatorRuntime::observe_peer_vote` already
                            // ran inside `on_prevote`/`on_precommit`): a
                            // stale far-behind vote or an absurd far-ahead
                            // vote is true information about where the peer
                            // is, and dropping it is what wedged A r1550 vs
                            // B r318 forever (live 2026-10-14). Only verified
                            // votes update liveness/timer state here.
                            if vh == st.rt.hc.height && vote_verified {
                                // Verified same-height vote (down-proposer
                                // fast timeout): the voter is provably alive
                                // right now, even though this vote itself is
                                // not votable (stale round / too far ahead).
                                st.votes_seen_voters.insert(vcopy.voter);
                                st.peer_round_seen = Some((vh, vr, std::time::Instant::now()));
                                if round_timer_should_restart(round_before, st.rt.hc.round, false) {
                                    st.round_started = std::time::Instant::now();
                                }
                            }
                            // REACTIVE CATCH-UP TRIGGER (vote): a verified
                            // vote at a height above ours proves the voter's
                            // chain is ahead — it is voting where we have not
                            // arrived. Signature + membership checked, so an
                            // unverified claim never drives DHT work.
                            if named_ahead.is_some() && vote_verified {
                                // A vote AT height H says the voter has
                                // decided H-1 at least — at-tip evidence.
                                let tip = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                                st.peer_named_height = clamp_peer_evidence_height(
                                    tip,
                                    st.peer_named_height.max(vh.saturating_sub(1)),
                                );
                                st.catchup_pending = true;
                                stellereum::rpc::note_peer_height(vh);
                            }
                            // Behind-peer retro gate: a VERIFIED vote from
                            // below our height proves a lagging peer is
                            // talking — the only consumer a retro push can
                            // serve. Forged votes never land here (unverified),
                            // so an attacker cannot wake retro — worst case a
                            // real behind peer keeps it awake.
                            if vh < st.rt.hc.height && vote_verified {
                                st.last_behind_peer_seen = Some(std::time::Instant::now());
                            }
                            continue;
                        }
                        // Verified-only height fast path: this vote passed
                        // signature + membership + scope checks, so a height
                        // above ours proves a peer finalized ahead of us.
                        // (Down-proposer fast timeout: an ACCEPTED vote is the
                        // strongest aliveness proof — record the voter before
                        // any of the bookkeeping below.)
                        if vh == st.rt.hc.height {
                            st.votes_seen_voters.insert(voter);
                        }
                        // Behind-peer retro gate: an ACCEPTED vote passed
                        // signature + membership + scope, so a height below
                        // ours proves a lagging peer is talking — stamp it.
                        if vh < st.rt.hc.height {
                            st.last_behind_peer_seen = Some(std::time::Instant::now());
                        }
                        // REACTIVE CATCH-UP TRIGGER (vote): an ACCEPTED vote
                        // for a height above ours is attributable evidence
                        // that the network moved on. Latch it; the next tick
                        // top runs the catch-up instead of waiting out the
                        // backstop interval while we burn view changes
                        // collecting "wrong height".
                        if named_ahead.is_some() {
                            let tip = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                            st.peer_named_height = clamp_peer_evidence_height(
                                tip,
                                st.peer_named_height.max(vh.saturating_sub(1)),
                            );
                            st.catchup_pending = true;
                            stellereum::rpc::note_peer_height(vh);
                        }
                        // A nil prevote carrying the sender's locked hash is a
                        // rescue request: it is stuck on one of OUR values.
                        // `note_lock_hint` resolves the (possibly older)
                        // signed hash to the round-free value id and records
                        // the demand; our next proposer slot re-stamps that
                        // value at the current round (see
                        // `ValidatorRuntime::propose`).
                        st.rt.note_lock_hint(vh, vk, vbh, locked);
                        // Adopt a peer's round when it is ahead, so the two stay in the
                        // same PHASE.
                        //
                        // This is subtle with an even validator count. `proposer_for`
                        // hash-schedules per round, so two validators walking their
                        // rounds independently still meet rounds where neither is
                        // the scheduled proposer while each waits for a proposal
                        // in its own round: every proposal is rejected as
                        // "wrong proposer", and the height never finalises --
                        // observed live as r78/r73, r80/r75, all "wrong proposer",
                        // forever. (Pre-hash-slot the schedule even alternated by
                        // round parity, making opposite phases PERMANENT.)
                        //
                        // Catching up one round at a time cannot fix that, because the
                        // offset (and its parity) is preserved. A node must move to the
                        // round its peers are in. `sync_round_to` is bounded (to
                        // ROUND_LOOKBACK rounds per message) and only moves forward,
                        // so this cannot drag a node backwards or jump it unreachably
                        // far; it only runs for a vote that already verified.
                        if vh == st.rt.hc.height {
                            st.peer_round_seen = Some((vh, vr, std::time::Instant::now()));
                            // SAME-VALUE COHERENCE: a vote for the body we
                            // already hold pulls us to the round the
                            // network is voting it in, and keeps the
                            // proposal live there; other votes use the
                            // conservative corroborated chase.
                            let drain_moved = st.rt.note_peer_vote_round_for(vh, vr, vbh);
                            // The round may ALSO have moved inside
                            // `on_prevote`/`on_precommit` above (they run
                            // the same future-round chase). Restart on ANY
                            // observed movement: restarting only when this
                            // follow-up reports a move left the timer at the
                            // OLD round's origin, so the very next tick
                            // view-changed straight past the peer it had
                            // just aligned with (live: 269ms after syncing).
                            if round_timer_should_restart(round_before, st.rt.hc.round, drain_moved)
                            {
                                st.round_started = std::time::Instant::now();
                            }
                        }
                    }
                    ConsensusMsg::Committed {
                        height,
                        block,
                        certificate,
                    } => {
                        // PUSH-BASED PROPAGATION, receive side: a commit for
                        // a height ABOVE ours is peer evidence that the
                        // network finalized ahead of us. It cannot be adopted
                        // in place (`adopt_committed` requires OUR exact next
                        // height), so schedule catch-up NOW — reacting to the
                        // push is the whole point; waiting for the backstop
                        // timer is what stranded lagging nodes.
                        //
                        // ATTRIBUTION: only a commit whose certificate is a
                        // precommit quorum for THIS height and block, under
                        // the validator set in force at that height, may
                        // drive DHT work (and plant the head hint). A forged
                        // far-ahead commit is ignored here.
                        //
                        // "Above ours" is measured against our FINALIZED TIP,
                        // not `hc.height`: a commit for the height we are
                        // currently voting on is still one block ahead of what
                        // we have decided (and adopt refuses it when it does
                        // not extend our tip — the refusal must not strand
                        // us on the backstop timer).
                        let our_tip = st.rt.finalized.last().map(|(h, _)| *h).unwrap_or(0);
                        if height > our_tip {
                            // CHEAP HEIGHT GATE FIRST (F-5): `Committed` is
                            // byte-limiter-exempt and may carry a 32 MiB
                            // block plus thousands of µQC markers. A
                            // far-ahead height is not adoptable under ANY
                            // certificate (`adopt_committed` refuses it), so
                            // the BODY is never hashed on that path.
                            //
                            // LIVENESS (live 2026-11-23, nodeC): this arm
                            // used to `continue` BEFORE recording anything,
                            // so a far-behind node whose only inbound
                            // evidence was far-ahead commits learned NO head
                            // at all. It then fell back to a DHT head read
                            // that returned its own stale echo and a tip+1
                            // QC probe whose sidecar was pruned — never the
                            // snapshot path — and sat at its old height for
                            // hours. A commit's QC is a quorum-signed
                            // statement about `(height, block_hash)`, so it
                            // can be verified WITHOUT the body: the
                            // certificate signs its own `block_hash`, not
                            // the 32 MiB blob. That verified head is exactly
                            // what catch-up needs.
                            let cheap = committed_height_is_cheaply_relevant(our_tip, height);
                            let attested_hash = if cheap {
                                let block_hash = block.compute_hash();
                                (certificate.kind == VoteKind::Precommit
                                    && certificate.height == height
                                    && certificate.block_hash == Some(block_hash)
                                    && certificate.verify_with_schedule(
                                        &st.rt.validator_set_for_height(height),
                                        st.rt.committee_schedule_at(height),
                                    ))
                                .then_some(block_hash)
                            } else {
                                // Far ahead: verify the QC's OWN signed
                                // block-hash binding (no body hashing, no
                                // body/QC equality check). Adoption later
                                // still requires the walked body to match
                                // this hash and every block is re-verified.
                                match certificate.block_hash {
                                    Some(bh)
                                        if certificate.kind == VoteKind::Precommit
                                            && certificate.height == height
                                            && certificate.shard_id == cfg.block_shard
                                            && block.shard_id == cfg.block_shard
                                            && certificate.verify_with_schedule(
                                                &st.rt.validator_set_for_height(height),
                                                st.rt.committee_schedule_at(height),
                                            ) =>
                                    {
                                        Some(bh)
                                    }
                                    _ => None,
                                }
                            };
                            if let Some(attested_hash) = attested_hash {
                                // The certificate DECODED and VERIFIED
                                // (precommit kind + height + a signed block
                                // hash + quorum under the set in force at
                                // this height): the `_hq_` sidecar for this
                                // height is now known, so lift any miss
                                // cooldown. `clear_qc_backoff` is only ever
                                // called on such a validated QC, never on a
                                // hint.
                                cfg.adapter.clear_qc_backoff(cfg.block_shard, height);
                                st.peer_named_height = clamp_peer_evidence_height(
                                    our_tip,
                                    st.peer_named_height.max(height),
                                );
                                // VERIFIED far-ahead head: retain it as
                                // catch-up evidence (the 64-height
                                // pre-hash gate must never delete it — that
                                // was nodeC's permanent stall). The hint
                                // carries the QC-signed hash so the walk
                                // anchors on exactly the decided head.
                                let accept =
                                    st.rt.peer_hint.map(|(ph, _)| ph < height).unwrap_or(true);
                                if let Some(h) = verified_head_hint(our_tip, height, attested_hash)
                                    .filter(|_| accept)
                                {
                                    st.rt.peer_hint = Some(h);
                                    st.peer_hint_at = Some(std::time::Instant::now());
                                }
                                st.catchup_pending = true;
                                stellereum::rpc::note_peer_height(height);
                                info!(
                                    "[sync][push] peer committed #{height} ahead of our tip #{our_tip}: catch-up scheduled for the next tick"
                                );
                                // A far-ahead commit can only be EVIDENCE
                                // (adopt requires our exact next height);
                                // skip the pointless adopt/bind work.
                                if !cheap {
                                    continue;
                                }
                            } else if !cheap {
                                st.inbound_overcap_count += 1;
                                if st.inbound_overcap_count % 20 == 1 {
                                    tracing::warn!(
                                        "[sync][push] ignoring far-ahead commit #{height} (tip #{our_tip}, max lookahead {MAX_COMMITTED_LOOKAHEAD}) without a verifying QC; {} time(s)",
                                        st.inbound_overcap_count
                                    );
                                }
                                continue;
                            } else {
                                tracing::debug!(
                                    "[sync][push] ignoring commit at #{height} above our tip #{our_tip}: certificate does not prove it"
                                );
                            }
                        }
                        // §7 Phase 2: adopting means executing, and the worker
                        // is still applying the decided height. The message is
                        // dropped, not queued: the peer rebroadcasts the commit
                        // at its next finalize and the periodic catch-up
                        // re-walks the same body, so a one-tick deferral loses
                        // nothing and can never double-apply a height.
                        if st.rt.has_pending_apply() {
                            // PARK, do not drop: `adopt_committed` sees the
                            // in-flight apply and parks this commit in its
                            // bounded one-slot buffer (returning the
                            // "parked for replay" error). The replay hook
                            // after `try_poll_apply` re-runs every check.
                            //
                            // Only the NEXT height survives the replay: the
                            // install advances us to `hc.height + 1`, so a
                            // commit for H+1 is exactly the one the replay
                            // can adopt. Parking the CURRENT (already
                            // executing) height would instead sit in the
                            // one-slot buffer and be dropped, evicting the
                            // useful H+1 copy.
                            if commit_parkable_during_apply(st.rt.hc.height, height) {
                                let _ = st
                                    .rt
                                    .adopt_committed(height, block.clone(), certificate.clone())
                                    .await;
                            }
                            info!(
                                "[consensus] deferring peer commit at #{height}: apply still in flight (parked for replay)"
                            );
                            continue;
                        }
                        // A peer already committed this height. Adopt it (after
                        // checking the certificate) so a node that missed the
                        // deciding vote does not stall behind the network.
                        // `adopt_committed` checks the certificate against our own
                        // validator set internally, so a peer cannot nominate the
                        // quorum it is measured against.
                        match st
                            .rt
                            .adopt_committed(height, block.clone(), certificate)
                            .await
                        {
                            Ok(bh) => {
                                // QC verified inside adopt and the block
                                // applied: any `_hq_` miss cooldown for
                                // this height is obsolete.
                                cfg.adapter.clear_qc_backoff(cfg.block_shard, height);
                                {
                                    let pq_reg = st.rt.state.pq_registry_read().await;
                                    let active =
                                        stellereum::pq_registry::pq_lifecycle_active_at(height);
                                    if active || !pq_reg.is_empty() {
                                        stellereum::consensus::sync_committed_pq_registry(
                                            &pq_reg, active,
                                        );
                                    }
                                }
                                // Verified commit (QC checked inside adopt):
                                // feed the syncing signal too (audit follow-up).
                                stellereum::rpc::note_peer_height(height);
                                // The live flow just delivered: stamp it so the
                                // tick-top defer above keeps the DHT machine off
                                // these heights even when the next Committed is
                                // still in transit at the next tick top.
                                st.last_live_adopt = std::time::Instant::now();
                                // LIVE-ADOPT PUBLISH OFFLOAD (observer C, 2026-10-13):
                                // `store_blob` can wait seconds for a replica. Awaited
                                // here it held the drain while more Committed messages
                                // queued behind it — ~30s/block at 1 block/s chain tempo
                                // on empty blocks (execution trivial, publishes dominant).
                                // Same order as the finalize path (body then header),
                                // but on `publish_lane`: the tick keeps draining and the
                                // next height adopts immediately.
                                if let Some(body) = st.rt.blocks.get(&bh).cloned() {
                                    let is_proposer = body.proposer == cfg.self_vote_id;
                                    let validator_count = st.rt.validators.len();
                                    let publish_body = should_publish_body_now(
                                        validator_count,
                                        is_proposer,
                                        height,
                                    );
                                    let publish_header = should_publish_header_now(
                                        validator_count,
                                        is_proposer,
                                        height,
                                    );
                                    if publish_body || publish_header {
                                        let a = cfg.adapter.clone();
                                        let shard_id = cfg.block_shard;
                                        cfg.publish_lane.submit(async move {
                                            if publish_body {
                                                let _ = a.retro_publish_blocks([&body], 1).await;
                                            }
                                            if publish_header {
                                                a.persist_block_header(shard_id, &body).await;
                                            }
                                        });
                                    }
                                }
                                // Replication for adopters (bodies + receipts):
                                // the adopted block carries its transactions
                                // (adopt verified their signatures) and
                                // `rt.applied_statuses` holds THIS application's
                                // outcome (set by adopt's apply_and_advance).
                                // File both so adopters serve real txs/receipts
                                // instead of txs=0. Verified data only: the
                                // block passed adopt_committed's QC/proposer/
                                // root checks. Records ride `record_lane` (the
                                // same FIFO the finalize path uses: receipts
                                // before the block summary inside one job,
                                // heights in order across jobs) instead of two
                                // contended write locks awaited inline while
                                // more Committed messages queue behind them.
                                // The body itself is persisted by
                                // `enqueue_block` below (async, finalize-path
                                // parity): the synchronous sled
                                // `committed_body` + `put_verified_block` round
                                // trip that used to sit here re-hashed the block
                                // twice and held the drain on disk I/O for bytes
                                // the queue already carries. A not-yet-persisted
                                // body is an honest serve-miss (fetch covers it),
                                // never fabricated data.
                                let adopted_post_root = st.rt.state.get_state_root().await;
                                if let Some(ap) = &cfg.persistence {
                                    let store = ap.storage();
                                    let _ =
                                        store.put_finalized_post_root(height, adopted_post_root);
                                }
                                if st.rt.applied_statuses.len() == block.transactions.len() {
                                    let r = cfg.rpc.clone();
                                    let txs = block.transactions.clone();
                                    let statuses = st.rt.applied_statuses.clone();
                                    let fees = st.rt.applied_fees.clone();
                                    let events = st.rt.applied_events.clone();
                                    let ts = block.timestamp;
                                    let hdr = block.clone();
                                    let persist_store =
                                        cfg.persistence.as_ref().map(|ap| ap.storage());
                                    let is_mc =
                                        cfg.block_shard == stellereum::sharding::MASTERCHAIN_SHARD;
                                    let block_shard = cfg.block_shard;
                                    cfg.record_lane.submit(async move {
                                        // LIGHT CLIENT (audit W8.3): the
                                        // adopted header's quorum certificate
                                        // is what makes its state root
                                        // externally verifiable.
                                        r.record_finalized_header(&hdr).await;
                                        r.record_adopted_block_with_events(
                                            height, bh, &txs, &statuses, &fees, &events, ts,
                                        )
                                        .await;
                                        // GEYSER-LITE DELTAS: same contract
                                        // as the finalize path — publish the
                                        // block's real account deltas and
                                        // token transfers OUTSIDE the
                                        // receipts/head write locks, through
                                        // the non-blocking fan-out.
                                        stellereum::rpc::publish_block_deltas(
                                            height,
                                            bh,
                                            block_shard,
                                            &txs,
                                            &statuses,
                                        );
                                        if is_mc {
                                            if let Some(store) = persist_store {
                                                let exec_hardening =
                                                    stellereum::chain_spec::exec_hardening_v1_active_at(height);
                                                for (i, tx) in txs.iter().enumerate() {
                                                    if !statuses.get(i).copied().unwrap_or(false) {
                                                        continue;
                                                    }
                                                    if let Some((evm, pq)) =
                                                        stellereum::evm_adapter::verified_binding_from_tx_at(
                                                            tx,
                                                            exec_hardening,
                                                        )
                                                    {
                                                        let _ = store.put_evm_binding_if_absent(
                                                            &evm, &pq,
                                                        );
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
                                    eprintln!(
                                        "[repl] adopt #{}: statuses {}/{} txs, receipts skipped",
                                        height,
                                        st.rt.applied_statuses.len(),
                                        block.transactions.len()
                                    );
                                }
                                info!(
                                    "[consensus] adopted committed block #{} {} from a peer",
                                    height,
                                    hex::encode(&bh[..6])
                                );
                                // New height, new round timer: an adopted block
                                // advanced us without a view change, so a stale
                                // timer would fire a view change within
                                // milliseconds and drop the peer's first vote
                                // (live: 269ms from adopt to view change).
                                st.round_started = std::time::Instant::now();
                                // Persist adopted bodies + finalized pointer synchronously
                                // (with embedded precommit QC from `rt.blocks` and flush)
                                // instead of queuing an async `Finalized` job: eliminates
                                // multi-block lag and prevents out-of-order queue writes
                                // from regressing `storage.finalized()` behind `safety_record_v1`.
                                if let Some(ap) = &cfg.persistence {
                                    let adopted_block =
                                        st.rt.blocks.get(&bh).cloned().unwrap_or(block);
                                    if let Err(e) = write_ahead_finalized_block(
                                        ap,
                                        height,
                                        bh,
                                        adopted_block,
                                        true,
                                    )
                                    .await
                                    {
                                        tracing::error!(
                                            height,
                                            error = %e,
                                            "[storage] adopted block synchronous persist failed"
                                        );
                                    }
                                    if height.is_multiple_of(25) {
                                        ap.enqueue_validator_set_history(
                                            st.rt.export_validator_set_history(),
                                        );
                                        ap.request_flush();
                                    }
                                }
                            }
                            Err(e) => {
                                info!("[consensus] refused peer commit at #{}: {}", height, e)
                            }
                        }
                    }
                }
            }
        }
    }
    // SEC-06: deferred messages already reside in `inbound_deferred` with
    // their scheduled `wake_at` times; no re-parking needed.
}
