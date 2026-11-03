//! Audit-network close-out (2026-10-14): one pin per finding in
//! `/home/imm/audit-network.md` that this mission owns.
//!
//! NEW file only (mission rule: never edit shared tests). All policy is
//! exercised through public lib APIs with synthetic clocks/sleeps — no node,
//! no network, no env mutation (parse helpers take `Option<String>`).

use std::time::{Duration, Instant};
use stellereum::bootstrap::{
    next_boundary_after_stale, select_bootstrap_boundary, BOOTSTRAP_SNAPSHOT_GAP,
};
use stellereum::consensus::VoteKind;
use stellereum::consensus_net::{
    broadcast_join_timeout_ms, committed_height_of, cons_bcast_min_interval_ms,
    cons_probe_min_interval_ms, inbound_is_critical, join_should_dial, join_with_timeout, pace_due,
    pace_wait_ms, parse_broadcast_join_timeout_ms, parse_probe_evict_after, plan_peer_send,
    prioritize_inbound_for_verify, probe_evict_after, probe_timeout_should_evict, ConsensusMsg,
    InboundBulkLimiter, InboundDecision, SendPlan, VoteSendFilter,
    BROADCAST_JOIN_TIMEOUT_MS_DEFAULT, CONS_BCAST_MIN_INTERVAL_MS_DEFAULT,
    CONS_PROBE_MIN_INTERVAL_MS_DEFAULT, INBOUND_BULK_BURST_BYTES_DEFAULT,
    INBOUND_BULK_BYTES_PER_SEC_DEFAULT, PROBE_EVICT_AFTER_DEFAULT, VOTE_SEND_DEDUP_TTL_MS,
};
use stellereum::dns_seeds::{merge_seeds, parse_seed_domains, parse_txt_record, MAX_DNS_PEERS};
use stellereum::network::{
    dht_blob_ttl_ms, parse_repl_circuit_cooldown_ms, parse_repl_circuit_threshold,
    parse_repl_head_min_interval_ms, parse_repl_max_attempts, parse_repl_max_concurrent,
    parse_repl_min_interval_ms, parse_repl_store_timeout_ms, prune_batch, prune_below_exclusive,
    repl_lane_key, repl_retry_backoff_ms, repl_should_retry, ReplBackpressure, ReplPublishConfig,
    ReplStoreKind, REPL_CIRCUIT_COOLDOWN_MS_DEFAULT, REPL_CIRCUIT_THRESHOLD_DEFAULT,
    REPL_HEAD_MIN_INTERVAL_MS_DEFAULT, REPL_PUBLISH_MAX_CONCURRENT_DEFAULT,
    REPL_PUBLISH_MIN_INTERVAL_MS_DEFAULT, REPL_STORE_MAX_ATTEMPTS_DEFAULT,
    REPL_STORE_TIMEOUT_MS_DEFAULT,
};

fn test_vote(height: u64) -> ConsensusMsg {
    ConsensusMsg::Vote {
        vote: stellereum::consensus::Vote {
            height,
            round: 0,
            kind: VoteKind::Prevote,
            block_hash: None,
            voter: [height as u8; 32],
            signature: vec![0u8; 64],
        },
        locked: None,
    }
}

fn test_commit(height: u64) -> ConsensusMsg {
    ConsensusMsg::Committed {
        height,
        block: stellereum::sharding::Block {
            shard_id: 0,
            height,
            prev_hash: [1u8; 32],
            state_root: [2u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1,
            proposer: [3u8; 32],
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        },
        certificate: stellereum::consensus::QuorumCertificate {
            height,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    }
}

fn test_proposal(height: u64) -> ConsensusMsg {
    ConsensusMsg::Proposal {
        height,
        round: 0,
        block: stellereum::sharding::Block {
            shard_id: 0,
            height,
            prev_hash: [1u8; 32],
            state_root: [2u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1,
            proposer: [3u8; 32],
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        },
    }
}

// --- F1: inbound limiter is wired policy (admit Batch, bypass critical) ------
// POLICY (PENTEST F2 hardening): only `Committed` (the catch-up proof) bypasses
// the inbound byte limiter. Singleton votes/proposals are budget-checked like
// bulk gossip — the old `!matches!(Batch)` predicate let an attacker trickle
// singleton votes and burn verifications while the limiter saw nothing.

#[test]
fn f1_bulk_limiter_defers_flood_but_never_drops_and_bypasses_critical() {
    // Tiny bucket: 1000 B/s, 1000 B burst — one 512 KiB batch must defer.
    let mut lim = InboundBulkLimiter::new(1000, 1000);
    // Critical traffic (Committed catch-up proof only) always passes untouched.
    let c = test_commit(1);
    assert!(inbound_is_critical(&c));
    assert_eq!(
        lim.admit("peer", 512 * 1024, inbound_is_critical(&c), 0),
        InboundDecision::Allow,
        "critical must bypass the budget"
    );
    // Singleton votes/proposals are budget-checked, not exempt.
    for m in [test_vote(1), test_proposal(1)] {
        assert!(!inbound_is_critical(&m));
    }
    // Bulk Batch within burst passes once, then defers with a bounded hint.
    let batch = ConsensusMsg::Batch(vec![test_vote(1)]);
    assert!(!inbound_is_critical(&batch));
    assert_eq!(lim.admit("flood", 800, false, 0), InboundDecision::Allow);
    match lim.admit("flood", 800, false, 0) {
        InboundDecision::Defer { wait_ms } => {
            assert!(
                (1..=5_000).contains(&wait_ms),
                "bounded hint, got {wait_ms}"
            );
        }
        InboundDecision::Allow => panic!("second burst must defer"),
    }
    // Refill over time re-admits: deferral is scheduling, not parking.
    assert_eq!(
        lim.admit("flood", 100, false, 5_000),
        InboundDecision::Allow
    );
    // Per-peer isolation: another peer is unaffected by the flooder.
    assert_eq!(lim.admit("honest", 800, false, 0), InboundDecision::Allow);
}

#[test]
fn f1_limiter_defaults_and_memory_bound_hold() {
    assert_eq!(INBOUND_BULK_BYTES_PER_SEC_DEFAULT, 512 * 1024);
    assert_eq!(INBOUND_BULK_BURST_BYTES_DEFAULT, 1024 * 1024);
    let mut lim = InboundBulkLimiter::with_defaults();
    for i in 0..1100u32 {
        let _ = lim.admit(&format!("peer-{i}"), 10, false, 0);
    }
    assert!(lim.peer_count() <= 1024, "tracked peers must stay capped");
}

// --- F2: Committed priority lane --------------------------------------------

#[test]
fn f2_committed_sorts_first_and_never_counts_as_flood_tail() {
    let v1 = test_vote(1);
    let c9 = test_commit(9);
    let v2 = test_vote(2);
    let out = prioritize_inbound_for_verify(vec![v1, c9.clone(), v2]);
    assert!(matches!(out[0], ConsensusMsg::Committed { height: 9, .. }));
    assert_eq!(out.len(), 3, "nothing dropped, only reordered");
    // Stable within class: votes keep sender order.
    match (&out[1], &out[2]) {
        (ConsensusMsg::Vote { vote: a, .. }, ConsensusMsg::Vote { vote: b, .. }) => {
            assert_eq!((a.height, b.height), (1, 2));
        }
        _ => panic!("votes must follow the commit in order"),
    }
    assert_eq!(committed_height_of(&c9), Some(9));
    assert_eq!(committed_height_of(&test_vote(1)), None);
    assert_eq!(committed_height_of(&test_proposal(1)), None);
}

// --- F4: probe N-streak eviction + join backoff ------------------------------

#[test]
fn f4_probe_evicts_only_on_streak_and_parses_clamped() {
    assert_eq!(PROBE_EVICT_AFTER_DEFAULT, 3);
    assert_eq!(probe_evict_after(), 3, "default without env");
    assert!(
        !probe_timeout_should_evict(1, 3),
        "single timeout must NOT evict"
    );
    assert!(!probe_timeout_should_evict(2, 3));
    assert!(probe_timeout_should_evict(3, 3));
    assert!(probe_timeout_should_evict(9, 3));
    assert_eq!(parse_probe_evict_after(None), 3);
    assert_eq!(
        parse_probe_evict_after(Some("0".into())),
        3,
        "zero clamps to default"
    );
    assert_eq!(parse_probe_evict_after(Some("garbage".into())), 3);
    assert_eq!(parse_probe_evict_after(Some("2".into())), 2);
}

#[test]
fn join_backoff_cooldown_peers_get_no_dials() {
    assert!(join_should_dial(false), "live peer joins");
    assert!(!join_should_dial(true), "cooldown peer gets no join dial");
    // Same bit drives the send plan: normal payloads skip, exempt detaches.
    assert_eq!(plan_peer_send(true, false), SendPlan::Skipped);
    assert_eq!(plan_peer_send(true, true), SendPlan::Detached);
    assert_eq!(plan_peer_send(false, false), SendPlan::Joined);
    assert_eq!(plan_peer_send(false, true), SendPlan::Joined);
}

// --- Cooldown adversarial: dead peer NEVER delays live delivery -------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_peer_never_delays_live_delivery() {
    // Live peer answers in ~10ms; dead peer sleeps 500ms. Join budget 50ms:
    // the flush must return in well under the dead peer's stall with the live
    // result joined and the dead one detached (still running, never aborted).
    let live = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        "live-ok"
    });
    let dead = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        "dead-late"
    });
    let t = Instant::now();
    let (done, detached) = join_with_timeout(vec![live, dead], Duration::from_millis(50)).await;
    let took = t.elapsed();
    assert_eq!(done, vec!["live-ok"], "live delivery must join");
    assert_eq!(detached, 1, "dead peer detaches, never blocks");
    assert!(
        took < Duration::from_millis(400),
        "flush must not inherit the stall, took {took:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exempt_detach_keeps_catchup_off_the_joined_set() {
    // Models send_payload_with_skip: cooldown peer on an exempt (Committed)
    // payload is attempted DETACHED from the start — never in the joined set —
    // so a dead peer's stall cannot ride along on a catch-up send.
    assert_eq!(plan_peer_send(true, true), SendPlan::Detached);
    let fast = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        7u32
    });
    let (done, detached) = join_with_timeout(vec![fast], Duration::from_millis(50)).await;
    assert_eq!(done, vec![7u32]);
    assert_eq!(detached, 0);
}

// --- Live tempo pins (do NOT retune without measurement) --------------------

#[test]
fn tempo_sender_detach_budget_stays_500ms() {
    assert_eq!(BROADCAST_JOIN_TIMEOUT_MS_DEFAULT, 500);
    assert_eq!(broadcast_join_timeout_ms(), 500, "default without env");
    assert_eq!(parse_broadcast_join_timeout_ms(None), 500);
    assert_eq!(
        parse_broadcast_join_timeout_ms(Some("0".into())),
        500,
        "zero clamps"
    );
    assert_eq!(parse_broadcast_join_timeout_ms(Some("garbage".into())), 500);
    assert_eq!(parse_broadcast_join_timeout_ms(Some("250".into())), 250);
}

#[test]
fn tempo_pacing_floors_stay_put() {
    assert_eq!(CONS_BCAST_MIN_INTERVAL_MS_DEFAULT, 25);
    assert_eq!(CONS_PROBE_MIN_INTERVAL_MS_DEFAULT, 5_000);
    assert_eq!(cons_bcast_min_interval_ms(), 25);
    assert_eq!(cons_probe_min_interval_ms(), 5_000);
    // Pure pacing shape: due when never sent or floor elapsed.
    assert!(pace_due(None, 1_000, 25));
    assert!(!pace_due(Some(1_000), 1_010, 25));
    assert!(pace_due(Some(1_000), 1_025, 25));
    assert_eq!(pace_wait_ms(Some(1_000), 1_010, 25), 15);
    assert_eq!(pace_wait_ms(None, 1_010, 25), 0);
}

#[test]
fn tempo_c_slot_and_alignment_stay_put() {
    assert_eq!(
        stellereum::runtime::PROPOSAL_ALIGN_WINDOW_ROUNDS,
        8,
        "+8 alignment"
    );
    // Retransmit cadence at the live 800ms timeout: fast first retries, then
    // backoff, capped — loss recovery without thunder.
    assert_eq!(
        stellereum::consensus_net::retransmit_interval_ms(800, 0),
        400
    );
    assert_eq!(
        stellereum::consensus_net::retransmit_interval_ms(800, 10_000),
        1600
    );
}

#[test]
fn sent_votes_dedup_ttl_coalesces_then_recovers() {
    assert_eq!(
        VOTE_SEND_DEDUP_TTL_MS, 200,
        "shorter than the 400ms retransmit cadence"
    );
    let mut f = VoteSendFilter::new(Duration::from_millis(VOTE_SEND_DEDUP_TTL_MS));
    let v = test_vote(9);
    let p = test_proposal(9);
    let t0 = Instant::now();
    assert!(f.should_send(&v, t0), "first send always passes");
    assert!(
        !f.should_send(&v, t0 + Duration::from_millis(50)),
        "same-tick dup coalesces"
    );
    assert!(
        f.should_send(&p, t0 + Duration::from_millis(50)),
        "proposals never deduped"
    );
    assert!(
        f.should_send(&v, t0 + Duration::from_millis(1_000)),
        "retry past TTL recovers"
    );
}

// --- F7: replication lanes + 1vCPU defaults ----------------------------------

#[test]
fn f7_replication_defaults_sane_for_1vcpu() {
    let cfg = ReplPublishConfig::default();
    assert_eq!(cfg.max_concurrent, REPL_PUBLISH_MAX_CONCURRENT_DEFAULT);
    assert_eq!(cfg.max_concurrent, 4);
    assert_eq!(
        cfg.bulk_min_interval_ms,
        REPL_PUBLISH_MIN_INTERVAL_MS_DEFAULT
    );
    assert_eq!(cfg.bulk_min_interval_ms, 100, "~10 bulk/s sustained");
    assert_eq!(cfg.head_min_interval_ms, REPL_HEAD_MIN_INTERVAL_MS_DEFAULT);
    assert_eq!(cfg.head_min_interval_ms, 10, "pointers never lag the tip");
    assert_eq!(cfg.store_timeout_ms, REPL_STORE_TIMEOUT_MS_DEFAULT);
    assert_eq!(cfg.store_timeout_ms, 5_000);
    assert_eq!(cfg.max_attempts, REPL_STORE_MAX_ATTEMPTS_DEFAULT);
    assert_eq!(cfg.max_attempts, 3);
    assert_eq!(cfg.queue_wait_ms, 10_000);
    assert_eq!(cfg.pace_wait_ms, 5_000);
    assert_eq!(cfg.circuit_threshold, REPL_CIRCUIT_THRESHOLD_DEFAULT);
    assert_eq!(cfg.circuit_threshold, 5);
    assert_eq!(cfg.circuit_cooldown_ms, REPL_CIRCUIT_COOLDOWN_MS_DEFAULT);
    assert_eq!(cfg.circuit_cooldown_ms, 5_000);
    // Parsers clamp instead of disabling.
    assert_eq!(parse_repl_max_concurrent(None), 4);
    assert_eq!(parse_repl_min_interval_ms(None), 100);
    assert_eq!(parse_repl_head_min_interval_ms(None), 10);
    assert_eq!(parse_repl_store_timeout_ms(None), 5_000);
    assert_eq!(parse_repl_max_attempts(None), 3);
    assert_eq!(parse_repl_circuit_threshold(None), 5);
    assert_eq!(parse_repl_circuit_cooldown_ms(None), 5_000);
    // Retry ladder + attempt bound: never infinite, never hurried.
    assert_eq!(repl_retry_backoff_ms(1), 200);
    assert!(repl_should_retry(2, 3));
    assert!(!repl_should_retry(3, 3));
}

#[test]
fn f7_breaker_is_per_lane_not_overlay_global() {
    // Lane keys split by bucket AND kind: a slow body lane must not shed
    // pointers or other buckets.
    let body = repl_lane_key("stell_blocks", ReplStoreKind::Bulk);
    let head = repl_lane_key("stell_head", ReplStoreKind::Pointer);
    let other_bucket = repl_lane_key("stell_headers", ReplStoreKind::Bulk);
    assert_ne!(body, head);
    assert_ne!(body, other_bucket);
    assert_eq!(body, repl_lane_key("stell_blocks", ReplStoreKind::Bulk));
    // Breaker behaviour per lane: 5 consecutive timeouts open ONLY that lane.
    let mut bp = ReplBackpressure::new(4, 10.0, 100, 5, 5_000, 256);
    for _ in 0..5 {
        bp.record_timeout(&body, 0);
    }
    assert!(bp.in_cooldown(&body, 1_000), "slow lane sheds");
    assert!(!bp.in_cooldown(&head, 1_000), "pointer lane unaffected");
    assert!(
        !bp.in_cooldown(&other_bucket, 1_000),
        "other bucket unaffected"
    );
    // Success closes the lane immediately (half-open, no sticky shed).
    bp.record_success(&body);
    assert_eq!(bp.consec_timeouts(&body), 0);
    // Memory stays bounded under attacker-chosen keys.
    for i in 0..300u32 {
        bp.record_timeout(&format!("lane-{i}"), 0);
    }
    assert!(bp.peer_count() <= 256);
}

// --- F10/F-eclipse: DNS peers never mint consensus power ---------------------

fn ed_of(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn id_of(ed: &[u8; 32]) -> String {
    let h = blake3::hash(ed);
    format!("inf1:{}", hex::encode(&h.as_bytes()[..20]))
}

#[test]
fn dns_records_enforce_binding_cap_and_charset() {
    // Spoofed id (victim id + attacker key) rejected.
    let ed = ed_of(0x31);
    let other = id_of(&ed_of(0x32));
    assert!(parse_txt_record(&format!(
        "stellereum/v1 node_id={other} ed={} host=n.example port=9411",
        hex::encode(ed)
    ))
    .is_none());
    // Privileged ports rejected; sane record parses.
    let id = id_of(&ed);
    assert!(parse_txt_record(&format!(
        "stellereum/v1 node_id={id} ed={} host=n.example port=80",
        hex::encode(ed)
    ))
    .is_none());
    let rec = format!(
        "stellereum/v1 node_id={} ed={} host=node.example port=9411",
        id_of(&ed_of(0x51)),
        hex::encode(ed_of(0x51))
    );
    assert!(parse_txt_record(&rec).is_some());
    // Seed-domain parsing lowercases, drops junk, never panics.
    assert_eq!(
        parse_seed_domains(" Seeds.Example.Org , bad host! , a.b "),
        vec!["seeds.example.org".to_string(), "a.b".to_string()]
    );
}

#[test]
fn dns_merge_never_overflows_and_dedups_validator_ids() {
    // 50 records cap at 32; validator-id/keys dedup as duplicates.
    let mk = |seed: u8| stellereum::dns_seeds::DiscoveredPeer {
        node_id: id_of(&ed_of(seed)),
        ed_pub: ed_of(seed),
        x_pub: None,
        host: "n.example".into(),
        port: 9411,
    };
    let many: Vec<_> = (0..50u8).map(mk).collect();
    let r = merge_seeds(&[], many);
    assert_eq!(r.new_peers.len(), MAX_DNS_PEERS);
    assert_eq!(r.new_peers.len(), 32);
    assert_eq!(r.over_cap, 18);
    // A discovered record reusing a known ed key is a duplicate, never new.
    let cfg_peer = infnode::config::PeerConfig {
        name: "validator".into(),
        node_id: id_of(&ed_of(0x77)),
        ed_pub: hex::encode(ed_of(0x77)),
        x_pub: hex::encode(ed_of(0x78)),
        pq_pub: None, // GATE: classical-only fixture (no PQ identity announced)
        endpoints: vec!["127.0.0.1:9411".into()],
        allow: vec!["*".into()],
        rate_limit_per_sec: 0,
        role: None,
        storage_roles: vec![],
    };
    let mut spoof = mk(0x77);
    spoof.host = "evil.example".into();
    let r2 = merge_seeds(&[cfg_peer], vec![spoof]);
    assert!(
        r2.new_peers.is_empty(),
        "known validator key must not re-enter as new"
    );
    assert_eq!(r2.duplicates, 1);
}

// --- DHT retention/prune + snapshot-pointer trust ----------------------------

#[test]
fn dht_retention_prune_is_bounded_and_ttl_clamped() {
    assert_eq!(prune_below_exclusive(10_000, 8_000), 2_000);
    assert_eq!(prune_below_exclusive(100, 8_000), 0);
    let (batch, next) = prune_batch(0, 100_000, 64);
    assert!(batch.len() <= 64);
    assert!(next <= 100_000);
    // TTL is generous, never tight, clamped to [7d, 30d].
    const DAY: i64 = 24 * 3600 * 1000;
    assert_eq!(
        dht_blob_ttl_ms(8_000),
        (8_000i64 * 120_000).clamp(7 * DAY, 30 * DAY)
    );
    assert!(
        dht_blob_ttl_ms(1) >= 7 * DAY,
        "tiny KEEP cannot outrun the prune"
    );
    assert!(
        dht_blob_ttl_ms(u64::MAX) <= 30 * DAY,
        "huge KEEP cannot disable expiry"
    );
}

#[test]
fn bootstrap_boundary_mirrors_engine_and_steps_down_loudly() {
    assert_eq!(BOOTSTRAP_SNAPSHOT_GAP, 100, "mirrors the >100 walk gate");
    assert_eq!(
        select_bootstrap_boundary(50, 0, None),
        None,
        "walk-sized gap: no snapshot"
    );
    assert_eq!(select_bootstrap_boundary(72704, 0, None), Some(72700));
    assert_eq!(
        select_bootstrap_boundary(78620, 0, Some(78519)),
        Some(78519),
        "exact pointer wins"
    );
    assert_eq!(
        select_bootstrap_boundary(78620, 0, Some(99999)),
        Some(78600),
        "insane pointer ignored"
    );
    assert_eq!(
        next_boundary_after_stale(72700, 2, 0),
        Some(72700),
        "budget holds: retry"
    );
    assert_eq!(
        next_boundary_after_stale(72700, 3, 0),
        Some(72600),
        "budget spent: step down"
    );
    assert_eq!(
        next_boundary_after_stale(100, 3, 0),
        None,
        "floor refuses loudly"
    );
}
