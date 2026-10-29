//! Replication-backpressure regression suite (2026-10-14 storm).
//!
//! Live symptom: validator A was hammered by B with ~10-20 `dht.store`
//! reqs/sec sustained; every timed-out store was retried, retries added load,
//! load caused more timeouts — a mutual-DDoS feedback loop between two honest
//! nodes that stalled consensus. Fetch-side storm bounds (8-wide fetch lane,
//! 2-wide snapshot lane) already existed; replication PUBLISHES had no pacing.
//!
//! What this pins (local policy only, no wire-protocol change):
//! * `network::paced_store_blob` policy core — token-bucket pacing + min
//!   publish interval ([`ReplBackpressure`]), bounded retries with jittered
//!   backoff (never infinite, never silent), consecutive-timeout circuit
//!   breaking (short bounded cooldown, half-open recovery);
//! * `consensus_net` broadcast/probe pacing floors and the inbound bulk guard:
//!   votes/proposals/commits bypass the limiter, only bulk gossip is deferred —
//!   and deferral is scheduling with a bounded wait hint, never a silent drop.
//!
//! All policy is time-injected and deterministic: no sleeps, no network, the
//! whole suite runs in milliseconds.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{QuorumCertificate, Vote, VoteKind};
use stellereum::consensus_net::{
    inbound_bulk_burst_bytes, inbound_bulk_bytes_per_sec, inbound_is_critical, pace_due,
    pace_wait_ms, ConsensusMsg, InboundBulkLimiter, InboundDecision,
    CONS_BCAST_MIN_INTERVAL_MS_DEFAULT, CONS_PROBE_MIN_INTERVAL_MS_DEFAULT,
    INBOUND_BULK_BURST_BYTES_DEFAULT, INBOUND_BULK_BYTES_PER_SEC_DEFAULT,
    INBOUND_MAX_DEFER_WAIT_MS,
};
use stellereum::network::{
    parse_repl_circuit_cooldown_ms, parse_repl_circuit_threshold, parse_repl_head_min_interval_ms,
    parse_repl_max_attempts, parse_repl_max_concurrent, parse_repl_min_interval_ms,
    parse_repl_store_timeout_ms, repl_retry_backoff_ms, repl_retry_backoff_with_jitter_ms,
    repl_should_retry, ReplBackpressure, ReplPublishConfig, ReplStoreKind,
    REPL_CIRCUIT_COOLDOWN_MS_DEFAULT, REPL_CIRCUIT_THRESHOLD_DEFAULT,
    REPL_HEAD_MIN_INTERVAL_MS_DEFAULT, REPL_PUBLISH_MAX_CONCURRENT_DEFAULT,
    REPL_PUBLISH_MIN_INTERVAL_MS_DEFAULT, REPL_RETRY_JITTER_MAX_MS,
    REPL_STORE_MAX_ATTEMPTS_DEFAULT, REPL_STORE_TIMEOUT_MS_DEFAULT,
};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};

// ==================== network: defaults & env parsing ====================

#[test]
fn publish_defaults_are_sane_and_pinned() {
    // The anti-hammer shape: at most 4 concurrent stores (each spawns a
    // background replicator fan-out), sustained bulk at ~10/sec with burst
    // headroom, bounded attempts, short bounded breaker.
    let cfg = ReplPublishConfig::default();
    assert_eq!(cfg.max_concurrent, 4);
    assert_eq!(cfg.max_concurrent, REPL_PUBLISH_MAX_CONCURRENT_DEFAULT);
    assert_eq!(cfg.bulk_min_interval_ms, 100);
    assert_eq!(
        cfg.bulk_min_interval_ms,
        REPL_PUBLISH_MIN_INTERVAL_MS_DEFAULT
    );
    assert_eq!(cfg.head_min_interval_ms, 10);
    assert_eq!(cfg.head_min_interval_ms, REPL_HEAD_MIN_INTERVAL_MS_DEFAULT);
    assert_eq!(cfg.store_timeout_ms, 5_000);
    assert_eq!(cfg.store_timeout_ms, REPL_STORE_TIMEOUT_MS_DEFAULT);
    assert_eq!(cfg.max_attempts, 3);
    assert_eq!(cfg.max_attempts, REPL_STORE_MAX_ATTEMPTS_DEFAULT);
    assert_eq!(cfg.circuit_threshold, 5);
    assert_eq!(cfg.circuit_threshold, REPL_CIRCUIT_THRESHOLD_DEFAULT);
    assert_eq!(cfg.circuit_cooldown_ms, 5_000);
    assert_eq!(cfg.circuit_cooldown_ms, REPL_CIRCUIT_COOLDOWN_MS_DEFAULT);
    // Sustained bulk ceiling sits at/below the observed hammer floor (10/sec):
    // the loop cannot sustain what it could not pace.
    assert!(1000 / cfg.bulk_min_interval_ms <= 10);
    // Cooldown is SHORT (seconds, not minutes): honest replication recovers fast.
    assert!(cfg.circuit_cooldown_ms <= 10_000);
}

#[test]
fn publish_env_parsers_clamp_garbage_instead_of_disabling() {
    assert_eq!(parse_repl_max_concurrent(None), 4);
    assert_eq!(parse_repl_max_concurrent(Some("0".into())), 4);
    assert_eq!(parse_repl_max_concurrent(Some("nope".into())), 4);
    assert_eq!(parse_repl_max_concurrent(Some("2".into())), 2);

    assert_eq!(parse_repl_min_interval_ms(None), 100);
    assert_eq!(parse_repl_min_interval_ms(Some("0".into())), 100);
    assert_eq!(parse_repl_min_interval_ms(Some("250".into())), 250);

    assert_eq!(parse_repl_head_min_interval_ms(None), 10);

    // Timeout floor keeps a typo from turning every store into an instant timeout.
    assert_eq!(parse_repl_store_timeout_ms(Some("10".into())), 5_000);
    assert_eq!(parse_repl_store_timeout_ms(Some("8000".into())), 8_000);

    // Attempts clamped to 1..=8: always at least one try, never an unbounded budget.
    assert_eq!(parse_repl_max_attempts(Some("0".into())), 3);
    assert_eq!(parse_repl_max_attempts(Some("99".into())), 3);
    assert_eq!(parse_repl_max_attempts(Some("1".into())), 1);

    assert_eq!(parse_repl_circuit_threshold(Some("0".into())), 5);
    assert_eq!(parse_repl_circuit_cooldown_ms(Some("1".into())), 5_000);
}

// ==================== network: retry budget ====================

#[test]
fn retry_backoff_is_floored_capped_and_jitter_bounded() {
    // Exponential ladder with a floor: a timed-out store never retries sooner
    // than 200ms (the old shape re-fired inside the timeout window).
    assert_eq!(repl_retry_backoff_ms(1), 200);
    assert_eq!(repl_retry_backoff_ms(2), 400);
    assert_eq!(repl_retry_backoff_ms(3), 800);
    assert_eq!(repl_retry_backoff_ms(4), 1600);
    assert_eq!(repl_retry_backoff_ms(5), 2000);
    assert_eq!(repl_retry_backoff_ms(100), 2000, "capped, never growing");
    // Jitter spreads same-tick retries without ever going below the floor.
    for jitter in [0u64, 1, 17, 250, 251, 9999] {
        let b = repl_retry_backoff_with_jitter_ms(1, jitter);
        assert!(
            (200..=(200 + REPL_RETRY_JITTER_MAX_MS)).contains(&b),
            "attempt-1 backoff {b} out of [200, 450] for jitter {jitter}"
        );
    }
}

#[test]
fn retry_budget_is_bounded_never_infinite() {
    assert!(repl_should_retry(0, 3));
    assert!(repl_should_retry(1, 3));
    assert!(repl_should_retry(2, 3));
    assert!(!repl_should_retry(3, 3), "budget spent: drop, do not retry");
    assert!(!repl_should_retry(9, 3));
    // A single-attempt configuration still tries exactly once.
    assert!(repl_should_retry(0, 1));
    assert!(!repl_should_retry(1, 1));
    // Simulate the attempt loop: total tries never exceed the budget.
    let mut completed = 0u32;
    let mut tries = 0u32;
    while repl_should_retry(completed, 3) {
        completed += 1;
        tries += 1;
        assert!(tries <= 3, "attempt loop escaped its budget");
    }
    assert_eq!(tries, 3);
}

// ==================== network: token bucket + interval ====================

#[test]
fn same_tick_hammer_passes_once_then_paces() {
    // The exact hammer shape: 20 publishes inside one millisecond.
    let mut g = ReplBackpressure::with_defaults();
    let allowed = (0..20).filter(|_| g.publish_allowed("peer-b", 0)).count();
    assert_eq!(allowed, 1, "same-tick burst must not pass as a burst");
}

#[test]
fn sustained_hammer_is_capped_at_the_paced_rate() {
    // 20/sec sustained for 2 virtual seconds against the default gate
    // (burst 4, sustained 10/sec, 100ms floor): the interval binds, so exactly
    // every other publish passes — the storm halves instead of amplifying.
    let mut g = ReplBackpressure::with_defaults();
    let mut allowed = 0usize;
    for i in 0..40u64 {
        if g.publish_allowed("peer-b", i * 50) {
            allowed += 1;
        }
    }
    assert_eq!(
        allowed, 20,
        "sustained 20/sec must pace down to 10/sec, got {allowed}"
    );
}

#[test]
fn token_bucket_gives_burst_headroom_without_interval_floor() {
    // Without a spacing floor the bucket alone governs: burst 4 passes at once,
    // the 5th waits for refill, and after 1s the bucket is full again.
    let mut g = ReplBackpressure::new(4, 10.0, 0, 5, 5_000, 256);
    let burst = (0..6).filter(|_| g.publish_allowed("p", 0)).count();
    assert_eq!(
        burst, 4,
        "burst capacity must absorb exactly 4, got {burst}"
    );
    let later = (0..4).filter(|_| g.publish_allowed("p", 1_000)).count();
    assert_eq!(later, 4, "1s of refill at 10/s must restore the full burst");
}

#[test]
fn min_interval_spaces_even_tiny_bursts() {
    let mut g = ReplBackpressure::new(100, 1000.0, 100, 5, 5_000, 256);
    assert!(g.publish_allowed("p", 1_000), "first publish always passes");
    assert!(
        !g.publish_allowed("p", 1_000),
        "same-ms republish must wait"
    );
    assert!(
        !g.publish_allowed("p", 1_099),
        "99ms is still inside the floor"
    );
    assert!(g.publish_allowed("p", 1_100), "floor elapsed: pass again");
}

// ==================== network: circuit breaker ====================

#[test]
fn circuit_opens_on_consecutive_timeouts_then_half_opens() {
    let mut g = ReplBackpressure::new(100, 1000.0, 0, 5, 5_000, 256);
    for i in 0..4u64 {
        g.record_timeout("slow-peer", i);
        assert!(
            !g.in_cooldown("slow-peer", i),
            "4 timeouts must not trip yet"
        );
        assert_eq!(g.consec_timeouts("slow-peer"), (i + 1) as u32);
    }
    g.record_timeout("slow-peer", 4);
    assert!(
        g.in_cooldown("slow-peer", 4),
        "5th consecutive timeout opens the circuit"
    );
    // Shed during the window (bounded: exactly the 5s cooldown)...
    assert!(!g.publish_allowed("slow-peer", 100));
    assert!(!g.publish_allowed("slow-peer", 5_003));
    // ...then half-open automatically: the next publish is attempted, and a
    // success closes the breaker immediately (honest recovery, no manual reset).
    assert!(
        g.publish_allowed("slow-peer", 5_004),
        "cooldown expired: half-open"
    );
    g.record_success("slow-peer");
    assert_eq!(g.consec_timeouts("slow-peer"), 0);
    assert!(!g.in_cooldown("slow-peer", 5_004));
    // A fresh streak needs a full 5 again (no sticky tripping).
    for i in 0..4u64 {
        g.record_timeout("slow-peer", 6_000 + i);
    }
    assert!(!g.in_cooldown("slow-peer", 6_010));
}

#[test]
fn circuit_is_per_key_and_success_on_unknown_is_safe() {
    let mut g = ReplBackpressure::new(100, 1000.0, 0, 2, 5_000, 256);
    g.record_timeout("bad", 0);
    g.record_timeout("bad", 0);
    assert!(g.in_cooldown("bad", 0));
    // A healthy peer is unaffected by another peer's breaker.
    assert!(g.publish_allowed("good", 0));
    assert!(!g.in_cooldown("good", 0));
    // Recording success for an unknown key is a no-op, never a panic.
    g.record_success("never-seen");
}

#[test]
fn pacing_map_is_memory_bounded() {
    let mut g = ReplBackpressure::new(4, 10.0, 0, 5, 5_000, 8);
    for i in 0..50u64 {
        g.publish_allowed(&format!("peer-{i}"), i);
    }
    assert!(
        g.peer_count() <= 8,
        "map must stay capped, got {}",
        g.peer_count()
    );
}

#[test]
fn store_kinds_name_the_charge_model() {
    // One logical publish charges once: Bulk bills the gate, Companion sidecars
    // (header index, QC) and Pointer overwrites are distinct kinds so a header
    // never pays 3x the floor.
    assert_eq!(ReplStoreKind::Bulk.as_str(), "bulk");
    assert_eq!(ReplStoreKind::Companion.as_str(), "companion");
    assert_eq!(ReplStoreKind::Pointer.as_str(), "pointer");
}

// ==================== consensus_net: pacing floors ====================

#[test]
fn broadcast_and_probe_floors_gate_repeats() {
    assert!(pace_due(None, 0, CONS_BCAST_MIN_INTERVAL_MS_DEFAULT));
    assert!(!pace_due(
        Some(1_000),
        1_010,
        CONS_BCAST_MIN_INTERVAL_MS_DEFAULT
    ));
    assert!(pace_due(
        Some(1_000),
        1_025,
        CONS_BCAST_MIN_INTERVAL_MS_DEFAULT
    ));
    assert_eq!(pace_wait_ms(None, 0, 25), 0);
    assert_eq!(pace_wait_ms(Some(1_000), 1_010, 25), 15);
    assert_eq!(
        pace_wait_ms(Some(1_000), 2_000, 25),
        0,
        "elapsed floor waits nothing"
    );
    // Defaults pinned: 25ms send floor (far below the 800ms round timeout),
    // 5s probe floor (probes are full round trips).
    assert_eq!(CONS_BCAST_MIN_INTERVAL_MS_DEFAULT, 25);
    assert_eq!(CONS_PROBE_MIN_INTERVAL_MS_DEFAULT, 5_000);
}

// ==================== consensus_net: inbound bulk guard ====================

fn sample_block() -> Block {
    let sk = SigningKey::generate(&mut OsRng);
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 7,
        prev_hash: [1u8; 32],
        state_root: [2u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 123,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(&sk);
    b
}

fn sample_vote() -> ConsensusMsg {
    let sk = SigningKey::generate(&mut OsRng);
    ConsensusMsg::Vote {
        vote: Vote::sign(&sk, 1, 0, VoteKind::Prevote, None),
        locked: None,
    }
}

#[test]
fn only_committed_bypasses_the_bulk_limiter() {
    let sk = SigningKey::generate(&mut OsRng);
    let vote = sample_vote();
    let proposal = ConsensusMsg::Proposal {
        height: 1,
        round: 0,
        block: sample_block(),
    };
    let commit = ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: QuorumCertificate {
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    };
    // PENTEST F2 (P1): ONLY Committed bypasses. Votes and proposals are
    // budget-checked like any other gossip (per-peer buckets; deferred —
    // never dropped — under flood, see
    // `bulk_over_budget_defers_never_drops_and_recovers`). The old contract
    // pinned here (`!Batch` bypasses) let an attacker trickle singleton
    // votes past the limiter entirely, making it dead code for the cheapest
    // flood shape — so the predicate was narrowed deliberately, and this
    // test pins the narrowed contract, not the old one.
    assert!(
        !inbound_is_critical(&vote),
        "singleton votes are budgeted per-peer, not exempt"
    );
    assert!(
        !inbound_is_critical(&proposal),
        "proposals are budgeted per-peer, not exempt"
    );
    assert!(
        inbound_is_critical(&commit),
        "commits (the catch-up path) must bypass"
    );
    // Only the bulk shape is budgeted — even a batch OF votes is bulk on the
    // wire (deferred under flood, never dropped).
    assert!(!inbound_is_critical(&ConsensusMsg::Batch(vec![vote])));
    let _ = sk;
}

#[test]
fn bulk_over_budget_defers_never_drops_and_recovers() {
    let mut lim = InboundBulkLimiter::new(
        INBOUND_BULK_BYTES_PER_SEC_DEFAULT,
        INBOUND_BULK_BURST_BYTES_DEFAULT,
    );
    // One honest batch fits the burst...
    assert_eq!(
        lim.admit("peer-a", INBOUND_BULK_BURST_BYTES_DEFAULT, false, 0),
        InboundDecision::Allow
    );
    // ...the next one, on an empty bucket, DEFERS with a bounded wait hint —
    // the hammer shape (10-20/sec) is exactly what lands here.
    match lim.admit("peer-a", 100_000, false, 0) {
        InboundDecision::Defer { wait_ms } => {
            assert!(wait_ms > 0 && wait_ms <= INBOUND_MAX_DEFER_WAIT_MS);
        }
        InboundDecision::Allow => panic!("over-budget bulk must defer, not pass"),
    }
    // Critical traffic still passes on the same empty bucket at the same instant:
    // votes never starve behind bulk, and bulk never consumes the vote lane.
    assert_eq!(
        lim.admit("peer-a", 64 * 1024, true, 0),
        InboundDecision::Allow
    );
    // Budgets are per-peer: another peer is unaffected by peer-a's flood.
    assert_eq!(
        lim.admit("peer-b", 100_000, false, 0),
        InboundDecision::Allow
    );
    // After refill time the bulk lane re-opens on its own (2s * 512KiB refills
    // the 1MiB burst; no manual reset, no operator action).
    assert_eq!(
        lim.admit("peer-a", 100_000, false, 2_000),
        InboundDecision::Allow
    );
}

#[test]
fn absurd_bulk_gets_a_capped_wait_hint() {
    let mut lim = InboundBulkLimiter::new(
        INBOUND_BULK_BYTES_PER_SEC_DEFAULT,
        INBOUND_BULK_BURST_BYTES_DEFAULT,
    );
    // 10MiB at once: far past any honest batch, still a Defer (never a drop),
    // with the wait hint capped so deferral stays scheduling, not parking.
    match lim.admit("peer-z", 10 * 1024 * 1024, false, 0) {
        InboundDecision::Defer { wait_ms } => assert_eq!(wait_ms, INBOUND_MAX_DEFER_WAIT_MS),
        InboundDecision::Allow => panic!("10MiB bulk must not pass a 1MiB burst"),
    }
}

#[test]
fn inbound_peer_map_is_memory_bounded() {
    let mut lim = InboundBulkLimiter::new(1024, 1024);
    for i in 0..2000 {
        let _ = lim.admit(&format!("peer-{i}"), 10, false, 0);
    }
    assert!(lim.peer_count() <= 1024, "inbound map must stay capped");
}

#[test]
fn inbound_defaults_are_sane_and_pinned() {
    assert_eq!(INBOUND_BULK_BYTES_PER_SEC_DEFAULT, 512 * 1024);
    assert_eq!(INBOUND_BULK_BURST_BYTES_DEFAULT, 1024 * 1024);
    // Env accessors agree with the defaults when unset (CI-safe: no env mutation).
    assert_eq!(inbound_bulk_bytes_per_sec(), 512 * 1024);
    assert_eq!(inbound_bulk_burst_bytes(), 1024 * 1024);
}
