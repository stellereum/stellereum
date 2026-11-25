use super::admission::*;
use super::compact_prop;
use super::framing::*;
use super::gossip::*;
use super::limiter::*;
use crate::consensus::{Vote, VoteKind};
use crate::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[test]
fn warn_gate_rate_limits_within_window() {
    let gate = AtomicU64::new(0);
    // First slow stage logs; a second one inside the window is suppressed;
    // once the window elapses the next one logs again.
    assert!(warn_allowed(&gate, 1_000));
    assert!(!warn_allowed(&gate, 1_000 + SUBTIMING_WARN_MIN_GAP_MS - 1));
    assert!(warn_allowed(&gate, 1_000 + SUBTIMING_WARN_MIN_GAP_MS));
    // Saturating behaviour: a clock that appears to go backwards must not
    // underflow into a spurious "allowed".
    assert!(!warn_allowed(&gate, 0));
}

#[test]
fn log_stage_never_panics_for_fast_or_slow() {
    // Instrumentation only: both branches must be panic-free and leave the
    // gate usable.
    let gate = AtomicU64::new(0);
    log_stage(&gate, "test", "fast", std::time::Duration::from_micros(1));
    log_stage(&gate, "test", "slow", std::time::Duration::from_millis(250));
    log_stage(
        &gate,
        "test",
        "slow-again",
        std::time::Duration::from_millis(300),
    );
}

/// FIRE-AND-FORGET is not a delivery proof: a local write success must
/// NOT mark the peer healthy, because that RESET its consecutive-failure
/// counter and a peer that fails intermittently was then never skipped
/// (audit W6.7).
#[test]
fn fire_and_forget_success_does_not_mark_a_peer_healthy() {
    assert!(
        !send_outcome_records_health(true),
        "a fire-and-forget success must not touch the peer-health ledger"
    );
    assert!(
        send_outcome_records_health(false),
        "an acknowledged send must mark the peer healthy"
    );
}

/// The per-peer inbound limiter: a noisy neighbour can only defer its OWN
/// traffic, and the bucket is bounded in count (memory) and in rate.
#[test]
fn inbound_limiter_is_per_peer_and_bounded() {
    let mut lim = InboundBulkLimiter::new(1024, 4096);
    let a = "aa";
    let b = "bb";
    // A big burst for peer A is deferred...
    let d = lim.admit(a, 8192, false, 0);
    assert!(
        matches!(d, InboundDecision::Defer { .. }),
        "a peer over its burst budget must be deferred, not dropped"
    );
    // ...and peer B is UNAFFECTED (its own bucket is full).
    assert_eq!(
        lim.admit(b, 100, false, 0),
        InboundDecision::Allow,
        "one peer's over-budget traffic must not defer another peer's"
    );
    // Critical traffic always passes and never spends the budget.
    assert_eq!(lim.admit(a, 1_000_000, true, 0), InboundDecision::Allow);
    // The bucket count is bounded: many peers do not grow it without
    // bound (the overflow evicts an arbitrary entry).
    for i in 0..(INBOUND_MAX_TRACKED_PEERS + 50) {
        lim.admit(&format!("p{i}"), 1, false, 0);
    }
    assert!(
        lim.peer_count() <= INBOUND_MAX_TRACKED_PEERS,
        "the limiter must not grow without bound ({} peers)",
        lim.peer_count()
    );
}

#[test]
fn inbound_peer_key_prefers_src_then_from() {
    // The pubsub envelope infnode delivers carries the SENDER's node id
    // in `src`; `from` is the legacy spelling. `src` wins when both are
    // present.
    let raw = r#"{"topic":"t","data":"00","msg_id":7,"src":"aa","from":"bb"}"#;
    assert_eq!(inbound_peer_key(raw).as_str(), "aa");
    let legacy = r#"{"topic":"t","data":"00","msg_id":7,"from":"bb"}"#;
    assert_eq!(inbound_peer_key(legacy).as_str(), "bb");
    // `inf1:` is infnode's canonical node-id prefix: the same peer must
    // key identically no matter which form the sender used.
    let prefixed = r#"{"topic":"t","data":"00","msg_id":7,"src":"inf1:cc"}"#;
    assert_eq!(inbound_peer_key(prefixed).as_str(), "cc");
    // No sender at all: the shared fallback bucket (and only that one).
    let bare = r#"{"topic":"t","data":"00","msg_id":7}"#;
    assert_eq!(inbound_peer_key(bare).as_str(), INBOUND_BROADCAST_PEER_KEY);
    // Garbage is not a crash and not a distinct peer.
    assert_eq!(
        inbound_peer_key("not json").as_str(),
        INBOUND_BROADCAST_PEER_KEY
    );
    // An empty sender is not a peer either.
    let empty = r#"{"topic":"t","data":"00","msg_id":7,"src":""}"#;
    assert_eq!(inbound_peer_key(empty).as_str(), INBOUND_BROADCAST_PEER_KEY);
}

#[test]
fn inbound_limiter_buckets_are_per_peer() {
    // The bug this pins: the pubsub envelope used to carry no sender, so
    // EVERY peer's inbound bulk traffic shared ONE token bucket and a
    // single noisy neighbour could exhaust everybody else's budget.
    let peer_a = "aa".repeat(20);
    let peer_b = "bb".repeat(20);
    let raw_a = format!(r#"{{"topic":"t","data":"00","msg_id":1,"src":"{peer_a}"}}"#);
    let raw_b = format!(r#"{{"topic":"t","data":"00","msg_id":2,"src":"{peer_b}"}}"#);
    let key_a = inbound_peer_key(&raw_a);
    let key_b = inbound_peer_key(&raw_b);
    assert_ne!(key_a, key_b, "two peers must key differently");
    assert_eq!(key_a.as_str(), peer_a);
    assert_eq!(key_b.as_str(), peer_b);

    // A limiter with a 1 KiB/s rate and a 1 KiB burst: peer A spends its
    // whole burst, peer B still has its own bucket.
    let mut limiter = InboundBulkLimiter::new(1024, 1024);
    let now = 1_000u64;
    assert_eq!(
        limiter.admit(key_a.as_str(), 1024, false, now),
        InboundDecision::Allow
    );
    // A is now over budget -> deferred.
    assert!(
        matches!(
            limiter.admit(key_a.as_str(), 1024, false, now),
            InboundDecision::Defer { .. }
        ),
        "the noisy peer must be deferred once it is over budget"
    );
    // B is untouched: its own bucket still has the full burst.
    assert_eq!(
        limiter.admit(key_b.as_str(), 1024, false, now),
        InboundDecision::Allow,
        "one peer exhausting its budget must not defer another peer's traffic"
    );
    assert_eq!(limiter.peer_count(), 2, "each peer gets its own bucket");
}

#[test]
fn probe_rtt_emission_populates_latency_series() {
    // HDAE calibration-emission: an answered ping probe populates
    // `stell_peer_latency_seconds{peer}` with the measured RTT
    // (workspace-root FIXES.md §2.12 latency side).
    //
    // The process-global registry is shared with every concurrently
    // running test, so exact count/sum assertions need a series nobody
    // else writes: this peer label is unique to this test.
    let peer = "hdae-cal-probe-rtt";
    record_probe_rtt(peer, Duration::from_millis(25));
    let text = crate::metrics::global().render();

    // Emit -> scrape -> assert present with sane values.
    let count_line = format!("stell_peer_latency_seconds_count{{peer=\"{peer}\"}} 1");
    assert!(
        text.contains(&count_line),
        "exactly one latency sample for this peer:\n{text}"
    );
    let sum: f64 = text
        .lines()
        .find(|l| {
            l.starts_with(&format!(
                "stell_peer_latency_seconds_sum{{peer=\"{peer}\"}}"
            ))
        })
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
        .expect("latency _sum sample must be present");
    assert!(
        (sum - 0.025).abs() < 1e-12,
        "25ms probe must sum to 0.025s, got {sum}"
    );
    // The +Inf bucket is the total: the sample landed in the histogram.
    let inf_line = format!("stell_peer_latency_seconds_bucket{{le=\"+Inf\",peer=\"{peer}\"}} 1");
    assert!(
        text.contains(&inf_line),
        "+Inf bucket must equal the observation count:\n{text}"
    );
}

#[test]
fn peer_cooldown_skips_only_inside_the_window() {
    use std::time::{Duration, Instant};
    let now = Instant::now();
    // Below threshold: never skip, even with a fresh failure.
    assert!(!peer_in_cooldown(2, Some(now), now));
    // At threshold with a fresh failure: skip.
    assert!(peer_in_cooldown(3, Some(now), now));
    assert!(peer_in_cooldown(9, Some(now), now));
    // Same count but the failure aged out: retry now.
    let old = now - PEER_SKIP_COOLDOWN - Duration::from_secs(1);
    assert!(!peer_in_cooldown(3, Some(old), now));
    // No failure recorded at all: never skip.
    assert!(!peer_in_cooldown(0, None, now));
    assert!(!peer_in_cooldown(99, None, now));
}

#[test]
fn join_dials_skip_cooldown_and_resume_when_cleared() {
    // Join backoff (handshake-storm fix): a peer in failure cooldown gets
    // no join dial on this pass; every other peer does. A returning peer
    // re-announces via DHT/probe (which clears cooldown on success), so
    // `in_cooldown == false` again and join resumes automatically.
    assert!(!join_should_dial(true), "cooldown peer: no dial");
    assert!(join_should_dial(false), "live peer: dial");
    assert!(
        join_should_dial(false),
        "cooldown cleared (returning peer): dial again"
    );
}

#[test]
fn dial_backoff_grows_exponentially_and_caps() {
    // Below the skip threshold there is no backoff: healthy peers see
    // zero behavior change.
    assert_eq!(dial_backoff_ms(0, 2000, 300_000), 0);
    assert_eq!(dial_backoff_ms(1, 2000, 300_000), 0);
    assert_eq!(dial_backoff_ms(PEER_SKIP_THRESHOLD - 1, 2000, 300_000), 0);
    // At threshold: base; then doubling per consecutive failure.
    assert_eq!(dial_backoff_ms(PEER_SKIP_THRESHOLD, 2000, 300_000), 2_000);
    assert_eq!(
        dial_backoff_ms(PEER_SKIP_THRESHOLD + 1, 2000, 300_000),
        4_000
    );
    assert_eq!(
        dial_backoff_ms(PEER_SKIP_THRESHOLD + 2, 2000, 300_000),
        8_000
    );
    assert_eq!(
        dial_backoff_ms(PEER_SKIP_THRESHOLD + 3, 2000, 300_000),
        16_000
    );
    // The cap binds a long-dead peer: no overflow, no unbounded growth.
    assert_eq!(
        dial_backoff_ms(PEER_SKIP_THRESHOLD + 10, 2000, 300_000),
        300_000
    );
    assert_eq!(dial_backoff_ms(u32::MAX, 2000, 300_000), 300_000);
    // Custom knobs are honored (env parsing below pins the defaults).
    assert_eq!(dial_backoff_ms(PEER_SKIP_THRESHOLD, 500, 10_000), 500);
    assert_eq!(dial_backoff_ms(PEER_SKIP_THRESHOLD + 1, 500, 10_000), 1_000);
    assert_eq!(
        dial_backoff_ms(PEER_SKIP_THRESHOLD + 10, 500, 10_000),
        10_000
    );
}

#[test]
fn dial_backoff_jitter_stays_in_bounds() {
    // Equal jitter: every sample lands in [backoff/2, backoff], so
    // co-dead peers desynchronize without ever exceeding the level.
    for backoff in [1u64, 2, 100, 2_000, 16_000, 300_000] {
        for seed in [0u64, 1, 7, 12345, u64::MAX] {
            let j = dial_backoff_jittered_ms(backoff, seed);
            assert!(
                j >= backoff / 2 && j <= backoff,
                "jittered {j} out of [{}, {backoff}]",
                backoff / 2,
            );
        }
    }
    // Zero backoff stays zero (healthy peers never wait).
    assert_eq!(dial_backoff_jittered_ms(0, 999), 0);
    // The seed actually spreads: not every seed maps to the same delay.
    let spread: std::collections::HashSet<u64> = (0..32)
        .map(|s| dial_backoff_jittered_ms(2_000, s))
        .collect();
    assert!(
        spread.len() > 1,
        "jitter must desynchronize retries, got a single value"
    );
}

#[test]
fn dial_backoff_env_parsing_pins_defaults() {
    assert_eq!(
        parse_dial_backoff_base_ms(None),
        DIAL_BACKOFF_BASE_MS_DEFAULT
    );
    assert_eq!(parse_dial_backoff_base_ms(Some("garbage".into())), 2_000);
    assert_eq!(parse_dial_backoff_base_ms(Some("0".into())), 2_000);
    assert_eq!(parse_dial_backoff_base_ms(Some("500".into())), 500);
    assert_eq!(parse_dial_backoff_max_ms(None), DIAL_BACKOFF_MAX_MS_DEFAULT);
    assert_eq!(parse_dial_backoff_max_ms(Some("nope".into())), 300_000);
    assert_eq!(parse_dial_backoff_max_ms(Some("0".into())), 300_000);
    assert_eq!(parse_dial_backoff_max_ms(Some("60_000".into())), 300_000);
    assert_eq!(parse_dial_backoff_max_ms(Some("60000".into())), 60_000);
    assert_eq!(parse_dial_budget_per_sec(None), DIAL_BUDGET_PER_SEC_DEFAULT);
    assert_eq!(parse_dial_budget_per_sec(Some("junk".into())), 4);
    assert_eq!(parse_dial_budget_per_sec(Some("0".into())), 4);
    assert_eq!(parse_dial_budget_per_sec(Some("10".into())), 10);
}

#[test]
fn dial_budget_gate_allows_n_per_second() {
    // 4/s => one slot per 250ms. First dial always allowed.
    assert!(dial_budget_should_allow(None, 1_000, 4));
    assert!(!dial_budget_should_allow(Some(1_000), 1_000, 4));
    assert!(!dial_budget_should_allow(Some(1_000), 1_249, 4));
    assert!(dial_budget_should_allow(Some(1_000), 1_250, 4));
    // A faster budget shortens the interval; a clamped (>= 1) one never
    // divides by zero.
    assert!(dial_budget_should_allow(Some(1_000), 1_100, 10));
    assert!(!dial_budget_should_allow(Some(1_000), 1_000, 0));
    assert!(dial_budget_should_allow(Some(1_000), 2_000, 0));
    // The stateful gate stamps on allow and holds back within the window.
    let gate = DialBudget::new(4);
    assert!(gate.try_acquire_at(5_000));
    assert!(!gate.try_acquire_at(5_100));
    assert!(gate.try_acquire_at(5_250));
    // Independent gates do not share state (regression: one global would
    // serialize unrelated test clocks).
    let other = DialBudget::new(4);
    assert!(other.try_acquire_at(5_100));
}

#[test]
fn dead_peer_dials_back_off() {
    use std::time::{Duration, Instant};
    // A dead peer's dial suppression OUTLIVES the fixed 3s cooldown: the
    // exponential backoff keeps stretching the silence while the peer
    // stays down, and success resets the streak to zero.
    let health = Mutex::new(HashMap::new());
    let pid = [7u8; 20];
    // Healthy peer: no backoff, no suppression.
    assert_eq!(dial_backoff_ms(0, 2000, 300_000), 0);
    // Three consecutive dial failures: threshold reached, suppressed now.
    for _ in 0..PEER_SKIP_THRESHOLD {
        ConsensusNetwork::record_health(&health, pid, false);
    }
    let now = Instant::now();
    let entry = health.lock().unwrap().get(&pid).copied().unwrap();
    assert_eq!(entry.fails, PEER_SKIP_THRESHOLD);
    assert!(peer_dial_suppressed(
        entry.fails,
        entry.last_fail,
        entry.backoff_until,
        now
    ));
    // Keep failing: with defaults (base 2s) the 6th consecutive failure
    // already backs off 16s (jittered to [8s, 16s]) — far past the fixed
    // 3s cooldown, so the peer stays silent after the cooldown ages out.
    for _ in 0..3 {
        ConsensusNetwork::record_health(&health, pid, false);
    }
    let entry = health.lock().unwrap().get(&pid).copied().unwrap();
    assert_eq!(entry.fails, PEER_SKIP_THRESHOLD + 3);
    let past_cooldown = entry.last_fail.unwrap() + PEER_SKIP_COOLDOWN + Duration::from_secs(1);
    assert!(
        !peer_in_cooldown(entry.fails, entry.last_fail, past_cooldown),
        "the fixed cooldown must have aged out here"
    );
    assert!(
        peer_dial_suppressed(
            entry.fails,
            entry.last_fail,
            entry.backoff_until,
            past_cooldown
        ),
        "but the exponential backoff must still suppress the dial"
    );
    // Success resets to zero: the ledger entry is gone, dials resume.
    let fails_before = ConsensusNetwork::record_health(&health, pid, true);
    assert_eq!(fails_before, PEER_SKIP_THRESHOLD + 3);
    assert!(!health.lock().unwrap().contains_key(&pid));
    assert!(!peer_dial_suppressed(0, None, None, Instant::now()));
}

#[tokio::test]
async fn dead_peer_keeps_flush_latency_bounded() {
    // Flush-latency bound: one dead peer's multi-second stall must not
    // hold the flush past the join budget. The slow task is DETACHED
    // (still runs to completion), only the waiter moves on.
    let fast = tokio::spawn(async { 1u32 });
    let slow = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        2u32
    });
    let t0 = Instant::now();
    let (done, detached) = join_with_timeout(vec![fast, slow], Duration::from_millis(50)).await;
    let elapsed = t0.elapsed();
    assert_eq!(done, vec![1u32], "the fast peer must still join");
    assert_eq!(detached, 1, "the dead peer must detach, not block");
    assert!(
        elapsed < Duration::from_secs(2),
        "flush must return on the join budget, not the dead peer (took {elapsed:?})"
    );
}

#[test]
fn committed_bypasses_peer_skip_votes_and_proposals_do_not() {
    // Transport-audit contract: the Committed live path of a lagging node
    // must not starve for the 60s peer-skip cooldown; votes and proposals
    // stay skippable.
    let commit = ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: crate::consensus::QuorumCertificate {
            shard_id: 0,
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    };
    assert!(committed_bypasses_skip(&commit));
    assert!(batch_bypasses_skip(std::slice::from_ref(&commit)));
    let proposal = ConsensusMsg::Proposal {
        height: 9,
        round: 0,
        block: sample_block(),
    };
    assert!(!committed_bypasses_skip(&proposal));
    assert!(!batch_bypasses_skip(std::slice::from_ref(&proposal)));
    // A batch of only votes/proposals carries no live path.
    let votes = vec![tagged_vote(1), tagged_vote(2)];
    assert!(!batch_bypasses_skip(&votes));
    // A mixed batch carrying a commit still bypasses (the whole payload
    // is the catch-up path); votes alone never do.
    let mut mixed = votes.clone();
    mixed.push(commit);
    assert!(batch_bypasses_skip(&mixed));
}

#[test]
fn votes_and_proposals_are_fire_and_forget_but_commits_are_not() {
    // Transport-audit contract (D): a vote/proposal is delivered without
    // waiting for the peer's ACK — the ACK is a fixed `{"ok":true,...}`
    // that carries no information, but it costs a full round trip
    // (300-1200 ms on WAN) and the ordered sender is FIFO, so an awaited
    // ACK also delays the NEXT chunk.
    let vote = tagged_vote(1);
    assert!(message_is_fire_and_forget(&vote));
    let proposal = ConsensusMsg::Proposal {
        height: 9,
        round: 0,
        block: sample_block(),
    };
    assert!(message_is_fire_and_forget(&proposal));
    // A chunk of votes/proposals is fire-and-forget.
    assert!(batch_is_fire_and_forget(std::slice::from_ref(&vote)));
    assert!(batch_is_fire_and_forget(std::slice::from_ref(&proposal)));
    assert!(batch_is_fire_and_forget(&[vote.clone(), proposal.clone()]));

    // The catch-up path keeps the acknowledged form: its ACK is the
    // sender's proof that the peer really got the block.
    let commit = ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: crate::consensus::QuorumCertificate {
            shard_id: 0,
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    };
    assert!(!message_is_fire_and_forget(&commit));
    assert!(!batch_is_fire_and_forget(std::slice::from_ref(&commit)));
    // A mixed chunk keeps the acknowledged form for the WHOLE chunk.
    assert!(!batch_is_fire_and_forget(&[vote, commit]));
    // An empty chunk is never fire-and-forget (nothing to send).
    assert!(!batch_is_fire_and_forget(&[]));
}

/// The gossip frame builder must emit EXACTLY the bytes the pre-refactor
/// composition did (bincode encode → hex → JSON `{topic,data}`); the wire
/// format is frozen. Also pins the owned batch encoder to the borrowed one.
#[test]
fn broadcast_framing_is_byte_identical_to_the_legacy_composition() {
    use std::borrow::Cow;
    let topic = "stellereum/consensus/v1/epoch-test";

    // Single message: the payload is `msgs[0].encode()` framed as JSON.
    let vote = tagged_vote(7);
    let live = vec![Cow::Borrowed(&vote)];
    let frame = encode_broadcast_payload(topic, &live).expect("single frame encodes");
    let inner = vote.encode().expect("single encodes");
    let expected = serde_json::json!({ "topic": topic, "data": hex::encode(&inner) })
        .to_string()
        .into_bytes();
    assert_eq!(
        frame.payload, expected,
        "single-frame bytes must be unchanged"
    );
    assert_eq!(frame.encoded_len, inner.len());
    assert!(!frame.is_batch);

    // Several messages: one `Batch` frame of the SAME encoded batch.
    let msgs = vec![tagged_vote(1), tagged_vote(2)];
    let live: Vec<Cow<'_, ConsensusMsg>> = msgs.iter().map(Cow::Borrowed).collect();
    let frame = encode_broadcast_payload(topic, &live).expect("batch frame encodes");
    let legacy = ConsensusMsg::batch_encode(&msgs).expect("legacy batch encodes");
    let expected = serde_json::json!({ "topic": topic, "data": hex::encode(&legacy) })
        .to_string()
        .into_bytes();
    assert_eq!(
        frame.payload, expected,
        "batch-frame bytes must be unchanged"
    );
    assert!(frame.is_batch);
    // Taking ownership must not change the bincode string either.
    assert_eq!(
        ConsensusMsg::batch_encode_owned(msgs).expect("owned batch encodes"),
        legacy
    );
}

/// The borrowing dedup filter must select exactly what the cloning filter
/// selected, and the resulting frame must be identical.
#[test]
fn coalesce_live_for_send_matches_the_cloned_filter() {
    use std::borrow::Cow;
    let chunk = vec![
        tagged_vote(1),
        tagged_vote(1), // same wire key: suppressed by the TTL filter
        tagged_vote(2),
        ConsensusMsg::Proposal {
            height: 9,
            round: 0,
            block: sample_block(),
        },
    ];
    let now = Instant::now();
    let ttl = Duration::from_millis(200);
    let mut borrow_filter = VoteSendFilter::new(ttl);
    let live = coalesce_live_for_send(&chunk, &mut borrow_filter, now);
    let mut clone_filter = VoteSendFilter::new(ttl);
    let legacy: Vec<ConsensusMsg> = chunk
        .iter()
        .filter(|m| clone_filter.should_send(m, now))
        .cloned()
        .collect();
    assert_eq!(live.len(), legacy.len(), "same live subset");
    for (a, b) in live.iter().zip(legacy.iter()) {
        assert_eq!(
            a.encode().expect("encode live"),
            b.encode().expect("encode legacy"),
            "same message, same order"
        );
    }
    let topic = "stellereum/consensus/v1/epoch-test";
    let borrowed_frame = encode_broadcast_payload(topic, &live).expect("borrowed frames");
    let legacy_live: Vec<Cow<'_, ConsensusMsg>> = legacy.iter().map(Cow::Borrowed).collect();
    let cloned_frame = encode_broadcast_payload(topic, &legacy_live).expect("legacy frames");
    assert_eq!(borrowed_frame.payload, cloned_frame.payload);
    // A second pass over the same filter suppresses the repeated vote but
    // keeps the proposal (identical in both forms).
    let again = coalesce_live_for_send(&chunk, &mut borrow_filter, now);
    assert_eq!(again.len(), 1, "only the proposal survives re-dedup");
}

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
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
        cnvrf_v3: None,
        round: 0,
    };
    b.sign_block(&sk);
    b
}

#[test]
fn proposal_roundtrip() {
    let msg = ConsensusMsg::Proposal {
        height: 7,
        round: 0,
        block: sample_block(),
    };
    let bytes = msg.encode().unwrap();
    let dec = ConsensusMsg::decode(&bytes).unwrap();
    match dec {
        ConsensusMsg::Proposal {
            height,
            round,
            block,
        } => {
            assert_eq!(height, 7);
            assert_eq!(round, 0);
            assert_eq!(block.height, 7);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn vote_roundtrip() {
    let sk = SigningKey::generate(&mut OsRng);
    // FULL-PQ: a classical `Vote::sign` no longer verifies, so the
    // round-tripped vote carries a Falcon half (mirrors
    // `consensus::tests::fvote`).
    let fk = crate::consensus::FalconKeypair::generate_from_seed(0xA1);
    crate::consensus::register_validator_pq_key(
        sk.verifying_key().to_bytes(),
        crate::post_quantum::PqScheme::Falcon512,
        fk.public_key.clone(),
    );
    let v = Vote::sign_with_falcon(&sk, &fk, 3, 1, VoteKind::Prevote, Some([9u8; 32]));
    let msg = ConsensusMsg::Vote {
        vote: v.clone(),
        locked: None,
    };
    let bytes = msg.encode().unwrap();
    match ConsensusMsg::decode(&bytes).unwrap() {
        ConsensusMsg::Vote { vote: v2, locked } => {
            assert_eq!(locked, None);
            assert_eq!(v2.height, 3);
            assert_eq!(v2.round, 1);
            assert!(v2.verify());
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn decode_rejects_garbage() {
    assert!(ConsensusMsg::decode(&[]).is_err(), "empty must be rejected");
    assert!(
        ConsensusMsg::decode(&[0xFF, 0x00, 0x01]).is_err(),
        "garbage must be rejected"
    );
}

#[test]
fn decode_rejects_oversized() {
    let big = vec![0u8; MAX_CONSENSUS_MSG + 1];
    assert!(
        ConsensusMsg::decode(&big).is_err(),
        "oversized must be rejected"
    );
}

/// PENTEST F1 (P1): appended trailing bytes must not ride along a valid
/// message. Before the fix `decode` used `allow_trailing_bytes`, so an
/// attacker could pad every vote with megabytes of junk that still
/// decoded — wire-size accounting (512 KiB batch cap, 32 MiB frame cap)
/// was bypassed and each tick paid the bandwidth + stream-buffer cost.
#[test]
fn pentest_decode_rejects_trailing_bytes() {
    let sk = SigningKey::generate(&mut OsRng);
    let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    let mut bytes = ConsensusMsg::Vote {
        vote: v,
        locked: None,
    }
    .encode()
    .unwrap();
    bytes.extend_from_slice(&[0xAA; 64]);
    assert!(
        ConsensusMsg::decode(&bytes).is_err(),
        "trailing junk after a valid message must be rejected"
    );
    // A single trailing byte is the same attack at minimum size.
    let mut one = ConsensusMsg::Proposal {
        height: 7,
        round: 0,
        block: sample_block(),
    }
    .encode()
    .unwrap();
    one.push(0x00);
    assert!(
        ConsensusMsg::decode(&one).is_err(),
        "one trailing byte must already fail the decode"
    );
    // Exact bytes still decode (no false positive from the hardening).
    let exact = ConsensusMsg::Proposal {
        height: 7,
        round: 0,
        block: sample_block(),
    }
    .encode()
    .unwrap();
    assert!(ConsensusMsg::decode(&exact).is_ok());
}

/// PENTEST F2 (P1): only the Committed catch-up proof bypasses the
/// inbound bulk limiter. Before the fix every non-Batch message
/// (votes AND proposals) bypassed it, and the receiver loop only
/// consulted the limiter for Batch envelopes at all — so an attacker
/// trickling singleton votes (a few hundred bytes each, never a Batch)
/// burned an Ed25519 verification per message while the limiter saw
/// nothing.
#[test]
fn pentest_only_committed_bypasses_inbound_limiter() {
    let vote = tagged_vote(1);
    let proposal = ConsensusMsg::Proposal {
        height: 9,
        round: 0,
        block: sample_block(),
    };
    let batch = ConsensusMsg::Batch(vec![vote.clone()]);
    assert!(
        !inbound_is_critical(&vote),
        "a singleton vote must be budget-checked, not exempt"
    );
    assert!(
        !inbound_is_critical(&proposal),
        "a proposal must be budget-checked, not exempt"
    );
    assert!(
        !inbound_is_critical(&batch),
        "bulk gossip must stay budget-checked"
    );
    let commit = ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: crate::consensus::QuorumCertificate {
            shard_id: 0,
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    };
    assert!(
        inbound_is_critical(&commit),
        "the catch-up proof is the only exempt shape"
    );
    // Limiter level: a singleton vote spends the sender's budget, and a
    // second over-budget vote from the same peer defers instead of
    // executing inline.
    let mut lim = InboundBulkLimiter::new(1024, 1024);
    let now = 1_000u64;
    assert_eq!(
        lim.admit("flooder", 512, inbound_is_critical(&vote), now),
        InboundDecision::Allow
    );
    assert!(
        matches!(
            lim.admit("flooder", 1024, inbound_is_critical(&vote), now),
            InboundDecision::Defer { .. }
        ),
        "an over-budget singleton vote must defer, not execute inline"
    );
    // The catch-up proof never spends budget, at any size.
    assert_eq!(
        lim.admit("lagging", 1_000_000, inbound_is_critical(&commit), now),
        InboundDecision::Allow
    );
}

/// PENTEST F3 (P1): the limiter bucket key is validated. Before the fix
/// any `src` string — kilobytes long, non-hex — became a distinct
/// attacker-minted `HashMap` key, so one peer could mint unbounded map
/// keys (memory) and rotate identities per message (a fresh bucket every
/// time, i.e. no rate limiting at all).
#[test]
fn pentest_inbound_peer_key_validates_sender() {
    // Oversized sender: shared bucket, not a new map key.
    let huge = "ab".repeat(1024);
    let raw = format!(r#"{{"topic":"t","data":"00","msg_id":1,"src":"{huge}"}}"#);
    assert_eq!(
        inbound_peer_key(&raw).as_str(),
        INBOUND_BROADCAST_PEER_KEY,
        "an oversized src must not become a distinct bucket"
    );
    // Non-hex sender: shared bucket.
    let raw = r#"{"topic":"t","data":"00","msg_id":2,"src":"../../evil"}"#;
    assert_eq!(
        inbound_peer_key(raw).as_str(),
        INBOUND_BROADCAST_PEER_KEY,
        "a non-hex src must not become a bucket key"
    );
    // Honest forms keep working: short hex, full node id, inf1: prefix.
    assert_eq!(
        inbound_peer_key(r#"{"topic":"t","data":"00","src":"aa"}"#).as_str(),
        "aa"
    );
    let full = "ab".repeat(20);
    let raw = format!(r#"{{"topic":"t","data":"00","src":"inf1:{full}"}}"#);
    assert_eq!(inbound_peer_key(&raw).as_str(), full);
    // Distinct honest peers still key distinctly (per-peer isolation kept).
    let ka = inbound_peer_key(r#"{"topic":"t","data":"00","src":"aa"}"#);
    let kb = inbound_peer_key(r#"{"topic":"t","data":"00","src":"bb"}"#);
    assert_ne!(ka, kb);
}

#[test]
fn parse_incoming_fail_closed() {
    assert!(parse_incoming("not json").is_none());
    assert!(parse_incoming("{}").is_none());
    assert!(parse_incoming(r#"{"data": 123}"#).is_none());
    assert!(parse_incoming(r#"{"data": "zzzz"}"#).is_none()); // bad hex

    // a well-formed message parses
    let sk = SigningKey::generate(&mut OsRng);
    let v = Vote::sign(&sk, 1, 0, VoteKind::Precommit, None);
    let data = hex::encode(
        ConsensusMsg::Vote {
            vote: v,
            locked: None,
        }
        .encode()
        .unwrap(),
    );
    let raw = serde_json::json!({ "topic": consensus_topic("test"), "data": data }).to_string();
    assert!(matches!(
        parse_incoming(&raw),
        Some(ConsensusMsg::Vote { .. })
    ));
}

#[test]
fn tampered_vote_fails_signature_check() {
    let sk = SigningKey::generate(&mut OsRng);
    let mut v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    v.block_hash = Some([2u8; 32]); // tamper after signing
    let msg = ConsensusMsg::Vote {
        vote: v,
        locked: None,
    };
    let bytes = msg.encode().unwrap();
    match ConsensusMsg::decode(&bytes).unwrap() {
        ConsensusMsg::Vote { vote: v2, .. } => {
            assert!(!v2.verify(), "tampered vote must fail verification")
        }
        _ => panic!("wrong variant"),
    }
}

/// VERIFICATION F1-hardening: the trailing-byte fix must hold for every
/// envelope shape, not just a singleton vote.
///
/// Stronger exploits than the original pentest:
/// * trailing junk after a BATCH envelope (the batch path has its own
///   length accounting — padding must not ride along);
/// * trailing junk after a COMMITTED proof (the largest variant: full
///   block + QC — padding here is the most expensive to relay);
/// * a nested Batch in SECOND position (the fast-path prefix check only
///   inspects the first item, so this exercises the full-deserialize +
///   `check_batch` leg);
/// * a maximal-size frame plus one byte (the size gate must fire before
///   any deserialization work).
#[test]
fn verification_decode_rejects_trailing_on_every_shape() {
    // Batch envelope + trailing junk.
    let sk = SigningKey::generate(&mut OsRng);
    let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
    let batch_bytes = ConsensusMsg::batch_encode(&[ConsensusMsg::Vote {
        vote: v,
        locked: None,
    }])
    .unwrap();
    let mut padded = batch_bytes.clone();
    padded.extend_from_slice(&[0xBB; 128]);
    assert!(
        ConsensusMsg::decode(&padded).is_err(),
        "trailing junk after a Batch envelope must be rejected"
    );
    assert!(
        ConsensusMsg::decode(&batch_bytes).is_ok(),
        "exact Batch bytes must still decode"
    );
    // Committed proof + one trailing byte (minimum-size padding attack).
    let commit = ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: crate::consensus::QuorumCertificate {
            shard_id: 0,
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    };
    let mut cbytes = commit.encode().unwrap();
    cbytes.push(0x00);
    assert!(
        ConsensusMsg::decode(&cbytes).is_err(),
        "one trailing byte after a Committed proof must fail the decode"
    );
    cbytes.pop();
    assert!(ConsensusMsg::decode(&cbytes).is_ok());
    // Nested batch in SECOND position: the prefix fast-path only sees the
    // first item (a Vote), so this must be caught by check_batch.
    let inner = ConsensusMsg::Batch(vec![tagged_vote(2)]);
    let sneaky = ConsensusMsg::Batch(vec![tagged_vote(1), inner]);
    let raw = bincode::serialize(&sneaky).unwrap();
    assert_eq!(raw[0..4], [3, 0, 0, 0], "outer envelope must be a Batch");
    assert_ne!(
        raw[12..16],
        [3, 0, 0, 0],
        "first inner item must be a Vote (fast-path blind spot)"
    );
    let err = ConsensusMsg::decode(&raw).unwrap_err();
    assert!(err.contains("nested"), "got: {err}");
    // Maximal frame + 1 byte: the size gate fires before deserialization.
    let big = vec![0u8; MAX_CONSENSUS_MSG + 1];
    assert!(ConsensusMsg::decode(&big).is_err());
    let edge = vec![0u8; MAX_CONSENSUS_MSG];
    assert!(
        ConsensusMsg::decode(&edge).is_err(),
        "a max-size garbage frame must still fail deserialization"
    );
}

/// C1-F2: a nested Batch at ANY position is refused by the hand-rolled
/// element decoder, without ever entering bincode's recursive
/// `Vec<ConsensusMsg>` deserializer (which aborted the process on a deep
/// enough nest).
#[test]
fn f1x_nested_batch_at_any_position_is_refused_without_recursion() {
    // Depth 2: Batch([Vote, Batch([Vote])]).
    let inner = ConsensusMsg::Batch(vec![tagged_vote(1)]);
    let depth_two = ConsensusMsg::Batch(vec![tagged_vote(2), inner]);
    let raw = bincode::serialize(&depth_two).expect("nested fixture serializes");
    let err = ConsensusMsg::decode(&raw).expect_err("nested batch must be refused");
    assert!(err.contains("nested"), "got: {err}");

    // Depth 5: every level inserts the nest after a harmless Vote, so the
    // old element-0 pre-check never saw it.
    let mut deep = ConsensusMsg::Batch(vec![tagged_vote(3)]);
    for _ in 0..4 {
        deep = ConsensusMsg::Batch(vec![tagged_vote(4), deep]);
    }
    let raw = bincode::serialize(&deep).expect("deep fixture serializes");
    let err = ConsensusMsg::decode(&raw).expect_err("deep nest must be refused");
    assert!(err.contains("nested"), "got: {err}");

    // The tag must be rejected BEFORE the inner element is deserialized.
    // Hand-build `Batch([Vote, <Batch tag + count 2 with no elements>])`:
    // the old full-deserialize path tried to read the inner batch and
    // failed with a generic EOF decode error; the hand-rolled path refuses
    // the nested tag itself.
    let mut sneaky = ConsensusMsg::batch_encode(&[tagged_vote(5)]).expect("valid batch");
    sneaky[4..12].copy_from_slice(&2u64.to_le_bytes());
    sneaky.extend_from_slice(&BATCH_VARIANT_TAG);
    sneaky.extend_from_slice(&2u64.to_le_bytes());
    let err = ConsensusMsg::decode(&sneaky).expect_err("nested tag must be refused");
    assert!(
        err.contains("nested"),
        "nested tag must be rejected before inner deserialization, got: {err}"
    );

    // Header-level cap: a count above MAX_BATCH_ITEMS is refused BEFORE
    // any element is deserialized (no allocation, no loop).
    let mut header = Vec::new();
    header.extend_from_slice(&[3, 0, 0, 0]);
    header.extend_from_slice(&((MAX_BATCH_ITEMS as u64) + 1).to_le_bytes());
    let err = ConsensusMsg::decode(&header).expect_err("over-cap count must be refused");
    assert!(err.contains("too many items"), "got: {err}");
}

/// C1-F4: the critical (Committed) class has its own LARGE per-peer byte
/// budget, charged before decode and DROPPED (never deferred) past it. A
/// flood of maximal frames in one tick is capped; one honest maximal frame
/// still fits; other peers keep their own bucket.
#[test]
fn f1x_critical_predecode_budget_caps_a_committed_flood() {
    let mut budget = InboundCriticalBudget::new(
        INBOUND_CRITICAL_BYTES_PER_SEC_DEFAULT,
        INBOUND_CRITICAL_BURST_BYTES_DEFAULT,
    );
    let frame = MAX_CONSENSUS_MSG as u64;
    let now = 1_000u64;
    assert!(
        budget.admit_predecode("peer-a", frame, now),
        "one maximal Committed proof must always be admitted"
    );
    assert!(
        !budget.admit_predecode("peer-a", frame, now),
        "a second maximal frame in the same tick is flood tail: DROP, never defer"
    );
    assert!(
        budget.admit_predecode("peer-b", frame, now),
        "per-peer budget: a flooder cannot starve an honest peer"
    );

    // Tag recognition happens on the hex prefix, before decode.
    let commit = ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: crate::consensus::QuorumCertificate {
            shard_id: 0,
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    };
    assert_eq!(
        frame_tag_from_hex(&hex::encode(commit.encode().expect("commit encodes"))),
        Some(COMMITTED_VARIANT_TAG)
    );
    assert_ne!(
        frame_tag_from_hex(&hex::encode(tagged_vote(1).encode().expect("vote encodes"))),
        Some(COMMITTED_VARIANT_TAG),
        "votes must not spend the critical budget"
    );
}

/// VERIFICATION F2-hardening: a singleton-vote flood from ONE peer must
/// not touch an honest peer's budget, sustained across ticks.
///
/// Stronger than the original pentest: the flooder keeps spending (32
/// back-to-back singleton votes in the same millisecond — a full Batch
/// worth, never a Batch), while the honest peer sends at the same
/// instants and after a refill window. Every flooder vote past the burst
/// defers; every honest vote passes.
#[test]
fn verification_singleton_flood_is_per_peer_isolated() {
    let vote = tagged_vote(1);
    assert!(
        !inbound_is_critical(&vote),
        "a singleton vote must be budget-checked, not exempt"
    );
    let mut lim = InboundBulkLimiter::new(1024, 1024);
    let now = 1_000u64;
    // Flooder spends its whole 1 KiB burst on the first vote...
    assert_eq!(
        lim.admit("flooder", 1024, false, now),
        InboundDecision::Allow
    );
    // ...and every further singleton vote in the same tick defers.
    for i in 0..32 {
        assert!(
            matches!(
                lim.admit("flooder", 300, false, now),
                InboundDecision::Defer { .. }
            ),
            "flooder vote {i} over budget must defer, not execute inline"
        );
    }
    // The honest peer's traffic passes at the same instant, byte for byte.
    for i in 0..3 {
        assert_eq!(
            lim.admit("honest", 300, false, now),
            InboundDecision::Allow,
            "honest vote {i} must pass while the flooder is over budget"
        );
    }
    // After a refill window the flooder earns budget back (deferral is
    // scheduling, not a ban) and the honest peer is still unaffected.
    let later = now + 2_000;
    assert_eq!(
        lim.admit("flooder", 300, false, later),
        InboundDecision::Allow
    );
    assert_eq!(
        lim.admit("honest", 300, false, later),
        InboundDecision::Allow
    );
}

/// VERIFICATION F2-hardening, second half: a giant fake Committed bypasses
/// the byte limiter by design — so the per-tick verification cap must
/// bound it instead. The limiter still admits it (documented tradeoff);
/// the drain policy below caps how many get verified per tick.
#[test]
fn verification_committed_bypass_is_capped_per_tick() {
    let commit = ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: crate::consensus::QuorumCertificate {
            shard_id: 0,
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    };
    assert!(inbound_is_critical(&commit));
    // Even a maximal fake proof bypasses the byte limiter...
    let mut lim = InboundBulkLimiter::new(1024, 1024);
    assert_eq!(
        lim.admit("attacker", MAX_CONSENSUS_MSG as u64, true, 1_000),
        InboundDecision::Allow,
        "Committed bypasses the byte limiter at any size (by design)"
    );
    // ...so the tick cap is the bound that stops the CPU burn: the live
    // path needs ~1 proof per finalize, the cap is generous, and the 9th
    // proof in one tick is flood tail.
    for i in 0..COMMITTED_INNER_BUDGET_PER_TICK {
        assert!(
            committed_admit_this_tick(i),
            "proof {i} within cap must verify"
        );
    }
    assert!(
        !committed_admit_this_tick(COMMITTED_INNER_BUDGET_PER_TICK),
        "proofs past the per-tick cap must be dropped, not verified"
    );
}

/// VERIFICATION F3-hardening: the bucket-key gate must hold against a
/// MALICIOUS sender, not just a malformed one.
///
/// Stronger than the original pentest: unicode lookalikes, boundary
/// lengths (128 accepted / 129 shared), non-string JSON values, a bare
/// `inf1:` prefix, whitespace games — and the key property: two distinct
/// malicious senders collapse into the SAME shared bucket (no minting),
/// while honest hex senders keep per-peer isolation.
#[test]
fn verification_peer_key_holds_against_malicious_senders() {
    let shared = INBOUND_BROADCAST_PEER_KEY;
    // Unicode lookalike: full-width/cyrillic hex lookalikes are not ASCII hex.
    let uni = "ab".repeat(10) + "аа"; // trailing chars are Cyrillic 'a'
    assert_eq!(
        inbound_peer_key(&format!(r#"{{"topic":"t","data":"00","src":"{uni}"}}"#)).as_str(),
        shared,
        "unicode sender must not become a bucket"
    );
    // Boundary: exactly 128 hex chars is a distinct bucket...
    let k128 = "ab".repeat(64);
    assert_eq!(k128.len(), 128);
    assert_eq!(
        inbound_peer_key(&format!(r#"{{"topic":"t","data":"00","src":"{k128}"}}"#)).as_str(),
        k128
    );
    // ...129 chars collapses to shared.
    let k129 = format!("{k128}ab");
    assert_eq!(
        inbound_peer_key(&format!(r#"{{"topic":"t","data":"00","src":"{k129}"}}"#)).as_str(),
        shared,
        "a 129-char src must not mint a bucket"
    );
    // Non-string JSON values are not senders.
    for raw in [
        r#"{"topic":"t","data":"00","src":12345}"#.to_string(),
        r#"{"topic":"t","data":"00","src":null}"#.to_string(),
        r#"{"topic":"t","data":"00","src":{"x":1}}"#.to_string(),
        r#"{"topic":"t","data":"00","src":["aa"]}"#.to_string(),
        r#"{"topic":"t","data":"00","src":"inf1:"}"#.to_string(),
        r#"{"topic":"t","data":"00","src":"   "}"#.to_string(),
        r#"{"topic":"t","data":"00","from":"zz-top"}"#.to_string(),
    ] {
        assert_eq!(inbound_peer_key(&raw).as_str(), shared, "raw={raw}");
    }
    // `from` fallback is gated identically (non-hex -> shared, hex distinct).
    assert_eq!(
        inbound_peer_key(r#"{"topic":"t","data":"00","from":"cc"}"#).as_str(),
        "cc"
    );
    // Two distinct malicious senders share ONE bucket: no minting, and the
    // shared bucket still rate-limits the aggregate (it is one token
    // bucket, not an exemption).
    let m1 = inbound_peer_key(r#"{"topic":"t","data":"00","src":"../../evil"}"#);
    let m2 = inbound_peer_key(&format!(r#"{{"topic":"t","data":"00","src":"{k129}"}}"#));
    assert_eq!(m1.as_str(), shared);
    assert_eq!(m2.as_str(), shared);
    let mut lim = InboundBulkLimiter::new(1024, 1024);
    assert_eq!(
        lim.admit(m1.as_str(), 1024, false, 1_000),
        InboundDecision::Allow
    );
    assert!(
        matches!(
            lim.admit(m2.as_str(), 1024, false, 1_000),
            InboundDecision::Defer { .. }
        ),
        "malicious senders share one budget: the second must defer"
    );
    assert_eq!(
        lim.peer_count(),
        1,
        "malicious senders must not grow the map"
    );
}

/// VERIFICATION G1: only an attributable proposal (valid proposer
/// signature + a signer with stake) may plant the catch-up hint.
///
/// Exploit: a single FORGED proposal for H+1 (garbage signature, or a
/// key with no stake) used to set `peer_hint` in the receiver loop
/// before any verification, forcing the catch-up timer every tick and
/// keeping the node on loudly-failing DHT walks. The gate below is what
/// the loop must consult before recording the hint.
#[test]
fn verification_only_attributable_proposals_plant_hints() {
    use crate::consensus::ValidatorSet;
    let sk = SigningKey::generate(&mut OsRng);
    let proposer = sk.verifying_key().to_bytes();
    let mut validators = ValidatorSet::new();
    validators.validators.insert(proposer, 100);
    let mut block = sample_block();
    block.proposer = proposer;
    // Falconize: Ed-only refuses `verify_proposer_signature` (no
    // classical fallback); mirror the runtime proposal path
    // (`runtime.rs` pushes `(self.id, ed_sig)` + `(falcon_id,
    // falcon_sig)`) so the genuine member verifies.
    let fk = crate::consensus::FalconKeypair::generate_from_seed(0xC1);
    crate::consensus::register_validator_pq_key(
        proposer,
        crate::post_quantum::PqScheme::Falcon512,
        fk.public_key.clone(),
    );
    block.sign_block(&sk);
    {
        let hash = block.compute_hash();
        let falcon_id = fk.validator_id();
        let falcon_sig = fk.sign(&hash);
        block.validator_signatures.push((falcon_id, falcon_sig));
    }
    assert!(
        proposal_hint_admissible(&block, &validators),
        "a genuine member proposal must plant the hint"
    );
    // Tamper after signing: the body no longer matches the signature.
    let mut tampered = block.clone();
    tampered.height += 1;
    assert!(
        !proposal_hint_admissible(&tampered, &validators),
        "a tampered proposal must not plant a hint"
    );
    // Valid signature, zero stake: an outsider must not steer catch-up.
    let outsider_sk = SigningKey::generate(&mut OsRng);
    let mut outsider = sample_block();
    outsider.proposer = outsider_sk.verifying_key().to_bytes();
    // Falconize the outsider too (valid signature, still no stake):
    // membership — not signature shape — must be the refusal reason.
    let outsider_fk = crate::consensus::FalconKeypair::generate_from_seed(0xC2);
    crate::consensus::register_validator_pq_key(
        outsider.proposer,
        crate::post_quantum::PqScheme::Falcon512,
        outsider_fk.public_key.clone(),
    );
    outsider.sign_block(&outsider_sk);
    {
        let hash = outsider.compute_hash();
        let falcon_id = outsider_fk.validator_id();
        let falcon_sig = outsider_fk.sign(&hash);
        outsider.validator_signatures.push((falcon_id, falcon_sig));
    }
    assert!(
        !proposal_hint_admissible(&outsider, &validators),
        "a non-member proposal must not plant a hint"
    );
    // Unsigned block: no signatures at all.
    let mut bare = sample_block();
    bare.proposer = proposer;
    bare.validator_signatures.clear();
    assert!(
        !proposal_hint_admissible(&bare, &validators),
        "an unsigned proposal must not plant a hint"
    );
}

/// P1-G2..G4 closure pin (R3 CODE-TAILS sweep): G2–G4 were filed as bare
/// IDs with no recorded content (see the `P1-G2..G4 — ACCEPTED` note on
/// [`proposal_hint_admissible`]), so the only verifiable statement is
/// that the G-series bookends — G1 (hint attribution) and G5 (oracle
/// fetch re-verification) — hold. This test re-asserts both through the
/// same pure gates the feature tests use, so a future audit can confirm
/// the series is closed without re-diagnosing the middle IDs.
///
/// FULL-PQ (mirrors `network::retention_tests::
/// verification_oracle_fetch_reverifies_signature`): classical Ed25519
/// feed verification is removed with no PQ feed path (wire frozen), so
/// EVERY classical feed — genuine, tampered, or self-consistent forgery
/// — reads as a miss. Same fail-closed property, stronger verdict.
#[test]
fn report_p1_g2_g4_filed_without_content_is_closed_as_accepted() {
    use crate::consensus::ValidatorSet;
    // Bookend G1: attribution still requires membership, not just a
    // valid signature.
    let sk = SigningKey::generate(&mut OsRng);
    let proposer = sk.verifying_key().to_bytes();
    let mut validators = ValidatorSet::new();
    validators.validators.insert(proposer, 100);
    let mut block = sample_block();
    block.proposer = proposer;
    // Falconize (same envelope as the G1 test above): Ed-only refuses
    // `verify_proposer_signature`, so the genuine member carries the
    // runtime-style `(falcon_id, falcon_sig)` half.
    let fk = crate::consensus::FalconKeypair::generate_from_seed(0xC3);
    crate::consensus::register_validator_pq_key(
        proposer,
        crate::post_quantum::PqScheme::Falcon512,
        fk.public_key.clone(),
    );
    block.sign_block(&sk);
    {
        let hash = block.compute_hash();
        let falcon_id = fk.validator_id();
        let falcon_sig = fk.sign(&hash);
        block.validator_signatures.push((falcon_id, falcon_sig));
    }
    assert!(proposal_hint_admissible(&block, &validators));
    let outsider_sk = SigningKey::generate(&mut OsRng);
    let mut outsider = sample_block();
    outsider.proposer = outsider_sk.verifying_key().to_bytes();
    let outsider_fk = crate::consensus::FalconKeypair::generate_from_seed(0xC4);
    crate::consensus::register_validator_pq_key(
        outsider.proposer,
        crate::post_quantum::PqScheme::Falcon512,
        outsider_fk.public_key.clone(),
    );
    outsider.sign_block(&outsider_sk);
    {
        let hash = outsider.compute_hash();
        let falcon_id = outsider_fk.validator_id();
        let falcon_sig = outsider_fk.sign(&hash);
        outsider.validator_signatures.push((falcon_id, falcon_sig));
    }
    assert!(!proposal_hint_admissible(&outsider, &validators));
    // Bookend G5: stored oracle bytes are re-verified on the way out —
    // under FULL-PQ every classical feed reads as a miss (no PQ feed
    // path), so a re-priced feed with the old signature reads as a miss,
    // and so does the genuine one — never as market evidence.
    let feed = crate::oracle::PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &sk);
    let stored = hex::encode(bincode::serialize(&feed).unwrap());
    assert!(crate::network::decode_verified_price_feed(&stored).is_none());
    let mut tampered = feed.clone();
    tampered.price_micro_usd = 1;
    let bad = hex::encode(bincode::serialize(&tampered).unwrap());
    assert!(crate::network::decode_verified_price_feed(&bad).is_none());
}

#[test]
fn batch_roundtrip_preserves_order() {
    let sk = SigningKey::generate(&mut OsRng);
    let v1 = Vote::sign(&sk, 1, 0, VoteKind::Prevote, Some([1u8; 32]));
    let v2 = Vote::sign(&sk, 1, 0, VoteKind::Precommit, None);
    let items = vec![
        ConsensusMsg::Vote {
            vote: v1,
            locked: None,
        },
        ConsensusMsg::Vote {
            vote: v2,
            locked: Some([2u8; 32]),
        },
        ConsensusMsg::Proposal {
            height: 7,
            round: 0,
            block: sample_block(),
        },
    ];
    let bytes = ConsensusMsg::batch_encode(&items).unwrap();
    assert!(bytes.len() <= MAX_BATCH_BYTES);
    match ConsensusMsg::decode(&bytes).unwrap() {
        ConsensusMsg::Batch(inner) => {
            assert_eq!(inner.len(), 3);
            assert!(matches!(inner[0], ConsensusMsg::Vote { .. }));
            assert!(matches!(inner[1], ConsensusMsg::Vote { .. }));
            assert!(matches!(inner[2], ConsensusMsg::Proposal { .. }));
        }
        _ => panic!("must decode as Batch"),
    }
    // free-function helper agrees
    let bytes2 = batch_encode(&items).unwrap();
    assert_eq!(bytes, bytes2);
}

#[test]
fn batch_rejects_nested() {
    let sk = SigningKey::generate(&mut OsRng);
    let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
    let inner = ConsensusMsg::Batch(vec![ConsensusMsg::Vote {
        vote: v,
        locked: None,
    }]);
    let outer = ConsensusMsg::Batch(vec![inner]);
    // batch_encode rejects nesting up front
    if let ConsensusMsg::Batch(items) = &outer {
        assert!(ConsensusMsg::batch_encode(items).is_err());
    } else {
        panic!("expected Batch");
    }
    // and decode rejects a nested payload crafted past the encoder
    let raw = bincode::serialize(&outer).unwrap();
    let err = ConsensusMsg::decode(&raw).unwrap_err();
    assert!(err.contains("nested"), "got: {err}");
}

#[test]
fn batch_rejects_over_items() {
    let sk = SigningKey::generate(&mut OsRng);
    let items: Vec<ConsensusMsg> = (0..(MAX_BATCH_ITEMS + 1) as u64)
        .map(|i| ConsensusMsg::Vote {
            vote: Vote::sign(&sk, i, 0, VoteKind::Prevote, None),
            locked: None,
        })
        .collect();
    assert!(ConsensusMsg::batch_encode(&items).is_err());
    // decode path enforces the same bound
    let raw = bincode::serialize(&ConsensusMsg::Batch(items)).unwrap();
    let err = ConsensusMsg::decode(&raw).unwrap_err();
    assert!(err.contains("too many"), "got: {err}");
}

#[test]
fn batch_rejects_over_bytes() {
    // Unsigned dummy txs: only the encoded size matters here.
    let txs: Vec<Transaction> = (0..4000)
        .map(|i| Transaction {
            from: [1u8; 32],
            to: [2u8; 32],
            amount: i,
            gas_limit: 5,
            nonce: i,
            source_shard: 1,
            target_shard: 1,
            signature: vec![0u8; 64],
            payload: vec![],
            priority_fee_per_gas: 0,
        })
        .collect();
    let sk = SigningKey::generate(&mut OsRng);
    let mut big = sample_block();
    big.transactions = txs;
    big.sign_block(&sk);
    let msg = ConsensusMsg::Proposal {
        height: 7,
        round: 0,
        block: big,
    };
    assert!(
        msg.encode().unwrap().len() > MAX_BATCH_BYTES,
        "fixture must exceed the batch cap"
    );
    let items = vec![msg.clone(), msg];
    assert!(ConsensusMsg::batch_encode(&items).is_err());
    let raw = bincode::serialize(&ConsensusMsg::Batch(items)).unwrap();
    assert!(raw.len() > MAX_BATCH_BYTES);
    let err = ConsensusMsg::decode(&raw).unwrap_err();
    assert!(err.contains("too large"), "got: {err}");
}

#[test]
fn batch_rejects_empty() {
    let empty: Vec<ConsensusMsg> = vec![];
    assert!(ConsensusMsg::batch_encode(&empty).is_err());
    let raw = bincode::serialize(&ConsensusMsg::Batch(empty)).unwrap();
    assert!(ConsensusMsg::decode(&raw).is_err());
}

#[test]
fn old_decoder_rejects_batch() {
    // Pre-batch software has no Batch variant: it must fail closed on
    // batch bytes rather than misreading them as a proposal/vote.
    #[derive(serde::Serialize, serde::Deserialize)]
    enum OldConsensusMsg {
        Proposal {
            height: u64,
            round: u32,
            block: Block,
        },
        Vote {
            vote: Vote,
            locked: Option<[u8; 32]>,
        },
        Committed {
            height: u64,
            block: Block,
            certificate: crate::consensus::QuorumCertificate,
        },
    }
    let sk = SigningKey::generate(&mut OsRng);
    let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
    let bytes = ConsensusMsg::batch_encode(&[ConsensusMsg::Vote {
        vote: v,
        locked: None,
    }])
    .unwrap();
    let res: Result<OldConsensusMsg, _> = bincode::deserialize(&bytes);
    assert!(res.is_err(), "old decoder must reject batch bytes");
}

#[test]
fn is_large_flags_proposals_and_commits() {
    let sk = SigningKey::generate(&mut OsRng);
    let v = Vote::sign(&sk, 1, 0, VoteKind::Prevote, None);
    let vote = ConsensusMsg::Vote {
        vote: v,
        locked: None,
    };
    assert!(!is_large(&vote));
    assert!(!vote.is_large());
    assert!(ConsensusMsg::Proposal {
        height: 1,
        round: 0,
        block: sample_block()
    }
    .is_large());
}

#[test]
fn tx_gossip_roundtrip_and_fail_closed() {
    // FULL-PQ: implicit Falcon-512 envelope (mirrors the mempool `tx`
    // idiom); a classical `Transaction::sign` no longer verifies.
    let seed = 0x42u8;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = crate::post_quantum::derive_pq_address(
        crate::post_quantum::PqScheme::Falcon512,
        &pk,
        &crate::post_quantum::DEFAULT_SALT,
    );
    Transaction::global_implicit_registry()
        .register(
            from,
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        )
        .expect("PQ test key must register");
    let mut tx = Transaction {
        from,
        to: [1u8; 32],
        amount: 10,
        gas_limit: 5,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = crate::sharding::PqSignatureEnvelope::new_implicit(
        crate::post_quantum::PqScheme::Falcon512,
        sig,
    )
    .encode();
    let bytes = bincode::serialize(&tx).unwrap();
    let raw =
        serde_json::json!({ "topic": tx_topic("test"), "data": hex::encode(bytes) }).to_string();
    let parsed = parse_tx_incoming(&raw).unwrap();
    assert_eq!(parsed.amount, 10);
    assert!(parsed.verify_signature());

    // fail-closed on garbage
    assert!(parse_tx_incoming("not json").is_none());
    assert!(parse_tx_incoming(r#"{"data":"zz"}"#).is_none());
}

/// Build a vote message directly (no signing) whose `height` identifies it.
/// Structural only: these tests exercise queue ordering, not crypto.
fn tagged_vote(height: u64) -> ConsensusMsg {
    ConsensusMsg::Vote {
        vote: Vote {
            shard_id: 0,
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

fn tagged_height(msg: &ConsensusMsg) -> u64 {
    match msg {
        ConsensusMsg::Vote { vote, .. } => vote.height,
        _ => u64::MAX,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordered_sender_preserves_fifo_order_under_slow_first_send() {
    // Regression for the transport decoupling: chunks must reach the wire in
    // the order they were drained even when the FIRST send is slow (the live
    // case: the peer's handler is not scheduled for hundreds of ms). The
    // sender serializes them, so order is never sacrificed to overlap.
    let seen = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
    let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let sender = spawn_ordered_sender({
        let seen = Arc::clone(&seen);
        let first = Arc::clone(&first);
        move |chunk: BroadcastChunk| {
            let seen = Arc::clone(&seen);
            let first = Arc::clone(&first);
            async move {
                let id = tagged_height(&chunk[0]);
                if first.swap(false, Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                }
                seen.lock().unwrap().push(id);
            }
        }
    });

    for id in 0u64..5 {
        assert!(
            sender.enqueue(vec![tagged_vote(id)]),
            "enqueue {id} must succeed"
        );
    }
    assert_eq!(
        sender.queued(),
        5,
        "all five chunks are pending before send"
    );

    // The enqueue path is non-blocking: five chunks are already queued while
    // the worker is still sleeping on the first.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while seen.lock().unwrap().len() < 5 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        *seen.lock().unwrap(),
        vec![0, 1, 2, 3, 4],
        "FIFO order must hold"
    );
    assert_eq!(sender.queued(), 0, "pending must drain to zero");
}

#[test]
fn superseded_votes_drop_without_touching_proposals_or_commits() {
    // Tail-killer contract: a vote two rounds old at the same height is
    // worthless (no quorum can form there anymore); everything else —
    // proposals, commits, other heights, fresh votes — survives.
    let sk = SigningKey::generate(&mut OsRng);
    let old_prevote = ConsensusMsg::Vote {
        vote: Vote::sign(&sk, 9, 3, VoteKind::Prevote, Some([1u8; 32])),
        locked: None,
    };
    assert!(is_superseded_vote(&old_prevote, 9, 5));
    assert!(is_superseded_vote(&old_prevote, 9, 6));
    assert!(!is_superseded_vote(&old_prevote, 9, 4), "r+1 still counts");
    assert!(
        !is_superseded_vote(&old_prevote, 10, 5),
        "other heights never drop"
    );
    assert!(!is_superseded_vote(
        &ConsensusMsg::Proposal {
            height: 9,
            round: 0,
            block: sample_block()
        },
        9,
        99,
    ));
    let commit = ConsensusMsg::Committed {
        height: 9,
        block: sample_block(),
        certificate: crate::consensus::QuorumCertificate {
            shard_id: 0,
            height: 9,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: None,
            signatures: vec![],
        },
    };
    assert!(!is_superseded_vote(&commit, 9, 99));
    let late_precommit = ConsensusMsg::Vote {
        vote: Vote::sign(&sk, 9, 0, VoteKind::Precommit, Some([1u8; 32])),
        locked: None,
    };
    assert!(
        !is_superseded_vote(&late_precommit, 9, 11),
        "late-polka precommit at r0 must not be dropped when local round is 11"
    );
}

#[test]
fn coalesce_for_send_dedups_and_prunes_in_order() {
    // Duplicate RX coalescing at SEND time: identical votes collapse to
    // the first, superseded ones vanish, proposals keep their slots.
    let sk = SigningKey::generate(&mut OsRng);
    let v = || ConsensusMsg::Vote {
        vote: Vote::sign(&sk, 9, 4, VoteKind::Prevote, Some([1u8; 32])),
        locked: None,
    };
    let stale = ConsensusMsg::Vote {
        vote: Vote::sign(&sk, 9, 1, VoteKind::Prevote, Some([1u8; 32])),
        locked: None,
    };
    let p = ConsensusMsg::Proposal {
        height: 9,
        round: 5,
        block: sample_block(),
    };
    let out = coalesce_for_send(vec![v(), v(), stale, p.clone(), v()], 9, 5);
    assert_eq!(
        out.len(),
        2,
        "one live vote + the proposal, got {}",
        out.len()
    );
    assert!(matches!(out[0], ConsensusMsg::Vote { .. }));
    assert!(matches!(out[1], ConsensusMsg::Proposal { .. }));
}

#[test]
fn vote_send_filter_coalesces_duplicates_but_passes_retries_and_nonvotes() {
    // Send-time dedupe across flushes: the second copy inside the window
    // dies, a retry after the window passes, proposals always pass.
    let sk = SigningKey::generate(&mut OsRng);
    let v = ConsensusMsg::Vote {
        vote: Vote::sign(&sk, 9, 4, VoteKind::Prevote, Some([1u8; 32])),
        locked: None,
    };
    let p = ConsensusMsg::Proposal {
        height: 9,
        round: 4,
        block: sample_block(),
    };
    let t0 = Instant::now();
    let mut f = VoteSendFilter::new(Duration::from_millis(200));
    assert!(f.should_send(&v, t0));
    assert!(
        !f.should_send(&v, t0 + Duration::from_millis(50)),
        "same-tick dup must coalesce"
    );
    assert!(
        f.should_send(&p, t0 + Duration::from_millis(50)),
        "proposals never deduped"
    );
    assert!(
        f.should_send(&p, t0 + Duration::from_millis(51)),
        "proposals never deduped twice"
    );
    assert!(
        f.should_send(&v, t0 + Duration::from_millis(1000)),
        "loss-recovery retry past the window must pass"
    );
}

#[test]
fn retransmit_backoff_starts_fast_then_relaxes_without_thundering() {
    // Front-loaded loss recovery, then backoff, capped so a wedged round
    // never storms. At the live 800ms timeout the first retransmit fires
    // after 150ms (`base = clamp(T/10, 150, 350)`), then 300ms, then the
    // round timeout itself.
    assert_eq!(retransmit_interval_ms(800, 0), 150);
    assert_eq!(retransmit_interval_ms(800, 399), 300);
    assert_eq!(retransmit_interval_ms(800, 400), 800);
    assert_eq!(
        retransmit_interval_ms(800, 10_000),
        1600,
        "capped at 2x timeout"
    );
    // Small timeouts keep a sane floor instead of a hot loop.
    assert_eq!(retransmit_interval_ms(200, 0), 150);
}

#[test]
fn retransmit_schedule_is_front_loaded_at_the_live_round_timeout() {
    // Live 3000ms round timeout: the FIRST retransmit must be sub-block
    // (<= 400ms), not the old `T/2 = 1500ms` that turned one lost packet
    // into a multi-second stall (incident: block #21508 took 7.54s).
    let first = retransmit_interval_ms(3000, 0);
    assert!(
        first <= 400,
        "first retransmit at a 3000ms timeout must be <= 400ms, got {first}ms"
    );
    assert!(
        first >= 250,
        "first retransmit must not be a hot loop: {first}ms"
    );
    // Second tier is roughly double the first, still well under T.
    let second = retransmit_interval_ms(3000, 500);
    assert_eq!(second, first * 2);
    // Mid-round tier is the round timeout itself.
    assert_eq!(retransmit_interval_ms(3000, 1500), 3000);
    // And the schedule still covers a wedged round: it reaches the 2T cap.
    assert_eq!(retransmit_interval_ms(3000, 6000), 6000);
    assert_eq!(retransmit_interval_ms(3000, 60_000), 6000);
}

#[tokio::test]
async fn ordered_sender_saturation_returns_false_without_dropping() {
    // Backpressure contract: once the queue is at MAX_PENDING_CHUNKS further
    // enqueues are refused and do not consume another slot. The bool
    // compatibility wrapper drops refused chunks; use try_enqueue to retain them.
    let sender = spawn_ordered_sender(|_chunk: BroadcastChunk| async {
        // Never completes within the test window: models a wedged transport.
        std::future::pending::<()>().await;
    });

    let cap = MAX_PENDING_CHUNKS;
    for i in 0..cap {
        assert!(
            sender.enqueue(vec![tagged_vote(i as u64)]),
            "chunk {i} within the cap must be accepted"
        );
    }
    assert_eq!(sender.queued(), cap);
    assert!(
        !sender.enqueue(vec![tagged_vote(255)]),
        "enqueue past MAX_PENDING_CHUNKS must be refused, not silently dropped"
    );
    assert_eq!(
        sender.queued(),
        cap,
        "a refused enqueue must not consume a slot"
    );
}

#[test]
fn sender_refusal_returns_chunk_and_rolls_back_closed_reservation() {
    let (tx, rx) = mpsc::unbounded_channel();
    let sender = ConsensusSender {
        tx,
        pending: Arc::new(AtomicUsize::new(0)),
    };
    drop(rx);
    let returned = sender.try_enqueue(vec![tagged_vote(73)]).unwrap_err();
    assert_eq!(tagged_height(&returned[0]), 73);
    assert_eq!(sender.queued(), 0);
}

#[test]
fn sender_refusal_at_usize_max_does_not_overflow() {
    let (tx, _rx) = mpsc::unbounded_channel();
    let sender = ConsensusSender {
        tx,
        pending: Arc::new(AtomicUsize::new(usize::MAX)),
    };
    let returned = sender.try_enqueue(vec![tagged_vote(74)]).unwrap_err();
    assert_eq!(tagged_height(&returned[0]), 74);
    assert_eq!(sender.queued(), usize::MAX);
}

#[tokio::test]
async fn sender_task_failure_releases_inflight_and_queued_reservations() {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut started_tx = Some(started_tx);
    let mut release_rx = Some(release_rx);
    let sender = spawn_ordered_sender(move |_chunk| {
        let started = started_tx.take().unwrap();
        let release = release_rx.take().unwrap();
        async move {
            started.send(()).unwrap();
            release.await.unwrap();
            panic!("controlled sender failure");
        }
    });
    let clone = sender.clone();
    assert!(sender.try_enqueue(vec![tagged_vote(1)]).is_ok());
    started_rx.await.unwrap();
    assert!(clone.try_enqueue(vec![tagged_vote(2)]).is_ok());
    assert_eq!(sender.queued(), 2);
    release_tx.send(()).unwrap();
    clone.tx.closed().await;
    assert_eq!(sender.queued(), 0);
    let returned = clone.try_enqueue(vec![tagged_vote(3)]).unwrap_err();
    assert_eq!(tagged_height(&returned[0]), 3);
    assert_eq!(sender.queued(), 0);
}

#[test]
fn sender_refusal_concurrent_reservations_do_not_exceed_cap() {
    let (tx, _rx) = mpsc::unbounded_channel();
    let sender = ConsensusSender {
        tx,
        pending: Arc::new(AtomicUsize::new(MAX_PENDING_CHUNKS - 1)),
    };
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let mut threads = Vec::new();
    for i in 0..8 {
        let sender = sender.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            sender.try_enqueue(vec![tagged_vote(i)]).is_ok()
        }));
    }
    barrier.wait();
    assert_eq!(
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        1
    );
    assert_eq!(sender.queued(), MAX_PENDING_CHUNKS);
    let returned = sender.try_enqueue(vec![tagged_vote(99)]).unwrap_err();
    assert_eq!(tagged_height(&returned[0]), 99);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sender_refusal_fast_receiver_never_underflows_pending() {
    let sender = spawn_ordered_sender(|_chunk| async {});
    for i in 0..2000 {
        let mut chunk = vec![tagged_vote(i)];
        loop {
            match sender.try_enqueue(chunk) {
                Ok(()) => break,
                Err(returned) => {
                    chunk = returned;
                    tokio::task::yield_now().await;
                }
            }
        }
        assert!(sender.queued() <= MAX_PENDING_CHUNKS);
    }
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while sender.queued() != 0 {
            assert!(sender.queued() <= MAX_PENDING_CHUNKS);
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(result.is_ok(), "pending did not drain");
}

/// Structural µQC QC fixture (signature bytes are patterned filler, NOT
/// crypto — verification stays in `QuorumCertificate::verify` and is
/// never exercised here; only framing round-trips).
fn sample_micro_qc(
    committee_size: u32,
    signers: &[usize],
    sig_len: usize,
) -> crate::consensus::QuorumCertificate {
    use crate::consensus::PqMicroCertificate;
    let mut bits = vec![false; committee_size as usize];
    for &i in signers {
        bits[i] = true;
    }
    let cert = PqMicroCertificate::new(
        crate::post_quantum::PqScheme::Falcon512,
        900,
        3,
        committee_size,
        compact_prop::pack_bitfield(&bits),
        signers
            .iter()
            .map(|&i| vec![(i as u8).wrapping_mul(3).wrapping_add(5); sig_len])
            .collect(),
        [0x77u8; 32],
    );
    let env = crate::consensus::encode_pq_micro_envelope(&cert);
    crate::consensus::QuorumCertificate {
        shard_id: 0,
        height: 900,
        round: 3,
        kind: VoteKind::Precommit,
        block_hash: Some([0xABu8; 32]),
        signatures: vec![(crate::consensus::PQ_UQC_MARKER_ID, env)],
    }
}

#[test]
fn compact_qc_gossip_round_trip() {
    // µQC QC -> compact frame -> rebuilt QC: routing fields equal and the
    // re-wrapped envelope byte-identical (verifier sees the same bytes).
    let qc = sample_micro_qc(7, &[0, 2, 4], 666);
    let frame = encode_compact_qc_gossip(&qc).expect("µQC QC must compact-encode");
    assert!(
        frame.starts_with(compact_prop::COMPACT_QC_MAGIC),
        "new envelope kind carries the new magic"
    );
    let back = decode_compact_qc_gossip(&frame).expect("must decode");
    assert_eq!(back.height, qc.height);
    assert_eq!(back.round, qc.round);
    assert_eq!(back.kind, qc.kind);
    assert_eq!(back.block_hash, qc.block_hash);
    assert_eq!(
        back.signatures, qc.signatures,
        "rebuilt µQC envelope must be byte-identical"
    );
    // A QC with no µQC envelope refuses: the caller keeps the full path.
    let bare = crate::consensus::QuorumCertificate {
        shard_id: 0,
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: None,
        signatures: vec![],
    };
    assert!(encode_compact_qc_gossip(&bare).is_err());
    // An Epoch/CEC envelope is NOT compacted either (µQC-only wiring).
    let mut epoch_qc = sample_micro_qc(7, &[0, 2, 4], 666);
    let (cert_h, cert_r) = (epoch_qc.height, epoch_qc.round);
    let bits = vec![true, false, true, false, true, false, false];
    let cert = crate::consensus::PqMicroCertificate::new(
        crate::post_quantum::PqScheme::Falcon512,
        cert_h,
        cert_r,
        7,
        compact_prop::pack_bitfield(&bits),
        vec![vec![9u8; 666], vec![10u8; 666], vec![11u8; 666]],
        [0x77u8; 32],
    );
    epoch_qc.signatures = vec![(
        crate::consensus::PQ_QC_MARKER_ID,
        crate::consensus::encode_pq_epoch_envelope(&cert),
    )];
    assert!(
        encode_compact_qc_gossip(&epoch_qc).is_err(),
        "epoch envelopes keep the full Committed path"
    );
}

#[test]
fn old_parser_ignores_compact_qc() {
    // Interop: software WITHOUT this change (old nodes) never emits the
    // new magic and must IGNORE the frame, never choke. Today's parser IS
    // the old parser for an un-upgraded node, so the frame must fail
    // closed through it — no misread, no panic.
    #[derive(serde::Serialize, serde::Deserialize)]
    enum OldConsensusMsg {
        Proposal {
            height: u64,
            round: u32,
            block: Block,
        },
        Vote {
            vote: Vote,
            locked: Option<[u8; 32]>,
        },
        Committed {
            height: u64,
            block: Block,
            certificate: crate::consensus::QuorumCertificate,
        },
        Batch(Vec<OldConsensusMsg>),
    }
    let qc = sample_micro_qc(7, &[0, 2, 4], 666);
    let frame = encode_compact_qc_gossip(&qc).expect("must encode");
    assert!(
        ConsensusMsg::decode(&frame).is_err(),
        "the current (== old) parser must reject the new frame"
    );
    let res: Result<OldConsensusMsg, _> = bincode::deserialize(&frame);
    assert!(res.is_err(), "old decoder must reject the new frame");
    // Same at the pubsub framing layer: the old path ignores it.
    let raw = serde_json::json!({ "topic": consensus_topic("test"), "data": hex::encode(&frame) })
        .to_string();
    assert!(
        parse_incoming(&raw).is_none(),
        "old inbound path must ignore the new frame"
    );
}

#[test]
fn compact_qc_gossip_tamper_refusal() {
    // Frame-level fail-closed on STRUCTURE (crypto verification
    // downstream stays untouched and refuses forgeries anyway: a flip
    // inside a signature PAYLOAD still decodes structurally — different
    // bytes — and only fails at `QuorumCertificate::verify`).
    let qc = sample_micro_qc(7, &[0, 2, 4], 666);
    let frame = encode_compact_qc_gossip(&qc).expect("must encode");
    assert!(decode_compact_qc_gossip(&frame).is_some());
    // Structural flips refuse: kind tag (to an out-of-range value) and
    // bitmask-length prefix.
    let mut flipped_kind = frame.clone();
    flipped_kind[8 + 8 + 4] = 0x02;
    assert_eq!(decode_compact_qc_gossip(&flipped_kind), None);
    let bitlen_off = 8 + 8 + 4 + 1 + 1 + 32 + 1 + 4 + 32;
    let mut flipped_len = frame.clone();
    flipped_len[bitlen_off] ^= 0x01;
    assert_eq!(decode_compact_qc_gossip(&flipped_len), None);
    // Signature-payload flip decodes structurally but to DIFFERENT
    // content (downstream `verify` refuses the forgery — the codec is
    // structural, never crypto).
    let mut flipped = frame.clone();
    flipped[frame.len() / 2] ^= 0x01;
    let tampered =
        decode_compact_qc_gossip(&flipped).expect("payload flip stays structurally valid");
    let orig = decode_compact_qc_gossip(&frame).expect("must decode");
    assert_ne!(tampered, orig, "payload mutation must change the QC");
    assert_eq!(decode_compact_qc_gossip(&frame[..frame.len() - 1]), None);
    let mut padded = frame.clone();
    padded.push(0x00);
    assert_eq!(decode_compact_qc_gossip(&padded), None);
    assert_eq!(decode_compact_qc_gossip(&[]), None);
    assert_eq!(decode_compact_qc_gossip(&[0xFF; 100]), None);
    assert_eq!(
        decode_compact_qc_gossip(&frame[8..]),
        None,
        "stripped magic must refuse"
    );
}

#[test]
fn compact_gossip_activation_boundary() {
    // ACTIVE from genesis: this is a new chain, so height 0 already
    // gossips compactly. The frozen `u64::MAX` sentinel height is still
    // never admitted.
    assert_eq!(COMPACT_GOSSIP_ACTIVATION_HEIGHT, 0);
    assert!(compact_gossip_active(0));
    assert!(compact_gossip_active(1));
    assert!(compact_gossip_active(u64::MAX - 1));
    assert!(compact_gossip_admits(0));
    assert!(!compact_gossip_admits(u64::MAX));

    // Below a temporary non-zero gate NOTHING compacts — every variant,
    // even a convertible Committed with a real µQC inside: the send path
    // is byte-identical to the pre-compact wire.
    with_compact_gossip_gate(1_000, || {
        assert!(!compact_gossip_active(900));
        assert!(compact_gossip_active(1_000));
        let qc = sample_micro_qc(7, &[0, 2, 4], 666);
        let commit = ConsensusMsg::Committed {
            height: 900,
            block: sample_block(),
            certificate: qc,
        };
        assert!(compact_gossip_bytes_for(&commit).is_none());
        assert!(compact_gossip_bytes_for(&tagged_vote(1)).is_none());
        assert!(compact_gossip_bytes_for(&ConsensusMsg::Proposal {
            height: 1,
            round: 0,
            block: sample_block(),
        })
        .is_none());
        assert!(compact_gossip_bytes_for(&ConsensusMsg::Batch(vec![tagged_vote(1)])).is_none());
        // And admission refuses even a well-formed frame below the gate.
        let cert = match &commit {
            ConsensusMsg::Committed { certificate, .. } => certificate,
            _ => unreachable!(),
        };
        let frame = encode_compact_qc_gossip(cert).expect("codec itself is ungated");
        let raw = serde_json::json!({
            "topic": consensus_topic("test"),
            "data": hex::encode(&frame)
        })
        .to_string();
        assert!(
            parse_compact_qc_incoming(&raw).is_none(),
            "admission stays off below the gate"
        );
    });

    // At the live gate the same commit compacts and admission accepts it.
    let qc = sample_micro_qc(7, &[0, 2, 4], 666);
    let commit = ConsensusMsg::Committed {
        height: 900,
        block: sample_block(),
        certificate: qc,
    };
    let frame = compact_gossip_bytes_for(&commit).expect("live gate must compact a µQC commit");
    let raw = serde_json::json!({ "topic": consensus_topic("test"), "data": hex::encode(&frame) })
        .to_string();
    assert!(parse_compact_qc_incoming(&raw).is_some());
}

#[test]
fn compact_vs_full_qc_size_64_seat() {
    // 64 seats, full-sign, Falcon-512 sigs — the live finality shape.
    // Full = bincode `QuorumCertificate` carrying ONE µQC envelope under
    // `PQ_UQC_MARKER_ID` (the live path: outer framing 97 B + envelope
    // 42961 B); compact = the new frame (bitfield-indexed, 107 B +
    // sigs). Same signatures, so the delta is pure framing savings —
    // honest wire math, measured here, not projected.
    let signers: Vec<usize> = (0..64).collect();
    let qc = sample_micro_qc(64, &signers, compact_prop::COMPACT_QC_SIG_LEN_FALCON);
    let full = bincode::serialize(&qc).expect("QC must serialize").len();
    let compact = encode_compact_qc_gossip(&qc).expect("must compact").len();
    // Layout math (live µQC-envelope shape, `PqMicroCertificate` in consensus.rs):
    // envelope = 16 magic + 32 parent + 1 scheme + 8 height + 4 round
    //   + 4 committee + 4 bitmask_len + 8 bitmask + 4 sig_count
    //   + 64*(4 len + 666 sig) = 42961;
    // full = 8 height + 4 round + 4 kind + 1 hash_flag + 32 hash
    //   + 8 vec_len + 32 marker + 8 env_len + envelope
    //   + 4 shard_id (the V3 vote binding) = 101 + 42961;
    // compact (compact_prop.rs:compact_qc_bytes) = 8 magic + 8 height
    //   + 4 round + 1 kind + 1 hash_flag + 32 hash + 1 scheme + 4
    //   committee + 32 parent + 4 bitmask_len + 8 bitmask + 4 sig_count
    //   + 64*(4 len + 666 sig) = 107 + 64*(4+666).
    assert_eq!(full, 101 + 42961);
    assert_eq!(full, 43062);
    assert_eq!(compact, 107 + 64 * (4 + 666));
    assert_eq!(compact, 42987);
    assert_eq!(
        compact,
        compact_prop::compact_qc_bytes(64, 64, compact_prop::COMPACT_QC_SIG_LEN_FALCON, true)
    );
    assert!(
        compact < full,
        "compact {compact} must beat full {full} on identical sig material"
    );
    // 75 B saved on the live shape = 101 (outer QC framing incl. the
    // shard binding) - 26 (compact cert framing 107 vs envelope 81).
    assert_eq!(full - compact, 75);
}

#[cfg(test)]
mod epoch_topic_tests {
    use super::*;

    #[test]
    fn consensus_and_tx_topics_are_scoped_to_the_chain_epoch() {
        // The property that fixes the live symptom: a node on a new genesis must not
        // hear the previous chain's votes and proposals, which were relayed under a
        // fixed topic name and produced endless "wrong height" / state-root rejections.
        let a = consensus_topic("aaaa");
        let b = consensus_topic("bbbb");
        assert_ne!(a, b, "two chains must not share a consensus topic");
        assert_ne!(tx_topic("aaaa"), tx_topic("bbbb"));

        // Distinct namespaces for the two message kinds, so a tx cannot be mistaken
        // for consensus traffic.
        assert_ne!(consensus_topic("aaaa"), tx_topic("aaaa"));

        // Same chain, same topic, every time.
        assert_eq!(consensus_topic("aaaa"), consensus_topic("aaaa"));
    }
}

/// Decoder fuzz regressions (Agent 1): everything a peer sends is untrusted.
/// A panic here is a remote DoS. Appended without touching existing code.
#[cfg(test)]
mod decoder_fuzz_regressions {
    use super::*;

    #[test]
    fn adversarial_prefixes_never_panic() {
        let mut corpus = vec![vec![], vec![0xFF], vec![0u8; 128]];
        if let Ok(bytes) = (ConsensusMsg::Vote {
            vote: crate::consensus::Vote::signed_with(
                [7u8; 32],
                1,
                0,
                crate::consensus::VoteKind::Prevote,
                None,
                vec![0u8; 64],
            ),
            locked: None,
        }
        .encode())
        {
            for n in 0..bytes.len() {
                corpus.push(bytes[..n].to_vec());
            }
            let mut maxed = bytes.clone();
            if !maxed.is_empty() {
                maxed[0] = 0xFF;
                for b in maxed.iter_mut() {
                    *b = 0xFF;
                }
                corpus.push(maxed);
            }
        }
        for input in &corpus {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = ConsensusMsg::decode(input);
            }));
            assert!(
                r.is_ok(),
                "ConsensusMsg::decode panicked on len {}",
                input.len()
            );
        }
        for raw in ["", "not json", "{}", r#"{"data": "zz"}"#] {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = parse_incoming(raw);
                let _ = parse_tx_incoming(raw);
            }));
            assert!(r.is_ok(), "parse_* panicked on {raw:?}");
        }
    }
}

/// O1x optimisations (O8 `is_large`, O9 limiter key allocation, O10
/// fixed-size peer key). Each test is a differential pin against a test-local
/// copy of the pre-optimisation algorithm.
#[cfg(test)]
mod o1x_tests {
    use super::*;
    use crate::consensus::{Vote, VoteKind};
    use std::collections::HashMap;

    /// O8: for every vote shape, the arithmetic classification equals the old
    /// `serialize().len() >= 64 KiB` classification, and the formula is the
    /// exact encoded length.
    #[test]
    fn o8_vote_is_large_matches_serialized_length() {
        let voter = [0x77u8; 32];
        let mut lengths: Vec<usize> = (0..=150).collect();
        lengths.extend([666, 1024, 4096, 32_768, 6 * 1024 * 1024]);

        for &hash in &[None, Some([0x31u8; 32])] {
            for &locked in &[None, Some([0x99u8; 32])] {
                // Exact threshold boundary for this option shape.
                let probe = Vote::signed_with_in_shard(
                    voter,
                    0,
                    11,
                    4,
                    VoteKind::Precommit,
                    hash,
                    Vec::new(),
                );
                let header = vote_encoded_len(&probe, &locked) - probe.signature.len();
                for delta in 0..3usize {
                    lengths.push(64usize * 1024 - (header + delta));
                    lengths.push((64 * 1024) + delta);
                }
                for &len in &lengths {
                    let vote = Vote::signed_with_in_shard(
                        voter,
                        1,
                        11,
                        4,
                        VoteKind::Prevote,
                        hash,
                        vec![0xAB; len],
                    );
                    let msg = ConsensusMsg::Vote {
                        vote: vote.clone(),
                        locked,
                    };
                    assert_eq!(
                        vote_encoded_len(&vote, &locked),
                        msg.encode().expect("vote encodes").len(),
                        "formula must equal bincode length (len={len})"
                    );
                    let old = msg.encode().expect("vote encodes").len() >= 64 * 1024;
                    assert_eq!(msg.is_large(), old, "classification changed (len={len})");
                    assert_eq!(is_large(&msg), old);
                }
            }
        }
    }

    /// O10: fixed-size `PeerKey` validates and stringifies exactly like the
    /// original allocating implementation, and two equal senders share one
    /// bucket / two distinct senders do not.
    #[test]
    fn o10_peer_key_matches_string_reference() {
        fn old_peer_key_from_json(v: &serde_json::Value) -> String {
            let sender = v
                .get("src")
                .or_else(|| v.get("from"))
                .and_then(|s| s.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            match sender {
                Some(s) => {
                    let bare = s.strip_prefix("inf1:").unwrap_or(s);
                    let ok = !bare.is_empty()
                        && bare.len() <= INBOUND_PEER_KEY_MAX_LEN
                        && bare.bytes().all(|b| b.is_ascii_hexdigit());
                    if ok {
                        bare.to_string()
                    } else {
                        INBOUND_BROADCAST_PEER_KEY.to_string()
                    }
                }
                None => INBOUND_BROADCAST_PEER_KEY.to_string(),
            }
        }
        fn old_peer_key(raw: &str) -> String {
            match serde_json::from_str::<serde_json::Value>(raw) {
                Ok(v) => old_peer_key_from_json(&v),
                Err(_) => INBOUND_BROADCAST_PEER_KEY.to_string(),
            }
        }

        let k128 = "aB".repeat(64);
        let k129 = format!("{k128}f");
        let mut corpus = vec![
            "not json".to_string(),
            "{}".to_string(),
            r#"{"topic":"t","data":"00"}"#.to_string(),
            r#"{"topic":"t","data":"00","src":""}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"   "}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"aa"}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"AA"}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"inf1:cc"}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"inf1:"}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"  inf1:dd  "}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"../../evil"}"#.to_string(),
            r#"{"topic":"t","data":"00","src":"аа"}"#.to_string(),
            r#"{"topic":"t","data":"00","from":"bb"}"#.to_string(),
            r#"{"topic":"t","data":"00","from":"zz-top"}"#.to_string(),
            r#"{"topic":"t","data":"00","src":123}"#.to_string(),
            r#"{"topic":"t","data":"00","src":null}"#.to_string(),
            r#"{"topic":"t","data":"00","src":{"x":1}}"#.to_string(),
            format!(r#"{{"topic":"t","data":"00","src":"{k128}"}}"#),
            format!(r#"{{"topic":"t","data":"00","src":"{k129}"}}"#),
        ];
        let mut seed: u64 = 0xC0FF_EE00_1234_5678;
        for _ in 0..200 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = (seed % 140) as usize;
            let mut s = String::with_capacity(len);
            for i in 0..len {
                let c = match (seed >> (i % 32)) % 4 {
                    0 => 'a',
                    1 => '0',
                    2 => 'F',
                    _ => '.',
                };
                s.push(c);
            }
            corpus.push(format!(r#"{{"topic":"t","data":"00","src":"{s}"}}"#));
        }

        let mut limiters = (
            InboundBulkLimiter::new(4096, 4096),
            InboundBulkLimiter::new(4096, 4096),
        );
        let mut now = 1_000u64;
        for (i, raw) in corpus.iter().enumerate() {
            let key = inbound_peer_key(raw);
            let reference = old_peer_key(raw);
            assert_eq!(key.as_str(), reference, "key mismatch for {raw}");
            assert_eq!(key.to_string(), reference);

            // Bucket identity is the STRING identity: driving two limiters,
            // one with the typed key and one with the reference string, must
            // give the same decision pattern.
            let bytes = 100 + (i as u64 % 17) * 100;
            now += 5;
            assert_eq!(
                limiters.0.admit(key.as_str(), bytes, false, now),
                limiters.1.admit(&reference, bytes, false, now),
                "bucket accounting diverged for {raw}"
            );
            if key.is_broadcast() {
                assert_eq!(reference, INBOUND_BROADCAST_PEER_KEY);
            } else {
                assert_ne!(key, PeerKey::Broadcast);
                assert_eq!(inbound_peer_key(raw), key, "same raw frame, same key");
            }
        }
    }

    /// O9: the allocation-free bucket lookup keeps the EXACT accounting of the
    /// old `entry(peer.to_string()).or_insert(...)` implementation.
    #[test]
    fn o9_limiter_accounting_matches_old_entry_implementation() {
        #[derive(Debug)]
        struct OldBucket {
            tokens: f64,
            last_ms: u64,
        }
        struct OldLimiter {
            rate_bps: f64,
            burst: f64,
            peers: HashMap<String, OldBucket>,
            max_peers: usize,
        }
        impl OldLimiter {
            fn new(rate_bps: u64, burst_bytes: u64, max_peers: usize) -> Self {
                Self {
                    rate_bps: rate_bps.max(1) as f64,
                    burst: burst_bytes.max(1) as f64,
                    peers: HashMap::new(),
                    max_peers,
                }
            }
            fn admit(
                &mut self,
                peer: &str,
                bytes: u64,
                critical: bool,
                now_ms: u64,
            ) -> InboundDecision {
                if critical {
                    return InboundDecision::Allow;
                }
                if !self.peers.contains_key(peer) && self.peers.len() >= self.max_peers {
                    if let Some(k) = self.peers.keys().next().cloned() {
                        self.peers.remove(&k);
                    }
                }
                let bucket = self.peers.entry(peer.to_string()).or_insert(OldBucket {
                    tokens: self.burst,
                    last_ms: now_ms,
                });
                let elapsed = now_ms.saturating_sub(bucket.last_ms);
                if elapsed > 0 {
                    bucket.tokens =
                        (bucket.tokens + elapsed as f64 / 1000.0 * self.rate_bps).min(self.burst);
                    bucket.last_ms = now_ms;
                }
                let need = bytes as f64;
                if bucket.tokens >= need {
                    bucket.tokens -= need;
                    InboundDecision::Allow
                } else {
                    let shortfall = need - bucket.tokens;
                    let wait = (shortfall / self.rate_bps * 1000.0).ceil() as u64;
                    InboundDecision::Defer {
                        wait_ms: wait.clamp(1, INBOUND_MAX_DEFER_WAIT_MS),
                    }
                }
            }
        }

        let peers = ["aa", "bb", "cc", "dd", "ee", "ff", "broadcast"];
        let mut new_limiter = InboundBulkLimiter::new(32_000, 96_000);
        let mut old_limiter = OldLimiter::new(32_000, 96_000, INBOUND_MAX_TRACKED_PEERS);
        let mut seed: u64 = 0xDEAD_BEEF_0BAD_F00D;
        let mut now = 1_000u64;
        for _ in 0..5_000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let peer = peers[(seed >> 3) as usize % peers.len()];
            let bytes = (seed >> 17) % 40_000;
            let critical = (seed >> 41).is_multiple_of(23);
            now += (seed >> 29) % 60;
            assert_eq!(
                new_limiter.admit(peer, bytes, critical, now),
                old_limiter.admit(peer, bytes, critical, now),
                "decision divergence at peer={peer} bytes={bytes} now={now}"
            );
        }
        assert_eq!(new_limiter.peer_count(), old_limiter.peers.len());
        for (peer, old) in &old_limiter.peers {
            let new = new_limiter
                .peers
                .get(peer)
                .expect("every old bucket must still exist");
            assert_eq!(
                new.tokens, old.tokens,
                "token accounting changed for {peer}"
            );
            assert_eq!(new.last_ms, old.last_ms, "stamp changed for {peer}");
        }
    }

    /// O9: the memory bound (evict one bucket at the cap) is unchanged, and
    /// the just-inserted peer always gets a full fresh bucket.
    #[test]
    fn o9_limiter_eviction_bound_and_fresh_bucket() {
        let mut limiter = InboundBulkLimiter {
            rate_bps: 1_000.0,
            burst: 1_000.0,
            peers: HashMap::new(),
            max_peers: 3,
        };
        for (i, peer) in ["aa", "bb", "cc"].iter().enumerate() {
            assert_eq!(
                limiter.admit(peer, 1_000, false, 1_000 + i as u64),
                InboundDecision::Allow
            );
        }
        assert_eq!(limiter.peer_count(), 3);
        // A fourth peer evicts exactly one, and keeps its own fresh burst.
        assert_eq!(
            limiter.admit("dd", 1_000, false, 2_000),
            InboundDecision::Allow
        );
        assert_eq!(limiter.peer_count(), 3);
        assert_eq!(limiter.peers["dd"].tokens, 0.0);
        assert_eq!(limiter.peers["dd"].last_ms, 2_000);
        // Re-admitting an EXISTING peer never evicts another one.
        let before: Vec<String> = limiter.peers.keys().cloned().collect();
        let _ = limiter.admit("dd", 10, false, 2_001);
        let mut after: Vec<String> = limiter.peers.keys().cloned().collect();
        let mut before_sorted = before;
        before_sorted.sort();
        after.sort();
        assert_eq!(before_sorted, after);
    }
}
