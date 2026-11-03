//! CometBFT-style SEND-side flood controls ("как у больших").
//!
//! Covers the four gates, each with an attack case AND an honest-traffic
//! case (existing behavior is byte-identical under no-attack conditions):
//!  1. per-peer SEND rate limiter on gossip publish (drops over-budget
//!     peers, never blocks the publisher),
//!  2. mempool RECHECK after each commit (spent nonce / drained balance /
//!     moved fee floor),
//!  3. peer eviction past the target (evict-worst, never static/validators),
//!  4. inbound bandwidth shed (per-second counter, refuse new + keep
//!     existing, recovers next second).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus_net::{
    evict_candidate, InboundShed, PeerScore, SendRateLimiter, INBOUND_SHED_BYTES_PER_SEC,
    PEER_EVICT_TARGET_MAX,
};
use stellereum::mempool::Mempool;
use stellereum::sharding::Transaction;

fn peer_id(n: u64) -> [u8; 20] {
    let mut id = [0u8; 20];
    id[..8].copy_from_slice(&n.to_le_bytes());
    id
}

#[test]
fn send_limiter_caps_spammer_publisher() {
    // Honest: one full-size gossip frame always fits the production burst.
    let mut honest = SendRateLimiter::with_defaults();
    let peer = [7u8; 20];
    assert!(
        honest.try_send(&peer, 1024 * 1024, 0),
        "honest single publish must pass"
    );
    assert_eq!(honest.dropped_total(), 0);

    // Spammer publisher: rapid back-to-back publishes against a small budget.
    let mut lim = SendRateLimiter::new(1000, 2000);
    let spammer = [9u8; 20];
    let mut allowed = 0u32;
    for _ in 0..10 {
        if lim.try_send(&spammer, 500, 0) {
            allowed += 1;
        }
    }
    assert!(
        allowed <= 4,
        "spammer must be capped (allowed {allowed}/10)"
    );
    assert!(
        lim.dropped_total() > 0,
        "over-budget publishes must be counted, got {}",
        lim.dropped_total()
    );

    // The spammer's exhaustion never touches another peer's bucket.
    assert!(
        lim.try_send(&[8u8; 20], 500, 0),
        "honest peer must be unaffected by the spammer's budget"
    );

    // A single message larger than the burst never passes (fail-closed).
    assert!(
        !lim.try_send(&spammer, 2001, 0),
        "oversize send must be dropped, never admitted"
    );

    // Budget refills with time: the same spammer passes again later.
    assert!(
        lim.try_send(&spammer, 500, 2000),
        "refilled budget must admit again"
    );
}

#[test]
fn recheck_drops_spent_nonce_txs_post_commit() {
    let sk = SigningKey::generate(&mut OsRng);
    let me: [u8; 32] = sk.verifying_key().to_bytes();
    let mut mp = Mempool::new(100, 100);
    for i in 0..3u64 {
        mp.add_checked(
            Transaction::sign(&sk, [1u8; 32], 10, 1_000, i, 1, 1),
            1_000_000,
        )
        .unwrap();
    }
    // The commit consumed nonce 0 (which `prune_confirmed` removes by hash)
    // and advanced the on-chain nonce to 1: the recheck must drop nothing
    // else — nonces 1,2 are still executable.
    let confirmed = mp
        .all()
        .into_iter()
        .find(|tx| tx.nonce == 0)
        .unwrap()
        .compute_tx_hash();
    mp.prune_confirmed(&[confirmed]);
    assert_eq!(mp.len(), 2);
    let dropped = mp.recheck(1_000_000, |a| {
        if *a == me {
            Some((1u64, 1_000_000u64))
        } else {
            None
        }
    });
    assert_eq!(dropped, 0, "no stale tx yet");
    assert_eq!(mp.len(), 2);

    // A later commit consumes nonce 1 on-chain (a competing variant was
    // included): our pooled nonce-1 tx is now stuck-invalid — execution
    // would refuse it — and the recheck must drop it, proving no
    // stuck-invalid accumulation. Nonce 2 stays.
    let dropped = mp.recheck(1_000_001, |a| {
        if *a == me {
            Some((2u64, 1_000_000u64))
        } else {
            None
        }
    });
    assert_eq!(dropped, 1, "spent nonce 1 must be dropped");
    assert_eq!(mp.len(), 1);
    assert_eq!(mp.all()[0].nonce, 2);

    // Honest traffic unaffected: pre-commit view drops nothing.
    let mut mp3 = Mempool::new(100, 100);
    for i in 0..3u64 {
        mp3
            .add_checked(
                Transaction::sign(&sk, [1u8; 32], 10, 1_000, i, 1, 1),
                1_000_000,
            )
            .unwrap();
    }
    let dropped = mp3.recheck(1_000_003, |a| {
        if *a == me {
            Some((0u64, 1_000_000u64))
        } else {
            None
        }
    });
    assert_eq!(dropped, 0, "honest pool must survive recheck");
    assert_eq!(mp3.len(), 3);

    // Moved fee floor: a D2 failure penalty accrues post-commit, pushing the
    // floor above the pooled txs' gas_limit — all must drop, while another
    // sender's txs are untouched.
    let sk2 = SigningKey::generate(&mut OsRng);
    let other: [u8; 32] = sk2.verifying_key().to_bytes();
    let mut mp4 = Mempool::new(100, 100);
    for i in 0..2u64 {
        mp4
            .add_checked(
                Transaction::sign(&sk, [1u8; 32], 10, 1_000, i, 1, 1),
                1_000_000,
            )
            .unwrap();
    }
    mp4
        .add_checked(
            Transaction::sign(&sk2, [1u8; 32], 10, 1_000, 0, 1, 1),
            1_000_000,
        )
        .unwrap();
    mp4.penalize_sender(&me);
    let dropped = mp4.recheck(1_000_004, |a| {
        if *a == me || *a == other {
            Some((0u64, 1_000_000u64))
        } else {
            None
        }
    });
    assert_eq!(dropped, 2, "floor-spent txs must be dropped");
    assert_eq!(mp4.len(), 1, "other sender's tx must survive");
    assert_eq!(mp4.all()[0].from, other);
}

#[test]
fn over_target_evicts_worst_non_static() {
    let target = PEER_EVICT_TARGET_MAX;
    // Honest: at/below target nothing is ever evicted.
    let few: Vec<PeerScore> = (0..5u64)
        .map(|i| PeerScore {
            id: peer_id(i),
            fails: 10,
            is_static: false,
        })
        .collect();
    assert_eq!(evict_candidate(&few, target), None);

    // Attack: table past target — the worst non-static peer is chosen even
    // though a static peer has the worst score overall (static exempt).
    let mut many: Vec<PeerScore> = (0..=target as u64)
        .map(|i| PeerScore {
            id: peer_id(i),
            fails: i as u32,
            is_static: false,
        })
        .collect();
    assert!(many.len() > target);
    let static_id = [0xAAu8; 20];
    many.push(PeerScore {
        id: static_id,
        fails: u32::MAX,
        is_static: true,
    });
    let worst: [u8; 20] = many
        .iter()
        .filter(|p| !p.is_static)
        .max_by_key(|p| p.fails)
        .unwrap()
        .id;
    assert_eq!(
        evict_candidate(&many, target),
        Some(worst),
        "must evict the worst non-static peer"
    );
    assert_ne!(
        evict_candidate(&many, target),
        Some(static_id),
        "static peers (incl. validators) are never evicted"
    );

    // All-static past target: no candidate (validators keep serving).
    let all_static: Vec<PeerScore> = (0..=target as u64)
        .map(|i| PeerScore {
            id: peer_id(100_000 + i),
            fails: 99,
            is_static: true,
        })
        .collect();
    assert_eq!(evict_candidate(&all_static, target), None);
}

#[test]
fn bandwidth_shed_triggers_and_recovers() {
    // Honest trickle under the cap always passes.
    let mut shed = InboundShed::new(10_000);
    assert!(shed.observe(100, 0));
    assert_eq!(shed.refused_total(), 0);

    // Flood within the same second trips the shed (counted).
    let mut tripped = false;
    for _ in 0..20 {
        if !shed.observe(1000, 0) {
            tripped = true;
        }
    }
    assert!(tripped, "flood must trigger the shed");
    assert!(
        shed.refused_total() > 0,
        "shed must count refusals"
    );
    assert!(shed.shed_active(0), "shed must be active this second");

    // Next second recovers: existing traffic flows again.
    assert!(
        shed.observe(100, 1000),
        "shed must recover in the next second"
    );
    assert!(!shed.shed_active(1000));

    // Honest traffic at production consts is never shed.
    let mut prod = InboundShed::new(INBOUND_SHED_BYTES_PER_SEC);
    for t in [0u64, 250, 500, 750] {
        assert!(prod.observe(1_000_000, t));
    }
    assert_eq!(prod.refused_total(), 0);
}
