//! Dandelion stem/fluff publish-path wiring tests: deterministic, no sockets.
//!
//! What is under test is the wiring in `stellereum::consensus_net` (default-OFF
//! const gate, tx/peer identity mapping, stem-frame codec, and the
//! originate/stem/fluff/failover/timeout decision API on `TxGossip`) driving
//! the EXACT policy state machine from `consensus_net::dandelion` (the same
//! `#[path]`-included `src/dandelion.rs`, reused — not duplicated — by the
//! publish path). The pure-policy proofs (12/12 geometric, anonymity,
//! failover, bounds, determinism) live in `tests/dandelion_tests.rs` and are
//! not repeated here; these tests pin the WIRING around them:
//!
//! ```text
//! cargo test --test dandelion_wiring_tests -- --nocapture
//! ```
//!
//! DETERMINISM: every ON-path decision reseeds the gossip RNG explicitly
//! (`dandelion_reseed`); where a seed must exhibit a behaviour (stem vs fluff)
//! the test scans fixed seeds exactly like `dandelion_tests.rs` does. No wall
//! clock, no OS randomness in assertions, no network (empty peer tables plus
//! synthetic candidate tables with caller-supplied liveness).
//!
//! GATE MAP (task: stem/fluff/failover/bounds/completeness + off-proof):
//! * OFF default + OFF path untouched ......... `off_by_default_and_off_path_untouched`
//! * stem codec round-trip + fail-closed ...... `stem_codec_*`
//! * stem forwards to one peer per policy ..... `stem_decision_forwards_to_one_live_peer`
//! * fluff (empty/dead/zero-hop) .............. `fluff_*`
//! * failover on dead stem .................... `failover_*`
//! * bounded maps (caps + oldest eviction) .... `stem_map_stays_bounded_through_wiring`
//! * loop protection (fluff wins, dup drop) ... `duplicate_*`, `stem_loop_*`
//! * no stall (timeout forces broadcast) ..... `fluff_timeout_forces_broadcast_no_stall`
//! * completeness (everyone relays once) ..... `wiring_end_to_end_*`

use std::collections::HashSet;
use std::sync::Arc;
use stellereum::consensus_net::{
    dandelion, dandelion_peer_id, dandelion_tx_hash, decode_dandelion_stem, encode_dandelion_stem,
    DandelionPublishDecision, TxGossip, DANDELION_ENABLED, DANDELION_FLUFF_TIMEOUT_MS,
    DANDELION_STEM_MAGIC, MAX_TX_MSG,
};
use stellereum::mev_epoch::{
    DKG_PAYLOAD_MAGIC, EPOCH_ANNOUNCE_PAYLOAD_MAGIC, ORDER_COMMIT_PAYLOAD_MAGIC,
    SEALED_PAYLOAD_MAGIC, SHARE_RELEASE_PAYLOAD_MAGIC,
};
use stellereum::network::P2pNetworkAdapter;

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Build a `TxGossip` on an empty-peer test node (no network, no dials).
async fn test_gossip(tag: &str) -> Arc<TxGossip> {
    let dir = std::env::temp_dir().join(format!(
        "stell-dandelion-wiring-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmpdir");
    let cfg = infnode::config::NodeConfig {
        name: "test".to_string(),
        listen: "127.0.0.1:0".to_string(),
        client_listen: None,
        advertise: None,
        peers: vec![],
        allow_unknown: false,
        unknown_allow: vec![],
        metrics_listen: None,
        log_level: Some(0),
        roles: Default::default(),
        outbox_ttl_secs: 3600,
        storage_roles: vec![],
        validators: vec![],
        domain: None,
        web_listen: None,
        wallet: None,
        web_static: None,
    };
    let node = infnode::node::Node::new(
        cfg,
        infnode::keyring::NodeKeys::generate(),
        infnode::keyring::PqKeys::generate(),
        dir,
        std::path::PathBuf::new(),
    )
    .await
    .expect("test node");
    Arc::new(TxGossip::new(Arc::new(P2pNetworkAdapter::new(node))))
}

/// Synthetic 20-byte peer id with `low` in the low word (bijective mapping).
fn pid(low: u64) -> [u8; 20] {
    let mut p = [0xABu8; 20];
    p[..8].copy_from_slice(&low.to_le_bytes());
    p
}

/// Candidate table from low words, in order.
fn table(lows: &[u64]) -> Vec<([u8; 20], u64)> {
    lows.iter()
        .map(|w| (pid(*w), dandelion_peer_id(&pid(*w))))
        .collect()
}

fn all_alive() -> impl Fn(u64) -> bool {
    |_| true
}

fn dummy_tx() -> stellereum::sharding::Transaction {
    stellereum::sharding::Transaction {
        from: [1u8; 32],
        to: [2u8; 32],
        amount: 1,
        gas_limit: 10,
        nonce: 0,
        source_shard: 0,
        target_shard: 0,
        signature: vec![],
        payload: vec![],
        priority_fee_per_gas: 0,
    }
}

// ---------------------------------------------------------------------------
// OFF gate: default OFF, and the OFF path never touches Dandelion state.
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::assertions_on_constants)] // GATE: asserting the const OFF default IS the off-proof; the const-ness is the point.
async fn off_by_default_and_off_path_untouched() {
    assert!(
        !DANDELION_ENABLED,
        "dandelion publish wiring must default OFF (no env knob)"
    );
    assert!(
        DANDELION_FLUFF_TIMEOUT_MS >= 1_000,
        "fluff timeout must cover a few sequential-hop RTTs"
    );
    let gossip = test_gossip("off").await;
    assert_eq!(gossip.dandelion_stem_len(), 0);
    assert_eq!(gossip.dandelion_seen_len(), 0);
    // OFF publish with no peers: full fanout over zero peers, no Dandelion
    // state touched (byte-identical path — same `broadcast_bytes` as before).
    gossip.broadcast(&dummy_tx()).await;
    assert_eq!(gossip.dandelion_stem_len(), 0, "OFF must not hold stem");
    assert_eq!(gossip.dandelion_seen_len(), 0, "OFF must not mark seen");
    println!("[wiring][off] DANDELION_ENABLED=false; broadcast left stem=0 seen=0");
}

// ---------------------------------------------------------------------------
// Identity mapping + stem-frame codec.
// ---------------------------------------------------------------------------

#[test]
fn tx_hash_is_deterministic_32_bytes() {
    let a = dandelion_tx_hash(b"hello");
    let b = dandelion_tx_hash(b"hello");
    let c = dandelion_tx_hash(b"world");
    assert_eq!(a, b, "same bytes must map to the same tx id");
    assert_ne!(a, c, "distinct payloads must map to distinct tx ids");
    assert_eq!(a.len(), 32);
    println!("[wiring][hash] sha256(hello)={}", hex::encode(a));
}

#[test]
fn peer_mapping_is_low_word_le() {
    let p = pid(0x0102_0304_0506_0708);
    assert_eq!(dandelion_peer_id(&p), 0x0102_0304_0506_0708);
    assert_ne!(dandelion_peer_id(&pid(11)), dandelion_peer_id(&pid(22)));
}

#[test]
fn stem_codec_round_trips_and_fail_closes() {
    for hops in [0u32, 1, 4, 10, u32::MAX] {
        let body = vec![7u8; 64];
        let frame = encode_dandelion_stem(hops, &body);
        assert_eq!(&frame[..4], DANDELION_STEM_MAGIC);
        let (h, b) = decode_dandelion_stem(&frame).expect("own encoding must decode");
        assert_eq!((h, b), (hops, body));
    }
    assert!(decode_dandelion_stem(&[]).is_none(), "empty refused");
    assert!(
        decode_dandelion_stem(&[0u8; 7]).is_none(),
        "truncated header refused"
    );
    assert!(
        decode_dandelion_stem(&encode_dandelion_stem(3, &[])).is_none(),
        "empty body refused"
    );
    let mut bad_magic = encode_dandelion_stem(3, &[9u8; 8]);
    bad_magic[0] ^= 0xFF;
    assert!(
        decode_dandelion_stem(&bad_magic).is_none(),
        "wrong magic refused"
    );
    // Oversized bodies (past MAX_TX_MSG) are refused even with the header.
    assert!(
        decode_dandelion_stem(&encode_dandelion_stem(3, &vec![0u8; MAX_TX_MSG + 1])).is_none(),
        "oversized stem body refused"
    );
    // The stem magic collides with no epoch-seal magic (no mis-decodes).
    for m in [
        SEALED_PAYLOAD_MAGIC,
        DKG_PAYLOAD_MAGIC,
        ORDER_COMMIT_PAYLOAD_MAGIC,
        SHARE_RELEASE_PAYLOAD_MAGIC,
        EPOCH_ANNOUNCE_PAYLOAD_MAGIC,
    ] {
        assert_ne!(DANDELION_STEM_MAGIC, m, "stem magic must stay distinct");
    }
    println!(
        "[wiring][codec] round-trip ok; magic={:?}",
        DANDELION_STEM_MAGIC
    );
}

// ---------------------------------------------------------------------------
// Stem: forwards to exactly one live peer per policy, budget attached.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stem_decision_forwards_to_one_live_peer() {
    let gossip = test_gossip("stem").await;
    let cands = table(&[11, 22, 33, 44]);
    let self_id = 999u64;
    // Scan fixed seeds for one that stems (same idiom as dandelion_tests).
    let mut stemmed = None;
    for seed in 0..40u64 {
        gossip.dandelion_reseed(seed);
        let tx = dandelion::txid_from_u64(5000 + seed);
        match gossip.dandelion_publish_decision_with_liveness(&tx, &cands, self_id, &all_alive()) {
            DandelionPublishDecision::Stem { to, hops_left } => {
                stemmed = Some((seed, tx, to, hops_left));
                break;
            }
            DandelionPublishDecision::Fluff => continue,
            DandelionPublishDecision::Drop => {
                panic!("fresh tx must never Drop (seed {seed})")
            }
        }
    }
    let (seed, tx, to, hops_left) = stemmed.expect("40 seeds never stemmed — check policy p");
    let valid: HashSet<[u8; 20]> = cands.iter().map(|(p, _)| *p).collect();
    assert!(valid.contains(&to), "stem target must be a table peer");
    assert_ne!(
        dandelion_peer_id(&to),
        self_id,
        "stem must never target self"
    );
    assert!(
        hops_left <= dandelion::MAX_STEM_HOPS,
        "budget honours the hard cap"
    );
    assert!(
        gossip.dandelion_holds(&tx),
        "stem decision must hold an entry"
    );
    assert!(
        !gossip.dandelion_is_fluffed(&tx),
        "stemmed tx is not fluffed"
    );
    println!(
        "[wiring][stem] seed={seed} to={} hops_left={hops_left}",
        hex::encode(to)
    );
}

#[tokio::test]
async fn fluff_when_no_peer_or_no_budget() {
    let gossip = test_gossip("fluff").await;
    // Empty candidate table: nowhere to stem, must fluff with no held state.
    gossip.dandelion_reseed(7);
    let tx0 = dandelion::txid_from_u64(6001);
    assert_eq!(
        gossip.dandelion_publish_decision_with_liveness(&tx0, &[], 999, &all_alive()),
        DandelionPublishDecision::Fluff
    );
    assert!(!gossip.dandelion_holds(&tx0));
    assert!(gossip.dandelion_is_fluffed(&tx0));
    // All-known-dead peers: failover exhausts retries, fluffs locally.
    let cands = table(&[11, 22]);
    let tx1 = dandelion::txid_from_u64(6002);
    assert_eq!(
        gossip.dandelion_publish_decision_with_liveness(&tx1, &cands, 999, &|_| false),
        DandelionPublishDecision::Fluff
    );
    assert!(!gossip.dandelion_holds(&tx1));
    // A zero-hop stem delivery fluffs at once (budget exhausted on arrival).
    let tx2 = dandelion::txid_from_u64(6003);
    assert_eq!(
        gossip.dandelion_on_stem_with_liveness(&tx2, 0, &cands, 999, &all_alive()),
        DandelionPublishDecision::Fluff
    );
    println!("[wiring][fluff] empty/dead/zero-hop all fluff with no held stem");
}

// ---------------------------------------------------------------------------
// Failover: dead stem target reroutes (budget kept) or fluffs, never drops.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failover_reroutes_around_dead_stem_or_fluffs() {
    let gossip = test_gossip("failover").await;
    let cands = table(&[11, 22, 33]);
    let self_id = 999u64;
    // Find a stem with at least 1 hop of budget to check budget preservation.
    let mut stemmed = None;
    for seed in 0..60u64 {
        gossip.dandelion_reseed(seed);
        let tx = dandelion::txid_from_u64(7000 + seed);
        if let DandelionPublishDecision::Stem { to, hops_left } =
            gossip.dandelion_publish_decision_with_liveness(&tx, &cands, self_id, &all_alive())
        {
            if hops_left >= 1 {
                stemmed = Some((tx, to, hops_left));
                break;
            }
        }
    }
    let (tx, first, hops) = stemmed.expect("no budgeted stem in 60 seeds");
    let dead_first = dandelion_peer_id(&first);
    // Target still alive: re-emit unchanged (no spurious reroute).
    assert_eq!(
        gossip.dandelion_failover_with_liveness(&tx, &cands, self_id, &all_alive()),
        DandelionPublishDecision::Stem {
            to: first,
            hops_left: hops
        },
        "alive stem peer must be re-emitted unchanged"
    );
    // Target dead, others live: reroute to a DIFFERENT live peer, budget kept.
    let without_first = |p: u64| p != dead_first;
    match gossip.dandelion_failover_with_liveness(&tx, &cands, self_id, &without_first) {
        DandelionPublishDecision::Stem { to, hops_left } => {
            assert_ne!(to, first, "failover must move off the dead peer");
            assert_eq!(hops_left, hops, "failover keeps the budget");
            println!(
                "[wiring][failover] {} -> {} hops={hops_left}",
                hex::encode(first),
                hex::encode(to)
            );
        }
        other => panic!("dead stem with live alternatives must reroute, got {other:?}"),
    }
    // All dead: drop the stem and fluff locally — never blackhole.
    assert_eq!(
        gossip.dandelion_failover_with_liveness(&tx, &cands, self_id, &|_| false),
        DandelionPublishDecision::Fluff
    );
    assert!(
        !gossip.dandelion_holds(&tx),
        "failed-over-to-fluff must clear the stem"
    );
    // Nothing held: nothing to recover.
    let fresh = dandelion::txid_from_u64(7999);
    assert_eq!(
        gossip.dandelion_failover_with_liveness(&fresh, &cands, self_id, &all_alive()),
        DandelionPublishDecision::Drop
    );
}

// ---------------------------------------------------------------------------
// Loop protection: duplicates drop, fluff wins, budgets strictly decrease.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn duplicate_originate_and_relay_are_dropped() {
    let gossip = test_gossip("dup").await;
    let cands = table(&[11, 22, 33]);
    let self_id = 999u64;
    gossip.dandelion_reseed(3);
    let tx = dandelion::txid_from_u64(8001);
    let first = gossip.dandelion_publish_decision_with_liveness(&tx, &cands, self_id, &all_alive());
    assert_ne!(first, DandelionPublishDecision::Drop, "fresh tx must act");
    // Re-originating the same tx is a duplicate: no second stem, no second fluff.
    assert_eq!(
        gossip.dandelion_publish_decision_with_liveness(&tx, &cands, self_id, &all_alive()),
        DandelionPublishDecision::Drop,
        "re-originate must Drop"
    );
    // First fluff sighting relays onward exactly once iff we had only stemmed;
    // repeats are always ignored (storm termination).
    let expect_relay = matches!(first, DandelionPublishDecision::Stem { .. });
    assert_eq!(gossip.dandelion_on_fluff(&tx), expect_relay);
    assert!(
        !gossip.dandelion_holds(&tx),
        "fluff must drop held stem (fluff wins)"
    );
    assert!(gossip.dandelion_is_fluffed(&tx));
    assert!(
        !gossip.dandelion_on_fluff(&tx),
        "second fluff must not relay"
    );
    // Late stem deliveries of the fluffed tx are ignored (fluff wins).
    assert_eq!(
        gossip.dandelion_on_stem_with_liveness(&tx, 4, &cands, self_id, &all_alive()),
        DandelionPublishDecision::Drop
    );
    println!("[wiring][dup] first={first:?} relay-once then drop; fluff wins");
}

#[tokio::test]
async fn stem_loop_consumes_budget_then_fluffs() {
    let gossip = test_gossip("loop").await;
    let cands = table(&[11, 22]);
    let self_id = 999u64;
    gossip.dandelion_reseed(11);
    let tx = dandelion::txid_from_u64(8101);
    // Budget 5 arrives: forward with 4.
    match gossip.dandelion_on_stem_with_liveness(&tx, 5, &cands, self_id, &all_alive()) {
        DandelionPublishDecision::Stem { hops_left, .. } => assert_eq!(hops_left, 4),
        other => panic!("budgeted stem must forward, got {other:?}"),
    }
    // The same stem loops back with its remaining budget: keep walking (4->3),
    // never die silently, never spin.
    match gossip.dandelion_on_stem_with_liveness(&tx, 4, &cands, self_id, &all_alive()) {
        DandelionPublishDecision::Stem { hops_left, .. } => assert_eq!(hops_left, 3),
        other => panic!("looped stem must consume budget, got {other:?}"),
    }
    // Budget exhausted on revisit: this node becomes the fluff source.
    assert_eq!(
        gossip.dandelion_on_stem_with_liveness(&tx, 0, &cands, self_id, &all_alive()),
        DandelionPublishDecision::Fluff
    );
    assert!(gossip.dandelion_is_fluffed(&tx));
    assert!(!gossip.dandelion_holds(&tx));
    println!("[wiring][loop] 5->4->3->fluff: budget strictly decreases, then fluffs");
}

// ---------------------------------------------------------------------------
// Bounded maps: flood through the wiring sits AT the cap, oldest evicted.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stem_map_stays_bounded_through_wiring() {
    let gossip = test_gossip("bounds").await;
    let cands = table(&[11, 22, 33, 44]);
    let self_id = 999u64;
    const FLOOD: u64 = 1200;
    // Deterministic flood: first fixed seed whose stem count exceeds the cap
    // (Binomial(1200, 0.8) per seed — missing the cap in 8 seeds is ~impossible
    // and would itself prove a policy break).
    let mut run = None;
    for seed in 0..8u64 {
        gossip.dandelion_reseed(0xF100_D000 + seed);
        // Fresh relay state per probe: re-create the gossip handle is heavy,
        // so probe counts on a scratch instance instead.
        let probe = test_gossip(&format!("bounds-probe-{seed}")).await;
        probe.dandelion_reseed(0xF100_D000 + seed);
        let mut n_stem = 0u64;
        for i in 0..FLOOD {
            let tx = dandelion::txid_from_u64(1_000_000 + i);
            if matches!(
                probe.dandelion_publish_decision_with_liveness(&tx, &cands, self_id, &all_alive()),
                DandelionPublishDecision::Stem { .. }
            ) {
                n_stem += 1;
            }
        }
        if n_stem as usize > dandelion::MAX_STEM_ENTRIES {
            run = Some((seed, n_stem));
            break;
        }
    }
    let (seed, n_stem) = run.expect("flood must exceed the stem cap on some fixed seed");
    // Replay the winning seed on the measured instance, recording stem order.
    gossip.dandelion_reseed(0xF100_D000 + seed);
    let mut stem_order: Vec<[u8; 32]> = Vec::new();
    for i in 0..FLOOD {
        let tx = dandelion::txid_from_u64(1_000_000 + i);
        if matches!(
            gossip.dandelion_publish_decision_with_liveness(&tx, &cands, self_id, &all_alive()),
            DandelionPublishDecision::Stem { .. }
        ) {
            stem_order.push(tx);
        }
    }
    assert_eq!(stem_order.len() as u64, n_stem);
    println!(
        "[wiring][bound] seed={seed} flood={FLOOD} stemmed={n_stem} stem_len={} seen_len={}",
        gossip.dandelion_stem_len(),
        gossip.dandelion_seen_len()
    );
    assert_eq!(
        gossip.dandelion_stem_len(),
        dandelion::MAX_STEM_ENTRIES,
        "stem map must sit AT the cap"
    );
    assert!(
        gossip.dandelion_seen_len() <= dandelion::MAX_SEEN_ENTRIES,
        "seen-set must stay bounded"
    );
    assert_eq!(
        gossip.dandelion_seen_len(),
        FLOOD as usize,
        "every tx is seen exactly once (1200 < 4096, no seen eviction)"
    );
    // Oldest-first eviction: the held set is exactly the most recent inserts.
    let want: HashSet<[u8; 32]> = stem_order[stem_order.len() - dandelion::MAX_STEM_ENTRIES..]
        .iter()
        .copied()
        .collect();
    let mut held = HashSet::new();
    for tx in &stem_order {
        if gossip.dandelion_holds(tx) {
            held.insert(*tx);
        }
    }
    assert_eq!(held, want, "eviction must drop oldest first");
}

// ---------------------------------------------------------------------------
// No stall: the fluff timeout force-fluffs a held stem.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fluff_timeout_forces_broadcast_no_stall() {
    let gossip = test_gossip("timeout").await;
    let cands = table(&[11, 22, 33]);
    let self_id = 999u64;
    let mut stemmed = None;
    for seed in 0..40u64 {
        gossip.dandelion_reseed(seed);
        let tx = dandelion::txid_from_u64(9000 + seed);
        if matches!(
            gossip.dandelion_publish_decision_with_liveness(&tx, &cands, self_id, &all_alive()),
            DandelionPublishDecision::Stem { .. }
        ) {
            stemmed = Some(tx);
            break;
        }
    }
    let tx = stemmed.expect("40 seeds never stemmed");
    assert!(
        gossip.dandelion_holds(&tx),
        "stem must be held before the timeout"
    );
    // The timeout forces the broadcast: the caller fluffs on `Some(Fluff)`.
    assert_eq!(
        gossip.dandelion_fluff_timeout(&tx),
        Some(DandelionPublishDecision::Fluff),
        "held stem must force-fluff on timeout (no stall)"
    );
    assert!(!gossip.dandelion_holds(&tx), "timeout must clear the stem");
    assert!(gossip.dandelion_is_fluffed(&tx));
    // Timeout on a non-held tx is a no-op.
    assert_eq!(
        gossip.dandelion_fluff_timeout(&dandelion::txid_from_u64(123_456)),
        None
    );
    println!("[wiring][timeout] held stem force-fluffed; unknown tx no-op");
}

// ---------------------------------------------------------------------------
// Completeness: stem chain terminates in fluff; every node relays fluff once.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wiring_end_to_end_stem_then_fluff_reaches_all() {
    let a = test_gossip("e2e-a").await;
    let b = test_gossip("e2e-b").await;
    let c = test_gossip("e2e-c").await;
    // Three-node mesh, synthetic ids shared by all views (bijective mapping).
    let cands = table(&[11, 22, 33]);
    let nodes: Vec<(u64, Arc<TxGossip>)> = vec![(11, a.clone()), (22, b.clone()), (33, c.clone())];
    let by_id =
        |id: u64| -> &Arc<TxGossip> { &nodes.iter().find(|(i, _)| *i == id).expect("member").1 };
    let id_of = |pid: [u8; 20]| dandelion_peer_id(&pid);
    // Find a seed whose walk from node 11 actually stems.
    let mut walk = None;
    for seed in 0..40u64 {
        a.dandelion_reseed(seed);
        b.dandelion_reseed(seed + 1_000);
        c.dandelion_reseed(seed + 2_000);
        let tx = dandelion::txid_from_u64(10_000 + seed);
        if let DandelionPublishDecision::Stem { to, hops_left } =
            a.dandelion_publish_decision_with_liveness(&tx, &cands, 11, &all_alive())
        {
            walk = Some((tx, to, hops_left));
            break;
        }
    }
    let (tx, mut to, mut hops) = walk.expect("40 seeds never stemmed from node 11");
    // Walk the stem through the REAL per-node wiring API until someone fluffs.
    // Each forward strictly consumes budget, so this terminates (<= 10 hops).
    let mut stem_path = vec![11u64];
    let mut fluffer = None;
    for _ in 0..20 {
        let next_id = id_of(to);
        stem_path.push(next_id);
        match by_id(next_id).dandelion_on_stem_with_liveness(
            &tx,
            hops,
            &cands,
            next_id,
            &all_alive(),
        ) {
            DandelionPublishDecision::Stem { to: nxt, hops_left } => {
                to = nxt;
                hops = hops_left;
            }
            DandelionPublishDecision::Fluff => {
                fluffer = Some(next_id);
                break;
            }
            DandelionPublishDecision::Drop => panic!("unfluffed stem must never Drop"),
        }
    }
    let fluffer = fluffer.expect("stem walk must terminate in fluff (budget strictly decreases)");
    assert!(
        stem_path.len() - 1 <= dandelion::MAX_STEM_HOPS as usize + 1,
        "stem walk honours the hop cap"
    );
    // Fluff phase: every node relays the fluff exactly once (completeness +
    // storm termination at the wiring layer).
    for (id, g) in &nodes {
        if *id == fluffer {
            continue; // the fluffer already relayed by deciding Fluff
        }
        assert!(
            g.dandelion_on_fluff(&tx),
            "node {id} must relay the fluff onward (completeness)"
        );
        assert!(
            !g.dandelion_on_fluff(&tx),
            "node {id} must relay a given fluff at most once"
        );
    }
    println!("[wiring][e2e] stem_path={stem_path:?} fluffer={fluffer} all=3/3 relayed-once");
}

// ---------------------------------------------------------------------------
// Relay ingress clamp (pentest Medium): over-cap wire budgets fail closed to
// fluff through the wiring; exactly-at-cap stems are untouched.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stem_ingress_over_cap_fails_closed_to_fluff() {
    let gossip = test_gossip("clamp").await;
    let cands = table(&[11, 22, 33]);
    let self_id = 999u64;
    // Adversarial budgets: just over the cap, and the u32::MAX extreme from
    // the finding (previously forwarded as MAX-1 through this exact site).
    for incoming in [dandelion::MAX_STEM_HOPS + 1, u32::MAX] {
        let tx = dandelion::txid_from_u64(20_000 + incoming as u64);
        assert_eq!(
            gossip.dandelion_on_stem_with_liveness(&tx, incoming, &cands, self_id, &all_alive()),
            DandelionPublishDecision::Fluff,
            "over-cap {incoming} must fluff, never stem"
        );
        assert!(
            !gossip.dandelion_holds(&tx),
            "over-cap {incoming} must hold no stem"
        );
        assert!(gossip.dandelion_is_fluffed(&tx));
        // Repeat terminates (fluff wins surfaces as Drop at the wiring layer).
        assert_eq!(
            gossip.dandelion_on_stem_with_liveness(&tx, incoming, &cands, self_id, &all_alive()),
            DandelionPublishDecision::Drop,
            "repeat over-cap {incoming} must terminate"
        );
    }
    // Boundary: exactly MAX_STEM_HOPS still stems with MAX_STEM_HOPS - 1.
    gossip.dandelion_reseed(0xC14A_0003);
    let tx = dandelion::txid_from_u64(20_042);
    match gossip.dandelion_on_stem_with_liveness(
        &tx,
        dandelion::MAX_STEM_HOPS,
        &cands,
        self_id,
        &all_alive(),
    ) {
        DandelionPublishDecision::Stem { hops_left, .. } => assert_eq!(
            hops_left,
            dandelion::MAX_STEM_HOPS - 1,
            "at-cap stem must hand on exactly one less"
        ),
        other => panic!("at-cap stem must forward, got {other:?}"),
    }
    assert!(gossip.dandelion_holds(&tx));
    println!("[wiring][clamp] over-cap {{11, u32::MAX}} fluff with no held stem; at-cap stems with cap-1");
}
