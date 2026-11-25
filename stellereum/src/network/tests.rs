use super::*;
use crate::oracle::PriceFeedUpdate;
use crate::sharding::{CrossShardMessage, Transaction};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

#[tokio::test]
async fn prune_fetch_lane_is_bounded_and_released() {
    // Transport-audit regression: `maybe_prune_retained` resolves its
    // header-index lookup through `fetch_sem` — the same lane as every
    // other fetch — so prune traffic can never exceed
    // `FETCH_MAX_CONCURRENCY` concurrent streams.
    let max = crate::sync::FETCH_MAX_CONCURRENCY.max(1);
    let held = fetch_sem()
        .acquire()
        .await
        .expect("fetch lane must grant permits");
    let during = fetch_sem().available_permits();
    assert!(
        during < max,
        "one held permit must reduce availability below the cap {max}"
    );
    drop(held);
    let after = fetch_sem().available_permits();
    assert!(
        after <= max,
        "permits must never exceed the cap {max}, got {after}"
    );
    assert!(
        after > during,
        "dropping the permit must return it to the lane"
    );
}

#[test]
fn network_cross_shard_message_is_never_trusted() {
    // A locally trusted message, once serialized and decoded from the wire,
    // must come back UNtrusted so the inclusion proof is enforced.
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, [9u8; 32], 10, 0, 0, 1, 2);
    let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);
    assert!(msg.trusted);
    let bytes = bincode::serialize(&msg).unwrap();
    let decoded = P2pNetworkAdapter::parse_cross_shard_incoming(&bytes).unwrap();
    assert!(!decoded.trusted, "wire message must never be trusted");
    // malformed input is rejected (fail-closed)
    assert!(P2pNetworkAdapter::parse_cross_shard_incoming(&[0xff, 0x00]).is_none());
}

#[test]
fn replication_bounds_are_sane_and_pinned() {
    // Guards the "no backfill storm" invariant: bounded concurrency, bounded
    // retries, bounded pass size, and reuse of the existing retro/KEEP
    // windows (4096 / 8000) so retention and replication cannot disagree.
    assert_eq!(crate::sync::ADOPT_REPL_MAX_CONCURRENCY, 8);
    assert_eq!(crate::sync::ADOPT_REPL_MAX_RETRIES, 3);
    assert_eq!(crate::sync::ADOPT_REPL_BACKFILL_MAX_PER_PASS, 64);
    assert_eq!(crate::sync::ADOPT_REPL_RETRO_DEPTH, 4096);
    assert_eq!(crate::sync::ADOPT_REPL_KEEP_WINDOW, 8000);
    assert_eq!(
        crate::sync::ADOPT_REPL_KEEP_WINDOW,
        STELL_DHT_KEEP_BLOCKS_DEFAULT
    );
}

#[test]
fn verified_fetch_names_the_same_slot_it_publishes() {
    // The fetch boundary (`fetch_verified_body`) must look up the exact blob
    // name the publish paths write, or replication fetches a slot nobody
    // fills. Pinned here, not trusted to a comment.
    let epoch = EpochTag::default();
    let hash = [0x42u8; 32];
    assert_eq!(
        block_body_blob_name(&epoch, &hash),
        format!("{}_blk_{}", epoch.as_str(), hex::encode(hash))
    );
}

#[tokio::test]
async fn p2p_cross_shard_message_is_broadcast_and_received() {
    // The cross-shard gossip path: shard 1 publishes to the topic of
    // shard 2 and the transport hosting shard 2 receives the message over
    // the pubsub channel. The received copy must be UNTRUSTED: the
    // inclusion proof is enforced on everything that arrives over the
    // wire, whatever the publisher claimed.
    let bus = InMemoryCrossShardPubSub::shared();
    let sender = P2pCrossShardTransport::new(bus.clone(), "epoch-a");
    let receiver = P2pCrossShardTransport::new(bus.clone(), "epoch-a");

    let mut inbound = receiver
        .listen_inbound(2)
        .await
        .expect("subscribe to the cross-shard topic");

    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, [9u8; 32], 10, 0, 0, 1, 2);
    let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);
    assert!(msg.trusted, "the locally produced message is trusted");

    sender.send_outbound(&msg).await.expect("publish");

    let got = tokio::time::timeout(std::time::Duration::from_secs(2), inbound.recv())
        .await
        .expect("inbound message within the timeout")
        .expect("inbound channel open");
    assert_eq!(got.msg_id, msg.msg_id);
    assert_eq!(got.source_shard, 1);
    assert_eq!(got.target_shard, 2);
    assert!(
        !got.trusted,
        "a gossiped message must never be trusted (inclusion proof enforced)"
    );
}

#[tokio::test]
async fn p2p_cross_shard_topic_is_epoch_scoped() {
    // The topic name is part of the routing contract: epoch first (two
    // chains must not share a mailbox), target shard second (each shard
    // has its own mailbox).
    assert_eq!(cross_shard_topic(2, "abc"), "stell/cross_shard/abc/2");
    assert_ne!(
        cross_shard_topic(2, "abc"),
        cross_shard_topic(2, "def"),
        "two chains must not share a cross-shard mailbox"
    );
    assert_ne!(
        cross_shard_topic(1, "abc"),
        cross_shard_topic(2, "abc"),
        "each shard must have its own mailbox"
    );

    // And the isolation is real, not only in the name: a transport of
    // another epoch must never hear the message.
    let bus = InMemoryCrossShardPubSub::shared();
    let sender = P2pCrossShardTransport::new(bus.clone(), "epoch-a");
    let other_chain = P2pCrossShardTransport::new(bus.clone(), "epoch-b");
    let mut inbound = other_chain
        .listen_inbound(2)
        .await
        .expect("subscribe to the cross-shard topic");

    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, [4u8; 32], 10, 0, 0, 1, 2);
    let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);
    sender.send_outbound(&msg).await.expect("publish");

    let leaked = tokio::time::timeout(std::time::Duration::from_millis(250), inbound.recv()).await;
    assert!(
        leaked.is_err(),
        "a different chain epoch must never receive the message"
    );
}

#[tokio::test]
async fn p2p_cross_shard_transport_variant_polls_and_prunes() {
    // The poll path the runtime uses: `fetch_cross_shard_inbound` drains
    // the inbox, `prune_consumed` drops the entries the shard already
    // committed (idempotently).
    let bus = InMemoryCrossShardPubSub::shared();
    let sender = CrossShardTransport::p2p(Arc::new(P2pCrossShardTransport::new(
        bus.clone(),
        "epoch-a",
    )));
    let receiver = CrossShardTransport::p2p(Arc::new(P2pCrossShardTransport::new(
        bus.clone(),
        "epoch-a",
    )));

    // Subscribe BEFORE the publish: gossip has no replay.
    assert!(receiver.fetch_cross_shard_inbound(2).await.is_empty());

    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, [5u8; 32], 10, 0, 0, 1, 2);
    let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);
    sender.broadcast_cross_shard(&msg).await.expect("publish");

    let inbound = receiver.fetch_cross_shard_inbound(2).await;
    assert_eq!(inbound.len(), 1, "the published message must be received");
    assert_eq!(inbound[0].msg_id, msg.msg_id);
    assert!(!inbound[0].trusted);

    // A second copy of the same message is dropped (gossip dedupe).
    sender.broadcast_cross_shard(&msg).await.expect("republish");
    assert!(receiver.fetch_cross_shard_inbound(2).await.is_empty());

    // Pruning a consumed entry removes it exactly once.
    let tx2 = Transaction::sign(&sk, [6u8; 32], 10, 0, 1, 1, 2);
    let msg2 = CrossShardMessage::new_trusted(1, 2, tx2, [0u8; 32], [4u8; 32]);
    sender.broadcast_cross_shard(&msg2).await.expect("publish");
    assert_eq!(receiver.prune_consumed(2, &[msg2.msg_id]).await, 1);
    assert_eq!(receiver.prune_consumed(2, &[msg2.msg_id]).await, 0);
    assert!(receiver.fetch_cross_shard_inbound(2).await.is_empty());
}

#[test]
fn l01_wire_decoder_rejects_pathological_prefix_and_trailing() {
    use std::time::Instant;
    // Pathological length-prefix: 0xFFFFFFFF count for a Vec<u8> must be
    // refused by the limit before any large allocation.
    let mut evil = Vec::new();
    evil.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    evil.extend_from_slice(&[0x41u8; 16]);
    let start = Instant::now();
    let res: Result<Vec<u8>, String> = decode_wire_limited(&evil, MAX_WIRE_SMALL_BYTES);
    assert!(res.is_err(), "pathological prefix must be refused");
    assert!(
        start.elapsed().as_secs() < 5,
        "refusal took too long: {:?}",
        start.elapsed()
    );
    // Trailing bytes are rejected even when the prefix is valid.
    let sk = SigningKey::generate(&mut OsRng);
    let tx = Transaction::sign(&sk, [2u8; 32], 1, 10_000, 0, 0, 0);
    let mut bytes = bincode::serialize(&tx).expect("tx serializes");
    bytes.push(0xFF);
    assert!(
        decode_wire_limited::<Transaction>(&bytes, MAX_WIRE_SMALL_BYTES).is_err(),
        "trailing byte must be rejected"
    );
    bytes.pop();
    let back: Transaction =
        decode_wire_limited(&bytes, MAX_WIRE_SMALL_BYTES).expect("valid tx must decode");
    assert_eq!(back.compute_tx_hash(), tx.compute_tx_hash());
    // parse_cross_shard_incoming inherits both guards.
    assert!(
        P2pNetworkAdapter::parse_cross_shard_incoming(&evil).is_none(),
        "evil cross-shard bytes must not decode"
    );
}

/// The header group (header + height index + QC sidecar) must ride ONE
/// rate-limit lane.
///
/// Regression (audit P2P C): the header was published as `Pointer` while its
/// QC sidecar rode the Bulk lane. A bulk-lane cooldown therefore shed the QC
/// while the header still landed, and every catch-up node reads "header
/// present, QC missing" as "not anchorable" — the header is rejected as
/// unanchored even though it was published correctly.
#[cfg(test)]
mod header_lane_tests {
    use super::*;

    #[test]
    fn qc_sidecar_rides_the_header_lane_not_the_bulk_lane() {
        let slots = header_publish_slots();
        assert_eq!(slots.len(), 3, "header, height index and QC sidecar");

        // Every blob of the group rides the SAME lane: the per-lane circuit
        // breaker then treats them as one unit and can never shed the QC
        // while the header lands.
        let lanes: Vec<String> = slots
            .iter()
            .map(|s| repl_lane_key(BUCKET_STELLEREUM_HEADERS, s.lane))
            .collect();
        assert!(
            lanes.windows(2).all(|w| w[0] == w[1]),
            "the header group must ride ONE lane, got {lanes:?}"
        );
        // And that lane is the Pointer lane, NOT the Bulk lane the sidecars
        // used to ride.
        assert_eq!(
            lanes[0],
            repl_lane_key(BUCKET_STELLEREUM_HEADERS, ReplStoreKind::Pointer)
        );
        assert_ne!(
            lanes[0],
            repl_lane_key(BUCKET_STELLEREUM_HEADERS, ReplStoreKind::Bulk),
            "the header lane must not be the bulk lane"
        );

        // The sidecars still ride along without charging the pacing gate, so
        // one header never pays 3x the publish floor.
        assert_eq!(slots[0].charge, ReplStoreKind::Pointer);
        assert_eq!(slots[1].charge, ReplStoreKind::Companion);
        assert_eq!(slots[2].charge, ReplStoreKind::Companion);
    }

    #[test]
    fn companion_kind_still_rides_a_pointer_lane_when_asked() {
        // `paced_store_blob_in_lane` decouples "does this publish charge the
        // pacing gate" (kind) from "which lane does it ride" (lane_kind): a
        // Companion in a Pointer lane is exactly the header-group sidecar.
        assert!(!matches!(
            ReplStoreKind::Companion,
            ReplStoreKind::Bulk | ReplStoreKind::Pointer
        ));
        // The default (charge-derived) companion lane is the split lane the
        // fix moved away from.
        assert_ne!(
            repl_lane_key(BUCKET_STELLEREUM_HEADERS, ReplStoreKind::Companion),
            repl_lane_key(BUCKET_STELLEREUM_HEADERS, ReplStoreKind::Pointer),
            "the default (charge-derived) companion lane is the split lane"
        );
    }
}

#[cfg(test)]
mod epoch_tests {
    use super::*;

    #[test]
    fn epoch_from_genesis_is_deterministic_and_short() {
        let root = [0xABu8; 32];
        let a = EpochTag::from_genesis(&root);
        let b = EpochTag::from_genesis(&root);
        assert_eq!(a, b, "the same chain must always name the same epoch");
        assert_eq!(a.as_str().len(), 16, "short and blob-name-safe");
        assert!(a.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_different_genesis_is_a_different_epoch() {
        let a = EpochTag::from_genesis(&[0x01u8; 32]);
        let b = EpochTag::from_genesis(&[0x02u8; 32]);
        assert_ne!(a, b, "two chains must not share a namespace");
    }

    #[test]
    fn every_published_name_is_scoped_to_the_epoch() {
        let e1 = EpochTag::from_genesis(&[0x11u8; 32]);
        let e2 = EpochTag::from_genesis(&[0x22u8; 32]);

        // The property that fixes the wipe problem: no name can collide across chains,
        // so a fresh node cannot read a previous run's head, header or snapshot.
        assert_ne!(head_name(&e1, 1), head_name(&e2, 1));
        assert_ne!(header_name(&e1, 7), header_name(&e2, 7));
        assert_ne!(header_index_name(&e1, 1, 7), header_index_name(&e2, 1, 7));
        assert_ne!(block_name(&e1, "deadbeef"), block_name(&e2, "deadbeef"));
        assert_ne!(snapshot_name(&e1, 1, 100), snapshot_name(&e2, 1, 100));

        // And the same chain always agrees on them.
        assert_eq!(
            head_name(&e1, 1),
            head_name(&EpochTag::from_genesis(&[0x11u8; 32]), 1)
        );
    }

    #[test]
    fn the_default_epoch_is_well_formed() {
        // Before genesis exists the tag is a fixed placeholder, not an empty string,
        // so early publishes produce valid names instead of colliding on "".
        let d = EpochTag::default();
        assert!(!d.as_str().is_empty());
        assert!(!head_name(&d, 1).starts_with('_'));
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    #[test]
    fn keep_blocks_parses_env_and_defaults() {
        assert_eq!(parse_keep_blocks(None), STELL_DHT_KEEP_BLOCKS_DEFAULT);
        assert_eq!(parse_keep_blocks(Some("8000".into())), 8000);
        assert_eq!(parse_keep_blocks(Some("50000".into())), 50_000);
        // Garbage and non-positive values fall back instead of disabling prune.
        assert_eq!(
            parse_keep_blocks(Some("".into())),
            STELL_DHT_KEEP_BLOCKS_DEFAULT
        );
        assert_eq!(
            parse_keep_blocks(Some("nope".into())),
            STELL_DHT_KEEP_BLOCKS_DEFAULT
        );
        assert_eq!(
            parse_keep_blocks(Some("0".into())),
            STELL_DHT_KEEP_BLOCKS_DEFAULT
        );
    }

    #[test]
    fn blob_ttl_is_a_generous_backstop_not_a_tight_bound() {
        const DAY: i64 = 24 * 3600 * 1000;
        // At the live KEEP=8000 the TTL is ~11 days: the height prune (which
        // deletes below finalized−8000 within minutes on a live chain) always
        // wins, and this only collects replicas/strays in the sweep.
        assert_eq!(dht_blob_ttl_ms(8000), 8000 * 120_000);
        assert!(dht_blob_ttl_ms(8000) > 7 * DAY);
        // Clamped on both ends: a tiny KEEP cannot expire the sync window, a
        // huge KEEP cannot disable expiry.
        assert_eq!(dht_blob_ttl_ms(1), 7 * DAY);
        assert_eq!(dht_blob_ttl_ms(100), 7 * DAY);
        assert_eq!(dht_blob_ttl_ms(1_000_000), 30 * DAY);
        assert_eq!(
            dht_blob_ttl_ms(u64::MAX),
            30 * DAY,
            "no overflow on absurd KEEP"
        );
    }

    #[test]
    fn prune_cursor_key_is_epoch_and_shard_scoped() {
        // A wiped chain (new epoch) must never resume a foreign cursor, and
        // shards must not share one. Pinned: restart-resume relies on it.
        let a = EpochTag::from_genesis(&[0x01u8; 32]);
        let b = EpochTag::from_genesis(&[0x02u8; 32]);
        assert_ne!(prune_cursor_key(&a, 0), prune_cursor_key(&b, 0));
        assert_ne!(prune_cursor_key(&a, 0), prune_cursor_key(&a, 1));
        assert!(prune_cursor_key(&a, 0).starts_with("stell_prune/cursor/"));
    }

    #[test]
    fn prune_cursor_value_round_trips_and_rejects_garbage() {
        assert_eq!(parse_prune_cursor("171234"), Some(171234));
        assert_eq!(parse_prune_cursor("  42\n"), Some(42));
        assert_eq!(parse_prune_cursor(""), None);
        assert_eq!(parse_prune_cursor("abc"), None);
        assert_eq!(parse_prune_cursor("-1"), None);
    }

    #[test]
    fn prune_pass_is_sized_to_drain_a_big_backlog() {
        // Live lesson 2026-10-06: 512/pass drains a 170k backlog in ~5 days
        // while the disk sits at 95%. 2048/pass brings it under a day.
        assert_eq!(STELL_DHT_PRUNE_MAX_PER_RUN, 2048);
    }

    #[test]
    fn prune_bound_keeps_exactly_keep_heights() {
        assert_eq!(prune_below_exclusive(9000, 8000), 1000);
        // Heights below the bound are exactly the prunable ones; the KEEP
        // window itself (bound..=tip) is untouched.
        assert_eq!(
            prune_below_exclusive(8000, 8000),
            0,
            "nothing to prune at exactly KEEP"
        );
        assert_eq!(
            prune_below_exclusive(100, 8000),
            0,
            "young chain prunes nothing"
        );
        assert_eq!(prune_below_exclusive(0, 8000), 0);
    }

    #[test]
    fn prune_batch_is_capped_monotonic_and_skips_genesis() {
        // Fresh cursor, bound beyond the cap: one capped batch, cursor advances.
        let (b, next) = prune_batch(0, 10_000, 512);
        assert_eq!(b.len(), 512);
        assert_eq!(b[0], 1, "height 0 (genesis) is never pruned");
        assert_eq!(*b.last().unwrap(), 512);
        assert_eq!(next, 512);
        // Continuation resumes where the last batch stopped...
        let (b2, next2) = prune_batch(next, 10_000, 512);
        assert_eq!(b2[0], 513);
        assert_eq!(next2, 1024);
        // ...and the tail batch stops exactly at the bound.
        let (b3, next3) = prune_batch(9_900, 10_000, 512);
        assert_eq!(
            b3,
            vec![
                9901, 9902, 9903, 9904, 9905, 9906, 9907, 9908, 9909, 9910, 9911, 9912, 9913, 9914,
                9915, 9916, 9917, 9918, 9919, 9920, 9921, 9922, 9923, 9924, 9925, 9926, 9927, 9928,
                9929, 9930, 9931, 9932, 9933, 9934, 9935, 9936, 9937, 9938, 9939, 9940, 9941, 9942,
                9943, 9944, 9945, 9946, 9947, 9948, 9949, 9950, 9951, 9952, 9953, 9954, 9955, 9956,
                9957, 9958, 9959, 9960, 9961, 9962, 9963, 9964, 9965, 9966, 9967, 9968, 9969, 9970,
                9971, 9972, 9973, 9974, 9975, 9976, 9977, 9978, 9979, 9980, 9981, 9982, 9983, 9984,
                9985, 9986, 9987, 9988, 9989, 9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997, 9998,
                9999, 10000
            ]
        );
        assert_eq!(next3, 10_000);
        // Caught-up cursor prunes nothing.
        let (b4, next4) = prune_batch(10_000, 10_000, 512);
        assert!(b4.is_empty());
        assert_eq!(next4, 10_000);
    }

    #[test]
    fn header_index_roundtrips_and_rejects_garbage() {
        let good_hash = "ab".repeat(32);
        let good = format!("42000:{good_hash}");
        assert_eq!(
            parse_header_index(good.as_bytes()),
            Some((42000, good_hash.clone()))
        );
        assert_eq!(parse_header_index(b"not-an-index"), None);
        assert_eq!(parse_header_index(b"abc:deadbeef"), None);
        assert_eq!(parse_header_index(b""), None);
    }

    /// PENTEST F4 (P0): a hostile index blob must not smuggle names/keys.
    /// Before the fix every one of these parsed `Some` and its hash half
    /// flowed into blob names and kv keys on the prune/fetch path.
    #[test]
    fn pentest_header_index_rejects_hostile_hashes() {
        // Path traversal: would escape the blob namespace on the prune path.
        assert_eq!(parse_header_index(b"5:../../evil"), None);
        assert_eq!(parse_header_index(b"5:..\\..\\evil"), None);
        assert_eq!(parse_header_index(b"5:/etc/passwd"), None);
        // Wrong shape: short, empty, too long, non-hex, embedded whitespace.
        assert_eq!(parse_header_index(b"5:deadbeef"), None);
        assert_eq!(parse_header_index(b"5:"), None);
        let long = format!("5:{}", "ab".repeat(64));
        assert_eq!(parse_header_index(long.as_bytes()), None);
        let nonhex = format!("5:{}", "zz".repeat(32));
        assert_eq!(parse_header_index(nonhex.as_bytes()), None);
        let spaced = format!("5:{}", "ab ".repeat(32));
        assert_eq!(parse_header_index(spaced.as_bytes()), None);
        // Uppercase hex is still hex: honest publishers interoperate.
        let upper = format!("5:{}", "AB".repeat(32));
        assert!(parse_header_index(upper.as_bytes()).is_some());
    }

    /// VERIFICATION F4-hardening: case, prefixes, trailing bytes and extra
    /// segments — which of these pass, and is that correct?
    ///
    /// * mixed-case 64-hex PASSES (correct: `hex::decode` accepts it, and our
    ///   own publishers emit lowercase — interop, not confusion);
    /// * `0x`-prefixed FAILS (correct: 66 chars, not 64 — no silent prefix
    ///   stripping that could alias two names);
    /// * 64-hex plus a trailing newline FAILS (correct: overlong);
    /// * a second `:segment` after the hash FAILS (correct: this exact shape
    ///   used to be ACCEPTED by `fetch_head_hash`'s ad-hoc split, which took
    ///   the first two segments — the inconsistency the F4 fix closes);
    /// * no blob name can be smuggled through the height field: heights are
    ///   `u64` and format as decimal (`header_index_name`/`header_name` only
    ///   ever interpolate the parsed integer, never the raw string).
    #[test]
    fn verification_header_index_case_prefix_and_segments() {
        let good = "ab".repeat(32);
        // Mixed case passes (canonical hex alphabet, both cases).
        let mixed = format!("5:{}", "aB".repeat(32));
        assert_eq!(
            parse_header_index(mixed.as_bytes()),
            Some((5, "aB".repeat(32))),
            "mixed-case 64-hex must parse (hex::decode accepts it)"
        );
        // `0x` prefix: 66 chars -> rejected, never stripped.
        let prefixed = format!("5:0x{good}");
        assert_eq!(parse_header_index(prefixed.as_bytes()), None);
        // Trailing newline: overlong -> rejected.
        let newline = format!("5:{good}\n");
        assert_eq!(parse_header_index(newline.as_bytes()), None);
        // Trailing segment: the shape fetch_head_hash used to accept.
        let extra = format!("5:{good}:evil");
        assert_eq!(
            parse_header_index(extra.as_bytes()),
            None,
            "an extra segment after the hash must be refused"
        );
        // Height field: only a decimal u64 parses; blob-name smuggling
        // (`..`, `/`, hex-looking path bytes) cannot survive the parse, and
        // the name builders below only interpolate the parsed integer.
        assert_eq!(parse_header_index(format!("..:{good}").as_bytes()), None);
        assert_eq!(parse_header_index(format!("-1:{good}").as_bytes()), None);
        assert_eq!(parse_header_index(format!("0x5:{good}").as_bytes()), None);
        let epoch = EpochTag::from_genesis(&[0x11u8; 32]);
        let name = super::header_index_name(&epoch, 0, 5);
        assert!(!name.contains("..") && !name.contains('/'));
        assert!(name.ends_with("_5"));
        // Exact good input still parses (no false positive).
        assert_eq!(
            parse_header_index(format!("5:{good}").as_bytes()),
            Some((5, good))
        );
    }

    /// VERIFICATION G5: a forged oracle feed planted in local KV (via
    /// `dht.sync` replication from an untrusted peer) must never be served
    /// as market evidence.
    /// FULL-PQ (mirrors `oracle::tests::pure_pq_refuses_classical_feed`):
    /// classical Ed25519 feed verification is removed with no PQ feed path
    /// (wire frozen), so EVERY classical feed — genuine, tampered, or
    /// self-consistent forgery — reads as a miss. Same fail-closed property,
    /// stronger verdict.
    #[test]
    fn verification_oracle_fetch_reverifies_signature() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let feed = PriceFeedUpdate::sign("STELL", 250_000, 1_700_000_000, &sk);
        let stored = hex::encode(bincode::serialize(&feed).unwrap());
        // Genuine classical feed: refused under FULL-PQ (no PQ feed path).
        assert!(
            decode_verified_price_feed(&stored).is_none(),
            "a classical feed must NOT decode under FULL-PQ"
        );
        // Tampered price bytes: signature no longer matches -> miss.
        let mut tampered = feed.clone();
        tampered.price_micro_usd = 1;
        let bad_price = hex::encode(bincode::serialize(&tampered).unwrap());
        assert!(
            decode_verified_price_feed(&bad_price).is_none(),
            "a re-priced feed with the old signature must read as a miss"
        );
        // Forged publisher key (attacker signs with their own key but claims
        // the asset): refused — under FULL-PQ even a self-consistent classical
        // signature fails the integrity gate (membership is checked by
        // OracleState on top of this).
        let attacker = SigningKey::generate(&mut OsRng);
        let forged = PriceFeedUpdate::sign("STELL", 1, 1_700_000_000, &attacker);
        let forged_hex = hex::encode(bincode::serialize(&forged).unwrap());
        assert!(
            decode_verified_price_feed(&forged_hex).is_none(),
            "a self-consistent classical signature must still read as a miss under FULL-PQ"
        );
        // Garbage: miss, never a panic or a fabricated feed.
        assert!(decode_verified_price_feed("zzzz").is_none());
        assert!(decode_verified_price_feed("").is_none());
    }

    #[test]
    fn prune_plan_covers_body_header_index_and_kv_but_never_head_or_snapshot() {
        let epoch = EpochTag::from_genesis(&[0x11u8; 32]);
        let hash_hex = "ab".repeat(32);
        let plan = plan_retained_prune(&epoch, 0, 1000, Some(&hash_hex));
        // Three header blobs (header + height→hash index + A1 QC sidecar,
        // same retention window) plus the hash-addressed
        // body resolved through that index...
        assert_eq!(plan.blobs.len(), 4);
        assert!(plan
            .blobs
            .iter()
            .any(|(b, n)| *b == BUCKET_STELLEREUM_HEADERS && n.contains("_h_1000")));
        assert!(plan
            .blobs
            .iter()
            .any(|(b, n)| *b == BUCKET_STELLEREUM_HEADERS && n.contains("_hi_0_1000")));
        assert!(plan
            .blobs
            .iter()
            .any(|(b, n)| *b == BUCKET_STELLEREUM_HEADERS && n.contains("_hq_0_1000")));
        assert!(plan
            .blobs
            .iter()
            .any(|(b, n)| *b == BUCKET_STELLEREUM_BLOCKS && n.contains(&hash_hex)));
        // ...and the per-hash kv index `broadcast_block` wrote alongside it.
        assert_eq!(plan.kv, vec![format!("{}{}", PREFIX_BLOCK_HASH, hash_hex)]);
        // The head pointer and snapshots are never planned: they stay forever.
        for (_, name) in &plan.blobs {
            assert!(!name.contains("_head"), "head pointer must never be pruned");
            assert!(!name.contains("_snap_"), "snapshots must never be pruned");
        }
        for k in &plan.kv {
            assert!(!k.starts_with(PREFIX_LATEST_HEIGHT), "height pointer stays");
        }
        // Without the index the body is unaddressable: headers are still
        // planned, the body falls back to the TTL backstop.
        let plan2 = plan_retained_prune(&epoch, 0, 1000, None);
        assert_eq!(plan2.blobs.len(), 3);
        assert!(plan2.kv.is_empty());
        // Epoch-scoped: a wipes-and-restart chain never prunes the old chain.
        let other = EpochTag::from_genesis(&[0x22u8; 32]);
        let plan3 = plan_retained_prune(&other, 0, 1000, Some(&hash_hex));
        assert_ne!(plan.blobs, plan3.blobs);
    }

    #[test]
    fn sync_paths_do_not_change_with_retention() {
        // The retention change is strictly additive on the publish side: the
        // fetch surface sync depends on is untouched. Pin the plan shape the
        // retro path relies on (body-only, no kv) so a future edit cannot
        // silently couple retention to sync correctness.
        let epoch = EpochTag::default();
        let sk = {
            use ed25519_dalek::SigningKey;
            use rand::rngs::OsRng;
            SigningKey::generate(&mut OsRng)
        };
        let block = crate::sharding::Block {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height: 7,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 0,
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
        let writes = plan_block_body_publish(&epoch, &block).expect("plan");
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].bucket, BUCKET_STELLEREUM_BLOCKS);
        assert!(writes[0].kv.is_empty(), "retro publish still writes no kv");
        assert_eq!(
            writes[0].name,
            block_body_blob_name(&epoch, &block.compute_hash())
        );
        assert!(
            plan_block_qc_publish(&epoch, &block).is_none(),
            "block without precommit_qc plans no _hq_ write"
        );

        let mut qc_block = block.clone();
        qc_block.precommit_qc = Some(crate::consensus::QuorumCertificate {
            height: 7,
            round: 0,
            kind: crate::consensus::VoteKind::Precommit,
            block_hash: Some(block.compute_hash()),
            signatures: vec![],
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
        });
        let qc_write = plan_block_qc_publish(&epoch, &qc_block).expect("qc write");
        assert_eq!(qc_write.bucket, BUCKET_STELLEREUM_HEADERS);
        assert_eq!(qc_write.name, header_qc_name(&epoch, 0, 7));
        assert!(qc_write.kv.is_empty(), "qc sidecar writes no kv");
    }

    #[test]
    fn qc_miss_backoff_scales_resets_and_stays_bounded() {
        let mut backoff = QcMissBackoff::default();
        assert!(!backoff.should_skip(0, 100, 1_000));

        // 300ms -> 600ms -> 1.2s -> 2.4s -> 4.8s -> 5s -> 5s
        let d1 = backoff.record_miss(0, 100, 1_000);
        assert_eq!(d1, QcMissBackoff::BASE_MS);
        assert_eq!(d1, 300, "first QC miss cooldown is sub-second");
        assert!(backoff.should_skip(0, 100, 1_299));
        assert!(!backoff.should_skip(0, 100, 1_300));
        assert!(!backoff.should_skip(0, 101, 1_500));

        assert_eq!(backoff.record_miss(0, 100, 1_300), 600);
        assert_eq!(backoff.record_miss(0, 100, 1_900), 1_200);
        assert_eq!(backoff.record_miss(0, 100, 3_100), 2_400);
        assert_eq!(backoff.record_miss(0, 100, 5_500), 4_800);
        assert_eq!(backoff.record_miss(0, 100, 10_300), 5_000);
        assert_eq!(backoff.record_miss(0, 100, 15_300), 5_000);

        backoff.record_hit(0, 100);
        assert!(!backoff.should_skip(0, 100, 15_301));
        assert_eq!(backoff.record_miss(0, 100, 15_301), 300);

        for h in 1..=(QcMissBackoff::CAP as u64 + 32) {
            backoff.record_miss(0, h + 1_000, 100_000 + h);
        }
        assert!(backoff.len() <= QcMissBackoff::CAP);
    }

    #[test]
    fn qc_clear_drops_cooldown_for_exactly_one_height() {
        let mut backoff = QcMissBackoff::default();
        // Three distinct heights are in cooldown.
        assert_eq!(backoff.record_miss(0, 7, 10_000), 300);
        assert_eq!(backoff.record_miss(0, 8, 10_000), 300);
        assert_eq!(backoff.record_miss(3, 7, 10_000), 300);
        assert!(backoff.should_skip(0, 7, 10_100));
        assert!(backoff.should_skip(0, 8, 10_100));
        assert!(backoff.should_skip(3, 7, 10_100));

        // `clear` (the public path callers use for an out-of-band QC) drops
        // exactly the named (shard, height), not its neighbours or namesakes.
        backoff.clear(0, 7);
        assert!(!backoff.should_skip(0, 7, 10_100));
        assert!(backoff.should_skip(0, 8, 10_100));
        assert!(backoff.should_skip(3, 7, 10_100));

        // Clearing an absent entry is a no-op, and the next miss restarts at
        // the sub-second base instead of carrying an old tier.
        backoff.clear(9, 999);
        assert_eq!(backoff.record_miss(0, 7, 10_100), QcMissBackoff::BASE_MS);
        assert_eq!(backoff.len(), 3);
    }
}

#[cfg(test)]
mod pointer_overwrite_tests {
    //! Orphan-chunk regression for fixed-name pointer overwrites.
    //!
    //! Chunk ids are content-addressed, so every head/snapshot-pointer rewrite
    //! retires its whole chunk set, while the kv sweep only collects EXPIRED
    //! manifests — never an overwritten one. A bare `store_blob_with_ttl` on
    //! the head key therefore leaks one chunk file per finalize (~130k/day).
    //! `store_pointer_overwrite` (delete-first) must keep the chunk count flat.
    //! These tests run against a REAL `Node` (like infnode's own
    //! `disk_growth_tests`): the leak is chunk FILES, invisible to any fake.
    use super::*;
    use std::sync::Arc;

    static TEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    async fn test_adapter(tag: &str) -> (P2pNetworkAdapter, std::path::PathBuf) {
        let n = TEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "stell-pointer-orphan-{tag}-{}-{n}",
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
            dir.clone(),
            std::path::PathBuf::new(),
        )
        .await
        .expect("test node");
        let adapter = P2pNetworkAdapter::new(node);
        adapter.set_epoch(EpochTag::from_genesis(&[0x77u8; 32]));
        (adapter, dir)
    }

    /// The peer-count hook reads the LIVE peer table (not a constant): a
    /// fresh node with no connections reports 0. `net_peerCount` is fed by
    /// `publish_live_peer_count` (see `rpc::note_peer_count`), so this pins
    /// the read path that makes the RPC value observed data.
    #[tokio::test]
    async fn live_peer_count_reads_the_peer_table() {
        let (adapter, dir) = test_adapter("peercount").await;
        assert_eq!(
            adapter.live_peer_count().await,
            0,
            "a node with no established peer connection observes 0 peers"
        );
        assert_eq!(
            adapter.publish_live_peer_count().await,
            0,
            "the hook publishes the observed table size"
        );
        assert_eq!(
            crate::rpc::observed_peer_count(),
            0,
            "the RPC counter follows the observed count (0, never fabricated)"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Live (non-hidden) chunk files under `<data_dir>/chunks`, all buckets.
    /// Hidden `.*.tmp.*` files are atomic-write leftovers, counted separately.
    fn chunk_files(
        data_dir: &std::path::Path,
    ) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
        let mut live = Vec::new();
        let mut hidden = Vec::new();
        let mut stack = vec![data_dir.join("chunks")];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if e.file_name().to_string_lossy().starts_with('.') {
                    hidden.push(p);
                } else {
                    live.push(p);
                }
            }
        }
        (live, hidden)
    }

    /// Live cadence between pointer overwrites in the regression tests.
    ///
    /// WHY PACED: every `store_blob_with_ttl` spawns a background
    /// `replicate_blob` task, which — with no peers to take the replica —
    /// falls back to a LOCAL chunk write (`store_chunk_replicated`). At
    /// production cadence (a finalize/probe per seconds) that task is long
    /// done before the next overwrite's delete, so delete-first is exact.
    /// Hammered back-to-back, the previous task can land AFTER the next
    /// delete and resurrect its version's file — an artifact of the
    /// no-peer fallback, not of the overwrite logic. Pacing each publish
    /// past the task's sub-ms work keeps the test on the production
    /// regime it is supposed to pin.
    const POINTER_REPUBLISH_PACE_MS: u64 = 5;

    #[tokio::test]
    async fn head_pointer_1000_overwrites_do_not_grow_chunks() {
        let (adapter, dir) = test_adapter("head").await;
        let adapter = Arc::new(adapter);
        let (base_live, _) = chunk_files(&dir);
        assert!(base_live.is_empty(), "fresh node holds no chunks");

        for h in 1..=1000u64 {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&h.to_le_bytes());
            assert!(
                adapter.publish_head(0, h, hash).await,
                "height {h} must publish (strictly increasing)"
            );
            // Production-regime pacing (see `POINTER_REPUBLISH_PACE_MS`).
            tokio::time::sleep(std::time::Duration::from_millis(POINTER_REPUBLISH_PACE_MS)).await;
        }
        // Drain the last publishes' background replication tasks before
        // counting (and before removing the temp dir, so no straggler
        // recreates files under it afterwards).
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let (live, hidden) = chunk_files(&dir);
        assert!(
            hidden.is_empty(),
            "no atomic-write leftovers after 1000 overwrites: {hidden:?}"
        );
        // Steady state is ONE live chunk set (the tiny head payload is 1 chunk);
        // without delete-first cleanup this would be 1000 orphaned files.
        // +1 slack for a straggler replication task under parallel-test load
        // (it writes exactly one version's file, once).
        assert!(
            live.len() <= base_live.len() + 2,
            "1000 head overwrites grew chunks {} -> {} (orphan leak)",
            base_live.len(),
            live.len()
        );

        // The pointer itself is still live and correct: overwrite cleanup must
        // never cost the latest value.
        let (h, hash) = adapter.fetch_head(0).await.expect("head must read back");
        assert_eq!(h, 1000);
        assert_eq!(&hash[..8], &1000u64.to_le_bytes());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn snapshot_pointer_overwrites_do_not_orphan_chunks() {
        let (adapter, dir) = test_adapter("snapptr").await;
        const N: u64 = 25;
        for h in 1..=N {
            // Small but height-distinct snapshot bodies (1 chunk each at 256B).
            let mut snap = vec![0u8; 256];
            snap[..8].copy_from_slice(&h.to_le_bytes());
            adapter.persist_state_snapshot(0, h * 100, &snap).await;
            // Production-regime pacing (see `POINTER_REPUBLISH_PACE_MS`).
            tokio::time::sleep(std::time::Duration::from_millis(POINTER_REPUBLISH_PACE_MS)).await;
        }
        // Drain background replication before counting (see head test).
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let (live, hidden) = chunk_files(&dir);
        assert!(
            hidden.is_empty(),
            "no atomic-write leftovers after {N} snapshots: {hidden:?}"
        );
        // N height-scoped snapshots (kept FOREVER by design) + exactly ONE live
        // pointer chunk; without delete-first cleanup the pointer alone would
        // add N orphaned files (2N total). +1 slack for a straggler task.
        assert!(
            live.len() <= N as usize + 2,
            "{N} snapshot publishes hold {} chunk files, want <= {} (pointer orphans?)",
            live.len(),
            N + 2
        );

        let latest = adapter
            .fetch_latest_snapshot(0)
            .await
            .expect("pointer must read back");
        assert_eq!(latest, N * 100);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn retro_publish_blocks_republishes_hq_qc_without_moving_head_and_backs_off_misses() {
        let (adapter, dir) = test_adapter("retro_hq").await;
        let sk = {
            use ed25519_dalek::SigningKey;
            use rand::rngs::OsRng;
            SigningKey::generate(&mut OsRng)
        };
        let mut block = crate::sharding::Block {
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
            height: 42,
            prev_hash: [0x11u8; 32],
            state_root: [0x22u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_042,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            round: 0,
        };
        let hash = block.compute_hash();
        let qc = crate::consensus::QuorumCertificate {
            height: 42,
            round: 0,
            kind: crate::consensus::VoteKind::Precommit,
            block_hash: Some(hash),
            signatures: vec![],
            shard_id: crate::sharding::MASTERCHAIN_SHARD,
        };
        block.precommit_qc = Some(qc.clone());

        // Missing height triggers backoff so the second immediate probe is skipped.
        assert!(adapter.fetch_block_qc_probe(0, 999).await.is_none());
        assert!(
            adapter
                .qc_miss_backoff
                .lock()
                .unwrap()
                .should_skip(0, 999, mesh_now_ms()),
            "missing _hq_ must enter miss backoff immediately"
        );
        assert!(adapter.fetch_block_qc_probe(0, 999).await.is_none());

        let report = adapter.retro_publish_blocks([&block], 1).await;
        assert_eq!(report.published, 1);
        assert_eq!(report.failed, 0);

        // Body, immutable headers/index, and _hq_ sidecar are all retrievable,
        // while shard_head remains untouched.
        assert!(adapter.fetch_block(&hash).await.is_some());
        let fetched_hash = adapter
            .fetch_head_hash(0, 42)
            .await
            .expect("retro_publish_blocks must publish immutable height index");
        assert_eq!(fetched_hash, hash);
        assert!(
            adapter.fetch_block_header(0, 42, hash).await.is_some(),
            "retro_publish_blocks must publish immutable header"
        );
        assert!(
            adapter.fetch_block_header_v2(0, 42, hash).await.is_some(),
            "retro_publish_blocks must publish immutable v2 header"
        );
        let fetched_qc = adapter
            .fetch_block_qc(0, 42)
            .await
            .expect("retro_publish_blocks must republish _hq_ QC");
        assert_eq!(fetched_qc.height, 42);
        assert_eq!(fetched_qc.block_hash, Some(hash));
        assert!(
            adapter.fetch_head(0).await.is_none(),
            "retro_publish_blocks must never touch shard_head"
        );

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
