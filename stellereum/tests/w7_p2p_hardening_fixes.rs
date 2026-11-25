//! Wave 7 P2P, Infnode, and Compact Gossip hardening regression tests
//! (W6-A3-1 .. W6-A3-10, with W6-A3-9 tested inside `infmail::web`).

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use infnode::config::{NodeConfig, PeerConfig};
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::node::{
    chunk_routes_for_gossip, Node, Route, MAX_ROUTES_TOTAL, MAX_UNSEALED_BLOB_BYTES,
};
use infnode::proto::{self, Frame};
use serde_json::json;
use stellereum::consensus::{register_validator_pq_key, Vote, VoteKind};
use stellereum::consensus_net::compact_prop::{BodyPull, CompactProposal};
use stellereum::consensus_net::{
    compact_proposal_from_block, dispatch_compact_body_reply, encode_broadcast_payload,
    open_compact_proposal_verified, short_id_index_for, BodyReplyRoute, CompactBodyServer,
    CompactInbound, CompactReceiver, CompactReplyCounters, ConsensusMsg,
    COMPACT_FULL_REPLY_COOLDOWN_MS, MAX_CONSENSUS_PUBSUB_BYTES, MAX_TX_MSG,
};
use stellereum::network::{InfnodeMeshTransport, ValidatorMeshTransport, MAX_CROSS_SHARD_MSG};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};

fn fresh_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stell-w7-p2p-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tmpdir");
    dir
}

fn base_cfg(name: &str, listen: &str, peers: Vec<PeerConfig>, allow_unknown: bool) -> NodeConfig {
    NodeConfig {
        name: name.to_string(),
        listen: listen.to_string(),
        client_listen: None,
        advertise: None,
        peers,
        allow_unknown,
        unknown_allow: vec!["*".to_string()],
        metrics_listen: None,
        log_level: Some(0),
        roles: Default::default(),
        outbox_ttl_secs: 3600,
        storage_roles: Vec::new(),
        validators: Vec::new(),
        domain: None,
        web_listen: None,
        wallet: None,
        web_static: None,
    }
}

fn peer_cfg(name: &str, pq: &PqKeys, endpoint: &str, storage_roles: Vec<String>) -> PeerConfig {
    PeerConfig {
        name: name.to_string(),
        consensus_pub: None,
        pq_pub: Some(pq.pq_pub_hex()),
        endpoints: vec![endpoint.to_string()],
        allow: vec!["*".to_string()],
        rate_limit_per_sec: 0,
        role: None,
        storage_roles,
    }
}

fn sample_tx(seed: u64) -> Transaction {
    Transaction {
        from: [seed as u8; 32],
        to: [0xBBu8; 32],
        amount: 500 + seed,
        gas_limit: 21_000,
        nonce: seed,
        source_shard: 0,
        target_shard: 0,
        signature: vec![0u8; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
}

fn signed_block(height: u64, txs: Vec<Transaction>, seed: u8) -> Block {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let proposer = sk.verifying_key().to_bytes();
    let fk = FalconKeypair::generate_from_seed(seed);
    register_validator_pq_key(proposer, PqScheme::Falcon512, fk.public_key.clone());
    let mut b = Block::new_for_test(MASTERCHAIN_SHARD, height, [0x11u8; 32], [0x22u8; 32], txs)
        .with_proposer(proposer)
        .with_timestamp(1_700_000_000 + height);
    b.sign_block(&sk);
    let hash = b.compute_hash();
    let falcon_id = fk.validator_id();
    let falcon_sig = fk.sign(&hash);
    b.validator_signatures.push((falcon_id, falcon_sig));
    b
}

// ===========================================================================
// W6-A3-1: Pubsub data budget vs MAX_FRAME, MAX_TX_MSG, MAX_CROSS_SHARD_MSG
// ===========================================================================

#[test]
fn w6_a3_1_pubsub_data_cap_fits_tx_and_xshard_and_respects_max_frame() {
    const _: () = assert!(proto::MAX_PUBSUB_DATA_LEN >= 8 * 1024 * 1024);
    const _: () = assert!(proto::MAX_PUBSUB_DATA_LEN <= proto::MAX_FRAME / 2);
    const _: () = assert!(MAX_TX_MSG * 2 <= proto::MAX_PUBSUB_DATA_LEN);
    const _: () = assert!(MAX_CROSS_SHARD_MSG * 2 <= proto::MAX_PUBSUB_DATA_LEN);
    assert_eq!(MAX_CONSENSUS_PUBSUB_BYTES, proto::MAX_PUBSUB_DATA_LEN / 2);

    // Legal max-tx and max-xshard hex strings pass `pubsub_data_ok`.
    assert!(proto::pubsub_data_ok(&"a".repeat(MAX_TX_MSG * 2)));
    assert!(proto::pubsub_data_ok(&"b".repeat(MAX_CROSS_SHARD_MSG * 2)));
    assert!(!proto::pubsub_data_ok(
        &"c".repeat(proto::MAX_PUBSUB_DATA_LEN + 1)
    ));

    // `encode_broadcast_payload` refuses a single consensus message whose hex
    // representation exceeds `MAX_PUBSUB_DATA_LEN`.
    let oversized_vote = ConsensusMsg::Vote {
        vote: Vote::signed_with_in_shard(
            [1u8; 32],
            0,
            1,
            0,
            VoteKind::Prevote,
            None,
            vec![0xAA; MAX_CONSENSUS_PUBSUB_BYTES + 1024],
        ),
        locked: None,
    };
    let err = encode_broadcast_payload(
        "stellereum/consensus/v1/t",
        &[Cow::Borrowed(&oversized_vote)],
    )
    .expect_err("oversized consensus payload must be refused before transport");
    assert!(!err.is_batch());
    assert!(err.message().contains("MAX_PUBSUB_DATA_LEN"));

    // Transport frame pre-flight check surfaces oversize rejections cleanly.
    let too_big_data = "f".repeat(proto::MAX_PUBSUB_DATA_LEN + 1);
    let res = InfnodeMeshTransport::validate_pubsub_frame(
        "stellereum/consensus/v1/t",
        &too_big_data,
        too_big_data.len() + 64,
    );
    assert!(res.is_err());
    let over_frame = InfnodeMeshTransport::validate_pubsub_frame(
        "stellereum/consensus/v1/t",
        "00",
        proto::MAX_FRAME,
    );
    assert!(over_frame.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w6_a3_1_deliver_direct_frame_rejects_oversize_before_send() {
    let dir = fresh_dir("a3-1-mesh");
    let node = Node::new(
        base_cfg("mesh", "127.0.0.1:0", Vec::new(), false),
        NodeKeys::generate(),
        PqKeys::from_seed([0x12u8; 32]),
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");
    let transport = InfnodeMeshTransport::new(node);
    let oversized = vec![b'a'; proto::MAX_FRAME];
    let res = transport
        .deliver_direct_frame([0x99u8; 20], "stellereum/consensus/v1/t", "00", &oversized)
        .await;
    assert!(res.is_err(), "oversized frame must be rejected cleanly");
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// W6-A3-2: Reject post-auth CHALLENGE, debit rep, close conn, no dht.json
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w6_a3_2_post_auth_challenge_rejected_debited_and_closes_conn() {
    let dir = fresh_dir("a3-2");
    let pq_a = PqKeys::from_seed([0x21u8; 32]);
    let pq_b = PqKeys::from_seed([0x22u8; 32]);
    let id_a = pq_a.pq_id();
    let id_b = pq_b.pq_id();

    let listen_a = "127.0.0.1:19921";
    let listen_b = "127.0.0.1:19922";

    let dir_a = dir.join("a");
    let dir_b = dir.join("b");
    let node_a = Node::new(
        base_cfg(
            "A",
            listen_a,
            vec![peer_cfg("B", &pq_b, listen_b, vec![])],
            false,
        ),
        NodeKeys::generate(),
        pq_a.clone(),
        dir_a,
        PathBuf::new(),
    )
    .await
    .expect("node A");
    let node_b = Node::new(
        base_cfg(
            "B",
            listen_b,
            vec![peer_cfg("A", &pq_a, listen_a, vec![])],
            false,
        ),
        NodeKeys::generate(),
        pq_b.clone(),
        dir_b.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node B");

    let sa = {
        let n = Arc::clone(&node_a);
        tokio::spawn(async move {
            let _ = n.serve().await;
        })
    };
    let sb = {
        let n = Arc::clone(&node_b);
        tokio::spawn(async move {
            let _ = n.serve().await;
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    node_a
        .warm_peer(id_b)
        .await
        .expect("initial auth handshake");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Remove dht.json after initial handshake so we can prove post-auth
    // CHALLENGE does NOT trigger `persist_routing` / rewrite `dht.json`.
    let dht_path = dir_b.join("dht.json");
    let _ = std::fs::remove_file(&dht_path);
    let score_before = node_b.rep_score(&id_a).await;

    let conn = {
        let peers = node_a.peers.read().await;
        let peer = peers.get(&id_b).expect("peer B");
        let guard = peer.conn.read().await;
        guard.clone().expect("live authenticated connection")
    };

    // Send a signed CHALLENGE frame over the already-authenticated connection.
    let mut challenge = Frame {
        kind: proto::kind::CHALLENGE,
        seq: 999,
        ts: proto::now_ms(),
        src: id_a,
        dst: id_b,
        svc: 0,
        payload: json!({
            "nonce": "deadbeef01020304",
            "at": proto::now_ms(),
            "fresh": hex::encode([0x55u8; 32]),
            "pq_pub": pq_a.pq_pub_hex(),
            "pq_ver": proto::PQ_TRANSCRIPT_VERSION,
            "pq_suite": proto::PQ_SUITE_MLKEM768_HYBRID,
            "pq_ek": hex::encode([0x33u8; 1184]),
        })
        .to_string()
        .into_bytes(),
        nonce: Vec::new(),
        sig: Vec::new(),
    };
    let digest = challenge.sign_digest();
    challenge.sig = pq_a.sign_digest(&digest);
    let wire = challenge.try_encode().expect("encode challenge");

    let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(&wire).await.expect("write");
    let _ = send.finish();

    // Connection must be closed by B due to unsolicited post-auth CHALLENGE.
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    assert!(
        closed.is_ok(),
        "post-auth CHALLENGE must close the connection"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;

    let score_after = node_b.rep_score(&id_a).await;
    assert!(
        score_after < score_before,
        "post-auth CHALLENGE must debit reputation (before={score_before}, after={score_after})"
    );
    assert!(
        !dht_path.exists(),
        "post-auth CHALLENGE must not call persist_routing / rewrite dht.json"
    );

    sa.abort();
    sb.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// W6-A3-3: Unsealed blob manifest aggregate cap & chunk running byte limit
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w6_a3_3_unsealed_blob_rejects_oversize_manifest_and_mismatched_chunk() {
    let dir = fresh_dir("a3-3");
    let node = Node::new(
        base_cfg("blob", "127.0.0.1:0", Vec::new(), false),
        NodeKeys::generate(),
        PqKeys::from_seed([0x32u8; 32]),
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");

    // 1. Unsealed manifest exceeding MAX_UNSEALED_BLOB_BYTES is refused BEFORE
    //    downloading or assembling chunks (even with 0 chunks on disk).
    let over_size = MAX_UNSEALED_BLOB_BYTES + 1;
    let n_chunks = over_size.div_ceil(1024 * 1024);
    let mut chunks = Vec::with_capacity(n_chunks);
    let mut off = 0usize;
    while off < over_size {
        let len = (over_size - off).min(1024 * 1024);
        chunks.push(json!({
            "id": format!("{off:064x}"),
            "off": off,
            "len": len,
        }));
        off += len;
    }
    let bad_manifest = json!({
        "bucket": "files",
        "name": "oversize.bin",
        "size": over_size,
        "nonce": "00",
        "key": hex::encode([0x11u8; 32]),
        "chunks": chunks,
    })
    .to_string();
    node.kv_store_local(
        &Node::blob_manifest_key("files", "oversize.bin"),
        &bad_manifest,
    )
    .await;
    assert!(
        node.fetch_blob("files", "oversize.bin").await.is_none(),
        "unsealed manifest > MAX_UNSEALED_BLOB_BYTES must be rejected"
    );

    // 2. Chunk whose on-disk/wire length exceeds manifest `len` is rejected.
    let bucket_dir = dir.join("chunks").join("files");
    std::fs::create_dir_all(&bucket_dir).unwrap();
    let cid = format!("{:064x}", 1usize);
    std::fs::write(bucket_dir.join(&cid), vec![0xAAu8; 4096]).unwrap();
    let mismatched_manifest = json!({
        "bucket": "files",
        "name": "mismatch.bin",
        "size": 100usize,
        "nonce": "00",
        "key": hex::encode([0x11u8; 32]),
        "chunks": [{ "id": cid, "off": 0usize, "len": 100usize }],
    })
    .to_string();
    node.kv_store_local(
        &Node::blob_manifest_key("files", "mismatch.bin"),
        &mismatched_manifest,
    )
    .await;
    assert!(
        node.fetch_blob("files", "mismatch.bin").await.is_none(),
        "chunk longer than manifest len must be discarded"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// W6-A3-4: Compact proposal proposer signature verification & replay safety
// ===========================================================================

#[test]
fn w6_a3_4_compact_receiver_verifies_signature_before_parking_and_no_replay_burn() {
    // 1. Park a valid signed proposal (missing 1 tx so it parks at attempts=1).
    let valid = signed_block(10, vec![sample_tx(1), sample_tx(2)], 0x41);
    let valid_prop = match compact_proposal_from_block(&valid, 0).expect("compact") {
        ConsensusMsg::CompactProposal { proposal } => proposal,
        other => panic!("expected CompactProposal, got {other:?}"),
    };
    let valid_index = short_id_index_for(&valid_prop.header, vec![sample_tx(1)]);

    let mut rx = CompactReceiver::new();
    match rx.on_proposal_indexed(valid_prop.clone(), &valid_index) {
        CompactInbound::Pull(pull) => assert_eq!(pull.attempt, 1),
        other => panic!("expected Pull(1), got {other:?}"),
    }
    assert_eq!(rx.parked_len(), 1);

    // 2. Flood 8 forged/unsigned compact proposals via `on_proposal_indexed`:
    //    must all be refused BEFORE parking or evicting the valid proposal.
    for i in 0..8u64 {
        let mut forged = Block::new_for_test(
            MASTERCHAIN_SHARD,
            11 + i,
            [0x11u8; 32],
            [0x22u8; 32],
            vec![sample_tx(100 + i)],
        )
        .with_proposer([0x99u8; 32]);
        forged.validator_signatures.clear();
        let forged_prop = CompactProposal::for_block(&forged, 0, &[]).expect("structural");
        assert!(open_compact_proposal_verified(forged_prop.clone()).is_err());

        let forged_idx = short_id_index_for(&forged_prop.header, std::iter::empty());
        assert!(matches!(
            rx.on_proposal_indexed(forged_prop, &forged_idx),
            CompactInbound::Refused(_)
        ));
    }
    assert_eq!(rx.parked_len(), 1);
    assert!(
        rx.is_parked(&valid_prop.block_hash),
        "forged proposals must never evict a parked authentic proposal"
    );

    // 3. Replaying the valid parked proposal must NOT increment attempts or
    //    trigger FetchFull.
    for _ in 0..5 {
        assert!(matches!(
            rx.on_proposal_indexed(valid_prop.clone(), &valid_index),
            CompactInbound::Refused(_)
        ));
    }
    assert!(
        rx.is_parked(&valid_prop.block_hash),
        "replaying a parked proposal must not exhaust attempts into FetchFull"
    );

    // 4. Now supply all txs in the index and replay: completes cleanly!
    let full_index = short_id_index_for(&valid_prop.header, vec![sample_tx(1), sample_tx(2)]);
    match rx.on_proposal_indexed(valid_prop, &full_index) {
        CompactInbound::Ready { block, .. } => {
            assert_eq!(block.compute_hash(), valid.compute_hash());
        }
        other => panic!("expected Ready when mempool completes, got {other:?}"),
    }
    assert_eq!(rx.parked_len(), 0);
}

// ===========================================================================
// W6-A3-5: dht.lookup visited tracking, cycle rejection, tightened TTL
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w6_a3_5_dht_lookup_rejects_cycles_and_tightens_ttl() {
    const _: () = assert!(proto::MAX_DHT_LOOKUP_TTL <= 4);

    let dir = fresh_dir("a3-5");
    let pq = PqKeys::from_seed([0x51u8; 32]);
    let self_id = pq.pq_id();
    let node = Node::new(
        base_cfg("lookup", "127.0.0.1:0", Vec::new(), false),
        NodeKeys::generate(),
        pq,
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");

    let missing_target = hex::encode([0xAAu8; proto::NODEID_LEN]);
    // Cyclic hop: our own ID already in `visited` must stop immediately.
    let resp = node
        .bp_handle_dht_lookup_raw(
            json!({
                "node": missing_target,
                "ttl": 4,
                "visited": [hex::encode(self_id)],
            }),
            [0x33u8; proto::NODEID_LEN],
        )
        .await
        .expect("response");
    let v: serde_json::Value = serde_json::from_slice(&resp).expect("json");
    assert_eq!(v["found"], false);

    // Oversized visited list is also rejected fail-closed.
    let too_many: Vec<String> = (0..(proto::MAX_DHT_LOOKUP_VISITED + 1))
        .map(|i| hex::encode([i as u8; proto::NODEID_LEN]))
        .collect();
    let resp2 = node
        .bp_handle_dht_lookup_raw(
            json!({
                "node": missing_target,
                "ttl": 4,
                "visited": too_many,
            }),
            [0x33u8; proto::NODEID_LEN],
        )
        .await
        .expect("response");
    let v2: serde_json::Value = serde_json::from_slice(&resp2).expect("json");
    assert_eq!(v2["found"], false);

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// W6-A3-6: Route table LRU eviction (keeping static) & chunked route gossip
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w6_a3_6_routes_evict_oldest_non_static_and_chunk_gossip() {
    let dir = fresh_dir("a3-6");
    let static_pq = PqKeys::from_seed([0x61u8; 32]);
    let static_id = static_pq.pq_id();

    // Pre-populate routes.json with MAX_ROUTES_TOTAL - 1 dynamic routes plus 1
    // static peer in config = MAX_ROUTES_TOTAL total.
    let mut persisted: HashMap<String, Route> = HashMap::new();
    for i in 0..(MAX_ROUTES_TOTAL - 1) {
        let mut id = [0u8; proto::NODEID_LEN];
        id[..4].copy_from_slice(&(i as u32 + 100).to_le_bytes());
        persisted.insert(
            format!("inf1:{}", hex::encode(id)),
            Route {
                endpoints: vec!["127.0.0.1:9001".to_string()],
                pq_hex: String::new(),
            },
        );
    }
    std::fs::write(
        dir.join("routes.json"),
        serde_json::to_string(&persisted).unwrap(),
    )
    .unwrap();

    let node = Node::new(
        base_cfg(
            "routes",
            "127.0.0.1:0",
            vec![peer_cfg("static", &static_pq, "127.0.0.1:9000", vec![])],
            false,
        ),
        NodeKeys::generate(),
        PqKeys::from_seed([0x63u8; 32]),
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");

    assert_eq!(node.bp_routes_len().await, MAX_ROUTES_TOTAL);

    // Admit 2 fresh valid PQ routes: must evict oldest non-static routes and
    // stay at MAX_ROUTES_TOTAL while keeping the static peer.
    let fresh_1 = PqKeys::from_seed([0x64u8; 32]);
    let fresh_2 = PqKeys::from_seed([0x65u8; 32]);
    let mut upd = serde_json::Map::new();
    upd.insert(
        fresh_1.pq_id_hex(),
        json!({ "endpoints": ["127.0.0.1:9101"], "pq_pub": fresh_1.pq_pub_hex() }),
    );
    upd.insert(
        fresh_2.pq_id_hex(),
        json!({ "endpoints": ["127.0.0.1:9102"], "pq_pub": fresh_2.pq_pub_hex() }),
    );
    let resp = node
        .bp_handle_dht_update(json!({ "routes": upd }))
        .await
        .expect("update resp");
    let rv: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    assert_eq!(rv["ok"], true);
    assert_eq!(node.bp_routes_len().await, MAX_ROUTES_TOTAL);

    // Both fresh routes and the static route are resolvable via dht.lookup.
    for target in [static_id, fresh_1.pq_id(), fresh_2.pq_id()] {
        let lr = node
            .bp_handle_dht_lookup(&hex::encode(target), [0x11u8; proto::NODEID_LEN])
            .await
            .expect("lookup resp");
        let lv: serde_json::Value = serde_json::from_slice(&lr).unwrap();
        assert_eq!(
            lv["found"],
            true,
            "route {} must remain present",
            hex::encode(target)
        );
    }

    // Chunked route gossip stays <= MAX_ROUTES_PER_UPDATE (512) per update.
    let entries: Vec<(String, Route)> = (0..1_200u32)
        .map(|i| {
            let mut id = [0u8; proto::NODEID_LEN];
            id[..4].copy_from_slice(&i.to_le_bytes());
            (
                format!("inf1:{}", hex::encode(id)),
                Route {
                    endpoints: vec!["127.0.0.1:9200".to_string()],
                    pq_hex: String::new(),
                },
            )
        })
        .collect();
    let chunks = chunk_routes_for_gossip(entries, proto::MAX_ROUTES_PER_UPDATE);
    assert_eq!(chunks.len(), 3);
    for c in &chunks {
        assert!(c.len() <= proto::MAX_ROUTES_PER_UPDATE);
        let r = node
            .bp_handle_dht_update(json!({ "routes": c }))
            .await
            .expect("chunk update");
        let v: serde_json::Value = serde_json::from_slice(&r).unwrap();
        assert_eq!(v["ok"], true);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// W6-A3-7: BodyPull::full_request per-peer sliding cooldown & unicast reply
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w6_a3_7_full_request_enforces_per_peer_sliding_cooldown_and_unicasts() {
    let b1 = signed_block(50, vec![sample_tx(1)], 0x71);
    let b2 = signed_block(51, vec![sample_tx(2)], 0x72);
    let h1 = b1.compute_hash();
    let h2 = b2.compute_hash();

    let mut server = CompactBodyServer::new();
    server.remember(&b1, 0);
    server.remember(&b2, 0);

    // Peer asks for b1 at t=4999ms (just before 5000ms bucket boundary).
    let req1 = BodyPull::full_request(50, 0, h1);
    assert!(server
        .serve_full_msg_for("peer-1", &req1, COMPACT_FULL_REPLY_COOLDOWN_MS - 1)
        .expect("valid")
        .is_some());

    // At t=5000ms (1ms later, crossing the old fixed-bucket boundary) for a
    // DIFFERENT cached block b2, the per-peer sliding cooldown MUST suppress it.
    let req2 = BodyPull::full_request(51, 0, h2);
    assert!(
        server
            .serve_full_msg_for("peer-1", &req2, COMPACT_FULL_REPLY_COOLDOWN_MS)
            .expect("valid")
            .is_none(),
        "per-peer sliding cooldown must block 1ms boundary-straddling full replies"
    );

    // Another peer is unaffected (isolated per-peer cooldown).
    let msg = server
        .serve_full_msg_for("peer-2", &req2, COMPACT_FULL_REPLY_COOLDOWN_MS)
        .expect("valid")
        .expect("distinct peer allowed");

    // After the full sliding cooldown elapses, peer-1 may retry.
    assert!(server
        .serve_full_msg_for("peer-1", &req2, COMPACT_FULL_REPLY_COOLDOWN_MS * 2 - 1,)
        .expect("valid")
        .is_some());

    // Verify full-block reply dispatches via unicast (never all-peer broadcast)
    // when the requester is a valid 40-hex node id.
    let counters = CompactReplyCounters::new();
    let peer_hex = "aa".repeat(20);
    let route = dispatch_compact_body_reply(
        &peer_hex,
        msg,
        &counters,
        |_peer, _msg| async { Ok(()) },
        |_msg| panic!("known peer full reply must unicast, never broadcast"),
    )
    .await;
    assert_eq!(route, BodyReplyRoute::Unicast([0xAAu8; 20]));
    assert_eq!(counters.unicast_sends(), 1);
    assert_eq!(counters.broadcast_sends(), 0);
}

// ===========================================================================
// W6-A3-8: handle_dht_find_value role enforcement (mail:/m: + files:/f:) & TOFU
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w6_a3_8_find_value_enforces_roles_on_short_prefixes_and_fails_closed_for_tofu() {
    let dir = fresh_dir("a3-8");
    let mail_only_pq = PqKeys::from_seed([0x81u8; 32]);
    let tofu_pq = PqKeys::from_seed([0x82u8; 32]);
    let unknown_id = [0x83u8; proto::NODEID_LEN];

    let node = Node::new(
        base_cfg(
            "acl",
            "127.0.0.1:0",
            vec![peer_cfg(
                "mail-peer",
                &mail_only_pq,
                "127.0.0.1:9300",
                vec!["mail".to_string()],
            )],
            true,
        ),
        NodeKeys::generate(),
        PqKeys::from_seed([0x85u8; 32]),
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");

    // Add a dynamic TOFU peer with empty `storage_roles`.
    node.bp_add_dynamic_peer(
        tofu_pq.pq_id(),
        PeerConfig {
            name: "tofu".to_string(),
            consensus_pub: None,
            pq_pub: Some(tofu_pq.pq_pub_hex()),
            endpoints: vec!["127.0.0.1:9301".to_string()],
            allow: vec!["*".to_string()],
            rate_limit_per_sec: 20,
            role: None,
            storage_roles: Vec::new(),
        },
    )
    .await
    .expect("add tofu peer");

    for (k, val) in [
        ("mail:alice", "m-long"),
        ("m:alice:1", "m-short"),
        ("files:alice", "f-long"),
        ("f:alice:1", "f-short"),
        ("public:key", "pub-val"),
    ] {
        node.kv_store_local(k, val).await;
    }

    // 1. Static peer with `storage_roles = ["mail"]` can read `mail:` & `m:`,
    //    NOT `files:` or `f:`.
    for (k, expect_found) in [
        ("mail:alice", true),
        ("m:alice:1", true),
        ("files:alice", false),
        ("f:alice:1", false),
        ("public:key", true),
    ] {
        let resp = node
            .bp_handle_dht_find_value(k, mail_only_pq.pq_id())
            .await
            .expect("resp");
        let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(
            v["found"], expect_found,
            "mail-only peer query for {k} got {v}"
        );
    }

    // 2. Dynamic TOFU peer with empty `storage_roles` fails CLOSED for all
    //    role-scoped keys (`mail:`, `m:`, `files:`, `f:`), while keeping public keys.
    assert!(!node.peer_allows(&tofu_pq.pq_id(), "mail").await);
    assert!(!node.peer_allows(&tofu_pq.pq_id(), "files").await);
    assert!(!node.peer_allows(&unknown_id, "mail").await);
    assert!(!node.peer_allows(&unknown_id, "files").await);

    for (k, expect_found) in [
        ("mail:alice", false),
        ("m:alice:1", false),
        ("files:alice", false),
        ("f:alice:1", false),
        ("public:key", true),
    ] {
        let resp = node
            .bp_handle_dht_find_value(k, tofu_pq.pq_id())
            .await
            .expect("resp");
        let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["found"], expect_found, "TOFU peer query for {k} got {v}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ===========================================================================
// W6-A3-10: pubsub.msg origin binding & mark_seen (topic, msg_id) namespace
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w6_a3_10_pubsub_msg_binds_origin_and_mark_seen_namespaces_by_topic() {
    let dir = fresh_dir("a3-10");
    let pq_a = PqKeys::from_seed([0x91u8; 32]);
    let pq_b = PqKeys::from_seed([0x92u8; 32]);
    let id_a = pq_a.pq_id();
    let id_b = pq_b.pq_id();

    let listen_a = "127.0.0.1:19931";
    let listen_b = "127.0.0.1:19932";

    let node_a = Node::new(
        base_cfg(
            "A",
            listen_a,
            vec![peer_cfg("B", &pq_b, listen_b, vec![])],
            false,
        ),
        NodeKeys::generate(),
        pq_a.clone(),
        dir.join("a"),
        PathBuf::new(),
    )
    .await
    .expect("node A");
    let node_b = Node::new(
        base_cfg(
            "B",
            listen_b,
            vec![peer_cfg("A", &pq_a, listen_a, vec![])],
            false,
        ),
        NodeKeys::generate(),
        pq_b.clone(),
        dir.join("b"),
        PathBuf::new(),
    )
    .await
    .expect("node B");

    let sa = {
        let n = Arc::clone(&node_a);
        tokio::spawn(async move {
            let _ = n.serve().await;
        })
    };
    let sb = {
        let n = Arc::clone(&node_b);
        tokio::spawn(async move {
            let _ = n.serve().await;
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 1. mark_seen is namespaced by (topic, msg_id): same msg_id on two
    //    different topics must NOT collide/suppress each other.
    assert!(!node_b.bp_mark_seen("topic-alpha", 42).await);
    assert!(node_b.bp_mark_seen("topic-alpha", 42).await);
    assert!(!node_b.bp_mark_seen("topic-beta", 42).await);

    // 2. Spoofed `req.origin` in `pubsub.msg` (not matching authenticated
    //    sender `id_a`) must be rejected cleanly with `bad origin`.
    let mut rx_b = node_b.register_app_sub("t-origin").await;
    let spoofed = json!({
        "topic": "t-origin",
        "origin": format!("inf1:{}", hex::encode([0xEEu8; proto::NODEID_LEN])),
        "seq": 1,
        "data": "spoofed-payload",
    })
    .to_string()
    .into_bytes();
    let resp = node_a
        .request_to(id_b, "pubsub.msg", spoofed)
        .await
        .expect("rpc ok");
    let v: serde_json::Value = serde_json::from_slice(&resp).expect("json");
    assert_eq!(v["ok"], false);
    assert_eq!(v["err"], "bad origin");
    assert!(
        rx_b.try_recv().is_err(),
        "spoofed origin must not deliver to subscriber"
    );

    // 3. Authentic `req.origin` matching `id_a` succeeds and delivers.
    let authentic = json!({
        "topic": "t-origin",
        "origin": format!("inf1:{}", hex::encode(id_a)),
        "seq": 1,
        "data": "authentic-payload",
    })
    .to_string()
    .into_bytes();
    let resp_ok = node_a
        .request_to(id_b, "pubsub.msg", authentic)
        .await
        .expect("rpc ok");
    let v_ok: serde_json::Value = serde_json::from_slice(&resp_ok).expect("json");
    assert_eq!(v_ok["ok"], true);
    let delivered = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .expect("delivery timeout")
        .expect("channel open");
    assert!(delivered.contains("authentic-payload"));

    sa.abort();
    sb.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
