//! Wave 14A: ShardRpcRouter multi-shard JSON-RPC & Explorer routing tests.
//!
//! Verifies that when shard 0 and shard 1 are linked via `ShardRpcRouter`
//! (`peer_shards`), calls arriving at shard 0's RPC/Explorer dispatch route
//! cleanly to shard 1 for:
//! - address-scoped reads (`stell_getBalance`, `stell_getBalanceSpv`, `stell_getProof`)
//! - shard-id-scoped reads (`stell_getBlock`, `stell_latestBlocks`,
//!   `stell_getBlockTransactions`, `stell_getFinalizedHeader`)
//! - cross-shard tx lookups (`stell_getTransactionReceipt`, `stell_getTransactionByHash`)
//! - address/source-shard-scoped writes (`stell_sendRawTransaction`, `stell_faucet`)
//! - merged Explorer `/api/blocks` (while preserving single-shard `/api/blocks` verbatim)
//!
//! while requests targeting a non-hosted shard (shard 2) still refuse fail-closed.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use stellereum::consensus::{QuorumCertificate, VoteKind};
use stellereum::explorer::{self, GatewayState};
use stellereum::governance::Governance;
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::rpc::{Faucet, ReceiptIndex, RpcState, ShardRpcRouter};
use stellereum::sharding::{Block, ShardRegistry, Transaction};
use stellereum::staking::StakingLedger;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const TEST_CHAIN_ID: u64 = 5757;
const FAUCET_TOKEN: &str = "w14-test-faucet-token";

fn make_rpc_state(
    shard_id: u32,
    registry: ShardRegistry,
    faucet: Option<Arc<Faucet>>,
) -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID));
    engine.set_shard_id(shard_id);
    let mempool = Mempool::default()
        .with_base_fee(Mempool::frozen_base_fee_floor())
        .pin_admission_shard(registry.is_sharded().then_some(shard_id));
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(RwLock::new(mempool)),
        height: Arc::new(AtomicU64::new(0)),
        node_id: format!("w14:shard-{shard_id}"),
        chain_id: TEST_CHAIN_ID,
        staking: Arc::new(RwLock::new(StakingLedger::new())),
        governance: Arc::new(RwLock::new(Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet,
        faucet_token: Some(FAUCET_TOKEN.to_string()),
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: registry,
    })
}

async fn make_linked_two_shard_pair(with_faucets: bool) -> (Arc<RpcState>, Arc<RpcState>) {
    let reg = ShardRegistry::from_ids([0, 1]);
    let f0 = with_faucets.then(|| {
        Arc::new(
            Faucet::new([0x11u8; 32], 0, 10_000_000_000, 100_000_000_000)
                .with_chain_id(TEST_CHAIN_ID),
        )
    });
    let f1 = with_faucets.then(|| {
        Arc::new(
            Faucet::new([0x22u8; 32], 1, 10_000_000_000, 100_000_000_000)
                .with_chain_id(TEST_CHAIN_ID),
        )
    });
    let st0 = make_rpc_state(0, reg.clone(), f0.clone());
    let st1 = make_rpc_state(1, reg, f1.clone());
    if let Some(f) = f0 {
        st0.engine
            .update_account(AccountState::new(f.account(), 10_000_000_000_000))
            .await;
    }
    if let Some(f) = f1 {
        st1.engine
            .update_account(AccountState::new(f.account(), 10_000_000_000_000))
            .await;
    }

    let router: ShardRpcRouter = Arc::new(RwLock::new(BTreeMap::new()));
    {
        let mut map = router.write().await;
        map.insert(0, Arc::clone(&st0));
        map.insert(1, Arc::clone(&st1));
    }
    st0.set_peer_shards(Arc::clone(&router));
    st1.set_peer_shards(router);
    (st0, st1)
}

fn signed_pq_tx(seed: u8, source_shard: u32, target_shard: u32, nonce: u64) -> Transaction {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    let mut tx = Transaction {
        from,
        to: [0x77u8; 32],
        amount: 1_000,
        gas_limit: 500_000,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, sig).encode();
    tx
}

async fn http_get(addr: std::net::SocketAddr, path: &str) -> (String, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
    (head.to_string(), body.to_string())
}

#[tokio::test]
async fn two_shard_router_helpers_lookup_hosted_and_reject_unhosted() {
    let (st0, st1) = make_linked_two_shard_pair(false).await;
    assert!(Arc::ptr_eq(
        &st0.state_for_shard(0).await.expect("shard 0 hosted"),
        &st0
    ));
    assert!(Arc::ptr_eq(
        &st0.state_for_shard(1).await.expect("shard 1 hosted"),
        &st1
    ));
    assert!(st0.state_for_shard(2).await.is_none());

    // Bare workchain address routes to shard 1 under the default topology.
    let addr = [0x44u8; 32];
    let routed = st0
        .state_for_address(&addr)
        .await
        .expect("address routes to hosted shard 1");
    assert!(Arc::ptr_eq(&routed, &st1));
}

#[tokio::test]
async fn shard0_rpc_routes_balance_spv_and_proof_to_shard1_and_refuses_shard2() {
    let (st0, st1) = make_linked_two_shard_pair(false).await;

    // Fund a workchain address ONLY on shard 1 (shard 0 holds 0 for it).
    let wc_addr = [0x44u8; 32];
    st1.engine
        .update_account(AccountState::new(wc_addr, 9_876_543))
        .await;
    st1.height.store(7, std::sync::atomic::Ordering::Relaxed);

    // Masterchain-funded address on shard 0 only.
    let mc_addr = [0x12u8; 32];
    st0.engine
        .update_account(AccountState::new(mc_addr, 111_222))
        .await;

    let wc_hex = hex::encode(wc_addr);
    let bal = st0.call("stell_getBalance", json!(wc_hex)).await;
    assert_eq!(
        bal["balance"], "9876543",
        "must read shard 1 balance: {bal}"
    );
    assert!(bal.get("error").is_none(), "unexpected error: {bal}");

    // Explicit `1:` prefix also routes cleanly to shard 1.
    let bal_prefixed = st0
        .call("stell_getBalance", json!(format!("1:{wc_hex}")))
        .await;
    assert_eq!(bal_prefixed["balance"], "9876543");

    // Masterchain explicit `-1:` form routes locally to shard 0.
    let mc_bal = st0
        .call(
            "stell_getBalance",
            json!(format!("-1:{}", hex::encode(mc_addr))),
        )
        .await;
    assert_eq!(mc_bal["balance"], "111222");

    // SPV + Proof route to shard 1 and return shard 1's balance/height/state_root.
    let spv = st0
        .call("stell_getBalanceSpv", json!({ "address": wc_hex }))
        .await;
    assert_eq!(spv["balance"], "9876543", "spv balance: {spv}");
    let proof = st0
        .call("stell_getProof", json!({ "address": wc_hex }))
        .await;
    assert_eq!(proof["balance"], 9_876_543u64, "proof balance: {proof}");
    assert_eq!(proof["height"], 7u64, "proof height from shard 1: {proof}");
    assert_eq!(proof["exists"], true);

    // Non-hosted shard 2 MUST refuse fail-closed.
    let denied = st0
        .call("stell_getBalance", json!(format!("2:{wc_hex}")))
        .await;
    assert!(
        denied["error"]
            .as_str()
            .is_some_and(|m| m.contains("shard 2")),
        "unhosted shard 2 must refuse fail-closed: {denied}"
    );
    let denied_proof = st0
        .call(
            "stell_getProof",
            json!({ "address": format!("2:{wc_hex}") }),
        )
        .await;
    assert!(
        denied_proof["error"]
            .as_str()
            .is_some_and(|m| m.contains("shard 2")),
        "unhosted shard 2 proof must refuse fail-closed: {denied_proof}"
    );
}

#[tokio::test]
async fn shard0_rpc_routes_blocks_headers_and_receipts_across_shards() {
    let (st0, st1) = make_linked_two_shard_pair(false).await;

    // Record distinct blocks on shard 0 (height 1) and shard 1 (height 1 & 2).
    let s0_hash = [0xA0u8; 32];
    st0.record_block(1, s0_hash, 0, 1_700_000_010).await;

    let tx1 = signed_pq_tx(0x55, 1, 1, 0);
    let tx1_hash = tx1.compute_tx_hash();
    let s1_b1_hash = [0xB1u8; 32];
    let mut b1 = Block {
        shard_id: 1,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0x33u8; 32],
        transactions: vec![tx1.clone()],
        cross_shard_out: vec![],
        timestamp: 1_700_000_020,
        proposer: [0x01u8; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    };
    let bh = b1.compute_hash();
    b1.precommit_qc = Some(QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: vec![],
        shard_id: 1,
    });
    st1.record_finalized_header(&b1).await;
    st1.record_adopted_block(1, s1_b1_hash, &[tx1], &[true], &[21_000], 1_700_000_020)
        .await;
    st1.record_block(2, [0xB2u8; 32], 0, 1_700_000_030).await;

    // `stell_getBlock` with `shard_id: 1` returns shard 1's block 1 (not shard 0's).
    let blk1 = st0
        .call("stell_getBlock", json!({ "height": 1, "shard_id": 1 }))
        .await;
    assert_eq!(
        blk1["hash"],
        hex::encode(s1_b1_hash),
        "shard 1 block: {blk1}"
    );
    assert_eq!(blk1["txs"], 1);

    // Without `shard_id`, `stell_getBlock` still returns shard 0's block 1.
    let blk0 = st0.call("stell_getBlock", json!({ "height": 1 })).await;
    assert_eq!(blk0["hash"], hex::encode(s0_hash), "shard 0 block: {blk0}");

    // `stell_latestBlocks` with `shard_id: 1` returns shard 1's recent blocks.
    let latest1 = st0
        .call("stell_latestBlocks", json!({ "shard_id": 1, "limit": 5 }))
        .await;
    let arr1 = latest1.as_array().expect("latestBlocks array");
    assert_eq!(arr1.len(), 2, "shard 1 has 2 blocks: {latest1}");
    assert_eq!(arr1[0]["height"], 2);

    // `stell_getBlockTransactions` with `shard_id: 1` returns shard 1's tx.
    let btx = st0
        .call(
            "stell_getBlockTransactions",
            json!({ "height": 1, "shard_id": 1 }),
        )
        .await;
    assert_eq!(
        btx["txs"][0]["tx_hash"],
        hex::encode(tx1_hash),
        "shard 1 block txs: {btx}"
    );

    // `stell_getFinalizedHeader` with `shard_id: 1` returns shard 1's header.
    let hdr1 = st0
        .call(
            "stell_getFinalizedHeader",
            json!({ "height": 1, "shard_id": 1 }),
        )
        .await;
    assert_eq!(hdr1["shard_id"], 1, "shard 1 finalized header: {hdr1}");
    assert_eq!(hdr1["block_hash"], hex::encode(bh));

    // Cross-shard `stell_getTransactionReceipt` on shard 0 (NO shard_id) finds shard 1's receipt!
    let rcpt = st0
        .call(
            "stell_getTransactionReceipt",
            json!({ "hash": hex::encode(tx1_hash) }),
        )
        .await;
    assert_eq!(rcpt["status"], "success", "cross-shard receipt: {rcpt}");
    assert_eq!(rcpt["height"], 1);
    // Confirmations computed against shard 1's tip (height 2 -> 2 - 1 + 1 = 2).
    assert_eq!(rcpt["confirmations"], 2);

    // Cross-shard `stell_getTransactionByHash` on shard 0 (NO shard_id) finds shard 1's tx!
    let tx_info = st0
        .call(
            "stell_getTransactionByHash",
            json!({ "hash": hex::encode(tx1_hash) }),
        )
        .await;
    assert_eq!(
        tx_info["status"], "success",
        "cross-shard tx lookup: {tx_info}"
    );
    assert_eq!(tx_info["source_shard"], 1);

    // Non-hosted shard 2 refuses fail-closed on block/receipt queries.
    let denied_blk = st0
        .call("stell_getBlock", json!({ "height": 1, "shard_id": 2 }))
        .await;
    assert!(
        denied_blk["error"]
            .as_str()
            .is_some_and(|m| m.contains("shard 2")),
        "unhosted shard 2 block must refuse: {denied_blk}"
    );
    let denied_rcpt = st0
        .call(
            "stell_getTransactionReceipt",
            json!({ "hash": hex::encode(tx1_hash), "shard_id": 2 }),
        )
        .await;
    assert!(
        denied_rcpt["error"]
            .as_str()
            .is_some_and(|m| m.contains("shard 2")),
        "unhosted shard 2 receipt must refuse: {denied_rcpt}"
    );
}

#[tokio::test]
async fn shard0_rpc_routes_send_raw_transaction_and_faucet_to_shard1() {
    let (st0, st1) = make_linked_two_shard_pair(true).await;

    // Fund sender ONLY on shard 1.
    let tx_s1 = signed_pq_tx(0x66, 1, 1, 0);
    let tx_s1_hash = tx_s1.compute_tx_hash();
    st1.engine
        .update_account(AccountState::new(tx_s1.from, 100_000_000))
        .await;
    let raw_s1 = hex::encode(bincode::serialize(&tx_s1).unwrap());

    // Submit to shard 0's RPC; shard 0's mempool is pinned to shard 0, so only
    // routing to shard 1 can succeed!
    let res = st0
        .call("stell_sendRawTransaction", json!({ "tx": raw_s1 }))
        .await;
    assert_eq!(
        res,
        json!(hex::encode(tx_s1_hash)),
        "shard-1 tx submitted to shard 0 must admit to shard 1: {res}"
    );
    assert_eq!(
        st0.mempool.read().await.len(),
        0,
        "shard 0 pool must stay empty"
    );
    assert_eq!(
        st1.mempool.read().await.len(),
        1,
        "shard 1 pool must admit tx"
    );

    // Non-hosted shard 2 transaction MUST refuse fail-closed.
    let tx_s2 = signed_pq_tx(0x67, 2, 2, 0);
    let raw_s2 = hex::encode(bincode::serialize(&tx_s2).unwrap());
    let denied_tx = st0
        .call("stell_sendRawTransaction", json!({ "tx": raw_s2 }))
        .await;
    assert!(
        denied_tx["error"]
            .as_str()
            .is_some_and(|m| m.contains("source_shard 2")),
        "unhosted shard 2 tx must refuse fail-closed: {denied_tx}"
    );

    // Faucet request on shard 0 for a shard-1 recipient routes to shard 1's faucet.
    let wc_recipient = hex::encode([0x88u8; 32]);
    let drip = st0
        .call(
            "stell_faucet",
            json!({ "address": wc_recipient, "token": FAUCET_TOKEN }),
        )
        .await;
    assert_eq!(
        drip["shard"], 1,
        "faucet drip must route to shard 1: {drip}"
    );
    assert_eq!(
        st1.mempool.read().await.len(),
        2,
        "drip must land in shard 1 pool"
    );

    // Faucet request for non-hosted shard 2 refuses fail-closed.
    let denied_drip = st0
        .call(
            "stell_faucet",
            json!({ "address": format!("2:{wc_recipient}"), "token": FAUCET_TOKEN }),
        )
        .await;
    assert!(
        denied_drip["error"].is_string(),
        "unhosted shard 2 faucet must refuse fail-closed: {denied_drip}"
    );
}

#[tokio::test]
async fn explorer_api_blocks_merges_hosted_shards_and_preserves_single_shard_verbatim() {
    // 1. Single-shard {0}: /api/blocks output stays verbatim (no shard_id field).
    let single = make_rpc_state(0, ShardRegistry::single(), None);
    single.record_block(1, [0xC0u8; 32], 2, 1_700_000_100).await;
    let gw_single = Arc::new(GatewayState::new(single, 1000));
    let l_single = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_single = l_single.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            l_single,
            explorer::router(gw_single)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let (head, body) = http_get(addr_single, "/api/blocks").await;
    assert!(head.contains("200 OK"), "single /api/blocks status: {head}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0],
        json!({
            "height": 1,
            "hash": hex::encode([0xC0u8; 32]),
            "txs": 2,
            "timestamp": 1_700_000_100u64,
        })
    );

    // 2. Multi-shard {0, 1}: /api/blocks merges shard 0 + shard 1 newest-first.
    let (st0, st1) = make_linked_two_shard_pair(false).await;
    st0.record_block(10, [0xD0u8; 32], 1, 1_700_000_200).await;
    st1.record_block(20, [0xD1u8; 32], 3, 1_700_000_250).await;
    let gw_multi = Arc::new(GatewayState::new(st0, 1000));
    let l_multi = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_multi = l_multi.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            l_multi,
            explorer::router(gw_multi)
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let (head_m, body_m) = http_get(addr_multi, "/api/blocks").await;
    assert!(
        head_m.contains("200 OK"),
        "multi /api/blocks status: {head_m}"
    );
    let vm: Value = serde_json::from_str(&body_m).unwrap();
    let am = vm.as_array().unwrap();
    assert_eq!(am.len(), 2, "merged blocks from shard 0 and 1: {vm}");
    assert_eq!(am[0]["shard_id"], 1);
    assert_eq!(am[0]["height"], 20);
    assert_eq!(am[1]["shard_id"], 0);
    assert_eq!(am[1]["height"], 10);
}
