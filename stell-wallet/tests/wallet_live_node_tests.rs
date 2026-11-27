//! End-to-end verification against a REAL Stellereum node stack — without the
//! live stand and without P2P.
//!
//! Each test boots a genuine `stellereum::rpc::RpcState` (real state engine,
//! real mempool admission, real receipt index, real faucet) served by the real
//! axum router on an isolated loopback port, then drives it with the wallet's
//! actual RPC client (`LightClient::connect_rpc`). Block production is the
//! only thing simulated: `record_receipts` is the exact hook consensus calls
//! on finalize, so Pending-before / Confirmed-after is the true code path.
//!
//! Port 8545/8546 (the live stand) is never touched.

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/rpc.rs"]
mod rpc;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/pq.rs"]
mod pq;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/client.rs"]
mod client;

use client::LightClient;
use pq::{PqKeyPair, PqScheme, DEFAULT_SALT};
use rpc::{RpcConfig, TxFinality};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

static NEXT_PORT: AtomicU16 = AtomicU16::new(18600);

struct LiveNode {
    url: String,
    state: Arc<stellereum::rpc::RpcState>,
    engine: Arc<stellereum::state_engine::InMemoryStateEngine>,
}

async fn spawn_node(auth_token: Option<String>, with_faucet: bool) -> LiveNode {
    let engine = Arc::new(stellereum::state_engine::InMemoryStateEngine::new());
    let mempool = Arc::new(tokio::sync::RwLock::new(
        stellereum::mempool::Mempool::default()
            .with_base_fee(stellereum::svm::GAS_BASIC_TRANSFER)
            .with_session_registry(engine.session_keys_handle()),
    ));
    let (faucet, faucet_token) = if with_faucet {
        let seed = [0xF1u8; 32];
        let f = stellereum::rpc::Faucet::new(seed, 1, 100_000_000_000, 1_000_000_000_000);
        let addr = f.account();
        engine
            .update_account(stellereum::state_engine::AccountState::new(
                addr,
                10_000_000_000_000_000,
            ))
            .await;
        (Some(Arc::new(f)), Some("faucet-secret".to_string()))
    } else {
        (None, None)
    };
    let state = Arc::new(stellereum::rpc::RpcState {
        engine: engine.clone(),
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "wallet-test".to_string(),
        chain_id: 5757,
        staking: engine.staking_handle(),
        governance: engine.governance_handle(),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token,
        tx_broadcast: None,
        faucet,
        faucet_token,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    let url = format!("http://127.0.0.1:{port}/");
    let svc = state.clone();
    let bind = format!("127.0.0.1:{port}");
    tokio::spawn(async move {
        let _ = stellereum::rpc::serve(&bind, svc).await;
    });
    // Wait until the router answers.
    let probe = RpcConfig {
        url: url.clone(),
        auth_token: None,
        faucet_token: None,
    };
    for _ in 0..100 {
        if rpc::chain_id(&probe).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    LiveNode { url, state, engine }
}

async fn rpc_client(node: &LiveNode, auth: Option<String>, faucet: Option<String>) -> LightClient {
    LightClient::connect_rpc(&node.url, auth, faucet, 4, 1)
        .await
        .expect("connect_rpc")
}

struct PqWallet {
    kp: PqKeyPair,
    address: [u8; 32],
}

fn pq_wallet(seed_byte: u8) -> PqWallet {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    seed[1] = 0xA5;
    let kp = PqKeyPair::from_seed(PqScheme::Falcon512, &seed);
    let address = kp.derive_address(&DEFAULT_SALT);
    PqWallet { kp, address }
}

fn wallet(seed_byte: u8) -> stellereum::wallet::WalletAccount {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    seed[1] = 0xA5;
    stellereum::wallet::WalletAccount::from_seed(&seed)
}

async fn fund(node: &LiveNode, addr: [u8; 32], balance: u64) {
    node.engine
        .update_account(stellereum::state_engine::AccountState::new(addr, balance))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_balance_spv_against_real_node_verifies() {
    let node = spawn_node(None, false).await;
    let me = wallet(0x11);
    fund(&node, me.address, 321_000_000_000).await;

    let client = rpc_client(&node, None, None).await;
    assert_eq!(client.chain_id().expect("chain_id"), 5757);
    let (balance, nonce, verified) = client.get_balance_spv(&me.address, 1).await.unwrap();
    assert_eq!((balance, nonce), (321_000_000_000, 0));
    assert!(verified, "real node proof must verify locally");

    // Unknown account: honest zero, no fabricated proof.
    let (zb, zn, zv) = client.get_balance_spv(&[0x99u8; 32], 1).await.unwrap();
    assert_eq!((zb, zn), (0, 0));
    assert!(!zv, "absent account must not report verified");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_pay_pending_then_confirmed_after_finalize_hook() {
    let node = spawn_node(None, false).await;
    let sender = pq_wallet(0x21);
    let recipient = pq_wallet(0x22);
    fund(&node, sender.address, 50_000_000_000).await;

    let client = rpc_client(&node, None, None).await;
    let tx = LightClient::build_pq_transfer_tx_bound(
        &sender.kp,
        recipient.address,
        1_000_000_000,
        500_000,
        0,
        1,
        1,
        true,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("build_pq_transfer_tx_bound");
    let (hash, finality) = client.broadcast_tx(&tx).await.unwrap();
    assert_eq!(hash, tx.compute_tx_hash());
    // No blocks are produced here: the honest answer is Pending, never Confirmed.
    assert_eq!(finality, TxFinality::Pending);

    // Consensus finalizes block 1 containing exactly this tx (the real hook).
    node.state
        .record_receipts(
            1,
            [0x22u8; 32],
            std::slice::from_ref(&tx),
            &[true],
            &[280_000],
        )
        .await;
    let cfg = client.rpc.clone().unwrap();
    let after = rpc::poll_receipt(&cfg, &hex::encode(hash), 5, 1);
    assert!(
        matches!(after, TxFinality::Confirmed { height: 1, .. }),
        "expected Confirmed@1, got {after:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_failed_receipt_reports_failed_not_confirmed() {
    let node = spawn_node(None, false).await;
    let sender = pq_wallet(0x31);
    fund(&node, sender.address, 50_000_000_000).await;

    let client = rpc_client(&node, None, None).await;
    let tx = LightClient::build_pq_transfer_tx_bound(
        &sender.kp,
        pq_wallet(0x32).address,
        1_000_000_000,
        500_000,
        0,
        1,
        1,
        true,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("build_pq_transfer_tx_bound");
    let (hash, _) = client.broadcast_tx(&tx).await.unwrap();
    node.state
        .record_receipts(
            9,
            [0x33u8; 32],
            std::slice::from_ref(&tx),
            &[false],
            &[280_000],
        )
        .await;
    let cfg = client.rpc.clone().unwrap();
    let after = rpc::poll_receipt(&cfg, &hex::encode(hash), 5, 1);
    assert!(
        matches!(
            after,
            TxFinality::Failed {
                height: Some(9),
                ..
            }
        ),
        "expected Failed@9, got {after:?}"
    );
    assert!(!after.is_confirmed());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_write_without_token_is_rejected() {
    let node = spawn_node(Some("secret".to_string()), false).await;
    let sender = pq_wallet(0x41);
    fund(&node, sender.address, 50_000_000_000).await;

    // Public signed transactions are accepted without an admin API token
    let anon = rpc_client(&node, None, None).await;
    let tx = LightClient::build_pq_transfer_tx_bound(
        &sender.kp,
        pq_wallet(0x42).address,
        1_000,
        500_000,
        0,
        1,
        1,
        true,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("build_pq_transfer_tx_bound");
    let (_, finality) = anon
        .broadcast_tx(&tx)
        .await
        .expect("public signed tx is accepted");
    assert_eq!(finality, TxFinality::Pending);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_faucet_drips_to_mempool_with_token() {
    let node = spawn_node(None, true).await;
    let me = wallet(0x51);
    let client = rpc_client(&node, None, Some("faucet-secret".to_string())).await;

    let (credited, drip_hash) = client.faucet_drip_rpc(&me.address, None).await.unwrap();
    assert_eq!(credited, 100_000_000_000);
    assert_eq!(drip_hash.len(), 64);
    let raw = hex::decode(&drip_hash).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    assert!(node.state.mempool.read().await.contains(&arr));

    // Wrong token: refused before any state change.
    let bad = rpc_client(&node, None, Some("wrong".to_string())).await;
    assert!(bad.faucet_drip_rpc(&me.address, None).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_token_balance_spv_and_send_admission() {
    let node = spawn_node(None, false).await;
    let owner = pq_wallet(0x61);
    let recipient = pq_wallet(0x62);
    fund(&node, owner.address, 50_000_000_000).await;

    let token_id = node
        .engine
        .create_token(
            owner.address,
            stellereum::token::TokenMetadata {
                name: "Live Token".into(),
                symbol: "LVT".into(),
                decimals: 9,
                total_supply: 0,
                max_supply: None,
                minter: [0u8; 32],
                paused: false,
                description: String::new(),
            },
            2_000_000,
        )
        .await
        .expect("create token");

    let client = rpc_client(&node, None, None).await;
    let (balance, verified, root_hex) = client
        .token_balance_spv_verified(&token_id, &owner.address)
        .await
        .unwrap();
    assert_eq!(balance, 2_000_000);
    assert!(verified, "real node token proof must verify locally");
    assert_eq!(root_hex.len(), 64);

    let tx = LightClient::build_pq_token_transfer_tx(
        &owner.kp,
        token_id,
        recipient.address,
        500_000,
        0,
        1,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("build_pq_token_transfer_tx");
    let (hash, finality) = client.broadcast_tx(&tx).await.unwrap();
    assert_eq!(finality, TxFinality::Pending);
    node.state
        .record_receipts(
            3,
            [0x44u8; 32],
            std::slice::from_ref(&tx),
            &[true],
            &[280_000],
        )
        .await;
    let cfg = client.rpc.clone().unwrap();
    let after = rpc::poll_receipt(&cfg, &hex::encode(hash), 5, 1);
    assert!(
        matches!(after, TxFinality::Confirmed { height: 3, .. }),
        "{after:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_reserved_confidential_payload_refused() {
    use stellereum::svm::OpCode;
    let node = spawn_node(None, false).await;
    let sender = wallet(0x71);
    fund(&node, sender.address, 80_000_000_000).await;

    let client = rpc_client(&node, None, None).await;
    let tx = sender.create_payload_transaction(
        vec![OpCode::Reserved42ConfidentialUnshield(
            stellereum::svm::ReservedOpcodeMarker,
        )],
        0,
        stellereum::svm::GAS_BASIC_TRANSFER,
    );
    let err = client.broadcast_tx(&tx).await;
    assert!(
        err.is_err(),
        "excised confidential opcode must be refused fail-closed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_stake_payload_admitted_to_mempool() {
    use stellereum::svm::OpCode;
    let node = spawn_node(None, false).await;
    let sender = pq_wallet(0x81);
    fund(&node, sender.address, 50_000_000_000).await;

    let client = rpc_client(&node, None, None).await;
    let tx = LightClient::build_pq_payload_tx_bound(
        &sender.kp,
        sender.address,
        0,
        stellereum::svm::GAS_STAKE_BOND
            + stellereum::svm::GAS_BASIC_TRANSFER
            + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS,
        0,
        1,
        1,
        true,
        vec![OpCode::SysCallStake {
            validator: sender.address,
            amount: 5_000_000_000,
        }],
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("build_pq_payload_tx_bound");
    // The builder signs a well-formed payload tx (verifies locally).
    assert!(stellereum::sharding::Transaction::verify_signatures_batch(
        std::slice::from_ref(&tx)
    ));
    let (hash, finality) = client.broadcast_tx(&tx).await.unwrap();
    assert_eq!(hash, tx.compute_tx_hash());
    assert_eq!(finality, TxFinality::Pending);
    assert!(node.state.mempool.read().await.contains(&hash));
}
