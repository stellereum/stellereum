//! Minimal demo: run the explorer + rate-limited gateway with seeded data.
//!     cargo run --release --example gateway_demo
//! Then open http://127.0.0.1:18080/ or curl the /api endpoints.

use std::sync::Arc;
use stellereum::explorer::{self, GatewayState};
use stellereum::rpc::RpcState;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

#[tokio::main]
async fn main() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let who = [3u8; 32];
    engine
        .update_account(AccountState::new(who, 123_450_000_000))
        .await;

    // Deploy a tiny WASM contract so /api/contracts is non-empty.
    // (func (export "double") (param i64) (result i64) local.get 0; i64.const 2; i64.mul)
    const DOUBLE_WASM: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60, 0x01, 0x7e, 0x01,
        0x7e, 0x03, 0x02, 0x01, 0x00, 0x07, 0x0a, 0x01, 0x06, 0x64, 0x6f, 0x75, 0x62, 0x6c, 0x65,
        0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x42, 0x02, 0x7e, 0x0b,
    ];
    let _ = engine
        .deploy_contract([1u8; 32], DOUBLE_WASM.to_vec(), 0)
        .await
        .unwrap();

    let st = Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        node_id: "inf1:demo".to_string(),
        chain_id: stellereum::zkml::DEFAULT_CHAIN_ID,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token: None,
        tx_broadcast: None,
        faucet: Some(Arc::new(stellereum::rpc::Faucet::new(
            [0x11u8; 32],
            1,
            100 * 1_000_000_000,
            1_000 * 1_000_000_000,
        ))),
        // The faucet is fail-closed, so a demo that wants it to dispense has to
        // present a token. Mirrors STELL_FAUCET_TOKEN.
        faucet_token: Some("demo-token".to_string()),
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });
    for h in 1..=5u64 {
        st.record_block(h, [h as u8; 32], (h as usize) * 2, 1_700_000_000 + h)
            .await;
    }

    let addr = std::env::var("GATEWAY_LISTEN").unwrap_or_else(|_| "127.0.0.1:18080".to_string());
    let gw = Arc::new(GatewayState::new(st, explorer::DEFAULT_RATE_LIMIT_PER_SEC));
    println!("Explorer gateway on http://{addr}/  (Ctrl-C to stop)");
    if let Err(e) = explorer::serve(&addr, gw).await {
        eprintln!("gateway error: {e}");
    }
}
