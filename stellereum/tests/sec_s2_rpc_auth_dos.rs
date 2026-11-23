//! SEC-S2: RPC/API auth, DoS and shard-state confidentiality regressions.
//!
//! Each test below was written to FAIL against the pre-fix code and pass with
//! the minimal fix:
//!
//! 1. an EMPTY configured `STELL_RPC_AUTH_TOKEN` / `STELL_FAUCET_TOKEN` was
//!    matchable by an empty presented token (fail-open on the governance,
//!    mempool-dump, wallet-sign and faucet gates);
//! 2. an `events` subscription filter accepted arbitrarily long topic strings
//!    (count-capped, byte-unbounded) — per-subscription memory amplification;
//! 3. `stell_getEvents` scanned the whole receipt/event index without a scan
//!    budget on its legacy (non-cursor) path;
//! 4. per-IP budgets keyed on the EXACT IPv6 address, so one host rotating
//!    inside its own /64 reset every bucket;
//! 5. `stell_getBalance` / `stell_getBalanceSpv` / `stell_getProof` answered
//!    from the local trie for an address that routes to ANOTHER shard,
//!    presenting a local zero / exclusion proof as that shard's state.

use serde_json::json;
use std::sync::Arc;

use stellereum::contract::ContractEvent;
use stellereum::explorer::RateLimiter;
use stellereum::mempool::Mempool;
use stellereum::rpc::{
    budget_bucket_ip, configured_secret, faucet_ip_max_per_hour, Faucet, ReceiptIndex, RpcState,
    TxReceipt,
};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;

fn base_state(auth_token: Option<&str>, faucet_token: Option<&str>) -> Arc<RpcState> {
    Arc::new(RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(1_000)),
        node_id: "sec-s2".to_string(),
        chain_id: 777,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: auth_token.map(str::to_string),
        tx_broadcast: None,
        faucet: None,
        faucet_token: faucet_token.map(str::to_string),
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

fn err_of(v: &serde_json::Value) -> Option<String> {
    v.get("error").and_then(|e| e.as_str()).map(str::to_string)
}

// ---------------------------------------------------------------------------
// 1. Empty configured token is "not configured", never a matchable password.
// ---------------------------------------------------------------------------

#[test]
fn configured_secret_treats_empty_and_blank_as_absent() {
    assert_eq!(configured_secret(None), None);
    assert_eq!(configured_secret(Some("")), None);
    assert_eq!(configured_secret(Some("   ")), None);
    assert_eq!(configured_secret(Some("\t\n")), None);
    assert_eq!(configured_secret(Some("s3cret")), Some("s3cret"));
}

#[tokio::test]
async fn empty_configured_auth_token_does_not_open_mempool_dump() {
    let st = base_state(Some(""), None);
    let r = st.call("stell_mempoolDump", json!({ "token": "" })).await;
    let e = err_of(&r).expect("an empty configured token must fail closed, got a result");
    assert!(
        e.contains("auth_token is not configured") || e.contains("unauthorized"),
        "mempoolDump must refuse an empty configured token: {r}"
    );
}

#[tokio::test]
async fn empty_configured_auth_token_does_not_open_governance_writes() {
    let st = base_state(Some(""), None);
    let r = st
        .call("stell_executeProposal", json!({ "token": "", "id": 0 }))
        .await;
    let e = err_of(&r).expect("an empty configured token must not pass the gov gate");
    assert!(
        e.contains("requires STELL_RPC_AUTH_TOKEN"),
        "governance write must fail closed when the configured token is empty: {r}"
    );
}

#[tokio::test]
async fn empty_configured_auth_token_does_not_open_wallet_signing() {
    let base = base_state(Some(""), None);
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: base.receipts.clone(),
        auth_token: base.auth_token.clone(),
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        // Dev signing material is configured, so ONLY the token gate stands
        // between a caller and the dev key.
        msg_signing_seed: Some([0x22u8; 32]),
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    let r = st
        .call("stell_signMessage", json!({ "message": "hi", "token": "" }))
        .await;
    let e = err_of(&r).expect("dev signing must not open on an empty configured token");
    assert!(
        e.contains("unauthorized"),
        "signMessage must require a real token when one is configured: {r}"
    );
}

#[tokio::test]
async fn empty_configured_faucet_token_does_not_dispense() {
    let base = base_state(None, Some(""));
    let st = Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: base.receipts.clone(),
        auth_token: None,
        tx_broadcast: None,
        faucet: Some(Arc::new(Faucet::new([0x5Eu8; 32], 0, 10, 1_000))),
        faucet_token: base.faucet_token.clone(),
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    });
    let who = hex::encode([0x42u8; 32]);
    let r = st
        .call("stell_faucet", json!({ "address": who, "token": "" }))
        .await;
    let e = err_of(&r).expect("an empty configured faucet token must not dispense");
    assert!(
        e.contains("STELL_FAUCET_TOKEN"),
        "faucet must fail closed when its configured token is empty: {r}"
    );
}

// ---------------------------------------------------------------------------
// 2. Subscription FILTER BYTES are bounded, not just the topic COUNT.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn subscription_topic_strings_are_byte_capped() {
    let st = base_state(None, None);
    let contract = hex::encode([0x7Au8; 32]);
    let huge = "x".repeat(200_000);
    let r = st
        .call(
            "stell_subscribe",
            json!(["events", { "contract": contract, "topics": [huge] }]),
        )
        .await;
    let e = err_of(&r).expect("an oversized topic string must be refused");
    assert!(
        e.contains("topic") && (e.contains("long") || e.contains("large")),
        "oversized event topic must be refused explicitly: {r}"
    );
    // A short topic still subscribes (the cap is a bound, not a freeze).
    let r = st
        .call(
            "stell_subscribe",
            json!(["events", { "contract": contract, "topics": ["42"] }]),
        )
        .await;
    let sid = r.as_str().expect("a normal topic must still subscribe");
    assert!(stellereum::rpc::hub().unsubscribe(sid));
}

// ---------------------------------------------------------------------------
// 3. stell_getEvents legacy path has a scan budget.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_events_legacy_scan_is_budgeted() {
    let st = base_state(None, None);
    let contract = [0xAAu8; 32];
    let events: Vec<ContractEvent> = (0..stellereum::storage::STORAGE_SCAN_HARD_CAP + 1)
        .map(|i| ContractEvent {
            contract,
            topic: 1,
            value: i as i64,
        })
        .collect();
    st.receipts.write().await.insert(TxReceipt {
        tx_hash: [0x11u8; 32],
        height: 1,
        block_hash: [0x22u8; 32],
        index: 0,
        success: true,
        gas_limit: 0,
        fee_charged: 0,
        raw_tx: None,
        return_value: None,
        gas_used: None,
        events,
        contract_address: None,
    });
    // A filter that matches NOTHING forces the scan to walk every event; the
    // budget must stop it and refuse instead of burning the whole index.
    let r = st
        .call(
            "stell_getEvents",
            json!({ "contract": hex::encode(contract), "topic": 999_999_999i64 }),
        )
        .await;
    let e = err_of(&r).expect("an over-budget event scan must refuse, not return silently");
    assert!(
        e.contains("scan budget") || e.contains("too broad"),
        "over-budget event scan must name the budget: {r}"
    );
}

// ---------------------------------------------------------------------------
// 4. IPv6 /64 aggregation for every per-IP budget.
// ---------------------------------------------------------------------------

#[test]
fn ipv6_budget_buckets_aggregate_a_64() {
    let a = "2001:db8:aaaa:bbbb::1".parse().unwrap();
    let b = "2001:db8:aaaa:bbbb::2".parse().unwrap();
    let other = "2001:db8:aaaa:cccc::1".parse().unwrap();
    assert_eq!(budget_bucket_ip(a), budget_bucket_ip(b));
    assert_ne!(budget_bucket_ip(a), budget_bucket_ip(other));
    // IPv4 is exact (no aggregation beyond canonicalization).
    let v4 = "203.0.113.7".parse().unwrap();
    assert_eq!(budget_bucket_ip(v4), v4);

    let rl = RateLimiter::new(2);
    let t = 1_700_000_000u64;
    assert!(rl.check_at(a, t));
    assert!(rl.check_at(b, t));
    assert!(
        !rl.check_at("2001:db8:aaaa:bbbb::3".parse().unwrap(), t),
        "a third address in the same /64 must share the bucket"
    );
    assert!(
        rl.check_at(other, t),
        "a different /64 keeps its own bucket"
    );
}

#[tokio::test]
async fn faucet_ip_budget_aggregates_a_64() {
    let faucet = Faucet::new([0x33u8; 32], 0, 10, 1_000_000);
    let max = faucet_ip_max_per_hour();
    let now = 1_700_000_000u64;
    for i in 0..max {
        let ip: std::net::IpAddr = format!("2001:db8:dead:beef::{i:x}").parse().unwrap();
        assert!(
            faucet.check_ip_throttle(Some(ip), now).await,
            "drip {i} within the /64 budget must pass"
        );
    }
    let next: std::net::IpAddr = "2001:db8:dead:beef::ffff".parse().unwrap();
    assert!(
        !faucet.check_ip_throttle(Some(next), now).await,
        "a fresh address in the same /64 must NOT get a fresh hourly budget"
    );
}

// ---------------------------------------------------------------------------
// 5. Foreign-shard reads are refused, never answered from local state.
// ---------------------------------------------------------------------------

fn sharded_state() -> Arc<RpcState> {
    let base = base_state(None, None);
    // Shard 0 (masterchain) process with both shards in its registry: a bare
    // workchain address routes to shard 1, which this engine does not hold.
    base.engine.set_shard_id(0);
    Arc::new(RpcState {
        engine: base.engine.clone(),
        mempool: base.mempool.clone(),
        height: base.height.clone(),
        node_id: base.node_id.clone(),
        chain_id: base.chain_id,
        staking: base.staking.clone(),
        governance: base.governance.clone(),
        recent_blocks: base.recent_blocks.clone(),
        receipts: base.receipts.clone(),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::from_ids([0, 1]),
    })
}

#[tokio::test]
async fn foreign_shard_balance_reads_fail_closed() {
    let st = sharded_state();
    let addr = hex::encode([0x44u8; 32]);
    let r = st.call("stell_getBalance", json!(addr)).await;
    let e = err_of(&r).expect("a foreign-shard balance must be refused, not answered as 0");
    assert!(
        e.contains("shard 1") && e.contains("serves shard 0"),
        "refusal must name both shards: {r}"
    );

    let r = st
        .call("stell_getBalanceSpv", json!({ "address": addr }))
        .await;
    let e = err_of(&r).expect("a foreign-shard SPV balance must be refused");
    assert!(
        e.contains("shard 1"),
        "SPV refusal must name the shard: {r}"
    );

    let r = st.call("stell_getProof", json!({ "address": addr })).await;
    let e = err_of(&r).expect("a foreign-shard proof must be refused");
    assert!(
        e.contains("shard 1"),
        "proof refusal must name the shard: {r}"
    );

    let r = st
        .call("eth_getProof", json!([addr.clone(), [], "latest"]))
        .await;
    let e = err_of(&r).expect("an EVM foreign-shard proof must be refused");
    assert!(
        e.contains("shard 1"),
        "EVM proof refusal must name the shard: {r}"
    );

    // The explicitly-named masterchain form is local and still answerable.
    let mc = format!("-1:{addr}");
    let r = st.call("stell_getBalance", json!(mc)).await;
    assert!(
        err_of(&r).is_none(),
        "the local masterchain form must still be served: {r}"
    );
}
