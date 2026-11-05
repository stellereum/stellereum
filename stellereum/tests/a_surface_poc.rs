//! A-SURFACE PoC suite: unauthenticated / unbounded-input / DoS-amplification
//! probes over the RPC + P2P serve paths. Local only, no network.
//!
//! Each `poc_*` test crafts a malicious input and documents whether the node
//! fails closed (rejects with a bound error) or fails open (accepts). A
//! passing PoC here = the flaw EXISTS (fail-open proven offline).

use serde_json::{json, Value};
use stellereum::consensus_net::{ConsensusMsg, MAX_BATCH_BYTES, MAX_CONSENSUS_MSG};
use stellereum::governance::Governance;
use stellereum::mempool::Mempool;
use stellereum::native_api;
use stellereum::rpc::{handle_rpc_call, ReceiptIndex, RpcRequest, RpcState};
use stellereum::sharding::{Block, ShardRegistry, Transaction};
use stellereum::staking::StakingLedger;
use stellereum::state_engine::InMemoryStateEngine;
use std::sync::Arc;

fn test_rpc_state() -> Arc<RpcState> {
    Arc::new(RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(42)),
        node_id: "poc:test".to_string(),
        chain_id: 777,
        staking: Arc::new(tokio::sync::RwLock::new(StakingLedger::new())),
        governance: Arc::new(tokio::sync::RwLock::new(Governance::new())),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

/// F1 (P0): `stell_shieldedBalance` was removed with the shielded protocol
/// (Ristretto deletion wave: confidential sled tree + GAS_CONFIDENTIAL_*
/// consts deleted, no migration — fresh genesis writes nothing confidential).
/// Any call must fail closed as an unknown method, so no payload array —
/// bounded or not — can reach decrypt work on an unauthenticated read.
#[tokio::test]
async fn poc_shielded_balance_cap_refuses_over_cap() {
    let engine = InMemoryStateEngine::new();
    const N: usize = 2500;
    let mut payloads = Vec::with_capacity(N);
    for i in 0..N as u32 {
        payloads.push(json!({
            "ephemeral_pub": format!("{:064x}", i.wrapping_mul(2654435761)),
            "ciphertext": "ab".repeat(48),
            "nonce": "00".repeat(24),
        }));
        if payloads.len() >= N {
            break;
        }
    }
    assert_eq!(payloads.len(), N);
    let params = json!({
        "viewing_key": "07".repeat(32),
        "payloads": payloads,
    });
    let out = native_api::dispatch(&engine, "stell_shieldedBalance", &params).await;
    // REMOVED: the method no longer exists (unknown-method, never a scan).
    assert!(
        matches!(
            out,
            Err(stellereum::native_api::NativeApiError::UnknownMethod(_))
        ),
        "shieldedBalance must be an unknown method, got: {out:?}"
    );
    // Boundary: even a single payload is refused the same way (no cap path).
    let params_one = json!({
        "viewing_key": "07".repeat(32),
        "payloads": payloads[..1].to_vec(),
    });
    let out_one = native_api::dispatch(&engine, "stell_shieldedBalance", &params_one).await;
    assert!(
        matches!(
            out_one,
            Err(stellereum::native_api::NativeApiError::UnknownMethod(_))
        ),
        "shieldedBalance must stay unknown for any payload count, got: {out_one:?}"
    );
}

/// F2 (P1): `stell_estimateFee` funnels an unbounded `method` string into the
/// simulation. A non-hex `method` becomes raw call bytes verbatim
/// (`s.as_bytes().to_vec()` in `parse_estimate_payload`) with no length cap
/// before a full SVM execution on a state clone — unauthenticated.
#[tokio::test]
async fn poc_estimate_fee_method_cap_refused() {
    let st = test_rpc_state();
    let big_method = "G".repeat(200_000);
    let req = RpcRequest {
        jsonrpc: None,
        id: Some(Value::from(1)),
        method: "stell_estimateFee".to_string(),
        params: json!({
            "from": "00".repeat(32),
            "to": "11".repeat(32),
            "method": big_method,
        }),
    };
    let resp = handle_rpc_call(&st, &req).await;
    // FIXED (audit F2): over-cap method bytes are parse-refused (-32602)
    // before any simulation runs.
    match (&resp.result, &resp.error) {
        (None, Some(e)) => assert_eq!(
            e.code, -32602,
            "200KB method must be parse-rejected; got: {}",
            e.message
        ),
        (Some(_), _) => panic!("over-cap method must not reach simulation"),
        (None, None) => panic!("estimate returned neither result nor error"),
    }
}

/// F3 (P2): `stell_sessionKeys` has no pagination/limit — the full registry
/// dumps in one answer and a caller-supplied `limit` is silently ignored.
/// Contrast `stell_bridgeDeposits`, which honors `limit` capped at 1000.
#[tokio::test]
async fn poc_session_keys_limit_honored() {
    let engine = InMemoryStateEngine::new();
    // Seed 5 grants directly (registry is the store of record).
    {
        let mut reg = engine.session_keys_write().await;
        for i in 0..5u8 {
            let mut pk = [0u8; 32];
            pk[0] = i + 1;
            reg.entries.insert(
                pk,
                stellereum::zkml::SessionKeyRecord {
                    master: [0xAu8; 32],
                    valid_until: u64::MAX,
                    max_gas_spend: 1_000_000,
                    gas_spent: 0,
                    scope: 0,
                    max_value_per_tx: u64::MAX,
                    revoked: false,
                },
            );
        }
    }
    let base = native_api::dispatch(&engine, "stell_sessionKeys", &json!({}))
        .await
        .expect("sessionKeys must answer");
    assert_eq!(base["count"], json!(5u64));
    // FIXED (audit F4): `limit` is honored (default 100, cap 1000).
    let limited = native_api::dispatch(&engine, "stell_sessionKeys", &json!({"limit": 2}))
        .await
        .expect("sessionKeys with limit must answer");
    assert_eq!(limited["count"], json!(2u64));
    assert_eq!(limited["session_keys"].as_array().unwrap().len(), 2);
}

/// F4 (P1): the 512KB batch DoS bound (`MAX_BATCH_BYTES`) is bypassable via
/// the singleton path. A Proposal whose encoding exceeds the batch cap is
/// refused by `batch_encode` yet still `decode`s fine and is re-sent alone by
/// `broadcast_singles` (capped only at 32MiB) — cheap gossip forces a full
/// block decode downstream.
#[test]
fn poc_singleton_proposal_size_bounds() {
    // 8000 dummy txs (no payload, no sig — decode performs no signature
    // checks, exactly like an attacker's bytes).
    let txs: Vec<Transaction> = (0..8000u64)
        .map(|n| Transaction {
            from: [0x01; 32],
            to: [0x02; 32],
            amount: 1,
            gas_limit: 21_000,
            nonce: n,
            source_shard: 0,
            target_shard: 0,
            signature: Vec::new(),
            payload: Vec::new(),
            priority_fee_per_gas: 0,
        })
        .collect();
    let block = Block {
        height: 9,
        transactions: txs,
        ..Block::default()
    };
    let msg = ConsensusMsg::Proposal {
        height: 9,
        round: 0,
        block,
    };
    let bytes = msg.encode().expect("proposal must encode");
    assert!(
        bytes.len() > MAX_BATCH_BYTES,
        "fixture must exceed the batch cap to prove the bypass (got {} bytes)",
        bytes.len()
    );
    assert!(bytes.len() < MAX_CONSENSUS_MSG);
    // Batch path refuses it (512KB is a BATCHING threshold, not a security
    // boundary) ...
    assert!(ConsensusMsg::batch_encode(std::slice::from_ref(&msg)).is_err());
    // ... and the singleton path MUST accept it: an 8000-tx proposal is a
    // legitimate size (under MAX_BLOCK_TXS=10k and MAX_BLOCK_WIRE_BYTES=24MB).
    // Capping singletons at the batch bound would strand valid large blocks
    // (liveness). The security boundary is the 32MB frame cap, pinned below.
    assert!(ConsensusMsg::decode(&bytes).is_ok());
    // Frame cap still enforced: >32MB refused at decode.
    let huge = vec![0u8; MAX_CONSENSUS_MSG + 1];
    assert!(ConsensusMsg::decode(&huge).is_err());
}

/// Negative controls: bounds that ARE enforced (these must keep passing).
#[tokio::test]
async fn poc_negative_controls_still_fail_closed() {
    let st = test_rpc_state();
    // getProof storage_keys > 32 refused.
    let keys: Vec<Value> = (0..33).map(|_| json!("00".repeat(32))).collect();
    let req = RpcRequest {
        jsonrpc: None,
        id: Some(Value::from(1)),
        method: "stell_getProof".to_string(),
        params: json!({"address": "00".repeat(32), "storage_keys": keys}),
    };
    let resp = handle_rpc_call(&st, &req).await;
    let code = resp.error.as_ref().map(|e| e.code);
    assert_eq!(code, Some(-32602));

    // unshield > 64 inputs refused (native dispatch, no engine state needed
    // for the length gate).
    let inputs: Vec<Value> = (0..65)
        .map(|_| {
            json!({"commitment": "00".repeat(32), "amount": "1", "blinding": "00".repeat(32)})
        })
        .collect();
    let err = native_api::dispatch(
        &st.engine,
        "stell_unshield",
        &json!({"to": "00".repeat(32), "amount": 1, "inputs": inputs}),
    )
    .await
    .expect_err("65 unshield inputs must be refused");
    assert_eq!(err.code(), -32602);
}
