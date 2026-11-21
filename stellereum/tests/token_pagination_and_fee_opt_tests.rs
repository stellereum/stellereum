//! Tests for deterministic `TokenRegistry` / `stell_listTokens` cursor pagination
//! and the `stell_estimateFee` plain-transfer fast path (differential equivalence
//! against `clone_for_simulation`).

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use stellereum::commitment::tokens_preimage;
use stellereum::evm_adapter::CHAIN_ID;
use stellereum::mempool::{Mempool, PQ_ACTIVATION_SURCHARGE_GAS};
use stellereum::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::rpc::{handle_rpc_batch_call, ReceiptIndex, RpcState, ESTIMATE_FEE_GAS_CEILING};
use stellereum::sharding::{ShardRegistry, Transaction};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::DomainSnapshot;
use stellereum::svm::{OpCode, VmExecutionResult, GAS_BASIC_TRANSFER};
use stellereum::token::{TokenActor, TokenMetadata, TokenRegistry, ZERO_ADDRESS};

fn test_rpc_state(engine: Arc<InMemoryStateEngine>) -> Arc<RpcState> {
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(100)),
        node_id: "inf1:test_pagination_fee".to_string(),
        chain_id: CHAIN_ID,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

async fn rpc_call_as(st: &RpcState, ip: IpAddr, method: &str, params: Value) -> Value {
    let item = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let res = handle_rpc_batch_call(st, &[item], 256, None, Some(ip))
        .await
        .expect("single-item batch must succeed");
    let first = res.into_iter().next().expect("single response");
    if let Some(e) = first.error {
        json!({ "error": { "code": e.code, "message": e.message } })
    } else {
        first.result.unwrap_or(Value::Null)
    }
}

fn fresh_ip() -> IpAddr {
    static NEXT_OCTET: AtomicU8 = AtomicU8::new(10);
    let n = NEXT_OCTET.fetch_add(1, Ordering::Relaxed);
    IpAddr::V4(Ipv4Addr::new(10, 240, 0, n))
}

fn mk_token_actor(id_byte: u8, sym: &str) -> ([u8; 32], TokenActor) {
    let id = [id_byte; 32];
    let meta = TokenMetadata {
        name: format!("Token-{sym}"),
        symbol: sym.to_string(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: [0x11; 32],
        paused: false,
        description: String::new(),
    };
    let actor = TokenActor::new(id, meta, 1_000_000).expect("valid token actor");
    (id, actor)
}

#[tokio::test]
async fn token_registry_and_list_tokens_are_deterministic_across_insertion_orders() {
    let order_a: Vec<u8> = vec![0x50, 0x10, 0x90, 0x30, 0x70, 0x20, 0x80, 0x40, 0x60];
    let order_b: Vec<u8> = vec![0x60, 0x90, 0x20, 0x80, 0x10, 0x40, 0x70, 0x30, 0x50];

    let engine_a = Arc::new(InMemoryStateEngine::new());
    let engine_b = Arc::new(InMemoryStateEngine::new());

    {
        let mut reg_a = engine_a.tokens_write().await;
        for (i, b) in order_a.iter().enumerate() {
            let (id, actor) = mk_token_actor(*b, &format!("TA{i}"));
            reg_a.tokens.insert(id, actor);
        }
    }
    {
        let mut reg_b = engine_b.tokens_write().await;
        for (i, b) in order_b.iter().enumerate() {
            let (id, actor) = mk_token_actor(*b, &format!("TB{i}"));
            reg_b.tokens.insert(id, actor);
        }
    }

    let ids_a = engine_a.tokens_read().await.all_token_ids();
    let ids_b = engine_b.tokens_read().await.all_token_ids();
    assert_eq!(ids_a, ids_b);
    assert!(
        ids_a.windows(2).all(|w| w[0] < w[1]),
        "BTreeMap key order must be strictly ascending"
    );

    let st_a = test_rpc_state(engine_a);
    let st_b = test_rpc_state(engine_b);
    let ip = fresh_ip();

    // Offset pagination must match identically across both nodes.
    for offset in [0u64, 3, 6] {
        let ra = rpc_call_as(
            &st_a,
            ip,
            "stell_listTokens",
            json!({ "limit": 3, "offset": offset }),
        )
        .await;
        let rb = rpc_call_as(
            &st_b,
            ip,
            "stell_listTokens",
            json!({ "limit": 3, "offset": offset }),
        )
        .await;
        assert_eq!(ra, rb);
        assert_eq!(ra["total"], json!(9));
        assert_eq!(ra["offset"], json!(offset));
    }

    // Cursor pagination must yield identical sorted pages across both nodes.
    let mut cursor: Option<String> = None;
    let mut collected = Vec::new();
    loop {
        let params = match &cursor {
            Some(c) => json!({ "limit": 4, "cursor": c }),
            None => json!({ "limit": 4 }),
        };
        let ra = rpc_call_as(&st_a, ip, "stell_listTokens", params.clone()).await;
        let rb = rpc_call_as(&st_b, ip, "stell_listTokens", params).await;
        assert_eq!(ra["tokens"], rb["tokens"]);
        assert_eq!(ra["has_more"], rb["has_more"]);
        assert_eq!(ra["next_cursor"], rb["next_cursor"]);

        let page: Vec<String> = serde_json::from_value(ra["tokens"].clone()).unwrap();
        collected.extend(page);
        if ra["has_more"] == json!(true) {
            cursor = ra["next_cursor"].as_str().map(str::to_string);
            assert!(cursor.is_some());
        } else {
            assert!(ra["next_cursor"].is_null());
            break;
        }
    }

    let expected: Vec<String> = ids_a.iter().map(hex::encode).collect();
    assert_eq!(collected, expected);
}

#[tokio::test]
async fn list_tokens_cursor_pagination_survives_mid_scan_insertions_without_skips_or_dups() {
    let engine = Arc::new(InMemoryStateEngine::new());
    {
        let mut reg = engine.tokens_write().await;
        for (i, b) in [0x10u8, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70]
            .into_iter()
            .enumerate()
        {
            let (id, actor) = mk_token_actor(b, &format!("T{i}"));
            reg.tokens.insert(id, actor);
        }
    }
    let st = test_rpc_state(engine.clone());
    let ip = fresh_ip();

    // Page 1: [0x10, 0x20, 0x30]
    let p1 = rpc_call_as(&st, ip, "stell_listTokens", json!({ "limit": 3 })).await;
    assert_eq!(
        p1["tokens"],
        json!([
            hex::encode([0x10u8; 32]),
            hex::encode([0x20u8; 32]),
            hex::encode([0x30u8; 32]),
        ])
    );
    assert_eq!(p1["has_more"], json!(true));
    let c1 = p1["next_cursor"].as_str().unwrap().to_string();
    assert_eq!(c1, hex::encode([0x30u8; 32]));

    // Insert both a smaller ID (0x05) and a larger ID (0x80) between pages.
    {
        let mut reg = engine.tokens_write().await;
        let (small_id, small_actor) = mk_token_actor(0x05, "SMALL");
        let (large_id, large_actor) = mk_token_actor(0x80, "LARGE");
        reg.tokens.insert(small_id, small_actor);
        reg.tokens.insert(large_id, large_actor);
    }

    // Page 2 with cursor=c1: must start strictly after 0x30 -> [0x40, 0x50, 0x60].
    let p2 = rpc_call_as(
        &st,
        ip,
        "stell_listTokens",
        json!({ "limit": 3, "cursor": format!("0x{c1}") }),
    )
    .await;
    assert_eq!(
        p2["tokens"],
        json!([
            hex::encode([0x40u8; 32]),
            hex::encode([0x50u8; 32]),
            hex::encode([0x60u8; 32]),
        ])
    );
    assert_eq!(p2["has_more"], json!(true));
    assert_eq!(p2["total"], json!(9));
    let c2 = p2["next_cursor"].as_str().unwrap().to_string();

    // Page 3 via `last_token_id` alias: gets [0x70, 0x80] (includes the new larger ID).
    let p3 = rpc_call_as(
        &st,
        ip,
        "stell_listTokens",
        json!({ "limit": 3, "last_token_id": c2 }),
    )
    .await;
    assert_eq!(
        p3["tokens"],
        json!([hex::encode([0x70u8; 32]), hex::encode([0x80u8; 32])])
    );
    assert_eq!(p3["has_more"], json!(false));
    assert!(p3["next_cursor"].is_null());

    // Invalid cursor must return -32602.
    let bad = rpc_call_as(&st, ip, "stell_listTokens", json!({ "cursor": "not-hex" })).await;
    assert_eq!(bad["error"]["code"], json!(-32602));
}

#[test]
fn token_registry_bincode_roundtrip_and_legacy_hashmap_snapshot_compat() {
    #[derive(Serialize)]
    struct LegacyTokenRegistry {
        tokens: HashMap<[u8; 32], TokenActor>,
        next_nonce: u64,
    }

    #[derive(Serialize)]
    struct LegacyDomainSnapshotPrefix {
        tokens: LegacyTokenRegistry,
    }

    // 1. Round-trip of the new BTreeMap-backed TokenRegistry.
    let mut reg = TokenRegistry::new();
    let creator = [0xAA; 32];
    let id1 = reg
        .create_token(
            creator,
            TokenMetadata {
                name: "Alpha".into(),
                symbol: "ALP".into(),
                decimals: 6,
                total_supply: 0,
                max_supply: Some(10_000_000),
                minter: ZERO_ADDRESS,
                paused: false,
                description: "first".into(),
            },
            500_000,
        )
        .unwrap();
    let id2 = reg
        .create_token(
            creator,
            TokenMetadata {
                name: "Beta".into(),
                symbol: "BET".into(),
                decimals: 9,
                total_supply: 0,
                max_supply: None,
                minter: ZERO_ADDRESS,
                paused: false,
                description: "second".into(),
            },
            250_000,
        )
        .unwrap();

    let encoded = bincode::serialize(&reg).unwrap();
    let decoded: TokenRegistry = bincode::deserialize(&encoded).unwrap();
    assert_eq!(decoded.next_nonce, reg.next_nonce);
    assert_eq!(decoded.all_token_ids(), reg.all_token_ids());
    assert_eq!(decoded.balance_of(&id1, &creator), 500_000);
    assert_eq!(decoded.balance_of(&id2, &creator), 250_000);
    assert_eq!(tokens_preimage(&decoded), tokens_preimage(&reg));

    // 2. Legacy HashMap-serialized bytes (arbitrary HashMap key order) must
    //    decode cleanly into the BTreeMap-backed TokenRegistry & DomainSnapshot
    //    with identical preimage / state commitment.
    let mut legacy_map = HashMap::new();
    for (id, actor) in &reg.tokens {
        legacy_map.insert(*id, actor.clone());
    }
    let legacy = LegacyTokenRegistry {
        tokens: legacy_map,
        next_nonce: reg.next_nonce,
    };
    let legacy_bytes = bincode::serialize(&legacy).unwrap();
    let upgraded: TokenRegistry = bincode::deserialize(&legacy_bytes).unwrap();
    assert_eq!(upgraded.next_nonce, reg.next_nonce);
    assert_eq!(upgraded.all_token_ids(), reg.all_token_ids());
    assert_eq!(tokens_preimage(&upgraded), tokens_preimage(&reg));

    // Verify DomainSnapshot prefix compatibility too.
    let snap = DomainSnapshot {
        tokens: reg.clone(),
        ..Default::default()
    };
    let snap_bytes = bincode::serialize(&snap).unwrap();
    let legacy_prefix = bincode::serialize(&LegacyDomainSnapshotPrefix { tokens: legacy }).unwrap();
    let snap_decoded: DomainSnapshot = bincode::deserialize(&snap_bytes).unwrap();
    assert_eq!(tokens_preimage(&snap_decoded.tokens), tokens_preimage(&reg));
    // The TokenRegistry prefix inside DomainSnapshot encodes identically:
    // len(u64) + entries + next_nonce(u64) -> same byte length as BTreeMap.
    assert_eq!(legacy_prefix.len(), bincode::serialize(&reg).unwrap().len());
}

/// Exact reference implementation of `simulate_and_estimate_fee` using
/// `clone_for_simulation()` (the unoptimized baseline).
async fn reference_estimate_fee_via_clone(
    st: &RpcState,
    mut sim_tx: Transaction,
    gas_budget: u64,
) -> Value {
    let is_cross_shard = sim_tx.source_shard != sim_tx.target_shard;
    let sim_engine = st.engine.clone_for_simulation().await;

    let (floor_base, surcharge) = sim_engine.consensus_floor_parts(&sim_tx).await;
    let pool_floor = st.mempool.read().await.base_fee;
    let base_fee = pool_floor.max(floor_base).max(GAS_BASIC_TRANSFER);

    {
        let mut map = sim_engine.accounts.write().await;
        let entry = map
            .entry(sim_tx.from)
            .or_insert_with(|| AccountState::new(sim_tx.from, 0));
        if entry.balance < 100_000_000_000 {
            entry.balance = 100_000_000_000;
        }
    }
    for op in &sim_tx.payload {
        if let OpCode::SysCallTokenTransfer {
            token_id, amount, ..
        } = op
        {
            let mut tokens = sim_engine.tokens_write().await;
            if let Some(tok) = tokens.tokens.get_mut(token_id) {
                let cur = tok.balance_of(&sim_tx.from);
                if cur < *amount {
                    tok.balances
                        .insert(sim_tx.from, cur.saturating_add(*amount));
                }
            }
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let gas_consumed = if sim_tx.payload.is_empty() {
        GAS_BASIC_TRANSFER
    } else {
        sim_tx.gas_limit = gas_budget;
        match sim_engine.execute_payload(&sim_tx, now).await {
            Ok((VmExecutionResult::Success { gas_used, .. }, _)) => gas_used,
            Ok((VmExecutionResult::OutOfGas, _)) => {
                return json!({ "error": { "code": -32000, "message": "simulation out of gas" } });
            }
            Ok((VmExecutionResult::Reverted(reason), _)) => {
                return json!({ "error": { "code": -32000, "message": format!("simulation reverted: {reason}") } });
            }
            Err(e) => {
                return json!({ "error": { "code": -32000, "message": format!("simulation failed: {e}") } });
            }
        }
    };

    let effective_gas = gas_consumed.max(base_fee);
    let estimated_fee = effective_gas.saturating_add(surcharge);
    let gas_limit = estimated_fee;

    json!({
        "gas_limit": gas_limit,
        "estimated_fee": estimated_fee,
        "base_fee": base_fee,
        "source_shard": sim_tx.source_shard,
        "target_shard": sim_tx.target_shard,
        "is_cross_shard": is_cross_shard,
        "gas_budget": gas_budget,
        "gas_ceiling": ESTIMATE_FEE_GAS_CEILING,
        "status": "ok"
    })
}

#[allow(clippy::too_many_arguments)]
// GATE: test helper mirrors Transaction::new_pq_implicit fields.
fn sign_pq_implicit_tx(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    payload: Vec<OpCode>,
) -> Transaction {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("implicit PQ test key must register");
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    tx
}

fn sign_pq_activation_tx(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    source_shard: u32,
    target_shard: u32,
) -> Transaction {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit: GAS_BASIC_TRANSFER,
        nonce: 0,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, sig).encode();
    assert!(tx.is_pq_activation());
    tx
}

#[tokio::test]
async fn estimate_fee_fast_path_is_differential_equivalent_to_clone_for_simulation() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let recipient = [0xBB; 32];

    // Seed an unfunded / low-balance sender and a funded penalized sender.
    let low_bal_seed = 0xD1u8;
    let low_bal_pk = Transaction::sample_falcon512_pubkey(low_bal_seed);
    let low_bal_addr = derive_pq_address(PqScheme::Falcon512, &low_bal_pk, &DEFAULT_SALT);
    engine
        .update_account(AccountState::new(low_bal_addr, 5))
        .await;

    let d2_seed = 0xD2u8;
    let d2_pk = Transaction::sample_falcon512_pubkey(d2_seed);
    let d2_addr = derive_pq_address(PqScheme::Falcon512, &d2_pk, &DEFAULT_SALT);
    engine
        .update_account(AccountState::new(d2_addr, 10_000_000))
        .await;

    // Trigger a genuine D2 consensus penalty on `d2_addr` by failing an OOM tx.
    let oom_tx = sign_pq_implicit_tx(
        d2_seed,
        recipient,
        0,
        0,
        0,
        0,
        0,
        vec![OpCode::Transfer {
            recipient,
            amount: 1,
        }],
    );
    let (_, _, _, statuses, _) = engine
        .apply_block_parallel_fees(&[oom_tx], 1_760_000_000)
        .await;
    assert_eq!(statuses, vec![false]);

    let st = test_rpc_state(engine.clone());

    // Helper comparing `stell_estimateFee` against `reference_estimate_fee_via_clone`.
    async fn assert_equiv(st: &RpcState, tx: &Transaction, label: &str) {
        let tx_hex = hex::encode(bincode::serialize(tx).unwrap());
        let actual =
            rpc_call_as(st, fresh_ip(), "stell_estimateFee", json!({ "tx": tx_hex })).await;
        let expected =
            reference_estimate_fee_via_clone(st, tx.clone(), ESTIMATE_FEE_GAS_CEILING).await;
        assert_eq!(actual, expected, "mismatch on {label}");
    }

    // 1. Normal intra-shard plain transfer (implicit PQ, unfunded/missing sender).
    let missing_sender = [0x44; 32];
    let plain_intra = Transaction {
        from: missing_sender,
        to: recipient,
        amount: 1_000,
        gas_limit: 10_000_000,
        nonce: 0,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    assert_equiv(&st, &plain_intra, "plain intra-shard missing sender").await;
    assert!(
        engine.get_account(&missing_sender).await.is_none(),
        "fast path must not mutate live engine accounts"
    );

    // Also check JSON-object request form (from/to/amount/source_shard/target_shard).
    let json_actual = rpc_call_as(
        &st,
        fresh_ip(),
        "stell_estimateFee",
        json!({
            "from": hex::encode(missing_sender),
            "to": hex::encode(recipient),
            "amount": 1_000,
            "source_shard": 0,
            "target_shard": 0,
        }),
    )
    .await;
    let json_expected =
        reference_estimate_fee_via_clone(&st, plain_intra.clone(), ESTIMATE_FEE_GAS_CEILING).await;
    assert_eq!(json_actual, json_expected);

    // 2. Cross-shard plain transfer.
    let plain_cross = Transaction {
        source_shard: 0,
        target_shard: 1,
        ..plain_intra.clone()
    };
    assert_equiv(&st, &plain_cross, "plain cross-shard").await;
    assert_eq!(json_expected["is_cross_shard"], json!(false));

    // 3. PQ-activation plain transfer (+45_000 surcharge).
    let pq_act = sign_pq_activation_tx(0xD3, recipient, 1_000, 0, 0);
    assert_equiv(&st, &pq_act, "pq activation plain transfer").await;
    let pq_res = reference_estimate_fee_via_clone(&st, pq_act, ESTIMATE_FEE_GAS_CEILING).await;
    assert_eq!(
        pq_res["estimated_fee"],
        json!(GAS_BASIC_TRANSFER + PQ_ACTIVATION_SURCHARGE_GAS)
    );

    // 4. Insufficient balance sender (balance=5, transfer amount=1_000_000).
    let low_bal_tx = sign_pq_implicit_tx(
        low_bal_seed,
        recipient,
        1_000_000,
        GAS_BASIC_TRANSFER,
        0,
        0,
        0,
        Vec::new(),
    );
    assert_equiv(&st, &low_bal_tx, "insufficient balance plain transfer").await;
    assert_eq!(
        engine.get_account(&low_bal_addr).await.unwrap().balance,
        5,
        "live balance must remain untouched"
    );

    // 5. D2 consensus penalty on `d2_addr`.
    let d2_plain = sign_pq_implicit_tx(
        d2_seed,
        recipient,
        100,
        GAS_BASIC_TRANSFER,
        0,
        0,
        0,
        Vec::new(),
    );
    let (d2_floor, _) = engine.consensus_floor_parts(&d2_plain).await;
    assert!(
        d2_floor > 0,
        "expected non-zero D2 penalty floor after attributable failure"
    );
    assert_equiv(&st, &d2_plain, "D2-penalized plain transfer").await;

    // 6. Governed `min_gas_limit` + D2 penalty + PQ activation + cross-shard combined.
    engine.governance_write().await.applied.min_gas_limit = Some(600_000);
    let d2_activation = sign_pq_activation_tx(d2_seed, recipient, 100, 0, 1);
    assert_equiv(
        &st,
        &d2_activation,
        "min_gas_limit + D2 + PQ activation + cross-shard",
    )
    .await;
    let combined =
        reference_estimate_fee_via_clone(&st, d2_activation, ESTIMATE_FEE_GAS_CEILING).await;
    assert_eq!(
        combined["estimated_fee"],
        json!(600_000 + d2_floor + PQ_ACTIVATION_SURCHARGE_GAS)
    );
    assert_eq!(combined["is_cross_shard"], json!(true));

    // 7. Mempool `base_fee` higher than governed floor.
    st.mempool.write().await.base_fee = 950_000;
    assert_equiv(&st, &plain_intra, "mempool base_fee dominates").await;

    // 8. Non-empty payload fallback still matches reference.
    let payload_tx = sign_pq_implicit_tx(
        d2_seed,
        recipient,
        0,
        GAS_BASIC_TRANSFER,
        0,
        0,
        0,
        vec![OpCode::Transfer {
            recipient,
            amount: 50,
        }],
    );
    assert_equiv(&st, &payload_tx, "non-empty payload fallback").await;
}
