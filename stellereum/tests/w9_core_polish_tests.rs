//! Wave 9 core polish regressions:
//! 1. `feature_gates::table()` metadata sync for `wasm-table-elements-cap`,
//!    `contract-block-hash`, and `bridge-target-address-cap`.
//! 2. `explorer::router` public faucet HTML copy matches `PUBLIC_DRIP_NANO`
//!    (`2 STELL`, not stale `5 STELL`).
//! 3. `XPC-PREPARED-UNBOUNDED` gate-protected bounds on `XpcPhase::Prepared`
//!    (per-`(source_shard, from, source_nonce)` uniqueness, sender cap, and
//!    TTL retirement) while leaving pre-activation behavior unchanged.

use std::net::SocketAddr;
use std::sync::Arc;

use stellereum::chain_spec::{
    current_activation_schedule, set_xshard_bounce_escrow_override,
    xshard_bounce_escrow_required_active_at, XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT,
};
use stellereum::explorer::{self, GatewayState, ReadinessConfig};
use stellereum::feature_gates;
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::rpc::{ReceiptIndex, RpcState, PUBLIC_DRIP_NANO};
use stellereum::sharding::{
    Block, CrossShardMessage, FinalizedHeaderRegistry, ShardRegistry, Transaction,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::turnstile::CaptchaGate;
use stellereum::xshard2pc::{
    is_retired, target_prepare_slot_available, XpcPhase, XpcRecord, MAX_ACTIVE_PREPARED_PER_SENDER,
    XPC_PREPARE, XPC_PREPARE_TTL_HEIGHTS,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct XshardBounceGateGuard;

impl Drop for XshardBounceGateGuard {
    fn drop(&mut self) {
        set_xshard_bounce_escrow_override(None);
    }
}

fn sign_explicit_pq_tx(
    kp: &FalconKeypair,
    recipient: [u8; 32],
    amount: u64,
    nonce: u64,
) -> Transaction {
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        recipient,
        amount,
        280_000,
        nonce,
        0,
        1,
        vec![],
        &DEFAULT_SALT,
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
        recipient,
        amount,
        280_000,
        nonce,
        0,
        1,
        vec![],
        &DEFAULT_SALT,
    )
}

fn empty_target_block(height: u64, cross_shard_out: Vec<CrossShardMessage>) -> Block {
    Block {
        shard_id: 1,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out,
        timestamp: 1_780_000_000 + height,
        proposer: [0x11; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        round: 0,
    }
}

#[test]
fn feature_gates_table_metadata_is_synced_for_verified_gates() {
    let table = feature_gates::table();

    let wasm_cap = table
        .iter()
        .find(|g| g.id == "wasm-table-elements-cap")
        .expect("wasm-table-elements-cap gate must exist");
    assert_eq!(wasm_cap.test, Some("tests/w7_svm_and_contracts_fixes.rs"));

    let block_hash = table
        .iter()
        .find(|g| g.id == "contract-block-hash")
        .expect("contract-block-hash gate must exist");
    assert_eq!(
        block_hash.test,
        Some("tests/w3_activation_boundary_e2e_tests.rs")
    );

    let bridge_cap = table
        .iter()
        .find(|g| g.id == "bridge-target-address-cap")
        .expect("bridge-target-address-cap gate must exist");
    assert_eq!(
        bridge_cap.test,
        Some("tests/w3_activation_boundary_e2e_tests.rs")
    );
    assert!(
        !bridge_cap
            .note
            .contains("missing from current_activation_schedule"),
        "stale schedule claim must be removed from bridge-target-address-cap note: {}",
        bridge_cap.note
    );
    assert!(
        !bridge_cap.note.contains("add the gate to that schedule"),
        "stale schedule action item must be removed from bridge-target-address-cap note: {}",
        bridge_cap.note
    );

    let schedule = current_activation_schedule();
    assert!(
        schedule
            .gates
            .iter()
            .any(|g| g.name == "BRIDGE_TARGET_ADDRESS_CAP_HEIGHT"),
        "BRIDGE_TARGET_ADDRESS_CAP_HEIGHT must be present in current_activation_schedule()"
    );
}

#[tokio::test]
async fn explorer_index_renders_public_drip_amount_matching_public_drip_nano() {
    let rpc = Arc::new(RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        node_id: "w9:explorer-copy-test".to_string(),
        chain_id: 5757,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: ShardRegistry::single(),
    });
    let gw = Arc::new(GatewayState::with_captcha(
        rpc,
        100,
        ReadinessConfig::default(),
        Arc::new(CaptchaGate::disabled()),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            explorer::router(gw).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf);
    let (_head, body) = response.split_once("\r\n\r\n").unwrap_or(("", &response));

    let expected_stell = PUBLIC_DRIP_NANO / 1_000_000_000;
    assert_eq!(expected_stell, 2, "PUBLIC_DRIP_NANO default is 2 STELL");
    let expected_label = format!("{expected_stell} STELL");
    assert!(
        body.contains(&format!("{expected_label} per address every")),
        "explorer index must render '{expected_label} per address every ...', got: {body}"
    );
    assert!(
        body.contains(&format!("Request {expected_label}")),
        "explorer index button must render 'Request {expected_label}', got: {body}"
    );
    assert!(
        !body.contains("5 STELL"),
        "stale '5 STELL' copy must not appear in explorer index: {body}"
    );
}

#[tokio::test]
async fn xpc_prepared_unbounded_guard_blocks_same_nonce_spam_when_gated_and_preserves_pre_activation(
) {
    let _guard = XshardBounceGateGuard;
    assert_eq!(XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT, u64::MAX);

    let kp = FalconKeypair::generate_from_seed(91);
    let sender_addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    let initial_bal = 5_000_000_000u64;

    let source = InMemoryStateEngine::new();
    source
        .update_account(AccountState::new(sender_addr, initial_bal))
        .await;
    source
        .pin_pubkey(
            sender_addr,
            PqScheme::Falcon512,
            &kp.public_key,
            &DEFAULT_SALT,
        )
        .await
        .expect("pin sender pq key");
    let source_root = source.get_state_root().await;
    let proof = source.get_account_proof(&sender_addr).await;
    let pk_hash = source
        .get_account(&sender_addr)
        .await
        .and_then(|a| a.pubkey_hash)
        .expect("pinned pq pubkey hash");
    let anchor_block = [0xAAu8; 32];

    let reg = Arc::new(std::sync::RwLock::new(FinalizedHeaderRegistry::default()));
    reg.write()
        .unwrap()
        .note_finalized(0, anchor_block, source_root);

    // Two distinct transactions from the SAME sender at the SAME nonce = 0.
    let tx_a = sign_explicit_pq_tx(&kp, [0x71u8; 32], 1_000_000, 0);
    let tx_b = sign_explicit_pq_tx(&kp, [0x72u8; 32], 1_000_000, 0);
    let hash_a = tx_a.compute_tx_hash();
    let hash_b = tx_b.compute_tx_hash();
    assert_ne!(hash_a, hash_b, "distinct recipients yield distinct hashes");

    let prep_a = CrossShardMessage::new_xpc(
        XPC_PREPARE,
        0,
        1,
        tx_a,
        source_root,
        anchor_block,
        proof.clone(),
    )
    .with_source_balance(initial_bal)
    .with_sender_pubkey_hash(PqScheme::Falcon512.id(), pk_hash);
    let prep_b =
        CrossShardMessage::new_xpc(XPC_PREPARE, 0, 1, tx_b, source_root, anchor_block, proof)
            .with_source_balance(initial_bal)
            .with_sender_pubkey_hash(PqScheme::Falcon512.id(), pk_hash);

    // 1. Pre-activation (gate inert): both same-nonce Prepares are admitted and never TTL-retire.
    set_xshard_bounce_escrow_override(None);
    assert!(!xshard_bounce_escrow_required_active_at(10));
    let target_pre = InMemoryStateEngine::new();
    target_pre.enable_cross_shard();
    target_pre.with_finalized_headers(reg.clone());
    target_pre
        .apply_cross_shard_consumptions(&empty_target_block(10, vec![prep_a.clone()]))
        .await;
    target_pre
        .apply_cross_shard_consumptions(&empty_target_block(11, vec![prep_b.clone()]))
        .await;
    assert_eq!(
        target_pre.xpc_len().await,
        2,
        "pre-activation must preserve existing unbounded behavior"
    );
    target_pre
        .apply_cross_shard_consumptions(&empty_target_block(10 + XPC_PREPARE_TTL_HEIGHTS, vec![]))
        .await;
    assert_eq!(
        target_pre.xpc_len().await,
        2,
        "pre-activation Prepared records must not TTL-retire"
    );

    // 2. Post-activation (gate armed at H = 10): second distinct tx_hash at same nonce is refused,
    //    and expired Prepared records retire at prepared_height + XPC_PREPARE_TTL_HEIGHTS.
    const H: u64 = 10;
    set_xshard_bounce_escrow_override(Some(H));
    assert!(xshard_bounce_escrow_required_active_at(H));

    let target_post = InMemoryStateEngine::new();
    target_post.enable_cross_shard();
    target_post.with_finalized_headers(reg);

    target_post
        .apply_cross_shard_consumptions(&empty_target_block(H, vec![prep_a.clone()]))
        .await;
    assert_eq!(
        target_post.xpc_record(&hash_a).await.map(|r| r.phase),
        Some(XpcPhase::Prepared)
    );

    // Cross-block same-nonce spam attempt: must be refused.
    target_post
        .apply_cross_shard_consumptions(&empty_target_block(H + 1, vec![prep_b.clone()]))
        .await;
    assert!(
        target_post.xpc_record(&hash_b).await.is_none(),
        "second distinct tx_hash at same (source_shard, from, nonce) must be rejected"
    );
    assert_eq!(target_post.xpc_len().await, 1);

    // Just before TTL: Prepared record is retained.
    target_post
        .apply_cross_shard_consumptions(&empty_target_block(
            H + XPC_PREPARE_TTL_HEIGHTS - 1,
            vec![],
        ))
        .await;
    assert_eq!(target_post.xpc_len().await, 1);

    // At TTL: unresolved Prepared record retires deterministically.
    target_post
        .apply_cross_shard_consumptions(&empty_target_block(H + XPC_PREPARE_TTL_HEIGHTS, vec![]))
        .await;
    assert_eq!(
        target_post.xpc_len().await,
        0,
        "expired Prepared record must retire at prepared_height + XPC_PREPARE_TTL_HEIGHTS"
    );

    // Check pure helper invariants (sender cap + is_retired).
    let mut active = Vec::new();
    for nonce in 0..MAX_ACTIVE_PREPARED_PER_SENDER as u64 {
        let tx = sign_explicit_pq_tx(&kp, [0x80u8; 32], 1_000_000, nonce);
        active.push(XpcRecord::prepared(tx, 0, 1, H));
    }
    let extra_tx = sign_explicit_pq_tx(
        &kp,
        [0x80u8; 32],
        1_000_000,
        MAX_ACTIVE_PREPARED_PER_SENDER as u64,
    );
    assert!(!target_prepare_slot_available(
        active.iter(),
        0,
        &sender_addr,
        MAX_ACTIVE_PREPARED_PER_SENDER as u64,
        &extra_tx.compute_tx_hash()
    ));
    assert!(!is_retired(&active[0], H + XPC_PREPARE_TTL_HEIGHTS - 1));
    assert!(is_retired(&active[0], H + XPC_PREPARE_TTL_HEIGHTS));
}
