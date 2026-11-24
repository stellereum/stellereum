//! Wave 3 activation boundary (`H - 1 -> H`) E2E tests for the three older
//! INERT (`u64::MAX`) protocol gates documented in `docs/ACTIVATION_GATES.md`:
//!
//! 1. `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT` (`host.block_hash`):
//!    `apply_block_transition` across two independent engines + replay at `H - 1`
//!    under the armed height.
//! 2. `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` (`Withdraw.target_address` 128-byte cap):
//!    `apply_block_transition` across `H - 1 -> H`, UTF-8 byte-vs-char boundary,
//!    refusal before rate-window/balance mutation, `H - 1` replay under armed
//!    height, and post-`H` refund of pre-`H` parked long-target items.
//! 3. `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` (`ChainState::apply_block` cluster
//!    replay mirror parity with `ValidatorRuntime::record_apply_outcome`):
//!    below-gate legacy parity, `H - 1 -> H` boundary cleanse, refusal of
//!    escrowless and 2PC-owned bounces without poisoning replay sets, and exact
//!    mirror/live state-root parity.
//!
//! Every test drives its gate via the thread-local test override with a `Drop`
//! reset guard and runs single-threaded (`#[tokio::test]`) so parallel test
//! execution never leaks overrides across tests.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::bridge::{
    BridgeIntent, SupportedChain, BRIDGE_ESCROW, MAX_BRIDGE_TARGET_ADDRESS_BYTES, REFUND_GRACE_SECS,
};
use stellereum::chain_spec::{
    bridge_target_address_cap_active_at, contract_block_hash_active_at,
    set_bridge_target_address_cap_override, set_contract_block_hash_activation_override,
    set_xshard_bounce_escrow_override, xshard_bounce_escrow_required_active_at,
};
use stellereum::consensus::register_validator_pq_key;
use stellereum::mev::compute_order_merkle_root;
use stellereum::network::CrossShardTransport;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT,
};
use stellereum::runtime::{ChainState, ShardedCluster};
use stellereum::sharding::{
    Block, CrossShardKey, CrossShardMessage, ShardRegistry, Transaction,
    BASE_WORKCHAIN_SHARD_INITIAL, CROSS_SHARD_TIMEOUT_HEIGHTS, MASTERCHAIN_SHARD,
};
use stellereum::staking::{MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, VmExecutionResult, GAS_BASIC_TRANSFER};
use stellereum::xshard2pc::{XpcActivation, XpcRecord, XPC_PREPARE};

const TS: u64 = 1_780_000_000;
const STELL: u64 = 1_000_000_000;
const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;

// ---------------------------------------------------------------------------
// Thread-local gate reset guards
// ---------------------------------------------------------------------------

struct ContractBlockHashGateGuard;
impl Drop for ContractBlockHashGateGuard {
    fn drop(&mut self) {
        set_contract_block_hash_activation_override(None);
    }
}

struct BridgeCapGateGuard;
impl Drop for BridgeCapGateGuard {
    fn drop(&mut self) {
        set_bridge_target_address_cap_override(None);
    }
}

struct XshardBounceGateGuard;
impl Drop for XshardBounceGateGuard {
    fn drop(&mut self) {
        set_xshard_bounce_escrow_override(None);
    }
}

// ---------------------------------------------------------------------------
// Shared PQ + block fixture helpers
// ---------------------------------------------------------------------------

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pq_id(seed: u8) -> [u8; 32] {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    from
}

fn sign_pq(seed: u8, mut tx: Transaction) -> Transaction {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    tx.signature = Vec::new();
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    tx
}

fn signed_payload_tx(
    seed: u8,
    nonce: u64,
    gas_limit: u64,
    shard: u32,
    payload: Vec<OpCode>,
) -> Transaction {
    let from = pq_id(seed);
    let tx = Transaction {
        from,
        to: [0u8; 32],
        amount: 0,
        gas_limit,
        nonce,
        source_shard: shard,
        target_shard: shard,
        signature: Vec::new(),
        payload,
        priority_fee_per_gas: 0,
    };
    sign_pq(seed, tx)
}

fn pq_xshard_tx(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
) -> Transaction {
    let from = pq_id(seed);
    let tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    sign_pq(seed, tx)
}

fn make_block(
    shard_id: u32,
    height: u64,
    prev_hash: [u8; 32],
    timestamp: u64,
    proposer: [u8; 32],
    transactions: Vec<Transaction>,
    cross_shard_out: Vec<CrossShardMessage>,
) -> Block {
    let order_merkle_root = compute_order_merkle_root(&transactions);
    Block {
        shard_id,
        height,
        prev_hash,
        state_root: [0u8; 32],
        transactions,
        cross_shard_out,
        timestamp,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        round: 0,
    }
}

async fn pin(engine: &InMemoryStateEngine, addr: &[u8; 32]) {
    if let Some((scheme, pk)) = Transaction::global_implicit_registry().lookup(addr) {
        engine
            .pin_pubkey(*addr, scheme, &pk, &DEFAULT_SALT)
            .await
            .expect("PQ sender must pin");
    }
}

async fn balance(engine: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    engine
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

// ===========================================================================
// E2E 1: CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT
// ===========================================================================

fn block_hash_store_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"(module
             (import "host" "block_hash" (func $block_hash (param i32)))
             (import "host" "sstore" (func $sstore (param i64 i64)))
             (memory (export "memory") 1)
             (func (export "record") (param $slot_base i64) (result i64)
               (call $block_hash (i32.const 0))
               (call $sstore (local.get $slot_base) (i64.load (i32.const 0)))
               (call $sstore (i64.add (local.get $slot_base) (i64.const 1)) (i64.load (i32.const 8)))
               (call $sstore (i64.add (local.get $slot_base) (i64.const 2)) (i64.load (i32.const 16)))
               (call $sstore (i64.add (local.get $slot_base) (i64.const 3)) (i64.load (i32.const 24)))
               (i64.const 1)))"#,
    )
    .expect("block_hash store contract compiles")
}

async fn read_stored_hash(
    engine: &InMemoryStateEngine,
    contract: &[u8; 32],
    slot_base: i64,
) -> [u8; 32] {
    let c = engine
        .get_contract(contract)
        .await
        .expect("contract must be deployed");
    let mut out = [0u8; 32];
    for word in 0..4 {
        let val = c
            .storage
            .get(&(slot_base + word as i64))
            .copied()
            .expect("storage slot must be populated");
        out[word * 8..(word + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }
    out
}

#[tokio::test]
async fn contract_block_hash_h_minus_1_to_h_across_two_engines_and_replay() {
    const H: u64 = 3;
    set_contract_block_hash_activation_override(Some(H));
    let _gate = ContractBlockHashGateGuard;
    assert!(!contract_block_hash_active_at(H - 1));
    assert!(contract_block_hash_active_at(H));

    let sender_seed = 0x11u8;
    let sender = pq_id(sender_seed);
    let proposer = [0x12u8; 32];
    let initial_bal = 100 * STELL;

    let setup_engine = || async {
        let e = Arc::new(InMemoryStateEngine::new());
        e.update_account(AccountState::new(sender, initial_bal))
            .await;
        pin(&e, &sender).await;
        e
    };

    let e1 = setup_engine().await;
    let e2 = setup_engine().await;
    let e_replay = setup_engine().await;
    let mut cs = ChainState::new(setup_engine().await);

    // Block 1: deploy the contract through `apply_block_transition` on both engines.
    let deploy = signed_payload_tx(
        sender_seed,
        0,
        5_000_000,
        SHARD0,
        vec![OpCode::SysCallDeployContract {
            code: block_hash_store_wasm(),
        }],
    );
    let b1 = make_block(SHARD0, 1, [0u8; 32], TS, proposer, vec![deploy], vec![]);
    let out1 = e1.apply_block_transition(&b1, 0).await;
    let out2 = e2.apply_block_transition(&b1, 0).await;
    cs.apply_block(&b1).await;
    assert_eq!(out1.status, vec![true]);
    assert_eq!(out2.status, vec![true]);
    assert_eq!(e1.get_state_root().await, e2.get_state_root().await);
    assert_eq!(e1.get_state_root().await, cs.state.get_state_root().await);

    let addrs1 = e1.all_contract_addresses().await;
    let addrs2 = e2.all_contract_addresses().await;
    assert_eq!(addrs1.len(), 1);
    assert_eq!(addrs1, addrs2);
    let contract = addrs1[0];

    // Block H - 1 (height 2): non-zero parent hash, yet contract must store [0u8; 32].
    let parent_h_minus_1 = b1.compute_hash();
    assert_ne!(parent_h_minus_1, [0u8; 32]);
    let call_pre = signed_payload_tx(
        sender_seed,
        1,
        5_000_000,
        SHARD0,
        vec![OpCode::SysCallCallContract {
            contract,
            method: b"record".to_vec(),
            arg: 0,
        }],
    );
    let b_h_minus_1 = make_block(
        SHARD0,
        H - 1,
        parent_h_minus_1,
        TS + 1,
        proposer,
        vec![call_pre],
        vec![],
    );
    let out1 = e1.apply_block_transition(&b_h_minus_1, 0).await;
    let out2 = e2.apply_block_transition(&b_h_minus_1, 0).await;
    cs.apply_block(&b_h_minus_1).await;
    assert_eq!(out1.status, vec![true]);
    assert_eq!(out2.status, vec![true]);
    assert_eq!(read_stored_hash(&e1, &contract, 0).await, [0u8; 32]);
    assert_eq!(read_stored_hash(&e2, &contract, 0).await, [0u8; 32]);
    let root_h_minus_1 = e1.get_state_root().await;
    assert_eq!(root_h_minus_1, e2.get_state_root().await);
    assert_eq!(root_h_minus_1, cs.state.get_state_root().await);

    // Block H (height 3): contract must store `b_h.prev_hash` (!= b_h.compute_hash()).
    let parent_h = b_h_minus_1.compute_hash();
    assert_ne!(parent_h, [0u8; 32]);
    let call_at_h = signed_payload_tx(
        sender_seed,
        2,
        5_000_000,
        SHARD0,
        vec![OpCode::SysCallCallContract {
            contract,
            method: b"record".to_vec(),
            arg: 10,
        }],
    );
    let b_h = make_block(
        SHARD0,
        H,
        parent_h,
        TS + 2,
        proposer,
        vec![call_at_h],
        vec![],
    );
    let current_block_hash = b_h.compute_hash();
    assert_ne!(
        b_h.prev_hash, current_block_hash,
        "parent hash must differ from current block hash"
    );

    let out1 = e1.apply_block_transition(&b_h, 0).await;
    let out2 = e2.apply_block_transition(&b_h, 0).await;
    cs.apply_block(&b_h).await;
    assert_eq!(out1.status, vec![true]);
    assert_eq!(out2.status, vec![true]);
    assert_eq!(read_stored_hash(&e1, &contract, 10).await, b_h.prev_hash);
    assert_eq!(read_stored_hash(&e2, &contract, 10).await, b_h.prev_hash);
    assert_ne!(
        read_stored_hash(&e1, &contract, 10).await,
        current_block_hash
    );
    let root_h = e1.get_state_root().await;
    assert_eq!(root_h, e2.get_state_root().await);
    assert_eq!(root_h, cs.state.get_state_root().await);

    // Replay H - 1 on the armed engine itself (height-indexed, never latched):
    // executing at height H - 1 after H still sees [0u8; 32].
    let replay_call = signed_payload_tx(
        sender_seed,
        3,
        5_000_000,
        SHARD0,
        vec![OpCode::SysCallCallContract {
            contract,
            method: b"record".to_vec(),
            arg: 20,
        }],
    );
    let (res, _) = e1
        .execute_payload_with_preverify_at_height_and_parent(
            &replay_call,
            0,
            H - 1,
            b_h_minus_1.prev_hash,
        )
        .await
        .expect("height-indexed H-1 replay on armed engine succeeds");
    assert!(matches!(res, VmExecutionResult::Success { .. }));
    assert_eq!(read_stored_hash(&e1, &contract, 20).await, [0u8; 32]);

    // And full replay from genesis under the armed gate on a fresh engine matches both roots.
    e_replay.apply_block_transition(&b1, 0).await;
    let out_replay_pre = e_replay.apply_block_transition(&b_h_minus_1, 0).await;
    assert_eq!(out_replay_pre.status, vec![true]);
    assert_eq!(read_stored_hash(&e_replay, &contract, 0).await, [0u8; 32]);
    assert_eq!(e_replay.get_state_root().await, root_h_minus_1);

    let out_replay_h = e_replay.apply_block_transition(&b_h, 0).await;
    assert_eq!(out_replay_h.status, vec![true]);
    assert_eq!(
        read_stored_hash(&e_replay, &contract, 10).await,
        b_h.prev_hash
    );
    assert_eq!(e_replay.get_state_root().await, root_h);
}

// ===========================================================================
// E2E 2: BRIDGE_TARGET_ADDRESS_CAP_HEIGHT
// ===========================================================================

fn falcon_for(sk: &SigningKey) -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&sk.to_bytes())
}

async fn setup_bridge_engine(
    payer: [u8; 32],
    payer_balance: u64,
) -> (InMemoryStateEngine, [u8; 32]) {
    let e = InMemoryStateEngine::new();
    let mut proposer = [0u8; 32];
    for i in 0..3u8 {
        let k = key(0xD0 + i);
        let pk = k.verifying_key().to_bytes();
        if i == 0 {
            proposer = pk;
        }
        e.credit_native(&pk, 10 * MIN_VALIDATOR_BOND)
            .await
            .expect("fund validator");
        let fk = falcon_for(&k);
        {
            let mut ledger = e.staking_write().await;
            ledger
                .bond(pk, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
                .expect("bond validator");
            ledger
                .validator_pq_keys
                .insert(pk, (PqScheme::Falcon512, fk.public_key.clone()));
        }
        e.pq_registry_write()
            .await
            .adopt_legacy_key_at(pk, PqScheme::Falcon512, fk.public_key.clone(), 0, true)
            .expect("seed pq_registry");
        register_validator_pq_key(pk, PqScheme::Falcon512, fk.public_key.clone());
    }
    e.credit_native(&payer, payer_balance)
        .await
        .expect("fund payer");
    pin(&e, &payer).await;
    (e, proposer)
}

fn bridge_intent_tx(seed: u8, nonce: u64, intent: BridgeIntent) -> Transaction {
    signed_payload_tx(
        seed,
        nonce,
        GAS_BASIC_TRANSFER,
        SHARD0,
        vec![OpCode::SysCallBridge(Box::new(intent))],
    )
}

fn withdraw_intent(target_address: String, amount: u64) -> BridgeIntent {
    BridgeIntent::Withdraw {
        chain: SupportedChain::Ton,
        target_address,
        amount,
    }
}

#[tokio::test]
async fn bridge_target_address_cap_h_minus_1_to_h_and_utf8_bytes() {
    const H: u64 = 5;
    set_bridge_target_address_cap_override(Some(H));
    let _gate = BridgeCapGateGuard;
    assert!(!bridge_target_address_cap_active_at(H - 1));
    assert!(bridge_target_address_cap_active_at(H));

    let payer_seed = 0x21u8;
    let payer = pq_id(payer_seed);
    let initial_bal = 1_000 * STELL;
    let w_amount = 10 * STELL;

    let (e1, proposer) = setup_bridge_engine(payer, initial_bal).await;
    let (e2, _) = setup_bridge_engine(payer, initial_bal).await;
    let (e_replay, _) = setup_bridge_engine(payer, initial_bal).await;

    let addr_129 = "a".repeat(MAX_BRIDGE_TARGET_ADDRESS_BYTES + 1);
    assert_eq!(addr_129.len(), 129);
    let addr_utf8_over = format!("{}a", "\u{00e9}".repeat(64));
    assert_eq!(addr_utf8_over.chars().count(), 65);
    assert!(addr_utf8_over.chars().count() <= MAX_BRIDGE_TARGET_ADDRESS_BYTES);
    assert_eq!(addr_utf8_over.len(), 129);

    let addr_128 = "b".repeat(MAX_BRIDGE_TARGET_ADDRESS_BYTES);
    assert_eq!(addr_128.len(), 128);
    let addr_utf8_128 = "\u{00e9}".repeat(64);
    assert_eq!(addr_utf8_128.chars().count(), 64);
    assert_eq!(addr_utf8_128.len(), 128);

    // 1. At H - 1: both 129-byte ASCII and 65-char/129-byte UTF-8 Withdraw succeed & park.
    let b_pre = make_block(
        SHARD0,
        H - 1,
        [0u8; 32],
        TS,
        proposer,
        vec![
            bridge_intent_tx(payer_seed, 0, withdraw_intent(addr_129.clone(), w_amount)),
            bridge_intent_tx(
                payer_seed,
                1,
                withdraw_intent(addr_utf8_over.clone(), w_amount),
            ),
        ],
        vec![],
    );
    let out1 = e1.apply_block_transition(&b_pre, 0).await;
    let out2 = e2.apply_block_transition(&b_pre, 0).await;
    assert_eq!(out1.status, vec![true, true]);
    assert_eq!(out2.status, vec![true, true]);
    let root_pre = e1.get_state_root().await;
    assert_eq!(root_pre, e2.get_state_root().await);
    {
        let br = e1.bridge_read().await;
        assert_eq!(br.pending_withdrawals.len(), 2);
        assert_eq!(br.pending_withdrawals[&0].target_address, addr_129);
        assert_eq!(br.pending_withdrawals[&1].target_address, addr_utf8_over);
        assert_eq!(br.hourly_withdrawn, 2 * w_amount);
        assert_eq!(br.escrow_balance, 2 * w_amount);
    }
    assert_eq!(balance(&e1, &BRIDGE_ESCROW).await, 2 * w_amount);

    // Replay of H - 1 under the armed height reproduces the exact acceptance & root.
    let out_replay = e_replay.apply_block_transition(&b_pre, 0).await;
    assert_eq!(out_replay.status, vec![true, true]);
    assert_eq!(e_replay.get_state_root().await, root_pre);

    // 2. At H: 129-byte ASCII and 65-char/129-byte UTF-8 Withdraw are refused BEFORE
    //    rate-window, pending queue, or escrow/principal balance mutation.
    let bridge_before_h = e1.bridge_read().await.clone();
    let escrow_bal_before_h = balance(&e1, &BRIDGE_ESCROW).await;
    let payer_bal_before_h = balance(&e1, &payer).await;

    let tx_refuse_129 = bridge_intent_tx(payer_seed, 2, withdraw_intent(addr_129, w_amount));
    let tx_refuse_utf8 = bridge_intent_tx(payer_seed, 3, withdraw_intent(addr_utf8_over, w_amount));
    let max_fee = tx_refuse_129.gas_limit + tx_refuse_utf8.gas_limit;
    let b_at_h = make_block(
        SHARD0,
        H,
        b_pre.compute_hash(),
        TS + 1,
        proposer,
        vec![tx_refuse_129, tx_refuse_utf8],
        vec![],
    );
    let out1 = e1.apply_block_transition(&b_at_h, 0).await;
    let out2 = e2.apply_block_transition(&b_at_h, 0).await;
    assert_eq!(out1.status, vec![false, false]);
    assert_eq!(out2.status, vec![false, false]);
    assert_eq!(e1.get_state_root().await, e2.get_state_root().await);
    assert_eq!(
        *e1.bridge_read().await,
        bridge_before_h,
        "refused Withdraw at H must not touch rate window, pending queue, or escrow_balance"
    );
    assert_eq!(balance(&e1, &BRIDGE_ESCROW).await, escrow_bal_before_h);
    assert!(
        payer_bal_before_h - balance(&e1, &payer).await <= max_fee,
        "refused Withdraw at H must not debit withdrawal principal"
    );

    // 3. At H + 1 (>= H): exact 128-byte ASCII and 64-char/128-byte UTF-8 are accepted.
    let b_accept = make_block(
        SHARD0,
        H + 1,
        b_at_h.compute_hash(),
        TS + 2,
        proposer,
        vec![
            bridge_intent_tx(payer_seed, 4, withdraw_intent(addr_128.clone(), w_amount)),
            bridge_intent_tx(
                payer_seed,
                5,
                withdraw_intent(addr_utf8_128.clone(), w_amount),
            ),
        ],
        vec![],
    );
    let out1 = e1.apply_block_transition(&b_accept, 0).await;
    let out2 = e2.apply_block_transition(&b_accept, 0).await;
    assert_eq!(out1.status, vec![true, true]);
    assert_eq!(out2.status, vec![true, true]);
    assert_eq!(e1.get_state_root().await, e2.get_state_root().await);
    {
        let br = e1.bridge_read().await;
        assert_eq!(br.pending_withdrawals.len(), 4);
        assert_eq!(br.pending_withdrawals[&2].target_address, addr_128);
        assert_eq!(br.pending_withdrawals[&3].target_address, addr_utf8_128);
        assert_eq!(br.hourly_withdrawn, 4 * w_amount);
    }
    assert_eq!(balance(&e1, &BRIDGE_ESCROW).await, 4 * w_amount);

    // 4. Post-H refund of the pre-H parked 129-byte item (req_id 0) succeeds cleanly.
    let payer_before_refund = balance(&e1, &payer).await;
    let b_refund = make_block(
        SHARD0,
        H + 2,
        b_accept.compute_hash(),
        TS + REFUND_GRACE_SECS + 10,
        proposer,
        vec![bridge_intent_tx(
            payer_seed,
            6,
            BridgeIntent::Refund { req_id: 0 },
        )],
        vec![],
    );
    let out1 = e1.apply_block_transition(&b_refund, 0).await;
    let out2 = e2.apply_block_transition(&b_refund, 0).await;
    assert_eq!(out1.status, vec![true]);
    assert_eq!(out2.status, vec![true]);
    assert_eq!(e1.get_state_root().await, e2.get_state_root().await);
    {
        let br = e1.bridge_read().await;
        assert!(!br.pending_withdrawals.contains_key(&0));
        assert!(br.refunded_withdrawals.contains(&0));
        assert_eq!(br.escrow_balance, 3 * w_amount);
    }
    assert_eq!(balance(&e1, &BRIDGE_ESCROW).await, 3 * w_amount);
    assert!(
        balance(&e1, &payer).await >= payer_before_refund + w_amount - GAS_BASIC_TRANSFER,
        "refunded pre-H long-target withdrawal must return principal to sender"
    );
}

// ===========================================================================
// E2E 3: XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT (`ChainState::apply_block`)
// ===========================================================================

async fn sharded_pair_with_mirror(
    validator: &SigningKey,
    xpc: XpcActivation,
    funding: &[([u8; 32], u64)],
) -> (ShardedCluster, ChainState) {
    let s0 = Arc::new(InMemoryStateEngine::new());
    let mirror_s0 = Arc::new(InMemoryStateEngine::new());
    mirror_s0.enable_cross_shard();
    for (addr, bal) in funding {
        s0.update_account(AccountState::new(*addr, *bal)).await;
        pin(&s0, addr).await;
        mirror_s0
            .update_account(AccountState::new(*addr, *bal))
            .await;
        pin(&mirror_s0, addr).await;
    }
    let s1 = Arc::new(InMemoryStateEngine::new());
    let mut cluster = ShardedCluster::new(
        ShardRegistry::from_ids([SHARD0, SHARD1]),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    );
    cluster.with_xpc_activation(xpc);
    // Match `Cluster::new_sharded` (`ValidatorRuntime::new(..., 1)`).
    let mirror = ChainState::new(mirror_s0);
    (cluster, mirror)
}

fn failed_apply_outbound_tx(seed: u8, recipient: [u8; 32], amount: u64, nonce: u64) -> Transaction {
    let mut tx = pq_xshard_tx(seed, recipient, amount, 1_000_000, nonce, SHARD0, SHARD1);
    tx.payload = vec![OpCode::SysCallCallContract {
        contract: [0xE7u8; 32],
        method: b"missing".to_vec(),
        arg: 0,
    }];
    sign_pq(seed, tx)
}

#[tokio::test]
async fn xshard_bounce_escrow_cluster_mirror_matches_live_at_h_minus_1_and_h() {
    let _gate = XshardBounceGateGuard;

    // -----------------------------------------------------------------------
    // Part A: below-gate legacy parity (H = 100 > timeout height 65)
    // -----------------------------------------------------------------------
    {
        const H_FAR: u64 = 100;
        set_xshard_bounce_escrow_override(Some(H_FAR));
        assert!(!xshard_bounce_escrow_required_active_at(1));
        assert!(!xshard_bounce_escrow_required_active_at(
            1 + CROSS_SHARD_TIMEOUT_HEIGHTS
        ));

        let validator = key(0x30);
        let sender_seed = 0x31u8;
        let sender = pq_id(sender_seed);
        let recipient = key(0x32).verifying_key().to_bytes();
        let initial = 10_000_000u64;
        let amount = 500_000u64;

        let (mut sc, mut mirror) = sharded_pair_with_mirror(
            &validator,
            XpcActivation::FromHeight(H_FAR),
            &[(sender, initial)],
        )
        .await;

        let tx_fail = failed_apply_outbound_tx(sender_seed, recipient, amount, 0);
        let h_fail = tx_fail.compute_tx_hash();
        sc.shard_mut(SHARD0).nodes[0]
            .mempool
            .write()
            .await
            .add(tx_fail.clone())
            .expect("admit failed-apply fixture tx");

        let bh1 = sc.run_height(SHARD0, TS).await;
        let b1 = sc.shard(SHARD0).nodes[0].blocks[&bh1].clone();
        mirror.apply_block(&b1).await;

        let live = &sc.shard(SHARD0).nodes[0];
        assert_eq!(live.applied_statuses, vec![false]);
        assert_eq!(mirror.applied_statuses, vec![false]);
        assert_eq!(live.produced_cross_shard_height(&h_fail), Some(1));
        assert_eq!(mirror.produced_cross_shard_height(&h_fail), Some(1));
        assert_eq!(
            mirror.state.get_state_root().await,
            live.state.get_state_root().await
        );

        let target = 1 + CROSS_SHARD_TIMEOUT_HEIGHTS;
        let mut i = 1u64;
        while sc.shard(SHARD0).nodes[0].height() <= target {
            let bh = sc.run_height(SHARD0, TS + i).await;
            let b = sc.shard(SHARD0).nodes[0].blocks[&bh].clone();
            mirror.apply_block(&b).await;
            i += 1;
        }

        let live = &sc.shard(SHARD0).nodes[0];
        assert!(live.is_transfer_completed(&h_fail));
        assert!(mirror.is_transfer_completed(&h_fail));
        assert_eq!(
            balance(&mirror.state, &sender).await,
            balance(&live.state, &sender).await,
            "below-gate legacy bounce refund on ChainState must match live"
        );
        assert_eq!(
            mirror.state.get_state_root().await,
            live.state.get_state_root().await,
            "below-gate ChainState root must match live after legacy bounce"
        );
    }

    // -----------------------------------------------------------------------
    // Part B: boundary H - 1 (= 1) -> H (= 2)
    // -----------------------------------------------------------------------
    const H: u64 = 2;
    set_xshard_bounce_escrow_override(Some(H));
    assert!(!xshard_bounce_escrow_required_active_at(H - 1));
    assert!(xshard_bounce_escrow_required_active_at(H));

    let validator = key(0x40);
    let seed_fail = 0x41u8;
    let seed_valid = 0x42u8;
    let seed_2pc = 0x43u8;
    let sender_fail = pq_id(seed_fail);
    let sender_valid = pq_id(seed_valid);
    let sender_2pc = pq_id(seed_2pc);
    let recipient = key(0x44).verifying_key().to_bytes();

    let initial = 10_000_000u64;
    let amt_fail = 500_000u64;
    let amt_valid = 400_000u64;
    let amt_2pc = 300_000u64;

    let (mut sc, mut mirror) = sharded_pair_with_mirror(
        &validator,
        XpcActivation::FromHeight(H),
        &[
            (sender_fail, initial),
            (sender_valid, initial),
            (sender_2pc, initial),
        ],
    )
    .await;

    let tx_fail_pre = failed_apply_outbound_tx(seed_fail, recipient, amt_fail, 0);
    let tx_valid_pre = pq_xshard_tx(
        seed_valid,
        recipient,
        amt_valid,
        GAS_BASIC_TRANSFER,
        0,
        SHARD0,
        SHARD1,
    );
    let tx_2pc_conflict = pq_xshard_tx(
        seed_2pc,
        recipient,
        amt_2pc,
        GAS_BASIC_TRANSFER,
        0,
        SHARD0,
        SHARD1,
    );
    let h_fail = tx_fail_pre.compute_tx_hash();
    let h_valid = tx_valid_pre.compute_tx_hash();
    let h_2pc = tx_2pc_conflict.compute_tx_hash();

    {
        let mut mp = sc.shard_mut(SHARD0).nodes[0].mempool.write().await;
        mp.add(tx_fail_pre.clone()).expect("admit tx_fail_pre");
        mp.add(tx_valid_pre.clone()).expect("admit tx_valid_pre");
        mp.add(tx_2pc_conflict.clone())
            .expect("admit tx_2pc_conflict");
    }

    // Apply height H - 1 (= 1): unconditional produced records exist on both live & mirror.
    let bh1 = sc.run_height(SHARD0, TS).await;
    let b1 = sc.shard(SHARD0).nodes[0].blocks[&bh1].clone();
    mirror.apply_block(&b1).await;
    {
        let live = &sc.shard(SHARD0).nodes[0];
        assert_eq!(live.produced_cross_shard_height(&h_fail), Some(1));
        assert_eq!(live.produced_cross_shard_height(&h_valid), Some(1));
        assert_eq!(live.produced_cross_shard_height(&h_2pc), Some(1));

        assert_eq!(mirror.produced_cross_shard_height(&h_fail), Some(1));
        assert_eq!(mirror.produced_cross_shard_height(&h_valid), Some(1));
        assert_eq!(mirror.produced_cross_shard_height(&h_2pc), Some(1));

        assert!(!live.state.has_legacy_escrow_leaf(&tx_fail_pre).await);
        assert!(live.state.has_legacy_escrow_leaf(&tx_valid_pre).await);
        assert!(live.state.has_legacy_escrow_leaf(&tx_2pc_conflict).await);
        assert_eq!(
            mirror.state.get_state_root().await,
            live.state.get_state_root().await
        );
    }

    // Inject §9 2PC PREPARED record for `tx_2pc_conflict` on both live and mirror engines.
    let conflict_rec = XpcRecord::prepared(tx_2pc_conflict.clone(), SHARD0, SHARD1, 1);
    sc.shard(SHARD0).nodes[0]
        .state
        .restore_xpc_records(std::slice::from_ref(&conflict_rec))
        .await;
    mirror
        .state
        .restore_xpc_records(std::slice::from_ref(&conflict_rec))
        .await;

    // Cross into height H (= 2): first gated block prunes the escrowless produced record.
    let bh2 = sc.run_height(SHARD0, TS + 1).await;
    let b2 = sc.shard(SHARD0).nodes[0].blocks[&bh2].clone();
    mirror.apply_block(&b2).await;
    {
        let live = &sc.shard(SHARD0).nodes[0];
        assert_eq!(
            live.produced_cross_shard_height(&h_fail),
            None,
            "live path prunes unproven produced entry at H"
        );
        assert_eq!(
            mirror.produced_cross_shard_height(&h_fail),
            None,
            "ChainState mirror must prune unproven produced entry at H"
        );
        assert_eq!(mirror.produced_cross_shard_height(&h_valid), Some(1));
        assert_eq!(mirror.produced_cross_shard_height(&h_2pc), Some(1));
        assert_eq!(
            mirror.state.get_state_root().await,
            live.state.get_state_root().await
        );
    }

    // Drive through the bounce timeout window (1 + CROSS_SHARD_TIMEOUT_HEIGHTS = 65).
    let target = 1 + CROSS_SHARD_TIMEOUT_HEIGHTS;
    let mut step = 2u64;
    while sc.shard(SHARD0).nodes[0].height() <= target {
        let bh = sc.run_height(SHARD0, TS + step).await;
        let b = sc.shard(SHARD0).nodes[0].blocks[&bh].clone();
        mirror.apply_block(&b).await;
        step += 1;
    }

    let live = &sc.shard(SHARD0).nodes[0];
    assert!(live.is_transfer_completed(&h_valid));
    assert!(mirror.is_transfer_completed(&h_valid));
    assert!(!live.is_transfer_completed(&h_fail));
    assert!(!mirror.is_transfer_completed(&h_fail));
    assert!(!live.is_transfer_completed(&h_2pc));
    assert!(!mirror.is_transfer_completed(&h_2pc));

    assert_eq!(
        balance(&mirror.state, &sender_valid).await,
        balance(&live.state, &sender_valid).await
    );
    assert_eq!(
        balance(&mirror.state, &sender_valid).await,
        initial - GAS_BASIC_TRANSFER
    );
    assert_eq!(
        balance(&mirror.state, &sender_fail).await,
        balance(&live.state, &sender_fail).await
    );
    assert_eq!(
        balance(&mirror.state, &sender_2pc).await,
        balance(&live.state, &sender_2pc).await
    );
    assert_eq!(
        mirror.state.get_state_root().await,
        live.state.get_state_root().await
    );

    // -----------------------------------------------------------------------
    // Part C: adversarial ChainState::apply_block checks at >= H
    // -----------------------------------------------------------------------
    let fail_bal_before = balance(&mirror.state, &sender_fail).await;
    let pc_bal_before = balance(&mirror.state, &sender_2pc).await;
    let forged_fail_bounce = CrossShardMessage::new_bounce(tx_fail_pre.clone(), [0xE1u8; 32]);
    let forged_2pc_bounce = CrossShardMessage::new_bounce(tx_2pc_conflict.clone(), [0xE2u8; 32]);
    let key_fail_bounce = CrossShardKey::of(&forged_fail_bounce);
    let key_2pc_bounce = CrossShardKey::of(&forged_2pc_bounce);

    let adv_height = sc.shard(SHARD0).nodes[0].height();
    let adv_block = make_block(
        SHARD0,
        adv_height,
        [0u8; 32],
        TS + 10_000,
        validator.verifying_key().to_bytes(),
        vec![],
        vec![forged_fail_bounce, forged_2pc_bounce],
    );

    // Run the exact same adversarial block on both `live.state` and `mirror` (`ChainState::apply_block`).
    live.state.apply_block_transition(&adv_block, 0).await;
    mirror.apply_block(&adv_block).await;

    assert_eq!(balance(&mirror.state, &sender_fail).await, fail_bal_before);
    assert_eq!(balance(&mirror.state, &sender_2pc).await, pc_bal_before);
    assert!(!mirror.is_transfer_completed(&h_fail));
    assert!(!mirror.is_transfer_completed(&h_2pc));
    assert!(
        !mirror.is_cross_shard_consumed(&key_fail_bounce),
        "refused escrowless bounce must not poison consumed_cross_shard"
    );
    assert!(
        !mirror.is_cross_shard_consumed(&key_2pc_bounce),
        "refused 2PC-owned bounce must not poison consumed_cross_shard"
    );
    assert_eq!(
        mirror.state.get_state_root().await,
        live.state.get_state_root().await
    );

    // Failed-apply outbound transfer at height >= H must never enter `produced_cross_shard`
    // and its later bounce must be refused without poisoning replay sets.
    let tx_fail_at_h = failed_apply_outbound_tx(seed_fail, recipient, amt_fail, 1);
    let h_fail_at_h = tx_fail_at_h.compute_tx_hash();
    let outbound_at_h = CrossShardMessage::new(
        SHARD0,
        SHARD1,
        tx_fail_at_h.clone(),
        [0u8; 32],
        [0u8; 32],
        None,
    );
    let b_fail_at_h = make_block(
        SHARD0,
        adv_height + 1,
        [0u8; 32],
        TS + 10_001,
        validator.verifying_key().to_bytes(),
        vec![tx_fail_at_h.clone()],
        vec![outbound_at_h],
    );
    live.state.apply_block_transition(&b_fail_at_h, 0).await;
    mirror.apply_block(&b_fail_at_h).await;
    assert_eq!(mirror.produced_cross_shard_height(&h_fail_at_h), None);
    assert_eq!(
        mirror.state.get_state_root().await,
        live.state.get_state_root().await
    );

    let fail_bal_after_h = balance(&mirror.state, &sender_fail).await;
    let bounce_at_h = CrossShardMessage::new_bounce(tx_fail_at_h, [0xE3u8; 32]);
    let key_bounce_at_h = CrossShardKey::of(&bounce_at_h);
    let b_bounce_at_h = make_block(
        SHARD0,
        adv_height + 1 + CROSS_SHARD_TIMEOUT_HEIGHTS,
        [0u8; 32],
        TS + 10_002,
        validator.verifying_key().to_bytes(),
        vec![],
        vec![bounce_at_h],
    );
    live.state.apply_block_transition(&b_bounce_at_h, 0).await;
    mirror.apply_block(&b_bounce_at_h).await;
    assert_eq!(balance(&mirror.state, &sender_fail).await, fail_bal_after_h);
    assert!(!mirror.is_transfer_completed(&h_fail_at_h));
    assert!(!mirror.is_cross_shard_consumed(&key_bounce_at_h));
    assert_eq!(
        mirror.state.get_state_root().await,
        live.state.get_state_root().await
    );

    // Same-block XPC PREPARE + forged bounce for a 2PC transfer at >= H must refuse the bounce.
    let same_block_xpc = CrossShardMessage::new_xpc(
        XPC_PREPARE,
        SHARD0,
        SHARD1,
        tx_2pc_conflict.clone(),
        [0u8; 32],
        [0u8; 32],
        None,
    );
    let same_block_bounce = CrossShardMessage::new_bounce(tx_2pc_conflict, [0xE4u8; 32]);
    let same_block_bounce_key = CrossShardKey::of(&same_block_bounce);
    let b_same_block = make_block(
        SHARD0,
        adv_height + 2 + CROSS_SHARD_TIMEOUT_HEIGHTS,
        [0u8; 32],
        TS + 10_003,
        validator.verifying_key().to_bytes(),
        vec![],
        vec![same_block_xpc, same_block_bounce],
    );
    live.state.apply_block_transition(&b_same_block, 0).await;
    mirror.apply_block(&b_same_block).await;
    assert_eq!(balance(&mirror.state, &sender_2pc).await, pc_bal_before);
    assert!(!mirror.is_transfer_completed(&h_2pc));
    assert!(!mirror.is_cross_shard_consumed(&same_block_bounce_key));
    assert_eq!(
        mirror.state.get_state_root().await,
        live.state.get_state_root().await
    );
}
