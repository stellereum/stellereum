//! S6-2 regression: the legacy cross-shard timeout bounce must be backed by a
//! real source DEBIT (the XSHARD-01 escrow leaf) and must never complete a
//! transaction that owns a §9 2PC record.
//!
//! The gate under test is
//! [`stellereum::chain_spec::XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT`], compiled
//! `u64::MAX` (disabled). Every test here drives it through the test-only
//! thread-local override so the live `{0}` configuration stays untouched:
//!
//!  * (a) a validly signed transaction that FAILS at apply still has an
//!    outbound record; the gate must never derive or pay a bounce for it;
//!  * (b) a 2PC PREPARE + legacy record + hand-crafted bounce must not refund
//!    the source while the target's COMMIT credits the recipient;
//!  * (c) a genuinely debited, escrow-proven legacy transfer still bounces
//!    after the height timeout and refunds exactly once;
//!  * (d) below the gate the historical behaviour is unchanged.
//!
//! The gate is activated at height 2, so the transfer can be produced at
//! height 1 under the historical (below-gate) producer and the bounce is
//! tested at/above the gate. That models `{0,1}` activation: transfers
//! produced before the gate keep their escrow leaf and stay bounce-eligible,
//! while the gate re-checks the debit before it pays.

use ed25519_dalek::SigningKey;
use std::sync::{Arc, RwLock};
use stellereum::chain_spec::set_xshard_bounce_escrow_override;
use stellereum::network::CrossShardTransport;
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    Block, CrossShardMessage, CrossShardReplaySnapshot, FinalizedHeaderRegistry, ShardRegistry,
    Transaction, BASE_WORKCHAIN_SHARD_INITIAL, CROSS_SHARD_TIMEOUT_HEIGHTS, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::xshard2pc::{XpcActivation, XpcRecord, XPC_COMMIT};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const TS: u64 = 1_780_000_000;
/// The gate height used by the fail-before tests: above the height the legacy
/// transfer is produced at, below the first possible bounce.
const GATE: u64 = 2;

// ---------------------------------------------------------------------------
// Gate override lifetime (thread-scoped; every test runs on one thread).
// ---------------------------------------------------------------------------

struct GateGuard;

impl Drop for GateGuard {
    fn drop(&mut self) {
        set_xshard_bounce_escrow_override(None);
    }
}

fn gate_at(height: u64) -> GateGuard {
    set_xshard_bounce_escrow_override(Some(height));
    GateGuard
}

fn gate_off() -> GateGuard {
    set_xshard_bounce_escrow_override(None);
    GateGuard
}

// ---------------------------------------------------------------------------
// Fixtures (mirror the M3 / §9 test harness).
// ---------------------------------------------------------------------------

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// FULL-PQ sender address for a seed: implicit Falcon-512, registered
/// globally (no activation surcharge).
fn pq_id(seed: u8) -> [u8; 32] {
    use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ test key must register");
    from
}

fn sign_pq(seed: u8, mut tx: Transaction) -> Transaction {
    use stellereum::post_quantum::{PqScheme, PqSignatureEnvelope};
    let pk = Transaction::sample_falcon512_pubkey(seed);
    tx.signature = Vec::new();
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    tx
}

fn pq_tx(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
) -> Transaction {
    let from = pq_id(seed);
    let tx = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    sign_pq(seed, tx)
}

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

async fn pin(engine: &InMemoryStateEngine, addr: &[u8; 32]) {
    if let Some((scheme, pk)) = Transaction::global_implicit_registry().lookup(addr) {
        use stellereum::post_quantum::DEFAULT_SALT;
        engine
            .pin_pubkey(*addr, scheme, &pk, &DEFAULT_SALT)
            .await
            .expect("PQ sender must pin");
    }
}

async fn sharded_pair(
    validator: &SigningKey,
    xpc: XpcActivation,
    shard0_funding: &[([u8; 32], u64)],
) -> ShardedCluster {
    let s0 = Arc::new(InMemoryStateEngine::new());
    for (addr, bal) in shard0_funding {
        s0.update_account(AccountState::new(*addr, *bal)).await;
        pin(&s0, addr).await;
    }
    let s1 = Arc::new(InMemoryStateEngine::new());
    let mut cluster = ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator.clone(), s1)]),
        ],
        CrossShardTransport::local(),
    );
    cluster.with_xpc_activation(xpc);
    cluster
}

async fn balance(sc: &ShardedCluster, shard: u32, addr: &[u8; 32]) -> u64 {
    sc.shard(shard).nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

fn block_of(sc: &ShardedCluster, shard: u32, bh: [u8; 32]) -> Block {
    sc.shard(shard).nodes[0]
        .blocks
        .get(&bh)
        .cloned()
        .expect("block body retained")
}

fn carrier(shard: u32, height: u64, msg: CrossShardMessage) -> Block {
    Block {
        shard_id: shard,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![msg],
        timestamp: TS,
        proposer: [0x11u8; 32],
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

/// Run the source shard from its current height through `produce + TIMEOUT`
/// (the first height a bounce is eligible), returning every finalized body.
async fn run_to_bounce_window(sc: &mut ShardedCluster, ts0: u64) -> Vec<Block> {
    let mut bodies = Vec::new();
    let produce_height = sc.shard(SHARD0).nodes[0].height().saturating_sub(1);
    let target = produce_height + CROSS_SHARD_TIMEOUT_HEIGHTS;
    let mut i = 0u64;
    while sc.shard(SHARD0).nodes[0].height() <= target {
        let bh = sc.run_height(SHARD0, ts0 + i).await;
        bodies.push(block_of(sc, SHARD0, bh));
        i += 1;
        assert!(i < CROSS_SHARD_TIMEOUT_HEIGHTS + 16, "bounce window driver");
    }
    bodies
}

// ---------------------------------------------------------------------------
// (a) failed apply + outbound record => no bounce mint.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x8_bounce_failed_apply_outbound_record_cannot_mint() {
    let _gate = gate_at(GATE);
    let validator = key(0xE1);
    let sender_seed = 0xE2u8;
    let sender = pq_id(sender_seed);
    let recipient = key(0xE3).verifying_key().to_bytes();
    let initial = 10_000_000u64;
    let amount = 500_000u64;

    let mut sc = sharded_pair(
        &validator,
        XpcActivation::FromHeight(GATE),
        &[(sender, initial)],
    )
    .await;

    // A validly signed outbound transfer whose PAYLOAD reverts at apply: the
    // source debits no principal (only the failure fee), yet the block still
    // carries the outbound transfer record. This is the S6-2 mint shape.
    let mut tx = pq_tx(sender_seed, recipient, amount, 1_000_000, 0, SHARD0, SHARD1);
    tx.payload = vec![OpCode::SysCallCallContract {
        contract: [0xE7u8; 32],
        method: b"missing".to_vec(),
        arg: 0,
    }];
    let tx = sign_pq(sender_seed, tx);
    let tx_hash = tx.compute_tx_hash();

    // Mempool `add` (not `add_checked`) lets the failure be produced: the
    // payload is what fails at apply, not admission.
    sc.shard_mut(SHARD0).nodes[0]
        .mempool
        .write()
        .await
        .add(tx.clone())
        .expect("fixture tx admitted");

    let bh = sc.run_height(SHARD0, TS).await;
    let produced_block = block_of(&sc, SHARD0, bh);
    assert!(
        produced_block
            .transactions
            .iter()
            .any(|t| t.compute_tx_hash() == tx_hash),
        "the failed transaction must be in the produced block"
    );
    let node = &sc.shard(SHARD0).nodes[0];
    assert_eq!(
        node.applied_statuses.first().copied(),
        Some(false),
        "the fixture transaction must FAIL at apply (no principal debit)"
    );
    // Produced at height 1 is BELOW the gate (height 2), so the historical
    // unconditional record exists. This is exactly the inherited state the
    // gate must neutralize when the bounce becomes eligible.
    assert_eq!(
        node.produced_cross_shard_height(&tx_hash),
        Some(1),
        "below-gate production still records the outbound (the vulnerability's input)"
    );
    let balance_after_produce = balance(&sc, SHARD0, &sender).await;
    assert!(
        balance_after_produce < initial,
        "the failure fee was charged, the principal was not"
    );

    // Heights 2..=65 (gate active): the first gated block prunes the
    // unproven produced record, and no bounce may be derived for this tx.
    let bodies = run_to_bounce_window(&mut sc, TS + 10).await;
    assert_eq!(
        sc.shard(SHARD0).nodes[0].produced_cross_shard_height(&tx_hash),
        None,
        "the first gated block prunes the unproven produced record"
    );
    assert!(
        bodies.iter().all(|b| b
            .cross_shard_out
            .iter()
            .all(|m| !(m.is_bounce() && m.tx.compute_tx_hash() == tx_hash))),
        "a failed-apply outbound must never derive a bounce at/above the gate"
    );
    assert_eq!(
        balance(&sc, SHARD0, &sender).await,
        balance_after_produce,
        "the failed-apply transaction must never be refunded (no mint)"
    );
    assert!(!sc.shard(SHARD0).nodes[0].is_transfer_completed(&tx_hash));

    // Even a hand-crafted (Byzantine) bounce carrier is refused by the engine
    // mirror: no replay key, no completion, no value movement.
    let engine = sc.shard(SHARD0).nodes[0].state.clone();
    let consumed_before = engine.cross_shard_consumed_len().await;
    let forged = CrossShardMessage::new_bounce(tx.clone(), [0xEAu8; 32]);
    let at_height = sc.shard(SHARD0).nodes[0].height();
    let applied = engine
        .apply_cross_shard_consumptions(&carrier(SHARD0, at_height, forged))
        .await;
    assert_eq!(applied, 0, "a proof-less bounce must not be credited");
    assert_eq!(engine.cross_shard_consumed_len().await, consumed_before);
    assert!(!engine.is_cross_shard_completed(&tx_hash).await);
}

// ---------------------------------------------------------------------------
// (b) 2PC transfer + legacy record + bounce => no refund, no double credit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x8_bounce_2pc_transfer_bounce_cannot_double_spend() {
    let _gate = gate_at(GATE);
    let validator = key(0xF1);
    let sender_seed = 0xF2u8;
    let sender = pq_id(sender_seed);
    let recipient = key(0xF3).verifying_key().to_bytes();
    let initial = 1_000_000u64;
    let amount = 400_000u64;
    let gas = 10u64;

    let mut sc = sharded_pair(
        &validator,
        XpcActivation::FromHeight(GATE),
        &[(sender, initial)],
    )
    .await;

    // Height 1 (below the XPC activation): the transfer is produced through
    // the legacy path, so a real legacy record AND its escrow leaf exist.
    let tx = pq_tx(sender_seed, recipient, amount, gas, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    sc.broadcast_tx(tx.clone()).await;
    let bh = sc.run_height(SHARD0, TS).await;
    let legacy_block = block_of(&sc, SHARD0, bh);
    assert!(
        legacy_block
            .cross_shard_out
            .iter()
            .any(|m| m.is_transfer() && m.tx.compute_tx_hash() == tx_hash),
        "height 1 must publish the legacy transfer record"
    );
    assert_eq!(
        sc.shard(SHARD0).nodes[0].produced_cross_shard_height(&tx_hash),
        Some(1)
    );
    let engine = sc.shard(SHARD0).nodes[0].state.clone();
    assert!(
        engine.has_legacy_escrow_leaf(&tx).await,
        "the applied legacy transfer really escrowed the value"
    );
    let sender_after_legacy = balance(&sc, SHARD0, &sender).await;
    assert_eq!(sender_after_legacy, initial - amount - gas);

    // The exploit shape: a §9 2PC record exists for the SAME tx while the
    // legacy record is still in the produced mirror. Inject it into the
    // source's committed 2PC state and run one height so the runtime mirror
    // (what synchronous validation reads) is refreshed from the engine.
    engine
        .restore_xpc_records(&[XpcRecord::prepared(tx.clone(), SHARD0, SHARD1, 1)])
        .await;
    sc.run_height(SHARD0, TS + 1).await;

    // The target side of the same transfer: it PREPARED and then applies the
    // source's COMMIT, crediting the recipient EXACTLY once.
    let source_root = engine.get_state_root().await;
    let source_block = [0xB7u8; 32];
    let proof = engine
        .get_xpc_proof(&tx_hash)
        .await
        .expect("the PREPARED leaf is provable at the source root");
    let registry = Arc::new(RwLock::new(FinalizedHeaderRegistry::default()));
    registry
        .write()
        .unwrap()
        .note_finalized(SHARD0, source_block, source_root);
    let target = Arc::new(InMemoryStateEngine::new());
    target.enable_cross_shard();
    target.with_finalized_headers(registry);
    target
        .restore_xpc_records(&[XpcRecord::prepared(tx.clone(), SHARD0, SHARD1, 1)])
        .await;
    let commit = CrossShardMessage::new_xpc(
        XPC_COMMIT,
        SHARD0,
        SHARD1,
        tx.clone(),
        source_root,
        source_block,
        Some(proof),
    );
    target
        .apply_cross_shard_consumptions(&carrier(SHARD1, 3, commit))
        .await;
    assert_eq!(
        target.get_account(&recipient).await.map(|a| a.balance),
        Some(amount),
        "the target COMMIT credits the recipient exactly once"
    );

    // A hand-crafted bounce for the same tx enters the mailbox; it must never
    // refund the source while that COMMIT stands.
    let bounce = CrossShardMessage::new_bounce(tx.clone(), [0xF9u8; 32]);
    sc.transport
        .broadcast_cross_shard(&bounce)
        .await
        .expect("transport accepts the carrier");

    let bodies = run_to_bounce_window(&mut sc, TS + 10).await;
    assert!(
        bodies.iter().all(|b| b
            .cross_shard_out
            .iter()
            .all(|m| !(m.is_bounce() && m.tx.compute_tx_hash() == tx_hash))),
        "no bounce may be admitted for a transaction that owns a 2PC record"
    );
    assert_eq!(
        balance(&sc, SHARD0, &sender).await,
        sender_after_legacy,
        "the source must not refund a 2PC transfer (no double spend)"
    );
    assert!(!sc.shard(SHARD0).nodes[0].is_transfer_completed(&tx_hash));

    // The engine mirror refuses the same carrier too (no completion claim).
    let consumed_before = engine.cross_shard_consumed_len().await;
    let applied = engine
        .apply_cross_shard_consumptions(&carrier(
            SHARD0,
            sc.shard(SHARD0).nodes[0].height(),
            bounce.clone(),
        ))
        .await;
    assert_eq!(applied, 0);
    assert_eq!(engine.cross_shard_consumed_len().await, consumed_before);
    assert!(!engine.is_cross_shard_completed(&tx_hash).await);

    // Consensus validation refuses the forged bounce carrier at the gate.
    let node = &sc.shard(SHARD0).nodes[0];
    let root = node.state_root().await;
    let height = node.height();
    let prev = node.finalized.last().map(|(_, h)| *h).unwrap_or([0u8; 32]);
    let parent_ts = node.blocks.get(&prev).map(|b| b.timestamp).unwrap_or(TS);
    let mut forged = Block {
        shard_id: SHARD0,
        height,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![bounce],
        timestamp: parent_ts + 1,
        proposer: validator.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: stellereum::mev::compute_order_merkle_root(&[]),
        epoch_key_commitment: [0u8; 32],
        round: 0,
    };
    forged.sign_block(&validator);
    let err = node
        .validate_proposal(&forged, root)
        .expect_err("a bounce for a 2PC-owned tx must be refused");
    assert!(
        err.contains("linkage") || err.contains("2PC") || err.contains("escrow"),
        "refusal must name the gate rule: {err}"
    );

    // The target credit stands, and the value was never duplicated.
    assert_eq!(
        target.get_account(&recipient).await.map(|a| a.balance),
        Some(amount),
        "the single COMMIT credit is unchanged"
    );
}

// ---------------------------------------------------------------------------
// (c) a genuinely debited, escrow-proven transfer still bounces exactly once.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x8_bounce_escrow_proven_transfer_refunds_exactly_once() {
    let _gate = gate_at(GATE);
    let validator = key(0xA1);
    let sender_seed = 0xA2u8;
    let sender = pq_id(sender_seed);
    let recipient = key(0xA3).verifying_key().to_bytes();
    let initial = 1_000u64;
    let amount = 100u64;
    let gas = 10u64;

    let mut sc = sharded_pair(
        &validator,
        XpcActivation::FromHeight(GATE),
        &[(sender, initial)],
    )
    .await;

    let tx = pq_tx(sender_seed, recipient, amount, gas, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    sc.broadcast_tx(tx.clone()).await;
    let bh = sc.run_height(SHARD0, TS).await;
    let produced = block_of(&sc, SHARD0, bh);
    assert_eq!(produced.cross_shard_out.len(), 1);
    assert!(produced.cross_shard_out[0].is_transfer());
    assert_eq!(
        sc.shard(SHARD0).nodes[0].produced_cross_shard_height(&tx_hash),
        Some(1)
    );
    assert_eq!(balance(&sc, SHARD0, &sender).await, initial - amount - gas);
    assert!(
        sc.shard(SHARD0).nodes[0]
            .state
            .has_legacy_escrow_leaf(&tx)
            .await,
        "the applied transfer committed its XSHARD-01 escrow leaf"
    );

    // Heights 2..=65: the target never consumes, so the first eligible bounce
    // is derived at 1 + TIMEOUT = 65. The gate must let it through because the
    // source debit is proven by the committed escrow leaf.
    let bodies = run_to_bounce_window(&mut sc, TS + 10).await;
    let bounce = bodies
        .iter()
        .flat_map(|b| b.cross_shard_out.iter())
        .find(|m| m.is_bounce() && m.tx.compute_tx_hash() == tx_hash)
        .cloned()
        .expect("an escrow-proven transfer must still bounce after the timeout");
    assert_eq!(
        bounce.tx.compute_tx_hash(),
        tx_hash,
        "the bounce names the transfer"
    );
    assert!(sc.shard(SHARD0).nodes[0].is_transfer_completed(&tx_hash));
    assert_eq!(
        balance(&sc, SHARD0, &sender).await,
        initial - gas,
        "exactly `amount` is refunded once; gas is not"
    );

    // A replay of the consumed bounce and a rebuilt carrier for the same tx
    // must not refund a second time.
    sc.transport
        .broadcast_cross_shard(&bounce)
        .await
        .expect("transport accepts the replay");
    let rebuilt = CrossShardMessage::new_bounce(bounce.tx.clone(), [0xA9u8; 32]);
    sc.transport
        .broadcast_cross_shard(&rebuilt)
        .await
        .expect("transport accepts the rebuilt carrier");
    let bh2 = sc.run_height(SHARD0, TS + 10_000).await;
    let body2 = block_of(&sc, SHARD0, bh2);
    assert!(
        body2.cross_shard_out.iter().all(|m| !m.is_bounce()),
        "a completed transfer never bounces twice"
    );
    assert_eq!(balance(&sc, SHARD0, &sender).await, initial - gas);
}

// ---------------------------------------------------------------------------
// (d) below the gate: byte-identical historical behaviour.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x8_bounce_below_gate_unchanged() {
    let _gate = gate_off();
    let validator = key(0xB1);

    // Sub-scenario 1: the historical producer records EVERY outbound transfer,
    // including one that FAILS at apply (no escrow leaf). The gate is off, so
    // this is the pinned historical recording semantics.
    let fail_seed = 0xB2u8;
    let fail_sender = pq_id(fail_seed);
    let recipient = key(0xB3).verifying_key().to_bytes();
    let mut failing = sharded_pair(
        &validator,
        XpcActivation::FromHeight(GATE),
        &[(fail_sender, 10_000_000)],
    )
    .await;
    let mut bad = pq_tx(fail_seed, recipient, 500_000, 1_000_000, 0, SHARD0, SHARD1);
    bad.payload = vec![OpCode::SysCallCallContract {
        contract: [0xE7u8; 32],
        method: b"missing".to_vec(),
        arg: 0,
    }];
    let bad = sign_pq(fail_seed, bad);
    let bad_hash = bad.compute_tx_hash();
    failing.shard_mut(SHARD0).nodes[0]
        .mempool
        .write()
        .await
        .add(bad.clone())
        .expect("fixture tx admitted");
    failing.run_height(SHARD0, TS).await;
    assert_eq!(
        failing.shard(SHARD0).nodes[0]
            .applied_statuses
            .first()
            .copied(),
        Some(false)
    );
    assert_eq!(
        failing.shard(SHARD0).nodes[0].produced_cross_shard_height(&bad_hash),
        Some(1),
        "below the gate the unconditional produced record is unchanged"
    );

    // Sub-scenario 2: the historical happy path (a real transfer bounces and
    // refunds exactly once) is unchanged with the gate compiled off.
    let sender_seed = 0xB4u8;
    let sender = pq_id(sender_seed);
    let initial = 1_000u64;
    let amount = 100u64;
    let gas = 10u64;
    let mut sc = sharded_pair(
        &validator,
        XpcActivation::FromHeight(GATE),
        &[(sender, initial)],
    )
    .await;
    let tx = pq_tx(sender_seed, recipient, amount, gas, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    sc.broadcast_tx(tx.clone()).await;
    sc.run_height(SHARD0, TS).await;
    assert_eq!(
        sc.shard(SHARD0).nodes[0].produced_cross_shard_height(&tx_hash),
        Some(1)
    );
    let bodies = run_to_bounce_window(&mut sc, TS + 10).await;
    assert!(
        bodies.iter().any(|b| b
            .cross_shard_out
            .iter()
            .any(|m| m.is_bounce() && m.tx.compute_tx_hash() == tx_hash)),
        "below the gate a real transfer still bounces after the timeout"
    );
    assert!(sc.shard(SHARD0).nodes[0].is_transfer_completed(&tx_hash));
    assert_eq!(balance(&sc, SHARD0, &sender).await, initial - gas);
}

// ---------------------------------------------------------------------------
// (e) the gate deterministically prunes produced entries with no escrow leaf.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn x8_bounce_gate_prunes_unproven_produced_records() {
    let _gate = gate_at(GATE);
    let recipient = key(0xC5).verifying_key().to_bytes();

    let engine = Arc::new(InMemoryStateEngine::new());
    engine.enable_cross_shard();

    // Produce a below-gate outbound record whose transaction FAILED: the
    // engine records `produced` (below gate) but writes no escrow leaf.
    let tx = pq_tx(0xC2, recipient, 100, 10, 0, SHARD0, SHARD1);
    let tx_hash = tx.compute_tx_hash();
    let legacy = CrossShardMessage::new(SHARD0, SHARD1, tx.clone(), [0u8; 32], [0u8; 32], None);
    let below_gate = Block {
        shard_id: SHARD0,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![tx.clone()],
        cross_shard_out: vec![legacy],
        timestamp: TS,
        proposer: [0x11u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        round: 0,
    };
    engine.apply_cross_shard_consumptions(&below_gate).await;
    engine
        .record_legacy_escrow_receipts(&below_gate, &[false])
        .await;
    assert_eq!(engine.cross_shard_produced_len().await, 1);
    assert!(!engine.legacy_escrow_leaf_committed(&tx_hash).await);

    // The FIRST gated block (even an EMPTY one) prunes the unproven record.
    // Deterministic: it is a pure function of the committed trie.
    let empty = Block {
        transactions: vec![],
        cross_shard_out: vec![],
        ..below_gate.clone()
    };
    let gated = Block {
        height: GATE,
        ..empty
    };
    engine.apply_cross_shard_consumptions(&gated).await;
    assert_eq!(
        engine.cross_shard_produced_len().await,
        0,
        "an unproven below-gate record is pruned at the gate"
    );

    // With the record gone, a hand-crafted bounce cannot complete or refund.
    let consumed_before = engine.cross_shard_consumed_len().await;
    let bounce = CrossShardMessage::new_bounce(tx.clone(), [0xC7u8; 32]);
    let applied = engine
        .apply_cross_shard_consumptions(&carrier(SHARD0, GATE + 64, bounce))
        .await;
    assert_eq!(applied, 0);
    assert_eq!(engine.cross_shard_consumed_len().await, consumed_before);
    assert!(!engine.is_cross_shard_completed(&tx_hash).await);

    // An escrow-proven entry survives the same prune.
    let good = pq_tx(0xC3, recipient, 200, 10, 0, SHARD0, SHARD1);
    let good_hash = good.compute_tx_hash();
    engine
        .restore_cross_shard_replay(&CrossShardReplaySnapshot {
            produced: vec![(good_hash, good.clone(), 1)],
            ..Default::default()
        })
        .await;
    assert!(engine.has_legacy_escrow_leaf(&good).await);
    engine
        .apply_cross_shard_consumptions(&Block {
            height: GATE + 1,
            ..below_gate.clone()
        })
        .await;
    assert_eq!(engine.cross_shard_produced_len().await, 1);
    assert!(engine.has_legacy_escrow_leaf(&good).await);
}
