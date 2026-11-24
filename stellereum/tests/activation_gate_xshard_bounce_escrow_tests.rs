//! PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test
//! deliberately.
//!
//! `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` is compiled `u64::MAX` (INERT). The
//! legacy cross-shard flow therefore still:
//!
//!  * records `produced_cross_shard` for EVERY outbound transfer in an applied
//!    block, regardless of the transaction's apply `status` and regardless of
//!    whether an XSHARD-01 escrow leaf exists;
//!  * derives a timeout bounce from that record after
//!    `CROSS_SHARD_TIMEOUT_HEIGHTS`; and
//!  * refunds `tx.amount` through `credit_native_transfer`.
//!
//! The first two tests prove the unconditional record and the escrow-free
//! refund, i.e. the S6-2 mint shape the gate exists to close. If the constant is
//! lowered, `assert_bounce_gate_inert` fails in every test in this file, so
//! arming the gate cannot silently keep these assertions. The multi-shard e2e
//! and the `runtime/cluster.rs` replay-mirror fix are still missing; see
//! `docs/ACTIVATION_GATES.md` and `docs/specs/XSHARD_BOUNCE_ESCROW.md`.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::chain_spec::{
    set_xshard_bounce_escrow_override, xshard_bounce_escrow_required_active_at,
    XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT,
};
use stellereum::network::CrossShardTransport;
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    Block, ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL, CROSS_SHARD_TIMEOUT_HEIGHTS,
    MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;
use stellereum::xshard2pc::XpcActivation;

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const TS: u64 = 1_780_000_000;

/// Clears the thread-local override on drop so a panicking assertion cannot
/// leak a test activation into another test on the same worker thread.
struct GateReset;

impl Drop for GateReset {
    fn drop(&mut self) {
        set_xshard_bounce_escrow_override(None);
    }
}

fn assert_bounce_gate_inert() {
    assert_eq!(
        XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT,
        u64::MAX,
        "the bounce escrow gate was armed; this file pins the pre-activation \
         unconditional produced record/refund and must be updated with a \
         post-activation multi-shard e2e"
    );
    for height in [0u64, 1, 1_000, 253_000, 10_000_000, u64::MAX - 1, u64::MAX] {
        assert!(
            !xshard_bounce_escrow_required_active_at(height),
            "the compiled gate must be inactive at every height, including {height}"
        );
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// FULL-PQ sender address for a seed: implicit Falcon-512, registered globally.
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

/// A validly signed outbound transfer whose PAYLOAD reverts at apply: it debits
/// no principal and commits no escrow leaf, but the block still carries its
/// outbound transfer record below the gate.
fn failed_apply_outbound(seed: u8, recipient: [u8; 32], amount: u64) -> Transaction {
    let mut tx = pq_tx(seed, recipient, amount, 1_000_000, 0, SHARD0, SHARD1);
    tx.payload = vec![OpCode::SysCallCallContract {
        contract: [0xE7u8; 32],
        method: b"missing".to_vec(),
        arg: 0,
    }];
    sign_pq(seed, tx)
}

// PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test deliberately.
#[tokio::test]
async fn pins_pre_activation_records_an_unproven_outbound_transfer() {
    let _gate = GateReset;
    set_xshard_bounce_escrow_override(None);
    assert_bounce_gate_inert();

    let validator = key(0x91);
    let sender_seed = 0x92u8;
    let sender = pq_id(sender_seed);
    let recipient = key(0x93).verifying_key().to_bytes();
    let initial = 10_000_000u64;
    let amount = 500_000u64;

    let mut sc = sharded_pair(&validator, XpcActivation::Disabled, &[(sender, initial)]).await;

    let tx = failed_apply_outbound(sender_seed, recipient, amount);
    let tx_hash = tx.compute_tx_hash();

    // `mempool.add` (not `add_checked`) lets the payload failure happen at
    // apply, which is exactly the S6-2 input.
    sc.shard_mut(SHARD0).nodes[0]
        .mempool
        .write()
        .await
        .add(tx.clone())
        .expect("fixture tx admitted");

    let bh = sc.run_height(SHARD0, TS).await;
    assert!(
        block_of(&sc, SHARD0, bh)
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
    assert_eq!(
        node.produced_cross_shard_height(&tx_hash),
        Some(1),
        "pre-activation the unfiltered producer records the outbound even though it failed"
    );

    let engine = node.state.clone();
    assert!(
        !engine.has_legacy_escrow_leaf(&tx).await,
        "a failed apply escrows nothing, so there is no source debit to bounce"
    );
    assert!(
        !engine.legacy_escrow_leaf_committed(&tx_hash).await,
        "no committed XSHARD-01 leaf exists for the failed transaction"
    );

    let after_produce = balance(&sc, SHARD0, &sender).await;
    assert!(
        after_produce < initial,
        "only the failure fee was charged; the principal was never debited"
    );
}

// PINS PRE-ACTIVATION BEHAVIOUR — arming the gate must update this test deliberately.
#[tokio::test]
async fn pins_pre_activation_bounce_refunds_without_escrow() {
    let _gate = GateReset;
    set_xshard_bounce_escrow_override(None);
    assert_bounce_gate_inert();

    let validator = key(0xA1);
    let sender_seed = 0xA2u8;
    let sender = pq_id(sender_seed);
    let recipient = key(0xA3).verifying_key().to_bytes();
    let initial = 10_000_000u64;
    let amount = 500_000u64;

    let mut sc = sharded_pair(&validator, XpcActivation::Disabled, &[(sender, initial)]).await;

    let tx = failed_apply_outbound(sender_seed, recipient, amount);
    let tx_hash = tx.compute_tx_hash();

    sc.shard_mut(SHARD0).nodes[0]
        .mempool
        .write()
        .await
        .add(tx.clone())
        .expect("fixture tx admitted");

    let bh = sc.run_height(SHARD0, TS).await;
    assert!(block_of(&sc, SHARD0, bh)
        .transactions
        .iter()
        .any(|t| t.compute_tx_hash() == tx_hash));
    let node = &sc.shard(SHARD0).nodes[0];
    assert_eq!(node.applied_statuses.first().copied(), Some(false));
    assert_eq!(node.produced_cross_shard_height(&tx_hash), Some(1));

    let engine = node.state.clone();
    assert!(!engine.has_legacy_escrow_leaf(&tx).await);
    assert!(!engine.legacy_escrow_leaf_committed(&tx_hash).await);

    let after_produce = balance(&sc, SHARD0, &sender).await;

    // Drive past the 64-height timeout. Pre-activation the derived bounce is
    // admitted, completed, and refunded with no escrow leaf anywhere.
    let bodies = run_to_bounce_window(&mut sc, TS + 10).await;
    let bounce = bodies
        .iter()
        .flat_map(|b| b.cross_shard_out.iter())
        .find(|m| m.is_bounce() && m.tx.compute_tx_hash() == tx_hash)
        .cloned()
        .expect("pre-activation derives a bounce from the unproven produced record");

    assert!(bounce.is_bounce());
    assert!(
        sc.shard(SHARD0).nodes[0].is_transfer_completed(&tx_hash),
        "the bounce must finalize the transfer while the gate is inert"
    );
    assert_eq!(
        balance(&sc, SHARD0, &sender).await,
        after_produce + amount,
        "pre-activation the bounce credits `amount` although no source debit exists"
    );
    assert!(
        !engine.has_legacy_escrow_leaf(&tx).await,
        "the refund above was NOT backed by an escrow leaf"
    );
}
