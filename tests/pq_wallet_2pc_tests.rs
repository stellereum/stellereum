//! PQ wallet transfer path for `STELL_PURE_PQ=1` chains (the mode live + the
//! local cluster both run in).
//!
//! The gap this covers: the genesis-funded faucet account is a Falcon-512 PQ
//! address, but no transfer CLI could spend it — `wallet send` builds legacy
//! ed25519 txs, which pure-PQ verification refuses. `wallet send-pq` (backed
//! by `rpc::sign_pq_explicit_transfer`, the same shape `Faucet::build_transfer`
//! builds) closes it with NO verifier change.
//!
//! What each layer pins:
//!
//! * `rpc.rs` unit tests: the `send-pq` tx SHAPE verifies under enforced
//!   pure-PQ, ed-signed txs are refused, tampered txs are refused, and the
//!   shape is admitted by the mempool under pure-PQ.
//! * THIS file: that same shape flows end-to-end through a 2-shard in-process
//!   cluster — funding leg, second spend, full 2PC with exactly-once credit —
//!   mirroring the local-cluster demo legs (`docs/LIVE_DEMOS_RUNBOOK.md`, 2PC
//!   section).
//!
//! Override discipline (read before touching): `set_pure_pq_override` in an
//! integration binary writes a PROCESS-WIDE atomic, and pure-PQ also refuses
//! the harness's ed25519 validator VOTES — so the override is held ONLY
//! inside synchronous verify scopes (never across a `run_height`), and every
//! test holds `PQ_SERIAL` for its whole body so two tests can never
//! interleave override windows. The cluster steps run with pure-PQ OFF,
//! which is faithful: PQ envelopes verify in BOTH modes (only legacy ed is
//! mode-gated), so the flow exercised here is the flow a pure-PQ node runs,
//! minus the vote keys the harness cannot mint.
//!
//! PQ ACTIVATION RULE (measured, `verify_inclusion_untrusted` +
//! `commit_native` pin): a fresh PQ account holds a 16-byte trie leaf. Its
//! first spend pins the 49-byte PQ leaf (scheme + pubkey hash) at apply —
//! but a cross-shard first spend's opening PREPARE proves the PRE-block
//! 16-byte leaf while the message's PQ metadata forces the 49-byte check, so
//! the target refuses it (only the slower source re-PREPARE cadence, proving
//! the PREPARED XPC leaf, would save it — UNVERIFIED here). Therefore a PQ
//! account's first spend must be same-shard; cross-shard spends work from the
//! second spend on, with the opening PREPARE verifying first-try. The demo
//! and test 3 below follow exactly that order.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::network::CrossShardTransport;
use stellereum::post_quantum::{self, FalconKeypair};
use stellereum::rpc::{sign_pq_explicit_transfer, Faucet};
use stellereum::runtime::ShardedCluster;
use stellereum::sharding::{
    CrossShardKind, ShardRegistry, Transaction, BASE_WORKCHAIN_SHARD_INITIAL, MASTERCHAIN_SHARD,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::xshard2pc::{XpcActivation, XpcPhase};

const SHARD0: u32 = MASTERCHAIN_SHARD;
const SHARD1: u32 = BASE_WORKCHAIN_SHARD_INITIAL;
const TS: u64 = 1_770_000_000;

/// The shared local-cluster faucet seed (`STELL_FAUCET_KEY=1111..1`).
const FAUCET_SEED: [u8; 32] = [0x11u8; 32];
/// Fresh PQ recipient seed (any secret works; the address holds funds only
/// after the funding leg credits it).
const RECIP_SEED: [u8; 32] = [0x55u8; 32];

/// Serializes the override windows of the tests in this binary (see module
/// docs): without this, two parallel tests interleave `Some(true)` / `None`
/// on the process-wide atomic and one observes the other's reset. A tokio
/// mutex (not std): the guard is held across `.await` points.
static PQ_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn pq_gas() -> u64 {
    stellereum::svm::GAS_BASIC_TRANSFER + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS
}

/// Success-path debit for our activation tx:
/// `amount + max(gas_limit, floor) + surcharge`
/// (sequential apply: `state_engine.rs` total_cost =
/// `amount + fee_reserved + surcharge`; `fee_to_charge` contract in
/// `sharding.rs`: `max(gas_limit, floor) + surcharge`).
/// Our declared gas (325k) clears the base floor, so the fee is gas + one
/// surcharge.
fn pq_fee() -> u64 {
    pq_gas() + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS
}

fn faucet_keypair() -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&FAUCET_SEED)
}

fn faucet_addr() -> [u8; 32] {
    post_quantum::derive_pq_address(
        post_quantum::PqScheme::Falcon512,
        &faucet_keypair().public_key,
        &post_quantum::DEFAULT_SALT,
    )
}

fn recip_keypair() -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&RECIP_SEED)
}

fn recip_addr() -> [u8; 32] {
    post_quantum::derive_pq_address(
        post_quantum::PqScheme::Falcon512,
        &recip_keypair().public_key,
        &post_quantum::DEFAULT_SALT,
    )
}

fn ed_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sharded() -> ShardRegistry {
    ShardRegistry::from_ids([SHARD0, SHARD1])
}

/// Assert the tx verifies with pure-PQ ENFORCED. Synchronous scope only —
/// never held across an `.await` (the harness's ed votes would fail while it
/// is active and finality would stall).
fn assert_verifies_under_pure_pq(tx: &Transaction) {
    post_quantum::set_pure_pq_override(Some(true));
    let ok = tx.verify_signature();
    post_quantum::set_pure_pq_override(None);
    assert!(ok, "send-pq shape must verify under PURE_PQ");
}

/// Two-shard cluster with 2PC ACTIVE from height 0 and the faucet PQ account
/// funded on the source shard — mirroring masterchain genesis on a cluster
/// where the faucet account is the Falcon-512 address.
async fn pq_cluster(source_funding: u64) -> ShardedCluster {
    let s0 = Arc::new(InMemoryStateEngine::new());
    s0.update_account(AccountState::new(faucet_addr(), source_funding))
        .await;
    let s1 = Arc::new(InMemoryStateEngine::new());
    let validator = ed_key(1);
    let mut cluster = ShardedCluster::new(
        sharded(),
        vec![
            (SHARD0, vec![(validator.clone(), s0)]),
            (SHARD1, vec![(validator, s1)]),
        ],
        CrossShardTransport::local(),
    );
    cluster.with_xpc_activation(XpcActivation::FromHeight(0));
    cluster
}

async fn balance(cluster: &ShardedCluster, shard: u32, addr: &[u8; 32]) -> u64 {
    cluster.shard(shard).nodes[0]
        .state
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

async fn xpc_record(
    cluster: &ShardedCluster,
    shard: u32,
    tx_hash: &[u8; 32],
) -> Option<stellereum::xshard2pc::XpcRecord> {
    cluster.shard(shard).nodes[0]
        .state
        .xpc_record(tx_hash)
        .await
}

// ===========================================================================
// 1. Same-shard PQ funding leg: the faucet PQ account funds a fresh PQ account.
// ===========================================================================

#[tokio::test]
async fn pq_funding_leg_moves_value_on_the_masterchain() {
    let _serial = PQ_SERIAL.lock().await;
    let initial = 1_000_000_000_000_000u64;
    let amount = 10_000_000_000u64;
    let mut cluster = pq_cluster(initial).await;

    // The funded sender is the faucet's own PQ account (what `send-pq
    // --falcon-seed 1111..1` derives): pin it against `Faucet::account()`.
    // (`account()` reads the mode switch, so pin it with PQ enforced.)
    post_quantum::set_pure_pq_override(Some(true));
    let faucet_account = Faucet::new(FAUCET_SEED, SHARD0, 10, 25).account();
    post_quantum::set_pure_pq_override(None);
    assert_eq!(
        faucet_addr(),
        faucet_account,
        "helper sender must equal the pure-PQ faucet account"
    );

    let tx = sign_pq_explicit_transfer(
        &faucet_keypair(),
        recip_addr(),
        amount,
        pq_gas(),
        0,
        SHARD0,
        SHARD0,
    );
    assert_verifies_under_pure_pq(&tx);
    cluster.broadcast_tx(tx).await;
    cluster.run_height(SHARD0, TS).await;

    assert_eq!(
        balance(&cluster, SHARD0, &recip_addr()).await,
        amount,
        "the fresh PQ account is funded exactly once"
    );
    assert_eq!(
        balance(&cluster, SHARD0, &faucet_addr()).await,
        initial - amount - pq_fee(),
        "the sender is debited amount + gas + surcharge"
    );
}

// ===========================================================================
// 2. A funded PQ account spends (first, explicit send verifies + applies).
// ===========================================================================

#[tokio::test]
async fn funded_pq_account_spends_with_explicit_first_send() {
    let _serial = PQ_SERIAL.lock().await;
    let initial = 1_000_000_000_000_000u64;
    let fund_amount = 10_000_000_000u64;
    let spend_amount = 1_000_000_000u64;
    let mut cluster = pq_cluster(initial).await;

    let fund = sign_pq_explicit_transfer(
        &faucet_keypair(),
        recip_addr(),
        fund_amount,
        pq_gas(),
        0,
        SHARD0,
        SHARD0,
    );
    assert_verifies_under_pure_pq(&fund);
    cluster.broadcast_tx(fund).await;
    cluster.run_height(SHARD0, TS).await;
    assert_eq!(balance(&cluster, SHARD0, &recip_addr()).await, fund_amount);

    // The recipient's first spend is explicit too (always-explicit wallet
    // policy): it carries its own pubkey, so it verifies with no prior
    // registry state and the chain registers the key on apply.
    let third = [0x77u8; 32];
    let spend = sign_pq_explicit_transfer(
        &recip_keypair(),
        third,
        spend_amount,
        pq_gas(),
        0,
        SHARD0,
        SHARD0,
    );
    assert_verifies_under_pure_pq(&spend);
    cluster.broadcast_tx(spend).await;
    cluster.run_height(SHARD0, TS + 1).await;

    assert_eq!(
        balance(&cluster, SHARD0, &third).await,
        spend_amount,
        "the second hop credits"
    );
    assert_eq!(
        balance(&cluster, SHARD0, &recip_addr()).await,
        fund_amount - spend_amount - pq_fee(),
        "the funded account debits amount + gas + surcharge, no more"
    );
}

// ===========================================================================
// 3. Cross-shard PQ transfer runs the full 2PC and credits exactly once.
// ===========================================================================

#[tokio::test]
async fn pq_cross_shard_transfer_commits_exactly_once() {
    let _serial = PQ_SERIAL.lock().await;
    let initial = 1_000_000_000_000_000u64;
    let amount = 1_500_000_000u64;
    let mut cluster = pq_cluster(initial).await;

    // PQ ACTIVATION RULE (see module docs): the faucet account is fresh
    // (16-byte leaf), so its very first spend must be same-shard — that
    // spend pins the 49-byte PQ leaf at apply. The cross-shard spend below
    // (nonce 1) then proves the pinned leaf and its opening PREPARE verifies
    // first-try. A cross-shard FIRST spend's opening PREPARE is refused at
    // target admission (16-byte proof vs 49-byte metadata skew); only the
    // slower source re-PREPARE cadence would save it.
    let pin = sign_pq_explicit_transfer(
        &faucet_keypair(),
        [0x99u8; 32],
        1_000_000,
        pq_gas(),
        0,
        SHARD0,
        SHARD0,
    );
    assert_verifies_under_pure_pq(&pin);
    cluster.broadcast_tx(pin).await;
    cluster.run_height(SHARD0, TS).await;

    let tx = sign_pq_explicit_transfer(
        &faucet_keypair(),
        recip_addr(),
        amount,
        pq_gas(),
        1,
        SHARD0,
        SHARD1,
    );
    let tx_hash = tx.compute_tx_hash();
    assert_verifies_under_pure_pq(&tx);
    cluster.broadcast_tx(tx.clone()).await;

    // Height 2 on the source: the PREPARE (NOT a plain transfer) + escrow.
    // (Height 1 ran the pin leg above, so all 2PC heights shift by one.)
    let s0_h2 = cluster.run_height(SHARD0, TS + 1).await;
    let s0_block2 = cluster.shard(SHARD0).nodes[0]
        .blocks
        .get(&s0_h2)
        .cloned()
        .expect("source block retained");
    assert!(
        s0_block2.cross_shard_out.iter().any(|m| m.is_prepare()),
        "the source must publish a PREPARE, not a bare transfer"
    );
    assert!(
        !s0_block2.cross_shard_out.iter().any(|m| m.is_transfer()),
        "a 2PC transfer must NOT be published as a plain transfer"
    );
    assert_eq!(
        s0_block2
            .cross_shard_out
            .iter()
            .find(|m| m.is_prepare())
            .map(|m| m.kind()),
        Some(CrossShardKind::Prepare)
    );
    // Escrow on top of the pin leg (1_000_000 + one fee already spent).
    let after_pin = initial - 1_000_000 - pq_fee();
    assert_eq!(
        balance(&cluster, SHARD0, &faucet_addr()).await,
        after_pin - amount - pq_fee(),
        "the source escrows the value"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD0, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Prepared),
        "the source recorded PREPARED"
    );

    // Height 2 on the target: PREPARE consumed, NO credit yet.
    cluster.run_height(SHARD1, TS + 2).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recip_addr()).await,
        0,
        "the target must NOT credit on the PREPARE"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD1, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Prepared),
        "the target recorded PREPARED and voted YES"
    );

    // Height 3 on the target: PREPARE-ACK. Height 3 on the source: COMMIT.
    cluster.run_height(SHARD1, TS + 3).await;
    assert!(
        cluster
            .transport
            .fetch_cross_shard_inbound(SHARD0)
            .await
            .iter()
            .any(|m| m.is_prepare_ack()),
        "the target must publish a PREPARE-ACK"
    );
    cluster.run_height(SHARD0, TS + 4).await;
    assert_eq!(
        xpc_record(&cluster, SHARD0, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Committed),
        "the source commits on the target's vote"
    );

    // Height 4 on the source: COMMIT published. Height 4 on the target:
    // COMMIT consumed, recipient credited exactly once.
    cluster.run_height(SHARD0, TS + 5).await;
    assert!(
        cluster
            .transport
            .fetch_cross_shard_inbound(SHARD1)
            .await
            .iter()
            .any(|m| m.is_commit()),
        "the source must publish the COMMIT"
    );
    cluster.run_height(SHARD1, TS + 6).await;
    assert_eq!(
        balance(&cluster, SHARD1, &recip_addr()).await,
        amount,
        "the recipient is credited exactly once"
    );
    assert_eq!(
        xpc_record(&cluster, SHARD1, &tx_hash)
            .await
            .map(|r| r.phase),
        Some(XpcPhase::Committed),
        "the target committed"
    );

    // More heights must not credit again; escrow released, not refunded.
    for i in 0..3 {
        cluster.run_height(SHARD0, TS + 7 + i as u64 * 2).await;
        cluster.run_height(SHARD1, TS + 8 + i as u64 * 2).await;
    }
    assert_eq!(
        balance(&cluster, SHARD1, &recip_addr()).await,
        amount,
        "a second credit would be a mint"
    );
    assert_eq!(
        balance(&cluster, SHARD0, &faucet_addr()).await,
        after_pin - amount - pq_fee(),
        "the escrow was released, not refunded"
    );
}

// ===========================================================================
// 4. Legacy ed transfers stay refused under pure-PQ (fail-closed).
// ===========================================================================

#[tokio::test]
async fn ed_transfer_stays_refused_under_pure_pq() {
    let _serial = PQ_SERIAL.lock().await;
    let sender = ed_key(2);
    let tx = Transaction::sign(&sender, [0xABu8; 32], 1_000, 1000, 0, SHARD0, SHARD0);
    post_quantum::set_pure_pq_override(Some(true));
    let ok = tx.verify_signature();
    post_quantum::set_pure_pq_override(None);
    assert!(!ok, "legacy ed25519 txs must be refused under PURE_PQ");
}
