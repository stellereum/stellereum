//! Phase-3 replay-enforcement differentials (A14 chain-binding rollout).
//!
//! The height gate (`check_admission` / `verify_transaction_envelope_at_height`)
//! used to be verify-only: no production admission path called it, so setting
//! `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` changed nothing on the block path.
//! These tests pin the wiring, one step at a time, on the SAME fixture
//! transactions (copied from `wallet_chain_binding_tests.rs`):
//!
//! * RPC submit (`stell_sendRawTransaction`) refuses with the check's message
//!   once armed, admits metre+warn when default-off;
//! * mempool insert refuses + counts once armed (defense in depth for
//!   P2P-received transactions);
//! * state-engine apply (single-tx AND block path) refuses as an
//!   ADMISSION-stage failure — nothing moves, exactly like the neighbouring
//!   chain-id mismatch (see the failure-fee contract);
//! * the activation drain drops only unbound pool entries, and only when
//!   active;
//! * with the env UNSET the full three-step path accepts byte-identically to
//!   before (default-off pin).
//!
//! Every test holds `ENV_LOCK`: the gate reads process-global env, and the
//! refusal/admission counters are process-global too, so env-touching tests
//! must not interleave — even across failure (the `ArmedEnv` guard restores
//! default-off on drop).

use std::sync::Arc;

use stellereum::chain_binding::{
    ChainBindingActivation, CHAIN_BINDING_ACTIVATION_ENV, CHAIN_BINDING_NEVER,
    UNBOUND_REFUSED_ERR_PREFIX,
};
use stellereum::governance::Governance;
use stellereum::mempool::{AdmissionCtx, Mempool, MempoolError};
use stellereum::rpc::{ReceiptIndex, RpcState};
use stellereum::sharding::{ShardRegistry, Transaction};
use stellereum::staking::StakingLedger;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::wallet::WalletAccount;

const TEST_CHAIN_ID: u64 = 5757;
const ACTIVATION_HEIGHT: u64 = 10_000;
const FUNDING: u64 = 100_000_000;

// Serializes every test in this file: the gate reads process env and the
// metrics counters are process-global.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Holds `ENV_LOCK` and the requested env state; restores default-off
/// (var removed) on drop so a panicking test cannot arm the gate for the
/// rest of the binary.
struct ArmedEnv {
    _lock: tokio::sync::MutexGuard<'static, ()>,
}

impl ArmedEnv {
    async fn arm(height: u64) -> Self {
        let lock = ENV_LOCK.lock().await;
        std::env::set_var(CHAIN_BINDING_ACTIVATION_ENV, height.to_string());
        Self { _lock: lock }
    }

    async fn off() -> Self {
        let lock = ENV_LOCK.lock().await;
        std::env::remove_var(CHAIN_BINDING_ACTIVATION_ENV);
        Self { _lock: lock }
    }
}

impl Drop for ArmedEnv {
    fn drop(&mut self) {
        std::env::remove_var(CHAIN_BINDING_ACTIVATION_ENV);
    }
}

fn wallet(seed: u8) -> WalletAccount {
    WalletAccount::from_seed(&[seed; 32])
}

/// The replay fixture: a legacy UNBOUND envelope (no chain id), fundable and
/// nonce-ready. The SAME constructor feeds the refuse/accept sides of every
/// differential below.
fn unbound_fixture(seed: u8, nonce: u64) -> Transaction {
    let tx = wallet(seed).unbound_legacy_transfer([0x99u8; 32], 1_000, nonce, 0, 0);
    assert_eq!(tx.chain_id(), None, "replay fixture must stay unbound");
    tx
}

fn bound_fixture(seed: u8, nonce: u64) -> Transaction {
    let tx = wallet(seed).create_bound_transaction([0x99u8; 32], 1_000, nonce, 0, 0, TEST_CHAIN_ID);
    assert!(tx.chain_id().is_some(), "bound fixture must carry chain id");
    tx
}

fn sender_of(tx: &Transaction) -> [u8; 32] {
    tx.from
}

async fn rpc_state(chain_id: u64, finalized_height: u64) -> Arc<RpcState> {
    let engine = Arc::new(
        InMemoryStateEngine::new().with_chain_id(chain_id),
    );
    let mempool = Arc::new(tokio::sync::RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(std::sync::atomic::AtomicU64::new(finalized_height)),
        node_id: "test:replay".to_string(),
        chain_id,
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

async fn fund(engine: &InMemoryStateEngine, addr: [u8; 32]) {
    engine
        .update_account(AccountState::new(addr, FUNDING))
        .await;
}

async fn submit(st: &RpcState, tx: &Transaction) -> serde_json::Value {
    let raw = hex::encode(bincode::serialize(tx).unwrap());
    st.call("stell_sendRawTransaction", serde_json::json!({ "tx": raw }))
        .await
}

fn refused_count() -> u64 {
    stellereum::metrics::global().snapshot().unbound_refused as u64
}

fn admitted_count() -> u64 {
    stellereum::metrics::global().snapshot().unbound_tx as u64
}

// ============================================================================
// (a) RPC submit path
// ============================================================================

/// Same unbound fixture: REFUSED with the gate's message once armed at a
/// later height, ACCEPTED with the env unset. The refusal must carry the
/// pinned prefix (wallet discovery) and must not pool anything.
#[tokio::test]
async fn rpc_refuses_replay_at_later_height_but_admits_when_gate_off() {
    // Armed: finalized just below activation, so the earliest includable
    // height (finalized+1) is exactly the activation height (the replay).
    let _env = ArmedEnv::arm(ACTIVATION_HEIGHT).await;
    let st = rpc_state(TEST_CHAIN_ID, ACTIVATION_HEIGHT - 1).await;
    let tx = unbound_fixture(0xA1, 0);
    fund(&st.engine, sender_of(&tx)).await;

    let before = refused_count();
    let r = submit(&st, &tx).await;
    let err = r["error"]
        .as_str()
        .expect("armed gate must refuse the replay fixture");
    assert!(
        err.starts_with(UNBOUND_REFUSED_ERR_PREFIX),
        "RPC refusal must carry the pinned prefix, got: {err}"
    );
    assert!(
        err.contains(&ACTIVATION_HEIGHT.to_string()),
        "RPC refusal must name the activation height, got: {err}"
    );
    assert_eq!(refused_count(), before + 1, "one refusal counts exactly once");
    assert!(
        st.mempool.read().await.is_empty(),
        "a refused tx must never enter the mempool"
    );

    // Same fixture, gate off: admitted exactly like phase 1 (hash back,
    // pooled, metered as admitted — not as refused).
    std::env::remove_var(CHAIN_BINDING_ACTIVATION_ENV);
    let admitted_before = admitted_count();
    let refused_before = refused_count();
    let r2 = submit(&st, &tx).await;
    assert!(
        r2.as_str().is_some(),
        "default-off must admit the same fixture: {r2}"
    );
    assert_eq!(st.mempool.read().await.len(), 1);
    assert_eq!(admitted_count(), admitted_before + 1);
    assert_eq!(refused_count(), refused_before);
}

/// Same-height resubmit control (armed, but height below activation) plus the
/// bound-envelope control (armed, at/after activation): both admit.
#[tokio::test]
async fn rpc_same_height_control_and_bound_control_admit_while_armed() {
    let _env = ArmedEnv::arm(ACTIVATION_HEIGHT).await;

    // Unbound BEFORE activation: history compat, admitted while armed.
    let st = rpc_state(TEST_CHAIN_ID, ACTIVATION_HEIGHT - 2).await;
    let tx = unbound_fixture(0xA2, 0);
    fund(&st.engine, sender_of(&tx)).await;
    let r = submit(&st, &tx).await;
    assert!(
        r.as_str().is_some(),
        "unbound pre-activation must admit while armed: {r}"
    );

    // Bound AT/AFTER activation: always admitted.
    let st2 = rpc_state(TEST_CHAIN_ID, ACTIVATION_HEIGHT).await;
    let bound = bound_fixture(0xA3, 0);
    fund(&st2.engine, sender_of(&bound)).await;
    let r2 = submit(&st2, &bound).await;
    assert!(
        r2.as_str().is_some(),
        "bound envelope must admit post-activation: {r2}"
    );
}

// ============================================================================
// (b) Mempool insert (defense in depth for P2P-received transactions)
// ============================================================================

/// Same unbound fixture through `add_checked_ctx` with a carried height:
/// refused + counted once armed, admitted with the env unset, admitted
/// pre-activation while armed; bound always admitted.
#[tokio::test]
async fn mempool_insert_refuses_replay_at_later_height_but_admits_when_gate_off() {
    let _env = ArmedEnv::arm(ACTIVATION_HEIGHT).await;
    let ctx_at = |h: u64| AdmissionCtx::wall_now().with_chain_height(h);

    // Armed replay at a later height: refused with the pinned message.
    let mut mp = Mempool::new(100, 100);
    let tx = unbound_fixture(0xB1, 0);
    let before = refused_count();
    let err = mp
        .add_checked_ctx(tx.clone(), u64::MAX, ctx_at(ACTIVATION_HEIGHT))
        .expect_err("armed insert must refuse the replay fixture");
    match err {
        MempoolError::UnboundRefused(msg) => assert!(
            msg.starts_with(UNBOUND_REFUSED_ERR_PREFIX),
            "insert refusal must carry the pinned prefix, got: {msg}"
        ),
        other => panic!("wrong refusal variant: {other}"),
    }
    assert!(mp.is_empty(), "a refused tx must never pool");
    assert_eq!(refused_count(), before + 1);

    // Same fixture, same height, gate off: admitted.
    std::env::remove_var(CHAIN_BINDING_ACTIVATION_ENV);
    let refused_before = refused_count();
    mp.add_checked_ctx(tx.clone(), u64::MAX, ctx_at(ACTIVATION_HEIGHT))
        .expect("default-off must admit the same fixture");
    assert_eq!(mp.len(), 1);
    assert_eq!(refused_count(), refused_before);

    // Same-height resubmit control while armed: pre-activation admits.
    std::env::set_var(CHAIN_BINDING_ACTIVATION_ENV, ACTIVATION_HEIGHT.to_string());
    let mut mp2 = Mempool::new(100, 100);
    mp2.add_checked_ctx(tx.clone(), u64::MAX, ctx_at(ACTIVATION_HEIGHT - 1))
        .expect("unbound pre-activation must admit while armed");

    // Bound control while armed, after activation: admits.
    let bound = bound_fixture(0xB2, 0);
    mp2.add_checked_ctx(bound, u64::MAX, ctx_at(ACTIVATION_HEIGHT + 5))
        .expect("bound envelope must admit post-activation");

    // Height-less callers keep legacy behaviour even while armed.
    let mut mp3 = Mempool::new(100, 100);
    mp3.add_checked_ctx(unbound_fixture(0xB3, 0), u64::MAX, AdmissionCtx::wall_now())
        .expect("height-less insert must keep legacy behaviour while armed");
}

// ============================================================================
// (c) state-engine apply (last line of defense)
// ============================================================================

async fn chained_engine() -> InMemoryStateEngine {
    InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID)
}

/// Same unbound fixture at apply time: refused once armed at a later height
/// (moving NOTHING — admission-stage, exactly like the chain-id mismatch),
/// applied with the env unset.
#[tokio::test]
async fn apply_refuses_replay_at_later_height_but_applies_when_gate_off() {
    let _env = ArmedEnv::arm(ACTIVATION_HEIGHT).await;

    // Armed replay: refused with the pinned message, state untouched.
    let engine = chained_engine().await;
    let tx = unbound_fixture(0xC1, 0);
    let from = sender_of(&tx);
    fund(&engine, from).await;
    let err = engine
        .apply_transaction_at_height(&tx, 0, ACTIVATION_HEIGHT)
        .await
        .expect_err("armed apply must refuse the replay fixture");
    assert!(
        err.starts_with(UNBOUND_REFUSED_ERR_PREFIX),
        "apply refusal must carry the pinned prefix, got: {err}"
    );
    let acct = engine.get_account(&from).await.expect("sender exists");
    assert_eq!(acct.balance, FUNDING, "admission refusal moves no funds");
    assert_eq!(acct.nonce, 0, "admission refusal consumes no nonce");

    // Same fixture, gate off: applies (value moves, nonce advances).
    std::env::remove_var(CHAIN_BINDING_ACTIVATION_ENV);
    engine
        .apply_transaction_at_height(&tx, 0, ACTIVATION_HEIGHT)
        .await
        .expect("default-off must apply the same fixture");
    let acct = engine.get_account(&from).await.expect("sender exists");
    assert_eq!(acct.nonce, 1, "an applied tx advances the nonce");
    assert!(acct.balance < FUNDING, "an applied tx charges value + fee");

    // Same-height resubmit control while armed: pre-activation applies.
    std::env::set_var(CHAIN_BINDING_ACTIVATION_ENV, ACTIVATION_HEIGHT.to_string());
    let engine2 = chained_engine().await;
    let tx2 = unbound_fixture(0xC2, 0);
    fund(&engine2, sender_of(&tx2)).await;
    engine2
        .apply_transaction_at_height(&tx2, 0, ACTIVATION_HEIGHT - 1)
        .await
        .expect("unbound pre-activation must apply while armed");

    // Bound control while armed, after activation: applies.
    let engine3 = chained_engine().await;
    let bound = bound_fixture(0xC3, 0);
    fund(&engine3, sender_of(&bound)).await;
    engine3
        .apply_transaction_at_height(&bound, 0, ACTIVATION_HEIGHT + 1)
        .await
        .expect("bound envelope must apply post-activation");
}

/// The block path judges by the COMMITTED block height: an unbound tx in a
/// post-activation block is not admitted (plain failure, no fee), while the
/// same block is fully applied with the env unset.
#[tokio::test]
async fn block_path_judges_by_committed_height() {
    let _env = ArmedEnv::arm(ACTIVATION_HEIGHT).await;

    // Armed: the tx fails admission — (0 applied, 1 failed), no fee, sender
    // untouched.
    let engine = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    let tx = unbound_fixture(0xD1, 0);
    let from = sender_of(&tx);
    fund(&engine, from).await;
    let (applied, failed, fees, status, tx_fees) = engine
        .apply_block_parallel_fees_at_height(std::slice::from_ref(&tx), 0, ACTIVATION_HEIGHT)
        .await;
    assert_eq!((applied, failed), (0, 1), "armed block path must refuse it");
    assert_eq!(status, vec![false]);
    assert_eq!(fees, 0, "an admission refusal files no fee");
    assert_eq!(tx_fees, vec![0]);
    let acct = engine.get_account(&from).await.expect("sender exists");
    assert_eq!((acct.balance, acct.nonce), (FUNDING, 0));

    // Same block, gate off: applies.
    std::env::remove_var(CHAIN_BINDING_ACTIVATION_ENV);
    let engine2 = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    fund(&engine2, from).await;
    let (applied2, failed2, _, status2, _) = engine2
        .apply_block_parallel_fees_at_height(std::slice::from_ref(&tx), 0, ACTIVATION_HEIGHT)
        .await;
    assert_eq!((applied2, failed2), (1, 0));
    assert_eq!(status2, vec![true]);
}

/// `apply_block_transition` threads `block.height` into the gate: a
/// post-activation block carrying the replay fixture fails the tx without
/// moving funds.
#[tokio::test]
async fn block_transition_threads_committed_height_into_gate() {
    use ed25519_dalek::SigningKey;

    let _env = ArmedEnv::arm(ACTIVATION_HEIGHT).await;
    let block_signer = SigningKey::from_bytes(&[0xEu8; 32]);

    let mut block = stellereum::sharding::Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: ACTIVATION_HEIGHT,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![unbound_fixture(0xD2, 0)],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: block_signer.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    block.sign_block(&block_signer);

    let engine = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    let from = sender_of(&block.transactions[0]);
    fund(&engine, from).await;
    let outcome = engine.apply_block_transition(&block, 0).await;
    assert_eq!(
        outcome.applied, 0,
        "armed transition must not apply the replay fixture"
    );
    assert_eq!(outcome.failed, 1);
    let acct = engine.get_account(&from).await.expect("sender exists");
    assert_eq!((acct.balance, acct.nonce), (FUNDING, 0));
}

// ============================================================================
// (d) activation drain + default-off pin
// ============================================================================

/// The drain drops ONLY unbound entries and ONLY when active; pre-activation
/// and default-off leave the pool untouched.
#[tokio::test]
async fn activation_drain_drops_only_unbound_and_only_when_active() {
    let _env = ArmedEnv::off().await;
    let activation = ChainBindingActivation::at_height(ACTIVATION_HEIGHT);

    // Pool both fixtures while off (same heights the replay targets).
    let mut mp = Mempool::new(100, 100);
    let unbound = unbound_fixture(0xE1, 0);
    let bound = bound_fixture(0xE2, 0);
    mp.add_checked_ctx(
        unbound,
        u64::MAX,
        AdmissionCtx::wall_now().with_chain_height(ACTIVATION_HEIGHT),
    )
    .unwrap();
    mp.add_checked_ctx(
        bound,
        u64::MAX,
        AdmissionCtx::wall_now().with_chain_height(ACTIVATION_HEIGHT),
    )
    .unwrap();
    assert_eq!(mp.len(), 2);

    // Pre-activation: no-op.
    assert_eq!(
        mp.drop_unbound_at_activation(ACTIVATION_HEIGHT - 1, &activation),
        0
    );
    assert_eq!(mp.len(), 2);

    // At activation: drops exactly the unbound one, keeps the bound one.
    let before = refused_count();
    let dropped = mp.drop_unbound_at_activation(ACTIVATION_HEIGHT, &activation);
    assert_eq!(dropped, 1);
    assert_eq!(mp.len(), 1);
    assert_eq!(refused_count(), before + 1);
    let remaining = mp.all();
    assert!(
        remaining[0].chain_id().is_some(),
        "the survivor must be the bound tx"
    );

    // Default-off at any height (even u64::MAX): no-op.
    assert_eq!(
        mp.drop_unbound_at_activation(u64::MAX, &ChainBindingActivation::never()),
        0
    );
    assert_eq!(mp.len(), 1);
}

/// Default-off pin: with the env UNSET the full three-step path (RPC submit
/// -> mempool insert -> apply) accepts the same unbound fixture, the env
/// reads as `never()`, and no refusal is ever counted. This is the
/// byte-identical-behaviour proof for the rollout's default.
#[tokio::test]
async fn default_off_full_path_accepts_with_env_unset() {
    let _env = ArmedEnv::off().await;
    assert_eq!(
        ChainBindingActivation::from_env(),
        ChainBindingActivation::never()
    );
    assert_eq!(ChainBindingActivation::never().height, CHAIN_BINDING_NEVER);
    let refused_before = refused_count();

    // Step 1 (RPC): admitted + metered as phase-1 admission.
    let st = rpc_state(TEST_CHAIN_ID, ACTIVATION_HEIGHT + 1_000).await;
    let tx_rpc = unbound_fixture(0xF1, 0);
    fund(&st.engine, sender_of(&tx_rpc)).await;
    let r = submit(&st, &tx_rpc).await;
    assert!(r.as_str().is_some(), "RPC must admit while off: {r}");

    // Step 2 (mempool insert, P2P-style with carried height): admitted.
    let mut mp = Mempool::new(100, 100);
    let tx_pool = unbound_fixture(0xF2, 0);
    mp.add_checked_ctx(
        tx_pool.clone(),
        u64::MAX,
        AdmissionCtx::wall_now().with_chain_height(u64::MAX),
    )
    .expect("insert must admit while off, at any height");

    // Step 3 (apply, single + block): applies.
    let engine = InMemoryStateEngine::new().with_chain_id(TEST_CHAIN_ID);
    let tx_apply = unbound_fixture(0xF3, 0);
    let from = sender_of(&tx_apply);
    fund(&engine, from).await;
    fund(&engine, sender_of(&tx_pool)).await;
    engine
        .apply_transaction_at_height(&tx_apply, 0, u64::MAX)
        .await
        .expect("apply must succeed while off, at any height");
    let (applied, failed, _, status, _) = engine
        .apply_block_parallel_fees_at_height(
            std::slice::from_ref(&tx_pool),
            0,
            ACTIVATION_HEIGHT,
        )
        .await;
    // NOTE: `tx_pool` was never applied (fresh engine, nonce 0) — it applies
    // here on the block path.
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(status, vec![true]);

    assert_eq!(
        refused_count(),
        refused_before,
        "default-off must never count a refusal"
    );
}
