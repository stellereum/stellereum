//! Wave 12 / `EXECUTION_PIPELINE_V1` phase 2a: runtime data structures.
//!
//! These tests pin the INERT (compiled default `u64::MAX`) contract and the
//! armed behaviour behind `set_execution_pipeline_v1_activation_override`:
//!
//! 1. below the gate `can_accept_consensus_height` is exactly
//!    `!has_pending_apply()` and the queue depth stays 1 (a second decision is
//!    refused), i.e. the historical single-slot behaviour;
//! 2. at `A = 10`, accepting height 11 requires the committed post-state of
//!    state height 9 (`committed_state_height_at(11) == 9`) and the queue
//!    accepts depth 2 but refuses depth 3;
//! 3. `PendingExecView` predicts sequential nonces/balances, marks in-flight
//!    transactions, saturates instead of underflowing, and `rebuild` from
//!    applied state heals the projection;
//! 4. the post-state-root history ring keeps only the newest 64 heights.

use ed25519_dalek::{Signer as _, SigningKey};
use std::collections::BTreeMap;
use std::sync::Arc;
use stellereum::chain_spec::{
    committed_state_height_at, execution_pipeline_v1_active_at,
    set_execution_pipeline_v1_activation_override,
};
use stellereum::consensus::{
    sync_committed_pq_registry, FalconKeypair, QuorumCertificate, ValidatorSet,
};
use stellereum::governance::{
    GovAction, ProposalStatus, VoteChoice, GOVERNANCE_VOTING_PERIOD_SECS,
};
use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
use stellereum::runtime::{
    fund_genesis, shard_genesis_block, ApplyCompleted, PendingExecView, ValidatorRuntime,
    MAX_APPLY_IN_FLIGHT_DEPTH, POST_STATE_HISTORY_CAP,
};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

/// Serialize async tests that touch the process-global committed PQ registry.
static PQ_REG_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// RAII gate override: a panicking assertion must not leak a test activation
/// into another test on the same worker thread.
struct PipelineGate;

impl PipelineGate {
    fn arm(at: u64) -> Self {
        set_execution_pipeline_v1_activation_override(Some(at));
        Self
    }

    fn clear() -> Self {
        set_execution_pipeline_v1_activation_override(None);
        Self
    }
}

impl Drop for PipelineGate {
    fn drop(&mut self) {
        set_execution_pipeline_v1_activation_override(None);
    }
}

fn runtime() -> ValidatorRuntime {
    let key = SigningKey::from_bytes(&[1u8; 32]);
    let addr = key.verifying_key().to_bytes();
    let mut validators = ValidatorSet::new();
    validators.validators.insert(addr, 1_000);
    let engine = Arc::new(InMemoryStateEngine::new());
    ValidatorRuntime::new(key, validators, engine, 1)
}

fn tx(from: [u8; 32], nonce: u64, amount: u64, gas_limit: u64) -> Transaction {
    Transaction {
        from,
        to: [0xAAu8; 32],
        amount,
        gas_limit,
        nonce,
        source_shard: MASTERCHAIN_SHARD,
        target_shard: MASTERCHAIN_SHARD,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
}

fn block_with_txs(height: u64, transactions: Vec<Transaction>) -> Block {
    let mut block = shard_genesis_block(MASTERCHAIN_SHARD, [0u8; 32], [9u8; 32], 0);
    block.height = height;
    block.transactions = transactions;
    block
}

#[test]
fn below_gate_acceptance_matches_single_slot() {
    let _gate = PipelineGate::clear();
    let mut rt = runtime();

    // Empty queue: the predicate is `!has_pending_apply()` at every height and
    // the gate is inert even at u64::MAX.
    for height in [0u64, 1, 2, 9, 10, 11, 100, 5_000, u64::MAX - 1, u64::MAX] {
        assert!(!execution_pipeline_v1_active_at(height));
        assert_eq!(
            rt.can_accept_consensus_height(height),
            !rt.has_pending_apply()
        );
        assert!(rt.can_accept_consensus_height(height));
    }
    assert_eq!(rt.apply_in_flight_depth(), 0);

    // A synthetic decision fills the single slot (the test hook mirrors
    // `prepare_decided_block`'s below-gate depth limit of 1).
    assert!(rt.debug_try_enqueue_apply_inflight(5, [1u8; 32]));
    assert_eq!(rt.apply_in_flight_depth(), 1);
    assert!(rt.has_pending_apply());
    for height in [0u64, 1, 5, 10, 11, 100, u64::MAX] {
        assert_eq!(
            rt.can_accept_consensus_height(height),
            !rt.has_pending_apply()
        );
        assert!(!rt.can_accept_consensus_height(height));
    }

    // A second decision is refused: the depth stays 1 (byte-identical to the
    // old `apply_in_flight.is_some()` gate).
    assert!(!rt.debug_try_enqueue_apply_inflight(6, [2u8; 32]));
    assert_eq!(rt.apply_in_flight_depth(), 1);
}

#[test]
fn armed_gate_requires_committed_post_state_and_bounds_depth() {
    let _gate = PipelineGate::arm(10);
    assert!(!execution_pipeline_v1_active_at(9));
    assert!(execution_pipeline_v1_active_at(10));
    assert!(execution_pipeline_v1_active_at(11));

    let mut rt = runtime();

    // Height 11 commits the post-state of state height 9. Without a recorded
    // root for 9 the decision must be refused even though the queue is empty.
    assert!(!rt.can_accept_consensus_height(11));

    rt.note_post_state_root(9, [0x11u8; 32]);
    assert!(rt.can_accept_consensus_height(11));

    // Depth: two decided blocks may queue, the third is refused.
    assert_eq!(MAX_APPLY_IN_FLIGHT_DEPTH, 2);
    assert!(rt.debug_try_enqueue_apply_inflight(10, [1u8; 32]));
    assert_eq!(rt.apply_in_flight_depth(), 1);
    assert!(rt.can_accept_consensus_height(11)); // 1 < 2, root present

    assert!(rt.debug_try_enqueue_apply_inflight(11, [2u8; 32]));
    assert_eq!(rt.apply_in_flight_depth(), 2);
    assert!(!rt.can_accept_consensus_height(11)); // depth limit reached

    assert!(!rt.debug_try_enqueue_apply_inflight(12, [3u8; 32]));
    assert_eq!(rt.apply_in_flight_depth(), 2);
}

#[test]
fn pending_exec_view_predicts_sequential_nonces_and_heals() {
    let sender = [7u8; 32];
    let mut view = PendingExecView::default();

    let applied: BTreeMap<[u8; 32], (u64, u64)> = BTreeMap::from([(sender, (0u64, 1_000_000u64))]);
    view.rebuild(&applied, &[]);
    assert_eq!(view.predicted_nonce(&sender), Some(0));
    assert_eq!(view.predicted_balance(&sender), Some(1_000_000));

    // Three sequential transactions from one sender: nonces 0, 1, 2 pack, so
    // the projection advances to nonce 3 and debits each `amount + gas_limit`
    // (a plain transaction carries no PQ/EVM surcharge).
    let block = block_with_txs(
        5,
        vec![
            tx(sender, 0, 10, 100),
            tx(sender, 1, 10, 100),
            tx(sender, 2, 10, 100),
        ],
    );
    let hashes: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(Transaction::compute_tx_hash)
        .collect();
    view.note_decided(5, &block);

    assert_eq!(view.predicted_nonce(&sender), Some(3));
    assert_eq!(view.predicted_balance(&sender), Some(1_000_000 - 3 * 110));
    for hash in &hashes {
        assert!(view.is_in_flight(hash));
    }

    // Saturating underflow: a 40-unit balance cannot be debited 200, so the
    // prediction clamps at zero instead of wrapping.
    let poor = [8u8; 32];
    let poor_applied: BTreeMap<[u8; 32], (u64, u64)> = BTreeMap::from([(poor, (0u64, 40u64))]);
    view.rebuild(&poor_applied, &[]);
    view.note_decided(6, &block_with_txs(6, vec![tx(poor, 0, 100, 100)]));
    assert_eq!(view.predicted_balance(&poor), Some(0));

    // Rebuilding from applied state discards the optimistic prediction: the
    // committed (nonce 0, balance 1_000_000) wins and no tx is in flight.
    view.rebuild(&applied, &[]);
    assert_eq!(view.predicted_nonce(&sender), Some(0));
    assert_eq!(view.predicted_balance(&sender), Some(1_000_000));
    for hash in &hashes {
        assert!(!view.is_in_flight(hash));
    }
}

#[test]
fn post_state_history_ring_keeps_only_newest_64() {
    let _gate = PipelineGate::clear();
    let mut rt = runtime();

    for height in 1..=100u64 {
        rt.note_post_state_root(height, [height as u8; 32]);
    }

    assert_eq!(POST_STATE_HISTORY_CAP, 64);
    assert_eq!(rt.post_state_roots.len(), POST_STATE_HISTORY_CAP);
    assert_eq!(rt.post_state_roots.get(&100), Some(&[100u8; 32]));

    // The newest 64 heights (37..=100) survive; the oldest 36 are pruned.
    for height in 1..=36u64 {
        assert!(
            !rt.post_state_roots.contains_key(&height),
            "height {height} should have been pruned"
        );
    }
    for height in 37..=100u64 {
        assert!(rt.post_state_roots.contains_key(&height));
    }
}

async fn make_pq_runtime(
    seed: u8,
    start_height: u64,
    bond_nano: u64,
) -> (ValidatorRuntime, SigningKey, FalconKeypair) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = key.verifying_key().to_bytes();
    let fk = FalconKeypair::generate_from_seed(seed.wrapping_add(0x40));
    let mut validators = ValidatorSet::new();
    validators.validators.insert(id, bond_nano);

    let engine = Arc::new(InMemoryStateEngine::new());
    {
        let mut ledger = engine.staking_write().await;
        ledger.bond_genesis(id, bond_nano, 0).expect("bond_genesis");
        ledger
            .validator_pq_keys
            .insert(id, (PqScheme::Falcon512, fk.public_key.clone()));
    }
    fund_genesis(&engine, &validators, bond_nano.saturating_mul(10)).await;
    {
        let mut pq_reg = engine.pq_registry_write().await;
        let _ = pq_reg.adopt_legacy_key_at(id, PqScheme::Falcon512, fk.public_key.clone(), 0, true);
        sync_committed_pq_registry(&pq_reg, true);
    }

    let rt_key = SigningKey::from_bytes(&[seed; 32]);
    let mut rt =
        ValidatorRuntime::new(rt_key, validators, engine, start_height).with_falcon_key(fk.clone());
    rt.hc.set_parent_hash([0u8; 32]);
    (rt, key, fk)
}

fn build_signed_block(
    key: &SigningKey,
    fk: &FalconKeypair,
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    timestamp: u64,
    last_qc: Option<QuorumCertificate>,
) -> Block {
    let proposer = key.verifying_key().to_bytes();
    let mut block = shard_genesis_block(MASTERCHAIN_SHARD, state_root, proposer, timestamp);
    block.height = height;
    block.prev_hash = prev_hash;
    block.last_qc = last_qc;
    let bh = block.compute_hash();
    let ed_sig = key.sign(&bh).to_bytes().to_vec();
    let fq_sig = fk.sign(&bh);
    block.validator_signatures.push((proposer, ed_sig));
    block.validator_signatures.push((fk.validator_id(), fq_sig));
    block
}

async fn vote_and_submit(rt: &mut ValidatorRuntime) -> [u8; 32] {
    let prevote = rt.make_prevote().expect("make_prevote");
    rt.on_prevote(prevote).expect("on_prevote");
    let precommit = rt.make_precommit().expect("make_precommit");
    rt.on_precommit(precommit).expect("on_precommit");
    rt.try_finalize_submit().await.expect("try_finalize_submit")
}

async fn poll_until_completed(rt: &mut ValidatorRuntime) -> ApplyCompleted {
    for _ in 0..200 {
        if let Some(done) = rt.try_poll_apply().await {
            return done;
        }
        tokio::task::yield_now().await;
    }
    panic!("ApplyLane did not complete in time");
}

#[tokio::test]
async fn apply_lane_sweeps_gov_finalize_inside_worker_when_gated() {
    let _pq_guard = PQ_REG_TEST_LOCK.lock().await;
    let h = 1u64;
    let bond = 20_000 * 1_000_000_000;
    let ts = GOVERNANCE_VOTING_PERIOD_SECS + 10;

    // 1. Sequential baseline (below gate): `try_finalize` sweeps gov after apply.
    let seq_root = {
        let _gate = PipelineGate::clear();
        let (mut rt_seq, key, fk) = make_pq_runtime(0x21, h, bond).await;
        let id = rt_seq.id;
        {
            let mut g = rt_seq.state.governance_write().await;
            let mut ledger = rt_seq.state.staking_write().await;
            let pid = g
                .propose(
                    &mut ledger,
                    id,
                    "w12-gov".into(),
                    GovAction::Signal("ok".into()),
                    0,
                )
                .expect("propose gov");
            g.vote(&mut ledger, id, pid, VoteChoice::Yes, 1)
                .expect("vote gov");
            assert!(ledger.locked_governance_of(&id) > 0);
        }
        let pre_root = rt_seq.state.get_state_root().await;
        let block = build_signed_block(&key, &fk, h, [0u8; 32], pre_root, ts, None);
        rt_seq
            .on_proposal(id, block, 0)
            .await
            .expect("on_proposal seq");
        let pv = rt_seq.make_prevote().expect("prevote seq");
        rt_seq.on_prevote(pv).expect("on_prevote seq");
        let pc = rt_seq.make_precommit().expect("precommit seq");
        rt_seq.on_precommit(pc).expect("on_precommit seq");
        assert!(rt_seq.try_finalize().await.is_some());
        assert_eq!(
            rt_seq.state.staking_read().await.locked_governance_of(&id),
            0
        );
        rt_seq.state.get_state_root().await
    };

    // 2. Armed gate at H=5: `ApplyLane` sweeps gov inside the worker BEFORE certifying `root`.
    let _gate = PipelineGate::arm(h);
    let (mut rt, key, fk) = make_pq_runtime(0x21, h, bond).await;
    let id = rt.id;
    let pid = {
        let mut g = rt.state.governance_write().await;
        let mut ledger = rt.state.staking_write().await;
        let pid = g
            .propose(
                &mut ledger,
                id,
                "w12-gov".into(),
                GovAction::Signal("ok".into()),
                0,
            )
            .expect("propose gov");
        g.vote(&mut ledger, id, pid, VoteChoice::Yes, 1)
            .expect("vote gov");
        assert!(ledger.locked_governance_of(&id) > 0);
        pid
    };
    let seeded_committed_root = [0x33u8; 32];
    rt.note_post_state_root(committed_state_height_at(h), seeded_committed_root);
    let block = build_signed_block(&key, &fk, h, [0u8; 32], seeded_committed_root, ts, None);
    let bh = block.compute_hash();

    rt.on_proposal(id, block, 0)
        .await
        .expect("on_proposal pipelined");
    let submitted = vote_and_submit(&mut rt).await;
    assert_eq!(submitted, bh);

    let completed = poll_until_completed(&mut rt).await;
    assert_eq!(completed.height, h);
    assert_eq!(completed.hash, bh);
    assert_eq!(
        completed.root, seq_root,
        "worker-certified root at/above gate must commit gov finalization bit-identical to sequential"
    );
    assert_eq!(
        rt.state
            .governance_read()
            .await
            .proposals
            .get(&pid)
            .map(|p| p.status),
        Some(ProposalStatus::Passed)
    );
    assert_eq!(rt.state.staking_read().await.locked_governance_of(&id), 0);
}

#[test]
fn can_propose_and_validate_proposal_gates_enforce_lag2_and_fail_closed() {
    // Below the gate: both helpers strictly mirror `apply_in_flight.is_empty()`.
    {
        let _gate = PipelineGate::clear();
        let mut rt = runtime();
        assert!(rt.can_propose_at_height(10));
        assert!(rt.can_validate_proposal_at_height(10));
        assert!(rt.debug_try_enqueue_apply_inflight(9, [1u8; 32]));
        assert!(!rt.can_propose_at_height(10));
        assert!(!rt.can_validate_proposal_at_height(10));
    }

    // Armed at A = 10: height 11 commits state height 9 (`committed_state_height_at(11) == 9`).
    let _gate = PipelineGate::arm(10);
    let mut rt = runtime();
    assert_eq!(committed_state_height_at(11), 9);

    // Missing committed root => both gates fail closed even when queue is empty.
    assert!(!rt.can_propose_at_height(11));
    assert!(!rt.can_validate_proposal_at_height(11));
    assert_eq!(rt.state_root_for_committed_height(11), None);

    // Note root for height 9 => both gates open.
    rt.note_post_state_root(9, [0x99u8; 32]);
    assert_eq!(rt.state_root_for_committed_height(11), Some([0x99u8; 32]));
    assert!(rt.can_propose_at_height(11));
    assert!(rt.can_validate_proposal_at_height(11));

    // Depth 1 in flight (height 10 executing): lag-2 overlap still permits proposing/validating 11.
    assert!(rt.debug_try_enqueue_apply_inflight(10, [0x10u8; 32]));
    assert_eq!(rt.apply_in_flight_depth(), 1);
    assert!(rt.can_propose_at_height(11));
    assert!(rt.can_validate_proposal_at_height(11));

    // Depth 2 in flight: `can_propose_at_height` refuses depth >= MAX_APPLY_IN_FLIGHT_DEPTH,
    // and height 12 (missing root 10) fails closed on both propose and validate.
    assert!(rt.debug_try_enqueue_apply_inflight(11, [0x11u8; 32]));
    assert_eq!(rt.apply_in_flight_depth(), 2);
    assert!(!rt.can_propose_at_height(11));
    assert!(rt.can_validate_proposal_at_height(11));
    assert!(!rt.can_propose_at_height(12));
    assert!(!rt.can_validate_proposal_at_height(12));
}

#[tokio::test]
async fn depth2_fifo_try_finalize_submit_and_try_poll_apply_preserves_post_state_roots() {
    let _pq_guard = PQ_REG_TEST_LOCK.lock().await;
    let _gate = PipelineGate::arm(3);
    let bond = 20_000 * 1_000_000_000;
    let (mut rt, key, fk) = make_pq_runtime(0x31, 1, bond).await;
    let id = rt.id;

    // Heights 1 and 2 run sequentially below the gate (A = 3), populating `post_state_roots[1]` and `[2]`.
    let b1 = rt.propose(1_700_000_000).await.expect("propose h=1");
    let bh1 = b1.compute_hash();
    assert_eq!(vote_and_submit(&mut rt).await, bh1);
    let c1 = poll_until_completed(&mut rt).await;
    assert_eq!(c1.height, 1);
    assert_eq!(rt.post_state_roots.get(&1), Some(&c1.root));

    let b2 = rt.propose(1_700_000_001).await.expect("propose h=2");
    let bh2 = b2.compute_hash();
    assert_eq!(vote_and_submit(&mut rt).await, bh2);
    let c2 = poll_until_completed(&mut rt).await;
    assert_eq!(c2.height, 2);
    assert_eq!(rt.post_state_roots.get(&2), Some(&c2.root));
    assert_eq!(rt.hc.height, 3);

    // Height 3 (at the gate): commits state height 1 (`c1.root`).
    assert!(rt.can_propose_at_height(3));
    assert!(rt.can_validate_proposal_at_height(3));
    assert_eq!(rt.state_root_for_committed_height(3), Some(c1.root));
    let qc2 = rt.last_decision.as_ref().map(|(_, _, qc)| qc.clone());
    let b3 = build_signed_block(&key, &fk, 3, bh2, c1.root, 1_700_000_002, qc2);
    let bh3 = b3.compute_hash();
    rt.on_proposal(id, b3, 0).await.expect("on_proposal h=3");
    assert_eq!(vote_and_submit(&mut rt).await, bh3);

    // Height 3 is queued in flight; consensus already moved to height 4.
    assert_eq!(rt.apply_in_flight_depth(), 1);
    assert_eq!(rt.hc.height, 4);
    assert_eq!(rt.finalized.len(), 2);
    assert!(!rt.post_state_roots.contains_key(&3));

    // Height 4 (lag-2 overlap while height 3 is still in flight): commits state height 2 (`c2.root`).
    assert!(rt.can_propose_at_height(4));
    assert!(rt.can_validate_proposal_at_height(4));
    assert_eq!(rt.state_root_for_committed_height(4), Some(c2.root));
    let qc3 = rt.last_decision.as_ref().map(|(_, _, qc)| qc.clone());
    let b4 = build_signed_block(&key, &fk, 4, bh3, c2.root, 1_700_000_003, qc3);
    let bh4 = b4.compute_hash();
    rt.on_proposal(id, b4, 0)
        .await
        .expect("on_proposal h=4 while h=3 in flight");
    assert_eq!(vote_and_submit(&mut rt).await, bh4);

    // Depth-2 queue full: height 5 cannot propose, validate, or submit yet.
    assert_eq!(rt.apply_in_flight_depth(), MAX_APPLY_IN_FLIGHT_DEPTH);
    assert_eq!(rt.hc.height, 5);
    assert!(!rt.can_propose_at_height(5));
    assert!(!rt.can_validate_proposal_at_height(5));
    assert!(rt.try_finalize_submit().await.is_none());

    // Drain FIFO: height 3 installs before height 4, recording both post-state roots.
    let done3 = poll_until_completed(&mut rt).await;
    assert_eq!(done3.height, 3);
    assert_eq!(done3.hash, bh3);
    assert_eq!(rt.post_state_roots.get(&3), Some(&done3.root));
    assert_eq!(rt.apply_in_flight_depth(), 1);

    let done4 = poll_until_completed(&mut rt).await;
    assert_eq!(done4.height, 4);
    assert_eq!(done4.hash, bh4);
    assert_eq!(rt.post_state_roots.get(&4), Some(&done4.root));
    assert_eq!(rt.apply_in_flight_depth(), 0);
    assert_eq!(rt.finalized, vec![(1, bh1), (2, bh2), (3, bh3), (4, bh4)]);
}

#[test]
fn pending_exec_view_ignores_unknown_accounts_handles_sponsored_and_guards_nonce() {
    let known = [0x11u8; 32];
    let unknown = [0x22u8; 32];
    let poor = [0x33u8; 32];
    let gapped = [0x44u8; 32];

    let user_kp = FalconKeypair::generate_from_seed(0x55);
    let sponsor_kp = FalconKeypair::generate_from_seed(0x56);
    let user_addr = derive_pq_address(PqScheme::Falcon512, &user_kp.public_key, &DEFAULT_SALT);
    let sponsor_addr =
        derive_pq_address(PqScheme::Falcon512, &sponsor_kp.public_key, &DEFAULT_SALT);

    let sponsored_tx = Transaction::sign_with_sponsor_falcon512(
        &user_kp,
        &sponsor_kp,
        [0x99u8; 32],
        250,
        280_000,
        0,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        Vec::new(),
        0,
        500_000,
        u64::MAX,
        Vec::new(),
        1,
    );
    let unknown_tx = tx(unknown, 0, 100, 100);
    let unknown_tx_hash = unknown_tx.compute_tx_hash();

    let mut view = PendingExecView::default();
    view.seed_account(known, 0, 1_000);
    view.seed_account(poor, 0, 40);
    view.seed_account(gapped, 2, 1_000);
    view.seed_account(user_addr, 0, 1_000);
    view.seed_account(sponsor_addr, 7, 500_000);

    let block = block_with_txs(
        10,
        vec![
            unknown_tx,
            tx(poor, 0, 100, 100), // balance 40 < cost 200 -> nonce must NOT advance
            tx(gapped, 5, 10, 10), // nonce 5 != 2 -> neither nonce nor balance moves
            tx(known, 0, 100, 100), // valid plain tx
            sponsored_tx.clone(),  // user pays 250, sponsor pays 280_000
        ],
    );
    view.note_decided(10, &block);

    // Unknown sender must NEVER be fabricated with balance=0.
    assert_eq!(view.predicted_nonce(&unknown), None);
    assert_eq!(view.predicted_balance(&unknown), None);
    assert!(view.is_in_flight(&unknown_tx_hash));

    // Underfunded account clamps balance at 0 and keeps nonce at 0.
    assert_eq!(view.predicted_nonce(&poor), Some(0));
    assert_eq!(view.predicted_balance(&poor), Some(0));

    // Gapped nonce is untouched.
    assert_eq!(view.predicted_nonce(&gapped), Some(2));
    assert_eq!(view.predicted_balance(&gapped), Some(1_000));

    // Known plain sender advances nonce and debits amount+gas.
    assert_eq!(view.predicted_nonce(&known), Some(1));
    assert_eq!(view.predicted_balance(&known), Some(800));

    // Sponsored tx splits legs: user pays amount + advances nonce; sponsor pays fee + PQ activation surcharge + keeps nonce.
    assert_eq!(view.predicted_nonce(&user_addr), Some(1));
    assert_eq!(view.predicted_balance(&user_addr), Some(750));
    assert_eq!(view.predicted_nonce(&sponsor_addr), Some(7));
    assert_eq!(
        view.predicted_balance(&sponsor_addr),
        Some(500_000 - (280_000 + stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS))
    );

    // Sponsored tx with an unknown sponsor must not fabricate sponsor or advance user nonce.
    let missing_sponsor_kp = FalconKeypair::generate_from_seed(0x57);
    let missing_sponsor_addr = derive_pq_address(
        PqScheme::Falcon512,
        &missing_sponsor_kp.public_key,
        &DEFAULT_SALT,
    );
    let tx_missing_sponsor = Transaction::sign_with_sponsor_falcon512(
        &user_kp,
        &missing_sponsor_kp,
        [0x99u8; 32],
        100,
        280_000,
        1,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        Vec::new(),
        0,
        500_000,
        u64::MAX,
        Vec::new(),
        1,
    );
    view.note_decided(11, &block_with_txs(11, vec![tx_missing_sponsor]));
    assert_eq!(view.predicted_nonce(&missing_sponsor_addr), None);
    assert_eq!(view.predicted_balance(&missing_sponsor_addr), None);
    assert_eq!(view.predicted_nonce(&user_addr), Some(1));
}

#[tokio::test]
async fn depth2_on_proposal_parks_h_plus_2_and_take_parked_replays_once_h_completes() {
    let _pq_guard = PQ_REG_TEST_LOCK.lock().await;
    let _gate = PipelineGate::arm(3);
    let bond = 20_000 * 1_000_000_000;

    // Shadow runtime computes the deterministic post-height-3 root.
    let expected_root_h3 = {
        let (mut shadow, s_key, s_fk) = make_pq_runtime(0x41, 1, bond).await;
        let b1 = shadow.propose(1_700_010_000).await.expect("shadow h=1");
        let bh1 = b1.compute_hash();
        assert_eq!(vote_and_submit(&mut shadow).await, bh1);
        let c1 = poll_until_completed(&mut shadow).await;

        let b2 = shadow.propose(1_700_010_001).await.expect("shadow h=2");
        let bh2 = b2.compute_hash();
        assert_eq!(vote_and_submit(&mut shadow).await, bh2);
        let _c2 = poll_until_completed(&mut shadow).await;

        let qc2 = shadow.last_decision.as_ref().map(|(_, _, qc)| qc.clone());
        let b3 = build_signed_block(&s_key, &s_fk, 3, bh2, c1.root, 1_700_010_002, qc2);
        shadow
            .on_proposal(shadow.id, b3, 0)
            .await
            .expect("shadow prop 3");
        vote_and_submit(&mut shadow).await;
        poll_until_completed(&mut shadow).await.root
    };

    let (mut rt, key, fk) = make_pq_runtime(0x41, 1, bond).await;
    let id = rt.id;

    let b1 = rt.propose(1_700_010_000).await.expect("propose h=1");
    let bh1 = b1.compute_hash();
    assert_eq!(vote_and_submit(&mut rt).await, bh1);
    let c1 = poll_until_completed(&mut rt).await;

    let b2 = rt.propose(1_700_010_001).await.expect("propose h=2");
    let bh2 = b2.compute_hash();
    assert_eq!(vote_and_submit(&mut rt).await, bh2);
    let c2 = poll_until_completed(&mut rt).await;

    // Queue H=3 and H=4 at depth 2 so `hc.height == 5` while `post_state_roots[3]` is absent.
    let qc2 = rt.last_decision.as_ref().map(|(_, _, qc)| qc.clone());
    let b3 = build_signed_block(&key, &fk, 3, bh2, c1.root, 1_700_010_002, qc2);
    let bh3 = b3.compute_hash();
    rt.on_proposal(id, b3, 0).await.expect("on_proposal h=3");
    assert_eq!(vote_and_submit(&mut rt).await, bh3);

    let qc3 = rt.last_decision.as_ref().map(|(_, _, qc)| qc.clone());
    let b4 = build_signed_block(&key, &fk, 4, bh3, c2.root, 1_700_010_003, qc3);
    let bh4 = b4.compute_hash();
    rt.on_proposal(id, b4, 0).await.expect("on_proposal h=4");
    assert_eq!(vote_and_submit(&mut rt).await, bh4);

    assert_eq!(rt.hc.height, 5);
    assert_eq!(rt.apply_in_flight_depth(), 2);
    assert!(!rt.can_validate_proposal_at_height(5));

    // Proposal for H=5 (H+2 relative to in-flight H=3) arrives at depth 2: must be PARKED.
    let qc4 = rt.last_decision.as_ref().map(|(_, _, qc)| qc.clone());
    let b5 = build_signed_block(&key, &fk, 5, bh4, expected_root_h3, 1_700_010_004, qc4);
    let bh5 = b5.compute_hash();
    let err = rt
        .on_proposal(id, b5, 0)
        .await
        .expect_err("depth-2 proposal must park while H=3 is in flight");
    assert!(err.contains("parked"), "unexpected error: {err}");
    assert!(rt.has_parked());

    // Complete H=3 (H=4 remains in flight at depth 1): `post_state_roots[3]` is now present.
    let done3 = poll_until_completed(&mut rt).await;
    assert_eq!(done3.height, 3);
    assert_eq!(done3.root, expected_root_h3);
    assert_eq!(rt.apply_in_flight_depth(), 1);
    assert!(rt.can_validate_proposal_at_height(5));

    // `take_parked` must return the parked H=5 proposal even though `parked_at.0 == hc.height`.
    let (parked_prop, parked_commit) = rt.take_parked();
    assert!(parked_commit.is_none());
    let p = parked_prop.expect("depth-2 parked proposal must replay once H completes");
    assert_eq!(p.block.height, 5);
    assert_eq!(p.block.compute_hash(), bh5);

    let accepted = rt
        .on_proposal(p.proposer, p.block, p.round)
        .await
        .expect("replayed H=5 proposal must validate and accept");
    assert_eq!(accepted, bh5);
}

#[tokio::test]
async fn pipelined_validator_rotation_stages_at_h_plus_2_across_producer_and_adopter() {
    let _pq_guard = PQ_REG_TEST_LOCK.lock().await;
    let _gate = PipelineGate::arm(3);
    let bond = 20_000 * 1_000_000_000;

    let (mut prod, p_key, p_fk) = make_pq_runtime(0x61, 1, bond).await;
    let (mut adopt, _, _) = make_pq_runtime(0x61, 1, bond).await;
    let initial_set = prod.validators.clone();

    // Advance both runtimes through heights 1 and 2 below the gate.
    for (h, ts) in [(1u64, 1_700_020_000u64), (2u64, 1_700_020_001u64)] {
        let b = prod.propose(ts).await.expect("propose");
        let bh = b.compute_hash();
        assert_eq!(vote_and_submit(&mut prod).await, bh);
        let _ = poll_until_completed(&mut prod).await;
        let (_, decided_b, qc) = prod.last_decision.clone().expect("last_decision");
        assert_eq!(
            adopt
                .adopt_committed(h, decided_b, qc)
                .await
                .expect("adopt"),
            bh
        );
    }
    assert_eq!(prod.hc.height, 3);
    assert_eq!(adopt.hc.height, 3);

    // Prepare a deterministic staking rotation at height 3 on both nodes.
    let joiner = [0xEEu8; 32];
    for rt in [&mut prod, &mut adopt] {
        rt.state
            .credit_native(&joiner, bond.saturating_mul(2))
            .await
            .expect("credit joiner");
        rt.state
            .staking_write()
            .await
            .bond(joiner, bond, 0)
            .expect("bond joiner");
    }

    // Height 3 decides on producer (`hc.height` immediately moves to 4 with `initial_set`).
    let root1 = prod.post_state_roots[&1];
    let bh2 = prod.finalized.last().unwrap().1;
    let qc2 = prod.last_decision.as_ref().map(|(_, _, qc)| qc.clone());
    let b3 = build_signed_block(&p_key, &p_fk, 3, bh2, root1, 1_700_020_002, qc2);
    let bh3 = b3.compute_hash();
    prod.on_proposal(prod.id, b3, 0).await.expect("prop h=3");
    assert_eq!(vote_and_submit(&mut prod).await, bh3);
    let (_, decided_b3, qc3) = prod.last_decision.clone().expect("decided 3");
    assert_eq!(prod.hc.height, 4);
    assert_eq!(prod.hc.validators.validators, initial_set.validators);

    // Height 3 finishes on producer: rotation MUST stage at `3 + 2 = 5`, NEVER mutate H=4 mid-height.
    let done3 = poll_until_completed(&mut prod).await;
    assert_eq!(done3.height, 3);
    assert_eq!(
        prod.pending_validators.as_ref().map(|(act, _)| *act),
        Some(5),
        "pipelined rotation at height 3 must stage for activation at 5"
    );
    assert_eq!(
        prod.validators.validators, initial_set.validators,
        "producer must not mutate in-force set during height 4"
    );
    assert_eq!(
        prod.hc.validators.validators, initial_set.validators,
        "producer hc.validators must not mutate mid-height 4"
    );

    // Adopter adopts height 3: must agree identically (H=4 keeps old set, H=5 staged).
    assert_eq!(
        adopt
            .adopt_committed(3, decided_b3, qc3)
            .await
            .expect("adopt h=3"),
        bh3
    );
    assert_eq!(adopt.hc.height, 4);
    assert_eq!(
        adopt.pending_validators.as_ref().map(|(act, _)| *act),
        Some(5)
    );
    assert_eq!(adopt.validators.validators, initial_set.validators);
    assert_eq!(adopt.hc.validators.validators, initial_set.validators);

    // Height 4 decides/adopts: transitioning into height 5 activates the rotated set on both.
    let root2 = prod.post_state_roots[&2];
    let qc3_ref = prod.last_decision.as_ref().map(|(_, _, qc)| qc.clone());
    let b4 = build_signed_block(&p_key, &p_fk, 4, bh3, root2, 1_700_020_003, qc3_ref);
    let bh4 = b4.compute_hash();
    prod.on_proposal(prod.id, b4, 0).await.expect("prop h=4");
    assert_eq!(vote_and_submit(&mut prod).await, bh4);
    let (_, decided_b4, qc4) = prod.last_decision.clone().expect("decided 4");
    assert_eq!(prod.hc.height, 5);
    assert!(prod.validators.validators.contains_key(&joiner));
    assert!(prod.hc.validators.validators.contains_key(&joiner));

    assert_eq!(
        adopt
            .adopt_committed(4, decided_b4, qc4)
            .await
            .expect("adopt h=4"),
        bh4
    );
    assert_eq!(adopt.hc.height, 5);
    assert_eq!(prod.validators.validators, adopt.validators.validators);
    assert_eq!(
        prod.hc.validators.validators,
        adopt.hc.validators.validators
    );
    assert_eq!(
        prod.validator_set_for_height(4).validators,
        adopt.validator_set_for_height(4).validators
    );
    assert_eq!(
        prod.validator_set_for_height(5).validators,
        adopt.validator_set_for_height(5).validators
    );
}

#[tokio::test]
async fn genesis_and_snapshot_post_state_roots_seeding_enables_lag2() {
    let _pq_guard = PQ_REG_TEST_LOCK.lock().await;
    let _gate = PipelineGate::arm(0);
    let bond = 20_000 * 1_000_000_000;

    // 1. Fresh genesis runtime (post_state_roots starts empty because anchors.rs is unchanged):
    //    fallback permits height 1, and `ensure_genesis_root_seeded` populates `post_state_roots[0]`
    //    so height 2 overlaps while height 1 is in flight.
    let (mut rt, _, _) = make_pq_runtime(0x71, 1, bond).await;
    assert!(rt.post_state_roots.is_empty());
    assert!(rt.can_propose_at_height(1));
    assert!(rt.can_validate_proposal_at_height(1));
    assert!(rt.can_accept_consensus_height(1));

    rt.ensure_genesis_root_seeded().await;
    let genesis_root = rt.state.get_state_root().await;
    assert_eq!(rt.post_state_roots.get(&0), Some(&genesis_root));

    let b1 = rt
        .propose(1_700_030_000)
        .await
        .expect("propose genesis child h=1");
    assert_eq!(b1.state_root, genesis_root);
    let bh1 = b1.compute_hash();
    assert_eq!(vote_and_submit(&mut rt).await, bh1);
    assert_eq!(rt.hc.height, 2);
    assert_eq!(rt.apply_in_flight_depth(), 1);
    assert!(rt.can_propose_at_height(2));
    assert!(rt.can_validate_proposal_at_height(2));
    assert!(rt.can_accept_consensus_height(2));

    // 2. Snapshot / restart seeding: `advance_to_verified_snapshot` seeds `boundary`, and
    //    `advance_to_verified_snapshot_with_roots` seeds both `boundary` and `boundary - 1`.
    let mut snap_rt = runtime();
    let root49 = [0x49u8; 32];
    let root50 = [0x50u8; 32];
    snap_rt.advance_to_verified_snapshot_with_roots(50, [0xAAu8; 32], root50, Some(root49));
    assert_eq!(snap_rt.hc.height, 51);
    assert_eq!(snap_rt.post_state_roots.get(&50), Some(&root50));
    assert_eq!(snap_rt.post_state_roots.get(&49), Some(&root49));
    assert!(snap_rt.can_propose_at_height(51));
    assert!(snap_rt.can_validate_proposal_at_height(51));
    assert!(snap_rt.can_accept_consensus_height(51));
    assert_eq!(snap_rt.state_root_for_committed_height(51), Some(root49));
}

#[tokio::test]
async fn adopt_committed_fails_closed_when_apply_worker_drops() {
    let _pq_guard = PQ_REG_TEST_LOCK.lock().await;
    let _gate = PipelineGate::arm(0);
    let bond = 20_000 * 1_000_000_000;

    let (mut prod, _, _) = make_pq_runtime(0x79, 1, bond).await;
    prod.ensure_genesis_root_seeded().await;
    let b1 = prod.propose(1_700_040_000).await.expect("propose h=1");
    let bh1 = b1.compute_hash();
    assert_eq!(vote_and_submit(&mut prod).await, bh1);
    let b2 = prod.propose(1_700_040_001).await.expect("propose h=2");
    let bh2 = b2.compute_hash();
    assert_eq!(vote_and_submit(&mut prod).await, bh2);
    let (_, decided_b2, qc2) = prod.last_decision.clone().expect("decided h=2");

    let (mut rt, _, _) = make_pq_runtime(0x79, 1, bond).await;
    rt.ensure_genesis_root_seeded().await;
    // Enqueue height 1 in-flight with matching hash `bh1` whose sender is
    // dropped immediately (simulating a panicked/closed ApplyLane worker),
    // and advance consensus height to 2 so `b2` passes all header/QC checks.
    assert!(rt.debug_try_enqueue_apply_inflight(1, bh1));
    rt.hc.height = 2;
    rt.hc.set_parent_hash(bh1);
    assert_eq!(rt.apply_in_flight_depth(), 1);

    let err = rt
        .adopt_committed(2, decided_b2, qc2)
        .await
        .expect_err("adopt_committed must fail closed if apply worker drops");
    assert!(
        err.contains("worker") || err.contains("closed") || err.contains("terminated"),
        "unexpected error: {err}"
    );
}
