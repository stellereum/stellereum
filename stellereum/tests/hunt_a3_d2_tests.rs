//! Hunt A3 (consensus timestamps fail-open) + D2 (free failures).
//!
//! A3: `validate_proposal_unaligned` (src/runtime.rs) skips the backward
//! timestamp check whenever `last_decision` is `None` ("fail-open for
//! liveness") and enforces the future bound against the LOCAL wall clock
//! (`now_secs() + 300`), which is non-deterministic across validators.
//! Block timestamps exist on every block, so both rules can and must be
//! deterministic functions of (parent, child) only.
//!
//! D2: error paths that cost the sender nothing —
//!   (a) `Mempool::add` (unchecked path) skips the `base_fee` floor, so
//!       zero-fee spam occupies pool slots for free;
//!   (b) a transaction that FAILS at apply pays `fee_charged == 0` while its
//!       bytes occupied block wire/gas and burned verifier CPU
//!       (`apply_block_parallel_fees` marks `failed` with `fees[i] == 0`).

use std::sync::Arc;
use tokio::sync::RwLock;

use ed25519_dalek::Signer;
use stellereum::consensus::{vote_sign_bytes, QuorumCertificate, ValidatorSet, VoteKind};
use stellereum::mempool::{Mempool, MempoolError, FAILED_SENDER_PENALTY};
use stellereum::rpc::{ReceiptIndex, RpcState};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn key(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

async fn solo_rt() -> (ValidatorRuntime, ed25519_dalek::SigningKey) {
    let k = key(0xA1);
    let me = k.verifying_key().to_bytes();
    let vs = ValidatorSet::from_list(vec![(me, 1)]);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 1_000_000_000).await;
    let rt = ValidatorRuntime::new(k.clone(), vs, st, 1);
    (rt, k)
}

fn signed_block(
    k: &ed25519_dalek::SigningKey,
    height: u64,
    prev: [u8; 32],
    root: [u8; 32],
    timestamp: u64,
) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp,
        proposer: k.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(k);
    b
}

// A3: a child timestamp behind its parent must be refused, even when
// `last_decision` is None (fresh/adopted node). Today it is accepted.
#[tokio::test]
async fn a3_backward_timestamp_refused_without_last_decision() {
    let (mut rt, k) = solo_rt().await;
    assert!(rt.last_decision.is_none(), "precondition: no last decision");
    let root = rt.state.get_state_root().await;

    let parent = signed_block(&k, 1, [0u8; 32], root, 1_000);
    let ph = parent.compute_hash();
    rt.blocks.insert(ph, parent);
    rt.finalized.push((1, ph));
    rt.hc.height = 2;

    let child = signed_block(&k, 2, ph, root, 500);
    let r = rt.validate_proposal(&child, root);
    assert!(
        r.is_err(),
        "BUG (A3): backward timestamp accepted fail-open: {r:?}"
    );
    assert!(
        r.unwrap_err().contains("backwards"),
        "refusal must name the timestamp rule"
    );
}

// A3: with no known parent at all, the verdict must be fail-closed, not
// "skip the check and accept".
#[tokio::test]
async fn a3_unknown_parent_timestamp_refused() {
    let (mut rt, k) = solo_rt().await;
    let root = rt.state.get_state_root().await;
    let ghost = [0xEEu8; 32];
    rt.finalized.push((1, ghost)); // prev-hash gate passes...
    rt.hc.height = 2;
    // ...but no body for `ghost` exists anywhere (no blocks entry, no decision).
    let child = signed_block(&k, 2, ghost, root, 2_000);
    let r = rt.validate_proposal(&child, root);
    assert!(
        r.is_err(),
        "BUG (A3): unknown-parent timestamp accepted fail-open: {r:?}"
    );
}

// A3: unbounded forward skew must be refused deterministically (vs the
// parent), not vs the wall clock. Parent+3600 is the bound; parent+3601 fails.
#[tokio::test]
async fn a3_future_jump_refused_vs_parent() {
    let (mut rt, k) = solo_rt().await;
    let root = rt.state.get_state_root().await;
    let parent = signed_block(&k, 1, [0u8; 32], root, 1_000);
    let ph = parent.compute_hash();
    rt.blocks.insert(ph, parent);
    rt.finalized.push((1, ph));
    rt.hc.height = 2;

    let edge = signed_block(&k, 2, ph, root, 1_000 + 3_600);
    assert!(
        rt.validate_proposal(&edge, root).is_ok(),
        "parent+3600 (the bound) must still admit"
    );
    let far = signed_block(&k, 2, ph, root, 1_000 + 3_601);
    let r = rt.validate_proposal(&far, root);
    assert!(
        r.is_err(),
        "BUG (A3): unbounded forward skew accepted: {r:?}"
    );
}

// A3: timestamp 0 on a non-genesis block is a missing timestamp and must be
// refused (the VM reads it as "now": unbonding/contract time at epoch 0).
#[tokio::test]
async fn a3_zero_timestamp_refused() {
    let (rt, k) = solo_rt().await;
    let root = rt.state.get_state_root().await;
    let b = signed_block(&k, 1, [0u8; 32], root, 0);
    let r = rt.validate_proposal(&b, root);
    assert!(
        r.is_err(),
        "BUG (A3): missing (zero) timestamp accepted: {r:?}"
    );
}

// A3: validation must not read the wall clock. A child 10s past a far-future
// parent is rejected today (future-drift vs `now_secs`), but deterministically
// it is perfectly monotone and must be accepted.
#[tokio::test]
async fn a3_no_wall_clock_in_timestamp_verdict() {
    let (mut rt, k) = solo_rt().await;
    let root = rt.state.get_state_root().await;
    let parent_ts: u64 = 9_000_000_000; // far ahead of any wall clock
    let parent = signed_block(&k, 1, [0u8; 32], root, parent_ts);
    let ph = parent.compute_hash();
    rt.blocks.insert(ph, parent);
    rt.finalized.push((1, ph));
    rt.hc.height = 2;

    let child = signed_block(&k, 2, ph, root, parent_ts + 10);
    let r = rt.validate_proposal(&child, root);
    assert!(
        r.is_ok(),
        "BUG (A3): wall-clock drift gate rejects a monotone timestamp: {r:?}"
    );
}

// D2a: the unchecked admission path must enforce the fee floor too — a
// below-floor transaction must not occupy pool space for free.
#[test]
fn d2_unchecked_below_floor_admits_free() {
    let mut mp = Mempool::new(100, 100).with_base_fee(100);
    let sk = key(0xB2);
    let cheap = Transaction::sign(&sk, [1u8; 32], 10, 5, 0, 1, 1);
    assert_eq!(
        mp.add(cheap),
        Err(MempoolError::FeeTooLow),
        "BUG (D2): unchecked path admits below-floor spam for free"
    );
    let ok_tx = Transaction::sign(&sk, [1u8; 32], 10, 100, 1, 1, 1);
    assert!(mp.add(ok_tx).is_ok(), "at-floor tx must still admit");
}

// D2b (gate): a sender whose transaction failed at apply must over-post to
// re-enter — the failure is no longer free to retry forever. One success
// clears the sender; other senders are unaffected.
#[test]
fn d2_failed_sender_posts_penalty_bond() {
    use stellereum::mempool::{FAILED_SENDER_PENALTY, MAX_FAILED_SENDER_PENALTY};

    let mut mp = Mempool::new(100, 100);
    let bad_sk = key(0xD4);
    let bad_sender = bad_sk.verifying_key().to_bytes();
    let good_sk = key(0xD5);

    // No penalty yet: the floor admits.
    let t0 = Transaction::sign(&bad_sk, [1u8; 32], 10, 1_000, 0, 1, 1);
    assert!(
        mp.add_checked(t0, u64::MAX).is_ok(),
        "precondition: admits clean"
    );

    // One applied-block verdict with this sender failed.
    mp.note_apply_feedback(&[bad_sender], &[]);
    assert_eq!(mp.effective_floor(&bad_sender), FAILED_SENDER_PENALTY);

    // Retry at the old fee is now refused; over-posting the bond re-admits.
    let retry_cheap = Transaction::sign(&bad_sk, [1u8; 32], 10, 1_000, 1, 1, 1);
    assert_eq!(
        mp.add_checked(retry_cheap, u64::MAX),
        Err(MempoolError::FeeTooLow),
        "a failing sender must bond to retry"
    );
    let retry_bonded = Transaction::sign(
        &bad_sk,
        [1u8; 32],
        10,
        1_000 + FAILED_SENDER_PENALTY,
        2,
        1,
        1,
    );
    assert!(
        mp.add_checked(retry_bonded, u64::MAX).is_ok(),
        "bonded retry admits"
    );

    // Escalation is capped, never runaway pricing.
    for _ in 0..100 {
        mp.note_apply_feedback(&[bad_sender], &[]);
    }
    assert_eq!(mp.effective_floor(&bad_sender), MAX_FAILED_SENDER_PENALTY);

    // An unrelated sender is untouched throughout.
    let other = Transaction::sign(&good_sk, [1u8; 32], 10, 1_000, 0, 1, 1);
    assert!(
        mp.add_checked(other, u64::MAX).is_ok(),
        "good senders unaffected"
    );

    // One success clears the failing sender entirely.
    mp.note_apply_feedback(&[], &[bad_sender]);
    assert_eq!(mp.effective_floor(&bad_sender), 0);
    let fresh = Transaction::sign(&bad_sk, [1u8; 32], 10, 1_000, 3, 1, 1);
    assert!(
        mp.add_checked(fresh, u64::MAX).is_ok(),
        "cleared sender re-admits at floor"
    );
}
#[tokio::test]
async fn d2_failed_block_tx_pays_nothing() {
    let e = InMemoryStateEngine::new();
    let sk = key(0xC3);
    let sender = sk.verifying_key().to_bytes();
    e.update_account(AccountState::new(sender, 1_000_000)).await;
    // Wrong nonce: a Byzantine proposer can include it anyway; apply fails it.
    let bad = Transaction::sign(&sk, [9u8; 32], 10, 1_000, 5, 1, 1);
    let (applied, failed, fees_collected, status, fees) = e
        .apply_block_parallel_fees(std::slice::from_ref(&bad), 1_760_000_000)
        .await;
    assert_eq!((applied, failed), (0, 1), "the bad-nonce tx must fail");
    assert_eq!(status, vec![false]);
    assert_eq!(
        fees,
        vec![0],
        "confirmed (D2): failed txs pay nothing while occupying block space"
    );
    assert_eq!(fees_collected, 0);
}

// A3 (adopt side): adopt_committed must enforce the same fail-closed
// timestamp rules as proposal validation. A block whose timestamp moved
// backwards relative to the parent must be refused.
#[tokio::test]
async fn a3_adopt_committed_refuses_backward_timestamp() {
    let (mut rt, k) = solo_rt().await;
    let root = rt.state.get_state_root().await;

    let parent = signed_block(&k, 1, [0u8; 32], root, 1_000);
    let ph = parent.compute_hash();
    rt.blocks.insert(ph, parent);
    rt.finalized.push((1, ph));
    rt.hc.height = 2;

    let child = signed_block(&k, 2, ph, root, 500); // backward: 500 < 1000
    let ch = child.compute_hash();
    let msg = vote_sign_bytes(2, 0, VoteKind::Precommit, &Some(ch));
    let sig = k.sign(&msg).to_vec();
    let cert = QuorumCertificate {
        height: 2,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(ch),
        signatures: vec![(k.verifying_key().to_bytes(), sig)],
    };

    let r = rt.adopt_committed(2, child, cert).await;
    assert!(
        r.is_err(),
        "BUG (A3): backward timestamp accepted on adopt path: {r:?}"
    );
    assert!(
        r.unwrap_err().contains("backwards"),
        "adopt_committed refusal must name the timestamp rule"
    );
}

// D2 (live block feedback): applying a block with a failed transaction
// penalizes the sender in the runtime's mempool, and the proposer skips
// pooled retries that do not pay the bond.
#[tokio::test]
async fn d2_runtime_apply_penalizes_failed_sender_and_proposer_skips() {
    let (mut rt, k) = solo_rt().await;
    let bad_sk = key(0xE1);
    let bad_sender = bad_sk.verifying_key().to_bytes();
    rt.state
        .update_account(AccountState::new(bad_sender, 10_000_000))
        .await;

    // Bad tx: wrong nonce (5 != 0).
    let bad_tx = Transaction::sign(&bad_sk, [1u8; 32], 10, 1_000, 5, 1, 1);
    let root_before = rt.state.get_state_root().await;
    let mut block = signed_block(&k, 1, [0u8; 32], root_before, 1_000);
    block.transactions = vec![bad_tx];
    block.sign_block(&k);
    let bh = block.compute_hash();

    assert_eq!(rt.mempool.read().await.effective_floor(&bad_sender), 0);

    // Apply the block directly through runtime
    rt.apply_and_advance(bh, &block).await;

    // The failed sender is now penalized in the mempool
    assert_eq!(
        rt.mempool.read().await.effective_floor(&bad_sender),
        FAILED_SENDER_PENALTY,
        "runtime apply must penalize the failed sender"
    );

    // Cheap retry (under penalty floor) is rejected by mempool
    let retry_cheap = Transaction::sign(&bad_sk, [1u8; 32], 10, 1_000, 0, 1, 1);
    assert_eq!(
        rt.mempool
            .write()
            .await
            .add_checked(retry_cheap, 10_000_000),
        Err(MempoolError::FeeTooLow)
    );

    // Bonded retry is admitted
    let bonded_tx = Transaction::sign(
        &bad_sk,
        [1u8; 32],
        10,
        1_000 + FAILED_SENDER_PENALTY,
        0,
        1,
        1,
    );
    assert!(rt
        .mempool
        .write()
        .await
        .add_checked(bonded_tx, 10_000_000)
        .is_ok());

    // Propose at height 2: proposer packs the bonded transaction
    let proposed = rt.propose(1_010).await.expect("propose must yield a block");
    assert_eq!(proposed.transactions.len(), 1);
}

// D2 (RPC admission): RPC stell_sendRawTransaction rejects unbonded retries
// from penalized senders with a clear error, and admits once the bond is posted.
#[tokio::test]
async fn d2_rpc_rejects_unbonded_retry_from_penalized_sender() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    let st = Arc::new(RpcState {
        engine: engine.clone(),
        mempool: mempool.clone(),
        height: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        node_id: "inf1:test".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });

    let bad_sk = key(0xF1);
    let bad_sender = bad_sk.verifying_key().to_bytes();
    engine
        .update_account(AccountState::new(bad_sender, 10_000_000))
        .await;

    // Penalize bad_sender via feedback
    mempool
        .write()
        .await
        .note_apply_feedback(&[bad_sender], &[]);

    // RPC stell_sendRawTransaction with unbonded fee
    let cheap_tx = Transaction::sign(&bad_sk, [1u8; 32], 10, 1_000, 0, 1, 1);
    let params_cheap = serde_json::json!({
        "tx": hex::encode(bincode::serialize(&cheap_tx).unwrap())
    });
    let res = st.call("stell_sendRawTransaction", params_cheap).await;
    assert!(
        res.get("error").is_some(),
        "RPC must reject unbonded retry from penalized sender: {res:?}"
    );
    assert!(
        res["error"]
            .as_str()
            .unwrap_or_default()
            .contains("below the base fee"),
        "error message must reflect fee floor: {res:?}"
    );

    // RPC stell_sendRawTransaction with bonded fee
    let bonded_tx = Transaction::sign(
        &bad_sk,
        [1u8; 32],
        10,
        1_000 + FAILED_SENDER_PENALTY,
        0,
        1,
        1,
    );
    let params_bonded = serde_json::json!({
        "tx": hex::encode(bincode::serialize(&bonded_tx).unwrap())
    });
    let res_ok = st.call("stell_sendRawTransaction", params_bonded).await;
    assert!(
        res_ok.get("error").is_none(),
        "RPC must admit bonded retry: {res_ok:?}"
    );
}
