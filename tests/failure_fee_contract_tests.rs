//! THE F-01 / SEC-07 FAILURE-FEE CONTRACT (`PROTOCOL.md` §4c), pinned in one
//! place.
//!
//! A REFUSED transaction is not free, but it is not a robbery either. The
//! policy is a four-case rule and it is the SAME on the single-transaction
//! path and on the block path:
//!
//! | case | pays | nonce |
//! | --- | --- | --- |
//! | refused at ADMISSION (bad signature, wrong nonce, cannot cover `amount + fee`) | nothing - it never ran | unchanged |
//! | replay / nonce gap (not attributable) | nothing | unchanged |
//! | attributable failure the sender CAN cover | `max(gas_limit, consensus floor) + surcharge` | **advanced by one** |
//! | attributable failure the sender CANNOT cover | **nothing moves at all** (I15, the grief rule) | unchanged |
//!
//! WHY THE FEE EXISTS (anti-DoS): a free failure is a free DoS - a spammer
//! could push failing transactions at the chain for nothing - and a failure
//! that keeps its nonce is replayable for free.
//!
//! WHY THE GRIEF RULE EXISTS (I15): a transaction whose fee the sender cannot
//! cover was never going to run. "Pay what you can" would burn their
//! remaining dust for a failure they could not have known about, and a burned
//! nonce on such a failure makes their NEXT transaction impossible. So the
//! rule is atomic: an uncoverable failure moves NOTHING.
//!
//! WHAT A REFUSED TRANSACTION MUST NEVER MOVE: the VALUE it carried - the
//! `amount`, the payload's transfers, a CLOB fill, an escrow lock. Only the
//! fee may move.
//!
//! The per-domain consequences of the same rule are pinned by the tests that
//! own them (the CLOB rollback in `clob_atomicity.rs`, the escrow refusal in
//! `clob_settlement_tests.rs`, the staking refusals in `hunt_staking_theft.rs`
//! / `hunt_staking_grief.rs` / `vuln_bundle_tests.rs`, the privacy refusals in
//! `privacy_live_tests.rs`). THIS file pins the parts that are domain
//! independent: the two rows where NOTHING may move.

use ed25519_dalek::SigningKey;

use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

mod support;
use support::{
    assert_refused_tx_moved_nothing, assert_refused_tx_paid_failure_fee, balance_of, failure_fee,
    nonce_of,
};

/// The gas a plain `OpCode::Transfer` costs (`svm::GAS_BASIC_TRANSFER` is
/// 280_000); the declared limit below must cover it.
const GAS_TRANSFER_LIMIT: u64 = 300_000;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn addr_of(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}

fn tx_of(
    k: &SigningKey,
    nonce: u64,
    amount: u64,
    gas_limit: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let from = k.verifying_key().to_bytes();
    Transaction::sign_with_payload(k, from, amount, gas_limit, nonce, 1, 1, payload)
}

async fn engine_with(balance: u64, seed: u8) -> (InMemoryStateEngine, [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let addr = addr_of(seed);
    engine
        .update_account(AccountState::new(addr, balance))
        .await;
    (engine, addr)
}

// ===========================================================================
// 1. An admission refusal moves NOTHING.
// ===========================================================================

/// ROW 1: a transaction the sender CANNOT COVER is refused at ADMISSION - it
/// never ran, so it pays no fee and consumes no nonce.
///
/// The single-transaction path and the block path must agree, and neither may
/// burn the sender's dust: "pay what you can" for a transaction that was
/// never going to run is a griefing surface, not a fee.
#[tokio::test]
async fn an_admission_refusal_moves_nothing() {
    let (engine, _addr) = engine_with(1_000, 0xA1).await;
    let k = key(0xA1);

    // amount + fee = 5_000 + 100 -> the sender holds 1_000 and cannot cover it.
    let t = tx_of(&k, 0, 5_000, 100, vec![]);

    // Single-transaction path: refused, and NOTHING moved.
    let err = engine
        .apply_transaction(&t, 0)
        .await
        .expect_err("a transaction the sender cannot cover must be refused");
    assert!(
        err.contains("Insufficient balance"),
        "the refusal must be the affordability one: {err}"
    );
    assert_refused_tx_moved_nothing(&engine, &t, 1_000, 0).await;

    // Block path: same verdict, same untouched state.
    let (applied, failed, fees, status, tx_fees) = engine
        .apply_block_parallel_fees(std::slice::from_ref(&t), 0)
        .await;
    assert_eq!((applied, failed), (0, 1), "the block path refuses it too");
    assert_eq!(status, vec![false]);
    assert_eq!(
        fees, 0,
        "an admission refusal is not free to spam, but it is free to make"
    );
    assert_eq!(
        tx_fees,
        vec![0],
        "the receipt files no fee for a transaction that never ran"
    );
    assert_refused_tx_moved_nothing(&engine, &t, 1_000, 0).await;
}

// ===========================================================================
// 2. A replay / a nonce gap is not attributable: it moves nothing.
// ===========================================================================

/// ROW 2: a REPLAY or a nonce GAP is not attributable - the transaction did
/// not fail, it was never accepted - so it moves nothing at all.
///
/// The nonce advance on an attributable failure is what makes the failure
/// non-replayable; a replay that moved state would be the hole this closes.
#[tokio::test]
async fn a_replay_or_a_nonce_gap_moves_nothing() {
    let (engine, addr) = engine_with(1_000_000, 0xA2).await;
    let k = key(0xA2);

    // A first transaction moves the account's nonce to 1.
    let first = tx_of(&k, 0, 0, 100, vec![]);
    engine
        .apply_transaction(&first, 0)
        .await
        .expect("the first transaction applies");
    assert_eq!(nonce_of(&engine, &addr).await, 1);

    // The REPLAY of it (the same nonce) is refused: it is not attributable.
    let replay = tx_of(&k, 0, 0, 100, vec![]);
    assert!(
        engine.apply_transaction(&replay, 0).await.is_err(),
        "a replay must be refused"
    );
    let after_replay = balance_of(&engine, &addr).await;
    assert_refused_tx_moved_nothing(&engine, &replay, after_replay, 1).await;

    // A GAP (a nonce in the future) is refused the same way.
    let gap = tx_of(&k, 7, 0, 100, vec![]);
    assert!(
        engine.apply_transaction(&gap, 0).await.is_err(),
        "a nonce gap must be refused"
    );
    let after_gap = balance_of(&engine, &addr).await;
    assert_refused_tx_moved_nothing(&engine, &gap, after_gap, 1).await;

    // Block path: same verdict on both.
    let (applied, failed, fees, status, tx_fees) = engine
        .apply_block_parallel_fees(&[replay.clone(), gap.clone()], 0)
        .await;
    assert_eq!((applied, failed), (0, 2));
    assert_eq!(status, vec![false, false]);
    assert_eq!(fees, 0);
    assert_eq!(
        tx_fees,
        vec![0, 0],
        "no fee for a transaction that never ran"
    );
    assert_refused_tx_moved_nothing(&engine, &replay, after_gap, 1).await;
}

// ===========================================================================
// 3. An attributable failure the sender CANNOT cover moves NOTHING (I15).
// ===========================================================================

/// ROW 4 (I15, THE GRIEF RULE): an attributable failure whose fee the sender
/// CANNOT cover moves NOTHING - no fee, no nonce, no state change.
///
/// THE SETUP: one block, two transactions from the same sender.
///
/// * tx1 MOVES value out through a payload transfer. Admission reserves only
///   `amount + fee`, so the block path charges the DECLARED limit
///   (`GAS_TRANSFER_LIMIT`) and the sender is left with
///   `10_000_000 - 9_000_000 - 300_000 = 700_000`.
/// * tx2 DECLARES a limit (1_000_000) the sender can no longer cover. It was
///   admitted (the admission reserve still saw the pre-drain balance), so
///   its refusal is ATTRIBUTABLE - the block path treats it as a failure that
///   owes the floor - but the floor is UNCOVERABLE.
///
/// The rule is atomic: nothing is charged (not even the dust), and the nonce
/// is NOT burned, so the sender's NEXT transaction is still possible.
#[tokio::test]
async fn a_failure_the_sender_cannot_cover_moves_nothing() {
    let (engine, addr) = engine_with(10_000_000, 0xA3).await;
    let k = key(0xA3);
    let sink = [0xB2; 32];

    let drain = tx_of(
        &k,
        0,
        0,
        GAS_TRANSFER_LIMIT,
        vec![OpCode::Transfer {
            recipient: sink,
            amount: 9_000_000,
        }],
    );
    // The declared limit is what the block path charges on a SUCCESS, so the
    // sender is left with exactly 700_000 - less than tx2's 1_000_000 limit.
    let doomed = tx_of(
        &k,
        1,
        0,
        1_000_000,
        vec![OpCode::Transfer {
            recipient: sink,
            amount: 1,
        }],
    );

    let (applied, failed, fees, status, tx_fees) = engine
        .apply_block_parallel_fees(&[drain.clone(), doomed.clone()], 0)
        .await;
    assert_eq!(
        (applied, failed),
        (1, 1),
        "the drain applies, the doomed one fails"
    );
    assert_eq!(status, vec![true, false]);
    assert_eq!(fees, GAS_TRANSFER_LIMIT, "only the drain paid a fee");
    assert_eq!(
        tx_fees,
        vec![GAS_TRANSFER_LIMIT, 0],
        "I15: the uncoverable failure is charged NOTHING - not even the dust"
    );

    // The sender keeps every coin it had after the drain, and its nonce was
    // not burned: the failure moves NOTHING.
    let balance_after_drain = 10_000_000 - 9_000_000 - GAS_TRANSFER_LIMIT;
    assert_eq!(
        balance_of(&engine, &addr).await,
        balance_after_drain,
        "I15: an uncoverable failure charges no fee at all"
    );
    assert_eq!(
        nonce_of(&engine, &addr).await,
        1,
        "I15: an uncoverable failure burns no nonce - the sender's next transaction stays possible"
    );
    assert_refused_tx_moved_nothing(&engine, &doomed, balance_after_drain, 1).await;

    // The VALUE did not move either: the sink holds exactly the drained
    // amount, and not one extra coin from the refused transaction.
    assert_eq!(
        balance_of(&engine, &sink).await,
        9_000_000,
        "the refused transaction moved no value - not even the 1 nano it carried"
    );
}

// ===========================================================================
// 4. The mirror image: a failure the sender CAN cover pays exactly the fee.
// ===========================================================================

/// ROW 3: an attributable failure the sender CAN cover pays EXACTLY the
/// failure fee (`max(gas_limit, consensus floor) + surcharge`) and advances
/// the nonce by ONE - and the VALUE it carried does not move.
///
/// This is the anti-DoS half of the contract, and it is the exact mirror of
/// the I15 row above: the same shape, one case apart.
#[tokio::test]
async fn an_attributable_failure_pays_exactly_the_failure_fee() {
    let (engine, addr) = engine_with(1_000_000, 0xA4).await;
    let k = key(0xA4);
    let sink = [0xB5; 32];

    // A payload transfer of 500 that the engine REFUSES: the recipient is
    // already full to the brim, so the credit overflows and `commit_native`
    // refuses the whole transaction AFTER the payload ran - an attributable
    // failure.
    engine
        .update_account(AccountState::new(sink, u64::MAX - 1))
        .await;
    let t = tx_of(
        &k,
        0,
        0,
        GAS_TRANSFER_LIMIT,
        vec![OpCode::Transfer {
            recipient: sink,
            amount: 500,
        }],
    );

    let fee = failure_fee(&engine, &t).await;
    assert_eq!(
        fee, GAS_TRANSFER_LIMIT,
        "the declared limit is the floor here"
    );
    let before = balance_of(&engine, &addr).await;
    assert!(
        engine.apply_transaction(&t, 0).await.is_err(),
        "the overflowing credit must be refused"
    );
    assert_refused_tx_paid_failure_fee(&engine, &t, fee, before, 0).await;

    // The VALUE did not move: the sender lost exactly the fee and the
    // recipient's balance is untouched (it overflowed to nothing).
    assert_eq!(
        balance_of(&engine, &sink).await,
        u64::MAX - 1,
        "the overflowed credit landed nowhere - the VALUE never moved"
    );
}
