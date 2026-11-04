//! Shared integration-test helpers.
//!
//! # THE F-01 FAILURE FEE (`PROTOCOL.md` §4c, SEC-07)
//!
//! A REFUSED transaction is **not free**. The engine charges the *failure
//! fee* and consumes the sender's nonce for an **attributable** failure (one
//! that got past admission and then failed during execution):
//!
//! | case | pays | nonce |
//! | --- | --- | --- |
//! | refused at ADMISSION (bad signature, wrong nonce, cannot cover `amount + fee`) | nothing - it never ran | unchanged |
//! | replay / nonce gap (not attributable) | nothing | unchanged |
//! | attributable failure the sender CAN cover | `max(gas_limit, consensus floor) + surcharge` | **advanced by one** |
//! | attributable failure the sender CANNOT cover | **nothing moves at all** (I15, the grief rule) | unchanged |
//!
//! WHY THE FEE EXISTS: a free failure is a free DoS. A spammer could push
//! failing transactions at the chain for nothing, and a payload that mutates
//! shared state before failing could be replayed for free. The nonce advance
//! is what makes the failure non-replayable.
//!
//! WHY THE GRIEF RULE EXISTS (I15): a transaction whose fee the sender
//! cannot cover was never going to run. "Pay what you can" would burn their
//! remaining dust for a failure they could not have known about, and a burned
//! nonce on such a failure makes their NEXT transaction impossible. So the
//! rule is atomic: an uncoverable failure moves NOTHING.
//!
//! WHAT A REFUSED TRANSACTION MUST NEVER MOVE: the VALUE it carried - the
//! `amount`, the payload's transfers/payouts, a CLOB fill, an escrow lock.
//! Only the fee may move. The helpers below state that contract ONCE, so
//! every test that pins it says exactly the same thing.
//!
//! USAGE: add `mod support;` to the test file and call
//! [`assert_refused_tx_paid_failure_fee`] (or
//! [`assert_refused_tx_moved_nothing`]) instead of hand-rolling the
//! "balance before - fee / nonce before + 1" expectation.
//!
//! # THE CONSENSUS LIVENESS HARNESS
//!
//! [`consensus_cluster`] holds a deterministic, in-process MULTI-NODE
//! consensus rig: N real `ValidatorRuntime`s with skewed round clocks, a
//! virtual clock and a seeded message pump. It is where the "the chain must
//! actually finalize" assertions live (the live 4-node WAN stand was parked
//! at height 285027 with a prevote QC but never a precommit QC, and nothing
//! in the suite covered that class of failure).
//!
//! USAGE: add `mod support;` to the test file, then
//!
//! ```ignore
//! use support::consensus_cluster::{ConsensusCluster, NodeProfile};
//!
//! #[tokio::test]
//! async fn my_scenario() {
//!     let profiles = vec![
//!         NodeProfile::default(),
//!         NodeProfile::default(),
//!         NodeProfile::default().late_by(30),
//!     ];
//!     let mut c = ConsensusCluster::with_profiles(3, profiles);
//!     c.seed_transactions(3).await;
//!     let report = c.run_until(2, 240_000).await;
//!     assert!(report.best_height >= 2, "{}", report.diagnostics());
//! }
//! ```
//!
//! [`ClusterReport::diagnostics`] is the one-call failure dump: per-node
//! height, round, prevote/precommit counts, the round the QC formed in and
//! the round the precommit was expected in.

#![allow(dead_code)]

pub mod consensus_cluster;
pub mod live_stand;

use stellereum::sharding::Transaction;
use stellereum::state_engine::InMemoryStateEngine;

/// The fee the engine charges for a refused `tx`.
///
/// The number is the ENGINE's own rule - `max(declared gas_limit, consensus
/// floor) + surcharge` (see `state_engine::consensus_floor_parts`, which is
/// the same helper admission uses) - so the expectation cannot drift from the
/// implementation.
///
/// CALL IT BEFORE the transaction is applied. The consensus floor carries the
/// D2 failure penalty, and the block path records that penalty at the END of
/// the block - so a floor read AFTER the refusal would already include the
/// penalty the refusal itself caused, and would over-state what was charged.
pub async fn failure_fee(engine: &InMemoryStateEngine, tx: &Transaction) -> u64 {
    let (floor_base, surcharge) = engine.consensus_floor_parts(tx).await;
    tx.gas_limit.max(floor_base).saturating_add(surcharge)
}

/// THE F-01 CONTRACT: after an attributable refusal the sender paid exactly
/// `fee` (the value [`failure_fee`] returned BEFORE the transaction was
/// applied) and its nonce advanced by ONE.
///
/// `balance_before` / `nonce_before` are the sender's values BEFORE the
/// refused transaction was applied.
pub async fn assert_refused_tx_paid_failure_fee(
    engine: &InMemoryStateEngine,
    tx: &Transaction,
    fee: u64,
    balance_before: u64,
    nonce_before: u64,
) {
    let acct = engine
        .get_account(&tx.from)
        .await
        .unwrap_or_else(|| panic!("the sender account must still exist"));
    assert_eq!(
        acct.balance,
        balance_before.saturating_sub(fee),
        "F-01: a refused transaction pays EXACTLY the failure fee ({fee}) and nothing else - \
         the value it carried never moved"
    );
    assert_eq!(
        acct.nonce,
        nonce_before + 1,
        "F-01: a refused transaction consumes its nonce (a failure is not free to replay)"
    );
}

/// THE GRIEF RULE (I15): a failure the sender CANNOT cover moves NOTHING -
/// no fee, no nonce, no state change at all.
pub async fn assert_refused_tx_moved_nothing(
    engine: &InMemoryStateEngine,
    tx: &Transaction,
    balance_before: u64,
    nonce_before: u64,
) {
    let acct = engine
        .get_account(&tx.from)
        .await
        .unwrap_or_else(|| panic!("the sender account must still exist"));
    assert_eq!(
        acct.balance, balance_before,
        "I15: a failure the sender cannot cover charges no fee at all"
    );
    assert_eq!(
        acct.nonce, nonce_before,
        "I15: a failure the sender cannot cover burns no nonce"
    );
}

/// The balance of `addr` (0 for an account that does not exist).
pub async fn balance_of(engine: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    engine
        .get_account(addr)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// The nonce of `addr` (0 for an account that does not exist).
pub async fn nonce_of(engine: &InMemoryStateEngine, addr: &[u8; 32]) -> u64 {
    engine.get_account(addr).await.map(|a| a.nonce).unwrap_or(0)
}
