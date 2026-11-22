//! ORACLE GOVERNANCE: the two deferred on-chain items.
//!
//! 1. PUBLISHER REGISTRATION. `OracleState.publishers` was already committed
//!    (commit 95df70c) but had no on-chain writer: every oracle test injected
//!    keys by hand, so "who may publish a price" was node-local configuration
//!    dressed as consensus state. It is now a `GovAction`
//!    (`RegisterOraclePublisher` / `UnregisterOraclePublisher`): a proposal that
//!    must be voted through and executed, and whose effect is a committed
//!    change to the oracle domain (and therefore to the state root).
//!
//! 2. BREAKER RESET. The circuit breaker latches automatically on a peg or
//!    deviation violation. Clearing it was a manual test-set
//!    (`oracle.breaker_tripped = false`). It is now `GovAction::ResetOracleBreaker`
//!    - only a passed vote may silence the alarm - and the cleared latch is
//!      committed like every other domain field.
//!
//! The determinism rule is the same one the oracle already pins: the only
//! writer of oracle state is the execution of a committed governance action
//! (gossip/RPC never touch it), so two nodes that apply the same passed
//! proposal land on the same root.
//!
//! NO COMMITMENT LAYOUT CHANGE: registration mutates fields that were already
//! in `OracleState`, and the publisher key is folded into the EXISTING
//! governance digest (only for the appended action variants), so
//! `COMMITMENT_VERSION` stays 4 and the genesis known-answer test is untouched.

use ed25519_dalek::SigningKey;
use serde::Serialize;
use stellereum::governance::{
    GovAction, GovError, ProposalStatus, VoteChoice, GOVERNANCE_VOTING_PERIOD_SECS,
};
use stellereum::oracle::{pq_publisher_binding, OracleState, PqPriceFeedUpdate};
use stellereum::post_quantum::FalconKeypair;
use stellereum::staking::DEFAULT_COMMISSION_BPS;
use stellereum::state_engine::InMemoryStateEngine;

/// The block timestamp every feed below is committed against.
const BLOCK_TIME: u64 = 1_700_000_000;
const STELL: u64 = 1_000_000_000;

fn publisher_kp() -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[0x42; 32])
}

fn publisher_binding() -> [u8; 32] {
    pq_publisher_binding(publisher_kp().pubkey())
}

/// A node with one bonded validator (enough to propose: >= 10k STELL and a
/// 100%-turnout quorum).
async fn gov_engine() -> (InMemoryStateEngine, [u8; 32]) {
    let e = InMemoryStateEngine::new();
    let validator = SigningKey::from_bytes(&[0x51; 32])
        .verifying_key()
        .to_bytes();
    e.credit_native(&validator, 1_000_000_000_000_000)
        .await
        .expect("fund validator");
    e.staking_write()
        .await
        .bond(validator, 100_000 * STELL, DEFAULT_COMMISSION_BPS)
        .expect("bond validator");
    (e, validator)
}

/// Drive a proposal through propose -> vote yes -> finalize, leaving it
/// `Passed` and un-executed (execution is the step each test controls, because
/// for an oracle action it needs the oracle domain).
async fn pass(e: &InMemoryStateEngine, proposer: [u8; 32], action: GovAction) -> u64 {
    let mut ledger = e.staking_read().await.clone();
    let mut gov = e.governance_write().await;
    let id = gov
        .propose(&mut ledger, proposer, "oracle governance".into(), action, 0)
        .expect("propose");
    gov.vote(&mut ledger, proposer, id, VoteChoice::Yes, 1)
        .expect("vote");
    let status = gov
        .finalize(&mut ledger, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
        .expect("finalize");
    assert_eq!(status, ProposalStatus::Passed, "unanimous vote must pass");
    drop(gov);
    id
}

/// Execute a passed proposal through the oracle-aware path: the governance
/// record AND the committed oracle move in one call.
async fn execute_with_oracle(e: &InMemoryStateEngine, proposer: [u8; 32], id: u64) {
    let mut gov = e.governance_write().await;
    let mut oracle = e.oracle_write().await;
    gov.execute_with_oracle(proposer, id, &mut oracle)
        .expect("execute passed oracle action");
}

/// Full governance registration: pass the action, then execute it.
async fn register_publisher(e: &InMemoryStateEngine, proposer: [u8; 32], pk: [u8; 32]) {
    let id = pass(e, proposer, GovAction::RegisterOraclePublisher(pk)).await;
    execute_with_oracle(e, proposer, id).await;
}

/// Commit a signed feed through the engine oracle; returns whether it committed.
///
/// Engine-level admission (the committed-state half of the old block helper;
/// the apply-path fee/nonce accounting lives one layer up in `svm`, is
/// unchanged by the feed-scheme change, and is pinned by the order entry-point
/// suites that still route orders through blocks).
async fn apply_feed(e: &InMemoryStateEngine, feed: PqPriceFeedUpdate, block_time: u64) -> bool {
    e.oracle_write()
        .await
        .commit_feed_pq(&feed, block_time)
        .is_ok()
}

fn stell_feed(price: u64, ts: u64) -> PqPriceFeedUpdate {
    PqPriceFeedUpdate::sign("STELL", price, ts, &publisher_kp())
}

// ===========================================================================
// 1. Registration is a governance action, not a manual registry write.
// ===========================================================================

#[test]
fn unregistered_publisher_feed_is_refused_even_with_a_valid_signature() {
    // The gate is authorisation, not cryptography: the signature is perfectly
    // valid, but the key is not in the committed set.
    let mut oracle = OracleState::default();
    let feed = stell_feed(250_000, BLOCK_TIME - 10);
    assert!(feed.verify(), "the signature itself is valid");
    let err = oracle
        .commit_feed_pq(&feed, BLOCK_TIME)
        .expect_err("an unregistered publisher must be refused");
    assert!(
        err.contains("publisher"),
        "the refusal must name the set: {err}"
    );
    assert!(oracle.feeds.is_empty(), "nothing may be committed");
}

#[tokio::test]
async fn passing_the_proposal_is_not_enough_only_execution_registers() {
    let (e, voter) = gov_engine().await;
    let pk = publisher_binding();

    let id = pass(&e, voter, GovAction::RegisterOraclePublisher(pk)).await;
    // Voted and passed, but NOT executed: the oracle must not have moved.
    assert!(
        !e.oracle_read().await.publishers.contains(&pk),
        "a passed-but-unexecuted proposal cannot authorise a publisher"
    );
    assert!(
        !apply_feed(&e, stell_feed(250_000, BLOCK_TIME - 10), BLOCK_TIME).await,
        "a feed cannot be committed before the action is executed"
    );

    execute_with_oracle(&e, voter, id).await;
    assert!(
        e.oracle_read().await.publishers.contains(&pk),
        "execution is what registers the publisher"
    );
    assert_eq!(
        e.governance_read().await.get(id).unwrap().status,
        ProposalStatus::Executed
    );
    // The earlier refusal committed nothing (engine-level admission moves no
    // state on refusal), so the retry commits the same feed verbatim.
    assert!(
        apply_feed(&e, stell_feed(250_000, BLOCK_TIME - 10), BLOCK_TIME).await,
        "the registered publisher's feed now commits"
    );
    assert_eq!(
        e.oracle_read().await.feeds["STELL"].price_micro_usd,
        250_000
    );
}

#[tokio::test]
async fn governance_registration_lets_a_feed_commit_and_moves_the_root() {
    let (e, voter) = gov_engine().await;
    let pk = publisher_binding();

    let before = e.get_state_root().await;
    // Before registration the same feed is refused, and the refusal commits
    // nothing — engine-level admission moves no state on refusal (the
    // apply-path fee/nonce accounting lives one layer up in `svm`).
    assert!(!apply_feed(&e, stell_feed(250_000, BLOCK_TIME - 10), BLOCK_TIME).await);
    assert_eq!(
        e.get_state_root().await,
        before,
        "a refused direct commit moves nothing"
    );
    assert!(
        e.oracle_read().await.feeds.is_empty(),
        "the refused feed commits no price"
    );

    register_publisher(&e, voter, pk).await;
    let registered = e.get_state_root().await;
    assert_ne!(registered, before, "registering a publisher is committed");

    assert!(apply_feed(&e, stell_feed(250_000, BLOCK_TIME - 10), BLOCK_TIME).await);
    assert_eq!(
        e.oracle_read().await.feeds["STELL"].price_micro_usd,
        250_000
    );
    assert_ne!(
        e.get_state_root().await,
        registered,
        "the feed is committed"
    );
}

#[tokio::test]
async fn unregister_revokes_future_feeds_but_keeps_committed_history() {
    let (e, voter) = gov_engine().await;
    let pk = publisher_binding();
    register_publisher(&e, voter, pk).await;

    assert!(apply_feed(&e, stell_feed(250_000, BLOCK_TIME - 60), BLOCK_TIME).await);
    let with_feed = e.get_state_root().await;

    let id = pass(&e, voter, GovAction::UnregisterOraclePublisher(pk)).await;
    execute_with_oracle(&e, voter, id).await;
    assert!(!e.oracle_read().await.publishers.contains(&pk));
    assert_ne!(
        e.get_state_root().await,
        with_feed,
        "revocation is committed"
    );

    // Future feeds are refused; the price already committed is history.
    assert!(!apply_feed(&e, stell_feed(251_000, BLOCK_TIME - 5), BLOCK_TIME).await);
    assert_eq!(
        e.oracle_read().await.feeds["STELL"].price_micro_usd,
        250_000,
        "revocation must not rewrite committed history"
    );
}

// ===========================================================================
// 2. Breaker reset is a governance action, not a manual latch clear.
// ===========================================================================

#[tokio::test]
async fn breaker_reset_requires_a_passed_executed_governance_action() {
    // Engine-level commit flow (the committed-state half of the old block
    // test; the apply-path fee-floor accounting it used to assert —
    // SEC-07/F-01, `max(declared, floor)` — lives one layer up in `svm`,
    // is unchanged by the feed-scheme change, and stays pinned by the order
    // entry-point suites that still route through blocks).
    let (e, voter) = gov_engine().await;
    let pk = publisher_binding();
    register_publisher(&e, voter, pk).await;

    // Seed the reference price, then trip the breaker with a 20% deviation.
    assert!(
        apply_feed(&e, stell_feed(250_000, BLOCK_TIME - 60), BLOCK_TIME).await,
        "seed feed must apply"
    );
    let root_before_trip = e.get_state_root().await;
    assert!(
        !apply_feed(&e, stell_feed(300_000, BLOCK_TIME - 30), BLOCK_TIME).await,
        "deviation feed must be refused"
    );
    assert!(
        e.oracle_read().await.breaker_tripped,
        "deviation latches the breaker"
    );
    assert_eq!(
        e.oracle_read().await.feeds["STELL"].price_micro_usd,
        250_000,
        "the deviating price must NOT have been committed"
    );
    assert_ne!(
        e.get_state_root().await,
        root_before_trip,
        "the latch itself is committed"
    );
    let tripped = e.get_state_root().await;

    // The latch refuses even a fresh, in-band feed — and the refusal commits
    // nothing, so the root is unchanged (no fee debit at this layer).
    assert!(
        !apply_feed(&e, stell_feed(251_000, BLOCK_TIME - 5), BLOCK_TIME).await,
        "latched feed must still be refused"
    );
    assert_eq!(
        e.get_state_root().await,
        tripped,
        "a refused direct commit moves nothing"
    );
    assert!(
        e.oracle_read().await.breaker_tripped,
        "the latch is still set"
    );

    // A passed-but-unexecuted reset does nothing.
    let id = pass(&e, voter, GovAction::ResetOracleBreaker).await;
    assert!(
        e.oracle_read().await.breaker_tripped,
        "voting alone must not clear it"
    );

    execute_with_oracle(&e, voter, id).await;
    assert!(
        !e.oracle_read().await.breaker_tripped,
        "execution clears the latch"
    );
    assert_ne!(e.get_state_root().await, tripped, "the reset is committed");

    // The market reopens: a fresh in-band feed commits.
    assert!(
        apply_feed(&e, stell_feed(251_000, BLOCK_TIME - 5), BLOCK_TIME).await,
        "post-reset feed must apply"
    );
    assert_eq!(
        e.oracle_read().await.feeds["STELL"].price_micro_usd,
        251_000
    );
    assert_ne!(e.get_state_root().await, tripped, "the feed is committed");
}

#[tokio::test]
async fn plain_execute_fails_closed_on_an_oracle_action() {
    let (e, voter) = gov_engine().await;
    let id = pass(&e, voter, GovAction::ResetOracleBreaker).await;

    {
        let mut gov = e.governance_write().await;
        // `execute` cannot reach the oracle, so it must refuse rather than mark
        // the proposal Executed while changing nothing.
        assert_eq!(
            gov.execute(voter, id),
            Err(GovError::InvalidAction),
            "an oracle action executed without the oracle must fail closed"
        );
        assert_eq!(
            gov.get(id).unwrap().status,
            ProposalStatus::Passed,
            "a failed execution must leave the proposal re-executable"
        );
    }

    execute_with_oracle(&e, voter, id).await;
    assert_eq!(
        e.governance_read().await.get(id).unwrap().status,
        ProposalStatus::Executed
    );
}

#[tokio::test]
async fn resetting_an_already_clear_breaker_leaves_the_oracle_unchanged() {
    let (e, voter) = gov_engine().await;
    let oracle_before = e.oracle_read().await.clone();
    let id = pass(&e, voter, GovAction::ResetOracleBreaker).await;
    execute_with_oracle(&e, voter, id).await;
    // The proposal is consumed (governance moved, so the root moves), but the
    // ORACLE is byte-for-byte unchanged: resetting a clear breaker is a no-op,
    // not a phantom state change.
    assert_eq!(
        e.oracle_read().await.clone(),
        oracle_before,
        "resetting a clear breaker must not change the oracle"
    );
    assert_eq!(
        e.governance_read().await.get(id).unwrap().status,
        ProposalStatus::Executed
    );
}

// ===========================================================================
// 3. Determinism and commitment.
// ===========================================================================

#[tokio::test]
async fn identical_governance_flows_land_on_identical_roots() {
    // Two nodes, same genesis, same passed actions, no gossip: the oracle
    // changes are derived from the committed governance state alone.
    async fn run() -> [u8; 32] {
        let (e, voter) = gov_engine().await;
        let pk = publisher_binding();
        register_publisher(&e, voter, pk).await;
        assert!(apply_feed(&e, stell_feed(250_000, BLOCK_TIME - 60), BLOCK_TIME).await);
        assert!(!apply_feed(&e, stell_feed(300_000, BLOCK_TIME - 30), BLOCK_TIME).await);
        let id = pass(&e, voter, GovAction::ResetOracleBreaker).await;
        execute_with_oracle(&e, voter, id).await;
        e.get_state_root().await
    }
    assert_eq!(
        run().await,
        run().await,
        "the same governance flow must reach the same root on every node"
    );
}

#[tokio::test]
async fn publisher_payload_is_folded_into_the_governance_digest() {
    // Two engines with identical genesis. Same proposal id/title/proposer, but
    // a different publisher key. The key must be part of the committed proposal
    // or two nodes could hold different pending registrations under one root.
    let (a, va) = gov_engine().await;
    let (b, vb) = gov_engine().await;
    assert_eq!(a.get_state_root().await, b.get_state_root().await);

    pass(&a, va, GovAction::RegisterOraclePublisher([0x11; 32])).await;
    pass(&b, vb, GovAction::RegisterOraclePublisher([0x22; 32])).await;

    assert_ne!(
        a.get_state_root().await,
        b.get_state_root().await,
        "a different publisher key in a pending proposal must move the root"
    );
}

#[tokio::test]
async fn zero_key_registration_is_rejected_at_proposal_time() {
    let (e, voter) = gov_engine().await;
    let mut ledger = e.staking_read().await.clone();
    let mut gov = e.governance_write().await;
    assert_eq!(
        gov.propose(
            &mut ledger,
            voter,
            "zero publisher".into(),
            GovAction::RegisterOraclePublisher([0u8; 32]),
            0,
        ),
        Err(GovError::InvalidAction),
        "the all-zero key is not a publisher"
    );
}

#[test]
fn gov_action_discriminants_are_append_only() {
    // `GovAction` is bincode-serialized inside committed proposals; the first
    // four bytes are the variant index. Pinning the indices proves the new
    // variants were APPENDED and that no existing action was renumbered (which
    // would change the tag `commitment.rs` writes for already-committed
    // proposals).
    fn index<A: Serialize>(a: &A) -> u32 {
        let bytes = bincode::serialize(a).expect("serialize");
        u32::from_le_bytes(bytes[0..4].try_into().unwrap())
    }
    assert_eq!(index(&GovAction::SetMinValidatorBond(1)), 0);
    assert_eq!(index(&GovAction::SetEquivocationSlashBps(1)), 1);
    assert_eq!(index(&GovAction::SetDefaultCommissionBps(1)), 2);
    assert_eq!(index(&GovAction::SetBlockReward(1)), 3);
    assert_eq!(index(&GovAction::SetPmmRedemptionBufferBps(1)), 4);
    assert_eq!(index(&GovAction::SetGovernanceQuorumBps(1)), 5);
    assert_eq!(index(&GovAction::Signal("s".into())), 6);
    assert_eq!(index(&GovAction::RegisterOraclePublisher([1; 32])), 7);
    assert_eq!(index(&GovAction::UnregisterOraclePublisher([1; 32])), 8);
    assert_eq!(index(&GovAction::ResetOracleBreaker), 9);
}

#[test]
fn oracle_action_classification() {
    assert!(GovAction::RegisterOraclePublisher([1; 32]).is_oracle_action());
    assert!(GovAction::UnregisterOraclePublisher([1; 32]).is_oracle_action());
    assert!(GovAction::ResetOracleBreaker.is_oracle_action());
    assert!(!GovAction::Signal("s".into()).is_oracle_action());
    assert!(!GovAction::SetBlockReward(1).is_oracle_action());
}

#[test]
fn oracle_registry_helpers_are_idempotent() {
    let mut o = OracleState::default();
    assert!(
        o.register_publisher([0x11; 32]),
        "first insert changes the set"
    );
    assert!(
        !o.register_publisher([0x11; 32]),
        "duplicate insert is a no-op"
    );
    assert!(
        o.unregister_publisher([0x11; 32]),
        "removal changes the set"
    );
    assert!(
        !o.unregister_publisher([0x11; 32]),
        "second removal is a no-op"
    );

    assert!(
        !o.reset_breaker(),
        "an already-clear breaker reports no change"
    );
    o.breaker_tripped = true;
    assert!(
        o.reset_breaker(),
        "clearing a latched breaker reports a change"
    );
    assert!(!o.breaker_tripped);
}
