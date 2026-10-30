//! E-series regression pins (governance/oracle HIGHs left open after E3/E5/E8).
//!
//! - E4: unbounded governance strings (proposal title + `Signal` text).
//! - E6: `RegisterOraclePublisher` zero-key missing at execute time.
//! - E7 (FIXED): vote-then-exit flips a Rejected proposal to Passed
//!   (denominator drifted, weight persisted). Fixed by freezing the quorum
//!   base at propose time and locking voters' stake until finalization.
//! - E9: zero-price feed commits.
//! - E10: arbitrary asset symbols commit.
//!
//! E4/E6/E7/E9/E10 assert the FIXED (fail-closed) behavior and FAIL on the
//! unfixed code.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use stellereum::governance::{
    GovAction, GovError, Governance, Proposal, ProposalStatus, VoteChoice,
    GOVERNANCE_VOTING_PERIOD_SECS,
};
use stellereum::oracle::{OracleState, PriceFeedUpdate};
use stellereum::staking::{StakingLedger, DEFAULT_COMMISSION_BPS, UNBONDING_PERIOD_SECS};

const BLOCK_TIME: u64 = 1_700_000_000;

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

fn pubkey(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

/// Ledger: validator A (10k self), validator C (10k self, silent),
/// delegator B (9k delegated to A). Total voting power = 29k STELL.
fn ledger_29k() -> (StakingLedger, [u8; 32], [u8; 32], [u8; 32]) {
    let a = [0xA1u8; 32];
    let b = [0xB2u8; 32];
    let c = [0xC3u8; 32];
    let mut l = StakingLedger::new();
    l.bond(a, stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
    l.bond(c, stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
    l.delegate(b, a, stell(9_000)).unwrap();
    assert_eq!(Governance::total_voting_power(&l), stell(29_000) as u128);
    (l, a, b, c)
}

fn oracle_with_publisher(sk: &SigningKey) -> (OracleState, [u8; 32]) {
    let mut o = OracleState::default();
    let pk = sk.verifying_key().to_bytes();
    o.publishers.insert(pk);
    (o, pk)
}

// ---------- E4: title length ----------

#[test]
fn e4_oversize_title_rejected_at_propose_time() {
    let (mut l, a, _, _) = ledger_29k();
    let mut g = Governance::new();
    let big = "t".repeat(257);
    assert_eq!(
        g.propose(&mut l, a, big, GovAction::Signal("ok".into()), 0),
        Err(GovError::InvalidAction),
        "E4: 257B title must be refused"
    );
    // Boundary: 256B is accepted.
    let ok_title = "t".repeat(256);
    assert!(
        g.propose(&mut l, a, ok_title, GovAction::Signal("ok".into()), 0)
            .is_ok(),
        "E4: 256B title must be accepted"
    );
}

#[test]
fn e4_oversize_title_fails_closed_at_execute_time() {
    let (l, a, _, _) = ledger_29k();
    let mut g = Governance::new();
    // Smuggle past propose-time validation via direct insert.
    let id = g.next_id;
    g.next_id += 1;
    g.proposals.insert(
        id,
        Proposal {
            id,
            proposer: a,
            title: "t".repeat(10_000),
            action: GovAction::Signal("ok".into()),
            created_at: 0,
            voting_end: GOVERNANCE_VOTING_PERIOD_SECS,
            yes: 0,
            no: 0,
            abstain: 0,
            voters: HashMap::new(),
            status: ProposalStatus::Passed,
            electorate: 0,
            electorate_weights: None,
            proposer_lock: 0,
            weights: HashMap::new(),
        },
    );
    let _ = &l;
    assert_eq!(
        g.execute(a, id),
        Err(GovError::InvalidAction),
        "E4: oversize title must fail closed at execution"
    );
    assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
}

// ---------- E4: Signal length ----------

#[test]
fn e4_oversize_signal_rejected_at_propose_time() {
    let (mut l, a, _, _) = ledger_29k();
    let mut g = Governance::new();
    assert_eq!(
        g.propose(&mut l, a, "t".into(), GovAction::Signal("s".repeat(1025)), 0),
        Err(GovError::InvalidAction),
        "E4: 1025B signal must be refused"
    );
    assert!(
        g.propose(&mut l, a, "t".into(), GovAction::Signal("s".repeat(1024)), 0)
            .is_ok(),
        "E4: 1024B signal must be accepted"
    );
}

#[test]
fn e4_oversize_signal_fails_closed_at_execute_time() {
    let (l, a, _, _) = ledger_29k();
    let mut g = Governance::new();
    let id = g.next_id;
    g.next_id += 1;
    g.proposals.insert(
        id,
        Proposal {
            id,
            proposer: a,
            title: "t".into(),
            action: GovAction::Signal("s".repeat(1_000_000)),
            created_at: 0,
            voting_end: GOVERNANCE_VOTING_PERIOD_SECS,
            yes: 0,
            no: 0,
            abstain: 0,
            voters: HashMap::new(),
            status: ProposalStatus::Passed,
            electorate: 0,
            electorate_weights: None,
            proposer_lock: 0,
            weights: HashMap::new(),
        },
    );
    let _ = &l;
    assert_eq!(
        g.execute(a, id),
        Err(GovError::InvalidAction),
        "E4: oversize signal must fail closed at execution"
    );
    assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
    assert!(g.applied.signal.is_none());
}

// ---------- E6: zero-key publisher execute backstop ----------

#[test]
fn e6_zero_key_publisher_fails_closed_at_execute_time() {
    let (mut l, a, _, _) = ledger_29k();
    let mut g = Governance::new();
    // Propose-time already refuses it (pinned); the hole is execute-time.
    assert_eq!(
        g.propose(
            &mut l,
            a,
            "z".into(),
            GovAction::RegisterOraclePublisher([0u8; 32]),
            0
        ),
        Err(GovError::InvalidAction)
    );
    // Smuggle past propose-time validation via direct insert.
    let id = g.next_id;
    g.next_id += 1;
    g.proposals.insert(
        id,
        Proposal {
            id,
            proposer: a,
            title: "sneaky".into(),
            action: GovAction::RegisterOraclePublisher([0u8; 32]),
            created_at: 0,
            voting_end: GOVERNANCE_VOTING_PERIOD_SECS,
            yes: 0,
            no: 0,
            abstain: 0,
            voters: HashMap::new(),
            status: ProposalStatus::Passed,
            electorate: 0,
            electorate_weights: None,
            proposer_lock: 0,
            weights: HashMap::new(),
        },
    );
    let mut oracle = OracleState::default();
    assert_eq!(
        g.execute_with_oracle(a, id, &mut oracle),
        Err(GovError::InvalidAction),
        "E6: zero-key registration must fail closed at execution"
    );
    assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
    assert!(
        !oracle.publishers.contains(&[0u8; 32]),
        "E6: the zero key must never enter the committed publisher set"
    );
}

#[test]
fn e6_oracle_registry_itself_refuses_the_zero_key() {
    let mut o = OracleState::default();
    assert!(
        !o.register_publisher([0u8; 32]),
        "E6: OracleState must refuse the all-zero key"
    );
    assert!(!o.publishers.contains(&[0u8; 32]));
    // Non-zero keys are unaffected.
    assert!(o.register_publisher([0x11u8; 32]));
    assert!(o.publishers.contains(&[0x11u8; 32]));
}

// ---------- E7: vote-then-exit cannot flip the outcome (FIXED) ----------

/// E7 FIXED: the quorum base is frozen at propose time and a voter's weight
/// is locked in the staking ledger until finalization. 29k total needs
/// 19,331 (19k turnout falls short); yes-voter B's 9k exit is refused while
/// the vote is open, and finalization measures the 19k against the frozen
/// 29k base — Rejected stays Rejected. Locks release on the terminal
/// transition, so the exit succeeds after finalization.
#[test]
fn e7_vote_then_exit_cannot_flip_rejected_to_passed() {
    use stellereum::staking::StakingError;

    // World 1: finalize with the electorate intact -> Rejected.
    let (mut l1, a1, b1, _) = ledger_29k();
    let mut g1 = Governance::new();
    let id1 = g1
        .propose(&mut l1, a1, "t".into(), GovAction::Signal("t".into()), 0)
        .unwrap();
    assert_eq!(g1.get(id1).unwrap().electorate, stell(29_000) as u128);
    g1.vote(&mut l1, a1, id1, VoteChoice::Yes, 1).unwrap(); // 10k
    g1.vote(&mut l1, b1, id1, VoteChoice::Yes, 1).unwrap(); // 9k
    assert_eq!(g1.get(id1).unwrap().turnout(), stell(19_000) as u128);
    let s1 = g1
        .finalize(&mut l1, id1, GOVERNANCE_VOTING_PERIOD_SECS + 1)
        .unwrap();
    assert_eq!(
        s1,
        ProposalStatus::Rejected,
        "19k < 19331 quorum on 29k base"
    );

    // World 2: identical votes, then yes-voter B tries to exit before finalize.
    let (mut l2, a2, b2, _) = ledger_29k();
    let mut g2 = Governance::new();
    let id2 = g2
        .propose(&mut l2, a2, "t".into(), GovAction::Signal("t".into()), 0)
        .unwrap();
    g2.vote(&mut l2, a2, id2, VoteChoice::Yes, 1).unwrap();
    g2.vote(&mut l2, b2, id2, VoteChoice::Yes, 1).unwrap();
    assert_eq!(
        l2.undelegate(b2, a2, stell(9_000), 1),
        Err(StakingError::LockedInGovernanceVote),
        "E7: stake locked in an open vote must not exit"
    );
    let s2 = g2
        .finalize(&mut l2, id2, GOVERNANCE_VOTING_PERIOD_SECS + 1)
        .unwrap();
    assert_eq!(
        s2,
        ProposalStatus::Rejected,
        "E7: the frozen 29k base still needs 19,331 — no flip without a new vote"
    );
    // Terminal transition released the locks: the exit now succeeds.
    l2.undelegate(b2, a2, stell(9_000), 2).unwrap();
    l2.process_unbonding(UNBONDING_PERIOD_SECS + 3).unwrap();
    assert_eq!(Governance::total_voting_power(&l2), stell(20_000) as u128);
}

// ---------- E9: zero-price feed ----------

#[test]
fn e9_zero_price_feed_is_refused_without_commit_or_latch() {
    let sk = pubkey(0x42);
    let (mut o, _) = oracle_with_publisher(&sk);
    let zero = PriceFeedUpdate::sign("STELL", 0, BLOCK_TIME - 10, &sk);
    let err = o
        .commit_feed(&zero, BLOCK_TIME)
        .expect_err("E9: price 0 must be refused");
    assert!(
        err.contains("price"),
        "refusal must name the price, got: {err}"
    );
    assert!(o.feeds.is_empty(), "E9: nothing may be committed");
    assert!(!o.breaker_tripped, "E9: malformed data latches nothing");
}

#[test]
fn e9_zero_price_usdt_is_malformed_not_a_depeg_latch() {
    let sk = pubkey(0x42);
    let (mut o, _) = oracle_with_publisher(&sk);
    let zero = PriceFeedUpdate::sign("USDT", 0, BLOCK_TIME - 10, &sk);
    let err = o
        .commit_feed(&zero, BLOCK_TIME)
        .expect_err("E9: price 0 must be refused");
    assert!(err.contains("price"), "got: {err}");
    assert!(o.feeds.is_empty());
    assert!(
        !o.breaker_tripped,
        "E9: a zero price is malformed input, not market evidence of a depeg"
    );
}

// ---------- E10: asset-symbol shape ----------

#[test]
fn e10_malformed_asset_symbols_are_refused() {
    let sk = pubkey(0x42);
    for bad in [
        "",
        " ",
        "ST ELL",
        "STELL!",
        "stell$",
        &"A".repeat(33),
        &"X".repeat(1024),
    ] {
        let (mut o, _) = oracle_with_publisher(&sk);
        let feed = PriceFeedUpdate::sign(bad, 250_000, BLOCK_TIME - 10, &sk);
        let err = o
            .commit_feed(&feed, BLOCK_TIME)
            .expect_err(&format!("E10: asset {bad:?} must be refused"));
        assert!(
            err.contains("asset"),
            "refusal must name the asset, got: {err}"
        );
        assert!(o.feeds.is_empty());
        assert!(!o.breaker_tripped);
    }
}

#[test]
fn e10_legitimate_assets_still_commit() {
    let sk = pubkey(0x42);
    for asset in ["STELL", "USDT", "TON", "BTC", "STELL/USDT"] {
        let (mut o, _) = oracle_with_publisher(&sk);
        let price = if asset == "USDT" { 1_000_000 } else { 250_000 };
        let feed = PriceFeedUpdate::sign(asset, price, BLOCK_TIME - 10, &sk);
        assert!(
            o.commit_feed(&feed, BLOCK_TIME).is_ok(),
            "E10: legitimate asset {asset:?} must still commit"
        );
        assert_eq!(o.feeds[asset].price_micro_usd, price);
    }
}

// ---------- B-GOV/G1: frozen electorate admits late-bond inflation ----------
//
// The E7 fix froze the quorum base at propose time and locks VOTERS' stake,
// but stake bonded AFTER propose votes at full weight without raising the
// base. Turnout can therefore exceed the electorate the quorum was computed
// against: a late-bonded whale boosts its own proposal mid-vote.
// DESIRED: turnout <= electorate. FAILS on current code (40k > 30k).

#[test]
fn bgov_late_bond_inflates_turnout_past_frozen_electorate() {
    let a = [0xA1u8; 32];
    let b = [0xB2u8; 32];
    let c = [0xC3u8; 32];
    let d = [0xD4u8; 32];
    let mut l = StakingLedger::new();
    for id in [a, b, c] {
        l.bond(id, stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
    }
    let mut g = Governance::new();
    let id = g
        .propose(&mut l, a, "x".into(), GovAction::Signal("t".into()), 0)
        .expect("propose");
    assert_eq!(g.get(id).unwrap().electorate, stell(30_000) as u128);
    g.vote(&mut l, a, id, VoteChoice::Yes, 1).unwrap();
    g.vote(&mut l, b, id, VoteChoice::Yes, 1).unwrap();
    g.vote(&mut l, c, id, VoteChoice::Yes, 1).unwrap();
    // New money bonded mid-vote votes at ZERO (frozen snapshot): refused.
    l.bond(d, stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
    assert!(
        g.vote(&mut l, d, id, VoteChoice::Yes, 2).is_err(),
        "FIXED (audit G1): post-creation bond must not vote against a frozen base"
    );
    let p = g.get(id).unwrap();
    assert!(
        p.turnout() <= p.electorate,
        "B-GOV/G1 REAL: turnout {} exceeds frozen electorate {}",
        p.turnout(),
        p.electorate
    );
}

// ---------- B-GOV/G2: proposer stake is never locked ----------
//
// `vote` locks the voter's weight, but `propose` locks nothing: the proposer
// can fully unbond the 10k-STELL stake that qualified the proposal while the
// vote is still open, leaving a live proposal with no skin in the game
// (bond -> propose -> exit recycles one stake into serial proposals).
// DESIRED: proposer exit while its proposal is open is refused.
// FAILS on current code (unbond succeeds).

#[test]
fn bgov_proposer_may_exit_while_proposal_open() {
    let a = [0xA1u8; 32];
    let mut l = StakingLedger::new();
    l.bond(a, stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
    let mut g = Governance::new();
    let _id = g
        .propose(&mut l, a, "x".into(), GovAction::Signal("t".into()), 0)
        .expect("propose");
    assert_eq!(
        l.locked_governance_of(&a),
        stell(10_000),
        "FIXED (audit G2): proposer holds full-stake lock while proposal open"
    );
    let err = l.unbond(a, stell(10_000), 1);
    assert!(
        err == Err(stellereum::staking::StakingError::LockedInGovernanceVote),
        "B-GOV/G2 REAL: proposer fully exited while its proposal is open: {err:?}"
    );
}
