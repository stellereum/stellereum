//! Governance audit attack tests (scope: `src/governance.rs` only).
//!
//! Lifecycle under test: `propose` -> `vote` -> `finalize` -> `execute`.
//! Every test pins FAIL-CLOSED behavior: out-of-bounds parameters are refused
//! at BOTH propose time (`GovAction::validate`) and execute time
//! (`execute_inner` backstops); double execution is refused; unauthorized
//! callers cannot propose/vote; threshold math is exact; the governed
//! `equivocation_slash_bps` cap agrees with the staking cap
//! (`StakingLedger::slash` refuses `> 10000`); there is deliberately NO
//! timelock (deferred design decision, documented in `execute`), so execution
//! immediately after finalization must succeed.

use std::collections::HashMap;

use stellereum::governance::{
    GovAction, GovError, Governance, Proposal, ProposalStatus, VoteChoice,
    GOVERNANCE_QUORUM_BPS, GOVERNANCE_QUORUM_FLOOR_BPS, GOVERNANCE_VOTING_PERIOD_SECS,
    MAX_BLOCK_REWARD_NANO, MAX_MIN_GAS_LIMIT, MAX_PROPOSAL_TITLE_BYTES, MAX_SIGNAL_BYTES,
    MAX_VALIDATOR_BOND, PROPOSAL_MIN_STAKE_NANO,
};
use stellereum::oracle::OracleState;
use stellereum::staking::{StakingLedger, DEFAULT_COMMISSION_BPS, MIN_VALIDATOR_BOND};

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

fn vid(n: u8) -> [u8; 32] {
    [n; 32]
}

/// Ledger with `n` validators bonded `bond_stell` STELL each (>= 10k to propose).
fn funded_ledger(n: usize, bond_stell: u64) -> (StakingLedger, Vec<[u8; 32]>) {
    let mut l = StakingLedger::new();
    let ids: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
    for id in &ids {
        l.bond(*id, stell(bond_stell), DEFAULT_COMMISSION_BPS)
            .unwrap();
    }
    (l, ids)
}

/// Insert a proposal DIRECTLY as `Passed` (bypasses propose-time validation),
/// exactly the "deserialized history / direct state write" case the
/// execute-time backstops exist for. Returns the proposal id.
fn smuggle_passed(g: &mut Governance, action: GovAction, title: String) -> u64 {
    let id = g.next_id;
    g.next_id += 1;
    g.proposals.insert(
        id,
        Proposal {
            id,
            proposer: [0x77u8; 32],
            title,
            action,
            created_at: 0,
            voting_end: 1,
            yes: 0,
            no: 0,
            abstain: 0,
            voters: HashMap::new(),
            status: ProposalStatus::Passed,
            electorate: stell(30_000) as u128,
            electorate_weights: None,
            proposer_lock: 0,
            weights: HashMap::new(),
        },
    );
    id
}

// ---------- 1. out-of-bounds parameters refused at propose time ----------

/// Every tunable attacked at propose time. Each must be `InvalidAction`.
#[test]
fn attack_out_of_bounds_refused_at_propose_time() {
    let (mut l, ids) = funded_ledger(1, 10_000);
    let mut g = Governance::new();
    let bad: Vec<GovAction> = vec![
        // equivocation slash >100% (cross-checks the staking cap).
        GovAction::SetEquivocationSlashBps(10_001),
        GovAction::SetEquivocationSlashBps(u64::MAX),
        GovAction::SetDefaultCommissionBps(10_001),
        GovAction::SetDefaultCommissionBps(u64::MAX),
        GovAction::SetPmmRedemptionBufferBps(10_001),
        GovAction::SetPmmRedemptionBufferBps(u64::MAX),
        // quorum: below floor, above 100%, extremes.
        GovAction::SetGovernanceQuorumBps(0),
        GovAction::SetGovernanceQuorumBps(1),
        GovAction::SetGovernanceQuorumBps(GOVERNANCE_QUORUM_FLOOR_BPS - 1),
        GovAction::SetGovernanceQuorumBps(10_001),
        GovAction::SetGovernanceQuorumBps(u64::MAX),
        // min bond outside [MIN, MAX].
        GovAction::SetMinValidatorBond(MIN_VALIDATOR_BOND - 1),
        GovAction::SetMinValidatorBond(MAX_VALIDATOR_BOND + 1),
        GovAction::SetMinValidatorBond(u64::MAX),
        // block reward above the anti-hyperinflation cap.
        GovAction::SetBlockReward(MAX_BLOCK_REWARD_NANO + 1),
        GovAction::SetBlockReward(u64::MAX),
        // min gas: zero and above cap.
        GovAction::SetMinGasLimit(0),
        GovAction::SetMinGasLimit(MAX_MIN_GAS_LIMIT + 1),
        GovAction::SetMinGasLimit(u64::MAX),
        // oracle publisher zero key (both directions).
        GovAction::RegisterOraclePublisher([0u8; 32]),
        GovAction::UnregisterOraclePublisher([0u8; 32]),
        // upgrade: empty/traversal/oversize name, zero height/sha.
        GovAction::SoftwareUpgrade {
            name: String::new(),
            height: 100,
            sha256: [1u8; 32],
        },
        GovAction::SoftwareUpgrade {
            name: "../evil".into(),
            height: 100,
            sha256: [1u8; 32],
        },
        GovAction::SoftwareUpgrade {
            name: "x".repeat(65),
            height: 100,
            sha256: [1u8; 32],
        },
        GovAction::SoftwareUpgrade {
            name: "v1.0.0".into(),
            height: 0,
            sha256: [1u8; 32],
        },
        GovAction::SoftwareUpgrade {
            name: "v1.0.0".into(),
            height: 100,
            sha256: [0u8; 32],
        },
    ];
    for action in &bad {
        assert_eq!(
            action.validate(),
            Err(GovError::InvalidAction),
            "validate() must refuse {action:?}"
        );
        assert_eq!(
            g.propose(&mut l, ids[0], "t".into(), action.clone(), 0),
            Err(GovError::InvalidAction),
            "propose() must refuse {action:?}"
        );
    }
    // Oversize title / signal text refused at propose time.
    assert_eq!(
        g.propose(
            &mut l,
            ids[0],
            "t".repeat(MAX_PROPOSAL_TITLE_BYTES + 1),
            GovAction::Signal("ok".into()),
            0
        ),
        Err(GovError::InvalidAction),
        "257B title must be refused"
    );
    assert_eq!(
        g.propose(
            &mut l,
            ids[0],
            "t".into(),
            GovAction::Signal("s".repeat(MAX_SIGNAL_BYTES + 1)),
            0
        ),
        Err(GovError::InvalidAction),
        "1025B signal must be refused"
    );
    // Nothing was committed.
    assert_eq!(g.count_status(ProposalStatus::Open), 0);
}

// ---------- 2. smuggled out-of-bounds refused at execute time ----------

/// The same attacks, smuggled PAST propose-time validation: execution must
/// fail closed, the proposal stays `Passed`, and no parameter moves.
#[test]
fn attack_smuggled_out_of_bounds_refused_at_execute_time() {
    let bad: Vec<GovAction> = vec![
        GovAction::SetEquivocationSlashBps(10_001),
        GovAction::SetEquivocationSlashBps(u64::MAX),
        GovAction::SetDefaultCommissionBps(10_001),
        GovAction::SetPmmRedemptionBufferBps(10_001),
        GovAction::SetGovernanceQuorumBps(1),
        GovAction::SetGovernanceQuorumBps(10_001),
        GovAction::SetMinValidatorBond(MIN_VALIDATOR_BOND - 1),
        GovAction::SetMinValidatorBond(u64::MAX),
        GovAction::SetBlockReward(MAX_BLOCK_REWARD_NANO + 1),
        GovAction::SetBlockReward(u64::MAX),
        GovAction::SetMinGasLimit(0),
        GovAction::SetMinGasLimit(u64::MAX),
        GovAction::RegisterOraclePublisher([0u8; 32]),
        GovAction::UnregisterOraclePublisher([0u8; 32]),
        GovAction::Signal("s".repeat(MAX_SIGNAL_BYTES + 1)),
        GovAction::SoftwareUpgrade {
            name: "../evil".into(),
            height: 100,
            sha256: [7u8; 32],
        },
        GovAction::SoftwareUpgrade {
            name: "v1.0.0".into(),
            height: 0,
            sha256: [7u8; 32],
        },
    ];
    for action in bad {
        let mut g = Governance::new();
        let pristine = g.applied.clone();
        let id = smuggle_passed(&mut g, action.clone(), "t".into());
        assert_eq!(
            g.execute([0xEu8; 32], id),
            Err(GovError::InvalidAction),
            "execute() must refuse smuggled {action:?}"
        );
        assert_eq!(
            g.get(id).unwrap().status,
            ProposalStatus::Passed,
            "refused proposal stays Passed (fail closed, retryable)"
        );
        assert_eq!(g.applied, pristine, "refused action must move nothing");
        // Retry fails identically (no partial state).
        assert_eq!(g.execute([0xEu8; 32], id), Err(GovError::InvalidAction));
    }
    // Smuggled oversize title fails closed too.
    let mut g = Governance::new();
    let id = smuggle_passed(
        &mut g,
        GovAction::Signal("ok".into()),
        "t".repeat(MAX_PROPOSAL_TITLE_BYTES + 1),
    );
    assert_eq!(g.execute([0xEu8; 32], id), Err(GovError::InvalidAction));
    assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
}

// ---------- 3. boundary values accepted ----------

/// The largest/smallest LEGAL values pass both gates (no off-by-one).
#[test]
fn attack_boundary_values_accepted() {
    let (mut l, ids) = funded_ledger(1, 10_000);
    let mut g = Governance::new();
    let good: Vec<GovAction> = vec![
        GovAction::SetEquivocationSlashBps(10_000),
        GovAction::SetEquivocationSlashBps(0),
        GovAction::SetDefaultCommissionBps(10_000),
        GovAction::SetPmmRedemptionBufferBps(10_000),
        GovAction::SetGovernanceQuorumBps(GOVERNANCE_QUORUM_FLOOR_BPS),
        GovAction::SetGovernanceQuorumBps(10_000),
        GovAction::SetMinValidatorBond(MIN_VALIDATOR_BOND),
        GovAction::SetMinValidatorBond(MAX_VALIDATOR_BOND),
        GovAction::SetBlockReward(MAX_BLOCK_REWARD_NANO),
        GovAction::SetBlockReward(0),
        GovAction::SetMinGasLimit(1),
        GovAction::SetMinGasLimit(MAX_MIN_GAS_LIMIT),
        GovAction::RegisterOraclePublisher([1u8; 32]),
        GovAction::Signal("s".repeat(MAX_SIGNAL_BYTES)),
        GovAction::SoftwareUpgrade {
            name: "v1.0.0".into(),
            height: 1,
            sha256: [1u8; 32],
        },
        GovAction::CancelUpgrade,
        GovAction::ResetOracleBreaker,
    ];
    for action in &good {
        assert!(
            action.validate().is_ok(),
            "boundary action must validate: {action:?}"
        );
    }
    // Propose-time acceptance for a sample (each propose locks; reuse ledger).
    let id = g
        .propose(
            &mut l,
            ids[0],
            "t".repeat(MAX_PROPOSAL_TITLE_BYTES),
            GovAction::SetEquivocationSlashBps(10_000),
            0,
        )
        .expect("256B title + 10000 bps slash must propose");
    assert_eq!(g.get(id).unwrap().status, ProposalStatus::Open);
    assert_eq!(GOVERNANCE_QUORUM_BPS, 6_666, "pin the default quorum");
    assert_eq!(PROPOSAL_MIN_STAKE_NANO, stell(10_000));
}

// ---------- 4. double execution ----------

#[test]
fn attack_double_execution_refused() {
    let (mut l, ids) = funded_ledger(3, 10_000);
    let mut g = Governance::new();
    let id = g
        .propose(
            &mut l,
            ids[0],
            "reward".into(),
            GovAction::SetBlockReward(stell(7)),
            0,
        )
        .unwrap();
    g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
    g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
    assert_eq!(
        g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap(),
        ProposalStatus::Passed
    );
    g.execute(ids[2], id).unwrap();
    assert_eq!(g.applied.block_reward, Some(stell(7)));
    // Second execution — same path and oracle path — is refused.
    assert_eq!(g.execute(ids[2], id), Err(GovError::AlreadyExecuted));
    let mut oracle = OracleState::default();
    assert_eq!(
        g.execute_with_oracle(ids[0], id, &mut oracle),
        Err(GovError::AlreadyExecuted)
    );
    assert_eq!(g.get(id).unwrap().status, ProposalStatus::Executed);
    assert_eq!(g.applied.block_reward, Some(stell(7)), "no double apply");
}

// ---------- 5. unauthorized propose / vote ----------

#[test]
fn attack_unauthorized_propose_and_vote_refused() {
    let (mut l, ids) = funded_ledger(2, 10_000);
    let mut g = Governance::new();
    // Zero-stake caller cannot propose.
    assert_eq!(
        g.propose(&mut l, [0xFFu8; 32], "t".into(), GovAction::Signal("t".into()), 0),
        Err(GovError::NotStaker)
    );
    // Below-minimum stake cannot propose; exact minimum can.
    let mut small = StakingLedger::new();
    small
        .bond(vid(9), stell(9_999), DEFAULT_COMMISSION_BPS)
        .unwrap();
    assert_eq!(
        g.propose(&mut small, vid(9), "t".into(), GovAction::Signal("t".into()), 0),
        Err(GovError::InsufficientStake)
    );
    // Voting gates.
    let id = g
        .propose(&mut l, ids[0], "t".into(), GovAction::Signal("t".into()), 0)
        .unwrap();
    assert_eq!(
        g.vote(&mut l, ids[0], 999_999, VoteChoice::Yes, 1),
        Err(GovError::UnknownProposal)
    );
    assert_eq!(
        g.vote(&mut l, [0xFEu8; 32], id, VoteChoice::Yes, 1),
        Err(GovError::NotStaker),
        "non-staker must not vote"
    );
    g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
    assert_eq!(
        g.vote(&mut l, ids[0], id, VoteChoice::No, 1),
        Err(GovError::AlreadyVoted),
        "no vote flipping"
    );
    assert_eq!(
        g.vote(&mut l, ids[1], id, VoteChoice::Yes, GOVERNANCE_VOTING_PERIOD_SECS + 1),
        Err(GovError::VotingClosed),
        "no voting after close"
    );
}

// ---------- 6. execution gates ----------

#[test]
fn attack_execute_gates() {
    let (mut l, ids) = funded_ledger(3, 10_000);
    let mut g = Governance::new();
    // Unknown proposal.
    assert_eq!(g.execute(ids[0], 424_242), Err(GovError::UnknownProposal));
    // Open proposal cannot execute (must finalize first).
    let open = g
        .propose(&mut l, ids[0], "t".into(), GovAction::Signal("t".into()), 0)
        .unwrap();
    assert_eq!(g.execute(ids[0], open), Err(GovError::NotPassed));
    // Rejected proposal cannot execute.
    g.vote(&mut l, ids[0], open, VoteChoice::No, 1).unwrap();
    g.vote(&mut l, ids[1], open, VoteChoice::No, 1).unwrap();
    g.vote(&mut l, ids[2], open, VoteChoice::No, 1).unwrap();
    assert_eq!(
        g.finalize(&mut l, open, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap(),
        ProposalStatus::Rejected
    );
    assert_eq!(g.execute(ids[0], open), Err(GovError::NotPassed));
    // Oracle action via the PLAIN path fails closed and stays Passed ...
    let mut g2 = Governance::new();
    let (mut l2, ids2) = funded_ledger(3, 10_000);
    let oid = g2
        .propose(
            &mut l2,
            ids2[0],
            "reg".into(),
            GovAction::RegisterOraclePublisher([0x31u8; 32]),
            0,
        )
        .unwrap();
    g2.vote(&mut l2, ids2[0], oid, VoteChoice::Yes, 1).unwrap();
    g2.vote(&mut l2, ids2[1], oid, VoteChoice::Yes, 1).unwrap();
    g2.finalize(&mut l2, oid, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
    assert_eq!(g2.execute(ids2[0], oid), Err(GovError::InvalidAction));
    assert_eq!(g2.get(oid).unwrap().status, ProposalStatus::Passed);
    // ... and the oracle-aware path then applies it exactly once.
    let mut oracle = OracleState::default();
    g2.execute_with_oracle(ids2[1], oid, &mut oracle).unwrap();
    assert!(oracle.publishers.contains(&[0x31u8; 32]));
    assert_eq!(g2.get(oid).unwrap().status, ProposalStatus::Executed);
    // Anyone (not just the proposer) may execute a passed proposal.
    let mut g3 = Governance::new();
    let (mut l3, ids3) = funded_ledger(3, 10_000);
    let aid = g3
        .propose(&mut l3, ids3[0], "s".into(), GovAction::Signal("hi".into()), 0)
        .unwrap();
    g3.vote(&mut l3, ids3[0], aid, VoteChoice::Yes, 1).unwrap();
    g3.vote(&mut l3, ids3[1], aid, VoteChoice::Yes, 1).unwrap();
    g3.finalize(&mut l3, aid, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
    assert!(g3.execute(ids3[2], aid).is_ok(), "anyone-can-execute by design");
}

// ---------- 7. threshold edge cases ----------

/// Frozen electorate 10_000 at default quorum 6666 bps needs exactly 6666.
#[test]
fn attack_quorum_threshold_edges() {
    fn case(yes: u128, no: u128, abstain: u128) -> ProposalStatus {
        let mut g = Governance::new();
        let mut l = StakingLedger::new();
        let id = g.next_id;
        g.next_id += 1;
        g.proposals.insert(
            id,
            Proposal {
                id,
                proposer: [1u8; 32],
                title: "edge".into(),
                action: GovAction::Signal("e".into()),
                created_at: 0,
                voting_end: 100,
                yes,
                no,
                abstain,
                voters: HashMap::new(),
                status: ProposalStatus::Open,
                electorate: 10_000,
                electorate_weights: None,
                proposer_lock: 0,
                weights: HashMap::new(),
            },
        );
        g.finalize(&mut l, id, 101).unwrap()
    }
    // Exactly quorum (6666/6666) passes; one below fails.
    assert_eq!(case(6_666, 0, 0), ProposalStatus::Passed);
    assert_eq!(case(6_665, 0, 0), ProposalStatus::Rejected);
    // yes == no never passes, even with full turnout.
    assert_eq!(case(5_000, 5_000, 0), ProposalStatus::Rejected);
    // Empty / abstain-only never passes.
    assert_eq!(case(0, 0, 0), ProposalStatus::Rejected);
    assert_eq!(case(0, 0, 10_000), ProposalStatus::Rejected);
    // Abstain counts toward quorum but not toward the majority.
    assert_eq!(case(4_000, 3_000, 3_000), ProposalStatus::Passed);
    assert_eq!(case(3_000, 4_000, 3_000), ProposalStatus::Rejected);
    // Full-flow pin: 2/3 yes of 30k passes, 1/3 does not.
    let (mut l, ids) = funded_ledger(3, 10_000);
    let mut g = Governance::new();
    let id = g
        .propose(&mut l, ids[0], "q".into(), GovAction::Signal("q".into()), 0)
        .unwrap();
    g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
    assert_eq!(
        g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap(),
        ProposalStatus::Rejected,
        "10k/30k turnout must miss the 6666 bps quorum"
    );
}

// ---------- 8. slash-bps cap cross-checked with staking ----------

#[test]
fn attack_slash_bps_matches_staking_cap() {
    // Governed 10000 bps is legal AND staking accepts it.
    let (mut l, ids) = funded_ledger(1, 10_000);
    let mut g = Governance::new();
    let id = g
        .propose(
            &mut l,
            ids[0],
            "slash".into(),
            GovAction::SetEquivocationSlashBps(10_000),
            0,
        )
        .expect("10000 bps must propose");
    g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
    g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS + 1).unwrap();
    g.execute(ids[0], id).unwrap();
    assert_eq!(g.applied.equivocation_slash_bps, Some(10_000));
    let mut ls = StakingLedger::new();
    ls.bond(vid(5), stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
    assert!(ls.slash(vid(5), 10_000).is_ok(), "staking accepts 100% slash");
    // Governed 10001 bps is refused at BOTH gates; staking refuses it too.
    assert_eq!(
        GovAction::SetEquivocationSlashBps(10_001).validate(),
        Err(GovError::InvalidAction)
    );
    let mut g2 = Governance::new();
    let smuggled = smuggle_passed(&mut g2, GovAction::SetEquivocationSlashBps(10_001), "s".into());
    assert_eq!(g2.execute(ids[0], smuggled), Err(GovError::InvalidAction));
    assert_eq!(g2.get(smuggled).unwrap().status, ProposalStatus::Passed);
    let mut ls2 = StakingLedger::new();
    ls2.bond(vid(6), stell(10_000), DEFAULT_COMMISSION_BPS).unwrap();
    assert!(
        ls2.slash(vid(6), 10_001).is_err(),
        "staking refuses >10000 bps — caps agree"
    );
}

// ---------- 9. timelock: none by design; early finalize refused ----------

#[test]
fn attack_no_timelock_execute_immediately_after_finalize() {
    let (mut l, ids) = funded_ledger(3, 10_000);
    let mut g = Governance::new();
    let id = g
        .propose(&mut l, ids[0], "t".into(), GovAction::Signal("now".into()), 0)
        .unwrap();
    // Finalizing BEFORE the window ends is refused (no early pass).
    assert_eq!(
        g.finalize(&mut l, id, GOVERNANCE_VOTING_PERIOD_SECS - 1),
        Err(GovError::VotingStillOpen)
    );
    g.vote(&mut l, ids[0], id, VoteChoice::Yes, 1).unwrap();
    g.vote(&mut l, ids[1], id, VoteChoice::Yes, 1).unwrap();
    let end = g.get(id).unwrap().voting_end;
    g.finalize(&mut l, id, end).unwrap();
    // No timelock: execution in the SAME instant as finalization succeeds.
    assert!(g.execute(ids[0], id).is_ok());
    assert_eq!(g.get(id).unwrap().status, ProposalStatus::Executed);
}

// ---------- 10. regression: unregister zero-key fails closed at execute ----------

#[test]
fn regression_unregister_zero_key_fails_closed_at_execute() {
    let mut g = Governance::new();
    let id = smuggle_passed(
        &mut g,
        GovAction::UnregisterOraclePublisher([0u8; 32]),
        "zero-unreg".into(),
    );
    assert_eq!(g.execute([0xAu8; 32], id), Err(GovError::InvalidAction));
    let mut oracle = OracleState::default();
    assert_eq!(
        g.execute_with_oracle([0xAu8; 32], id, &mut oracle),
        Err(GovError::InvalidAction)
    );
    assert_eq!(g.get(id).unwrap().status, ProposalStatus::Passed);
    assert!(oracle.publishers.is_empty(), "oracle must be untouched");
}

// ---------- 11. regression: voting_end saturates near u64::MAX ----------

#[test]
fn regression_voting_end_saturates_near_u64_max() {
    let (mut l, ids) = funded_ledger(1, 10_000);
    let mut g = Governance::new();
    let now = u64::MAX - 10;
    let id = g
        .propose(&mut l, ids[0], "edge".into(), GovAction::Signal("e".into()), now)
        .expect("propose near u64::MAX must not wrap/panic");
    assert_eq!(
        g.get(id).unwrap().voting_end,
        u64::MAX,
        "deadline clamps, never wraps"
    );
    g.vote(&mut l, ids[0], id, VoteChoice::Yes, now).unwrap();
    assert_eq!(
        g.finalize(&mut l, id, u64::MAX).unwrap(),
        ProposalStatus::Passed
    );
    assert!(g.execute(ids[0], id).is_ok());
}
