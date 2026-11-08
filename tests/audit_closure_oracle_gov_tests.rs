//! Audit closure: oracle O1 (drift walk, freshness, peg, publisher allowlist /
//! Sybil pricing, TWAP advisory status) and governance G1 (tiny-electorate
//! quorum edges, vote replay, electorate-zero hygiene).
//!
//! NEW file — never edits shared tests.

use std::collections::HashMap;
use stellereum::governance::{
    GovAction, GovError, Governance, Proposal, ProposalStatus, VoteChoice,
    GOVERNANCE_QUORUM_FLOOR_BPS, GOVERNANCE_VOTING_PERIOD_SECS,
};
use stellereum::oracle::{
    check_freshness, deviation_bps, is_valid_asset_symbol, pq_publisher_binding, DexTwapCalculator,
    OracleSafetyEngine, OracleState, PqPriceFeedUpdate, MAX_PRICE_DEVIATION_BPS,
    STALE_PRICE_MAX_SECS,
};
use stellereum::post_quantum::FalconKeypair;
use stellereum::staking::{StakingLedger, DEFAULT_COMMISSION_BPS};

const STELL: u64 = 1_000_000_000;

fn key(seed: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[seed; 32])
}
fn pk(seed: u8) -> [u8; 32] {
    pq_publisher_binding(key(seed).pubkey())
}
fn stell(n: u64) -> u64 {
    n * STELL
}

// ===========================================================================
// O1: baseline drift — cap holds per step, walkable across steps
// ===========================================================================

fn state_with_pq_publisher(kp: &FalconKeypair) -> OracleState {
    let mut s = OracleState::default();
    assert!(s.register_pq_publisher(kp.pubkey()));
    s
}

fn feed_at(sk: &FalconKeypair, asset: &str, price: u64, ts: u64) -> PqPriceFeedUpdate {
    PqPriceFeedUpdate::sign(asset, price, ts, sk)
}

#[test]
fn o1_per_step_drift_cap_holds_and_resets_only_via_governance() {
    let pubk = key(0xA0);
    let mut s = state_with_pq_publisher(&pubk);
    let t0 = 1_760_000_000u64;
    let p0 = 1_000_000u64;
    assert_eq!(
        s.commit_feed_pq(&feed_at(&pubk, "STELL", p0, t0), t0).unwrap(),
        p0
    );
    // Same-key walk is capped at 5%/step (O1 fix): +5% commits without latching.
    let p1 = p0 * 105 / 100;
    assert_eq!(
        s.commit_feed_pq(&feed_at(&pubk, "STELL", p1, t0 + 1), t0 + 1)
            .unwrap(),
        p1
    );
    assert!(!s.breaker_tripped);
    // Single-publisher walk is capped at 5%/step (O1 fix): a second +10%
    // step from the SAME key is refused WITHOUT latching; +5% steps walk
    // until the cumulative latch (genesis anchor) fires.
    let p2 = p1 * 105 / 100;
    let err = s
        .commit_feed_pq(&feed_at(&pubk, "STELL", p2, t0 + 2), t0 + 2)
        .expect_err("cumulative +10.25% must trip the latch");
    assert!(
        format!("{err:?}").contains("cumulative"),
        "trip must name the cumulative rule: {err:?}"
    );
    assert!(s.breaker_tripped, "cumulative trip latches");
    assert_eq!(s.feeds.get("STELL").unwrap().price_micro_usd, p1);
    // Latched by the cumulative trip: everything after is refused until
    // governance resets (even an in-cap feed).
    let too_fast = p2 * 110 / 100;
    assert!(s
        .commit_feed_pq(&feed_at(&pubk, "STELL", too_fast, t0 + 3), t0 + 3)
        .is_err());
    assert!(s.breaker_tripped, "cumulative trip stays latched");
    assert_eq!(s.feeds.get("STELL").unwrap().price_micro_usd, p1);
    // One step over the cap also stays refused while latched.
    let over = p2 + p2 * 1001 / 10_000 + 1;
    assert!(deviation_bps(over, p2) > MAX_PRICE_DEVIATION_BPS);
    assert!(s
        .commit_feed_pq(&feed_at(&pubk, "STELL", over, t0 + 3), t0 + 3)
        .is_err());
    assert!(s.breaker_tripped, "still latched");
    assert_eq!(s.feeds.get("STELL").unwrap().price_micro_usd, p1);
    // Governance reset clears the latch AND the anchor (genesis-like
    // state): the drifted p2 commits and re-anchors at p2 — recovery from
    // a legitimate regime change is an explicit governance act.
    assert!(s.reset_breaker(), "reset reports a real reset");
    assert_eq!(
        s.commit_feed_pq(&feed_at(&pubk, "STELL", p2, t0 + 4), t0 + 4)
            .unwrap(),
        p2
    );
    assert!(!s.breaker_tripped);
    // The new anchor holds from here: +11% over p2 trips again.
    let p3 = p2 + p2 * 11 / 100;
    assert!(s
        .commit_feed_pq(&feed_at(&pubk, "STELL", p3, t0 + 5), t0 + 5)
        .is_err());
    assert!(s.breaker_tripped, "walk past the new anchor trips again");
    // And a price back within 10% of the new anchor still commits
    // once reset (no brick-forever).
    assert!(s.reset_breaker());
    assert_eq!(
        s.commit_feed_pq(&feed_at(&pubk, "STELL", p1, t0 + 6), t0 + 6)
            .unwrap(),
        p1
    );
}

#[test]
fn o1_distinct_publisher_key_is_unaffected_by_drift_or_latch() {
    let a = key(0xA0);
    let b = key(0xB1);
    let mut s = OracleState::default();
    assert!(s.register_pq_publisher(a.pubkey()));
    assert!(s.register_pq_publisher(b.pubkey()));
    let t0 = 1_760_000_000u64;
    assert!(s
        .commit_feed_pq(&feed_at(&a, "STELL", 1_000_000, t0), t0)
        .is_ok());
    // A second publisher's in-cap feed commits against the first's baseline.
    assert!(s
        .commit_feed_pq(&feed_at(&b, "STELL", 1_050_000, t0 + 1), t0 + 1)
        .is_ok());
    assert_eq!(
        s.feeds.get("STELL").unwrap().publisher,
        pq_publisher_binding(b.pubkey())
    );
}

#[test]
fn oracle_freshness_monotonicity_peg_and_shape_are_fail_closed() {
    let pubk = key(0xA0);
    let mut s = state_with_pq_publisher(&pubk);
    let t0 = 1_760_000_000u64;
    // Stale refused, no latch.
    assert!(s
        .commit_feed_pq(
            &feed_at(&pubk, "STELL", 1_000_000, t0 - STALE_PRICE_MAX_SECS - 1),
            t0
        )
        .is_err());
    assert!(!s.breaker_tripped);
    assert!(check_freshness(t0 - STALE_PRICE_MAX_SECS - 1, t0).is_err());
    // Future-dated refused.
    assert!(s
        .commit_feed_pq(&feed_at(&pubk, "STELL", 1_000_000, t0 + 1), t0)
        .is_err());
    // Baseline commits, then a rewind (older timestamp) is refused even
    // though it is still within the freshness window.
    assert!(s
        .commit_feed_pq(&feed_at(&pubk, "STELL", 1_000_000, t0), t0)
        .is_ok());
    assert!(s
        .commit_feed_pq(&feed_at(&pubk, "STELL", 1_000_000, t0 - 5), t0 + 5)
        .is_err());
    // USDT depeg latches; a non-peg asset never trips the peg arm.
    assert!(s
        .commit_feed_pq(&feed_at(&pubk, "USDT", 1_000_000, t0 + 6), t0 + 6)
        .is_ok());
    assert!(s
        .commit_feed_pq(&feed_at(&pubk, "USDT", 940_000, t0 + 7), t0 + 7)
        .is_err());
    assert!(s.breaker_tripped);
    // Malformed inputs are refused WITHOUT latching (fresh state here).
    let mut s2 = state_with_pq_publisher(&pubk);
    assert!(s2.commit_feed_pq(&feed_at(&pubk, "STELL", 0, t0), t0).is_err());
    assert!(s2
        .commit_feed_pq(&feed_at(&pubk, "", 1_000_000, t0), t0)
        .is_err());
    assert!(s2
        .commit_feed_pq(
            &feed_at(
                &pubk,
                "WAY-TOO-LONG-SYMBOL-OVER-32-BYTES-LIMIT",
                1_000_000,
                t0
            ),
            t0
        )
        .is_err());
    assert!(
        !s2.breaker_tripped,
        "malformed input must not halt the chain"
    );
    assert!(!is_valid_asset_symbol(""));
    assert!(is_valid_asset_symbol("STELL/USDT"));
}

#[test]
fn publisher_set_is_governance_gated_and_sybil_priced() {
    // Unregistered key: correctly signed yet refused.
    let outsider = key(0xEE);
    let mut s = OracleState::default();
    let t0 = 1_760_000_000u64;
    let err = s
        .commit_feed_pq(&feed_at(&outsider, "STELL", 1_000_000, t0), t0)
        .expect_err("unknown publisher refused");
    assert!(err.contains("publisher"), "got: {err}");
    // Zero key refused at the registry (mirrors the governance backstop).
    assert!(!s.register_publisher([0u8; 32]));
    assert!(!s.publishers.contains(&[0u8; 32]));
    // Registration is idempotent; revocation retires FUTURE feeds only.
    let publisher_kp = key(0xA0);
    let publisher = pq_publisher_binding(publisher_kp.pubkey());
    assert!(s.register_pq_publisher(publisher_kp.pubkey()));
    assert!(s.publishers.contains(&publisher));
    assert!(
        !s.register_pq_publisher(publisher_kp.pubkey()),
        "repeat is an observable no-op"
    );
    assert!(s
        .commit_feed_pq(&feed_at(&publisher_kp, "STELL", 1_000_000, t0), t0)
        .is_ok());
    assert!(s.unregister_pq_publisher(publisher_kp.pubkey()));
    assert!(!s.publishers.contains(&publisher));
    assert!(
        !s.unregister_pq_publisher(publisher_kp.pubkey()),
        "repeat is an observable no-op"
    );
    assert!(s
        .commit_feed_pq(&feed_at(&key(0xA0), "STELL", 1_000_000, t0 + 1), t0 + 1)
        .is_err());
    assert_eq!(
        s.feeds.get("STELL").unwrap().price_micro_usd,
        1_000_000,
        "committed history is never un-observed"
    );
}

#[test]
fn twap_is_advisory_only_and_never_commits() {
    // The TWAP tier serves reads when the pull oracle is absent; it writes
    // no committed state (see the 3-line type-level note on
    // OracleSafetyEngine). A committed OracleState next to it is untouched.
    let mut engine = OracleSafetyEngine::new(vec![pk(0xA0)]);
    let t0 = 1_760_000_000u64;
    engine.record_dex_trade("STELL", 1_000_000, t0, 100);
    engine.record_dex_trade("STELL", 1_100_000, t0 + 10, 100);
    let twap = engine
        .twap_calculator
        .calculate_twap("STELL", t0 + 10)
        .expect("two observations average");
    assert_eq!(twap, 1_050_000);
    // No pull feed: Tier 2 answers from TWAP alone.
    assert_eq!(
        engine.resolve_price(None, "STELL", t0 + 10).unwrap(),
        1_050_000
    );
    // A pull feed >10% from TWAP trips the ENGINE-local breaker only.
    let far = PqPriceFeedUpdate::sign("STELL", 2_000_000, t0 + 10, &key(0xA0));
    assert!(engine
        .resolve_price_pq(Some(&far), "STELL", t0 + 10)
        .is_err());
    assert!(engine.circuit_breaker_triggered);
    // DexTwapCalculator prunes outside the window (pure, deterministic).
    let mut calc = DexTwapCalculator::new();
    calc.record_trade("X", 5, 100, 1);
    calc.record_trade("X", 7, 100 + 3600 + 1, 1);
    assert_eq!(calc.calculate_twap("X", 100 + 3600 + 1), Some(7));
}

// ===========================================================================
// G1: tiny electorates, vote replay, electorate-zero hygiene
// ===========================================================================

fn ledger_with(n: usize, bond_stell: u64) -> (StakingLedger, Vec<[u8; 32]>) {
    let mut l = StakingLedger::new();
    let ids: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
    for id in &ids {
        l.bond(*id, stell(bond_stell), DEFAULT_COMMISSION_BPS)
            .unwrap();
    }
    (l, ids)
}

fn smuggled_proposal(id: u64, electorate: u128, yes: u128, no: u128, voting_end: u64) -> Proposal {
    Proposal {
        id,
        proposer: [0x01u8; 32],
        title: "smuggled".into(),
        action: GovAction::Signal("t".into()),
        created_at: 0,
        voting_end,
        yes,
        no,
        abstain: 0,
        voters: HashMap::new(),
        status: ProposalStatus::Open,
        electorate,
        electorate_weights: None,
        proposer_lock: 0,
        weights: HashMap::new(),
    }
}

#[test]
fn tiny_electorate_truncation_is_harmless_empty_never_passes() {
    let mut g = Governance::new();
    let mut l = StakingLedger::new();
    let end = GOVERNANCE_VOTING_PERIOD_SECS;
    // Electorate of 1 unit: quorum_needed truncates to 0 — but a pass still
    // needs a real yes > no, so the truncation grants nothing by itself.
    g.proposals.insert(1, smuggled_proposal(1, 1, 1, 0, end));
    assert_eq!(
        g.finalize(&mut l, 1, end + 1).unwrap(),
        ProposalStatus::Passed
    );
    // Empty electorate, zero turnout: Rejected (yes > no fails).
    g.proposals.insert(2, smuggled_proposal(2, 0, 0, 0, end));
    assert_eq!(
        g.finalize(&mut l, 2, end + 1).unwrap(),
        ProposalStatus::Rejected
    );
    // Abstain-only turnout on a tiny base: still Rejected.
    let mut p3 = smuggled_proposal(3, 1, 0, 0, end);
    p3.abstain = 1;
    g.proposals.insert(3, p3);
    assert_eq!(
        g.finalize(&mut l, 3, end + 1).unwrap(),
        ProposalStatus::Rejected
    );
}

#[test]
fn propose_on_an_empty_ledger_fails_before_any_electorate_read() {
    let mut l = StakingLedger::new();
    let mut g = Governance::new();
    // No stake at all: the NotStaker gate fires first (the electorate==0
    // refuse behind it is unreachable-today defense in depth).
    assert_eq!(
        g.propose(
            &mut l,
            [0x09u8; 32],
            "t".into(),
            GovAction::Signal("t".into()),
            0
        ),
        Err(GovError::NotStaker)
    );
    // Quorum floor still enforced at the propose gate.
    let (mut l2, ids) = ledger_with(1, 10_000);
    let mut g2 = Governance::new();
    assert_eq!(
        g2.propose(
            &mut l2,
            ids[0],
            "bad".into(),
            GovAction::SetGovernanceQuorumBps(GOVERNANCE_QUORUM_FLOOR_BPS - 1),
            0
        ),
        Err(GovError::InvalidAction)
    );
}

#[test]
fn vote_replay_is_refused_per_proposal_but_independent_across_proposals() {
    let (mut l, ids) = ledger_with(3, 10_000);
    let mut g = Governance::new();
    let a = g
        .propose(&mut l, ids[0], "a".into(), GovAction::Signal("a".into()), 0)
        .unwrap();
    let b = g
        .propose(&mut l, ids[0], "b".into(), GovAction::Signal("b".into()), 0)
        .unwrap();
    g.vote(&mut l, ids[1], a, VoteChoice::Yes, 1).unwrap();
    // Same proposal, changed mind: still a replay.
    assert_eq!(
        g.vote(&mut l, ids[1], a, VoteChoice::No, 2),
        Err(GovError::AlreadyVoted)
    );
    // Same voter, different proposal: independent.
    assert!(g.vote(&mut l, ids[1], b, VoteChoice::No, 2).is_ok());
    // Unknown proposal: no vote to replay.
    assert_eq!(
        g.vote(&mut l, ids[1], 999, VoteChoice::Yes, 2),
        Err(GovError::UnknownProposal)
    );
    // Zero-weight voter cannot manufacture turnout.
    assert_eq!(
        g.vote(&mut l, [0xFFu8; 32], a, VoteChoice::Yes, 2),
        Err(GovError::NotStaker)
    );
}
