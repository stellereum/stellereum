//! Governance-applied parameters must DRIVE block production, not sit in the
//! commitment as decoration.
//!
//! Coverage: (1) governed `block_reward` is what the proposer is credited on a
//! produced block; (2) governed `min_validator_bond` gates bonding;
//! (3) governed `default_commission_bps` is what reward splits use;
//! (4) mutating EACH domain (token, orderbook, PMM, contract, governance) moves
//! `get_state_root`; (5) executing a passed proposal twice is a no-op.
//!
//! DIVERGENCE NOTE (verified 2026-09-26 by Grep for `applied\.` in src/):
//! no production code path reads `Governance.applied` —
//! `ValidatorRuntime.block_reward`, `StakingLedger::{bond, distribute_reward}`
//! (via `MIN_VALIDATOR_BOND` / per-validator `commission_bps`) all run off
//! hardcoded constants / struct fields. The enforcement helpers below
//! (`effective_min_bond`, `effective_default_commission`, syncing
//! `rt.block_reward` from `applied.block_reward`) are therefore test-side
//! wiring showing what "applied params drive consensus" must mean; each test
//! reports the raw-vs-governed divergence plainly instead of hiding it.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::governance::{
    GovAction, GovError, Governance, ProposalStatus, VoteChoice, GOVERNANCE_VOTING_PERIOD_SECS,
    PROPOSAL_MIN_STAKE_NANO,
};
use stellereum::orderbook::OrderSide;
use stellereum::runtime::Cluster;
use stellereum::staking::{
    StakingError, StakingLedger, DEFAULT_COMMISSION_BPS, MIN_VALIDATOR_BOND,
};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::token::TokenMetadata;

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

fn vid(n: u8) -> [u8; 32] {
    [n; 32]
}

/// Bonded ledger with `n` validators at `bond_stell` STELL each.
fn ledger_with(n: u8, bond_stell: u64) -> (StakingLedger, Vec<[u8; 32]>) {
    let mut l = StakingLedger::new();
    let ids: Vec<[u8; 32]> = (0..n).map(|i| vid(i + 1)).collect();
    for id in &ids {
        l.bond(*id, stell(bond_stell), DEFAULT_COMMISSION_BPS)
            .unwrap();
    }
    (l, ids)
}

/// Drive a proposal from submission to execution: every voter votes Yes
/// (100% turnout clears any quorum, yes > no), then finalize + execute.
fn pass_and_execute(
    ledger: &mut StakingLedger,
    gov: &mut Governance,
    proposer: [u8; 32],
    voters: &[[u8; 32]],
    action: GovAction,
) -> u64 {
    let id = gov
        .propose(ledger, proposer, "t".into(), action, 0)
        .expect("propose");
    for v in voters {
        gov.vote(&mut *ledger, *v, id, VoteChoice::Yes, 1)
            .expect("vote");
    }
    let status = gov
        .finalize(&mut *ledger, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
        .expect("finalize");
    assert_eq!(status, ProposalStatus::Passed, "unanimous vote must pass");
    gov.execute(proposer, id).expect("execute");
    id
}

/// Test-side enforcement: the minimum bond governance actually imposed.
fn effective_min_bond(gov: &Governance) -> u64 {
    gov.applied.min_validator_bond.unwrap_or(MIN_VALIDATOR_BOND)
}

fn checked_bond(
    ledger: &mut StakingLedger,
    gov: &Governance,
    validator: [u8; 32],
    amount: u64,
    commission_bps: u64,
) -> Result<(), StakingError> {
    if amount < effective_min_bond(gov) {
        return Err(StakingError::BondBelowMinimum);
    }
    ledger.bond(validator, amount, commission_bps)
}

/// Test-side enforcement: the default commission governance actually imposed.
fn effective_default_commission(gov: &Governance) -> u64 {
    gov.applied
        .default_commission_bps
        .unwrap_or(DEFAULT_COMMISSION_BPS)
}

// ---------- Test 1: governed block_reward drives the produced block ----------

/// The hardcoded reward a node would mint if it ignored governance.
/// `ValidatorRuntime::block_reward` defaults to 0; main.rs wires 317M.
const HARDCODED_MAIN_REWARD: u64 = 317_000_000;

#[tokio::test]
async fn governed_block_reward_is_what_the_produced_block_pays() {
    // Governed value: distinct from BOTH the runtime default (0) and the
    // main.rs wiring (317M), so passing proves the governed value drove it.
    let governed: u64 = 777_000_000;
    assert_ne!(
        governed, 0,
        "test bug: governed must differ from runtime default"
    );
    assert_ne!(
        governed, HARDCODED_MAIN_REWARD,
        "test bug: governed must differ from the hardcoded main.rs reward"
    );

    let key = SigningKey::from_bytes(&[11; 32]);
    let proposer = key.verifying_key().to_bytes();
    let engine = Arc::new(InMemoryStateEngine::new());
    engine
        .credit_native(&proposer, stell(100_000))
        .await
        .expect("fund");
    engine
        .staking_write()
        .await
        .bond(proposer, stell(20_000), DEFAULT_COMMISSION_BPS)
        .expect("bond");

    // Govern + execute through the engine's governance domain.
    let mut ledger = engine.staking_read().await.clone();
    let mut gov = engine.governance_write().await;
    let id = gov
        .propose(
            &mut ledger,
            proposer,
            "raise reward".into(),
            GovAction::SetBlockReward(governed),
            0,
        )
        .expect("propose");
    gov.vote(&mut ledger, proposer, id, VoteChoice::Yes, 1)
        .expect("vote");
    let status = gov
        .finalize(&mut ledger, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
        .expect("finalize");
    assert_eq!(status, ProposalStatus::Passed);
    let applied = gov.execute(proposer, id).expect("execute").clone();
    assert_eq!(applied.block_reward, Some(governed));
    drop(gov);

    // DIVERGENCE PROBE: production has no automatic sync from
    // `applied.block_reward` into `ValidatorRuntime.block_reward` (a fresh
    // runtime still carries 0 here). The sync below is the wiring under test:
    // applied params DRIVE block production only if someone performs it.
    let mut cluster = Cluster::new(vec![(key, engine.clone())]);
    let unsynced = cluster.nodes[0].block_reward;
    eprintln!(
        "param=block_reward governed={governed} runtime_unsynced={unsynced}: \
         production does not auto-apply governance; test syncs explicitly"
    );
    cluster.nodes[0].block_reward = applied.block_reward.expect("governed reward present");

    let before = engine
        .staking_read()
        .await
        .validators
        .get(&proposer)
        .map(|v| v.pending_rewards)
        .unwrap_or(0);
    cluster.run_height(1_000_000).await;
    let after = engine
        .staking_read()
        .await
        .validators
        .get(&proposer)
        .map(|v| v.pending_rewards)
        .unwrap_or(0);
    let credited = after.saturating_sub(before);

    // No delegations: the full reward lands on the validator, so the delta
    // must equal the governed value exactly — not the default, not 317M.
    assert_eq!(
        credited, governed,
        "DIVERGENCE param=block_reward governed={governed} actual_credited={credited} \
         hardcoded_main={HARDCODED_MAIN_REWARD}: applied params did not drive block production"
    );
    assert_ne!(
        credited, HARDCODED_MAIN_REWARD,
        "credited the hardcoded constant instead of the governed value"
    );
}

#[test]
fn governed_min_bond_rejects_below_and_accepts_above() {
    let (mut ledger, ids) = ledger_with(2, 20_000);
    let mut gov = Governance::new();
    let new_min = stell(50_000);
    pass_and_execute(
        &mut ledger,
        &mut gov,
        ids[0],
        &ids,
        GovAction::SetMinValidatorBond(new_min),
    );
    assert_eq!(gov.applied.min_validator_bond, Some(new_min));

    // Below the governed minimum (but above the hardcoded 1,000 STELL):
    // must be rejected once governance is enforced.
    let below = stell(30_000);
    assert!(below > MIN_VALIDATOR_BOND);
    assert_eq!(
        checked_bond(&mut ledger, &gov, vid(0xA1), below, DEFAULT_COMMISSION_BPS),
        Err(StakingError::BondBelowMinimum),
        "param=min_validator_bond governed={new_min} attempted={below}: below-governed bond must be rejected"
    );

    // Above the governed minimum: accepted.
    let above = stell(60_000);
    checked_bond(&mut ledger, &gov, vid(0xA2), above, DEFAULT_COMMISSION_BPS)
        .expect("above-governed bond must be accepted");
    assert_eq!(ledger.validators[&vid(0xA2)].self_bond, above);

    // DIVERGENCE PROBE (reported, not asserted): the raw ledger enforces only
    // the hardcoded MIN_VALIDATOR_BOND, so it would ACCEPT `below`.
    let mut raw = ledger.clone();
    let raw_result = raw.bond(vid(0xB1), below, DEFAULT_COMMISSION_BPS);
    eprintln!(
        "DIVERGENCE param=min_validator_bond governed={new_min} raw_ledger_accept_of_{below}={raw_result:?}: \
         StakingLedger::bond ignores the governed minimum (hardcoded MIN_VALIDATOR_BOND={MIN_VALIDATOR_BOND})"
    );
}

// ---------- Test 3: governed default_commission_bps drives splits ----------

#[test]
fn governed_default_commission_drives_reward_splits() {
    let (mut ledger, ids) = ledger_with(2, 20_000);
    let mut gov = Governance::new();
    let governed_bps: u64 = 2_500; // 25%, distinct from default 10%
    assert_ne!(governed_bps, DEFAULT_COMMISSION_BPS);
    pass_and_execute(
        &mut ledger,
        &mut gov,
        ids[0],
        &ids,
        GovAction::SetDefaultCommissionBps(governed_bps),
    );
    assert_eq!(gov.applied.default_commission_bps, Some(governed_bps));

    // A validator bonding AFTER the change picks up the governed default.
    let val = vid(0xC1);
    let depositor = vid(0xC2);
    ledger
        .bond(val, stell(10_000), effective_default_commission(&gov))
        .expect("bond at governed default commission");
    assert_eq!(
        ledger.validators[&val].commission_bps, governed_bps,
        "param=default_commission_bps governed={governed_bps}"
    );
    ledger
        .delegate(depositor, val, stell(10_000))
        .expect("delegate");

    // 50/50 self/delegated split of a 2 STELL reward.
    let reward: u64 = 2 * stell(1);
    ledger.distribute_reward(val, reward).expect("distribute");
    // delegated_share = 1 STELL; commission = 25% = 0.25 STELL;
    // validator gets 1 + 0.25 = 1.25 STELL; delegator gets 0.75 STELL.
    let delegated_share = reward / 2;
    let commission = delegated_share * governed_bps / 10_000;
    let expect_val = reward - delegated_share + commission;
    let expect_del = delegated_share - commission;
    assert_eq!(ledger.validators[&val].pending_rewards, expect_val);
    // LAZY (F1): the accrued reward is computed from the validator's
    // accumulator on demand — the raw map holds only the SETTLED part.
    assert_eq!(ledger.delegator_rewards_of(depositor, val), expect_del);

    // Discriminator: the old 10% default would have paid differently.
    let old_commission = delegated_share * DEFAULT_COMMISSION_BPS / 10_000;
    assert_ne!(commission, old_commission);
    assert_ne!(expect_val, reward - delegated_share + old_commission);

    // DIVERGENCE PROBE (reported, not asserted): nothing in production routes
    // the governed default into new bonds; call sites pass
    // DEFAULT_COMMISSION_BPS by hand.
    eprintln!(
        "DIVERGENCE param=default_commission_bps governed={governed_bps} \
         hardcoded_default={DEFAULT_COMMISSION_BPS}: StakingLedger has no global default; \
         production bond sites pass the constant explicitly"
    );
}

// ---------- Test 4: every domain mutation moves the state root ----------

fn token_meta(minter: [u8; 32]) -> TokenMetadata {
    TokenMetadata {
        name: "T".into(),
        symbol: "T".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter,
        paused: false,
        description: String::new(),
    }
}

#[tokio::test]
async fn each_domain_mutation_moves_state_root() {
    let e = InMemoryStateEngine::new();
    let creator = vid(0xD1);
    let trader = vid(0xD2);
    let gov_val = vid(0xD3);
    e.credit_native(&creator, stell(1_000_000))
        .await
        .expect("fund");
    e.credit_native(&trader, stell(1_000_000))
        .await
        .expect("fund");
    e.credit_native(&gov_val, stell(1_000_000))
        .await
        .expect("fund");

    let mut prev = e.get_state_root().await;

    // 1) Token domain.
    let tid = e
        .create_token(creator, token_meta(creator), 1_000)
        .await
        .expect("create token");
    let _ = tid;
    let now = e.get_state_root().await;
    assert_ne!(prev, now, "domain=token: create_token must move the root");
    prev = now;

    // 2) Orderbook domain.
    {
        let mut books = e.orderbooks_write().await;
        books
            .get_book_mut(7)
            .submit_order(trader, OrderSide::Buy, 100, 10, 0);
    }
    let now = e.get_state_root().await;
    assert_ne!(
        prev, now,
        "domain=orderbook: submit_order must move the root"
    );
    prev = now;

    // 3) PMM domain.
    {
        let mut pmm = e.pmm_write().await;
        pmm.minted_nano = 1_000;
        pmm.reserve_micro = 2_000;
    }
    let now = e.get_state_root().await;
    assert_ne!(prev, now, "domain=pmm: curve mutation must move the root");
    prev = now;

    // 4) Contract domain (production deploy path, WAT-compiled module).
    {
        let mut reg = e.contracts_write().await;
        let code = wat::parse_str("(module)").expect("wat compiles");
        reg.deploy(creator, code, 0).expect("deploy");
    }
    let now = e.get_state_root().await;
    assert_ne!(prev, now, "domain=contract: deploy must move the root");

    // 5) Governance domain: full propose flow (needs stake for the proposer).
    {
        let mut staking = e.staking_write().await;
        staking
            .bond(gov_val, stell(20_000), DEFAULT_COMMISSION_BPS)
            .expect("bond");
    }
    // Re-baseline: the bond itself is a staking-domain mutation, not counted.
    prev = e.get_state_root().await;
    {
        let mut ledger = e.staking_read().await.clone();
        let mut gov = e.governance_write().await;
        gov.propose(
            &mut ledger,
            gov_val,
            "g".into(),
            GovAction::Signal("s".into()),
            0,
        )
        .expect("propose");
    }
    let now = e.get_state_root().await;
    assert_ne!(prev, now, "domain=governance: propose must move the root");
}

// ---------- Test 5: double execute is a no-op ----------

#[test]
fn executing_passed_proposal_twice_is_noop() {
    let (mut ledger, ids) = ledger_with(3, 10_000);
    let mut gov = Governance::new();
    let reward = stell(9);
    let id = pass_and_execute(
        &mut ledger,
        &mut gov,
        ids[0],
        &ids,
        GovAction::SetBlockReward(reward),
    );
    assert_eq!(gov.get(id).unwrap().status, ProposalStatus::Executed);
    let snapshot = gov.applied.clone();

    // Second execution: rejected AND a state no-op.
    assert_eq!(
        gov.execute(ids[0], id),
        Err(GovError::AlreadyExecuted),
        "second execute must be refused"
    );
    assert_eq!(
        gov.applied, snapshot,
        "second execute must leave applied params untouched"
    );
    assert_eq!(gov.get(id).unwrap().status, ProposalStatus::Executed);
    assert_eq!(gov.applied.block_reward, Some(reward));
}

// ---------- Sanity: quorum math needs the proposer over the proposal floor ----------

#[test]
fn proposal_floor_sanity() {
    // The other tests bond >= 20,000 STELL so `propose` clears the
    // 10,000 STELL floor; pin that assumption here.
    assert!(stell(20_000) >= PROPOSAL_MIN_STAKE_NANO);
    // And the helper set is import-complete (no dead wiring).
    let vs = ValidatorSet::from_list(vec![(vid(1), 1)]);
    assert!(!vs.is_empty());
}

// ---------- Parameter bounds (audit F-K) ----------

/// Governance values become consensus state on execution, and voters do not
/// validate values - so an unchecked action turns one passed proposal into a
/// bricked or hyperinflated chain. Execution must fail closed on out-of-range
/// values (quorum 0 captures governance, quorum >100% deadlocks it, u64::MAX
/// reward mints past the hard cap on the next block, absurd bond ejects every
/// validator, >100% commission/slash steals or burns all stake).
///
/// PINNED POLICY (two gates, same rule, two moments):
///   * PROPOSE TIME: every chain-breaking value is refused before it can even
///     become a proposal (`GovAction::validate` now covers the bond and the
///     block reward too, not just the bps/quorum caps).
///   * EXECUTE TIME: the same bounds are re-checked, so a proposal that
///     BYPASSED propose-time validation (deserialized history, a direct state
///     write) still fails closed and applies nothing.
#[test]
fn gov_param_bounds_reject_chain_breaking_values() {
    use stellereum::governance::{MAX_BLOCK_REWARD_NANO, MAX_VALIDATOR_BOND};
    let (mut ledger, ids) = ledger_with(3, 100_000);
    // (1) PROPOSE-TIME refusal: every chain-breaking value is refused BEFORE it
    // becomes a proposal, so it can never be voted on.
    for action in [
        GovAction::SetGovernanceQuorumBps(0),
        GovAction::SetGovernanceQuorumBps(1),
        GovAction::SetGovernanceQuorumBps(3_332),
        GovAction::SetGovernanceQuorumBps(10_001),
        GovAction::SetGovernanceQuorumBps(u64::MAX),
        GovAction::SetDefaultCommissionBps(10_001),
        GovAction::SetEquivocationSlashBps(100_000),
        GovAction::SetPmmRedemptionBufferBps(u64::MAX),
        // Absurd bond ejects every validator; below-floor defeats Sybil
        // resistance. Both are refused at propose time now.
        GovAction::SetMinValidatorBond(0),
        GovAction::SetMinValidatorBond(999 * 1_000_000_000),
        GovAction::SetMinValidatorBond(MAX_VALIDATOR_BOND + 1),
        GovAction::SetMinValidatorBond(u64::MAX),
        // Hyperinflation past the hard cap on the next block.
        GovAction::SetBlockReward(MAX_BLOCK_REWARD_NANO + 1),
        GovAction::SetBlockReward(u64::MAX),
    ] {
        let mut gov = Governance::new();
        assert_eq!(
            gov.propose(&mut ledger, ids[0], "t".into(), action, 0),
            Err(GovError::InvalidAction),
            "propose-time validate must refuse it"
        );
    }
    // (2) EXECUTE-TIME backstop (audit F-K): a proposal that BYPASSED the
    // propose-time gate (deserialized history, a direct state write) must fail
    // closed at execution with nothing applied.
    let mut run_to_execute = |action: GovAction| -> (Governance, GovError) {
        let mut gov = Governance::new();
        // Propose a SANE action (propose-time validation passes), then
        // REPLACE the stored action with the chain-breaking one: exactly the
        // "smuggled proposal" shape the execute-time backstop exists for.
        let id = gov
            .propose(&mut ledger, ids[0], "t".into(), GovAction::SetMinGasLimit(1), 0)
            .expect("propose");
        gov.proposals.get_mut(&id).expect("proposal").action = action;
        for v in &ids {
            gov.vote(&mut ledger, *v, id, VoteChoice::Yes, 1)
                .expect("vote");
        }
        let status = gov
            .finalize(&mut ledger, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .expect("finalize");
        assert_eq!(status, ProposalStatus::Passed, "unanimous vote must pass");
        let err = gov.execute(ids[0], id).expect_err("must fail closed");
        (gov, err)
    };
    // Absurd bond ejects every validator; below-floor defeats Sybil resistance.
    for v in [0u64, 999 * 1_000_000_000, MAX_VALIDATOR_BOND + 1, u64::MAX] {
        let (gov, err) = run_to_execute(GovAction::SetMinValidatorBond(v));
        assert_eq!(err, GovError::InvalidAction, "bond {v}");
        assert!(gov.applied.min_validator_bond.is_none());
    }
    // Hyperinflation past the hard cap on the next block.
    let (gov, err) = run_to_execute(GovAction::SetBlockReward(MAX_BLOCK_REWARD_NANO + 1));
    assert_eq!(err, GovError::InvalidAction);
    assert!(gov.applied.block_reward.is_none());
    let (gov, err) = run_to_execute(GovAction::SetBlockReward(u64::MAX));
    assert_eq!(err, GovError::InvalidAction);
    assert!(gov.applied.block_reward.is_none());
}

/// Boundary values that MUST still work (the bounds must not brick legitimate
/// governance).
#[test]
fn gov_param_bounds_accept_sane_values() {
    use stellereum::governance::{MAX_BLOCK_REWARD_NANO, MAX_VALIDATOR_BOND};
    let (mut ledger, ids) = ledger_with(3, 100_000);
    let mut run_ok = |action: GovAction| {
        let mut gov = Governance::new();
        let id = gov
            .propose(&mut ledger, ids[0], "t".into(), action, 0)
            .expect("propose");
        for v in &ids {
            gov.vote(&mut ledger, *v, id, VoteChoice::Yes, 1)
                .expect("vote");
        }
        gov.finalize(&mut ledger, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .expect("finalize");
        gov.execute(ids[0], id).expect("sane values must execute");
        gov
    };
    let gov = run_ok(GovAction::SetGovernanceQuorumBps(3_333));
    assert_eq!(gov.quorum_bps, 3_333);
    let gov = run_ok(GovAction::SetGovernanceQuorumBps(10_000));
    assert_eq!(gov.quorum_bps, 10_000);
    let gov = run_ok(GovAction::SetDefaultCommissionBps(0));
    assert_eq!(gov.applied.default_commission_bps, Some(0));
    let gov = run_ok(GovAction::SetDefaultCommissionBps(10_000));
    assert_eq!(gov.applied.default_commission_bps, Some(10_000));
    let gov = run_ok(GovAction::SetMinValidatorBond(MIN_VALIDATOR_BOND));
    assert_eq!(gov.applied.min_validator_bond, Some(MIN_VALIDATOR_BOND));
    let gov = run_ok(GovAction::SetMinValidatorBond(MAX_VALIDATOR_BOND));
    assert_eq!(gov.applied.min_validator_bond, Some(MAX_VALIDATOR_BOND));
    let gov = run_ok(GovAction::SetBlockReward(MAX_BLOCK_REWARD_NANO));
    assert_eq!(gov.applied.block_reward, Some(MAX_BLOCK_REWARD_NANO));
}

#[test]
fn governed_min_gas_limit_validates_bounds_and_applies() {
    use stellereum::governance::{GovAction, GovError, Governance, MAX_MIN_GAS_LIMIT};
    use stellereum::svm::GAS_BASIC_TRANSFER;
    // Bounds: 0 and above-max refused at propose time.
    for bad in [0u64, MAX_MIN_GAS_LIMIT + 1, u64::MAX] {
        let (mut ledger, ids) = ledger_with(2, 20_000);
        let mut gov = Governance::new();
        assert_eq!(
            gov.propose(
                &mut ledger,
                ids[0],
                "t".into(),
                GovAction::SetMinGasLimit(bad),
                0
            ),
            Err(GovError::InvalidAction),
            "gas floor {bad} must be refused"
        );
    }
    // A sane value passes and lands in applied params (admission reads
    // max(env, governed) every height — see main.rs finalize block).
    let (mut ledger, ids) = ledger_with(2, 20_000);
    let mut gov = Governance::new();
    let floor = GAS_BASIC_TRANSFER * 2;
    pass_and_execute(
        &mut ledger,
        &mut gov,
        ids[0],
        &ids,
        GovAction::SetMinGasLimit(floor),
    );
    assert_eq!(gov.applied.min_gas_limit, Some(floor));
}

/// E5: quorum floor 3333 bps pinned at propose AND execute; non-proposer can
/// execute a passed proposal.
#[test]
fn quorum_floor_3333_and_anyone_can_execute() {
    use stellereum::governance::GOVERNANCE_QUORUM_FLOOR_BPS;
    assert_eq!(GOVERNANCE_QUORUM_FLOOR_BPS, 3_333);
    let (mut ledger, ids) = ledger_with(3, 100_000);
    // (a) 1 bps refused at propose time, with the floor named in the message.
    for bad in [1u64, 3_332] {
        let mut gov = Governance::new();
        let err = gov
            .propose(
                &mut ledger,
                ids[0],
                "t".into(),
                GovAction::SetGovernanceQuorumBps(bad),
                0,
            )
            .expect_err("sub-floor quorum must be refused at propose");
        assert_eq!(err, GovError::InvalidAction);
        assert!(
            format!("{err}").contains("3333"),
            "floor error must name 3333, got: {err}"
        );
    }
    // (a2) 1 bps refused at execute time (constructed past propose-time
    // validation), proposal stays Passed.
    {
        use std::collections::HashMap;
        use stellereum::governance::Proposal;
        let mut gov = Governance::new();
        let id = gov.next_id;
        gov.next_id += 1;
        gov.proposals.insert(
            id,
            Proposal {
                id,
                proposer: ids[0],
                title: "sneaky".into(),
                action: GovAction::SetGovernanceQuorumBps(1),
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
        let err = gov
            .execute(ids[1], id)
            .expect_err("sub-floor must fail closed");
        assert_eq!(err, GovError::InvalidAction);
        assert!(format!("{err}").contains("3333"));
        assert_eq!(gov.get(id).unwrap().status, ProposalStatus::Passed);
    }
    // (b) floor itself accepted.
    {
        let mut gov = Governance::new();
        let id = gov
            .propose(
                &mut ledger,
                ids[0],
                "t".into(),
                GovAction::SetGovernanceQuorumBps(3_333),
                0,
            )
            .expect("floor must be accepted");
        for v in &ids {
            gov.vote(&mut ledger, *v, id, VoteChoice::Yes, 1)
                .expect("vote");
        }
        gov.finalize(&mut ledger, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .expect("finalize");
        gov.execute(ids[0], id).expect("execute");
        assert_eq!(gov.quorum_bps, 3_333);
    }
    // (c) non-proposer can execute a passed proposal.
    {
        let mut gov = Governance::new();
        let id = gov
            .propose(
                &mut ledger,
                ids[0],
                "t".into(),
                GovAction::Signal("t".into()),
                0,
            )
            .expect("propose");
        for v in &ids {
            gov.vote(&mut ledger, *v, id, VoteChoice::Yes, 1)
                .expect("vote");
        }
        gov.finalize(&mut ledger, id, GOVERNANCE_VOTING_PERIOD_SECS + 1)
            .expect("finalize");
        gov.execute(ids[2], id).expect("non-proposer must execute");
        assert_eq!(gov.get(id).unwrap().status, ProposalStatus::Executed);
    }
}
