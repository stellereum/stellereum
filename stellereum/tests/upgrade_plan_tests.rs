//! Coordinated software-upgrade plan: COMMITTED + DETERMINISTIC ally executed.
//!
//! Two defects made the on-chain upgrade path unusable before these tests
//! (verified in `docs/UPGRADE_AND_RECOVERY.md` §1.2.2):
//!
//!  1. `AppliedParams::upgrade_plan` was **not in the state commitment**
//!     (`commitment::governance_digest` had no arm for it), so two nodes could
//!     hold different plans — different target version, halt height or binary
//!     hash — under the SAME state root, and nothing compared them.
//!  2. `Governance::execute_at_height` was called ONLY from the RPC
//!     (`stell_executeProposal`), so a passed and matured plan never executed
//!     unless a human hit one node. Every other node kept its own (empty)
//!     plan, i.e. the halt trigger was local, not consensus.
//!
//! The fix under test:
//!  * the plan is folded into the digest CONDITIONALLY (zero bytes while no
//!    plan is set), so the genesis root is byte-identical and no
//!    `COMMITMENT_VERSION` bump is needed;
//!  * `apply_block_transition` drives a height-pure sweep
//!    (`InMemoryStateEngine::apply_upgrade_execution`) that executes every
//!    passed, timelock-matured upgrade action at the exact block height —
//!    behind the frozen `UPGRADE_EXEC_ACTIVATION_HEIGHT` gate, opened in these
//!    tests through the thread-scoped override (the `QC_SPLIT` pattern).
//!
//! Authority is the EXISTING vote tally (no new vote scheme): a candidate must
//! be `Passed`, and the sweep re-derives `turnout >= quorum`, `yes > no` from
//! the committed proposal before executing. Anything else — a wrong chain id, a
//! plan whose halt height has already passed, a conflicting hash for an
//! already-committed plan, an unsafe/empty version label, a zero digest — is
//! refused loudly and leaves the proposal `Passed`.

use std::sync::Arc;

use stellereum::consensus::{consensus_chain_id, ValidatorSet};
use stellereum::governance::{
    set_upgrade_exec_activation_override, GovAction, ProposalStatus, UpgradePlan, VoteChoice,
    GOVERNANCE_VOTING_PERIOD_SECS, GOV_TIMELOCK_HEIGHTS, UPGRADE_EXEC_ACTIVATION_HEIGHT,
};
use stellereum::sharding::Block;
use stellereum::state_engine::InMemoryStateEngine;

/// Genesis balance per validator: large enough that a genesis validator can
/// also clear `PROPOSAL_MIN_STAKE_NANO` once the fixture raises its bond.
const BAL: u64 = 100_000 * 1_000_000_000;
/// Bond the fixture writes into the ledger before proposing. Direct field write
/// is intentional: it is the committed staking state both engines are given
/// identically, and it avoids depending on `bond`'s pool plumbing.
const FIXTURE_BOND: u64 = 20_000 * 1_000_000_000;
/// A realistic, non-zero block clock (never 0: 0 is the hardcoded-clock bug).
const TS: u64 = 1_760_000_000;
/// The target version + digest of the plan used by most tests.
const VERSION: &str = "v0.2.0";
const DIGEST: [u8; 32] = [0xABu8; 32];
/// Coordinated halt height: must stay in the FUTURE at execution time.
const HALT: u64 = 100_000;

/// Thread-scoped activation guard: clears the override on drop so a panicking
/// assertion cannot leak a reachable gate into another test on the same thread.
struct Gate;

impl Gate {
    fn at(height: u64) -> Self {
        set_upgrade_exec_activation_override(Some(height));
        Self
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        set_upgrade_exec_activation_override(None);
    }
}

fn ids(n: usize) -> Vec<[u8; 32]> {
    (0..n).map(|i| [i as u8 + 1; 32]).collect()
}

async fn engine_with(n: usize) -> (Arc<InMemoryStateEngine>, Vec<[u8; 32]>) {
    let ids = ids(n);
    let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 1)).collect());
    let engine = Arc::new(InMemoryStateEngine::new());
    stellereum::runtime::fund_genesis(&engine, &vs, BAL).await;
    (engine, ids)
}

/// Open, vote (unanimous yes) and finalize an upgrade action at `pass_height`.
/// Returns the proposal id. Uses the REAL governance paths so the authority the
/// sweep re-checks is the authority the vote actually produced.
async fn pass_upgrade(
    engine: &InMemoryStateEngine,
    ids: &[[u8; 32]],
    action: GovAction,
    pass_height: u64,
) -> u64 {
    // Lock order matches the live apply path: governance, then staking.
    let mut gov = engine.governance_write().await;
    let mut ledger = engine.staking_write().await;
    for id in ids {
        if let Some(v) = ledger.validators.get_mut(id) {
            v.self_bond = FIXTURE_BOND;
        }
    }
    let id = gov
        .propose(&mut ledger, ids[0], "upgrade".into(), action, 0)
        .expect("proposal must open");
    for v in ids {
        gov.vote(&mut ledger, *v, id, VoteChoice::Yes, 1)
            .expect("vote must count");
    }
    let status = gov
        .finalize_at_height(
            &mut ledger,
            id,
            GOVERNANCE_VOTING_PERIOD_SECS + 1,
            pass_height,
        )
        .expect("finalize");
    assert_eq!(status, ProposalStatus::Passed, "fixture must pass");
    assert!(
        gov.applied.upgrade_plan.is_none(),
        "opening the proposal must not install a plan"
    );
    id
}

fn upgrade_action(version: &str, halt: u64, digest: [u8; 32]) -> GovAction {
    GovAction::SoftwareUpgrade {
        name: version.to_string(),
        height: halt,
        sha256: digest,
    }
}

/// An EMPTY block (no body, no QC): applying it moves nothing except the
/// upgrade sweep under test, so any root change is attributable to the plan.
fn empty_block(height: u64) -> Block {
    Block {
        height,
        timestamp: TS + height,
        ..Default::default()
    }
}

async fn plan_of(engine: &InMemoryStateEngine) -> Option<UpgradePlan> {
    engine.governance_read().await.applied.upgrade_plan.clone()
}

// ---------------------------------------------------------------------------
// 1. The plan is committed
// ---------------------------------------------------------------------------

/// Installing a plan moves the state root. Before the digest arm existed it did
/// not, so this is the direct regression pin for §1.2.2's "last defect".
#[tokio::test]
async fn a_plan_moves_the_state_root() {
    let (engine, _) = engine_with(3).await;
    let before = engine.get_state_root().await;

    engine.governance_write().await.applied.upgrade_plan = Some(UpgradePlan {
        name: VERSION.into(),
        height: HALT,
        sha256: DIGEST,
    });
    let with_plan = engine.get_state_root().await;
    assert_ne!(
        before, with_plan,
        "a committed upgrade plan MUST move the state root (it is consensus state)"
    );

    // Every field is load-bearing: changing only the version, only the halt
    // height, or only the binary hash must move the root again. Otherwise two
    // materially different plans could collide under one root.
    let mut variants = Vec::new();
    for plan in [
        UpgradePlan {
            name: "v0.2.1".into(),
            height: HALT,
            sha256: DIGEST,
        },
        UpgradePlan {
            name: VERSION.into(),
            height: HALT + 1,
            sha256: DIGEST,
        },
        UpgradePlan {
            name: VERSION.into(),
            height: HALT,
            sha256: [0xCDu8; 32],
        },
    ] {
        engine.governance_write().await.applied.upgrade_plan = Some(plan);
        variants.push(engine.get_state_root().await);
    }
    for (i, root) in variants.iter().enumerate() {
        assert_ne!(
            *root, with_plan,
            "variant {i} must be a distinct committed plan"
        );
        for (j, other) in variants.iter().enumerate() {
            if i != j {
                assert_ne!(*root, *other, "plan variants {i} and {j} must not collide");
            }
        }
    }
}

/// Two engines with identical committed state but DIFFERENT plans must diverge.
/// This is the property that makes a silent "different plan, same root" split
/// impossible, and it is symmetric (same plan ⇒ same root).
#[tokio::test]
async fn two_engines_with_different_plans_diverge_and_reconverge() {
    let (a, _) = engine_with(3).await;
    let (b, _) = engine_with(3).await;
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "the fixtures must start from the same state"
    );

    a.governance_write().await.applied.upgrade_plan = Some(UpgradePlan {
        name: VERSION.into(),
        height: HALT,
        sha256: DIGEST,
    });
    b.governance_write().await.applied.upgrade_plan = Some(UpgradePlan {
        name: VERSION.into(),
        height: HALT,
        sha256: [0x11u8; 32],
    });
    assert_ne!(
        a.get_state_root().await,
        b.get_state_root().await,
        "different plans under one state root would be a silent split"
    );

    // Same plan ⇒ same root: the digest is a pure function of committed state.
    b.governance_write().await.applied.upgrade_plan = Some(UpgradePlan {
        name: VERSION.into(),
        height: HALT,
        sha256: DIGEST,
    });
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "identical plans must converge on one root"
    );

    // Clearing the plan returns to the exact pre-plan root (conditional arm).
    a.governance_write().await.applied.upgrade_plan = None;
    b.governance_write().await.applied.upgrade_plan = None;
    assert_eq!(a.get_state_root().await, b.get_state_root().await);
}

// ---------------------------------------------------------------------------
// 2. Deterministic execution
// ---------------------------------------------------------------------------

/// A matured plan executes exactly at its maturity height, on EVERY node that
/// applies the block, and re-application/replay is a byte-identical no-op.
#[tokio::test]
async fn maturation_executes_at_the_exact_height_and_only_once() {
    let _gate = Gate::at(1);
    let (engine, validators) = engine_with(3).await;
    let pass_height = 1_000u64;
    let id = pass_upgrade(
        &engine,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        pass_height,
    )
    .await;
    let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
    assert_eq!(
        engine.governance_read().await.executable_height_of(id),
        Some(maturity)
    );

    let before = engine.get_state_root().await;

    // One height BEFORE maturity: nothing is due, nothing moves.
    engine
        .apply_block_transition(&empty_block(maturity - 1), 0)
        .await;
    assert_eq!(
        plan_of(&engine).await,
        None,
        "a proposal must not execute before its maturity height"
    );
    assert_eq!(
        engine.get_state_root().await,
        before,
        "a pre-maturity block must be byte-identical"
    );
    assert_eq!(
        engine.governance_read().await.get(id).unwrap().status,
        ProposalStatus::Passed
    );

    // EXACT maturity height: the block itself installs the plan.
    let at_maturity = empty_block(maturity);
    engine.apply_block_transition(&at_maturity, 0).await;
    assert_eq!(
        plan_of(&engine).await,
        Some(UpgradePlan {
            name: VERSION.into(),
            height: HALT,
            sha256: DIGEST,
        }),
        "the matured plan must be installed by the block at maturity"
    );
    assert_eq!(
        engine.governance_read().await.get(id).unwrap().status,
        ProposalStatus::Executed,
        "execution is the single Passed -> Executed transition"
    );
    let executed_root = engine.get_state_root().await;
    assert_ne!(
        executed_root, before,
        "installing the plan must move the committed root"
    );

    // Re-apply the SAME block (replay / reorg re-apply): idempotent.
    let replay = engine.apply_block_transition(&at_maturity, 0).await;
    assert_eq!(
        replay.applied, 0,
        "replay of an empty block applies no transactions"
    );
    assert_eq!(
        engine.get_state_root().await,
        executed_root,
        "re-applying the maturity block must not double-execute or re-root"
    );
    assert_eq!(
        plan_of(&engine).await,
        Some(UpgradePlan {
            name: VERSION.into(),
            height: HALT,
            sha256: DIGEST,
        })
    );

    // Any later height is also a no-op (the proposal is terminal).
    engine
        .apply_block_transition(&empty_block(maturity + 5), 0)
        .await;
    assert_eq!(
        engine.get_state_root().await,
        executed_root,
        "a later block must not re-execute a terminal proposal"
    );
}

/// Two independent engines applying the SAME maturity block land on the same
/// plan AND the same root: the sweep is a pure function of committed state.
#[tokio::test]
async fn two_engines_execute_the_same_plan_at_the_same_height() {
    let _gate = Gate::at(1);
    let (a, validators) = engine_with(3).await;
    let (b, _) = engine_with(3).await;
    let pass_height = 5_000u64;
    pass_upgrade(
        &a,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        pass_height,
    )
    .await;
    pass_upgrade(
        &b,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        pass_height,
    )
    .await;
    assert_eq!(a.get_state_root().await, b.get_state_root().await);

    let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
    let block = empty_block(maturity);
    a.apply_block_transition(&block, 0).await;
    b.apply_block_transition(&block, 0).await;

    assert_eq!(plan_of(&a).await, plan_of(&b).await);
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "the upgrade sweep must be deterministic across nodes"
    );
}

/// PRE-ACTIVATION: with the frozen `u64::MAX` gate (no override) a due plan is
/// NOT executed and the block leaves the root byte-identical. This is what
/// makes the default binary's apply path unchanged.
#[tokio::test]
async fn pre_activation_is_a_byte_identical_no_op() {
    assert_eq!(
        UPGRADE_EXEC_ACTIVATION_HEIGHT,
        u64::MAX,
        "the frozen default must stay inert"
    );
    // No override installed: the gate is `u64::MAX`.
    let (engine, validators) = engine_with(3).await;
    let pass_height = 1_000u64;
    pass_upgrade(
        &engine,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        pass_height,
    )
    .await;
    let before = engine.get_state_root().await;

    engine
        .apply_block_transition(&empty_block(pass_height + GOV_TIMELOCK_HEIGHTS), 0)
        .await;

    assert_eq!(
        plan_of(&engine).await,
        None,
        "pre-activation must not install a plan"
    );
    assert_eq!(
        engine.get_state_root().await,
        before,
        "pre-activation apply must be byte-identical"
    );
}

// ---------------------------------------------------------------------------
// 3. Authority + fail-closed refusals
// ---------------------------------------------------------------------------

/// The sweep re-derives the vote verdict from the committed tally. A proposal
/// whose recorded status says Passed but whose tally never reached quorum is
/// refused (and nothing is installed).
#[tokio::test]
async fn execution_requires_a_real_quorum_from_the_committed_tally() {
    let (engine, validators) = engine_with(3).await;
    let pass_height = 1_000u64;
    let id = pass_upgrade(
        &engine,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        pass_height,
    )
    .await;
    // Smuggle the status past finalize (the deserialised-history case) while
    // leaving the tally at zero: the sweep must not trust the status alone.
    {
        let mut gov = engine.governance_write().await;
        let p = gov.proposals.get_mut(&id).unwrap();
        p.status = ProposalStatus::Passed;
        p.yes = 0;
        p.no = 0;
        p.abstain = 0;
        p.voters.clear();
        p.weights.clear();
    }
    let before = engine.get_state_root().await;
    let chain = consensus_chain_id();
    let out = engine
        .governance_write()
        .await
        .execute_due_upgrades_at_height(pass_height + GOV_TIMELOCK_HEIGHTS, chain);
    assert!(out.executed.is_empty(), "the zero tally must be refused");
    assert_eq!(out.refused.len(), 1, "the zero tally must be refused");
    assert!(
        out.refused[0].1.contains("quorum"),
        "the refusal must name the quorum rule: {}",
        out.refused[0].1
    );
    assert_eq!(plan_of(&engine).await, None);
    assert_eq!(
        engine.get_state_root().await,
        before,
        "a refused execution must not move state"
    );
    assert_eq!(
        engine.governance_read().await.get(id).unwrap().status,
        ProposalStatus::Passed,
        "a refused proposal stays retryable/fail-closed"
    );
}

/// A plan for a DIFFERENT chain id is refused loudly. The plan is executable
/// only on the chain whose votes tallied it (`consensus_chain_id`, the id bound
/// into every vote preimage and block hash).
#[tokio::test]
async fn wrong_chain_id_is_refused() {
    let (engine, validators) = engine_with(3).await;
    let pass_height = 1_000u64;
    let id = pass_upgrade(
        &engine,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        pass_height,
    )
    .await;
    let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
    let chain = consensus_chain_id();
    let foreign = chain.wrapping_add(1);
    assert_ne!(foreign, chain);

    let before = engine.get_state_root().await;
    let out = engine
        .governance_write()
        .await
        .execute_due_upgrades_at_height(maturity, foreign);
    assert!(out.executed.is_empty());
    assert_eq!(out.refused.len(), 1);
    assert!(
        out.refused[0].1.contains("chain id"),
        "the refusal must name the chain binding: {}",
        out.refused[0].1
    );
    assert_eq!(plan_of(&engine).await, None);
    assert_eq!(engine.get_state_root().await, before);
    assert_eq!(
        engine.governance_read().await.get(id).unwrap().status,
        ProposalStatus::Passed
    );

    // The SAME proposal on the correct chain executes.
    let out = engine
        .governance_write()
        .await
        .execute_due_upgrades_at_height(maturity, chain);
    assert_eq!(out.executed, vec![id]);
    assert!(out.refused.is_empty());
    assert_eq!(
        plan_of(&engine).await,
        Some(UpgradePlan {
            name: VERSION.into(),
            height: HALT,
            sha256: DIGEST,
        })
    );
}

/// A plan whose hash does not match the committed plan for the same halt height
/// is refused: an already-committed upgrade can never be silently retargeted at
/// a different binary.
#[tokio::test]
async fn a_plan_that_conflicts_with_the_committed_hash_is_refused() {
    let (engine, validators) = engine_with(3).await;
    let pass_height = 1_000u64;
    let id = pass_upgrade(
        &engine,
        &validators,
        upgrade_action(VERSION, HALT, [0xAAu8; 32]),
        pass_height,
    )
    .await;
    let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
    let chain = consensus_chain_id();

    // A DIFFERENT plan is already committed for this halt height (as if an
    // earlier proposal had been executed): the new hash does not match it.
    let committed = UpgradePlan {
        name: VERSION.into(),
        height: HALT,
        sha256: [0xBBu8; 32],
    };
    engine.governance_write().await.applied.upgrade_plan = Some(committed.clone());
    let before = engine.get_state_root().await;

    let out = engine
        .governance_write()
        .await
        .execute_due_upgrades_at_height(maturity, chain);
    assert!(out.executed.is_empty());
    assert_eq!(out.refused.len(), 1);
    assert!(
        out.refused[0]
            .1
            .contains("does not match the committed plan"),
        "the refusal must name the hash mismatch: {}",
        out.refused[0].1
    );
    assert_eq!(plan_of(&engine).await, Some(committed));
    assert_eq!(
        engine.get_state_root().await,
        before,
        "a refused retarget must not move state"
    );
    assert_eq!(
        engine.governance_read().await.get(id).unwrap().status,
        ProposalStatus::Passed
    );
}

/// Unparseable / mismatched plans are refused and leave the proposal `Passed`:
/// an unsafe version label, a zero halt height, a zero binary hash, or a halt
/// height that has already passed at execution time (the silent dud in §1.2.3).
#[tokio::test]
async fn malformed_and_stale_plans_are_refused() {
    let chain = consensus_chain_id();

    for (label, action) in [
        (
            "unsafe version label",
            upgrade_action("../../etc/evil", HALT, DIGEST),
        ),
        ("zero halt height", upgrade_action(VERSION, 0, DIGEST)),
        ("zero binary hash", upgrade_action(VERSION, HALT, [0u8; 32])),
    ] {
        let (engine, validators) = engine_with(3).await;
        let pass_height = 1_000u64;
        // Propose a VALID plan, then overwrite the committed action: this is
        // exactly the "deserialised history / direct state write" case the
        // propose-time validation cannot see, and the one the execute-time
        // backstops exist for.
        let id = pass_upgrade(
            &engine,
            &validators,
            upgrade_action(VERSION, HALT, DIGEST),
            pass_height,
        )
        .await;
        engine
            .governance_write()
            .await
            .proposals
            .get_mut(&id)
            .unwrap()
            .action = action;
        let before = engine.get_state_root().await;
        let out = engine
            .governance_write()
            .await
            .execute_due_upgrades_at_height(pass_height + GOV_TIMELOCK_HEIGHTS, chain);
        assert!(
            out.executed.is_empty(),
            "{label}: a malformed plan must never execute"
        );
        assert_eq!(out.refused.len(), 1, "{label}: exactly one refusal");
        assert_eq!(plan_of(&engine).await, None, "{label}: no plan installed");
        assert_eq!(
            engine.get_state_root().await,
            before,
            "{label}: state must not move"
        );
        assert_eq!(
            engine.governance_read().await.get(id).unwrap().status,
            ProposalStatus::Passed,
            "{label}: stays fail-closed"
        );
    }

    // STALE: a halt height at or below the execution height is a silent dud in
    // the event-based path (`plan.height == height` fires once, ever).
    let (engine, validators) = engine_with(3).await;
    let pass_height = 1_000u64;
    let stale_halt = pass_height + GOV_TIMELOCK_HEIGHTS;
    let id = pass_upgrade(
        &engine,
        &validators,
        upgrade_action(VERSION, stale_halt, DIGEST),
        pass_height,
    )
    .await;
    let out = engine
        .governance_write()
        .await
        .execute_due_upgrades_at_height(stale_halt, chain);
    assert!(out.executed.is_empty());
    assert_eq!(out.refused.len(), 1);
    assert!(
        out.refused[0].1.contains("not in the future"),
        "a stale halt height must be refused loudly: {}",
        out.refused[0].1
    );
    assert_eq!(
        engine.governance_read().await.get(id).unwrap().status,
        ProposalStatus::Passed
    );
}

/// `CancelUpgrade` is deterministic too: a passed, matured cancel clears the
/// committed plan at the block that matures it.
#[tokio::test]
async fn cancel_upgrade_clears_the_plan_deterministically() {
    let _gate = Gate::at(1);
    let (engine, validators) = engine_with(3).await;
    let pass_height = 2_000u64;
    pass_upgrade(&engine, &validators, GovAction::CancelUpgrade, pass_height).await;
    // The plan to cancel is committed (as if its own SoftwareUpgrade had been
    // executed earlier): the matured CancelUpgrade must clear it on-chain.
    engine.governance_write().await.applied.upgrade_plan = Some(UpgradePlan {
        name: VERSION.into(),
        height: HALT,
        sha256: DIGEST,
    });
    let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
    engine
        .apply_block_transition(&empty_block(maturity), 0)
        .await;
    assert_eq!(
        plan_of(&engine).await,
        None,
        "a matured CancelUpgrade must clear the committed plan"
    );
}

// ---------------------------------------------------------------------------
// 4. Genesis is untouched
// ---------------------------------------------------------------------------

/// The conditional digest arm writes ZERO bytes when no plan is set, so the
/// pinned genesis root is unchanged. Same fixture (validator ids, funding,
/// faucet seed) as `tests/genesis_root_known_answer_tests.rs`; the constant
/// below must only ever move together with that test's `EXPECTED_GENESIS_ROOT`.
#[tokio::test]
async fn genesis_root_is_unchanged_by_the_upgrade_plan_domain() {
    const EXPECTED: &str = "c07880e016dbb60dd84d9d1dd64bd141e4694d99ba919c288b9b08554f9373a5";
    const V1: [u8; 32] = [0x11u8; 32];
    const V2: [u8; 32] = [0x22u8; 32];
    const FAUCET_SEED_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    let engine = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(vec![(V1, 1), (V2, 1)]);
    stellereum::runtime::fund_genesis(&engine, &vs, 100_000_000_000_000_000).await;
    let seed = hex::decode(FAUCET_SEED_HEX).unwrap();
    let faucet = stellereum::rpc::Faucet::new(
        <[u8; 32]>::try_from(seed.as_slice()).unwrap(),
        1,
        100 * 1_000_000_000,
        1_000 * 1_000_000_000,
    );
    let _ = engine
        .credit_native_transfer(&faucet.account(), 1_000_000_000_000_000)
        .await; // GATE: intentional ignore

    assert_eq!(
        hex::encode(engine.get_state_root().await),
        EXPECTED,
        "the upgrade-plan digest arm MUST write zero bytes when no plan is set"
    );
}
