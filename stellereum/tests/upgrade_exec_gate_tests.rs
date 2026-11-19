//! On-chain upgrade execution armed from the GENESIS CHAIN SPEC.
//!
//! The compiled `UPGRADE_EXEC_ACTIVATION_HEIGHT` is only the default for a
//! chain that does not set the gate. The effective value is
//! `chain_spec::GenesisChainSpec::upgrade_exec_activation_height`, fixed once
//! per process by `install_genesis_chain_spec` (tests drive the same value
//! through the thread-scoped override, the `QC_SPLIT_ACTIVATION_HEIGHT`
//! pattern used across the tree).
//!
//! These tests pin the safety rules that make the gate usable:
//!  * below the chain-spec height a passed plan is NOT installed; at/after it
//!    the plan installs;
//!  * a chain that does not set the gate keeps the old `u64::MAX` behaviour;
//!  * a plan whose halt height is at/below the current block is refused (no
//!    retroactive plans);
//!  * installation is single-shot and `CancelUpgrade` clears the plan, before
//!    AND after the gate opens;
//!  * the plan is committed: two nodes with different plans have different
//!    state roots.

use std::sync::Arc;

use stellereum::chain_spec::{
    active_genesis_chain_spec, set_genesis_chain_spec_override, GenesisChainSpec,
    DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT,
};
use stellereum::consensus::{consensus_chain_id, ValidatorSet};
use stellereum::governance::{
    GovAction, GovError, ProposalStatus, UpgradePlan, VoteChoice, GOVERNANCE_VOTING_PERIOD_SECS,
    GOV_TIMELOCK_HEIGHTS, UPGRADE_EXEC_ACTIVATION_HEIGHT,
};
use stellereum::sharding::Block;
use stellereum::state_engine::InMemoryStateEngine;

const BAL: u64 = 100_000 * 1_000_000_000;
const FIXTURE_BOND: u64 = 20_000 * 1_000_000_000;
const TS: u64 = 1_760_000_000;
const VERSION: &str = "v0.2.0";
const DIGEST: [u8; 32] = [0xABu8; 32];
const HALT: u64 = 100_000;

/// Thread-scoped genesis chain-spec guard: clears the override on drop so a
/// panicking assertion cannot leak a reachable gate into another test.
struct ChainSpecGate;

impl ChainSpecGate {
    fn at(height: u64) -> Self {
        set_genesis_chain_spec_override(Some(GenesisChainSpec::new(height)));
        Self
    }
}

impl Drop for ChainSpecGate {
    fn drop(&mut self) {
        set_genesis_chain_spec_override(None);
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

/// Open, vote (unanimous yes) and finalize an action at `pass_height`.
async fn pass_action(
    engine: &InMemoryStateEngine,
    ids: &[[u8; 32]],
    action: GovAction,
    pass_height: u64,
) -> u64 {
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
    id
}

fn upgrade_action(version: &str, halt: u64, digest: [u8; 32]) -> GovAction {
    GovAction::SoftwareUpgrade {
        name: version.to_string(),
        height: halt,
        sha256: digest,
    }
}

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
// 1. Default chain spec == old compiled behaviour
// ---------------------------------------------------------------------------

#[test]
fn default_chain_spec_keeps_the_old_u64_max_gate() {
    assert_eq!(
        UPGRADE_EXEC_ACTIVATION_HEIGHT,
        u64::MAX,
        "the compiled default must stay inert"
    );
    assert_eq!(
        DEFAULT_UPGRADE_EXEC_ACTIVATION_HEIGHT,
        u64::MAX,
        "the chain-spec default must be the same compiled sentinel"
    );
    assert_eq!(
        active_genesis_chain_spec(),
        GenesisChainSpec::compiled_default(),
        "a chain that sets nothing gets the compiled default"
    );
    assert!(!active_genesis_chain_spec().upgrade_exec_active_at(u64::MAX - 1));
    assert!(!stellereum::governance::upgrade_exec_active_at(
        u64::MAX - 1
    ));
    let schedule = stellereum::chain_spec::current_activation_schedule();
    assert_eq!(
        schedule.is_active("UPGRADE_EXEC_ACTIVATION_HEIGHT", u64::MAX - 1),
        Some(false),
        "the operator-visible schedule must show the default gate is off"
    );
}

// ---------------------------------------------------------------------------
// 2. Gate H: refused below, installed at/after
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gate_h_refuses_below_and_installs_at_or_after_h() {
    let pass_height = 1_000u64;
    let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
    let gate_h = maturity + 1;

    let _gate = ChainSpecGate::at(gate_h);
    assert!(!stellereum::governance::upgrade_exec_active_at(maturity));
    assert!(stellereum::governance::upgrade_exec_active_at(gate_h));

    let (engine, validators) = engine_with(3).await;
    pass_action(
        &engine,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        pass_height,
    )
    .await;
    let before = engine.get_state_root().await;

    // Maturity is due, but the genesis chain-spec gate is still closed: the
    // block must be a byte-identical no-op and the proposal stays retryable.
    engine
        .apply_block_transition(&empty_block(maturity), 0)
        .await;
    assert_eq!(
        plan_of(&engine).await,
        None,
        "a plan must not install below the chain-spec height"
    );
    assert_eq!(
        engine.get_state_root().await,
        before,
        "a pre-gate block must not move the root"
    );
    assert_eq!(
        engine
            .governance_read()
            .await
            .count_status(ProposalStatus::Passed),
        1,
        "the refused action stays Passed"
    );

    // The first block at H opens the gate and installs the same plan.
    engine.apply_block_transition(&empty_block(gate_h), 0).await;
    assert_eq!(
        plan_of(&engine).await,
        Some(UpgradePlan {
            name: VERSION.into(),
            height: HALT,
            sha256: DIGEST,
        }),
        "the block at the chain-spec height must install the plan"
    );
    assert_ne!(
        engine.get_state_root().await,
        before,
        "installing the plan must move the committed root"
    );
    assert_eq!(
        engine
            .governance_read()
            .await
            .count_status(ProposalStatus::Executed),
        1
    );
}

// ---------------------------------------------------------------------------
// 3. No retroactive plans
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_plan_at_or_below_the_current_height_is_refused_at_apply() {
    let _gate = ChainSpecGate::at(1);
    let pass_height = 1_000u64;
    let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;

    for halt in [maturity, maturity.saturating_sub(1)] {
        let (engine, validators) = engine_with(3).await;
        // The proposal itself is valid at propose time (halt is in the future
        // then); the REFUSAL is the apply-time retroactivity rule.
        let id = pass_action(
            &engine,
            &validators,
            upgrade_action(VERSION, halt, DIGEST),
            pass_height,
        )
        .await;
        let before = engine.get_state_root().await;

        // The sweep already has a pre-check; exercise the DIRECT executor too,
        // because every path must enforce the same rule.
        let err = engine
            .governance_write()
            .await
            .execute_at_height([0x77u8; 32], id, maturity)
            .expect_err("a halt height at/below the current height is retroactive");
        assert_eq!(err, GovError::InvalidAction);
        assert_eq!(plan_of(&engine).await, None);
        assert_eq!(
            engine.get_state_root().await,
            before,
            "a refused retroactive plan must not move state"
        );
        assert_eq!(
            engine.governance_read().await.get(id).unwrap().status,
            ProposalStatus::Passed,
            "refusal is fail-closed and retryable"
        );
    }
}

#[tokio::test]
async fn the_legacy_heightless_execute_refuses_a_plan_instead_of_guessing() {
    let _gate = ChainSpecGate::at(0);
    let (engine, validators) = engine_with(3).await;
    let id = pass_action(
        &engine,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        1_000,
    )
    .await;
    // Exercise the legacy executor itself, not the KI-23 timelock: drop the
    // scheduled maturity so the height-less call reaches the plan arm.
    engine.governance_write().await.timelocks.remove(&id);

    let err = engine
        .governance_write()
        .await
        .execute([0x77u8; 32], id)
        .expect_err("without a block height a retroactive plan cannot be ruled out");
    assert_eq!(err, GovError::InvalidAction);
    assert_eq!(plan_of(&engine).await, None);
}

// ---------------------------------------------------------------------------
// 4. Install once, cancel before/after the gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plan_installs_exactly_once_and_replays_are_no_ops() {
    let _gate = ChainSpecGate::at(1);
    let pass_height = 2_000u64;
    let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
    let (engine, validators) = engine_with(3).await;
    pass_action(
        &engine,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        pass_height,
    )
    .await;

    engine
        .apply_block_transition(&empty_block(maturity), 0)
        .await;
    let installed = plan_of(&engine).await.expect("the plan installs");
    let root = engine.get_state_root().await;

    // Replay and later blocks must not double-execute or re-root.
    engine
        .apply_block_transition(&empty_block(maturity), 0)
        .await;
    engine
        .apply_block_transition(&empty_block(maturity + 10), 0)
        .await;
    assert_eq!(plan_of(&engine).await, Some(installed));
    assert_eq!(engine.get_state_root().await, root);
    assert_eq!(
        engine
            .governance_read()
            .await
            .count_status(ProposalStatus::Executed),
        1
    );
}

#[tokio::test]
async fn cancel_upgrade_clears_the_plan_before_and_after_the_gate_opens() {
    let gate_h = 10_000u64;
    let _gate = ChainSpecGate::at(gate_h);
    let (engine, validators) = engine_with(3).await;

    // BEFORE the gate: a cancel is a safety valve and must still execute.
    let before_pass_height = 1_000u64;
    let before_maturity = before_pass_height + GOV_TIMELOCK_HEIGHTS;
    assert!(before_maturity < gate_h);
    pass_action(
        &engine,
        &validators,
        GovAction::CancelUpgrade,
        before_pass_height,
    )
    .await;
    engine.governance_write().await.applied.upgrade_plan = Some(UpgradePlan {
        name: VERSION.into(),
        height: HALT,
        sha256: DIGEST,
    });
    engine
        .apply_block_transition(&empty_block(before_maturity), 0)
        .await;
    assert_eq!(
        plan_of(&engine).await,
        None,
        "a cancel below the gate height must clear the plan"
    );

    // AFTER the gate: the same action still clears a new plan.
    let after_pass_height = gate_h + 1_000;
    let after_maturity = after_pass_height + GOV_TIMELOCK_HEIGHTS;
    assert!(after_maturity >= gate_h);
    pass_action(
        &engine,
        &validators,
        GovAction::CancelUpgrade,
        after_pass_height,
    )
    .await;
    engine.governance_write().await.applied.upgrade_plan = Some(UpgradePlan {
        name: VERSION.into(),
        height: HALT,
        sha256: DIGEST,
    });
    engine
        .apply_block_transition(&empty_block(after_maturity), 0)
        .await;
    assert_eq!(
        plan_of(&engine).await,
        None,
        "a cancel at/after the gate height must clear the plan"
    );
    assert_eq!(
        engine
            .governance_read()
            .await
            .count_status(ProposalStatus::Executed),
        2,
        "each cancel is a single-shot committed execution"
    );
}

// ---------------------------------------------------------------------------
// 5. The plan is in the commitment digest
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_nodes_with_different_plans_have_different_roots() {
    let (a, _) = engine_with(3).await;
    let (b, _) = engine_with(3).await;
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "the fixtures start from identical genesis"
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
        "two different committed plans must not share a state root"
    );

    // Same plan => same root: the digest is a pure function of the plan.
    b.governance_write().await.applied.upgrade_plan = Some(UpgradePlan {
        name: VERSION.into(),
        height: HALT,
        sha256: DIGEST,
    });
    assert_eq!(a.get_state_root().await, b.get_state_root().await);

    // Clearing is deterministic too.
    a.governance_write().await.applied.upgrade_plan = None;
    b.governance_write().await.applied.upgrade_plan = None;
    assert_eq!(a.get_state_root().await, b.get_state_root().await);
}

// ---------------------------------------------------------------------------
// 6. The chain-spec value is in the genesis commitment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn different_chain_spec_values_have_different_genesis_roots() {
    // Two chains with the same validator/funding inputs but different
    // upgrade-execution gates must not share a genesis root.
    let a_ids = ids(3);
    set_genesis_chain_spec_override(Some(GenesisChainSpec::new(100)));
    let a = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(a_ids.iter().map(|id| (*id, 1)).collect());
    stellereum::runtime::fund_genesis(&a, &vs, BAL).await;
    let root_a = a.get_state_root().await;

    set_genesis_chain_spec_override(Some(GenesisChainSpec::new(101)));
    let b = Arc::new(InMemoryStateEngine::new());
    stellereum::runtime::fund_genesis(&b, &vs, BAL).await;
    let root_b = b.get_state_root().await;
    set_genesis_chain_spec_override(None);

    assert_ne!(
        root_a, root_b,
        "the chain-spec gate must be part of the genesis identity"
    );

    // The compiled default still hashes to the pre-chain-spec root: an
    // explicit `u64::MAX` spec is equivalent to not setting one.
    let c = Arc::new(InMemoryStateEngine::new());
    stellereum::runtime::fund_genesis(&c, &vs, BAL).await;
    let root_default = c.get_state_root().await;
    assert_eq!(
        root_default,
        {
            set_genesis_chain_spec_override(Some(GenesisChainSpec::compiled_default()));
            let d = Arc::new(InMemoryStateEngine::new());
            stellereum::runtime::fund_genesis(&d, &vs, BAL).await;
            let root = d.get_state_root().await;
            set_genesis_chain_spec_override(None);
            root
        },
        "the compiled default must remain byte-identical to an explicit default"
    );
}

// ---------------------------------------------------------------------------
// 7. The chain spec is the single source of truth for every execution path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sweep_and_direct_path_observe_the_same_genesis_gate() {
    let h = 9_000u64;
    let _gate = ChainSpecGate::at(h);
    assert_eq!(
        stellereum::governance::upgrade_exec_activation_height(),
        h,
        "the governance predicate must read the chain-spec value"
    );
    assert_eq!(stellereum::chain_spec::upgrade_exec_activation_height(), h);

    let (engine, validators) = engine_with(3).await;
    let pass_height = 1_000u64;
    let maturity = pass_height + GOV_TIMELOCK_HEIGHTS;
    let id = pass_action(
        &engine,
        &validators,
        upgrade_action(VERSION, HALT, DIGEST),
        pass_height,
    )
    .await;

    // Below H the sweep refuses and the direct executor refuses identically.
    if maturity < h {
        let out = engine
            .governance_write()
            .await
            .execute_due_upgrades_at_height(maturity, consensus_chain_id());
        assert!(out.executed.is_empty());
        assert!(!out.refused.is_empty());
        let err = engine
            .governance_write()
            .await
            .execute_at_height([0x77u8; 32], id, maturity)
            .expect_err("the direct path uses the same gate");
        assert_eq!(err, GovError::Timelocked);
    }
}
