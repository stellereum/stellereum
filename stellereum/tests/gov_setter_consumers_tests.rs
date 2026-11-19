//! PENTEST2 S5 / S7 — governance setters must have a consumer or refuse.
//!
//! * `SetMinValidatorBond` must update the CONSENSUS SET FILTER
//!   (`staking.min_validator_bond`), not just the committed `applied` snapshot.
//! * `SetEquivocationSlashBps` has no wired slash consumer, so it must be
//!   REFUSED at apply (deterministic, proposal stays `Passed`) instead of
//!   committing a parameter nothing enforces.
//! * A `SoftwareUpgrade` cannot execute through the direct executor while the
//!   upgrade gate is closed (the old direct arm bypassed the sweep's gate).
//!
//! Every assertion is on the OBSERVABLE effect, not only on `applied`.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;

use stellereum::governance::{
    upgrade_exec_active_at, GovAction, GovError, Proposal, ProposalStatus, GOV_TIMELOCK_HEIGHTS,
};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

const VALIDATOR: [u8; 32] = [0x61u8; 32];
const BOND_NANO: u64 = 20_000 * 1_000_000_000;
const FUNDS: u64 = 100_000_000_000;
const TS: u64 = 1_760_000_000;

async fn engine_with_passed(action: GovAction) -> InMemoryStateEngine {
    let engine = InMemoryStateEngine::new();
    engine.enable_gov_ops_for_tests();
    engine.credit_native(&VALIDATOR, FUNDS).await.expect("fund");
    engine
        .staking_write()
        .await
        .bond(
            VALIDATOR,
            BOND_NANO,
            stellereum::staking::DEFAULT_COMMISSION_BPS,
        )
        .expect("bond");
    let mut gov = engine.governance_write().await;
    gov.proposals.insert(
        1,
        Proposal {
            id: 1,
            proposer: VALIDATOR,
            title: "passed action".to_string(),
            action,
            created_at: 0,
            voting_end: 0,
            yes: 1,
            no: 0,
            abstain: 0,
            voters: HashMap::new(),
            status: ProposalStatus::Passed,
            electorate: 1,
            electorate_weights: None,
            proposer_lock: 0,
            weights: HashMap::new(),
        },
    );
    gov.next_id = 2;
    drop(gov);
    engine
}

fn empty_block(height: u64) -> Block {
    let txs: Vec<Transaction> = Vec::new();
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS + height,
        proposer: SigningKey::from_bytes(&[0x5Au8; 32])
            .verifying_key()
            .to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
    }
}

#[tokio::test]
async fn set_min_validator_bond_updates_the_consensus_set_filter() {
    let new_min = BOND_NANO * 2;
    let engine = engine_with_passed(GovAction::SetMinValidatorBond(new_min)).await;
    assert!(
        engine
            .staking_read()
            .await
            .to_validator_set()
            .validators
            .contains_key(&VALIDATOR),
        "precondition: the bonded validator is in the set"
    );

    engine.apply_block_transition(&empty_block(1), 0).await;

    let ledger = engine.staking_read().await;
    assert_eq!(
        ledger.min_validator_bond,
        Some(new_min),
        "the consensus set filter must be updated in the same apply step"
    );
    assert!(
        !ledger
            .to_validator_set()
            .validators
            .contains_key(&VALIDATOR),
        "raising the min bond above the self-bond must eject the validator from the set"
    );
    drop(ledger);
    assert_eq!(
        engine.governance_read().await.applied.min_validator_bond,
        Some(new_min)
    );
}

#[tokio::test]
async fn set_equivocation_slash_bps_is_refused_not_silently_committed() {
    let engine = engine_with_passed(GovAction::SetEquivocationSlashBps(9_000)).await;
    let root_before = engine.get_state_root().await;

    engine.apply_block_transition(&empty_block(1), 0).await;

    assert_eq!(
        engine.get_state_root().await,
        root_before,
        "a refused action moves no state"
    );
    let gov = engine.governance_read().await;
    assert_eq!(
        gov.applied.equivocation_slash_bps, None,
        "the decorative parameter must never be committed"
    );
    assert_eq!(
        gov.proposals.get(&1).map(|p| p.status),
        Some(ProposalStatus::Passed),
        "refusal is fail-closed and retryable, never a silent no-op"
    );
}

#[tokio::test]
async fn direct_upgrade_execution_is_refused_while_the_gate_is_closed() {
    // No test override installed: the frozen gate is u64::MAX (inert).
    assert!(!upgrade_exec_active_at(TS));
    let engine = engine_with_passed(GovAction::SoftwareUpgrade {
        name: "v-next".to_string(),
        height: TS + 1_000,
        sha256: [0xABu8; 32],
    })
    .await;

    // A direct call at a (pretend) mature height, the shape the ungated RPC
    // arm used. It must refuse before writing `applied.upgrade_plan`.
    let maturity = 1_000 + GOV_TIMELOCK_HEIGHTS;
    {
        let mut gov = engine.governance_write().await;
        let err = gov
            .execute_at_height([0x77u8; 32], 1, maturity)
            .expect_err("the upgrade executor is gated even on the direct path");
        assert_eq!(err, GovError::Timelocked);
    }
    let gov = engine.governance_read().await;
    assert_eq!(gov.applied.upgrade_plan, None, "no plan was installed");
    assert_eq!(
        gov.proposals.get(&1).map(|p| p.status),
        Some(ProposalStatus::Passed)
    );
}

/// S5 completeness (direct path / snapshot restore): a governed
/// `min_validator_bond` that reached `applied` WITHOUT going through the
/// block-path execution sweep (the solo-node RPC executor, or a restored
/// snapshot) must still reach the CONSENSUS-SET FILTER on the next applied
/// block. The filter reads `staking.min_validator_bond`; leaving it stale
/// means governance "passed" a security parameter that does not apply.
///
/// Before the fix the sweep returned early (nothing due) and the ledger kept
/// `None`, so the under-bonded validator stayed in the set.
#[tokio::test]
async fn governed_min_bond_is_mirrored_even_without_a_due_action() {
    let engine = InMemoryStateEngine::new();
    engine.enable_gov_ops_for_tests();
    engine.credit_native(&VALIDATOR, FUNDS).await.expect("fund");
    engine
        .staking_write()
        .await
        .bond(
            VALIDATOR,
            BOND_NANO,
            stellereum::staking::DEFAULT_COMMISSION_BPS,
        )
        .expect("bond");
    let new_min = BOND_NANO * 2;
    // The direct RPC executor writes `applied` only (state_engine cannot see
    // that call); no proposal is due, so the block sweep has no other reason
    // to touch the ledger.
    engine.governance_write().await.applied.min_validator_bond = Some(new_min);

    engine.apply_block_transition(&empty_block(1), 0).await;

    let ledger = engine.staking_read().await;
    assert_eq!(
        ledger.min_validator_bond,
        Some(new_min),
        "committed governance must be mirrored into the consensus-set filter"
    );
    assert!(
        !ledger
            .to_validator_set()
            .validators
            .contains_key(&VALIDATOR),
        "raising the governed minimum ejects the under-bonded validator"
    );
}
