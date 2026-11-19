use super::*;

// -----------------------------------------------------------------------
// Block-carried governance ops (SysCallGovPropose / SysCallGovVote).
//
// The SVM dispatch arms are pure carriers (charge + push); the
// authoritative apply is `apply_gov_ops` (step 5c of
// `apply_block_transition`), gated by `GOV_OPS_ACTIVATION_HEIGHT`
// (INACTIVE default) with a per-instance test override. These tests open
// the gate via `enable_gov_ops_for_tests` (never on the live path) and
// drive the FULL block path, so carrier pricing, step-1 status plumbing
// and the scan are all covered together.
// -----------------------------------------------------------------------

/// Bonded stake per gov-ops test validator: 20k STELL, above
/// `PROPOSAL_MIN_STAKE_NANO` (10k STELL) so propose passes the stake gate.
const GOV_OPS_TEST_STAKE_NANO: u64 = 20_000 * 1_000_000_000;
/// Native funds per gov-ops test account: covers carrier gas with margin.
const GOV_OPS_TEST_FUNDS: u64 = 5_000_000;

/// Fresh engine with the gov gate open and `seeds` bonded as validators
/// (each seed also funds its Falcon-512 test account). Returns the engine
/// plus the validator addresses in seed order.
async fn gov_ops_engine_with_validators(seeds: &[u8]) -> (InMemoryStateEngine, Vec<[u8; 32]>) {
    let engine = InMemoryStateEngine::new();
    engine.enable_gov_ops_for_tests();
    let mut addrs = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let (addr, _pk) = pq_pair(*seed);
        engine
            .credit_native(&addr, GOV_OPS_TEST_FUNDS)
            .await
            .unwrap();
        engine
            .staking_write()
            .await
            .bond(
                addr,
                GOV_OPS_TEST_STAKE_NANO,
                crate::staking::DEFAULT_COMMISSION_BPS,
            )
            .expect("gov-ops test validator must bond");
        addrs.push(addr);
    }
    (engine, addrs)
}

/// Minimal decided block carrying `txs` at (`height`, `timestamp`),
/// signed by a fresh classical proposer key (block-signature
/// verification is outside tx admission, same as the existing block-path
/// tests).
fn gov_ops_block(
    proposer: &ed25519_dalek::SigningKey,
    height: u64,
    timestamp: u64,
    txs: Vec<crate::sharding::Transaction>,
) -> crate::sharding::Block {
    use crate::sharding::{Block, MASTERCHAIN_SHARD};
    let order_merkle_root = crate::mev::compute_order_merkle_root(&txs);
    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp,
        proposer: proposer.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    };    block.sign_block(proposer);
    block
}

fn gov_ops_proposer() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
}

fn gov_ops_signal_action() -> Box<crate::governance::GovAction> {
    Box::new(crate::governance::GovAction::Signal(
        "gov-ops test".to_string(),
    ))
}

/// Post-activation happy path: a bonded validator's block-carried propose
/// opens proposal 1 through the full block path, byte-identical to the
/// direct path (same proposer, same electorate snapshot, same lock).
#[tokio::test]
async fn gov_ops_propose_happy_path_post_activation() {
    use crate::svm::OpCode;
    let (engine, addrs) = gov_ops_engine_with_validators(&[0xC1]).await;
    let proposer = gov_ops_proposer();
    let (tx, _, _) = pq_tx_payload(
        0xC1,
        [0x77u8; 32],
        0,
        1_000_000,
        0,
        vec![OpCode::SysCallGovPropose {
            proposal_id: 1,
            title: "gov-ops propose".to_string(),
            action: gov_ops_signal_action(),
            height_observed: 1,
        }],
    );
    let block = gov_ops_block(&proposer, 1, 1000, vec![tx]);
    let outcome = engine.apply_block_transition(&block, 0).await;
    assert_eq!(outcome.status, vec![true], "carrier must succeed step 1");
    let gov = engine.governance_read().await;
    assert_eq!(gov.next_id, 2, "one proposal consumed id 1");
    let p = gov.proposals.get(&1).expect("proposal 1 must exist");
    assert_eq!(
        p.proposer, addrs[0],
        "proposer is the tx signer, never a field"
    );
    assert_eq!(p.title, "gov-ops propose");
    assert_eq!(
        p.created_at, 1000,
        "block timestamp is the clock, never wall-clock"
    );
    assert_eq!(
        p.voting_end,
        1000 + crate::governance::GOVERNANCE_VOTING_PERIOD_SECS
    );
    assert!(matches!(p.action, crate::governance::GovAction::Signal(_)));
}

/// Post-activation happy path: a block-carried vote records the
/// snapshot-weighted tally (self-bond, no delegations) and the voter.
#[tokio::test]
async fn gov_ops_vote_happy_path_post_activation() {
    use crate::svm::OpCode;
    let (engine, addrs) = gov_ops_engine_with_validators(&[0xC2]).await;
    let proposer = gov_ops_proposer();
    let (ptx, _, _) = pq_tx_payload(
        0xC2,
        [0x77u8; 32],
        0,
        1_000_000,
        0,
        vec![OpCode::SysCallGovPropose {
            proposal_id: 1,
            title: "gov-ops vote base".to_string(),
            action: gov_ops_signal_action(),
            height_observed: 1,
        }],
    );
    let block1 = gov_ops_block(&proposer, 1, 1000, vec![ptx]);
    let o1 = engine.apply_block_transition(&block1, 0).await;
    assert_eq!(o1.status, vec![true]);
    let (vtx, _, _) = pq_tx_payload(
        0xC2,
        [0x77u8; 32],
        0,
        1_000_000,
        1,
        vec![OpCode::SysCallGovVote {
            proposal_id: 1,
            choice: crate::governance::VoteChoice::Yes,
            height_observed: 2,
        }],
    );
    let block2 = gov_ops_block(&proposer, 2, 1001, vec![vtx]);
    let o2 = engine.apply_block_transition(&block2, 0).await;
    assert_eq!(o2.status, vec![true], "carrier must succeed step 1");
    let expected_weight = GOV_OPS_TEST_STAKE_NANO as u128;
    let gov = engine.governance_read().await;
    let p = gov.proposals.get(&1).expect("proposal 1 must exist");
    assert_eq!(
        p.yes, expected_weight,
        "tally is the propose-time snapshot weight"
    );
    assert_eq!(p.no, 0);
    assert_eq!(
        p.voters.get(&addrs[0]),
        Some(&crate::governance::VoteChoice::Yes)
    );
}

/// Duplicate refusal: a second propose naming an already-consumed id
/// refuses WITHOUT failing the block (the carrier still succeeds; only
/// the scan refuses) and moves no governance state.
#[tokio::test]
async fn gov_ops_duplicate_propose_refuses() {
    use crate::svm::OpCode;
    let (engine, _) = gov_ops_engine_with_validators(&[0xC3]).await;
    let proposer = gov_ops_proposer();
    let mk_propose = |nonce: u64, height: u64| {
        pq_tx_payload(
            0xC3,
            [0x77u8; 32],
            0,
            1_000_000,
            nonce,
            vec![OpCode::SysCallGovPropose {
                proposal_id: 1,
                title: "dup".to_string(),
                action: gov_ops_signal_action(),
                height_observed: height,
            }],
        )
        .0
    };
    let o1 = engine
        .apply_block_transition(
            &gov_ops_block(&proposer, 1, 1000, vec![mk_propose(0, 1)]),
            0,
        )
        .await;
    assert_eq!(o1.status, vec![true]);
    // Same id again in the next block: stale id, must refuse.
    let o2 = engine
        .apply_block_transition(
            &gov_ops_block(&proposer, 2, 1001, vec![mk_propose(1, 2)]),
            0,
        )
        .await;
    assert_eq!(
        o2.status,
        vec![true],
        "duplicate refusal never fails the block (gas already paid)"
    );
    let gov = engine.governance_read().await;
    assert_eq!(gov.next_id, 2, "duplicate consumed no id");
    assert_eq!(gov.proposals.len(), 1, "duplicate opened nothing");
    // A future id also refuses (no skipping past unconsumed ids).
    drop(gov);
    let (future_tx, _, _) = pq_tx_payload(
        0xC3,
        [0x77u8; 32],
        0,
        1_000_000,
        2,
        vec![OpCode::SysCallGovPropose {
            proposal_id: 7,
            title: "future".to_string(),
            action: gov_ops_signal_action(),
            height_observed: 3,
        }],
    );
    let o3 = engine
        .apply_block_transition(&gov_ops_block(&proposer, 3, 1002, vec![future_tx]), 0)
        .await;
    assert_eq!(o3.status, vec![true]);
    let gov = engine.governance_read().await;
    assert_eq!(gov.next_id, 2, "future id consumed no id");
    assert_eq!(gov.proposals.len(), 1, "future id opened nothing");
}

/// One-vote rule: a different choice refuses `AlreadyVoted` (tally
/// frozen); a same-choice replay is idempotent (Ok, tally unchanged).
/// Neither refusal fails its block.
#[tokio::test]
async fn gov_ops_double_vote_refuses_and_replay_idempotent() {
    use crate::svm::OpCode;
    let (engine, addrs) = gov_ops_engine_with_validators(&[0xC4]).await;
    let proposer = gov_ops_proposer();
    let (ptx, _, _) = pq_tx_payload(
        0xC4,
        [0x77u8; 32],
        0,
        1_000_000,
        0,
        vec![OpCode::SysCallGovPropose {
            proposal_id: 1,
            title: "one-vote".to_string(),
            action: gov_ops_signal_action(),
            height_observed: 1,
        }],
    );
    let o1 = engine
        .apply_block_transition(&gov_ops_block(&proposer, 1, 1000, vec![ptx]), 0)
        .await;
    assert_eq!(o1.status, vec![true]);
    let mk_vote = |nonce: u64, height: u64, choice: crate::governance::VoteChoice| {
        pq_tx_payload(
            0xC4,
            [0x77u8; 32],
            0,
            1_000_000,
            nonce,
            vec![OpCode::SysCallGovVote {
                proposal_id: 1,
                choice,
                height_observed: height,
            }],
        )
        .0
    };
    let yes_w = GOV_OPS_TEST_STAKE_NANO as u128;
    let o2 = engine
        .apply_block_transition(
            &gov_ops_block(
                &proposer,
                2,
                1001,
                vec![mk_vote(1, 2, crate::governance::VoteChoice::Yes)],
            ),
            0,
        )
        .await;
    assert_eq!(o2.status, vec![true]);
    // Different choice: refused, tally frozen.
    let o3 = engine
        .apply_block_transition(
            &gov_ops_block(
                &proposer,
                3,
                1002,
                vec![mk_vote(2, 3, crate::governance::VoteChoice::No)],
            ),
            0,
        )
        .await;
    assert_eq!(
        o3.status,
        vec![true],
        "double-vote refusal never fails the block"
    );
    // Same-choice replay: idempotent Ok, tally unchanged.
    let o4 = engine
        .apply_block_transition(
            &gov_ops_block(
                &proposer,
                4,
                1003,
                vec![mk_vote(3, 4, crate::governance::VoteChoice::Yes)],
            ),
            0,
        )
        .await;
    assert_eq!(o4.status, vec![true]);
    let gov = engine.governance_read().await;
    let p = gov.proposals.get(&1).expect("proposal 1 must exist");
    assert_eq!(
        p.yes, yes_w,
        "exactly one counted weight after flip attempt + replay"
    );
    assert_eq!(p.no, 0, "refused flip recorded nothing");
    assert_eq!(
        p.voters.get(&addrs[0]),
        Some(&crate::governance::VoteChoice::Yes),
        "first choice wins"
    );
}

/// Closed-window refusal: a vote at/after `voting_end` refuses
/// (`VotingClosed`, same as the direct path) and records nothing.
#[tokio::test]
async fn gov_ops_closed_window_vote_refuses() {
    use crate::svm::OpCode;
    let (engine, _) = gov_ops_engine_with_validators(&[0xC5]).await;
    let proposer = gov_ops_proposer();
    let (ptx, _, _) = pq_tx_payload(
        0xC5,
        [0x77u8; 32],
        0,
        1_000_000,
        0,
        vec![OpCode::SysCallGovPropose {
            proposal_id: 1,
            title: "window".to_string(),
            action: gov_ops_signal_action(),
            height_observed: 1,
        }],
    );
    let o1 = engine
        .apply_block_transition(&gov_ops_block(&proposer, 1, 1000, vec![ptx]), 0)
        .await;
    assert_eq!(o1.status, vec![true]);
    let late_ts = 1000 + crate::governance::GOVERNANCE_VOTING_PERIOD_SECS + 1;
    let (vtx, _, _) = pq_tx_payload(
        0xC5,
        [0x77u8; 32],
        0,
        1_000_000,
        1,
        vec![OpCode::SysCallGovVote {
            proposal_id: 1,
            choice: crate::governance::VoteChoice::Yes,
            height_observed: 2,
        }],
    );
    let o2 = engine
        .apply_block_transition(&gov_ops_block(&proposer, 2, late_ts, vec![vtx]), 0)
        .await;
    assert_eq!(
        o2.status,
        vec![true],
        "closed-window refusal never fails the block"
    );
    let gov = engine.governance_read().await;
    let p = gov.proposals.get(&1).expect("proposal 1 must exist");
    assert_eq!(p.yes, 0, "late vote recorded no weight");
    assert!(p.voters.is_empty(), "late vote recorded no voter");
}

/// Pre-activation refusal: with the gate forced closed (per-thread override;
/// the shipped `GOV_OPS_ACTIVATION_HEIGHT` is `0`, active from genesis), a
/// block-carried propose moves NOTHING — the standard apply path is
/// byte-identical — while the carrier itself still succeeds (gas paid, no
/// block failure).
struct ClosedGovGate;

impl ClosedGovGate {
    fn install() -> Self {
        crate::governance::set_gov_ops_activation_override(Some(u64::MAX));
        Self
    }
}

impl Drop for ClosedGovGate {
    fn drop(&mut self) {
        crate::governance::set_gov_ops_activation_override(None);
    }
}

#[tokio::test]
async fn gov_ops_pre_activation_refuses_and_moves_nothing() {
    use crate::svm::OpCode;
    assert_eq!(
        GOV_OPS_ACTIVATION_HEIGHT, 0,
        "gate must ship ACTIVE from genesis (block-carried governance is the only N>1 write path)"
    );
    let _closed = ClosedGovGate::install();
    let engine = InMemoryStateEngine::new();
    // Gate closed by the per-thread override.
    assert!(!engine.gov_ops_active_at(1));
    assert!(!engine.gov_ops_active_at(u64::MAX - 1));
    let (addr, _pk) = pq_pair(0xC6);
    engine
        .credit_native(&addr, GOV_OPS_TEST_FUNDS)
        .await
        .unwrap();
    engine
        .staking_write()
        .await
        .bond(
            addr,
            GOV_OPS_TEST_STAKE_NANO,
            crate::staking::DEFAULT_COMMISSION_BPS,
        )
        .expect("bond");
    let proposer = gov_ops_proposer();
    let (tx, _, _) = pq_tx_payload(
        0xC6,
        [0x77u8; 32],
        0,
        1_000_000,
        0,
        vec![OpCode::SysCallGovPropose {
            proposal_id: 1,
            title: "pre-activation".to_string(),
            action: gov_ops_signal_action(),
            height_observed: 1,
        }],
    );
    let block = gov_ops_block(&proposer, 1, 1000, vec![tx]);
    let outcome = engine.apply_block_transition(&block, 0).await;
    assert_eq!(
        outcome.status,
        vec![true],
        "carrier succeeds even pre-activation"
    );
    let scan = engine.apply_gov_ops(&block, &outcome.status).await;
    assert_eq!(scan.proposed, 0);
    assert_eq!(scan.voted, 0);
    assert_eq!(
        scan.refused, 1,
        "the lone gov op refused at the closed gate"
    );
    let gov = engine.governance_read().await;
    assert_eq!(gov.next_id, 1, "pre-activation consumed no id");
    assert!(gov.proposals.is_empty(), "pre-activation opened nothing");
}

/// Determinism: applying the SAME block twice reaches the SAME state.
/// The replay's tx fails step 1 (nonce consumed), the scan refuses the
/// duplicate id, and neither the state root nor governance moves.
#[tokio::test]
async fn gov_ops_same_block_twice_same_state() {
    use crate::svm::OpCode;
    let (engine, _) = gov_ops_engine_with_validators(&[0xC7]).await;
    let proposer = gov_ops_proposer();
    let (tx, _, _) = pq_tx_payload(
        0xC7,
        [0x77u8; 32],
        0,
        1_000_000,
        0,
        vec![OpCode::SysCallGovPropose {
            proposal_id: 1,
            title: "determinism".to_string(),
            action: gov_ops_signal_action(),
            height_observed: 1,
        }],
    );
    let block = gov_ops_block(&proposer, 1, 1000, vec![tx]);
    let o1 = engine.apply_block_transition(&block, 0).await;
    assert_eq!(o1.status, vec![true]);
    let root1 = engine.get_state_root().await;
    let (next1, n1) = {
        let gov = engine.governance_read().await;
        (gov.next_id, gov.proposals.len())
    };
    let o2 = engine.apply_block_transition(&block, 0).await;
    assert_eq!(
        o2.status,
        vec![false],
        "replay fails step 1 (nonce consumed)"
    );
    let root2 = engine.get_state_root().await;
    let (next2, n2) = {
        let gov = engine.governance_read().await;
        (gov.next_id, gov.proposals.len())
    };
    assert_eq!(root1, root2, "same block twice yields the same state root");
    assert_eq!(
        (next1, n1),
        (next2, n2),
        "same block twice moves no governance"
    );
    assert_eq!((next1, n1), (2, 1));
}
