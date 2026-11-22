//! On-chain governance on a MULTI-VALIDATOR network.
//!
//! The regression these tests pin: governance used to be inert on any N>1
//! deployment. Block-carried propose/vote opcodes were gated off
//! (`GOV_OPS_ACTIVATION_HEIGHT = u64::MAX`) and the only write path that
//! actually applied an action was the direct RPC mutation, which refuses
//! whenever the in-force validator set has more than one member (a local
//! write would fork the state root).
//!
//! The fix:
//!  * `GOV_OPS_ACTIVATION_HEIGHT = 0` (active from genesis — see the constant's
//!    doc for why a new chain can activate at height 0);
//!  * a gov operation submitted over RPC is a TRANSACTION carrying the gov
//!    opcode (`Governance::gov_propose_tx` / `gov_vote_tx`), admitted to the
//!    mempool and applied by the normal block path exactly like a transfer;
//!  * `apply_block_transition` deterministically finalizes proposals whose
//!    voting window closed at `block.timestamp` and executes every passed,
//!    timelock-matured action at `block.height` — on every node, from block
//!    bytes + committed state only;
//!  * the N>1 refusal remains ONLY on the direct-ledger-write path.
//!
//! Every test drives the REAL block path (`apply_block_transition`), so the
//! carrier pricing, step-1 status plumbing, finalize sweep and executor are
//! covered together.

use ed25519_dalek::SigningKey;

use stellereum::governance::{
    governance_write_allowed, GovAction, Governance, ProposalStatus, VoteChoice,
    GOVERNANCE_VOTING_PERIOD_SECS, GOV_TIMELOCK_HEIGHTS,
};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::sharding::{Block, PqSignatureEnvelope, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::OpCode;

/// Realistic block clock (never 0: 0 is the hardcoded-clock bug).
const TS: u64 = 1_760_000_000;
/// Bonded stake per validator: above `PROPOSAL_MIN_STAKE_NANO` (10k STELL).
const BOND_NANO: u64 = 20_000 * 1_000_000_000;
/// Native balance per validator: covers the declared carrier gas.
const FUNDS_NANO: u64 = 1_000_000_000;
/// Declared gas for one carrier transaction (fees are the declared limit in
/// this revision, so this is also the fee).
const GAS: u64 = 1_000_000;

/// One node's committed engine plus its validator identities.
struct Node {
    engine: InMemoryStateEngine,
    keys: Vec<FalconKeypair>,
}

impl Node {
    /// Fresh engine with `n` equal-stake validators, each funded enough to pay
    /// for its carrier transactions.
    async fn new(n: u8) -> Self {
        let engine = InMemoryStateEngine::new();
        let mut keys = Vec::with_capacity(n as usize);
        for seed in 0..n {
            let kp = FalconKeypair::generate_from_seed(seed);
            let addr = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
            engine
                .credit_native(&addr, FUNDS_NANO)
                .await
                .expect("fund validator");
            engine
                .staking_write()
                .await
                .bond(addr, BOND_NANO, stellereum::staking::DEFAULT_COMMISSION_BPS)
                .expect("bond validator");
            keys.push(kp);
        }
        Self { engine, keys }
    }

    async fn apply(&self, block: &Block) {
        self.engine.apply_block_transition(block, 0).await;
    }
}

fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT)
}

/// Sign a transaction template with the caller's own Falcon-512 key. This is
/// exactly the wallet flow: build the carrier (`gov_propose_tx` /
/// `gov_vote_tx`), sign `signing_message()`, submit the sealed tx.
fn sign_with(kp: &FalconKeypair, mut tx: Transaction) -> Transaction {
    let msg = tx.signing_message();
    let sig = kp.sign(&msg);
    tx.signature = PqSignatureEnvelope::new_explicit_with_salt(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
        DEFAULT_SALT,
    )
    .encode();
    tx
}

fn propose_tx(
    kp: &FalconKeypair,
    nonce: u64,
    proposal_id: u64,
    title: &str,
    action: GovAction,
    height: u64,
) -> Transaction {
    let tx = Governance::gov_propose_tx(
        pq_addr(kp),
        nonce,
        GAS,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        proposal_id,
        title.to_string(),
        action,
        height,
    )
    .expect("propose builder");
    sign_with(kp, tx)
}

fn vote_tx(
    kp: &FalconKeypair,
    nonce: u64,
    proposal_id: u64,
    choice: VoteChoice,
    height: u64,
) -> Transaction {
    let tx = Governance::gov_vote_tx(
        pq_addr(kp),
        nonce,
        GAS,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        proposal_id,
        choice,
        height,
    );
    sign_with(kp, tx)
}

/// Minimal decided block carrying `txs` at (`height`, `timestamp`).
fn block(height: u64, timestamp: u64, txs: Vec<Transaction>) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    let proposer = SigningKey::from_bytes(&[0x5Au8; 32]);
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
    };
    block.sign_block(&proposer);
    block
}

/// Open + vote + finalize + execute one governance action on the block path.
/// Returns (proposal id, maturity height, finalization block, execution block).
async fn run_action(
    node: &Node,
    votes: usize,
    action: GovAction,
    title: &str,
) -> (u64, u64, Block, Block) {
    let id = 1u64;
    let mut txs = vec![propose_tx(&node.keys[0], 0, id, title, action, 1)];
    node.apply(&block(1, TS, txs)).await;
    assert_eq!(
        node.engine
            .governance_read()
            .await
            .proposals
            .get(&id)
            .map(|p| p.status),
        Some(ProposalStatus::Open),
        "block-carried propose must open the proposal"
    );

    // Vote: each validator uses its own transaction nonce (the proposer
    // already consumed nonce 0).
    txs = Vec::new();
    for (i, key) in node.keys.iter().enumerate().take(votes) {
        let nonce = if i == 0 { 1 } else { 0 };
        txs.push(vote_tx(key, nonce, id, VoteChoice::Yes, 2));
    }
    node.apply(&block(2, TS + 1, txs)).await;

    // Voting window closed: the next block finalizes deterministically.
    let finalize_height = 3u64;
    let after_window = TS + GOVERNANCE_VOTING_PERIOD_SECS + 1;
    let finalize_block = block(finalize_height, after_window, vec![]);
    node.apply(&finalize_block).await;

    let maturity = finalize_height + GOV_TIMELOCK_HEIGHTS;
    let execute_block = block(maturity, after_window + 1, vec![]);
    node.apply(&execute_block).await;
    (id, maturity, finalize_block, execute_block)
}

// ---------------------------------------------------------------------------
// 1. propose -> vote -> finalize -> mature -> execute on N=3
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multi_validator_parameter_change_executes_on_the_block_path() {
    let node = Node::new(3).await;
    let new_reward = 2_000_000_000u64; // 2 STELL, within MAX_BLOCK_REWARD_NANO
    let (id, _maturity, _, _) = run_action(
        &node,
        2,
        GovAction::SetBlockReward(new_reward),
        "raise block reward",
    )
    .await;

    let gov = node.engine.governance_read().await;
    let p = gov.proposals.get(&id).expect("proposal exists");
    assert_eq!(
        p.status,
        ProposalStatus::Executed,
        "a quorum-passed, matured parameter change must execute"
    );
    assert_eq!(
        gov.applied.block_reward,
        Some(new_reward),
        "the executed action's value is committed governance state"
    );
    assert_eq!(
        p.yes,
        2 * BOND_NANO as u128,
        "both yes votes counted at their snapshot weight"
    );
}

/// Oracle actions execute through the SAME deterministic sweep, writing the
/// governance half and the oracle half all-or-nothing (`execute_with_oracle`).
#[tokio::test]
async fn oracle_action_executes_from_the_block_path() {
    let node = Node::new(3).await;
    let publisher = [0xABu8; 32];
    let (id, _maturity, _, _) = run_action(
        &node,
        2,
        GovAction::RegisterOraclePublisher(publisher),
        "register publisher",
    )
    .await;

    let gov = node.engine.governance_read().await;
    assert_eq!(
        gov.proposals.get(&id).map(|p| p.status),
        Some(ProposalStatus::Executed)
    );
    drop(gov);
    assert!(
        node.engine
            .oracle_read()
            .await
            .publishers
            .contains(&publisher),
        "the oracle domain must carry the ratified publisher"
    );
}

/// The direct-ledger-write guard is UNCHANGED for N>1 (it would fork), while
/// the block-carried transaction path is available and is what the RPC block
/// form admits. This pins the policy split the fix is built on.
#[test]
fn multinode_guard_stays_on_the_direct_path_only() {
    assert_eq!(
        stellereum::governance::GOV_OPS_ACTIVATION_HEIGHT,
        0,
        "block-carried governance is active from genesis"
    );
    assert!(stellereum::governance::gov_ops_active_at(0));
    let kp = FalconKeypair::generate_from_seed(7);
    assert!(
        governance_write_allowed(3, false).is_err(),
        "a direct governance write on N>1 must stay refused"
    );
    let tx = Governance::gov_propose_tx(
        pq_addr(&kp),
        0,
        GAS,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        1,
        "tx form".to_string(),
        GovAction::Signal("block carried".to_string()),
        1,
    )
    .expect("block-carried builder is always available");
    assert!(matches!(
        tx.payload.as_slice(),
        [OpCode::SysCallGovPropose { .. }]
    ));
}

// ---------------------------------------------------------------------------
// 2. Two nodes derive identical governance state from the same blocks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_nodes_derive_the_same_governance_state_from_the_same_blocks() {
    let a = Node::new(3).await;
    let b = Node::new(3).await;
    let new_reward = 3_000_000_000u64;

    // Build the SAME block sequence once, apply it to both nodes.
    let id = 1u64;
    let b1 = block(
        1,
        TS,
        vec![propose_tx(
            &a.keys[0],
            0,
            id,
            "deterministic",
            GovAction::SetBlockReward(new_reward),
            1,
        )],
    );
    let b2 = block(
        2,
        TS + 1,
        vec![
            vote_tx(&a.keys[0], 1, id, VoteChoice::Yes, 2),
            vote_tx(&a.keys[1], 0, id, VoteChoice::Yes, 2),
        ],
    );
    let after_window = TS + GOVERNANCE_VOTING_PERIOD_SECS + 1;
    let b3 = block(3, after_window, vec![]);
    let b4 = block(3 + GOV_TIMELOCK_HEIGHTS, after_window + 1, vec![]);

    for block in [&b1, &b2, &b3, &b4] {
        a.apply(block).await;
        b.apply(block).await;
        assert_eq!(
            a.engine.get_state_root().await,
            b.engine.get_state_root().await,
            "the same block must produce the same state root on every node"
        );
    }

    let ga = a.engine.governance_read().await;
    let gb = b.engine.governance_read().await;
    assert_eq!(
        ga.get(id).map(|p| (p.status, p.yes, p.no)),
        gb.get(id).map(|p| (p.status, p.yes, p.no)),
        "tally + status are derived from block bytes, not node-local state"
    );
    assert_eq!(ga.applied, gb.applied, "applied params converge");
    assert_eq!(ga.applied.block_reward, Some(new_reward));
}

// ---------------------------------------------------------------------------
// 3. No quorum -> no execution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn proposal_without_quorum_does_not_execute() {
    let node = Node::new(3).await;
    let new_reward = 4_000_000_000u64;
    let (id, _maturity, _, _) = run_action(
        &node,
        1,
        GovAction::SetBlockReward(new_reward),
        "raise block reward",
    )
    .await;

    let gov = node.engine.governance_read().await;
    let p = gov.proposals.get(&id).expect("proposal exists");
    assert_eq!(
        p.status,
        ProposalStatus::Rejected,
        "one of three equal bonds is below the 2/3 quorum"
    );
    assert_eq!(
        gov.applied.block_reward, None,
        "a proposal without quorum must not move the applied params"
    );

    // Even blocks AFTER the timelock height execute nothing.
    drop(gov);
    let before = node.engine.get_state_root().await;
    node.apply(&block(3 + GOV_TIMELOCK_HEIGHTS + 5, TS + 10_000, vec![]))
        .await;
    assert_eq!(
        node.engine.get_state_root().await,
        before,
        "a rejected proposal is terminal: later blocks move no state"
    );
    let gov = node.engine.governance_read().await;
    assert_eq!(
        gov.proposals.get(&id).map(|p| p.status),
        Some(ProposalStatus::Rejected)
    );
    assert_eq!(gov.applied.block_reward, None);
}

// ---------------------------------------------------------------------------
// 4. Replayed blocks do not double-execute
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replayed_blocks_do_not_double_execute() {
    let node = Node::new(3).await;
    let new_reward = 5_000_000_000u64;
    let (id, _maturity, finalize_block, execute_block) = run_action(
        &node,
        2,
        GovAction::SetBlockReward(new_reward),
        "raise block reward",
    )
    .await;

    let root = node.engine.get_state_root().await;
    let applied = node.engine.governance_read().await.applied.clone();
    assert_eq!(applied.block_reward, Some(new_reward));

    // Replay the execution block (empty body) and the finalization block.
    node.apply(&execute_block).await;
    node.apply(&finalize_block).await;

    assert_eq!(
        node.engine.get_state_root().await,
        root,
        "replaying a terminal block must leave the root byte-identical"
    );
    let gov = node.engine.governance_read().await;
    assert_eq!(gov.applied, applied, "no second application of the action");
    assert_eq!(
        gov.proposals.get(&id).map(|p| p.status),
        Some(ProposalStatus::Executed),
        "single-shot Passed -> Executed transition"
    );
}

/// Replaying the PROPOSE block is also a no-op for governance: the
/// transaction fails step 1 (nonce consumed) and the carrier applies nothing,
/// so the state root does not move.
#[tokio::test]
async fn replayed_propose_block_moves_no_governance_state() {
    let node = Node::new(3).await;
    let ptx = propose_tx(
        &node.keys[0],
        0,
        1,
        "replay propose",
        GovAction::Signal("once".to_string()),
        1,
    );
    let b = block(1, TS, vec![ptx]);
    node.apply(&b).await;
    let root = node.engine.get_state_root().await;
    let next_id = node.engine.governance_read().await.next_id;

    node.apply(&b).await;
    assert_eq!(
        node.engine.get_state_root().await,
        root,
        "same block twice yields the same root"
    );
    let gov = node.engine.governance_read().await;
    assert_eq!(gov.next_id, next_id, "no second proposal minted");
    assert_eq!(gov.proposals.len(), 1);
}
