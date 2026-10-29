//! Partition-heal tests: a partitioned network must heal, not deadlock.
//!
//! Background: the live stand once deadlocked permanently after a network
//! partition because (a) a 1-block height skew made each side reject the other
//! as "wrong height", (b) round counters diverged, and (c) there was no
//! block-body sync. The catch-up machinery in `src/sync.rs`
//! (`collect_missing_blocks` / `validate_sync_chain`) plus the round-counter
//! caps in `src/consensus.rs` exist to fix exactly that. These tests prove a
//! partitioned network heals, all in-process (no real network, no sleeps).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use stellereum::consensus::{HeightConsensus, ValidatorSet, Vote, VoteKind};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::sync::{collect_missing_blocks, validate_sync_chain};

// ============================================================================
// Helpers
// ============================================================================

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}

fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

async fn funded(payer: [u8; 32], bal: u64) -> Arc<InMemoryStateEngine> {
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(payer, bal)).await;
    st
}

/// A REAL block: proper `prev_hash` linkage, header committing to the state
/// root in force *before* the block (the F3.2 rule), signed by its declared
/// proposer. Quorum co-signatures are added separately via `quorum_sign`.
fn mkblock(
    height: u64,
    prev: [u8; 32],
    pre_root: [u8; 32],
    proposer: &SigningKey,
    txs: Vec<Transaction>,
    timestamp: u64,
) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root: pre_root,
        transactions: txs,
        cross_shard_out: vec![],
        timestamp,
        proposer: id(proposer),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(proposer);
    b
}

/// Attach a genuine precommit QC so the block carries a quorum that
/// `validate_sync_chain` can verify (membership + power).
///
/// The quorum lives in the QC, not in extra block-hash signatures: validators agree
/// via votes (over vote_sign_bytes), and only the QC proves they did.
fn quorum_sign(b: &mut Block, ks: &[SigningKey], round: u32) {
    let bh = b.compute_hash();
    let sigs = ks
        .iter()
        .map(|k| {
            let v = Vote::sign(k, b.height, round, VoteKind::Precommit, Some(bh));
            (v.voter, v.signature)
        })
        .collect();
    b.precommit_qc = Some(stellereum::consensus::QuorumCertificate {
        height: b.height,
        round,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: sigs,
    });
}

fn store(blocks: &[Block]) -> HashMap<[u8; 32], Block> {
    blocks
        .iter()
        .map(|b| (b.compute_hash(), b.clone()))
        .collect()
}

/// The catch-up sequence as the node performs it: walk `prev_hash` back to our
/// own finalized block, refuse forks and quorum-less histories, then replay
/// each block only after checking its header commits to the state we hold.
async fn catch_up(
    map: &HashMap<[u8; 32], Block>,
    head: [u8; 32],
    our_last: [u8; 32],
    first_height: u64,
    validators: &ValidatorSet,
    our_state: &Arc<InMemoryStateEngine>,
) -> Result<u64, String> {
    let missing = collect_missing_blocks(head, our_last, 100_000, |h| {
        let b = map.get(&h).cloned();
        async move { b }
    })
    .await?;
    if missing.is_empty() {
        return Ok(0);
    }
    if missing[0].height != first_height {
        return Err(format!(
            "first synced height {} != expected {first_height}",
            missing[0].height
        ));
    }
    validate_sync_chain(&missing, first_height, our_last, validators)?;
    for b in &missing {
        let root_before = our_state.get_state_root().await;
        if root_before != b.state_root {
            return Err(format!(
                "block {} commits to {} but our state is {}",
                b.height,
                hex::encode(b.state_root),
                hex::encode(root_before)
            ));
        }
        let (applied, failed, _, _, _) = our_state
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
        if failed != 0 || applied != b.transactions.len() {
            return Err(format!(
                "block {} applied {applied}/{} txs ({} failed)",
                b.height,
                b.transactions.len(),
                failed
            ));
        }
    }
    Ok(missing.len() as u64)
}

/// Drive one height to decision with exactly `voters`' votes. Returns the
/// decided hash, or `None` when the voters hold less than quorum.
fn decide_with(
    hc: &mut HeightConsensus,
    voters: &[SigningKey],
    height: u64,
    round: u32,
    bh: [u8; 32],
) -> Option<[u8; 32]> {
    for k in voters {
        hc.add_prevote(Vote::sign(k, height, round, VoteKind::Prevote, Some(bh)))
            .unwrap();
    }
    hc.try_prevote_quorum();
    for k in voters {
        hc.add_precommit(Vote::sign(k, height, round, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    hc.try_precommit_quorum()
}

// ============================================================================
// Test 1 — split brain 2+2: neither side finalizes, then both converge.
// ============================================================================

#[tokio::test]
async fn split_brain_two_plus_two_finalizes_nothing_then_heals() {
    let ks = keys(4);
    let vs = vset(&ks);
    assert_eq!(vs.quorum_power(), 3, "4 validators need 3 for quorum");

    // One funded payer; both sides start from byte-identical state.
    let payer_key = SigningKey::generate(&mut OsRng);
    let payer = id(&payer_key);
    let recipient = [0x99u8; 32];
    let eng_a = funded(payer, 1_000_000_000).await;
    let eng_b = funded(payer, 1_000_000_000).await;

    // The proposer's block is disseminated just before the split, so both
    // sides vote on the SAME value; only the votes are partitioned.
    let proposer_idx = vs
        .proposer_for(1, 0)
        .map(|p| ks.iter().position(|k| id(k) == p).unwrap());
    let proposer_idx = proposer_idx.expect("non-empty set has a proposer");
    let pre_root = eng_a.get_state_root().await;
    assert_eq!(pre_root, eng_b.get_state_root().await);
    let tx = Transaction::sign(&payer_key, recipient, 1_000, 0, 0, 1, 1);
    let mut block = mkblock(1, [0u8; 32], pre_root, &ks[proposer_idx], vec![tx], 1_000);
    // Only the two sides' own keys ever sign: each partition holds 2 of 3 needed.
    // On heal both sides' votes combine into one QC over all four keys.
    quorum_sign(&mut block, &ks, 0);
    let bh = block.compute_hash();
    {
        let qc = block
            .precommit_qc
            .as_ref()
            .expect("quorum_sign attaches a QC");
        assert!(qc.verify(&vs), "the reunited votes must form a real quorum");
    }

    let mut side_a = HeightConsensus::new(1, vs.clone());
    let mut side_b = HeightConsensus::new(1, vs.clone());
    let prop = vs.proposer_for(1, 0).unwrap();
    side_a.receive_proposal(prop, bh).unwrap();
    side_b.receive_proposal(prop, bh).unwrap();

    // Partition {0,1} vs {2,3}: each side sees only its own two votes.
    for k in &ks[..2] {
        side_a
            .add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
        side_a
            .add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    for k in &ks[2..] {
        side_b
            .add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
        side_b
            .add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }

    // NEITHER side may finalize: 2 of 4 is below the quorum of 3.
    assert_eq!(
        side_a.try_prevote_quorum(),
        None,
        "2 prevotes are not a quorum"
    );
    assert_eq!(
        side_b.try_prevote_quorum(),
        None,
        "2 prevotes are not a quorum"
    );
    assert_eq!(side_a.try_precommit_quorum(), None, "side A must stall");
    assert_eq!(side_b.try_precommit_quorum(), None, "side B must stall");
    assert_eq!(side_a.decided, None);
    assert_eq!(side_b.decided, None);

    // HEAL: deliver all cross-partition votes and blocks.
    for k in &ks[2..] {
        side_a
            .add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
        side_a
            .add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    for k in &ks[..2] {
        side_b
            .add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
        side_b
            .add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    // Late votes for the round we waited in still count (rounds_to_inspect).
    assert_eq!(side_a.try_precommit_quorum(), Some(bh));
    assert_eq!(side_b.try_precommit_quorum(), Some(bh));
    assert_eq!(side_a.decided, Some(bh), "side A converges");
    assert_eq!(
        side_b.decided,
        Some(bh),
        "side B converges on the SAME hash"
    );

    // Both sides apply the reunited block after the F3.2 root check.
    // The block already carries the reunited 4-of-4 QC attached above; re-assert
    // it here so the applied block keeps a genuine quorum (not a sub-quorum).
    quorum_sign(&mut block, &ks, 0);
    for (eng, name) in [(&eng_a, "A"), (&eng_b, "B")] {
        assert_eq!(
            eng.get_state_root().await,
            block.state_root,
            "side {name} header must commit to its pre-apply root"
        );
        let (applied, failed, _, _, _) = eng
            .apply_block_parallel_fees(&block.transactions, block.timestamp)
            .await;
        assert_eq!((applied, failed), (1, 0), "side {name} must apply the tx");
    }
    assert_eq!(
        eng_a.get_state_root().await,
        eng_b.get_state_root().await,
        "both sides converge on the same state root"
    );
}

// ============================================================================
// Test 2 — asymmetric partition 3+1: majority finalizes, minority catches up.
// ============================================================================

#[tokio::test]
async fn asymmetric_partition_three_plus_one_heals_via_block_sync() {
    let ks = keys(4);
    let vs = vset(&ks);
    let majority: Vec<SigningKey> = ks[..3].to_vec();
    let lone = &ks[3];

    let payer_key = SigningKey::generate(&mut OsRng);
    let payer = id(&payer_key);
    let recipient = [0x77u8; 32];
    // Majority nodes each hold their OWN engine; the isolated node holds its own.
    let mut maj_engines = vec![];
    for _ in 0..3 {
        maj_engines.push(funded(payer, 1_000_000_000).await);
    }
    let lone_engine = funded(payer, 1_000_000_000).await;

    // The isolated node sits at height 1 with no votes at all.
    let mut lone_hc = HeightConsensus::new(1, vs.clone());

    const HEIGHTS: u64 = 6;
    let mut chain: Vec<Block> = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=HEIGHTS {
        // If the schedule names the isolated validator, the majority walks
        // past it with view changes until one of its own must propose.
        let mut round: u32 = 0;
        let mut maj_hc = HeightConsensus::new(h, vs.clone());
        while !majority
            .iter()
            .any(|k| id(k) == vs.proposer_for(h, round).unwrap())
        {
            maj_hc.next_round();
            round += 1;
        }
        let prop = vs.proposer_for(h, round).unwrap();
        let proposer = majority.iter().find(|k| id(k) == prop).unwrap().clone();

        // REAL block: links to the majority head, commits to the pre-apply root.
        let pre_root = maj_engines[0].get_state_root().await;
        for e in &maj_engines[1..] {
            assert_eq!(
                e.get_state_root().await,
                pre_root,
                "majority stays in lockstep"
            );
        }
        let tx = Transaction::sign(&payer_key, recipient, 1_000, 0, h - 1, 1, 1);
        let mut b = mkblock(h, prev, pre_root, &proposer, vec![tx], 1_000 + h);
        quorum_sign(&mut b, &majority, round);
        let bh = b.compute_hash();
        assert!(b.verify_proposer_signature());
        // The quorum lives in the attached precommit QC, not in extra block-hash
        // signatures: production blocks carry the proposer signature plus the QC,
        // because validators agree via votes and only the QC proves they did.
        {
            let qc = b.precommit_qc.as_ref().expect("quorum_sign attaches a QC");
            assert_eq!(qc.kind, VoteKind::Precommit);
            assert_eq!(qc.block_hash, Some(bh));
            assert!(
                qc.verify(&vs),
                "3 of 4 is a genuine quorum the isolated node can verify"
            );
        }

        // The 3-side runs a real round and finalizes without the isolated node.
        maj_hc.receive_proposal(prop, bh).unwrap();
        assert_eq!(
            decide_with(&mut maj_hc, &majority, h, round, bh),
            Some(bh),
            "the 3-side finalizes height {h}"
        );
        for e in &maj_engines {
            assert_eq!(e.get_state_root().await, b.state_root, "F3.2 root check");
            let (applied, failed, _, _, _) = e
                .apply_block_parallel_fees(&b.transactions, b.timestamp)
                .await;
            assert_eq!((applied, failed), (1, 0));
        }

        // The 1-side sees nothing and stalls: no proposal, no votes, no decision.
        assert_eq!(
            lone_hc.try_precommit_quorum(),
            None,
            "the isolated node stalls"
        );
        assert_eq!(lone_hc.decided, None);

        prev = bh;
        chain.push(b);
    }
    let majority_root = maj_engines[0].get_state_root().await;
    for e in &maj_engines[1..] {
        assert_eq!(
            e.get_state_root().await,
            majority_root,
            "the majority replicas agree with each other"
        );
    }

    // HEAL: the isolated node catches up via block sync and lands on the
    // majority's root.
    let map = store(&chain);
    let head = chain.last().unwrap().compute_hash();
    let n = catch_up(&map, head, [0u8; 32], 1, &vs, &lone_engine)
        .await
        .expect("heal must succeed");
    assert_eq!(
        n, HEIGHTS,
        "exactly the {HEIGHTS} missed blocks are replayed"
    );
    assert_eq!(
        lone_engine.get_state_root().await,
        majority_root,
        "the isolated node lands on the majority's root"
    );
    let _ = lone;
}

// ============================================================================
// Test 3 — long gap (N=25): exact replay; a hole is an error, never partial.
// ============================================================================

#[tokio::test]
async fn long_gap_replays_exactly_n_and_a_hole_is_an_error() {
    const N: u64 = 25;
    let ks = keys(4);
    let vs = vset(&ks);

    let payer_key = SigningKey::generate(&mut OsRng);
    let payer = id(&payer_key);
    let recipient = [0x55u8; 32];
    let builder = funded(payer, 1_000_000_000_000).await;

    // Build N REAL blocks, each committing to its pre-apply root.
    let mut chain: Vec<Block> = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=N {
        let prop = vs.proposer_for(h, 0).unwrap();
        let proposer = ks.iter().find(|k| id(k) == prop).unwrap().clone();
        let pre_root = builder.get_state_root().await;
        let tx = Transaction::sign(&payer_key, recipient, 1_000, 0, h - 1, 1, 1);
        let mut b = mkblock(h, prev, pre_root, &proposer, vec![tx], 2_000 + h);
        quorum_sign(&mut b, &ks, 0);
        let (applied, failed, _, _, _) = builder
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
        assert_eq!((applied, failed), (1, 0), "build tx {h} must execute");
        prev = b.compute_hash();
        chain.push(b);
    }
    let network_root = builder.get_state_root().await;
    let map = store(&chain);
    let head = chain.last().unwrap().compute_hash();

    // The isolated node missed all N blocks; catch-up replays exactly N.
    let isolated = funded(payer, 1_000_000_000_000).await;
    let n = catch_up(&map, head, [0u8; 32], 1, &vs, &isolated)
        .await
        .expect("a 25-block gap must heal");
    assert_eq!(n, N, "catch-up replays exactly N blocks");
    assert_eq!(
        isolated.get_state_root().await,
        network_root,
        "the final root matches the network's"
    );

    // A gap the walk cannot close: the body in the middle was never published.
    let hole_hash = chain[12].compute_hash();
    let partial: HashMap<[u8; 32], Block> = map
        .iter()
        .filter(|(h, _)| **h != hole_hash)
        .map(|(h, b)| (*h, b.clone()))
        .collect();
    let victim = funded(payer, 1_000_000_000_000).await;
    let before = victim.get_state_root().await;
    let err = catch_up(&partial, head, [0u8; 32], 1, &vs, &victim)
        .await
        .expect_err("a hole in the middle must be an ERROR, not a silent partial advance");
    assert!(
        err.contains("missing"),
        "the error must name the missing block: {err}"
    );
    assert!(
        err.contains(&hex::encode(hole_hash)[..16]),
        "the error must identify WHICH block is missing: {err}"
    );
    assert_eq!(
        victim.get_state_root().await,
        before,
        "a failed catch-up must leave state untouched (no partial advance)"
    );
}

// ============================================================================
// Test 4 — a forked history with a foreign quorum is REFUSED.
// ============================================================================

#[tokio::test]
async fn forked_history_with_a_foreign_quorum_is_refused() {
    let ks = keys(4);
    let vs = vset(&ks);
    // A DIFFERENT validator set: same size, disjoint keys, its own quorum.
    let foreign_keys = keys(4);
    for k in &foreign_keys {
        assert_eq!(vs.power_of(&id(k)), 0, "foreign keys hold no power here");
    }
    let foreign_vs = vset(&foreign_keys);

    let payer_key = SigningKey::generate(&mut OsRng);
    let payer = id(&payer_key);
    let ours = funded(payer, 1_000_000_000).await;

    // OUR chain through height 6 (recipient A).
    let mut prev = [0u8; 32];
    let mut own: Vec<Block> = Vec::new();
    for h in 1..=6u64 {
        let prop = vs.proposer_for(h, 0).unwrap();
        let proposer = ks.iter().find(|k| id(k) == prop).unwrap().clone();
        let pre_root = ours.get_state_root().await;
        let tx = Transaction::sign(&payer_key, [0xAAu8; 32], 1_000, 0, h - 1, 1, 1);
        let mut b = mkblock(h, prev, pre_root, &proposer, vec![tx], 3_000 + h);
        quorum_sign(&mut b, &ks, 0);
        let (applied, failed, _, _, _) = ours
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
        assert_eq!((applied, failed), (1, 0));
        prev = b.compute_hash();
        own.push(b);
    }
    let own_root = ours.get_state_root().await;
    let own_last_3 = own[2].compute_hash(); // our finalized block at height 3
    let own_head = own.last().unwrap().compute_hash();

    // The peer's FORK: same heights 4..=6, correctly linked to OUR block 3
    // (so the parent-link check passes), different hashes (recipient B), and a
    // quorum that is genuine -- but from the FOREIGN set.
    let fork_state = funded(payer, 1_000_000_000).await;
    for b in own.iter().take(3) {
        let (applied, failed, _, _, _) = fork_state
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
        assert_eq!((applied, failed), (1, 0));
    }
    assert_eq!(fork_state.get_state_root().await, own[3].state_root);
    let mut fork: Vec<Block> = Vec::new();
    let mut fprev = own_last_3;
    for h in 4..=6u64 {
        let prop = foreign_vs.proposer_for(h, 0).unwrap();
        let proposer = foreign_keys.iter().find(|k| id(k) == prop).unwrap().clone();
        let pre_root = fork_state.get_state_root().await;
        let tx = Transaction::sign(&payer_key, [0xBBu8; 32], 9_999, 0, h - 1, 1, 1);
        let mut b = mkblock(h, fprev, pre_root, &proposer, vec![tx], 9_000 + h);
        quorum_sign(&mut b, &foreign_keys, 0);
        let (applied, failed, _, _, _) = fork_state
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
        assert_eq!((applied, failed), (1, 0));
        fprev = b.compute_hash();
        fork.push(b);
    }
    assert_ne!(
        fork.last().unwrap().compute_hash(),
        own_head,
        "the fork really diverges (same heights, different hashes)"
    );
    // The fork IS well-formed under its own set: refusal is about membership.
    assert!(
        validate_sync_chain(&fork, 4, own_last_3, &foreign_vs).is_ok(),
        "the fork carries a valid quorum from its own set"
    );

    // REFUSED against our own set, and the node keeps its own chain.
    let err = validate_sync_chain(&fork, 4, own_last_3, &vs)
        .expect_err("a forked history with a foreign quorum must be REFUSED");
    assert!(
        err.contains("quorum"),
        "the refusal must be the quorum check, not a malformed block: {err}"
    );
    let node = funded(payer, 1_000_000_000).await;
    for b in &own {
        let (applied, failed, _, _, _) = node
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
        assert_eq!((applied, failed), (1, 0));
    }
    assert_eq!(
        node.get_state_root().await,
        own_root,
        "the node keeps its own chain and root"
    );
    assert_ne!(
        node.get_state_root().await,
        fork_state.get_state_root().await,
        "the foreign history must not leak into our state"
    );
}

// ============================================================================
// Test 5 — stale round after partition: the returnee still converges.
// ============================================================================

#[tokio::test]
async fn stale_round_returnee_accepts_the_network_proposal_and_converges() {
    let ks = keys(4);
    let vs = vset(&ks);

    let payer_key = SigningKey::generate(&mut OsRng);
    let payer = id(&payer_key);
    let recipient = [0x33u8; 32];
    let net_state = funded(payer, 1_000_000_000).await;
    let ret_state = funded(payer, 1_000_000_000).await;

    // Height 1: the network finalizes WITHOUT the partitioned node (keys 0..3
    // still form a quorum of 3, so the chain does not stall for the returnee).
    let mut round1: u32 = 0;
    let mut hc_net = HeightConsensus::new(1, vs.clone());
    while vs.proposer_for(1, round1).unwrap() == id(&ks[3]) {
        hc_net.next_round();
        round1 += 1;
    }
    let prop1 = vs.proposer_for(1, round1).unwrap();
    let proposer1 = ks.iter().find(|k| id(k) == prop1).unwrap().clone();
    let pre1 = net_state.get_state_root().await;
    let mut b1 = mkblock(
        1,
        [0u8; 32],
        pre1,
        &proposer1,
        vec![Transaction::sign(&payer_key, recipient, 1_000, 0, 0, 1, 1)],
        4_001,
    );
    quorum_sign(&mut b1, &ks[..3], round1);
    let bh1 = b1.compute_hash();
    hc_net.receive_proposal(prop1, bh1).unwrap();
    assert_eq!(
        decide_with(&mut hc_net, &ks[..3], 1, round1, bh1),
        Some(bh1)
    );
    assert_eq!(net_state.get_state_root().await, b1.state_root);
    net_state
        .apply_block_parallel_fees(&b1.transactions, b1.timestamp)
        .await;

    // Meanwhile the returnee's round counter ran far ahead of the network's.
    // Pick the far-ahead round so it names a DIFFERENT proposer than the
    // network's round (proposer rotates with the round), deterministically
    // regardless of key order: that is the wedge pressure.
    let mut hc_ret = HeightConsensus::new(1, vs.clone());
    let mut ret_round: u32 = 500;
    if vs.proposer_for(1, ret_round).unwrap() == prop1 {
        ret_round += 1;
    }
    for _ in 0..ret_round {
        hc_ret.next_round();
    }
    assert!(hc_ret.round >= 500, "the returnee is far ahead on rounds");
    assert_eq!(hc_ret.decided, None, "it decided nothing while partitioned");
    // At round 500 it expects a different proposer, so the network's old
    // proposal is (correctly) not for its round -- the wedge pressure.
    assert!(hc_ret.receive_proposal(prop1, bh1).is_err());

    // The round-cap work: ONE stale message may move a node at most one round,
    // so the returnee cannot drag the network up to round 500 with it.
    let mut hc_cap = HeightConsensus::new(2, vs.clone());
    hc_cap.advance_to_round(hc_ret.round);
    assert_eq!(
        hc_cap.round, 1,
        "one peer message advances at most one round (round-DoS cap)"
    );
    // And a stale far-round vote stored on arrival does not wedge the round
    // the network is actually running.
    let stale = Vote::sign(
        &ks[3],
        2,
        hc_ret.round,
        VoteKind::Prevote,
        Some([0xFEu8; 32]),
    );
    hc_cap.add_prevote(stale).unwrap();
    assert_eq!(
        hc_cap.try_prevote_quorum(),
        None,
        "a stray far-round vote forms no quorum"
    );

    // HEAL: the returnee syncs height 1 (block body sync closes the height
    // skew instead of wedging on "wrong height")...
    let map = store(&[b1.clone()]);
    let n = catch_up(&map, bh1, [0u8; 32], 1, &vs, &ret_state)
        .await
        .expect("height sync must succeed");
    assert_eq!(n, 1);
    assert_eq!(
        ret_state.get_state_root().await,
        net_state.get_state_root().await,
        "height sync reunites the state roots"
    );

    // ...then both run height 2 from round 0 and must converge on the SAME
    // block, whatever rounds they held before (convergence, not a number).
    let mut hc_net2 = HeightConsensus::new(2, vs.clone());
    let mut hc_ret2 = HeightConsensus::new(2, vs.clone());
    let prop2 = vs.proposer_for(2, 0).unwrap();
    let proposer2 = ks.iter().find(|k| id(k) == prop2).unwrap().clone();
    let pre2 = net_state.get_state_root().await;
    assert_eq!(ret_state.get_state_root().await, pre2);
    let mut b2 = mkblock(
        2,
        bh1,
        pre2,
        &proposer2,
        vec![Transaction::sign(&payer_key, recipient, 2_000, 0, 1, 1, 1)],
        4_002,
    );
    quorum_sign(&mut b2, &ks, 0);
    let bh2 = b2.compute_hash();
    // The returnee accepts the network's proposal for the current height/round.
    hc_net2.receive_proposal(prop2, bh2).unwrap();
    hc_ret2
        .receive_proposal(prop2, bh2)
        .expect("the returnee must accept the network proposal, not wedge");
    assert_eq!(decide_with(&mut hc_net2, &ks, 2, 0, bh2), Some(bh2));
    assert_eq!(decide_with(&mut hc_ret2, &ks, 2, 0, bh2), Some(bh2));
    assert_eq!(
        hc_net2.decided, hc_ret2.decided,
        "both sides decide the same block"
    );
    for st in [&net_state, &ret_state] {
        assert_eq!(st.get_state_root().await, b2.state_root);
        let (applied, failed, _, _, _) = st
            .apply_block_parallel_fees(&b2.transactions, b2.timestamp)
            .await;
        assert_eq!((applied, failed), (1, 0));
    }
    assert_eq!(
        net_state.get_state_root().await,
        ret_state.get_state_root().await,
        "the healed network converges on one state root"
    );
}
