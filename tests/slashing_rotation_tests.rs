//! Agent B: slashing parity (local vs adopt_committed) + validator rotation proofs.
//!
//! Context (a): `adopt_committed` mints a fresh `HeightConsensus`, so
//! `precommit_qc` is `None` and `apply_downtime_slashes` early-returns: NO burn
//! on the catch-up path while the local path slashes. Context (b): rotation
//! from the ledger has no live-ish proof.
//!
//! Tests 1-2 assert PARITY (same burn / pool debit / root). On the current code
//! they FAIL and the failure message names what each path skipped. Tests 3-5
//! prove rotation live and must PASS.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorId, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::staking::{MIN_VALIDATOR_BOND, STAKING_POOL, STELL_MIN_BOND_BUFFER};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const BAL: u64 = 10_000_000_000_000;

/// Genesis bond every validator in `cluster()` carries (and the floor every
/// new bond must clear): bare-MIN bonds are refused.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}
fn ids(ks: &[SigningKey]) -> Vec<ValidatorId> {
    ks.iter().map(|k| k.verifying_key().to_bytes()).collect()
}

async fn cluster(ks: &[SigningKey]) -> Vec<ValidatorRuntime> {
    let vs = vset(ks);
    let mut out = Vec::new();
    for k in ks {
        let st = Arc::new(InMemoryStateEngine::new());
        fund_genesis(&st, &vs, BAL).await;
        out.push(ValidatorRuntime::new(k.clone(), vs.clone(), st, 1));
    }
    out
}

fn mkblock(pkey: &SigningKey, h: u64, prev: [u8; 32], root: [u8; 32]) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000,
        proposer: pkey.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(pkey);
    b
}

fn proposer_key<'a>(ks: &'a [SigningKey], vs: &ValidatorSet, h: u64, r: u32) -> &'a SigningKey {
    let want = vs.proposer_for(h, r).expect("non-empty set has a proposer");
    ks.iter()
        .find(|k| k.verifying_key().to_bytes() == want)
        .expect("schedule proposer is one of our keys")
}

async fn pool_of(st: &Arc<InMemoryStateEngine>) -> u64 {
    st.get_account(&STAKING_POOL)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}

/// Preset one engine for the downtime-threshold test: silent validator sits at
/// `missed = threshold-1` so the NEXT miss fires exactly one slash, and the
/// staking pool is funded so the pool debit is observable.
async fn preset_downtime_threshold(st: &Arc<InMemoryStateEngine>, silent: &ValidatorId) {
    st.credit_native(&STAKING_POOL, 10 * MIN_VALIDATOR_BOND)
        .await
        .unwrap();
    let mut l = st.staking_write().await;
    let rec = l.validators.get_mut(silent).expect("silent must be bonded");
    rec.missed = stellereum::staking::DOWNTIME_MISS_THRESHOLD - 1;
    rec.last_downtime_penalty = 0;
}

// ============================================================================
// Test 1 — downtime parity: local path vs adopt_committed with a genuine QC
// ============================================================================
// ============================================================================
// Test 1 — downtime parity: local path vs adopt_committed with a genuine QC
//
// W10.5 canonical-evidence form: downtime is attributed ONLY from the
// block-carried `last_qc` (height H-1), on EVERY path, through the same
// `apply_block_transition` — never from local vote observations. A
// height-1 block is a genesis child (`last_qc: None`), so height 1
// attributes nothing on either path; height 2 carries the height-1 QC and
// BOTH paths must burn, debit and mark identically.
#[tokio::test]
async fn test1_downtime_parity_local_vs_adopt() {
    let ks = keys(4);
    let vs = vset(&ks);
    let idv = ids(&ks);
    let silent = idv[3];
    let signers = [0usize, 1, 2];

    // Two identical engines, silent parked one miss short of the threshold.
    let mut c1 = cluster(&ks).await;
    let mut c2 = cluster(&ks).await;
    preset_downtime_threshold(&c1[0].state, &silent).await;
    preset_downtime_threshold(&c2[0].state, &silent).await;
    let root_before_1 = c1[0].state.get_state_root().await;
    let root_before_2 = c2[0].state.get_state_root().await;
    assert_eq!(
        root_before_1, root_before_2,
        "precondition: engines must start identical"
    );

    // Block authored by the schedule proposer for (1,0), committing to the live root.
    let pkey = proposer_key(&ks, &vs, 1, 0).clone();
    let block1 = mkblock(&pkey, 1, [0u8; 32], root_before_1);
    let bh1 = block1.compute_hash();

    // Height-1 round on path A (local): 3 honest votes, silent absent.
    for &i in &signers {
        c1[0]
            .on_prevote(Vote::sign(&ks[i], 1, 0, VoteKind::Prevote, Some(bh1)))
            .unwrap();
        c1[0]
            .on_precommit(Vote::sign(&ks[i], 1, 0, VoteKind::Precommit, Some(bh1)))
            .unwrap();
    }
    assert_eq!(c1[0].hc.try_precommit_quorum(), Some(bh1));
    let cert1: QuorumCertificate = c1[0].hc.precommit_qc.clone().expect("local QC exists");
    assert!(cert1.verify(&vs), "precondition: QC must be genuine");
    c1[0].blocks.insert(bh1, block1.clone());
    assert_eq!(c1[0].try_finalize().await, Some(bh1));
    // Path B adopts height 1.
    assert_eq!(
        c2[0]
            .adopt_committed(1, block1.clone(), cert1.clone())
            .await,
        Ok(bh1),
        "precondition: adopt must accept the genuine cert"
    );
    // Genesis child: no evidence on either path, so nothing attributed —
    // identically — and the roots agree.
    let root_after_1_a = c1[0].state.get_state_root().await;
    let root_after_1_b = c2[0].state.get_state_root().await;
    assert_eq!(root_after_1_a, root_after_1_b, "height-1 roots must agree");
    for (tag, rt) in [("local", &c1[0]), ("adopt", &c2[0])] {
        assert_eq!(
            rt.state.staking_read().await.validators[&silent].missed,
            stellereum::staking::DOWNTIME_MISS_THRESHOLD - 1,
            "{tag}: with no canonical evidence, the parked streak must be untouched"
        );
    }

    // Height 2 carries the height-1 QC as canonical evidence (production
    // `decided_parent_qc`); the silent validator misses it at the threshold.
    let pkey2 = proposer_key(&ks, &c1[0].validators, 2, 0).clone();
    let mut block2 = mkblock(&pkey2, 2, bh1, root_after_1_a);
    block2.last_qc = Some(cert1.clone());
    block2.validator_signatures.clear();
    block2.sign_block(&pkey2);
    let bh2 = block2.compute_hash();
    let cert2 = QuorumCertificate {
        height: 2,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh2),
        signatures: signers
            .iter()
            .map(|&i| {
                let v = Vote::sign(&ks[i], 2, 0, VoteKind::Precommit, Some(bh2));
                (v.voter, v.signature)
            })
            .collect(),
    };

    // ---- Local path: run the height-2 round, then try_finalize. ----
    let burn_before_l = c1[0].state.staking_read().await.total_burned;
    let pool_before_l = pool_of(&c1[0].state).await;
    for &i in &signers {
        c1[0]
            .on_prevote(Vote::sign(&ks[i], 2, 0, VoteKind::Prevote, Some(bh2)))
            .unwrap();
        c1[0]
            .on_precommit(Vote::sign(&ks[i], 2, 0, VoteKind::Precommit, Some(bh2)))
            .unwrap();
    }
    assert_eq!(c1[0].hc.try_precommit_quorum(), Some(bh2));
    c1[0].blocks.insert(bh2, block2.clone());
    let decided = c1[0].try_finalize().await;
    assert_eq!(
        decided,
        Some(bh2),
        "precondition: local path must finalize height 2"
    );
    let burn_local = c1[0].state.staking_read().await.total_burned - burn_before_l;
    let pool_after_l = pool_of(&c1[0].state).await;
    let pool_debit_local = pool_before_l.saturating_sub(pool_after_l);
    let root_local = c1[0].state.get_state_root().await;
    let missed_local = c1[0].state.staking_read().await.validators[&silent].missed;

    // ---- Catch-up path: adopt height 2 with the genuine decision QC. ----
    let burn_before_c = c2[0].state.staking_read().await.total_burned;
    let pool_before_c = pool_of(&c2[0].state).await;
    let r = c2[0]
        .adopt_committed(2, block2.clone(), cert2.clone())
        .await;
    assert_eq!(
        r,
        Ok(bh2),
        "precondition: adopt must accept the height-2 cert: {r:?}"
    );
    let burn_catchup = c2[0].state.staking_read().await.total_burned - burn_before_c;
    let pool_after_c = pool_of(&c2[0].state).await;
    let pool_debit_catchup = pool_before_c.saturating_sub(pool_after_c);
    let root_catchup = c2[0].state.get_state_root().await;
    let missed_catchup = c2[0]
        .state
        .staking_read()
        .await
        .validators
        .get(&silent)
        .map(|v| v.missed)
        .unwrap_or(999);

    println!(
        "[test1] burn local={} catchup={} | pool_debit local={} catchup={} | missed local={} catchup={} | root_local={} root_catchup={}",
        burn_local,
        burn_catchup,
        pool_debit_local,
        pool_debit_catchup,
        missed_local,
        missed_catchup,
        hex::encode(&root_local[..8]),
        hex::encode(&root_catchup[..8]),
    );
    assert!(
        burn_local > 0,
        "precondition: the height-2 evidence must slash at the threshold (missed was threshold-1)"
    );
    assert_eq!(
        burn_local, burn_catchup,
        "DOWNTIME PARITY FAILURE: local path burned {burn_local} from the block-carried last_qc; \
         catch-up path burned {burn_catchup} — both must attribute the same canonical evidence"
    );
    assert_eq!(
        pool_debit_local, pool_debit_catchup,
        "DOWNTIME POOL PARITY FAILURE: local debited {pool_debit_local} from STAKING_POOL, catch-up debited {pool_debit_catchup}"
    );
    assert_eq!(
        missed_local, missed_catchup,
        "DOWNTIME MISS PARITY FAILURE: local marked {missed_local}, catch-up marked {missed_catchup}"
    );
    assert_eq!(
        root_local, root_catchup,
        "DOWNTIME ROOT PARITY FAILURE: local root {} != catch-up root {} (staking_digest commits missed/last_penalty + pool balance, so a skipped slash splits the chain)",
        hex::encode(&root_local[..8]),
        hex::encode(&root_catchup[..8]),
    );
}

// ============================================================================
// Test 2 — equivocation parity, same shape
// ============================================================================
#[tokio::test]
async fn test2_equivocation_parity_local_vs_adopt() {
    let ks = keys(4);
    let vs = vset(&ks);
    let idv = ids(&ks);
    let cheater = idv[3];
    let signers = [0usize, 1, 2];

    let mut c1 = cluster(&ks).await;
    let mut c2 = cluster(&ks).await;
    // Fund the pool identically so pool-debit comparison is meaningful (equiv
    // path currently debits nothing on either path; the point is the burn).
    for c in [&c1[0], &c2[0]] {
        c.state
            .credit_native(&STAKING_POOL, 10 * MIN_VALIDATOR_BOND)
            .await
            .unwrap();
    }
    let root_before_1 = c1[0].state.get_state_root().await;
    let root_before_2 = c2[0].state.get_state_root().await;
    assert_eq!(
        root_before_1, root_before_2,
        "precondition: identical engines"
    );

    let pkey = proposer_key(&ks, &vs, 1, 0).clone();
    let block = mkblock(&pkey, 1, [0u8; 32], root_before_1);
    let bh = block.compute_hash();

    // ---- Local: honest quorum for bh + a conflicting prevote by the cheater.
    let burn_before_l = c1[0].state.staking_read().await.total_burned;
    let pool_before_l = pool_of(&c1[0].state).await;
    for &i in &signers {
        c1[0]
            .on_prevote(Vote::sign(&ks[i], 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
    }
    // Cheater's first prevote (for bh) then conflicting prevote (for 0x99..).
    let v1 = Vote::sign(&ks[3], 1, 0, VoteKind::Prevote, Some(bh));
    let v2 = Vote::sign(&ks[3], 1, 0, VoteKind::Prevote, Some([0x99u8; 32]));
    c1[0].on_prevote(v1).unwrap();
    c1[0].on_prevote(v2).unwrap();
    assert_eq!(
        c1[0].hc.equivocations().len(),
        1,
        "precondition: local node must hold double-vote evidence"
    );
    for &i in &signers {
        c1[0]
            .on_precommit(Vote::sign(&ks[i], 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    assert_eq!(c1[0].hc.try_precommit_quorum(), Some(bh));
    let cert = c1[0].hc.precommit_qc.clone().expect("local QC");
    assert!(cert.verify(&vs), "precondition: genuine QC");
    c1[0].blocks.insert(bh, block.clone());
    assert_eq!(c1[0].try_finalize().await, Some(bh));
    let burn_local = c1[0].state.staking_read().await.total_burned - burn_before_l;
    let pool_debit_local = pool_before_l.saturating_sub(pool_of(&c1[0].state).await);
    let root_local = c1[0].state.get_state_root().await;
    let bond_local = c1[0].state.staking_read().await.validators[&cheater].self_bond;

    // ---- Catch-up: same block + same genuine QC, but no local equiv evidence.
    let burn_before_c = c2[0].state.staking_read().await.total_burned;
    let pool_before_c = pool_of(&c2[0].state).await;
    assert!(
        c2[0].hc.equivocations().is_empty(),
        "precondition: catch-up node never saw the conflicting vote"
    );
    assert_eq!(
        c2[0].adopt_committed(1, block.clone(), cert.clone()).await,
        Ok(bh)
    );
    let burn_catchup = c2[0].state.staking_read().await.total_burned - burn_before_c;
    let pool_debit_catchup = pool_before_c.saturating_sub(pool_of(&c2[0].state).await);
    let root_catchup = c2[0].state.get_state_root().await;
    let bond_catchup = c2[0].state.staking_read().await.validators[&cheater].self_bond;

    println!(
        "[test2] burn local={} catchup={} | bond local={} catchup={} | pool_debit local={} catchup={} | root_local={} root_catchup={}",
        burn_local,
        burn_catchup,
        bond_local,
        bond_catchup,
        pool_debit_local,
        pool_debit_catchup,
        hex::encode(&root_local[..8]),
        hex::encode(&root_catchup[..8]),
    );
    assert!(
        burn_local == 0,
        "F4 FIX: equivocation slashing must be absent from the state transition \
         (evidence is node-local vote gossip, not block content)"
    );
    // F4 FIX: equivocation slashing is no longer part of ANY state transition.
    // The local node still OBSERVED the double-vote (asserted above), but that
    // observation must not move consensus state, because a catching-up node
    // never sees it and the two would otherwise commit different state roots for
    // the same block. Both routes burn nothing and reach the SAME root.
    assert_eq!(
        burn_catchup, 0,
        "F4 FIX: catch-up burns nothing; equivocation is deferred"
    );
    assert_eq!(
        bond_local, MIN_VALIDATOR_BOND,
        "F4 FIX: local path must NOT slash on local evidence (genesis bonds at bare MIN)"
    );
    assert_eq!(
        bond_catchup, MIN_VALIDATOR_BOND,
        "F4 FIX: catch-up bond must be untouched (genesis bonds at bare MIN)"
    );
    assert_eq!(pool_debit_local, 0, "F4 FIX: no local burn, no pool debit");
    assert_eq!(
        pool_debit_catchup, 0,
        "F4 FIX: no catch-up burn, no pool debit"
    );
    assert_eq!(
        root_local,
        root_catchup,
        "F4 PARITY FAILURE: local finalize root {} != adopt root {}. Equivocation \
         slashing must be a function of block content, not of which votes this \
         node happened to receive.",
        hex::encode(&root_local[..8]),
        hex::encode(&root_catchup[..8]),
    );
    let _ = (
        hex::encode(&root_local[..8]),
        hex::encode(&root_catchup[..8]),
    );
}

// ============================================================================
// Test 3 — bond a new validator mid-chain
// ============================================================================
#[tokio::test]
async fn test3_bond_new_validator_mid_chain() {
    let ks = keys(4);
    let mut nodes = cluster(&ks).await;
    // Drive one finished height so the bond happens "mid-chain".
    let vs0 = nodes[0].validators.clone();
    let pkey0 = proposer_key(&ks, &vs0, 1, 0).clone();
    let root0 = nodes[0].state.get_state_root().await;
    let b1 = mkblock(&pkey0, 1, [0u8; 32], root0);
    let bh1 = b1.compute_hash();
    for k in ks.iter() {
        nodes[0]
            .on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh1)))
            .unwrap();
        nodes[0]
            .on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh1)))
            .unwrap();
    }
    assert_eq!(nodes[0].hc.try_precommit_quorum(), Some(bh1));
    nodes[0].blocks.insert(bh1, b1);
    assert_eq!(nodes[0].try_finalize().await, Some(bh1));
    assert_eq!(nodes[0].height(), 2);

    let before = nodes[0].validators.clone();
    let q_before = before.quorum_power();
    let p_before = before.proposer_for(2, 0);
    let len_before = before.len();

    // Bond a brand-new validator through the funded-account path.
    let new_k = SigningKey::generate(&mut OsRng);
    let new_id = new_k.verifying_key().to_bytes();
    nodes[0]
        .state
        .update_account(AccountState::new(new_id, 10 * MIN_VALIDATOR_BOND))
        .await;
    nodes[0]
        .stake_bond(new_id, floor(), 0)
        .await
        .expect("bond must succeed");
    // W10.5 ACTIVATION BOUNDARY: a set derived at ledger-height L takes
    // effect at height L+1, NEVER immediately — the refresh only STAGES the
    // change, so a round in flight never has its quorum moved under it.
    // Here L == hc.height == 2, so the change is staged for height 3 and
    // the in-force set is untouched until this node advances there.
    let changed = nodes[0].refresh_validator_set_from_staking().await;
    assert!(changed, "validator set must refresh after the bond");
    let (activation, _) = nodes[0]
        .pending_validators
        .clone()
        .expect("the rotation must be staged, not installed");
    assert_eq!(
        activation, 3,
        "a change derived at height 2 takes effect at height 3"
    );
    assert_eq!(
        nodes[0].validators.len(),
        len_before,
        "the in-force set must not move mid-flight"
    );

    // Advance one height under the STILL-IN-FORCE old set (all four old
    // members vote; the newcomer is not yet a member and must not be
    // needed for quorum).
    let pkey2 = proposer_key(&ks, &nodes[0].validators, 2, 0).clone();
    let root2 = nodes[0].state.get_state_root().await;
    let prev2 = nodes[0]
        .finalized
        .last()
        .map(|(_, h)| *h)
        .unwrap_or([0u8; 32]);
    let b2 = mkblock(&pkey2, 2, prev2, root2);
    let bh2 = b2.compute_hash();
    for k in ks.iter() {
        nodes[0]
            .on_prevote(Vote::sign(k, 2, 0, VoteKind::Prevote, Some(bh2)))
            .unwrap();
        nodes[0]
            .on_precommit(Vote::sign(k, 2, 0, VoteKind::Precommit, Some(bh2)))
            .unwrap();
    }
    assert_eq!(nodes[0].hc.try_precommit_quorum(), Some(bh2));
    nodes[0].blocks.insert(bh2, b2);
    assert_eq!(nodes[0].try_finalize().await, Some(bh2));
    assert_eq!(nodes[0].height(), 3);

    // The staged set activates exactly on arrival at height 3.
    let after = nodes[0].validators.clone();
    println!(
        "[test3] len {} -> {} | quorum {} -> {} | proposer(2,0) {:?} -> {:?}",
        len_before,
        after.len(),
        q_before,
        after.quorum_power(),
        p_before.map(|p| hex::encode(&p[..4])),
        after.proposer_for(2, 0).map(|p| hex::encode(&p[..4])),
    );
    assert_eq!(
        after.len(),
        len_before + 1,
        "set must gain exactly one member"
    );
    assert!(after.contains(&new_id), "new validator must be in the set");
    assert_ne!(
        after.quorum_power(),
        q_before,
        "quorum_power must update with the new stake"
    );
    // The schedule must reflect the new member. Hash-slot draws are
    // statistical, so probe a wide window: the new key holds ~21.6% of the
    // power (1.1/5.1), and missing it in 64 draws has probability ~1e-7.
    // (A 5-height probe flaked ~45% — same class as the finding-5 flake.)
    let before_seq: Vec<_> = (1..=64u64).map(|h| before.proposer_for(h, 0)).collect();
    let after_seq: Vec<_> = (1..=64u64).map(|h| after.proposer_for(h, 0)).collect();
    assert!(
        after_seq.contains(&Some(new_id)),
        "new validator must own slots in the new schedule"
    );
    assert_ne!(
        before_seq, after_seq,
        "adding a member must change the rotation"
    );
}

// ============================================================================
// Test 4 — full unbond drops the validator at the boundary
// ============================================================================
#[tokio::test]
async fn test4_full_unbond_drops_validator_at_boundary() {
    let ks = keys(4);
    let idv = ids(&ks);
    let mut nodes = cluster(&ks).await;
    let victim = idv[0];

    // Full exit of one validator, then the boundary rotation. The fixture is
    // genesis-bonded at bare MIN (bond_genesis is floor-exempt by design), so
    // the full exit unbonds MIN, not the runtime floor.
    nodes[0]
        .stake_unbond(victim, MIN_VALIDATOR_BOND, 0)
        .await
        .expect("full unbond must succeed");
    // W10.5 ACTIVATION BOUNDARY (see test3): the refresh STAGES the removal
    // for height H+1 instead of dropping the victim mid-flight. The victim
    // is still in force for the current height — and must still be counted
    // for its quorum — until this node advances.
    assert!(nodes[0].refresh_validator_set_from_staking().await);
    let (activation, staged) = nodes[0]
        .pending_validators
        .clone()
        .expect("the removal must be staged, not installed");
    assert_eq!(activation, nodes[0].height() + 1);
    assert!(
        !staged.contains(&victim),
        "the staged set must drop the victim"
    );
    assert!(
        nodes[0].validators.contains(&victim),
        "the victim stays in force until the boundary"
    );
    assert_eq!(nodes[0].validators.len(), 4);

    // Later blocks finalize WITHOUT the dropped validator's vote.
    let h = nodes[0].height();
    let r = nodes[0].hc.round;
    let pkey = proposer_key(&ks, &nodes[0].validators, h, r).clone();
    // NOTE: the proposer may legitimately BE the victim here: it is still
    // the scheduled proposer for the in-force (pre-boundary) set, and
    // authorship is not a vote. What matters is that no vote from it is
    // needed — only the 3 survivors vote below, and the quorum they form
    // (3 of 4 in-force power) is what finalizes.
    let root = nodes[0].state.get_state_root().await;
    let prev = nodes[0]
        .finalized
        .last()
        .map(|(_, h)| *h)
        .unwrap_or([0u8; 32]);
    let blk = mkblock(&pkey, h, prev, root);
    let bh = blk.compute_hash();
    // Only the 3 remaining validators vote; the victim is silent/absent.
    for k in ks.iter().skip(1) {
        nodes[0]
            .on_prevote(Vote::sign(k, h, r, VoteKind::Prevote, Some(bh)))
            .unwrap();
    }
    for k in ks.iter().skip(1) {
        nodes[0]
            .on_precommit(Vote::sign(k, h, r, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    assert_eq!(
        nodes[0].hc.try_precommit_quorum(),
        Some(bh),
        "remaining 3 must still reach quorum without the dropped validator"
    );
    nodes[0].blocks.insert(bh, blk);
    let fin = nodes[0].try_finalize().await;
    println!(
        "[test4] finalized height {h} without victim vote: {:?}",
        fin.map(|x| hex::encode(&x[..4]))
    );
    assert_eq!(
        fin,
        Some(bh),
        "later block must finalize without the victim"
    );
    assert!(!nodes[0].validators.contains(&victim), "victim stays out");
}

// ============================================================================
// Test 5 — downtime slash below MIN drops the validator, remainder quorate
// ============================================================================
#[tokio::test]
async fn test5_downtime_slash_ejects_below_min_and_remainder_quorate() {
    let ks = keys(4);
    let vs = vset(&ks);
    let idv = ids(&ks);
    let victim = idv[3];
    let mut nodes = cluster(&ks).await;
    nodes[0]
        .state
        .credit_native(&STAKING_POOL, 10 * MIN_VALIDATOR_BOND)
        .await
        .unwrap();
    // Victim sits exactly at MIN with a 9-miss streak: the next miss ejects it.
    {
        let mut l = nodes[0].state.staking_write().await;
        let rec = l.validators.get_mut(&victim).expect("victim bonded");
        rec.self_bond = MIN_VALIDATOR_BOND;
        rec.missed = stellereum::staking::DOWNTIME_MISS_THRESHOLD - 1;
        rec.last_downtime_penalty = 0;
    }

    let pkey = proposer_key(&ks, &vs, 1, 0).clone();
    let root = nodes[0].state.get_state_root().await;
    let blk = mkblock(&pkey, 1, [0u8; 32], root);
    let bh = blk.compute_hash();
    for &i in &[0usize, 1, 2] {
        nodes[0]
            .on_prevote(Vote::sign(&ks[i], 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
        nodes[0]
            .on_precommit(Vote::sign(&ks[i], 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    assert_eq!(nodes[0].hc.try_precommit_quorum(), Some(bh));
    let cert1 = nodes[0]
        .hc
        .precommit_qc
        .clone()
        .expect("height-1 QC exists");
    nodes[0].blocks.insert(bh, blk);
    assert_eq!(
        nodes[0].try_finalize().await,
        Some(bh),
        "height 1 must finalize on the 3 honest votes"
    );
    // Genesis child: no canonical evidence, so no attribution yet — the
    // victim survives height 1 with its streak intact.
    assert_eq!(
        nodes[0].state.staking_read().await.validators[&victim].missed,
        stellereum::staking::DOWNTIME_MISS_THRESHOLD - 1
    );

    // Height 2 carries the height-1 QC as canonical evidence
    // (`decided_parent_qc`): the victim misses it at the threshold, the
    // 0.1% slash fires, and the bare-MIN bond drops below the minimum.
    let pkey2 = proposer_key(&ks, &nodes[0].validators, 2, 0).clone();
    let root2 = nodes[0].state.get_state_root().await;
    let mut blk2 = mkblock(&pkey2, 2, bh, root2);
    blk2.last_qc = Some(cert1);
    blk2.validator_signatures.clear();
    blk2.sign_block(&pkey2);
    let bh2 = blk2.compute_hash();
    for &i in &[0usize, 1, 2] {
        nodes[0]
            .on_prevote(Vote::sign(&ks[i], 2, 0, VoteKind::Prevote, Some(bh2)))
            .unwrap();
        nodes[0]
            .on_precommit(Vote::sign(&ks[i], 2, 0, VoteKind::Precommit, Some(bh2)))
            .unwrap();
    }
    assert_eq!(nodes[0].hc.try_precommit_quorum(), Some(bh2));
    nodes[0].blocks.insert(bh2, blk2);
    let fin = nodes[0].try_finalize().await;
    assert_eq!(
        fin,
        Some(bh2),
        "height 2 must finalize on the 3 honest votes"
    );

    let bond = nodes[0].state.staking_read().await.validators[&victim].self_bond;
    println!("[test5] victim bond after slash: {bond} (MIN={MIN_VALIDATOR_BOND})");
    assert!(
        bond < MIN_VALIDATOR_BOND,
        "0.1% slash on exactly-MIN bond must push it below the minimum"
    );
    assert!(
        !nodes[0].validators.contains(&victim),
        "validator below MIN must be dropped from the set at the boundary"
    );
    assert_eq!(nodes[0].validators.len(), 3);
    let q = nodes[0].validators.quorum_power();
    let total = nodes[0].validators.total_power();
    println!("[test5] remainder total={total} quorum={q}");
    assert_ne!(q, u64::MAX, "remainder must still have a reachable quorum");
    assert!(total >= q, "remainder must still be quorate");

    // The remainder can still certify: build a QC from the 3 survivors for the
    // NEXT height and verify it against the post-rotation set.
    let h2 = nodes[0].height();
    let bh2 = [0x77u8; 32];
    let sigs: Vec<(ValidatorId, Vec<u8>)> = [0usize, 1, 2]
        .iter()
        .map(|&i| {
            let v = Vote::sign(&ks[i], h2, 0, VoteKind::Precommit, Some(bh2));
            (v.voter, v.signature)
        })
        .collect();
    let qc = QuorumCertificate {
        height: h2,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh2),
        signatures: sigs,
    };
    // NOTE: post-rotation powers are stake-weighted (MIN each), while the votes
    // above were checked against power; QC::verify weights by the CURRENT set,
    // so it must verify with the survivors alone.
    assert!(
        qc.verify(&nodes[0].validators),
        "survivor-only QC must verify against the rotated set"
    );
}
