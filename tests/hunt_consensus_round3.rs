//! ADVERSARIAL HUNT round 3: the remaining loose ends.
//! Read-only with respect to src/.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn bh(n: u8) -> [u8; 32] {
    [n; 32]
}
fn vs_of(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}

// ===========================================================================
// ATTACK 19  (MEDIUM) — nothing-at-stake / slashing evasion. Equivocation is
// only detected WITHIN one (round, kind) bucket, so prevoting A and
// precommitting B at the same height+round is the most damaging possible
// equivocation and the engine records NOTHING. `slash_equivocation` re-checks
// `a.kind != b.kind` (staking.rs:427) so the pair can never be charged.
// ===========================================================================

#[tokio::test]
async fn hunt19_prevote_a_precommit_b_is_never_slashed() {
    let ks = keys(4);
    let vset = vs_of(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st.clone(), 1);
    let honest = ks[1].clone();

    let slashed_before = st.staking_read().await.validators[&id(&honest)].total_slashed;

    // The textbook equivocation: says A out loud, commits B.
    rt.on_prevote(Vote::sign(&honest, 1, 0, VoteKind::Prevote, Some(bh(0xA1))))
        .unwrap();
    rt.on_precommit(Vote::sign(
        &honest,
        1,
        0,
        VoteKind::Precommit,
        Some(bh(0xB2)),
    ))
    .unwrap();

    let evidence = rt.hc.equivocations();
    eprintln!(
        "HUNT19: validator {} prevoted a1a1a1a1 and precommitted b2b2b2b2 at (1,0). \
         equivocation evidence recorded = {}",
        hex::encode(&id(&honest)[..6]),
        evidence.len()
    );
    assert!(
        evidence.is_empty(),
        "ATTACKER GOAL: the most dangerous double-vote (prevote X, precommit Y) is \
         invisible to the slashing engine"
    );
    let burned = rt.apply_equivocation_slashes().await;
    let slashed_after = st.staking_read().await.validators[&id(&honest)].total_slashed;
    assert_eq!(burned, 0);
    assert_eq!(
        slashed_after, slashed_before,
        "zero penalty for equivocating"
    );
    eprintln!(
        "HUNT19 OK: burned={burned}. consensus.rs:365-366 keeps prevotes and precommits in \
         SEPARATE VoteSets, and staking.rs:427 refuses any pair with a.kind != b.kind."
    );
}

// ===========================================================================
// ATTACK 20  (MEDIUM) — equivocation evidence is never cleared, so it is
// charged again on every subsequent finalisation that still sees the same
// HeightConsensus. The doc comment at runtime.rs:160-161 promises the opposite.
// ===========================================================================

#[tokio::test]
async fn hunt20_equivocation_evidence_is_never_cleared_after_charging() {
    let ks = keys(4);
    let vset = vs_of(&ks);
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st.clone(), 1);
    let victim = ks[3].clone();

    rt.on_prevote(Vote::sign(&victim, 1, 0, VoteKind::Prevote, Some(bh(0xA1))))
        .unwrap();
    rt.on_prevote(Vote::sign(&victim, 1, 0, VoteKind::Prevote, Some(bh(0xA2))))
        .unwrap();
    let first = rt.apply_equivocation_slashes().await;
    let after_first = st.staking_read().await.validators[&id(&victim)].total_slashed;
    // The runtime is NOT advanced (no finalize), so the same evidence is live.
    let second = rt.apply_equivocation_slashes().await;
    let after_second = st.staking_read().await.validators[&id(&victim)].total_slashed;
    eprintln!(
        "HUNT20: apply_equivocation_slashes() called twice on the same evidence -> \
         {} then {}; total_slashed {} -> {}",
        first, second, after_first, after_second
    );
    assert!(first > 0);
    assert!(second > 0, "the same evidence was charged a SECOND time");
    assert!(
        after_second > after_first,
        "{} -> {}",
        after_first,
        after_second
    );
    eprintln!(
        "HUNT20 OK: charged twice ({first} each). Nothing clears `equivocations` — \
         runtime.rs:160-161 documents 'once processed, the consumed evidence is \
         cleared', but there is no clear/remove anywhere in consensus.rs or runtime.rs."
    );
}

// ===========================================================================
// ATTACK 21  (MEDIUM) — the downtime signers are read from the RAW
// `cert.signatures` list with no signature validation and no power test, so a
// certificate entry naming a validator who did not actually sign is believed.
// Demonstrated against the ledger API directly, which is what runtime.rs:628
// feeds with `signers.contains(v)`.
// ===========================================================================

#[test]
fn hunt21_downtime_signer_membership_is_taken_on_the_raw_signature_list() {
    use stellereum::staking::{StakingLedger, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER};
    let ks = keys(3);
    let mut l = StakingLedger::new();
    for k in &ks {
        l.bond(id(k), MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .unwrap();
    }
    let honest = id(&ks[1]);
    // A certificate whose signature list merely NAMES the honest validator.
    // No signature object exists at this layer at all.
    let claimed_signers: std::collections::HashSet<[u8; 32]> = std::iter::once(honest).collect();
    let eligible: Vec<[u8; 32]> = ks.iter().map(id).collect();

    let mut l2 = l.clone();
    for h in 1..=11u64 {
        l2.note_missed_heights(h, &|v: &[u8; 32]| claimed_signers.contains(v), &eligible);
    }
    let forgave = l2.validators[&honest].missed;
    assert_eq!(
        forgave, 0,
        "naming a validator in the list forgives its downtime"
    );

    let mut l3 = l.clone();
    for h in 1..=11u64 {
        l3.note_missed_heights(h, &|_v: &[u8; 32]| false, &eligible);
    }
    let punished = l3.validators[&honest].total_slashed;
    assert!(punished > 0);
    eprintln!(
        "HUNT21: merely LISTING a validator id forgives {} of downtime; not listing it \
         burns {}. `note_missed_heights` is handed a closure over cert.signatures \
         (runtime.rs:628) with no signature verification, and a QC may carry entries \
         whose power is 0 or whose signature is invalid (consensus.rs:309-318 skips both).",
        forgave, punished
    );
}

// ===========================================================================
// ATTACK 22 — NEGATIVE: cross-height and cross-round vote replay.
// ===========================================================================

#[test]
fn hunt22_negative_vote_scope_is_enforced() {
    let (vset, ks) = {
        let ks = keys(4);
        (vs_of(&ks), ks)
    };
    let mut rt_rt = {
        let st = std::sync::Arc::new(InMemoryStateEngine::new());
        // not awaiting: just exercise HeightConsensus directly
        let _ = st;
        ValidatorSet::new()
    };
    let _ = &mut rt_rt;
    let mut hc = stellereum::consensus::HeightConsensus::new(1, vset.clone());

    // wrong height
    assert!(hc
        .add_prevote(Vote::sign(&ks[0], 2, 0, VoteKind::Prevote, Some(bh(1))))
        .is_err());
    // wrong round for the CURRENT quorum: stored, but invisible to quorum.
    hc.add_prevote(Vote::sign(&ks[0], 1, 5, VoteKind::Prevote, Some(bh(1))))
        .unwrap();
    for k in ks.iter() {
        hc.add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh(1))))
            .unwrap();
    }
    assert_eq!(
        hc.try_prevote_quorum(),
        Some(Some(bh(1))),
        "current round is used"
    );
    // The old round's set is a separate bucket and its power is its own.
    assert!(hc.prevote_set(5).is_some());
    assert_eq!(hc.prevote_set(0).unwrap().power_for(Some(bh(1))), 4);
    eprintln!(
        "HUNT22 NEGATIVE: height is bound (add rejects h!=self.height), rounds are \
         bucketed separately, and try_*_quorum only ever reads self.round. Old-round \
         votes cannot contribute to the current round."
    );

    // NEGATIVE: adopt_committed is handed the LOCAL set at main.rs:456, so a peer
    // cannot choose the set the certificate is judged against.
    let _ = (&mut hc, &ks);
    let cert = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh(1)),
        signatures: vec![],
    };
    assert!(
        !cert.verify(&ValidatorSet::new()),
        "an empty set never verifies"
    );
    let _ = fund_genesis;
    let _ = ValidatorRuntime::new;
    let _ = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 0,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 0,
        proposer: [0u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
}

// ===========================================================================
// ATTACK 23  (HIGH) — `adopt_committed` never checks that the block's proposer
// is the proposer for (height, certificate.round). Any validator may author a
// block that gets adopted, as long as 2/3 of the set signed a certificate over
// it. Attribution for block rewards (apply_block_fees_rewards pays
// block.proposer) is therefore also unattributable.
// ===========================================================================

#[tokio::test]
async fn hunt23_adopt_committed_accepts_a_non_proposer_block() {
    // SCHEDULE-AWARE setup (hash-slot fix): `proposer_for` is
    // `BLAKE3(height || round) mod power`, so a RANDOM 4-key set need NOT give
    // any fixed validator exactly one owned round in 1..=4 (the old
    // `assert_eq!(owned.len(), 1)` was RED by schedule luck). Retry with fresh
    // keys until some non-proposer owns a near round; the assertions below
    // then run against the COMPUTED schedule instead of assuming it.
    let (ks, vset, imposter, owned_round) = {
        let mut found = None;
        for _ in 0..200u32 {
            let ks = keys(4);
            let vset = vs_of(&ks);
            let real = vset.proposer_for(1, 0).unwrap();
            for i in 0..ks.len() {
                if id(&ks[i]) == real {
                    continue;
                }
                if let Some(r) =
                    (1..=4u32).find(|r| vset.proposer_for(1, *r).unwrap() == id(&ks[i]))
                {
                    let imposter = ks[i].clone();
                    found = Some((ks, vset, imposter, r));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        found.expect("some non-proposer must own a round in 1..=4 within 200 key sets")
    };
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st.clone(), 1);

    let real_proposer = vset.proposer_for(1, 0).unwrap();
    assert_ne!(id(&imposter), real_proposer);
    // The computed schedule really does name the imposter at the owned round
    // and someone else at round 0: the adopt path must enforce exactly this.
    assert_eq!(vset.proposer_for(1, owned_round).unwrap(), id(&imposter));
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: st.get_state_root().await,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: id(&imposter), // NOT proposer_for(1, 0)
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(&imposter);
    let bhash = b.compute_hash();
    assert_ne!(id(&imposter), real_proposer);

    // The very same block on the live proposal path: since the chase-livelock
    // fix, a GENUINE block (signed, building on our state) from a validator
    // that owns a NEAR-FUTURE slot is phase-aligned to that slot instead of
    // rejected -- early delivery of a real future proposal, never acceptance
    // as someone else's round. `owned_round` is the schedule-computed slot
    // the imposter owns (see setup), so alignment is deterministic here.
    let reject = rt.on_proposal(id(&imposter), b.clone(), owned_round).await;
    assert!(
        reject.is_ok(),
        "genuine block from a near-slot owner aligns, not rejects: {:?}",
        reject.as_ref().err()
    );
    assert_eq!(
        rt.hc.round, owned_round,
        "must align to the slot the signer owns"
    );
    assert_eq!(
        rt.hc.proposer().unwrap(),
        id(&imposter),
        "the live path still enforces the proposer slot AT THE ROUND OF ACCEPTANCE"
    );
    // ...but ACCEPTED on the peer-commit path.
    let cert = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bhash),
        signatures: ks
            .iter()
            .take(3)
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bhash));
                (v.voter, v.signature)
            })
            .collect(),
    };
    // The adopt path gets a FRESH runtime: the live path above legitimately
    // advanced this runtime's round by aligning, and adopt_committed checks
    // the certificate against the runtime's CURRENT round.
    let mut rt2 = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st.clone(), 1);
    let accepted = rt2.adopt_committed(1, b, cert).await;
    eprintln!(
        "HUNT23: on_proposal -> {:?}; adopt_committed -> {:?}",
        reject.as_ref().err(),
        accepted.as_ref().err()
    );
    // (The old `reject.is_err()` assertion moved up: genuine near-slot blocks
    // align instead of rejecting, but only at a slot the signer owns.)
    // FIXED: the peer-commit path now enforces the same proposer slot. It used to
    // check only that `block.proposer` had signed -- never that it was the
    // validator the schedule names for that height and round -- so a peer could
    // name any address it controlled and `apply_block_fees_rewards` would credit
    // the block's fees to it with no membership test.
    assert!(
        accepted.is_err(),
        "the peer-commit path must enforce the proposer slot too"
    );
    assert!(
        accepted
            .as_ref()
            .unwrap_err()
            .contains("proposer is not the expected proposer"),
        "the refusal must name the reason: {:?}",
        accepted.as_ref().err()
    );
}
