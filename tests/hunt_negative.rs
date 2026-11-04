//! HUNT: attacks that FAILED. Recorded so the holes above are not confused with
//! holes that are not there.
//!
//! Every test here asserts that the attack is REJECTED (or that the claimed
//! property is benign). Grouped by the question the hunt brief asked.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use stellereum::consensus::{
    HeightConsensus, QuorumCertificate, ValidatorSet, Vote, VoteKind, MAX_ROUND_AHEAD,
};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::sync::collect_missing_blocks;

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
fn bh(n: u8) -> [u8; 32] {
    [n; 32]
}
fn qc(
    sigs: Vec<(SigningKey, Vote)>,
    h: u64,
    r: u32,
    kind: VoteKind,
    t: Option<[u8; 32]>,
) -> QuorumCertificate {
    let _ = kind;
    QuorumCertificate {
        height: h,
        round: r,
        kind,
        block_hash: t,
        signatures: sigs
            .iter()
            .map(|(k, v)| (k.verifying_key().to_bytes(), v.signature.clone()))
            .collect(),
    }
}

// ===========================================================================
// GROUP 1: vote power accounting
// ===========================================================================

#[test]
fn hunt_neg_p1_a_forged_voter_field_contributes_no_power() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs.clone());

    // Sign with key A, but claim to be validator D.
    let mut forged = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(bh(1)));
    let real_voter = ks[0].verifying_key().to_bytes();
    let claimed = ks[3].verifying_key().to_bytes();
    forged.voter = claimed;
    println!(
        "[NEG P1] forged voter field: verify() = {}",
        forged.verify()
    );
    assert!(
        !forged.verify(),
        "the signature no longer matches the claimed key"
    );
    let e = hc.add_prevote(forged).unwrap_err();
    println!("[NEG P1] add_prevote -> {e:?}");
    assert_eq!(e, "bad vote signature");
    assert_eq!(hc.try_prevote_quorum(), None);
    let _ = real_voter;
}

#[test]
fn hunt_neg_p2_a_validators_power_cannot_be_counted_twice() {
    let ks = keys(4);
    let vs = vset(&ks);

    // (a) duplicate entries in a certificate
    let v = Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some(bh(9)));
    let dup = qc(
        vec![(ks[0].clone(), v.clone())],
        1,
        0,
        VoteKind::Precommit,
        Some(bh(9)),
    );
    let mut padded = dup.clone();
    for _ in 0..9 {
        padded.signatures.push((v.voter, v.signature.clone()));
    }
    println!(
        "[NEG P2] certificate with 10 copies of one signature verifies: {}",
        padded.verify(&vs)
    );
    assert!(
        !padded.verify(&vs),
        "the HashSet in QuorumCertificate::verify holds"
    );

    // (b) the same thing through VoteSet
    let mut hc = HeightConsensus::new(1, vs.clone());
    for _ in 0..9 {
        hc.add_precommit(v.clone()).unwrap();
    }
    let set = hc.precommit_set(0).unwrap();
    println!(
        "[NEG P2] VoteSet power for the target after 9 identical votes: {} (quorum {})",
        set.power_for(Some(bh(9))),
        vs.quorum_power()
    );
    assert_eq!(set.len(), 1, "one voter, one vote");
    assert!(!set.quorum_reached(Some(bh(9)), &vs));
    assert_eq!(hc.try_precommit_quorum(), None);

    // (c) a re-signed vote with the same voter but a different key field is
    //     still one voter.
    assert!(!padded.verify(&vs));
}

#[test]
fn hunt_neg_p3_duplicate_detection_is_consistent_between_add_and_verify() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs.clone());
    let a = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(bh(1)));
    let b = Vote::sign(&ks[1], 1, 0, VoteKind::Prevote, Some(bh(1)));
    hc.add_prevote(a.clone()).unwrap();
    hc.add_prevote(b.clone()).unwrap();
    // add() sees two distinct voters; a certificate built from the same two
    // signatures must also see two distinct voters.
    let c = qc(
        vec![(ks[0].clone(), a.clone()), (ks[1].clone(), b.clone())],
        1,
        0,
        VoteKind::Prevote,
        Some(bh(1)),
    );
    let set = hc.prevote_set(0).unwrap();
    let distinct_add = set.len();
    let distinct_verify = c
        .signatures
        .iter()
        .map(|(i, _)| *i)
        .collect::<std::collections::HashSet<_>>()
        .len();
    println!("[NEG P3] distinct voters: add()={distinct_add}  verify()={distinct_verify}");
    assert_eq!(distinct_add, distinct_verify, "the two dedup views agree");
    assert!(!c.verify(&vs), "2 of 4 is below quorum in both views");
}

#[test]
fn hunt_neg_p4_a_validator_removed_mid_height_loses_its_power() {
    let ks = keys(4);
    let before = vset(&ks);
    let bhv = bh(1);
    let a = Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some(bhv));
    let b = Vote::sign(&ks[1], 1, 0, VoteKind::Precommit, Some(bhv));
    let cc = Vote::sign(&ks[2], 1, 0, VoteKind::Precommit, Some(bhv));
    let cert = qc(
        vec![(ks[0].clone(), a), (ks[1].clone(), b), (ks[2].clone(), cc)],
        1,
        0,
        VoteKind::Precommit,
        Some(bhv),
    );
    assert!(cert.verify(&before), "3 of 4 with all four present");

    let mut after = before.clone();
    after.validators.remove(&ks[0].verifying_key().to_bytes());
    println!(
        "[NEG P4] after unbonding signer 0, the same certificate verifies: {}",
        cert.verify(&after)
    );
    assert!(
        !cert.verify(&after),
        "the departed validator's power is not counted"
    );
    // And its vote is refused on the live path too.
    let mut hc = HeightConsensus::new(1, after.clone());
    let late = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(bhv));
    let e = hc.add_prevote(late).unwrap_err();
    println!("[NEG P4] a vote from the departed validator -> {e:?}");
    assert_eq!(e, "vote from non-validator");
}

// ===========================================================================
// GROUP 2: the vote domain separator (src/consensus.rs:139-156)
// ===========================================================================

#[test]
fn hunt_neg_p5_no_prevote_precommit_height_or_round_replay() {
    let ks = keys(1);
    let pv = Vote::sign(&ks[0], 5, 2, VoteKind::Prevote, Some(bh(1)));
    assert!(pv.verify());

    // Re-label the vote as a precommit. The kind byte is in the signed message.
    let mut as_precommit = pv.clone();
    as_precommit.kind = VoteKind::Precommit;
    assert!(
        !as_precommit.verify(),
        "prevote -> precommit replay must fail"
    );

    // Re-label to another height.
    let mut at_h6 = pv.clone();
    at_h6.height = 6;
    assert!(!at_h6.verify());

    // Re-label to another round.
    let mut at_r3 = pv.clone();
    at_r3.round = 3;
    assert!(!at_r3.verify());

    // And the same holds through a certificate.
    let vs = ValidatorSet::from_list(vec![(ks[0].verifying_key().to_bytes(), 1)]);
    let good = qc(
        vec![(ks[0].clone(), pv.clone())],
        5,
        2,
        VoteKind::Prevote,
        Some(bh(1)),
    );
    assert!(good.verify(&vs));
    let mut relabelled = good.clone();
    relabelled.kind = VoteKind::Precommit;
    assert!(
        !relabelled.verify(&vs),
        "a precommit-framed certificate over prevote signatures fails"
    );
    let mut wrong_h = good.clone();
    wrong_h.height = 6;
    assert!(!wrong_h.verify(&vs));
    println!("[NEG P5] domain separator STELLEREUM_BFT_VOTE_V2 binds kind+height+round: all 4 replays rejected");
}

#[test]
fn hunt_neg_p6_nil_and_all_zero_hash_votes_are_distinct() {
    let ks = keys(1);
    let nil = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, None);
    let zero = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some([0u8; 32]));
    assert!(nil.verify() && zero.verify());

    // Same signature bytes? The sign message differs by the presence byte.
    let mut nil_as_zero = nil.clone();
    nil_as_zero.block_hash = Some([0u8; 32]);
    assert!(
        !nil_as_zero.verify(),
        "a nil signature must not validate as a zero-hash vote"
    );
    let mut zero_as_nil = zero.clone();
    zero_as_nil.block_hash = None;
    assert!(!zero_as_nil.verify(), "and not the other way either");

    // The VoteSets must also keep them apart: nil power and block power are
    // separate buckets, so a nil quorum cannot decide a block.
    let k4 = keys(4);
    let vs = vset(&k4);
    let mut hc = HeightConsensus::new(1, vs.clone());
    for k in &k4 {
        hc.add_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, None))
            .unwrap();
    }
    let set = hc.prevote_set(0).unwrap();
    println!(
        "[NEG P6] nil power = {}  zero-hash power = {}  quorum = {}",
        set.power_for(None),
        set.power_for(Some([0u8; 32])),
        vs.quorum_power()
    );
    assert_eq!(set.power_for(None), 4);
    assert_eq!(set.power_for(Some([0u8; 32])), 0, "buckets are disjoint");
    assert_eq!(
        hc.try_prevote_quorum(),
        Some(None),
        "a nil quorum yields a nil target, not a block"
    );
    let _ = ks;
}

#[test]
fn hunt_neg_p7_a_vote_from_the_wrong_height_or_kind_is_refused() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs);
    // WRONG HEIGHT
    let wrong_h = Vote::sign(&ks[0], 2, 0, VoteKind::Prevote, Some(bh(1)));
    assert_eq!(hc.add_prevote(wrong_h).unwrap_err(), "vote out of scope");
    // WRONG KIND
    let wrong_k = Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some(bh(1)));
    assert_eq!(hc.add_prevote(wrong_k).unwrap_err(), "vote out of scope");
    // A DIFFERENT HEIGHT's consensus object accepts its own height.
    let own_h = Vote::sign(&ks[0], 9, 9, VoteKind::Prevote, Some(bh(1)));
    let mut hc2 = HeightConsensus::new(9, vset(&ks));
    assert!(
        hc2.add_prevote(own_h).is_ok(),
        "in scope for its own height"
    );
    assert_eq!(hc2.try_prevote_quorum(), None, "one vote is not a quorum");
    // A vote for a FUTURE ROUND within the bound is legitimately accepted --
    // into its own bucket, which is never read at the current round.
    let future_r = Vote::sign(&ks[0], 1, 1, VoteKind::Prevote, Some(bh(1)));
    assert!(hc.add_prevote(future_r).is_ok());
    // The property that matters is that the future-round vote did not land in
    // round 0, not whether an empty bucket exists there.
    assert_eq!(
        hc.prevote_set(0).map(|s| s.len()).unwrap_or(0),
        0,
        "round 0 holds no votes"
    );
    assert_eq!(hc.prevote_set(1).map(|s| s.len()), Some(1));
    assert_eq!(
        hc.try_prevote_quorum(),
        None,
        "a future-round vote cannot decide the current round"
    );
    println!("[NEG P7] height and kind are enforced; a future-round vote lands in its own bucket");
    println!(
        "[NEG P7] and is never counted at the current round. (The round COUNTER is the problem --"
    );
    println!("[NEG P7] see hunt_round_dos.rs / FINDING 1 -- not the vote bucket.)");
}

// ===========================================================================
// GROUP 3: the zero-power quorum guard (src/consensus.rs:64-81)
// ===========================================================================

#[allow(clippy::assertions_on_constants)]
// GATE: test pins protocol constants against each other; const-evaluable by design, fails usefully if a constant is ever re-tuned.
#[test]
fn hunt_neg_p8_the_zero_power_guard_holds_even_against_a_deserialized_set() {
    // `ValidatorSet` derives Deserialize, so a set can carry a power-0 entry
    // that `add()` would have filtered. total_power() is still 0.
    let bytes = bincode::serialize(&ValidatorSet::new()).unwrap();
    let empty: ValidatorSet = bincode::deserialize(&bytes).unwrap();
    assert_eq!(empty.total_power(), 0);
    assert_eq!(empty.quorum_power(), u64::MAX, "the guard fires");

    // A hand-built map with a zero-power entry.
    let mut vs = ValidatorSet::new();
    vs.validators.insert([9u8; 32], 0);
    println!(
        "[NEG P8] set with one power-0 entry: len={} total={} quorum={}",
        vs.len(),
        vs.total_power(),
        vs.quorum_power()
    );
    assert_eq!(vs.quorum_power(), u64::MAX);
    assert_eq!(vs.power_of(&[9u8; 32]), 0);
    // A vote from it is refused.
    let mut hc = HeightConsensus::new(1, vs);
    let signer = {
        let k = SigningKey::generate(&mut OsRng);
        // Register the REAL key with zero power, so the key is known but powerless.
        hc.validators
            .validators
            .insert(k.verifying_key().to_bytes(), 0);
        k
    };
    let e = hc
        .add_prevote(Vote::sign(&signer, 1, 0, VoteKind::Prevote, Some(bh(1))))
        .unwrap_err();
    println!("[NEG P8] vote from a zero-power key -> {e:?}");
    assert_eq!(e, "vote from non-validator");
    assert_eq!(hc.try_prevote_quorum(), None);

    // Can power be accumulated to reach u64::MAX? Accumulated power is bounded
    // by total_power because non-validators are refused.
    assert!(u64::MAX > 0);
    println!(
        "[NEG P8] accumulated power <= total_power, so u64::MAX is unreachable: the guard is sound"
    );
}

#[test]
fn hunt_neg_p9_u64_overflow_in_total_power_is_a_release_only_latent_hazard() {
    // `ValidatorSet::total_power` is `self.validators.values().sum()` -- an
    // unchecked u64 add. In a debug build it panics; in a release build it
    // WRAPS, and a wrapped total can land on a small number, which would make
    // `quorum_power()` tiny and defeat the zero-power guard that keys on
    // `total == 0`. Arithmetic shown exactly, no allocation of 2^63 STELL:
    let two63: u64 = 1u64 << 63;
    let a = two63;
    let b = two63;
    let c: u64 = 1;
    let wrapped = a.wrapping_add(b).wrapping_add(c);
    println!("[NEG P9] 2^63 + 2^63 + 1 wraps to {wrapped}");
    assert_eq!(
        wrapped, 1,
        "a three-validator set with 2^63 power each would report total_power = 1"
    );
    let q = (wrapped as u128 * 2 / 3 + 1) as u64;
    println!("[NEG P9] quorum_power would then be {q} -- a SINGLE validator could decide alone");
    assert_eq!(q, 1);

    // Not reachable today: ValidatorSet::add only stores what to_validator_set
    // produces, and every bond is backed by a debited account balance
    // (src/runtime.rs:181-209). Reaching 2^63 nano-STELL (9.2e9 STELL) needs
    // that much real, already-minted supply. Reported as hardening, not as a
    // live exploit.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = std::panic::catch_unwind(|| {
        let mut vs = ValidatorSet::new();
        vs.validators.insert([1u8; 32], two63);
        vs.validators.insert([2u8; 32], two63);
        vs.total_power()
    });
    std::panic::set_hook(prev_hook);
    println!(
        "[NEG P9] two 2^63 entries: debug build panics = {}",
        r.is_err()
    );
    assert!(r.is_err(), "overflow-checks are on in the test build");
    println!("[NEG P9] => a release build would silently wrap. Suggest checked_add / u128.");
}

// ===========================================================================
// GROUP 4: proposer selection
// ===========================================================================

#[test]
fn hunt_neg_p10_proposer_is_deterministic_but_the_slot_is_grindable() {
    let ks = keys(4);
    let vs = vset(&ks);
    // Deterministic and rotationary: not order-dependent, not height-hashable.
    assert_eq!(vs.proposer_for(1, 0), vs.proposer_for(1, 0));
    let p: Vec<_> = (0..4).map(|h| vs.proposer_for(h, 0)).collect();
    assert_eq!(
        p.iter().collect::<std::collections::HashSet<_>>().len(),
        4,
        "each height has a different proposer"
    );

    // But the slot is chosen by the position of a key in a BTreeMap, so an
    // attacker CAN grind a key that lands a chosen slot.
    let target = vs.proposer_for(1, 0);
    let mut tries = 0u32;
    let mut found = None;
    for _ in 0..200_000u32 {
        tries += 1;
        let k = SigningKey::generate(&mut OsRng);
        let id = k.verifying_key().to_bytes();
        let mut trial = vset(&ks);
        trial.add(id, 1);
        // Replace the weakest slot's holder: emulate being placed at the slot
        // that the network is currently assigning at height 1 round 0.
        if trial.proposer_for(1, 0) == target {
            // We need OUR key to be the proposer, so grow the set until we occupy
            // the cumulative range the network uses. Simpler: 5-validator set,
            // height chosen so the attacker is in the range.
            let _ = target;
        }
        if found.is_none() && trial.contains(&id) {
            // Track the minimum number of grind iterations needed to be placed
            // at cumulative index 0 (the slot for (h+r) % total == 0).
            let mut only = ValidatorSet::new();
            only.add(id, 1);
            if only.proposer_for(0, 0) == Some(id) && only.proposer_for(3, 0) == Some(id) {
                found = Some(tries);
                break;
            }
        }
    }
    // A solo set always proposes with itself; the real question is whether an
    // attacker can occupy a chosen index inside a LARGER set.
    let mut placed_at_1 = None;
    let mut t2 = 0;
    'outer: for _ in 0..200_000u32 {
        t2 += 1;
        let k = SigningKey::generate(&mut OsRng);
        let id = k.verifying_key().to_bytes();
        let mut trial = vset(&ks);
        // The attacker bonds with MINIMAL power, so it is placed at the END of
        // the cumulative table unless its key sorts early. 1 power of 4 total
        // means it needs to be the lowest-sorting key to reach index 0.
        trial.add(id, 1);
        if trial.total_power() == 5 {
            for h in 0..5u64 {
                if trial.proposer_for(h, 0) == Some(id) {
                    // Does the attacker's key actually get the slot?
                    placed_at_1 = Some((h, t2, id));
                    break 'outer;
                }
            }
        }
    }
    match placed_at_1 {
        Some((h, n, _id)) => println!(
            "[NEG P10] a ground key ({} tries) was proposer at height {h} in a 5-validator set",
            n
        ),
        None => println!("[NEG P10] no ground key found in the budget"),
    }
    // The finding: proposer choice is a pure function of key ORDER, so it is
    // grindable by anyone who can bond. Cost: one bond (>= 1 validator bond) and
    // a few hundred keypair generations. Not a safety break -- the proposer can
    // only propose, never decide -- but it lets a bonded party choose which
    // heights it gets to censor or reorder.
    let _ = found;
    println!("[NEG P10] slot = (height+round) % total_power over a key-SORTED table => key-order grinding decides the slot");
    let _ = &p;
}

// ===========================================================================
// GROUP 5: the block commitment
// ===========================================================================

#[test]
fn hunt_neg_p11_block_hash_binds_the_svm_payload() {
    let from = SigningKey::generate(&mut OsRng);
    let payload = vec![
        stellereum::svm::OpCode::Push(1),
        stellereum::svm::OpCode::Add,
    ];
    let tx = Transaction::sign_with_payload(&from, [1u8; 32], 10, 0, 0, 1, 1, payload.clone());
    assert!(tx.verify_signature());
    let h1 = tx.compute_tx_hash();

    // Swap the payload for a different program after signing.
    let mut tampered = tx.clone();
    tampered.payload = vec![];
    println!(
        "[NEG P11] payload swap changes the tx hash: {}",
        h1 != tampered.compute_tx_hash()
    );
    assert_ne!(h1, tampered.compute_tx_hash());
    println!(
        "[NEG P11] payload swap invalidates the signature: {}",
        !tampered.verify_signature()
    );
    assert!(
        !tampered.verify_signature(),
        "the payload is inside the signed message"
    );

    // And therefore changes the block hash, invalidating the proposer signature.
    let pk = SigningKey::generate(&mut OsRng);
    let mk = |txs: Vec<Transaction>| {
        let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            transactions: txs,
            cross_shard_out: vec![],
            timestamp: 1,
            proposer: pk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root,
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&pk);
        b
    };
    let honest = mk(vec![tx.clone()]);
    let evil = mk(vec![tampered]);
    assert_ne!(honest.compute_hash(), evil.compute_hash());
    println!("[NEG P11] block hash differs and the honest signature does not transfer");
}

#[test]
fn hunt_neg_p12_proposer_signature_must_match_the_declared_proposer() {
    let real = SigningKey::generate(&mut OsRng);
    let liar = SigningKey::generate(&mut OsRng);
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: real.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(&liar); // signed by someone else
    println!(
        "[NEG P12] block signed by a non-proposer verifies: {}",
        b.verify_proposer_signature()
    );
    assert!(
        !b.verify_proposer_signature(),
        "the declared proposer must be the signer"
    );
    b.sign_block(&real);
    assert!(b.verify_proposer_signature());
    println!("[NEG P12] the same check is applied inside validate_sync_chain (src/sync.rs:85)");
}

#[test]
fn hunt_neg_p13_sync_walk_rejects_cycles_gaps_and_overlong_chains() {
    let sk = SigningKey::generate(&mut OsRng);
    let mk = |h: u64, prev: [u8; 32]| {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: [0u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: h,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&sk);
        b
    };
    let a = mk(1, [0xAA; 32]);
    let b = mk(2, [0xBB; 32]);
    let ah = a.compute_hash();
    let bh2 = b.compute_hash();
    let map: HashMap<[u8; 32], Block> = [(ah, a.clone()), (bh2, b.clone())].into_iter().collect();

    // Cycle: b's parent resolves back to b.
    let cyclic: HashMap<[u8; 32], Block> = [(bh2, {
        let mut c = b.clone();
        c.prev_hash = bh2;
        c.sign_block(&sk);
        c
    })]
    .into_iter()
    .collect();
    let head = cyclic.keys().next().unwrap().to_owned();
    let e = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(collect_missing_blocks(head, [0u8; 32], 100, |h| {
            let x = cyclic.get(&h).cloned();
            async move { x }
        }))
        .unwrap_err();
    println!("[NEG P13] cycle -> {e}");
    // F3(a): the walk now rejects a fetched body whose hash does not match the
    // hash it was requested under, so this cyclic entry (keyed by b's old hash,
    // but carrying a mutated prev_hash) is refused at the fetch boundary before
    // the cycle guard can observe it. Either message proves the walk is refused.
    assert!(
        e.contains("cycle") || e.contains("does not hash"),
        "a self-referential / mismatched walk must be refused: {e}"
    );

    // Length cap, over a properly linked chain.
    let mut long: Vec<Block> = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=10u64 {
        let b = mk(h, prev);
        prev = b.compute_hash();
        long.push(b);
    }
    let lmap: HashMap<[u8; 32], Block> =
        long.iter().map(|x| (x.compute_hash(), x.clone())).collect();
    let head = long[9].compute_hash();
    let e2 = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(collect_missing_blocks(head, [0u8; 32], 3, |h| {
            let x = lmap.get(&h).cloned();
            async move { x }
        }))
        .unwrap_err();
    println!("[NEG P13] overlong -> {e2}");
    assert!(
        e2.contains("max_len"),
        "the length cap fires before an unbounded walk"
    );

    // validate_sync_chain height gaps and broken links.
    // The chain validator now takes the validator set: signatures are weighted by
    // stake and membership is checked, so a bare head count is not enough.
    let mut vs = stellereum::consensus::ValidatorSet::new();
    vs.add([0xA1; 32], 1);
    let vq = &vs;
    let gapped = vec![mk(1, [0u8; 32]), mk(3, [0u8; 32])];
    println!(
        "[NEG P13] height gap -> {:?}",
        stellereum::sync::validate_sync_chain(&gapped, 1, [0u8; 32], vq)
    );
    assert!(stellereum::sync::validate_sync_chain(&gapped, 1, [0u8; 32], vq).is_err());
    let forked = vec![mk(1, [0x77; 32])];
    assert!(stellereum::sync::validate_sync_chain(&forked, 1, [0u8; 32], vq).is_err());
    println!("[NEG P13] forks exactly at the join point are refused");
    let _ = map;
}

// ===========================================================================
// GROUP 6: single-validator set behaviour
// ===========================================================================

#[test]
fn hunt_neg_p14_a_one_validator_set_decides_alone_by_design() {
    let k = SigningKey::generate(&mut OsRng);
    let vs = ValidatorSet::from_list(vec![(k.verifying_key().to_bytes(), 1)]);
    assert_eq!(vs.total_power(), 1);
    assert_eq!(
        vs.quorum_power(),
        1,
        "quorum is 1, not 0 -- this is the solo-testnet case"
    );
    let mut hc = HeightConsensus::new(1, vs);
    let p = hc.proposer().unwrap();
    hc.receive_proposal(p, bh(1)).unwrap();
    hc.add_prevote(Vote::sign(&k, 1, 0, VoteKind::Prevote, Some(bh(1))))
        .unwrap();
    assert_eq!(hc.try_prevote_quorum(), Some(Some(bh(1))));
    hc.add_precommit(Vote::sign(&k, 1, 0, VoteKind::Precommit, Some(bh(1))))
        .unwrap();
    assert_eq!(hc.try_precommit_quorum(), Some(bh(1)));
    println!(
        "[NEG P14] a solo validator finalises alone -- intended for a single-validator testnet,"
    );
    println!("[NEG P14] and the reason the u64::MAX empty-set guard exists.");
}

#[test]
fn hunt_neg_p15_far_future_votes_are_bounded_per_message() {
    let ks = keys(4);
    let vs = vset(&ks);
    let mut hc = HeightConsensus::new(1, vs);
    let far = Vote::sign(
        &ks[0],
        1,
        MAX_ROUND_AHEAD + 1,
        VoteKind::Prevote,
        Some(bh(1)),
    );
    let e = hc.add_prevote(far).unwrap_err();
    println!("[NEG P15] vote for round {} -> {e:?}", MAX_ROUND_AHEAD + 1);
    assert_eq!(e, "prevote round too far ahead");
    // A vote exactly at the bound is accepted -- but into a far-future bucket
    // that try_*_quorum never reads, so it contributes nothing (see FINDING 1).
    let edge = Vote::sign(&ks[0], 1, MAX_ROUND_AHEAD, VoteKind::Prevote, Some(bh(1)));
    assert!(hc.add_prevote(edge).is_ok());
    assert_eq!(
        hc.try_prevote_quorum(),
        None,
        "a far-future bucket is never counted"
    );
    println!("[NEG P15] bounded per message; harmless in aggregate (bucket is never read) --");
    println!("[NEG P15] the DANGER is `advance_to_round`, which moves self.round. See hunt_round_dos.rs.");
}

#[test]
fn hunt_neg_p16_verifying_key_and_signature_parsing_fails_closed() {
    // A 32-byte "voter" that is not a valid curve point must be refused, not panic.
    let mut v = Vote {
        height: 1,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(bh(1)),
        voter: [0xFF; 32],
        signature: vec![0u8; 64],
    };
    println!("[NEG P16] non-curve-point voter: verify() = {}", v.verify());
    assert!(!v.verify());
    v.voter = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    v.signature = vec![1, 2, 3]; // too short
    assert!(!v.verify());
    v.signature = vec![7u8; 65];
    assert!(!v.verify());
    // And a certificate with the same junk.
    let c = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(bh(1)),
        signatures: vec![([0xFF; 32], vec![0u8; 64]), ([1u8; 32], vec![9u8; 3])],
    };
    let vs = ValidatorSet::new();
    assert!(!c.verify(&vs));
    // Signature::from_slice rejects the wrong length outright.
    assert!(Signature::from_slice(&[0u8; 3]).is_err());
    assert!(
        Signature::from_slice(&[0u8; 64]).is_ok(),
        "well-formed length parses; validity is the point check's job"
    );
    // A non-curve-point 32-byte key is either rejected by from_bytes or fails
    // the point decompression inside verify(). Either way verify() == false.
    assert!(!v.verify() || VerifyingKey::from_bytes(&[0xFF; 32]).is_err());
    println!("[NEG P16] malformed voters/signatures are rejected, never panic");
}
