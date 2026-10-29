//! Adversarial 4-node tests: thinking-byzantine attacks, not just crash faults.
//!
//! QUORUM MATH: n = 4, power 1 each => total = 4,
//! quorum = floor(2*4/3)+1 = 3, F = 1.
//! All tests are in-process on `HeightConsensus` (pure state machine),
//! deterministic, fast, no sleeps, no `#[ignore]`.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::{HeightConsensus, ValidatorSet, Vote, VoteKind};

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}
fn idx_of(ks: &[SigningKey], target: [u8; 32]) -> usize {
    ks.iter()
        .position(|k| id(k) == target)
        .expect("known validator")
}
fn h(x: u8) -> [u8; 32] {
    [x; 32]
}

/// Deliver one height/round of unanimous voting for `bh` to every node in
/// `hcs`, using signatures from `voters`. Returns per-node decide outcome.
fn vote_all(
    hcs: &mut [HeightConsensus],
    ks: &[SigningKey],
    height: u64,
    round: u32,
    bh: [u8; 32],
    voters: &[usize],
) {
    for &i in voters {
        let pv = Vote::sign(&ks[i], height, round, VoteKind::Prevote, Some(bh));
        for hc in hcs.iter_mut() {
            hc.add_prevote(pv.clone()).unwrap();
        }
    }
    for hc in hcs.iter_mut() {
        hc.try_prevote_quorum();
    }
    for &i in voters {
        let pc = Vote::sign(&ks[i], height, round, VoteKind::Precommit, Some(bh));
        for hc in hcs.iter_mut() {
            hc.add_precommit(pc.clone()).unwrap();
        }
    }
}

// Test 1 — byzantine proposer equivocation: scheduled proposer sends
// DIFFERENT blocks to different halves (A,B get X; C,D get Y, same height).
// Neither half may finalize; a later honest proposer reunites all four on Z.
#[test]
fn adv_equivocating_proposer_splits_halves_but_cannot_hold_the_split() {
    let ks = keys(4);
    let vs = vset(&ks);
    assert_eq!(vs.quorum_power(), 3);
    let height = 1u64;

    // The adversary IS the scheduled proposer for round 0.
    let byz = idx_of(&ks, vs.proposer_for(height, 0).unwrap());
    let byz_id = id(&ks[byz]);
    let x = h(0x11);
    let y = h(0x22);
    assert_ne!(x, y);

    // Halves: {byz, next} get X, the other two get Y.
    let gx = vec![byz, (byz + 1) % 4];
    let gy: Vec<usize> = (0..4).filter(|i| !gx.contains(i)).collect();
    assert_eq!(gy.len(), 2);

    let mut hcs: Vec<HeightConsensus> = (0..4)
        .map(|_| HeightConsensus::new(height, vs.clone()))
        .collect();
    for &i in &gx {
        hcs[i].receive_proposal(byz_id, x).unwrap();
    }
    for &i in &gy {
        hcs[i].receive_proposal(byz_id, y).unwrap();
    }

    // Each half prevotes what it saw; broadcast everything so every node
    // sees a 2-vs-2 split.
    for &i in &gx {
        let v = Vote::sign(&ks[i], height, 0, VoteKind::Prevote, Some(x));
        for hc in hcs.iter_mut() {
            hc.add_prevote(v.clone()).unwrap();
        }
    }
    for &i in &gy {
        let v = Vote::sign(&ks[i], height, 0, VoteKind::Prevote, Some(y));
        for hc in hcs.iter_mut() {
            hc.add_prevote(v.clone()).unwrap();
        }
    }
    for (i, hc) in hcs.iter_mut().enumerate() {
        assert_eq!(
            hc.try_prevote_quorum(),
            None,
            "node {i}: 2-vs-2 is no quorum"
        );
        assert_eq!(hc.prevote_set(0).unwrap().power_for(Some(x)), 2);
        assert_eq!(hc.prevote_set(0).unwrap().power_for(Some(y)), 2);
    }

    // Even if both halves precommit their halves, 2 < 3 everywhere.
    for &i in &gx {
        let v = Vote::sign(&ks[i], height, 0, VoteKind::Precommit, Some(x));
        for hc in hcs.iter_mut() {
            hc.add_precommit(v.clone()).unwrap();
        }
    }
    for &i in &gy {
        let v = Vote::sign(&ks[i], height, 0, VoteKind::Precommit, Some(y));
        for hc in hcs.iter_mut() {
            hc.add_precommit(v.clone()).unwrap();
        }
    }
    for (i, hc) in hcs.iter_mut().enumerate() {
        assert_eq!(
            hc.try_precommit_quorum(),
            None,
            "node {i}: neither half finalizes"
        );
        assert_eq!(
            hc.decided, None,
            "node {i}: nothing decided on equivocation"
        );
    }

    // Later round with an HONEST proposer reunites everyone on Z.
    let mut r: u32 = 1;
    while idx_of(&ks, vs.proposer_for(height, r).unwrap()) == byz {
        r += 1;
    }
    let honest = idx_of(&ks, vs.proposer_for(height, r).unwrap());
    let honest_id = id(&ks[honest]);
    let z = h(0x33);
    for hc in hcs.iter_mut() {
        while hc.round < r {
            hc.next_round();
        }
        hc.receive_proposal(honest_id, z).unwrap();
    }
    let all = vec![0usize, 1, 2, 3];
    vote_all(&mut hcs, &ks, height, r, z, &all);
    for (i, hc) in hcs.iter_mut().enumerate() {
        assert_eq!(
            hc.try_precommit_quorum(),
            Some(z),
            "node {i}: honest round {r} must decide Z"
        );
        assert_eq!(
            hc.decided,
            Some(z),
            "node {i}: converged on Z, no permanent split"
        );
    }
}

// Test 2 — targeted round inflation: byzantine sends far-future-round votes
// ONLY to one victim (not broadcast). Victim moves at most one round per
// message and still finalizes with the honest three.
#[test]
fn adv_targeted_round_inflation_is_capped_and_victim_still_finalizes() {
    let ks = keys(4);
    let vs = vset(&ks);
    let height = 1u64;
    let byz = 3usize;
    let victim = 0usize;
    let x = h(0x44);

    let mut hcs: Vec<HeightConsensus> = (0..4)
        .map(|_| HeightConsensus::new(height, vs.clone()))
        .collect();
    assert_eq!(hcs[victim].round, 0);

    // Far-future vote delivered ONLY to the victim.
    let far: u32 = 500;
    let evil = Vote::sign(&ks[byz], height, far, VoteKind::Prevote, Some(x));
    assert!(evil.verify());
    hcs[victim].add_prevote(evil.clone()).unwrap();
    // Nobody else saw it.
    for (i, hc) in hcs.iter().enumerate() {
        if i == victim {
            continue;
        }
        assert!(
            hc.prevote_set(far).is_none(),
            "node {i}: uninfected by targeted vote"
        );
    }
    // One message moves the victim at most one round.
    hcs[victim].advance_to_round(far);
    assert_eq!(
        hcs[victim].round, 1,
        "one inflated claim must advance at most one round, not to {far}"
    );
    // A second inflated claim still moves at most one more round.
    let far2: u32 = 900;
    let evil2 = Vote::sign(&ks[byz], height, far2, VoteKind::Prevote, Some(x));
    hcs[victim].add_prevote(evil2).unwrap();
    hcs[victim].advance_to_round(far2);
    assert_eq!(hcs[victim].round, 2, "N messages advance at most N rounds");
    // The stray far-round vote forms no quorum on the victim.
    assert_eq!(hcs[victim].try_prevote_quorum(), None);

    // The victim still finalizes with the honest three: meet at a shared
    // round with an honest proposer, then run the round.
    let honest = vec![0usize, 1, 2];
    let mut r = hcs[victim].round; // 2
    while idx_of(&ks, vs.proposer_for(height, r).unwrap()) == byz {
        r += 1;
    }
    // Everyone honest (incl. victim) walks to round r via local timeouts.
    for &i in &honest {
        while hcs[i].round < r {
            hcs[i].next_round();
        }
    }
    let prop = vs.proposer_for(height, r).unwrap();
    assert_ne!(
        prop,
        id(&ks[byz]),
        "reunion round must have an honest proposer"
    );
    let z = h(0x45);
    let mut reunion: Vec<HeightConsensus> = honest.iter().map(|&i| hcs[i].clone()).collect();
    for hc in reunion.iter_mut() {
        hc.receive_proposal(prop, z).unwrap();
    }
    vote_all(&mut reunion, &ks, height, r, z, &honest);
    for (k, hc) in reunion.iter_mut().enumerate() {
        assert_eq!(
            hc.try_precommit_quorum(),
            Some(z),
            "honest node {} must finalize with the honest three despite inflation",
            honest[k]
        );
    }
}

// Test 3 — QC withholding + replay: a genuine precommit QC for X at H,
// withheld then replayed at H+1, is inert (no finalize, no rewind).
#[test]
fn adv_withheld_qc_replay_at_next_height_is_inert() {
    let ks = keys(4);
    let vs = vset(&ks);
    let h1 = 1u64;
    let h2 = 2u64;
    let x = h(0x66);

    // Build a GENUINE QC for X at H=1 (3 prevotes + 3 precommits).
    let mut hc1 = HeightConsensus::new(h1, vs.clone());
    for k in ks.iter().take(3) {
        hc1.add_prevote(Vote::sign(k, h1, 0, VoteKind::Prevote, Some(x)))
            .unwrap();
    }
    assert_eq!(hc1.try_prevote_quorum(), Some(Some(x)));
    for k in ks.iter().take(3) {
        hc1.add_precommit(Vote::sign(k, h1, 0, VoteKind::Precommit, Some(x)))
            .unwrap();
    }
    assert_eq!(hc1.try_precommit_quorum(), Some(x));
    let qc = hc1
        .precommit_qc
        .clone()
        .expect("genuine precommit QC exists");
    assert_eq!(qc.height, h1);
    assert!(
        qc.verify(&vs),
        "the withheld QC is cryptographically genuine"
    );

    // The network moves to H+1 (fresh per-height state).
    let mut hc2 = HeightConsensus::new(h2, vs.clone());
    assert_eq!(hc2.decided, None);

    // Replay: every vote inside the old QC is out-of-scope at H+1.
    for k in ks.iter().take(3) {
        let stale_pv = Vote::sign(k, h1, 0, VoteKind::Prevote, Some(x));
        let e = hc2
            .add_prevote(stale_pv)
            .expect_err("stale height-1 vote must be rejected");
        assert!(
            e.contains("out of scope"),
            "reject reason must be scope: {e}"
        );
        let stale_pc = Vote::sign(k, h1, 0, VoteKind::Precommit, Some(x));
        let e2 = hc2
            .add_precommit(stale_pc)
            .expect_err("stale height-1 vote must be rejected");
        assert!(
            e2.contains("out of scope"),
            "reject reason must be scope: {e2}"
        );
    }
    // The old QC changes nothing: no finalize, no rewind.
    assert_eq!(hc2.try_prevote_quorum(), None);
    assert_eq!(hc2.try_precommit_quorum(), None);
    assert_eq!(
        hc2.decided, None,
        "stale QC must not finalize anything at H+1"
    );
    assert_eq!(hc2.height, h2, "stale QC must not rewind the height");
    assert!(hc2.precommit_qc.is_none(), "no QC installed from replay");

    // And the fresh height still finalizes normally on a new value.
    let y = h(0x67);
    for k in ks.iter().take(3) {
        hc2.add_prevote(Vote::sign(k, h2, 0, VoteKind::Prevote, Some(y)))
            .unwrap();
    }
    assert_eq!(hc2.try_prevote_quorum(), Some(Some(y)));
    for k in ks.iter().take(3) {
        hc2.add_precommit(Vote::sign(k, h2, 0, VoteKind::Precommit, Some(y)))
            .unwrap();
    }
    assert_eq!(hc2.try_precommit_quorum(), Some(y));
}

// Test 4 — 1-byzantine liveness grind: adversary votes nil on everything
// with valid signatures. The honest three still finalize; chain advances.
#[test]
fn adv_nil_grind_does_not_deny_quorum_and_chain_advances() {
    let ks = keys(4);
    let vs = vset(&ks);
    assert_eq!(vs.quorum_power(), 3);
    // Byzantine is NOT the round-0 proposer, so proposals stay honest.
    let p0 = idx_of(&ks, vs.proposer_for(1, 0).unwrap());
    let byz = (p0 + 1) % 4;
    let honest: Vec<usize> = (0..4).filter(|&i| i != byz).collect();
    assert_eq!(honest.len(), 3);

    for height in [1u64, 2u64] {
        let mut hcs: Vec<HeightConsensus> = (0..4)
            .map(|_| HeightConsensus::new(height, vs.clone()))
            .collect();
        // Honest proposer for this height/round 0 (never the byzantine:
        // heights rotate but with 4 keys round 0 may still name `byz` at
        // some height — walk rounds until honest, deterministically).
        let mut r: u32 = 0;
        while idx_of(&ks, vs.proposer_for(height, r).unwrap()) == byz {
            r += 1;
            for hc in hcs.iter_mut() {
                hc.next_round();
            }
        }
        let prop = vs.proposer_for(height, r).unwrap();
        let bh = h(height as u8);
        for hc in hcs.iter_mut() {
            hc.receive_proposal(prop, bh).unwrap();
        }
        // Honest three prevote the block; byzantine prevotes NIL (valid sig).
        for &i in &honest {
            let v = Vote::sign(&ks[i], height, r, VoteKind::Prevote, Some(bh));
            assert!(v.verify());
            for hc in hcs.iter_mut() {
                hc.add_prevote(v.clone()).unwrap();
            }
        }
        let nil_pv = Vote::sign(&ks[byz], height, r, VoteKind::Prevote, None);
        assert!(
            nil_pv.verify(),
            "nil vote carries an honest signature on nil"
        );
        for hc in hcs.iter_mut() {
            hc.add_prevote(nil_pv.clone()).unwrap();
        }
        for (i, hc) in hcs.iter_mut().enumerate() {
            let set = hc.prevote_set(r).unwrap();
            assert_eq!(set.power_for(Some(bh)), 3, "node {i}: block keeps 3");
            assert_eq!(set.power_for(None), 1, "node {i}: nil holds only 1");
            assert_eq!(
                hc.try_prevote_quorum(),
                Some(Some(bh)),
                "node {i}: nil votes must not steal the block quorum at height {height}"
            );
        }
        // Precommits: same shape.
        for &i in &honest {
            let v = Vote::sign(&ks[i], height, r, VoteKind::Precommit, Some(bh));
            for hc in hcs.iter_mut() {
                hc.add_precommit(v.clone()).unwrap();
            }
        }
        let nil_pc = Vote::sign(&ks[byz], height, r, VoteKind::Precommit, None);
        assert!(nil_pc.verify());
        for hc in hcs.iter_mut() {
            hc.add_precommit(nil_pc.clone()).unwrap();
        }
        for &i in &honest {
            assert_eq!(
                hcs[i].try_precommit_quorum(),
                Some(bh),
                "honest node {i} finalizes height {height} despite the nil grind"
            );
            assert_eq!(hcs[i].decided, Some(bh));
        }
    }
}

// Test 5 — amnesia replay: the adversary replays its OWN old valid votes
// (previous heights) at the current height. They are rejected as
// out-of-scope and change nothing.
#[test]
fn adv_amnesia_replay_of_own_old_votes_is_rejected_and_inert() {
    let ks = keys(4);
    let vs = vset(&ks);
    let byz = 3usize;
    let old_h = 1u64;
    let cur_h = 2u64;
    let old_block = h(0x88);

    // Genuine old votes the adversary really cast at H=1.
    let old_pv = Vote::sign(&ks[byz], old_h, 0, VoteKind::Prevote, Some(old_block));
    let old_pc = Vote::sign(&ks[byz], old_h, 0, VoteKind::Precommit, Some(old_block));
    assert!(old_pv.verify() && old_pc.verify());

    let mut hc = HeightConsensus::new(cur_h, vs.clone());
    let round_before = hc.round;

    // Replay at H=2: rejected as out-of-scope.
    let e1 = hc
        .add_prevote(old_pv.clone())
        .expect_err("old-height prevote must be rejected");
    assert!(
        e1.contains("out of scope"),
        "reject reason must be scope: {e1}"
    );
    let e2 = hc
        .add_precommit(old_pc.clone())
        .expect_err("old-height precommit must be rejected");
    assert!(
        e2.contains("out of scope"),
        "reject reason must be scope: {e2}"
    );

    // Nothing changed: no power counted, no quorum, no round move.
    // (Note: `add_*` leaves an empty per-round `VoteSet` entry behind on
    // rejection, so absence is asserted as emptiness, not `None`.)
    assert_eq!(hc.decided, None);
    assert_eq!(hc.round, round_before, "replay must not move the round");
    assert!(hc.prevote_set(0).map(|s| s.is_empty()).unwrap_or(true));
    assert!(hc.precommit_set(0).map(|s| s.is_empty()).unwrap_or(true));
    assert_eq!(hc.try_prevote_quorum(), None);
    assert_eq!(hc.try_precommit_quorum(), None);

    // The current height still finalizes on fresh votes afterwards.
    let cur_block = h(0x89);
    for k in ks.iter().take(3) {
        hc.add_prevote(Vote::sign(k, cur_h, 0, VoteKind::Prevote, Some(cur_block)))
            .unwrap();
    }
    assert_eq!(hc.try_prevote_quorum(), Some(Some(cur_block)));
    for k in ks.iter().take(3) {
        hc.add_precommit(Vote::sign(
            k,
            cur_h,
            0,
            VoteKind::Precommit,
            Some(cur_block),
        ))
        .unwrap();
    }
    assert_eq!(
        hc.try_precommit_quorum(),
        Some(cur_block),
        "fresh quorum finalizes after the rejected replay"
    );
}
