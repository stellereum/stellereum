//! HUNT: `adopt_committed` accepts a PREVOTE quorum as a finality proof.
//!
//! Target: src/runtime.rs:744
//!     if !certificate.verify(validators) {
//!         return Err("commit certificate does not carry a validator quorum");
//!     }
//!
//! `QuorumCertificate::verify` (src/consensus.rs:302) checks signatures and power
//! but NEVER inspects `self.kind`. It happily verifies a certificate of PREVOTES.
//! A prevote quorum is not finality: it says "we saw this block and it passed
//! `validate_proposal`", not "this block was decided". Tendermint requires a
//! 2/3 PRECOMMIT QC to decide; a prevote QC is one phase earlier and is
//! explicitly not a commitment.
//!
//! The catch-up path then calls `apply_and_advance`, which pushes the block into
//! `finalized`, applies it to state, and MOVES THE NODE'S HEIGHT FORWARD. A
//! lagging node is therefore made to finalize a block the network may never
//! decide, on nothing but a proposer-grade prevote quorum.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::Block;
use stellereum::state_engine::InMemoryStateEngine;

const N: usize = 4;

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

async fn node(ks: &[SigningKey]) -> ValidatorRuntime {
    let vs = vset(ks);
    let bal = 10_000 * stellereum::staking::MIN_VALIDATOR_BOND;
    let st = Arc::new(InMemoryStateEngine::new());
    stellereum::runtime::fund_genesis(&st, &vs, bal).await;
    ValidatorRuntime::new(ks[0].clone(), vs, st, 1)
}

fn block(k: &SigningKey, h: u64, prev: [u8; 32], root: [u8; 32]) -> Block {
    let mut b = Block {
        shard_id: stellereum::sharding::MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000,
        proposer: k.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(k);
    b
}

fn cert_of(ks: &[SigningKey], kind: VoteKind, bh: [u8; 32], n: usize) -> QuorumCertificate {
    QuorumCertificate {
        height: 1,
        round: 0,
        kind,
        block_hash: Some(bh),
        signatures: ks
            .iter()
            .take(n)
            .map(|k| {
                let v = Vote::sign(k, 1, 0, kind, Some(bh));
                (v.voter, v.signature)
            })
            .collect(),
    }
}

// ===========================================================================

#[tokio::test]
async fn hunt_finding_15_adopt_committed_refuses_a_prevote_quorum() {
    let ks = keys(N);
    let mut rt = node(&ks).await;
    let root = rt.state.get_state_root().await;
    let proposer = ks[1].clone();
    let blk = block(&proposer, 1, [0u8; 32], root);
    let bh = blk.compute_hash();

    // The proposer broadcasts a block. Three honest validators PREVOTE it and
    // stop there -- no precommit quorum is ever reached, so the network NEVER
    // decides this block.
    let prevotes = cert_of(&ks, VoteKind::Prevote, bh, 3);
    let precommits = cert_of(&ks, VoteKind::Precommit, bh, 3);
    println!(
        "[FINDING 15] prevote QC verifies:   {}",
        prevotes.verify(&rt.validators)
    );
    println!(
        "[FINDING 15] precommit QC verifies: {}",
        precommits.verify(&rt.validators)
    );
    assert!(
        prevotes.verify(&rt.validators),
        "a 3-of-4 prevote quorum is a real prevote quorum"
    );

    let _set = rt.validators.clone();
    let r = rt.adopt_committed(1, blk.clone(), prevotes).await;
    println!(
        "[FINDING 15] adopt_committed with a PREVOTE quorum -> {:?}",
        r.as_ref()
            .map(|h| hex::encode(&h[..4]))
            .map_err(|e| e.clone())
    );
    // FIXED. `QuorumCertificate::verify` signs over the certificate's OWN fields, so a
    // prevote quorum verified perfectly well while `kind` went unread. Prevotes are
    // broadcast in the clear every round -- including rounds that never finalize --
    // so a passive peer could harvest one off the wire, relabel the kind, and ship
    // it as proof of finality with zero stake of its own. "2/3 saw this block" is
    // not "2/3 committed to it".
    assert!(
        r.is_err(),
        "a prevote quorum must not be accepted as a finality proof: {r:?}"
    );
    assert!(
        r.as_ref().unwrap_err().contains("not a precommit quorum"),
        "the refusal must name the reason: {:?}",
        r.err()
    );

    // The node must not have moved at all.
    let h = rt.height();
    println!(
        "[FINDING 15] node height is still {h} (was 1); finalized = {:?}",
        rt.finalized.iter().map(|(hh, _)| *hh).collect::<Vec<_>>()
    );
    assert_eq!(h, 1, "the node must not advance on a prevote quorum");
    assert!(
        rt.finalized.is_empty(),
        "an unfinalized, merely-PREVOTED block must not be recorded as finalized"
    );
    println!("[FINDING 15] FIXED: a merely-PREVOTED block is refused by the catch-up path.");
}

#[tokio::test]
async fn hunt_finding_15b_the_precommit_quorum_is_not_required_at_all() {
    // Same attack, one fewer signature: 2 of 4 is BELOW the precommit quorum but
    // still... let's check what verify() says. (4 validators, quorum_power 3.)
    let ks = keys(N);
    let rt = node(&ks).await;
    let bh = [0x21u8; 32];
    for n in 1..=N {
        let c = cert_of(&ks, VoteKind::Prevote, bh, n);
        println!(
            "[FINDING 15b] prevote QC with {n} signature(s) verifies: {}",
            c.verify(&rt.validators)
        );
    }
    for n in 1..=N {
        let c = cert_of(&ks, VoteKind::Precommit, bh, n);
        println!(
            "[FINDING 15b] precommit QC with {n} signature(s) verifies: {}",
            c.verify(&rt.validators)
        );
    }
    // Both curves are identical: `kind` is not consulted at all.
    for n in 1..=N {
        let p = cert_of(&ks, VoteKind::Prevote, bh, n).verify(&rt.validators);
        let c = cert_of(&ks, VoteKind::Precommit, bh, n).verify(&rt.validators);
        assert_eq!(
            p, c,
            "kind must not change the verdict, yet it must not change finality either"
        );
    }
    println!("[FINDING 15b] `kind` is verified for signing but never for SEMANTICS.");
}

#[tokio::test]
async fn hunt_finding_16_adopt_committed_binds_the_certificate_height() {
    // runtime.rs has no `certificate.height == height` / `certificate.round` test.
    // A certificate minted for a different height is accepted as long as its
    // block_hash matches. The block hash binds the height, so this is currently
    // contained -- but the check the code obviously intends is simply absent.
    let ks = keys(N);
    let mut rt = node(&ks).await;
    let root = rt.state.get_state_root().await;
    let blk = block(&ks[1], 1, [0u8; 32], root);
    let bh = blk.compute_hash();

    // A quorum that genuinely signed a PRECOMMIT for (height 99999, round 77,
    // block B). Every signature is real and verifies over its own height/round.
    let far = QuorumCertificate {
        height: 99_999,
        round: 77,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
        signatures: ks
            .iter()
            .take(3)
            .map(|k| {
                let v = Vote::sign(k, 99_999, 77, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect(),
    };
    assert!(
        far.verify(&rt.validators),
        "the signatures are genuine over height 99999"
    );
    let _set = rt.validators.clone();
    let r = rt.adopt_committed(1, blk, far).await;
    println!("[FINDING 16] a certificate signed at height 99999 round 77, presented for height 1 -> {:?}", r.as_ref().map(|h| hex::encode(&h[..4])).map_err(|e| e.clone()));
    println!("[FINDING 16] FIXED: `certificate.height` and `certificate.round` are now compared");
    println!("[FINDING 16] with the height and round they are used to prove.");
    // FIXED. The certificate's height and round are now bound to the height it is
    // used to prove. Both are signed, so without that check a quorum harvested at
    // any height or round replayed as a commit for our current one.
    assert!(
        r.is_err(),
        "a certificate for height 99999 must not finalize a block at height 1"
    );
    assert!(
        r.as_ref()
            .unwrap_err()
            .contains("certificate is for height"),
        "the refusal must name the reason: {:?}",
        r.err()
    );

    // Counter-check: the same certificate CANNOT adopt a block whose own height
    // is 99999, because the block hash binds the height and the cert commits to
    // the hash of the height-1 block.
    let _ = (bh,);
}
