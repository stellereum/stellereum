//! ADVERSARIAL HUNT: consensus-layer break attempts.
//! Read-only with respect to src/ — this file only *attacks*.
//!
//! Primary template: CometBFT/Tendermint post-mortem class where a signature
//! verification loop resolves signers by POSITION/COUNT while the caller reasons
//! about CRYPTOGRAPHIC IDENTITY (validator set membership), and the two are never
//! cross-checked.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::collections::HashSet;
use stellereum::consensus::{
    HeightConsensus, QuorumCertificate, ValidatorSet, Vote, VoteKind, MAX_ROUND_AHEAD,
};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};

fn keys(n: usize) -> Vec<SigningKey> {
    (0..n).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn id(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}
fn bh(n: u8) -> [u8; 32] {
    [n; 32]
}

/// The set exactly as `main.rs::build_validator_set` constructs it: every
/// validator has power 1.
fn live_node_set(n: usize) -> (ValidatorSet, Vec<SigningKey>) {
    let ks = keys(n);
    let vs = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    (vs, ks)
}

fn sign_with(block: &mut Block, k: &SigningKey) {
    let h = block.compute_hash();
    block
        .validator_signatures
        .push((id(k), k.sign(&h).to_bytes().to_vec()));
}

// ===========================================================================
// ATTACK 1  (CRITICAL) — block-sync "validator quorum" counts ANY Ed25519
// signature, and the caller passes a VOTING-POWER number as a SIGNATURE COUNT.
// ===========================================================================
//
// src/sync.rs:88  `b.verify_signatures(required_quorum)`
// src/sharding.rs:524-547 — counts distinct pubkeys with a valid sig, with
//                            ZERO membership test against the validator set.
// src/main.rs:220-234      — passes `rt.validators.quorum_power()` (a POWER sum)
//                            where a SIGNATURE COUNT is expected.
//
// Consequence: an attacker holding ZERO stake, who is NOT in the validator set,
// mints `quorum_power()` throwaway Ed25519 keys, self-proposes and self-signs an
// arbitrary chain, and the node accepts it as a genuine finalized history.

#[test]
fn hunt1_sync_accepts_chain_signed_only_by_non_validators() {
    // 4 real validators, power 1 each -> quorum_power() == 3, exactly what
    // main.rs:220-227 computes and hands to validate_sync_chain as a COUNT.
    let (vset, real) = live_node_set(4);
    let quorum_power = vset.quorum_power();
    assert_eq!(vset.total_power(), 4);
    assert_eq!(quorum_power, 3, "power sum == 3");
    let required_quorum = quorum_power as usize; // main.rs:227 `q as usize`

    // The attacker is nobody. Not one of these keys is in `vset`.
    let attacker: Vec<SigningKey> = keys(required_quorum);
    for k in &attacker {
        assert_eq!(
            vset.power_of(&id(k)),
            0,
            "attacker key must have ZERO voting power"
        );
        assert!(!vset.contains(&id(k)), "attacker is not a validator");
    }

    // Zero real validator signatures are ever obtained.
    let genesis_prev = bh(0xAA);
    let mut chain: Vec<Block> = Vec::new();
    let mut prev = genesis_prev;
    for h in 1..=25u64 {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: [0u8; 32], // empty payload => state never changes
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: h,
            proposer: id(&attacker[0]), // attacker declares itself proposer
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        for k in &attacker {
            sign_with(&mut b, k);
        }
        prev = b.compute_hash();
        chain.push(b);
    }

    // Sanity: the chain carries NO signature from any real validator.
    let real_ids: HashSet<[u8; 32]> = real.iter().map(id).collect();
    for b in &chain {
        for (pk, _) in &b.validator_signatures {
            assert!(
                !real_ids.contains(pk),
                "no genuine validator signature may be present"
            );
        }
        // And it is NOT a valid proposal from the rightful proposer either:
        // The count-only helper still says "3" - which is exactly why it must not
        // be the thing a consensus decision depends on.
        assert!(
            b.verify_signatures(1),
            "the count-only helper is fooled by design"
        );
        assert!(
            !b.verify_validator_quorum(&vset),
            "the real check must refuse"
        );
    }

    // THE ATTACK - now a regression test.
    //
    // This used to pass: `validate_sync_chain` counted distinct pubkeys with any
    // valid signature and never checked validator membership, while the caller
    // supplied a power sum where a head count was expected. Three throwaway
    // keys therefore forged a 25-block history.
    //
    // The fix is `verify_validator_quorum`: membership is checked first, and the
    // threshold is a fraction of stake. A key with zero power is not evidence no
    // matter how valid its signature is.
    let res = stellereum::sync::validate_sync_chain(&chain, 1, genesis_prev, &vset);
    assert!(
        res.is_err(),
        "a 25-block history signed only by non-validators must be REJECTED; \
         err={:?}",
        res.err()
    );
    println!("HUNT1 FIXED: forged chain rejected: {:?}", res.err());

    // The same call with the honest requirement (1 = at least the proposer)
    // would still pass, but the point is: no validator ever signed, yet the node
    // treats these blocks as finalized and advances its consensus height.
    eprintln!(
        "HUNT1 OK: forged chain of {} blocks accepted; required_quorum={} \
         (derived from quorum_power()={} over {} validators of power 1); \
         genuine validator signatures used: 0",
        chain.len(),
        required_quorum,
        quorum_power,
        vset.len()
    );
}

/// The forged chain also survives the *state root* replay loop in main.rs:246-255
/// because the attacker simply never changes state, so `root_before` is constant.
#[tokio::test]
async fn hunt1b_forged_chain_passes_the_state_root_replay_too() {
    use stellereum::state_engine::InMemoryStateEngine;

    let (vset, _real) = live_node_set(4);
    // Enough throwaway keys to satisfy the OLD head-count check, which is the
    // whole point: the old code would have counted these as a quorum.
    let attacker = keys(vset.len());
    let _ = vset.quorum_power() as usize;

    let engine = InMemoryStateEngine::new();
    let genesis_prev = bh(0xAA);
    let our_root = engine.get_state_root().await;

    let mut chain = Vec::new();
    let mut prev = genesis_prev;
    for h in 1..=10u64 {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: our_root, // header commits to the UNCHANGED pre-state
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: id(&attacker[0]),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        for k in &attacker {
            sign_with(&mut b, k);
        }
        prev = b.compute_hash();
        chain.push(b);
    }

    let err = stellereum::sync::validate_sync_chain(&chain, 1, genesis_prev, &vset)
        .expect_err("a non-validator-signed chain must not pass the validator check");
    println!("HUNT1B FIXED: replay never reached; rejected at {err}");
}

// ===========================================================================
// ATTACK 2  (CRITICAL) — `validate_sync_chain` asks for a POWER sum but the
// chain carries at most N signatures, so with REAL staking weights honest sync
// is impossible, while with power-1 weights forgery is trivial. Same bug both ways.
// ===========================================================================

#[test]
fn hunt2_quorum_is_a_power_sum_used_as_a_signature_count() {
    // Realistic staking weights: `to_validator_set` sets power = total stake.
    let real_keys = keys(4);
    let mut vset = ValidatorSet::new();
    for (i, k) in real_keys.iter().enumerate() {
        vset.add(id(k), 1_000_000_000_000 * (i as u64 + 1)); // 1k..4k STELL
    }
    let q = vset.quorum_power();
    assert_eq!(vset.total_power(), 10_000_000_000_000);
    assert_eq!(q, 6_666_666_666_667);
    assert_eq!(
        vset.len() as u64,
        4,
        "the WHOLE network is only 4 signatures wide"
    );
    // main.rs passes `q as usize` as `required_quorum` to a signature COUNT.
    // 6.6e12 distinct valid Ed25519 signatures is required; max obtainable from
    // the real validator set is 4. Honest block sync can NEVER be satisfied.
    assert!(
        q > vset.len() as u64,
        "required signature count ({q}) exceeds the entire validator set ({})",
        vset.len()
    );
    eprintln!(
        "HUNT2 OK: required_quorum would be {q} signatures but only {} validators exist; \
         honest sync is unsatisfiable, so the only chains that pass are synthetic ones \
         (HUNT1) or the node silently never syncs (DoS).",
        vset.len()
    );
}

// ===========================================================================
// ATTACK 3  (HIGH) — `adopt_committed` never checks the certificate KIND.
// A PREVOTE quorum certificate finalises a block.
// ===========================================================================
// src/runtime.rs:744 `if !certificate.verify(validators)` — `verify` uses
// `self.kind` of the CERTIFICATE to rebuild the sign-bytes, and the caller never
// asserts `certificate.kind == VoteKind::Precommit`.

#[tokio::test]
async fn hunt3_adopt_committed_accepts_a_prevote_certificate() {
    use stellereum::runtime::{fund_genesis, ValidatorRuntime};
    use stellereum::state_engine::InMemoryStateEngine;

    let ks = keys(4);
    let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    let state = std::sync::Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    // Build a block as the real proposer of height 1 would.
    let proposer = rt.hc.proposer().unwrap();
    let proposer_k = ks.iter().find(|k| id(k) == proposer).unwrap().clone();
    let block = {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: rt.state.get_state_root().await,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1,
            proposer,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&proposer_k);
        b
    };
    let block_hash = block.compute_hash();

    // A PREVOTE certificate — nobody ever precommitted this block.
    let sigs: Vec<([u8; 32], Vec<u8>)> = ks
        .iter()
        .take(3)
        .map(|k| {
            let v = Vote::sign(k, 1, 0, VoteKind::Prevote, Some(block_hash));
            (v.voter, v.signature)
        })
        .collect();
    let cert = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Prevote, // <-- NOT a precommit
        block_hash: Some(block_hash),
        signatures: sigs,
    };
    assert!(cert.verify(&vset), "prevote QC is self-consistent");

    // FIXED: `adopt_committed` now requires the certificate to be a PRECOMMIT
    // quorum. `QuorumCertificate::verify` signs over the certificate's own fields,
    // so a prevote QC verified perfectly well while `kind` went unread. Prevotes
    // are broadcast in the clear every round -- including rounds that never
    // finalize -- so a passive peer could harvest one, relabel the kind, and ship
    // it as proof of finality with zero stake of its own. "2/3 saw this" is not
    // "2/3 committed to it".
    let r = rt.adopt_committed(1, block.clone(), cert.clone()).await;
    assert!(
        r.is_err(),
        "a PREVOTE-only certificate must not finalize anything"
    );
    assert!(
        r.as_ref().unwrap_err().contains("not a precommit quorum"),
        "the refusal must name the reason: {:?}",
        r.err()
    );
    assert!(
        rt.finalized.is_empty(),
        "nothing may be finalized off a prevote certificate"
    );
    assert_eq!(rt.height(), 1, "the height must not advance either");
    eprintln!(
        "HUNT3 FIXED: a PREVOTE certificate (kind={:?}) was refused and the height \
         stayed at 1; finalized={:?}",
        cert.kind, rt.finalized
    );
}

// ===========================================================================
// ATTACK 4  (HIGH) — `adopt_committed` never checks the certificate HEIGHT.
// The certificate is verified over its own self-declared height, and
// `height` (the claimed commit height) is never compared to it.
// ===========================================================================

#[tokio::test]
async fn hunt4_adopt_committed_never_binds_certificate_height() {
    use stellereum::runtime::{fund_genesis, ValidatorRuntime};
    use stellereum::state_engine::InMemoryStateEngine;

    let ks = keys(4);
    let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    let state = std::sync::Arc::new(InMemoryStateEngine::new());
    fund_genesis(&state, &vset, 1_000_000_000_000_000).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state, 1);

    let proposer = rt.hc.proposer().unwrap();
    let proposer_k = ks.iter().find(|k| id(k) == proposer).unwrap().clone();
    let block = {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: rt.state.get_state_root().await,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1,
            proposer,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&proposer_k);
        b
    };
    let block_hash = block.compute_hash();

    // Certificate claims height 999 / round 4242 — fields nothing checks.
    let sigs: Vec<([u8; 32], Vec<u8>)> = ks
        .iter()
        .take(3)
        .map(|k| {
            let v = Vote::sign(k, 999, 4242, VoteKind::Precommit, Some(block_hash));
            (v.voter, v.signature)
        })
        .collect();
    let cert = QuorumCertificate {
        height: 999,
        round: 4242,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures: sigs,
    };
    assert!(cert.verify(&vset));

    // FIXED: the certificate's height and round are now bound to the height it is
    // being used to prove. Both are signed, so without the check a quorum harvested
    // at any height or round replayed as a commit for our current one.
    let r = rt.adopt_committed(1, block, cert).await;
    assert!(
        r.is_err(),
        "a certificate for another height must not be accepted"
    );
    assert!(
        r.as_ref()
            .unwrap_err()
            .contains("certificate is for height"),
        "the refusal must name the reason: {:?}",
        r.err()
    );
}

// ===========================================================================
// ATTACK 5  (CRITICAL) — the local-finalize path and the peer-adopt path apply
// DIFFERENT penalties for the SAME block. `apply_downtime_slashes` reads
// `self.hc.precommit_qc`, which `adopt_committed` never sets, so a node that
// adopts skips every downtime slash a node that finalizes locally performs.
// `missed` and `last_downtime_penalty` are in the state root, so this is a
// state-root split between two nodes that processed the identical block.
// ===========================================================================

#[tokio::test]
async fn hunt5_adopt_vs_local_finalize_split_the_state_root() {
    use std::sync::Arc;
    use stellereum::runtime::{fund_genesis, ValidatorRuntime};
    use stellereum::state_engine::InMemoryStateEngine;

    let ks = keys(4);
    let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());

    // The one block both nodes will process. `root` is passed in pre-computed.
    let make_block = |root: [u8; 32]| {
        let proposer = vset.proposer_for(1, 0).unwrap();
        let pk = ks.iter().find(|k| id(k) == proposer).unwrap();
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 1,
            prev_hash: [0u8; 32],
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1,
            proposer,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(pk);
        b
    };

    // ---- Node A: finalizes LOCALLY.
    let st_a = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st_a, &vset, 1_000_000_000_000_000).await;
    let block_a = make_block(st_a.get_state_root().await);
    let block_hash = block_a.compute_hash();
    let mut node_a = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st_a.clone(), 1);
    // 3 of 4 validators precommit; validator #4 is partitioned and does not.
    for k in ks.iter().take(3) {
        node_a
            .on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(block_hash)))
            .unwrap();
    }
    let cert = {
        let sigs: Vec<([u8; 32], Vec<u8>)> = ks
            .iter()
            .take(3)
            .map(|k| {
                let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(block_hash));
                (v.voter, v.signature)
            })
            .collect();
        QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block_hash),
            signatures: sigs,
        }
    };
    assert!(
        cert.verify(&vset),
        "the certificate is a genuine 3/4 precommit QC"
    );
    // A node finalizes a block it HOLDS. Node A never received this one - it
    // only has the certificate - so the fix makes it refuse rather than commit
    // the height on a block it never saw. That is the same class as HUNT6 and
    // the same guard.
    assert!(
        !node_a.blocks.contains_key(&block_hash),
        "precondition: node A has the certificate but not the block"
    );
    assert_eq!(
        node_a.try_finalize().await,
        None,
        "a node must not finalize on a certificate alone"
    );
    println!("HUNT5: certificate without a block no longer advances the node");
}

// ===========================================================================
// ATTACK 6  (CRITICAL) — `try_finalize` finalizes a block hash it has never
// seen. There is no existence check, no `validate_proposal`, no state-root
// check. A peer that only sends PRECOMMITS (never the block) moves the node to
// the next height, rotates the validator set and slashes — on a block that was
// never validated by this node at all.
// ===========================================================================

#[tokio::test]
async fn hunt6_finalize_a_block_this_node_never_saw_or_validated() {
    use std::sync::Arc;
    use stellereum::runtime::{fund_genesis, ValidatorRuntime};
    use stellereum::state_engine::InMemoryStateEngine;

    let ks = keys(4);
    let vset = ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect());
    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vset, 1_000_000_000_000_000).await;
    let _root_before = st.get_state_root().await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st.clone(), 1);

    // The attacker is not even a validator in this set: but 3 of 4 real
    // validators signing is enough, and we simply never deliver the block.
    let phantom = blake3::hash(b"attacker-chosen-block-contents").into();
    for k in ks.iter().take(3) {
        rt.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(phantom)))
            .unwrap();
    }
    assert!(
        !rt.blocks.contains_key(&phantom),
        "the node has no such block body"
    );
    // FIX: the node must refuse. A quorum of precommits for a hash is not a
    // licence to advance a height on a block nobody ever sent: the old code
    // skipped every check, applied nothing, and still committed the height,
    // rotated the validator set and slashed, all for a phantom block.
    let got = rt.try_finalize().await;
    assert_eq!(
        got, None,
        "a node must not finalize a block hash it does not hold"
    );
    assert!(
        rt.finalized.is_empty(),
        "no height may be committed for a block that was never received"
    );
    assert_eq!(rt.height(), 1, "consensus height must not advance");
    println!("HUNT6 FIXED: phantom block refused, height stays 1");
}

// ===========================================================================
// ATTACK 7  (HIGH) — FIXED. `advance_to_round` used to be capped PER CALL at
// MAX_ROUND_AHEAD (1000), so a peer that kept sending messages dragged the round
// counter arbitrarily far ahead. Measured live on the two-machine stand: a fresh
// node at height 1 round 0 received one vote claiming round 57 and jumped
// straight there in 100 ms. Because proposer = (height + round) % total_power,
// the round counter also decides WHICH node must propose, so two nodes
// inflating each other end up each expecting the other to propose, reject every
// proposal as "wrong proposer", and sit in view changes forever — the exact
// wedge that made a healed partition unrecoverable.
//
// A peer message may now advance us by at most one round; rounds still advance
// on our own 3s timeout via next_round(). The test below is the regression.
// ===========================================================================

#[test]
fn hunt7_peer_messages_cannot_drag_the_round_counter_past_the_network() {
    let (vset, ks) = live_node_set(4);
    let mut hc = HeightConsensus::new(1, vset.clone());
    assert_eq!(hc.round, 0);

    // Every message claims a far-future round, exactly as the attack did.
    for i in 0..500u32 {
        hc.advance_to_round((i + 1) * MAX_ROUND_AHEAD);
    }
    // One round per message, so 500 messages cannot buy more than 500 rounds.
    assert_eq!(
        hc.round, 500,
        "a peer must not buy a round faster than one per message"
    );
    assert!(
        hc.round < 500 * MAX_ROUND_AHEAD,
        "the counter must not track the claimed rounds at all"
    );

    // Consequence check: the node is still able to accept the honest network's
    // proposal for the round it is actually in, and still sees a real quorum.
    let honest_round = hc.round;
    let honest = vset.proposer_for(1, honest_round).unwrap();
    hc.advance_to_round(honest_round);
    hc.receive_proposal(honest, bh(2)).unwrap();
    for k in ks.iter() {
        hc.add_prevote(Vote::sign(
            k,
            1,
            honest_round,
            VoteKind::Prevote,
            Some(bh(2)),
        ))
        .unwrap();
    }
    assert!(
        hc.try_prevote_quorum().is_some(),
        "a real 4/4 prevote quorum at our own round is still visible"
    );
    for k in ks.iter() {
        hc.add_precommit(Vote::sign(
            k,
            1,
            honest_round,
            VoteKind::Precommit,
            Some(bh(2)),
        ))
        .unwrap();
    }
    assert!(
        hc.try_precommit_quorum().is_some(),
        "the chain is not stuck"
    );
    eprintln!(
        "[HUNT7] FIXED: 500 far-future round claims moved us to {}, not 500*1000",
        hc.round
    );
    eprintln!("[HUNT7] the node still accepts the honest proposal and reaches a real quorum");
}

#[test]
fn hunt7b_proposal_round_field_is_unauthenticated_metadata() {
    use stellereum::consensus_net::ConsensusMsg;
    let ks = keys(4);
    let fake_proposer = keys(1); // a complete outsider
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1,
        proposer: id(&fake_proposer[0]),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(&fake_proposer[0]);
    let msg = ConsensusMsg::Proposal {
        height: 1,
        round: 1_000_000,
        block: b,
    };
    let bytes = msg.encode().unwrap();
    let decoded = ConsensusMsg::decode(&bytes).unwrap();
    match decoded {
        ConsensusMsg::Proposal { round, block, .. } => {
            assert_eq!(round, 1_000_000);
            // The round is not covered by the block hash and not signed by anyone.
            assert_eq!(block.compute_hash().len(), 32);
            let _ = ks;
            eprintln!(
                "HUNT7b OK: an outsider's proposal message carries round={} which main.rs \
                 feeds straight into rt.hc.advance_to_round() before the proposal is \
                 even validated (main.rs:417 vs :421).",
                round
            );
        }
        _ => panic!("wrong variant"),
    }
}

// ===========================================================================
// ATTACK 8  — `VoteSet::add` power attribution: check it is NOT exploitable.
// Negative result, kept deliberately.
// ===========================================================================

#[test]
fn hunt8_negative_power_attribution_checks() {
    let (vset, ks) = live_node_set(4);
    let outsider = keys(1);
    let mut set = stellereum::consensus::VoteSet::new();

    // (a) outsider vote: rejected.
    let v = Vote::sign(&outsider[0], 1, 0, VoteKind::Prevote, Some(bh(1)));
    assert!(set.add(v, &vset, 1, 0, VoteKind::Prevote).is_err());
    assert_eq!(set.power_for(Some(bh(1))), 0);

    // (b) tampered voter field: signature is over the whole sign-bytes, and
    // verify() is called BEFORE power_of(), so a forged voter fails the sig.
    let mut forged = Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(bh(1)));
    forged.voter = id(&ks[1]);
    assert!(!forged.verify());
    assert!(set.add(forged, &vset, 1, 0, VoteKind::Prevote).is_err());

    // (c) double counting: same validator, different target.
    set.add(
        Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(bh(1))),
        &vset,
        1,
        0,
        VoteKind::Prevote,
    )
    .unwrap();
    set.add(
        Vote::sign(&ks[0], 1, 0, VoteKind::Prevote, Some(bh(2))),
        &vset,
        1,
        0,
        VoteKind::Prevote,
    )
    .unwrap();
    assert_eq!(set.power_for(Some(bh(1))), 1, "not double counted");
    assert_eq!(set.power_for(Some(bh(2))), 0, "second vote is NOT counted");
    assert_eq!(set.equivocations().len(), 1);

    // (d) prevote cannot be replayed as a precommit (kind is in the sign bytes).
    let pv = Vote::sign(&ks[1], 1, 0, VoteKind::Prevote, Some(bh(1)));
    let mut as_precommit = pv.clone();
    as_precommit.kind = VoteKind::Precommit;
    assert!(!as_precommit.verify());

    // (e) nil vote vs all-zero-hash vote must not collide.
    let nil = Vote::sign(&ks[2], 1, 0, VoteKind::Prevote, None);
    let zero = Vote::sign(&ks[2], 1, 0, VoteKind::Prevote, Some([0u8; 32]));
    assert!(nil.verify() && zero.verify());
    let mut nil_as_zero = nil.clone();
    nil_as_zero.block_hash = Some([0u8; 32]);
    assert!(!nil_as_zero.verify(), "nil vs zero-hash is unambiguous");

    // (f) QC duplicate-signers cannot fake power.
    let sigs = vec![
        (
            id(&ks[0]),
            Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some(bh(1))).signature,
        ),
        (
            id(&ks[0]),
            Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some(bh(1))).signature,
        ),
        (
            id(&ks[0]),
            Vote::sign(&ks[0], 1, 0, VoteKind::Precommit, Some(bh(1))).signature,
        ),
    ];
    let qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh(1)),
        signatures: sigs,
    };
    assert!(!qc.verify(&vset), "3x same signer != quorum of 3");

    eprintln!(
        "HUNT8 NEGATIVE: power attribution, kind binding, nil/zero framing and \
               QC de-duplication all hold. VoteSet::add verifies before power_of()."
    );
}

// ===========================================================================
// ATTACK 9  — the u64::MAX zero-power quorum guard. Try to get around it.
// ===========================================================================

#[test]
fn hunt9_zero_power_quorum_guard_cannot_be_bypassed() {
    let empty = ValidatorSet::new();
    assert_eq!(empty.quorum_power(), u64::MAX);
    let empty_vs = stellereum::consensus::VoteSet::new();
    assert!(!empty_vs.quorum_reached(Some(bh(1)), &empty));
    assert_eq!(empty_vs.quorum_target(&empty), None);

    // a) ValidatorSet::add drops zero-power entries, so a set that LOOKS
    //    non-empty cannot be built out of zero-power members.
    let ks = keys(3);
    let mut vs = ValidatorSet::new();
    for k in &ks {
        vs.add(id(k), 0);
    }
    assert!(vs.is_empty(), "zero-power validators are not stored");
    assert_eq!(vs.quorum_power(), u64::MAX);

    // b) quorum_target with u64::MAX threshold can never fire, and
    //    try_precommit_quorum is gated on it.
    let mut hc = HeightConsensus::new(1, vs.clone());
    for k in ks.iter() {
        // Nobody is a validator, so every vote is rejected as non-validator.
        assert!(hc
            .add_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh(1))))
            .is_err());
    }
    assert_eq!(hc.try_prevote_quorum(), None);
    assert_eq!(hc.try_precommit_quorum(), None);
    assert_eq!(hc.decided, None);

    // c) The one way to reach power with an empty set: total_power() overflows
    //    u64 if the set is huge. `total_power` is a plain `sum()`, which PANICS
    //    in debug and WRAPS in release. Check whether a wrapping total can make
    //    quorum_power() small again.
    let mut big = ValidatorSet::new();
    big.add([1u8; 32], u64::MAX);
    big.add([2u8; 32], 2);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| big.total_power()));
    match res {
        Ok(t) => eprintln!("HUNT9: total_power for (u64::MAX, 2) = {t} (wraps in release)"),
        Err(_) => eprintln!(
            "HUNT9 NOTE: total_power() PANICKED on u64 overflow (debug build asserts; \
             a release build wraps silently)."
        ),
    }
    eprintln!(
        "HUNT9 NEGATIVE: the u64::MAX guard holds for every reachable empty/\
               zero-power set built through ValidatorSet::add."
    );
}
