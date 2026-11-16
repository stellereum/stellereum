use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashSet;

use super::sortition::qc_split_active_at;
use super::*;

/// A REAL Falcon-512 keypair (produced by the FIPS 206 reference
/// implementation), so the tests below exercise the PRODUCTION verifier
/// and not a test-only shortcut.
///
/// AUDIT W6.5: these fixtures used to be a hand-rolled BLAKE3
/// "check-digest" pseudo-signature that only the `cfg(test)` branch of
/// `verify_falcon_signature_or_test` accepted — the tests therefore
/// proved nothing about the real lattice verification. They now sign with
/// the real signer.
fn make_sample_falcon512(seed: u8) -> crate::post_quantum::FalconKeypair {
    crate::post_quantum::FalconKeypair::generate_from_seed(seed)
}

fn make_sample_falcon512_sig(fk: &crate::post_quantum::FalconKeypair, msg: &[u8]) -> Vec<u8> {
    fk.sign(msg)
}

#[test]
fn test_sortition_committee_determinism_and_stake_weighting() {
    let mut vs = ValidatorSet::new();
    let id_a = [0x01; 32];
    let id_b = [0x02; 32];
    let id_c = [0x03; 32];
    let id_d = [0x04; 32];

    // Validator A holds 90% of total voting power
    vs.add(id_a, 900);
    vs.add(id_b, 33);
    vs.add(id_c, 33);
    vs.add(id_d, 34);

    // The parent block hash seeds the draw: every node of a height MUST
    // pass the same one (the hash committed in the block header).
    let parent = [0xA5; 32];

    // 1. Determinism: identical parameters yield identical committee
    let c1 = derive_sortition_committee(&vs, 10, 0, 2, &parent);
    let c2 = derive_sortition_committee(&vs, 10, 0, 2, &parent);
    assert_eq!(
        c1, c2,
        "Sortition committee selection must be strictly deterministic"
    );
    assert_eq!(c1.len(), 2);

    // 2. Different height / round yields different ticket outcomes
    let c3 = derive_sortition_committee(&vs, 11, 0, 2, &parent);
    assert_eq!(c3.len(), 2);

    // 3. Stake weighting: Validator A (90% stake) must be selected in almost all single-seat draws
    let mut a_selected_count = 0;
    let trials = 100;
    for h in 1..=trials {
        let comm = derive_sortition_committee(&vs, h as u64, 0, 1, &parent);
        assert_eq!(comm.len(), 1);
        if comm[0] == id_a {
            a_selected_count += 1;
        }
    }
    assert!(
        a_selected_count >= 80,
        "Validator with 90% stake should win sortition >= 80% of trials, got {a_selected_count}"
    );

    // 4. Edge cases
    let empty_vs = ValidatorSet::new();
    assert!(derive_sortition_committee(&empty_vs, 1, 0, 16, &parent).is_empty());
    assert!(derive_sortition_committee(&vs, 1, 0, 0, &parent).is_empty());

    // Committee size larger than validator set returns all active validators
    let all_comm = derive_sortition_committee(&vs, 1, 0, 100, &parent);
    assert_eq!(all_comm.len(), 4);
}

/// The committee must NOT be computable from `(height, round)` alone: the
/// parent block hash is the entropy that is unknown until the chain has
/// produced that parent, so an adversary cannot compute future committee
/// memberships (and aim a DDoS / a collusion at a chosen round) ahead of
/// time.
#[test]
fn test_sortition_committee_depends_on_parent_block_hash() {
    let mut vs = ValidatorSet::new();
    for i in 0..16u8 {
        vs.add([i + 1; 32], 10);
    }

    let parent_a = [0x11; 32];
    let parent_b = [0x22; 32];

    // Same height, same round, DIFFERENT parent -> the seed differs.
    assert_ne!(
        sortition_seed(&parent_a, 7, 0),
        sortition_seed(&parent_b, 7, 0),
        "the sortition seed must commit to the parent block hash"
    );

    // The committee itself must differ for at least one of many draws:
    // with 16 equally staked validators and an 8-seat committee the draw is
    // wide enough for the parent hash to matter.
    let mut differs = false;
    for round in 0..32u32 {
        let a = derive_sortition_committee(&vs, 7, round, 8, &parent_a);
        let b = derive_sortition_committee(&vs, 7, round, 8, &parent_b);
        assert_eq!(a.len(), 8);
        assert_eq!(b.len(), 8);
        if a != b {
            differs = true;
            break;
        }
    }
    assert!(
        differs,
        "changing the parent block hash must change the elected committee"
    );

    // A one-bit change of the parent is enough (the seed is a hash).
    let mut parent_c = parent_a;
    parent_c[0] ^= 1;
    assert_ne!(
        sortition_seed(&parent_a, 7, 0),
        sortition_seed(&parent_c, 7, 0),
        "a single flipped bit of the parent must change the seed"
    );

    // And the same parent yields the same committee everywhere (the
    // agreement requirement): two nodes that pass the same parent hash
    // elect exactly the same committee.
    assert_eq!(
        derive_sortition_committee(&vs, 7, 0, 8, &parent_a),
        derive_sortition_committee(&vs, 7, 0, 8, &parent_a),
    );
}

/// BEACON DRAW (gated OFF): determinism — identical inputs elect the
/// identical committee, and the activation gate is closed at every
/// reachable height.
#[test]
fn test_beacon_draw_committee_is_deterministic_and_gated_off() {
    let mut vs = ValidatorSet::new();
    for i in 0..16u8 {
        vs.add([i + 1; 32], 10);
    }
    let beacon = [0xBBu8; 32];
    // Height 7 is in epoch 0 (7 / 128 == 0).
    let a = beacon_draw_committee(&vs, 7, 0, 8, &beacon, 0);
    let b = beacon_draw_committee(&vs, 7, 0, 8, &beacon, 0);
    assert_eq!(a, b, "beacon draw must be strictly deterministic");
    assert_eq!(a.len(), 8);

    // Gated OFF: the activation height is the never-value, so the live
    // default stays the parent-hash draw at every reachable height.
    assert_eq!(BEACON_DRAW_ACTIVATION_HEIGHT, u64::MAX);
    assert!(!beacon_draw_active_at(0));
    assert!(!beacon_draw_active_at(1));
    assert!(!beacon_draw_active_at(u64::MAX - 1));
}

/// BEACON DRAW epoch binding: a beacon from the wrong epoch is REFUSED
/// (empty committee — elects nobody, reaches no quorum); the height's own
/// epoch draws normally.
#[test]
fn test_beacon_draw_committee_refuses_a_wrong_epoch() {
    let mut vs = ValidatorSet::new();
    for i in 0..16u8 {
        vs.add([i + 1; 32], 10);
    }
    let beacon = [0xBBu8; 32];
    // Height 7 -> epoch 0: epoch 0 draws, epoch 1 refuses.
    assert_eq!(crate::mev_epoch::epoch_of_height(7), 0);
    assert_eq!(beacon_draw_committee(&vs, 7, 0, 8, &beacon, 0).len(), 8);
    assert!(
        beacon_draw_committee(&vs, 7, 0, 8, &beacon, 1).is_empty(),
        "a beacon from epoch 1 must not elect any committee at an epoch-0 height"
    );
    // Height 128 -> epoch 1: the binding moves with the height.
    assert_eq!(crate::mev_epoch::epoch_of_height(128), 1);
    assert_eq!(beacon_draw_committee(&vs, 128, 0, 8, &beacon, 1).len(), 8);
    assert!(
        beacon_draw_committee(&vs, 128, 0, 8, &beacon, 0).is_empty(),
        "a beacon from epoch 0 must not elect any committee at an epoch-1 height"
    );
    // The epoch is bound into the seed itself: same beacon bytes, same
    // height-shape, different epoch -> different seed.
    assert_ne!(
        beacon_seed(&beacon, 0, 7, 0),
        beacon_seed(&beacon, 1, 7, 0),
        "the beacon seed must commit to the epoch"
    );
}

/// BEACON DRAW distribution sanity: stake-weighted without replacement —
/// a 90% whale wins ~90% of single-seat draws, and the beacon (not the
/// parent hash) moves the committee.
#[test]
fn test_beacon_draw_committee_is_stake_weighted_and_beacon_sourced() {
    let mut vs = ValidatorSet::new();
    let id_a = [0x01; 32];
    let id_b = [0x02; 32];
    let id_c = [0x03; 32];
    let id_d = [0x04; 32];
    vs.add(id_a, 900);
    vs.add(id_b, 33);
    vs.add(id_c, 33);
    vs.add(id_d, 34);

    let beacon = [0xBBu8; 32];
    let mut a_selected_count = 0;
    let trials = 100u64;
    // Heights 1..=100 are all epoch 0, so one epoch-0 beacon covers them.
    for h in 1..=trials {
        let comm = beacon_draw_committee(&vs, h, 0, 1, &beacon, 0);
        assert_eq!(comm.len(), 1);
        if comm[0] == id_a {
            a_selected_count += 1;
        }
    }
    assert!(
        a_selected_count >= 80,
        "validator with 90% stake should win beacon sortition >= 80% of trials, got {a_selected_count}"
    );

    // Beacon-sourced: same height/round, different beacon -> a different
    // committee for at least one of many rounds (16 equal stakes, 8 seats).
    let mut vs16 = ValidatorSet::new();
    for i in 0..16u8 {
        vs16.add([i + 1; 32], 10);
    }
    let beacon_b = [0xCCu8; 32];
    let mut differs = false;
    for round in 0..32u32 {
        let a = beacon_draw_committee(&vs16, 7, round, 8, &beacon, 0);
        let b = beacon_draw_committee(&vs16, 7, round, 8, &beacon_b, 0);
        assert_eq!(a.len(), 8);
        assert_eq!(b.len(), 8);
        if a != b {
            differs = true;
            break;
        }
    }
    assert!(
        differs,
        "changing the beacon output must change the elected committee"
    );

    // Edge cases mirror the parent-hash draw: empty set / zero target /
    // oversize target behave identically.
    let empty_vs = ValidatorSet::new();
    assert!(beacon_draw_committee(&empty_vs, 1, 0, 16, &beacon, 0).is_empty());
    assert!(beacon_draw_committee(&vs, 1, 0, 0, &beacon, 0).is_empty());
    assert_eq!(beacon_draw_committee(&vs, 1, 0, 100, &beacon, 0).len(), 4);
}

/// CROSS-CHAIN REPLAY: a vote signed on one chain id must not verify on
/// another, even with the very same validator key.
#[test]
fn test_vote_signature_is_bound_to_chain_id() {
    const TESTNET: u64 = 999_001;
    const MAINNET: u64 = 5757;

    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let fk = FalconKeypair::generate_from_seed(0x77);
    let id = key.verifying_key().to_bytes();
    register_validator_pq_key(
        id,
        crate::post_quantum::PqScheme::Falcon512,
        fk.public_key.clone(),
    );
    let height: Height = 42;
    let round: Round = 3;
    let kind = VoteKind::Prevote;
    let target = Some([0xAB; 32]);

    // Sign on the TESTNET (FULL-PQ: Falcon-signed vote).
    set_consensus_chain_id_for_tests(TESTNET);
    let vote = Vote::sign_with_falcon(&key, &fk, height, round, kind, target);
    assert!(
        vote.verify(),
        "the vote must verify on the chain it was signed for"
    );
    let testnet_bytes = vote_sign_bytes(height, round, kind, &target);
    assert!(
        testnet_bytes.windows(8).any(|w| w == TESTNET.to_be_bytes()),
        "the vote preimage must commit to the chain id"
    );

    // The same vote, verified on the MAINNET, must be REJECTED.
    set_consensus_chain_id_for_tests(MAINNET);
    let mainnet_bytes = vote_sign_bytes(height, round, kind, &target);
    assert_ne!(
        testnet_bytes, mainnet_bytes,
        "the preimage must differ across chain ids"
    );
    assert!(
        !vote.verify(),
        "a testnet vote must NOT verify under a different chain id"
    );

    // ... and the chain id is the ONLY thing that changed.
    set_consensus_chain_id_for_tests(TESTNET);
    assert!(vote.verify(), "the vote verifies again on its own chain");

    // Restore the frozen default for the rest of this thread.
    set_consensus_chain_id_for_tests(0);
}

/// The chain id is bound into the vote preimage, so a nil vote and a
/// targeted vote of the same height/round still differ, and neither can be
/// replayed on another chain.
#[test]
fn test_vote_preimage_commits_to_chain_id_and_fields() {
    let a = vote_sign_bytes(1, 2, VoteKind::Prevote, &Some([0x11; 32]));
    let b = vote_sign_bytes(1, 2, VoteKind::Precommit, &Some([0x11; 32]));
    let c = vote_sign_bytes(1, 2, VoteKind::Prevote, &None);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);

    // Domain separation: the preimage starts with the vote domain tag.
    assert!(a.starts_with(b"STELLEREUM_BFT_VOTE_V2"));
    // ... followed by the chain id.
    let tag_len = b"STELLEREUM_BFT_VOTE_V2".len();
    let chain = crate::consensus::consensus_chain_id().to_be_bytes();
    assert!(
        a[tag_len..tag_len + 8] == chain,
        "the chain id must follow the domain tag"
    );
}

#[test]
fn test_uqc_encoding_decoding_and_verification_16_falcon() {
    let mut vs = ValidatorSet::new();
    let mut falcon_keys = Vec::new();

    // Register 20 validators with Falcon-512 keys
    for i in 0..20u8 {
        let fk = make_sample_falcon512(i + 10);
        let pk = fk.public_key().to_vec();
        let id = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        );
        vs.add(id, 10);
        register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk.clone());
        falcon_keys.push((id, fk));
    }

    let height: Height = 42;
    let round: Round = 1;
    // AUDIT W6.5: the committee size is the SHARED production rule, not a
    // literal — a test that hard-codes it drifts from the verifier the
    // moment the rule changes (and then fails for the wrong reason).
    let committee_size: u32 = micro_committee_size(vs.len());
    // The parent block hash the committee is elected with.
    let parent = [0x77; 32];
    let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
    assert_eq!(committee.len(), committee_size as usize);

    let kind = VoteKind::Precommit;
    let block_hash = Some([0xAA; 32]);
    let msg = vote_sign_bytes(height, round, kind, &block_hash);

    // Generate one valid Falcon signature per committee member
    let mut signatures = Vec::new();
    let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
    for (i, val_id) in committee.iter().enumerate() {
        let (_, fk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
        let sig = make_sample_falcon512_sig(fk, &msg);
        signatures.push(sig);
        bitmask[i / 8] |= 1 << (i % 8);
    }

    let uqc = PqMicroCertificate {
        scheme: crate::post_quantum::PqScheme::Falcon512,
        height,
        round,
        committee_size,
        signers_bitmask: bitmask,
        signatures,
        sortition_parent: parent,
    };

    // Test wire encoding & decoding roundtrip
    let payload = encode_pq_micro_envelope(&uqc);
    assert!(payload.starts_with(QC_UQC_MAGIC));
    let decoded = decode_pq_micro_envelope(&payload).expect("decoding µQC envelope must succeed");
    assert_eq!(uqc, decoded);

    // Verify QuorumCertificate with µQC sentinel marker
    let qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, payload)],
    };

    assert!(qc.verify(&vs), "µQC with 16 Falcon signatures must verify");
    assert!(
        qc.verify_unified(&vs),
        "µQC with 16 Falcon signatures must verify under verify_unified"
    );

    // Helper attachment / extraction check
    let mut qc2 = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: Vec::new(),
    };
    qc2.attach_pq_micro_certificate(&uqc);
    assert_eq!(qc2.pq_micro_certificate(), Some(uqc));
    assert!(qc2.verify(&vs));
}

#[test]
fn test_rejection_of_tampered_uqc_signatures_or_sub_quorum_bitmasks() {
    let mut vs = ValidatorSet::new();
    let mut falcon_keys = Vec::new();

    for i in 0..16u8 {
        let fk = make_sample_falcon512(i + 60);
        let pk = fk.public_key().to_vec();
        let id = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        );
        vs.add(id, 10);
        register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk.clone());
        falcon_keys.push((id, fk));
    }

    let height: Height = 100;
    let round: Round = 0;
    let committee_size: u32 = 16;
    let parent = [0x33; 32];
    let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
    let kind = VoteKind::Precommit;
    let block_hash = Some([0x55; 32]);
    let msg = vote_sign_bytes(height, round, kind, &block_hash);

    // 1. Sub-quorum bitmask test: quorum is 11 of 16. Provide only 10 signatures!
    let mut sub_sigs = Vec::new();
    let mut sub_bitmask = vec![0u8; 2];
    for i in 0..10 {
        let val_id = &committee[i];
        let (_, fk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
        let sig = make_sample_falcon512_sig(fk, &msg);
        sub_sigs.push(sig);
        sub_bitmask[i / 8] |= 1 << (i % 8);
    }
    let sub_uqc = PqMicroCertificate {
        scheme: crate::post_quantum::PqScheme::Falcon512,
        height,
        round,
        committee_size,
        signers_bitmask: sub_bitmask,
        signatures: sub_sigs,
        sortition_parent: parent,
    };
    let sub_qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&sub_uqc))],
    };
    assert!(
        !sub_qc.verify(&vs),
        "Sub-quorum (10 of 16) µQC must fail verification"
    );
    assert!(
        !sub_qc.verify_unified(&vs),
        "Sub-quorum must fail under verify_unified"
    );

    // 2. Tampered signature test: 11 valid signers (quorum), but 1 signature corrupted
    let mut quorum_sigs = Vec::new();
    let mut quorum_bitmask = vec![0u8; 2];
    for i in 0..11 {
        let val_id = &committee[i];
        let (_, fk) = falcon_keys.iter().find(|(id, _)| id == val_id).unwrap();
        let sig = make_sample_falcon512_sig(fk, &msg);
        quorum_sigs.push(sig);
        quorum_bitmask[i / 8] |= 1 << (i % 8);
    }
    quorum_sigs[4][50] ^= 0xFF; // Tamper with byte 50 of the 5th signature

    let tampered_uqc = PqMicroCertificate {
        scheme: crate::post_quantum::PqScheme::Falcon512,
        height,
        round,
        committee_size,
        signers_bitmask: quorum_bitmask,
        signatures: quorum_sigs,
        sortition_parent: parent,
    };
    let tampered_qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&tampered_uqc))],
    };
    assert!(
        !tampered_qc.verify(&vs),
        "Tampered signature in µQC must fail verification"
    );

    // 3. Mismatched height / round
    let mut mismatched_uqc = tampered_uqc;
    mismatched_uqc.height = height + 1; // Wrong height
    let mismatched_qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&mismatched_uqc))],
    };
    assert!(
        !mismatched_qc.verify(&vs),
        "Height mismatch between QC and µQC must fail"
    );

    // 4. Corrupted envelope magic
    let mut bad_magic = encode_pq_micro_envelope(&sub_uqc);
    bad_magic[0] ^= 0xFF;
    assert_eq!(decode_pq_micro_envelope(&bad_magic), None);
}

/// AUDIT W6.5 (committee capture) + P1 (quorum intersection) — the pure
/// quorum math.
///
/// The µQC threshold is `max(2/3 of the committee, 2/3 of the NETWORK)`.
/// The second term is what stops a captured committee from finalizing a
/// block: without it, a 16-seat committee of a 100-validator network
/// (holding ~16% of the stake) would accept a certificate worth ~11% of
/// the NETWORK's stake. The old second term (`floor(W/2)+1`) is NOT
/// enough either — see `dual_finality_counterexample_w100_b32` below.
#[test]
fn test_micro_quorum_power_is_anchored_to_the_network() {
    // Committee 640 of a 1000-power network.
    let committee_total = 640u64;
    let network_total = 1000u64;
    // The committee's own 2/3 would be 427 — 43% of the NETWORK.
    assert_eq!(pq_micro_quorum_power(committee_total), 427);
    // The network anchor raises it to the network's 2/3 BFT floor (667).
    // P1: the old strict-majority anchor (501) is UNSAFE — two
    // conflicting 501-certs can share a purely Byzantine intersection
    // (`2·501 − 1000 = 2 ≯ 320`); the floor refuses them both.
    assert_eq!(pq_micro_required_power(committee_total, network_total), 667);
    assert!(
        pq_micro_required_power(committee_total, network_total)
            > pq_micro_quorum_power(committee_total)
    );
    // A committee that IS the whole network keeps the legacy rule
    // (2/3 of the network) — the live N=4 configuration is unchanged.
    assert_eq!(pq_micro_required_power(1000, 1000), 667);
    assert_eq!(pq_micro_required_power(4, 4), 3);
    // Fail-closed: a zero-power committee can never reach quorum.
    assert_eq!(pq_micro_required_power(0, 1000), u64::MAX);
    // The legacy head-count curve is untouched (pinned by the bridge test).
    assert_eq!(pq_micro_quorum_threshold(16), 11);
    // The committee size is the SHARED production rule (cap now 128 for
    // the 2^-40 capture bound — N <= 128 is the whole set).
    assert_eq!(micro_committee_size(4), 4);
    assert_eq!(micro_committee_size(16), 16);
    assert_eq!(micro_committee_size(100), 100);
    assert_eq!(micro_committee_size(10_000), MICRO_COMMITTEE_MAX_SIZE);
}

/// AUDIT W6.5 (committee capture) + P1 (quorum intersection) — end to end.
///
/// A µQC whose committee is a STRICT SUBSET of the validator set (N=190,
/// a 128-seat committee holding ~67% of the stake) must not be accepted on
/// the strength of the committee's own 2/3: the certificate has to carry
/// TWO THIRDS of the WHOLE network's stake (`2t − W > B_w`). This is the
/// property that keeps "an attacker with < 1/3 of the stake cannot
/// finalize a block" true even when the committee is small relative to
/// the network. (N=190, not 100: with the 128-seat cap a 100-member set
/// elects the whole set — the subset shape needs N > cap — and N=190
/// keeps the network floor (1267) just under what the full 128-seat
/// committee can carry (1280), so both the refuse and the accept case
/// are constructible.)
#[test]
fn test_uqc_of_a_subset_committee_must_reach_a_network_majority() {
    const N: usize = 190;
    const POWER: u64 = 10;
    let mut vs = ValidatorSet::new();
    for i in 0..N {
        vs.add([(i % 251 + 1) as u8; 32], POWER);
    }
    let height: Height = 77;
    let round: Round = 0;
    let parent = [0x42; 32];
    let committee_size = micro_committee_size(vs.len());
    assert_eq!(committee_size as usize, MICRO_COMMITTEE_MAX_SIZE as usize);
    let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
    assert_eq!(committee.len(), committee_size as usize);

    let committee_total: u64 = committee.iter().map(|id| vs.power_of(id)).sum();
    let network_total = vs.total_power();
    assert_eq!(network_total, N as u64 * POWER);
    assert_eq!(committee_total, MICRO_COMMITTEE_MAX_SIZE as u64 * POWER);
    // The committee's own 2/3 (854) is BELOW the network anchor (1267).
    let required = pq_micro_required_power(committee_total, network_total);
    assert_eq!(required, consensus_quorum_min(network_total));
    assert_eq!(required, 1267);
    assert!(required > pq_micro_quorum_power(committee_total));
    // 126 members carry 1260 < 1267 power: refused. 127 carry 1270: accepted.
    let sub_quorum_members = required.div_ceil(POWER) as usize - 1;
    assert_eq!(sub_quorum_members, 126);

    let kind = VoteKind::Precommit;
    let block_hash = Some([0x21; 32]);
    let msg = vote_sign_bytes(height, round, kind, &block_hash);

    // Real Falcon keys for the committee members that sign (one distinct
    // seed per committee position — no key reuse across members).
    let mut signers: Vec<(ValidatorId, crate::post_quantum::FalconKeypair)> = Vec::new();
    for (idx, val_id) in committee.iter().take(sub_quorum_members + 1).enumerate() {
        let fk = make_sample_falcon512(0x80u8.wrapping_add((idx % 251) as u8));
        register_validator_pq_key(
            *val_id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key().to_vec(),
        );
        signers.push((*val_id, fk));
    }

    let build_uqc = |n: usize| -> PqMicroCertificate {
        let mut signatures = Vec::with_capacity(n);
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        for (i, val_id) in committee.iter().enumerate().take(n) {
            let (_, fk) = signers.iter().find(|(id, _)| id == val_id).unwrap();
            signatures.push(fk.sign(&msg));
            bitmask[i / 8] |= 1 << (i % 8);
        }
        PqMicroCertificate {
            scheme: crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            signers_bitmask: bitmask,
            signatures,
            sortition_parent: parent,
        }
    };
    let wrap = |uqc: &PqMicroCertificate| QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(uqc))],
    };

    // 126 of 128 committee members: the committee's own 2/3 (854) is met
    // (1260 >= 854) but the NETWORK's two-thirds floor (1267) is not —
    // and the old strict-majority floor (951) WOULD have accepted it:
    // the P1 gap in one inequality.
    let sub = build_uqc(sub_quorum_members);
    let old_floor = network_total / 2 + 1;
    assert_eq!(old_floor, 951);
    assert!(sub.signed_power(&committee, &vs) >= pq_micro_quorum_power(committee_total));
    assert!(sub.signed_power(&committee, &vs) < required);
    assert!(
        sub.signed_power(&committee, &vs) >= old_floor,
        "fixture must sit inside the old vulnerable band (else it proves nothing)"
    );
    assert!(
        !wrap(&sub).verify(&vs),
        "a µQC that clears only the committee's 2/3 must NOT finalize a block"
    );

    // 127 of 128: the network's two-thirds floor is reached -> accepted,
    // and the full-quorum gate agrees (item 3: verify subsumes it now).
    let ok = build_uqc(sub_quorum_members + 1);
    assert!(ok.signed_power(&committee, &vs) >= required);
    assert!(
        wrap(&ok).verify(&vs),
        "a µQC carrying TWO THIRDS of the NETWORK's stake must verify"
    );
    assert!(
        vs.qc_meets_quorum(&wrap(&ok)),
        "an accepted µQC-alone cert carries full-quorum power (no second gate needed)"
    );
    assert!(
        !vs.qc_meets_quorum(&wrap(&sub)),
        "the refused sub-floor cert carries no full-quorum power either"
    );
}

/// P1 (Theorems 1+4) — the dual-finality counterexample, pinned live.
///
/// Paper `papers/01_quorum.md` §4 Thm. 3 + `results/q_quorum.json →
/// weighted.explicit_attack`: with `W = 100, B = 32` the OLD floor
/// `t = floor(W/2)+1 = 51` admits TWO conflicting certificates
/// (32 Byzantine + 19 honest each, all-Byzantine intersection of weight
/// 32), because `2·51 − 100 = 2 ≯ 32`. The theorem `2t − W > B_w` is
/// pinned in-test in BOTH directions; the live half of the test scales
/// it by 10 (POWER=10: `W = 1000, B_w = 320, t_old = 501, t_new = 667`)
/// and proves with REAL Falcon signatures that the new floor refuses
/// both conflicting certs while a 67-signer cert still verifies.
/// Old-floor acceptance is constructible only as threshold arithmetic
/// (the vulnerable code path is gone) — asserted, not executed.
#[test]
#[allow(clippy::assertions_on_constants)]
// GATE: the pinned paper arithmetic 2·51−100=2 / 2·67−100=34 is
// intentionally constant — the test's job is to pin Theorem 1 in both
// directions, and rewriting it through runtime values would unpin it.
fn dual_finality_counterexample_w100_b32() {
    // --- Paper-unit pins (Theorem 1, both directions) ---
    let (w, b, t_old, t_new) = (100u64, 32u64, 51u64, 67u64);
    assert_eq!(t_old, w / 2 + 1, "old floor: strict majority");
    assert_eq!(t_new, consensus_quorum_min(w), "new floor: BFT 2/3");
    assert!(
        2 * t_old - w <= b,
        "2·51−100 = 2 ≯ 32: old floor UNSAFE (dual finality possible)"
    );
    assert!(2 * t_new - w > b, "2·67−100 = 34 > 32: new floor safe");
    // Cross-tier form of the same pins (Cor. 3): an old-µQC/new-full pair
    // shares only 18 guaranteed weight (≤ 33 = B allowance) — attackable;
    // two new-floor certs share 34 — safe.
    assert!(!mixed_quorum_pair_safe(t_old, t_new, w));
    assert!(mixed_quorum_pair_safe(t_new, t_new, w));

    // --- Live scaled replica: N=100 uniform ×10 (whole-set committee) ---
    const N: usize = 100;
    const POWER: u64 = 10;
    const NW: u64 = 1000; // N * POWER
    const BW: u64 = 320; // 32 "byzantine" members × POWER
    let mut vs = ValidatorSet::new();
    for i in 0..N {
        // 0xE5-domain ids: disjoint from every other test's id space, so
        // the global PQ-key registry cannot alias across parallel tests.
        let mut id = [0xE5; 32];
        id[0] = (i & 0xFF) as u8;
        id[1] = ((i >> 8) & 0xFF) as u8;
        id[2] = 0xE5;
        vs.add(id, POWER);
    }
    assert_eq!(vs.total_power(), NW);
    let height: Height = 101;
    let round: Round = 0;
    let parent = [0x43; 32];
    let committee_size = micro_committee_size(vs.len());
    assert_eq!(committee_size as usize, N, "N <= cap: whole-set committee");
    let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
    assert_eq!(committee.len(), N);

    // Threshold pins at live scale.
    assert_eq!(consensus_quorum_min(NW), 667);
    assert_eq!(pq_micro_required_power(NW, NW), 667);
    let old_floor = NW / 2 + 1;
    assert_eq!(old_floor, 501);
    assert_eq!(2 * old_floor - NW, 2, "old floor guarantees 2 weight");
    assert!(2 * old_floor - NW <= BW, "2 ≯ 320: old floor unsafe");
    assert!(2 * 667 - NW > BW, "334 > 320: new floor safe");

    // 32 shared "byzantine" + 19 distinct honest per conflicting cert.
    let byz: Vec<ValidatorId> = committee.iter().take(32).copied().collect();
    let honest_a: Vec<ValidatorId> = committee.iter().skip(32).take(19).copied().collect();
    let honest_b: Vec<ValidatorId> = committee.iter().skip(32 + 19).take(19).copied().collect();
    assert_eq!(honest_a.len(), 19);
    assert_eq!(honest_b.len(), 19);

    // Real Falcon keys for all 70 signers (distinct seed per member).
    let mut fks: Vec<(ValidatorId, crate::post_quantum::FalconKeypair)> = Vec::new();
    for (idx, val_id) in byz
        .iter()
        .chain(honest_a.iter())
        .chain(honest_b.iter())
        .enumerate()
    {
        let fk = make_sample_falcon512(0x11u8.wrapping_add((idx % 251) as u8));
        register_validator_pq_key(
            *val_id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key().to_vec(),
        );
        fks.push((*val_id, fk));
    }
    let sign_for = |members: &[ValidatorId],
                    block: [u8; 32],
                    fks: &[(ValidatorId, crate::post_quantum::FalconKeypair)]|
     -> QuorumCertificate {
        let msg = vote_sign_bytes(height, round, VoteKind::Precommit, &Some(block));
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        let mut sigs = Vec::new();
        for (i, val_id) in committee.iter().enumerate() {
            if members.contains(val_id) {
                let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
                sigs.push(fk.sign(&msg));
                bitmask[i / 8] |= 1 << (i % 8);
            }
        }
        let uqc = PqMicroCertificate {
            scheme: crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            signers_bitmask: bitmask,
            signatures: sigs,
            sortition_parent: parent,
        };
        QuorumCertificate {
            height,
            round,
            kind: VoteKind::Precommit,
            block_hash: Some(block),
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
        }
    };

    let mut members_a = byz.clone();
    members_a.extend(honest_a.iter().copied());
    let mut members_b = byz.clone();
    members_b.extend(honest_b.iter().copied());
    let qc_a = sign_for(&members_a, [0xA1; 32], &fks);
    let qc_b = sign_for(&members_b, [0xB2; 32], &fks);

    // Both carry 510 power: the OLD floor (501) accepts each of them —
    // dual finality under the old rule, constructible here as the exact
    // arithmetic the old code evaluated.
    for qc in [&qc_a, &qc_b] {
        let power = vs.qc_signed_power(qc);
        assert_eq!(power, 510);
        assert!(
            power >= old_floor,
            "old floor accepts this conflicting cert (501 ≤ 510)"
        );
        // ...while the honest signer sets are disjoint by construction
        // (intersection = the 32 shared Byzantine), and the new floor
        // refuses both.
        assert!(
            !qc.verify(&vs),
            "new floor (667) MUST refuse a 510-power conflicting cert"
        );
        assert!(
            !vs.qc_meets_quorum(qc),
            "no full-quorum power either (510 < 667)"
        );
    }
    // Safety is preserved, not just refusal: 67 signers (670 ≥ 667) verify.
    let members_ok: Vec<ValidatorId> = committee.iter().take(67).copied().collect();
    for (idx, val_id) in members_ok.iter().enumerate() {
        if fks.iter().all(|(id, _)| id != val_id) {
            let fk = make_sample_falcon512(0xC0u8.wrapping_add((idx % 200) as u8));
            register_validator_pq_key(
                *val_id,
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key().to_vec(),
            );
            fks.push((*val_id, fk));
        }
    }
    let qc_ok = sign_for(&members_ok, [0xCC; 32], &fks);
    assert!(qc_ok.verify(&vs), "67 of 100 (670 ≥ 667) must verify");
    assert!(vs.qc_meets_quorum(&qc_ok));
}

/// P1 (Corollary 3) — the mixed-pair gate pins.
///
/// `mixed_quorum_pair_safe` is the fail-closed predicate behind the
/// tripwire in `verify_micro_cert`: exact paper numbers
/// (`results/q_quorum.json → weighted.threshold_table`), degenerate
/// inputs refuse, and `u64::MAX` thresholds (the fail-closed sentinel)
/// can never pass.
#[test]
fn mixed_quorum_pair_gate_pins() {
    // Paper mixed pair: q_micro=51, q_full=67, W=100, B=32 →
    // guaranteed cross-intersection 18 ≤ 33: UNSAFE.
    assert!(!mixed_quorum_pair_safe(51, 67, 100));
    // Post-fix: 67 + 67 − 100 = 34 > 33: safe.
    assert!(mixed_quorum_pair_safe(67, 67, 100));
    // Degenerate inputs fail closed.
    assert!(!mixed_quorum_pair_safe(67, 67, 0));
    assert!(!mixed_quorum_pair_safe(u64::MAX, 67, 100));
    assert!(!mixed_quorum_pair_safe(67, u64::MAX, 100));
    // Live whole-set shape: the two live thresholds always pair safe
    // (this is why the tripwire in `verify_micro_cert` is behavior-
    // identical on the current topology — it can only fire if a future
    // edit breaks the floor).
    for w in [1u64, 2, 3, 4, 5, 6, 7, 8, 100, 1000, 1900, 2000] {
        let t = consensus_quorum_min(w);
        assert!(
            mixed_quorum_pair_safe(t, t, w),
            "live pair ({t}, {t}, {w}) must be safe"
        );
    }
}

/// Item 3 — the µQC-alone gate, proved instead of changed.
///
/// `verify_unified` (≈2528) DOES accept a µQC alone — that is the fast
/// path by design. The full-2/3 QC requirement lives one layer up and is
/// already enforced twice: [`ValidatorSet::qc_meets_quorum`] (≈1088,
/// same-set power ≥ `quorum_power()`) and the LOUD commit-path refusal in
/// `runtime.rs` (≈7707: `signed < required` → error + metric, never
/// adopt). Post-fix the two gates coincide on every topology: any
/// verifying µQC carries ≥ `pq_micro_required_power` ≥ `quorum_power()`,
/// so `verify ⇒ meets_quorum` and no second check can disagree.
/// This test pins that agreement on the LIVE shape (N=4, whole-set
/// committee — the topology the fleet runs): 2-of-4 fails both gates,
/// 3-of-4 passes both. Behavior-identical proof for the live network.
#[test]
fn micro_qc_alone_gate_agrees_with_full_quorum_on_live_shape() {
    let mut vs = ValidatorSet::new();
    let mut fks = Vec::new();
    for i in 0..4u8 {
        let mut id = [0xE1; 32];
        id[0] = i;
        let fk = make_sample_falcon512(0x30 + i);
        register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key().to_vec(),
        );
        vs.add(id, 1);
        fks.push((id, fk));
    }
    let height: Height = 7;
    let round: Round = 0;
    let parent = [0x44; 32];
    let committee_size = micro_committee_size(vs.len());
    assert_eq!(committee_size, 4);
    let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
    assert_eq!(committee.len(), 4);
    let build = |n: usize| -> QuorumCertificate {
        let block = [0xBB; 32];
        let msg = vote_sign_bytes(height, round, VoteKind::Precommit, &Some(block));
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        let mut sigs = Vec::new();
        for (i, val_id) in committee.iter().enumerate().take(n) {
            let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
            sigs.push(fk.sign(&msg));
            bitmask[i / 8] |= 1 << (i % 8);
        }
        let uqc = PqMicroCertificate {
            scheme: crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            signers_bitmask: bitmask,
            signatures: sigs,
            sortition_parent: parent,
        };
        QuorumCertificate {
            height,
            round,
            kind: VoteKind::Precommit,
            block_hash: Some(block),
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
        }
    };
    // 2-of-4: below every floor — both gates refuse, identically.
    let sub = build(2);
    assert!(!sub.verify(&vs), "2-of-4 µQC must not verify");
    assert!(
        !vs.qc_meets_quorum(&sub),
        "2-of-4 carries no full-quorum power"
    );
    // 3-of-4: the live quorum — both gates accept, identically.
    let ok = build(3);
    assert!(ok.verify(&vs), "3-of-4 µQC must verify (live pin)");
    assert!(vs.qc_meets_quorum(&ok), "3-of-4 carries full-quorum power");
}

/// C1 split (FIXES §1.7, sketch §4.1, formulas §2.3) — threshold math pins.
///
/// * `pq_micro_advisory_power(W_c) = floor(2W_c/3)+1` — advisory, NEVER
///   finality;
/// * `pq_full_required_power(W_n) = floor(2W_n/3)+1` — the finality gate;
/// * the split is height-gated and INACTIVE by default
///   (`QC_SPLIT_ACTIVATION_HEIGHT = u64::MAX`, flipped only by the lead);
/// * the liveness trap the split removes: a small committee reaches its
///   advisory threshold but can never reach `max(committee, network)` —
///   so `max` must not serve as the finality bar.
#[test]
#[allow(clippy::assertions_on_constants)]
// GATE: the pinned values ARE the spec (formulas §2.3, inactive default);
// rewriting them through runtime values would unpin the test's job.
fn qc_split_threshold_math_pins() {
    // Sketch §4.1 shapes.
    assert_eq!(pq_micro_advisory_power(1000), 667);
    assert_eq!(pq_full_required_power(1000), 667);
    assert_eq!(pq_micro_advisory_power(640), 427);
    // Fail-closed on zero power, like `quorum_power` / `pq_micro_quorum_power`.
    assert_eq!(pq_micro_advisory_power(0), u64::MAX);
    assert_eq!(pq_full_required_power(0), u64::MAX);
    // Legacy `max` rule preserved pre-activation (byte-identical behavior).
    assert_eq!(pq_micro_required_power(640, 1000), 667);
    assert_eq!(pq_micro_required_power(1000, 1000), 667);
    assert_eq!(pq_micro_required_power(0, 1000), u64::MAX);
    // The liveness trap (FIXES §1.7): committee 640 of network 1000 —
    // advisory (427) is reachable by the committee alone, the full gate
    // (667) is NOT, so `max` (= 667) as a finality bar strands the µQC.
    assert!(pq_micro_advisory_power(640) <= 640, "advisory reachable");
    assert!(
        pq_full_required_power(1000) > 640,
        "full gate unreachable alone"
    );
    // Inactive default: only `u64::MAX` itself counts as active.
    assert_eq!(QC_SPLIT_ACTIVATION_HEIGHT, u64::MAX);
    assert!(!qc_split_active_at(0));
    assert!(!qc_split_active_at(u64::MAX - 1));
    assert!(qc_split_active_at(u64::MAX));
    assert!(qc_split_active_at(QC_SPLIT_ACTIVATION_HEIGHT));
}

/// C1 split — advisory ≠ finality, end to end with real Falcon signatures.
///
/// N=4 whole-set committee. Post-activation height (the inactive-default
/// gate itself, `u64::MAX`):
/// * a 3-of-4 µQC MEETS the advisory threshold yet `verify`/`verify_unified`
///   REFUSE it — µQC-alone never finalizes post-activation;
/// * the same-strength epoch/CEC (full-set envelope) VERIFIES — the full
///   network QC (`quorum_power() == pq_full_required_power(total)`)
///   finalizes;
/// * pre-activation control: the identical µQC at a small height verifies
///   (legacy `max` rule, byte-identical — existing pins unmodified);
/// * the W=100/B=32 counterexample pair still refuses (the
///   `mixed_quorum_pair_safe` tripwire is untouched).
#[test]
fn qc_split_post_activation_micro_alone_never_finalizes() {
    // Fresh id domain (0x9C): the PQ-key registry is global, so parallel
    // tests must not share ids with different keys.
    let mut vs = ValidatorSet::new();
    let mut fks = Vec::new();
    for i in 0..4u8 {
        let mut id = [0x9Cu8; 32];
        id[0] = i;
        let fk = make_sample_falcon512(0x70 + i);
        register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key().to_vec(),
        );
        vs.add(id, 1);
        fks.push((id, fk));
    }
    assert_eq!(vs.total_power(), 4);
    assert_eq!(vs.quorum_power(), pq_full_required_power(vs.total_power()));
    assert_eq!(vs.quorum_power(), 3);

    const PRE: Height = 7;
    const POST: Height = QC_SPLIT_ACTIVATION_HEIGHT;
    let round: Round = 0;
    let kind = VoteKind::Precommit;
    let block = [0xBBu8; 32];
    let committee_size = micro_committee_size(vs.len());
    assert_eq!(committee_size, 4);

    // Build a 3-of-4 µQC at `height` (first 3 committee members sign).
    let build_micro = |height: Height, parent: [u8; 32]| -> QuorumCertificate {
        let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
        assert_eq!(committee.len(), 4);
        let msg = vote_sign_bytes(height, round, kind, &Some(block));
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        let mut sigs = Vec::new();
        for (i, val_id) in committee.iter().enumerate().take(3) {
            let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
            sigs.push(fk.sign(&msg));
            bitmask[i / 8] |= 1 << (i % 8);
        }
        let committee_total: u64 = committee.iter().map(|id| vs.power_of(id)).sum();
        assert_eq!(
            sigs.len(),
            3,
            "fixture must carry advisory power before proving refusal"
        );
        let signed: u64 = 3; // power 1 each
        assert!(signed >= pq_micro_advisory_power(committee_total));
        let uqc = PqMicroCertificate {
            scheme: crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            signers_bitmask: bitmask,
            signatures: sigs,
            sortition_parent: parent,
        };
        QuorumCertificate {
            height,
            round,
            kind,
            block_hash: Some(block),
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
        }
    };
    // Build the same-strength full-set epoch/CEC cert at `height`.
    let build_full = |height: Height| -> QuorumCertificate {
        let mut ids: Vec<ValidatorId> = vs.validators.keys().copied().collect();
        ids.sort_unstable();
        let msg = vote_sign_bytes(height, round, kind, &Some(block));
        let mut bitmask = vec![0u8; ids.len().div_ceil(8)];
        let mut sigs = Vec::new();
        for (i, val_id) in ids.iter().enumerate().take(3) {
            let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
            sigs.push(fk.sign(&msg));
            bitmask[i / 8] |= 1 << (i % 8);
        }
        let cec = PqMicroCertificate {
            scheme: crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size: ids.len() as u32,
            signers_bitmask: bitmask,
            signatures: sigs,
            sortition_parent: [0u8; 32],
        };
        QuorumCertificate {
            height,
            round,
            kind,
            block_hash: Some(block),
            signatures: vec![(PQ_QC_MARKER_ID, encode_pq_epoch_envelope(&cec))],
        }
    };

    // Pre-activation control: legacy `max` rule — 3-of-4 verifies.
    let pre = build_micro(PRE, [0xC7; 32]);
    assert!(
        pre.verify(&vs),
        "pre-activation µQC must verify (legacy pin)"
    );
    assert!(pre.verify_unified(&vs));

    // Post-activation: advisory met, finality REFUSED for µQC-alone.
    let post = build_micro(POST, [0xC8; 32]);
    assert!(
        !post.verify(&vs),
        "post-activation µQC-alone must never verify"
    );
    assert!(
        !post.verify_unified(&vs),
        "post-activation µQC-alone must never verify_unified"
    );

    // Post-activation: the full network QC finalizes.
    let full = build_full(POST);
    assert!(full.verify(&vs), "post-activation full QC must verify");
    assert!(full.verify_unified(&vs));
    assert!(vs.qc_meets_quorum(&full));

    // Counterexample W=100/B=32 still refused (tripwire untouched).
    assert!(!mixed_quorum_pair_safe(51, 67, 100));
    assert!(mixed_quorum_pair_safe(67, 67, 100));
}

#[test]
fn test_backward_compatibility_classical_ed25519_qc() {
    // FULL-PQ (nodes wiped, no compat): classical Ed25519 QC legs deleted.
    // An Ed-only QC is REJECTED (fail-closed); a Falcon µQC with the same
    // 3-of-4 quorum shape VERIFIES. Same strength as before (genuine pass,
    // tampered fail), fixtures converted to Falcon/PQ.
    //
    // Part A: Ed-only QC (3 of 4) must now FAIL on both paths.
    let mut vs_ed = ValidatorSet::new();
    let mut ed_signers = Vec::new();
    for _ in 0..4 {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let id = sk.verifying_key().to_bytes();
        vs_ed.add(id, 10);
        ed_signers.push(sk);
    }
    let height = 5;
    let round = 0;
    let kind = VoteKind::Precommit;
    let block_hash = Some([0x12; 32]);
    let msg = vote_sign_bytes(height, round, kind, &block_hash);
    let mut ed_sigs = Vec::new();
    for sk in &ed_signers[0..3] {
        let sig = sk.sign(&msg).to_bytes().to_vec();
        ed_sigs.push((sk.verifying_key().to_bytes(), sig));
    }
    let ed_qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash,
        signatures: ed_sigs,
    };
    assert!(
        !ed_qc.verify(&vs_ed),
        "FULL-PQ: Ed-only QC must be rejected (Ed legs deleted)"
    );
    assert!(
        !ed_qc.verify_unified(&vs_ed),
        "FULL-PQ: Ed-only QC must be rejected on verify_unified"
    );
    assert!(
        ed_qc.signers_set(&vs_ed).is_empty(),
        "FULL-PQ: rejected Ed-only QC attributes nobody"
    );

    // Part B: Falcon µQC with the same 3-of-4 shape VERIFIES.
    let mut vs = ValidatorSet::new();
    let mut fks = Vec::new();
    for i in 0..4u8 {
        let fk = make_sample_falcon512(0xA0 + i);
        let pk = fk.public_key().to_vec();
        let id = crate::post_quantum::derive_pq_address(
            crate::post_quantum::PqScheme::Falcon512,
            &pk,
            &crate::post_quantum::DEFAULT_SALT,
        );
        vs.add(id, 10);
        register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk.clone());
        fks.push((id, fk));
    }
    let committee_size = micro_committee_size(vs.len());
    assert_eq!(committee_size, 4);
    let parent = [0x34; 32];
    let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
    assert_eq!(committee.len(), 4);
    let target = Some([0x12; 32]);
    let qc_msg = vote_sign_bytes(height, round, kind, &target);
    // 3 of 4 committee members sign (exceeds 2/3 power quorum, same shape
    // as the deleted Ed fixture above).
    let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
    let mut msigs = Vec::new();
    for (i, val_id) in committee.iter().enumerate().take(3) {
        bitmask[i / 8] |= 1 << (i % 8);
        let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
        msigs.push(make_sample_falcon512_sig(fk, &qc_msg));
    }
    let uqc = PqMicroCertificate::new(
        crate::post_quantum::PqScheme::Falcon512,
        height,
        round,
        committee_size,
        bitmask,
        msigs,
        parent,
    );
    let qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash: target,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
    };
    assert!(qc.verify(&vs), "Falcon µQC 3-of-4 must verify");
    assert!(
        qc.verify_unified(&vs),
        "Falcon µQC 3-of-4 must verify with verify_unified"
    );

    // Tamper with one Falcon signature: surviving power below quorum,
    // verification fails (same tamper shape as the deleted Ed fixture).
    let mut bad_sigs = uqc.signatures.clone();
    bad_sigs[0][10] ^= 0xFF;
    let bad_uqc = PqMicroCertificate::new(
        crate::post_quantum::PqScheme::Falcon512,
        height,
        round,
        committee_size,
        uqc.signers_bitmask.clone(),
        bad_sigs,
        parent,
    );
    let tampered_qc = QuorumCertificate {
        height,
        round,
        kind,
        block_hash: target,
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&bad_uqc))],
    };
    assert!(
        !tampered_qc.verify(&vs),
        "Tampered Falcon µQC must fail verification"
    );
}

#[test]
fn test_voteset_certificate_automatically_compiles_uqc_and_verifies_unified() {
    let mut vs = ValidatorSet::new();
    let mut signers = Vec::new();
    let mut falcon_keys = Vec::new();

    // Register 16 validators with Falcon-512 keys
    for i in 0..16u8 {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let id = sk.verifying_key().to_bytes();
        let fk = FalconKeypair::generate_from_seed(i + 1);
        vs.add(id, 10);
        register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        signers.push((sk, id));
        falcon_keys.push(fk);
    }

    let height: Height = 50;
    let round: Round = 0;
    let kind = VoteKind::Precommit;
    let block_hash = Some([0x77; 32]);

    let mut vote_set = VoteSet::new();

    // All 16 validators cast votes signed with Falcon keys
    for i in 0..16 {
        let (ref sk, _) = signers[i];
        let fk = &falcon_keys[i];
        let vote = Vote::sign_with_falcon(sk, fk, height, round, kind, block_hash);
        assert!(vote.falcon_signature().is_some());
        assert!(vote_set.add(vote, &vs, height, round, kind).is_ok());
    }

    assert_eq!(vote_set.falcon_votes_count(), 16);
    let collected = vote_set.collect_falcon_signatures(block_hash);
    assert_eq!(collected.len(), 16);

    // Certificate compilation must automatically compile the PqMicroCertificate
    // and attach PQ_UQC_MARKER_ID
    let parent = [0x44; 32];
    let qc = vote_set
        .certificate(block_hash, &vs, &parent)
        .expect("certificate must form");
    assert!(
        qc.signatures
            .iter()
            .any(|(voter, _)| *voter == PQ_UQC_MARKER_ID),
        "compiled QC must carry PQ_UQC_MARKER_ID sentinel marker"
    );

    let uqc = qc
        .pq_micro_certificate()
        .expect("micro-QC must be retrievable");
    assert_eq!(uqc.scheme, crate::post_quantum::PqScheme::Falcon512);
    assert_eq!(uqc.height, height);
    assert_eq!(uqc.round, round);
    assert_eq!(uqc.committee_size, 16);
    assert_eq!(uqc.signatures.len(), 16);

    // Verification under QuorumCertificate::verify_unified
    assert!(
        qc.verify_unified(&vs),
        "micro-QC must verify under verify_unified"
    );
    assert!(qc.verify(&vs), "micro-QC must verify under verify");

    // Verify that under Pure Post-Quantum Mode, the QC verifies via the µQC path
    crate::post_quantum::set_pure_pq_override(Some(true));
    assert!(
        qc.verify_unified(&vs),
        "micro-QC must verify under Pure PQ mode"
    );
    crate::post_quantum::set_pure_pq_override(None);
}

#[test]
fn test_height_consensus_tracks_and_collects_falcon_signatures() {
    let mut vs = ValidatorSet::new();
    let mut signers = Vec::new();
    let mut falcon_keys = Vec::new();

    for i in 0..16u8 {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let id = sk.verifying_key().to_bytes();
        let fk = FalconKeypair::generate_from_seed(i + 20);
        vs.add(id, 10);
        register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        signers.push((sk, id));
        falcon_keys.push(fk);
    }

    let height: Height = 10;
    let mut hc = HeightConsensus::new(height, vs.clone());
    // The sortition committee is elected from the PARENT block hash: the
    // node must know it before it can compile a micro-certificate (an
    // unknown parent compiles none — fail closed, see `VoteSet::certificate`).
    hc.set_parent_hash([0xA5; 32]);
    let block_hash = [0xBB; 32];
    let proposer = hc.proposer().unwrap();

    // 1. Propose
    assert!(hc.receive_proposal(proposer, block_hash).is_ok());

    // 2. Prevote with Falcon signatures
    for i in 0..16 {
        let (ref sk, _) = signers[i];
        let fk = &falcon_keys[i];
        let vote = Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Prevote, Some(block_hash));
        assert!(hc.add_prevote(vote).is_ok());
    }

    assert_eq!(hc.falcon_votes_count(0, VoteKind::Prevote), 16);
    let falcon_prevotes = hc.collect_falcon_signatures(0, VoteKind::Prevote, Some(block_hash));
    assert_eq!(falcon_prevotes.len(), 16);

    let polka = hc.try_prevote_quorum_at().expect("polka must form");
    assert_eq!(polka, (0, Some(block_hash)));
    let prevote_qc = hc.prevote_qc.get(&0).expect("prevote QC must exist");
    assert!(prevote_qc
        .signatures
        .iter()
        .any(|(v, _)| *v == PQ_UQC_MARKER_ID));
    assert!(prevote_qc.verify_unified(&vs));

    // 3. Precommit with Falcon signatures
    for i in 0..16 {
        let (ref sk, _) = signers[i];
        let fk = &falcon_keys[i];
        let vote = Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Precommit, Some(block_hash));
        assert!(hc.add_precommit(vote).is_ok());
    }

    assert_eq!(hc.falcon_votes_count(0, VoteKind::Precommit), 16);
    let decided = hc
        .try_precommit_quorum()
        .expect("precommit quorum must decide");
    assert_eq!(decided, block_hash);
    let precommit_qc = hc.precommit_qc.as_ref().expect("precommit QC must exist");
    assert!(precommit_qc
        .signatures
        .iter()
        .any(|(v, _)| *v == PQ_UQC_MARKER_ID));
    assert!(precommit_qc.verify_unified(&vs));
}

#[test]
fn test_multi_validator_cluster_falcon_votes_compile_uqc_and_decide_block() {
    let mut vs = ValidatorSet::new();
    let mut signers = Vec::new();
    let mut falcon_keys = Vec::new();

    for i in 0..16u8 {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let id = sk.verifying_key().to_bytes();
        let fk = FalconKeypair::generate_from_seed(i + 1);
        vs.add(id, 10);
        register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        signers.push((sk, id));
        falcon_keys.push(fk);
    }

    let height: Height = 100;
    let mut hc = HeightConsensus::new(height, vs.clone());
    // The sortition parent must be known before a micro-certificate can
    // be compiled (see `VoteSet::certificate`).
    hc.set_parent_hash([0xC7; 32]);
    let block_hash = [0x5A; 32];
    let proposer = hc.proposer().expect("proposer must be selected");

    // Verify proposal
    assert!(hc.receive_proposal(proposer, block_hash).is_ok());

    // Cast Falcon-512 prevotes
    for i in 0..16 {
        let (ref sk, _) = signers[i];
        let fk = &falcon_keys[i];
        let prevote =
            Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Prevote, Some(block_hash));
        assert!(prevote.verify());
        assert!(hc.add_prevote(prevote).is_ok());
    }

    let polka = hc.try_prevote_quorum_at().expect("polka must form");
    assert_eq!(polka, (0, Some(block_hash)));
    let prevote_qc = hc.prevote_qc.get(&0).expect("prevote QC must exist");
    assert!(
        prevote_qc
            .signatures
            .iter()
            .any(|(v, _)| *v == PQ_UQC_MARKER_ID),
        "prevote QC must contain PQ_UQC_MARKER_ID"
    );
    assert!(prevote_qc.verify_unified(&vs));

    // Cast Falcon-512 precommits
    for i in 0..16 {
        let (ref sk, _) = signers[i];
        let fk = &falcon_keys[i];
        let precommit =
            Vote::sign_with_falcon(sk, fk, height, 0, VoteKind::Precommit, Some(block_hash));
        assert!(precommit.verify());
        assert!(hc.add_precommit(precommit).is_ok());
    }

    let decided = hc
        .try_precommit_quorum()
        .expect("precommit quorum must decide");
    assert_eq!(decided, block_hash);
    let precommit_qc = hc.precommit_qc.as_ref().expect("precommit QC must exist");
    assert!(
        precommit_qc
            .signatures
            .iter()
            .any(|(v, _)| *v == PQ_UQC_MARKER_ID),
        "precommit QC must contain PQ_UQC_MARKER_ID"
    );
    assert!(precommit_qc.verify_unified(&vs));
    assert!(precommit_qc.verify(&vs));

    let signers_set = precommit_qc.signers_set(&vs);
    assert_eq!(signers_set.len(), 16);
    for (_, id) in &signers {
        assert!(signers_set.contains(id));
    }
}

#[test]
fn test_signers_set_extraction_falcon_uqc_and_classical() {
    // Real keys throughout: attribution mirrors verification (V-P34 R2),
    // so every attributed signer must carry a verifying signature and
    // every unverifiable entry attributes nobody.
    let mut vs = ValidatorSet::new();
    let mut sks = Vec::new();
    let mut fks = Vec::new();
    for i in 0u8..3 {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let id = sk.verifying_key().to_bytes();
        let fk = FalconKeypair::generate_from_seed(0xC0 + i);
        vs.add(id, 100);
        register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        sks.push(sk);
        fks.push(fk);
    }
    let ids: Vec<ValidatorId> = sks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let target = [0xAA; 32];

    // 1. Classical signatures: FULL-PQ deletes the Ed threshold, so a
    // genuine Ed quorum is REJECTED and attributes nobody (fail-closed);
    // a forged entry in a REJECTED certificate attributes nobody.
    let genuine: Vec<(ValidatorId, Vec<u8>)> = sks
        .iter()
        .map(|k| {
            let v = Vote::sign(k, 1, 0, VoteKind::Precommit, Some(target));
            (v.voter, v.signature)
        })
        .collect();
    let classical_qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(target),
        signatures: genuine,
    };
    assert!(
        !classical_qc.verify(&vs),
        "FULL-PQ: genuine Ed quorum must be rejected (Ed legs deleted)"
    );
    assert!(
        !classical_qc.verify_unified(&vs),
        "FULL-PQ: genuine Ed quorum must be rejected on verify_unified"
    );
    let signers_classical = classical_qc.signers_set(&vs);
    assert!(
        signers_classical.is_empty(),
        "FULL-PQ: rejected Ed quorum attributes nobody"
    );
    let forged_qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(target),
        signatures: vec![(ids[0], vec![7u8; 64]), (ids[1], vec![8u8; 64])],
    };
    assert!(
        !forged_qc.verify(&vs),
        "forged classical QC must be rejected"
    );
    assert!(
        forged_qc.signers_set(&vs).is_empty(),
        "a rejected classical QC must attribute nobody"
    );

    // 2. Genuine Falcon µQC: every verified committee member attributed.
    let parent = [0x55; 32];
    let committee = derive_sortition_committee(&vs, 1, 0, 3, &parent);
    assert_eq!(committee.len(), 3);
    let msg = vote_sign_bytes(1, 0, VoteKind::Precommit, &Some(target));
    let mut bitmask = vec![0u8; 1];
    let mut msigs = Vec::new();
    for (i, id) in committee.iter().enumerate() {
        bitmask[0] |= 1 << i;
        let fk = &fks[ids
            .iter()
            .position(|x| x == id)
            .expect("committee is members")];
        msigs.push(fk.sign(&msg));
    }
    let uqc = PqMicroCertificate::new(
        crate::post_quantum::PqScheme::Falcon512,
        1,
        0,
        3,
        bitmask,
        msigs,
        parent,
    );
    let uqc_qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(target),
        signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
    };
    assert!(uqc_qc.verify(&vs), "genuine Falcon µQC must verify");
    let signers_uqc = uqc_qc.signers_set(&vs);
    assert_eq!(signers_uqc.len(), 3);
    for id in &committee {
        assert!(signers_uqc.contains(id));
    }

    // 3. Garbage marker (unknown id): verify ignores the entry, and
    // attribution mirrors verify — the undecodable marker attributes
    // NOBODY.
    let marker_qc = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some([0xAA; 32]),
        signatures: vec![(PQ_UQC_MARKER_ID, b"garbage-not-an-envelope".to_vec())],
    };
    assert!(!marker_qc.verify(&vs), "marker-only QC must be rejected");
    assert!(
        marker_qc.signers_set(&vs).is_empty(),
        "an unverifiable marker must attribute nobody"
    );
}

/// VOTE-VERIFY BATCH PARITY (Falcon-only, fixed fixtures k=4/7/16/100):
/// `Vote::verify_batch` / `partition_valid` must equal scalar `verify`
/// on all-valid fixtures AND on 1-forged variants. Converted from the
/// deleted classical Ed25519 QC parity (same k values, same strength):
/// Ed-only votes are rejected; tampering the Ed half of a dual envelope
/// still verifies (Ed ignored — proof of deletion); tampering the Falcon
/// half fails. Extends the vote suites; weakens nothing.
#[test]
fn qc_verify_batch_parity_classical_ed25519_k4716_and_forged() {
    // NOTE: historic name kept for traceability; fixtures are Falcon-only
    // (FULL-PQ conversion). The classical Ed25519 QC parity legs are
    // deleted — see `verify_unified_with_pq_keys` (now unconditional
    // `false` after the PQ path) and `signers_set` (classical skipped).
    use rand::rngs::OsRng;
    for &k in &[4usize, 7, 16, 100] {
        let mut vs = ValidatorSet::new();
        let mut sks = Vec::new();
        let mut fks = Vec::new();
        for i in 0..k {
            let sk = SigningKey::generate(&mut OsRng);
            let id = sk.verifying_key().to_bytes();
            let fk = make_sample_falcon512((k as u8).wrapping_mul(31).wrapping_add(i as u8));
            vs.add(id, 1);
            register_validator_pq_key(
                id,
                crate::post_quantum::PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            sks.push(sk);
            fks.push(fk);
        }
        let height = 5;
        let round = 0;
        let kind = VoteKind::Precommit;
        let target = Some([0x12; 32]);
        let votes: Vec<Vote> = (0..k)
            .map(|i| Vote::sign_with_falcon(&sks[i], &fks[i], height, round, kind, target))
            .collect();
        // Serial oracle: scalar Falcon predicate per vote.
        let serial: Vec<bool> = votes.iter().map(|v| v.verify()).collect();
        assert!(
            serial.iter().all(|&b| b),
            "k={k} all-Falcon fixture must verify serially"
        );
        assert!(
            Vote::verify_batch(&votes),
            "k={k} all-Falcon batch must verify"
        );
        assert_eq!(
            Vote::partition_valid(&votes),
            serial,
            "k={k} partition == serial"
        );
        // Deterministic across repeats (cache hit path).
        // GATE: black_box defeats const-folding; pin must fail loudly if changed.
        assert!(
            std::hint::black_box(Vote::verify_batch(&votes)),
            "k={k} batch verdict stable"
        );
        assert_eq!(
            Vote::partition_valid(&votes),
            serial,
            "k={k} partition stable"
        );
        // 1-forged Falcon half: offender fails on every path; survivors pass.
        let mut forged_falcon = votes.clone();
        forged_falcon[0].signature[90] ^= 0xFF;
        assert!(
            !forged_falcon[0].verify(),
            "k={k} Falcon-tampered vote must fail scalar"
        );
        assert!(
            !Vote::verify_batch(&forged_falcon),
            "k={k} Falcon-forged batch must fail"
        );
        let part = Vote::partition_valid(&forged_falcon);
        assert!(!part[0], "k={k} Falcon forger marked false");
        assert!(
            part[1..].iter().all(|&b| b),
            "k={k} honest survivors still pass"
        );
        // Ed-half tamper still verifies (Ed ignored — proof of deletion).
        let mut ed_tampered = votes.clone();
        ed_tampered[0].signature[20] ^= 0xFF;
        assert!(
            ed_tampered[0].verify(),
            "k={k} Ed-tampered dual vote must still verify (Ed ignored)"
        );
        assert!(
            Vote::verify_batch(&ed_tampered),
            "k={k} Ed-tampered batch must still verify"
        );
        // Ed-only votes (no Falcon half) are rejected on every path.
        let ed_only: Vec<Vote> = sks
            .iter()
            .map(|sk| Vote::sign(sk, height, round, kind, target))
            .collect();
        assert!(
            ed_only.iter().all(|v| !v.verify()),
            "k={k} Ed-only votes must fail scalar"
        );
        assert!(
            !Vote::verify_batch(&ed_only),
            "k={k} Ed-only batch must fail"
        );
        assert!(
            Vote::partition_valid(&ed_only).iter().all(|&b| !b),
            "k={k} Ed-only partition all false"
        );
    }
}

/// QC-VERIFY BATCH PARITY (Falcon µQC, fixed fixtures k=4/7/16/100): the
/// batched (rayon-chunked) per-signature verification must equal the serial
/// scalar verdict. A 1-forged member invalidates the WHOLE QC on both paths
/// (fail-closed all-must-pass) with identical (empty) signer accounting.
/// Extends the QC suites; weakens nothing.
#[test]
fn qc_verify_batch_parity_falcon_uqc_k4716_and_forged() {
    for &k in &[4usize, 7, 16, 100] {
        let mut vs = ValidatorSet::new();
        let mut fks = Vec::new();
        for i in 0..k {
            let fk = make_sample_falcon512(0x51u8.wrapping_add(i as u8));
            let pk = fk.public_key().to_vec();
            let id = crate::post_quantum::derive_pq_address(
                crate::post_quantum::PqScheme::Falcon512,
                &pk,
                &crate::post_quantum::DEFAULT_SALT,
            );
            vs.add(id, 10);
            register_validator_pq_key(id, crate::post_quantum::PqScheme::Falcon512, pk);
            fks.push((id, fk));
        }
        let height = 42u64;
        let round = 1u32;
        let kind = VoteKind::Precommit;
        let target = Some([0xAA; 32]);
        let committee_size = micro_committee_size(vs.len());
        let parent = [0x77; 32];
        let committee = derive_sortition_committee(&vs, height, round, committee_size, &parent);
        let msg = vote_sign_bytes(height, round, kind, &target);
        let mut signatures = Vec::new();
        let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
        for (i, val_id) in committee.iter().enumerate() {
            let (_, fk) = fks.iter().find(|(id, _)| id == val_id).unwrap();
            signatures.push(make_sample_falcon512_sig(fk, &msg));
            bitmask[i / 8] |= 1 << (i % 8);
        }
        let uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            bitmask,
            signatures,
            parent,
        );
        let qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash: target,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&uqc))],
        };
        // Serial oracle: the pre-batch scalar loop — every marked member
        // must verify (fail-closed), then the power quorum. A failure
        // attributes nobody (the `None` arm of `micro_cert_valid_signers`).
        // (Fixtures use Falcon512 with registered keys, so the Ed25519
        // address fallback never fires — same as production here.)
        let serial = |cert: &PqMicroCertificate| -> (bool, HashSet<ValidatorId>) {
            let mut ok = true;
            let mut set = HashSet::new();
            let mut sig_idx = 0;
            for (i, val_id) in committee.iter().enumerate() {
                if !cert.is_signer(i) {
                    continue;
                }
                let sig = &cert.signatures[sig_idx];
                sig_idx += 1;
                let pass = match get_validator_pq_key(val_id) {
                    Some((scheme, pk)) if scheme == cert.scheme => {
                        verify_falcon_signature(&pk, &msg, sig)
                    }
                    _ => false,
                };
                if pass {
                    set.insert(*val_id);
                } else {
                    ok = false;
                }
            }
            let committee_total: u64 = committee.iter().map(|id| vs.power_of(id)).sum();
            let required = pq_micro_required_power(committee_total, vs.total_power());
            let power: u64 = set.iter().map(|id| vs.power_of(id)).sum();
            if ok && power >= required {
                (true, set)
            } else {
                (false, HashSet::new())
            }
        };
        let (exp_v, exp_s) = serial(&uqc);
        assert!(exp_v, "k={k} all-valid µQC must verify serially");
        assert_eq!(exp_s.len(), committee.len());
        assert_eq!(qc.verify(&vs), exp_v, "k={k} batched == serial verdict");
        assert_eq!(
            qc.signers_set(&vs),
            exp_s,
            "k={k} identical signer accounting"
        );
        // Deterministic across repeats.
        assert_eq!(qc.verify(&vs), exp_v, "k={k} verdict stable");
        assert_eq!(qc.signers_set(&vs), exp_s, "k={k} attribution stable");
        // 1-forged member: the WHOLE QC is invalid on both paths, and the
        // forged envelope attributes nobody on either path.
        let mut bad_sigs = uqc.signatures.clone();
        bad_sigs[0][50] ^= 0xFF;
        let bad_uqc = PqMicroCertificate::new(
            crate::post_quantum::PqScheme::Falcon512,
            height,
            round,
            committee_size,
            uqc.signers_bitmask.clone(),
            bad_sigs,
            parent,
        );
        let bad_qc = QuorumCertificate {
            height,
            round,
            kind,
            block_hash: target,
            signatures: vec![(PQ_UQC_MARKER_ID, encode_pq_micro_envelope(&bad_uqc))],
        };
        let (b_v, b_s) = serial(&bad_uqc);
        assert!(!b_v, "k={k} 1-forged µQC fails serially");
        assert!(b_s.is_empty(), "k={k} forged envelope attributes nobody");
        assert!(
            !bad_qc.verify(&vs),
            "k={k} 1-forged µQC invalid on batched path"
        );
        assert!(
            bad_qc.signers_set(&vs).is_empty(),
            "k={k} 1-forged µQC attributes nobody on batched path"
        );
    }
}
