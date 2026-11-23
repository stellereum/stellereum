//! Regression pins for the consensus read-only review findings C1-F1..F6.
//!
//! Each test FAILS on the pre-fix code:
//! * `f1x_proposer_scan_accepts_a_valid_entry_behind_junk` (C1-F1),
//! * `f1x_split_micro_cert_verifies_and_attributes_nobody` (C1-F3),
//! * `f1x_proposer_signature_list_caps_entries_and_bytes` (C1-F5),
//! * `f1x_non_member_batch_vote_skips_the_signature_screen` / the cache tests
//!   for C1-F6 (membership-first + O(1) set fingerprint + cache hit).

use ed25519_dalek::SigningKey;
use std::collections::HashMap;

use stellereum::consensus::{
    clear_verified_vote_cache, derive_sortition_committee, encode_pq_micro_envelope,
    invalidate_verified_vote_cache, micro_committee_size, register_validator_pq_key,
    verified_vote_cache_reset_stats, verified_vote_cache_stats, verify_proposer_signature,
    vote_sign_bytes, Height, PqMicroCertificate, QuorumCertificate, Round, ValidatorId,
    ValidatorSet, Vote, VoteKind, VoteSet, MAX_PROPOSER_SIG_BYTES, MAX_PROPOSER_SIG_ENTRIES,
    PQ_UQC_MARKER_ID,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme, FALCON512_SIG_LEN};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};

static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ed_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A genuine Falcon-signed proposal: Ed25519 half + Falcon half under the
/// derived PQ address, with the Falcon public key registered for the proposer.
fn falcon_block(sk: &SigningKey, fk: &FalconKeypair, height: Height) -> Block {
    let proposer = sk.verifying_key().to_bytes();
    register_validator_pq_key(proposer, PqScheme::Falcon512, fk.public_key.clone());
    let mut block = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        proposer,
        timestamp: 1_234,
        ..Default::default()
    };
    block.sign_block(sk);
    let hash = block.compute_hash();
    block
        .validator_signatures
        .push((fk.validator_id(), fk.sign(&hash)));
    block
}

// ==================== C1-F1 ====================

#[test]
fn f1x_proposer_scan_accepts_a_valid_entry_behind_junk() {
    let _guard = TEST_LOCK.lock().unwrap();
    let sk = ed_key(0x41);
    let fk = FalconKeypair::generate_from_seed(0x42);
    let block = falcon_block(&sk, &fk, 11);
    assert!(
        verify_proposer_signature(&block),
        "fixture must start as a genuine, verifiable proposal"
    );

    // The attack: insert a slot-matching entry with an all-zero Falcon-length
    // signature BEFORE the genuine one. `validator_signatures` is not in the
    // block hash, so a peer can re-serve the same block this way.
    let mut shadowed = block.clone();
    shadowed
        .validator_signatures
        .insert(0, (block.proposer, vec![0u8; FALCON512_SIG_LEN]));
    assert!(
        verify_proposer_signature(&shadowed),
        "a bad slot-matching entry must not veto a later valid Falcon entry"
    );

    // A wrong-length slot entry is skipped, not treated as a reason to stop.
    let mut wrong_len = block.clone();
    wrong_len
        .validator_signatures
        .insert(0, (block.proposer, vec![0u8; 63]));
    assert!(verify_proposer_signature(&wrong_len));

    // Only junk => still refused. Acceptance NEVER widened.
    let mut junk_only = block.clone();
    junk_only.validator_signatures = vec![
        (block.proposer, vec![0u8; FALCON512_SIG_LEN]),
        (block.proposer, vec![0xFFu8; FALCON512_SIG_LEN]),
    ];
    assert!(
        !verify_proposer_signature(&junk_only),
        "no valid Falcon signature anywhere must still refuse"
    );
}

// ==================== C1-F5 ====================

#[test]
fn f1x_proposer_signature_list_caps_entries_and_bytes() {
    let _guard = TEST_LOCK.lock().unwrap();
    let sk = ed_key(0x51);
    let fk = FalconKeypair::generate_from_seed(0x52);
    // Genuine block: the valid Falcon entry is FIRST, so WITHOUT the admission
    // cap the old scan accepts every padded variant below (this is what makes
    // these assertions fail on the pre-fix code, not just return false for an
    // unrelated reason).
    let block = falcon_block(&sk, &fk, 12);
    assert!(verify_proposer_signature(&block));

    // More than MAX_PROPOSER_SIG_ENTRIES entries (small ones, so the byte cap
    // is not the reason) are refused before any scan.
    let mut too_many = block.clone();
    while too_many.validator_signatures.len() <= MAX_PROPOSER_SIG_ENTRIES {
        too_many
            .validator_signatures
            .push((block.proposer, vec![0u8; 16]));
    }
    assert!(
        !verify_proposer_signature(&too_many),
        "9 entries must be refused at admission even though one is valid"
    );

    // The literal F5 shape: 9 REAL-SIZED (Falcon-length) entries.
    let mut nine_real = block.clone();
    while nine_real.validator_signatures.len() < 9 {
        nine_real
            .validator_signatures
            .push((block.proposer, vec![0u8; FALCON512_SIG_LEN]));
    }
    assert_eq!(nine_real.validator_signatures.len(), 9);
    assert!(
        !verify_proposer_signature(&nine_real),
        "9 real-sized entries must be refused at admission even though one is valid"
    );

    // Within the entry cap (8) but over the byte cap (4 KiB).
    let mut too_big = block.clone();
    while too_big.validator_signatures.len() <= MAX_PROPOSER_SIG_ENTRIES {
        too_big
            .validator_signatures
            .push((block.proposer, vec![0u8; FALCON512_SIG_LEN]));
    }
    // 3 entries => 9; trim to the 8-entry boundary for the byte-cap case.
    too_big.validator_signatures.pop();
    assert_eq!(too_big.validator_signatures.len(), MAX_PROPOSER_SIG_ENTRIES);
    assert!(
        too_big
            .validator_signatures
            .iter()
            .map(|(_, sig)| sig.len())
            .sum::<usize>()
            > MAX_PROPOSER_SIG_BYTES
    );
    assert!(
        !verify_proposer_signature(&too_big),
        "more than 4 KiB of signature bytes must be refused at admission"
    );

    // A 100k-entry empty-signature list must be refused by the O(1) cap, not
    // scanned entry by entry — the genuine entry is still present.
    let mut huge = block.clone();
    huge.validator_signatures
        .extend((0..100_000).map(|_| (block.proposer, Vec::new())));
    let start = std::time::Instant::now();
    assert!(!verify_proposer_signature(&huge));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "the entry cap must reject 100k entries without a full scan"
    );
}

// ==================== C1-F3 ====================

#[allow(clippy::too_many_arguments)]
fn micro_marker(
    scheme: PqScheme,
    height: Height,
    round: Round,
    committee_size: u32,
    parent: [u8; 32],
    committee: &[ValidatorId],
    keys: &HashMap<ValidatorId, FalconKeypair>,
    signer_idx: &[usize],
    msg: &[u8],
) -> Vec<u8> {
    let mut bitmask = vec![0u8; (committee_size as usize).div_ceil(8)];
    let mut signatures = Vec::with_capacity(signer_idx.len());
    for &i in signer_idx {
        bitmask[i / 8] |= 1 << (i % 8);
        let key = keys
            .get(&committee[i])
            .expect("fixture registers every committee key");
        signatures.push(key.sign(msg));
    }
    encode_pq_micro_envelope(&PqMicroCertificate {
        scheme,
        height,
        round,
        committee_size,
        signers_bitmask: bitmask,
        signatures,
        sortition_parent: parent,
    })
}

#[test]
fn f1x_split_micro_cert_verifies_and_attributes_nobody() {
    let _guard = TEST_LOCK.lock().unwrap();
    const HEIGHT: Height = 9;
    const ROUND: Round = 0;
    let parent = [0x66u8; 32];

    let mut vs = ValidatorSet::new();
    let mut keys: HashMap<ValidatorId, FalconKeypair> = HashMap::new();
    for i in 0..4u8 {
        let mut id = [0x71u8; 32];
        id[0] = i;
        let fk = FalconKeypair::generate_from_seed(0x80 + i);
        register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key.clone());
        vs.add(id, 1);
        keys.insert(id, fk);
    }

    let committee_size = micro_committee_size(vs.len());
    assert_eq!(committee_size, 4);
    let committee = derive_sortition_committee(&vs, HEIGHT, ROUND, committee_size, &parent);
    assert_eq!(committee.len(), 4);

    let kind = VoteKind::Precommit;
    let block_hash = Some([0x99u8; 32]);
    let msg = vote_sign_bytes(HEIGHT, ROUND, kind, &block_hash);

    // Two markers, SAME parent/height/round, DISJOINT halves (2 + 2 of 4).
    // No single marker reaches the 3-of-4 quorum, but the union is the whole
    // committee: the pre-fix `signers_set` union let `qc_meets_quorum` return
    // true for a certificate `verify` refuses.
    let half_a = micro_marker(
        PqScheme::Falcon512,
        HEIGHT,
        ROUND,
        committee_size,
        parent,
        &committee,
        &keys,
        &[0, 1],
        &msg,
    );
    let half_b = micro_marker(
        PqScheme::Falcon512,
        HEIGHT,
        ROUND,
        committee_size,
        parent,
        &committee,
        &keys,
        &[2, 3],
        &msg,
    );
    let split = QuorumCertificate {
        shard_id: 0,
        height: HEIGHT,
        round: ROUND,
        kind,
        block_hash,
        signatures: vec![
            (PQ_UQC_MARKER_ID, half_a.clone()),
            (PQ_UQC_MARKER_ID, half_b),
        ],
    };
    assert!(!split.verify(&vs), "2+2 split marks never verify");
    assert!(
        split.signers_set(&vs).is_empty(),
        "a certificate the verifier refuses must attribute nobody"
    );
    assert!(
        !vs.qc_meets_quorum(&split),
        "attribution must not manufacture quorum the verifier refuses"
    );
    assert_eq!(
        split.verify_and_signed_power(&vs),
        (false, 0),
        "the fused verify+power path must not report the split union's power"
    );

    // Control: a SINGLE marker with 3 of 4 still verifies and attributes 3.
    let quorum_marker = micro_marker(
        PqScheme::Falcon512,
        HEIGHT,
        ROUND,
        committee_size,
        parent,
        &committee,
        &keys,
        &[0, 1, 2],
        &msg,
    );
    let honest = QuorumCertificate {
        shard_id: 0,
        height: HEIGHT,
        round: ROUND,
        kind,
        block_hash,
        signatures: vec![(PQ_UQC_MARKER_ID, quorum_marker.clone())],
    };
    assert!(honest.verify(&vs));
    assert_eq!(honest.signers_set(&vs).len(), 3);
    assert!(vs.qc_meets_quorum(&honest));

    // A sub-quorum decoy marker in FRONT of the genuine quorum marker must not
    // contribute its signers: attribution names the first QUORUM-bearing
    // marker only (no cross-marker union).
    let mixed = QuorumCertificate {
        shard_id: 0,
        height: HEIGHT,
        round: ROUND,
        kind,
        block_hash,
        signatures: vec![
            (PQ_UQC_MARKER_ID, half_a.clone()),
            (PQ_UQC_MARKER_ID, quorum_marker),
        ],
    };
    assert!(mixed.verify(&vs));
    assert_eq!(
        mixed.signers_set(&vs).len(),
        3,
        "the sub-quorum decoy's signers must not be unioned in"
    );
    assert!(vs.qc_meets_quorum(&mixed));
}

// ==================== C1-F6 ====================

#[test]
fn f1x_vote_cache_hits_and_set_fingerprint_change_invalidates() {
    let _guard = TEST_LOCK.lock().unwrap();
    clear_verified_vote_cache();
    invalidate_verified_vote_cache();
    verified_vote_cache_reset_stats();

    let sk = ed_key(0x61);
    let voter = sk.verifying_key().to_bytes();
    let fk = FalconKeypair::generate_from_seed(0x62);
    register_validator_pq_key(voter, PqScheme::Falcon512, fk.public_key.clone());
    let mut vs = ValidatorSet::new();
    vs.add(voter, 1);
    let vote = Vote::sign_with_falcon(&sk, &fk, 21, 0, VoteKind::Prevote, Some([5u8; 32]));

    let mut set = VoteSet::new();
    assert!(set.add(vote.clone(), &vs, 21, 0, VoteKind::Prevote).is_ok());
    assert_eq!(
        verified_vote_cache_stats(),
        (0, 1),
        "first ingest must fully verify"
    );

    // Repeated honest vote: exact cache hit, no Falcon work.
    verified_vote_cache_reset_stats();
    let mut set2 = VoteSet::new();
    assert!(set2
        .add(vote.clone(), &vs, 21, 0, VoteKind::Prevote)
        .is_ok());
    assert_eq!(
        verified_vote_cache_stats(),
        (1, 0),
        "identical vote bytes under the same set must hit the verdict cache"
    );

    // CONTENT change with the SAME length: a power edit must change the
    // fingerprint and invalidate every cached verdict.
    let mut changed = vs.clone();
    changed.add(voter, 2);
    assert_ne!(vs.fingerprint(), changed.fingerprint());
    verified_vote_cache_reset_stats();
    let mut set3 = VoteSet::new();
    assert!(set3
        .add(vote.clone(), &changed, 21, 0, VoteKind::Prevote)
        .is_ok());
    assert_eq!(
        verified_vote_cache_stats(),
        (0, 1),
        "a set fingerprint change must force a full re-verify"
    );
}
