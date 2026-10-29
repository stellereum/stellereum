use stellereum::bls::*;

/// A syntactically valid (but meaningless) aggregate for the FORMAT checks: those
/// ask only whether BLS is the legal encoding at a height, not whether it verifies.
fn dummy_aggregate(n: usize) -> BlsAggregateSignature {
    // A real signature, from a throwaway key, so the container is well-formed. The
    // format checks do not verify it; they only ask which ENCODING is legal.
    let sig = BlsSecretKey::generate().sign(b"format-check");
    BlsAggregateSignature {
        signature: sig,
        participants: SignerBitVector::new(n),
    }
}

#[test]
fn test_single_bls_sign_and_verify() {
    let sk = BlsSecretKey::generate();
    let pk = sk.public_key();
    let msg: &[u8] = b"consensus_block_hash_proposal_123";

    let sig = sk.sign(msg);
    assert!(pk.verify(msg, &sig), "valid signature must verify");

    let bad_msg: &[u8] = b"tampered_proposal";
    assert!(!pk.verify(bad_msg, &sig), "wrong message must fail");

    let other_sk = BlsSecretKey::generate();
    let other_pk = other_sk.public_key();
    assert!(!other_pk.verify(msg, &sig), "wrong pubkey must fail");
}

#[test]
fn test_bls_aggregate_signatures_n_validators() {
    let n = 5;
    let keys: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
    let pubkeys: Vec<BlsPublicKey> = keys.iter().map(|k| k.public_key()).collect();
    let msg: &[u8] = b"block_height_42_quorum_target";

    // 4 out of 5 sign
    let signed_indices = vec![0, 1, 3, 4];
    let mut sigs = Vec::new();
    for &idx in &signed_indices {
        sigs.push((idx, keys[idx].sign(msg)));
    }

    let agg = aggregate_signatures(&sigs, n).expect("aggregation succeeds");
    assert_eq!(agg.participants.signed_count(), 4);
    assert_eq!(agg.participants.absent_indices(), vec![2]);

    assert!(
        verify_aggregate_signature(&pubkeys, msg, &agg),
        "valid aggregate signature must verify"
    );

    // Tampered message fails
    assert!(
        !verify_aggregate_signature(&pubkeys, b"other_msg", &agg),
        "tampered message fails aggregate verify"
    );

    // Tampered validator public key fails
    let mut tampered_pubkeys = pubkeys.clone();
    tampered_pubkeys[0] = BlsSecretKey::generate().public_key();
    assert!(
        !verify_aggregate_signature(&tampered_pubkeys, msg, &agg),
        "tampered public key fails aggregate verify"
    );
}

#[test]
fn test_signer_bitvector_downtime_tracking() {
    let mut bitvec = SignerBitVector::new(10);
    assert_eq!(bitvec.signed_count(), 0);
    assert_eq!(bitvec.absent_indices().len(), 10);

    bitvec.set(0, true);
    bitvec.set(4, true);
    bitvec.set(9, true);

    assert_eq!(bitvec.signed_count(), 3);
    assert!(bitvec.is_set(0));
    assert!(bitvec.is_set(4));
    assert!(bitvec.is_set(9));
    assert!(!bitvec.is_set(1));

    let absent = bitvec.absent_indices();
    assert_eq!(absent, vec![1, 2, 3, 5, 6, 7, 8]);
}

#[test]
fn test_soft_fork_activation_height() {
    let activation = 10_000;
    assert!(!is_bls_active(9_999, activation));
    assert!(is_bls_active(10_000, activation));
    assert!(is_bls_active(10_001, activation));

    let pre_fork_cert = HybridCertificate::Ed25519 {
        height: 500,
        round: 0,
        block_hash: [1u8; 32],
        signatures: vec![([0u8; 32], [0u8; 64])],
    };
    assert!(pre_fork_cert.is_format_valid(activation));

    let invalid_pre_fork = HybridCertificate::BlsAggregate {
        height: 500,
        round: 0,
        block_hash: [1u8; 32],
        aggregate: dummy_aggregate(4),
    };
    assert!(!invalid_pre_fork.is_format_valid(activation));

    let post_fork_cert = HybridCertificate::BlsAggregate {
        height: 10_500,
        round: 0,
        block_hash: [2u8; 32],
        aggregate: dummy_aggregate(4),
    };
    assert!(post_fork_cert.is_format_valid(activation));
}

#[test]
fn test_aggregate_is_one_signature_regardless_of_signer_count() {
    // The whole point: N signers cost ONE 96-byte signature plus ceil(N/8) bytes of
    // bitvector, not N * 64 bytes.
    for n in [1usize, 8, 9, 64, 100] {
        let keys: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
        let sigs: Vec<(usize, BlsSignature)> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| (i, k.sign(b"blk")))
            .collect();
        let agg = aggregate_signatures(&sigs, n).expect("aggregate");
        let (sig_bytes, bits) = agg.to_bytes();
        assert_eq!(
            sig_bytes.len(),
            SIGNATURE_LEN,
            "still one signature for n={n}"
        );
        assert_eq!(
            bits.len(),
            n.div_ceil(8),
            "bitvector is one bit per validator"
        );
        let pks: Vec<BlsPublicKey> = keys.iter().map(|k| k.public_key()).collect();
        assert!(
            verify_aggregate_signature(&pks, b"blk", &agg),
            "n={n} must verify"
        );
    }
}

#[test]
fn test_rogue_key_attack_needs_the_bitvector() {
    // Classic BLS rogue-key attack: if the verifier took only a bare list of public
    // keys, an attacker could pick pk_evil = pk_target_something and forge an
    // aggregate. Here the verifier is handed the FULL canonical set plus a bitvector,
    // so a key that is not IN the set simply cannot be selected.
    let honest = BlsSecretKey::generate();
    let honest_pk = honest.public_key();
    let attacker = BlsSecretKey::generate();
    let attacker_pk = attacker.public_key();

    // Attacker aggregates its own signature with the honest validator's public key
    // pretending it is both signers.
    let combined_key = {
        // pk_evil = attacker_pk - honest_pk would be the real rogue construction; we
        // do not need to build it to show the defence, only that a 2-of-2 claim over
        // {honest, attacker} requires BOTH secrets.
        let agg = aggregate_signatures(&[(0, attacker.sign(b"m"))], 2)
            .expect("one signer aggregate over a 2-set");
        // Bitvector says only index 0 signed.
        assert_eq!(agg.participants.signed_count(), 1);
        agg
    };
    let set = vec![honest_pk, attacker_pk];
    // Index 0 is the HONEST validator, which never signed: verification must fail
    // because the signature is the attacker's and the selected key is not.
    assert!(
        !verify_aggregate_signature(&set, b"m", &combined_key),
        "a signature must not verify under a key that did not produce it"
    );
}

#[test]
fn test_public_key_and_signature_round_trip_bytes() {
    let sk = BlsSecretKey::generate();
    let pk = sk.public_key();
    let sig = sk.sign(b"roundtrip");

    let pk2 = BlsPublicKey::from_bytes(&pk.to_bytes()).expect("pk parses");
    let sig2 = BlsSignature::from_bytes(&sig.to_bytes()).expect("sig parses");
    assert_eq!(pk, pk2);
    assert_eq!(sig, sig2);
    assert!(pk2.verify(b"roundtrip", &sig2));
}

#[test]
fn test_key_from_seed_is_deterministic() {
    let seed = [0x5Au8; 32];
    let a = BlsSecretKey::from_seed(&seed);
    let b = BlsSecretKey::from_seed(&seed);
    assert_eq!(a.public_key(), b.public_key(), "same seed, same key");
    let other = BlsSecretKey::from_seed(&[0x5Bu8; 32]);
    assert_ne!(
        a.public_key(),
        other.public_key(),
        "different seed, different key"
    );
}

#[test]
fn test_duplicate_signer_in_aggregate_is_refused() {
    let k = BlsSecretKey::generate();
    let err = aggregate_signatures(&[(0, k.sign(b"m")), (0, k.sign(b"m"))], 4)
        .expect_err("a repeated signer must be refused");
    assert!(err.contains("twice"), "got: {err}");
}

#[test]
fn test_out_of_range_signer_is_refused() {
    let k = BlsSecretKey::generate();
    let err = aggregate_signatures(&[(9, k.sign(b"m"))], 4)
        .expect_err("index 9 in a 4-validator set must be refused");
    assert!(err.contains("out of range"), "got: {err}");
}

#[test]
fn test_aggregate_verifies_only_for_the_exact_participant_set() {
    let keys: Vec<BlsSecretKey> = (0..5).map(|_| BlsSecretKey::generate()).collect();
    let pks: Vec<BlsPublicKey> = keys.iter().map(|k| k.public_key()).collect();
    // Only 0 and 2 sign.
    let agg = aggregate_signatures(&[(0, keys[0].sign(b"m")), (2, keys[2].sign(b"m"))], 5).unwrap();
    assert!(verify_aggregate_signature(&pks, b"m", &agg));

    // Claim the same signature covers validator 1 instead: must fail.
    let mut tampered = agg.clone();
    tampered.participants.set(0, false);
    tampered.participants.set(1, true);
    assert!(
        !verify_aggregate_signature(&pks, b"m", &tampered),
        "the bitvector is part of the proof"
    );
}

#[test]
fn test_empty_aggregate_is_refused() {
    assert!(aggregate_signatures(&[], 4).is_err());
}

#[test]
fn test_aggregate_with_zero_signed_participants_is_refused() {
    let keys: Vec<BlsSecretKey> = (0..3).map(|_| BlsSecretKey::generate()).collect();
    let pks: Vec<BlsPublicKey> = keys.iter().map(|k| k.public_key()).collect();
    let agg = aggregate_signatures(&[(1, keys[1].sign(b"m"))], 3).unwrap();
    let mut none = agg.clone();
    none.participants.set(1, false);
    assert!(
        !verify_aggregate_signature(&pks, b"m", &none),
        "a certificate where nobody signed must not verify"
    );
}

#[test]
fn test_bitmask_oversize_and_handbuilt_identity_fail_closed() {
    // ATTACK: bitmask / oversize-envelope abuse. A relay can hand-build
    // `BlsAggregateSignature` (public fields) with a bitvector whose
    // `total_validators` does not match the verifier's key list, pad the
    // trailing bits beyond the set, or splice the identity point as the
    // aggregate. Every shape must fail CLOSED at verify (never panic, never
    // verify), while the genuine certificate still verifies.
    use bls12_381::G2Affine;

    let keys: Vec<BlsSecretKey> = (0..4).map(|_| BlsSecretKey::generate()).collect();
    let pks: Vec<BlsPublicKey> = keys.iter().map(|k| k.public_key()).collect();
    let msg: &[u8] = b"bitmask-oversize-probe";
    let sigs: Vec<(usize, BlsSignature)> =
        keys.iter().enumerate().map(|(i, k)| (i, k.sign(msg))).collect();
    let agg = aggregate_signatures(&sigs, 4).expect("genuine aggregate builds");
    assert!(verify_aggregate_signature(&pks, msg, &agg));

    // (1) total_validators mismatch: same bytes measured against a
    // shorter/longer key list must refuse (attacker must not re-frame the set).
    assert!(
        !verify_aggregate_signature(&pks[..3], msg, &agg),
        "truncated key list must refuse"
    );
    let mut longer = pks.clone();
    longer.push(BlsSecretKey::generate().public_key());
    assert!(
        !verify_aggregate_signature(&longer, msg, &agg),
        "extended key list must refuse"
    );
    // Hand-built envelope with total=8 carrying the same 4 signatures.
    let mut wide = SignerBitVector::new(8);
    for i in 0..4 {
        wide.set(i, true);
    }
    let wide_agg = BlsAggregateSignature {
        signature: agg.signature,
        participants: wide,
    };
    assert!(
        !verify_aggregate_signature(&pks, msg, &wide_agg),
        "oversize bitvector (total 8 vs 4 keys) must refuse"
    );

    // (2) Wire-length confusion: 2 bytes for a 4-validator set never parses;
    // 0 bytes never parses; the exact 1 byte does.
    assert!(SignerBitVector::from_bitmask(vec![0u8; 2], 4).is_none());
    assert!(SignerBitVector::from_bitmask(vec![], 4).is_none());
    assert!(SignerBitVector::from_bitmask(vec![0u8; 1], 4).is_some());

    // (3) Trailing pad bits beyond total_validators grant no power: n=5 needs
    // 1 byte but only bits 0..5 are addressable.
    let mut pad = SignerBitVector::new(5);
    pad.set(5, true);
    pad.set(6, true);
    pad.set(7, true);
    assert!(!pad.is_set(5) && !pad.is_set(6) && !pad.is_set(7));
    assert_eq!(pad.signed_count(), 0);
    assert_eq!(pad.absent_indices().len(), 5);

    // (4) Hand-built identity aggregate with FULL participation still refuses.
    let identity = BlsSignature(G2Affine::identity().to_compressed());
    let mut full = SignerBitVector::new(4);
    for i in 0..4 {
        full.set(i, true);
    }
    let forged = BlsAggregateSignature {
        signature: identity,
        participants: full,
    };
    assert!(
        !verify_aggregate_signature(&pks, msg, &forged),
        "identity aggregate must never verify"
    );
}
