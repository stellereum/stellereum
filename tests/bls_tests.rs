use stellereum::bls::*;

// REMOVED (aggregate-counting + hybrid-format tests): `dummy_aggregate`,
// `test_bls_aggregate_signatures_n_validators`,
// `test_soft_fork_activation_height` (HybridCertificate/is_bls_active),
// `test_aggregate_is_one_signature_regardless_of_signer_count`,
// `test_rogue_key_attack_needs_the_bitvector`, duplicate/out-of-range/
// exact-set/empty/zero-participant tests — deleted with the code they
// pinned (`aggregate_signatures`, `verify_aggregate_signature`,
// `HybridCertificate`, `is_bls_active`; reported). What stays: single
// sign/verify, key determinism, byte round-trips, bitvector parser pins.


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
fn bls_envelope_bitvector_parser_pins() {
    // Parser pins (wire compat): the inert envelope bitvector layer. (1)/(4)
    // of the old verify battery (key-list reframe, identity aggregate at
    // verify) were deleted with `verify_aggregate_signature`; the parse
    // refusals below stay: no bitvector confusion may cross into counting.
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
}
