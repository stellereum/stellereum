//! R1-A: Canonical `PqSignatureEnvelope` decode hardening tests (`sharding/envelope.rs`).
//!
//! Verifies:
//! 1. `Transaction::new_pq_explicit` (Falcon-512) produces canonical `PQ1` bytes accepted by both
//!    `PqSignatureEnvelope::decode` (heights `< H`) and `PqSignatureEnvelope::decode_canonical` (`>= H`).
//! 2. Reordered legacy `salt || key` and salt-free `key || sig` explicit framings remain accepted
//!    by `decode` (pre-gate `< H` compatibility), produce a distinct `tx_hash`, and are strictly
//!    rejected by `decode_canonical` (`>= H`).
//! 3. Implicit envelopes, `chain_id`-bound envelopes, invalid lengths/flags, and trailing bytes
//!    are handled fail-closed by `decode_canonical` and `decode_at_height`.

use stellereum::post_quantum::{
    FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN,
    PQ_ENVELOPE_MAGIC,
};
use stellereum::sharding::{PqSignatureEnvelope, Transaction};

fn signed_falcon_explicit_tx(
    seed: u8,
    salt: &[u8; 16],
    chain_id: Option<u64>,
) -> (FalconKeypair, Transaction) {
    let kp = FalconKeypair::generate_from_seed(seed);
    let pk = kp.public_key.clone();
    let to = [0xAAu8; 32];
    let dummy_sig = vec![0u8; FALCON512_SIG_LEN];

    match chain_id {
        Some(cid) => {
            let probe = Transaction::new_pq_explicit_with_chain(
                PqScheme::Falcon512,
                pk.clone(),
                dummy_sig,
                to,
                1_000,
                50_000,
                0,
                1,
                1,
                Vec::new(),
                salt,
                cid,
            );
            let sig = kp.sign(&probe.signing_message());
            let tx = Transaction::new_pq_explicit_with_chain(
                PqScheme::Falcon512,
                pk,
                sig,
                to,
                1_000,
                50_000,
                0,
                1,
                1,
                Vec::new(),
                salt,
                cid,
            );
            (kp, tx)
        }
        None => {
            let probe = Transaction::new_pq_explicit(
                PqScheme::Falcon512,
                pk.clone(),
                dummy_sig,
                to,
                1_000,
                50_000,
                0,
                1,
                1,
                Vec::new(),
                salt,
            );
            let sig = kp.sign(&probe.signing_message());
            let tx = Transaction::new_pq_explicit(
                PqScheme::Falcon512,
                pk,
                sig,
                to,
                1_000,
                50_000,
                0,
                1,
                1,
                Vec::new(),
                salt,
            );
            (kp, tx)
        }
    }
}

fn encode_legacy_salt_first(env: &PqSignatureEnvelope) -> Vec<u8> {
    let pk = env.pubkey.as_ref().expect("explicit envelope");
    let mut out = Vec::new();
    out.extend_from_slice(PQ_ENVELOPE_MAGIC);
    out.push(env.scheme.id());
    out.push(0); // explicit
    out.extend_from_slice(&env.salt);
    out.extend_from_slice(&(pk.len() as u16).to_le_bytes());
    out.extend_from_slice(pk);
    out.extend_from_slice(&(env.signature_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&env.signature_bytes);
    if let Some(cid) = env.chain_id {
        out.extend_from_slice(&cid.to_be_bytes());
    }
    out
}

fn encode_legacy_no_salt(env: &PqSignatureEnvelope) -> Vec<u8> {
    let pk = env.pubkey.as_ref().expect("explicit envelope");
    let mut out = Vec::new();
    out.extend_from_slice(PQ_ENVELOPE_MAGIC);
    out.push(env.scheme.id());
    out.push(0); // explicit
    out.extend_from_slice(&(pk.len() as u16).to_le_bytes());
    out.extend_from_slice(pk);
    out.extend_from_slice(&(env.signature_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&env.signature_bytes);
    if let Some(cid) = env.chain_id {
        out.extend_from_slice(&cid.to_be_bytes());
    }
    out
}

#[test]
fn explicit_falcon512_tx_canonical_pq1_passes_decode_and_decode_canonical() {
    let custom_salt = [0x42u8; 16];
    let (_kp, tx) = signed_falcon_explicit_tx(0x11, &custom_salt, None);

    assert!(
        tx.verify_signature(),
        "canonical explicit PQ tx must verify"
    );

    let pre_gate = PqSignatureEnvelope::decode(&tx.signature)
        .expect("canonical PQ1 must pass legacy-compatible decode (< H)");
    let post_gate = PqSignatureEnvelope::decode_canonical(&tx.signature)
        .expect("canonical PQ1 must pass decode_canonical (>= H)");

    assert_eq!(pre_gate, post_gate);
    assert!(!post_gate.is_implicit);
    assert_eq!(post_gate.scheme, PqScheme::Falcon512);
    assert_eq!(post_gate.salt, custom_salt);
    assert_eq!(post_gate.chain_id, None);
    assert_eq!(post_gate.encoded_len(), tx.signature.len());
    assert_eq!(post_gate.encode(), tx.signature);

    assert_eq!(
        PqSignatureEnvelope::decode_at_height(&tx.signature, false).unwrap(),
        post_gate
    );
    assert_eq!(
        PqSignatureEnvelope::decode_at_height(&tx.signature, true).unwrap(),
        post_gate
    );
}

#[test]
fn explicit_falcon512_salt_first_malleability_accepted_pre_gate_rejected_at_canonical() {
    for chain_id in [None, Some(5757u64)] {
        let salt = [0x42u8; 16];
        let (_kp, tx) = signed_falcon_explicit_tx(0x22, &salt, chain_id);
        let canonical_env = PqSignatureEnvelope::decode_canonical(&tx.signature).unwrap();

        // Permute `key || salt` -> `salt || key` for the exact same logical signature.
        let salt_first_bytes = encode_legacy_salt_first(&canonical_env);
        assert_ne!(salt_first_bytes, tx.signature);

        let mut tx_malleated = tx.clone();
        tx_malleated.signature = salt_first_bytes.clone();
        assert_ne!(
            tx_malleated.compute_tx_hash(),
            tx.compute_tx_hash(),
            "reordered salt || key framing changes tx_hash"
        );

        // Pre-gate (< H) keeps accepting historical `salt || key` framing.
        let decoded_legacy = PqSignatureEnvelope::decode(&salt_first_bytes)
            .expect("pre-gate decode (< H) must preserve salt || key compatibility");
        assert_eq!(decoded_legacy, canonical_env);
        assert_eq!(
            PqSignatureEnvelope::decode_at_height(&salt_first_bytes, false).unwrap(),
            canonical_env
        );

        // Hardened gate (>= H) strictly rejects `salt || key`.
        assert!(
            PqSignatureEnvelope::decode_canonical(&salt_first_bytes).is_err(),
            "decode_canonical (>= H) must reject salt || key framing"
        );
        assert!(
            PqSignatureEnvelope::decode_at_height(&salt_first_bytes, true).is_err(),
            "decode_at_height(..., true) must reject salt || key framing"
        );

        // Legacy salt-free explicit framing (`key || sig`) also passes `< H` and fails `>= H`.
        let default_salt_env = PqSignatureEnvelope::new_explicit(
            PqScheme::Falcon512,
            canonical_env.pubkey.clone().unwrap(),
            canonical_env.signature_bytes.clone(),
        );
        let default_salt_env = PqSignatureEnvelope {
            chain_id,
            ..default_salt_env
        };
        let no_salt_bytes = encode_legacy_no_salt(&default_salt_env);
        let decoded_no_salt = PqSignatureEnvelope::decode(&no_salt_bytes)
            .expect("pre-gate decode (< H) accepts salt-free explicit framing");
        assert_eq!(decoded_no_salt.salt, DEFAULT_SALT);
        assert!(
            PqSignatureEnvelope::decode_canonical(&no_salt_bytes).is_err(),
            "decode_canonical (>= H) must reject salt-free explicit framing"
        );
    }
}

#[test]
fn canonical_decoder_handles_implicit_and_chain_id_roundtrips() {
    let kp = FalconKeypair::generate_from_seed(0x33);
    let sig = kp.sign(b"canonical implicit + chain_id test");

    // Implicit without chain_id
    let imp = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig.clone());
    let imp_bytes = imp.encode();
    assert_eq!(imp.encoded_len(), imp_bytes.len());
    assert_eq!(PqSignatureEnvelope::decode(&imp_bytes).unwrap(), imp);
    assert_eq!(
        PqSignatureEnvelope::decode_canonical(&imp_bytes).unwrap(),
        imp
    );
    assert_eq!(
        PqSignatureEnvelope::decode_at_height(&imp_bytes, true).unwrap(),
        imp
    );

    // Implicit with chain_id
    let imp_chain = PqSignatureEnvelope::new_implicit_with_chain(PqScheme::Falcon512, sig, 5757);
    let imp_chain_bytes = imp_chain.encode();
    assert_eq!(imp_chain.encoded_len(), imp_chain_bytes.len());
    assert_eq!(
        PqSignatureEnvelope::decode(&imp_chain_bytes).unwrap(),
        imp_chain
    );
    let decoded_imp_chain = PqSignatureEnvelope::decode_canonical(&imp_chain_bytes).unwrap();
    assert_eq!(decoded_imp_chain, imp_chain);
    assert_eq!(decoded_imp_chain.chain_id, Some(5757));

    // Explicit Transaction::new_pq_explicit_with_chain
    let (_kp_exp, tx_chain) = signed_falcon_explicit_tx(0x44, &[0x77u8; 16], Some(5757));
    assert!(tx_chain.verify_signature_for_chain(5757, true));
    let decoded_tx_chain = PqSignatureEnvelope::decode_canonical(&tx_chain.signature)
        .expect("canonical explicit with chain_id must decode");
    assert_eq!(decoded_tx_chain.chain_id, Some(5757));
    assert_eq!(decoded_tx_chain.encoded_len(), tx_chain.signature.len());
}

#[test]
fn canonical_decoder_rejects_invalid_lengths_flags_and_trailing_bytes() {
    let (_kp, tx) = signed_falcon_explicit_tx(0x55, &[0x19u8; 16], None);
    let exp_bytes = tx.signature.clone();
    let exp_env = PqSignatureEnvelope::decode_canonical(&exp_bytes).unwrap();
    let imp_env =
        PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, exp_env.signature_bytes.clone());
    let imp_bytes = imp_env.encode();

    // 1. Short / wrong magic / bad scheme / bad flag
    assert!(PqSignatureEnvelope::decode_canonical(&exp_bytes[..6]).is_err());

    let mut bad_magic = exp_bytes.clone();
    bad_magic[2] = b'2';
    assert!(PqSignatureEnvelope::decode_canonical(&bad_magic).is_err());

    for bad_scheme in [0u8, 1u8, 3u8, 4u8, 0xFFu8] {
        let mut bad = exp_bytes.clone();
        bad[3] = bad_scheme;
        assert!(
            PqSignatureEnvelope::decode_canonical(&bad).is_err(),
            "scheme {bad_scheme} must be rejected"
        );
    }

    for bad_flag in [2u8, 3u8, 0xFFu8] {
        let mut bad = imp_bytes.clone();
        bad[4] = bad_flag;
        assert!(PqSignatureEnvelope::decode_canonical(&bad).is_err());
    }

    // 2. Implicit envelope errors: non-zero pk_len, bad sig_len, truncation, trailing bytes
    let mut imp_with_pk = Vec::new();
    imp_with_pk.extend_from_slice(&imp_bytes[..5]);
    imp_with_pk.extend_from_slice(&4u16.to_le_bytes());
    imp_with_pk.extend_from_slice(&[0xAAu8; 4]);
    imp_with_pk.extend_from_slice(&imp_bytes[7..]);
    assert!(PqSignatureEnvelope::decode_canonical(&imp_with_pk).is_err());

    let mut imp_nonzero_pk_len = imp_bytes.clone();
    imp_nonzero_pk_len[5..7].copy_from_slice(&1u16.to_le_bytes());
    assert!(PqSignatureEnvelope::decode_canonical(&imp_nonzero_pk_len).is_err());

    let mut imp_bad_sig_len = imp_bytes.clone();
    imp_bad_sig_len[7..9].copy_from_slice(&((FALCON512_SIG_LEN - 1) as u16).to_le_bytes());
    assert!(PqSignatureEnvelope::decode_canonical(&imp_bad_sig_len).is_err());

    assert!(PqSignatureEnvelope::decode_canonical(&imp_bytes[..imp_bytes.len() - 1]).is_err());

    for extra in [1usize, 4, 7, 9] {
        let mut trailing = imp_bytes.clone();
        trailing.resize(trailing.len() + extra, 0xEE);
        assert!(
            PqSignatureEnvelope::decode_canonical(&trailing).is_err(),
            "implicit envelope with {extra} trailing bytes must fail"
        );
    }

    let mut imp_chain_trailing = PqSignatureEnvelope::new_implicit_with_chain(
        PqScheme::Falcon512,
        exp_env.signature_bytes.clone(),
        5757,
    )
    .encode();
    imp_chain_trailing.push(0x00);
    assert!(PqSignatureEnvelope::decode_canonical(&imp_chain_trailing).is_err());

    // 3. Explicit envelope errors: wrong pk_len, wrong sig_len, truncations, trailing bytes
    for bad_pk_len in [0usize, FALCON512_PUBKEY_LEN - 1, FALCON512_PUBKEY_LEN + 1] {
        let mut bad = exp_bytes.clone();
        bad[5..7].copy_from_slice(&(bad_pk_len as u16).to_le_bytes());
        assert!(
            PqSignatureEnvelope::decode_canonical(&bad).is_err(),
            "explicit pk_len={bad_pk_len} must fail"
        );
    }

    let sig_len_off = 7 + FALCON512_PUBKEY_LEN + 16;
    for bad_sig_len in [0usize, FALCON512_SIG_LEN - 1, FALCON512_SIG_LEN + 1] {
        let mut bad = exp_bytes.clone();
        bad[sig_len_off..sig_len_off + 2].copy_from_slice(&(bad_sig_len as u16).to_le_bytes());
        assert!(
            PqSignatureEnvelope::decode_canonical(&bad).is_err(),
            "explicit sig_len={bad_sig_len} must fail"
        );
    }

    // Truncations at pk, salt, sig_len, sig boundaries
    for cut in [1usize, 16, FALCON512_SIG_LEN, exp_bytes.len() - 10] {
        assert!(
            PqSignatureEnvelope::decode_canonical(&exp_bytes[..exp_bytes.len() - cut]).is_err(),
            "truncated explicit envelope (-{cut} bytes) must fail"
        );
    }

    // Trailing bytes on explicit (without and with chain_id)
    for extra in [1usize, 4, 7, 9] {
        let mut trailing = exp_bytes.clone();
        trailing.resize(trailing.len() + extra, 0xDD);
        assert!(
            PqSignatureEnvelope::decode_canonical(&trailing).is_err(),
            "explicit envelope with {extra} trailing bytes must fail"
        );
    }

    let (_kp_c, tx_chain) = signed_falcon_explicit_tx(0x66, &[0x23u8; 16], Some(5757));
    let mut exp_chain_trailing = tx_chain.signature.clone();
    exp_chain_trailing.push(0x00);
    assert!(PqSignatureEnvelope::decode_canonical(&exp_chain_trailing).is_err());

    // Partial chain_id (4 bytes instead of 8)
    assert!(PqSignatureEnvelope::decode_canonical(
        &tx_chain.signature[..tx_chain.signature.len() - 4]
    )
    .is_err());
}
