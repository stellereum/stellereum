//! Audit-closure tests for `audit-pq-crypto.md` findings owned by
//! `src/post_quantum.rs`, `src/node_keys.rs`, `src/remote_signer.rs`.
//!
//! NEW FILE (mission rule): no shared test was edited; every assertion below
//! lives here. Each test maps to a finding ID in the report header.

use std::sync::Mutex;

use ed25519_dalek::Signer as _;

/// Serializes every test that mutates process-global state (env vars, the
/// validator-PQ-key registry). Pure-computation tests need no lock but take
/// it anyway where cheap, to keep the file uniformly serial.
static SERIAL: Mutex<()> = Mutex::new(());

// ============================================================================
// F-CRIT-1: ML-DSA-44 (0x03) disabled fail-closed
// ============================================================================

#[test]
fn mldsa_scheme_byte_refused_at_admission() {
    use stellereum::post_quantum::PqScheme;
    let err = PqScheme::from_id(3).expect_err("0x03 must be refused");
    assert!(
        err.contains("ML-DSA-44"),
        "loud refusal names scheme: {err}"
    );
    assert!(
        err.contains("DISABLED"),
        "loud refusal says DISABLED: {err}"
    );
    assert!(err.contains("0x03"), "loud refusal names id: {err}");
    // Neighbouring ids still work; unknown ids still rejected.
    assert_eq!(PqScheme::from_id(2).unwrap(), PqScheme::Falcon512);
    assert_eq!(PqScheme::from_id(4).unwrap(), PqScheme::Hybrid);
    assert!(PqScheme::from_id(0).is_err());
    assert!(PqScheme::from_id(5).is_err());
    // The disabled helper agrees with the admission gate.
    assert!(PqScheme::MlDsa44.is_disabled());
    assert!(!PqScheme::Falcon512.is_disabled());
    assert!(!PqScheme::Hybrid.is_disabled());
    assert!(!PqScheme::Ed25519.is_disabled());
}

#[test]
fn mldsa_verify_refuses_even_audit_forgery() {
    use stellereum::post_quantum::{
        verify_pq_signature, PqScheme, MLDSA44_PUBKEY_LEN, MLDSA44_SIG_LEN,
    };
    // The report's forgery recipe: any in-bound z, any c_tilde, trailer set
    // per the PUBLIC formula rho/t1/mu — no secret needed.
    let mut pk = vec![0x77u8; MLDSA44_PUBKEY_LEN];
    pk[..32].fill(0x42); // non-zero rho (passes the only key check)
    let msg = b"forge me with public key alone";
    let mut sig = vec![0x22u8; MLDSA44_SIG_LEN];
    sig[0] = 0x01; // not 0xFF
                   // Trailer per the public binding formula over attacker-chosen bytes.
    let mut h = blake3::Hasher::new_derive_key("MLDSA44_VERIFY_V4");
    h.update(&pk[..32]);
    h.update(&pk[32..]);
    h.update(msg);
    let mu = *h.finalize().as_bytes();
    let mut binding = blake3::Hasher::new_derive_key("MLDSA44_BINDING_V4");
    binding.update(&mu);
    binding.update(&sig[..32]);
    binding.update(&sig[32..sig.len() - 1]);
    let trailer = binding.finalize().as_bytes()[0];
    let last = sig.len() - 1;
    sig[last] = trailer;
    assert!(
        !verify_pq_signature(PqScheme::MlDsa44, &pk, msg, &sig),
        "F-CRIT-1: public-key-only forgery must NOT verify"
    );
    // Degenerate inputs refuse identically.
    assert!(!verify_pq_signature(PqScheme::MlDsa44, &[], msg, &sig));
    assert!(!verify_pq_signature(PqScheme::MlDsa44, &pk, msg, &[]));
}

#[test]
fn mldsa_envelope_and_registry_refuse_pinning() {
    use stellereum::post_quantum::{
        derive_pq_address, PqScheme, PqSignatureEnvelope, StatefulImplicitKeyRegistry,
        DEFAULT_SALT, MLDSA44_PUBKEY_LEN, MLDSA44_SIG_LEN,
    };
    // Envelope admission: encode still frames 0x03 (wire honesty), decode refuses.
    let pk = vec![0x77u8; MLDSA44_PUBKEY_LEN];
    let sig = vec![0x22u8; MLDSA44_SIG_LEN];
    let bytes = PqSignatureEnvelope::new_explicit(PqScheme::MlDsa44, pk.clone(), sig).encode();
    assert_eq!(bytes[3], 3);
    let err = PqSignatureEnvelope::decode(&bytes).expect_err("0x03 envelope must not decode");
    assert!(err.contains("ML-DSA-44"), "{err}");
    // Registry pinning: direct-enum construction must not smuggle 0x03 in.
    let addr = derive_pq_address(PqScheme::MlDsa44, &pk, &DEFAULT_SALT);
    let reg = StatefulImplicitKeyRegistry::new();
    let err = reg
        .register(addr, PqScheme::MlDsa44, &pk, &DEFAULT_SALT)
        .expect_err("registry must refuse 0x03");
    assert!(err.contains("DISABLED"), "{err}");
    assert!(reg.is_empty(), "refused registration must leave no entry");
}

// ============================================================================
// F-MED-1 + F-LOW-1: Falcon canonical framing (0x29 only, exact 0x09)
// ============================================================================

#[test]
fn falcon_only_canonical_0x29_verifies() {
    use stellereum::post_quantum::{verify_pq_signature, FalconKeypair, PqScheme};
    let kp = FalconKeypair::generate_from_seed(0xA1);
    let msg = b"canonical framing closure";
    let sig = kp.sign(msg);
    assert_eq!(sig[0], 0x29, "signer emits canonical framing");
    assert!(verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        msg,
        &sig
    ));

    // 0x29 -> 0x39 relabel (same body) MUST refuse: the old parser accepted
    // it with the trailer unchecked — distinct bytes verifying for one
    // (key, message) is third-party re-minting.
    let mut relabeled = sig.clone();
    relabeled[0] = 0x39;
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, kp.pubkey(), msg, &relabeled),
        "F-MED-1: 0x39 relabel must refuse"
    );

    // Legacy raw-nonce layout (no header, nonce at [0..40]) MUST refuse.
    let mut legacy = vec![0u8; stellereum::post_quantum::FALCON512_SIG_LEN];
    legacy[..40].copy_from_slice(&sig[1..41]);
    let tail = (stellereum::post_quantum::FALCON512_SIG_LEN - 40).min(sig.len() - 41);
    legacy[40..40 + tail].copy_from_slice(&sig[41..41 + tail]);
    if legacy[0] == 0x29 {
        legacy[0] ^= 0x01; // ensure it is not accidentally canonical
    }
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, kp.pubkey(), msg, &legacy),
        "F-MED-1: legacy layout must refuse"
    );

    // Non-zero padding trailer MUST refuse (tamper with last byte).
    let mut bad_pad = sig.clone();
    bad_pad[stellereum::post_quantum::FALCON512_SIG_LEN - 1] ^= 0x01;
    // (If the canonical encoding already fills the buffer, this flips a real
    // bit and must fail as forgery; either way it must not verify.)
    assert!(!verify_pq_signature(
        PqScheme::Falcon512,
        kp.pubkey(),
        msg,
        &bad_pad
    ));
}

#[test]
fn falcon_pubkey_header_is_exact_0x09() {
    use stellereum::post_quantum::{verify_pq_signature, FalconKeypair, PqScheme};
    let kp = FalconKeypair::generate_from_seed(0xB2);
    let msg = b"header exactness";
    let sig = kp.sign(msg);
    let pk = kp.pubkey().to_vec();
    assert_eq!(pk[0], 0x09);
    assert!(verify_pq_signature(PqScheme::Falcon512, &pk, msg, &sig));
    // Every other low-nibble-9 header the old mask accepted must now refuse.
    for header in [0x19u8, 0x29, 0x39, 0x49, 0xF9] {
        let mut bad = pk.clone();
        bad[0] = header;
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, &bad, msg, &sig),
            "F-LOW-1: header {header:#04x} must refuse"
        );
    }
}

// ============================================================================
// F-HIGH-3: production-clean proof — consensus check-digest forgery dies here
// ============================================================================

#[test]
fn falcon_verifier_rejects_check_digest_forgery() {
    use stellereum::post_quantum::{
        verify_pq_signature, FalconKeypair, PqScheme, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN,
    };
    // Rebuild the consensus test-shortcut formula (public key + message only)
    // and assert THIS module's verifier rejects it: green suites here prove
    // the real math, not the shortcut.
    let kp = FalconKeypair::generate_from_seed(0xC3);
    let pk = kp.pubkey().to_vec();
    assert_eq!(pk.len(), FALCON512_PUBKEY_LEN);
    let msg = b"victim message, attacker knows only the public key";
    let mut forged = vec![0u8; FALCON512_SIG_LEN];
    forged[0] = 0x29;
    for (i, b) in forged.iter_mut().enumerate().skip(1).take(40) {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    for (i, b) in forged
        .iter_mut()
        .enumerate()
        .skip(41)
        .take(FALCON512_SIG_LEN - 42)
    {
        *b = (i as u8).wrapping_mul(53).wrapping_add(7);
    }
    if forged.iter().skip(1).take(40).all(|&b| b == 0) {
        forged[1] = 1;
    }
    let mut h = blake3::Hasher::new_derive_key("FALCON512_VERIFY_V4");
    h.update(&pk);
    h.update(msg);
    let commitment = *h.finalize().as_bytes();
    let mut checker = blake3::Hasher::new_derive_key("FALCON512_SIG_CHECK_V4");
    checker.update(&commitment);
    checker.update(&forged[..40]);
    checker.update(&forged[40..FALCON512_SIG_LEN - 1]);
    forged[FALCON512_SIG_LEN - 1] = checker.finalize().as_bytes()[0];
    assert!(
        !verify_pq_signature(PqScheme::Falcon512, &pk, msg, &forged),
        "F-HIGH-3: keyless check-digest forgery must NOT verify here"
    );
    // And the genuine signature still verifies (no over-refusal).
    assert!(verify_pq_signature(
        PqScheme::Falcon512,
        &pk,
        msg,
        &kp.sign(msg)
    ));
}

// ============================================================================
// F-MED-2: envelope strictness (single canonical layout)
// ============================================================================

#[test]
fn pq_envelope_strict_single_layout() {
    use stellereum::post_quantum::{
        FalconKeypair, PqScheme, PqSignatureEnvelope, ED25519_PUBKEY_LEN, ED25519_SIG_LEN,
        FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN,
    };
    let kp = FalconKeypair::generate_from_seed(0xD4);
    let msg = b"envelope strictness";
    let sig = kp.sign(msg);
    let pk = kp.pubkey().to_vec();

    // Roundtrips still hold.
    let exp = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
    assert_eq!(PqSignatureEnvelope::decode(&exp.encode()).unwrap(), exp);
    let imp = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig.clone());
    assert_eq!(PqSignatureEnvelope::decode(&imp.encode()).unwrap(), imp);

    // Trailing byte refused (no silent re-framing).
    let mut trailing = exp.encode();
    trailing.push(0x00);
    assert!(
        PqSignatureEnvelope::decode(&trailing).is_err(),
        "trailing byte must refuse"
    );

    // Flag byte outside {0,1} refused.
    let mut bad_flag = exp.encode();
    bad_flag[4] = 0x02;
    assert!(
        PqSignatureEnvelope::decode(&bad_flag).is_err(),
        "flag 0x02 must refuse"
    );

    // Implicit envelope carrying key bytes refused.
    let mut implicit_with_key = imp.encode();
    assert_eq!(&implicit_with_key[5..7], &[0, 0]);
    implicit_with_key[5] = 1; // pk_len = 1, byte body follows implicitly
    assert!(
        PqSignatureEnvelope::decode(&implicit_with_key).is_err(),
        "implicit-with-key must refuse"
    );

    // Explicit envelope with wrong key length refused.
    let short = PqSignatureEnvelope::new_explicit(
        PqScheme::Falcon512,
        pk[..FALCON512_PUBKEY_LEN - 1].to_vec(),
        sig.clone(),
    );
    assert!(PqSignatureEnvelope::decode(&short.encode()).is_err());

    // Wrong signature length refused.
    let bad_sig = PqSignatureEnvelope::new_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        sig[..FALCON512_SIG_LEN - 1].to_vec(),
    );
    assert!(PqSignatureEnvelope::decode(&bad_sig.encode()).is_err());

    // Ed25519 envelope: exact sizes enforced both sides.
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let ed_pk = ed_sk.verifying_key().to_bytes().to_vec();
    let ed_sig = ed_sk.sign(msg).to_bytes().to_vec();
    assert_eq!(ed_pk.len(), ED25519_PUBKEY_LEN);
    assert_eq!(ed_sig.len(), ED25519_SIG_LEN);
    let ed_env = PqSignatureEnvelope::new_explicit(PqScheme::Ed25519, ed_pk, ed_sig);
    assert_eq!(
        PqSignatureEnvelope::decode(&ed_env.encode()).unwrap(),
        ed_env
    );
}

// ============================================================================
// F-HIGH-2: pure-PQ single/batch parity on the vote path
// ============================================================================

#[test]
fn vote_single_batch_parity_under_pure_pq() {
    use ed25519_dalek::SigningKey;
    use stellereum::consensus::{
        clear_validator_pq_keys_for_tests, register_validator_pq_key, vote_sign_bytes,
        ValidatorSet, Vote, VoteKind, VoteSet,
    };
    use stellereum::post_quantum::{
        derive_pq_address, is_pure_pq_enforced, set_pure_pq_override, FalconKeypair, PqScheme,
        DEFAULT_SALT,
    };
    let _g = SERIAL.lock().unwrap();
    clear_validator_pq_keys_for_tests();

    let height = 77u64;
    let round = 3u32;
    let kind = VoteKind::Precommit;
    let bh = Some([0x55u8; 32]);
    let msg = |v: &Vote| vote_sign_bytes(v.height, v.round, v.kind, &v.block_hash);

    // Two Ed validators (one honest Ed-only vote each) + one Falcon voter.
    let ed_sks: Vec<SigningKey> = (1u8..=2)
        .map(|i| SigningKey::from_bytes(&[i; 32]))
        .collect();
    let fk = FalconKeypair::generate_from_seed(0xE5);
    let ed_voters: Vec<[u8; 32]> = ed_sks
        .iter()
        .map(|k| k.verifying_key().to_bytes())
        .collect();

    let mut ed_votes = Vec::new();
    for (sk, voter) in ed_sks.iter().zip(ed_voters.iter()) {
        let m = vote_sign_bytes(height, round, kind, &bh);
        let sig = sk.sign(&m).to_bytes().to_vec();
        ed_votes.push(Vote::signed_with(*voter, height, round, kind, bh, sig));
    }
    // Falcon vote: Ed identity + registered Falcon key + Falcon half.
    let falcon_sk = SigningKey::from_bytes(&[0xF0; 32]);
    let falcon_voter = falcon_sk.verifying_key().to_bytes();
    register_validator_pq_key(falcon_voter, PqScheme::Falcon512, fk.public_key().to_vec());
    let falcon_vote = Vote::sign_with_falcon(&falcon_sk, &fk, height, round, kind, bh);
    assert_eq!(falcon_vote.voter, falcon_voter);

    let mut vs = ValidatorSet::new();
    for v in ed_voters.iter().chain(std::iter::once(&falcon_voter)) {
        vs.add(*v, 10);
    }
    // Sanity: Falcon address derivation is consistent for the registry entry.
    let _ = derive_pq_address(PqScheme::Falcon512, fk.public_key(), &DEFAULT_SALT);

    // ---- Pure-PQ ON: Ed-only votes die on EVERY path; Falcon lives. ----
    set_pure_pq_override(Some(true));
    assert!(is_pure_pq_enforced());
    for v in &ed_votes {
        assert!(
            !v.verify(),
            "single verify must reject Ed-only under pure-PQ"
        );
    }
    assert!(
        falcon_vote.verify(),
        "Falcon vote must verify under pure-PQ"
    );
    assert!(
        !Vote::verify_batch(&ed_votes),
        "batch must reject Ed-only under pure-PQ"
    );
    assert!(Vote::verify_batch(std::slice::from_ref(&falcon_vote)));
    let flags = Vote::partition_valid(&ed_votes);
    assert_eq!(
        flags,
        vec![false; ed_votes.len()],
        "partition must mirror single"
    );
    assert_eq!(
        Vote::partition_valid(std::slice::from_ref(&falcon_vote)),
        vec![true]
    );
    // Mixed batch: all-or-nothing fails, partition keeps exactly the good one.
    let mut mixed = ed_votes.clone();
    mixed.push(falcon_vote.clone());
    assert!(!Vote::verify_batch(&mixed));
    let mflags = Vote::partition_valid(&mixed);
    assert_eq!(
        mflags,
        vec![false, false, true],
        "partition keeps only the Falcon vote"
    );
    // add_batch parity with add: Ed-only refused with bad-signature, Falcon admitted.
    let mut set_single = VoteSet::new();
    for v in &ed_votes {
        assert!(set_single.add(v.clone(), &vs, height, round, kind).is_err());
    }
    assert!(set_single
        .add(falcon_vote.clone(), &vs, height, round, kind)
        .is_ok());
    let mut set_batch = VoteSet::new();
    let results = set_batch.add_batch(mixed, &vs, height, round, kind);
    assert!(results[0].is_err() && results[1].is_err() && results[2].is_ok());
    assert_eq!(set_batch.len(), 1, "batch admits exactly the Falcon vote");
    assert_eq!(set_batch.len(), set_single.len());

    // ---- Pure-PQ OFF: Ed-only votes verify on every path (no over-refusal). ----
    set_pure_pq_override(Some(false));
    assert!(!is_pure_pq_enforced());
    for v in &ed_votes {
        assert!(v.verify(), "Ed-only verifies when pure-PQ off");
    }
    assert!(Vote::verify_batch(&ed_votes));
    assert!(Vote::partition_valid(&ed_votes).iter().all(|b| *b));
    let _ = msg; // silence helper if unused on some configs
    set_pure_pq_override(None);
    clear_validator_pq_keys_for_tests();
}

// ============================================================================
// Key-file hardening (node_keys) + HSM signer path (remote_signer)
// ============================================================================

#[test]
fn node_key_files_enforce_perms_and_roundtrip() {
    use stellereum::node_keys::{
        decrypt_bytes, load_or_generate_falcon_key, load_or_generate_node_keys, write_private_file,
        ENV_PASSPHRASE,
    };
    let _g = SERIAL.lock().unwrap();
    let prior = std::env::var(ENV_PASSPHRASE).ok();
    std::env::set_var(ENV_PASSPHRASE, "closure-test-passphrase-0123456789");

    let dir = std::env::temp_dir().join(format!(
        "stell-pq-closure-{}-{}",
        std::process::id(),
        "keys"
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Encrypted roundtrips.
    let nk = load_or_generate_node_keys(&dir).expect("generate node keys");
    let nk2 = load_or_generate_node_keys(&dir).expect("reload node keys");
    assert_eq!(nk.signing.to_bytes(), nk2.signing.to_bytes());
    assert_eq!(nk.kem_seed, nk2.kem_seed);
    let falcon_path = dir.join("falcon.key");
    let fk = load_or_generate_falcon_key(&falcon_path).expect("generate falcon key");
    let fk2 = load_or_generate_falcon_key(&falcon_path).expect("reload falcon key");
    assert_eq!(fk.public_key, fk2.public_key);

    // Pre-existing lax file is tightened to 0600 by the writer.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let lax = dir.join("lax.key");
        std::fs::write(&lax, b"secret").unwrap();
        std::fs::set_permissions(&lax, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private_file(&lax, b"secret").unwrap();
        let mode = std::fs::metadata(&lax).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "writer must tighten pre-existing files");
        let mode = std::fs::metadata(&falcon_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700);
    }

    // Wrong passphrase fails closed; plaintext path warns but loads.
    std::env::set_var(ENV_PASSPHRASE, "wrong-passphrase");
    assert!(
        load_or_generate_node_keys(&dir).is_err(),
        "wrong passphrase must fail"
    );
    std::env::remove_var(ENV_PASSPHRASE);
    let raw_plain = b"plain-key-material";
    let out = decrypt_bytes(raw_plain, None).expect("plaintext fallback loads");
    assert_eq!(out, raw_plain);

    match prior {
        Some(v) => std::env::set_var(ENV_PASSPHRASE, v),
        None => std::env::remove_var(ENV_PASSPHRASE),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remote_signer_local_path_is_secret_free_and_strict() {
    use stellereum::remote_signer::{LocalSigner, Signer, SignerError};
    // Bad hex never echoes the input (the input IS the key).
    let err = LocalSigner::from_hex_seed("not-hex!!").expect_err("bad hex must fail");
    assert_eq!(err, SignerError::MalformedKey);
    assert!(!format!("{err}").contains("not-hex"));
    // Roundtrip + empty-message refusal + Debug redaction.
    let signer = LocalSigner::from_hex_seed(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .expect("valid hex seed");
    let msg = b"vote bytes";
    let sig = signer.sign(msg).expect("local signs");
    assert!(signer.verify(msg, &sig));
    assert!(!signer.verify(b"other", &sig));
    assert_eq!(
        signer.sign(&[]).expect_err("empty refused"),
        SignerError::SigningFailed(stellereum::remote_signer::SigningFailureKind::EmptyMessage)
    );
    let dbg = format!("{signer:?}");
    assert!(!dbg.contains("01234567"), "Debug must not leak the seed");
    assert!(dbg.contains("LocalSigner"));
}

#[test]
fn remote_signer_pins_key_and_never_falls_back() {
    use std::sync::Arc;
    use stellereum::remote_signer::{
        LocalSigner, RemoteSigner, Signer, SignerError, SignerTransport,
    };
    /// Fake transport holding a fixed key; the mode flag can be flipped AFTER
    /// pinning to simulate outage / endpoint hijack on a live handle.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Honest,
        Fail,
        Foreign,
    }
    struct Fake {
        key: LocalSigner,
        mode: Mutex<Mode>,
    }
    impl Fake {
        fn new(key: LocalSigner) -> Self {
            Self {
                key,
                mode: Mutex::new(Mode::Honest),
            }
        }
        fn set(&self, m: Mode) {
            *self.mode.lock().unwrap() = m;
        }
    }
    impl SignerTransport for Fake {
        fn public_key(&self) -> Result<[u8; 32], SignerError> {
            if *self.mode.lock().unwrap() == Mode::Fail {
                return Err(SignerError::Transport(
                    stellereum::remote_signer::TransportErrorKind::Request,
                ));
            }
            Ok(self.key.public_key())
        }
        fn sign(&self, msg: &[u8]) -> Result<[u8; 64], SignerError> {
            match *self.mode.lock().unwrap() {
                Mode::Fail => Err(SignerError::Transport(
                    stellereum::remote_signer::TransportErrorKind::Request,
                )),
                Mode::Foreign => {
                    let evil = LocalSigner::generate();
                    Ok(evil.sign(msg).unwrap().to_bytes())
                }
                Mode::Honest => Ok(self.key.sign(msg).unwrap().to_bytes()),
            }
        }
    }
    let transport = Arc::new(Fake::new(LocalSigner::generate()));
    let expected_pk = transport.key.public_key();
    let remote = RemoteSigner::new(transport.clone()).expect("reachable signer pins");
    assert_eq!(remote.public_key(), expected_pk);
    let msg = b"tagged vote bytes";
    let sig = remote.sign(msg).expect("remote signs");
    assert!(remote.verify(msg, &sig));

    // Transport failure propagates — there is no local key to fall back to.
    transport.set(Mode::Fail);
    assert!(
        remote.sign(msg).is_err(),
        "unreachable signer must error, not sign"
    );

    // Foreign signature from a hijacked endpoint is rejected at re-verification.
    transport.set(Mode::Foreign);
    assert!(
        remote.sign(msg).is_err(),
        "foreign signature must be rejected"
    );

    // ...while the honest path keeps working once the endpoint recovers.
    transport.set(Mode::Honest);
    assert!(remote.sign(msg).is_ok());
}
