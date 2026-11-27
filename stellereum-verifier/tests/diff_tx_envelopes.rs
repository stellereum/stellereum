//! Differential parity for transaction envelope verification.
//!
//! Builds transactions with the production `stellereum` constructors, feeds
//! their canonical wire bytes to the clean-room decoder, and asserts that the
//! clean-room verdict matches `stellereum` for:
//!
//! * `PQ1` explicit and implicit envelopes;
//! * a custom 16-byte salt;
//! * `chain_id` binding (match, mismatch, required-but-absent);
//! * `SF1` Falcon-512 session-key delegation;
//! * `SP1` Paymaster v2 sponsorship (including a priority bid);
//! * `PRIORITY` fee bids on plain envelopes;
//! * legacy `Ed25519`, `SK1`, `CH1`, `EV1`, and disabled-scheme envelopes
//!   (all refused fail-closed by both sides).

use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, StatefulImplicitKeyRegistry, DEFAULT_SALT,
};
use stellereum::sharding::{PqSignatureEnvelope, Transaction};
use stellereum::svm::OpCode;
use stellereum::zkml::SessionKeyAuthorization;
use stellereum_verifier::tx::{verify_tx, verify_tx_at, ImplicitKeyRegistry};
use stellereum_verifier::wire;

const CHAIN_A: u64 = 0x5354_4c31;
const CHAIN_B: u64 = 0x5354_4c32;
const FALCON_SIG_LEN: usize = 666;

fn keypair(seed: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[seed; 32])
}

fn payload() -> Vec<OpCode> {
    vec![OpCode::Push(9), OpCode::Halt]
}

/// Serialize → strict-decode → canonical re-encode. Any wire drift fails here
/// before the signature verdict is compared.
fn to_wire(tx: &Transaction) -> wire::Transaction {
    let bytes = bincode::serialize(tx).expect("stellereum transaction serialize");
    let decoded = wire::decode_transaction_v7_strict(&bytes)
        .unwrap_or_else(|e| panic!("clean-room strict decode failed: {e}"));
    let reencoded = wire::encode_transaction_v7_canonical(&decoded).expect("canonical encode");
    assert_eq!(reencoded, bytes, "wire round-trip must be byte-identical");
    decoded
}

/// Compare our `verify_tx` with `stellereum`'s chain-aware verifier + stateless policies.
fn verdict(
    tx: &Transaction,
    expected_chain: u64,
    require_chain_id: bool,
    registry: &mut ImplicitKeyRegistry,
) -> bool {
    let wire_tx = to_wire(tx);
    let reference = tx.verify_signature_for_chain(expected_chain, require_chain_id)
        && tx.check_session_policy(0).is_ok()
        && tx.check_sponsor_policy(0, tx.gas_limit).is_ok();
    let ours = verify_tx(&wire_tx, expected_chain, require_chain_id, registry).is_ok();
    assert_eq!(
        ours, reference,
        "verdict mismatch (chain={expected_chain}, require={require_chain_id}) for signature blob of {} bytes",
        tx.signature.len()
    );
    reference
}

fn explicit_tx(
    kp: &FalconKeypair,
    salt: [u8; 16],
    chain_id: Option<u64>,
    priority: u64,
    nonce: u64,
) -> Transaction {
    let pk = kp.public_key().to_vec();
    let to = [0x77u8; 32];
    let mut tx = match chain_id {
        Some(cid) => Transaction::new_pq_explicit_with_chain(
            PqScheme::Falcon512,
            pk.clone(),
            vec![0u8; FALCON_SIG_LEN],
            to,
            1_000,
            50_000,
            nonce,
            0,
            1,
            payload(),
            &salt,
            cid,
        ),
        None => Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            pk.clone(),
            vec![0u8; FALCON_SIG_LEN],
            to,
            1_000,
            50_000,
            nonce,
            0,
            1,
            payload(),
            &salt,
        ),
    };
    tx.priority_fee_per_gas = priority;
    let msg = tx.signing_message();
    let sig = kp.sign(&msg);
    tx.signature = match chain_id {
        Some(cid) => {
            PqSignatureEnvelope::new_explicit_with_chain(PqScheme::Falcon512, pk, sig, salt, cid)
                .encode()
        }
        None => {
            PqSignatureEnvelope::new_explicit_with_salt(PqScheme::Falcon512, pk, sig, salt).encode()
        }
    };
    tx
}

fn implicit_tx(
    kp: &FalconKeypair,
    chain_id: Option<u64>,
    priority: u64,
    nonce: u64,
) -> (Transaction, [u8; 32]) {
    let pk = kp.public_key().to_vec();
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    let to = [0x88u8; 32];
    let mut tx = match chain_id {
        Some(cid) => Transaction::new_pq_implicit_with_chain(
            from,
            PqScheme::Falcon512,
            vec![0u8; FALCON_SIG_LEN],
            to,
            1_000,
            50_000,
            nonce,
            0,
            1,
            payload(),
            cid,
        ),
        None => Transaction::new_pq_implicit(
            from,
            PqScheme::Falcon512,
            vec![0u8; FALCON_SIG_LEN],
            to,
            1_000,
            50_000,
            nonce,
            0,
            1,
            payload(),
        ),
    };
    tx.priority_fee_per_gas = priority;
    let msg = tx.signing_message();
    let sig = kp.sign(&msg);
    tx.signature = match chain_id {
        Some(cid) => {
            PqSignatureEnvelope::new_implicit_with_chain(PqScheme::Falcon512, sig, cid).encode()
        }
        None => PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode(),
    };
    (tx, from)
}

#[test]
fn pq1_explicit_salt_chain_and_priority() {
    let kp = keypair(0x41);
    let mut registry = ImplicitKeyRegistry::new();

    let plain = explicit_tx(&kp, DEFAULT_SALT, None, 0, 0);
    assert!(verdict(&plain, CHAIN_A, false, &mut registry));
    // An unbound transaction is refused when the caller requires binding.
    assert!(!verdict(&plain, CHAIN_A, true, &mut registry));

    let prioritized = explicit_tx(&kp, DEFAULT_SALT, None, 123, 1);
    assert_eq!(prioritized.priority_fee_per_gas, 123);
    assert!(verdict(&prioritized, CHAIN_A, false, &mut registry));

    let custom_salt = [0xA5u8; 16];
    let salted = explicit_tx(&kp, custom_salt, None, 0, 2);
    assert!(verdict(&salted, CHAIN_A, false, &mut registry));

    let bound = explicit_tx(&kp, DEFAULT_SALT, Some(CHAIN_A), 7, 3);
    assert!(verdict(&bound, CHAIN_A, false, &mut registry));
    assert!(verdict(&bound, CHAIN_A, true, &mut registry));
    assert!(!verdict(&bound, CHAIN_B, false, &mut registry));
    assert!(!verdict(&bound, CHAIN_B, true, &mut registry));

    // Tampered signature bytes are refused by both.
    let mut tampered = bound.clone();
    let last = tampered.signature.len() - 1;
    tampered.signature[last - 8] ^= 0x01;
    assert!(!verdict(&tampered, CHAIN_A, true, &mut registry));
}

#[test]
fn pq1_implicit_requires_registered_key() {
    let kp = keypair(0x42);
    let (tx, from) = implicit_tx(&kp, Some(CHAIN_A), 0, 10);

    // Without a registration neither side can verify an implicit key.
    let mut registry = ImplicitKeyRegistry::new();
    assert!(!verdict(&tx, CHAIN_A, false, &mut registry));

    let global: &StatefulImplicitKeyRegistry = Transaction::global_implicit_registry();
    global
        .register(from, PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT)
        .expect("register implicit key");
    registry
        .register(
            from,
            wire::PqScheme::Falcon512,
            kp.public_key(),
            &DEFAULT_SALT,
        )
        .expect("register clean-room implicit key");

    assert!(verdict(&tx, CHAIN_A, false, &mut registry));
    assert!(verdict(&tx, CHAIN_A, true, &mut registry));
    assert!(!verdict(&tx, CHAIN_B, false, &mut registry));

    // An implicit envelope whose wire carries a public key is non-canonical.
    let mut smuggled = tx.clone();
    let mut bytes = smuggled.signature.clone();
    bytes[4] = 0; // flip the implicit flag, keep the payload shape
    smuggled.signature = bytes;
    assert!(!verdict(&smuggled, CHAIN_A, false, &mut registry));
}

#[test]
fn sf1_session_key_delegation() {
    let master = keypair(0x51);
    let session = keypair(0x52);
    let delegation = SessionKeyAuthorization::sign_delegation_falcon512(
        &master,
        PqScheme::Falcon512,
        session.public_key(),
        2_000_000,
        10_000_000,
        stellereum::zkml::SCOPE_ALL,
        1_000_000,
        CHAIN_A,
    );
    let tx = Transaction::sign_with_session_falcon512(
        &session,
        delegation,
        [0x99u8; 32],
        1_000,
        50_000,
        11,
        0,
        1,
        payload(),
    );

    let mut registry = ImplicitKeyRegistry::new();
    assert!(verdict(&tx, CHAIN_A, true, &mut registry));
    assert!(!verdict(&tx, CHAIN_B, true, &mut registry));

    // Changing any signed field invalidates the session signature.
    let mut tampered = tx.clone();
    tampered.amount += 1;
    assert!(!verdict(&tampered, CHAIN_A, true, &mut registry));
}

#[test]
fn sp1_paymaster_v2_sponsorship() {
    let user = keypair(0x53);
    let sponsor = keypair(0x54);
    let tx = Transaction::sign_with_sponsor_falcon512(
        &user,
        &sponsor,
        [0xAAu8; 32],
        1_000,
        50_000,
        12,
        0,
        1,
        payload(),
        42,
        100_000,
        9_000_000,
        vec![[0xAAu8; 32]],
        CHAIN_A,
    );

    let mut registry = ImplicitKeyRegistry::new();
    assert!(verdict(&tx, CHAIN_A, true, &mut registry));
    assert!(!verdict(&tx, CHAIN_B, true, &mut registry));

    // Corrupt the sponsor's own signature. The envelope framing is rebuilt
    // canonically, so the only change is the 666-byte sponsor signature.
    let auth = tx.sponsor_auth().expect("SP1 grant");
    let mut bad_auth = auth.clone();
    bad_auth.sponsor_sig[7] ^= 0x01;
    let (inner_len, _, _) = Transaction::split_sponsor_envelope(&tx.signature);
    let auth_bytes = bincode::serialize(&bad_auth).expect("sponsor auth serialize");
    let mut tampered = tx.clone();
    let mut signature = tx.signature[..inner_len].to_vec();
    signature.extend_from_slice(&auth_bytes);
    signature.extend_from_slice(&(auth_bytes.len() as u32).to_be_bytes());
    signature.extend_from_slice(b"SP1");
    tampered.signature = signature;
    assert!(!verdict(&tampered, CHAIN_A, true, &mut registry));
}

#[test]
fn rejected_legacy_envelopes() {
    let kp = keypair(0x55);
    let base = explicit_tx(&kp, DEFAULT_SALT, Some(CHAIN_A), 0, 20);
    let mut registry = ImplicitKeyRegistry::new();

    let cases: [(&str, Vec<u8>); 6] = [
        ("bare Ed25519", vec![0x22u8; 64]),
        ("SK1", {
            let mut v = vec![0x22u8; 64];
            v.extend_from_slice(b"SK1");
            v.extend_from_slice(&[0u8; 8]);
            v
        }),
        ("CH1", {
            let mut v = vec![0x22u8; 64];
            v.extend_from_slice(b"CH1");
            v.extend_from_slice(&CHAIN_A.to_be_bytes());
            v
        }),
        ("EV1", {
            let mut v = b"EV1".to_vec();
            v.extend_from_slice(&[0x33u8; 64]);
            v
        }),
        ("disabled scheme 0x03", {
            let mut v = b"PQ1".to_vec();
            v.push(0x03);
            v.push(1);
            v.extend_from_slice(&0u16.to_le_bytes());
            v.extend_from_slice(&(FALCON_SIG_LEN as u16).to_le_bytes());
            v.extend_from_slice(&[0x44u8; FALCON_SIG_LEN]);
            v
        }),
        ("random PQ1 body", {
            let mut v = b"PQ1".to_vec();
            v.extend_from_slice(&[0x77u8; 700]);
            v
        }),
    ];

    for (name, signature) in cases {
        let mut tx = base.clone();
        tx.signature = signature;
        assert!(
            !verdict(&tx, CHAIN_A, false, &mut registry),
            "legacy envelope `{name}` must be refused by both verifiers"
        );
    }
}

#[test]
fn signature_framing_parity_for_empty_and_oversized() {
    let kp = keypair(0x56);
    let base = explicit_tx(&kp, DEFAULT_SALT, Some(CHAIN_A), 0, 21);
    let mut registry = ImplicitKeyRegistry::new();

    for size in [0usize, 1, 33, 64, 65, 665, 666, 667, 1_024] {
        let mut tx = base.clone();
        tx.signature = vec![0x00u8; size];
        assert!(!verdict(&tx, CHAIN_A, false, &mut registry));
    }
}

#[test]
fn sf1_session_policy_enforcement() {
    let master = keypair(0x57);
    let session = keypair(0x58);
    let mut registry = ImplicitKeyRegistry::new();

    // 1. Out of scope: grant only allows SCOPE_TRANSFER, tx carries SVM payload.
    let transfer_only = SessionKeyAuthorization::sign_delegation_falcon512(
        &master,
        PqScheme::Falcon512,
        session.public_key(),
        2_000_000,
        10_000_000,
        stellereum::zkml::SCOPE_TRANSFER,
        1_000_000,
        CHAIN_A,
    );
    let tx_bad_scope = Transaction::sign_with_session_falcon512(
        &session,
        transfer_only,
        [0x99u8; 32],
        1_000,
        50_000,
        1,
        0,
        1,
        payload(),
    );
    assert!(!verdict(&tx_bad_scope, CHAIN_A, true, &mut registry));

    // 2. Value exceeds max_value_per_tx.
    let small_val = SessionKeyAuthorization::sign_delegation_falcon512(
        &master,
        PqScheme::Falcon512,
        session.public_key(),
        2_000_000,
        10_000_000,
        stellereum::zkml::SCOPE_ALL,
        500,
        CHAIN_A,
    );
    let tx_over_val = Transaction::sign_with_session_falcon512(
        &session,
        small_val,
        [0x99u8; 32],
        501,
        50_000,
        2,
        0,
        1,
        Vec::new(),
    );
    assert!(!verdict(&tx_over_val, CHAIN_A, true, &mut registry));

    // 3. Gas limit exceeds max_gas_spend.
    let small_gas = SessionKeyAuthorization::sign_delegation_falcon512(
        &master,
        PqScheme::Falcon512,
        session.public_key(),
        2_000_000,
        10_000,
        stellereum::zkml::SCOPE_ALL,
        1_000_000,
        CHAIN_A,
    );
    let tx_over_gas = Transaction::sign_with_session_falcon512(
        &session,
        small_gas,
        [0x99u8; 32],
        100,
        50_000,
        3,
        0,
        1,
        Vec::new(),
    );
    assert!(!verdict(&tx_over_gas, CHAIN_A, true, &mut registry));

    // 4. Valid grant passes at now <= valid_until and fails at now > valid_until.
    let valid_grant = SessionKeyAuthorization::sign_delegation_falcon512(
        &master,
        PqScheme::Falcon512,
        session.public_key(),
        2_000_000,
        10_000_000,
        stellereum::zkml::SCOPE_ALL,
        1_000_000,
        CHAIN_A,
    );
    let tx_ok = Transaction::sign_with_session_falcon512(
        &session,
        valid_grant,
        [0x99u8; 32],
        100,
        50_000,
        4,
        0,
        1,
        Vec::new(),
    );
    let wire_ok = to_wire(&tx_ok);
    verify_tx_at(&wire_ok, CHAIN_A, true, 2_000_000, &mut registry)
        .expect("grant valid at boundary");
    assert!(verify_tx_at(&wire_ok, CHAIN_A, true, 2_000_001, &mut registry).is_err());
}

#[test]
fn sp1_sponsor_policy_and_trailing_bytes_enforcement() {
    let user = keypair(0x59);
    let sponsor = keypair(0x5A);
    let mut registry = ImplicitKeyRegistry::new();

    // 1. Target not in allowlist.
    let tx_bad_target = Transaction::sign_with_sponsor_falcon512(
        &user,
        &sponsor,
        [0xBBu8; 32],
        1_000,
        50_000,
        1,
        0,
        1,
        payload(),
        0,
        100_000,
        9_000_000,
        vec![[0xAAu8; 32]],
        CHAIN_A,
    );
    assert!(!verdict(&tx_bad_target, CHAIN_A, true, &mut registry));

    // 2. gas_limit exceeds max_fee_per_tx.
    let tx_over_cap = Transaction::sign_with_sponsor_falcon512(
        &user,
        &sponsor,
        [0xAAu8; 32],
        1_000,
        50_000,
        2,
        0,
        1,
        payload(),
        0,
        49_999,
        9_000_000,
        vec![[0xAAu8; 32]],
        CHAIN_A,
    );
    assert!(!verdict(&tx_over_cap, CHAIN_A, true, &mut registry));

    // 3. Valid sponsored tx passes at now <= valid_until and fails at now > valid_until.
    let tx_ok = Transaction::sign_with_sponsor_falcon512(
        &user,
        &sponsor,
        [0xAAu8; 32],
        1_000,
        50_000,
        3,
        0,
        1,
        payload(),
        0,
        100_000,
        9_000_000,
        vec![[0xAAu8; 32]],
        CHAIN_A,
    );
    let wire_ok = to_wire(&tx_ok);
    verify_tx_at(&wire_ok, CHAIN_A, true, 9_000_000, &mut registry)
        .expect("sponsor grant valid at boundary");
    assert!(verify_tx_at(&wire_ok, CHAIN_A, true, 9_000_001, &mut registry).is_err());

    // 4. Trailing junk inside sponsor auth_bytes must be rejected by split_sponsor_envelope.
    let (inner_len, auth_opt, malformed) =
        wire::Transaction::split_sponsor_envelope(&wire_ok.signature);
    assert!(!malformed);
    let auth = auth_opt.expect("sponsor auth");
    let mut padded_auth = bincode::serialize(&auth).expect("serialize auth");
    padded_auth.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let mut junk_sig = wire_ok.signature[..inner_len].to_vec();
    junk_sig.extend_from_slice(&padded_auth);
    junk_sig.extend_from_slice(&(padded_auth.len() as u32).to_be_bytes());
    junk_sig.extend_from_slice(b"SP1");
    let (_, _, junk_malformed) = wire::Transaction::split_sponsor_envelope(&junk_sig);
    assert!(
        junk_malformed,
        "trailing bytes inside sponsor auth_bytes must fail closed"
    );
    let mut junk_tx = wire_ok.clone();
    junk_tx.signature = junk_sig;
    assert!(verify_tx(&junk_tx, CHAIN_A, true, &mut registry).is_err());
}
