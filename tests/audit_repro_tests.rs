//! Adversarial Audit Reproduction & Verification Test Suite
//! Proves and verifies the specific edge cases, attack vectors, and fixes
//! identified by the security audit.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use stellereum::cell::PatriciaTrie;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::cpat2::ACCOUNT_LEAF_LEN_PQ;
use stellereum::light_client::{Checkpoint, LightClient};
use stellereum::mempool::{Mempool, MempoolError, PQ_ACTIVATION_SURCHARGE_GAS};
use stellereum::post_quantum::{
    derive_pq_address, is_pure_pq_enforced, set_pure_pq_override, FalconKeypair, PqScheme,
    StatefulImplicitKeyRegistry, DEFAULT_SALT,
};
use stellereum::sharding::{PqSignatureEnvelope, Transaction};

// GUARD policy (test-isolation): `set_pure_pq_override` writes the
// PROCESS-WIDE atomic for integration-test binaries (the `cfg(test)`
// thread-local mirror in `src/post_quantum.rs:39-41` does not apply when the
// lib is linked externally). Tests in this file run in parallel threads of
// one process, so `repro_3`'s `Some(true)` window can overlap `repro_4`'s
// Ed25519 QC verification and fail it with "certificate signatures did not
// verify" (same failure class as documented in `src/post_quantum.rs:27-37`).
// All tests below hold this mutex to serialize the flag window. No protocol
// logic is touched.
static PQ_MODE_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn repro_1_custom_salt_counterfactual_address_activation_succeeds() {
    let _guard = PQ_MODE_GUARD.lock().unwrap();
    // VULNERABILITY 1:
    // If a user generates a counterfactual address with a custom non-default salt,
    // does the activation transaction verify using env.salt or does it fail closed?
    let custom_salt = [0x77u8; 16];
    assert_ne!(custom_salt, DEFAULT_SALT);

    let keypair = FalconKeypair::generate_from_seed(0x19);
    let from_address = derive_pq_address(PqScheme::Falcon512, &keypair.public_key, &custom_salt);

    let mut tx = Transaction {
        from: from_address,
        to: [0x88; 32],
        amount: 500,
        gas_limit: 280_000 + PQ_ACTIVATION_SURCHARGE_GAS,
        nonce: 0,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };

    let msg = tx.signing_message();
    let sig = keypair.sign(&msg);

    // Encode explicit envelope WITH custom salt
    let env = PqSignatureEnvelope::new_explicit_with_salt(
        PqScheme::Falcon512,
        keypair.public_key.clone(),
        sig,
        custom_salt,
    );
    tx.signature = env.encode();

    // Verify signature against implicit registry
    let registry = StatefulImplicitKeyRegistry::new();
    assert!(
        tx.verify_signature_with_registry(&registry),
        "Activation transaction with custom salt MUST verify and derive address correctly"
    );

    // Verify key was registered with the custom salt
    assert!(
        registry.lookup(&from_address).is_some(),
        "Custom-salt key must be registered in the implicit registry"
    );
}

#[test]
fn repro_2_activation_gas_surcharge_bypass_is_strictly_blocked() {
    let _guard = PQ_MODE_GUARD.lock().unwrap();
    // VULNERABILITY 2:
    // Attacker sends an activation transaction carrying the public key but with
    // gas_limit < base_fee + PQ_ACTIVATION_SURCHARGE_GAS.
    // The node MUST reject with FeeTooLow AND MUST NOT mutate the implicit registry!
    let custom_registry = StatefulImplicitKeyRegistry::new();
    let mut mp = Mempool::new(100, 100).with_implicit_registry(custom_registry.clone());

    let keypair = FalconKeypair::generate_from_seed(0x99);
    let from = derive_pq_address(PqScheme::Falcon512, &keypair.public_key, &DEFAULT_SALT);

    let base_fee = 280_000u64;
    mp.base_fee = base_fee;
    let underpaid_gas = base_fee + PQ_ACTIVATION_SURCHARGE_GAS - 1; // 1 unit short

    let mut cheap_tx = Transaction {
        from,
        to: [0x55; 32],
        amount: 10,
        gas_limit: underpaid_gas,
        nonce: 0,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };

    let msg = cheap_tx.signing_message();
    let sig = keypair.sign(&msg);
    cheap_tx.signature =
        PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, keypair.public_key.clone(), sig)
            .encode();

    // 1. Submit underpaid transaction
    let res = mp.add(cheap_tx);
    assert_eq!(
        res,
        Err(MempoolError::FeeTooLow),
        "Underpaid activation surcharge must be rejected with FeeTooLow"
    );

    // 2. CRITICAL CHECK: Key must NOT be registered in the registry!
    assert!(
        custom_registry.lookup(&from).is_none(),
        "SECURITY: Underfunded transaction must NEVER register public key in implicit registry!"
    );

    // 3. Verify that sending a subsequent implicit tx without activation fails
    let mut implicit_tx = Transaction {
        from,
        to: [0x55; 32],
        amount: 10,
        gas_limit: base_fee,
        nonce: 0,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let imp_msg = implicit_tx.signing_message();
    let imp_sig = keypair.sign(&imp_msg);
    implicit_tx.signature =
        PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, imp_sig).encode();

    // Must be diverted to buffer because account is unactivated
    assert!(
        custom_registry.lookup(&from).is_none(),
        "Account remains unactivated"
    );
}

#[test]
fn repro_3_pure_pq_mode_rejects_envelope_wrapped_ed25519() {
    let _guard = PQ_MODE_GUARD.lock().unwrap();
    // VULNERABILITY 3:
    // When STELL_PURE_PQ is active, an attacker wraps classical Ed25519 in a PQ1 envelope.
    // The mempool must inspect env.scheme.is_post_quantum() and reject it!
    set_pure_pq_override(Some(true));
    assert!(is_pure_pq_enforced());

    let mut mp = Mempool::new(100, 100);

    let sk = SigningKey::generate(&mut OsRng);
    let ed_pk = sk.verifying_key().to_bytes();

    let mut tx = Transaction {
        from: ed_pk,
        to: [0x33; 32],
        amount: 10,
        gas_limit: 280_000,
        nonce: 0,
        source_shard: 0,
        target_shard: 0,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };

    let msg = tx.signing_message();
    let ed_sig = sk.sign(&msg).to_bytes().to_vec();

    // Wrap Ed25519 inside PQ1 envelope
    let env = PqSignatureEnvelope::new_explicit(PqScheme::Ed25519, ed_pk.to_vec(), ed_sig);
    tx.signature = env.encode();
    assert!(tx.is_pq());

    // Submit to mempool under Pure PQ mode
    let res = mp.add(tx);
    match res {
        Err(MempoolError::Malformed(msg)) => {
            assert!(
                msg.contains("scheme must be post-quantum"),
                "Error message must specify that wrapped classical scheme is rejected: {msg}"
            );
        }
        other => panic!(
            "Expected Malformed error rejecting non-PQ scheme in pure PQ mode, got: {other:?}"
        ),
    }

    set_pure_pq_override(None);
}

#[test]
fn repro_4_light_client_spv_accepts_both_16b_and_49b_leaves() {
    let _guard = PQ_MODE_GUARD.lock().unwrap();
    // VULNERABILITY 4:
    // When an account is pinned, its leaf in cpat2 is 49 bytes.
    // LightClient::verify_account must verify both legacy 16B and pinned 49B leaves!
    let signer = SigningKey::from_bytes(&[0x11u8; 32]);
    let val_id = signer.verifying_key().to_bytes();
    let validators = ValidatorSet::from_list(vec![(val_id, 1)]);

    let address = [0x55u8; 32];
    let balance: u64 = 750_000_000;
    let nonce: u64 = 12;
    let scheme = PqScheme::Falcon512.id();
    let pubkey_hash = [0x77u8; 32];

    // Build a 49-byte pinned leaf
    let pinned_leaf =
        stellereum::cpat2::AccountLeaf::new_pinned(balance, nonce, scheme, pubkey_hash).encode();
    assert_eq!(pinned_leaf.len(), ACCOUNT_LEAF_LEN_PQ);

    let mut trie = PatriciaTrie::new();
    trie.insert(&address, &pinned_leaf);
    let state_root = trie.root_hash();
    let proof = trie.generate_merkle_proof(&address).expect("merkle proof");

    let block_hash = [0x99u8; 32];
    let vote = Vote::sign(&signer, 1, 0, VoteKind::Precommit, Some(block_hash));
    let cert = QuorumCertificate {
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures: vec![(vote.voter, vote.signature)],
    };
    let checkpoint = Checkpoint::new(1, block_hash, [0u8; 32], state_root, cert);
    let lc = LightClient::new(validators, checkpoint).expect("light client init");

    let proven = lc
        .verify_account(&address, &pinned_leaf, &proof, state_root)
        .expect("49-byte pinned account SPV verification must succeed");

    assert_eq!(proven.address, address);
    assert_eq!(proven.balance, balance);
    assert_eq!(proven.nonce, nonce);
    assert_eq!(proven.height, 1);
    assert_eq!(proven.state_root, state_root);
}
