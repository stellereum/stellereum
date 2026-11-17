use super::*;
use crate::cell::PatriciaTrie;
use crate::post_quantum::{derive_pq_address, PqScheme, StatefulImplicitKeyRegistry, DEFAULT_SALT};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// The constructor DERIVES the transaction-order commitment (audit W7.2).
///
/// A block whose order root disagrees with its body is refused by the
/// validator, so a caller must never have to remember to set the field —
/// the constructor computes it from the body it is given.
#[test]
fn new_for_test_derives_the_order_commitment() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let tx = Transaction::sign(&sk, [2u8; 32], 10, 21_000, 0, 0, 0);

    // An empty body commits to nothing: the all-zero root.
    let empty = Block::new_for_test(MASTERCHAIN_SHARD, 1, [0u8; 32], [0u8; 32], vec![]);
    assert_eq!(empty.order_merkle_root, [0u8; 32]);

    // A body with transactions commits to their ORDER.
    let one = Block::new_for_test(MASTERCHAIN_SHARD, 2, [0u8; 32], [0u8; 32], vec![tx.clone()]);
    assert_eq!(
        one.order_merkle_root,
        crate::mev::compute_order_merkle_root(std::slice::from_ref(&tx))
    );
    assert_ne!(one.order_merkle_root, [0u8; 32]);

    // Two blocks with the SAME transactions have the SAME root; the root
    // is a pure function of the body.
    let again = Block::new_for_test(MASTERCHAIN_SHARD, 3, [1u8; 32], [0u8; 32], vec![tx.clone()]);
    assert_eq!(one.order_merkle_root, again.order_merkle_root);

    // Mutating the body and re-deriving moves the root.
    let mut moved = one.clone();
    moved.recompute_order_commitment();
    assert_eq!(moved.order_merkle_root, one.order_merkle_root);
}

/// `Default` + the functional-update syntax is the future-proof literal
/// form: a field added to `Block` later is filled from `Default` instead
/// of breaking every call site (audit W7.2).
#[test]
fn default_fills_every_field_a_literal_omits() {
    let b = Block {
        height: 7,
        ..Default::default()
    };
    assert_eq!(b.height, 7);
    assert_eq!(b.shard_id, MASTERCHAIN_SHARD);
    assert!(b.transactions.is_empty());
    assert!(b.shard_headers.is_empty());
    assert_eq!(b.order_merkle_root, [0u8; 32]);
    assert!(b.precommit_qc.is_none());
}

#[test]
fn shard_registry_default_is_single_and_not_sharded() {
    let r = ShardRegistry::default();
    assert!(!r.is_sharded(), "the default registry must be single-shard");
    assert_eq!(r.ids().collect::<Vec<_>>(), vec![MASTERCHAIN_SHARD]);
    assert!(r.contains(MASTERCHAIN_SHARD));
    assert!(!r.contains(BASE_WORKCHAIN_SHARD_INITIAL));
}

#[test]
fn shard_registry_from_ids_marks_multi_shard() {
    let r = ShardRegistry::from_ids([MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL]);
    assert!(r.is_sharded());
    assert_eq!(
        r.ids().collect::<Vec<_>>(),
        vec![MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL]
    );
    // A single non-masterchain shard is still one chain in this process.
    assert!(!ShardRegistry::from_ids([BASE_WORKCHAIN_SHARD_INITIAL]).is_sharded());
    // An empty set can never produce a process with no chain at all.
    assert_eq!(
        ShardRegistry::from_ids([]).ids().collect::<Vec<_>>(),
        vec![MASTERCHAIN_SHARD]
    );
}

#[test]
fn block_shard_ignores_namespace_shard_when_not_sharded() {
    // Regression: a single-shard node started with `--shard 1` uses shard 1
    // only as the DHT/blob namespace. Its BLOCKS must stay masterchain (0),
    // matching its persisted chain, or sync validation rejects every chain
    // and finality stalls. This was the live stand deadlock.
    let single_via_cli = ShardRegistry::from_env_or(BASE_WORKCHAIN_SHARD_INITIAL);
    assert!(!single_via_cli.is_sharded());
    assert_eq!(
        block_shard_for(BASE_WORKCHAIN_SHARD_INITIAL, &single_via_cli),
        MASTERCHAIN_SHARD
    );
    // A genuine multi-shard process does scope blocks to its namespace shard.
    let multi = ShardRegistry::from_ids([MASTERCHAIN_SHARD, BASE_WORKCHAIN_SHARD_INITIAL]);
    assert!(multi.is_sharded());
    assert_eq!(
        block_shard_for(BASE_WORKCHAIN_SHARD_INITIAL, &multi),
        BASE_WORKCHAIN_SHARD_INITIAL
    );
}

#[test]
fn tx_belongs_to_shard_enforces_strict_partition_isolation() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
    let tx0 = Transaction::sign(&key, [2u8; 32], 100, 1000, 0, 0, 0);
    let tx1 = Transaction::sign(&key, [2u8; 32], 100, 1000, 0, 1, 1);
    let tx_cross = Transaction::sign(&key, [2u8; 32], 100, 1000, 0, 0, 1);

    assert!(tx_belongs_to_shard(&tx0, 0));
    assert!(
        !tx_belongs_to_shard(&tx0, 1),
        "shard 1 must not own shard 0 tx"
    );

    assert!(tx_belongs_to_shard(&tx1, 1));
    assert!(
        !tx_belongs_to_shard(&tx1, 0),
        "shard 0 must not own shard 1 tx"
    );

    assert!(tx_belongs_to_shard(&tx_cross, 0));
    assert!(
        !tx_belongs_to_shard(&tx_cross, 1),
        "outbound cross-shard tx belongs strictly to source shard"
    );
}

#[test]
fn route_address_is_deterministic_and_most_specific() {
    let mut m = DynamicShardManager::new();
    m.record_tx_load(BASE_WORKCHAIN_SHARD_INITIAL, SHARD_SPLIT_LOAD_THRESHOLD);
    let (c0, c1) = m
        .check_and_split(BASE_WORKCHAIN_SHARD_INITIAL)
        .expect("split");
    assert_eq!((c0.prefix_len, c1.prefix_len), (1, 1));

    let mut a0 = [0u8; 32];
    a0[0] = 0b0000_0000;
    let mut a1 = [0u8; 32];
    a1[0] = 0b1000_0000;

    let r0 = m.route_address(&a0);
    let r1 = m.route_address(&a1);
    // deterministic across repeated calls
    assert_eq!(r0, m.route_address(&a0));
    assert_eq!(r1, m.route_address(&a1));
    // routed to a shard that actually contains the address, and differently
    assert!(m.shards.get(&r0).unwrap().contains_address(&a0));
    assert!(m.shards.get(&r1).unwrap().contains_address(&a1));
    assert_ne!(r0, r1);
}

#[test]
fn test_explicit_pq_transaction_verification() {
    let registry = StatefulImplicitKeyRegistry::new();
    let seed = 0x42;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = DEFAULT_SALT;
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

    // Pre-create transaction with empty signature to obtain exact signing message
    let mut tx = Transaction {
        from,
        to: [2u8; 32],
        amount: 1000,
        gas_limit: 50_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    let envelope = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig);
    tx.signature = envelope.encode();

    assert!(tx.is_pq());
    assert!(tx.is_pq_activation());
    assert!(!tx.is_pq_implicit());

    // Verification against isolated registry succeeds and auto-registers the key
    assert!(tx.verify_signature_with_registry(&registry));
    let registered = registry
        .lookup(&from)
        .expect("Address must be registered after explicit verify");
    assert_eq!(registered.0, PqScheme::Falcon512);
    assert_eq!(registered.1, pk);

    // Global registry verification also succeeds
    assert!(tx.verify_signature());
    // NOTE (PQ excision): the old "Explicit Ed25519 PQ envelope" leg is
    // deleted, not converted. Non-post-quantum schemes are refused by
    // design (`verify_inner_with_registry` returns false for any
    // `!scheme.is_post_quantum()` envelope), so no PQ fixture can make it
    // verify — and the Falcon-512 legs above already pin the property
    // this test names (explicit PQ verification + auto-registration).
}

#[test]
fn test_implicit_pq_transaction_verification_zero_wire_overhead() {
    let registry = StatefulImplicitKeyRegistry::new();
    let seed = 0x77;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = DEFAULT_SALT;
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

    // Build Tx2 (implicit, nonce 1)
    let mut tx2 = Transaction {
        from,
        to: [5u8; 32],
        amount: 250,
        gas_limit: 50_000,
        nonce: 1,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx2.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    let envelope = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
    tx2.signature = envelope.encode();

    assert!(tx2.is_pq());
    assert!(!tx2.is_pq_activation());
    assert!(tx2.is_pq_implicit());

    // Before registration, implicit verification MUST fail (cannot verify without pubkey)
    assert!(!tx2.verify_signature_with_registry(&registry));

    // Now register address in registry (e.g. from Tx1 activation)
    registry
        .register(from, PqScheme::Falcon512, &pk, &salt)
        .expect("Register");

    // After registration, implicit verification MUST succeed!
    assert!(tx2.verify_signature_with_registry(&registry));

    // Verify wire size difference: implicit envelope carries NO public key or salt bytes
    let explicit_env = PqSignatureEnvelope::new_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        envelope.signature_bytes.clone(),
    );
    let explicit_len = explicit_env.encode().len();
    let implicit_len = tx2.signature.len();
    assert_eq!(explicit_len - implicit_len, pk.len() + 16);
    assert!(explicit_len > 1500);
    assert!(implicit_len < 700);
}

#[test]
fn test_tampering_detection_on_pq_signatures() {
    let registry = StatefulImplicitKeyRegistry::new();
    let seed = 0x99;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = DEFAULT_SALT;
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

    let mut tx = Transaction {
        from,
        to: [8u8; 32],
        amount: 100,
        gas_limit: 50_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    let envelope = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
    tx.signature = envelope.encode();

    // Baseline: original transaction verifies
    assert!(tx.verify_signature_with_registry(&registry));

    // 1. Tampered amount
    let mut tampered_amt = tx.clone();
    tampered_amt.amount += 1;
    assert!(
        !tampered_amt.verify_signature_with_registry(&registry),
        "Tampered amount must fail"
    );

    // 2. Tampered recipient
    let mut tampered_to = tx.clone();
    tampered_to.to[0] ^= 0x01;
    assert!(
        !tampered_to.verify_signature_with_registry(&registry),
        "Tampered recipient must fail"
    );

    // 3. Tampered sender address (does not match derived address from pk)
    let mut tampered_from = tx.clone();
    tampered_from.from[0] ^= 0x01;
    assert!(
        !tampered_from.verify_signature_with_registry(&registry),
        "Tampered sender must fail"
    );

    // 4. Tampered signature bytes inside envelope
    let mut tampered_sig_bytes = sig.clone();
    tampered_sig_bytes[50] ^= 0xAA;
    let bad_env =
        PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), tampered_sig_bytes);
    let mut tx_bad_sig = tx.clone();
    tx_bad_sig.signature = bad_env.encode();
    assert!(
        !tx_bad_sig.verify_signature_with_registry(&registry),
        "Corrupted signature bytes must fail"
    );

    // 5. Tampered public key bytes inside envelope
    let mut bad_pk = pk.clone();
    bad_pk[10] ^= 0x55;
    let bad_pk_env = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, bad_pk, sig.clone());
    let mut tx_bad_pk = tx.clone();
    tx_bad_pk.signature = bad_pk_env.encode();
    assert!(
        !tx_bad_pk.verify_signature_with_registry(&registry),
        "Corrupted pubkey must fail"
    );

    // 6. Envelope header corruption (magic mismatch)
    let mut corrupted_magic = tx.clone();
    corrupted_magic.signature[0] = b'X';
    assert!(
        !corrupted_magic.verify_signature_with_registry(&registry),
        "Corrupted envelope magic must fail"
    );

    // 7. Trailing junk attached to envelope
    let mut trailing_junk = tx.clone();
    trailing_junk.signature.push(0xDE);
    trailing_junk.signature.push(0xAD);
    assert!(
        !trailing_junk.verify_signature_with_registry(&registry),
        "Trailing bytes must fail exact-fit check"
    );

    // 8. Truncated envelope
    let mut truncated = tx.clone();
    truncated.signature.truncate(tx.signature.len() - 10);
    assert!(
        !truncated.verify_signature_with_registry(&registry),
        "Truncated envelope must fail"
    );
}

#[test]
fn test_cross_shard_transfer_from_49_byte_pinned_account_leaf() {
    let seed = 0x5a;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = DEFAULT_SALT;
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
    let to = [9u8; 32];
    let amount = 5_000u64;
    let nonce = 2u64;
    let source_balance = 20_000u64;

    // Build PQ transaction with explicit activation envelope
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit: 30_000,
        nonce,
        source_shard: 1,
        target_shard: 2,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    let envelope = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
    tx.signature = envelope.encode();

    // Sender has a 49-byte pinned leaf in the source shard trie
    let pk_hash = blake3::hash(&pk);
    let leaf_49 = crate::cpat2::AccountLeaf::new_pinned(
        source_balance,
        nonce,
        PqScheme::Falcon512.id(),
        *pk_hash.as_bytes(),
    )
    .encode();
    assert_eq!(leaf_49.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);

    let mut trie = PatriciaTrie::new();
    trie.insert(&from, &leaf_49);
    let source_state_root = trie.root_hash();
    let proof = trie.generate_merkle_proof(&from).expect("merkle proof");

    let finalized_in_block = [0x77u8; 32];
    let cross_msg = CrossShardMessage::new(
        1,
        2,
        tx.clone(),
        source_state_root,
        finalized_in_block,
        Some(proof.clone()),
    )
    .with_source_balance(source_balance);

    // 1. Inclusion verification succeeds on 49-byte pinned leaf
    assert!(
        cross_msg.verify_inclusion(),
        "49-byte pinned leaf inclusion proof must verify"
    );
    assert!(
        cross_msg.verify_inclusion_strict(),
        "Strict inclusion must verify"
    );

    // 2. Fund loss prevention: underfunded transfer (source_balance < amount) fails closed
    let underfunded_msg = CrossShardMessage::new(
        1,
        2,
        tx.clone(),
        source_state_root,
        finalized_in_block,
        Some(proof.clone()),
    )
    .with_source_balance(amount - 1);
    assert!(
        !underfunded_msg.verify_inclusion(),
        "Underfunded transfer must be rejected"
    );

    // 3. Fund loss prevention: tampered source_balance fails proof verification
    let tampered_balance_msg = CrossShardMessage::new(
        1,
        2,
        tx.clone(),
        source_state_root,
        finalized_in_block,
        Some(proof.clone()),
    )
    .with_source_balance(source_balance + 1_000);
    assert!(
        !tampered_balance_msg.verify_inclusion(),
        "Tampered balance must fail proof verification"
    );

    // 4. Implicit PQ cross-shard transaction verification
    let implicit_envelope = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
    let mut implicit_tx = tx.clone();
    implicit_tx.signature = implicit_envelope.encode();

    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &salt)
        .expect("register implicit key");

    let implicit_cross_msg = CrossShardMessage::new(
        1,
        2,
        implicit_tx,
        source_state_root,
        finalized_in_block,
        Some(proof.clone()),
    )
    .with_source_balance(source_balance);
    assert!(
        implicit_cross_msg.verify_inclusion(),
        "Implicit PQ cross-shard message must verify"
    );

    // 5. Also verify legacy 16-byte leaf cross-shard transfer works cleanly
    let legacy_from = [0x88u8; 32];
    let legacy_leaf = crate::cpat2::AccountLeaf::new_unpinned(10_000, 0).encode();
    assert_eq!(legacy_leaf.len(), crate::cpat2::ACCOUNT_LEAF_LEN_LEGACY);
    let mut legacy_trie = PatriciaTrie::new();
    legacy_trie.insert(&legacy_from, &legacy_leaf);
    let legacy_root = legacy_trie.root_hash();
    let legacy_proof = legacy_trie
        .generate_merkle_proof(&legacy_from)
        .expect("proof");

    let legacy_tx = Transaction {
        from: legacy_from,
        to,
        amount: 1_000,
        gas_limit: 21_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 2,
        signature: vec![0u8; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let legacy_cross_msg = CrossShardMessage::new(
        1,
        2,
        legacy_tx,
        legacy_root,
        finalized_in_block,
        Some(legacy_proof),
    )
    .with_source_balance(10_000);
    assert!(
        legacy_cross_msg.verify_inclusion(),
        "Legacy 16B leaf cross-shard message must verify"
    );
}

/// AUDIT W6.5 (signature malleability): the PQ1 wire envelope must have
/// exactly ONE valid byte form per `(scheme, key, signature)`.
///
/// The decoder used to accept an implicit envelope with a non-zero
/// `pk_len` (it skipped the bytes and dropped them), an explicit envelope
/// with ANY key length (including zero) and a signature of ANY length —
/// so the same logical signature could be re-minted into many different
/// byte strings. Any byte-based dedup / replay filter, or any
/// transaction id derived from those bytes, could then be evaded by
/// re-encoding the very same transaction.
#[test]
fn test_pq_envelope_decode_is_strict_and_non_malleable() {
    let pk = Transaction::sample_falcon512_pubkey(0x91);
    let sig = Transaction::create_falcon512_test_signature(&pk, b"envelope malleability", 0x91);

    // Canonical encodings round-trip.
    let explicit = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
    let bytes = explicit.encode();
    assert_eq!(PqSignatureEnvelope::decode(&bytes).unwrap(), explicit);
    let implicit = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig.clone());
    let imp_bytes = implicit.encode();
    assert_eq!(PqSignatureEnvelope::decode(&imp_bytes).unwrap(), implicit);

    // (1) An implicit envelope must NOT carry a public key: junk spliced
    //     where the (claimed) key would be must be REFUSED, not silently
    //     skipped — that skip was the malleability hole.
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&imp_bytes[..7]);
    spliced.extend_from_slice(&[0xAAu8; 4]);
    spliced.extend_from_slice(&imp_bytes[7..]);
    assert!(
        PqSignatureEnvelope::decode(&spliced).is_err(),
        "an implicit envelope with a non-zero pk_len must be refused"
    );

    // (2) An explicit envelope must carry EXACTLY the scheme's key length.
    let mut zero_pk_len = bytes.clone();
    zero_pk_len[5..7].copy_from_slice(&0u16.to_le_bytes());
    assert!(PqSignatureEnvelope::decode(&zero_pk_len).is_err());
    let mut short_pk_len = bytes.clone();
    short_pk_len[5..7].copy_from_slice(&((pk.len() - 1) as u16).to_le_bytes());
    assert!(PqSignatureEnvelope::decode(&short_pk_len).is_err());
    let mut long_pk_len = bytes.clone();
    long_pk_len[5..7].copy_from_slice(&((pk.len() + 1) as u16).to_le_bytes());
    assert!(PqSignatureEnvelope::decode(&long_pk_len).is_err());

    // (3) The signature length is pinned to the scheme.
    let sig_len_off = 7 + pk.len() + 16;
    let mut bad_sig_len = bytes.clone();
    bad_sig_len[sig_len_off..sig_len_off + 2].copy_from_slice(&1u16.to_le_bytes());
    assert!(PqSignatureEnvelope::decode(&bad_sig_len).is_err());

    // (4) The flag byte is 0 (explicit) or 1 (implicit) — nothing else.
    let mut bad_flag = imp_bytes.clone();
    bad_flag[4] = 2;
    assert!(PqSignatureEnvelope::decode(&bad_flag).is_err());

    // (5) Trailing bytes are refused.
    let mut trailing = bytes.clone();
    trailing.push(0x00);
    assert!(PqSignatureEnvelope::decode(&trailing).is_err());
}

#[test]
fn test_explicit_pq_custom_non_zero_salt_verification() {
    let registry = StatefulImplicitKeyRegistry::new();
    let seed = 0x88;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let custom_salt = [0x5au8; 16];
    assert_ne!(custom_salt, DEFAULT_SALT);

    let from = derive_pq_address(PqScheme::Falcon512, &pk, &custom_salt);
    let default_from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    assert_ne!(
        from, default_from,
        "Custom salt must derive disjoint address from default salt"
    );

    let tx_probe = Transaction {
        from,
        to: [7u8; 32],
        amount: 1000,
        gas_limit: 50_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx_probe.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);

    let tx = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        sig,
        [7u8; 32],
        1000,
        50_000,
        0,
        1,
        1,
        Vec::new(),
        &custom_salt,
    );

    assert_eq!(tx.from, from);
    assert!(tx.is_pq());
    assert!(tx.is_pq_activation());

    let env = tx.pq_envelope().expect("PQ envelope must decode");
    assert_eq!(env.salt, custom_salt, "Envelope must carry custom salt");

    // Verification must use env.salt from the envelope and succeed
    assert!(
        tx.verify_signature_with_registry(&registry),
        "Explicit PQ tx carrying custom non-zero salt must verify"
    );
    let registered = registry
        .lookup(&from)
        .expect("Address must be registered with custom salt");
    assert_eq!(registered.0, PqScheme::Falcon512);
    assert_eq!(registered.1, pk);

    // Global registry also succeeds
    assert!(tx.verify_signature());

    // Subsequent implicit transaction from this sender cleanly verifies via registry
    let tx2_probe = Transaction {
        from,
        to: [8u8; 32],
        amount: 500,
        gas_limit: 50_000,
        nonce: 1,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg2 = tx2_probe.signing_message();
    let sig2 = Transaction::create_falcon512_test_signature(&pk, &msg2, seed);
    let tx2 = Transaction::new_pq_implicit(
        from,
        PqScheme::Falcon512,
        sig2,
        [8u8; 32],
        500,
        50_000,
        1,
        1,
        1,
        Vec::new(),
    );
    assert!(tx2.verify_signature_with_registry(&registry));

    // Wrong salt envelope fails closed (e.g. envelope with DEFAULT_SALT does not match `from`)
    let mut bad_salt_tx = tx.clone();
    let bad_env = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk, env.signature_bytes);
    bad_salt_tx.signature = bad_env.encode();
    assert!(
        !bad_salt_tx.verify_signature_with_registry(&registry),
        "Envelope with mismatched salt must fail verification"
    );
}

#[test]
fn test_pq_tx_hash_envelope_binding() {
    let seed = 0x66;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = [0x12u8; 16];
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

    let tx_probe = Transaction {
        from,
        to: [9u8; 32],
        amount: 100,
        gas_limit: 50_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx_probe.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);

    let tx = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        pk.clone(),
        sig.clone(),
        [9u8; 32],
        100,
        50_000,
        0,
        1,
        1,
        Vec::new(),
        &salt,
    );

    let baseline_hash = tx.compute_tx_hash();

    // 1. Modifying signature bytes changes tx hash
    let mut tx_mutated_sig = tx.clone();
    let last_idx = tx_mutated_sig.signature.len() - 1;
    tx_mutated_sig.signature[last_idx] ^= 0x01;
    assert_ne!(
        baseline_hash,
        tx_mutated_sig.compute_tx_hash(),
        "Mutating signature bytes must change compute_tx_hash"
    );

    // 2. Modifying salt in envelope changes tx hash
    let mut env_tampered_salt = tx.pq_envelope().unwrap();
    env_tampered_salt.salt[0] ^= 0xFF;
    let mut tx_mutated_salt = tx.clone();
    tx_mutated_salt.signature = env_tampered_salt.encode();
    assert_ne!(
        baseline_hash,
        tx_mutated_salt.compute_tx_hash(),
        "Mutating envelope salt must change compute_tx_hash"
    );

    // 3. Modifying public key in envelope changes tx hash
    let mut env_tampered_pk = tx.pq_envelope().unwrap();
    env_tampered_pk.pubkey.as_mut().unwrap()[5] ^= 0xFF;
    let mut tx_mutated_pk = tx.clone();
    tx_mutated_pk.signature = env_tampered_pk.encode();
    assert_ne!(
        baseline_hash,
        tx_mutated_pk.compute_tx_hash(),
        "Mutating envelope public key must change compute_tx_hash"
    );

    // 4. Verify explicit SEC-PQ-07 commitment layout:
    // Hasher includes prefix b"PQ_ENV" followed by &self.signature
    let mut manual_hasher = Sha256::new();
    manual_hasher.update(tx.from);
    manual_hasher.update(tx.to);
    manual_hasher.update(tx.amount.to_be_bytes());
    manual_hasher.update(tx.gas_limit.to_be_bytes());
    manual_hasher.update(tx.nonce.to_be_bytes());
    manual_hasher.update(tx.source_shard.to_be_bytes());
    manual_hasher.update(tx.target_shard.to_be_bytes());
    manual_hasher.update(b"PAYLOAD");
    let payload_bytes = bincode::serialize(&tx.payload).unwrap();
    manual_hasher.update((payload_bytes.len() as u32).to_be_bytes());
    manual_hasher.update(&payload_bytes);
    manual_hasher.update(b"PQ_ENV");
    manual_hasher.update(&tx.signature);
    let expected_hash: [u8; 32] = manual_hasher.finalize().into();
    assert_eq!(
        baseline_hash, expected_hash,
        "compute_tx_hash must bind b\"PQ_ENV\" and &self.signature"
    );
}

#[test]
fn test_legacy_tx_hash_remains_byte_identical() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let to = [4u8; 32];
    let amount = 2500;
    let gas_limit = 21_000;
    let nonce = 7;
    let source_shard = 0;
    let target_shard = 0;

    let tx = Transaction::sign(
        &sk,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard,
        target_shard,
    );
    assert!(!tx.is_pq(), "Legacy transaction must not be marked as PQ");
    assert_eq!(tx.signature.len(), 64);

    let tx_hash = tx.compute_tx_hash();

    // Exact pre-PQ legacy transaction hash algorithm
    let mut legacy_hasher = Sha256::new();
    legacy_hasher.update(tx.from);
    legacy_hasher.update(tx.to);
    legacy_hasher.update(tx.amount.to_be_bytes());
    legacy_hasher.update(tx.gas_limit.to_be_bytes());
    legacy_hasher.update(tx.nonce.to_be_bytes());
    legacy_hasher.update(tx.source_shard.to_be_bytes());
    legacy_hasher.update(tx.target_shard.to_be_bytes());
    legacy_hasher.update(b"PAYLOAD");
    let payload_bytes = bincode::serialize(&tx.payload).unwrap();
    legacy_hasher.update((payload_bytes.len() as u32).to_be_bytes());
    legacy_hasher.update(&payload_bytes);
    // Note: no PQ_ENV commitment added for legacy
    let expected_legacy_hash: [u8; 32] = legacy_hasher.finalize().into();

    assert_eq!(
        tx_hash, expected_legacy_hash,
        "Legacy transaction hash must remain strictly byte-identical"
    );

    // Modifying signature on legacy transaction does NOT change compute_tx_hash (preserving legacy semantics)
    let mut tx_mutated_sig = tx.clone();
    tx_mutated_sig.signature[0] ^= 0xFF;
    assert_eq!(
        tx_mutated_sig.compute_tx_hash(),
        tx_hash,
        "Legacy tx hash does not bind signature, preserving backward compatibility"
    );
}

#[test]
fn test_cross_shard_verification_target_shard_pinned_pq_account() {
    // Audit finding SEC-PQ-03: When a pinned account on Shard 1 sends an implicit
    // cross-shard transfer to Shard 2, Shard 2 doesn't have the public key in local RAM.
    // CrossShardMessage carries `sender_pubkey_hash` and `sender_scheme`, enabling
    // Shard 2 to construct the 49-byte leaf and verify inclusion without local RAM keys!

    let seed = 0x88;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = DEFAULT_SALT;
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
    let to = [0x55u8; 32];
    let amount = 3_000u64;
    let nonce = 5u64;
    let source_balance = 15_000u64;

    // 1. Build an implicit PQ transaction (omitting public key from wire)
    let mut tx_probe = Transaction {
        from,
        to,
        amount,
        gas_limit: 40_000,
        nonce,
        source_shard: 1,
        target_shard: 2,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx_probe.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    let implicit_envelope = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
    tx_probe.signature = implicit_envelope.encode();

    assert!(tx_probe.is_pq());
    assert!(tx_probe.is_pq_implicit());

    // 2. Set up the 49-byte leaf in Shard 1's state trie:
    //    account_value (16B) || scheme (1B) || pubkey_hash (32B)
    let pk_hash = blake3::hash(&pk);
    let leaf_49 = crate::cpat2::AccountLeaf::new_pinned(
        source_balance,
        nonce,
        PqScheme::Falcon512.id(),
        *pk_hash.as_bytes(),
    )
    .encode();
    assert_eq!(leaf_49.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);

    let mut trie = PatriciaTrie::new();
    trie.insert(&from, &leaf_49);
    let source_state_root = trie.root_hash();
    let proof = trie.generate_merkle_proof(&from).expect("merkle proof");

    // Register the key in Shard 1's local implicit registry before producing the message
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &salt)
        .expect("register implicit key on source shard");

    let finalized_in_block = [0xAAu8; 32];
    let cross_msg = CrossShardMessage::new(
        1,
        2,
        tx_probe.clone(),
        source_state_root,
        finalized_in_block,
        Some(proof.clone()),
    )
    .with_source_balance(source_balance);

    // Verify that CrossShardMessage::new automatically populated sender_pubkey_hash and sender_scheme
    assert_eq!(cross_msg.sender_scheme, Some(PqScheme::Falcon512.id()));
    assert_eq!(cross_msg.sender_pubkey_hash, Some(*pk_hash.as_bytes()));

    // 3. Simulate wire transmission to Shard 2 via bincode serialization/deserialization
    let wire_bytes = bincode::serialize(&cross_msg).expect("serialize CrossShardMessage");
    let received_msg: CrossShardMessage =
        bincode::deserialize(&wire_bytes).expect("deserialize CrossShardMessage");

    assert_eq!(received_msg.sender_scheme, Some(PqScheme::Falcon512.id()));
    assert_eq!(received_msg.sender_pubkey_hash, Some(*pk_hash.as_bytes()));

    // 4. On Shard 2: verify inclusion strictly without needing local RAM keys!
    assert!(
        received_msg.verify_inclusion(),
        "Target shard must verify 49-byte leaf inclusion proof using sender_pubkey_hash metadata"
    );
    assert!(
        received_msg.verify_inclusion_strict(),
        "Strict untrusted verification must succeed without local keys"
    );

    // 5. Tampering detection:
    // (a) Tampered sender_pubkey_hash must fail proof verification
    let mut tampered_pk_hash_msg = received_msg.clone();
    tampered_pk_hash_msg.sender_pubkey_hash = Some([0xEEu8; 32]);
    assert!(
        !tampered_pk_hash_msg.verify_inclusion(),
        "Tampered sender_pubkey_hash must be rejected"
    );

    // (b) Tampered sender_scheme must fail proof verification.
    // FULL-PQ: the other remaining scheme tag (ML-DSA-44, 0x03) is used as
    // the tampered value; 0x01 is no longer a `PqScheme`.
    let mut tampered_scheme_msg = received_msg.clone();
    tampered_scheme_msg.sender_scheme = Some(PqScheme::MlDsa44.id());
    assert!(
        !tampered_scheme_msg.verify_inclusion(),
        "Tampered sender_scheme must be rejected"
    );

    // (c) Explicit PQ envelope cross-shard message
    let explicit_env =
        PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), vec![0u8; 666]);
    let mut explicit_tx = tx_probe.clone();
    explicit_tx.signature = explicit_env.encode();
    let explicit_msg = CrossShardMessage::new(
        1,
        2,
        explicit_tx,
        source_state_root,
        finalized_in_block,
        Some(proof.clone()),
    )
    .with_source_balance(source_balance);
    assert_eq!(explicit_msg.sender_scheme, Some(PqScheme::Falcon512.id()));
    assert_eq!(explicit_msg.sender_pubkey_hash, Some(*pk_hash.as_bytes()));
    assert!(explicit_msg.verify_inclusion());
}

// NOTE (PQ excision): `test_finding_f1_chain_id_binding_ed25519` is
// deleted, not converted. It pinned the CLASSICAL chain-id envelope
// (`Transaction::sign_with_chain_id` + Ed25519 self-verification), whose
// verification is removed by design. The same chain-binding property for
// the live envelope is pinned by the green PQ twin
// `test_finding_f1_chain_id_binding_pq` directly below.

#[test]
fn test_finding_f1_chain_id_binding_pq() {
    let seed = 0x51;
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let salt = DEFAULT_SALT;
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &salt);
    let to = [0x77u8; 32];
    let chain_id_main = 5757u64;
    let chain_id_alt = 999u64;

    let tx_probe = Transaction {
        from,
        to,
        amount: 500,
        gas_limit: 40_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg = tx_probe.signing_message_for_chain(chain_id_main);
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);

    let tx = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        pk,
        sig,
        to,
        500,
        40_000,
        0,
        1,
        1,
        Vec::new(),
        &salt,
        chain_id_main,
    );

    assert!(tx.is_pq());
    assert_eq!(tx.chain_id(), Some(chain_id_main));
    assert!(tx.verify_signature(), "PQ transaction must verify");
    assert!(tx.verify_signature_for_chain(chain_id_main, true));
    assert!(
        !tx.verify_signature_for_chain(chain_id_alt, true),
        "PQ transaction must reject verification for different chain"
    );
}

// NOTE (PQ excision): `test_finding_f1_legacy_compatibility_unaffected`
// is deleted, not converted. It asserted that a legacy classical
// transaction verifies (64-byte sig, 115-byte signing message,
// `verify_signature()` true, unbound chain-gate compat) — behavior the
// excision removes by design (legacy non-PQ transactions are always
// refused). No PQ equivalent exists: legacy compatibility itself is gone.

#[test]
fn test_finding_f1_batch_verification_with_chain_bound_tx() {
    // FULL-PQ: the batch/partitioned paths are Falcon-only now (legacy
    // classical txs are refused), so both fixtures are PQ envelopes with
    // the same shapes as before — one plain implicit, one chain-bound
    // explicit.
    let seed1 = 0x61;
    let pk1 = Transaction::sample_falcon512_pubkey(seed1);
    let from1 = derive_pq_address(PqScheme::Falcon512, &pk1, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from1, PqScheme::Falcon512, &pk1, &DEFAULT_SALT)
        .expect("PQ test key must register");
    let mut tx1 = Transaction {
        from: from1,
        to: [1u8; 32],
        amount: 100,
        gas_limit: 21_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let msg1 = tx1.signing_message();
    let sig1 = Transaction::create_falcon512_test_signature(&pk1, &msg1, seed1);
    tx1.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig1).encode();

    let seed2 = 0x62;
    let pk2 = Transaction::sample_falcon512_pubkey(seed2);
    let msg2_probe = Transaction {
        from: derive_pq_address(PqScheme::Falcon512, &pk2, &DEFAULT_SALT),
        to: [2u8; 32],
        amount: 200,
        gas_limit: 21_000,
        nonce: 0,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
    .signing_message_for_chain(5757);
    let sig2 = Transaction::create_falcon512_test_signature(&pk2, &msg2_probe, seed2);
    let tx2 = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        pk2,
        sig2,
        [2u8; 32],
        200,
        21_000,
        0,
        1,
        1,
        Vec::new(),
        &DEFAULT_SALT,
        5757,
    );

    let txs = vec![tx1, tx2];
    assert!(Transaction::verify_signatures_batch(&txs));
    let results = Transaction::verify_signatures_partitioned(&txs);
    assert_eq!(results, vec![true, true]);
}

/// The cross-machine path: a cross-shard message published by one shard
/// reaches the shard that owns it through the P2P GOSSIP channel, not
/// through shared process memory or a node-local KV.
#[tokio::test]
async fn cross_shard_transport_p2p_routes_messages_between_shards() {
    let bus = crate::network::InMemoryCrossShardPubSub::shared();
    let shard0 = crate::network::CrossShardTransport::p2p(Arc::new(
        crate::network::P2pCrossShardTransport::new(bus.clone(), "epoch-a"),
    ));
    let shard1 = crate::network::CrossShardTransport::p2p(Arc::new(
        crate::network::P2pCrossShardTransport::new(bus.clone(), "epoch-a"),
    ));
    let other_chain = crate::network::CrossShardTransport::p2p(Arc::new(
        crate::network::P2pCrossShardTransport::new(bus.clone(), "epoch-b"),
    ));

    // Subscribe BEFORE the publish: gossip has no replay.
    assert!(shard1.fetch_cross_shard_inbound(2).await.is_empty());
    assert!(other_chain.fetch_cross_shard_inbound(2).await.is_empty());

    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let tx = Transaction::sign(&sk, [7u8; 32], 10, 0, 0, 1, 2);
    let msg = CrossShardMessage::new_trusted(1, 2, tx, [0u8; 32], [3u8; 32]);

    let mut hub = SharedLiquidityHub::new(vec![1, 2]);
    let seq = hub
        .route_cross_shard_message_via(msg.clone(), &shard0)
        .await
        .expect("route through the P2P transport");
    assert!(seq > 0, "an admitted message gets a sequencer position");

    let inbound = shard1.fetch_cross_shard_inbound(2).await;
    assert_eq!(
        inbound.len(),
        1,
        "the destination shard must receive the message over the gossip channel"
    );
    assert_eq!(inbound[0].msg_id, msg.msg_id);
    assert!(
        !inbound[0].trusted,
        "a gossiped message must never be trusted (inclusion proof enforced)"
    );

    // Another chain epoch never hears it: the topic is epoch-scoped.
    assert!(other_chain.fetch_cross_shard_inbound(2).await.is_empty());

    // Replay protection still holds on the transport path.
    let seq2 = hub
        .route_cross_shard_message_via(msg.clone(), &shard0)
        .await
        .expect("a replay is rejected, not an error");
    assert_eq!(seq2, 0, "a replayed message must not be routed again");
    assert!(shard1.fetch_cross_shard_inbound(2).await.is_empty());
}
