//! Differential parity for `cpat2` proofs and the `CommitmentSnapshot` v5
//! digest against `stellereum`.
//!
//! The digest test feeds `stellereum`'s own per-domain preimage extractors into
//! the clean-room assembler: that isolates the consensus-critical framing
//! (version tag, domain order, conditional empty domains) from the per-domain
//! state serializers, which belong to the state engine.

use std::collections::HashMap;

use stellereum::commitment as refc;
use stellereum::cpat2 as refcpat;
use stellereum::sharding::CrossShardKey;
use stellereum::state_engine::InMemoryStateEngine;

use stellereum_verifier::commitment as vc;

/// Drive a future that never actually waits.
///
/// The state-engine root read and commitment snapshot only take uncontended
/// `tokio::sync` locks, so every poll is immediately ready. The verifier's
/// integration tests deliberately have no `tokio` dev-dependency (and adding
/// one would widen this task's scope), so this is the smallest correct executor
/// for that case: a no-op waker plus a bounded poll loop that fails loudly if a
/// future really does park.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};

    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = std::pin::pin!(future);
    for _ in 0..1_000_000 {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
    panic!("future stayed pending: this test provides no reactor for it to await");
}

fn empty_snapshot() -> refc::CommitmentSnapshot {
    refc::CommitmentSnapshot {
        tokens: stellereum::token::TokenRegistry::new(),
        staking: stellereum::staking::StakingLedger::new(),
        orderbooks: stellereum::orderbook::OrderbookManager::new(),
        order_escrow: HashMap::new(),
        pmm: stellereum::pmm::PrimaryMarketMaker::new(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        contracts: stellereum::contract::ContractRegistry::new(),
        governance: stellereum::governance::Governance::new(),
        oracle: stellereum::oracle::OracleState::default(),
        session_keys: stellereum::zkml::SessionKeyRegistry::default(),
        bridge: stellereum::bridge::BridgeState::default(),
        cross_shard_consumed: Vec::new(),
        cross_shard_produced: Vec::new(),
        cross_shard_completed: Vec::new(),
        cross_shard_xpc: Vec::new(),
    }
}

/// Capture the exact domain preimages and hand them to the clean-room
/// assembler.
fn assemble(snapshot: &refc::CommitmentSnapshot) -> vc::VerifierCommitmentSnapshot {
    vc::VerifierCommitmentSnapshot {
        version: refc::COMMITMENT_VERSION,
        tokens: refc::tokens_preimage(&snapshot.tokens),
        staking: refc::staking_preimage(&snapshot.staking),
        pmm: refc::pmm_preimage(
            &snapshot.pmm,
            &snapshot.pmm_usdt_token,
            &snapshot.pmm_treasury,
        ),
        contracts: refc::contracts_preimage(&snapshot.contracts),
        escrow: refc::escrow_preimage(&snapshot.order_escrow),
        governance: refc::governance_preimage(&snapshot.governance),
        oracle: refc::oracle_preimage(&snapshot.oracle),
        session_keys: refc::session_keys_preimage(&snapshot.session_keys),
        books: refc::books_preimage(&snapshot.orderbooks),
        bridge: refc::bridge_preimage(&snapshot.bridge),
        cross_shard: refc::cross_shard_preimage(
            &snapshot.cross_shard_consumed,
            &snapshot.cross_shard_produced,
            &snapshot.cross_shard_completed,
        ),
        xpc: refc::xpc_preimage(&snapshot.cross_shard_xpc),
        zkml: Vec::new(),
        cnvrf: Vec::new(),
        total_minted_nano: 0,
        evm_bindings: Vec::new(),
        pq_registry: Vec::new(),
    }
}

fn assemble_from_engine(engine: &InMemoryStateEngine) -> vc::VerifierCommitmentSnapshot {
    let snapshot = block_on(engine.commitment_snapshot());
    let mut vsnap = assemble(&snapshot);
    let zkml_models = block_on(engine.zkml_models_read()).clone();
    let cnvrf_snap = block_on(engine.cnvrf_v3_snapshot());
    let evm_bindings = block_on(engine.evm_bindings_read()).clone();
    let pq_registry = block_on(engine.pq_registry_read()).clone();
    vsnap.zkml = refc::zkml_preimage(&zkml_models);
    vsnap.cnvrf = refc::cnvrf_v3_preimage(&cnvrf_snap);
    vsnap.total_minted_nano = engine.total_minted_nano();
    vsnap.evm_bindings = refc::evm_bindings_preimage(&evm_bindings);
    vsnap.pq_registry = refc::pq_registry_preimage(&pq_registry);
    vsnap
}

#[test]
fn commitment_key_and_version_parity() {
    assert_eq!(refc::COMMITMENT_VERSION, vc::COMMITMENT_VERSION);
    assert_eq!(refc::commitment_key(), vc::commitment_key());
}

#[test]
fn empty_snapshot_digest_parity() {
    let snapshot = empty_snapshot();
    assert_eq!(
        assemble(&snapshot).digest(),
        refc::commitment_digest(&snapshot)
    );
    // Deterministic: assembling the same empty snapshot twice agrees.
    assert_eq!(
        assemble(&snapshot).digest(),
        assemble(&empty_snapshot()).digest()
    );
}

#[test]
fn non_empty_domains_digest_parity() {
    let mut snapshot = empty_snapshot();

    // PMM: treasury + USDT token are unconditional fields.
    snapshot.pmm_treasury = [0xABu8; 32];
    snapshot.pmm_usdt_token = Some([0xCDu8; 32]);
    assert_eq!(
        assemble(&snapshot).digest(),
        refc::commitment_digest(&snapshot)
    );

    // Cross-shard replay set: a CONDITIONAL domain, so an empty set writes
    // zero bytes and a non-empty one must move the digest.
    let empty_digest = assemble(&snapshot).digest();
    snapshot.cross_shard_consumed.push(CrossShardKey {
        source_shard: 3,
        finalized_in_block: [0x11u8; 32],
        msg_id: [0x22u8; 32],
    });
    let non_empty = assemble(&snapshot);
    assert_eq!(non_empty.digest(), refc::commitment_digest(&snapshot));
    assert_ne!(
        non_empty.digest(),
        empty_digest,
        "a non-empty cross-shard replay set must move the commitment"
    );
}

#[test]
fn cpat2_leaf_and_branch_hash_parity() {
    let key = [0x37u8; 32];
    let long_value = [0xFFu8; 300];
    let values: [&[u8]; 4] = [b"", b"a", b"hello world", &long_value];
    for value in values {
        assert_eq!(
            vc::leaf_hash(&key, value),
            refcpat::leaf_hash(&key, value),
            "leaf hash for {} value bytes",
            value.len()
        );
    }
    let left = [0x01u8; 32];
    let right = [0x02u8; 32];
    for skip in [0u16, 1, 7, 8, 255, 256, u16::MAX] {
        for bit in [0u8, 1, 2, 0xFF] {
            assert_eq!(
                vc::branch_hash(skip, bit, &left, &right),
                refcpat::branch_hash(skip, bit, &left, &right),
                "branch hash skip={skip} bit={bit}"
            );
        }
    }
    assert_eq!(refcpat::CompressedTrie::new().root_hash(), vc::EMPTY_ROOT);
}

fn trie_key(index: u64) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&index.to_be_bytes());
    key[31] = (index.wrapping_mul(37)) as u8;
    key
}

fn convert(proof: &refcpat::MerkleProof) -> vc::MerkleProof {
    vc::MerkleProof {
        key: proof.key,
        value: proof.value.clone(),
        leaf_hash: proof.leaf_hash,
        path: proof
            .path
            .iter()
            .map(|step| vc::Step {
                sibling_right: step.sibling_right,
                sibling_hash: step.sibling_hash,
                skip: step.skip,
                bit: step.bit,
            })
            .collect(),
        kind: match proof.kind {
            refcpat::ProofKind::Inclusion => vc::ProofKind::Inclusion,
            refcpat::ProofKind::Exclusion => vc::ProofKind::Exclusion,
        },
        witness_key: proof.witness_key,
        divergence: proof.divergence.map(|d| match d {
            refcpat::Divergence::Leaf => vc::Divergence::Leaf,
            refcpat::Divergence::Branch { step } => vc::Divergence::Branch { step },
        }),
    }
}

#[test]
fn cpat2_inclusion_proof_parity() {
    let mut trie = refcpat::CompressedTrie::new();
    for i in 0..100u64 {
        trie.insert(&trie_key(i), format!("value-{i}").as_bytes());
    }
    let root = trie.root_hash();

    for i in 0..100u64 {
        let key = trie_key(i);
        let value = format!("value-{i}").into_bytes();
        let reference_proof = trie.generate_proof(&key).expect("inclusion proof");
        let proof = convert(&reference_proof);

        assert_eq!(
            vc::verify_proof(&root, &key, &value, &proof),
            refcpat::verify_proof(&root, &key, &value, &reference_proof)
        );
        assert!(vc::verify_proof(&root, &key, &value, &proof));
        assert!(vc::MerkleProof::verify_inclusion(
            &proof, &root, &key, &value
        ));

        // Wrong value, wrong key, wrong root, flipped sibling: all refused.
        assert!(!vc::verify_proof(&root, &key, b"not-the-value", &proof));
        assert!(!vc::verify_proof(
            &root,
            &trie_key(i + 1_000),
            &value,
            &proof
        ));
        assert!(!vc::verify_proof(&[0u8; 32], &key, &value, &proof));

        let mut tampered = proof.clone();
        tampered.path[0].sibling_hash[0] ^= 0x01;
        assert!(!vc::verify_proof(&root, &key, &value, &tampered));
    }
}

#[test]
fn cpat2_exclusion_proof_parity() {
    let mut trie = refcpat::CompressedTrie::new();
    for i in 0..64u64 {
        trie.insert(&trie_key(i), format!("value-{i}").as_bytes());
    }
    let root = trie.root_hash();

    for i in 1_000..1_040u64 {
        let key = trie_key(i);
        let reference_proof = trie
            .generate_exclusion_proof(&key)
            .expect("exclusion proof for an absent key");
        let proof = convert(&reference_proof);

        assert_eq!(
            vc::verify_exclusion_proof(&root, &key, &proof),
            refcpat::verify_exclusion_proof(&root, &key, &reference_proof)
        );
        assert!(vc::verify_exclusion_proof(&root, &key, &proof));
        assert!(vc::MerkleProof::verify_exclusion(&proof, &root, &key));

        // An exclusion proof is not an inclusion proof for any value.
        assert!(!vc::verify_proof(&root, &key, &proof.value, &proof));
        // Nor is it evidence for a different key.
        assert!(!vc::verify_exclusion_proof(&root, &trie_key(i + 1), &proof));
    }

    // A key that IS in the trie has no exclusion witness.
    assert!(trie.generate_exclusion_proof(&trie_key(0)).is_none());
    // ...and an absent key has no inclusion proof.
    assert!(trie.generate_proof(&trie_key(1_000)).is_none());
}

#[test]
fn proof_node_codec_roundtrip_matches_reference() {
    let mut trie = refcpat::CompressedTrie::new();
    trie.insert(&trie_key(1), b"one");
    trie.insert(&trie_key(2), b"two");
    let root = trie.root_hash();

    let reference = trie.generate_proof(&trie_key(1)).expect("inclusion proof");
    let nodes = reference.to_nodes();
    let parsed = vc::MerkleProof::from_nodes(&nodes).expect("parse canonical nodes");
    assert!(parsed.verify_inclusion(&root, &trie_key(1), b"one"));
    assert!(!parsed.verify_inclusion(&root, &trie_key(1), b"other"));

    assert!(vc::MerkleProof::from_nodes(&[]).is_err());
    assert!(vc::MerkleProof::from_nodes(&["zz".to_string()]).is_err());
}

#[test]
fn engine_state_root_verifies_against_snapshot_and_proof() {
    let engine = InMemoryStateEngine::new();

    // Real account leaves. `credit_native_transfer` moves existing value
    // rather than minting, so `total_minted_nano` stays zero: a mint would add
    // a conditional minted-supply domain to the live digest that this
    // snapshot framing deliberately does not carry.
    for i in 0..8u64 {
        let mut address = [0u8; 32];
        address[..8].copy_from_slice(&i.to_be_bytes());
        address[8] = 0xA5;
        block_on(engine.credit_native_transfer(&address, 1_000 + i)).expect("credit account");
    }

    let state_root = block_on(engine.get_state_root());
    let snapshot = assemble(&block_on(engine.commitment_snapshot()));

    let (reference_proof, account_leaves) = block_on(async {
        let trie = engine.state_trie.read().await;
        let proof = trie
            .compressed()
            .generate_proof(&vc::commitment_key())
            .expect("the root read commits the digest under the commitment key");
        let leaves = trie
            .compressed()
            .entries
            .iter()
            .filter(|(key, _)| **key != vc::commitment_key())
            .map(|(key, value)| (*key, value.clone()))
            .collect::<Vec<_>>();
        (proof, leaves)
    });
    assert_eq!(
        account_leaves.len(),
        8,
        "every credited account must be a trie leaf"
    );
    let proof = convert(&reference_proof);

    let digest = vc::verify_state_root_against_snapshot(&state_root, &snapshot, &proof)
        .expect("snapshot digest must be the commitment leaf of the engine root");
    assert_eq!(digest, snapshot.digest());

    vc::verify_state_root_full(&state_root, &snapshot, &account_leaves)
        .expect("the full leaf set must rebuild the engine root");

    // Flip one byte of a digest-domain preimage: the digest moves, so the
    // proof no longer authenticates it and the full rebuild disagrees too.
    let mut tampered = snapshot.clone();
    tampered.governance.push(0x01);
    assert_ne!(tampered.digest(), snapshot.digest());
    assert!(vc::verify_state_root_against_snapshot(&state_root, &tampered, &proof).is_err());
    assert!(vc::verify_state_root_full(&state_root, &tampered, &account_leaves).is_err());

    // A different state root is refused as well.
    let mut wrong_root = state_root;
    wrong_root[0] ^= 0x80;
    assert!(vc::verify_state_root_against_snapshot(&wrong_root, &snapshot, &proof).is_err());
}

#[test]
fn full_root_rebuild_matches_reference_trie() {
    let mut snapshot = vc::VerifierCommitmentSnapshot::new();
    snapshot.tokens = vec![0xAA, 0xBB, 0xCC];

    let mut trie = refcpat::CompressedTrie::new();
    let mut leaves = Vec::new();
    for i in 0..48u64 {
        let key = trie_key(i.wrapping_mul(7_919));
        let value = format!("account-{i}").into_bytes();
        trie.insert(&key, &value);
        leaves.push((key, value));
    }
    let digest = snapshot.digest();
    trie.insert(&refc::commitment_key(), &digest);
    let root = trie.root_hash();

    vc::verify_state_root_full(&root, &snapshot, &leaves).expect("rebuild must match the trie");

    let mut wrong_root = root;
    wrong_root[31] ^= 0x01;
    assert!(vc::verify_state_root_full(&wrong_root, &snapshot, &leaves).is_err());

    // Two values for one trie key are ambiguous, so they are refused.
    let mut duplicate = leaves.clone();
    duplicate.push(leaves[0].clone());
    assert!(vc::verify_state_root_full(&root, &snapshot, &duplicate).is_err());

    // The commitment value comes from the snapshot, never from the caller.
    let mut commitment_clash = leaves.clone();
    commitment_clash.push((refc::commitment_key(), vec![0u8; 32]));
    assert!(vc::verify_state_root_full(&root, &snapshot, &commitment_clash).is_err());
}

#[test]
fn all_17_domains_digest_and_engine_state_root_parity() {
    let engine = InMemoryStateEngine::new();

    // Populate all 5 additional domains beyond the original 12:
    // 1. total_minted_nano (via mint_native)
    let addr = [0xA1u8; 32];
    block_on(engine.mint_native(&addr, 500_000)).expect("mint_native");
    assert_ne!(engine.total_minted_nano(), 0);

    // 2. zkml (domain 13)
    let model =
        stellereum::zkml::QuantizedLinearModel::new(vec![stellereum::zkml::QuantizedLayer::new(
            2,
            1,
            vec![3, -1],
            vec![5],
        )]);
    block_on(async {
        let mut zkml = engine.zkml_models_write().await;
        zkml.register([0x12u8; 32], model)
            .expect("register zkml model");
    });

    // 3. cnvrf (domain 14)
    block_on(async {
        let mut cn = engine.cnvrf_v3_write().await;
        cn.rolling_mix = [0x44u8; 48];
        cn.rolling_mix_epoch = 2;
        cn.epoch_rolling_mixes.insert(1, vec![0x33u8; 48]);
        let mut beacons = engine.epoch_vdf_beacons_write().await;
        beacons.insert(1, [0x55u8; 48]);
    });

    // 4. evm_bindings (domain 16)
    block_on(async {
        let mut evm = engine.evm_bindings_write().await;
        evm.bind([0x22u8; 20], [0xA1u8; 32])
            .expect("bind evm address");
    });

    // 5. pq_registry (domain 17)
    let kp = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
    block_on(async {
        let mut pq = engine.pq_registry_write().await;
        pq.register_with_seq(
            [0x88u8; 32],
            stellereum::post_quantum::PqScheme::Falcon512,
            kp.public_key().to_vec(),
            1,
            0,
            0,
            true,
        )
        .expect("register pq key");
    });

    let state_root = block_on(engine.get_state_root());
    let vsnap = assemble_from_engine(&engine);

    let ref_snap = block_on(engine.commitment_snapshot());
    let ref_zkml = block_on(engine.zkml_models_read()).clone();
    let ref_cnvrf = block_on(engine.cnvrf_v3_snapshot());
    let ref_evm = block_on(engine.evm_bindings_read()).clone();
    let ref_pq = block_on(engine.pq_registry_read()).clone();
    let ref_digest = refc::commitment_digest_with_all_domains(
        &ref_snap,
        &ref_zkml,
        &ref_cnvrf,
        engine.total_minted_nano(),
        &ref_evm,
        &ref_pq,
    );
    assert_eq!(
        vsnap.digest(),
        ref_digest,
        "17-domain VerifierCommitmentSnapshot::digest must match commitment_digest_with_all_domains bit-for-bit"
    );

    let (reference_proof, account_leaves) = block_on(async {
        let trie = engine.state_trie.read().await;
        let proof = trie
            .compressed()
            .generate_proof(&vc::commitment_key())
            .expect("commitment proof");
        let leaves = trie
            .compressed()
            .entries
            .iter()
            .filter(|(key, _)| **key != vc::commitment_key())
            .map(|(key, value)| (*key, value.clone()))
            .collect::<Vec<_>>();
        (proof, leaves)
    });
    let proof = convert(&reference_proof);

    let verified_digest = vc::verify_state_root_against_snapshot(&state_root, &vsnap, &proof)
        .expect("all 17 domains must verify against live engine state_root");
    assert_eq!(verified_digest, ref_digest);
    vc::verify_state_root_full(&state_root, &vsnap, &account_leaves)
        .expect("full trie rebuild with all 17 domains must match live engine state_root");

    // Mutating any of the 5 newly folded domains must fail verification.
    let mut bad = vsnap.clone();
    bad.total_minted_nano += 1;
    assert!(vc::verify_state_root_against_snapshot(&state_root, &bad, &proof).is_err());

    let mut bad = vsnap.clone();
    bad.zkml[0] ^= 0x01;
    assert!(vc::verify_state_root_against_snapshot(&state_root, &bad, &proof).is_err());

    let mut bad = vsnap.clone();
    bad.cnvrf[0] ^= 0x01;
    assert!(vc::verify_state_root_against_snapshot(&state_root, &bad, &proof).is_err());

    let mut bad = vsnap.clone();
    bad.evm_bindings[0] ^= 0x01;
    assert!(vc::verify_state_root_against_snapshot(&state_root, &bad, &proof).is_err());

    let mut bad = vsnap.clone();
    bad.pq_registry[0] ^= 0x01;
    assert!(vc::verify_state_root_against_snapshot(&state_root, &bad, &proof).is_err());
}
