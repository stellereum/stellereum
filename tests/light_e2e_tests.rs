//! Light-client end-to-end third-party verify flow (light 8.0 -> 9.0, no network).
//!
//! This is the `docs/program/LIGHT_CLIENT_VERIFY.md` recipe executed in-test
//! against fixture validator sets instead of a live network:
//!
//! 1. pin the genesis validator set out-of-band (4 validators, power 1 each,
//!    quorum 3) and bootstrap a [`LightClient`] from the GENESIS anchor;
//! 2. follow N headers ([`LightClient::apply_header`]) under the genesis set;
//! 3. apply a rotation event ([`LightClient::rotate_validator_set`]) whose
//!    point carries a supermajority QC of the OLD set, installing the new set;
//! 4. keep following under the NEW set;
//! 5. prove a balance/state proof ([`LightClient::verify_proof_answer`], the
//!    lib-level `stell_getProof` equivalent) under the new anchor;
//! 6. refuse every forgery class fail-closed (bad QC, stale set, forked
//!    header, rolled-back anchor);
//! 7. anchor export/import round-trip: serialize the anchor, bootstrap a fresh
//!    client from it (via the offline CLI file helpers), and re-verify the
//!    same proof there.
//!
//! Every quorum certificate is really signed (ed25519 [`Vote::sign`]), so a
//! forgery fails for the same reason it would live: not enough genuine power
//! from the set in force behind the point. All fixtures live in per-test temp
//! dirs; no network is touched; everything is deterministic.

use ed25519_dalek::SigningKey;
use stellereum::consensus::{QuorumCertificate, ValidatorId, ValidatorSet, Vote, VoteKind};
use stellereum::light_client::{
    Checkpoint, GenesisAnchor, LightAnchor, LightClient, LightHeader, ProofAnswer,
    StorageProofAnswer, ValidatorSetRotation,
};
use std::path::{Path, PathBuf};

// ============================================================================
// Fixtures (same idiom as `light_cli_tests.rs`)
// ============================================================================

fn test_keys(start: u8, n: u8) -> Vec<SigningKey> {
    (start..start + n)
        .map(|i| SigningKey::from_bytes(&[i; 32]))
        .collect()
}

fn ids_of(keys: &[SigningKey]) -> Vec<ValidatorId> {
    keys.iter().map(|k| k.verifying_key().to_bytes()).collect()
}

fn set_of(keys: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ids_of(keys).iter().map(|id| (*id, 1u64)).collect())
}

fn qc_from(keys: &[SigningKey], height: u64, block_hash: [u8; 32]) -> QuorumCertificate {
    let votes: Vec<(ValidatorId, Vec<u8>)> = keys
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(block_hash));
            (v.voter, v.signature)
        })
        .collect();
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures: votes,
    }
}

/// Deterministic opaque block identity for the fixture chain.
fn block_hash(height: u64, prev: &[u8; 32], root: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&height.to_le_bytes());
    h.update(prev);
    h.update(root);
    *h.finalize().as_bytes()
}

fn header_at(
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    proposer: ValidatorId,
    signers: &[SigningKey],
) -> LightHeader {
    let hash = block_hash(height, &prev_hash, &state_root);
    LightHeader {
        height,
        prev_hash,
        state_root,
        block_hash: hash,
        timestamp: 1_700_000_000 + height,
        proposer,
        cert: qc_from(signers, height, hash),
        signatures: Vec::new(),
    }
}

fn account_leaf(balance: u64, nonce: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&balance.to_be_bytes());
    v.extend_from_slice(&nonce.to_be_bytes());
    v
}

fn fresh_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stell-light-e2e-{}-{}-{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn write_json_file(dir: &Path, name: &str, value: &impl serde::Serialize) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(
        &path,
        serde_json::to_string_pretty(value).expect("json"),
    )
    .expect("write");
    path
}

fn write_validators_file(dir: &Path, name: &str, ids: &[ValidatorId]) -> PathBuf {
    let entries: Vec<serde_json::Value> = ids
        .iter()
        .map(|id| serde_json::json!({"validator": hex::encode(id), "power": 1u64}))
        .collect();
    write_json_file(dir, name, &serde_json::json!({"validators": entries}))
}

/// Build the `stell_getProof` answer a node would serve for `trie`.
fn proof_answer_for(
    trie: &stellereum::cpat2::CompressedTrie,
    address: &[u8; 32],
    storage: &[([u8; 32], Option<Vec<u8>>)],
) -> ProofAnswer {
    let account_proof = trie
        .generate_proof(address)
        .or_else(|| trie.generate_exclusion_proof(address))
        .expect("account proof");
    let (balance, nonce) = match account_proof.kind {
        stellereum::cpat2::ProofKind::Inclusion => {
            let v = &account_proof.value;
            (
                u64::from_be_bytes(v[..8].try_into().expect("balance")),
                u64::from_be_bytes(v[8..16].try_into().expect("nonce")),
            )
        }
        stellereum::cpat2::ProofKind::Exclusion => (0, 0),
    };
    let storage_proofs = storage
        .iter()
        .map(|(k, want)| {
            let p = trie
                .generate_proof(k)
                .or_else(|| trie.generate_exclusion_proof(k))
                .expect("storage proof");
            StorageProofAnswer {
                key: *k,
                value: want.clone(),
                exists: want.is_some(),
                proof: p.to_nodes(),
            }
        })
        .collect();
    ProofAnswer {
        address: *address,
        balance,
        nonce,
        account_proof: account_proof.to_nodes(),
        storage_proofs,
        state_root: trie.root_hash(),
        height: None,
    }
}

// ============================================================================
// Shared chain scaffold: genesis -> h1..h3 (old set) -> h4 rotation ->
// h5..h6 (new set), with an evolving state trie.
// ============================================================================

const ACCOUNT: [u8; 32] = [0xABu8; 32];
const SLOT: [u8; 32] = [0xCDu8; 32];
const MISSING: [u8; 32] = [0xEEu8; 32];

struct E2eChain {
    old_keys: Vec<SigningKey>,
    new_keys: Vec<SigningKey>,
    old_set: ValidatorSet,
    new_set: ValidatorSet,
    client: LightClient,
    roots: Vec<[u8; 32]>,
    tip: LightHeader,
    answer: ProofAnswer,
}

fn build_chain() -> E2eChain {
    let old_keys = test_keys(1, 4);
    let new_keys = test_keys(101, 4);
    let old_set = set_of(&old_keys);
    let new_set = set_of(&new_keys);

    // --- state evolution --------------------------------------------------
    let mut trie = stellereum::cpat2::CompressedTrie::new();
    trie.insert(&ACCOUNT, &account_leaf(1_000_000, 0));
    let r0 = trie.root_hash();

    // --- step 1: genesis set pinned out-of-band ---------------------------
    assert_eq!(old_set.len(), 4, "genesis set must hold 4 validators");
    assert_eq!(old_set.total_power(), 4);
    assert_eq!(old_set.quorum_power(), 3, "quorum of 4x1-power is 3");

    // --- step 2: anchor at genesis ----------------------------------------
    let genesis = GenesisAnchor {
        height: 0,
        block_hash: [0u8; 32],
        parent_hash: [0u8; 32],
        state_root: r0,
    };
    let mut client =
        LightClient::with_genesis_anchor(old_set.clone(), genesis).expect("genesis anchor");
    assert_eq!(client.tip_height(), 0);
    assert!(client.trusts_root(&r0));

    let proposer = ids_of(&old_keys)[0];
    let mut prev = [0u8; 32];

    // --- step 3: follow N=3 headers under the genesis set -----------------
    // h1/h2 are no-op blocks (they repeat the parent root, which is legal);
    // h3 moves the state to r1.
    let h1 = header_at(1, prev, r0, proposer, &old_keys[..3]);
    client.apply_header(h1.clone()).expect("h1 must apply");
    prev = h1.block_hash;
    let h2 = header_at(2, prev, r0, proposer, &old_keys[1..4]);
    client.apply_header(h2.clone()).expect("h2 must apply");
    prev = h2.block_hash;
    trie.insert(&ACCOUNT, &account_leaf(750_000, 3));
    trie.insert(&SLOT, b"slot-v1");
    let r1 = trie.root_hash();
    let h3 = header_at(3, prev, r1, proposer, &old_keys[..3]);
    client.apply_header(h3.clone()).expect("h3 must apply");
    prev = h3.block_hash;
    assert_eq!(client.tip_height(), 3);

    // --- step 4: rotation event at h4 (old-set supermajority signs) -------
    trie.insert(&ACCOUNT, &account_leaf(600_000, 4));
    let r2 = trie.root_hash();
    let rotation = header_at(4, prev, r2, proposer, &old_keys[..3]);
    client
        .rotate_validator_set(ValidatorSetRotation::new(rotation.clone(), new_set.clone()))
        .expect("rotation must apply");
    assert_eq!(client.validator_set_height(), 4);
    prev = rotation.block_hash;

    // --- step 5: keep following under the NEW set --------------------------
    let new_proposer = ids_of(&new_keys)[0];
    let h5 = header_at(5, prev, r2, new_proposer, &new_keys[..3]);
    client.apply_header(h5.clone()).expect("h5 must apply");
    prev = h5.block_hash;
    trie.insert(&ACCOUNT, &account_leaf(500_000, 5));
    trie.insert(&SLOT, b"slot-v2");
    let r3 = trie.root_hash();
    let h6 = header_at(6, prev, r3, new_proposer, &new_keys[1..4]);
    client.apply_header(h6.clone()).expect("h6 must apply");
    assert_eq!(client.tip_height(), 6);
    assert_eq!(client.trusted_height_of_root(&r3), Some(6));

    // --- step 6: the proof the new anchor will verify ----------------------
    let answer = proof_answer_for(
        &trie,
        &ACCOUNT,
        &[
            (SLOT, Some(b"slot-v2".to_vec())),
            (MISSING, None),
        ],
    );
    assert_eq!(answer.state_root, r3);

    E2eChain {
        old_keys,
        new_keys,
        old_set,
        new_set,
        client,
        roots: vec![r0, r1, r2, r3],
        tip: h6,
        answer,
    }
}

// ============================================================================
// The end-to-end flow
// ============================================================================

#[test]
fn light_e2e_third_party_verify_flow() {
    // Steps 1-6: genesis set -> genesis anchor -> 3 headers -> rotation ->
    // 2 headers under the new set -> proof construction.
    let chain = build_chain();
    let client = &chain.client;
    eprintln!("step 1: genesis set pinned (4 validators, quorum 3)");
    eprintln!("step 2: genesis anchor bootstrapped at height 0");
    eprintln!("step 3: followed headers 1..=3 under the genesis set");
    eprintln!("step 4: rotation applied at height 4 (old-set supermajority QC)");
    eprintln!("step 5: followed headers 5..=6 under the new set");

    // Step 6: prove a balance/state proof under the new anchor.
    let proven = client
        .verify_proof_answer(&chain.answer)
        .expect("proof under the new anchor must verify");
    assert_eq!(proven.address, ACCOUNT);
    assert_eq!(proven.balance, 500_000, "proven balance must come from the leaf");
    assert_eq!(proven.nonce, 5);
    assert!(proven.exists);
    assert_eq!(proven.height, 6, "client reports the height IT finalized");
    assert_eq!(proven.state_root, chain.roots[3]);
    assert_eq!(proven.storage.len(), 2);
    assert!(proven.storage[0].exists);
    assert_eq!(proven.storage[0].value.as_deref(), Some(&b"slot-v2"[..]));
    assert!(!proven.storage[1].exists, "absence must be provable too");
    assert_eq!(proven.storage[1].value, None);
    eprintln!("step 6: balance/state proof verified at height 6 (incl. exclusion)");

    // Step 7: anchor export/import round-trip; a fresh client bootstraps
    // from the exported anchor and verifies the same proof.
    let dir = fresh_dir("e2e-anchor");
    let anchor_path = write_json_file(&dir, "anchor.json", client.anchor());
    let reloaded: LightAnchor =
        serde_json::from_str(&std::fs::read_to_string(&anchor_path).expect("read anchor"))
            .expect("anchor round-trip");
    assert_eq!(&reloaded, client.anchor(), "anchor must survive a round-trip");

    // Export the tip as a checkpoint file plus the NEW validator set file,
    // then bootstrap a fresh client purely from those files (the offline CLI
    // file helpers: read-only use of the CLI command layer).
    let tip_checkpoint = Checkpoint::of(&chain.tip);
    let checkpoint_path = write_json_file(&dir, "tip-checkpoint.json", &tip_checkpoint);
    let validators_path =
        write_validators_file(&dir, "new-validators.json", &ids_of(&chain.new_keys));
    let loaded_set =
        stellereum::light_client_cli::load_validator_set(&validators_path).expect("load set");
    let loaded_checkpoint =
        stellereum::light_client_cli::load_checkpoint_file(&checkpoint_path).expect("load cp");
    assert_eq!(loaded_checkpoint, tip_checkpoint);
    let fresh = LightClient::new(loaded_set, loaded_checkpoint).expect("fresh bootstrap");
    assert_eq!(fresh.tip_height(), 6);
    let reproven = fresh
        .verify_proof_answer(&chain.answer)
        .expect("fresh client must verify the same proof");
    assert_eq!(reproven.balance, 500_000);
    assert_eq!(reproven.height, 6);
    let show = stellereum::light_client_cli::anchor_show(&validators_path, &checkpoint_path)
        .expect("anchor show");
    assert!(show.contains("anchor height: 6"), "report: {show}");
    eprintln!("step 7: anchor round-trip ok; fresh client bootstrapped at height 6 and re-verified");

    eprintln!(
        "e2e complete: anchor=genesis(0) tip=6 rotation@4 proven_balance=500000 nonce=5"
    );
    let _ = chain.old_set;
    let _ = chain.new_set;
}

// ============================================================================
// Forgery classes: each must be refused fail-closed
// ============================================================================

#[test]
fn light_e2e_forgery_classes_refused() {
    let mut chain = build_chain();
    let tip_hash = chain.client.tip_hash();
    let new_proposer = ids_of(&chain.new_keys)[0];
    let old_proposer = ids_of(&chain.old_keys)[0];

    // 1. Bad QC: correct chaining, but only 1 of 4 new-set power signs
    //    (quorum is 3).
    let bad_qc = header_at(7, tip_hash, chain.roots[3], new_proposer, &chain.new_keys[..1]);
    let err = chain
        .client
        .apply_header(bad_qc)
        .expect_err("sub-quorum QC must be refused");
    assert!(
        err.contains("power"),
        "quorum failure must say why, got: {err}"
    );
    eprintln!("forgery 1 refused (bad QC): {err}");

    // 2. Stale set: correct chaining, quorum QC — but from the SUPERSEDED
    //    old set, which is no longer authoritative after height 4.
    let stale = header_at(7, tip_hash, chain.roots[3], old_proposer, &chain.old_keys[..3]);
    let err = chain
        .client
        .apply_header(stale)
        .expect_err("stale-set header must be refused");
    assert!(
        err.contains("outside") || err.contains("power") || err.contains("rejected"),
        "stale-set refusal must say why, got: {err}"
    );
    eprintln!("forgery 2 refused (stale set): {err}");

    // 3. Forked header: valid new-set QC, but the parent is not the tip.
    let forked = header_at(7, [0xF0u8; 32], chain.roots[3], new_proposer, &chain.new_keys[..3]);
    let err = chain
        .client
        .apply_header(forked)
        .expect_err("forked header must be refused");
    assert!(
        err.contains("fork"),
        "fork refusal must say why, got: {err}"
    );
    eprintln!("forgery 3 refused (forked header): {err}");

    // 4. Rolled-back anchor: a checkpoint older than the accepted tip whose
    //    QC genuinely verifies under the set in force, so the refusal comes
    //    from the ANCHOR gate (not from bad evidence).
    let rollback_hash = block_hash(3, &[0x99u8; 32], &chain.roots[1]);
    let rollback = Checkpoint::new(
        3,
        rollback_hash,
        [0x99u8; 32],
        chain.roots[1],
        qc_from(&chain.new_keys[..3], 3, rollback_hash),
    );
    rollback
        .verify(&chain.new_set)
        .expect("rollback QC itself verifies under the new set");
    let err = chain
        .client
        .advance_to_checkpoint(rollback)
        .expect_err("rolled-back anchor must be refused");
    assert!(
        err.contains("older than"),
        "rollback refusal must say why, got: {err}"
    );
    eprintln!("forgery 4 refused (rolled-back anchor): {err}");

    // The client is unmoved by all four attempts.
    assert_eq!(chain.client.tip_height(), 6);
    assert_eq!(chain.client.validator_set_height(), 4);
    chain
        .client
        .verify_proof_answer(&chain.answer)
        .expect("honest proof still verifies after refused forgeries");
    eprintln!("post-forgery: tip still 6, honest proof still verifies");
}
