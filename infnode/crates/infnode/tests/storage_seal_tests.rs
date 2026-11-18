//! Storage confidentiality pinning (`docs/REVIEW_QUALITY.md` 1.1).
//!
//! The old bucket path derived its XChaCha20 key+nonce from PUBLIC data
//! (`bucket:name:H(plaintext)`), so anyone holding the manifest and the chunks
//! could decrypt. These tests pin the two guarantees we now claim:
//!
//! 1. `store_blob_boxed(.., Some(owner_ek))` seals the payload to the owner's
//!    ML-KEM-768 key: a non-owner with the FULL stored blob (manifest + every
//!    chunk) cannot decrypt it, while the owner can (`fetch_blob_owner`).
//! 2. `store_blob` (no owner key) remains at-rest OBFUSCATION, not encryption:
//!    its key is publicly derivable and a third party CAN decrypt it. That test
//!    exists so nobody re-labels the legacy path as E2E confidentiality.

use infnode::config::NodeConfig;
use infnode::keyring::{NodeKeys, PqKeys};
use infnode::mailbox::MailKeys;
use infnode::node::{
    blob_content_hash, blob_key_nonce, blob_seal_aad, box_unwrap_key, e2e_decrypt, e2e_decrypt_aad,
    Node, BLOB_SEAL_V1,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn cfg() -> NodeConfig {
    NodeConfig {
        name: "storage-seal-test".to_string(),
        listen: "127.0.0.1:0".to_string(),
        client_listen: None,
        advertise: None,
        peers: vec![],
        allow_unknown: false,
        unknown_allow: vec![],
        metrics_listen: None,
        log_level: Some(0),
        roles: Default::default(),
        outbox_ttl_secs: 3600,
        storage_roles: vec![],
        validators: vec![],
        domain: None,
        web_listen: None,
        wallet: None,
        web_static: None,
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("infnode-seal-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

async fn test_node(tag: &str) -> (Arc<Node>, PathBuf) {
    let dir = tmpdir(tag);
    let node = Node::new(
        cfg(),
        NodeKeys::generate(),
        PqKeys::generate(),
        dir.clone(),
        PathBuf::new(),
    )
    .await
    .expect("node");
    (node, dir)
}

fn sample_blob(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// Everything a storage node / DHT peer can see: manifest JSON + the ciphertext
/// bytes of every chunk referenced by it.
async fn stored_blob(
    node: &Arc<Node>,
    data_dir: &Path,
    bucket: &str,
    name: &str,
) -> (Value, Vec<u8>) {
    let mkey = Node::blob_manifest_key(bucket, name);
    let raw = node
        .get_local_kv(&mkey)
        .await
        .expect("manifest in local KV");
    let manifest: Value = serde_json::from_str(&raw).expect("manifest");
    let dir = data_dir.join("chunks").join(bucket);
    let mut ct = Vec::new();
    for c in manifest["chunks"].as_array().expect("chunks") {
        let id = c["id"].as_str().expect("chunk id");
        ct.extend_from_slice(&std::fs::read(dir.join(id)).expect("chunk on disk"));
    }
    (manifest, ct)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_sealed_blob_is_not_decryptable_by_a_non_owner() {
    let (node, dir) = test_node("owner-seal").await;
    let owner = MailKeys::generate();
    let attacker = MailKeys::generate();
    let blob = sample_blob(3000);

    let owner_ek_hex = hex::encode(&owner.kem_ek);
    let owner_seed_hex = hex::encode(owner.kem_seed);
    let attacker_seed_hex = hex::encode(attacker.kem_seed);

    let stored = node
        .store_blob_boxed("files", "secret.bin", &blob, Some(&owner_ek_hex))
        .await;
    assert!(stored > 0, "owner-sealed store must persist chunks");

    let (manifest, ct) = stored_blob(&node, &dir, "files", "secret.bin").await;
    assert_eq!(
        manifest["seal"].as_str(),
        Some(BLOB_SEAL_V1),
        "owner-sealed manifest must be marked"
    );
    assert!(
        manifest.get("key").is_none(),
        "owner-sealed manifest must NEVER carry a plaintext data key"
    );
    assert!(
        manifest["key_box"].is_object(),
        "data key must be wrapped to the owner's KEM key"
    );
    assert!(!ct.is_empty(), "full ciphertext is on disk");

    let content_hash = blob_content_hash(&blob);

    // 1. The exact break from the review: key derived from public data.
    let (public_key, public_nonce) = blob_key_nonce("files", "secret.bin", &content_hash);
    assert!(
        e2e_decrypt(&public_key, &public_nonce, &ct).is_err(),
        "publicly derived key must NOT open an owner-sealed blob"
    );

    // 2. A third party with their own ML-KEM key cannot unwrap key_box.
    assert!(
        box_unwrap_key(&manifest["key_box"], &attacker_seed_hex).is_err(),
        "key_box must only open with the owner's KEM seed"
    );

    // 3. Even the OWNER's data key fails on a different AAD (bucket/name/content
    //    binding): a blob moved to another bucket is not confidential material
    //    that decrypts elsewhere.
    let owner_data_key = box_unwrap_key(&manifest["key_box"], &owner_seed_hex).expect("owner box");
    let nonce = hex::decode(manifest["nonce"].as_str().expect("nonce")).expect("hex nonce");
    assert!(
        e2e_decrypt(&owner_data_key, &nonce, &ct).is_err(),
        "sealed blob must not open with empty AAD"
    );
    assert!(
        e2e_decrypt_aad(
            &owner_data_key,
            &nonce,
            &blob_seal_aad("other-bucket", "secret.bin", &content_hash),
            &ct
        )
        .is_err(),
        "sealed blob must not open under a different bucket/name/content AAD"
    );

    // 4. The public fetch API refuses to guess: no owner key => None.
    assert!(
        node.fetch_blob("files", "secret.bin").await.is_none(),
        "fetch_blob must not return owner-sealed data without the owner key"
    );
    // 5. A non-owner using the owner API is refused too.
    assert!(
        node.fetch_blob_owner("files", "secret.bin", &attacker_seed_hex)
            .await
            .is_none(),
        "a non-owner must not decrypt even with the full blob"
    );
    // 6. The owner (possessor of the ML-KEM seed) reads it back intact.
    assert_eq!(
        node.fetch_blob_owner("files", "secret.bin", &owner_seed_hex)
            .await
            .expect("owner fetch"),
        blob
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_public_key_path_is_obfuscation_not_encryption() {
    let (node, dir) = test_node("legacy-obfuscation").await;
    let blob = sample_blob(2500);

    let stored = node.store_blob("files", "public.bin", &blob).await;
    assert!(stored > 0);

    let (manifest, ct) = stored_blob(&node, &dir, "files", "public.bin").await;
    assert!(
        manifest.get("seal").is_none(),
        "unboxed store_blob is the legacy format"
    );

    // The manifest publishes the data key...
    let published = hex::decode(manifest["key"].as_str().expect("legacy key")).expect("hex key");
    assert_eq!(published.len(), 32);

    // ...and that key is reproducible from public inputs alone, i.e. a third
    // party decrypts the full stored blob. This is the documented guarantee:
    // at-rest obfuscation, NOT confidentiality/E2E.
    let (derived_key, derived_nonce) =
        blob_key_nonce("files", "public.bin", &blob_content_hash(&blob));
    assert_eq!(published, derived_key, "legacy key is public derivation");
    assert_eq!(
        e2e_decrypt(&derived_key, &derived_nonce, &ct).expect("third party decrypts"),
        blob,
        "legacy path is obfuscation only; never advertise it as encryption"
    );

    // It still round-trips for existing data.
    assert_eq!(
        node.fetch_blob("files", "public.bin").await.expect("fetch"),
        blob
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_owner_key_fails_closed_instead_of_storing_a_plaintext_key() {
    let (node, dir) = test_node("invalid-owner").await;
    let blob = b"must not be stored under a downgraded key".to_vec();

    let stored = node
        .store_blob_boxed("files", "downgrade.bin", &blob, Some("deadbeef"))
        .await;
    assert_eq!(stored, 0, "invalid owner ek must be refused");
    assert!(
        node.get_local_kv(&Node::blob_manifest_key("files", "downgrade.bin"))
            .await
            .is_none(),
        "no manifest may be written on a refused owner-sealed store"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_sealed_fetch_rejects_tampered_chunk() {
    let (node, dir) = test_node("seal-tamper").await;
    let owner = MailKeys::generate();
    let owner_ek_hex = hex::encode(&owner.kem_ek);
    let owner_seed_hex = hex::encode(owner.kem_seed);
    let blob = sample_blob(1800);

    node.store_blob_boxed("files", "tamper.bin", &blob, Some(&owner_ek_hex))
        .await;
    let (mut manifest, _) = stored_blob(&node, &dir, "files", "tamper.bin").await;
    let first_id = manifest["chunks"][0]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let path = dir.join("chunks").join("files").join(&first_id);
    let mut raw = std::fs::read(&path).expect("chunk");
    raw[0] ^= 0x80;
    std::fs::write(&path, &raw).expect("tamper write");

    // Make the manifest agree with the tampered bytes, so the refusal below is
    // the AEAD layer (not merely the plaintext-chunk-hash check). The background
    // replication task may restore the original chunk in parallel; then the
    // (patched) manifest hash mismatches instead. Both outcomes are fail-closed,
    // which is exactly the property this test pins.
    manifest["chunks"][0]["hash"] = serde_json::json!(hex::encode(blake3::hash(&raw).as_bytes()));
    node.kv_store_local_with_ttl(
        &Node::blob_manifest_key("files", "tamper.bin"),
        &manifest.to_string(),
        30 * 24 * 3600 * 1000,
    )
    .await;

    assert!(
        node.fetch_blob_owner("files", "tamper.bin", &owner_seed_hex)
            .await
            .is_none(),
        "tampered ciphertext must fail closed (chunk hash / AEAD)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
