//! Light-client offline CLI (8.0): anchor show, header verify, rotation.
//!
//! All fixtures live in per-test temp dirs; no network is touched. Every
//! quorum certificate is really signed (genuine Falcon `fvote`s compiled by
//! `VoteSet::certificate`), so a
//! sub-quorum or stale-set fixture fails for the same reason it would live:
//! not enough genuine old-set power behind the point.

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};
use stellereum::consensus::{
    register_validator_pq_key, QuorumCertificate, ValidatorId, ValidatorSet, VoteKind, VoteSet,
};
use stellereum::light_client::{Checkpoint, LightClient, LightHeader};
use stellereum::light_client_cli::{
    anchor_show, load_checkpoint_file, load_rotation_proof_file, rotate_anchor, verify_header_file,
};
use stellereum::post_quantum::{FalconKeypair, PqScheme};

// This file uses `fvote` with file-local keys (`pq_for` below); `falcon_set`
// in the shared helper covers the fixed-seed case and is unused here.
#[allow(dead_code)]
#[path = "support/falcon_votes.rs"]
mod falcon_votes;

fn test_keys(start: u8, n: u8) -> Vec<SigningKey> {
    (start..start + n)
        .map(|i| SigningKey::from_bytes(&[i; 32]))
        .collect()
}

fn ids_of(keys: &[SigningKey]) -> Vec<ValidatorId> {
    keys.iter().map(|k| k.verifying_key().to_bytes()).collect()
}

fn qc_from(
    keys: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
    height: u64,
    block_hash: [u8; 32],
    parent: &[u8; 32],
) -> QuorumCertificate {
    // Genuine committee-compiled QC against the full set `vs`, bound to
    // `parent`; below quorum (or non-member signers) falls through to the
    // envelope-less shape, unconditionally invalid under FULL-PQ.
    let mut set = VoteSet::new();
    let mut ed_sigs = Vec::new();
    for (k, fk) in keys.iter().zip(fks.iter()) {
        let v = falcon_votes::fvote(k, fk, height, 0, VoteKind::Precommit, Some(block_hash));
        if set
            .add(v.clone(), vs, height, 0, VoteKind::Precommit)
            .is_ok()
        {
            ed_sigs.push((v.voter, v.ed25519_signature().to_vec()));
        }
    }
    if let Some(qc) = set.certificate(Some(block_hash), vs, parent) {
        return qc;
    }
    QuorumCertificate {
        shard_id: 0,
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(block_hash),
        signatures: ed_sigs,
    }
}

/// Falcon companions for file-local Ed keys, registered globally like
/// `falcon_set` does. `tag` separates Falcon-key domains so fixtures sharing
/// one test binary never collide.
fn pq_for(keys: &[SigningKey], tag: u8) -> Vec<FalconKeypair> {
    keys.iter()
        .enumerate()
        .map(|(i, k)| {
            let fk = FalconKeypair::generate_from_seed(tag.wrapping_add(i as u8));
            register_validator_pq_key(
                k.verifying_key().to_bytes(),
                PqScheme::Falcon512,
                fk.public_key.clone(),
            );
            fk
        })
        .collect()
}

fn full_set(keys: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn fresh_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "stell-light-cli-{}-{}-{}",
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

fn write_validators_file(dir: &Path, ids: &[ValidatorId]) -> PathBuf {
    let entries: Vec<serde_json::Value> = ids
        .iter()
        .map(|id| serde_json::json!({"validator": hex::encode(id), "power": 1u64}))
        .collect();
    let doc = serde_json::json!({"validators": entries});
    let path = dir.join("validators.json");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("json")).expect("write");
    path
}

fn write_json_file(dir: &Path, name: &str, value: &impl serde::Serialize) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string_pretty(value).expect("json")).expect("write");
    path
}

fn anchor_fixture(
    dir: &Path,
    keys: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
) -> (PathBuf, PathBuf, Checkpoint) {
    let ids = ids_of(keys);
    let validators_path = write_validators_file(dir, &ids);
    let block_hash = [0x11u8; 32];
    let state_root = [0xAAu8; 32];
    let cert = qc_from(&keys[..3], &fks[..3], vs, 1, block_hash, &[0u8; 32]);
    let checkpoint = Checkpoint::new(1, block_hash, [0u8; 32], state_root, cert);
    let checkpoint_path = write_json_file(dir, "checkpoint.json", &checkpoint);
    (validators_path, checkpoint_path, checkpoint)
}

// GATE: fixture helper threads parallel signer/key/set slices plus the header
// fields the QC binds; splitting it would obscure the call sites.
#[allow(clippy::too_many_arguments)]
fn header_at(
    height: u64,
    prev_hash: [u8; 32],
    block_hash: [u8; 32],
    state_root: [u8; 32],
    proposer: ValidatorId,
    signers: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
) -> LightHeader {
    LightHeader {
        height,
        prev_hash,
        state_root,
        block_hash,
        timestamp: 1_700_000_000 + height,
        proposer,
        cert: qc_from(signers, fks, vs, height, block_hash, &prev_hash),
        signatures: Vec::new(),
        shard_id: 0,
        round: 0,
        body_commitment: None,
        mmr_epoch_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    }
}

fn write_rotation_file(
    dir: &Path,
    name: &str,
    rotation: &LightHeader,
    next_ids: &[ValidatorId],
) -> PathBuf {
    let entries: Vec<serde_json::Value> = next_ids
        .iter()
        .map(|id| serde_json::json!({"validator": hex::encode(id), "power": 1u64}))
        .collect();
    let doc = serde_json::json!({"rotation": rotation, "next_set": {"validators": entries}});
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_string_pretty(&doc).expect("json")).expect("write");
    path
}

#[test]
fn anchor_show_reports_height_and_set_hash() {
    let keys = test_keys(1, 4);
    let fks = pq_for(&keys, 0x81);
    let vs = full_set(&keys);
    let dir = fresh_dir("anchor-show");
    let (validators_path, checkpoint_path, checkpoint) = anchor_fixture(&dir, &keys, &fks, &vs);
    let report = anchor_show(&validators_path, &checkpoint_path).expect("anchor show");
    assert!(report.contains("anchor height: 1"), "report: {report}");
    assert!(
        report.contains(&hex::encode(checkpoint.block_hash)),
        "report: {report}"
    );
    assert!(
        report.contains(&hex::encode(checkpoint.state_root)),
        "report: {report}"
    );
    let set = stellereum::light_client_cli::load_validator_set(&validators_path).expect("set");
    let digest = hex::encode(stellereum::light_client_cli::validator_set_digest(&set));
    assert!(report.contains(&digest), "report: {report}");
    let loaded = load_checkpoint_file(&checkpoint_path).expect("reload");
    assert_eq!(loaded, checkpoint);
}

#[test]
fn verify_accepts_valid_successor_header() {
    let keys = test_keys(11, 4);
    let fks = pq_for(&keys, 0x8B);
    let vs = full_set(&keys);
    let dir = fresh_dir("verify-valid");
    let (validators_path, checkpoint_path, checkpoint) = anchor_fixture(&dir, &keys, &fks, &vs);
    let header = header_at(
        2,
        checkpoint.block_hash,
        [0x22u8; 32],
        [0xBBu8; 32],
        ids_of(&keys)[0],
        &keys[..3],
        &fks[..3],
        &vs,
    );
    let header_path = write_json_file(&dir, "header.json", &header);
    let report = verify_header_file(&validators_path, &checkpoint_path, &header_path)
        .expect("valid header must verify");
    assert!(report.contains("height 2"), "report: {report}");
}

#[test]
fn verify_refuses_subquorum_header() {
    let keys = test_keys(21, 4);
    let fks = pq_for(&keys, 0x95);
    let vs = full_set(&keys);
    let dir = fresh_dir("verify-invalid");
    let (validators_path, checkpoint_path, checkpoint) = anchor_fixture(&dir, &keys, &fks, &vs);
    // Only one of four signers: 1 power of the 3-power quorum.
    let header = header_at(
        2,
        checkpoint.block_hash,
        [0x22u8; 32],
        [0xBBu8; 32],
        ids_of(&keys)[0],
        &keys[..1],
        &fks[..1],
        &vs,
    );
    let header_path = write_json_file(&dir, "header.json", &header);
    let err = verify_header_file(&validators_path, &checkpoint_path, &header_path)
        .expect_err("sub-quorum header must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("REFUSED"),
        "fail-closed refusal expected, got: {msg}"
    );
}

#[test]
fn rotate_accepts_supermajority_rotation() {
    let old_keys = test_keys(31, 4);
    let old_fks = pq_for(&old_keys, 0x9F);
    let old_vs = full_set(&old_keys);
    let new_keys = test_keys(41, 4);
    let dir = fresh_dir("rotate-valid");
    let (validators_path, checkpoint_path, checkpoint) =
        anchor_fixture(&dir, &old_keys, &old_fks, &old_vs);
    let new_ids = ids_of(&new_keys);
    let rotation_header = header_at(
        2,
        checkpoint.block_hash,
        [0x33u8; 32],
        [0xCCu8; 32],
        ids_of(&old_keys)[0],
        &old_keys[..3],
        &old_fks[..3],
        &old_vs,
    );
    let rotation_path = write_rotation_file(&dir, "rotation.json", &rotation_header, &new_ids);
    let loaded = load_rotation_proof_file(&rotation_path).expect("reload");
    assert_eq!(loaded.effective_height(), 2);
    let report = rotate_anchor(&validators_path, &checkpoint_path, &rotation_path)
        .expect("supermajority rotation must apply");
    assert!(report.contains("height 2"), "report: {report}");
}

#[test]
fn rotate_refuses_subquorum_rotation() {
    let old_keys = test_keys(51, 4);
    let old_fks = pq_for(&old_keys, 0xB3);
    let old_vs = full_set(&old_keys);
    let new_keys = test_keys(61, 4);
    let dir = fresh_dir("rotate-subquorum");
    let (validators_path, checkpoint_path, checkpoint) =
        anchor_fixture(&dir, &old_keys, &old_fks, &old_vs);
    let new_ids = ids_of(&new_keys);
    // A single old signer backs the point: not a supermajority of old power.
    let rotation_header = header_at(
        2,
        checkpoint.block_hash,
        [0x33u8; 32],
        [0xCCu8; 32],
        ids_of(&old_keys)[0],
        &old_keys[..1],
        &old_fks[..1],
        &old_vs,
    );
    let rotation_path = write_rotation_file(&dir, "rotation.json", &rotation_header, &new_ids);
    let err = rotate_anchor(&validators_path, &checkpoint_path, &rotation_path)
        .expect_err("sub-quorum rotation must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("REFUSED"),
        "fail-closed refusal expected, got: {msg}"
    );
}

#[test]
fn rotated_client_refuses_stale_set_header() {
    let old_keys = test_keys(71, 4);
    let old_fks = pq_for(&old_keys, 0xC7);
    let old_vs = full_set(&old_keys);
    let new_keys = test_keys(81, 4);
    let new_vs = full_set(&new_keys);
    let dir = fresh_dir("stale-set");
    let (validators_path, checkpoint_path, checkpoint) =
        anchor_fixture(&dir, &old_keys, &old_fks, &old_vs);
    let new_ids = ids_of(&new_keys);
    let rotation_header = header_at(
        2,
        checkpoint.block_hash,
        [0x33u8; 32],
        [0xCCu8; 32],
        ids_of(&old_keys)[0],
        &old_keys[..3],
        &old_fks[..3],
        &old_vs,
    );
    let rotation_path = write_rotation_file(&dir, "rotation.json", &rotation_header, &new_ids);
    // The CLI helper applies the rotation fail-closed first.
    rotate_anchor(&validators_path, &checkpoint_path, &rotation_path).expect("rotation must apply");
    // Replay the same evidence through the library: after the rotation the
    // NEW set is the only authority, so a header certified only by the OLD
    // set at height 3 is refused.
    let set = stellereum::light_client_cli::load_validator_set(&validators_path).expect("set");
    let anchor = load_checkpoint_file(&checkpoint_path).expect("anchor");
    let mut client = LightClient::new(set, anchor).expect("client");
    let proof = load_rotation_proof_file(&rotation_path).expect("proof");
    client.rotate_validator_set(proof).expect("rotate");
    assert_eq!(client.validator_set_height(), 2);
    let stale = header_at(
        3,
        rotation_header.block_hash,
        [0x44u8; 32],
        [0xDDu8; 32],
        ids_of(&old_keys)[0],
        &old_keys[..3],
        &old_fks[..3],
        &new_vs,
    );
    let err = client
        .apply_header(stale)
        .expect_err("stale-set header must be refused");
    assert!(
        err.contains("rejected") || err.contains("refusing") || err.contains("power"),
        "fail-closed refusal expected, got: {err}"
    );
    let _ = checkpoint;
}
