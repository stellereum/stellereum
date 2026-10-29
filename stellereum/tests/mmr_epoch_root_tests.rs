//! V5 Tier-2 MMR epoch roots, end to end at the RPC boundary.
//!
//! A full epoch of finalized headers is recorded, `stell_getEpochRoot`
//! serves `{epoch, start_height, end_height, mmr_root, peaks}`, and the
//! light client checks the answer against the quorum-signed boundary
//! commitment and verifies an inclusion proof with it. An incomplete epoch
//! is served honestly (`complete: false`) and its proofs are refused; an
//! unknown epoch is an honest miss, never a fabrication.
//!
//! This binary touches the process-wide finalized-header store, so every
//! test uses its OWN epoch range — tests in one binary share a process.

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::sync::Arc;
use stellereum::consensus::{BlockHash, QuorumCertificate, Vote, VoteKind};
use stellereum::light_client::{verify_mmr_inclusion, EpochRootAnswer};
use stellereum::rpc::RpcState;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};

fn keys() -> Vec<SigningKey> {
    (0..4)
        .map(|i| SigningKey::from_bytes(&[i as u8 + 1; 32]))
        .collect()
}

/// A genuine 3-of-4 precommit QC over `hash` at `height`.
fn cert(signers: &[SigningKey], height: u64, hash: BlockHash) -> QuorumCertificate {
    let signatures = signers
        .iter()
        .map(|k| {
            let v = Vote::sign(k, height, 0, VoteKind::Precommit, Some(hash));
            (v.voter, v.signature)
        })
        .collect();
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(hash),
        signatures,
    }
}

fn test_state(tip: u64) -> Arc<RpcState> {
    let engine = Arc::new(stellereum::state_engine::InMemoryStateEngine::new());
    Arc::new(RpcState {
        engine,
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(std::sync::atomic::AtomicU64::new(tip)),
        node_id: "inf1:mmr-test".to_string(),
        chain_id: 777,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(Default::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        archive_store: None,
        msg_signing_seed: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    })
}

/// Record one finalized header per height in `range`, returning the block
/// hashes in height order.
async fn record_epoch(
    st: &Arc<RpcState>,
    ks: &[SigningKey],
    range: std::ops::RangeInclusive<u64>,
) -> Vec<BlockHash> {
    let mut hashes = Vec::new();
    let mut prev = [0u8; 32];
    for h in range {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: [(h % 251) as u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: ks[0].verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        let bh = b.compute_hash();
        b.precommit_qc = Some(cert(&ks[..3], h, bh));
        st.record_finalized_header(&b).await;
        prev = bh;
        hashes.push(bh);
    }
    hashes
}

fn ok_body(v: &Value) -> &Value {
    assert!(
        v.get("error").is_none(),
        "the RPC must serve the epoch root, got: {v}"
    );
    v
}

/// A complete epoch is served with the recomputed root, and the light
/// client verifies the answer plus an inclusion proof — anchored on the
/// quorum-signed boundary commitment.
#[tokio::test]
async fn stell_get_epoch_root_serves_a_complete_epoch_for_light_clients() {
    let ks = keys();
    let st = test_state(200);
    // Epoch 0: heights 0..=127 (this binary's range — no other test here
    // records these heights).
    let leaves = record_epoch(&st, &ks, 0..=127).await;
    let (expected_root, expected_peaks) = stellereum::mmr::mmr_root_for_leaves(&leaves);
    assert_eq!(expected_peaks.len(), 1, "128 leaves form a single mountain");

    // Before the boundary block exists there is no signed commitment yet.
    let before = st.call("stell_getEpochRoot", json!({ "epoch": 0 })).await;
    let before = ok_body(&before);
    assert_eq!(before["epoch"], 0);
    assert_eq!(before["start_height"], 0);
    assert_eq!(before["end_height"], 127);
    assert_eq!(before["mmr_root"], json!(hex::encode(expected_root)));
    assert_eq!(before["peaks"].as_array().unwrap().len(), 1);
    assert_eq!(before["complete"], true);
    assert_eq!(before["leaves"], 128);
    assert!(before["committed_root"].is_null(), "no boundary header yet");

    // The first block of epoch 1 commits the epoch-0 root (the quorum-signed
    // half of the Tier-2 promise).
    let mut boundary = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 128,
        prev_hash: leaves[127],
        state_root: [0x77u8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_128,
        proposer: ks[0].verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: expected_root,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    let boundary_hash = boundary.compute_hash();
    boundary.precommit_qc = Some(cert(&ks[..3], 128, boundary_hash));
    st.record_finalized_header(&boundary).await;

    let served = st.call("stell_getEpochRoot", json!({ "epoch": 0 })).await;
    let served = ok_body(&served);
    assert_eq!(served["committed_root"], json!(hex::encode(expected_root)));
    assert_eq!(served["committed_in_height"], 128);

    // The light-client half, reusing the RPC answer: the answer is
    // self-consistent, and a proof for a finalized leaf verifies under it.
    let answer = EpochRootAnswer::from_json(served).expect("the served JSON parses");
    assert_eq!(answer.mmr_root, expected_root);
    let m = stellereum::mmr::Mmr::of(&leaves);
    let proof = m.prove(5).expect("height 5 proves");
    assert_eq!(proof.leaf, leaves[5]);
    assert!(
        verify_mmr_inclusion(&answer, &proof).is_ok(),
        "a finalized leaf proves under the served epoch root"
    );
    // …while a proof for a hash that was never finalized does not.
    let mut forged = proof.clone();
    forged.leaf = [0xFFu8; 32];
    assert!(verify_mmr_inclusion(&answer, &forged).is_err());
}

/// Selectors: `{height}` names the containing epoch, a bare number is an
/// epoch, and an epoch this node knows nothing about is an honest miss.
#[tokio::test]
async fn stell_get_epoch_root_selectors_and_honest_misses() {
    let ks = keys();
    let st = test_state(900);
    // Epoch 7 (this binary's range): two headers only.
    record_epoch(&st, &ks, 896..=897).await;

    let by_height_raw = st
        .call("stell_getEpochRoot", json!({ "height": 897 }))
        .await;
    let by_height = ok_body(&by_height_raw);
    assert_eq!(by_height["epoch"], 7);
    assert_eq!(by_height["start_height"], 896);
    assert_eq!(by_height["end_height"], 1023);
    assert_eq!(by_height["complete"], false);
    assert_eq!(by_height["leaves"], 2);

    let bare_raw = st.call("stell_getEpochRoot", json!(7)).await;
    let bare = ok_body(&bare_raw);
    assert_eq!(bare["epoch"], 7);

    let missing = st.call("stell_getEpochRoot", json!({ "epoch": 9 })).await;
    assert!(
        missing.get("error").is_some(),
        "an unknown epoch must be refused, never fabricated: {missing}"
    );

    let no_selector = st.call("stell_getEpochRoot", json!({})).await;
    assert!(
        no_selector.get("error").is_some(),
        "a missing selector is refused"
    );
}

/// An incomplete epoch has no epoch root yet: the answer says so, and the
/// light client refuses proofs against it.
#[tokio::test]
async fn stell_get_epoch_root_marks_partial_epochs_and_proofs_refuse() {
    let ks = keys();
    let st = test_state(642);
    // Epoch 5 (this binary's range): three of 128 heights.
    let leaves = record_epoch(&st, &ks, 640..=642).await;

    let served_raw = st.call("stell_getEpochRoot", json!({ "epoch": 5 })).await;
    let served = ok_body(&served_raw);
    assert_eq!(served["complete"], false);
    assert_eq!(served["leaves"], 3);

    let answer = EpochRootAnswer::from_json(served).expect("parses");
    assert!(stellereum::light_client::verify_epoch_root_answer(&answer).is_err());
    let m = stellereum::mmr::Mmr::of(&leaves);
    let proof = m.prove(0).expect("proves in the partial tree");
    assert!(verify_mmr_inclusion(&answer, &proof).is_err());
}
