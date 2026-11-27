//! Wave 12 / `EXECUTION_PIPELINE_V1`: INERT height-gated foundation for the
//! consensus<->execution pipeline.
//!
//! The gate is compiled at `u64::MAX` and only moves the block state-root
//! binding from lag 1 to lag 2:
//!
//! * `committed_state_height_at(H)` — the state height whose post-state block
//!   `H` commits (`H-1` inert, `H-2` armed);
//! * `anchor_height_for_post_state_at(S)` — the block height whose
//!   `state_root` anchors post-state `S` (`S+1` inert, `S+2` armed).
//!
//! What is pinned here:
//! 1. the compiled default is inert at every height and both helpers return
//!    exactly today's lag-1 / `S+1` values;
//! 2. under a thread-local override at `A = 10`, the helpers move by one
//!    height and the `state_height == A-2` boundary is anchored by BOTH
//!    `A-1` and `A` (they commit the same post-state);
//! 3. `Storage` round-trip parity: `put_block` / `finalized_post_root_at` /
//!    `expected_restore_root` / `historical_root` agree below, at and above
//!    the override, and the sync anchor walk still verifies armed;
//! 4. the helpers are overflow-safe at `u64::MAX`.

use ed25519_dalek::SigningKey;
use stellereum::chain_spec::{
    anchor_height_for_post_state_at, committed_state_height_at,
    execution_pipeline_v1_activation_height, execution_pipeline_v1_active_at,
    set_execution_pipeline_v1_activation_override, EXECUTION_PIPELINE_V1_ACTIVATION_HEIGHT,
};
use stellereum::consensus::{
    register_validator_pq_key, CommitteeSchedule, QuorumCertificate, ValidatorSet, VoteKind,
    VoteSet,
};
use stellereum::light_client::Checkpoint;
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::sharding::{Block, BlockHeader, MASTERCHAIN_SHARD};
use stellereum::storage::Storage;
use stellereum::sync::{verify_snapshot_anchor_with_sets_and_schedule, HeaderLink};

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

/// RAII gate override: a panicking assertion must not leak a test activation
/// into another test on the same worker thread.
struct PipelineGate;

impl PipelineGate {
    fn arm(at: u64) -> Self {
        set_execution_pipeline_v1_activation_override(Some(at));
        Self
    }

    fn clear() -> Self {
        set_execution_pipeline_v1_activation_override(None);
        Self
    }
}

impl Drop for PipelineGate {
    fn drop(&mut self) {
        set_execution_pipeline_v1_activation_override(None);
    }
}

#[test]
fn default_gate_is_inert_and_helpers_keep_lag_one() {
    let _gate = PipelineGate::clear();

    assert_eq!(
        EXECUTION_PIPELINE_V1_ACTIVATION_HEIGHT,
        u64::MAX,
        "the execution-pipeline gate was armed; this file pins its INERT default"
    );
    assert_eq!(execution_pipeline_v1_activation_height(), u64::MAX);

    // A broad sweep plus the extremes: `active_at` is false EVERYWHERE under
    // the `u64::MAX` sentinel, including `u64::MAX` itself.
    for height in 0u64..=5_000 {
        assert!(
            !execution_pipeline_v1_active_at(height),
            "gate must be inert at {height}"
        );
        assert_eq!(
            committed_state_height_at(height),
            height.saturating_sub(1),
            "inert committed_state_height_at({height}) changed"
        );
        assert_eq!(
            anchor_height_for_post_state_at(height),
            height.saturating_add(1),
            "inert anchor_height_for_post_state_at({height}) changed"
        );
    }
    for height in [u64::MAX - 2, u64::MAX - 1, u64::MAX] {
        assert!(!execution_pipeline_v1_active_at(height));
        assert_eq!(committed_state_height_at(height), height.saturating_sub(1));
        assert_eq!(
            anchor_height_for_post_state_at(height),
            height.saturating_add(1)
        );
    }
}

#[test]
fn gate_at_ten_moves_commit_and_anchor_by_one_height() {
    let _gate = PipelineGate::arm(10);

    assert!(!execution_pipeline_v1_active_at(9));
    assert!(execution_pipeline_v1_active_at(10));
    assert!(execution_pipeline_v1_active_at(11));
    assert!(execution_pipeline_v1_active_at(u64::MAX));

    // requested sweep, including both sides of the activation height.
    let commit_cases = [(8u64, 7u64), (9, 8), (10, 8), (11, 9), (12, 10), (13, 11)];
    for (height, want) in commit_cases {
        assert_eq!(
            committed_state_height_at(height),
            want,
            "committed_state_height_at({height}) with gate at 10"
        );
    }

    let anchor_cases = [(7u64, 8u64), (8, 10), (9, 11), (10, 12), (11, 13)];
    for (state_height, want) in anchor_cases {
        assert_eq!(
            anchor_height_for_post_state_at(state_height),
            want,
            "anchor_height_for_post_state_at({state_height}) with gate at 10"
        );
    }

    // Boundary: post-state at `A-2 == 8` is committed by BOTH block 9 (legacy,
    // `9-1`) and block 10 (armed, `10-2`); the helper names the armed anchor.
    assert_eq!(committed_state_height_at(9), 8);
    assert_eq!(committed_state_height_at(10), 8);
    assert_eq!(anchor_height_for_post_state_at(8), 10);

    // Every armed block's anchor resolves back to itself, and the lag-1 side
    // before the boundary still resolves `S -> S+1`.
    for height in 10u64..=20 {
        assert_eq!(
            anchor_height_for_post_state_at(committed_state_height_at(height)),
            height,
            "armed round-trip failed at {height}"
        );
    }
    for height in 1u64..=8 {
        assert_eq!(
            anchor_height_for_post_state_at(committed_state_height_at(height)),
            height
        );
    }
}

#[test]
fn helpers_are_overflow_safe_at_u64_max() {
    {
        let _gate = PipelineGate::clear();
        assert_eq!(committed_state_height_at(u64::MAX), u64::MAX - 1);
        assert_eq!(anchor_height_for_post_state_at(u64::MAX), u64::MAX);
        assert_eq!(anchor_height_for_post_state_at(u64::MAX - 1), u64::MAX);
        assert_eq!(committed_state_height_at(0), 0);
    }
    {
        let _gate = PipelineGate::arm(10);
        assert_eq!(committed_state_height_at(u64::MAX), u64::MAX - 2);
        assert_eq!(anchor_height_for_post_state_at(u64::MAX), u64::MAX);
        assert_eq!(anchor_height_for_post_state_at(u64::MAX - 1), u64::MAX);
        assert_eq!(committed_state_height_at(0), 0);
        assert_eq!(committed_state_height_at(1), 0);
    }
}

fn historical_root_answer(state_height: u64, anchor_height: u64) -> serde_json::Value {
    let state_root = [0xAAu8; 32];
    let prev_hash = [0xCCu8; 32];
    let body_commitment = [0xDDu8; 32];
    let header = BlockHeader {
        shard_id: MASTERCHAIN_SHARD,
        height: anchor_height,
        round: 0,
        prev_hash,
        state_root,
        body_commitment,
        mmr_epoch_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        timestamp: 0,
        proposer: [0u8; 32],
    };
    let anchor_hash = header.compute_hash();
    serde_json::json!({
        "finalized": true,
        "height": state_height,
        "state_root": hex::encode(state_root),
        "anchor_height": anchor_height,
        "anchor_hash": hex::encode(anchor_hash),
        "prev_hash": hex::encode(prev_hash),
        "shard_id": MASTERCHAIN_SHARD,
        "round": 0,
        "body_commitment": hex::encode(body_commitment),
        "cert": {
            "kind": "Precommit",
            "height": anchor_height,
            "round": 0,
            "block_hash": hex::encode(anchor_hash),
            "shard_id": MASTERCHAIN_SHARD,
            "signatures": [],
        },
    })
}

#[test]
fn light_client_historical_root_anchor_follows_the_gate() {
    // Inert: post-state 10 is anchored by block 11, exactly as before.
    {
        let _gate = PipelineGate::clear();
        let checkpoint = Checkpoint::from_historical_root_json(&historical_root_answer(10, 11))
            .expect("inert checkpoint parses with the legacy S+1 anchor");
        assert_eq!(checkpoint.height, 11);

        let err = Checkpoint::from_historical_root_json(&historical_root_answer(10, 12))
            .expect_err("inert parsing must refuse the armed S+2 anchor");
        assert!(
            err.contains("not the post-state anchor"),
            "unexpected refusal: {err}"
        );
    }

    // Armed at 10: post-state 10 is anchored by block 12.
    {
        let _gate = PipelineGate::arm(10);
        let checkpoint = Checkpoint::from_historical_root_json(&historical_root_answer(10, 12))
            .expect("armed checkpoint parses with the S+2 anchor");
        assert_eq!(checkpoint.height, 12);

        let err = Checkpoint::from_historical_root_json(&historical_root_answer(10, 11))
            .expect_err("armed parsing must refuse the legacy S+1 anchor");
        assert!(
            err.contains("not the post-state anchor"),
            "unexpected refusal: {err}"
        );
    }

    // Overflow is still refused (the helper saturates and never wraps).
    {
        let _gate = PipelineGate::clear();
        let err = Checkpoint::from_historical_root_json(&historical_root_answer(u64::MAX, 0))
            .expect_err("u64::MAX has no successor anchor");
        assert!(err.contains("overflows"), "unexpected refusal: {err}");
    }
}

// ---------------------------------------------------------------------------
// Storage round-trip parity
// ---------------------------------------------------------------------------

static DIR_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "stell-w12-pipeline-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// The post-state id a test block commits, encoded as the root bytes. Blocks
/// below the boundary use lag 1; blocks at/above it use lag 2, so block `A-1`
/// and block `A` deliberately carry the SAME root for post-state `A-2`.
fn post_root(committed_height: u64) -> [u8; 32] {
    [committed_height as u8; 32]
}

fn dummy_qc(height: u64) -> QuorumCertificate {
    QuorumCertificate {
        height,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: None,
        signatures: Vec::new(),
        shard_id: MASTERCHAIN_SHARD,
    }
}

fn mk_block(height: u64, prev: [u8; 32], state_root: [u8; 32]) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + height,
        proposer: [0x11u8; 32],
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: Some(dummy_qc(height)),
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    }
}

/// Write blocks `1..=13` under a gate at `A = 10`. The block at each height
/// commits `committed_state_height_at(height)`, exactly what the armed
/// pipeline means: `8,9` commit post-state `7,8`, `10` commits `8`, `11..13`
/// commit `9..11`.
fn write_pipeline_blocks(store: &Storage) -> Vec<Block> {
    let mut prev = [0u8; 32];
    let mut blocks = Vec::new();
    for height in 1u64..=13 {
        let committed = committed_state_height_at(height);
        let block = mk_block(height, prev, post_root(committed));
        prev = store.put_block(&block).expect("put block");
        blocks.push(block);
    }
    blocks
}

#[test]
fn storage_round_trip_agrees_with_the_helpers_armed() {
    let _gate = PipelineGate::arm(10);
    let dir = temp_dir("storage");
    let store = Storage::open(&dir).expect("open storage");
    let blocks = write_pipeline_blocks(&store);

    // put_block -> finalized_post_root_at: every height writes the key of the
    // state it commits (the boundary key 8 is written by 9 AND 10 with the
    // SAME value, which is the property that makes the transition seamless).
    for block in &blocks {
        let committed = committed_state_height_at(block.height);
        assert_eq!(
            store
                .finalized_post_root_at(committed)
                .expect("read finalized post root"),
            Some(block.state_root),
            "finalized_post_root_at({committed}) disagrees with block {}",
            block.height
        );
    }
    assert_eq!(store.finalized_post_root_at(8).unwrap(), Some(post_root(8)));
    assert_eq!(store.finalized_post_root_at(9).unwrap(), Some(post_root(9)));

    // expected_restore_root(S) resolves the armed anchor header (S+2 at/above
    // the boundary, S+1 below it) and returns that header's committed root.
    for state_height in 0u64..=11 {
        let anchor = anchor_height_for_post_state_at(state_height);
        assert!(
            anchor <= 13,
            "test fixture must contain the armed anchor {anchor}"
        );
        assert_eq!(
            store
                .expected_restore_root(state_height)
                .expect("expected restore root"),
            Some(post_root(state_height)),
            "expected_restore_root({state_height}) must read the header at {anchor}"
        );
    }
    // Above the written tip there is no anchor: nothing to compare against.
    assert!(store.expected_restore_root(12).unwrap().is_none());

    // historical_root(S, tip) anchors at the SAME height and root, with the
    // QC of that anchoring body.
    for state_height in 0u64..=11 {
        let record = store
            .historical_root(state_height, 13)
            .expect("historical root");
        assert_eq!(record.height, state_height);
        assert_eq!(
            record.anchor_height,
            anchor_height_for_post_state_at(state_height)
        );
        assert_eq!(record.state_root, post_root(state_height));
        assert!(record.finalized);
    }

    // The pre-existing overflow refusal is preserved.
    assert!(store.expected_restore_root(u64::MAX).is_err());

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn storage_round_trip_is_byte_identical_with_the_gate_inert() {
    let _gate = PipelineGate::clear();
    let dir = temp_dir("storage-inert");
    let store = Storage::open(&dir).expect("open storage");
    let blocks = write_pipeline_blocks(&store);

    for block in &blocks {
        let legacy = block.height - 1;
        assert_eq!(
            store.finalized_post_root_at(legacy).unwrap(),
            Some(block.state_root),
            "inert put_block must still key the post root at height-1"
        );
    }
    for state_height in 0u64..=11 {
        let anchor = anchor_height_for_post_state_at(state_height);
        assert_eq!(anchor, state_height + 1);
        assert_eq!(
            store.expected_restore_root(state_height).unwrap(),
            Some(post_root(state_height)),
            "inert expected_restore_root({state_height}) must read height+1"
        );
        let record = store.historical_root(state_height, 13).unwrap();
        assert_eq!(record.anchor_height, state_height + 1);
        assert_eq!(record.state_root, post_root(state_height));
    }

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Snapshot anchor walk above the gate
// ---------------------------------------------------------------------------

fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn fk_for(key: &SigningKey) -> FalconKeypair {
    let fk = FalconKeypair::generate_from_seed(key.to_bytes()[0]);
    register_validator_pq_key(
        key.verifying_key().to_bytes(),
        PqScheme::Falcon512,
        fk.public_key.clone(),
    );
    fk
}

fn qc_for(
    signers: &[SigningKey],
    set: &ValidatorSet,
    height: u64,
    block_hash: [u8; 32],
    prev_hash: [u8; 32],
) -> QuorumCertificate {
    let mut votes = VoteSet::new();
    for key in signers {
        let fk = fk_for(key);
        let vote = falcon_votes::fvote(key, &fk, height, 0, VoteKind::Precommit, Some(block_hash));
        votes
            .add(vote, set, height, 0, VoteKind::Precommit)
            .expect("genuine precommit vote admits");
    }
    votes
        .certificate(Some(block_hash), set, &prev_hash)
        .expect("quorum compiles a Falcon micro-certificate")
}

fn header_link(
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    set: &ValidatorSet,
    signers: &[SigningKey],
) -> HeaderLink {
    let proposer = set
        .proposer_for(height, 0)
        .expect("non-empty validator set names a proposer");
    let body_commitment = [height as u8; 32];
    let header = BlockHeader {
        shard_id: MASTERCHAIN_SHARD,
        height,
        round: 0,
        prev_hash,
        state_root,
        body_commitment,
        mmr_epoch_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        timestamp: 0,
        proposer,
    };
    let block_hash = header.compute_hash();
    HeaderLink {
        height,
        block_hash,
        prev_hash,
        state_root,
        proposer,
        qc: qc_for(signers, set, height, block_hash, prev_hash),
        shard_id: MASTERCHAIN_SHARD,
        round: 0,
        body_commitment: Some(body_commitment),
        mmr_epoch_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        timestamp: 0,
    }
}

#[tokio::test]
async fn snapshot_anchor_walk_verifies_with_the_gate_armed() {
    let _gate = PipelineGate::arm(10);

    let keys: Vec<SigningKey> = (0..4).map(|i| test_key(0x31 + i)).collect();
    let set = ValidatorSet::from_list(
        keys.iter()
            .map(|key| (key.verifying_key().to_bytes(), 1))
            .collect(),
    );

    // Heights 8..=12, each header committing its pipeline post-state:
    // h9 -> 8, h10 -> 8, h11 -> 9, h12 -> 10.
    let mut prev = [0x08u8; 32];
    let mut links = Vec::new();
    for height in 8u64..=12 {
        let state_root = post_root(committed_state_height_at(height));
        let link = header_link(height, prev, state_root, &set, &keys);
        prev = link.block_hash;
        links.push(link);
    }
    let our_finalized = (8u64, links[0].block_hash);
    let boundary = links
        .iter()
        .find(|link| link.height == 10)
        .expect("boundary link 10")
        .clone();

    let lookup = links.clone();
    let resolver = set.clone();
    let anchor = verify_snapshot_anchor_with_sets_and_schedule(
        Some(our_finalized),
        [0u8; 32],
        12, // armed anchor of post-state 10
        move |_| Some(resolver.clone()),
        |_| CommitteeSchedule::ParentHash,
        1_000_000,
        move |height| {
            let hit = lookup.iter().find(|link| link.height == height).cloned();
            async move { hit }
        },
    )
    .await
    .expect("armed snapshot anchor must verify");

    // The walked header at 12 commits post-state 10, and the boundary hash is
    // hash(10) — `boundary_hash = hash(boundary)`, resolved through the helper.
    assert_eq!(anchor.state_root, post_root(10));
    assert_eq!(anchor.boundary_hash, boundary.block_hash);
}
