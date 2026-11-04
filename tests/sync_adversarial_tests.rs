//! Sync 9.0 -> 9.5 adversarial battery (unit + integration).
//!
//! Pins, with deterministic fixed fixtures:
//! * (a) malicious snapshot anchor: forged linkage / forged QC, forged state
//!   root, mismatched set binding, and legacy blob are hard-refused and leave
//!   the sync target untouched;
//! * (b) byzantine walk peers: wrong heights, future/advertised-head desync,
//!   and conflicting QCs are refused promptly (bounded, no stall);
//! * (c) validator-set rotation mid-walk: the `_with_sets` path threads the
//!   rotation, the legacy single-set path fail-closes, and an unresolvable
//!   height fail-closes;
//! * (d) gap-0: a complete walk replays to exactly the canonical root, and
//!   any gap is refused rather than skipped.

use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::time::Duration;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::light_client::LightClient;
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{DomainSnapshot, DomainSnapshotV1};
use stellereum::sync::{
    check_snapshot_set_binding, collect_missing_blocks, fast_sync_state_with_set_binding,
    genesis_light_anchor, validate_sync_chain_for_shard_with_sets, verify_snapshot_anchor_with_sets,
    walked_head_anchor, HeaderLink,
};

// ==================== deterministic fixtures ====================

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn keys4(base: u8) -> Vec<SigningKey> {
    (0..4).map(|i| key(base.wrapping_add(i))).collect()
}

fn vset(keys: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn qc_for(signers: &[SigningKey], height: u64, hash: [u8; 32]) -> QuorumCertificate {
    let sigs = signers
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
        signatures: sigs,
    }
}

/// One honest header link at `height`, QC-signed by `signers` under `set`.
fn header_link(
    height: u64,
    block_hash: [u8; 32],
    prev_hash: [u8; 32],
    set: &ValidatorSet,
    signers: &[SigningKey],
) -> HeaderLink {
    let proposer = set
        .proposer_for(height, 0)
        .expect("non-empty fixture set names a proposer");
    HeaderLink {
        height,
        block_hash,
        prev_hash,
        state_root: [height as u8; 32],
        proposer,
        qc: qc_for(signers, height, block_hash),
    }
}

/// Honest hash-linked header window `1..=n` rooted at the zero sentinel.
fn honest_window(keys: &[SigningKey], vs: &ValidatorSet, n: u64) -> Vec<HeaderLink> {
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=n {
        let hash = [h as u8; 32];
        out.push(header_link(h, hash, prev, vs, keys));
        prev = hash;
    }
    out
}

/// Honest body chain `1..=n` on the masterchain shard, deterministic:
/// proposer = schedule winner at (height, 0), signed + quorum QC attached.
fn honest_blocks(keys: &[SigningKey], vs: &ValidatorSet, n: u64, root: [u8; 32]) -> Vec<Block> {
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=n {
        let proposer_id = vs.proposer_for(h, 0).expect("fixture set non-empty");
        let proposer = keys
            .iter()
            .find(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer is a fixture member");
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: proposer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(proposer);
        let bh = b.compute_hash();
        let sigs = keys
            .iter()
            .map(|k| {
                let v = Vote::sign(k, h, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect();
        b.precommit_qc = Some(QuorumCertificate {
            height: h,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: sigs,
        });
        prev = bh;
        out.push(b);
    }
    out
}

fn block_store(blocks: &[Block]) -> HashMap<[u8; 32], Block> {
    blocks
        .iter()
        .map(|b| (b.compute_hash(), b.clone()))
        .collect()
}

/// Bonded source engine: staking bonded INSIDE the engine so the state root
/// commits to the same ledger the `domains` blob carries.
async fn bonded_source(
    keys: &[SigningKey],
) -> (
    InMemoryStateEngine,
    stellereum::staking::StakingLedger,
    [u8; 32],
    Vec<u8>,
    Vec<u8>,
) {
    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new([0x55u8; 32], 1_000_000))
        .await;
    {
        let mut staking = engine.staking_write().await;
        for k in keys {
            staking
                .bond(
                    k.verifying_key().to_bytes(),
                    stellereum::staking::MIN_VALIDATOR_BOND
                        + stellereum::staking::STELL_MIN_BOND_BUFFER,
                    0,
                )
                .expect("fixture bond");
        }
    }
    let gov = engine.governance_read().await.clone();
    let staking = engine.staking_read().await.clone();
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(&engine, &staking, &gov).await;
    let domains = bincode::serialize(&dom).expect("domains serialize");
    (engine, staking, root, snap, domains)
}

fn light_at_genesis(vs: &ValidatorSet, root: [u8; 32]) -> LightClient {
    LightClient::with_genesis_anchor(vs.clone(), genesis_light_anchor(root))
        .expect("genesis anchor")
}

// ==================== (a) malicious snapshot anchor ====================

#[tokio::test]
async fn a1_snapshot_anchor_refuses_broken_linkage_and_forged_qc() {
    let ks = keys4(0x10);
    let vs = vset(&ks);
    let window = honest_window(&ks, &vs, 4);

    // Happy path first: the honest window verifies.
    let ok = verify_snapshot_anchor_with_sets(
        None,
        [0u8; 32],
        4,
        |_| Some(vs.clone()),
        1_000_000,
        {
            let w = window.clone();
            move |h: u64| {
                let hit = w.iter().find(|l| l.height == h).cloned();
                async move { hit }
            }
        },
    )
    .await
    .expect("honest window must verify");
    assert_eq!(ok.state_root, [4u8; 32]);

    // Forged linkage: height 3 names an attacker parent.
    let mut forged = window.clone();
    forged[2].prev_hash = [0xEEu8; 32];
    let err = verify_snapshot_anchor_with_sets(
        None,
        [0u8; 32],
        4,
        |_| Some(vs.clone()),
        1_000_000,
        {
            let w = forged.clone();
            move |h: u64| {
                let hit = w.iter().find(|l| l.height == h).cloned();
                async move { hit }
            }
        },
    )
    .await
    .expect_err("broken linkage must be refused");
    assert!(
        err.contains("does not link to parent"),
        "refusal names linkage, got: {err}"
    );

    // Forged QC: height 3 carries a single-signer's certificate (no quorum).
    let mut no_quorum = window.clone();
    let liar = key(0xF0);
    no_quorum[2].qc = qc_for(std::slice::from_ref(&liar), 3, no_quorum[2].block_hash);
    let err = verify_snapshot_anchor_with_sets(
        None,
        [0u8; 32],
        4,
        |_| Some(vs.clone()),
        1_000_000,
        {
            let w = no_quorum.clone();
            move |h: u64| {
                let hit = w.iter().find(|l| l.height == h).cloned();
                async move { hit }
            }
        },
    )
    .await
    .expect_err("single-signer QC must be refused");
    assert!(
        err.contains("no schedule slot") || err.contains("quorum"),
        "refusal is fail-closed, got: {err}"
    );
}

#[tokio::test]
async fn a2_snapshot_sync_refuses_forged_root_without_mutating_target() {
    let ks = keys4(0x20);
    let (_source, staking, root, snap, domains) = bonded_source(&ks).await;
    let anchor_set = staking.to_validator_set();
    assert!(!anchor_set.validators.is_empty());

    // The attacker offers the honest bytes but names a forged expected root.
    let forged_root = [0xFFu8; 32];
    assert_ne!(forged_root, root);
    let target = InMemoryStateEngine::new();
    let before = target.get_state_root().await;
    let err = fast_sync_state_with_set_binding(
        &target,
        forged_root,
        || async { Some(snap.clone()) },
        |kind: &'static str| {
            let d = domains.clone();
            async move {
                if kind == "domains" {
                    Some(d)
                } else {
                    None
                }
            }
        },
        7,
        &anchor_set,
    )
    .await
    .expect_err("forged root must be refused");
    assert!(
        err.contains("state root mismatch"),
        "refusal names the root mismatch, got: {err}"
    );
    assert_eq!(
        target.get_state_root().await,
        before,
        "refusal leaves the target untouched"
    );
    assert_ne!(target.get_state_root().await, forged_root);
}

#[tokio::test]
async fn a3_snapshot_sync_refuses_mismatched_set_without_mutating_target() {
    let ks = keys4(0x30);
    let (_source, _staking, root, snap, domains) = bonded_source(&ks).await;
    let other = vset(&keys4(0x31));
    assert!(!other.validators.is_empty());

    let target = InMemoryStateEngine::new();
    let before = target.get_state_root().await;
    let err = fast_sync_state_with_set_binding(
        &target,
        root,
        || async { Some(snap.clone()) },
        |kind: &'static str| {
            let d = domains.clone();
            async move {
                if kind == "domains" {
                    Some(d)
                } else {
                    None
                }
            }
        },
        7,
        &other,
    )
    .await
    .expect_err("mismatched set must be refused");
    assert!(
        err.contains("does not match"),
        "refusal names the set mismatch, got: {err}"
    );
    assert_eq!(
        target.get_state_root().await,
        before,
        "refusal leaves the target untouched"
    );
}

#[tokio::test]
async fn a4_snapshot_sync_refuses_legacy_blob() {
    let ks = keys4(0x40);
    let (_source, staking, root, snap, _domains) = bonded_source(&ks).await;
    let anchor_set = staking.to_validator_set();
    // Legacy V1 domains blob: same staking content, pre-upgrade shape.
    let old = DomainSnapshotV1 {
        tokens: Default::default(),
        contracts: Default::default(),
        orderbooks: Default::default(),
        pmm: Default::default(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        order_escrow: HashMap::new(),
        staking: stellereum::staking::StakingLedgerV1 {
            validators: staking.validators.clone(),
            delegations: staking.delegations.clone(),
            delegator_rewards: staking.delegator_rewards.clone(),
            unbonding: staking.unbonding.clone(),
            withdrawable: staking.withdrawable.clone(),
            total_burned: staking.total_burned,
        },
        governance: Default::default(),
        oracle: Default::default(),
    };
    let legacy = bincode::serialize(&old).expect("legacy serialize");

    // Direct binding gate refuses the legacy shape.
    let err = check_snapshot_set_binding(
        7,
        &[("domains", legacy.clone())],
        &anchor_set,
    )
    .expect_err("legacy blob must be refused");
    assert!(
        err.contains("legacy or unknown version"),
        "legacy refusal is explicit, got: {err}"
    );

    // End to end: the fast-sync trust path refuses before mutating.
    let target = InMemoryStateEngine::new();
    let before = target.get_state_root().await;
    let err = fast_sync_state_with_set_binding(
        &target,
        root,
        || async { Some(snap.clone()) },
        |kind: &'static str| {
            let l = legacy.clone();
            async move {
                if kind == "domains" {
                    Some(l)
                } else {
                    None
                }
            }
        },
        7,
        &anchor_set,
    )
    .await
    .expect_err("legacy blob must be refused end to end");
    assert!(
        err.contains("legacy or unknown version"),
        "end-to-end refusal names legacy, got: {err}"
    );
    assert_eq!(
        target.get_state_root().await,
        before,
        "legacy refusal leaves the target untouched"
    );
}

// ==================== (b) byzantine walk peers ====================

#[tokio::test]
async fn b1_walk_refuses_wrong_height_gap_without_stall() {
    let ks = keys4(0x50);
    let vs = vset(&ks);
    let root = [0x42u8; 32];
    let blocks = honest_blocks(&ks, &vs, 6, root);
    // Peer skips height 3: a gap the walk must refuse, not skip.
    let mut gapped = blocks.clone();
    gapped.remove(2);
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        async {
            validate_sync_chain_for_shard_with_sets(
                &gapped,
                1,
                [0u8; 32],
                &|_| Some(vs.clone()),
                MASTERCHAIN_SHARD,
            )
        },
    )
    .await
    .expect("walk verdict is bounded");
    let err = res.expect_err("height gap must be refused");
    assert!(
        err.contains("height gap"),
        "refusal names the gap, got: {err}"
    );
}

#[tokio::test]
async fn b2_walk_refuses_future_height_and_head_desync_without_stall() {
    let ks = keys4(0x60);
    let vs = vset(&ks);
    let root = [0x42u8; 32];
    let blocks = honest_blocks(&ks, &vs, 5, root);

    // Future height: peer serves a block above the advertised head's chain.
    let mut future = blocks.clone();
    future.last_mut().expect("non-empty").height = 99;
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        async {
            validate_sync_chain_for_shard_with_sets(
                &future,
                1,
                [0u8; 32],
                &|_| Some(vs.clone()),
                MASTERCHAIN_SHARD,
            )
        },
    )
    .await
    .expect("future-height verdict is bounded");
    assert!(
        res.is_err(),
        "future height must be refused, got: {res:?}"
    );

    // Advertised-head desync: walked head does not hash to the advertised head.
    let walked = honest_blocks(&ks, &vs, 4, root);
    let peer_hash = [0xABu8; 32];
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        async { walked_head_anchor(&walked, peer_hash, 4) },
    )
    .await
    .expect("head-anchor verdict is bounded");
    let err = res.expect_err("head desync must be refused");
    assert!(
        err.contains("does not hash to the advertised head"),
        "refusal names the desync, got: {err}"
    );

    // Advertised height above the served chain is refused as well.
    let head_hash = walked.last().expect("non-empty").compute_hash();
    let err = walked_head_anchor(&walked, head_hash, 99).expect_err("height desync refused");
    assert!(
        err.contains("advertised-head desync"),
        "refusal names the height desync, got: {err}"
    );
}

#[tokio::test]
async fn b3_walk_refuses_conflicting_qcs_without_stall() {
    let ks = keys4(0x70);
    let vs = vset(&ks);
    let root = [0x42u8; 32];
    let mut blocks = honest_blocks(&ks, &vs, 5, root);
    // Conflicting QC: heights 4..5 re-signed by outsiders (no quorum power).
    let liars = [key(0xF0), key(0xF1), key(0xF2)];
    for b in blocks.iter_mut().skip(3) {
        let bh = b.compute_hash();
        b.precommit_qc = Some(qc_for(&liars, b.height, bh));
    }
    let before_root = root;
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        async {
            validate_sync_chain_for_shard_with_sets(
                &blocks,
                1,
                [0u8; 32],
                &|_| Some(vs.clone()),
                MASTERCHAIN_SHARD,
            )
        },
    )
    .await
    .expect("conflicting-QC verdict is bounded");
    let err = res.expect_err("outsider QCs must be refused");
    assert!(
        err.contains("lacks a validator quorum"),
        "refusal names the quorum shortfall, got: {err}"
    );
    assert_eq!(before_root, root, "fixture root is unchanged");

    // The light-client probe refuses the same conflicting chain (anchor path).
    let light = light_at_genesis(&vs, root);
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        verify_synced_blocks_against_anchor_with_sets_wrapper(&light, &blocks),
    )
    .await
    .expect("anchor-probe verdict is bounded");
    assert!(res.is_err(), "anchor probe must refuse outsider QCs");
}

async fn verify_synced_blocks_against_anchor_with_sets_wrapper(
    light: &LightClient,
    blocks: &[Block],
) -> Result<[u8; 32], String> {
    stellereum::sync::verify_synced_blocks_against_anchor(light, blocks)
}

// ==================== (c) set rotation mid-walk ====================

#[tokio::test]
async fn c1_rotation_mid_walk_threads_with_sets_while_single_set_refuses() {
    // Old set: seeds 0x80,0x81,0x82 ; new set: seeds 0x81,0x82,0x83 (2/3 overlap).
    let old_keys: Vec<SigningKey> = [0x80u8, 0x81, 0x82].map(key).to_vec();
    let new_keys: Vec<SigningKey> = [0x81u8, 0x82, 0x83].map(key).to_vec();
    let old_set = vset(&old_keys);
    let new_set = vset(&new_keys);
    let root = [0x42u8; 32];

    // Heights 1..3 under the old set, 4..6 under the new set.
    let mut blocks: Vec<Block> = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=6u64 {
        let (set, signers) = if h <= 3 {
            (&old_set, &old_keys)
        } else {
            (&new_set, &new_keys)
        };
        let proposer_id = set.proposer_for(h, 0).expect("fixture set non-empty");
        let all: Vec<SigningKey> = [0x80u8, 0x81, 0x82, 0x83].map(key).to_vec();
        let proposer = all
            .iter()
            .find(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer in union");
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: proposer.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        // Sign with the rotation-correct proposer; QC from the height's set.
        b.validator_signatures.clear();
        b.sign_block(proposer);
        let bh = b.compute_hash();
        let sigs = signers
            .iter()
            .map(|k| {
                let v = Vote::sign(k, h, 0, VoteKind::Precommit, Some(bh));
                (v.voter, v.signature)
            })
            .collect();
        b.precommit_qc = Some(QuorumCertificate {
            height: h,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(bh),
            signatures: sigs,
        });
        prev = bh;
        blocks.push(b);
    }

    // Per-height resolver threads the rotation: the walk verifies.
    let old_c = old_set.clone();
    let new_c = new_set.clone();
    stellereum::sync::validate_sync_chain_with_sets(
        &blocks,
        1,
        [0u8; 32],
        &|h| {
            if h <= 3 {
                Some(old_c.clone())
            } else {
                Some(new_c.clone())
            }
        },
    )
    .expect("rotation-aware walk must verify");

    // Legacy single-set entries fail closed on the rotated half (and vice versa).
    let err = stellereum::sync::validate_sync_chain(&blocks, 1, [0u8; 32], &old_set)
        .expect_err("stale single set must refuse rotated heights");
    assert!(
        err.contains("quorum") || err.contains("no schedule slot"),
        "stale-set refusal is fail-closed, got: {err}"
    );
    let err = stellereum::sync::validate_sync_chain(&blocks, 1, [0u8; 32], &new_set)
        .expect_err("new single set must refuse pre-rotation heights");
    assert!(
        err.contains("quorum") || err.contains("no schedule slot"),
        "new-set refusal is fail-closed, got: {err}"
    );
}

#[tokio::test]
async fn c2_unresolvable_height_fail_closed() {
    let ks = keys4(0x90);
    let vs = vset(&ks);
    let root = [0x42u8; 32];
    let blocks = honest_blocks(&ks, &vs, 4, root);
    let err = validate_sync_chain_for_shard_with_sets(
        &blocks,
        1,
        [0u8; 32],
        &|h| {
            if h == 3 {
                None
            } else {
                Some(vs.clone())
            }
        },
        MASTERCHAIN_SHARD,
    )
    .expect_err("unresolvable height must be refused");
    assert!(
        err.contains("no validator set known for height 3"),
        "refusal names the height, got: {err}"
    );
}

// ==================== (d) gap-0: canonical replay ====================

/// Canonical replay: apply `blocks` ancestor-first against the header roots,
/// exactly as the node does after `collect_missing_blocks` + validation.
async fn replay_to_root(
    engine: &InMemoryStateEngine,
    blocks: &[Block],
    our_last: [u8; 32],
    first_height: u64,
    vs: &ValidatorSet,
) -> Result<[u8; 32], String> {
    let head = blocks.last().ok_or("empty chain")?.compute_hash();
    let map = block_store(blocks);
    let missing = collect_missing_blocks(head, our_last, 100_000, move |h| {
        let m = map.clone();
        async move { m.get(&h).cloned() }
    })
    .await?;
    if missing.is_empty() {
        return Err("empty walk proves nothing".to_string());
    }
    assert_eq!(
        missing.first().expect("non-empty").height,
        first_height,
        "walk starts at the join height"
    );
    validate_sync_chain_for_shard_with_sets(
        &missing,
        first_height,
        our_last,
        &|_| Some(vs.clone()),
        MASTERCHAIN_SHARD,
    )?;
    for b in &missing {
        let root_before = engine.get_state_root().await;
        if root_before != b.state_root {
            return Err(format!(
                "block {} commits to {} but our state is {}",
                b.height,
                hex::encode(b.state_root),
                hex::encode(root_before)
            ));
        }
        engine
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
    }
    Ok(engine.get_state_root().await)
}

#[tokio::test]
async fn d1_gap_zero_synced_state_equals_canonical_replay() {
    let ks = keys4(0xA0);
    let vs = vset(&ks);
    // Fixed funded account; empty bodies keep the root pinned while the walk
    // still proves linkage + quorum at every height.
    let payer = ks[0].verifying_key().to_bytes();
    let base = InMemoryStateEngine::new();
    base.update_account(AccountState::new(payer, 1_000_000))
        .await;
    let canonical_root = base.get_state_root().await;
    let blocks = honest_blocks(&ks, &vs, 8, canonical_root);

    // Lagging node holds the prefix 1..=5; the gap 6..=8 must replay exactly.
    let our_last = blocks[4].compute_hash();
    let lagging = InMemoryStateEngine::new();
    lagging
        .update_account(AccountState::new(payer, 1_000_000))
        .await;
    assert_eq!(lagging.get_state_root().await, canonical_root);
    for b in blocks.iter().take(5) {
        assert_eq!(lagging.get_state_root().await, b.state_root);
        lagging
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
    }

    let synced = replay_to_root(&lagging, &blocks, our_last, 6, &vs)
        .await
        .expect("complete walk must replay");
    assert_eq!(
        synced,
        blocks.last().expect("non-empty").state_root,
        "synced state equals the canonical (peer) root: no gaps tolerated"
    );

    // Any gap is refused rather than silently skipped: drop height 7.
    let mut gapped = blocks.clone();
    gapped.remove(6);
    let fresh = InMemoryStateEngine::new();
    fresh
        .update_account(AccountState::new(payer, 1_000_000))
        .await;
    for b in blocks.iter().take(5) {
        fresh
            .apply_block_parallel_fees(&b.transactions, b.timestamp)
            .await;
    }
    let before = fresh.get_state_root().await;
    let res = replay_to_root(&fresh, &gapped, our_last, 6, &vs).await;
    assert!(res.is_err(), "gapped walk must be refused: {res:?}");
    assert_eq!(
        fresh.get_state_root().await,
        before,
        "refused gap leaves state untouched"
    );
}
