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
use std::sync::OnceLock;
use std::time::Duration;
use stellereum::consensus::{
    cnvrf_v3_epoch_of_height, committee_for_height, micro_committee_size,
    produce_decision_certificate_with_schedule, register_validator_pq_key, CommitteeSchedule,
    EpochBeacon, QuorumCertificate, ValidatorSet, Vote, VoteKind, VoteSet,
    MICRO_COMMITTEE_MAX_SIZE,
};
use stellereum::light_client::LightClient;
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{DomainSnapshot, DomainSnapshotV1};
use stellereum::sync::{
    check_snapshot_set_binding, collect_missing_blocks, fast_sync_state_with_set_binding,
    genesis_light_anchor, validate_sync_chain_for_shard_with_sets,
    validate_sync_chain_for_shard_with_sets_hashed_with_schedule, verify_snapshot_anchor_with_sets,
    walked_head_anchor, HeaderLink,
};

// ==================== deterministic fixtures ====================

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// FULL-PQ: deterministic Falcon companion per ed id (cached process-wide so
/// every helper in a test resolves the same keypair for the same voter).
fn fk_for(k: &SigningKey) -> FalconKeypair {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<[u8; 32], FalconKeypair>>> = OnceLock::new();
    let id = k.verifying_key().to_bytes();
    let mut m = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    m.entry(id)
        .or_insert_with(|| FalconKeypair::generate_from_seed_bytes(&id))
        .clone()
}

fn fks_for(ks: &[SigningKey]) -> Vec<FalconKeypair> {
    ks.iter().map(fk_for).collect()
}

fn reg_all(ks: &[SigningKey]) {
    for k in ks {
        let fk = fk_for(k);
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
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

/// FULL-PQ genuine QC: Falcon halves + compiled µQC envelope (a raw ed list
/// carries no power). Sub-quorum signer sets compile to an ed-only QC that
/// verification refuses — same fail-closed verdict as before.
fn qc_for(
    signers: &[SigningKey],
    vs: &ValidatorSet,
    height: u64,
    hash: [u8; 32],
    parent: [u8; 32],
) -> QuorumCertificate {
    reg_all(signers);
    let fks = fks_for(signers);
    let mut set = VoteSet::new();
    let mut votes = Vec::new();
    for (k, fk) in signers.iter().zip(fks.iter()) {
        let v = Vote::sign_with_falcon(k, fk, height, 0, VoteKind::Precommit, Some(hash));
        // Non-members simply do not count (forged-QC shape); members admit.
        let _ = set.add(v.clone(), vs, height, 0, VoteKind::Precommit);
        votes.push(v);
    }
    // Quorum compiles to a µQC envelope; a sub-quorum signer set cannot
    // compile one, so fall back to the raw ed list — which verification
    // refuses (no power), the same fail-closed verdict as before.
    set.certificate_with_parent(Some(hash), vs, Some(&parent))
        .unwrap_or(QuorumCertificate {
            shard_id: 0,
            height,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(hash),
            signatures: votes.into_iter().map(|v| (v.voter, v.signature)).collect(),
        })
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
        qc: qc_for(signers, set, height, block_hash, prev_hash),
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
    reg_all(keys);
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
            cnvrf_v3: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block_with_falcon(proposer, &fk_for(proposer));
        let bh = b.compute_hash();
        b.precommit_qc = Some(qc_for(keys, vs, h, bh, prev));
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
    let ok =
        verify_snapshot_anchor_with_sets(None, [0u8; 32], 4, |_| Some(vs.clone()), 1_000_000, {
            let w = window.clone();
            move |h: u64| {
                let hit = w.iter().find(|l| l.height == h).cloned();
                async move { hit }
            }
        })
        .await
        .expect("honest window must verify");
    assert_eq!(ok.state_root, [4u8; 32]);

    // Forged linkage: height 3 names an attacker parent.
    let mut forged = window.clone();
    forged[2].prev_hash = [0xEEu8; 32];
    let err =
        verify_snapshot_anchor_with_sets(None, [0u8; 32], 4, |_| Some(vs.clone()), 1_000_000, {
            let w = forged.clone();
            move |h: u64| {
                let hit = w.iter().find(|l| l.height == h).cloned();
                async move { hit }
            }
        })
        .await
        .expect_err("broken linkage must be refused");
    assert!(
        err.contains("does not link to parent"),
        "refusal names linkage, got: {err}"
    );

    // Forged QC: height 3 carries a single-signer's certificate (no quorum).
    let mut no_quorum = window.clone();
    let liar = key(0xF0);
    let lprev = no_quorum[2].prev_hash;
    no_quorum[2].qc = qc_for(
        std::slice::from_ref(&liar),
        &vs,
        3,
        no_quorum[2].block_hash,
        lprev,
    );
    let err =
        verify_snapshot_anchor_with_sets(None, [0u8; 32], 4, |_| Some(vs.clone()), 1_000_000, {
            let w = no_quorum.clone();
            move |h: u64| {
                let hit = w.iter().find(|l| l.height == h).cloned();
                async move { hit }
            }
        })
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
    let err = check_snapshot_set_binding(7, &[("domains", legacy.clone())], &anchor_set)
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
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        validate_sync_chain_for_shard_with_sets(
            &gapped,
            1,
            [0u8; 32],
            &|_| Some(vs.clone()),
            MASTERCHAIN_SHARD,
        )
    })
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
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        validate_sync_chain_for_shard_with_sets(
            &future,
            1,
            [0u8; 32],
            &|_| Some(vs.clone()),
            MASTERCHAIN_SHARD,
        )
    })
    .await
    .expect("future-height verdict is bounded");
    assert!(res.is_err(), "future height must be refused, got: {res:?}");

    // Advertised-head desync: walked head does not hash to the advertised head.
    let walked = honest_blocks(&ks, &vs, 4, root);
    let peer_hash = [0xABu8; 32];
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        walked_head_anchor(&walked, peer_hash, 4)
    })
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
        let prev = b.prev_hash;
        b.precommit_qc = Some(qc_for(&liars, &vs, b.height, bh, prev));
    }
    let before_root = root;
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        validate_sync_chain_for_shard_with_sets(
            &blocks,
            1,
            [0u8; 32],
            &|_| Some(vs.clone()),
            MASTERCHAIN_SHARD,
        )
    })
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
    let all: Vec<SigningKey> = [0x80u8, 0x81, 0x82, 0x83].map(key).to_vec();
    reg_all(&all);
    let mut blocks: Vec<Block> = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=6u64 {
        let (set, signers) = if h <= 3 {
            (&old_set, &old_keys)
        } else {
            (&new_set, &new_keys)
        };
        let proposer_id = set.proposer_for(h, 0).expect("fixture set non-empty");
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
            cnvrf_v3: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        // Sign with the rotation-correct proposer; QC from the height's set.
        b.validator_signatures.clear();
        b.sign_block_with_falcon(proposer, &fk_for(proposer));
        let bh = b.compute_hash();
        b.precommit_qc = Some(qc_for(signers, set, h, bh, prev));
        prev = bh;
        blocks.push(b);
    }

    // Per-height resolver threads the rotation: the walk verifies.
    let old_c = old_set.clone();
    let new_c = new_set.clone();
    stellereum::sync::validate_sync_chain_with_sets(&blocks, 1, [0u8; 32], &|h| {
        if h <= 3 {
            Some(old_c.clone())
        } else {
            Some(new_c.clone())
        }
    })
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

// ============ (e) CN-VRF v3 committee schedule on the sync paths ============

/// Height the beacon-schedule fixture treats as active: one block past epoch 1,
/// i.e. the epoch whose `H_freeze` predates activation (the bootstrap epoch).
const SCHEDULE_ACTIVE_HEIGHT: u64 = stellereum::cn_vrf::EPOCH_LEN + 1;

/// Review F2 fixture: MORE validators than the µQC committee cap. With
/// `<= MICRO_COMMITTEE_MAX_SIZE` validators the draw elects the whole set, so
/// the beacon and parent-hash schedules are indistinguishable and a
/// wrong-schedule refusal could not be observed.
fn schedule_set() -> &'static (Vec<SigningKey>, Vec<FalconKeypair>, ValidatorSet) {
    static SET: OnceLock<(Vec<SigningKey>, Vec<FalconKeypair>, ValidatorSet)> = OnceLock::new();
    SET.get_or_init(|| {
        let n = MICRO_COMMITTEE_MAX_SIZE as usize + 2;
        // Distinct Ed seeds (0x80..=0xFF then 0x00..=0x02); `fk_for` derives the
        // Falcon companion deterministically from the Ed id, so every test in
        // this binary registers the same keypair for the same voter.
        let ks: Vec<SigningKey> = (0..n).map(|i| key(0x80u8.wrapping_add(i as u8))).collect();
        reg_all(&ks);
        let fks = fks_for(&ks);
        let vs = vset(&ks);
        (ks, fks, vs)
    })
}

/// One block to build plus the two draws it must use: the PROPOSER schedule and
/// the QC schedule. Splitting them lets the test keep the proposer valid while
/// the certificate is drawn from the wrong committee (the exact pre-fix sync
/// failure, review F2).
#[derive(Clone, Copy)]
struct BlockSchedules {
    proposer: CommitteeSchedule,
    qc: CommitteeSchedule,
}

/// `(height, round, parent hash, state root)` of the block under test.
#[derive(Clone, Copy)]
struct BlockSpec {
    height: u64,
    round: u32,
    parent: [u8; 32],
    root: [u8; 32],
}

/// Build one block whose proposer is drawn under `schedules.proposer` and whose
/// precommit QC is compiled under `schedules.qc`.
fn block_with_schedules(
    keys: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
    spec: BlockSpec,
    schedules: BlockSchedules,
) -> Block {
    let BlockSpec {
        height,
        round,
        parent,
        root,
    } = spec;
    let proposer_id = vs
        .proposer_for_with_schedule(height, round, schedules.proposer)
        .expect("fixture set names a proposer");
    let (idx, sk) = keys
        .iter()
        .enumerate()
        .find(|(_, k)| k.verifying_key().to_bytes() == proposer_id)
        .expect("the proposer is a fixture member");
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: parent,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + height,
        proposer: proposer_id,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block_with_falcon(sk, &fks[idx]);
    let bh = b.compute_hash();
    let mut votes = VoteSet::new();
    for (k, fk) in keys.iter().zip(fks.iter()) {
        votes
            .add(
                Vote::sign_with_falcon(k, fk, height, round, VoteKind::Precommit, Some(bh)),
                vs,
                height,
                round,
                VoteKind::Precommit,
            )
            .expect("genuine vote admits");
    }
    b.precommit_qc = Some(
        produce_decision_certificate_with_schedule(
            &votes,
            Some(bh),
            vs,
            Some(&parent),
            schedules.qc,
        )
        .expect("the whole set signs, so a certificate must compile"),
    );
    b
}

/// Review F2: the body walk must verify a certificate under the committee
/// schedule in force at its height.
///
/// * At activation a BEACON-drawn QC is accepted by sync, and the SAME block
///   carrying a parent-hash-drawn QC is refused (the pre-fix behaviour).
/// * Below activation a parent-hash QC is still accepted, byte-identically to
///   the pre-schedule path.
#[test]
fn e1_sync_verifies_qc_under_the_activation_schedule() {
    let (keys, fks, vs) = schedule_set();
    let parent = [0x31u8; 32];

    // --- at activation: beacon draw ---------------------------------------
    let height = SCHEDULE_ACTIVE_HEIGHT;
    let epoch = cnvrf_v3_epoch_of_height(height);
    let beacon = CommitteeSchedule::Beacon(Some(EpochBeacon {
        epoch,
        output: [0x5Au8; 48],
    }));
    // The fixture is only meaningful when the two draws really disagree.
    let committee_size = micro_committee_size(vs.len());
    assert!(
        (committee_size as usize) < vs.len(),
        "fixture must exceed the committee cap ({committee_size} vs {})",
        vs.len()
    );
    let beacon_committee =
        committee_for_height(vs, height, 0, committee_size, Some(&parent), beacon);
    let legacy_committee = committee_for_height(
        vs,
        height,
        0,
        committee_size,
        Some(&parent),
        CommitteeSchedule::ParentHash,
    );
    assert_ne!(
        beacon_committee, legacy_committee,
        "the beacon draw must select a different committee for this fixture"
    );

    // Proposer drawn under the BEACON schedule in both cases, so only the
    // certificate's committee differs.
    let beacon_qc_block = block_with_schedules(
        keys,
        fks,
        vs,
        BlockSpec {
            height,
            round: 0,
            parent,
            root: [0x21u8; 32],
        },
        BlockSchedules {
            proposer: beacon,
            qc: beacon,
        },
    );
    let legacy_qc_block = block_with_schedules(
        keys,
        fks,
        vs,
        BlockSpec {
            height,
            round: 0,
            parent,
            root: [0x21u8; 32],
        },
        BlockSchedules {
            proposer: beacon,
            qc: CommitteeSchedule::ParentHash,
        },
    );

    let resolve_set = |_h: u64| Some(vs.clone());
    let resolve_beacon = |_h: u64| beacon;

    // 1. A beacon-drawn QC IS accepted by the sync body walk at activation.
    let walked = validate_sync_chain_for_shard_with_sets_hashed_with_schedule(
        std::slice::from_ref(&beacon_qc_block),
        height,
        parent,
        &resolve_set,
        MASTERCHAIN_SHARD,
        &resolve_beacon,
    )
    .expect("a beacon-drawn certificate must be syncable at activation (review F2)");
    assert_eq!(walked, vec![beacon_qc_block.compute_hash()]);

    // 2. The SAME block with a parent-hash-drawn QC is REFUSED: the sync
    //    verifier attributes under the beacon schedule, so the pre-fix
    //    certificate no longer carries quorum there.
    let err = validate_sync_chain_for_shard_with_sets_hashed_with_schedule(
        std::slice::from_ref(&legacy_qc_block),
        height,
        parent,
        &resolve_set,
        MASTERCHAIN_SHARD,
        &resolve_beacon,
    )
    .expect_err("a parent-hash-drawn certificate must be refused at activation (review F2)");
    assert!(
        err.contains("lacks a validator quorum"),
        "refusal must name the committee mismatch, got: {err}"
    );
    assert!(
        legacy_qc_block
            .precommit_qc
            .as_ref()
            .expect("fixture carries a QC")
            .verify(vs),
        "the legacy certificate is genuine under the parent-hash draw"
    );

    // 3. Below activation a parent-hash QC is still accepted, unchanged.
    let pre_height = 5u64;
    let pre_block = block_with_schedules(
        keys,
        fks,
        vs,
        BlockSpec {
            height: pre_height,
            round: 0,
            parent,
            root: [0x22u8; 32],
        },
        BlockSchedules {
            proposer: CommitteeSchedule::ParentHash,
            qc: CommitteeSchedule::ParentHash,
        },
    );
    assert!(
        validate_sync_chain_for_shard_with_sets_hashed_with_schedule(
            std::slice::from_ref(&pre_block),
            pre_height,
            parent,
            &resolve_set,
            MASTERCHAIN_SHARD,
            &|_| CommitteeSchedule::ParentHash,
        )
        .is_ok(),
        "below activation the parent-hash draw stays the live rule"
    );
}
