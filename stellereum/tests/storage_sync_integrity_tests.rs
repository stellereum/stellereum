//! Storage/sync integrity audit: attack + fault tests for the snapshot
//! persist/restore/verify chain, body/header walks, fetch-path bindings,
//! pruning retention, and genesis/bootstrap gates.
//!
//! Scope is `src/storage.rs` + `src/sync.rs` + `src/bootstrap.rs` only. Every
//! test below pins a fail-closed property: forged state is refused (never
//! applied), torn writes are refused (never half-applied), gapped/forked
//! walks are refused (anchored on our own tip only), aggressive pruning keeps
//! the retained suffix verifiable while pruned heights fail as honest misses,
//! and corrupt/empty blobs are refused at the decode boundary.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::bootstrap;
use stellereum::consensus::{QuorumCertificate, ValidatorSet, Vote, VoteKind};
use stellereum::governance::Governance;
use stellereum::sharding::{
    Block, CrossShardKey, CrossShardReplaySnapshot, MASTERCHAIN_SHARD,
};
use stellereum::staking::StakingLedger;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{
    decode_domain_snapshot, load_full_state_into, DomainSnapshot, Storage,
};
use stellereum::sync;
use stellereum::token::{TokenMetadata, ZERO_ADDRESS};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "stell-integrity-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn mkblock(height: u64, prev: [u8; 32], state_root: [u8; 32]) -> Block {
    let sk = SigningKey::from_bytes(&[0x11u8; 32]);
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: prev,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_000 + height,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
    };
    b.sign_block(&sk);
    b
}

/// Quorum-certified chain, heights `1..=n`, every block carrying a full-set
/// precommit QC from the returned validator set (proposer follows the schedule
/// so the F8 proposer-slot gate passes).
fn quorum_chain(n: u64, n_keys: usize) -> (Vec<Block>, ValidatorSet) {
    assert!(n >= 1 && n_keys >= 2, "need a real chain and a real quorum");
    let keys: Vec<SigningKey> = (0..n_keys).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let vs = ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let mut out = Vec::new();
    let mut prev = [0u8; 32];
    for h in 1..=n {
        let proposer_id = vs.proposer_for(h, 0).expect("non-empty set has a proposer");
        let proposer = keys
            .iter()
            .find(|k| k.verifying_key().to_bytes() == proposer_id)
            .expect("proposer is a member")
            .clone();
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: h,
            prev_hash: prev,
            state_root: [h as u8; 32],
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: 1_700_000_000 + h,
            proposer: proposer_id,
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32],
        };
        b.sign_block(&proposer);
        let hash = b.compute_hash();
        let mut sigs = Vec::new();
        for k in &keys {
            let v = Vote::sign(k, h, 0, VoteKind::Precommit, Some(hash));
            sigs.push((v.voter, v.signature));
        }
        b.precommit_qc = Some(QuorumCertificate {
            height: h,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(hash),
            signatures: sigs,
        });
        prev = hash;
        out.push(b);
    }
    (out, vs)
}

fn link_of(b: &Block) -> sync::HeaderLink {
    sync::HeaderLink {
        height: b.height,
        block_hash: b.compute_hash(),
        prev_hash: b.prev_hash,
        state_root: b.state_root,
        proposer: b.proposer,
        qc: b.precommit_qc.clone().expect("quorum chain carries QCs"),
    }
}

async fn funded_engine() -> (InMemoryStateEngine, [u8; 32]) {
    let engine = InMemoryStateEngine::new();
    let user = [0xA1u8; 32];
    engine.update_account(AccountState::new(user, 50_000)).await;
    (engine, user)
}

fn token_meta() -> TokenMetadata {
    TokenMetadata {
        name: "Sync".into(),
        symbol: "SYN".into(),
        decimals: 6,
        total_supply: 0,
        max_supply: None,
        minter: ZERO_ADDRESS,
        paused: false,
        description: String::new(),
    }
}

/// Persist state+domains at `snap_h`, blocks through `tip_h` (block at
/// `snap_h + 1` commits to the post-snapshot root), finalized at the tip.
async fn persist_paired(
    store: &Storage,
    engine: &InMemoryStateEngine,
    snap_h: u64,
    tip_h: u64,
) -> [u8; 32] {
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(engine, &StakingLedger::new(), &Governance::new()).await;
    let dbytes = bincode::serialize(&dom).unwrap();
    store.put_state(snap_h, &snap).unwrap();
    store.put_domains(snap_h, &dbytes).unwrap();
    let mut prev = [0u8; 32];
    for h in 1..=tip_h {
        let sr = if h == snap_h + 1 { root } else { [0xEEu8; 32] };
        let b = mkblock(h, prev, sr);
        prev = store.put_block(&b).unwrap();
        if h == tip_h {
            store.set_finalized(h, &prev).unwrap();
        }
    }
    store.flush().unwrap();
    root
}

// ---------- Forged snapshots: refused, never applied ----------

#[tokio::test]
async fn forged_state_snapshot_is_refused_and_live_engine_untouched() {
    let dir = tmpdir("forged-state");
    let store = Storage::open(&dir).unwrap();
    let (engine, user) = funded_engine().await;
    persist_paired(&store, &engine, 100, 101).await;

    // Attacker/griefed disk: same height label, inflated balance.
    let poison = InMemoryStateEngine::new();
    poison
        .update_account(AccountState::new(user, 999_999_999))
        .await;
    let bad = poison.create_snapshot().await;
    store.put_state(100, &bad).unwrap();

    let fresh = InMemoryStateEngine::new();
    let err = load_full_state_into(&store, &fresh)
        .await
        .expect_err("forged snapshot must be refused");
    assert!(
        format!("{err:?}").contains("mismatch"),
        "loud mismatch refusal, got: {err:?}"
    );
    assert!(
        fresh.get_account(&user).await.is_none(),
        "rejected snapshot must leave the live engine untouched"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn forged_and_truncated_domain_blobs_are_refused() {
    let dir = tmpdir("forged-domains");
    let store = Storage::open(&dir).unwrap();
    let (engine, user) = funded_engine().await;
    persist_paired(&store, &engine, 100, 101).await;
    let good = store.domain_at(100).unwrap().expect("domains present");

    // Garbage bytes under the paired height.
    store.put_domains(100, &[0xFFu8; 64]).unwrap();
    let fresh = InMemoryStateEngine::new();
    assert!(
        load_full_state_into(&store, &fresh).await.is_err(),
        "garbage domain blob must be refused"
    );
    assert!(fresh.get_account(&user).await.is_none());

    // Truncated valid encoding.
    store.put_domains(100, &good[..good.len() / 2]).unwrap();
    let fresh2 = InMemoryStateEngine::new();
    assert!(
        load_full_state_into(&store, &fresh2).await.is_err(),
        "truncated domain blob must be refused"
    );
    assert!(fresh2.get_account(&user).await.is_none());

    // Empty blob.
    store.put_domains(100, &[]).unwrap();
    let fresh3 = InMemoryStateEngine::new();
    assert!(
        load_full_state_into(&store, &fresh3).await.is_err(),
        "empty domain blob must be refused"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn domain_decoder_refuses_empty_and_truncated_blobs() {
    let engine = InMemoryStateEngine::new();
    let dom = DomainSnapshot::capture(&engine, &StakingLedger::new(), &Governance::new()).await;
    let bytes = bincode::serialize(&dom).unwrap();
    assert!(decode_domain_snapshot(&[]).is_err(), "empty blob refused");
    assert!(
        decode_domain_snapshot(&bytes[..bytes.len() / 2]).is_err(),
        "truncated blob refused"
    );
    assert!(
        decode_domain_snapshot(&bytes).is_ok(),
        "valid blob still decodes"
    );
}

// ---------- Torn snapshots: refused or ignored, never half-applied ----------

#[tokio::test]
async fn torn_state_without_domains_is_refused_not_frankensteined() {
    let dir = tmpdir("torn-nodom");
    let store = Storage::open(&dir).unwrap();
    let (engine, user) = funded_engine().await;
    // Crash between the two snapshot jobs: state landed, domains never did.
    let snap = engine.create_snapshot().await;
    store.put_state(100, &snap).unwrap();
    let h0 = store.put_block(&mkblock(100, [0u8; 32], [0xEEu8; 32])).unwrap();
    let h1 = store.put_block(&mkblock(101, h0, engine.get_state_root().await)).unwrap();
    store.set_finalized(101, &h1).unwrap();

    let fresh = InMemoryStateEngine::new();
    assert!(
        load_full_state_into(&store, &fresh).await.is_err(),
        "unpaired state must be refused, not mixed with foreign domains"
    );
    assert!(fresh.get_account(&user).await.is_none());
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn torn_tail_is_ignored_in_favor_of_last_paired_snapshot() {
    let dir = tmpdir("torn-tail");
    let store = Storage::open(&dir).unwrap();
    let (engine, user) = funded_engine().await;
    persist_paired(&store, &engine, 100, 101).await;
    // A newer crashed tail: state@200 with no domains@200.
    engine.update_account(AccountState::new(user, 60_000)).await;
    let snap200 = engine.create_snapshot().await;
    store.put_state(200, &snap200).unwrap();

    let fresh = InMemoryStateEngine::new();
    let (h, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("paired height must still load")
        .expect("snapshot present");
    assert_eq!(h, 100, "only the newest PAIRED height may load");
    assert_eq!(
        fresh.get_account(&user).await.unwrap().balance,
        50_000,
        "no bytes from the torn height may leak into the live engine"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- Walk validation: gaps, forks, empty, shards, QCs ----------

#[test]
fn walk_refuses_gaps_forks_empty_and_wrong_shard() {
    let (blocks, vs) = quorum_chain(5, 3);
    let resolve = |_: u64| Some(vs.clone());

    // Healthy chain validates.
    assert!(sync::validate_sync_chain_with_sets(&blocks, 1, [0u8; 32], &resolve).is_ok());

    // Gap: drop height 3.
    let mut gapped: Vec<Block> = blocks
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, b)| b.clone())
        .collect();
    assert!(sync::validate_sync_chain_with_sets(&gapped, 1, [0u8; 32], &resolve).is_err());

    // Fork at the join point: first block does not extend OUR tip.
    let mut forked = blocks.clone();
    forked[0].prev_hash = [0x77u8; 32];
    assert!(sync::validate_sync_chain_with_sets(&forked, 1, [0u8; 32], &resolve).is_err());

    // Fork mid-chain: broken parent link.
    let mut mid = blocks.clone();
    mid[3].prev_hash = [0x77u8; 32];
    assert!(sync::validate_sync_chain_with_sets(&mid, 1, [0u8; 32], &resolve).is_err());

    // Empty chain proves nothing and must not validate.
    let empty: Vec<Block> = Vec::new();
    assert!(sync::validate_sync_chain_with_sets(&empty, 1, [0u8; 32], &resolve).is_err());
    assert!(
        sync::validate_sync_chain_for_shard_with_sets(&empty, 1, [0u8; 32], &resolve, 0).is_err()
    );

    // Another shard's blocks cannot ride our anchor.
    assert!(
        sync::validate_sync_chain_for_shard_with_sets(&blocks, 1, [0u8; 32], &resolve, 999).is_err()
    );
    assert!(
        sync::validate_sync_chain_for_shard_with_sets(
            &blocks,
            1,
            [0u8; 32],
            &resolve,
            MASTERCHAIN_SHARD
        )
        .is_ok()
    );

    // Duplicate height is a gap in disguise.
    gapped = blocks.clone();
    gapped[2] = blocks[1].clone();
    assert!(sync::validate_sync_chain_with_sets(&gapped, 1, [0u8; 32], &resolve).is_err());
}

#[test]
fn walk_refuses_stripped_and_mismatched_decision_proofs() {
    let (blocks, vs) = quorum_chain(3, 3);
    let resolve = |_: u64| Some(vs.clone());

    // Stripped QC.
    let mut stripped = blocks.clone();
    stripped[1].precommit_qc = None;
    assert!(sync::validate_sync_chain_with_sets(&stripped, 1, [0u8; 32], &resolve).is_err());

    // Wrong QC kind (prevote is not finality).
    let mut wrong_kind = blocks.clone();
    if let Some(qc) = wrong_kind[1].precommit_qc.as_mut() {
        qc.kind = stellereum::consensus::VoteKind::Prevote;
    }
    assert!(sync::validate_sync_chain_with_sets(&wrong_kind, 1, [0u8; 32], &resolve).is_err());

    // QC for another height.
    let mut wrong_h = blocks.clone();
    if let Some(qc) = wrong_h[1].precommit_qc.as_mut() {
        qc.height += 10;
    }
    assert!(sync::validate_sync_chain_with_sets(&wrong_h, 1, [0u8; 32], &resolve).is_err());

    // QC binding a different block.
    let mut wrong_hash = blocks.clone();
    if let Some(qc) = wrong_hash[1].precommit_qc.as_mut() {
        qc.block_hash = Some([0x99u8; 32]);
    }
    assert!(sync::validate_sync_chain_with_sets(&wrong_hash, 1, [0u8; 32], &resolve).is_err());

    // Unresolvable validator set fails closed, never guessed.
    let no_set = |_: u64| None;
    assert!(sync::validate_sync_chain_with_sets(&blocks, 1, [0u8; 32], &no_set).is_err());

    // Empty set (u64::MAX quorum) can never be satisfied.
    let empty_set = ValidatorSet::new();
    assert!(sync::validate_sync_chain(&blocks, 1, [0u8; 32], &empty_set).is_err());
}

#[tokio::test]
async fn walk_fetch_boundary_binds_body_to_requested_hash() {
    let (blocks, _) = quorum_chain(3, 3);
    let head = blocks[2].compute_hash();
    let mut map: HashMap<[u8; 32], Block> = HashMap::new();
    for b in &blocks {
        map.insert(b.compute_hash(), b.clone());
    }

    // Tampered body served under the requested hash: refused before any link walk.
    let mut evil = blocks[2].clone();
    evil.state_root = [0xBBu8; 32];
    let evil_map: HashMap<[u8; 32], Block> =
        [(head, evil)].into_iter().collect();
    let err = sync::collect_missing_blocks(head, [0u8; 32], 100, |h| {
        let b = evil_map.get(&h).cloned();
        async move { b }
    })
    .await
    .expect_err("mismatched body must be refused");
    assert!(err.contains("does not hash"), "got: {err}");

    // Missing parent: refused, never skipped.
    let err = sync::collect_missing_blocks(head, [0u8; 32], 100, |_| async { None })
        .await
        .expect_err("missing parent must be refused");
    assert!(err.contains("missing block"), "got: {err}");

    // Healthy fetch walks ancestor-first back to our tip.
    let genesis = blocks[0].compute_hash();
    let walked = sync::collect_missing_blocks(head, blocks[0].prev_hash, 100, |h| {
        let b = map.get(&h).cloned();
        async move { b }
    })
    .await
    .expect("healthy walk must succeed");
    assert_eq!(walked.len(), 3);
    assert_eq!(walked[0].height, 1);
    assert_eq!(walked[2].compute_hash(), head);
    let _ = genesis;
}

#[test]
fn walked_head_anchor_binds_advertised_height_and_hash() {
    let (blocks, _) = quorum_chain(3, 3);
    let head = blocks[2].compute_hash();
    assert_eq!(sync::walked_head_anchor(&blocks, head, 3).unwrap(), 4);

    // Peer advertises a hash the walk never served.
    assert!(sync::walked_head_anchor(&blocks, [0xABu8; 32], 3).is_err());
    // Peer advertises a height above the served chain.
    assert!(sync::walked_head_anchor(&blocks, head, 4).is_err());
    // Empty walk anchors nothing.
    assert!(sync::walked_head_anchor(&[], head, 3).is_err());
}

// ---------- Fetch-path bindings: body bytes, finality gate ----------

#[test]
fn replicated_body_binding_refuses_tamper_and_garbage() {
    let (blocks, _) = quorum_chain(2, 3);
    let good = &blocks[1];
    let hash = good.compute_hash();
    assert!(sync::verify_replicated_body(&hash, good).is_ok());

    let mut evil = good.clone();
    evil.state_root = [0xE1u8; 32];
    assert!(sync::verify_replicated_body(&hash, &evil).is_err());

    assert!(sync::verify_replicated_bytes(&hash, &[]).is_err());
    assert!(sync::verify_replicated_bytes(&hash, &[0xFFu8; 32]).is_err());
    let bytes = bincode::serialize(good).unwrap();
    assert!(sync::verify_replicated_bytes(&hash, &bytes).is_ok());
}

#[test]
fn finality_gate_rejects_every_qc_mismatch() {
    let (blocks, vs) = quorum_chain(3, 3);
    let b = &blocks[1];
    let hash = b.compute_hash();
    let qc = b.precommit_qc.clone().unwrap();
    assert!(sync::verify_finality_for_header(&vs, b.height, &hash, &b.proposer, &qc).is_ok());

    // Wrong kind.
    let mut wrong = qc.clone();
    wrong.kind = VoteKind::Prevote;
    assert!(sync::verify_finality_for_header(&vs, b.height, &hash, &b.proposer, &wrong).is_err());

    // QC for another height.
    let mut wrong = qc.clone();
    wrong.height += 1;
    assert!(sync::verify_finality_for_header(&vs, b.height, &hash, &b.proposer, &wrong).is_err());

    // QC binding another block.
    let mut wrong = qc.clone();
    wrong.block_hash = Some([0x5Eu8; 32]);
    assert!(sync::verify_finality_for_header(&vs, b.height, &hash, &b.proposer, &wrong).is_err());

    // Non-member proposer holds no schedule slot.
    assert!(
        sync::verify_finality_for_header(&vs, b.height, &hash, &[0x5Eu8; 32], &qc).is_err()
    );

    // Sub-quorum signatures: one of four votes cannot decide.
    let mut thin = qc.clone();
    thin.signatures.truncate(1);
    assert!(sync::verify_finality_for_header(&vs, b.height, &hash, &b.proposer, &thin).is_err());
}

// ---------- Snapshot anchor tail: linkage + QC per height ----------

#[tokio::test]
async fn snapshot_anchor_tail_proves_chain_and_refuses_forgery() {
    let (blocks, vs) = quorum_chain(6, 3);
    let links: HashMap<u64, sync::HeaderLink> =
        blocks.iter().map(|b| (b.height, link_of(b))).collect();

    // Healthy window [4, 5, 6]: trusted root is the successor's state root,
    // boundary hash is the QC-verified block at 5.
    let anchor = sync::verify_snapshot_anchor_tail(6, &vs, |h| {
        let l = links.get(&h).cloned();
        async move { l }
    })
    .await
    .expect("healthy tail must anchor");
    assert_eq!(anchor.state_root, blocks[5].state_root);
    assert_eq!(anchor.boundary_hash, blocks[4].compute_hash());

    // Missing header in the window: refuse, never skip.
    let mut missing = links.clone();
    missing.remove(&5);
    assert!(
        sync::verify_snapshot_anchor_tail(6, &vs, |h| {
            let l = missing.get(&h).cloned();
            async move { l }
        })
        .await
        .is_err()
    );

    // Broken linkage: a forked header inside the window.
    let mut forked = links.clone();
    forked.get_mut(&5).unwrap().prev_hash = [0xF0u8; 32];
    assert!(
        sync::verify_snapshot_anchor_tail(6, &vs, |h| {
            let l = forked.get(&h).cloned();
            async move { l }
        })
        .await
        .is_err()
    );

    // Misreported height: the header is not the height it claims.
    let mut lied = links.clone();
    lied.get_mut(&5).unwrap().height = 99;
    assert!(
        sync::verify_snapshot_anchor_tail(6, &vs, |h| {
            let l = lied.get(&h).cloned();
            async move { l }
        })
        .await
        .is_err()
    );

    // Stripped QC: linkage alone never suffices.
    let mut noqc = links.clone();
    noqc.get_mut(&5).unwrap().qc.signatures.clear();
    assert!(
        sync::verify_snapshot_anchor_tail(6, &vs, |h| {
            let l = noqc.get(&h).cloned();
            async move { l }
        })
        .await
        .is_err()
    );

    // Genesis edge: no height 0 to anchor on.
    assert!(sync::verify_snapshot_anchor_tail(0, &vs, |h| {
        let l = links.get(&h).cloned();
        async move { l }
    })
    .await
    .is_err());
}

// ---------- fast_sync_state: empty/corrupt/poisoned + replay gate ----------

#[tokio::test]
async fn fast_sync_rejects_empty_corrupt_and_wrong_root_blobs() {
    let (source, user) = funded_engine().await;
    let root = source.get_state_root().await;
    let snap = source.create_snapshot().await;

    // No snapshot published at all.
    let target = InMemoryStateEngine::new();
    assert!(
        sync::fast_sync_state(&target, root, || async { None }, |_| async { None })
            .await
            .is_err()
    );

    // Empty blob.
    let target = InMemoryStateEngine::new();
    assert!(
        sync::fast_sync_state(&target, root, || async { Some(vec![]) }, |_| async { None })
            .await
            .is_err()
    );

    // Truncated valid encoding.
    let target = InMemoryStateEngine::new();
    let cut = snap.clone();
    assert!(
        sync::fast_sync_state(
            &target,
            root,
            || async { Some(cut[..cut.len() / 2].to_vec()) },
            |_| async { None }
        )
        .await
        .is_err()
    );
    assert!(target.get_account(&user).await.is_none());

    // Right shape, wrong state (poisoned snapshot vs the anchored root).
    let evil = InMemoryStateEngine::new();
    evil.update_account(AccountState::new(user, 999_999_999)).await;
    let poisoned = evil.create_snapshot().await;
    let target = InMemoryStateEngine::new();
    let err = sync::fast_sync_state(
        &target,
        root,
        || async { Some(poisoned.clone()) },
        |_| async { None },
    )
    .await
    .expect_err("poisoned snapshot must be refused");
    assert!(err.contains("mismatch"), "got: {err}");
    assert!(
        target.get_account(&user).await.is_none(),
        "refused sync must leave the target untouched"
    );
}

#[tokio::test]
async fn fast_sync_accepts_full_bundle_and_converges_roots() {
    let source = InMemoryStateEngine::new();
    let user = [0x66u8; 32];
    source.update_account(AccountState::new(user, 1_000_000)).await;
    let _tid = source.create_token(user, token_meta(), 500).await.unwrap();
    let root = source.get_state_root().await;
    let snap = source.create_snapshot().await;
    let staking = source.staking_read().await.clone();
    let gov = source.governance_read().await.clone();
    let dom = DomainSnapshot::capture(&source, &staking, &gov).await;
    let dbytes = bincode::serialize(&dom).unwrap();
    let bundle: HashMap<String, Vec<u8>> =
        [("domains".to_string(), dbytes)].into_iter().collect();

    let target = InMemoryStateEngine::new();
    sync::fast_sync_state(
        &target,
        root,
        || async { Some(snap.clone()) },
        |kind: &'static str| {
            let bundle = bundle.clone();
            async move { bundle.get(kind).cloned() }
        },
    )
    .await
    .expect("full bundle must verify");
    assert_eq!(target.get_state_root().await, root);
    assert_eq!(target.get_account(&user).await.unwrap().balance, 1_000_000);
}

#[tokio::test]
async fn fast_sync_replay_gate_refuses_to_drop_local_replay_state() {
    let (source, _) = funded_engine().await;
    let root = source.get_state_root().await;
    let snap = source.create_snapshot().await;

    // Target already committed cross-shard replay; the incoming bundle omits it.
    let key = CrossShardKey {
        source_shard: MASTERCHAIN_SHARD,
        finalized_in_block: [0x11u8; 32],
        msg_id: [0x22u8; 32],
    };
    let local = CrossShardReplaySnapshot {
        engine_consumed: vec![key],
        runtime_consumed: vec![],
        produced: vec![],
        completed: vec![],
        xpc: vec![],
    };
    let target = InMemoryStateEngine::new();
    target.restore_cross_shard_replay(&local).await;
    let before = target.get_state_root().await;
    let err = sync::fast_sync_state(
        &target,
        root,
        || async { Some(snap.clone()) },
        |_| async { None },
    )
    .await
    .expect_err("dropping local replay must be refused");
    assert!(err.contains("cross_shard"), "got: {err}");
    assert_eq!(
        target.get_state_root().await, before,
        "refused sync must not mutate the target"
    );

    // A covering bundle (same replay state on both sides) proceeds.
    let seeded = InMemoryStateEngine::new();
    seeded.restore_cross_shard_replay(&local).await;
    let user = [0xA1u8; 32];
    seeded.update_account(AccountState::new(user, 50_000)).await;
    let root2 = seeded.get_state_root().await;
    let snap2 = seeded.create_snapshot().await;
    let incoming = bincode::serialize(&local).unwrap();
    let bundle: HashMap<String, Vec<u8>> =
        [("cross_shard".to_string(), incoming)].into_iter().collect();
    let target2 = InMemoryStateEngine::new();
    target2.restore_cross_shard_replay(&local).await;
    sync::fast_sync_state(
        &target2,
        root2,
        || async { Some(snap2.clone()) },
        |kind: &'static str| {
            let bundle = bundle.clone();
            async move { bundle.get(kind).cloned() }
        },
    )
    .await
    .expect("covering replay bundle must verify");
    assert_eq!(target2.get_state_root().await, root2);
}

// ---------- Pruning: retain-to-verify, refuse-the-rest ----------

#[tokio::test]
async fn prune_then_serve_retained_verifies_and_pruned_honestly_misses() {
    let dir = tmpdir("prune-serve");
    let store = Storage::open(&dir).unwrap();
    // Chain 1..=12, paired snapshots at 4 and 8, tip at 12.
    let (engine, user) = funded_engine().await;
    let root = engine.get_state_root().await;
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(&engine, &StakingLedger::new(), &Governance::new()).await;
    let dbytes = bincode::serialize(&dom).unwrap();
    for h in [4u64, 8] {
        store.put_state(h, &snap).unwrap();
        store.put_domains(h, &dbytes).unwrap();
    }
    let mut prev = [0u8; 32];
    for h in 1..=12u64 {
        let sr = if h == 9 { root } else { [h as u8; 32] };
        let b = mkblock(h, prev, sr);
        prev = store.put_block(&b).unwrap();
        if h == 12 {
            store.set_finalized(h, &prev).unwrap();
        }
    }
    store.flush().unwrap();

    // Aggressive prune: keep bodies from 10 on (boundary rule retains 9).
    store.prune_blocks_below(10).unwrap();
    store.prune_state_below(10).unwrap();
    store.prune_domains_below(10).unwrap();

    // Headers survive body pruning at every height: the anchor path needs them.
    for h in 1..=12u64 {
        assert!(
            store.header_at(h).unwrap().is_some(),
            "header at {h} must survive body pruning"
        );
    }
    // Boundary rule: keep_from - 1 stays so the suffix still links.
    assert!(
        store.hashes_at_height(9).unwrap().len() == 1,
        "height keep_from-1 must be retained"
    );
    assert!(store.hashes_at_height(8).unwrap().is_empty());
    // Retained bodies still verify against their committed hashes.
    for h in [9u64, 10, 11, 12] {
        let hashes = store.hashes_at_height(h).unwrap();
        assert_eq!(hashes.len(), 1, "retained height {h} must resolve");
        let body = store.committed_body(h, &hashes[0]).unwrap().expect("body present");
        assert_eq!(body.compute_hash(), hashes[0]);
    }
    // Pruned heights are honest misses, never fabrications.
    assert!(store.hashes_at_height(3).unwrap().is_empty());
    assert!(store.committed_body(3, &[0x44u8; 32]).unwrap().is_none());
    // Snapshot anchor for the retained paired height resolves via headers.
    assert_eq!(store.expected_restore_root(8).unwrap(), Some(root));
    assert_eq!(store.retained_archive_heights().unwrap(), vec![8]);
    // A paranoid re-verify of the retained snapshot passes through the anchor.
    let fresh = InMemoryStateEngine::new();
    let (h, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("retained snapshot must verify")
        .expect("present");
    assert_eq!(h, 8);
    assert_eq!(fresh.get_account(&user).await.unwrap().balance, 50_000);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn pruned_qc_anchor_refuses_but_retained_heights_still_serve() {
    let dir = tmpdir("prune-qc");
    let store = Storage::open(&dir).unwrap();
    let (blocks, _) = quorum_chain(12, 3);
    for b in &blocks {
        store.put_block(b).unwrap();
    }
    let tip_hash = blocks[11].compute_hash();
    store.set_finalized(12, &tip_hash).unwrap();
    store.flush().unwrap();

    // Pre-prune: the anchor + QC for height 11 are retained and serve.
    let served = store.historical_root(11, 12).unwrap();
    assert_eq!(served.anchor_height, 12);
    assert!(served.finalized);

    // Prune bodies below 10 (retains 9..=12, headers everywhere).
    store.prune_blocks_below(10).unwrap();

    // Still anchored: height 11's anchor block (12) is retained.
    assert!(store.historical_root(11, 12).is_ok());
    // Height 8's anchor block (9) is retained too.
    assert!(store.historical_root(8, 12).is_ok());
    // Height 7's anchor block (8) was pruned: honest refusal, never a bare root.
    let err = store
        .historical_root(7, 12)
        .expect_err("pruned QC anchor must be refused");
    assert!(
        format!("{err:?}").contains("not retained"),
        "fail-closed pruned error, got: {err:?}"
    );
    // Above-tip requests are refused as future, not served.
    assert!(store.historical_root(99, 12).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn keep_window_covers_walk_retro_and_prune_boundaries() {
    // The retention argument: KEEP >> retro publish depth >> the 256-block
    // body-walk cap (the cap lives in the binary's walk; read it here as the
    // documented bound), so pruning below tip-KEEP can never delete a body
    // the walk or the retro window may still ask for.
    let keep_win: u64 = sync::ADOPT_REPL_KEEP_WINDOW;
    let retro_depth: u64 = sync::ADOPT_REPL_RETRO_DEPTH;
    let walk_cap: u64 = 256;
    assert!(
        keep_win >= retro_depth,
        "KEEP ({keep_win}) must cover the retro depth ({retro_depth})"
    );
    assert!(
        retro_depth > walk_cap,
        "retro depth ({retro_depth}) must cover the body-walk cap ({walk_cap})"
    );

    let tip = 50_000u64;
    let keep = sync::ADOPT_REPL_KEEP_WINDOW;
    let retro = sync::ADOPT_REPL_RETRO_DEPTH;
    assert!(sync::height_is_replicable(tip, tip, keep, retro));
    assert!(sync::height_is_replicable(tip - retro, tip, keep, retro));
    assert!(!sync::height_is_replicable(tip - retro - 1, tip, keep, retro));
    assert!(!sync::height_is_replicable(tip - keep - 1, tip, keep, retro));
    assert!(!sync::height_is_replicable(tip + 1, tip, keep, retro));

    // Backfill plans tip-ward windows of replicable heights only.
    let plan = sync::plan_backfill_tip_ward(0, 5_000, 64, keep, retro);
    assert_eq!(plan.len(), 64);
    assert_eq!(*plan.last().unwrap(), 5_000);
    assert_eq!(*plan.first().unwrap(), 5_000 - 63);
    assert!(sync::plan_backfill_tip_ward(5_000, 5_000, 64, keep, retro).is_empty());
    assert!(sync::plan_backfill_tip_ward(0, 5_000, 0, keep, retro).is_empty());

    // Prune boundary rule: keep_from - 1 stays, everything older goes, so the
    // retained suffix always links back through one more parent.
    let dir = tmpdir("keep-bound");
    let store = Storage::open(&dir).unwrap();
    let mut prev = [0u8; 32];
    for h in 0..10u64 {
        prev = store.put_block(&mkblock(h, prev, [h as u8; 32])).unwrap();
    }
    store.prune_blocks_below(6).unwrap();
    assert_eq!(store.hashes_at_height(5).unwrap().len(), 1);
    assert!(store.hashes_at_height(4).unwrap().is_empty());
    assert!(!store.has_blocks_below(6).unwrap(), "second pass must be a no-op");
    let _ = prev;
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn aux_prune_preserves_snapshotted_heights_and_drops_junk() {
    let dir = tmpdir("aux-prune");
    let store = Storage::open(&dir).unwrap();
    for h in [5u64, 6, 7] {
        store.put_session_keys(h, b"sk").unwrap();
        store.put_bridge(h, b"br").unwrap();
        store.put_confidential(h, b"cf").unwrap();
        store.put_zkml_models(h, b"zk").unwrap();
        store.put_cross_shard(h, b"xs").unwrap();
    }
    store.put_state(7, b"st").unwrap();
    store.put_domains(7, b"dm").unwrap();

    // Prune far past the snapshotted height (stalled snapshot cadence):
    // rows at the snapshotted height survive, unsnapshotted rows go.
    store.prune_state_below(100).unwrap();
    store.prune_domains_below(100).unwrap();
    assert!(store.get_state(7).unwrap().is_some());
    assert!(store.domain_at(7).unwrap().is_some());
    assert!(store.session_keys_at(7).unwrap().is_some());
    assert!(store.bridge_at(7).unwrap().is_some());
    assert!(store.confidential_at(7).unwrap().is_some());
    assert!(store.zkml_models_at(7).unwrap().is_some());
    assert!(store.cross_shard_at(7).unwrap().is_some());
    assert!(store.session_keys_at(5).unwrap().is_none());
    assert!(store.bridge_at(5).unwrap().is_none());
    assert!(store.cross_shard_at(6).unwrap().is_none());
    std::fs::remove_dir_all(&dir).ok();

    // Orphan aux rows at heights no snapshot covers are collectable even when
    // they are the tree's newest: nothing will ever read them by height.
    let dir = tmpdir("aux-junk");
    let store = Storage::open(&dir).unwrap();
    store.put_state(11, b"st").unwrap();
    store.put_domains(11, b"dm").unwrap();
    store.put_domains(3, b"old").unwrap();
    store.put_cross_shard(3, b"old").unwrap();
    store.prune_domains_below(5).unwrap();
    assert!(store.domain_at(3).unwrap().is_none());
    assert!(store.cross_shard_at(3).unwrap().is_none());
    assert!(store.domain_at(11).unwrap().is_some());
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- Restore anchor branches: height 0, tip, overflow ----------

#[tokio::test]
async fn height_zero_mismatch_refuses_without_purging_evidence() {
    let dir = tmpdir("h0");
    let store = Storage::open(&dir).unwrap();
    let (engine, _) = funded_engine().await;
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(&engine, &StakingLedger::new(), &Governance::new()).await;
    store.put_state(0, &snap).unwrap();
    store.put_domains(0, &bincode::serialize(&dom).unwrap()).unwrap();
    // The finalized chain disagrees with the genesis snapshot bytes.
    let h1 = store.put_block(&mkblock(1, [0u8; 32], [0xEEu8; 32])).unwrap();
    store.set_finalized(1, &h1).unwrap();

    let fresh = InMemoryStateEngine::new();
    let err = load_full_state_into(&store, &fresh)
        .await
        .expect_err("height-0 mismatch must be refused, not purged-and-accepted");
    assert!(format!("{err:?}").contains("mismatch"), "got: {err:?}");
    assert!(
        store.get_state(0).unwrap().is_some(),
        "a refused snapshot must not be silently deleted"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn tip_without_anchor_loads_but_below_tip_without_anchor_refuses() {
    // Snapshot AT the finalized tip with no successor: nothing contradicts it.
    let dir = tmpdir("tip-ok");
    let store = Storage::open(&dir).unwrap();
    let (engine, user) = funded_engine().await;
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(&engine, &StakingLedger::new(), &Governance::new()).await;
    store.put_state(77, &snap).unwrap();
    store.put_domains(77, &bincode::serialize(&dom).unwrap()).unwrap();
    let hb = store.put_block(&mkblock(77, [0u8; 32], [0xEEu8; 32])).unwrap();
    store.set_finalized(77, &hb).unwrap();
    let fresh = InMemoryStateEngine::new();
    let (h, _, _) = load_full_state_into(&store, &fresh)
        .await
        .expect("tip snapshot must load")
        .expect("present");
    assert_eq!(h, 77);
    assert_eq!(fresh.get_account(&user).await.unwrap().balance, 50_000);
    std::fs::remove_dir_all(&dir).ok();

    // Same snapshot, but finality moved past it with no successor persisted:
    // loading blind would resume on unprovable state.
    let dir = tmpdir("tip-refuse");
    let store = Storage::open(&dir).unwrap();
    store.put_state(77, &snap).unwrap();
    store.put_domains(77, &bincode::serialize(&dom).unwrap()).unwrap();
    store.put_block(&mkblock(77, [0u8; 32], [0xEEu8; 32])).unwrap();
    store.set_finalized(80, &[0xABu8; 32]).unwrap();
    let fresh = InMemoryStateEngine::new();
    let err = load_full_state_into(&store, &fresh)
        .await
        .expect_err("unanchored snapshot below the tip must be refused");
    assert!(format!("{err:?}").contains("no anchor"), "got: {err:?}");
    assert!(fresh.get_account(&user).await.is_none());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn expected_restore_root_rejects_overflow_and_reports_unknown() {
    let dir = tmpdir("anchor-edge");
    let store = Storage::open(&dir).unwrap();
    assert!(store.expected_restore_root(u64::MAX).is_err());
    assert_eq!(store.expected_restore_root(999).unwrap(), None);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- Genesis fingerprint + bootstrap gates ----------

#[test]
fn genesis_mismatch_message_names_both_roots_and_recovery() {
    let expected = [0x11u8; 32];
    let found = vec![0x22u8; 32];
    let msg = bootstrap::genesis_mismatch_msg(None, &expected, &found);
    assert!(msg.contains(&hex::encode(expected)[..16]));
    assert!(msg.contains(&hex::encode(&found)[..16]));
    assert!(msg.contains("STELL_FAUCET_KEY"));
    assert!(msg.contains("Wipe"));
    let shard_msg = bootstrap::genesis_mismatch_msg(Some(3), &expected, &found);
    assert!(shard_msg.contains('3'));
}

#[test]
fn fresh_join_guard_and_observer_flag_are_fail_closed() {
    // Dirty dir = restart: the fingerprint guard owns it, not this gate.
    assert!(bootstrap::guard_fresh_data_dir(false, true, false).is_ok());
    // Clean dir, no peer pointer: founding is the only interpretation.
    assert!(bootstrap::guard_fresh_data_dir(true, false, false).is_ok());
    // Clean dir WITH peers and no explicit founding flag: refuse loudly.
    let err = bootstrap::guard_fresh_data_dir(true, true, false).expect_err("must refuse");
    assert!(err.contains(bootstrap::NEW_CHAIN_ENV), "got: {err}");
    // Explicit founding proceeds.
    assert!(bootstrap::guard_fresh_data_dir(true, true, true).is_ok());

    assert!(bootstrap::is_observer_env(Some("1")));
    assert!(bootstrap::is_observer_env(Some("TRUE")));
    assert!(!bootstrap::is_observer_env(None));
    assert!(!bootstrap::is_observer_env(Some("yes")));
    assert!(bootstrap::is_new_chain_explicit(Some("1")));
    assert!(!bootstrap::is_new_chain_explicit(None));

    assert!(bootstrap::data_dir_is_clean(false, false));
    assert!(!bootstrap::data_dir_is_clean(true, false));
    assert!(!bootstrap::data_dir_is_clean(false, true));
}

#[test]
fn bootstrap_boundary_selection_never_outruns_the_probe_window() {
    // Walk-sized gaps need no snapshot.
    assert_eq!(bootstrap::select_bootstrap_boundary(50, 0, None), None);
    assert_eq!(bootstrap::select_bootstrap_boundary(100, 0, None), None);
    // Newest 100-boundary below the tip.
    assert_eq!(bootstrap::select_bootstrap_boundary(72704, 0, None), Some(72700));
    // Sane exact pointer wins; insane pointers are ignored, never trusted.
    assert_eq!(
        bootstrap::select_bootstrap_boundary(78620, 0, Some(78519)),
        Some(78519)
    );
    assert_eq!(
        bootstrap::select_bootstrap_boundary(78620, 0, Some(99999)),
        Some(78600)
    );
    // Nothing ahead of us: nothing to do.
    assert_eq!(bootstrap::select_bootstrap_boundary(100, 100, None), None);
    assert_eq!(bootstrap::select_bootstrap_boundary(90, 100, None), None);

    // Stale-boundary stepping retries, then steps down, then refuses loudly.
    assert_eq!(bootstrap::next_boundary_after_stale(72700, 0, 0), Some(72700));
    assert_eq!(bootstrap::next_boundary_after_stale(72700, 3, 0), Some(72600));
    assert_eq!(bootstrap::next_boundary_after_stale(100, 3, 0), None);
    assert!(bootstrap::bootstrap_retry_delay_ms(1, 0) >= 100);
}

// ---------- Fetch-path pure bounds: timeouts, retries, budgets ----------

#[test]
fn retry_backoff_never_hurries_and_budgets_stay_bounded() {
    // Floor is always the exponential base: a timed-out fetch never retries
    // sooner than 100ms (the anti-re-flood contract).
    assert_eq!(sync::fetch_retry_backoff_ms(0), 100);
    assert_eq!(sync::fetch_retry_backoff_ms(1), 100);
    assert_eq!(sync::fetch_retry_backoff_ms(2), 200);
    assert_eq!(sync::fetch_retry_backoff_ms(100), sync::FETCH_RETRY_MAX_BACKOFF_MS);
    // Jitter only delays (clamped), never hurries.
    assert_eq!(
        sync::fetch_retry_backoff_with_jitter_ms(1, 10_000),
        sync::fetch_retry_backoff_with_jitter_ms(1, 0) + sync::FETCH_RETRY_JITTER_MAX_MS
    );
    // Snapshot blob budget: floored for small blobs, capped for huge ones.
    assert_eq!(sync::snapshot_blob_budget_ms(0), 60_000);
    assert_eq!(sync::snapshot_blob_budget_ms(1_000_000), sync::SNAPSHOT_BLOB_TIMEOUT_MS);
    // Probe pacing is linear then capped.
    assert_eq!(sync::snapshot_probe_pace_ms(0), 0);
    assert_eq!(
        sync::snapshot_probe_pace_ms(1_000_000),
        sync::SNAPSHOT_PROBE_PACE_MAX_MS
    );
    // Large blobs assemble strictly serially.
    assert_eq!(sync::chunk_batch_for_blob(50), 1);
    assert_eq!(sync::chunk_batch_for_blob(3), sync::FETCH_BLOB_CHUNK_BATCH);
    assert_eq!(
        sync::plan_chunk_batches(10, 4),
        vec![(0, 4), (4, 8), (8, 10)]
    );
    assert!(sync::plan_chunk_batches(0, 4).is_empty());
}

#[tokio::test]
async fn chunk_assembly_resumes_and_names_the_failed_chunk() {
    // All chunks present: assembled in order.
    let got = sync::assemble_chunks_resumable(3, 0, |i| async move { Some(vec![i as u8]) })
        .await
        .expect("complete fetch assembles");
    assert_eq!(got, vec![vec![0u8], vec![1u8], vec![2u8]]);

    // One chunk permanently missing: loud failure naming the chunk, with the
    // per-chunk attempt budget spent (max_retries + 1 tries).
    let err = sync::assemble_chunks_resumable(3, 2, |i| async move {
        if i == 1 { None } else { Some(vec![i as u8]) }
    })
    .await
    .expect_err("missing chunk must fail closed");
    assert_eq!(err.chunk_index, 1);
    assert_eq!(err.n_chunks, 3);
    assert_eq!(err.attempts, 3);
    assert_eq!(err.timeout_ms, sync::SNAPSHOT_CHUNK_TIMEOUT_MS);
}
