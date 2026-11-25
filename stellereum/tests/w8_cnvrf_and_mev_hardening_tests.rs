//! Wave 8 regression tests for Wave 6 CN-VRF v3, MEV Epoch Seal, and Storage Retention findings:
//!
//! 1. `W6-A7-1`: `cnvrf_freeze_inputs` is persisted in its own `"cnvrf_freeze_inputs"` sled tree,
//!    restored by `load_full_state_into` / `verify_restored_root`, synced to `ValidatorRuntime` on
//!    boot, and `apply_cnvrf_v3` does NOT skip `raw_seed == expected_seed` after `H_freeze`.
//! 2. `W6-A1-4`: `adopt_committed` and `walk_chain_once_with_lanes` extract & verify
//!    `block.cnvrf_v3.epoch_vdf` into `ready_vdf_beacons` before consulting
//!    `committee_schedule_at(H)`, while preserving pre-activation behavior.
//! 3. `W6-A7-2`: `OrderCommitment` Falcon-512 signing/verification + `EpochSealManager::note_commitment`
//!    epoch binding, committee/proposer membership, and `height_commitment` anti-equivocation.
//! 4. `W6-A7-3`: `ShareRelease` / `PqShareReleaseEnvelope` authentication, `1..=N` bounds checks,
//!    and no-overwrite anti-equivocation in `ingest_release` / `combine_partials_checked`.
//! 5. `W6-A7-4`: `EpochKeyAnnouncement::valid_signature_count` + `merge_announcement` require
//!    committee/validator membership (no arbitrary throwaway Ed25519 keys) with PQ support.
//! 6. `retention.rs:243`: `body_is_removable` avoids `u64::MAX + 1` overflow via `saturating_add(1)`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use stellereum::cn_vrf::{
    epoch_seed, freeze_height_of_epoch, EPOCH_LEN, V3_COMMIT_LOOKAHEAD_BLOCKS,
};
use stellereum::consensus::{
    produce_decision_certificate_with_schedule, register_validator_pq_key, CommitteeSchedule,
    EpochBeacon, FalconKeypair, HeightConsensus, ValidatorSet, Vote, VoteKind, VoteSet,
    MICRO_COMMITTEE_MAX_SIZE,
};
use stellereum::mev_epoch::{
    combine_partials_checked, compute_partial, kem_member_tag, pq_kem_ek_from_seed,
    pq_share_release_seal, pq_share_release_verify, pq_transport_seal, seal_transaction,
    CommitteeMember, DecryptionPartial, EpochCommittee, EpochSealManager, MevFrame,
    OrderCommitment, PqTransportEnvelope, ShareRelease, TransparentMeta,
};
use stellereum::mev_kem_registry::MevKemRegistry;
use stellereum::minroot_vdf::{derive_vdf_output, eval as vdf_eval};
use stellereum::network::{EpochTag, P2pNetworkAdapter};
use stellereum::post_quantum::{set_pure_pq_override, PqScheme};
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, CnVrfV3BlockPayload, EpochVdfBeacon, MASTERCHAIN_SHARD};
use stellereum::staking::required_bond_floor_nano;
use stellereum::state_engine::{CnVrfV3EngineSnapshot, InMemoryStateEngine};
use stellereum::storage::{load_full_state_into, AsyncPersistence, Storage};

#[path = "../src/node/policy.rs"]
#[allow(dead_code)]
pub(crate) mod node_policy;

#[allow(dead_code)]
mod node {
    pub(crate) use crate::node_policy as policy;
}

#[path = "../src/node/sync.rs"]
#[allow(dead_code)]
mod node_sync;

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("stell-w8-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

async fn flush_persist(ap: &AsyncPersistence) {
    ap.request_flush();
    for _ in 0..500 {
        if ap.pending() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

struct PurePqGuard(Option<bool>);

impl PurePqGuard {
    fn enforce() -> Self {
        let prev = stellereum::post_quantum::is_pure_pq_enforced();
        set_pure_pq_override(Some(true));
        Self(Some(prev))
    }
}

impl Drop for PurePqGuard {
    fn drop(&mut self) {
        set_pure_pq_override(self.0);
    }
}

fn empty_block(
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    proposer: [u8; 32],
) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_760_000_000u64.saturating_add(height),
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        order_merkle_root: stellereum::mev::compute_order_merkle_root(&[]),
        epoch_key_commitment: [0u8; 32],
        round: 0,
    }
}

#[tokio::test]
async fn w6_a7_1_cnvrf_freeze_inputs_persist_across_restart_and_enforce_seed_after_h_freeze() {
    let dir = temp_dir("w6-a7-1");
    let storage = Arc::new(Storage::open(&dir).expect("open storage"));
    let ap = AsyncPersistence::start(storage.clone());

    let sk = SigningKey::from_bytes(&[0x41u8; 32]);
    let proposer = sk.verifying_key().to_bytes();
    let h_freeze = freeze_height_of_epoch(1);
    assert_eq!(h_freeze, EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS);

    let engine = InMemoryStateEngine::new();
    engine.set_cnvrf_v3_activation_height_for_tests(0);

    // Apply H_freeze block so engine snapshots `cnvrf_freeze_inputs[1]`.
    let root_pre = engine.get_state_root().await;
    let b_freeze = empty_block(h_freeze, [0x11u8; 32], root_pre, proposer);
    let freeze_hash = b_freeze.compute_hash();
    engine.apply_block_transition(&b_freeze, 0).await;

    let expected_freeze = engine
        .cnvrf_freeze_inputs_read()
        .await
        .get(&1)
        .copied()
        .expect("H_freeze must populate cnvrf_freeze_inputs[1]");
    assert_eq!(expected_freeze.0, freeze_hash);

    // Persist snapshot at h_freeze alongside an anchor header at h_freeze + 1.
    let root_post = engine.get_state_root().await;
    ap.enqueue_block(b_freeze.clone());
    let anchor = empty_block(h_freeze + 1, freeze_hash, root_post, proposer);
    let anchor_hash = anchor.compute_hash();
    ap.enqueue_block(anchor.clone());
    ap.enqueue_finalized(h_freeze + 1, anchor_hash);
    ap.snapshot_state(&engine, h_freeze).await;
    let staking = engine.staking_read().await.clone();
    let gov = engine.governance_read().await.clone();
    ap.snapshot_domains(&engine, &staking, &gov, h_freeze).await;
    flush_persist(&ap).await;

    // Legacy empty CnVrfV3EngineSnapshot bincode decoding must still work cleanly.
    let legacy_bytes = bincode::serialize(&CnVrfV3EngineSnapshot::default()).unwrap();
    let legacy_decoded: CnVrfV3EngineSnapshot =
        bincode::deserialize(&legacy_bytes).expect("legacy CnVrfV3EngineSnapshot must decode");
    assert!(legacy_decoded.is_empty());

    // Restore into a fresh engine via load_full_state_into.
    let restored = Arc::new(InMemoryStateEngine::new());
    restored.set_cnvrf_v3_activation_height_for_tests(0);
    let (loaded_h, _, _) = load_full_state_into(&storage, &restored)
        .await
        .expect("load_full_state_into must verify")
        .expect("paired snapshot must exist");
    assert_eq!(loaded_h, h_freeze);
    assert_eq!(restored.get_state_root().await, root_post);
    assert_eq!(
        restored.cnvrf_freeze_inputs_read().await.get(&1).copied(),
        Some(expected_freeze),
        "cnvrf_freeze_inputs must survive snapshot/restart"
    );

    // Runtime boot sync loads persisted cnvrf_freeze_inputs into ValidatorRuntime mirror.
    let mut rt = ValidatorRuntime::new(
        sk.clone(),
        ValidatorSet::from_list(vec![(proposer, 1)]),
        restored.clone(),
        1,
    );
    rt.set_cnvrf_v3_activation_height_for_tests(0);
    rt.set_cnvrf_v3_vdf_steps(16);
    rt.sync_cnvrf_v3_on_boot().await;

    // A boundary block carrying a valid MinRoot proof over a FORGED raw_seed must be rejected
    // by both `validate_cnvrf_v3_payload` and `apply_block_transition`.
    let forged_seed = [0x99u8; 48];
    let forged_proof = vdf_eval(&forged_seed, 16, 4);
    let mut bad_boundary = empty_block(EPOCH_LEN, freeze_hash, root_post, proposer);
    bad_boundary.cnvrf_v3 = Some(CnVrfV3BlockPayload {
        reveal: None,
        commits: vec![],
        epoch_vdf: Some(EpochVdfBeacon {
            epoch: 1,
            raw_seed: forged_seed,
            proof: forged_proof.clone(),
        }),
    });
    assert!(
        rt.validate_cnvrf_v3_payload(&bad_boundary).is_err(),
        "restored runtime must reject forged raw_seed against persisted freeze input"
    );
    restored.apply_block_transition(&bad_boundary, 0).await;
    assert!(
        !restored.epoch_vdf_beacons_read().await.contains_key(&1),
        "state engine must not record epoch_vdf with mismatched raw_seed"
    );

    // Even on a fresh engine that jumped directly to EPOCH_LEN without freeze_inputs,
    // apply_cnvrf_v3 must NOT skip `raw_seed == expected_seed` (`seed_matches = true`) after H_freeze!
    let no_history = InMemoryStateEngine::new();
    no_history.set_cnvrf_v3_activation_height_for_tests(0);
    no_history.apply_block_transition(&bad_boundary, 0).await;
    assert!(
        !no_history.epoch_vdf_beacons_read().await.contains_key(&1),
        "post-H_freeze engine without freeze_inputs must NOT blindly accept unverified raw_seed"
    );

    // Genuine raw_seed derived from the persisted freeze input succeeds and records epoch 1.
    let genuine_seed = epoch_seed(
        restored.chain_id,
        1,
        None,
        false,
        &expected_freeze.0,
        &expected_freeze.1,
    );
    let genuine_proof = vdf_eval(&genuine_seed, 16, 4);
    let expected_out = derive_vdf_output(&genuine_seed, &genuine_proof);
    let mut good_boundary = empty_block(EPOCH_LEN, freeze_hash, root_post, proposer);
    good_boundary.cnvrf_v3 = Some(CnVrfV3BlockPayload {
        reveal: None,
        commits: vec![],
        epoch_vdf: Some(EpochVdfBeacon {
            epoch: 1,
            raw_seed: genuine_seed,
            proof: genuine_proof,
        }),
    });
    rt.validate_cnvrf_v3_payload(&good_boundary)
        .expect("genuine boundary beacon must verify after restart");
    restored.apply_block_transition(&good_boundary, 0).await;
    assert_eq!(
        restored.epoch_vdf_beacons_read().await.get(&1).copied(),
        Some(expected_out),
        "genuine epoch_vdf must be recorded after restart"
    );

    drop(ap);
    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)] // GATE: process-global PQ registry serialized across node_sync tests.
async fn w6_a1_4_adopt_committed_and_walk_chain_extract_epoch_vdf_before_schedule() {
    let _global = node_policy::test_support::global_lock();
    const ACTIVATION: u64 = 1;
    const VDF_STEPS: u64 = 16;
    let n = MICRO_COMMITTEE_MAX_SIZE as usize + 2;
    let bond = required_bond_floor_nano();

    let ks: Vec<SigningKey> = (0..n)
        .map(|i| {
            let mut b = [0x88u8; 32];
            b[0] = i as u8;
            SigningKey::from_bytes(&b)
        })
        .collect();
    let fks: Vec<FalconKeypair> = (0..n)
        .map(|i| FalconKeypair::generate_from_seed(0x40 + i as u8))
        .collect();
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    let vs = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), bond))
            .collect(),
    );

    let seed_engine = |engine: &InMemoryStateEngine| {
        let vs_ids: Vec<_> = ks.iter().zip(fks.iter()).collect();
        let rt_handle = engine.clone();
        async move {
            let mut ledger = rt_handle.staking_write().await;
            let mut pq_reg = rt_handle.pq_registry_write().await;
            for (k, fk) in vs_ids {
                let id = k.verifying_key().to_bytes();
                ledger.bond(id, bond, 0).unwrap();
                ledger
                    .validator_pq_keys
                    .insert(id, (PqScheme::Falcon512, fk.public_key.clone()));
                let _ = pq_reg.adopt_legacy_key_at(
                    id,
                    PqScheme::Falcon512,
                    fk.public_key.clone(),
                    0,
                    true,
                );
            }
            stellereum::consensus::sync_committed_pq_registry(&pq_reg, true);
        }
    };

    // Build shared state at H_freeze(1) and then EPOCH_LEN - 1 on producer, adopter, and walker.
    let h_freeze = freeze_height_of_epoch(1);
    let prod_eng = Arc::new(InMemoryStateEngine::new());
    let adopt_eng = Arc::new(InMemoryStateEngine::new());
    let walk_eng = Arc::new(InMemoryStateEngine::new());
    for e in [&prod_eng, &adopt_eng, &walk_eng] {
        seed_engine(e).await;
    }

    let mut producer = ValidatorRuntime::new(ks[0].clone(), vs.clone(), prod_eng, 1)
        .with_falcon_key(fks[0].clone());
    let mut adopter = ValidatorRuntime::new(ks[1].clone(), vs.clone(), adopt_eng, 1)
        .with_falcon_key(fks[1].clone());
    let mut walker = ValidatorRuntime::new(ks[2].clone(), vs.clone(), walk_eng, 1)
        .with_falcon_key(fks[2].clone());
    for rt in [&mut producer, &mut adopter, &mut walker] {
        rt.set_cnvrf_v3_activation_height_for_tests(ACTIVATION);
        rt.set_cnvrf_v3_vdf_steps(VDF_STEPS);
    }

    // Apply block at H_freeze(1) on all three nodes so freeze_inputs[1] is recorded.
    let make_signed_block = |height: u64,
                             prev_hash: [u8; 32],
                             state_root: [u8; 32],
                             schedule: CommitteeSchedule,
                             cnvrf_v3: Option<CnVrfV3BlockPayload>| {
        let prop_id = vs
            .proposer_for_with_schedule(height, 0, schedule)
            .expect("scheduled proposer");
        let pidx = ks
            .iter()
            .position(|k| k.verifying_key().to_bytes() == prop_id)
            .unwrap();
        let mut b = empty_block(height, prev_hash, state_root, prop_id);
        b.cnvrf_v3 = cnvrf_v3;
        b.sign_block_with_falcon(&ks[pidx], &fks[pidx]);
        let bh = b.compute_hash();
        let mut votes = VoteSet::new();
        for (k, fk) in ks.iter().zip(fks.iter()) {
            let v = Vote::sign_with_falcon(k, fk, height, 0, VoteKind::Precommit, Some(bh));
            votes
                .add(v, &vs, height, 0, VoteKind::Precommit)
                .expect("vote admits");
        }
        let qc = produce_decision_certificate_with_schedule(
            &votes,
            Some(bh),
            &vs,
            Some(&prev_hash),
            schedule,
        )
        .expect("quorum cert");
        b.precommit_qc = Some(qc.clone());
        (b, bh, qc)
    };

    let pre_freeze_sched = producer.committee_schedule_at(h_freeze);
    let root_f = producer.state.get_state_root().await;
    let (b_freeze, bh_freeze, _) =
        make_signed_block(h_freeze, [0u8; 32], root_f, pre_freeze_sched, None);
    for rt in [&mut producer, &mut adopter, &mut walker] {
        rt.hc = HeightConsensus::new(h_freeze, vs.clone());
        rt.hc.set_parent_hash([0u8; 32]);
        rt.blocks.insert(bh_freeze, b_freeze.clone());
        rt.apply_and_advance(bh_freeze, &b_freeze).await;
    }

    // Fast-forward all three runtimes to EPOCH_LEN - 1 (last block of epoch 0).
    let root_pre_end = producer.state.get_state_root().await;
    let pre_end_sched = producer.committee_schedule_at(EPOCH_LEN - 1);
    let (b_pre_end, bh_pre_end, _) =
        make_signed_block(EPOCH_LEN - 1, bh_freeze, root_pre_end, pre_end_sched, None);
    for rt in [&mut producer, &mut adopter, &mut walker] {
        rt.hc = HeightConsensus::new(EPOCH_LEN - 1, vs.clone());
        rt.hc.set_parent_hash(bh_freeze);
        rt.blocks.insert(bh_pre_end, b_pre_end.clone());
        rt.apply_and_advance(bh_pre_end, &b_pre_end).await;
        // Clear any local VDF lane output on adopter & walker to prove they extract from the block!
        rt.remove_ready_vdf_beacon(1);
    }

    // Build boundary block at EPOCH_LEN carrying epoch 1's verified MinRoot VDF beacon.
    let (freeze_hash, freeze_mix) = producer
        .state
        .cnvrf_freeze_inputs_read()
        .await
        .get(&1)
        .copied()
        .expect("freeze inputs for epoch 1");
    let raw_seed = epoch_seed(
        producer.state.chain_id,
        1,
        None,
        false,
        &freeze_hash,
        &freeze_mix,
    );
    let proof = vdf_eval(&raw_seed, VDF_STEPS, 4);
    let out1 = derive_vdf_output(&raw_seed, &proof);
    let beacon1 = EpochVdfBeacon {
        epoch: 1,
        raw_seed,
        proof,
    };
    let boundary_sched = CommitteeSchedule::Beacon(Some(EpochBeacon {
        epoch: 1,
        output: out1,
    }));
    let root_before_boundary = producer.state.get_state_root().await;
    let (b_boundary, bh_boundary, qc_boundary) = make_signed_block(
        EPOCH_LEN,
        bh_pre_end,
        root_before_boundary,
        boundary_sched,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(beacon1),
        }),
    );

    // Ensure adopter has NO beacon for epoch 1 before adopt_committed!
    assert!(!adopter.has_ready_vdf_beacon(1));
    assert!(adopter.active_epoch_beacon(EPOCH_LEN).is_none());

    // Negative check: forged/corrupt epoch_vdf in adopt_committed is rejected without leaking state.
    let mut bad_boundary = b_boundary.clone();
    bad_boundary
        .cnvrf_v3
        .as_mut()
        .unwrap()
        .epoch_vdf
        .as_mut()
        .unwrap()
        .raw_seed[0] ^= 0xFF;
    let bad_qc = produce_decision_certificate_with_schedule(
        &{
            let mut votes = VoteSet::new();
            let bbh = bad_boundary.compute_hash();
            for (k, fk) in ks.iter().zip(fks.iter()) {
                votes
                    .add(
                        Vote::sign_with_falcon(k, fk, EPOCH_LEN, 0, VoteKind::Precommit, Some(bbh)),
                        &vs,
                        EPOCH_LEN,
                        0,
                        VoteKind::Precommit,
                    )
                    .unwrap();
            }
            votes
        },
        Some(bad_boundary.compute_hash()),
        &vs,
        Some(&bh_pre_end),
        boundary_sched,
    )
    .unwrap();
    assert!(
        adopter
            .adopt_committed(EPOCH_LEN, bad_boundary, bad_qc)
            .await
            .is_err(),
        "adopt_committed must reject invalid epoch_vdf"
    );
    assert!(!adopter.has_ready_vdf_beacon(1));

    // Positive check 1: `adopt_committed` extracts & verifies epoch_vdf before schedule checks.
    adopter
        .adopt_committed(EPOCH_LEN, b_boundary.clone(), qc_boundary.clone())
        .await
        .expect("adopt_committed must succeed on boundary block carrying valid epoch_vdf");

    // Advance producer across EPOCH_LEN and EPOCH_LEN + 1 so we can test `walk_chain_once_with_lanes`.
    producer.apply_and_advance(bh_boundary, &b_boundary).await;
    let root_after_boundary = producer.state.get_state_root().await;
    let post_boundary_sched = producer.committee_schedule_at(EPOCH_LEN + 1);
    let (b_next, bh_next, _) = make_signed_block(
        EPOCH_LEN + 1,
        bh_boundary,
        root_after_boundary,
        post_boundary_sched,
        None,
    );
    producer.apply_and_advance(bh_next, &b_next).await;
    let tip_root = producer.state.get_state_root().await;
    assert_eq!(adopter.state.get_state_root().await, root_after_boundary);

    // Positive check 2: `walk_chain_once_with_lanes` (via `walk_chain_multi_hop_with_lanes` inside
    // one hop window) extracts & verifies `b_boundary.cnvrf_v3.epoch_vdf` before schedule checks.
    assert!(!walker.has_ready_vdf_beacon(1));
    let net_dir = temp_dir("w6-a1-4-net");
    let cfg = infnode::config::NodeConfig {
        name: "w8-walk-test".to_string(),
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
    };
    let net_node = infnode::node::Node::new(
        cfg,
        infnode::keyring::NodeKeys::generate(),
        infnode::keyring::PqKeys::generate(),
        net_dir.clone(),
        std::path::PathBuf::new(),
    )
    .await
    .expect("node");
    let adapter = Arc::new(P2pNetworkAdapter::new(net_node));
    adapter.set_epoch(EpochTag::from_genesis(&[0x51u8; 32]));
    let report = adapter
        .retro_publish_blocks(vec![&b_boundary, &b_next], 2)
        .await;
    assert_eq!(report.failed, 0);

    let rpc = Arc::new(stellereum::rpc::RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(tokio::sync::RwLock::new(
            stellereum::mempool::Mempool::default(),
        )),
        height: Arc::new(AtomicU64::new(0)),
        node_id: "w8-walk-test".to_string(),
        chain_id: stellereum::zkml::DEFAULT_CHAIN_ID,
        staking: Arc::new(tokio::sync::RwLock::new(
            stellereum::staking::StakingLedger::new(),
        )),
        governance: Arc::new(tokio::sync::RwLock::new(
            stellereum::governance::Governance::new(),
        )),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(
            stellereum::rpc::ReceiptIndex::default(),
        )),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: stellereum::sharding::ShardRegistry::single(),
    });

    let reached = node_sync::walk_chain_multi_hop_with_lanes(
        &adapter,
        &mut walker,
        MASTERCHAIN_SHARD,
        EPOCH_LEN + 1,
        bh_next,
        None,
        &rpc,
        node_policy::max_walk_gap(),
        node_sync::SyncLanes::default(),
    )
    .await;
    assert_eq!(
        reached,
        Some(EPOCH_LEN + 1),
        "walk_chain_once_with_lanes must extract & verify epoch_vdf before schedule check"
    );
    assert_eq!(walker.state.get_state_root().await, tip_root);

    // Pre-activation parity: below activation height, `extract_and_verify_epoch_vdf_from_block`
    // is a complete no-op (`Ok(None)`).
    let mut pre_act =
        ValidatorRuntime::new(ks[0].clone(), vs, Arc::new(InMemoryStateEngine::new()), 1);
    assert_eq!(
        pre_act
            .extract_and_verify_epoch_vdf_from_block(&b_boundary)
            .expect("pre-activation must be a no-op"),
        None
    );

    let _ = std::fs::remove_dir_all(&net_dir);
}

struct TestMember {
    id: [u8; 32],
    secret: [u8; 32],
    signing: SigningKey,
    falcon: FalconKeypair,
    kem_seed: [u8; 64],
}

fn make_test_member(seed: u8) -> TestMember {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let mut kem_seed = [0u8; 64];
    kem_seed[..32].copy_from_slice(&signing.to_bytes());
    kem_seed[32..].copy_from_slice(&[seed ^ 0xA5; 32]);
    let falcon = FalconKeypair::generate_from_seed(seed);
    register_validator_pq_key(
        signing.verifying_key().to_bytes(),
        PqScheme::Falcon512,
        falcon.public_key.clone(),
    );
    TestMember {
        id: signing.verifying_key().to_bytes(),
        secret: signing.to_bytes(),
        signing,
        falcon,
        kem_seed,
    }
}

fn setup_mev_committee(
    epoch: u64,
    base_seed: u8,
    n: usize,
) -> (EpochCommittee, Vec<TestMember>, Vec<EpochSealManager>) {
    let members: Vec<TestMember> = (0..n)
        .map(|i| make_test_member(base_seed + i as u8))
        .collect();
    let committee = EpochCommittee::build(
        epoch,
        members
            .iter()
            .map(|m| CommitteeMember {
                validator_id: m.id,
                enc_pk: kem_member_tag(&pq_kem_ek_from_seed(&m.kem_seed)),
            })
            .collect(),
    );
    let mut reg = MevKemRegistry::new();
    for m in &members {
        reg.register(m.id, pq_kem_ek_from_seed(&m.kem_seed), 0, 0, true)
            .unwrap();
    }
    let ids: Vec<[u8; 32]> = members.iter().map(|m| m.id).collect();
    let mut managers = Vec::with_capacity(n);
    let mut envelopes: Vec<PqTransportEnvelope> = Vec::new();
    for m in &members {
        let mut mgr = EpochSealManager::new();
        if let Some(c) = mgr
            .sync_epoch_pq(epoch, &ids, m.id, &m.secret, &m.kem_seed, &reg, 0)
            .unwrap()
        {
            envelopes.push(pq_transport_seal(&m.falcon, c));
        }
        managers.push(mgr);
    }
    for (i, m) in members.iter().enumerate() {
        for env in &envelopes {
            let expected_fk = members
                .iter()
                .find(|x| x.id == env.contribution.validator_id)
                .unwrap()
                .falcon
                .public_key
                .clone();
            managers[i]
                .ingest_contribution_pq(env, &m.kem_seed, &m.id, &expected_fk, &reg, 0)
                .unwrap();
        }
    }
    (committee, members, managers)
}

#[test]
fn w6_a7_2_order_commitment_pq_and_note_commitment_hardening() {
    let (committee, members, mut managers) = setup_mev_committee(7, 0x10, 4);
    let outsider = SigningKey::generate(&mut OsRng);
    let outsider_fk = FalconKeypair::generate_from_seed(0xFE);
    let tx_a = [0xAAu8; 32];
    let tx_b = [0xBBu8; 32];

    // 1. Falcon-512 OrderCommitment signing & verification.
    let pq_commit =
        OrderCommitment::sign_pq(7, 100, 0, vec![tx_a], members[0].id, &members[0].falcon);
    assert!(pq_commit.verify_pq(&members[0].falcon.public_key).is_ok());
    assert!(
        pq_commit.verify_pq(&outsider_fk.public_key).is_err(),
        "wrong Falcon key must be refused"
    );
    assert!(
        pq_commit.verify().is_err(),
        "PQ-only commitment must not pass unkeyed Ed25519 verify()"
    );

    // 2. Wrong epoch is refused.
    let wrong_epoch = OrderCommitment::sign_dual(
        8,
        100,
        0,
        vec![tx_a],
        &members[0].signing,
        &members[0].falcon,
    );
    assert!(managers[1].note_commitment(wrong_epoch).is_err());

    // 3. Non-committee throwaway proposer is refused.
    let non_member = OrderCommitment::sign_dual(7, 100, 0, vec![tx_a], &outsider, &outsider_fk);
    assert!(managers[1].note_commitment(non_member).is_err());

    // 4. Non-scheduled proposer is refused by `note_commitment_verified`.
    assert!(managers[1]
        .note_commitment_verified(
            pq_commit.clone(),
            Some(members[2].id),
            Some(&members[0].falcon.public_key),
        )
        .is_err());

    // 5. Genuine scheduled proposer PQ commitment succeeds.
    managers[1]
        .note_commitment_verified(
            pq_commit.clone(),
            Some(members[0].id),
            Some(&members[0].falcon.public_key),
        )
        .expect("valid PQ commitment must be accepted");

    // 6. Same-(height, round) overwrite with different order is refused.
    let conflicting_same_round =
        OrderCommitment::sign_pq(7, 100, 0, vec![tx_b], members[0].id, &members[0].falcon);
    assert!(managers[1]
        .note_commitment_verified(
            conflicting_same_round,
            Some(members[0].id),
            Some(&members[0].falcon.public_key),
        )
        .is_err());

    // 7. Proposer equivocation across rounds of same height is refused.
    let conflicting_next_round =
        OrderCommitment::sign_pq(7, 100, 1, vec![tx_b], members[0].id, &members[0].falcon);
    assert!(managers[1]
        .note_commitment_verified(
            conflicting_next_round,
            Some(members[0].id),
            Some(&members[0].falcon.public_key),
        )
        .is_err());

    // 8. `height_commitment` anti-equivocation blocks conflicting remote commitment.
    let _own = managers[0]
        .commit_order_pq(101, 0, vec![tx_a], &members[0].signing, &members[0].falcon)
        .unwrap();
    let conflicting_for_101 =
        OrderCommitment::sign_pq(7, 101, 1, vec![tx_b], members[1].id, &members[1].falcon);
    assert!(managers[0]
        .note_commitment_verified(
            conflicting_for_101,
            Some(members[1].id),
            Some(&members[1].falcon.public_key),
        )
        .is_err());

    // 9. Pure-PQ enforcement blocks Ed25519-only `OrderCommitment::verify()`.
    {
        let _pq_guard = PurePqGuard::enforce();
        let ed_only = OrderCommitment::sign(7, 102, 0, vec![tx_a], &members[0].signing);
        assert!(ed_only.verify().is_err());
        assert!(managers[1].note_commitment(ed_only).is_err());
    }
    let _ = committee;
}

#[test]
fn w6_a7_3_share_release_auth_bounds_and_no_overwrite_equivocation() {
    let (committee, members, mut managers) = setup_mev_committee(9, 0x20, 4);
    let key = managers[0].public_key().unwrap();
    let mat1 = managers[1].material().unwrap().clone();
    let mat2 = managers[2].material().unwrap().clone();
    let tx_hash = [0x55u8; 32];
    let other_tx = [0x66u8; 32];
    let envelope = seal_transaction(
        &key,
        b"sealed payload",
        tx_hash,
        TransparentMeta {
            from: members[0].id,
            nonce: 1,
            gas_limit: 50_000,
            priority_fee_per_gas: 1,
            source_shard: 0,
            target_shard: 0,
        },
    )
    .unwrap();

    let commit = managers[0]
        .commit_order_pq(
            50,
            0,
            vec![tx_hash],
            &members[0].signing,
            &members[0].falcon,
        )
        .unwrap();
    managers[1]
        .note_commitment_verified(
            commit.clone(),
            Some(members[0].id),
            Some(&members[0].falcon.public_key),
        )
        .unwrap();

    let idx1 = committee.index_of(&members[1].id).unwrap();
    let idx2 = committee.index_of(&members[2].id).unwrap();
    let pt1 = compute_partial(&mat1.share, &envelope.ephemeral_pk).unwrap();
    let pt2 = compute_partial(&mat2.share, &envelope.ephemeral_pk).unwrap();

    // 1. Out-of-bounds validator_index (0 and N+1) is refused.
    for bad_idx in [0u32, committee.members.len() as u32 + 1] {
        let bad_rel = ShareRelease {
            epoch: 9,
            height: 50,
            round: 0,
            order_root: commit.order_root,
            partials: vec![(
                tx_hash,
                DecryptionPartial {
                    validator_index: bad_idx,
                    point: pt1,
                },
            )],
        };
        assert!(managers[0].ingest_release(bad_rel).is_err());
    }

    // 2. Uncommitted tx_hash is refused.
    let uncommitted_rel = ShareRelease {
        epoch: 9,
        height: 50,
        round: 0,
        order_root: commit.order_root,
        partials: vec![(
            other_tx,
            DecryptionPartial {
                validator_index: idx1,
                point: pt1,
            },
        )],
    };
    assert!(managers[0].ingest_release(uncommitted_rel).is_err());

    // 3. Invalid Ristretto point is refused.
    let bad_pt_rel = ShareRelease {
        epoch: 9,
        height: 50,
        round: 0,
        order_root: commit.order_root,
        partials: vec![(
            tx_hash,
            DecryptionPartial {
                validator_index: idx1,
                point: [0xFFu8; 32],
            },
        )],
    };
    assert!(managers[0].ingest_release(bad_pt_rel).is_err());

    // 4. Spoofing another validator's index in PqShareReleaseEnvelope is refused.
    let spoofed_env = pq_share_release_seal(
        &members[1].falcon,
        members[1].id,
        ShareRelease {
            epoch: 9,
            height: 50,
            round: 0,
            order_root: commit.order_root,
            partials: vec![(
                tx_hash,
                DecryptionPartial {
                    validator_index: idx2,
                    point: pt2,
                },
            )],
        },
    );
    assert!(pq_share_release_verify(&spoofed_env, &members[1].falcon.public_key).is_ok());
    assert!(
        managers[0]
            .ingest_release_authenticated(&spoofed_env, &members[1].falcon.public_key)
            .is_err(),
        "authenticated release must bind signer_id to its own validator_index"
    );

    // 5. Valid PqShareReleaseEnvelope is accepted + frame round-trips cleanly.
    let good_rel = ShareRelease {
        epoch: 9,
        height: 50,
        round: 0,
        order_root: commit.order_root,
        partials: vec![(
            tx_hash,
            DecryptionPartial {
                validator_index: idx1,
                point: pt1,
            },
        )],
    };
    let good_env = pq_share_release_seal(&members[1].falcon, members[1].id, good_rel);
    let wire = MevFrame::PqRelease(good_env.clone()).encode().unwrap();
    assert_eq!(
        MevFrame::decode(&wire).unwrap(),
        MevFrame::PqRelease(good_env.clone())
    );
    assert_eq!(
        managers[0]
            .ingest_release_authenticated(&good_env, &members[1].falcon.public_key)
            .unwrap(),
        1
    );

    // 6. Re-submitting identical partial is idempotent (0 new, Ok), while conflicting point
    //    for the same (tx_hash, validator_index) is refused as equivocation without overwriting.
    assert_eq!(
        managers[0]
            .ingest_release_authenticated(&good_env, &members[1].falcon.public_key)
            .unwrap(),
        0
    );
    let equiv_env = pq_share_release_seal(
        &members[1].falcon,
        members[1].id,
        ShareRelease {
            epoch: 9,
            height: 50,
            round: 0,
            order_root: commit.order_root,
            partials: vec![(
                tx_hash,
                DecryptionPartial {
                    validator_index: idx1,
                    point: pt2,
                },
            )],
        },
    );
    assert!(managers[0]
        .ingest_release_authenticated(&equiv_env, &members[1].falcon.public_key)
        .is_err());
    assert_eq!(
        managers[0]
            .partials_for(&tx_hash)
            .into_iter()
            .find(|p| p.validator_index == idx1)
            .unwrap()
            .point,
        pt1,
        "equivocating partial must not overwrite accepted partial"
    );

    // 7. `combine_partials_checked` rejects out-of-range validator_index.
    let out_of_bounds = vec![
        DecryptionPartial {
            validator_index: idx1,
            point: pt1,
        },
        DecryptionPartial {
            validator_index: idx2,
            point: pt2,
        },
        DecryptionPartial {
            validator_index: committee.members.len() as u32 + 1,
            point: pt1,
        },
    ];
    assert!(
        combine_partials_checked(&out_of_bounds, committee.threshold, committee.members.len())
            .is_err()
    );
}

#[test]
fn w6_a7_4_epoch_announcement_rejects_throwaway_keys_and_enforces_committee_pq() {
    let (committee, members, mut managers) = setup_mev_committee(12, 0x30, 4);
    let outsider = SigningKey::generate(&mut OsRng);
    let outsider_fk = FalconKeypair::generate_from_seed(0xFD);

    let mut ann = managers[0].build_announcement(&members[0].signing).unwrap();
    assert_eq!(ann.valid_signature_count(), 1);
    assert_eq!(ann.valid_signature_count_with_committee(&committee), 1);

    // Adding an arbitrary throwaway Ed25519 key must NOT increase the valid count.
    ann.add_signature(&outsider);
    assert_eq!(
        ann.valid_signature_count(),
        1,
        "throwaway non-committee key must never be counted"
    );
    assert_eq!(ann.valid_signature_count_with_committee(&committee), 1);

    // `merge_announcement` refuses announcements carrying non-committee signers or wrong committee_hash.
    assert!(managers[1].merge_announcement(ann.clone()).is_err());
    let mut wrong_hash_ann = managers[0].build_announcement(&members[0].signing).unwrap();
    wrong_hash_ann.committee_hash = [0x99u8; 32];
    assert!(managers[1].merge_announcement(wrong_hash_ann).is_err());

    // PQ announcements with Falcon-512 signatures are accepted and counted under Pure-PQ mode too.
    let mut pq_ann = managers[0]
        .build_announcement_pq(&members[0].signing, &members[0].falcon)
        .unwrap();
    for m in members.iter().skip(1).take(committee.threshold - 1) {
        pq_ann.add_pq_signature(m.id, &m.falcon);
    }
    // Non-member Falcon signature is ignored by `valid_signature_count` and refused by `merge_announcement`.
    let mut poisoned_pq = pq_ann.clone();
    let mut outsider_id = [0u8; 32];
    OsRng.fill_bytes(&mut outsider_id);
    poisoned_pq.add_pq_signature(outsider_id, &outsider_fk);
    assert_eq!(poisoned_pq.valid_signature_count(), committee.threshold);
    assert!(managers[1].merge_announcement(poisoned_pq).is_err());

    {
        let _pq_guard = PurePqGuard::enforce();
        assert_eq!(pq_ann.valid_signature_count(), committee.threshold);
        assert!(pq_ann.has_quorum_with_committee(&committee, committee.threshold));
        let mut pq_map = HashMap::new();
        for m in &members {
            pq_map.insert(m.id, m.falcon.public_key.clone());
        }
        let member_ids: Vec<[u8; 32]> = members.iter().map(|m| m.id).collect();
        assert_eq!(
            pq_ann.valid_signature_count_with_keys(&member_ids, &pq_map),
            committee.threshold
        );
        managers[1]
            .merge_announcement(pq_ann)
            .expect("valid PQ committee announcement must merge under pure-PQ");
    }
}

#[test]
fn storage_retention_u64_max_does_not_overflow() {
    let dir = temp_dir("retention-u64-max");
    let storage = Storage::open(&dir).expect("open storage");

    let mut b_max = empty_block(u64::MAX, [0u8; 32], [0u8; 32], [1u8; 32]);
    b_max.timestamp = 1_760_000_000;
    storage.put_block(&b_max).expect("put block at u64::MAX");

    // Pre-fix `height + 1 < keep_from` panicked in debug mode on `u64::MAX + 1`.
    assert!(
        !storage
            .has_blocks_below(u64::MAX)
            .expect("has_blocks_below(u64::MAX) must not overflow"),
        "block at u64::MAX must not be removable when keep_from == u64::MAX"
    );
    assert_eq!(
        storage
            .prune_blocks_below(u64::MAX)
            .expect("prune_blocks_below(u64::MAX) must not overflow"),
        0
    );

    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}
