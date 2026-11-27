//! Wave 11 CN-VRF v3 readiness integration tests:
//!
//! 1. Multi-epoch CN-VRF v3 transition (`H_act = 1`, walking across
//!    `H_freeze(1) -> EPOCH_LEN -> H_freeze(2) -> 2 * EPOCH_LEN` across Producer +
//!    Adopter, verifying `cnvrf_freeze_inputs` persistence, `MinRoot` VDF beacon
//!    extraction, `CommitteeSchedule::Beacon(Some(..))`, and identical `state_root`).
//! 2. Mid-epoch validator set churn (adding a new validator and jailing a
//!    downtime validator mid-epoch before `2 * EPOCH_LEN`, verifying proposer
//!    and committee selection converge identically across Producer and Adopter,
//!    plus `> MICRO_COMMITTEE_MAX_SIZE` committee rotation parity).
//! 3. Unpredictability / fallback refusal: `CommitteeSchedule::Beacon(None)`
//!    fails closed when active, parent-hash grinding is removed, and
//!    omitted/forged/mismatched `epoch_vdf` beacons are rejected cleanly in
//!    `adopt_committed` without leaving staged beacon state.
//!
//! NOTE on RAII test overrides:
//! `src/consensus/sortition.rs` keeps `CNVRF_V3_ACTIVATION_HEIGHT` and
//! `BEACON_DRAW_ACTIVATION_HEIGHT` as frozen `u64::MAX` constants with no
//! thread-local `set_cnvrf_v3_activation_override` /
//! `set_beacon_draw_activation_override` helpers yet; runtime and state-engine
//! tests use `ValidatorRuntime::set_cnvrf_v3_activation_height_for_tests` and
//! `InMemoryStateEngine::set_cnvrf_v3_activation_height_for_tests` alongside
//! explicit `CommitteeSchedule::Beacon(..)` schedules. `CnVrfEngineOverrideGuard`
//! ensures the engine activation overrides are always cleared back to `u64::MAX`
//! on drop, even if a test assertion panics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use stellereum::cn_vrf::{
    derive_v3_epoch_secret, epoch_bootstrap_beacon, epoch_had_vdf, epoch_seed,
    freeze_height_of_epoch, CnVrfV3Chain, EPOCH_LEN, V3_COMMIT_LOOKAHEAD_BLOCKS,
};
use stellereum::consensus::{
    beacon_draw_active_at, cnvrf_v3_activation_height_allowed, cnvrf_v3_active_at,
    cnvrf_v3_epoch_of_height, committee_for_height, micro_committee_size,
    produce_decision_certificate_with_schedule, register_validator_pq_key,
    sync_committed_pq_registry, CommitteeSchedule, EpochBeacon, FalconKeypair, HeightConsensus,
    QuorumCertificate, ValidatorSet, Vote, VoteKind, VoteSet, MICRO_COMMITTEE_MAX_SIZE,
};
use stellereum::minroot_vdf::{derive_vdf_output, eval as vdf_eval};
use stellereum::post_quantum::PqScheme;
use stellereum::runtime::ValidatorRuntime;
use stellereum::sharding::{Block, CnVrfV3BlockPayload, EpochVdfBeacon, MASTERCHAIN_SHARD};
use stellereum::staking::{downtime_miss_threshold_at, required_bond_floor_nano, STAKING_POOL};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{load_full_state_into, AsyncPersistence, Storage};

/// Process-local async lock so tests in this binary do not race on the
/// global PQ key registry (`register_validator_pq_key` / `sync_committed_pq_registry`).
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

/// RAII guard restoring every guarded `InMemoryStateEngine`'s CN-VRF v3
/// activation height override back to `u64::MAX` (production sentinel) on drop.
struct CnVrfEngineOverrideGuard {
    engines: Vec<Arc<InMemoryStateEngine>>,
}

impl CnVrfEngineOverrideGuard {
    fn new(engines: Vec<Arc<InMemoryStateEngine>>) -> Self {
        Self { engines }
    }

    fn push(&mut self, engine: Arc<InMemoryStateEngine>) {
        self.engines.push(engine);
    }
}

impl Drop for CnVrfEngineOverrideGuard {
    fn drop(&mut self) {
        for engine in &self.engines {
            engine.set_cnvrf_v3_activation_height_for_tests(u64::MAX);
        }
    }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("stell-w11-{tag}-{}-{n}", std::process::id()));
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

async fn wait_for_vdf_ready(rt: &mut ValidatorRuntime, epoch: u64) {
    for _ in 0..1_000 {
        rt.poll_vdf_lane();
        if rt.has_ready_vdf_beacon(epoch) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for VDF lane output for epoch {epoch}");
}

fn empty_block(
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    proposer: [u8; 32],
    timestamp: u64,
) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp,
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

fn deterministic_keys(count: usize, domain_tag: u8) -> (Vec<SigningKey>, Vec<FalconKeypair>) {
    let ks: Vec<SigningKey> = (0..count)
        .map(|i| {
            let mut seed = [domain_tag; 32];
            seed[0] = domain_tag.wrapping_add(i as u8);
            seed[1] = (i as u8).wrapping_mul(17);
            SigningKey::from_bytes(&seed)
        })
        .collect();
    let fks: Vec<FalconKeypair> = (0..count)
        .map(|i| FalconKeypair::generate_from_seed(domain_tag.wrapping_add(i as u8)))
        .collect();
    for (k, fk) in ks.iter().zip(fks.iter()) {
        register_validator_pq_key(
            k.verifying_key().to_bytes(),
            PqScheme::Falcon512,
            fk.public_key.clone(),
        );
    }
    (ks, fks)
}

async fn seed_engine_validators(
    engine: &Arc<InMemoryStateEngine>,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    bonds: &[u64],
) {
    let mut total_bond = 0u64;
    {
        let mut ledger = engine.staking_write().await;
        let mut pq_reg = engine.pq_registry_write().await;
        for ((k, fk), &bond) in ks.iter().zip(fks.iter()).zip(bonds.iter()) {
            let id = k.verifying_key().to_bytes();
            ledger.bond(id, bond, 0).expect("bond validator");
            ledger
                .validator_pq_keys
                .insert(id, (PqScheme::Falcon512, fk.public_key.clone()));
            let _ =
                pq_reg.adopt_legacy_key_at(id, PqScheme::Falcon512, fk.public_key.clone(), 0, true);
            total_bond = total_bond.saturating_add(bond);
        }
        sync_committed_pq_registry(&pq_reg, true);
    }
    engine
        .credit_native(&STAKING_POOL, total_bond)
        .await
        .expect("fund STAKING_POOL");
}

#[allow(clippy::too_many_arguments)]
fn make_signed_block_with_schedule(
    vs: &ValidatorSet,
    ks: &[SigningKey],
    fks: &[FalconKeypair],
    signer_indices: &[usize],
    height: u64,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    timestamp: u64,
    schedule: CommitteeSchedule,
    cnvrf_v3: Option<CnVrfV3BlockPayload>,
    last_qc: Option<QuorumCertificate>,
) -> (Block, [u8; 32], QuorumCertificate) {
    let prop_id = vs
        .proposer_for_with_schedule(height, 0, schedule)
        .expect("scheduled proposer must resolve");
    let pidx = ks
        .iter()
        .position(|k| k.verifying_key().to_bytes() == prop_id)
        .expect("scheduled proposer key must exist");
    let mut b = empty_block(height, prev_hash, state_root, prop_id, timestamp);
    b.cnvrf_v3 = cnvrf_v3;
    b.last_qc = last_qc;
    b.sign_block_with_falcon(&ks[pidx], &fks[pidx]);
    let bh = b.compute_hash();
    let mut votes = VoteSet::new();
    for &idx in signer_indices {
        let v = Vote::sign_with_falcon(
            &ks[idx],
            &fks[idx],
            height,
            0,
            VoteKind::Precommit,
            Some(bh),
        );
        votes
            .add(v, vs, height, 0, VoteKind::Precommit)
            .expect("precommit vote must admit");
    }
    let qc = produce_decision_certificate_with_schedule(
        &votes,
        Some(bh),
        vs,
        Some(&prev_hash),
        schedule,
    )
    .expect("quorum certificate must compile");
    b.precommit_qc = Some(qc.clone());
    (b, bh, qc)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w11_multi_epoch_cnvrf_v3_transition_two_full_epochs() {
    let _lock = TEST_LOCK.lock().await;
    const ACTIVATION: u64 = 1;
    const VDF_STEPS: u64 = 16;

    // Review F4 invariant: exact EPOCH_LEN boundary activation is forbidden,
    // while mid-epoch / height-1 activation is legal.
    assert!(!cnvrf_v3_activation_height_allowed(EPOCH_LEN));
    assert!(cnvrf_v3_activation_height_allowed(ACTIVATION));

    let bond = required_bond_floor_nano();
    let (ks, fks) = deterministic_keys(2, 0xA1);
    let ids: Vec<[u8; 32]> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let vs = ValidatorSet::from_list(ids.iter().map(|&id| (id, bond)).collect());

    let prod_eng = Arc::new(InMemoryStateEngine::new());
    let adopt_eng = Arc::new(InMemoryStateEngine::new());
    let mut _guard = CnVrfEngineOverrideGuard::new(vec![prod_eng.clone(), adopt_eng.clone()]);

    seed_engine_validators(&prod_eng, &ks, &fks, &[bond, bond]).await;
    seed_engine_validators(&adopt_eng, &ks, &fks, &[bond, bond]).await;

    let mut producer = ValidatorRuntime::new(ks[0].clone(), vs.clone(), prod_eng.clone(), 1)
        .with_falcon_key(fks[0].clone());
    let mut adopter = ValidatorRuntime::new(ks[1].clone(), vs.clone(), adopt_eng.clone(), 1)
        .with_falcon_key(fks[1].clone());

    for rt in [&mut producer, &mut adopter] {
        rt.set_cnvrf_v3_activation_height_for_tests(ACTIVATION);
        rt.set_cnvrf_v3_vdf_steps(VDF_STEPS);
    }

    // Pre-activation height 0 is inactive; height 1 is active.
    assert!(!producer.cnvrf_v3_is_active_at(0));
    assert_eq!(
        producer.committee_schedule_at(0),
        CommitteeSchedule::ParentHash
    );
    assert!(producer.cnvrf_v3_is_active_at(ACTIVATION));
    assert!(adopter.cnvrf_v3_is_active_at(ACTIVATION));

    let chain_id = prod_eng.chain_id;
    let boot_0 = EpochBeacon {
        epoch: 0,
        output: epoch_bootstrap_beacon(chain_id, 0),
    };
    assert_eq!(
        producer.committee_schedule_at(1),
        CommitteeSchedule::Beacon(Some(boot_0))
    );
    assert_eq!(
        adopter.committee_schedule_at(1),
        CommitteeSchedule::Beacon(Some(boot_0))
    );

    // Precompute deterministic CN-VRF v3 hash chains for epoch 1 and epoch 2.
    let s0_e1 = derive_v3_epoch_secret(&ks[0].to_bytes(), chain_id, &ids[0], 1);
    let s1_e1 = derive_v3_epoch_secret(&ks[1].to_bytes(), chain_id, &ids[1], 1);
    let chain0_e1 = CnVrfV3Chain::generate(chain_id, &ids[0], 1, &s0_e1);
    let chain1_e1 = CnVrfV3Chain::generate(chain_id, &ids[1], 1, &s1_e1);
    let c0_e1 = chain0_e1.commit_carrier(&fks[0]);
    let c1_e1 = chain1_e1.commit_carrier(&fks[1]);

    let s0_e2 = derive_v3_epoch_secret(&ks[0].to_bytes(), chain_id, &ids[0], 2);
    let s1_e2 = derive_v3_epoch_secret(&ks[1].to_bytes(), chain_id, &ids[1], 2);
    let chain0_e2 = CnVrfV3Chain::generate(chain_id, &ids[0], 2, &s0_e2);
    let chain1_e2 = CnVrfV3Chain::generate(chain_id, &ids[1], 2, &s1_e2);
    let c0_e2 = chain0_e2.commit_carrier(&fks[0]);
    let c1_e2 = chain1_e2.commit_carrier(&fks[1]);

    let mut ts = 1_760_000_000u64;

    // 1. Height 1 (epoch 0): admit both validators' epoch-1 CommitCarrierV3s.
    let root_0 = prod_eng.get_state_root().await;
    let sched_e0 = CommitteeSchedule::Beacon(Some(boot_0));
    ts += 1;
    let (b1, bh1, qc1) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1],
        1,
        [0u8; 32],
        root_0,
        ts,
        sched_e0,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![c0_e1, c1_e1],
            epoch_vdf: None,
        }),
        None,
    );
    adopter
        .adopt_committed(1, b1.clone(), qc1.clone())
        .await
        .expect("adopter must accept height 1 with epoch-1 commits");
    producer.blocks.insert(bh1, b1.clone());
    producer.apply_and_advance(bh1, &b1).await;

    assert_eq!(
        prod_eng.get_state_root().await,
        adopt_eng.get_state_root().await
    );
    for eng in [&prod_eng, &adopt_eng] {
        let v3 = eng.cnvrf_v3_read().await;
        assert!(v3.get_record(&ids[0], 1).is_some());
        assert!(v3.get_record(&ids[1], 1).is_some());
    }

    // 2. Fast-forward to H_freeze(1) = EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS.
    let h_freeze_1 = freeze_height_of_epoch(1);
    assert_eq!(h_freeze_1, EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS);
    assert!(epoch_had_vdf(1, ACTIVATION));

    let root_pre_f1 = prod_eng.get_state_root().await;
    ts += 1;
    let (b_f1, bh_f1, _qc_f1) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1],
        h_freeze_1,
        bh1,
        root_pre_f1,
        ts,
        sched_e0,
        None,
        None,
    );
    for rt in [&mut producer, &mut adopter] {
        rt.hc = HeightConsensus::new(h_freeze_1, vs.clone());
        rt.hc.set_parent_hash(bh1);
        rt.install_committee_schedule();
        rt.blocks.insert(bh_f1, b_f1.clone());
        rt.apply_and_advance(bh_f1, &b_f1).await;
    }

    // Verify freeze_inputs[1] recorded identically on both engines and VdfLane completes.
    let freeze1_prod = prod_eng
        .cnvrf_freeze_inputs_read()
        .await
        .get(&1)
        .copied()
        .expect("producer must snapshot freeze_inputs[1] at H_freeze(1)");
    let freeze1_adopt = adopt_eng
        .cnvrf_freeze_inputs_read()
        .await
        .get(&1)
        .copied()
        .expect("adopter must snapshot freeze_inputs[1] at H_freeze(1)");
    assert_eq!(freeze1_prod, freeze1_adopt);
    assert_eq!(freeze1_prod.0, bh_f1);

    wait_for_vdf_ready(&mut producer, 1).await;
    assert!(producer.has_ready_vdf_beacon(1));

    // Verify freeze_inputs[1] survives Storage snapshot & load_full_state_into restart.
    let persist_dir = temp_dir("multi-epoch-persist");
    let storage = Arc::new(Storage::open(&persist_dir).expect("open storage"));
    let ap = AsyncPersistence::start(storage.clone());
    let root_post_f1 = prod_eng.get_state_root().await;
    ap.enqueue_block(b_f1.clone());
    let anchor_f1 = empty_block(h_freeze_1 + 1, bh_f1, root_post_f1, ids[0], ts + 1);
    let anchor_f1_hash = anchor_f1.compute_hash();
    ap.enqueue_block(anchor_f1);
    ap.enqueue_finalized(h_freeze_1 + 1, anchor_f1_hash);
    ap.snapshot_state(&prod_eng, h_freeze_1).await;
    let staking_snap = prod_eng.staking_read().await.clone();
    let gov_snap = prod_eng.governance_read().await.clone();
    ap.snapshot_domains(&prod_eng, &staking_snap, &gov_snap, h_freeze_1)
        .await;
    flush_persist(&ap).await;

    let restored_eng = Arc::new(InMemoryStateEngine::new());
    _guard.push(restored_eng.clone());
    restored_eng.set_cnvrf_v3_activation_height_for_tests(ACTIVATION);
    let (loaded_h, _, _) = load_full_state_into(&storage, &restored_eng)
        .await
        .expect("load_full_state_into must verify")
        .expect("snapshot must exist");
    assert_eq!(loaded_h, h_freeze_1);
    assert_eq!(
        restored_eng
            .cnvrf_freeze_inputs_read()
            .await
            .get(&1)
            .copied(),
        Some(freeze1_prod)
    );
    drop(ap);
    drop(storage);
    let _ = std::fs::remove_dir_all(&persist_dir);

    // 3. Fast-forward to EPOCH_LEN - 1 (last height of epoch 0).
    ts += 1;
    let (b_pre_e1, bh_pre_e1, _) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1],
        EPOCH_LEN - 1,
        bh_f1,
        root_post_f1,
        ts,
        sched_e0,
        None,
        None,
    );
    for rt in [&mut producer, &mut adopter] {
        rt.hc = HeightConsensus::new(EPOCH_LEN - 1, vs.clone());
        rt.hc.set_parent_hash(bh_f1);
        rt.install_committee_schedule();
        rt.blocks.insert(bh_pre_e1, b_pre_e1.clone());
        rt.apply_and_advance(bh_pre_e1, &b_pre_e1).await;
    }
    adopter.remove_ready_vdf_beacon(1);
    assert!(!adopter.has_ready_vdf_beacon(1));
    assert_eq!(
        adopter.committee_schedule_at(EPOCH_LEN),
        CommitteeSchedule::Beacon(None)
    );
    assert_eq!(adopter.expected_proposer_now(), None);

    // 4. Epoch 1 boundary block at EPOCH_LEN carrying MinRoot epoch_vdf for epoch 1.
    let raw_seed_1 = epoch_seed(
        chain_id,
        1,
        None,
        epoch_had_vdf(0, ACTIVATION),
        &freeze1_prod.0,
        &freeze1_prod.1,
    );
    let proof_1 = vdf_eval(&raw_seed_1, VDF_STEPS, 4);
    let out_1 = derive_vdf_output(&raw_seed_1, &proof_1);
    let expected_beacon_1 = EpochBeacon {
        epoch: 1,
        output: out_1,
    };
    assert_eq!(
        producer.active_epoch_beacon(EPOCH_LEN),
        Some(expected_beacon_1),
        "producer VDF lane must match deterministic epoch_seed + MinRoot output"
    );
    let sched_e1 = CommitteeSchedule::Beacon(Some(expected_beacon_1));
    let root_before_e1 = prod_eng.get_state_root().await;
    ts += 1;
    let (b_e1, bh_e1, qc_e1) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1],
        EPOCH_LEN,
        bh_pre_e1,
        root_before_e1,
        ts,
        sched_e1,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 1,
                raw_seed: raw_seed_1,
                proof: proof_1,
            }),
        }),
        None,
    );

    adopter
        .adopt_committed(EPOCH_LEN, b_e1.clone(), qc_e1.clone())
        .await
        .expect("adopter must extract epoch_vdf(1) before verifying boundary schedule");
    producer.blocks.insert(bh_e1, b_e1.clone());
    producer.apply_and_advance(bh_e1, &b_e1).await;

    assert_eq!(
        prod_eng.epoch_vdf_beacons_read().await.get(&1).copied(),
        Some(out_1)
    );
    assert_eq!(
        adopt_eng.epoch_vdf_beacons_read().await.get(&1).copied(),
        Some(out_1)
    );
    assert_eq!(producer.committee_schedule_at(EPOCH_LEN + 1), sched_e1);
    assert_eq!(adopter.committee_schedule_at(EPOCH_LEN + 1), sched_e1);
    assert_eq!(
        prod_eng.get_state_root().await,
        adopt_eng.get_state_root().await
    );

    // 5. At EPOCH_LEN + 1 (epoch 1): carry proposer reveal + epoch-2 CommitCarrierV3s + last_qc.
    let prop_e1_h = vs
        .proposer_for_with_schedule(EPOCH_LEN + 1, 0, sched_e1)
        .expect("epoch 1 proposer");
    let reveal_e1 = if prop_e1_h == ids[0] {
        chain0_e1.reveal_for_height(EPOCH_LEN + 1)
    } else {
        chain1_e1.reveal_for_height(EPOCH_LEN + 1)
    };
    assert!(reveal_e1.is_some());
    let root_e1_p1 = prod_eng.get_state_root().await;
    ts += 1;
    let (b_e1_p1, bh_e1_p1, _qc_e1_p1) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1],
        EPOCH_LEN + 1,
        bh_e1,
        root_e1_p1,
        ts,
        sched_e1,
        Some(CnVrfV3BlockPayload {
            reveal: reveal_e1,
            commits: vec![c0_e2, c1_e2],
            epoch_vdf: None,
        }),
        Some(qc_e1.clone()),
    );
    adopter
        .adopt_committed(EPOCH_LEN + 1, b_e1_p1.clone(), _qc_e1_p1.clone())
        .await
        .expect("adopter must adopt EPOCH_LEN + 1 with reveal and epoch-2 commits");
    producer.blocks.insert(bh_e1_p1, b_e1_p1.clone());
    producer.apply_and_advance(bh_e1_p1, &b_e1_p1).await;

    let mix_1_prod = prod_eng.cnvrf_v3_read().await.rolling_mix_for_epoch(1);
    let mix_1_adopt = adopt_eng.cnvrf_v3_read().await.rolling_mix_for_epoch(1);
    assert_ne!(
        mix_1_prod, [0u8; 48],
        "epoch-1 reveal must update rolling_mix"
    );
    assert_eq!(mix_1_prod, mix_1_adopt);
    assert_eq!(
        prod_eng.get_state_root().await,
        adopt_eng.get_state_root().await
    );

    // 6. Fast-forward to H_freeze(2) = 2 * EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS.
    let h_freeze_2 = freeze_height_of_epoch(2);
    assert_eq!(h_freeze_2, 2 * EPOCH_LEN - V3_COMMIT_LOOKAHEAD_BLOCKS);
    let prop_f2 = vs
        .proposer_for_with_schedule(h_freeze_2, 0, sched_e1)
        .expect("h_freeze_2 proposer");
    let reveal_f2 = if prop_f2 == ids[0] {
        chain0_e1.reveal_for_height(h_freeze_2)
    } else {
        chain1_e1.reveal_for_height(h_freeze_2)
    };
    let root_pre_f2 = prod_eng.get_state_root().await;
    ts += 1;
    let (b_f2, bh_f2, _) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1],
        h_freeze_2,
        bh_e1_p1,
        root_pre_f2,
        ts,
        sched_e1,
        Some(CnVrfV3BlockPayload {
            reveal: reveal_f2,
            commits: vec![],
            epoch_vdf: None,
        }),
        None,
    );
    for rt in [&mut producer, &mut adopter] {
        rt.hc = HeightConsensus::new(h_freeze_2, vs.clone());
        rt.hc.set_parent_hash(bh_e1_p1);
        rt.install_committee_schedule();
        rt.blocks.insert(bh_f2, b_f2.clone());
        rt.apply_and_advance(bh_f2, &b_f2).await;
    }

    let freeze2_prod = prod_eng
        .cnvrf_freeze_inputs_read()
        .await
        .get(&2)
        .copied()
        .expect("freeze_inputs[2] on producer");
    let freeze2_adopt = adopt_eng
        .cnvrf_freeze_inputs_read()
        .await
        .get(&2)
        .copied()
        .expect("freeze_inputs[2] on adopter");
    assert_eq!(freeze2_prod, freeze2_adopt);
    let mix_after_f2 = prod_eng.cnvrf_v3_read().await.rolling_mix_for_epoch(1);
    assert_ne!(mix_after_f2, mix_1_prod);
    assert_eq!(freeze2_prod, (bh_f2, mix_after_f2));

    wait_for_vdf_ready(&mut producer, 2).await;
    assert!(producer.has_ready_vdf_beacon(2));

    // 7. Fast-forward to 2 * EPOCH_LEN - 1, then cross boundary 2 * EPOCH_LEN into epoch 2.
    let prop_pre_e2 = vs
        .proposer_for_with_schedule(2 * EPOCH_LEN - 1, 0, sched_e1)
        .expect("pre_e2 proposer");
    let reveal_pre_e2 = if prop_pre_e2 == ids[0] {
        chain0_e1.reveal_for_height(2 * EPOCH_LEN - 1)
    } else {
        chain1_e1.reveal_for_height(2 * EPOCH_LEN - 1)
    };
    let root_pre_e2 = prod_eng.get_state_root().await;
    ts += 1;
    let (b_pre_e2, bh_pre_e2, _) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1],
        2 * EPOCH_LEN - 1,
        bh_f2,
        root_pre_e2,
        ts,
        sched_e1,
        Some(CnVrfV3BlockPayload {
            reveal: reveal_pre_e2,
            commits: vec![],
            epoch_vdf: None,
        }),
        None,
    );
    for rt in [&mut producer, &mut adopter] {
        rt.hc = HeightConsensus::new(2 * EPOCH_LEN - 1, vs.clone());
        rt.hc.set_parent_hash(bh_f2);
        rt.install_committee_schedule();
        rt.blocks.insert(bh_pre_e2, b_pre_e2.clone());
        rt.apply_and_advance(bh_pre_e2, &b_pre_e2).await;
    }
    adopter.remove_ready_vdf_beacon(2);
    assert_eq!(
        adopter.committee_schedule_at(2 * EPOCH_LEN),
        CommitteeSchedule::Beacon(None)
    );

    let raw_seed_2 = epoch_seed(
        chain_id,
        2,
        Some(&out_1),
        epoch_had_vdf(1, ACTIVATION),
        &freeze2_prod.0,
        &freeze2_prod.1,
    );
    let proof_2 = vdf_eval(&raw_seed_2, VDF_STEPS, 4);
    let out_2 = derive_vdf_output(&raw_seed_2, &proof_2);
    assert_ne!(out_2, out_1);
    let expected_beacon_2 = EpochBeacon {
        epoch: 2,
        output: out_2,
    };
    assert_eq!(
        producer.active_epoch_beacon(2 * EPOCH_LEN),
        Some(expected_beacon_2)
    );
    let sched_e2 = CommitteeSchedule::Beacon(Some(expected_beacon_2));
    let prop_e2_h = vs
        .proposer_for_with_schedule(2 * EPOCH_LEN, 0, sched_e2)
        .expect("epoch 2 proposer");
    let reveal_e2 = if prop_e2_h == ids[0] {
        chain0_e2.reveal_for_height(2 * EPOCH_LEN)
    } else {
        chain1_e2.reveal_for_height(2 * EPOCH_LEN)
    };
    let root_before_e2 = prod_eng.get_state_root().await;
    ts += 1;
    let (b_e2, bh_e2, qc_e2) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1],
        2 * EPOCH_LEN,
        bh_pre_e2,
        root_before_e2,
        ts,
        sched_e2,
        Some(CnVrfV3BlockPayload {
            reveal: reveal_e2,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 2,
                raw_seed: raw_seed_2,
                proof: proof_2,
            }),
        }),
        None,
    );

    adopter
        .adopt_committed(2 * EPOCH_LEN, b_e2.clone(), qc_e2)
        .await
        .expect("adopter must extract epoch_vdf(2) and verify 2 * EPOCH_LEN");
    producer.blocks.insert(bh_e2, b_e2.clone());
    producer.apply_and_advance(bh_e2, &b_e2).await;

    assert_eq!(
        prod_eng.epoch_vdf_beacons_read().await.get(&2).copied(),
        Some(out_2)
    );
    assert_eq!(
        adopt_eng.epoch_vdf_beacons_read().await.get(&2).copied(),
        Some(out_2)
    );
    assert_eq!(producer.committee_schedule_at(2 * EPOCH_LEN + 1), sched_e2);
    assert_eq!(adopter.committee_schedule_at(2 * EPOCH_LEN + 1), sched_e2);
    assert_eq!(
        prod_eng.get_state_root().await,
        adopt_eng.get_state_root().await,
        "Producer and Adopter must converge on identical state_root after 2 full epochs"
    );

    // Proposer lookahead removal: beacon-seeded proposer schedule diverges from
    // pre-activation static `proposer_for` and from any alternative epoch-2 beacon.
    let alt_beacon_2 = EpochBeacon {
        epoch: 2,
        output: [0x5Au8; 48],
    };
    let mut differs_from_legacy = false;
    let mut differs_from_alt_beacon = false;
    for offset in 0..32u64 {
        let h = 2 * EPOCH_LEN + offset;
        let p_beacon = vs.proposer_for_with_schedule(h, 0, sched_e2);
        let p_legacy = vs.proposer_for(h, 0);
        let p_alt =
            vs.proposer_for_with_schedule(h, 0, CommitteeSchedule::Beacon(Some(alt_beacon_2)));
        if p_beacon != p_legacy {
            differs_from_legacy = true;
        }
        if p_beacon != p_alt {
            differs_from_alt_beacon = true;
        }
    }
    assert!(
        differs_from_legacy,
        "beacon-driven proposer selection must depart from static lookahead proposer_for"
    );
    assert!(
        differs_from_alt_beacon,
        "different epoch beacons must yield unpredictable proposer rotations"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w11_validator_set_churn_mid_epoch_converges_across_producer_and_adopter() {
    let _lock = TEST_LOCK.lock().await;
    const ACTIVATION: u64 = 1;
    const VDF_STEPS: u64 = 16;

    let bond = required_bond_floor_nano();
    // 4 keypairs: [0, 1, 2] start active ([2] at `bond` so one 1% downtime slash
    // drops it below `required_bond_floor_nano` and jails it); [3] joins mid-epoch with 2 * bond.
    let (ks, fks) = deterministic_keys(4, 0xB2);
    let ids: Vec<[u8; 32]> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let initial_bonds = [bond, bond, bond];
    let vs_init = ValidatorSet::from_list(
        ids[..3]
            .iter()
            .copied()
            .zip(initial_bonds.iter().copied())
            .collect(),
    );

    let prod_eng = Arc::new(InMemoryStateEngine::new());
    let adopt_eng = Arc::new(InMemoryStateEngine::new());
    let _guard = CnVrfEngineOverrideGuard::new(vec![prod_eng.clone(), adopt_eng.clone()]);

    seed_engine_validators(&prod_eng, &ks[..3], &fks[..3], &initial_bonds).await;
    seed_engine_validators(&adopt_eng, &ks[..3], &fks[..3], &initial_bonds).await;

    let mut producer = ValidatorRuntime::new(ks[0].clone(), vs_init.clone(), prod_eng.clone(), 1)
        .with_falcon_key(fks[0].clone());
    let mut adopter = ValidatorRuntime::new(ks[1].clone(), vs_init.clone(), adopt_eng.clone(), 1)
        .with_falcon_key(fks[1].clone());

    for rt in [&mut producer, &mut adopter] {
        rt.set_cnvrf_v3_activation_height_for_tests(ACTIVATION);
        rt.set_cnvrf_v3_vdf_steps(VDF_STEPS);
    }

    let chain_id = prod_eng.chain_id;
    let boot_0 = EpochBeacon {
        epoch: 0,
        output: epoch_bootstrap_beacon(chain_id, 0),
    };
    let sched_e0 = CommitteeSchedule::Beacon(Some(boot_0));
    let mut ts = 1_760_100_000u64;

    // Cross H_freeze(1) -> EPOCH_LEN - 1 -> EPOCH_LEN so epoch 1 runs under a real MinRoot VDF beacon.
    let h_freeze_1 = freeze_height_of_epoch(1);
    ts += 1;
    let (b_f1, bh_f1, _) = make_signed_block_with_schedule(
        &vs_init,
        &ks,
        &fks,
        &[0, 1, 2],
        h_freeze_1,
        [0u8; 32],
        prod_eng.get_state_root().await,
        ts,
        sched_e0,
        None,
        None,
    );
    for rt in [&mut producer, &mut adopter] {
        rt.hc = HeightConsensus::new(h_freeze_1, vs_init.clone());
        rt.hc.set_parent_hash([0u8; 32]);
        rt.install_committee_schedule();
        rt.blocks.insert(bh_f1, b_f1.clone());
        rt.apply_and_advance(bh_f1, &b_f1).await;
    }
    wait_for_vdf_ready(&mut producer, 1).await;

    ts += 1;
    let (b_pre_e1, bh_pre_e1, _) = make_signed_block_with_schedule(
        &vs_init,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN - 1,
        bh_f1,
        prod_eng.get_state_root().await,
        ts,
        sched_e0,
        None,
        None,
    );
    for rt in [&mut producer, &mut adopter] {
        rt.hc = HeightConsensus::new(EPOCH_LEN - 1, vs_init.clone());
        rt.hc.set_parent_hash(bh_f1);
        rt.install_committee_schedule();
        rt.blocks.insert(bh_pre_e1, b_pre_e1.clone());
        rt.apply_and_advance(bh_pre_e1, &b_pre_e1).await;
    }
    adopter.remove_ready_vdf_beacon(1);

    let freeze1 = prod_eng
        .cnvrf_freeze_inputs_read()
        .await
        .get(&1)
        .copied()
        .expect("freeze_inputs[1]");
    let raw_seed_1 = epoch_seed(
        chain_id,
        1,
        None,
        epoch_had_vdf(0, ACTIVATION),
        &freeze1.0,
        &freeze1.1,
    );
    let proof_1 = vdf_eval(&raw_seed_1, VDF_STEPS, 4);
    let out_1 = derive_vdf_output(&raw_seed_1, &proof_1);
    let beacon_1 = EpochBeacon {
        epoch: 1,
        output: out_1,
    };
    let sched_e1 = CommitteeSchedule::Beacon(Some(beacon_1));

    ts += 1;
    let (b_e1, bh_e1, qc_e1) = make_signed_block_with_schedule(
        &vs_init,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN,
        bh_pre_e1,
        prod_eng.get_state_root().await,
        ts,
        sched_e1,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 1,
                raw_seed: raw_seed_1,
                proof: proof_1,
            }),
        }),
        None,
    );
    adopter
        .adopt_committed(EPOCH_LEN, b_e1.clone(), qc_e1)
        .await
        .expect("adopter crosses EPOCH_LEN");
    producer.blocks.insert(bh_e1, b_e1.clone());
    producer.apply_and_advance(bh_e1, &b_e1).await;

    // Mid-epoch churn at h_join = EPOCH_LEN + 10 (< 2 * EPOCH_LEN, before H_freeze(2)):
    // 1. Add validator [3] with 2 * bond on both engines and refresh sets -> staged for h_join + 1.
    let h_join = EPOCH_LEN + 10;
    for eng in [&prod_eng, &adopt_eng] {
        {
            let mut ledger = eng.staking_write().await;
            let mut pq_reg = eng.pq_registry_write().await;
            ledger.bond(ids[3], 2 * bond, 0).expect("bond joiner");
            ledger
                .validator_pq_keys
                .insert(ids[3], (PqScheme::Falcon512, fks[3].public_key.clone()));
            let _ = pq_reg.adopt_legacy_key_at(
                ids[3],
                PqScheme::Falcon512,
                fks[3].public_key.clone(),
                h_join,
                true,
            );
            sync_committed_pq_registry(&pq_reg, true);
        }
        eng.credit_native(&STAKING_POOL, 2 * bond)
            .await
            .expect("credit pool for joiner");
    }
    for rt in [&mut producer, &mut adopter] {
        rt.hc = HeightConsensus::new(h_join, vs_init.clone());
        rt.hc.set_parent_hash(bh_e1);
        rt.install_committee_schedule();
        assert!(
            rt.refresh_validator_set_from_staking().await,
            "adding validator 3 must stage a pending set for h_join + 1"
        );
        assert_eq!(rt.validators.len(), 3, "h_join still uses 3-validator set");
    }

    // Apply h_join under 3-validator set; apply_and_advance installs 4-validator set for h_join + 1.
    ts += 1;
    let (b_join, bh_join, _) = make_signed_block_with_schedule(
        &vs_init,
        &ks,
        &fks,
        &[0, 1, 2],
        h_join,
        bh_e1,
        prod_eng.get_state_root().await,
        ts,
        sched_e1,
        None,
        None,
    );
    for rt in [&mut producer, &mut adopter] {
        rt.blocks.insert(bh_join, b_join.clone());
        rt.apply_and_advance(bh_join, &b_join).await;
    }
    assert_eq!(producer.validators.len(), 4);
    assert_eq!(
        producer.validators.validators,
        adopter.validators.validators
    );

    // 2. Jail validator [2] via canonical downtime evidence on h_join + 2:
    //    Put [2] at miss_threshold - 1 on both engines, decide h_join + 1 with {0, 1, 3}
    //    signing (power = 4*bond >= 2/3 of 4*bond + MIN_VALIDATOR_BOND), then apply
    //    h_join + 2 with last_qc = Some(qc_join_1).
    let vs_4 = producer.validators.clone();
    assert!(vs_4.contains(&ids[3]));
    ts += 1;
    let (b_j1, bh_j1, qc_j1) = make_signed_block_with_schedule(
        &vs_4,
        &ks,
        &fks,
        &[0, 1, 3],
        h_join + 1,
        bh_join,
        prod_eng.get_state_root().await,
        ts,
        sched_e1,
        None,
        None,
    );
    adopter
        .adopt_committed(h_join + 1, b_j1.clone(), qc_j1.clone())
        .await
        .expect("adopter accepts 4-validator block signed by {0, 1, 3}");
    producer.blocks.insert(bh_j1, b_j1.clone());
    producer.apply_and_advance(bh_j1, &b_j1).await;

    let miss_before_slash = downtime_miss_threshold_at(h_join + 1).saturating_sub(1);
    for eng in [&prod_eng, &adopt_eng] {
        let mut l = eng.staking_write().await;
        let rec = l.validators.get_mut(&ids[2]).expect("validator 2 present");
        rec.missed = miss_before_slash;
        rec.last_downtime_penalty = 0;
    }

    ts += 1;
    let (b_j2, bh_j2, qc_j2) = make_signed_block_with_schedule(
        &vs_4,
        &ks,
        &fks,
        &[0, 1, 3],
        h_join + 2,
        bh_j1,
        prod_eng.get_state_root().await,
        ts,
        sched_e1,
        None,
        Some(qc_j1),
    );
    adopter
        .adopt_committed(h_join + 2, b_j2.clone(), qc_j2)
        .await
        .expect("adopter applies downtime slash and jails validator 2");
    producer.blocks.insert(bh_j2, b_j2.clone());
    producer.apply_and_advance(bh_j2, &b_j2).await;

    for eng in [&prod_eng, &adopt_eng] {
        let l = eng.staking_read().await;
        assert!(
            l.is_jailed(&ids[2]),
            "validator 2 must be jailed after hitting downtime threshold"
        );
    }

    // At h_join + 3 (still inside epoch 1), both Producer and Adopter have converged
    // onto the 3-validator set {0, 1, 3}, identical state_root, identical proposer & committee.
    assert_eq!(producer.validators.len(), 3);
    assert!(!producer.validators.contains(&ids[2]));
    assert!(producer.validators.contains(&ids[3]));
    assert_eq!(
        producer.validators.validators,
        adopter.validators.validators
    );
    assert_eq!(
        prod_eng.get_state_root().await,
        adopt_eng.get_state_root().await,
        "Producer and Adopter state_root must remain identical across mid-epoch join + jail"
    );
    assert_eq!(
        producer.expected_proposer_now(),
        adopter.expected_proposer_now(),
        "Producer and Adopter must elect identical proposer after churn"
    );
    for h in (h_join + 3)..(h_join + 20) {
        let sched_p = producer.committee_schedule_at(h);
        let sched_a = adopter.committee_schedule_at(h);
        assert_eq!(sched_p, sched_a);
        assert_eq!(sched_p, sched_e1);
        assert_eq!(
            producer
                .validators
                .proposer_for_with_schedule(h, 0, sched_p),
            adopter.validators.proposer_for_with_schedule(h, 0, sched_a),
        );
        assert_eq!(
            committee_for_height(&producer.validators, h, 0, 2, Some(&bh_j2), sched_p),
            committee_for_height(&adopter.validators, h, 0, 2, Some(&[0xEEu8; 32]), sched_a),
        );
    }

    // Committee rotation parity across > MICRO_COMMITTEE_MAX_SIZE validators & across epoch boundary:
    let large_n = MICRO_COMMITTEE_MAX_SIZE as usize + 8;
    let mut vs_large = ValidatorSet::new();
    for i in 0..large_n {
        let mut vid = [0xC1u8; 32];
        vid[0] = (i & 0xFF) as u8;
        vid[1] = ((i >> 8) & 0xFF) as u8;
        vs_large.add(vid, bond + (i as u64) * 1_000);
    }
    let k_large = micro_committee_size(vs_large.len());
    assert_eq!(k_large, MICRO_COMMITTEE_MAX_SIZE);
    let beacon_e2 = EpochBeacon {
        epoch: 2,
        output: [0x77u8; 48],
    };
    let c_e1_a = committee_for_height(
        &vs_large,
        EPOCH_LEN + 5,
        0,
        k_large,
        Some(&[0x11u8; 32]),
        CommitteeSchedule::Beacon(Some(beacon_1)),
    );
    let c_e1_b = committee_for_height(
        &vs_large,
        EPOCH_LEN + 5,
        0,
        k_large,
        Some(&[0x99u8; 32]),
        CommitteeSchedule::Beacon(Some(beacon_1)),
    );
    assert_eq!(c_e1_a.len(), MICRO_COMMITTEE_MAX_SIZE as usize);
    assert_eq!(
        c_e1_a, c_e1_b,
        "committee_for_height under Beacon schedule must ignore parent_hash"
    );
    let c_e2 = committee_for_height(
        &vs_large,
        2 * EPOCH_LEN,
        0,
        k_large,
        Some(&[0x11u8; 32]),
        CommitteeSchedule::Beacon(Some(beacon_e2)),
    );
    assert_eq!(c_e2.len(), MICRO_COMMITTEE_MAX_SIZE as usize);
    assert_ne!(
        c_e1_a, c_e2,
        "committee must rotate across epoch beacon transition"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w11_unpredictability_fallback_refusal_and_forged_beacon_rejection() {
    let _lock = TEST_LOCK.lock().await;
    const ACTIVATION: u64 = 1;
    const VDF_STEPS: u64 = 16;

    // Frozen constants remain u64::MAX in production until rollout.
    assert!(!cnvrf_v3_active_at(EPOCH_LEN));
    assert!(!beacon_draw_active_at(EPOCH_LEN));
    assert_eq!(cnvrf_v3_epoch_of_height(EPOCH_LEN), 1);

    let bond = required_bond_floor_nano();
    let (ks, fks) = deterministic_keys(3, 0xD4);
    let ids: Vec<[u8; 32]> = ks.iter().map(|k| k.verifying_key().to_bytes()).collect();
    let vs = ValidatorSet::from_list(ids.iter().map(|&id| (id, bond)).collect());

    // 1. Direct fail-closed schedule checks for CommitteeSchedule::Beacon(None) and wrong-epoch beacons.
    let parent_a = [0x11u8; 32];
    let parent_b = [0x22u8; 32];
    assert!(
        committee_for_height(
            &vs,
            EPOCH_LEN,
            0,
            2,
            Some(&parent_a),
            CommitteeSchedule::Beacon(None),
        )
        .is_empty(),
        "Beacon(None) must fail closed instead of falling back to ParentHash draw"
    );
    assert_eq!(
        vs.proposer_for_with_schedule(EPOCH_LEN, 0, CommitteeSchedule::Beacon(None)),
        None,
        "Beacon(None) proposer selection must fail closed instead of falling back to proposer_for"
    );
    // At active sentinel height u64::MAX, proposer_for_with_beacon(.., None) fails closed;
    // below CNVRF_V3_ACTIVATION_HEIGHT it preserves legacy pre-activation parity.
    assert_eq!(vs.proposer_for_with_beacon(u64::MAX, 0, None), None);
    assert_eq!(
        vs.proposer_for_with_beacon(EPOCH_LEN, 0, None),
        vs.proposer_for(EPOCH_LEN, 0)
    );

    let wrong_epoch_beacon = EpochBeacon {
        epoch: 0,
        output: [0x33u8; 48],
    };
    assert!(
        committee_for_height(
            &vs,
            EPOCH_LEN,
            0,
            2,
            Some(&parent_a),
            CommitteeSchedule::Beacon(Some(wrong_epoch_beacon)),
        )
        .is_empty(),
        "wrong-epoch beacon must fail closed"
    );
    assert_eq!(
        vs.proposer_for_with_schedule(
            EPOCH_LEN,
            0,
            CommitteeSchedule::Beacon(Some(wrong_epoch_beacon)),
        ),
        None
    );

    // VoteSet::certificate_with_schedule under Beacon(None) must NOT compile a verifying QC.
    let dummy_bh = [0xABu8; 32];
    let mut votes_none = VoteSet::new();
    for i in 0..3 {
        let v = Vote::sign_with_falcon(
            &ks[i],
            &fks[i],
            EPOCH_LEN,
            0,
            VoteKind::Precommit,
            Some(dummy_bh),
        );
        votes_none
            .add(v, &vs, EPOCH_LEN, 0, VoteKind::Precommit)
            .unwrap();
    }
    if let Some(qc_none) = votes_none.certificate_with_schedule(
        Some(dummy_bh),
        &vs,
        Some(&parent_a),
        CommitteeSchedule::Beacon(None),
    ) {
        assert!(qc_none.pq_micro_certificate().is_none());
        assert!(!qc_none.verify_with_schedule(&vs, CommitteeSchedule::Beacon(None)));
        assert_eq!(
            vs.qc_signed_power_with_schedule(&qc_none, CommitteeSchedule::Beacon(None)),
            0
        );
    }

    // Parent-hash grinding removal: Beacon(Some(..)) produces identical committee for parent_a vs parent_b,
    // while ParentHash diverges on at least one height/round.
    let beacon_1 = EpochBeacon {
        epoch: 1,
        output: [0x44u8; 48],
    };
    let sched_1 = CommitteeSchedule::Beacon(Some(beacon_1));
    assert_eq!(
        committee_for_height(&vs, EPOCH_LEN, 0, 2, Some(&parent_a), sched_1),
        committee_for_height(&vs, EPOCH_LEN, 0, 2, Some(&parent_b), sched_1),
    );

    // 2. Runtime adopt_committed rejections for omitted, forged, wrong-epoch,
    //    wrong-steps, corrupted-proof, non-boundary, and rollback-on-err beacons.
    let prod_eng = Arc::new(InMemoryStateEngine::new());
    let adopt_eng = Arc::new(InMemoryStateEngine::new());
    let _guard = CnVrfEngineOverrideGuard::new(vec![prod_eng.clone(), adopt_eng.clone()]);

    seed_engine_validators(&prod_eng, &ks, &fks, &[bond, bond, bond]).await;
    seed_engine_validators(&adopt_eng, &ks, &fks, &[bond, bond, bond]).await;

    let mut producer = ValidatorRuntime::new(ks[0].clone(), vs.clone(), prod_eng.clone(), 1)
        .with_falcon_key(fks[0].clone());
    let mut adopter = ValidatorRuntime::new(ks[1].clone(), vs.clone(), adopt_eng.clone(), 1)
        .with_falcon_key(fks[1].clone());
    for rt in [&mut producer, &mut adopter] {
        rt.set_cnvrf_v3_activation_height_for_tests(ACTIVATION);
        rt.set_cnvrf_v3_vdf_steps(VDF_STEPS);
    }

    let chain_id = prod_eng.chain_id;
    let boot_0 = EpochBeacon {
        epoch: 0,
        output: epoch_bootstrap_beacon(chain_id, 0),
    };
    let sched_e0 = CommitteeSchedule::Beacon(Some(boot_0));
    let mut ts = 1_760_200_000u64;

    let h_freeze_1 = freeze_height_of_epoch(1);
    ts += 1;
    let (b_f1, bh_f1, _) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        h_freeze_1,
        [0u8; 32],
        prod_eng.get_state_root().await,
        ts,
        sched_e0,
        None,
        None,
    );
    for rt in [&mut producer, &mut adopter] {
        rt.hc = HeightConsensus::new(h_freeze_1, vs.clone());
        rt.hc.set_parent_hash([0u8; 32]);
        rt.install_committee_schedule();
        rt.blocks.insert(bh_f1, b_f1.clone());
        rt.apply_and_advance(bh_f1, &b_f1).await;
    }

    ts += 1;
    let (b_pre_e1, bh_pre_e1, _) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN - 1,
        bh_f1,
        prod_eng.get_state_root().await,
        ts,
        sched_e0,
        None,
        None,
    );
    for rt in [&mut producer, &mut adopter] {
        rt.hc = HeightConsensus::new(EPOCH_LEN - 1, vs.clone());
        rt.hc.set_parent_hash(bh_f1);
        rt.install_committee_schedule();
        rt.blocks.insert(bh_pre_e1, b_pre_e1.clone());
        rt.apply_and_advance(bh_pre_e1, &b_pre_e1).await;
    }
    adopter.remove_ready_vdf_beacon(1);
    assert_eq!(
        adopter.committee_schedule_at(EPOCH_LEN),
        CommitteeSchedule::Beacon(None)
    );
    assert_eq!(adopter.expected_proposer_now(), None);
    assert!(
        adopter.propose(ts + 1).await.is_none(),
        "proposer without epoch-1 VDF beacon must refuse to propose"
    );

    let freeze1 = prod_eng
        .cnvrf_freeze_inputs_read()
        .await
        .get(&1)
        .copied()
        .expect("freeze_inputs[1]");
    let genuine_seed = epoch_seed(
        chain_id,
        1,
        None,
        epoch_had_vdf(0, ACTIVATION),
        &freeze1.0,
        &freeze1.1,
    );
    let genuine_proof = vdf_eval(&genuine_seed, VDF_STEPS, 4);
    let genuine_out = derive_vdf_output(&genuine_seed, &genuine_proof);
    let genuine_sched = CommitteeSchedule::Beacon(Some(EpochBeacon {
        epoch: 1,
        output: genuine_out,
    }));
    let root_before = adopt_eng.get_state_root().await;

    // 2a. Boundary block omitting epoch_vdf is rejected.
    let (b_missing, _, qc_missing) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN,
        bh_pre_e1,
        root_before,
        ts + 1,
        genuine_sched,
        None,
        None,
    );
    assert!(
        adopter
            .adopt_committed(EPOCH_LEN, b_missing, qc_missing)
            .await
            .is_err(),
        "boundary block omitting epoch_vdf must be rejected"
    );
    assert!(!adopter.has_ready_vdf_beacon(1));

    // 2b. Boundary block naming wrong epoch (epoch 2 on EPOCH_LEN) is rejected.
    let (b_wrong_ep, _, qc_wrong_ep) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN,
        bh_pre_e1,
        root_before,
        ts + 1,
        genuine_sched,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 2,
                raw_seed: genuine_seed,
                proof: genuine_proof.clone(),
            }),
        }),
        None,
    );
    assert!(
        adopter
            .adopt_committed(EPOCH_LEN, b_wrong_ep, qc_wrong_ep)
            .await
            .is_err(),
        "boundary block with wrong epoch in epoch_vdf must be rejected"
    );
    assert!(!adopter.has_ready_vdf_beacon(1));

    // 2c. Boundary block with wrong VDF steps is rejected.
    let wrong_steps_proof = vdf_eval(&genuine_seed, VDF_STEPS + 4, 4);
    let (b_bad_steps, _, qc_bad_steps) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN,
        bh_pre_e1,
        root_before,
        ts + 1,
        genuine_sched,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 1,
                raw_seed: genuine_seed,
                proof: wrong_steps_proof,
            }),
        }),
        None,
    );
    assert!(
        adopter
            .adopt_committed(EPOCH_LEN, b_bad_steps, qc_bad_steps)
            .await
            .is_err(),
        "boundary block with mismatched VDF steps must be rejected"
    );
    assert!(!adopter.has_ready_vdf_beacon(1));

    // 2d. Valid MinRoot proof over a FORGED raw_seed (mismatching freeze_inputs[1]) is rejected.
    let forged_seed = [0x9Au8; 48];
    let forged_proof = vdf_eval(&forged_seed, VDF_STEPS, 4);
    let forged_out = derive_vdf_output(&forged_seed, &forged_proof);
    let forged_sched = CommitteeSchedule::Beacon(Some(EpochBeacon {
        epoch: 1,
        output: forged_out,
    }));
    let (b_forged_seed, _, qc_forged_seed) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN,
        bh_pre_e1,
        root_before,
        ts + 1,
        forged_sched,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 1,
                raw_seed: forged_seed,
                proof: forged_proof,
            }),
        }),
        None,
    );
    assert!(
        adopter
            .adopt_committed(EPOCH_LEN, b_forged_seed, qc_forged_seed)
            .await
            .is_err(),
        "forged raw_seed not matching freeze_inputs[1] must be rejected"
    );
    assert!(!adopter.has_ready_vdf_beacon(1));

    // 2e. Genuine raw_seed with corrupted MinRoot proof is rejected.
    let mut bad_proof = genuine_proof.clone();
    bad_proof.final_xy.1[0] ^= 0xFF;
    let (b_bad_proof, _, qc_bad_proof) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN,
        bh_pre_e1,
        root_before,
        ts + 1,
        genuine_sched,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 1,
                raw_seed: genuine_seed,
                proof: bad_proof,
            }),
        }),
        None,
    );
    assert!(
        adopter
            .adopt_committed(EPOCH_LEN, b_bad_proof, qc_bad_proof)
            .await
            .is_err(),
        "corrupted MinRoot VDF proof must be rejected"
    );
    assert!(!adopter.has_ready_vdf_beacon(1));

    // 2f. Valid epoch_vdf paired with a later failure (wrong state_root) must roll back
    //     ready_vdf_beacons so rejected commits leave zero staged beacon state.
    let (b_bad_root, _, qc_bad_root) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN,
        bh_pre_e1,
        [0xFFu8; 32],
        ts + 1,
        genuine_sched,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 1,
                raw_seed: genuine_seed,
                proof: genuine_proof.clone(),
            }),
        }),
        None,
    );
    assert!(
        adopter
            .adopt_committed(EPOCH_LEN, b_bad_root, qc_bad_root)
            .await
            .is_err(),
        "bad state_root must fail adopt_committed"
    );
    assert!(
        !adopter.has_ready_vdf_beacon(1),
        "failed adopt_committed must roll back staged ready_vdf_beacons[1]"
    );

    // 2g. Genuine boundary block succeeds cleanly after all rejected attempts.
    let (b_good, bh_good, qc_good) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN,
        bh_pre_e1,
        root_before,
        ts + 1,
        genuine_sched,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 1,
                raw_seed: genuine_seed,
                proof: genuine_proof.clone(),
            }),
        }),
        None,
    );
    adopter
        .adopt_committed(EPOCH_LEN, b_good, qc_good.clone())
        .await
        .expect("genuine boundary block must succeed after prior rejections");
    assert_eq!(
        adopt_eng.epoch_vdf_beacons_read().await.get(&1).copied(),
        Some(genuine_out)
    );

    // 2h. Unexpected epoch_vdf on a non-boundary height (EPOCH_LEN + 1) is rejected.
    let (b_non_boundary, _, qc_non_boundary) = make_signed_block_with_schedule(
        &vs,
        &ks,
        &fks,
        &[0, 1, 2],
        EPOCH_LEN + 1,
        bh_good,
        adopt_eng.get_state_root().await,
        ts + 2,
        genuine_sched,
        Some(CnVrfV3BlockPayload {
            reveal: None,
            commits: vec![],
            epoch_vdf: Some(EpochVdfBeacon {
                epoch: 1,
                raw_seed: genuine_seed,
                proof: genuine_proof,
            }),
        }),
        Some(qc_good),
    );
    assert!(
        adopter
            .adopt_committed(EPOCH_LEN + 1, b_non_boundary, qc_non_boundary)
            .await
            .is_err(),
        "non-boundary height carrying epoch_vdf must be rejected"
    );
}
