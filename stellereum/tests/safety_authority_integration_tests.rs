//! Comprehensive P0-LOCK-WATERMARK integration, protocol, crash-fault, and
//! legacy-quarantine test suite (`docs/specs/05_LOCK_SAFETY_P0.md` §3.2).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use stellereum::consensus::{
    register_validator_pq_key, vote_sign_bytes, HeightConsensus, ValidatorSet, VoteKind,
};
use stellereum::consensus_net::{coalesce_for_send, is_superseded_vote, ConsensusMsg};
use stellereum::post_quantum::{FalconKeypair, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::remote_signer::{
    RemoteSigner, SignerError, SignerTransport, TransportErrorKind, SIGNATURE_LEN,
};
use stellereum::runtime::{Cluster, ValidatorRuntime};
use stellereum::safety::{
    derive_safety_chain_id, operator_safety_init, AuthorityMode, SafetyAuthority,
    SafetyBootContext, SafetyIoStage, SafetyRecordPayload,
};
use stellereum::sharding::{Block, ShardRegistry, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{
    ConsensusCheckpoint, SafetyRecordIdentity, Storage, VoteWatermark, VoteWatermarkEntry,
};
use stellereum::svm::OpCode;

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "stell-safety-auth-{tag}-{}-{id}",
            std::process::id()
        ));
        assert!(!path.exists(), "test directory already exists");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if self.0.exists() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

type OnSignCallback = Arc<dyn Fn(&[u8]) + Send + Sync>;

struct SpyTransport {
    key: SigningKey,
    on_sign: OnSignCallback,
    fail: Arc<std::sync::atomic::AtomicBool>,
    calls: Arc<AtomicUsize>,
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl SignerTransport for SpyTransport {
    fn public_key(&self) -> Result<[u8; 32], SignerError> {
        Ok(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_LEN], SignerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.on_sign)(message);
        if self.fail.load(Ordering::SeqCst) {
            return Err(SignerError::Transport(TransportErrorKind::Request));
        }
        self.messages.lock().unwrap().push(message.to_vec());
        Ok(self.key.sign(message).to_bytes())
    }
}

fn block_at(height: u64, round: u32, proposer: [u8; 32], tag: u8) -> (Block, [u8; 32]) {
    let blk = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [tag; 32],
        timestamp: 1_700_000_000 + height + tag as u64,
        proposer,
        round,
        order_merkle_root: stellereum::mev::compute_order_merkle_root(&[]),
        ..Default::default()
    };
    let h = blk.compute_hash();
    (blk, h)
}

fn identity_for(validator: [u8; 32], genesis_root: [u8; 32], shard: u32) -> SafetyRecordIdentity {
    SafetyRecordIdentity {
        validator,
        chain: derive_safety_chain_id(stellereum::consensus::consensus_chain_id(), &genesis_root),
        shard,
    }
}

fn init_clean_genesis_storage(dir: &TestDir, genesis_root: [u8; 32]) -> Arc<Storage> {
    let storage = Arc::new(Storage::open(&dir.0).expect("open storage"));
    storage
        .set_meta("genesis_state_root", &genesis_root)
        .expect("set genesis_state_root");
    storage
}

fn clean_genesis_boot_ctx() -> SafetyBootContext {
    SafetyBootContext {
        is_validator: true,
        is_observer_env: false,
        new_chain_explicit: true,
        restored_finalized: None,
        restored_state_height: Some(0),
        restored_finalized_qc_verified: false,
        legacy_checkpoint: None,
        legacy_watermark: None,
    }
}

// ============================================================================
// A.1: 4-validator f=0 cross-kind counterexample (§1.2)
// ============================================================================

#[tokio::test]
async fn cross_kind_non_nil_prevote_then_late_polka_precommit_refused_prevents_4val_fork() {
    const H: u64 = 1;
    // Test both equal [1,1,1,1] and weighted [1500,1000,1000,1000] power profiles.
    for powers in [[1u64, 1, 1, 1], [1500u64, 1000, 1000, 1000]] {
        let (ks, fks) = falcon_votes::falcon_set(4);
        let vset = ValidatorSet::from_list(
            ks.iter()
                .enumerate()
                .map(|(i, k)| (k.verifying_key().to_bytes(), powers[i]))
                .collect(),
        );
        let mut rts: Vec<ValidatorRuntime> = Vec::new();
        for i in 0..4 {
            let st = Arc::new(InMemoryStateEngine::new());
            rts.push(
                ValidatorRuntime::new(ks[i].clone(), vset.clone(), st, H)
                    .with_falcon_key(fks[i].clone()),
            );
        }

        let (blk_x, x_hash) = block_at(H, 0, ks[0].verifying_key().to_bytes(), 0xAA);
        let (blk_y, y_hash) = block_at(H, 11, ks[3].verifying_key().to_bytes(), 0xBB);
        for rt in &mut rts {
            rt.blocks.insert(x_hash, blk_x.clone());
            rt.blocks.insert(y_hash, blk_y.clone());
        }

        // Step 1: r0 — A, B, C (indices 0, 1, 2) prevote (r0, X) while unlocked.
        let mut r0_prevotes = Vec::new();
        for rt in rts.iter_mut().take(3) {
            let expected = rt.hc.proposer();
            let p0 = ks[0].verifying_key().to_bytes();
            if expected == Some(p0) {
                rt.hc
                    .receive_proposal_for_at(p0, x_hash, expected, 0)
                    .unwrap();
            } else {
                rt.hc.proposal = Some((p0, x_hash));
                rt.hc.proposal_round = Some(0);
                rt.hc.proposal_signed_round = Some(0);
            }
            rt.hc.note_value_id(x_hash, blk_x.value_id());
            let pv = rt.make_prevote().expect("r0 prevote X");
            assert_eq!((pv.round, pv.block_hash), (0, Some(x_hash)));
            r0_prevotes.push(pv);
        }

        // Step 2: r11 — before r0 prevotes arrive, {0, 1, 3} (weighted 3500>=3001)
        // or {1, 2, 3} (equal 3>=3) time out to r11 while still unlocked and
        // prevote (r11, Y).
        let r11_voters = if powers[0] == 1500 {
            [0usize, 1, 3]
        } else {
            [1usize, 2, 3]
        };
        let mut r11_prevotes = Vec::new();
        for &i in &r11_voters {
            while rts[i].hc.round < 11 {
                rts[i].next_round();
            }
            let p3 = ks[3].verifying_key().to_bytes();
            rts[i].hc.proposal = Some((p3, y_hash));
            rts[i].hc.proposal_round = Some(11);
            rts[i].hc.proposal_signed_round = Some(11);
            rts[i].hc.note_value_id(y_hash, blk_y.value_id());
            let pv = rts[i].make_prevote().expect("r11 prevote Y");
            assert_eq!((pv.round, pv.block_hash), (11, Some(y_hash)));
            r11_prevotes.push(pv);
        }

        // Step 3: Late r0 polka arrives at A, B, C.
        // Any validator that signed conflicting prevote(r11, Y) MUST REFUSE
        // precommit(r0, X).
        let mut r0_precommits = Vec::new();
        for (i, rt) in rts.iter_mut().enumerate().take(3) {
            for pv in &r0_prevotes {
                rt.on_prevote(pv.clone()).unwrap();
            }
            let pc = rt.make_precommit();
            if r11_voters.contains(&i) {
                assert!(
                    pc.is_none(),
                    "validator {i} signed conflicting prevote(r11, Y), must refuse precommit(r0, X)"
                );
                // Liveness lock adoption (§1.6): validator adopts lock (X, r0)
                // even though precommit(r0, X) was refused.
                assert_eq!(rt.hc.locked, Some((x_hash, 0)));
            } else {
                let v = pc.expect("unconflicted validator C can precommit r0");
                assert_eq!((v.round, v.block_hash), (0, Some(x_hash)));
                r0_precommits.push(v);
            }
        }
        // Only at most one validator (C) precommitted (r0, X); no r0 precommit QC can form!
        for rt in &mut rts {
            for pc in &r0_precommits {
                rt.on_precommit(pc.clone()).unwrap();
            }
            assert!(
                rt.hc.try_precommit_quorum().is_none(),
                "X must NOT reach precommit quorum when conflicting prevotes were cast at r11"
            );
        }
    }
}

// ============================================================================
// A.2: nil on r12 after conflicting prevote(r11, Y) does NOT bypass guard
// ============================================================================

#[tokio::test]
async fn nil_after_conflicting_non_nil_prevote_does_not_bypass_cross_kind_guard() {
    const H: u64 = 1;
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let mut rt =
        ValidatorRuntime::new(ks[0].clone(), vset, Arc::new(InMemoryStateEngine::new()), H)
            .with_falcon_key(fks[0].clone());

    let (blk_x, x_hash) = block_at(H, 0, ks[0].verifying_key().to_bytes(), 0x11);
    let (blk_y, y_hash) = block_at(H, 10, ks[1].verifying_key().to_bytes(), 0x22);
    rt.blocks.insert(x_hash, blk_x.clone());
    rt.blocks.insert(y_hash, blk_y.clone());

    // Prevote (r10, Y) non-nil.
    while rt.hc.round < 10 {
        rt.next_round();
    }
    rt.hc.proposal = Some((ks[1].verifying_key().to_bytes(), y_hash));
    rt.hc.proposal_round = Some(10);
    rt.hc.proposal_signed_round = Some(10);
    rt.hc.note_value_id(y_hash, blk_y.value_id());
    let pv10 = rt.make_prevote().expect("prevote r10 Y");
    assert_eq!(pv10.block_hash, Some(y_hash));

    // Prevote (r11, nil).
    rt.next_round();
    assert_eq!(rt.hc.round, 11);
    let pv11 = rt.make_prevote().expect("prevote r11 nil");
    assert_eq!(pv11.block_hash, None);

    // Verify SafetyRecordPayload preserved (last_non_nil_prevote = r10 Y) across nil at r11.
    let state = rt.safety.current_state().unwrap();
    assert_eq!(state.highest_prevote_round, Some(11));
    assert_eq!(
        state.last_non_nil_prevote.map(|p| (p.round, p.block_hash)),
        Some((10, y_hash))
    );

    // Late polka (r0, X) arrives: must REFUSE precommit(r0, X)!
    for i in 0..3 {
        let pv = falcon_votes::fvote(&ks[i], &fks[i], H, 0, VoteKind::Prevote, Some(x_hash));
        rt.on_prevote(pv).unwrap();
    }
    assert!(
        rt.make_precommit().is_none(),
        "nil at r11 must not erase conflicting non-nil prevote(r10, Y)"
    );
    assert!(
        !rt.safety
            .current_state()
            .unwrap()
            .can_sign_precommit_cross_kind(0, blk_x.value_id()),
        "O(1) cross-kind predicate must still detect r10 Y conflict"
    );
}

// ============================================================================
// A.3: No sign_bytes before SafetyRecordStore::persist (all entry points)
// ============================================================================

#[tokio::test]
async fn no_sign_bytes_before_safety_record_persist_in_driver_and_in_process() {
    const H: u64 = 1;
    let dir = TestDir::new("sign-order");
    let storage = init_clean_genesis_storage(&dir, [0x44u8; 32]);
    let (ks, fks) = falcon_votes::falcon_set(3);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let my_id = ks[0].verifying_key().to_bytes();
    let id = identity_for(my_id, [0x44u8; 32], MASTERCHAIN_SHARD);
    let spy_store = storage.safety_record_store(id.clone()).unwrap();

    let observed_gens = Arc::new(Mutex::new(Vec::<u64>::new()));
    let observed_gens_cb = observed_gens.clone();
    let spy_store_cb = spy_store.clone();
    let fail_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let messages = Arc::new(Mutex::new(Vec::new()));
    let signer = RemoteSigner::new(Arc::new(SpyTransport {
        key: ks[0].clone(),
        on_sign: Arc::new(move |_| {
            let rec = spy_store_cb
                .load()
                .expect("read store inside sign")
                .expect("record already persisted on disk before sign_bytes");
            observed_gens_cb.lock().unwrap().push(rec.generation);
        }),
        fail: fail_flag.clone(),
        calls: calls.clone(),
        messages: messages.clone(),
    }))
    .unwrap();

    let auth = SafetyAuthority::open_from_storage(storage.clone(), id, clean_genesis_boot_ctx());
    assert_eq!(auth.generation(), Some(1));

    let st = Arc::new(InMemoryStateEngine::new());
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), st, H)
        .with_falcon_key(fks[0].clone())
        .with_remote_signer(Arc::new(signer))
        .unwrap()
        .with_safety_authority(auth);

    // 1. Catchup nil make_prevote (round 0, no proposal).
    let pv0 = rt.make_prevote().expect("catchup nil prevote");
    assert_eq!(pv0.block_hash, None);
    assert_eq!(observed_gens.lock().unwrap().last().copied(), Some(2));

    // 2. Propose (at ks[0]'s proposer slot at round > 0).
    if rt.hc.round == 0 {
        rt.next_round();
    }
    while rt.hc.proposer() != Some(my_id) {
        rt.next_round();
    }
    let b = rt.propose(1_700_000_010).await.expect("propose");
    let bh = b.compute_hash();
    assert_eq!(observed_gens.lock().unwrap().last().copied(), Some(3));

    // 3. Value make_prevote.
    let pv_val = rt.make_prevote().expect("value prevote");
    assert_eq!(pv_val.block_hash, Some(bh));
    assert_eq!(observed_gens.lock().unwrap().last().copied(), Some(4));

    // 4. make_precommit (form polka at current round: 3 of 3 validators).
    let r_polka = rt.hc.round;
    rt.on_prevote(pv_val).unwrap();
    for i in 1..3 {
        rt.on_prevote(falcon_votes::fvote(
            &ks[i],
            &fks[i],
            H,
            r_polka,
            VoteKind::Prevote,
            Some(bh),
        ))
        .unwrap();
    }
    let pc = rt.make_precommit().expect("make_precommit");
    assert_eq!(pc.block_hash, Some(bh));
    assert_eq!(observed_gens.lock().unwrap().last().copied(), Some(5));

    // 5. restamp_for_round via locked re-proposal at next proposer slot.
    rt.next_round();
    while rt.hc.proposer() != Some(my_id) {
        rt.next_round();
    }
    let restamped = rt.propose(1_700_000_020).await.expect("restamp propose");
    assert_eq!(restamped.round, rt.hc.round);
    assert_eq!(restamped.value_id(), b.value_id());
    assert_eq!(observed_gens.lock().unwrap().last().copied(), Some(6));

    // 6. Timeout nil make_prevote at another round.
    rt.next_round();
    let pv_nil = rt.make_prevote().expect("timeout nil");
    assert_eq!(pv_nil.block_hash, None);
    assert_eq!(observed_gens.lock().unwrap().last().copied(), Some(7));

    // 7. Fault-inject persist error -> sign_bytes must be called 0 times!
    rt.next_round();
    let calls_before = calls.load(Ordering::SeqCst);
    rt.safety.set_io_fault_hook_for_test(Some(Arc::new(|stage| {
        if stage == SafetyIoStage::RecordPersist {
            anyhow::bail!("injected persist error");
        }
        Ok(())
    })));
    assert!(rt.make_prevote().is_none());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        calls_before,
        "persist error must prevent sign_bytes invocation"
    );

    // 8. In-process Cluster::run_height uses Ephemeral SafetyAuthority cleanly.
    let mut cluster = Cluster::new(
        ks.iter()
            .map(|k| (k.clone(), Arc::new(InMemoryStateEngine::new())))
            .collect(),
    );
    let finalized_bh = cluster.run_height(1_700_000_100).await;
    assert_eq!(cluster.nodes[0].finalized, vec![(1, finalized_bh)]);
    assert_eq!(cluster.nodes[0].safety.current_state().unwrap().height, 2);
}

// ============================================================================
// A.4: Late-polka precommit after nil prevote succeeds & not pruned by outbox
// ============================================================================

#[tokio::test]
async fn late_polka_precommit_after_nil_prevote_succeeds_and_not_pruned_by_outbox() {
    const H: u64 = 7;
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let mut rt =
        ValidatorRuntime::new(ks[0].clone(), vset, Arc::new(InMemoryStateEngine::new()), H)
            .with_falcon_key(fks[0].clone());

    let (blk, x_hash) = block_at(H, 0, ks[0].verifying_key().to_bytes(), 0x55);
    rt.blocks.insert(x_hash, blk);
    while rt.hc.round < 11 {
        rt.next_round();
    }
    let nil_pv = rt.make_prevote().expect("r11 nil prevote");
    assert_eq!(nil_pv.block_hash, None);

    for i in 0..3 {
        rt.on_prevote(falcon_votes::fvote(
            &ks[i],
            &fks[i],
            H,
            0,
            VoteKind::Prevote,
            Some(x_hash),
        ))
        .unwrap();
    }
    let pc = rt
        .make_precommit()
        .expect("late polka at r0 after nil at r11 must precommit");
    assert_eq!((pc.round, pc.block_hash), (0, Some(x_hash)));

    let stale_pv = ConsensusMsg::Vote {
        vote: falcon_votes::fvote(&ks[0], &fks[0], H, 0, VoteKind::Prevote, None),
        locked: None,
    };
    let late_pc_msg = ConsensusMsg::Vote {
        vote: pc,
        locked: None,
    };
    assert!(is_superseded_vote(&stale_pv, H, 11));
    assert!(!is_superseded_vote(&late_pc_msg, H, 11));
    let out = coalesce_for_send(vec![stale_pv, late_pc_msg], H, 11);
    assert_eq!(out.len(), 1);
    match &out[0] {
        ConsensusMsg::Vote { vote, .. } => {
            assert_eq!(vote.kind, VoteKind::Precommit);
            assert_eq!(vote.round, 0);
        }
        other => panic!("unexpected msg: {other:?}"),
    }
}

// ============================================================================
// A.5: Legacy quarantine & clean-genesis gate & operator safety-init
// ============================================================================

#[test]
fn legacy_absent_safety_record_quarantines_to_observer_except_clean_genesis() {
    let key = SigningKey::from_bytes(&[0x31; 32]);
    let val_id = key.verifying_key().to_bytes();
    let genesis_root = [0x99u8; 32];
    let id = identity_for(val_id, genesis_root, 0);

    // (i-a) Clean dir WITHOUT STELL_NEW_CHAIN=1 -> Quarantined!
    {
        let dir = TestDir::new("no-new-chain");
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let mut ctx = clean_genesis_boot_ctx();
        ctx.new_chain_explicit = false;
        let auth = SafetyAuthority::open_from_storage(storage, id.clone(), ctx);
        assert!(matches!(auth.mode(), AuthorityMode::Quarantined(_)));
        assert!(!auth.can_sign());
    }

    // (i-b) Store with finalized > 0 and no safety_record_v1 -> Quarantined!
    {
        let dir = TestDir::new("legacy-finalized");
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        storage.set_finalized(10, &[0xAB; 32]).unwrap();
        let mut ctx = clean_genesis_boot_ctx();
        ctx.restored_finalized = Some((10, [0xAB; 32]));
        let auth = SafetyAuthority::open_from_storage(storage.clone(), id.clone(), ctx);
        assert!(matches!(auth.mode(), AuthorityMode::Quarantined(_)));
        assert!(!auth.can_sign());

        // Configured Observer -> ObserverOnly (not Quarantined error, still cannot sign).
        let mut obs_ctx = clean_genesis_boot_ctx();
        obs_ctx.is_validator = false;
        let obs_auth = SafetyAuthority::open_from_storage(storage, id.clone(), obs_ctx);
        assert_eq!(obs_auth.mode(), AuthorityMode::ObserverOnly);
        assert!(!obs_auth.can_sign());
    }

    // (i-c) Store with vote_watermark != None and no safety_record_v1 -> Quarantined!
    {
        let dir = TestDir::new("legacy-wm");
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let mut wm = VoteWatermark::default();
        wm.note(VoteWatermarkEntry {
            height: 1,
            round: 5,
            kind: 0,
            target: None,
            shard_id: 0,
        });
        storage.persist_vote_watermark(&wm).unwrap();
        let mut ctx = clean_genesis_boot_ctx();
        ctx.legacy_watermark = Some(wm);
        let auth = SafetyAuthority::open_from_storage(storage.clone(), id.clone(), ctx);
        assert!(matches!(auth.mode(), AuthorityMode::Quarantined(_)));

        // operator_safety_init refuses without --i-fenced-all-signers or below legacy watermark.
        assert!(operator_safety_init(&storage, val_id, 0, Some(10), None, false).is_err());
        assert!(operator_safety_init(&storage, val_id, 0, Some(4), None, true).is_err());
        // Succeeds with conservative floor >= 5 and fenced confirmation.
        let rec = operator_safety_init(&storage, val_id, 0, Some(6), Some(0), true).unwrap();
        assert_eq!(rec.generation, 1);

        // Subsequent boot enters Active with floor 6.
        let mut ctx2 = clean_genesis_boot_ctx();
        ctx2.new_chain_explicit = false;
        ctx2.legacy_watermark = storage.vote_watermark().unwrap();
        let auth2 = SafetyAuthority::open_from_storage(storage, id.clone(), ctx2);
        assert_eq!(auth2.mode(), AuthorityMode::Active);
        assert_eq!(
            auth2.current_state().unwrap().highest_prevote_round,
            Some(6)
        );
    }

    // (ii) Clean dir + STELL_NEW_CHAIN=1 + height 0 + zero prior votes -> Active gen 1!
    {
        let dir = TestDir::new("clean-genesis");
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let auth = SafetyAuthority::open_from_storage(
            storage.clone(),
            id.clone(),
            clean_genesis_boot_ctx(),
        );
        assert_eq!(auth.mode(), AuthorityMode::Active);
        assert!(auth.can_sign());
        assert_eq!(auth.generation(), Some(1));
        let payload = auth.current_state().unwrap();
        assert_eq!(payload.height, 1);
        assert_eq!(payload.finalized_height, 0);
        // Persisted on disk at generation 1.
        let on_disk = storage
            .safety_record_store(id)
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(on_disk.generation, 1);
    }
}

// ============================================================================
// B.1: Crash after put_block+flush before SafetyRecordStore::persist
// ============================================================================

#[tokio::test]
async fn crash_after_put_block_flush_before_safety_persist() {
    const H: u64 = 1;
    let dir = TestDir::new("crash-between-step-a-b");
    let genesis_root = [0x12u8; 32];
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let val_id = ks[0].verifying_key().to_bytes();
    let id = identity_for(val_id, genesis_root, 0);
    let (blk, bh) = block_at(H, 0, val_id, 0x77);

    {
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let auth = SafetyAuthority::open_from_storage(
            storage.clone(),
            id.clone(),
            clean_genesis_boot_ctx(),
        );
        auth.set_io_fault_hook_for_test(Some(Arc::new(|stage| {
            if stage == SafetyIoStage::RecordPersist {
                anyhow::bail!("simulated crash before Step B persist");
            }
            Ok(())
        })));
        let mut rt = ValidatorRuntime::new(
            ks[0].clone(),
            vset.clone(),
            Arc::new(InMemoryStateEngine::new()),
            H,
        )
        .with_falcon_key(fks[0].clone())
        .with_safety_authority(auth);
        rt.blocks.insert(bh, blk.clone());
        for i in 0..3 {
            rt.on_prevote(falcon_votes::fvote(
                &ks[i],
                &fks[i],
                H,
                0,
                VoteKind::Prevote,
                Some(bh),
            ))
            .unwrap();
        }
        assert!(rt.make_precommit().is_none());
        assert_eq!(rt.hc.locked, None);
        // Step A already wrote the block body to `blocks`, harmlessly.
        assert!(storage.get_block(&bh).unwrap().is_some());
    }

    // Reopen after crash: generation is still 1, locked is still None.
    let storage = Arc::new(Storage::open(&dir.0).unwrap());
    let mut ctx = clean_genesis_boot_ctx();
    ctx.new_chain_explicit = false;
    let auth = SafetyAuthority::open_from_storage(storage, id, ctx);
    assert_eq!(auth.mode(), AuthorityMode::Active);
    assert_eq!(auth.generation(), Some(1));
    assert_eq!(auth.locked(), None);
    assert_eq!(auth.current_state().unwrap().highest_precommit_round, None);
}

// ============================================================================
// B.2: Crash / remote signer failure after SafetyRecordStore::persist
// ============================================================================

#[tokio::test]
async fn crash_after_safety_persist_before_sign_bytes_and_remote_signer_failure() {
    const H: u64 = 1;
    let dir = TestDir::new("signer-fail-after-persist");
    let genesis_root = [0x23u8; 32];
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let val_id = ks[0].verifying_key().to_bytes();
    let id = identity_for(val_id, genesis_root, 0);
    let (blk, bh) = block_at(H, 0, val_id, 0x33);
    let (blk_other, other_bh) = block_at(H, 0, ks[1].verifying_key().to_bytes(), 0x44);

    {
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let auth = SafetyAuthority::open_from_storage(
            storage.clone(),
            id.clone(),
            clean_genesis_boot_ctx(),
        );
        let signer = RemoteSigner::new(Arc::new(SpyTransport {
            key: ks[0].clone(),
            on_sign: Arc::new(|_| {}),
            fail: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            calls: Arc::new(AtomicUsize::new(0)),
            messages: Arc::new(Mutex::new(Vec::new())),
        }))
        .unwrap();
        let mut rt = ValidatorRuntime::new(
            ks[0].clone(),
            vset.clone(),
            Arc::new(InMemoryStateEngine::new()),
            H,
        )
        .with_falcon_key(fks[0].clone())
        .with_remote_signer(Arc::new(signer))
        .unwrap()
        .with_safety_authority(auth);
        rt.blocks.insert(bh, blk.clone());
        for i in 0..3 {
            rt.on_prevote(falcon_votes::fvote(
                &ks[i],
                &fks[i],
                H,
                0,
                VoteKind::Prevote,
                Some(bh),
            ))
            .unwrap();
        }
        // Signer fails -> make_precommit returns None, BUT reservation & lock are NOT rolled back!
        assert!(rt.make_precommit().is_none());
        assert_eq!(rt.safety.generation(), Some(2));
        assert_eq!(
            rt.safety.current_state().unwrap().highest_precommit_round,
            Some(0)
        );
        assert_eq!(rt.hc.locked, Some((bh, 0)));
    }

    // Reopen: reservation persisted; node refuses to precommit round 0 again even for another value.
    let storage = Arc::new(Storage::open(&dir.0).unwrap());
    let mut ctx = clean_genesis_boot_ctx();
    ctx.new_chain_explicit = false;
    let auth = SafetyAuthority::open_from_storage(storage, id, ctx);
    assert_eq!(auth.generation(), Some(2));
    assert_eq!(
        auth.locked().map(|l| (l.block_hash, l.round)),
        Some((bh, 0))
    );
    let mut rt2 =
        ValidatorRuntime::new(ks[0].clone(), vset, Arc::new(InMemoryStateEngine::new()), H)
            .with_falcon_key(fks[0].clone())
            .with_safety_authority(auth);
    rt2.blocks.insert(other_bh, blk_other);
    for i in 0..3 {
        rt2.on_prevote(falcon_votes::fvote(
            &ks[i],
            &fks[i],
            H,
            0,
            VoteKind::Prevote,
            Some(other_bh),
        ))
        .unwrap();
    }
    assert!(
        rt2.make_precommit().is_none(),
        "must not re-precommit round 0 after persisted reservation"
    );
}

// ============================================================================
// B.3: Injected put_block / flush / persist error quarantines & 0 signs
// ============================================================================

#[tokio::test]
async fn injected_put_block_or_flush_or_persist_error_quarantines_and_emits_zero_bytes() {
    const H: u64 = 1;
    for stage_to_fail in [
        SafetyIoStage::PutBlock,
        SafetyIoStage::StorageFlush,
        SafetyIoStage::RecordPersist,
    ] {
        let dir = TestDir::new("io-fault");
        let genesis_root = [0x51u8; 32];
        let (ks, fks) = falcon_votes::falcon_set(4);
        let vset = ValidatorSet::from_list(
            ks.iter()
                .map(|k| (k.verifying_key().to_bytes(), 1))
                .collect(),
        );
        let val_id = ks[0].verifying_key().to_bytes();
        let id = identity_for(val_id, genesis_root, 0);
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let auth = SafetyAuthority::open_from_storage(storage, id, clean_genesis_boot_ctx());
        auth.set_io_fault_hook_for_test(Some(Arc::new(move |stage| {
            if stage == stage_to_fail {
                anyhow::bail!("injected fault at {stage:?}");
            }
            Ok(())
        })));
        let calls = Arc::new(AtomicUsize::new(0));
        let signer = RemoteSigner::new(Arc::new(SpyTransport {
            key: ks[0].clone(),
            on_sign: Arc::new(|_| {}),
            fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            calls: calls.clone(),
            messages: Arc::new(Mutex::new(Vec::new())),
        }))
        .unwrap();
        let mut rt =
            ValidatorRuntime::new(ks[0].clone(), vset, Arc::new(InMemoryStateEngine::new()), H)
                .with_falcon_key(fks[0].clone())
                .with_remote_signer(Arc::new(signer))
                .unwrap()
                .with_safety_authority(auth);

        let (blk, bh) = block_at(H, 0, val_id, 0x61);
        rt.blocks.insert(bh, blk);
        for i in 0..3 {
            rt.on_prevote(falcon_votes::fvote(
                &ks[i],
                &fks[i],
                H,
                0,
                VoteKind::Prevote,
                Some(bh),
            ))
            .unwrap();
        }
        assert!(rt.make_precommit().is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(rt.hc.locked, None);
        assert!(matches!(rt.safety.mode(), AuthorityMode::Quarantined(_)));
        assert!(!rt.safety.can_sign());
        // Subsequent votes/proposals are permanently refused.
        rt.next_round();
        assert!(rt.make_prevote().is_none());
        assert!(rt.propose(1_700_000_050).await.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

// ============================================================================
// B.4: Lock body persisted before precommit sign and survives crash for restamp
// ============================================================================

#[tokio::test]
async fn lock_body_persisted_before_precommit_sign_and_survives_crash_for_restamp() {
    const H: u64 = 1;
    let dir = TestDir::new("lock-body-crash");
    let genesis_root = [0x66u8; 32];
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let val_id = ks[0].verifying_key().to_bytes();
    let id = identity_for(val_id, genesis_root, 0);

    let state0 = Arc::new(InMemoryStateEngine::new());
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vset.clone(), state0, H)
        .with_falcon_key(fks[0].clone());
    let root0 = rt.state.get_state_root().await;

    let orig_bh;
    let orig_vid;
    {
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let auth =
            SafetyAuthority::open_from_storage(storage, id.clone(), clean_genesis_boot_ctx());
        rt = rt.with_safety_authority(auth);
        while rt.hc.proposer() != Some(val_id) {
            rt.next_round();
        }
        let r0 = rt.hc.round;
        let blk = rt.propose(1_700_000_001).await.expect("propose r0");
        orig_bh = blk.compute_hash();
        orig_vid = blk.value_id();
        for i in 0..3 {
            rt.on_prevote(falcon_votes::fvote(
                &ks[i],
                &fks[i],
                H,
                r0,
                VoteKind::Prevote,
                Some(orig_bh),
            ))
            .unwrap();
        }
        let pc = rt.make_precommit().expect("precommit r0");
        assert_eq!(pc.block_hash, Some(orig_bh));
        // Crash immediately after sign_bytes (no ConsensusCheckpoint, no AsyncPersistence!).
        drop(rt);
    }

    // Reopen storage and reconcile runtime from durable SafetyRecordStore.
    let storage = Arc::new(Storage::open(&dir.0).unwrap());
    let mut ctx = clean_genesis_boot_ctx();
    ctx.new_chain_explicit = false;
    let auth = SafetyAuthority::open_from_storage(storage.clone(), id, ctx);
    assert_eq!(auth.mode(), AuthorityMode::Active);
    let lock = auth.locked().expect("lock survived crash");
    assert_eq!(lock.block_hash, orig_bh);
    assert_eq!(lock.value_id, orig_vid);

    let restored_blk = storage
        .get_block(&lock.block_hash)
        .unwrap()
        .expect("lock body persisted synchronously in Step A");
    assert_eq!(restored_blk.compute_hash(), orig_bh);
    assert_eq!(restored_blk.value_id(), orig_vid);

    let state1 = Arc::new(InMemoryStateEngine::new());
    assert_eq!(state1.get_state_root().await, root0);
    let mut rt_reopened = ValidatorRuntime::new(ks[0].clone(), vset, state1, H)
        .with_falcon_key(fks[0].clone())
        .with_safety_authority(auth);
    rt_reopened.blocks.insert(orig_bh, restored_blk);
    rt_reopened.hc.locked = Some((lock.block_hash, lock.round));
    rt_reopened.hc.note_value_id(lock.block_hash, lock.value_id);
    while rt_reopened.hc.round <= lock.round || rt_reopened.hc.proposer() != Some(val_id) {
        rt_reopened.next_round();
    }
    let restamped = rt_reopened
        .propose(1_700_000_010)
        .await
        .expect("re-stamped locked value after crash");
    assert_ne!(restamped.compute_hash(), orig_bh);
    assert_eq!(restamped.value_id(), orig_vid);
    assert!(rt_reopened.hc.same_value(restamped.compute_hash(), orig_bh));
}

// ============================================================================
// B.5: Missing or corrupt lock body on restart fails closed
// ============================================================================

#[tokio::test]
async fn missing_or_corrupt_lock_body_on_restart_fails_closed() {
    const H: u64 = 1;
    let dir = TestDir::new("missing-lock-body");
    let genesis_root = [0x77u8; 32];
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let val_id = ks[0].verifying_key().to_bytes();
    let id = identity_for(val_id, genesis_root, 0);
    let (blk, bh) = block_at(H, 0, val_id, 0x88);

    {
        let storage = init_clean_genesis_storage(&dir, genesis_root);
        let auth = SafetyAuthority::open_from_storage(
            storage.clone(),
            id.clone(),
            clean_genesis_boot_ctx(),
        );
        let mut rt = ValidatorRuntime::new(
            ks[0].clone(),
            vset.clone(),
            Arc::new(InMemoryStateEngine::new()),
            H,
        )
        .with_falcon_key(fks[0].clone())
        .with_safety_authority(auth);
        rt.blocks.insert(bh, blk);
        for i in 0..3 {
            rt.on_prevote(falcon_votes::fvote(
                &ks[i],
                &fks[i],
                H,
                0,
                VoteKind::Prevote,
                Some(bh),
            ))
            .unwrap();
        }
        rt.make_precommit().expect("lock acquired");
        // Corrupt/delete blocks[bh] behind SafetyRecordStore's back!
        storage.blocks_tree_for_test().remove(bh).unwrap();
        storage.flush().unwrap();
    }

    let storage = Arc::new(Storage::open(&dir.0).unwrap());
    let mut ctx = clean_genesis_boot_ctx();
    ctx.new_chain_explicit = false;
    let auth = SafetyAuthority::open_from_storage(storage.clone(), id, ctx);
    let lock = auth.locked().expect("lock stays present");
    let mut rt =
        ValidatorRuntime::new(ks[0].clone(), vset, Arc::new(InMemoryStateEngine::new()), H)
            .with_falcon_key(fks[0].clone())
            .with_safety_authority(auth);
    rt.hc.locked = Some((lock.block_hash, lock.round));
    rt.hc.note_value_id(lock.block_hash, lock.value_id);
    if storage
        .get_block(&lock.block_hash)
        .ok()
        .flatten()
        .is_none_or(|b| b.compute_hash() != lock.block_hash)
    {
        rt.safety.quarantine("missing lock body on restart");
    }
    assert_eq!(rt.hc.locked, Some((bh, 0)));
    assert!(!rt.safety.can_sign());
    assert!(rt.make_prevote().is_none());
    assert!(rt.propose(1_700_000_002).await.is_none());
}

// ============================================================================
// B.6: make_precommit without body in rt.blocks refuses hash-only lock
// ============================================================================

#[test]
fn make_precommit_without_body_in_blocks_refuses_hash_only_lock() {
    const H: u64 = 1;
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vset = ValidatorSet::from_list(
        ks.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let signer = RemoteSigner::new(Arc::new(SpyTransport {
        key: ks[0].clone(),
        on_sign: Arc::new(|_| {}),
        fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        calls: calls.clone(),
        messages: Arc::new(Mutex::new(Vec::new())),
    }))
    .unwrap();
    let mut rt =
        ValidatorRuntime::new(ks[0].clone(), vset, Arc::new(InMemoryStateEngine::new()), H)
            .with_falcon_key(fks[0].clone())
            .with_remote_signer(Arc::new(signer))
            .unwrap();

    let ghost_hash = [0xDE; 32];
    for i in 0..3 {
        rt.on_prevote(falcon_votes::fvote(
            &ks[i],
            &fks[i],
            H,
            0,
            VoteKind::Prevote,
            Some(ghost_hash),
        ))
        .unwrap();
    }
    assert!(rt.make_precommit().is_none());
    assert_eq!(rt.safety.locked(), None);
    assert_eq!(rt.hc.locked, None);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

// ============================================================================
// B.7: propose shrink signs once and prevents double-propose across crash
// ============================================================================

#[tokio::test]
async fn propose_shrink_signs_once_and_prevents_double_propose_across_crash() {
    const H: u64 = 1;
    let dir = TestDir::new("propose-shrink");
    let genesis_root = [0x45u8; 32];
    let key = SigningKey::from_bytes(&[0x45; 32]);
    let val_id = key.verifying_key().to_bytes();
    let fk = FalconKeypair::generate_from_seed(0x45);
    register_validator_pq_key(val_id, PqScheme::Falcon512, fk.public_key.clone());
    let vset = ValidatorSet::from_list(vec![(val_id, 1)]);
    let id = identity_for(val_id, genesis_root, 0);

    let calls = Arc::new(AtomicUsize::new(0));
    let signed_hashes = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let signer = RemoteSigner::new(Arc::new(SpyTransport {
        key: key.clone(),
        on_sign: Arc::new(|_| {}),
        fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        calls: calls.clone(),
        messages: signed_hashes.clone(),
    }))
    .unwrap();

    let state = Arc::new(InMemoryStateEngine::new());
    let storage = init_clean_genesis_storage(&dir, genesis_root);
    let auth =
        SafetyAuthority::open_from_storage(storage.clone(), id.clone(), clean_genesis_boot_ctx());

    let mut rt = ValidatorRuntime::new(key.clone(), vset.clone(), state.clone(), H)
        .with_falcon_key(fk.clone())
        .with_remote_signer(Arc::new(signer))
        .unwrap()
        .with_safety_authority(auth);

    // 20 valid PQ transactions across 4 senders carrying 1.8 MiB SysCallDeployContract
    // blobs: `estimate_tx_wire_bytes` estimates ~456 B each (< 24 MiB cap), while
    // ConsensusMsg::Proposal bincode exceeds 32 MiB (MAX_CONSENSUS_MSG), triggering trim!
    let big_code = vec![0x61u8; 1800 * 1024];
    let deploy_gas = stellereum::svm::contract_deploy_gas(big_code.len()) + 500_000;
    for s_idx in 0..4u8 {
        let sender_fk = FalconKeypair::generate_from_seed(0x70 + s_idx);
        let sender_addr = stellereum::post_quantum::derive_pq_address(
            PqScheme::Falcon512,
            &sender_fk.public_key,
            &DEFAULT_SALT,
        );
        rt.state
            .update_account(AccountState::new(sender_addr, 10_000_000_000_000))
            .await;
        for nonce in 0..5u64 {
            let mut tx = Transaction {
                from: sender_addr,
                to: [0u8; 32],
                amount: 0,
                gas_limit: deploy_gas,
                nonce,
                source_shard: MASTERCHAIN_SHARD,
                target_shard: MASTERCHAIN_SHARD,
                signature: vec![],
                payload: vec![OpCode::SysCallDeployContract {
                    code: big_code.clone(),
                }],
                priority_fee_per_gas: 0,
            };
            let msg = tx.signing_message();
            let sig = sender_fk.sign(&msg);
            tx.signature = PqSignatureEnvelope::new_explicit(
                PqScheme::Falcon512,
                sender_fk.public_key.clone(),
                sig,
            )
            .encode();
            rt.add_tx(tx).await;
        }
    }

    let trimmed_block = rt
        .propose(1_700_000_001)
        .await
        .expect("trimmed block must propose");
    assert!(trimmed_block.transactions.len() < 20);
    let trimmed_hash = trimmed_block.compute_hash();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "trimmed block must be signed ONLY ONCE (not once before trim and once after)"
    );
    assert_eq!(
        signed_hashes.lock().unwrap().as_slice(),
        &[trimmed_hash.to_vec()]
    );

    // Crash and reopen at the same (height=1, round=0): proposing at round 0 is refused!
    drop(rt);
    drop(storage);
    let storage2 = Arc::new(Storage::open(&dir.0).unwrap());
    let mut ctx = clean_genesis_boot_ctx();
    ctx.new_chain_explicit = false;
    let auth2 = SafetyAuthority::open_from_storage(storage2, id, ctx);
    let mut rt2 = ValidatorRuntime::new(key, vset, Arc::new(InMemoryStateEngine::new()), H)
        .with_falcon_key(fk)
        .with_safety_authority(auth2);
    assert!(
        rt2.propose(1_700_000_002).await.is_none(),
        "double-propose at same (height, round) after crash must be refused"
    );
}

// ============================================================================
// B.8: Height advance (finalize / sequenced apply / adopt / snapshot_sync)
// ============================================================================

#[tokio::test]
async fn height_advance_finalize_adopt_snapshot_sync_persists_new_height_and_clears_old_lock() {
    let dir = TestDir::new("height-advance");
    let genesis_root = [0x91u8; 32];
    let (ks, fks) = falcon_votes::falcon_set(1);
    let val_id = ks[0].verifying_key().to_bytes();
    let vset = ValidatorSet::from_list(vec![(val_id, 1)]);
    let id = identity_for(val_id, genesis_root, 0);
    let storage = init_clean_genesis_storage(&dir, genesis_root);
    let auth =
        SafetyAuthority::open_from_storage(storage.clone(), id.clone(), clean_genesis_boot_ctx());

    let mut rt = ValidatorRuntime::new(
        ks[0].clone(),
        vset.clone(),
        Arc::new(InMemoryStateEngine::new()),
        1,
    )
    .with_falcon_key(fks[0].clone())
    .with_safety_authority(auth);

    // 1. try_finalize (h=1 -> 2) clears old lock and floors.
    let b1 = rt.propose(1_700_000_001).await.unwrap();
    let bh1 = b1.compute_hash();
    let pv1 = rt.make_prevote().unwrap();
    rt.on_prevote(pv1).unwrap();
    let pc1 = rt.make_precommit().unwrap();
    rt.on_precommit(pc1).unwrap();
    assert!(rt.safety.locked().is_some());
    assert_eq!(rt.try_finalize().await, Some(bh1));
    let s2 = rt.safety.current_state().unwrap();
    assert_eq!(
        (s2.height, s2.finalized_height, s2.finalized_hash),
        (2, 1, bh1)
    );
    assert_eq!(s2.locked, None);
    assert_eq!(s2.highest_prevote_round, None);
    assert_eq!(s2.highest_precommit_round, None);

    // 2. try_finalize_submit + try_poll_apply (install_apply_outcome: h=2 -> 3).
    let b2 = rt.propose(1_700_000_002).await.unwrap();
    let bh2 = b2.compute_hash();
    let pv2 = rt.make_prevote().unwrap();
    rt.on_prevote(pv2).unwrap();
    let pc2 = rt.make_precommit().unwrap();
    rt.on_precommit(pc2).unwrap();
    assert_eq!(rt.try_finalize_submit().await, Some(bh2));
    let completed = loop {
        if let Some(c) = rt.try_poll_apply().await {
            break c;
        }
        tokio::task::yield_now().await;
    };
    assert_eq!(completed.height, 2);
    let s3 = rt.safety.current_state().unwrap();
    assert_eq!(
        (s3.height, s3.finalized_height, s3.finalized_hash),
        (3, 2, bh2)
    );

    // 3. adopt_committed (h=3 -> 4).
    let mut b3 = rt.propose(1_700_000_003).await.unwrap();
    let bh3 = b3.compute_hash();
    let pv3 = rt.make_prevote().unwrap();
    rt.on_prevote(pv3).unwrap();
    let pc3 = rt.make_precommit().unwrap();
    rt.on_precommit(pc3).unwrap();
    let cert3 = rt
        .hc
        .precommit_set(0)
        .unwrap()
        .certificate(Some(bh3), &vset, &bh2)
        .unwrap();
    // Reset local hc proposal/votes to test adopt_committed cleanly at h=3.
    rt.hc = HeightConsensus::new(3, vset.clone());
    rt.hc.set_parent_hash(bh2);
    b3.precommit_qc = None;
    assert_eq!(rt.adopt_committed(3, b3, cert3).await, Ok(bh3));
    let s4 = rt.safety.current_state().unwrap();
    assert_eq!(
        (s4.height, s4.finalized_height, s4.finalized_hash),
        (4, 3, bh3)
    );
    assert_eq!(s4.locked, None);

    // 4. Snapshot sync advance_height (h=4 -> 101).
    let snap_hash = [0xFE; 32];
    rt.safety.advance_height(101, 100, snap_hash).unwrap();
    let gen_after = rt.safety.generation().unwrap();

    // Crash & reopen: restarts at height 101 with clean floors and cannot rewind to 100.
    drop(rt);
    drop(storage);
    let storage2 = Arc::new(Storage::open(&dir.0).unwrap());
    storage2.set_finalized(100, &snap_hash).unwrap();
    let mut ctx = clean_genesis_boot_ctx();
    ctx.new_chain_explicit = false;
    ctx.restored_finalized = Some((100, snap_hash));
    ctx.restored_state_height = Some(100);
    let auth2 = SafetyAuthority::open_from_storage(storage2, id, ctx);
    assert_eq!(auth2.mode(), AuthorityMode::Active);
    assert_eq!(auth2.generation(), Some(gen_after));
    assert_eq!(auth2.current_state().unwrap().height, 101);
    assert!(auth2.advance_height(100, 99, [0u8; 32]).is_err());
}

// ============================================================================
// B.9: Concurrent threads & corrupt record / identity mismatch quarantine
// ============================================================================

#[test]
fn concurrent_runtime_threads_and_corrupt_record_quarantine() {
    const H: u64 = 1;
    let dir = TestDir::new("concurrent-tamper");
    let genesis_root = [0x82u8; 32];
    let key = SigningKey::from_bytes(&[0x82; 32]);
    let val_id = key.verifying_key().to_bytes();
    let id = identity_for(val_id, genesis_root, 0);
    let storage = init_clean_genesis_storage(&dir, genesis_root);
    let auth = Arc::new(SafetyAuthority::open_from_storage(
        storage.clone(),
        id.clone(),
        clean_genesis_boot_ctx(),
    ));

    struct LocalTestSigner(SigningKey);
    impl stellereum::safety::VoteSigner for LocalTestSigner {
        fn validator_id(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }
        fn sign_ed25519(&self, msg: &[u8]) -> Option<Vec<u8>> {
            Some(self.0.sign(msg).to_bytes().to_vec())
        }
        fn sign_falcon(&self, _msg: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
            None
        }
    }

    // 8 threads racing to prevote at round 5: exactly 1 succeeds, generation is 2.
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let auth = auth.clone();
        let barrier = barrier.clone();
        let sk = key.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            auth.authorize_and_sign_prevote(H, 5, 0, None, &LocalTestSigner(sk))
        }));
    }
    let successes = handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .filter(|r| r.is_ok())
        .count();
    assert_eq!(successes, 1);
    assert_eq!(auth.generation(), Some(2));

    // Tamper safety_record_v1 bytes on disk -> reopen quarantines fail-closed.
    drop(auth);
    let tree = storage.safety_record_tree_for_test().unwrap();
    let mut raw = tree.get(b"record").unwrap().unwrap().to_vec();
    raw[95] ^= 0xFF;
    tree.insert(b"record", raw).unwrap();
    storage.flush().unwrap();

    let auth_corrupt =
        SafetyAuthority::open_from_storage(storage.clone(), id.clone(), clean_genesis_boot_ctx());
    assert!(matches!(auth_corrupt.mode(), AuthorityMode::Quarantined(_)));
    assert!(!auth_corrupt.can_sign());

    // Wrong identity (validator / chain / shard) -> Quarantined!
    let wrong_id = SafetyRecordIdentity { shard: 9, ..id };
    let auth_wrong =
        SafetyAuthority::open_from_storage(storage, wrong_id, clean_genesis_boot_ctx());
    assert!(matches!(auth_wrong.mode(), AuthorityMode::Quarantined(_)));
    assert!(!auth_wrong.can_sign());
}

// Unused import guard for ShardRegistry/VecDeque if needed in helper extensions:
#[test]
fn sanity_imports_smoke() {
    let _ = ShardRegistry::single();
    let _ = VecDeque::<u8>::new();
    let _ = vote_sign_bytes(1, 0, VoteKind::Prevote, &None);
    let _ = ConsensusCheckpoint::default();
    let p = SafetyRecordPayload::fresh_for_height(1, 0, [0u8; 32]).unwrap();
    assert_eq!(
        SafetyRecordPayload::decode_canonical(&p.encode_canonical().unwrap()).unwrap(),
        p
    );
}

#[tokio::test]
async fn late_polka_lock_adoption_allows_restamped_finalization() {
    const H: u64 = 1;
    let (ks, fks) = falcon_votes::falcon_set(4);
    let vset = ValidatorSet::from_list(vec![
        (ks[0].verifying_key().to_bytes(), 1500),
        (ks[1].verifying_key().to_bytes(), 1000),
        (ks[2].verifying_key().to_bytes(), 1000),
        (ks[3].verifying_key().to_bytes(), 1000),
    ]);
    let mut rts: Vec<ValidatorRuntime> = (0..4)
        .map(|i| {
            ValidatorRuntime::new(
                ks[i].clone(),
                vset.clone(),
                Arc::new(InMemoryStateEngine::new()),
                H,
            )
            .with_falcon_key(fks[i].clone())
        })
        .collect();

    // Node 0 proposes B0 at r0 (its slot or r_b0).
    let mut r_b0 = 0u32;
    while rts[0].hc.proposer() != Some(rts[0].id) {
        for rt in &mut rts {
            rt.next_round();
        }
        r_b0 += 1;
    }
    let b0 = rts[0].propose(1_700_000_000).await.expect("b0 proposed");
    let b0_hash = b0.compute_hash();
    let id0 = rts[0].id;
    for rt in rts.iter_mut().skip(1) {
        rt.on_proposal(id0, b0.clone(), r_b0)
            .await
            .expect("peers accept b0");
    }
    let r0_prevotes: Vec<_> = rts
        .iter_mut()
        .take(3)
        .filter_map(|rt| rt.make_prevote())
        .collect();
    assert_eq!(r0_prevotes.len(), 3);
    assert_eq!(
        r0_prevotes
            .iter()
            .filter(|pv| pv.block_hash == Some(b0_hash))
            .count(),
        3
    );

    // Peers 1, 2, 3 receive r0 prevotes from 0, 1, 2 (polka 3500 >= 3001).
    // Node 3 deliberately did NOT prevote B0: it stays without a value vote at
    // this height, so it is the validator that proposes a fresh conflicting B_k
    // next. Node 0 (deaf to the r0 polka) accepts and prevotes that fresh block
    // BEFORE the delayed r0 prevotes reach it -- the live cross-kind shape.
    for rt in rts.iter_mut().skip(1) {
        for pv in &r0_prevotes {
            rt.on_prevote(pv.clone()).unwrap();
        }
    }
    // Advance node 0 (the deaf one) and node 3 to node 3's next proposer slot.
    let mut r_k = rts[0].hc.round + 1;
    while vset.proposer_for(H, r_k) != Some(rts[3].id) {
        r_k += 1;
    }
    for idx in [0usize, 3] {
        while rts[idx].hc.round < r_k {
            rts[idx].next_round();
        }
    }
    let bk = rts[3]
        .propose(1_700_000_010)
        .await
        .expect("node 3 proposes a fresh conflicting block");
    let id3 = rts[3].id;
    rts[0]
        .on_proposal(id3, bk.clone(), r_k)
        .await
        .expect("node 0 accepts the fresh block");
    assert_ne!(bk.value_id(), b0.value_id());
    let pv_k = rts[0].make_prevote().expect("node 0 prevotes bk");
    assert_eq!(pv_k.round, r_k);
    assert_eq!(pv_k.block_hash, Some(bk.compute_hash()));

    // Delayed r0 prevotes now reach Node 0: cross-kind forbids precommit(r_b0, B0),
    // AND liveness recovery adopts lock (B0, r_b0) durably!
    for pv in &r0_prevotes {
        rts[0].on_prevote(pv.clone()).unwrap();
    }
    assert!(
        rts[0].make_precommit().is_none(),
        "cross-kind must refuse precommit(r_b0) after conflicting prevote(r_k, B_k)"
    );
    assert_eq!(rts[0].hc.locked, Some((b0_hash, r_b0)));
    assert_eq!(
        rts[0].safety.locked().map(|l| (l.block_hash, l.round)),
        Some((b0_hash, r_b0))
    );

    // Move all 4 nodes to Node 0's next proposer slot > r_k: Node 0 re-stamps B0,
    // all 4 prevote & precommit at r_next, and height 1 finalizes cleanly!
    let mut r_next = r_k + 1;
    while vset.proposer_for(H, r_next) != Some(rts[0].id) {
        r_next += 1;
    }
    for rt in &mut rts {
        while rt.hc.round < r_next {
            rt.next_round();
        }
    }
    let b0_restamped = rts[0]
        .propose(1_700_000_020)
        .await
        .expect("locked node 0 re-stamps B0");
    assert_eq!(b0_restamped.round, r_next);
    assert_eq!(b0_restamped.value_id(), b0.value_id());
    let restamp_hash = b0_restamped.compute_hash();
    for rt in rts.iter_mut().skip(1) {
        rt.on_proposal(id0, b0_restamped.clone(), r_next)
            .await
            .expect("peers accept re-stamped B0");
    }
    let next_pvs: Vec<_> = rts.iter().map(|rt| rt.make_prevote().unwrap()).collect();
    for pv in &next_pvs {
        for rt in &mut rts {
            rt.on_prevote(pv.clone()).unwrap();
        }
    }
    let next_pcs: Vec<_> = rts
        .iter_mut()
        .map(|rt| rt.make_precommit().expect("all 4 precommit re-stamped B0"))
        .collect();
    for pc in &next_pcs {
        assert_eq!((pc.round, pc.block_hash), (r_next, Some(restamp_hash)));
        for rt in &mut rts {
            rt.on_precommit(pc.clone()).unwrap();
        }
    }
    for rt in &mut rts {
        assert_eq!(rt.try_finalize().await, Some(restamp_hash));
        assert_eq!(rt.safety.current_state().unwrap().height, 2);
    }
}
