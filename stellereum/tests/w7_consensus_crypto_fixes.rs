//! Wave 7 fail-before regression tests for confirmed Wave 6 findings.
//!
//! Covers every library-reachable finding in Wave 6:
//! - W6-A1-2: `restore_last_decision_from_finalized_block` degrades to
//!   `last_decision = None` on missing/forged QC, so `restored_finalized_qc_verified`
//!   must stay `false` and `SafetyAuthority` must quarantine when
//!   `restored_fh > safety.finalized_height`.
//! - W6-A1-3 (a)-(d): `POST /v2/set_lock` persistence from `RemotePqSigner` to
//!   `PqSignerService`, Precommit updating `locked_round`/`locked_value_id`,
//!   `last_non_nil_prevote` preventing `Prevote(r, None)` from erasing cross-kind
//!   equivocation history (with legacy bincode compat), and `PqSignerService`
//!   anti-spoof / lock enforcement over HTTP.
//! - W6-A1-5: `https_only(!is_loopback_base_url(&url))` on v1 `HttpSignerTransport`
//!   and `remote_signer_from_config`.
//! - W6-A1-6: `prepare_decided_block` (`try_finalize`) does not mutate
//!   `hc.step = Step::Commit` when the decided block body is absent.
//! - W6-A7-5: `LightHeader::verify_validator_quorum` never falls through to
//!   classical Ed25519 when a validator has a registered Falcon-512 key, even
//!   when pure-PQ enforcement is off.
//! - W6-A7-8: `pin_falcon_pubkey` protects validator consensus keys from
//!   eviction by verified tx traffic.
//! - W6-A7-6: `MevKemRegistry` validates ML-KEM-768 encapsulation keys via
//!   `ml_kem::EncapsulationKey768::new`.
//!
//! Binary-crate driver tests (W6-A1-1 UTF-8 truncation in `adopt.rs`, W6-A1-2
//! `finalize_restore_qc_verified` in `consensus_driver/mod.rs`, and W6-A2-4
//! write-ahead ordering in `adopt.rs`) live in `#[cfg(test)]` modules inside
//! those driver files.

use std::net::TcpListener;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use stellereum::consensus::{
    clear_validator_pq_keys_for_tests, register_validator_pq_key, sync_committed_pq_registry,
    FalconKeypair, QuorumCertificate, Step, ValidatorSet, Vote, VoteKind,
};
use stellereum::light_client::LightHeader;
use stellereum::mev_epoch::pq_kem_ek_from_seed;
use stellereum::mev_kem_registry::{MevKemRegistry, MevKemRegistryError, MEV_KEM_EK_LEN};
use stellereum::post_quantum::{
    pin_falcon_pubkey, set_pure_pq_override, verify_pq_signature, PqScheme,
};
use stellereum::pq_registry::PqRegistry;
use stellereum::remote_signer::{
    remote_signer_from_config, serve_v2_http_connection_with_timeout, ConsensusSafetyGuard,
    ConsensusSafetyState, ConsensusSignRequest, HttpPqSignerTransport, HttpSignerTransport,
    LocalPqSigner, PqSigner, PqSignerService, PqSignerTransport, RemotePqSigner, SignRequestV2,
    SignedProposalStamp, SignedVoteStamp, SignerError, SignerTransport,
};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::safety::{AuthorityMode, SafetyAuthority, SafetyBootContext};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{SafetyRecordIdentity, Storage};

static GLOBAL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "stell_w7_{tag}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn vote_req(
    height: u64,
    round: u32,
    kind: VoteKind,
    block_hash: Option<[u8; 32]>,
) -> ConsensusSignRequest {
    ConsensusSignRequest::Vote {
        chain_id: 5757,
        shard_id: 0,
        height,
        round,
        kind,
        block_hash,
    }
}

fn spawn_v2_service(
    service: Arc<PqSignerService>,
    max_connections: usize,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming().take(max_connections).flatten() {
            serve_v2_http_connection_with_timeout(
                &service,
                stream,
                std::time::Duration::from_secs(2),
            );
        }
    });
    (format!("http://{addr}"), handle)
}

// ---------------------------------------------------------------------------
// W6-A1-2: degraded restore must NOT set restored_finalized_qc_verified = true
// ---------------------------------------------------------------------------

#[test]
fn w6_a1_2_degraded_restore_keeps_last_decision_none_and_quarantines_safety() {
    let sk = SigningKey::from_bytes(&[0x12u8; 32]);
    let vid = sk.verifying_key().to_bytes();
    let vset = ValidatorSet::from_list(vec![(vid, 10)]);
    let engine = Arc::new(InMemoryStateEngine::new());
    let mut rt = ValidatorRuntime::new(sk, vset, engine, 0);

    let mut b1 = Block {
        height: 1,
        prev_hash: [0u8; 32],
        proposer: vid,
        timestamp: 1_700_000_001,
        precommit_qc: None,
        ..Default::default()
    };
    let bh1 = b1.compute_hash();
    // Forged/empty QC -> restore degrades to Ok(()) with last_decision == None.
    b1.precommit_qc = Some(QuorumCertificate {
        shard_id: 0,
        height: 1,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh1),
        signatures: Vec::new(),
    });
    rt.finalized.push((1, bh1));
    rt.hc.height = 2;

    rt.restore_last_decision_from_finalized_block(&b1)
        .expect("degrades cleanly instead of freezing");
    assert!(
        rt.last_decision.is_none(),
        "degraded restore must leave last_decision=None"
    );
    let restored_finalized_qc_verified = rt.last_decision.as_ref().is_some_and(|(h, _, _)| *h == 1);
    assert!(!restored_finalized_qc_verified);

    let dir = temp_dir("a1_2");
    let storage = Arc::new(Storage::open(&dir).expect("open storage"));
    let identity = SafetyRecordIdentity {
        validator: vid,
        chain: [0x51u8; 32],
        shard: MASTERCHAIN_SHARD,
    };
    let auth0 = SafetyAuthority::open_from_storage(
        storage.clone(),
        identity.clone(),
        SafetyBootContext {
            is_validator: true,
            is_observer_env: false,
            new_chain_explicit: true,
            restored_finalized: None,
            restored_state_height: Some(0),
            restored_finalized_qc_verified: true,
            legacy_checkpoint: None,
            legacy_watermark: None,
        },
    );
    assert_eq!(auth0.mode(), AuthorityMode::Active);
    drop(auth0);

    let auth1 = SafetyAuthority::open_from_storage(
        storage.clone(),
        identity,
        SafetyBootContext {
            is_validator: true,
            is_observer_env: false,
            new_chain_explicit: false,
            restored_finalized: Some((1, bh1)),
            restored_state_height: Some(1),
            restored_finalized_qc_verified,
            legacy_checkpoint: None,
            legacy_watermark: None,
        },
    );
    assert!(
        matches!(auth1.mode(), AuthorityMode::Quarantined(_)),
        "must quarantine when restored_fh > safety.finalized_height without a verified QC"
    );
    drop(auth1);
    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// W6-A1-3 (a)-(d): RemotePqSigner /v2/set_lock, Precommit lock, nil prevote,
// and PqSignerService enforcement
// ---------------------------------------------------------------------------

#[test]
fn w6_a1_3_a_d_remote_pq_set_lock_persists_on_service_and_blocks_bypass() {
    let dir = temp_dir("a1_3_set_lock");
    let storage = Arc::new(Storage::open(&dir).expect("open storage"));
    let kp = FalconKeypair::generate_from_seed_bytes(&[0x61u8; 32]);
    let pk: [u8; 897] = kp.public_key().try_into().expect("897B pk");
    let vid = kp.validator_id();
    let identity = SafetyRecordIdentity {
        validator: vid,
        chain: [0x22u8; 32],
        shard: 0,
    };

    let guard = ConsensusSafetyGuard::from_durable(
        storage
            .safety_record_store(identity.clone())
            .expect("safety store"),
        true,
    )
    .expect("init durable guard");
    let svc_signer = LocalPqSigner::with_safety_guard(kp, vid, guard).expect("service signer");
    let service = Arc::new(PqSignerService::new(svc_signer).with_bearer_token("w7-tok"));
    // 1) GET /v2/public_key
    // 2) POST /v2/set_lock (from remote.set_consensus_lock)
    // 3) POST /v2/sign (direct attacker attempt omitting value_id -> 409)
    // 4) POST /v2/sign (direct attacker attempt with nil vote carrying value_id -> 400)
    // 5) POST /v2/sign (valid locked value -> 200)
    let (base_url, handle) = spawn_v2_service(service.clone(), 5);

    let transport =
        Arc::new(HttpPqSignerTransport::new(base_url.clone()).with_bearer_token("w7-tok"));
    let remote = RemotePqSigner::new(transport, vid, Some(&pk)).expect("pin key");

    let locked_vid = [0xAAu8; 32];
    remote
        .set_consensus_lock(10, 2, locked_vid)
        .expect("POST /v2/set_lock succeeds");

    // Verify service persisted the lock durably into SafetyRecordStore.
    let svc_snap = service
        .signer()
        .safety_guard()
        .state_snapshot()
        .expect("service safety snapshot");
    assert_eq!(svc_snap.height, 10);
    assert_eq!(svc_snap.locked_round, Some(2));
    assert_eq!(svc_snap.locked_value_id, Some(locked_vid));

    // Even a rogue client bypassing RemotePqSigner's local guard and hitting
    // PqSignerService directly over HTTP is refused by the service's persisted lock!
    let attacker_transport = HttpPqSignerTransport::new(base_url).with_bearer_token("w7-tok");
    let rogue_no_vid = SignRequestV2::from_consensus(
        vid,
        vote_req(10, 3, VoteKind::Prevote, Some([0xBBu8; 32])),
        None,
    );
    assert_eq!(
        attacker_transport.sign_v2(&rogue_no_vid).err(),
        Some(SignerError::Transport(
            stellereum::remote_signer::TransportErrorKind::Rejected { status: 409 }
        )),
        "service must enforce persisted lock and reject omitted value_id"
    );

    // W6-A1-3 (d): nil vote carrying spurious value_id is rejected (400).
    let rogue_nil_with_vid = SignRequestV2::from_consensus(
        vid,
        vote_req(10, 3, VoteKind::Prevote, None),
        Some(locked_vid),
    );
    assert_eq!(
        attacker_transport.sign_v2(&rogue_nil_with_vid).err(),
        Some(SignerError::Transport(
            stellereum::remote_signer::TransportErrorKind::Rejected { status: 400 }
        )),
        "service must reject nil vote carrying spurious value_id"
    );

    // Valid vote for the locked value_id succeeds.
    let valid_sig = remote
        .sign_consensus_with_value_id(
            &vote_req(10, 3, VoteKind::Prevote, Some([0xCCu8; 32])),
            Some(locked_vid),
        )
        .expect("locked value vote succeeds");
    assert!(verify_pq_signature(
        PqScheme::Falcon512,
        &pk,
        &vote_req(10, 3, VoteKind::Prevote, Some([0xCCu8; 32])).canonical_signing_bytes(),
        &valid_sig
    ));

    handle.join().expect("server thread");

    // Reopen durable SafetyRecordStore and verify lock survived restart!
    drop(service);
    let reopened = ConsensusSafetyGuard::from_durable(
        storage.safety_record_store(identity).expect("reopen"),
        false,
    )
    .expect("reopen durable guard");
    let reopened_snap = reopened.state_snapshot().expect("reopened snapshot");
    assert_eq!(reopened_snap.height, 10);
    assert_eq!(reopened_snap.locked_round, Some(2));
    assert_eq!(reopened_snap.locked_value_id, Some(locked_vid));

    drop(reopened);
    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn w6_a1_3_b_precommit_updates_locked_round_and_value_id() {
    let val_a = [0x11u8; 32];
    let val_b = [0x22u8; 32];
    let s0 = ConsensusSafetyState {
        height: 7,
        ..Default::default()
    };
    let s1 = s0
        .check_and_advance(
            &vote_req(7, 2, VoteKind::Precommit, Some(val_a)),
            Some(val_a),
        )
        .expect("precommit succeeds");
    assert_eq!(s1.locked_round, Some(2));
    assert_eq!(s1.locked_value_id, Some(val_a));

    // Subsequent non-nil vote for a different value (or missing value_id) MUST fail!
    assert_eq!(
        s1.check_and_advance(&vote_req(7, 3, VoteKind::Prevote, Some(val_b)), Some(val_b)),
        Err(SignerError::SafetyViolation)
    );
    assert_eq!(
        s1.check_and_advance(&vote_req(7, 3, VoteKind::Prevote, Some(val_b)), None),
        Err(SignerError::SafetyViolation)
    );
    // Same locked value_id (even re-stamped block hash) stays permitted.
    assert!(s1
        .check_and_advance(&vote_req(7, 3, VoteKind::Prevote, Some(val_b)), Some(val_a))
        .is_ok());
}

#[test]
fn w6_a1_3_c_nil_prevote_does_not_erase_earlier_non_nil_prevote_target() {
    let val_a = [0x31u8; 32];
    let val_b = [0x42u8; 32];
    let s0 = ConsensusSafetyState {
        height: 9,
        ..Default::default()
    };
    // Round 3: non-nil prevote for A.
    let s1 = s0
        .check_and_advance(&vote_req(9, 3, VoteKind::Prevote, Some(val_a)), Some(val_a))
        .expect("non-nil prevote r=3");
    // Round 5: nil prevote (must NOT erase A from round 3 for cross-kind check).
    let s2 = s1
        .check_and_advance(&vote_req(9, 5, VoteKind::Prevote, None), None)
        .expect("nil prevote r=5");
    assert_eq!(
        s2.last_prevote.map(|s| (s.round, s.target)),
        Some((5, None))
    );
    assert_eq!(
        s2.last_non_nil_prevote.map(|s| (s.round, s.target)),
        Some((3, Some(val_a)))
    );

    // Cross-kind equivocation: Precommit(r=3, B != A) MUST be refused!
    assert_eq!(
        s2.check_and_advance(
            &vote_req(9, 3, VoteKind::Precommit, Some(val_b)),
            Some(val_b)
        ),
        Err(SignerError::SafetyViolation),
        "Prevote(r=5, None) must never erase Prevote(r=3, A) for cross-kind equivocation"
    );
    // Precommit(r=3, A) matches the earlier non-nil prevote and succeeds.
    assert!(s2
        .check_and_advance(
            &vote_req(9, 3, VoteKind::Precommit, Some(val_a)),
            Some(val_a)
        )
        .is_ok());
}

#[test]
fn w6_a1_3_c_legacy_v1_safety_state_bincode_still_decodes() {
    #[derive(Serialize)]
    struct LegacySafetyV1 {
        height: u64,
        locked_round: Option<u32>,
        locked_value_id: Option<[u8; 32]>,
        last_prevote: Option<SignedVoteStamp>,
        last_precommit: Option<SignedVoteStamp>,
        last_proposal: Option<SignedProposalStamp>,
    }
    let legacy = LegacySafetyV1 {
        height: 42,
        locked_round: Some(3),
        locked_value_id: Some([0x7Au8; 32]),
        last_prevote: Some(SignedVoteStamp {
            height: 42,
            round: 4,
            target: Some([0x11u8; 32]),
        }),
        last_precommit: None,
        last_proposal: None,
    };
    let mut payload = b"SQV2".to_vec();
    payload.extend_from_slice(&bincode::serialize(&legacy).expect("serialize legacy"));

    let dir = temp_dir("a1_3_legacy_bincode");
    let storage = Storage::open(&dir).expect("open storage");
    let identity = SafetyRecordIdentity {
        validator: [0x11u8; 32],
        chain: [0x22u8; 32],
        shard: 0,
    };
    let store = storage
        .safety_record_store(identity.clone())
        .expect("safety store");
    store.persist(None, payload).expect("persist legacy v1");
    drop(store);

    let guard = ConsensusSafetyGuard::from_durable(
        storage.safety_record_store(identity).expect("reopen"),
        false,
    )
    .expect("legacy v1 payload must decode without quarantining");
    let snap = guard.state_snapshot().expect("snapshot");
    assert_eq!(snap.height, 42);
    assert_eq!(snap.locked_round, Some(3));
    assert_eq!(snap.locked_value_id, Some([0x7Au8; 32]));
    assert_eq!(snap.last_non_nil_prevote, snap.last_prevote);

    drop(guard);
    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// W6-A1-5: v1 HttpSignerTransport enforces https_only on non-loopback URLs
// ---------------------------------------------------------------------------

#[test]
fn w6_a1_5_v1_http_signer_rejects_plain_http_on_non_loopback() {
    let t = HttpSignerTransport::new("http://signer.internal:8443");
    assert!(t.is_https_only());
    assert_eq!(
        t.public_key().err(),
        Some(SignerError::PlainHttpForbiddenOnNonLoopback)
    );
    assert_eq!(
        remote_signer_from_config(Some("http://signer.internal:8443".into()), None).err(),
        Some(SignerError::PlainHttpForbiddenOnNonLoopback)
    );

    let loopback = HttpSignerTransport::new("http://127.0.0.1:8443");
    assert!(!loopback.is_https_only());
}

// ---------------------------------------------------------------------------
// W6-A1-6: prepare_decided_block must not set Step::Commit on missing body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w6_a1_6_prepare_decided_block_does_not_mutate_step_when_body_missing() {
    let _guard = GLOBAL_LOCK.lock().await;
    let sk = SigningKey::from_bytes(&[0x71u8; 32]);
    let vid = sk.verifying_key().to_bytes();
    let fk = FalconKeypair::generate_from_seed(0x72);
    let vset = ValidatorSet::from_list(vec![(vid, 10)]);
    let engine = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&engine, &vset, 1_000_000).await;
    {
        let mut ledger = engine.staking_write().await;
        let mut pq_reg = engine.pq_registry_write().await;
        ledger
            .validator_pq_keys
            .insert(vid, (PqScheme::Falcon512, fk.public_key.clone()));
        let _ =
            pq_reg.adopt_legacy_key_at(vid, PqScheme::Falcon512, fk.public_key.clone(), 0, true);
        sync_committed_pq_registry(&pq_reg, true);
    }

    let mut prod = ValidatorRuntime::new(sk.clone(), vset.clone(), engine.clone(), 1)
        .with_falcon_key(fk.clone());
    prod.hc.set_parent_hash([0u8; 32]);
    let block = prod.propose(1_700_000_001).await.expect("propose h=1");
    let bh = block.compute_hash();

    let mut rt = ValidatorRuntime::new(sk.clone(), vset, engine, 1).with_falcon_key(fk.clone());
    rt.hc.set_parent_hash([0u8; 32]);
    // Feed prevote + precommit quorum for `bh` WITHOUT inserting `block` into `rt.blocks`!
    let pv = Vote::sign_with_falcon(&sk, &fk, 1, 0, VoteKind::Prevote, Some(bh));
    let pc = Vote::sign_with_falcon(&sk, &fk, 1, 0, VoteKind::Precommit, Some(bh));
    rt.hc.add_prevote(pv).expect("add_prevote");
    rt.hc.add_precommit(pc).expect("add_precommit");
    assert_eq!(rt.hc.step, Step::Propose);

    assert!(
        rt.try_finalize().await.is_none(),
        "must refuse to finalize without block body"
    );
    assert_ne!(
        rt.hc.step,
        Step::Commit,
        "hc.step must NOT advance to Step::Commit when proposal body is missing"
    );
    assert!(rt.hc.decided.is_none());
    assert!(rt.hc.precommit_qc.is_none());

    // Once the body arrives, finalization succeeds cleanly.
    rt.blocks.insert(bh, block);
    assert_eq!(rt.try_finalize().await, Some(bh));

    sync_committed_pq_registry(&PqRegistry::new(), true);
    clear_validator_pq_keys_for_tests();
}

// ---------------------------------------------------------------------------
// W6-A7-5: LightHeader::verify_validator_quorum never falls through to Ed25519
// ---------------------------------------------------------------------------

#[tokio::test]
async fn w6_a7_5_light_header_never_falls_through_to_ed25519_when_pq_key_registered() {
    let _guard = GLOBAL_LOCK.lock().await;
    set_pure_pq_override(Some(false));
    clear_validator_pq_keys_for_tests();
    sync_committed_pq_registry(&PqRegistry::new(), false);

    let sk = SigningKey::from_bytes(&[0x81u8; 32]);
    let val_id = sk.verifying_key().to_bytes();
    let fk = FalconKeypair::generate_from_seed(0x82);
    let validators = ValidatorSet::from_list(vec![(val_id, 10)]);
    register_validator_pq_key(val_id, PqScheme::Falcon512, fk.public_key().to_vec());

    let block_hash = [0x99u8; 32];
    // Valid classical Ed25519 signature over `block_hash` — must NOT be
    // accepted via fallthrough because `val_id` has a registered Falcon-512 key!
    let ed_sig = sk.sign(&block_hash).to_bytes().to_vec();
    let header = LightHeader {
        height: 1,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        block_hash,
        timestamp: 0,
        proposer: [0u8; 32],
        cert: QuorumCertificate {
            shard_id: 0,
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block_hash),
            signatures: Vec::new(),
        },
        signatures: vec![(val_id, ed_sig)],
        shard_id: 0,
        round: 0,
        body_commitment: None,
        mmr_epoch_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };

    assert!(
        header.verify_validator_quorum(&validators).is_err(),
        "registered PQ key must block Ed25519 fallthrough even when pure_pq=false"
    );

    // Real Falcon-512 signature succeeds.
    let mut good_header = header;
    good_header.signatures = vec![(val_id, fk.sign(&block_hash))];
    assert!(good_header.verify_validator_quorum(&validators).is_ok());

    clear_validator_pq_keys_for_tests();
    set_pure_pq_override(None);
}

// ---------------------------------------------------------------------------
// W6-A7-8: pin_falcon_pubkey survives note_falcon_pubkey_verified promotions
// ---------------------------------------------------------------------------

#[test]
fn w6_a7_8_explicit_pin_falcon_pubkey_survives_verified_tx_traffic() {
    let validator_fk = FalconKeypair::generate_from_seed(0x91);
    assert!(pin_falcon_pubkey(validator_fk.pubkey()));

    // Promote a set of tx keys via repeated successful verifications.
    for i in 0..16u8 {
        let tx_fk = FalconKeypair::generate_from_seed(0xA0u8.wrapping_add(i));
        let msg = b"tx-envelope";
        let sig = tx_fk.sign(msg);
        for _ in 0..3 {
            assert!(verify_pq_signature(
                PqScheme::Falcon512,
                tx_fk.pubkey(),
                msg,
                &sig
            ));
        }
    }

    let vmsg = b"validator-vote";
    let vsig = validator_fk.sign(vmsg);
    assert!(verify_pq_signature(
        PqScheme::Falcon512,
        validator_fk.pubkey(),
        vmsg,
        &vsig
    ));
}

// ---------------------------------------------------------------------------
// W6-A7-6: MevKemRegistry rejects malformed 1184-byte ML-KEM-768 keys
// ---------------------------------------------------------------------------

#[test]
fn w6_a7_6_mev_kem_registry_rejects_non_canonical_ml_kem_768_keys() {
    let mut reg = MevKemRegistry::new();
    let vid = [0xC1u8; 32];

    // 0xFF repeating gives 12-bit chunks 0xFFF = 4095 >= q (3329): invalid FIPS-203 ek.
    let bad_ek = vec![0xFFu8; MEV_KEM_EK_LEN];
    assert_eq!(
        reg.register(vid, bad_ek.clone(), 0, 0, true),
        Err(MevKemRegistryError::MalformedKey)
    );

    // Real ML-KEM-768 key generated from seed is accepted.
    let good_ek = pq_kem_ek_from_seed(&[0x55u8; 64]);
    assert!(reg.register(vid, good_ek, 0, 0, true).is_ok());

    // Malformed key is also refused on rotation announcement.
    assert_eq!(
        reg.announce_rotation(vid, bad_ek, 10, true),
        Err(MevKemRegistryError::MalformedKey)
    );
}
