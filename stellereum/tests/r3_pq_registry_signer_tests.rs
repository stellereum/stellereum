//! Ruleset v7 / R3-A tests for `pq_registry`, `remote_signer` v2 (Falcon-512),
//! and `chain_spec` `PQ_LIFECYCLE_ACTIVATION_HEIGHT`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use stellereum::chain_spec::{
    current_activation_schedule, ActivationStatus, PQ_LIFECYCLE_ACTIVATION_HEIGHT,
};
use stellereum::consensus::{consensus_chain_id, vote_sign_bytes_for_shard, ValidatorId, VoteKind};
use stellereum::post_quantum::{
    verify_pq_signature, FalconKeypair, PqScheme, FALCON512_PUBKEY_LEN, FALCON512_SIG_LEN,
};
use stellereum::pq_registry::{
    derive_validator_id, pq_lifecycle_active_at, pq_voting_key_pop_preimage,
    set_pq_lifecycle_activation_override, truncate_superseded_history, verify_voting_key_pop,
    PqRegistry, PqRegistryError, SupersededPqKey, PQ_EVIDENCE_RETENTION_HEIGHTS,
    PQ_KEY_HISTORY_LIMIT, PQ_KEY_HISTORY_MAX_COUNT, PQ_KEY_POP_DST, PQ_ROTATION_DELAY_HEIGHTS,
};
use stellereum::remote_signer::{
    is_loopback_base_url, serve_v2_http_connection, vote_sign_bytes_with_chain,
    ConsensusSafetyGuard, ConsensusSignRequest, HttpPqSignerTransport, LocalPqSigner, PqSigner,
    PqSignerService, PqSignerTransport, RemotePqSigner, RemotePublicKeyInfo, SignRequestV2,
    SignerError, SigningFailureKind, TransportErrorKind, FALCON_PUBLIC_KEY_LEN,
    FALCON_SIGNATURE_LEN,
};
use stellereum::storage::{SafetyRecordIdentity, Storage};

fn vid(n: u8) -> ValidatorId {
    [n; 32]
}

fn falcon_key(fill: u8) -> Vec<u8> {
    let mut k = vec![fill; FALCON512_PUBKEY_LEN];
    k[0] = 0x09;
    k
}

fn real_falcon(seed_byte: u8) -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[seed_byte; 32])
}

struct LifecycleOverrideReset;
impl Drop for LifecycleOverrideReset {
    fn drop(&mut self) {
        set_pq_lifecycle_activation_override(None);
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = PathBuf::from(format!("/tmp/opencode/r3_{tag}_{pid}_{n}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ============================================================================
// 1. PoP preimage, verify_voting_key_pop, derive_validator_id & chain_spec gate
// ============================================================================

#[test]
fn chain_spec_registers_pq_lifecycle_gate_at_u64_max() {
    let _reset = LifecycleOverrideReset;
    assert_eq!(PQ_LIFECYCLE_ACTIVATION_HEIGHT, u64::MAX);
    assert!(!pq_lifecycle_active_at(0));
    assert!(!pq_lifecycle_active_at(u64::MAX));

    let schedule = current_activation_schedule();
    let gate = schedule
        .gates
        .iter()
        .find(|g| g.name == "PQ_LIFECYCLE_ACTIVATION_HEIGHT")
        .expect("PQ_LIFECYCLE_ACTIVATION_HEIGHT must be registered in chain_spec");
    assert_eq!(gate.activation_height, u64::MAX);
    assert_eq!(gate.status, ActivationStatus::GatedOff);
    assert_eq!(
        schedule.is_active("PQ_LIFECYCLE_ACTIVATION_HEIGHT", 0),
        Some(false)
    );
    assert_eq!(
        schedule.is_active("PQ_LIFECYCLE_ACTIVATION_HEIGHT", u64::MAX),
        Some(false)
    );

    set_pq_lifecycle_activation_override(Some(500));
    assert!(!pq_lifecycle_active_at(499));
    assert!(pq_lifecycle_active_at(500));
    assert!(pq_lifecycle_active_at(501));
}

#[test]
fn pop_valid_falcon512_verifies_and_derive_validator_id_is_deterministic() {
    assert_eq!(PQ_KEY_POP_DST, b"STELL_PQ_KEY_POP_V1");

    let kp = real_falcon(0x11);
    let pk = kp.public_key();
    assert_eq!(pk.len(), FALCON512_PUBKEY_LEN);
    assert_eq!(pk[0], 0x09);

    let chain_id = 5757u64;
    let withdrawal = [0xAAu8; 32];
    let validator_id = derive_validator_id(chain_id, &withdrawal, pk);
    assert_eq!(
        validator_id,
        derive_validator_id(chain_id, &withdrawal, pk),
        "derive_validator_id must be deterministic"
    );
    assert_ne!(
        validator_id,
        derive_validator_id(chain_id + 1, &withdrawal, pk)
    );
    assert_ne!(
        validator_id,
        derive_validator_id(chain_id, &[0xBBu8; 32], pk)
    );

    let seq = 0u64;
    let preimage = pq_voting_key_pop_preimage(
        chain_id,
        &validator_id,
        &withdrawal,
        seq,
        PqScheme::Falcon512,
        pk,
    );
    assert!(preimage.starts_with(PQ_KEY_POP_DST));
    let pop_sig = kp.sign(&preimage);
    assert_eq!(pop_sig.len(), FALCON512_SIG_LEN);

    assert_eq!(
        verify_voting_key_pop(
            chain_id,
            &validator_id,
            &withdrawal,
            seq,
            PqScheme::Falcon512.id(),
            pk,
            &pop_sig,
        ),
        Ok(())
    );
}

#[test]
fn pop_refuses_tampered_inputs_wrong_key_bad_header_and_classical_schemes() {
    let kp = real_falcon(0x22);
    let other_kp = real_falcon(0x23);
    let pk = kp.public_key();
    let chain_id = 5757u64;
    let withdrawal = [0x33u8; 32];
    let validator_id = derive_validator_id(chain_id, &withdrawal, pk);
    let seq = 1u64;

    let preimage = pq_voting_key_pop_preimage(
        chain_id,
        &validator_id,
        &withdrawal,
        seq,
        PqScheme::Falcon512,
        pk,
    );
    let pop_sig = kp.sign(&preimage);

    // Wrong chain_id
    assert_eq!(
        verify_voting_key_pop(
            chain_id + 1,
            &validator_id,
            &withdrawal,
            seq,
            0x02,
            pk,
            &pop_sig,
        ),
        Err(PqRegistryError::InvalidPopSignature)
    );
    // Wrong rotation_seq
    assert_eq!(
        verify_voting_key_pop(
            chain_id,
            &validator_id,
            &withdrawal,
            seq + 1,
            0x02,
            pk,
            &pop_sig,
        ),
        Err(PqRegistryError::InvalidPopSignature)
    );
    // Wrong withdrawal_address
    assert_eq!(
        verify_voting_key_pop(
            chain_id,
            &validator_id,
            &[0x44u8; 32],
            seq,
            0x02,
            pk,
            &pop_sig,
        ),
        Err(PqRegistryError::InvalidPopSignature)
    );
    // Wrong validator_id
    assert_eq!(
        verify_voting_key_pop(
            chain_id,
            &[0x55u8; 32],
            &withdrawal,
            seq,
            0x02,
            pk,
            &pop_sig,
        ),
        Err(PqRegistryError::InvalidPopSignature)
    );
    // Signed by a different Falcon key (e.g. old voting key instead of new key)
    let wrong_sig = other_kp.sign(&preimage);
    assert_eq!(
        verify_voting_key_pop(
            chain_id,
            &validator_id,
            &withdrawal,
            seq,
            0x02,
            pk,
            &wrong_sig,
        ),
        Err(PqRegistryError::InvalidPopSignature)
    );

    // Classical & disabled schemes refused fail-closed: 0x01 (Ed25519), 0x03 (ML-DSA-44), 0x04 (Hybrid)
    for bad_scheme in [0x01u8, 0x03u8, 0x04u8, 0x99u8] {
        assert_eq!(
            verify_voting_key_pop(
                chain_id,
                &validator_id,
                &withdrawal,
                seq,
                bad_scheme,
                pk,
                &pop_sig,
            ),
            Err(PqRegistryError::DisabledScheme)
        );
    }

    // Wrong pubkey length
    assert_eq!(
        verify_voting_key_pop(
            chain_id,
            &validator_id,
            &withdrawal,
            seq,
            0x02,
            &pk[..FALCON512_PUBKEY_LEN - 1],
            &pop_sig,
        ),
        Err(PqRegistryError::OversizedKey)
    );

    // Missing canonical 0x09 Falcon-512 header byte
    let mut bad_header_pk = pk.to_vec();
    bad_header_pk[0] = 0x00;
    assert_eq!(
        verify_voting_key_pop(
            chain_id,
            &validator_id,
            &withdrawal,
            seq,
            0x02,
            &bad_header_pk,
            &pop_sig,
        ),
        Err(PqRegistryError::InvalidPubkeyHeader)
    );

    // Wrong signature length
    assert_eq!(
        verify_voting_key_pop(
            chain_id,
            &validator_id,
            &withdrawal,
            seq,
            0x02,
            pk,
            &pop_sig[..FALCON512_SIG_LEN - 1],
        ),
        Err(PqRegistryError::InvalidPopSignature)
    );
}

// ============================================================================
// 2. announce_rotation_seq, replay/overflow/SameKey/DuplicateKey & cancel_rotation
// ============================================================================

#[test]
fn announce_rotation_seq_enforces_replay_overflow_same_and_duplicate_key() {
    let mut reg = PqRegistry::new();
    let v1 = vid(1);
    let v2 = vid(2);
    let k1 = falcon_key(0x11);
    let k2 = falcon_key(0x22);
    let k3 = falcon_key(0x33);

    reg.register_with_seq(v1, PqScheme::Falcon512, k1.clone(), 0, 0, 0, true)
        .expect("v1 register");
    assert_eq!(reg.record_of(&v1).unwrap().next_seq, 1);

    // Duplicate pubkey across validators refused at register
    assert_eq!(
        reg.register_with_seq(v2, PqScheme::Falcon512, k1.clone(), 0, 0, 0, true),
        Err(PqRegistryError::DuplicateKey)
    );
    reg.register_with_seq(v2, PqScheme::Falcon512, k2.clone(), 0, 0, 0, true)
        .expect("v2 register");

    // Out-of-order / replayed rotation_seq refused
    assert_eq!(
        reg.announce_rotation_seq(v1, PqScheme::Falcon512, k3.clone(), 10, 0, true),
        Err(PqRegistryError::InvalidRotationSeq {
            expected: 1,
            got: 0
        })
    );
    assert_eq!(
        reg.announce_rotation_seq(v1, PqScheme::Falcon512, k3.clone(), 10, 2, true),
        Err(PqRegistryError::InvalidRotationSeq {
            expected: 1,
            got: 2
        })
    );

    // Own current key refused (SameKey)
    assert_eq!(
        reg.announce_rotation_seq(v1, PqScheme::Falcon512, k1.clone(), 10, 1, true),
        Err(PqRegistryError::SameKey)
    );

    // Another validator's current key refused (DuplicateKey)
    assert_eq!(
        reg.announce_rotation_seq(v1, PqScheme::Falcon512, k2.clone(), 10, 1, true),
        Err(PqRegistryError::DuplicateKey)
    );

    // Height arithmetic overflow refused (no saturating_add)
    assert_eq!(
        reg.announce_rotation_seq(v1, PqScheme::Falcon512, k3.clone(), u64::MAX - 5, 1, true),
        Err(PqRegistryError::ArithmeticOverflow)
    );
    assert_eq!(reg.record_of(&v1).unwrap().next_seq, 1);

    // Valid announce advances next_seq to 2
    reg.announce_rotation_seq(v1, PqScheme::Falcon512, k3.clone(), 100, 1, true)
        .expect("valid seq 1 announce");
    assert_eq!(reg.record_of(&v1).unwrap().next_seq, 2);

    // Another validator cannot claim v1's pending key (DuplicateKey)
    assert_eq!(
        reg.announce_rotation_seq(v2, PqScheme::Falcon512, k3, 100, 1, true),
        Err(PqRegistryError::DuplicateKey)
    );

    // Replaying seq=1 on v1 after pending fails with InvalidRotationSeq
    assert_eq!(
        reg.announce_rotation_seq(v1, PqScheme::Falcon512, falcon_key(0x44), 101, 1, true),
        Err(PqRegistryError::InvalidRotationSeq {
            expected: 2,
            got: 1
        })
    );
}

#[test]
fn cancel_rotation_allowed_only_before_effective_height_and_advances_seq() {
    let mut reg = PqRegistry::new();
    let v = vid(7);
    let k1 = falcon_key(0x71);
    let k2 = falcon_key(0x72);
    let k3 = falcon_key(0x73);

    reg.adopt_legacy_key(v, PqScheme::Falcon512, k1.clone(), true)
        .expect("adopt legacy");
    assert_eq!(reg.record_of(&v).unwrap().next_seq, 1);

    // Nothing pending -> NoPendingRotation
    assert_eq!(
        reg.cancel_rotation(v, 50, 1, true),
        Err(PqRegistryError::NoPendingRotation)
    );

    reg.announce_rotation_seq(v, PqScheme::Falcon512, k2, 100, 1, true)
        .expect("announce seq 1");
    let eff = 100 + PQ_ROTATION_DELAY_HEIGHTS;
    assert_eq!(reg.record_of(&v).unwrap().next_seq, 2);

    // Wrong seq -> InvalidRotationSeq
    assert_eq!(
        reg.cancel_rotation(v, eff - 1, 1, true),
        Err(PqRegistryError::InvalidRotationSeq {
            expected: 2,
            got: 1
        })
    );
    // At or after effective_height -> RotationAlreadyEffective (pending stays!)
    assert_eq!(
        reg.cancel_rotation(v, eff, 2, true),
        Err(PqRegistryError::RotationAlreadyEffective)
    );
    assert_eq!(
        reg.cancel_rotation(v, eff + 10, 2, true),
        Err(PqRegistryError::RotationAlreadyEffective)
    );
    assert!(reg.pending_of(&v).is_some());

    // Strictly before effective_height -> succeeds and advances next_seq to 3
    reg.cancel_rotation(v, eff - 1, 2, true)
        .expect("cancel before effective_height");
    assert!(reg.pending_of(&v).is_none());
    assert_eq!(reg.record_of(&v).unwrap().next_seq, 3);
    assert_eq!(
        reg.pq_key_at_height(&v, eff + 500),
        Some((PqScheme::Falcon512, k1))
    );

    // Next announce must use seq = 3
    reg.announce_rotation_seq(v, PqScheme::Falcon512, k3.clone(), eff - 1, 3, true)
        .expect("re-announce after cancel uses seq 3");
    assert_eq!(reg.record_of(&v).unwrap().next_seq, 4);
    assert_eq!(reg.pending_of(&v).unwrap().pubkey, k3);
}

// ============================================================================
// 3. 720,000-height evidence retention & 32-entry hard cap
// ============================================================================

#[test]
fn retention_720k_keeps_first_key_across_five_rotations_and_expires_past_window() {
    let _reset = LifecycleOverrideReset;
    set_pq_lifecycle_activation_override(Some(0));

    assert_eq!(PQ_EVIDENCE_RETENTION_HEIGHTS, 720_000);
    assert_eq!(PQ_KEY_HISTORY_MAX_COUNT, 32);

    let mut reg = PqRegistry::new();
    let v = vid(0x55);
    let key0 = falcon_key(0x10);
    reg.register(v, PqScheme::Falcon512, key0.clone(), 0, 0, true)
        .expect("register");

    // 5 rotations inside 720,000 heights: 0 -> 30k -> 60k -> 90k -> 120k -> 150k
    let mut seq = 1u64;
    let mut now = 0u64;
    for i in 1u8..=5 {
        let next_key = falcon_key(0x10 + i);
        reg.announce_rotation_seq(v, PqScheme::Falcon512, next_key, now, seq, true)
            .expect("announce");
        seq += 1;
        now += PQ_ROTATION_DELAY_HEIGHTS;
        reg.apply_rotation(v, now, true).expect("apply");
    }

    let hist = reg.history_of(&v).expect("history");
    assert_eq!(
        hist.len(),
        5,
        "all 5 superseded keys inside 720k must remain"
    );
    assert_eq!(hist[0].pubkey, key0);
    assert_eq!(hist[0].activated_at, 0);
    assert_eq!(hist[0].superseded_at, PQ_ROTATION_DELAY_HEIGHTS);

    // 1st key resolves at height 100 both via pq_key_at_height and within_retention
    assert_eq!(
        reg.pq_key_at_height(&v, 100),
        Some((PqScheme::Falcon512, key0.clone()))
    );
    assert_eq!(
        reg.pq_key_at_height_within_retention(&v, 100, now),
        Some((PqScheme::Falcon512, key0.clone()))
    );

    // Future height > now_height fails closed
    assert_eq!(
        reg.pq_key_at_height_within_retention(&v, now + 1, now),
        None
    );

    // Advance past 720,000 blocks from 30k..120k superseded_at (120,000 + 720,000 = 840,000)
    // so 30k..120k are pruned while 150k (840k - 150k = 690k < 720k) and 840k remain.
    let far_now = 90_000 + PQ_EVIDENCE_RETENTION_HEIGHTS;
    reg.announce_rotation_seq(v, PqScheme::Falcon512, falcon_key(0x99), far_now, seq, true)
        .expect("announce at far_now");
    let far_apply = far_now + PQ_ROTATION_DELAY_HEIGHTS;
    reg.apply_rotation(v, far_apply, true)
        .expect("apply at far_apply");

    let hist_after = reg.history_of(&v).expect("history after far prune");
    // Only the 2 newest entries (superseded at 150k and 780k) remain; 150k is kept
    // within 720k window (780k - 150k = 630k < 720k) while 30k..120k are pruned.
    assert_eq!(hist_after.len(), PQ_KEY_HISTORY_LIMIT);
    assert_eq!(reg.pq_key_at_height(&v, 100), None);
    assert_eq!(
        reg.pq_key_at_height_within_retention(&v, 100, far_apply),
        None
    );

    // An entry retained solely due to the PQ_KEY_HISTORY_LIMIT=2 floor STILL fails
    // pq_key_at_height_within_retention once now_height - superseded_at >= 720_000.
    let expired_check_now = 150_000 + PQ_EVIDENCE_RETENTION_HEIGHTS;
    assert_eq!(
        reg.pq_key_at_height_within_retention(&v, 140_000, expired_check_now),
        None
    );
}

#[test]
fn history_hard_cap_32_evicts_oldest_even_inside_retention_window() {
    let mut history: Vec<SupersededPqKey> = (0u64..40)
        .map(|i| SupersededPqKey {
            scheme: PqScheme::Falcon512,
            pubkey: falcon_key((i as u8).wrapping_add(1)),
            activated_at: i * 1_000,
            superseded_at: (i + 1) * 1_000,
        })
        .collect();
    // All 40 entries are within 720,000 heights of now_height = 50_000,
    // so the hard cap PQ_KEY_HISTORY_MAX_COUNT (32) must evict the oldest 8.
    truncate_superseded_history(&mut history, 50_000);
    assert_eq!(history.len(), PQ_KEY_HISTORY_MAX_COUNT);
    assert_eq!(history[0].activated_at, 8_000);
    assert_eq!(history[31].activated_at, 39_000);
}

// ============================================================================
// 4. RemotePqSigner v2 HTTP end-to-end, anti-oracle, no fallback & SafetyRecordStore
// ============================================================================

fn spawn_v2_server(
    service: Arc<PqSignerService>,
    max_requests: usize,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming().take(max_requests).flatten() {
            serve_v2_http_connection(&service, stream);
        }
    });
    (format!("http://{addr}"), handle)
}

fn spawn_canned_v2_server(
    pk_status: &'static str,
    pk_body: String,
    sign_status: &'static str,
    sign_body: String,
    requests: usize,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming().take(requests) {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut req_line = String::new();
            let _ = reader.read_line(&mut req_line);
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let trimmed = line.trim_end();
                if trimmed.is_empty() {
                    break;
                }
                if let Some((n, v)) = trimmed.split_once(':') {
                    if n.eq_ignore_ascii_case("Content-Length") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut buf = vec![0u8; content_length];
            if content_length > 0 {
                let _ = reader.read_exact(&mut buf);
            }
            let (status, body) = if req_line.starts_with("GET ") {
                (pk_status, pk_body.as_str())
            } else {
                (sign_status, sign_body.as_str())
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn remote_pq_signer_v2_http_end_to_end_vote_and_proposal() {
    let kp = real_falcon(0xA1);
    let pk: [u8; FALCON_PUBLIC_KEY_LEN] = kp.public_key().try_into().expect("897B pk");
    let vid_bytes = kp.validator_id();
    let local_service_signer = LocalPqSigner::new(kp, vid_bytes).expect("construct LocalPqSigner");
    let service =
        Arc::new(PqSignerService::new(local_service_signer).with_bearer_token("secret-tok"));

    let (base_url, handle) = spawn_v2_server(service, 4);
    let transport = HttpPqSignerTransport::new(base_url).with_bearer_token("secret-tok");
    let remote = RemotePqSigner::new(Arc::new(transport), vid_bytes, Some(&pk))
        .expect("RemotePqSigner pins 897B Falcon-512 key");

    assert_eq!(remote.scheme(), PqScheme::Falcon512);
    assert_eq!(remote.public_key(), &pk);
    assert_eq!(remote.validator_id(), vid_bytes);

    let bh = [0xDEu8; 32];
    let prevote = ConsensusSignRequest::Vote {
        chain_id: consensus_chain_id(),
        shard_id: 2,
        height: 100,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some(bh),
    };
    let sig_pv = remote.sign_consensus(&prevote).expect("sign prevote");
    assert_eq!(sig_pv.len(), FALCON_SIGNATURE_LEN);
    assert!(remote.verify_consensus(&prevote, &sig_pv));

    // Verify wire preimage matches consensus::vote_sign_bytes_for_shard
    assert_eq!(
        vote_sign_bytes_with_chain(
            consensus_chain_id(),
            2,
            100,
            0,
            VoteKind::Prevote,
            &Some(bh),
        ),
        vote_sign_bytes_for_shard(2, 100, 0, VoteKind::Prevote, &Some(bh))
    );

    let precommit = ConsensusSignRequest::Vote {
        chain_id: consensus_chain_id(),
        shard_id: 2,
        height: 100,
        round: 0,
        kind: VoteKind::Precommit,
        block_hash: Some(bh),
    };
    let sig_pc = remote.sign_consensus(&precommit).expect("sign precommit");
    assert!(remote.verify_consensus(&precommit, &sig_pc));

    let proposal = ConsensusSignRequest::Proposal {
        chain_id: consensus_chain_id(),
        shard_id: 2,
        height: 100,
        round: 0,
        block_hash: bh,
    };
    let sig_prop = remote.sign_consensus(&proposal).expect("sign proposal");
    assert!(verify_pq_signature(
        PqScheme::Falcon512,
        &pk,
        &bh,
        &sig_prop
    ));

    handle.join().expect("server join");
}

#[test]
fn remote_pq_signer_anti_oracle_rejects_arbitrary_bytes_and_mismatched_preimage() {
    let kp = real_falcon(0xB2);
    let pk: [u8; FALCON_PUBLIC_KEY_LEN] = kp.public_key().try_into().expect("897B pk");
    let vid_bytes = kp.validator_id();
    let local = LocalPqSigner::new(real_falcon(0xB2), vid_bytes).expect("local");
    let service = Arc::new(PqSignerService::new(
        LocalPqSigner::new(kp, vid_bytes).expect("service signer"),
    ));

    let (base_url, handle) = spawn_v2_server(service, 4);
    let remote = RemotePqSigner::new(
        Arc::new(HttpPqSignerTransport::new(base_url.clone())),
        vid_bytes,
        Some(&pk),
    )
    .expect("pin key");

    let vote_req = ConsensusSignRequest::Vote {
        chain_id: 5757,
        shard_id: 0,
        height: 55,
        round: 1,
        kind: VoteKind::Prevote,
        block_hash: Some([0x12; 32]),
    };

    // Client-side anti-oracle: arbitrary tx / non-consensus bytes refused before hitting network
    assert_eq!(
        remote.sign_consensus_checked(&vote_req, b"STELL_ARBITRARY_TX_BYTES"),
        Err(SignerError::SigningFailed(
            SigningFailureKind::InvalidRequest
        ))
    );
    assert_eq!(
        local.sign_consensus_checked(&vote_req, b""),
        Err(SignerError::SigningFailed(SigningFailureKind::EmptyMessage))
    );
    assert_eq!(
        local.sign_consensus_checked(&vote_req, b"wrong_preimage"),
        Err(SignerError::SigningFailed(
            SigningFailureKind::InvalidRequest
        ))
    );

    // Server-side anti-oracle over raw HTTP /v2/sign: arbitrary tx bytes refused (400)
    let raw_transport = HttpPqSignerTransport::new(base_url);
    let arbitrary_tx_wire = SignRequestV2 {
        validator_id: vid_bytes,
        request: vote_req.clone(),
        value_id: None,
        preimage: hex::encode(b"TX_TRANSFER_TO_ATTACKER"),
    };
    assert_eq!(
        raw_transport.sign_v2(&arbitrary_tx_wire),
        Err(SignerError::Transport(TransportErrorKind::Rejected {
            status: 400
        }))
    );

    // Server-side: mismatched validator_id refused (400)
    let wrong_vid_wire = SignRequestV2::from_consensus([0xEE; 32], vote_req, None);
    assert_eq!(
        raw_transport.sign_v2(&wrong_vid_wire),
        Err(SignerError::Transport(TransportErrorKind::Rejected {
            status: 400
        }))
    );

    // Verify nothing was signed by checking safety generation remained 0
    assert_eq!(remote.safety_guard().generation(), 0);
    // Use one valid call so server thread completes cleanly (4 total requests: GET, POST, POST, POST)
    let _ = remote
        .sign_consensus(&ConsensusSignRequest::Proposal {
            chain_id: 5757,
            shard_id: 0,
            height: 55,
            round: 1,
            block_hash: [0x99; 32],
        })
        .expect("valid proposal");

    handle.join().expect("server join");
}

#[test]
fn remote_pq_signer_refuses_outage_bad_responses_and_never_falls_back() {
    // 1. Unreachable endpoint -> Transport error, zero local fallback
    let local_oracle = LocalPqSigner::new(real_falcon(0xC3), real_falcon(0xC3).validator_id())
        .expect("healthy local key exists in-process");
    let unreachable = HttpPqSignerTransport::new("http://127.0.0.1:1");
    let err = RemotePqSigner::new(
        Arc::new(unreachable),
        local_oracle.validator_id(),
        Some(local_oracle.public_key()),
    )
    .expect_err("unreachable remote signer must fail closed");
    assert!(matches!(err, SignerError::Transport(_)));

    // 2. Non-loopback plain http:// forbidden automatically
    let non_loopback = HttpPqSignerTransport::new("http://remote-hsm.internal:8443");
    assert_eq!(
        non_loopback.public_key_v2().err(),
        Some(SignerError::PlainHttpForbiddenOnNonLoopback)
    );
    assert!(!is_loopback_base_url("http://localhost.attacker.tld:8443"));

    // 3. /v2/public_key returning Ed25519 32B key or classical scheme_id=1 -> fail closed
    let (url_ed, h_ed) = spawn_canned_v2_server(
        "200 OK",
        format!(
            r#"{{"scheme_id":1,"public_key":"{}","validator_id":"{}"}}"#,
            "aa".repeat(32),
            "bb".repeat(32)
        ),
        "200 OK",
        "{}".to_string(),
        1,
    );
    assert_eq!(
        HttpPqSignerTransport::new(url_ed).public_key_v2().err(),
        Some(SignerError::UnsupportedScheme { scheme_id: 1 })
    );
    h_ed.join().unwrap();

    // 4. /v2/public_key with bad Falcon header != 0x09 -> fail closed
    let mut bad_pk = vec![0x00u8; FALCON_PUBLIC_KEY_LEN];
    bad_pk[0] = 0x05;
    let (url_hdr, h_hdr) = spawn_canned_v2_server(
        "200 OK",
        format!(
            r#"{{"scheme_id":2,"public_key":"{}","validator_id":"{}"}}"#,
            hex::encode(&bad_pk),
            hex::encode(local_oracle.validator_id())
        ),
        "200 OK",
        "{}".to_string(),
        1,
    );
    assert_eq!(
        HttpPqSignerTransport::new(url_hdr).public_key_v2().err(),
        Some(SignerError::MalformedKey)
    );
    h_hdr.join().unwrap();

    // 5. Foreign Falcon signature returned by /v2/sign -> SignatureInvalid, no local fallback!
    let kp = real_falcon(0xD4);
    let foreign_kp = real_falcon(0xD5);
    let vid_bytes = kp.validator_id();
    let req = ConsensusSignRequest::Vote {
        chain_id: 5757,
        shard_id: 0,
        height: 10,
        round: 0,
        kind: VoteKind::Prevote,
        block_hash: Some([0x77; 32]),
    };
    let foreign_sig = foreign_kp.sign(&req.canonical_signing_bytes());
    let (url_for, h_for) = spawn_canned_v2_server(
        "200 OK",
        format!(
            r#"{{"scheme_id":2,"public_key":"{}","validator_id":"{}"}}"#,
            hex::encode(kp.public_key()),
            hex::encode(vid_bytes)
        ),
        "200 OK",
        format!(
            r#"{{"scheme_id":2,"signature":"{}","generation":1}}"#,
            hex::encode(&foreign_sig)
        ),
        2,
    );
    let remote = RemotePqSigner::new(
        Arc::new(HttpPqSignerTransport::new(url_for)),
        vid_bytes,
        Some(kp.public_key()),
    )
    .expect("pin");
    assert_eq!(
        remote.sign_consensus(&req),
        Err(SignerError::SigningFailed(
            SigningFailureKind::SignatureInvalid
        ))
    );
    // Healthy local signer still works in-process, proving RemotePqSigner did not fall back
    assert!(local_oracle.sign_consensus(&req).is_ok());
    h_for.join().unwrap();
}

struct FlakyTransport {
    kp: FalconKeypair,
    pk: [u8; FALCON_PUBLIC_KEY_LEN],
    vid: [u8; 32],
    fail_sign: AtomicBool,
    calls: Mutex<usize>,
}

impl PqSignerTransport for FlakyTransport {
    fn public_key_v2(&self) -> Result<RemotePublicKeyInfo, SignerError> {
        Ok(RemotePublicKeyInfo {
            scheme: PqScheme::Falcon512,
            public_key: self.pk,
            validator_id: self.vid,
        })
    }

    fn sign_v2(
        &self,
        req: &SignRequestV2,
    ) -> Result<([u8; FALCON_SIGNATURE_LEN], u64), SignerError> {
        *self.calls.lock().unwrap() += 1;
        if self.fail_sign.load(Ordering::SeqCst) {
            return Err(SignerError::Transport(TransportErrorKind::Timeout));
        }
        let msg = req.verify_and_extract_preimage(&self.vid)?;
        let sig_vec = self.kp.sign(&msg);
        let sig: [u8; FALCON_SIGNATURE_LEN] = sig_vec.try_into().expect("666B sig");
        Ok((sig, 1))
    }
}

#[test]
fn remote_pq_signer_enforces_safety_monotonicity_and_durable_store() {
    let dir = TempDir::new("safety_v2");
    let storage = Storage::open(&dir.path).expect("open storage");

    let kp = real_falcon(0xE6);
    let pk: [u8; FALCON_PUBLIC_KEY_LEN] = kp.public_key().try_into().expect("897B pk");
    let vid_bytes = kp.validator_id();
    let identity = SafetyRecordIdentity {
        validator: vid_bytes,
        chain: [0x11; 32],
        shard: 0,
    };

    // Absent store without explicit genesis init must fail closed!
    let store_refuse = storage
        .safety_record_store(identity.clone())
        .expect("safety store");
    assert_eq!(
        ConsensusSafetyGuard::from_durable(store_refuse, false).err(),
        Some(SignerError::SafetyStoreQuarantined)
    );

    // Explicit fresh genesis init -> generation 1
    let store = storage.safety_record_store(identity).expect("safety store");
    let guard = ConsensusSafetyGuard::from_durable(store, true).expect("init durable guard");
    assert_eq!(guard.generation(), 1);

    let transport = Arc::new(FlakyTransport {
        kp,
        pk,
        vid: vid_bytes,
        fail_sign: AtomicBool::new(false),
        calls: Mutex::new(0),
    });
    let remote = RemotePqSigner::new(transport.clone(), vid_bytes, Some(&pk))
        .expect("pin")
        .with_safety_guard(guard);

    let v_r1 = ConsensusSignRequest::Vote {
        chain_id: 5757,
        shard_id: 0,
        height: 10,
        round: 1,
        kind: VoteKind::Prevote,
        block_hash: Some([0x01; 32]),
    };
    assert!(remote.sign_consensus(&v_r1).is_ok());
    assert_eq!(remote.safety_guard().generation(), 2);

    // Same (height=10, round=1) or lower round=0 or lower height=9 -> SafetyViolation BEFORE transport!
    let v_r1_conflict = ConsensusSignRequest::Vote {
        chain_id: 5757,
        shard_id: 0,
        height: 10,
        round: 1,
        kind: VoteKind::Prevote,
        block_hash: Some([0x02; 32]),
    };
    assert_eq!(
        remote.sign_consensus(&v_r1_conflict),
        Err(SignerError::SafetyViolation)
    );
    assert_eq!(*transport.calls.lock().unwrap(), 1);

    let v_lower_height = ConsensusSignRequest::Vote {
        chain_id: 5757,
        shard_id: 0,
        height: 9,
        round: 5,
        kind: VoteKind::Prevote,
        block_hash: None,
    };
    assert_eq!(
        remote.sign_consensus(&v_lower_height),
        Err(SignerError::SafetyViolation)
    );

    // Failed remote sign AFTER durable reservation MUST NOT roll back SafetyRecord!
    transport.fail_sign.store(true, Ordering::SeqCst);
    let v_r2 = ConsensusSignRequest::Vote {
        chain_id: 5757,
        shard_id: 0,
        height: 10,
        round: 2,
        kind: VoteKind::Prevote,
        block_hash: Some([0x03; 32]),
    };
    assert_eq!(
        remote.sign_consensus(&v_r2),
        Err(SignerError::Transport(TransportErrorKind::Timeout))
    );
    assert_eq!(
        remote.safety_guard().generation(),
        3,
        "durable reservation must NOT roll back on transport failure"
    );

    // Even once transport recovers, re-signing round 2 is permanently blocked!
    transport.fail_sign.store(false, Ordering::SeqCst);
    assert_eq!(
        remote.sign_consensus(&v_r2),
        Err(SignerError::SafetyViolation)
    );
    // Round 3 succeeds
    let v_r3 = ConsensusSignRequest::Vote {
        chain_id: 5757,
        shard_id: 0,
        height: 10,
        round: 3,
        kind: VoteKind::Prevote,
        block_hash: Some([0x04; 32]),
    };
    assert!(remote.sign_consensus(&v_r3).is_ok());
    assert_eq!(remote.safety_guard().generation(), 4);
}
