//! R3-F integration tests: Runtime, Node, RPC, and CLI wiring for W3 PQ
//! validator lifecycle (`OpCode 59..=64`), engine-owned `pq_registry` RPC
//! reads, `SnapBundle` + `sync::install_bundle`, `PqSigner` v2 +
//! `SafetyAuthority` (`SafetyRecordStore`, zero local fallback), and
//! `STELL_PEER_PQ_KEYS` post-W3 ignore.

#[allow(dead_code)]
#[path = "../src/cli/tx_builders.rs"]
mod tx_builders;

use ed25519_dalek::SigningKey;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use stellereum::consensus::{
    clear_validator_pq_keys_for_tests, get_validator_pq_key, pq_key_at_height,
    register_validator_pq_key, sync_committed_pq_registry, verify_proposer_signature, ValidatorId,
    ValidatorSet,
};
use stellereum::explorer::describe_intent_op;
use stellereum::governance::Governance;
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::pq_registry::{
    derive_validator_id, pq_lifecycle_active_at, set_pq_lifecycle_activation_override, PqRegistry,
};
use stellereum::remote_signer::{
    HttpPqSignerTransport, LocalPqSigner, PqSignerService, RemotePqSigner,
};
use stellereum::rpc::{ReceiptIndex, RpcState};
use stellereum::runtime::ValidatorRuntime;
use stellereum::safety::{
    derive_safety_chain_id, operator_safety_init, SafetyAuthority, SafetyBootContext,
};
use stellereum::sharding::{Block, ShardRegistry, Transaction, MASTERCHAIN_SHARD};
use stellereum::staking::{
    StakingLedger, COMMISSION_EFFECT_DELAY_HEIGHTS, MIN_VALIDATOR_BOND, STELL_MIN_BOND_BUFFER,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{decode_pq_registry, SafetyRecordIdentity, Storage};
use stellereum::svm::OpCode;

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);
static CONSENSUS_GLOBAL_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

struct PqLifecycleGateGuard;

impl PqLifecycleGateGuard {
    fn at(height: u64) -> Self {
        set_pq_lifecycle_activation_override(Some(height));
        Self
    }
}

impl Drop for PqLifecycleGateGuard {
    fn drop(&mut self) {
        set_pq_lifecycle_activation_override(None);
    }
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("stell-r3f-{tag}-{}-{seq}", std::process::id()))
}

fn falcon(seed: u8) -> FalconKeypair {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = seed.wrapping_mul(29).wrapping_add(7);
    FalconKeypair::generate_from_seed_bytes(&s)
}

fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT)
}

fn test_rpc_state(tip: u64) -> Arc<RpcState> {
    Arc::new(RpcState {
        engine: Arc::new(InMemoryStateEngine::new()),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::default())),
        height: Arc::new(AtomicU64::new(tip)),
        node_id: "r3f-rpc:test".to_string(),
        chain_id: 5757,
        staking: Arc::new(tokio::sync::RwLock::new(StakingLedger::new())),
        governance: Arc::new(tokio::sync::RwLock::new(Governance::new())),
        recent_blocks: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        receipts: Arc::new(tokio::sync::RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

fn make_block(height: u64, txs: Vec<Transaction>) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: 1_760_000_000 + height,
        proposer: SigningKey::from_bytes(&[0x5Au8; 32])
            .verifying_key()
            .to_bytes(),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    }
}

// ============================================================================
// 1. Engine-local RPC pq_registry_read() isolation (no process-global handle)
// ============================================================================

#[tokio::test]
async fn rpc_pq_reads_come_from_engine_state_with_zero_cross_instance_leak() {
    let st_a = test_rpc_state(40_000);
    let st_b = test_rpc_state(40_000);

    let vid: ValidatorId = [0x41u8; 32];
    let withdrawal_addr = [0x77u8; 32];
    let pk1 = falcon(0xA1).public_key.clone();
    let pk2 = falcon(0xA2).public_key.clone();

    {
        let mut ledger = st_a.engine.staking_write().await;
        let mut reg = st_a.engine.pq_registry_write().await;
        ledger
            .bond_with_withdrawal(
                vid,
                MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER,
                500,
                withdrawal_addr,
            )
            .expect("bond with withdrawal");
        ledger
            .pq_register_key(&mut reg, vid, PqScheme::Falcon512, pk1.clone(), 10, 10)
            .expect("register initial key");
        ledger
            .pq_announce_rotation(&mut reg, vid, PqScheme::Falcon512, pk2.clone(), 100)
            .expect("announce pending rotation");
    }

    // st_a serves the committed engine pq_registry.
    let key_a = st_a
        .call(
            "stell_getPqKey",
            json!({ "validator": hex::encode(vid), "height": 100 }),
        )
        .await;
    assert_eq!(key_a["pubkey_hex"], json!(hex::encode(&pk1)));
    assert_eq!(key_a["pending"]["pubkey_hex"], json!(hex::encode(&pk2)));

    let status_a = st_a.call("stell_getPqRegistryStatus", json!({})).await;
    assert_eq!(status_a["count"], json!(1));

    let vstat_a = st_a
        .call(
            "stell_getValidatorStatus",
            json!({ "validator": hex::encode(vid) }),
        )
        .await;
    assert_eq!(
        vstat_a["withdrawal_address"],
        json!(hex::encode(withdrawal_addr))
    );
    assert_eq!(vstat_a["rotation_seq"], json!(2));

    // st_b has its own empty engine -> must NOT see st_a's registry!
    let key_b = st_b
        .call(
            "stell_getPqKey",
            json!({ "validator": hex::encode(vid), "height": 100 }),
        )
        .await;
    assert!(
        key_b.get("error").is_some(),
        "isolated engine B must not see engine A's pq_registry: {key_b}"
    );
    let status_b = st_b.call("stell_getPqRegistryStatus", json!({})).await;
    assert_eq!(status_b["count"], json!(0));
    let vstat_b = st_b
        .call(
            "stell_getValidatorStatus",
            json!({ "validator": hex::encode(vid) }),
        )
        .await;
    assert_eq!(vstat_b["known"], json!(false));
    assert!(vstat_b["withdrawal_address"].is_null());
    assert!(vstat_b["rotation_seq"].is_null());
}

// ============================================================================
// 2. SnapBundle + sync::install_bundle restore non-empty pq_registry
// ============================================================================

#[tokio::test]
async fn snap_bundle_and_install_bundle_restore_pq_registry_and_fail_closed_if_omitted() {
    let _gate = PqLifecycleGateGuard::at(1);

    let src = Arc::new(InMemoryStateEngine::new());
    let chain_id = src.chain_id;
    let cold_kp = falcon(0x11);
    let cold_addr = pq_addr(&cold_kp);
    let hot1_kp = falcon(0x12);
    let hot2_kp = falcon(0x13);

    src.update_account(AccountState::new(cold_addr, 50_000_000_000_000))
        .await;

    let (reg_tx, vid) = tx_builders::build_register_validator_tx_with_chain(
        &cold_kp,
        &hot1_kp,
        MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER,
        400,
        0,
        chain_id,
    );
    let rot_tx = tx_builders::build_rotate_voting_key_tx_with_chain(
        &cold_kp,
        vid,
        1,
        Some(&hot2_kp),
        1,
        chain_id,
    );

    let mut blk1 = make_block(1, vec![reg_tx]);
    let out1 = src.apply_block_transition(&blk1, 0).await;
    assert_eq!(out1.status, vec![true]);
    blk1.state_root = src.get_state_root().await;

    let blk2 = make_block(2, vec![rot_tx]);
    let out2 = src.apply_block_transition(&blk2, 0).await;
    assert_eq!(out2.status, vec![true]);
    let root2 = src.get_state_root().await;

    // Verify SnapBundle captures non-empty pq_registry on the ApplyLane.
    let ed_key = SigningKey::from_bytes(&[0x5Au8; 32]);
    let vset = ValidatorSet::from_list(vec![(ed_key.verifying_key().to_bytes(), 1)]);
    let mut rt = ValidatorRuntime::new(ed_key, vset, src.clone(), 2);
    assert!(rt.submit_snapshot(2, root2), "submit_snapshot accepted");
    let bundle = loop {
        if let Some(b) = rt.poll_snapshot() {
            break b;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    assert_eq!(bundle.height, 2);
    assert!(
        !bundle.pq_registry.is_empty(),
        "SnapBundle must capture non-empty pq_registry"
    );
    let decoded_reg =
        decode_pq_registry(&bundle.pq_registry).expect("decode SnapBundle pq_registry");
    assert_eq!(decoded_reg.len(), 1);
    assert!(decoded_reg.pending_of(&vid).is_some());

    // Build full domain blobs as consensus_driver does.
    let state_bytes = bincode::serialize(&bundle.accounts).expect("ser accounts");
    let domain_bytes = bincode::serialize(&bundle.domains).expect("ser domains");
    let xshard_bytes =
        bincode::serialize(&rt.cross_shard_replay_snapshot().await).expect("ser xshard");
    let pq_reg_bytes = bundle.pq_registry.clone();
    let session_bytes = bundle.session_keys.clone();
    let bridge_bytes = bundle.bridge.clone();
    let zkml_bytes = bundle.zkml_models.clone();
    let cnvrf_bytes = bundle.cnvrf_v3.clone();
    let evm_bytes = bundle.evm_bindings.clone();

    // Negative check: omitting pq_registry when committed registry is non-empty MUST fail closed!
    let bad_dst = Arc::new(InMemoryStateEngine::new());
    let err = stellereum::sync::fast_sync_state(
        &bad_dst,
        root2,
        || async { Some(state_bytes.clone()) },
        |kind| {
            let domain_bytes = domain_bytes.clone();
            let session_bytes = session_bytes.clone();
            let bridge_bytes = bridge_bytes.clone();
            let zkml_bytes = zkml_bytes.clone();
            let xshard_bytes = xshard_bytes.clone();
            let cnvrf_bytes = cnvrf_bytes.clone();
            let evm_bytes = evm_bytes.clone();
            async move {
                match kind {
                    "domains" => Some(domain_bytes),
                    "session" => Some(session_bytes),
                    "bridge" => Some(bridge_bytes),
                    "zkml" => Some(zkml_bytes),
                    "cross_shard" => Some(xshard_bytes),
                    "cnvrf_v3" => Some(cnvrf_bytes),
                    "evm_bindings" => Some(evm_bytes),
                    // Deliberately omit "pq_registry"
                    _ => None,
                }
            }
        },
    )
    .await
    .expect_err("omitting non-empty pq_registry must fail verify_restored_root");
    assert!(
        err.contains("state root mismatch"),
        "expected root mismatch error, got: {err}"
    );
    assert!(bad_dst.pq_registry_read().await.is_empty());

    // Negative check: corrupted pq_registry bytes MUST fail closed in install_bundle!
    let err_corrupt = stellereum::sync::fast_sync_state(
        &bad_dst,
        root2,
        || async { Some(state_bytes.clone()) },
        |kind| {
            let domain_bytes = domain_bytes.clone();
            let session_bytes = session_bytes.clone();
            let bridge_bytes = bridge_bytes.clone();
            let zkml_bytes = zkml_bytes.clone();
            let xshard_bytes = xshard_bytes.clone();
            let cnvrf_bytes = cnvrf_bytes.clone();
            let evm_bytes = evm_bytes.clone();
            async move {
                match kind {
                    "domains" => Some(domain_bytes),
                    "session" => Some(session_bytes),
                    "bridge" => Some(bridge_bytes),
                    "zkml" => Some(zkml_bytes),
                    "cross_shard" => Some(xshard_bytes),
                    "cnvrf_v3" => Some(cnvrf_bytes),
                    "evm_bindings" => Some(evm_bytes),
                    "pq_registry" => Some(vec![0xFFu8; 17]),
                    _ => None,
                }
            }
        },
    )
    .await
    .expect_err("corrupted pq_registry must fail install_bundle");
    assert!(
        err_corrupt.contains("restore pq_registry"),
        "expected restore pq_registry error, got: {err_corrupt}"
    );

    // Positive check: full bundle restores pq_registry BEFORE root check and matches root2.
    let dst = Arc::new(InMemoryStateEngine::new());
    stellereum::sync::fast_sync_state(
        &dst,
        root2,
        || async { Some(state_bytes.clone()) },
        |kind| {
            let domain_bytes = domain_bytes.clone();
            let session_bytes = session_bytes.clone();
            let bridge_bytes = bridge_bytes.clone();
            let zkml_bytes = zkml_bytes.clone();
            let xshard_bytes = xshard_bytes.clone();
            let cnvrf_bytes = cnvrf_bytes.clone();
            let evm_bytes = evm_bytes.clone();
            let pq_reg_bytes = pq_reg_bytes.clone();
            async move {
                match kind {
                    "domains" => Some(domain_bytes),
                    "session" => Some(session_bytes),
                    "bridge" => Some(bridge_bytes),
                    "zkml" => Some(zkml_bytes),
                    "cross_shard" => Some(xshard_bytes),
                    "cnvrf_v3" => Some(cnvrf_bytes),
                    "evm_bindings" => Some(evm_bytes),
                    "pq_registry" => Some(pq_reg_bytes),
                    _ => None,
                }
            }
        },
    )
    .await
    .expect("fast_sync_state with pq_registry must succeed");
    assert_eq!(dst.get_state_root().await, root2);
    assert_eq!(
        dst.pq_registry_read().await.records(),
        src.pq_registry_read().await.records()
    );
}

// ============================================================================
// 3. ValidatorRuntime + PqSigner v2 (HTTP mock) + SafetyAuthority (zero fallback)
// ============================================================================

struct MockHttpV2Server {
    base_url: String,
    fail_sign: Arc<AtomicBool>,
    sign_calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MockHttpV2Server {
    fn start(service: Arc<PqSignerService>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("local addr");
        let base_url = format!("http://{addr}");
        let fail_sign = Arc::new(AtomicBool::new(false));
        let sign_calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let fail_flag = Arc::clone(&fail_sign);
        let calls_ctr = Arc::clone(&sign_calls);
        let stop_flag = Arc::clone(&stop);

        let handle = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                        let mut buf = [0u8; 8192];
                        let n = match stream.read(&mut buf) {
                            Ok(n) if n > 0 => n,
                            _ => continue,
                        };
                        let raw = String::from_utf8_lossy(&buf[..n]);
                        let mut lines = raw.split("\r\n");
                        let req_line = lines.next().unwrap_or("");
                        let mut parts = req_line.split_whitespace();
                        let method = parts.next().unwrap_or("");
                        let path = parts.next().unwrap_or("");
                        let mut auth_header: Option<String> = None;
                        for l in &mut lines {
                            if l.is_empty() {
                                break;
                            }
                            if let Some((k, v)) = l.split_once(':') {
                                if k.eq_ignore_ascii_case("authorization") {
                                    auth_header = Some(v.trim().to_string());
                                }
                            }
                        }
                        let body = raw
                            .split_once("\r\n\r\n")
                            .map(|(_, b)| b.as_bytes())
                            .unwrap_or(b"");

                        let (status, resp_body) = if method == "POST"
                            && path == "/v2/sign"
                            && fail_flag.load(Ordering::Relaxed)
                        {
                            calls_ctr.fetch_add(1, Ordering::Relaxed);
                            (500u16, r#"{"error":"injected_hsm_failure"}"#.to_string())
                        } else {
                            if method == "POST" && path == "/v2/sign" {
                                calls_ctr.fetch_add(1, Ordering::Relaxed);
                            }
                            service.handle_http_request(method, path, auth_header.as_deref(), body)
                        };
                        let status_text = match status {
                            200 => "OK",
                            401 => "Unauthorized",
                            409 => "Conflict",
                            _ => "Internal Server Error",
                        };
                        let resp = format!(
                            "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            resp_body.len(),
                            resp_body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url,
            fail_sign,
            sign_calls,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MockHttpV2Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[tokio::test]
async fn validator_runtime_remote_pq_signer_v2_and_safety_store_zero_fallback() {
    let _serial = CONSENSUS_GLOBAL_LOCK.lock().await;
    let _gate = PqLifecycleGateGuard::at(0);

    let ed_sk = SigningKey::from_bytes(&[0x44u8; 32]);
    let vid = ed_sk.verifying_key().to_bytes();
    let vset = ValidatorSet::from_list(vec![(vid, 1)]);
    let remote_fk = falcon(0x45);
    let decoy_local_fk = falcon(0x46);

    // Register remote_fk as the committed key in engine + consensus::PQ_COMMITTED_REGISTRY.
    let engine = Arc::new(InMemoryStateEngine::new());
    let genesis_root = engine.get_state_root().await;
    {
        let mut ledger = engine.staking_write().await;
        let mut reg = engine.pq_registry_write().await;
        ledger
            .bond(vid, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .expect("bond");
        ledger
            .pq_register_key(
                &mut reg,
                vid,
                PqScheme::Falcon512,
                remote_fk.public_key.clone(),
                0,
                0,
            )
            .expect("register");
        sync_committed_pq_registry(&reg, true);
    }

    // Start mock HTTP v2 remote signer with bearer token.
    let service_signer = LocalPqSigner::new(remote_fk.clone(), vid).expect("service signer");
    let service = Arc::new(PqSignerService::new(service_signer).with_bearer_token("r3f-tok"));
    let server = MockHttpV2Server::start(service);

    // Durable SafetyRecordStore + SafetyAuthority (clean genesis init).
    let dir = temp_dir("safety_v2");
    let storage = Arc::new(Storage::open(&dir).expect("open storage"));
    storage
        .set_meta_durable("genesis_state_root", &genesis_root)
        .expect("set genesis meta");
    let identity = SafetyRecordIdentity {
        validator: vid,
        chain: derive_safety_chain_id(stellereum::consensus::consensus_chain_id(), &genesis_root),
        shard: MASTERCHAIN_SHARD,
    };
    let _ = operator_safety_init(&storage, vid, MASTERCHAIN_SHARD, None, None, true)
        .expect("safety init");
    let safety = SafetyAuthority::open_from_storage(
        storage.clone(),
        identity,
        SafetyBootContext {
            is_validator: true,
            is_observer_env: false,
            new_chain_explicit: false,
            restored_finalized: Some((0, [0u8; 32])),
            restored_state_height: Some(0),
            restored_finalized_qc_verified: true,
            legacy_checkpoint: None,
            legacy_watermark: None,
        },
    );
    assert!(safety.can_sign());
    let gen0 = safety.generation().expect("generation");

    // Wrong validator_id must be refused by RemotePqSigner & with_pq_signer.
    let bad_transport =
        HttpPqSignerTransport::new(server.base_url.clone()).with_bearer_token("r3f-tok");
    assert!(RemotePqSigner::new(Arc::new(bad_transport), [0x99u8; 32], None).is_err());

    let transport =
        HttpPqSignerTransport::new(server.base_url.clone()).with_bearer_token("r3f-tok");
    let remote = Arc::new(
        RemotePqSigner::new(Arc::new(transport), vid, Some(&remote_fk.public_key))
            .expect("RemotePqSigner pins committed key"),
    );

    // Even if decoy_local_fk is also attached via with_falcon_key, PqSigner v2 owns signing
    // and never falls back to decoy_local_fk.
    let mut rt = ValidatorRuntime::new(ed_sk, vset.clone(), engine.clone(), 1)
        .with_safety_authority(safety)
        .with_falcon_key(decoy_local_fk)
        .with_pq_signer(remote.clone())
        .expect("with_pq_signer succeeds");
    assert!(rt.pq_signer().is_some());

    // 1) Propose -> signs via HTTP v2 and advances SafetyAuthority generation.
    let block = rt.propose(1_760_000_001).await.expect("propose succeeds");
    assert!(
        verify_proposer_signature(&block),
        "proposal signed via RemotePqSigner v2 must verify against committed PqRegistry"
    );
    let gen_after_prop = rt.safety.generation().expect("gen");
    assert!(gen_after_prop > gen0);
    assert_eq!(server.sign_calls.load(Ordering::Relaxed), 1);

    // 2) Prevote -> signs via HTTP v2 and verifies under Vote::verify().
    let prevote = rt.make_prevote().expect("make_prevote succeeds");
    assert!(
        prevote.verify(),
        "prevote signed via RemotePqSigner v2 must verify"
    );
    let gen_after_pv = rt.safety.generation().expect("gen");
    assert!(gen_after_pv > gen_after_prop);
    assert_eq!(server.sign_calls.load(Ordering::Relaxed), 2);
    rt.on_prevote(prevote).expect("admit own prevote");

    // 3) Precommit -> signs via HTTP v2, locks, and verifies.
    let precommit = rt.make_precommit().expect("make_precommit succeeds");
    assert!(
        precommit.verify(),
        "precommit signed via RemotePqSigner v2 must verify"
    );
    let gen_after_pc = rt.safety.generation().expect("gen");
    assert!(gen_after_pc > gen_after_pv);
    assert_eq!(server.sign_calls.load(Ordering::Relaxed), 3);

    // 4) Inject HTTP 500 failure on /v2/sign at round 1 -> MUST return None (ZERO local fallback)
    //    AND SafetyRecordStore reservation must NOT roll back!
    rt.next_round();
    server.fail_sign.store(true, Ordering::Relaxed);
    let failed_pv = rt.make_prevote();
    assert!(
        failed_pv.is_none(),
        "when RemotePqSigner fails, make_prevote MUST return None with zero fallback to falcon_key"
    );
    assert_eq!(server.sign_calls.load(Ordering::Relaxed), 4);
    let gen_after_fail = rt.safety.generation().expect("gen");
    assert!(
        gen_after_fail > gen_after_pc,
        "SafetyRecordStore reservation must persist even when remote signing failed"
    );

    // Even after the remote server recovers, round 1 was durably reserved and cannot be re-signed!
    server.fail_sign.store(false, Ordering::Relaxed);
    assert!(
        rt.make_prevote().is_none(),
        "reserved round 1 must not be re-signed after remote recovery"
    );
    // Advancing to round 2 succeeds again via remote signer.
    rt.next_round();
    let r2_pv = rt.make_prevote().expect("round 2 prevote succeeds");
    assert!(r2_pv.verify());

    sync_committed_pq_registry(&PqRegistry::new(), true);
    clear_validator_pq_keys_for_tests();
    std::fs::remove_dir_all(&dir).ok();
}

// ============================================================================
// 4. STELL_PEER_PQ_KEYS / legacy key map cleared on W3 boundary
// ============================================================================

#[tokio::test]
async fn sync_committed_pq_registry_clears_legacy_peer_keys_post_w3_and_keeps_pre_w3() {
    let _serial = CONSENSUS_GLOBAL_LOCK.lock().await;
    let _gate = PqLifecycleGateGuard::at(100);

    clear_validator_pq_keys_for_tests();
    sync_committed_pq_registry(&PqRegistry::new(), true);

    let peer_id = [0x66u8; 32];
    let peer_fk = falcon(0x66);
    // Simulate pre-W3 STELL_PEER_PQ_KEYS registration at height 50 (< 100).
    assert!(!pq_lifecycle_active_at(50));
    register_validator_pq_key(peer_id, PqScheme::Falcon512, peer_fk.public_key.clone());
    assert_eq!(
        pq_key_at_height(&peer_id, 50),
        Some((PqScheme::Falcon512, peer_fk.public_key.clone()))
    );

    // Crossing activation height 100: sync_committed_pq_registry(..., pq_lifecycle_active_at(100))
    // installs the authoritative committed registry and clears PQ_VALIDATOR_KEYS, so
    // both pq_key_at_height and get_validator_pq_key return None for the legacy peer key.
    assert!(pq_lifecycle_active_at(100));
    sync_committed_pq_registry(&PqRegistry::new(), pq_lifecycle_active_at(100));
    assert_eq!(pq_key_at_height(&peer_id, 100), None);
    assert_eq!(
        get_validator_pq_key(&peer_id),
        None,
        "legacy PQ_VALIDATOR_KEYS must be cleared when pq_lifecycle_active_at(h) == true"
    );
    clear_validator_pq_keys_for_tests();
}

// ============================================================================
// 5. CLI builders & explorer labels for OpCode 59..=64 (chain-id + PoP + apply)
// ============================================================================

#[tokio::test]
async fn cli_builders_for_opcodes_59_to_64_roundtrip_pop_chain_id_and_execute() {
    let _gate = PqLifecycleGateGuard::at(1);

    let engine = Arc::new(InMemoryStateEngine::new());
    let chain_id = engine.chain_id;

    let cold1 = falcon(0x21);
    let cold1_addr = pq_addr(&cold1);
    let cold2 = falcon(0x22);
    let cold2_addr = pq_addr(&cold2);
    let hot1 = falcon(0x23);
    let hot2 = falcon(0x24);

    // Pre-W3 validator for ClaimWithdrawal (OpCode 62) test.
    let legacy_vid = [0x88u8; 32];
    let legacy_hot = falcon(0x25);
    let legacy_cold = falcon(0x26);
    let legacy_cold_addr = pq_addr(&legacy_cold);

    engine
        .update_account(AccountState::new(cold1_addr, 50_000_000_000_000))
        .await;
    engine
        .update_account(AccountState::new(cold2_addr, 50_000_000_000_000))
        .await;
    engine
        .update_account(AccountState::new(legacy_cold_addr, 50_000_000_000_000))
        .await;
    {
        let mut ledger = engine.staking_write().await;
        ledger
            .bond(legacy_vid, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
            .expect("legacy bond");
        ledger.validator_pq_keys.insert(
            legacy_vid,
            (PqScheme::Falcon512, legacy_hot.public_key.clone()),
        );
    }

    let bond_amt = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER;
    let (tx_reg, vid) = tx_builders::build_register_validator_tx_with_chain(
        &cold1, &hot1, bond_amt, 500, 0, chain_id,
    );
    let tx_rot_announce = tx_builders::build_rotate_voting_key_tx_with_chain(
        &cold1,
        vid,
        1,
        Some(&hot2),
        1,
        chain_id,
    );
    let tx_rot_cancel =
        tx_builders::build_rotate_voting_key_tx_with_chain(&cold1, vid, 2, None, 2, chain_id);
    let tx_change_wd =
        tx_builders::build_change_withdrawal_tx_with_chain(&cold1, vid, &cold2, 3, chain_id);
    let tx_claim_wd = tx_builders::build_claim_withdrawal_tx_with_chain(
        &legacy_cold,
        legacy_vid,
        &legacy_hot,
        0,
        chain_id,
    );
    let tx_ann_comm =
        tx_builders::build_announce_commission_tx_with_chain(&cold2, vid, 750, 0, chain_id);
    let tx_app_comm = tx_builders::build_apply_commission_tx_with_chain(&cold2, vid, 1, chain_id);

    let all_txs = [
        &tx_reg,
        &tx_rot_announce,
        &tx_rot_cancel,
        &tx_change_wd,
        &tx_claim_wd,
        &tx_ann_comm,
        &tx_app_comm,
    ];
    for tx in all_txs {
        assert_eq!(tx.chain_id(), Some(chain_id));
        assert!(tx.verify_signature_for_chain(chain_id, true));
        assert!(
            !tx.verify_signature_for_chain(chain_id + 1, true),
            "cross-chain replay must fail signature check"
        );
        // Wire round-trip check
        let encoded = bincode::serialize(tx).expect("serialize tx");
        let decoded: Transaction = bincode::deserialize(&encoded).expect("deserialize tx");
        assert_eq!(
            bincode::serialize(&decoded.payload).expect("ser decoded payload"),
            bincode::serialize(&tx.payload).expect("ser orig payload"),
        );
        // Explorer describe_intent_op check
        let desc = describe_intent_op(&decoded.payload[0]);
        assert!(!desc.is_empty());
    }

    assert_eq!(
        vid,
        derive_validator_id(chain_id, &cold1_addr, &hot1.public_key)
    );
    assert!(matches!(
        tx_reg.payload[0],
        OpCode::SysCallRegisterValidator(_)
    ));
    assert!(matches!(
        tx_rot_announce.payload[0],
        OpCode::SysCallRotateVotingKey(_)
    ));
    assert!(matches!(
        tx_change_wd.payload[0],
        OpCode::SysCallChangeWithdrawal(_)
    ));
    assert!(matches!(
        tx_claim_wd.payload[0],
        OpCode::SysCallClaimWithdrawal(_)
    ));
    assert!(matches!(
        tx_ann_comm.payload[0],
        OpCode::SysCallAnnounceCommission { .. }
    ));
    assert!(matches!(
        tx_app_comm.payload[0],
        OpCode::SysCallApplyCommission { .. }
    ));

    // Execute all 6 opcodes in blocks and verify state transitions succeed.
    // Block 1: RegisterValidator + ClaimWithdrawal.
    let b1 = make_block(1, vec![tx_reg.clone(), tx_claim_wd.clone()]);
    let o1 = engine.apply_block_transition(&b1, 0).await;
    assert_eq!(o1.status, vec![true, true]);

    // Block 2: RotateVotingKey (announce seq=1).
    let b2 = make_block(2, vec![tx_rot_announce.clone()]);
    let o2 = engine.apply_block_transition(&b2, 0).await;
    assert_eq!(o2.status, vec![true]);

    // Block 3: RotateVotingKey (cancel seq=2, before withdrawal address rotates).
    let b3 = make_block(3, vec![tx_rot_cancel.clone()]);
    let o3 = engine.apply_block_transition(&b3, 0).await;
    assert_eq!(o3.status, vec![true]);

    // Block 4: ChangeWithdrawal (cold1 -> cold2).
    let b4 = make_block(4, vec![tx_change_wd.clone()]);
    let o4 = engine.apply_block_transition(&b4, 0).await;
    assert_eq!(o4.status, vec![true]);

    {
        let ledger = engine.staking_read().await;
        let reg = engine.pq_registry_read().await;
        assert_eq!(ledger.withdrawal_address_of(&vid), Some(cold2_addr));
        assert_eq!(
            ledger.withdrawal_address_of(&legacy_vid),
            Some(legacy_cold_addr)
        );
        assert_eq!(reg.record_of(&vid).unwrap().next_seq, 3);
        assert!(reg.record_of(&vid).unwrap().pending.is_none());
    }

    // Block 5: AnnounceCommission (by new cold2 withdrawal_address).
    let b5 = make_block(5, vec![tx_ann_comm.clone()]);
    let o5 = engine.apply_block_transition(&b5, 0).await;
    assert_eq!(o5.status, vec![true]);

    // Block 5 + delay: ApplyCommission.
    let apply_h = 5 + COMMISSION_EFFECT_DELAY_HEIGHTS;
    let b6 = make_block(apply_h, vec![tx_app_comm.clone()]);
    let o6 = engine.apply_block_transition(&b6, 0).await;
    assert_eq!(o6.status, vec![true]);
    assert_eq!(
        engine
            .staking_read()
            .await
            .validators
            .get(&vid)
            .unwrap()
            .commission_bps,
        750
    );

    // Also verify the compiled binary CLI parses `validator register-validator --dry-run`
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_stellereum"))
        .args([
            "validator",
            "register-validator",
            "--withdrawal-seed",
            &hex::encode([0x21u8; 32]),
            "--voting-seed",
            &hex::encode([0x23u8; 32]),
            "--amount",
            &bond_amt.to_string(),
            "--commission-bps",
            "500",
            "--nonce",
            "0",
            "--chain-id",
            &chain_id.to_string(),
            "--dry-run",
        ])
        .output()
        .expect("run stellereum validator register-validator --dry-run");
    assert!(
        out.status.success(),
        "CLI dry-run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("RegisterValidator signed"));
    assert!(stdout.contains("raw:"));
}
