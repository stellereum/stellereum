//! End-to-end R2-E integration tests:
//! 1. `stell_getFinalizedHeader` + `stell_getFinalizedCheckpoint` + `stell_getHistoricalRoot`
//!    -> `light_client::Checkpoint::from_historical_root_json` + `Checkpoint::verify`
//!    across `H - 1 / H / H + 1`, plus rejection when `state_root` or `prev_hash` is forged.
//! 2. `evm_bindings_survive_50k_blocks_prune_and_restart_without_oom`:
//!    live binding persistence -> 50k+ blocks + pruning -> restart hydration via
//!    `hydrate_rpc_from_store` (O(1) RAM, no `Vec<Block>` / no `clear_evm_bindings`) ->
//!    `evm_binding_pq` + `eth_getBalance` + `stell_getEvmBinding` + incremental cursor catch-up.
//! 3. `SnapBundle` + `PersistJob::EvmBindingsState` + `load_full_state_into` roundtrip with
//!    non-empty `EvmBindingsState` and `finalized_post_root`.
//! 4. Default `u64::MAX` gate invariants (`FORK_ID == 0x0f584a46`, `COMMITMENT_VERSION == 5`,
//!    `EXPECTED_GENESIS_ROOT`).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde_json::json;
use stellereum::commitment::COMMITMENT_VERSION;
use stellereum::consensus::{
    register_validator_pq_key, FalconKeypair, QuorumCertificate, ValidatorSet, Vote, VoteKind,
    VoteSet,
};
use stellereum::evm_adapter;
use stellereum::governance::Governance;
use stellereum::light_client::{Checkpoint, LightClient};
use stellereum::light_client_cli::parse_served_header;
use stellereum::mempool::Mempool;
use stellereum::post_quantum::{derive_pq_address, PqScheme, DEFAULT_SALT};
use stellereum::protocol::{CONSENSUS_RULESET_VERSION, DOMAIN_SET_VERSION, FORK_ID};
use stellereum::rpc::{hydrate_rpc_from_store, ReceiptIndex, RpcState};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{
    set_header_commit_activation_override, Block, ShardRegistry, Transaction,
    HEADER_COMMIT_ACTIVATION_HEIGHT, MASTERCHAIN_SHARD,
};
use stellereum::staking::StakingLedger;
use stellereum::state_engine::{
    set_evm_bindings_state_activation_override, AccountState, InMemoryStateEngine,
    EVM_BINDINGS_STATE_ACTIVATION_HEIGHT,
};
use stellereum::storage::{load_full_state_into, AsyncPersistence, BlockHeaderRecord, Storage};
use tokio::sync::{Mutex, RwLock};

static DIR_SEQ: AtomicU64 = AtomicU64::new(1);
static EVM_E2E_LOCK: Mutex<()> = Mutex::const_new(());
static RPC_HEADER_LOCK: Mutex<()> = Mutex::const_new(());

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("stell-r2e-{tag}-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

struct HeaderGateGuard;
impl HeaderGateGuard {
    fn set(h: u64) -> Self {
        set_header_commit_activation_override(Some(h));
        Self
    }
}
impl Drop for HeaderGateGuard {
    fn drop(&mut self) {
        set_header_commit_activation_override(None);
    }
}

struct EvmGateGuard;
impl EvmGateGuard {
    fn set(h: u64) -> Self {
        set_evm_bindings_state_activation_override(Some(h));
        Self
    }
}
impl Drop for EvmGateGuard {
    fn drop(&mut self) {
        set_evm_bindings_state_activation_override(None);
    }
}

fn make_validator(tag: &[u8]) -> (SigningKey, FalconKeypair, ValidatorSet) {
    let seed = *blake3::hash(tag).as_bytes();
    let sk = SigningKey::from_bytes(&seed);
    let fk = FalconKeypair::generate_from_seed_bytes(&seed);
    let id = sk.verifying_key().to_bytes();
    register_validator_pq_key(id, PqScheme::Falcon512, fk.public_key().to_vec());
    register_validator_pq_key(
        fk.validator_id(),
        PqScheme::Falcon512,
        fk.public_key().to_vec(),
    );
    let vs = ValidatorSet::from_list(vec![(id, 1)]);
    (sk, fk, vs)
}

fn sign_qc(
    height: u64,
    round: u32,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    sk: &SigningKey,
    fk: &FalconKeypair,
    vs: &ValidatorSet,
) -> QuorumCertificate {
    let mut set = VoteSet::new();
    let vote = Vote::sign_with_falcon(sk, fk, height, round, VoteKind::Precommit, Some(block_hash));
    set.add(vote, vs, height, round, VoteKind::Precommit)
        .expect("vote ingest");
    set.certificate_with_parent(Some(block_hash), vs, Some(&parent_hash))
        .expect("certificate")
}

fn make_signed_block(
    height: u64,
    round: u32,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    txs: Vec<Transaction>,
    val: (&SigningKey, &FalconKeypair, &ValidatorSet),
) -> Block {
    let (sk, fk, vs) = val;
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root,
        transactions: txs,
        cross_shard_out: Vec::new(),
        timestamp: 1_760_000_000 + height,
        proposer: sk.verifying_key().to_bytes(),
        validator_signatures: Vec::new(),
        shard_headers: Vec::new(),
        precommit_qc: None,
        last_qc: None,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0x33u8; 32],
        mmr_epoch_root: if height == 10 {
            [0x77u8; 32]
        } else {
            [0u8; 32]
        },
        cnvrf_v3: None,
        round,
    };
    b.sign_block(sk);
    let bh = b.compute_hash();
    b.validator_signatures
        .push((fk.validator_id(), fk.sign(&bh)));
    b.precommit_qc = Some(sign_qc(height, round, bh, prev_hash, sk, fk, vs));
    b
}

fn make_rpc_state(
    engine: Arc<InMemoryStateEngine>,
    archive_store: Option<Arc<Storage>>,
) -> RpcState {
    RpcState {
        engine,
        mempool: Arc::new(RwLock::new(Mempool::default())),
        height: Arc::new(AtomicU64::new(0)),
        node_id: "inf1:r2e-test".to_string(),
        chain_id: evm_adapter::effective_chain_id(),
        staking: Arc::new(RwLock::new(StakingLedger::new())),
        governance: Arc::new(RwLock::new(Governance::new())),
        recent_blocks: Arc::new(RwLock::new(VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store,
        shard_registry: ShardRegistry::single(),
    }
}

fn falcon(seed: u8) -> stellereum::post_quantum::FalconKeypair {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = 0xC1;
    stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&s)
}

fn pq_of(kp: &stellereum::post_quantum::FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT)
}

fn secp(seed: u8) -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[seed; 32]).expect("secp key")
}

fn evm_of(key: &k256::ecdsa::SigningKey) -> [u8; 20] {
    evm_adapter::pubkey_to_address(key.verifying_key().to_encoded_point(false).as_bytes())
        .expect("evm address")
}

fn secp_binding_proof(
    key: &k256::ecdsa::SigningKey,
    chain: u64,
    evm: &[u8; 20],
    pq: &[u8; 32],
) -> Vec<u8> {
    let msg = evm_adapter::binding_message(chain, evm, pq);
    let (sig, recid) = key.sign_prehash_recoverable(&msg).expect("sig");
    let raw = sig.to_bytes();
    let mut s = [0u8; 32];
    s.copy_from_slice(&raw[32..64]);
    let mut rec = recid.to_byte();
    if !evm_adapter::is_low_s(&s) {
        let n = evm_adapter::SECP256K1_N;
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = n[i] as i32 - s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        s = out;
        rec ^= 1;
    }
    let mut p = Vec::with_capacity(65);
    p.extend_from_slice(&raw[..32]);
    p.extend_from_slice(&s);
    p.push(rec);
    p
}

fn build_binding_tx(
    kp: &stellereum::post_quantum::FalconKeypair,
    evm_key: &k256::ecdsa::SigningKey,
    evm: [u8; 20],
    nonce: u64,
) -> Transaction {
    const GAS: u64 = 1_000_000;
    let chain = evm_adapter::effective_chain_id();
    let pk = kp.public_key().to_vec();
    let pq = pq_of(kp);
    let claim_sig = kp.sign(&evm_adapter::binding_message(chain, &evm, &pq));
    let evm_proof = secp_binding_proof(evm_key, chain, &evm, &pq);
    let sign_this =
        evm_adapter::binding_template_message(&pk, evm, &claim_sig, &evm_proof, nonce, GAS)
            .expect("template");
    let tx_sig = kp.sign(&sign_this);
    evm_adapter::build_binding_transaction(&pk, evm, &claim_sig, &evm_proof, nonce, GAS, &tx_sig)
        .expect("binding tx")
}

#[tokio::test]
async fn rpc_headers_checkpoint_and_historical_root_verify_across_boundary_and_reject_forgery() {
    let _lock = RPC_HEADER_LOCK.lock().await;
    const H: u64 = 10;
    let _gate = HeaderGateGuard::set(H);
    let (sk, fk, vs) = make_validator(b"r2e_rpc_header_val");
    let dir = temp_dir("rpc_headers");
    let store = Arc::new(Storage::open(&dir).expect("open store"));
    let engine = Arc::new(InMemoryStateEngine::new());
    let rpc = make_rpc_state(engine, Some(store.clone()));

    let mut blocks = Vec::new();
    let mut prev = [0u8; 32];
    for height in 1..=12u64 {
        let state_root = *blake3::hash(&height.to_le_bytes()).as_bytes();
        let round = if height >= H { 2 } else { 0 };
        let b = make_signed_block(height, round, prev, state_root, Vec::new(), (&sk, &fk, &vs));
        prev = b.compute_hash();
        store.put_block(&b).expect("put block");
        rpc.record_finalized_header(&b).await;
        rpc.record_block(height, prev, 0, b.timestamp).await;
        blocks.push(b);
    }

    // 1. stell_getFinalizedHeader at H-1, H, H+1
    for height in [H - 1, H, H + 1] {
        let resp = rpc
            .call("stell_getFinalizedHeader", json!({ "height": height }))
            .await;
        assert!(resp.get("error").is_none(), "header {height} err: {resp}");
        assert_eq!(resp["shard_id"], 0);
        assert_eq!(resp["round"], if height >= H { 2 } else { 0 });
        if height < H {
            assert!(resp["body_commitment"].is_null());
        } else {
            let bc = resp["body_commitment"]
                .as_str()
                .expect("v4 header must carry body_commitment");
            assert_eq!(bc.len(), 64);
        }
        assert_eq!(
            resp["epoch_key_commitment"].as_str().map(str::len),
            Some(64)
        );
        assert_eq!(resp["mmr_epoch_root"].as_str().map(str::len), Some(64));

        let served = parse_served_header(&resp).expect("parse ServedHeader");
        let cp = Checkpoint {
            height: served.height,
            block_hash: served.block_hash,
            parent_hash: served.prev_hash,
            state_root: served.state_root,
            cert: served.cert,
            shard_id: served.shard_id,
            round: served.round,
            body_commitment: served.body_commitment,
            mmr_epoch_root: served.mmr_epoch_root,
            epoch_key_commitment: served.epoch_key_commitment,
            timestamp: served.timestamp,
            proposer: served.proposer,
        };
        cp.verify(&vs)
            .expect("Checkpoint from stell_getFinalizedHeader must verify");
        LightClient::new(vs.clone(), cp).expect("LightClient must accept served header");

        // Forgery rejection on >= H: tamper state_root / prev_hash in RPC JSON
        if height >= H {
            let mut forged_root = resp.clone();
            forged_root["state_root"] = json!(hex::encode([0xFAu8; 32]));
            let s_bad_root = parse_served_header(&forged_root).expect("parses");
            let cp_bad_root = Checkpoint {
                height: s_bad_root.height,
                block_hash: s_bad_root.block_hash,
                parent_hash: s_bad_root.prev_hash,
                state_root: s_bad_root.state_root,
                cert: s_bad_root.cert,
                shard_id: s_bad_root.shard_id,
                round: s_bad_root.round,
                body_commitment: s_bad_root.body_commitment,
                mmr_epoch_root: s_bad_root.mmr_epoch_root,
                epoch_key_commitment: s_bad_root.epoch_key_commitment,
                timestamp: s_bad_root.timestamp,
                proposer: s_bad_root.proposer,
            };
            assert!(
                cp_bad_root.verify(&vs).is_err(),
                "forged state_root in stell_getFinalizedHeader at {height} must fail verify"
            );

            let mut forged_prev = resp.clone();
            forged_prev["prev_hash"] = json!(hex::encode([0xFBu8; 32]));
            let s_bad_prev = parse_served_header(&forged_prev).expect("parses");
            let cp_bad_prev = Checkpoint {
                height: s_bad_prev.height,
                block_hash: s_bad_prev.block_hash,
                parent_hash: s_bad_prev.prev_hash,
                state_root: s_bad_prev.state_root,
                cert: s_bad_prev.cert,
                shard_id: s_bad_prev.shard_id,
                round: s_bad_prev.round,
                body_commitment: s_bad_prev.body_commitment,
                mmr_epoch_root: s_bad_prev.mmr_epoch_root,
                epoch_key_commitment: s_bad_prev.epoch_key_commitment,
                timestamp: s_bad_prev.timestamp,
                proposer: s_bad_prev.proposer,
            };
            assert!(
                cp_bad_prev.verify(&vs).is_err(),
                "forged prev_hash in stell_getFinalizedHeader at {height} must fail verify"
            );
        }
    }

    // 2. stell_getFinalizedCheckpoint -> build Checkpoint and verify at H+2 (12)
    let cp_json = rpc.call("stell_getFinalizedCheckpoint", json!({})).await;
    assert!(cp_json.get("error").is_none(), "cp err: {cp_json}");
    assert_eq!(cp_json["height"], 12);
    assert!(cp_json["body_commitment"].is_string());
    assert_eq!(cp_json["round"], 2);
    assert_eq!(cp_json["shard_id"], 0);
    let cp_cert: QuorumCertificate =
        serde_json::from_value(cp_json["cert"].clone()).expect("deserialize checkpoint cert");
    let hex32 = |field: &str, v: &serde_json::Value| -> [u8; 32] {
        let s = v[field].as_str().expect("hex32 string");
        hex::decode(s)
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    };
    let parsed_cp = Checkpoint {
        height: cp_json["height"].as_u64().expect("height"),
        block_hash: hex32("block_hash", &cp_json),
        parent_hash: hex32("prev_hash", &cp_json),
        state_root: hex32("state_root", &cp_json),
        cert: cp_cert.clone(),
        shard_id: cp_json["shard_id"].as_u64().expect("shard_id") as u32,
        round: cp_json["round"].as_u64().expect("round") as u32,
        body_commitment: cp_json["body_commitment"]
            .as_str()
            .map(|s| hex::decode(s).unwrap().try_into().unwrap()),
        mmr_epoch_root: hex32("mmr_epoch_root", &cp_json),
        epoch_key_commitment: hex32("epoch_key_commitment", &cp_json),
        timestamp: cp_json["timestamp"].as_u64().expect("timestamp"),
        proposer: hex32("proposer", &cp_json),
    };
    parsed_cp
        .verify(&vs)
        .expect("stell_getFinalizedCheckpoint must verify");
    let mut forged_cp = parsed_cp.clone();
    forged_cp.state_root = [0xCDu8; 32];
    assert!(
        forged_cp.verify(&vs).is_err(),
        "forged state_root in stell_getFinalizedCheckpoint must fail"
    );
    let mut forged_cp_prev = parsed_cp;
    forged_cp_prev.parent_hash = [0xCEu8; 32];
    assert!(
        forged_cp_prev.verify(&vs).is_err(),
        "forged prev_hash in stell_getFinalizedCheckpoint must fail"
    );

    // 3. stell_getHistoricalRoot -> Checkpoint::from_historical_root_json + verify
    //    for target heights H-2 (anchor H-1, pre-v4), H-1 (anchor H, v4!), and H (anchor H+1, v4!).
    for target_h in [H - 2, H - 1, H] {
        let hr = rpc
            .call("stell_getHistoricalRoot", json!({ "height": target_h }))
            .await;
        assert!(hr.get("error").is_none(), "hr {target_h} err: {hr}");
        let hr_cp = Checkpoint::from_historical_root_json(&hr)
            .expect("from_historical_root_json must accept honest RPC response");
        hr_cp
            .verify(&vs)
            .expect("Checkpoint from stell_getHistoricalRoot must verify");

        // Anchors at >= H (target_h = H-1 has anchor_height = H, target_h = H has anchor_height = H+1)
        if target_h + 1 >= H {
            let mut forged_hr_root = hr.clone();
            forged_hr_root["state_root"] = json!(hex::encode([0x99u8; 32]));
            forged_hr_root["stateRoot"] = json!(hex::encode([0x99u8; 32]));
            let res_root = Checkpoint::from_historical_root_json(&forged_hr_root)
                .and_then(|c| c.verify(&vs).map(|_| c));
            assert!(
                res_root.is_err(),
                "forged state_root in stell_getHistoricalRoot (target {target_h}) must fail"
            );

            let mut forged_hr_prev = hr.clone();
            forged_hr_prev["prev_hash"] = json!(hex::encode([0x88u8; 32]));
            let res_prev = Checkpoint::from_historical_root_json(&forged_hr_prev)
                .and_then(|c| c.verify(&vs).map(|_| c));
            assert!(
                res_prev.is_err(),
                "forged prev_hash in stell_getHistoricalRoot (target {target_h}) must fail"
            );
        }
    }

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn evm_bindings_survive_50k_blocks_prune_and_restart_without_oom() {
    let _lock = EVM_E2E_LOCK.lock().await;
    const H: u64 = 10;
    let _gate = EvmGateGuard::set(H);
    evm_adapter::clear_evm_bindings();
    evm_adapter::clear_evm_settlements();

    let dir = temp_dir("50k_prune_restart");
    let kp1 = falcon(0x11);
    let pq1 = pq_of(&kp1);
    let evm_key1 = secp(0x21);
    let evm1 = evm_of(&evm_key1);

    let kp2 = falcon(0x12);
    let pq2 = pq_of(&kp2);
    let evm_key2 = secp(0x22);
    let evm2 = evm_of(&evm_key2);

    let kp3 = falcon(0x13);
    let pq3 = pq_of(&kp3);
    let evm_key3 = secp(0x23);
    let evm3 = evm_of(&evm_key3);

    const INITIAL_BAL: u64 = 50_000_000_000_000;
    let tip_height: u64 = 50_015;
    let b2_hash;
    let b11_hash;
    let tx2_hash;
    let tx11_hash;
    let pre_restart_root;

    {
        let store = Arc::new(Storage::open(&dir).expect("open store"));
        let engine = Arc::new(InMemoryStateEngine::new());
        engine
            .update_account(AccountState::new(pq1, INITIAL_BAL))
            .await;
        engine
            .update_account(AccountState::new(pq2, INITIAL_BAL))
            .await;
        engine
            .update_account(AccountState::new(pq3, INITIAL_BAL))
            .await;
        let rpc = make_rpc_state(engine.clone(), Some(store.clone()));

        // Block 2 (pre-activation binding)
        let tx2 = build_binding_tx(&kp1, &evm_key1, evm1, 0);
        tx2_hash = tx2.compute_tx_hash();
        let b2 = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 2,
            prev_hash: [0u8; 32],
            state_root: engine.get_state_root().await,
            transactions: vec![tx2.clone()],
            cross_shard_out: Vec::new(),
            timestamp: 1_760_000_002,
            proposer: [0x01u8; 32],
            validator_signatures: Vec::new(),
            shard_headers: Vec::new(),
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            round: 0,
        };
        let o2 = engine.apply_block_transition(&b2, 0).await;
        assert_eq!(o2.status, vec![true]);
        b2_hash = store.put_block(&b2).expect("put b2");
        store
            .put_receipts_for_block(2, &b2_hash, &b2.transactions, &o2.status, &o2.tx_fees)
            .expect("put r2");
        rpc.record_receipts_with_events(2, b2_hash, &b2.transactions, &o2.status, &o2.tx_fees, &[])
            .await;

        // Block 11 (post-activation canonical Domain::EvmBindings binding)
        let tx11 = build_binding_tx(&kp2, &evm_key2, evm2, 0);
        tx11_hash = tx11.compute_tx_hash();
        let b11 = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: 11,
            prev_hash: b2_hash,
            state_root: engine.get_state_root().await,
            transactions: vec![tx11.clone()],
            cross_shard_out: Vec::new(),
            timestamp: 1_760_000_011,
            proposer: [0x01u8; 32],
            validator_signatures: Vec::new(),
            shard_headers: Vec::new(),
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            round: 0,
        };
        let o11 = engine.apply_block_transition(&b11, 0).await;
        assert_eq!(o11.status, vec![true]);
        b11_hash = store.put_block(&b11).expect("put b11");
        store
            .put_receipts_for_block(11, &b11_hash, &b11.transactions, &o11.status, &o11.tx_fees)
            .expect("put r11");
        rpc.record_receipts_with_events(
            11,
            b11_hash,
            &b11.transactions,
            &o11.status,
            &o11.tx_fees,
            &[],
        )
        .await;

        // Advance header history past 50k blocks without allocating 50k full bodies in RAM.
        for h in 12..=(tip_height - 1) {
            if h != 11 {
                let rec = BlockHeaderRecord {
                    height: h,
                    prev_hash: *blake3::hash(&(h - 1).to_be_bytes()).as_bytes(),
                    state_root: [0x55u8; 32],
                    proposer: [0x01u8; 32],
                    timestamp: 1_760_000_000 + h,
                    tx_count: 0,
                    gas_used: 0,
                    block_hash: *blake3::hash(&h.to_be_bytes()).as_bytes(),
                };
                store.put_header(&rec).expect("put header");
            }
        }
        store
            .set_evm_bindings_cursor(tip_height - 1)
            .expect("set cursor");

        // Block 50_015 (tail block AFTER cursor, persisted only in blocks + receipts_v1,
        // NOT yet in "evm_bindings" — simulates crash between put_block and live cursor advance!)
        let tx_tail = build_binding_tx(&kp3, &evm_key3, evm3, 0);
        let b_tail = Block {
            shard_id: MASTERCHAIN_SHARD,
            height: tip_height,
            prev_hash: *blake3::hash(&(tip_height - 1).to_be_bytes()).as_bytes(),
            state_root: engine.get_state_root().await,
            transactions: vec![tx_tail],
            cross_shard_out: Vec::new(),
            timestamp: 1_760_000_000 + tip_height,
            proposer: [0x01u8; 32],
            validator_signatures: Vec::new(),
            shard_headers: Vec::new(),
            precommit_qc: None,
            last_qc: None,
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
            mmr_epoch_root: [0u8; 32],
            cnvrf_v3: None,
            round: 0,
        };
        let o_tail = engine.apply_block_transition(&b_tail, 0).await;
        assert_eq!(o_tail.status, vec![true]);
        let b_tail_hash = store.put_block(&b_tail).expect("put b_tail");
        store
            .put_receipts_for_block(
                tip_height,
                &b_tail_hash,
                &b_tail.transactions,
                &o_tail.status,
                &o_tail.tx_fees,
            )
            .expect("put r_tail");

        // Prune blocks & receipts below 50_000 (far above heights 2 and 11!)
        store.prune_blocks_below(50_000).expect("prune blocks");
        store.prune_receipts_below(50_000).expect("prune receipts");
        assert!(store.get_block(&b2_hash).expect("get b2").is_none());
        assert!(store.get_block(&b11_hash).expect("get b11").is_none());
        assert!(store.get_receipt(&tx2_hash).expect("get tx2").is_none());
        assert!(store.get_receipt(&tx11_hash).expect("get tx11").is_none());

        // Persist canonical state snapshot at tip_height so the restarted engine has balances + evm_bindings_state
        let snap_bytes = engine.create_snapshot().await;
        let ledger = engine.staking_read().await.clone();
        let gov = engine.governance_read().await.clone();
        let dom = stellereum::storage::DomainSnapshot::capture(&engine, &ledger, &gov).await;
        let dom_bytes = bincode::serialize(&dom).expect("ser dom");
        let evm_state_bytes = engine.evm_bindings_snapshot().await;
        store.put_state(tip_height, &snap_bytes).expect("put state");
        store.put_domains(tip_height, &dom_bytes).expect("put dom");
        store
            .put_evm_bindings_state(tip_height, &evm_state_bytes)
            .expect("put evm_bindings_state");
        store
            .put_finalized_post_root(tip_height, engine.get_state_root().await)
            .expect("put post root");
        pre_restart_root = engine.get_state_root().await;
        store.flush().expect("flush");
    }

    // Simulate process restart: wipe in-memory process caches completely!
    evm_adapter::clear_evm_bindings();
    evm_adapter::clear_evm_settlements();
    assert_eq!(evm_adapter::lookup_bound_pq(&evm1), None);
    assert_eq!(evm_adapter::lookup_bound_pq(&evm2), None);
    assert_eq!(evm_adapter::lookup_bound_pq(&evm3), None);

    let store2 = Arc::new(Storage::open(&dir).expect("reopen store"));
    let engine2 = Arc::new(InMemoryStateEngine::new());
    let restored_h = load_full_state_into(&store2, &engine2)
        .await
        .expect("load_full_state_into");
    assert_eq!(restored_h.map(|(h, ..)| h), Some(tip_height));
    assert_eq!(engine2.get_state_root().await, pre_restart_root);

    let rpc2 = make_rpc_state(engine2.clone(), Some(store2.clone()));
    hydrate_rpc_from_store(&rpc2, &store2).await;

    // 1. Pre-activation binding from pruned height 2 survived via `"evm_bindings"`!
    assert_eq!(
        engine2.evm_binding_pq(&evm1).await,
        Some(pq1),
        "pre-activation binding from height 2 must survive 50k prune + restart"
    );
    // 2. Post-activation binding from pruned height 11 survived via both canonical state & index!
    assert_eq!(
        engine2.evm_binding_pq(&evm2).await,
        Some(pq2),
        "post-activation binding from height 11 must survive 50k prune + restart"
    );
    // 3. Tail binding at height 50_015 (after cursor) was caught up streamingly (O(1) RAM)!
    assert_eq!(
        engine2.evm_binding_pq(&evm3).await,
        Some(pq3),
        "tail binding after cursor must be hydrated incrementally"
    );
    assert_eq!(
        store2.evm_bindings_cursor().expect("cursor"),
        Some(tip_height),
        "cursor must advance to tip"
    );
    assert_eq!(
        store2.evm_binding_by_evm(&evm3).expect("db lookup"),
        Some(pq3)
    );

    // 4. eth_getBalance and stell_getEvmBinding resolve all three EVM addresses after restart!
    for (evm, pq) in [(evm1, pq1), (evm2, pq2), (evm3, pq3)] {
        let evm_hex = format!("0x{}", hex::encode(evm));
        let pq_hex = format!("0x{}", hex::encode(pq));
        let bal = rpc2
            .call("eth_getBalance", json!([evm_hex, "latest"]))
            .await;
        let bal_str = bal.as_str().expect("eth_getBalance hex string");
        assert_ne!(
            bal_str, "0x0",
            "eth_getBalance for bound EVM {evm_hex} must resolve to funded PQ account"
        );
        let binding_q = rpc2.call("stell_getEvmBinding", json!([pq_hex])).await;
        assert_eq!(binding_q["bound"], true);
        assert_eq!(binding_q["evmAddress"], evm_hex);
    }

    drop(store2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn snap_bundle_evm_bindings_state_and_load_full_state_into_roundtrip() {
    let _lock = EVM_E2E_LOCK.lock().await;
    const H: u64 = 1;
    let _gate = EvmGateGuard::set(H);
    evm_adapter::clear_evm_bindings();
    evm_adapter::clear_evm_settlements();

    let (sk, fk, vs) = make_validator(b"r2e_snap_bundle_val");
    let engine = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&engine, &vs, 100_000_000_000_000).await;

    let kp = falcon(0x51);
    let pq = pq_of(&kp);
    let evm_key = secp(0x61);
    let evm = evm_of(&evm_key);
    engine
        .update_account(AccountState::new(pq, 20_000_000_000_000))
        .await;
    let tx = build_binding_tx(&kp, &evm_key, evm, 0);

    let mut rt = ValidatorRuntime::new(sk.clone(), vs.clone(), engine.clone(), 1);
    let prev = [0u8; 32];
    let b1 = make_signed_block(
        1,
        0,
        prev,
        engine.get_state_root().await,
        vec![tx],
        (&sk, &fk, &vs),
    );
    let o1 = engine.apply_block_transition(&b1, 0).await;
    assert_eq!(o1.status, vec![true]);
    let root1 = engine.get_state_root().await;

    assert!(rt.submit_snapshot(1, root1), "submit_snapshot accepted");
    let bundle = loop {
        if let Some(b) = rt.poll_snapshot() {
            break b;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    assert_eq!(bundle.height, 1);
    assert!(
        !bundle.evm_bindings.is_empty(),
        "SnapBundle must capture non-empty evm_bindings"
    );

    let dir = temp_dir("snap_bundle_roundtrip");
    let store = Arc::new(Storage::open(&dir).expect("open store"));
    let ap = AsyncPersistence::start(store.clone());

    let state_bytes = bincode::serialize(&bundle.accounts).expect("ser accounts");
    let dom_bytes = bincode::serialize(&bundle.domains).expect("ser domains");
    let cross_shard = bincode::serialize(&rt.cross_shard_replay_snapshot().await).expect("xshard");
    ap.enqueue_state(bundle.height, state_bytes);
    ap.enqueue_cnvrf_v3(bundle.height, bundle.cnvrf_v3);
    ap.enqueue_evm_bindings_state(bundle.height, bundle.evm_bindings);
    ap.enqueue_domains(
        bundle.height,
        dom_bytes,
        bundle.session_keys,
        bundle.bridge,
        bundle.zkml_models,
        cross_shard,
    );
    ap.request_flush();
    // Wait until async persistence drains all queued jobs.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while ap.pending() > 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    store
        .put_finalized_post_root(1, root1)
        .expect("put post root");
    store.flush().expect("flush");

    // Clear process-local index and restore into a brand new engine from disk.
    evm_adapter::clear_evm_bindings();
    let restored = Arc::new(InMemoryStateEngine::new());
    let loaded_h = load_full_state_into(&store, &restored)
        .await
        .expect("load_full_state_into");
    assert_eq!(loaded_h.map(|(h, ..)| h), Some(1));
    assert_eq!(restored.get_state_root().await, root1);
    assert_eq!(
        restored.evm_binding_pq(&evm).await,
        Some(pq),
        "restored engine must carry canonical evm_bindings from PersistJob::EvmBindingsState"
    );

    drop(ap);
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn default_gates_preserve_fork_id_commitment_version_and_genesis_root() {
    assert_eq!(HEADER_COMMIT_ACTIVATION_HEIGHT, 0);
    assert_eq!(EVM_BINDINGS_STATE_ACTIVATION_HEIGHT, 0);
    assert_eq!(CONSENSUS_RULESET_VERSION, 7);
    assert_eq!(DOMAIN_SET_VERSION, 4);
    assert_eq!(FORK_ID, 0x3ae0_0ebc);
    assert_eq!(COMMITMENT_VERSION, 5);

    const V1: [u8; 32] = [0x11u8; 32];
    const V2: [u8; 32] = [0x22u8; 32];
    const FAUCET_SEED_HEX: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    const EXPECTED_GENESIS_ROOT: &str =
        "c07880e016dbb60dd84d9d1dd64bd141e4694d99ba919c288b9b08554f9373a5";

    let engine = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(vec![(V1, 1), (V2, 1)]);
    fund_genesis(&engine, &vs, 100_000_000_000_000_000).await;

    let seed = hex::decode(FAUCET_SEED_HEX).unwrap();
    let faucet = stellereum::rpc::Faucet::new(
        <[u8; 32]>::try_from(seed.as_slice()).unwrap(),
        1,
        100 * 1_000_000_000,
        1_000 * 1_000_000_000,
    );
    let _ = engine
        .credit_native_transfer(&faucet.account(), 1_000_000_000_000_000)
        .await;
    let root = engine.get_state_root().await;
    assert_eq!(hex::encode(root), EXPECTED_GENESIS_ROOT);
}
