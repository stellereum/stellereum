//! Wave 8 polish & hardening regression tests:
//! 1. `LegacyConsensusSafetyStateV1` decode preserves `last_non_nil_prevote`
//!    when `last_prevote.target.is_some()` (cross-kind safety across nil prevote).
//! 2. WebSocket `stell_unsubscribe` with `{"subscription": sid}` (and bare
//!    string `sid`) removes `sid` from the connection's `owned` set cleanly,
//!    allowing re-subscribing up to `WS_MAX_SUBS_PER_CONNECTION`.
//! 3. `ContractAbi::decode_return` decodes bare length-prefixed `Bytes` and
//!    `String` payloads as well as canonical tagged and bare raw payloads.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::RwLock;

use stellereum::consensus::VoteKind;
use stellereum::contract_abi::{AbiMethod, AbiType, AbiValue, ContractAbi};
use stellereum::mempool::Mempool;
use stellereum::remote_signer::{
    ConsensusSafetyGuard, ConsensusSignRequest, SignedProposalStamp, SignedVoteStamp, SignerError,
};
use stellereum::rpc::{hub, ReceiptIndex, RpcState, WS_MAX_SUBS_PER_CONNECTION};
use stellereum::sharding::ShardRegistry;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::storage::{SafetyRecordIdentity, Storage};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
static WS_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        let id = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("stell-w8-polish-{tag}-{}-{id}", std::process::id()));
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

#[derive(Serialize)]
struct LegacyConsensusSafetyStateV1Wire {
    height: u64,
    locked_round: Option<u32>,
    locked_value_id: Option<[u8; 32]>,
    last_prevote: Option<SignedVoteStamp>,
    last_precommit: Option<SignedVoteStamp>,
    last_proposal: Option<SignedProposalStamp>,
}

fn encode_legacy_v1_record(legacy: &LegacyConsensusSafetyStateV1Wire) -> Vec<u8> {
    let body = bincode::serialize(legacy).expect("serialize legacy v1 safety state");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(b"SQV2");
    out.extend_from_slice(&body);
    out
}

#[test]
fn legacy_v1_safety_state_upgrade_preserves_last_non_nil_prevote() {
    let target_a = [0xAAu8; 32];
    let target_b = [0xBBu8; 32];

    // Case 1: legacy record has a non-nil prevote at (height=10, round=2).
    let dir_non_nil = TestDir::new("legacy-non-nil");
    let storage = Storage::open(&dir_non_nil.0).expect("open storage");
    let identity = SafetyRecordIdentity {
        validator: [0x11u8; 32],
        chain: [0x22u8; 32],
        shard: 0,
    };
    let store = storage
        .safety_record_store(identity.clone())
        .expect("safety store");
    let prevote_stamp = SignedVoteStamp {
        height: 10,
        round: 2,
        target: Some(target_a),
    };
    let legacy = LegacyConsensusSafetyStateV1Wire {
        height: 10,
        locked_round: None,
        locked_value_id: None,
        last_prevote: Some(prevote_stamp),
        last_precommit: None,
        last_proposal: None,
    };
    store
        .persist(None, encode_legacy_v1_record(&legacy))
        .expect("persist legacy v1 record");

    let guard = ConsensusSafetyGuard::from_durable(
        storage.safety_record_store(identity).expect("reopen store"),
        false,
    )
    .expect("upgrade legacy v1 record");
    let snap = guard.state_snapshot().expect("snapshot");
    assert_eq!(snap.height, 10);
    assert_eq!(snap.last_prevote, Some(prevote_stamp));
    assert_eq!(
        snap.last_non_nil_prevote,
        Some(prevote_stamp),
        "upgraded V1 record must initialize last_non_nil_prevote when last_prevote has target"
    );

    // Advancing with a nil prevote at round 3 updates last_prevote to None target,
    // yet cross-kind protection against a conflicting precommit at round 2 remains active.
    let nil_prevote = ConsensusSignRequest::Vote {
        chain_id: 1,
        shard_id: 0,
        height: 10,
        round: 3,
        kind: VoteKind::Prevote,
        block_hash: None,
    };
    let after_nil = snap
        .check_and_advance(&nil_prevote, None)
        .expect("nil prevote at higher round succeeds");
    assert_eq!(after_nil.last_non_nil_prevote, Some(prevote_stamp));

    let conflicting_precommit = ConsensusSignRequest::Vote {
        chain_id: 1,
        shard_id: 0,
        height: 10,
        round: 2,
        kind: VoteKind::Precommit,
        block_hash: Some(target_b),
    };
    assert_eq!(
        after_nil.check_and_advance(&conflicting_precommit, Some(target_b)),
        Err(SignerError::SafetyViolation),
        "preserved last_non_nil_prevote must block conflicting precommit across nil prevote"
    );

    drop(guard);
    drop(storage);

    // Case 2: legacy record has a nil prevote (target: None) -> last_non_nil_prevote is None.
    let dir_nil = TestDir::new("legacy-nil");
    let storage_nil = Storage::open(&dir_nil.0).expect("open storage");
    let id_nil = SafetyRecordIdentity {
        validator: [0x33u8; 32],
        chain: [0x44u8; 32],
        shard: 0,
    };
    let store_nil = storage_nil
        .safety_record_store(id_nil.clone())
        .expect("safety store");
    let nil_stamp = SignedVoteStamp {
        height: 10,
        round: 2,
        target: None,
    };
    let legacy_nil = LegacyConsensusSafetyStateV1Wire {
        height: 10,
        locked_round: None,
        locked_value_id: None,
        last_prevote: Some(nil_stamp),
        last_precommit: None,
        last_proposal: None,
    };
    store_nil
        .persist(None, encode_legacy_v1_record(&legacy_nil))
        .expect("persist legacy v1 nil record");

    let guard_nil = ConsensusSafetyGuard::from_durable(
        storage_nil
            .safety_record_store(id_nil)
            .expect("reopen store"),
        false,
    )
    .expect("upgrade legacy v1 nil record");
    let snap_nil = guard_nil.state_snapshot().expect("snapshot");
    assert_eq!(snap_nil.last_prevote, Some(nil_stamp));
    assert_eq!(snap_nil.last_non_nil_prevote, None);
}

async fn ws_test_state() -> Arc<RpcState> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let mempool = Arc::new(RwLock::new(Mempool::default()));
    Arc::new(RpcState {
        engine,
        mempool,
        height: Arc::new(AtomicU64::new(42)),
        node_id: "w8:ws-test".to_string(),
        chain_id: 777,
        staking: Arc::new(RwLock::new(stellereum::staking::StakingLedger::new())),
        governance: Arc::new(RwLock::new(stellereum::governance::Governance::new())),
        recent_blocks: Arc::new(RwLock::new(VecDeque::new())),
        receipts: Arc::new(RwLock::new(ReceiptIndex::default())),
        auth_token: None,
        tx_broadcast: None,
        faucet: None,
        faucet_token: None,
        msg_signing_seed: None,
        archive_store: None,
        shard_registry: ShardRegistry::single(),
    })
}

async fn serve_ws(st: Arc<RpcState>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("addr");
    let app = stellereum::rpc::router(st);
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    (addr, server)
}

async fn recv_json<S>(ws: &mut S) -> Value
where
    S: StreamExt<
            Item = Result<
                tokio_tungstenite::tungstenite::Message,
                tokio_tungstenite::tungstenite::Error,
            >,
        > + Unpin,
{
    let frame = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .expect("reply timeout")
        .expect("stream item")
        .expect("frame");
    serde_json::from_str(frame.to_text().expect("text")).expect("json")
}

#[tokio::test]
async fn ws_unsubscribe_object_and_string_forms_do_not_leak_connection_cap() {
    let _serial = WS_SERIAL.lock().await;
    let st = ws_test_state().await;
    let hub_before = hub().len();
    let (addr, server) = serve_ws(st).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws"))
        .await
        .expect("ws handshake");

    let mut ids = Vec::with_capacity(WS_MAX_SUBS_PER_CONNECTION);
    for i in 0..WS_MAX_SUBS_PER_CONNECTION {
        ws.send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"jsonrpc": "2.0", "id": i, "method": "stell_subscribe", "params": ["newHeads"]})
                .to_string(),
        ))
        .await
        .expect("send subscribe");
        let reply = recv_json(&mut ws).await;
        let sid = reply["result"]
            .as_str()
            .unwrap_or_else(|| panic!("subscribe {i} must succeed: {reply}"));
        ids.push(sid.to_string());
        // Pace below the 5/s per-IP expensive-read budget.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // Confirm connection is at WS_MAX_SUBS_PER_CONNECTION.
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({"jsonrpc": "2.0", "id": 1000, "method": "stell_subscribe", "params": ["newHeads"]})
            .to_string(),
    ))
    .await
    .expect("send over-cap subscribe");
    let cap_reply = recv_json(&mut ws).await;
    assert!(
        cap_reply["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("per-connection"),
        "expected per-connection cap error, got: {cap_reply}"
    );
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Unsubscribe using object form `{"subscription": sid}` -> must remove `sid` from `owned`.
    let sid_obj = ids.pop().expect("at least one subscription");
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({
            "jsonrpc": "2.0",
            "id": 1001,
            "method": "stell_unsubscribe",
            "params": {"subscription": sid_obj}
        })
        .to_string(),
    ))
    .await
    .expect("send object-form unsubscribe");
    let unsub_obj_reply = recv_json(&mut ws).await;
    assert_eq!(unsub_obj_reply["result"], json!(true));

    // Re-subscribing now must succeed without hitting the per-connection cap.
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({"jsonrpc": "2.0", "id": 1002, "method": "stell_subscribe", "params": ["newHeads"]})
            .to_string(),
    ))
    .await
    .expect("send resubscribe after object-form unsubscribe");
    let resub_obj_reply = recv_json(&mut ws).await;
    let sid_resub = resub_obj_reply["result"].as_str().unwrap_or_else(|| {
        panic!("resubscribe after object-form unsubscribe failed: {resub_obj_reply}")
    });
    assert_eq!(sid_resub.len(), 32);
    ids.push(sid_resub.to_string());
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Unsubscribe using bare string form `params: sid` -> must also remove `sid` from `owned`.
    let sid_str = ids.pop().expect("at least one subscription");
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({
            "jsonrpc": "2.0",
            "id": 1003,
            "method": "stell_unsubscribe",
            "params": sid_str
        })
        .to_string(),
    ))
    .await
    .expect("send string-form unsubscribe");
    let unsub_str_reply = recv_json(&mut ws).await;
    assert_eq!(unsub_str_reply["result"], json!(true));

    // Re-subscribing again must succeed.
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        json!({"jsonrpc": "2.0", "id": 1004, "method": "stell_subscribe", "params": ["newHeads"]})
            .to_string(),
    ))
    .await
    .expect("send resubscribe after string-form unsubscribe");
    let resub_str_reply = recv_json(&mut ws).await;
    let sid_resub2 = resub_str_reply["result"].as_str().unwrap_or_else(|| {
        panic!("resubscribe after string-form unsubscribe failed: {resub_str_reply}")
    });
    assert_eq!(sid_resub2.len(), 32);

    let _ = ws.close(None).await;
    let start = std::time::Instant::now();
    while hub().len() != hub_before {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for hub subscription cleanup"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    server.abort();
}

#[test]
fn contract_abi_decode_return_handles_length_prefixed_bare_blobs() {
    let mut abi = ContractAbi::new();
    abi.add_method(AbiMethod::view("get_bytes", vec![], AbiType::Bytes));
    abi.add_method(AbiMethod::view("get_str", vec![], AbiType::String));

    let blob = AbiValue::Bytes(vec![10, 20, 30, 40, 50]);
    let tagged_blob = abi
        .encode_return("get_bytes", &blob)
        .expect("encode_return");
    assert_eq!(
        abi.decode_return("get_bytes", &tagged_blob)
            .expect("tagged"),
        blob
    );
    let bare_prefixed_blob = blob.encode_payload().expect("encode_payload");
    assert_eq!(
        abi.decode_return("get_bytes", &bare_prefixed_blob)
            .expect("bare length-prefixed bytes"),
        blob
    );
    assert_eq!(
        abi.decode_return("get_bytes", &[1, 2, 3])
            .expect("bare raw bytes"),
        AbiValue::Bytes(vec![1, 2, 3])
    );

    let text = AbiValue::String("stellereum".to_string());
    let tagged_text = abi.encode_return("get_str", &text).expect("encode_return");
    assert_eq!(
        abi.decode_return("get_str", &tagged_text).expect("tagged"),
        text
    );
    let bare_prefixed_text = text.encode_payload().expect("encode_payload");
    assert_eq!(
        abi.decode_return("get_str", &bare_prefixed_text)
            .expect("bare length-prefixed string"),
        text
    );
    assert_eq!(
        abi.decode_return("get_str", b"raw-utf8")
            .expect("bare raw string"),
        AbiValue::String("raw-utf8".to_string())
    );
}
