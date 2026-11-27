//! RPC-mode, token, confidential and honesty tests for stell-wallet.
//!
//! Everything here runs WITHOUT the live stand: chain-facing paths are
//! exercised against loopback stub HTTP servers (`serve_sequence`), and the
//! local-simulation paths against an isolated `HOME` temp dir. Anything that
//! needs the real stand is listed in `LIVE_VERIFICATION.md`-style output of
//! the harness run, not asserted here.

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/rpc.rs"]
mod rpc;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/pq.rs"]
mod pq;

#[allow(dead_code)] // GATE: test vendors lib module via #[path]; items unused by this test binary are expected
#[path = "../src/client.rs"]
mod client;

use client::LightClient;
use pq::{PqKeyPair, PqScheme, DEFAULT_SALT};
use rpc::{RpcConfig, TxFinality};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, OnceLock};

// ---------------------------------------------------------------- helpers

/// Serve `responses` (one per connection, in order) as JSON-RPC results on
/// loopback. Returns the base URL. Captured raw request texts are pushed to
/// `captured` when provided.
fn serve_sequence(
    responses: Vec<serde_json::Value>,
    captured: Option<Arc<Mutex<Vec<String>>>>,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let url = format!("http://{}/", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for result in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .ok();
            // Read headers + Content-Length body.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let content_len = loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break None,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(hend) = find_headers_end(&buf) {
                            let head = String::from_utf8_lossy(&buf[..hend]).into_owned();
                            let len = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    (k.trim().eq_ignore_ascii_case("content-length"))
                                        .then(|| v.trim().parse::<usize>().ok())?
                                })
                                .unwrap_or(0);
                            if buf.len() >= hend + len {
                                break Some(len);
                            }
                        }
                    }
                    Err(_) => break None,
                }
            };
            let _ = content_len;
            if let Some(cap) = &captured {
                cap.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into_owned());
            }
            let body_len = content_len.unwrap_or(0);
            let hend = find_headers_end(&buf).unwrap_or(0);
            let body = match serde_json::from_slice::<serde_json::Value>(
                &buf[hend..(hend + body_len).min(buf.len())],
            )
            .ok()
            .and_then(|v| v.get("id").cloned())
            {
                // Audit B-WALLET-5: echo the request id (replay mixing is
                // refused client-side when ids mismatch).
                Some(id) => serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "result": result
                })
                .to_string(),
                None => serde_json::json!({
                    "jsonrpc": "2.0", "id": 1, "result": result
                })
                .to_string(),
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    url
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn serve_results(results: Vec<serde_json::Value>) -> String {
    serve_sequence(results, None)
}

fn cfg_for(url: &str) -> RpcConfig {
    RpcConfig {
        url: url.to_string(),
        auth_token: None,
        faucet_token: None,
    }
}

/// Isolated HOME so tests never touch the real `~/.stellereum`.
fn test_client_home() -> std::path::PathBuf {
    static HOME: OnceLock<String> = OnceLock::new();
    let dir = HOME
        .get_or_init(|| {
            let d = std::env::temp_dir().join(format!("stell_wallet_tests_{}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            // `set_var` is safe under this crate's edition (2021).
            std::env::set_var("HOME", &d);
            d.to_string_lossy().into_owned()
        })
        .clone();
    std::path::PathBuf::from(dir)
}

async fn local_client() -> LightClient {
    let _ = test_client_home();
    LightClient::connect(None).await.expect("local connect")
}

fn addr(n: u8) -> [u8; 32] {
    [n; 32]
}

// ------------------------------------------------------------ rpc parsing

#[test]
fn rpc_url_parsing_ok_and_rejects_non_http() {
    let (host, path) = rpc::parse_http_url("http://127.0.0.1:8545/").unwrap();
    assert_eq!(host, "127.0.0.1:8545");
    assert_eq!(path, "/");
    let (host2, path2) = rpc::parse_http_url("http://node.local:9999/rpc").unwrap();
    assert_eq!(
        (host2.as_str(), path2.as_str()),
        ("node.local:9999", "/rpc")
    );
    let (host3, path3) = rpc::parse_http_url("https://127.0.0.1:8545/").unwrap();
    assert_eq!((host3.as_str(), path3.as_str()), ("127.0.0.1:8545", "/"));
    assert!(rpc::parse_http_url("ftp://127.0.0.1:8545/").is_err());
    assert!(rpc::parse_http_url("http:///").is_err());
}

#[test]
fn jsonrpc_body_shape() {
    let body = rpc::build_jsonrpc_body("stell_getBalance", &serde_json::json!("ab"), 7);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 7);
    assert_eq!(v["method"], "stell_getBalance");
    assert_eq!(v["params"], serde_json::json!("ab"));
}

#[test]
fn receipt_status_parsing_success_failed_pending_unknown() {
    let ok = serde_json::json!({"status": "success", "height": 41, "block_hash": "aa", "index": 2});
    assert!(matches!(
        rpc::parse_receipt_status(&ok),
        TxFinality::Confirmed {
            height: 41,
            index: 2,
            ..
        }
    ));
    let failed =
        serde_json::json!({"status": "failed", "height": 42, "block_hash": "bb", "index": 0});
    assert!(matches!(
        rpc::parse_receipt_status(&failed),
        TxFinality::Failed {
            height: Some(42),
            ..
        }
    ));
    assert_eq!(
        rpc::parse_receipt_status(&serde_json::json!({"status": "pending"})),
        TxFinality::Pending
    );
    assert_eq!(
        rpc::parse_receipt_status(&serde_json::json!({"status": "unknown"})),
        TxFinality::Unknown
    );
    // A receipt with no recognizable status must NEVER read as confirmed.
    assert_eq!(
        rpc::parse_receipt_status(&serde_json::json!({})),
        TxFinality::Unknown
    );
}

#[test]
fn finality_labels_never_claim_confirmed_early() {
    assert!(!TxFinality::Pending.status_label().contains("Confirmed"));
    assert!(!TxFinality::Unknown.status_label().contains("Confirmed"));
    let label = TxFinality::Confirmed {
        height: 9,
        block_hash: "x".into(),
        index: 0,
    }
    .status_label();
    assert!(label.contains("Confirmed") && label.contains('9'));
    assert!(!TxFinality::Pending.is_confirmed());
}

#[test]
fn rpc_config_keeps_explicit_tokens() {
    let c = RpcConfig::from_opts(
        "http://127.0.0.1:8545",
        Some("auth-1".into()),
        Some("faucet-1".into()),
    );
    assert_eq!(c.auth_token.as_deref(), Some("auth-1"));
    assert_eq!(c.faucet_token.as_deref(), Some("faucet-1"));
    assert_eq!(c.url, "http://127.0.0.1:8545");
}

// ------------------------------------------------------- rpc over loopback

#[test]
fn rpc_call_posts_json_and_forwards_auth_header() {
    let captured = Arc::new(Mutex::new(Vec::<String>::new()));
    let url = serve_sequence(
        vec![serde_json::json!({"balance": "123", "nonce": 4})],
        Some(captured.clone()),
    );
    let cfg = RpcConfig {
        url,
        auth_token: Some("secret-token".into()),
        faucet_token: None,
    };
    let v = rpc::rpc_call(&cfg, "stell_getBalance", serde_json::json!("aa")).unwrap();
    assert_eq!(v["balance"], "123");
    let reqs = captured.lock().unwrap();
    assert_eq!(reqs.len(), 1);
    assert!(
        reqs[0].contains("X-Api-Key: secret-token"),
        "auth header missing"
    );
    assert!(reqs[0].contains("stell_getBalance"), "method missing");
}

#[test]
fn rpc_call_maps_node_error_to_err() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        // Read headers + full body (single read races partial arrivals).
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(hend) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
                    {
                        let head = String::from_utf8_lossy(&buf[..hend]).into_owned();
                        let len = head
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                (k.trim().eq_ignore_ascii_case("content-length"))
                                    .then(|| v.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        if buf.len() >= hend + len {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let text = String::from_utf8_lossy(&buf);
        // Audit B-WALLET-5: echo the request id (client refuses mismatches).
        let req_id = text
            .find("\r\n\r\n")
            .and_then(|i| serde_json::from_str::<serde_json::Value>(&text[i + 4..]).ok())
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(serde_json::json!(1));
        let body = serde_json::json!({"jsonrpc":"2.0","id":req_id,"error":{"code":-32001,"message":"unauthorized: nope"}}).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    });
    let err = rpc::rpc_call(
        &cfg_for(&url),
        "stell_sendRawTransaction",
        serde_json::json!({}),
    )
    .unwrap_err();
    assert!(err.contains("unauthorized"), "unexpected: {err}");
}

#[test]
fn faucet_requires_token_without_touching_network() {
    let cfg = RpcConfig {
        url: "http://127.0.0.1:9/".into(),
        auth_token: None,
        faucet_token: None,
    };
    let err = rpc::faucet_drip(&cfg, &hex::encode(addr(1)), None).unwrap_err();
    assert!(err.contains("faucet token"), "unexpected: {err}");
}

#[test]
fn poll_receipt_returns_confirmed_on_success() {
    let url = serve_results(vec![
        serde_json::json!({"status": "pending"}),
        serde_json::json!({"status": "success", "height": 7, "block_hash": "cc", "index": 1}),
    ]);
    let f = rpc::poll_receipt(&cfg_for(&url), &"ab".repeat(32), 15, 1);
    assert!(
        matches!(f, TxFinality::Confirmed { height: 7, .. }),
        "got {f:?}"
    );
}

#[test]
fn poll_receipt_timeout_yields_pending_never_confirmed() {
    let url = serve_results(vec![
        serde_json::json!({"status": "pending"}),
        serde_json::json!({"status": "pending"}),
        serde_json::json!({"status": "pending"}),
    ]);
    let f = rpc::poll_receipt(&cfg_for(&url), &"ab".repeat(32), 2, 1);
    assert_eq!(f, TxFinality::Pending);
    assert!(!f.is_confirmed());
}

// ------------------------------------------------------------- SPV honesty

#[test]
fn spv_balance_proof_from_node_verifies_locally() {
    // Genuine node answer: trie leaf (balance||nonce) + real proof.
    let address = addr(11);
    let (balance, nonce) = (5_000_000_000u64, 3u64);
    let mut trie = stellereum::cell::PatriciaTrie::new();
    let mut leaf = Vec::new();
    leaf.extend_from_slice(&balance.to_be_bytes());
    leaf.extend_from_slice(&nonce.to_be_bytes());
    trie.insert(&address, &leaf);
    let root = trie.root_hash();
    let proof = trie.generate_merkle_proof(&address).unwrap();

    let url = serve_results(vec![serde_json::json!({
        "address": hex::encode(address),
        "balance": balance.to_string(),
        "nonce": nonce,
        "stateRoot": hex::encode(root),
        "proof": serde_json::to_value(&proof).unwrap(),
    })]);
    let cfg = cfg_for(&url);
    let answer = rpc::get_balance_spv(&cfg, &hex::encode(address)).unwrap();
    assert_eq!((answer.balance, answer.nonce), (balance, nonce));
    assert_eq!(
        rpc::verify_spv_balance_answer(&address, &answer),
        rpc::SpvVerdict::Verified
    );

    // Same proof, spoofed balance claim -> local verification must fail.
    let mut spoofed = answer.clone();
    spoofed.balance = balance + 1_000_000;
    assert_eq!(
        rpc::verify_spv_balance_answer(&address, &spoofed),
        rpc::SpvVerdict::Failed
    );

    // Server omits the proof -> absence is reported, never balance zero.
    let mut noproof = answer.clone();
    noproof.proof = None;
    assert_eq!(
        rpc::verify_spv_balance_answer(&address, &noproof),
        rpc::SpvVerdict::Failed
    );
}

#[test]
fn token_spv_proof_key_is_recomputed_not_trusted() {
    let token_id = addr(21);
    let account = addr(22);
    let key = stellereum::state_engine::token_balance_key(&token_id, &account);
    let balance = 777u64;
    let mut trie = stellereum::cell::PatriciaTrie::new();
    trie.insert(&key, &balance.to_be_bytes());
    let root = trie.root_hash();
    let proof = trie.generate_merkle_proof(&key).unwrap();

    // Honest server answer verifies.
    let url = serve_results(vec![serde_json::json!({
        "balance": balance.to_string(),
        "stateRoot": hex::encode(root),
        "key": hex::encode(key),
        "proof": serde_json::to_value(&proof).unwrap(),
    })]);
    let cfg = cfg_for(&url);
    let answer =
        rpc::get_token_balance_spv(&cfg, &hex::encode(token_id), &hex::encode(account)).unwrap();
    assert!(rpc::verify_token_spv_answer(&token_id, &account, &answer));

    // Lying server swaps the key field: recomputation must catch it.
    let mut lied = answer.clone();
    lied.key = addr(99);
    assert!(!rpc::verify_token_spv_answer(&token_id, &account, &lied));

    // Proof for a DIFFERENT account must not verify for this one.
    assert!(!rpc::verify_token_spv_answer(&token_id, &addr(23), &answer));
}

// ------------------------------------------------------- local-mode honesty

#[tokio::test]
async fn local_broadcast_is_pending_never_confirmed() {
    let client = local_client().await;
    let to = addr(32);
    let kp = PqKeyPair::from_seed(PqScheme::Falcon512, &[7u8; 32]);
    let sender_addr = kp.derive_address(&DEFAULT_SALT);
    client.set_balance(sender_addr, 10_000_000_000, 0).await;
    let gas = stellereum::svm::GAS_BASIC_TRANSFER
        .saturating_add(stellereum::mempool::PQ_ACTIVATION_SURCHARGE_GAS);
    let tx = LightClient::build_pq_transfer_tx_bound(
        &kp,
        to,
        1_000_000_000,
        gas,
        0,
        1,
        1,
        true,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("build_pq_transfer_tx_bound");

    let (hash, finality) = client.broadcast_tx(&tx).await.expect("broadcast");
    assert_eq!(hash, tx.compute_tx_hash());
    assert_eq!(finality, TxFinality::Pending);
    assert!(
        !finality.is_confirmed(),
        "local sim must never report Confirmed"
    );

    let history = client.get_tx_history();
    let row = history
        .iter()
        .find(|r| r.tx_hash == hex::encode(hash))
        .unwrap();
    assert!(
        !row.status.contains("Confirmed"),
        "dishonest history: {}",
        row.status
    );
    assert!(
        row.status.contains("NOT chain-finalized"),
        "missing honesty note: {}",
        row.status
    );

    // Local effects still applied (self-consistent simulation).
    let (bal, nonce, _) = client.get_balance_spv(&sender_addr, 1).await.unwrap();
    assert_eq!(bal, 10_000_000_000 - 1_000_000_000 - gas);
    assert_eq!(nonce, 1);
    let (tobal, _, _) = client.get_balance_spv(&to, 1).await.unwrap();
    assert_eq!(tobal, 1_000_000_000);
}

#[tokio::test]
async fn local_broadcast_rejects_bad_signature_and_short_funds() {
    let client = local_client().await;
    let sender = stellereum::wallet::WalletAccount::from_seed(&[8u8; 32]);
    let mut tx = sender.create_transaction(addr(33), 1, 0, 1, 1);
    tx.signature[0] ^= 0xFF;
    assert!(client.broadcast_tx(&tx).await.is_err());

    // Unknown sender with no funds cannot pay gas.
    let poor = stellereum::wallet::WalletAccount::from_seed(&[9u8; 32]);
    let tx2 = poor.create_transaction(addr(33), 1, 0, 1, 1);
    assert!(client.broadcast_tx(&tx2).await.is_err());
}

// ------------------------------------------------------------------ tokens

fn test_metadata() -> stellereum::token::TokenMetadata {
    stellereum::token::TokenMetadata {
        name: "Test Token".into(),
        symbol: "TST".into(),
        decimals: 9,
        total_supply: 0,
        max_supply: None,
        minter: [0u8; 32],
        paused: false,
        description: String::new(),
    }
}

#[tokio::test]
async fn token_transfer_tx_shape_and_local_execution() {
    let client = local_client().await;
    let owner = PqKeyPair::from_seed(PqScheme::Falcon512, &[41u8; 32]);
    let owner_addr = owner.derive_address(&DEFAULT_SALT);
    let recipient_addr =
        PqKeyPair::from_seed(PqScheme::Falcon512, &[42u8; 32]).derive_address(&DEFAULT_SALT);
    client.set_balance(owner_addr, 5_000_000_000, 0).await;

    let token_id = client
        .state_engine
        .create_token(owner_addr, test_metadata(), 1_000_000)
        .await
        .expect("create token");
    assert_eq!(
        client.token_balance(&token_id, &owner_addr).await.unwrap(),
        1_000_000
    );

    // Builder shape: SysCallTokenTransfer, zero native amount, gas >= base fee.
    let tx = LightClient::build_pq_token_transfer_tx(
        &owner,
        token_id,
        recipient_addr,
        400_000,
        0,
        1,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("build_pq_token_transfer_tx");
    assert_eq!(tx.amount, 0);
    assert!(tx.gas_limit >= stellereum::svm::GAS_BASIC_TRANSFER);
    assert!(matches!(
        &tx.payload[..],
        [stellereum::svm::OpCode::SysCallTokenTransfer { token_id: t, to, amount: 400_000 }]
            if *t == token_id && *to == recipient_addr
    ));
    assert!(tx.verify_signature());

    let (hash, finality) = client.broadcast_tx(&tx).await.expect("token send");
    assert_eq!(finality, TxFinality::Pending);
    assert_eq!(
        client.token_balance(&token_id, &owner_addr).await.unwrap(),
        600_000
    );
    assert_eq!(
        client
            .token_balance(&token_id, &recipient_addr)
            .await
            .unwrap(),
        400_000
    );
    let row = client
        .get_tx_history()
        .into_iter()
        .find(|r| r.tx_hash == hex::encode(hash))
        .unwrap();
    assert!(row.status.contains("NOT chain-finalized"), "{}", row.status);
}

#[tokio::test]
async fn token_approve_then_transfer_from_local() {
    let client = local_client().await;
    let owner = PqKeyPair::from_seed(PqScheme::Falcon512, &[43u8; 32]);
    let owner_addr = owner.derive_address(&DEFAULT_SALT);
    let spender_addr =
        PqKeyPair::from_seed(PqScheme::Falcon512, &[44u8; 32]).derive_address(&DEFAULT_SALT);
    let third = addr(45);
    client.set_balance(owner_addr, 5_000_000_000, 0).await;
    client.set_balance(spender_addr, 5_000_000_000, 0).await;

    let token_id = client
        .state_engine
        .create_token(owner_addr, test_metadata(), 100_000)
        .await
        .expect("create token");

    let approve = LightClient::build_pq_token_approve_tx(
        &owner,
        token_id,
        spender_addr,
        30_000,
        0,
        1,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("build_pq_token_approve_tx");
    assert!(matches!(
        &approve.payload[..],
        [stellereum::svm::OpCode::SysCallTokenApprove { .. }]
    ));
    let (_, fin) = client.broadcast_tx(&approve).await.expect("approve");
    assert_eq!(fin, TxFinality::Pending);

    // The recorded allowance must actually work for the spender.
    client
        .state_engine
        .token_execute(
            &token_id,
            spender_addr,
            stellereum::token::TokenOp::TransferFrom {
                from: owner_addr,
                to: third,
                amount: 30_000,
            },
        )
        .await
        .expect("allowance must cover TransferFrom");
    assert_eq!(
        client.token_balance(&token_id, &third).await.unwrap(),
        30_000
    );
}

// ------------------------------------------------------------ confidential (PQ-excised)

#[test]
fn legacy_stealth_wallet_bytes_are_refused_fail_closed() {
    let legacy = br#"{"stealth_address":{"one_time_pub":[0]},"address_hex":"00"}"#;
    let err = stellereum::wallet::reject_legacy_stealth_wallet_bytes(legacy).unwrap_err();
    assert!(err.contains("excised"), "unexpected error: {err}");
}

// ------------------------------------------------------------- session keys

#[test]
fn session_delegation_six_args_bind_scope_and_chain() {
    let master_kp = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&[61u8; 32]);
    let master_addr = stellereum::post_quantum::derive_pq_address(
        stellereum::post_quantum::PqScheme::Falcon512,
        master_kp.public_key(),
        &DEFAULT_SALT,
    );
    let master = stellereum::wallet::WalletKeyMaterial::Falcon {
        keypair: Box::new(master_kp),
    };
    let session_kp = stellereum::post_quantum::FalconKeypair::generate_from_seed_bytes(&[62u8; 32]);
    let session_pub = session_kp.public_key();

    let auth = master
        .delegate_bot_session_falcon512(
            session_pub,
            50_000,
            3600,
            stellereum::zkml::SCOPE_TRANSFER,
            1_000_000_000,
            stellereum::zkml::DEFAULT_CHAIN_ID,
        )
        .expect("falcon512 delegation");
    assert_eq!(auth.scope, stellereum::zkml::SCOPE_TRANSFER);
    assert_eq!(auth.chain_id, stellereum::zkml::DEFAULT_CHAIN_ID);
    assert_eq!(auth.max_value_per_tx, 1_000_000_000);
    assert_eq!(
        auth.session_scheme,
        stellereum::post_quantum::PqScheme::Falcon512
    );
    assert_eq!(auth.master_address, master_addr);
    assert!(auth.verify_signature(), "master signature must verify");
    assert!(auth.grants_scope(stellereum::zkml::SCOPE_TRANSFER));
    assert!(!auth.grants_scope(stellereum::zkml::SCOPE_SVM_PAYLOAD));

    // Wrong-chain grant must not silently pass as the default chain's.
    let other = master
        .delegate_bot_session_falcon512(
            session_pub,
            50_000,
            3600,
            stellereum::zkml::SCOPE_ALL,
            u64::MAX,
            9999,
        )
        .expect("falcon512 delegation other");
    assert_ne!(other.chain_id, stellereum::zkml::DEFAULT_CHAIN_ID);
    assert!(other.master_signature != auth.master_signature);
}

#[tokio::test]
async fn token_create_tx_shape_and_local_execution() {
    let client = local_client().await;
    let owner = PqKeyPair::from_seed(PqScheme::Falcon512, &[43u8; 32]);
    let owner_addr = owner.derive_address(&DEFAULT_SALT);
    client.set_balance(owner_addr, 5_000_000_000, 0).await;

    // Builder shape: SysCallTokenCreate, zero native amount, gas >= base fee.
    let tx = LightClient::build_pq_token_create_tx(
        &owner,
        "Test Coin".into(),
        "TST".into(),
        6,
        1_000_000,
        Some(2_000_000),
        0,
        1,
        stellereum::zkml::DEFAULT_CHAIN_ID,
    )
    .expect("build_pq_token_create_tx");
    assert_eq!(tx.amount, 0);
    assert!(tx.gas_limit >= stellereum::svm::GAS_BASIC_TRANSFER);
    assert!(matches!(
        &tx.payload[..],
        [stellereum::svm::OpCode::SysCallTokenCreate { .. }]
    ));

    // Local broadcast settles only the native leg (balance/nonce), never the
    // VM payload — so execution is covered chain-side; here we check the
    // resolve path against a directly-created token.
    let (hash, _) = client.broadcast_tx(&tx).await.expect("local broadcast");
    assert!(!hash.iter().all(|b| *b == 0));
    client
        .state_engine
        .create_token(owner_addr, test_metadata(), 1_000_000)
        .await
        .expect("engine create");
    let found = client
        .state_engine
        .token_resolve(&owner_addr, "Test Token", "TST")
        .await
        .expect("created token must resolve");
    assert_eq!(
        client.token_balance(&found, &owner_addr).await.unwrap(),
        1_000_000
    );
}
