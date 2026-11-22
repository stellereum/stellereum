//! Submission retry semantics.
//!
//! The critical property is that a retry resends the EXACT same signed bytes:
//! same nonce, same signature, same transaction hash. These tests run a real
//! HTTP server on loopback and compare every captured request body.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stellereum_sdk::key::FalconKeypair;
use stellereum_sdk::rpc::{RetryPolicy, RpcClient};
use stellereum_sdk::tx::{SignedTx, TxBuilder};

struct MockServer {
    url: String,
    bodies: Arc<Mutex<Vec<String>>>,
}

impl MockServer {
    fn start(responses: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&bodies);
        std::thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let header_end = loop {
                    let n = stream.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break None;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(p + 4);
                    }
                };
                let Some(header_end) = header_end else {
                    continue;
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_length = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            v.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);
                let mut req_body = buf[header_end..].to_vec();
                while req_body.len() < content_length {
                    let n = stream.read(&mut tmp).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    req_body.extend_from_slice(&tmp[..n]);
                }
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&req_body).to_string());
                let reason = if status == 200 { "OK" } else { "Server Error" };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
                let _ = stream.flush();
            }
        });
        Self {
            url: format!("http://{addr}"),
            bodies,
        }
    }
}

fn signed() -> SignedTx {
    let key = FalconKeypair::generate().unwrap();
    TxBuilder::transfer([0x42u8; 32], 777)
        .nonce(11)
        .sign(&key)
        .unwrap()
}

fn tx_hex_from_request(body: &str) -> (String, u64) {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(v["method"], "stell_sendRawTransaction");
    assert_eq!(v["jsonrpc"], "2.0");
    let hex = v["params"]["tx"].as_str().unwrap().to_string();
    // Decode just the fixed prefix enough to read the nonce.
    let bytes = hex::decode(&hex).unwrap();
    let nonce = u64::from_le_bytes(bytes[80..88].try_into().unwrap());
    (hex, nonce)
}

#[test]
fn retry_resends_identical_bytes_and_never_changes_nonce() {
    let signed = signed();
    let hash = signed.tx_hash_hex();
    let server = MockServer::start(vec![
        (500, "temporary".into()),
        (500, "temporary".into()),
        (
            200,
            format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{hash}"}}"#),
        ),
    ]);
    let client = RpcClient::new(&server.url);
    let policy = RetryPolicy {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
    };
    let out = client.send_with_retry(&signed, &policy).unwrap();
    assert_eq!(out.tx_hash, hash);
    assert_eq!(out.attempts, 3);
    assert!(!out.already_in_mempool);

    let bodies = server.bodies.lock().unwrap();
    assert_eq!(bodies.len(), 3, "all three attempts must reach the server");
    let (first_hex, first_nonce) = tx_hex_from_request(&bodies[0]);
    assert_eq!(first_hex, signed.to_hex());
    assert_eq!(first_nonce, 11);
    for body in bodies.iter() {
        let (hex, nonce) = tx_hex_from_request(body);
        assert_eq!(hex, first_hex, "retry changed the signed bytes");
        assert_eq!(nonce, first_nonce, "retry changed the nonce");
    }
}

#[test]
fn duplicate_is_success_and_is_not_resigned() {
    let signed = signed();
    let server = MockServer::start(vec![(
        200,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"rejected: transaction already in mempool"}}"#.into(),
    )]);
    let client = RpcClient::new(&server.url);
    let out = client
        .send_with_retry(&signed, &RetryPolicy::default())
        .unwrap();
    assert!(out.already_in_mempool);
    assert_eq!(out.attempts, 1);
    assert_eq!(out.tx_hash, signed.tx_hash_hex());
    let bodies = server.bodies.lock().unwrap();
    assert_eq!(bodies.len(), 1);
    let (hex, nonce) = tx_hex_from_request(&bodies[0]);
    assert_eq!(hex, signed.to_hex());
    assert_eq!(nonce, 11);
}

#[test]
fn non_retryable_rejection_is_returned_immediately() {
    let signed = signed();
    let server = MockServer::start(vec![(
        200,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"rejected: offered fee is below the base fee"}}"#.into(),
    )]);
    let client = RpcClient::new(&server.url);
    let err = client
        .send_with_retry(&signed, &RetryPolicy::default())
        .unwrap_err();
    assert!(!err.is_retryable());
    assert_eq!(server.bodies.lock().unwrap().len(), 1);
}
