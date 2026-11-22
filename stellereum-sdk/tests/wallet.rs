//! Wallet nonce-cache behaviour against a loopback JSON-RPC mock.
//!
//! The cache must advance only after submission and must not force another
//! `stell_getBalance` for the next transaction. It must NEVER be consulted by
//! a retry (retries resend one `SignedTx`).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stellereum_sdk::key::FalconKeypair;
use stellereum_sdk::rpc::{RetryPolicy, RpcClient};
use stellereum_sdk::wallet::Wallet;

#[derive(Default)]
struct Captured {
    methods: Vec<String>,
    nonces: Vec<u64>,
}

fn start_server() -> (String, Arc<Mutex<Captured>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Captured::default()));
    let sink = Arc::clone(&captured);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
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
            let mut body = buf[header_end..].to_vec();
            while body.len() < content_length {
                let n = stream.read(&mut tmp).unwrap_or(0);
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            let req: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let id = req["id"].clone();
            let method = req["method"].as_str().unwrap_or_default().to_string();
            let nonce = req["params"]["tx"]
                .as_str()
                .and_then(|hex| hex::decode(hex).ok())
                .map(|bytes| u64::from_le_bytes(bytes[80..88].try_into().unwrap()));
            {
                let mut c = sink.lock().unwrap();
                c.methods.push(method.clone());
                if let Some(n) = nonce {
                    c.nonces.push(n);
                }
            }
            let result = match method.as_str() {
                "stell_getBalance" => serde_json::json!({ "balance": "1000000000", "nonce": 5 }),
                "stell_baseFee" => serde_json::json!({ "base_fee": "280000" }),
                "stell_sendRawTransaction" => serde_json::json!("aabbccdd"),
                _ => serde_json::Value::Null,
            };
            let response = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result });
            let bytes = serde_json::to_vec(&response).unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&bytes);
            let _ = stream.flush();
        }
    });
    (format!("http://{addr}"), captured)
}

#[test]
fn nonce_cache_reads_once_and_advances_after_submit() {
    let (url, captured) = start_server();
    let key = FalconKeypair::generate().unwrap();
    let mut wallet = Wallet::new(key, RpcClient::new(url)).with_chain_id(5757);
    let policy = RetryPolicy {
        max_attempts: 2,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
    };

    let first = wallet.transfer([0x22u8; 32], 1).unwrap();
    assert_eq!(first.nonce(), 5);
    wallet.submit(&first, &policy).unwrap();
    assert_eq!(wallet.next_nonce().unwrap(), 6);

    let second = wallet.transfer([0x22u8; 32], 2).unwrap();
    assert_eq!(second.nonce(), 6, "the cache must supply the next nonce");
    wallet.submit(&second, &policy).unwrap();
    assert_eq!(wallet.next_nonce().unwrap(), 7);

    let c = captured.lock().unwrap();
    assert_eq!(
        c.methods
            .iter()
            .filter(|m| m.as_str() == "stell_getBalance")
            .count(),
        1,
        "nonce must be read once, not per transaction"
    );
    assert_eq!(c.nonces, vec![5, 6]);
}
