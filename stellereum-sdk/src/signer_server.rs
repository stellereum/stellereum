//! Minimal localhost HTTP signing helper.
//!
//! This exists because Falcon-512 signing is NOT available in JavaScript in
//! this repository. A dApp's TypeScript `buildAndSign` can shell out to the
//! CLI (`SubprocessFalconSigner`), or talk to this helper over loopback
//! (`HttpFalconSigner`). The helper is deliberately small and deliberately
//! local: plain HTTP, one endpoint, no key export.
//!
//! Endpoints:
//! * `GET /health` -> `{"ok":true,"address":"Stl57..."}`
//! * `POST /sign` with a [`SignRequest`](crate::signer::SignRequest) body.
//!
//! If `STELL_SDK_SIGNER_TOKEN` is set, `POST /sign` requires
//! `Authorization: Bearer <token>`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::key::FalconKeypair;
use crate::signer::{sign_request, SignErrorResponse, SignRequest};

/// A running signing helper.
pub struct SignerServer {
    address: String,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl SignerServer {
    /// Start the helper on `listener`. Returns immediately; connections are
    /// served on detached threads.
    pub fn start(
        listener: TcpListener,
        key: FalconKeypair,
        token: Option<String>,
    ) -> std::io::Result<Self> {
        listener.set_nonblocking(false)?;
        let addr = listener.local_addr()?;
        let key = Arc::new(key);
        let token = Arc::new(token);
        let address = key.address_stl57();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(s) => {
                        let key = Arc::clone(&key);
                        let token = Arc::clone(&token);
                        std::thread::spawn(move || {
                            let _ = handle_connection(s, &key, token.as_deref());
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        let _ = addr;
        Ok(Self {
            address,
            handle: Some(handle),
        })
    }

    /// Bind and start on `127.0.0.1:0`, returning the helper and its URL.
    pub fn bind_ephemeral(
        key: FalconKeypair,
        token: Option<String>,
    ) -> std::io::Result<(Self, String)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = Self::start(listener, key, token)?;
        Ok((server, format!("http://{addr}")))
    }

    /// The signer's address (`Stl57...`).
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl Drop for SignerServer {
    fn drop(&mut self) {
        // The accept loop only exits when the listener is closed; the thread
        // is detached and the process normally exits right after. There is no
        // portable way to unblock `incoming()` from here without an extra
        // shutdown socket, so dropping simply forgets the handle.
        self.handle.take();
    }
}

fn handle_connection(
    mut stream: TcpStream,
    key: &FalconKeypair,
    token: Option<&str>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            return respond(&mut stream, 413, "text/plain", b"request too large");
        }
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let mut content_length = 0usize;
    let mut authorization = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "content-length" {
                content_length = v.parse().unwrap_or(0);
            } else if k == "authorization" {
                authorization = Some(v.to_string());
            }
        }
    }
    if content_length > 1024 * 1024 {
        return respond(&mut stream, 413, "text/plain", b"request too large");
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    match (method, path) {
        ("GET", "/health") => {
            let json = serde_json::json!({ "ok": true, "address": key.address_stl57() });
            respond_json(&mut stream, 200, &json)
        }
        ("POST", "/sign") => {
            if let Some(expected) = token {
                let ok = authorization
                    .as_deref()
                    .and_then(|a| a.strip_prefix("Bearer "))
                    .is_some_and(|t| t == expected);
                if !ok {
                    return respond_json(
                        &mut stream,
                        401,
                        &serde_json::json!({ "ok": false, "error": { "code": "unauthorized", "message": "missing or bad bearer token", "retryable": false } }),
                    );
                }
            }
            let req: SignRequest = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => {
                    return respond_json(
                        &mut stream,
                        400,
                        &serde_json::json!({ "ok": false, "error": { "code": "bad_request", "message": e.to_string(), "retryable": false } }),
                    )
                }
            };
            match sign_request(key, &req) {
                Ok((_, resp)) => respond_json(&mut stream, 200, &resp),
                Err(e) => respond_json(&mut stream, 400, &SignErrorResponse::from_error(&e)),
            }
        }
        _ => respond(&mut stream, 404, "text/plain", b"not found"),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn respond_json(
    stream: &mut TcpStream,
    status: u16,
    v: &impl serde::Serialize,
) -> std::io::Result<()> {
    let body = serde_json::to_vec(v).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    respond(stream, status, "application/json", &body)
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SignRequest;

    #[test]
    fn http_sign_roundtrip() {
        let key = FalconKeypair::generate().unwrap();
        let (server, url) = SignerServer::bind_ephemeral(key.clone(), None).unwrap();
        assert_eq!(server.address(), key.address_stl57());
        let req = serde_json::json!({
            "tx": {
                "kind": "transfer",
                "to": crate::address::to_hex(&[7u8; 32]),
                "amount": 1,
                "nonce": 2
            }
        });
        let resp: serde_json::Value = ureq::post(&format!("{url}/sign"))
            .send_json(req)
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["nonce"], 2);
        let _: SignRequest = serde_json::from_value(serde_json::json!({
            "tx": {"kind": "transfer", "to": crate::address::to_hex(&[7u8; 32]), "amount": 1}
        }))
        .unwrap();
    }
}
