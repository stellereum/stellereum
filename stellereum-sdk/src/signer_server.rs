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

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::key::FalconKeypair;
use crate::signer::{sign_request, SignErrorResponse, SignRequest};

/// Maximum number of concurrent connection handler threads served by [`SignerServer`].
pub const MAX_CONCURRENT_CONNS: usize = 32;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A running signing helper.
pub struct SignerServer {
    address: String,
    handle: Option<std::thread::JoinHandle<()>>,
    #[cfg(test)]
    active_conns: Arc<AtomicUsize>,
}

impl SignerServer {
    /// Start the helper on `listener`. Returns immediately; connections are
    /// served on bounded worker threads (up to [`MAX_CONCURRENT_CONNS`]).
    pub fn start(
        listener: TcpListener,
        key: FalconKeypair,
        token: Option<String>,
    ) -> std::io::Result<Self> {
        Self::start_with_allowed_origins(listener, key, token, Vec::new())
    }

    /// Start the helper on `listener` with an explicit `Origin` allowlist.
    /// Requests carrying an `Origin` header not in `allowed_origins` are
    /// rejected with `403`.
    pub fn start_with_allowed_origins(
        listener: TcpListener,
        key: FalconKeypair,
        token: Option<String>,
        allowed_origins: Vec<String>,
    ) -> std::io::Result<Self> {
        listener.set_nonblocking(false)?;
        let addr = listener.local_addr()?;
        let key = Arc::new(key);
        let token = Arc::new(token);
        let allowed_origins = Arc::new(allowed_origins);
        let active_conns = Arc::new(AtomicUsize::new(0));
        let active_conns_loop = Arc::clone(&active_conns);
        let address = key.address_stl57();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut s) => {
                        let acquired = active_conns_loop
                            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                                if cur < MAX_CONCURRENT_CONNS {
                                    Some(cur + 1)
                                } else {
                                    None
                                }
                            })
                            .is_ok();
                        if !acquired {
                            let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
                            let _ = respond_json(
                                &mut s,
                                503,
                                &serde_json::json!({
                                    "ok": false,
                                    "error": {
                                        "code": "service_unavailable",
                                        "message": "too many concurrent connections",
                                        "retryable": true
                                    }
                                }),
                            );
                            let _ = s.shutdown(std::net::Shutdown::Write);
                            let _ = s.set_read_timeout(Some(Duration::from_millis(50)));
                            let mut drain = [0u8; 512];
                            let _ = s.read(&mut drain);
                            continue;
                        }
                        let guard = ConnGuard(Arc::clone(&active_conns_loop));
                        let key = Arc::clone(&key);
                        let token = Arc::clone(&token);
                        let allowed_origins = Arc::clone(&allowed_origins);
                        std::thread::spawn(move || {
                            let _guard = guard;
                            let _ = handle_connection(s, &key, token.as_deref(), &allowed_origins);
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
            #[cfg(test)]
            active_conns,
        })
    }

    #[cfg(test)]
    pub(crate) fn active_connections(&self) -> usize {
        self.active_conns.load(Ordering::Acquire)
    }

    /// Bind and start on `127.0.0.1:0`, returning the helper and its URL.
    pub fn bind_ephemeral(
        key: FalconKeypair,
        token: Option<String>,
    ) -> std::io::Result<(Self, String)> {
        Self::bind_ephemeral_with_allowed_origins(key, token, Vec::new())
    }

    /// Bind and start on `127.0.0.1:0` with an explicit `Origin` allowlist.
    pub fn bind_ephemeral_with_allowed_origins(
        key: FalconKeypair,
        token: Option<String>,
        allowed_origins: Vec<String>,
    ) -> std::io::Result<(Self, String)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let server = Self::start_with_allowed_origins(listener, key, token, allowed_origins)?;
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

fn read_with_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> std::io::Result<Option<usize>> {
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(None);
        };
        if remaining.is_zero() {
            return Ok(None);
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(buf) {
            Ok(n) => return Ok(Some(n)),
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn respond_timeout(stream: &mut TcpStream) -> std::io::Result<()> {
    respond_json(
        stream,
        408,
        &serde_json::json!({
            "ok": false,
            "error": {
                "code": "request_timeout",
                "message": "request deadline exceeded",
                "retryable": false
            }
        }),
    )
}

fn respond_bad_request(stream: &mut TcpStream, msg: &str) -> std::io::Result<()> {
    respond_json(
        stream,
        400,
        &serde_json::json!({
            "ok": false,
            "error": { "code": "bad_request", "message": msg, "retryable": false }
        }),
    )
}

fn parse_content_length_value(raw: &str) -> Option<usize> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<usize>().ok()
}

fn handle_connection(
    mut stream: TcpStream,
    key: &FalconKeypair,
    token: Option<&str>,
    allowed_origins: &[String],
) -> std::io::Result<()> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    stream.set_write_timeout(Some(REQUEST_DEADLINE))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let Some(n) = read_with_deadline(&mut stream, &mut tmp, deadline)? else {
            return respond_timeout(&mut stream);
        };
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEADER_BYTES {
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
    let mut content_length: Option<usize> = None;
    let mut bad_content_length = false;
    let mut has_transfer_encoding = false;
    let mut content_type: Option<String> = None;
    let mut authorization: Option<String> = None;
    let mut host: Option<String> = None;
    let mut host_count = 0usize;
    let mut origin: Option<String> = None;
    let mut origin_count = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim();
            if k == "content-length" {
                if content_length.is_some() {
                    bad_content_length = true;
                } else if let Some(parsed) = parse_content_length_value(v) {
                    content_length = Some(parsed);
                } else {
                    bad_content_length = true;
                }
            } else if k == "transfer-encoding" {
                has_transfer_encoding = true;
            } else if k == "content-type" {
                content_type = Some(v.to_string());
            } else if k == "authorization" {
                authorization = Some(v.to_string());
            } else if k == "host" {
                host_count += 1;
                host = Some(v.to_string());
            } else if k == "origin" {
                origin_count += 1;
                origin = Some(v.to_string());
            }
        }
    }

    if bad_content_length {
        return respond_bad_request(&mut stream, "malformed or duplicate Content-Length");
    }
    if has_transfer_encoding {
        return respond_bad_request(&mut stream, "Transfer-Encoding is not supported");
    }

    // DNS rebinding protection: require a single loopback Host header.
    if host_count != 1 || !host.as_deref().is_some_and(is_loopback_host) {
        return respond_json(
            &mut stream,
            403,
            &serde_json::json!({
                "ok": false,
                "error": { "code": "forbidden", "message": "non-loopback or missing Host header", "retryable": false }
            }),
        );
    }

    // CSRF / cross-origin protection: reject any Origin unless allowlisted.
    if origin_count > 1
        || origin
            .as_deref()
            .is_some_and(|orig| !allowed_origins.iter().any(|allowed| allowed == orig))
    {
        return respond_json(
            &mut stream,
            403,
            &serde_json::json!({
                "ok": false,
                "error": { "code": "forbidden", "message": "Origin header not allowed", "retryable": false }
            }),
        );
    }

    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return respond(&mut stream, 413, "text/plain", b"request too large");
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let Some(n) = read_with_deadline(&mut stream, &mut tmp, deadline)? else {
            return respond_timeout(&mut stream);
        };
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    if body.len() < content_length {
        return respond_bad_request(&mut stream, "truncated request body");
    }
    if body.len() > content_length {
        body.truncate(content_length);
    }

    match (method, path) {
        ("GET", "/health") => {
            let json = serde_json::json!({ "ok": true, "address": key.address_stl57() });
            respond_json(&mut stream, 200, &json)
        }
        ("POST", "/sign") => {
            if !content_type.as_deref().is_some_and(is_json_content_type) {
                return respond_json(
                    &mut stream,
                    415,
                    &serde_json::json!({
                        "ok": false,
                        "error": { "code": "unsupported_media_type", "message": "Content-Type must be application/json", "retryable": false }
                    }),
                );
            }
            if !check_bearer_token(authorization.as_deref(), token) {
                return respond_json(
                    &mut stream,
                    401,
                    &serde_json::json!({ "ok": false, "error": { "code": "unauthorized", "message": "missing or bad bearer token", "retryable": false } }),
                );
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
        ("POST", "/sign-digest") => {
            if !content_type.as_deref().is_some_and(is_json_content_type) {
                return respond_json(
                    &mut stream,
                    415,
                    &serde_json::json!({
                        "ok": false,
                        "error": { "code": "unsupported_media_type", "message": "Content-Type must be application/json", "retryable": false }
                    }),
                );
            }
            if !check_bearer_token(authorization.as_deref(), token) {
                return respond_json(
                    &mut stream,
                    401,
                    &serde_json::json!({ "ok": false, "error": { "code": "unauthorized", "message": "missing or bad bearer token", "retryable": false } }),
                );
            }
            let value: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => {
                    return respond_json(
                        &mut stream,
                        400,
                        &serde_json::json!({ "ok": false, "error": { "code": "bad_request", "message": e.to_string(), "retryable": false } }),
                    )
                }
            };
            let Some(digest) = value.get("digest").and_then(|v| v.as_str()) else {
                return respond_json(
                    &mut stream,
                    400,
                    &serde_json::json!({ "ok": false, "error": { "code": "bad_request", "message": "missing 'digest'", "retryable": false } }),
                );
            };
            let clean = digest.trim();
            let clean = clean.strip_prefix("0x").unwrap_or(clean);
            let bytes = match hex::decode(clean) {
                Ok(b) if b.len() == 32 => b,
                Ok(b) => {
                    return respond_json(
                        &mut stream,
                        400,
                        &serde_json::json!({ "ok": false, "error": { "code": "invalid_argument", "message": format!("digest must be 32 bytes, got {}", b.len()), "retryable": false } }),
                    )
                }
                Err(e) => {
                    return respond_json(
                        &mut stream,
                        400,
                        &serde_json::json!({ "ok": false, "error": { "code": "invalid_argument", "message": format!("digest: bad hex: {e}"), "retryable": false } }),
                    )
                }
            };
            match key.sign(&bytes) {
                Ok(signature) => respond_json(
                    &mut stream,
                    200,
                    &serde_json::json!({ "ok": true, "signature": hex::encode(signature) }),
                ),
                Err(e) => respond_json(&mut stream, 400, &SignErrorResponse::from_error(&e)),
            }
        }
        _ => respond(&mut stream, 404, "text/plain", b"not found"),
    }
}

fn is_json_content_type(ct: &str) -> bool {
    let trimmed = ct.trim();
    const PREFIX: &str = "application/json";
    if trimmed.len() < PREFIX.len() || !trimmed[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return false;
    }
    trimmed.len() == PREFIX.len() || matches!(trimmed.as_bytes()[PREFIX.len()], b';' | b' ' | b'\t')
}

fn is_loopback_host(host: &str) -> bool {
    if host.is_empty()
        || host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'@' | b'/' | b'?' | b'#'))
    {
        return false;
    }
    if let Some(after_open) = host.strip_prefix('[') {
        let Some((ip_str, rest)) = after_open.split_once(']') else {
            return false;
        };
        if !rest.is_empty() {
            let Some(port_str) = rest.strip_prefix(':') else {
                return false;
            };
            if port_str.is_empty() || port_str.parse::<u16>().is_err() {
                return false;
            }
        }
        return ip_str
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback());
    }
    let name = match host.split_once(':') {
        Some((name, port_str)) => {
            if port_str.is_empty() || port_str.parse::<u16>().is_err() {
                return false;
            }
            name
        }
        None => host,
    };
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff: u8 = if a.len() == b.len() { 0 } else { 1 };
    for (i, &expected_byte) in b.iter().enumerate() {
        let actual_byte = a.get(i).copied().unwrap_or(0);
        diff |= actual_byte ^ expected_byte;
    }
    std::hint::black_box(diff) == 0
}

fn check_bearer_token(authorization: Option<&str>, expected_token: Option<&str>) -> bool {
    let Some(expected) = expected_token else {
        return true;
    };
    authorization
        .and_then(|a| a.strip_prefix("Bearer "))
        .is_some_and(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()))
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
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        503 => "Service Unavailable",
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

    fn send_raw_http(addr: &str, raw: &str) -> (u16, String) {
        let host_port = addr.strip_prefix("http://").unwrap_or(addr);
        let mut stream = TcpStream::connect(host_port).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        let status = out
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        (status, out)
    }

    #[test]
    fn rejects_non_json_content_type_with_415() {
        let key = FalconKeypair::generate().unwrap();
        let (_server, url) = SignerServer::bind_ephemeral(key, None).unwrap();
        let host_port = url.strip_prefix("http://").unwrap();
        let body = serde_json::json!({
            "tx": {
                "kind": "transfer",
                "to": crate::address::to_hex(&[7u8; 32]),
                "amount": 1,
                "nonce": 1
            }
        })
        .to_string();

        for bad_ct in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "application/jsonp",
        ] {
            for path in ["/sign", "/sign-digest"] {
                let raw = format!(
                    "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: {bad_ct}\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let (status, _) = send_raw_http(&url, &raw);
                assert_eq!(status, 415, "expected 415 for {path} with {bad_ct}");
            }
        }

        // Missing Content-Type also yields 415.
        let raw_missing = format!(
            "POST /sign HTTP/1.1\r\nHost: {host_port}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (status, _) = send_raw_http(&url, &raw_missing);
        assert_eq!(status, 415);

        // Case-insensitive prefix with charset parameter is accepted.
        let raw_ok = format!(
            "POST /sign HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: Application/JSON; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (status, _) = send_raw_http(&url, &raw_ok);
        assert_eq!(status, 200);
    }

    #[test]
    fn rejects_origin_unless_allowlisted_and_non_loopback_host_with_403() {
        let key = FalconKeypair::generate().unwrap();
        let (_server, url) = SignerServer::bind_ephemeral_with_allowed_origins(
            key,
            None,
            vec!["https://wallet.stellereum.org".to_string()],
        )
        .unwrap();
        let host_port = url.strip_prefix("http://").unwrap();

        // Disallowed Origin -> 403
        let raw_bad_origin = format!(
            "GET /health HTTP/1.1\r\nHost: {host_port}\r\nOrigin: https://evil.example\r\n\r\n"
        );
        assert_eq!(send_raw_http(&url, &raw_bad_origin).0, 403);

        // Allowlisted Origin -> 200
        let raw_ok_origin = format!(
            "GET /health HTTP/1.1\r\nHost: {host_port}\r\nOrigin: https://wallet.stellereum.org\r\n\r\n"
        );
        assert_eq!(send_raw_http(&url, &raw_ok_origin).0, 200);

        // Non-loopback or missing Host -> 403 (DNS rebinding protection)
        for bad_host in ["evil.com:8787", "localhost.evil.com", "192.168.1.10:8787"] {
            let raw = format!("GET /health HTTP/1.1\r\nHost: {bad_host}\r\n\r\n");
            assert_eq!(send_raw_http(&url, &raw).0, 403, "host={bad_host}");
        }
        assert_eq!(send_raw_http(&url, "GET /health HTTP/1.1\r\n\r\n").0, 403);

        // Loopback Host variants -> 200
        for ok_host in [
            "localhost:8787",
            "LOCALHOST",
            "127.0.0.1:8787",
            "[::1]:8787",
        ] {
            let raw = format!("GET /health HTTP/1.1\r\nHost: {ok_host}\r\n\r\n");
            assert_eq!(send_raw_http(&url, &raw).0, 200, "host={ok_host}");
        }
    }

    #[test]
    fn bearer_token_auth_enforced_with_constant_time_check() {
        let key = FalconKeypair::generate().unwrap();
        let (_server, url) =
            SignerServer::bind_ephemeral(key, Some("s3cr3t-token".into())).unwrap();
        let req = serde_json::json!({
            "digest": format!("0x{}", "11".repeat(32))
        });

        let err = ureq::post(&format!("{url}/sign-digest"))
            .send_json(req.clone())
            .unwrap_err();
        assert_eq!(err.into_response().unwrap().status(), 401);

        let err = ureq::post(&format!("{url}/sign-digest"))
            .set("Authorization", "Bearer wrong")
            .send_json(req.clone())
            .unwrap_err();
        assert_eq!(err.into_response().unwrap().status(), 401);

        let resp: serde_json::Value = ureq::post(&format!("{url}/sign-digest"))
            .set("Authorization", "Bearer s3cr3t-token")
            .send_json(req)
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(resp["ok"], true);
    }

    #[test]
    fn rejects_malformed_overflowing_duplicate_content_length_and_chunked_with_400() {
        let key = FalconKeypair::generate().unwrap();
        let (_server, url) = SignerServer::bind_ephemeral(key, None).unwrap();
        let host_port = url.strip_prefix("http://").unwrap();

        for bad_cl in [
            "abc",
            "-1",
            "+5",
            "",
            "10, 10",
            "9999999999999999999999999999999999999999",
        ] {
            let raw = format!(
                "POST /sign HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {bad_cl}\r\n\r\n"
            );
            let (status, _) = send_raw_http(&url, &raw);
            assert_eq!(status, 400, "expected 400 for Content-Length={bad_cl:?}");
        }

        // Duplicate Content-Length (same or different values) -> 400.
        let dup_same = format!(
            "POST /sign HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        assert_eq!(send_raw_http(&url, &dup_same).0, 400);

        let dup_diff = format!(
            "POST /sign HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 5\r\n\r\n{{}}"
        );
        assert_eq!(send_raw_http(&url, &dup_diff).0, 400);

        // Transfer-Encoding: chunked -> 400.
        let chunked = format!(
            "POST /sign HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{{}}\r\n0\r\n\r\n"
        );
        assert_eq!(send_raw_http(&url, &chunked).0, 400);
    }

    #[test]
    fn returns_503_when_max_concurrent_conns_saturated() {
        let key = FalconKeypair::generate().unwrap();
        let (server, url) = SignerServer::bind_ephemeral(key, None).unwrap();
        let host_port = url.strip_prefix("http://").unwrap();

        let mut held = Vec::with_capacity(MAX_CONCURRENT_CONNS);
        for _ in 0..MAX_CONCURRENT_CONNS {
            let mut s = TcpStream::connect(host_port).unwrap();
            s.write_all(b"GET /health HTTP/1.1\r\n").unwrap();
            s.flush().unwrap();
            held.push(s);
        }

        let start = Instant::now();
        while server.active_connections() < MAX_CONCURRENT_CONNS
            && start.elapsed() < Duration::from_secs(2)
        {
            std::thread::yield_now();
        }
        assert_eq!(server.active_connections(), MAX_CONCURRENT_CONNS);

        let raw = format!("GET /health HTTP/1.1\r\nHost: {host_port}\r\n\r\n");
        let (status, _) = send_raw_http(&url, &raw);
        assert_eq!(status, 503);

        drop(held);
        let start = Instant::now();
        while server.active_connections() > 0 && start.elapsed() < Duration::from_secs(2) {
            std::thread::yield_now();
        }
        assert_eq!(server.active_connections(), 0);
    }
}
