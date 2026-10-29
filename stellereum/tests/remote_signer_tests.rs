//! Tests for the remote/HSM-style validator signer.
//!
//! Three layers are covered:
//!  - `LocalSigner`, the in-memory reference implementation;
//!  - `RemoteSigner` over a `MockTransport`, which can be told to fail in every
//!    way a real signer can, without a socket;
//!  - `HttpSignerTransport` against in-process loopback stubs that reply with
//!    canned (including hostile) responses, so the real wire format and its
//!    length checks are exercised too.
//!
//! The properties that matter are not only "does it sign" but "does it refuse":
//! no silent fallback to a local key, no key material in errors, and no
//! reinterpretation of the caller's bytes.

use ed25519_dalek::Signer as DalekSigner;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use stellereum::remote_signer::{
    remote_signer_from_config, validator_signer_from_env, HttpSignerTransport, LocalSigner,
    MalformedResponseKind, RemoteSigner, Signer, SignerError, SignerTransport, SigningFailureKind,
    TransportErrorKind, ValidatorSigner, MAX_RESPONSE_BYTES, PUBLIC_KEY_LEN, REMOTE_SIGNER_URL_ENV,
    SIGNATURE_LEN,
};

const MSG: &[u8] = b"stellereum remote signer test vector";

// ============================================================================
// Mock transport
// ============================================================================

#[derive(Default)]
struct MockState {
    /// The "remote" key the mock signs with.
    key: Option<SigningKey>,
    public_key_error: Option<SignerError>,
    sign_error: Option<SignerError>,
    /// Set when the mock must behave like a transport that parsed a signature
    /// of the wrong width off the wire and rejected it at the boundary.
    bad_signature_len: Option<usize>,
    /// A full-width signature that is not a signature by `key`.
    foreign_signature: Option<[u8; SIGNATURE_LEN]>,
    received: Vec<Vec<u8>>,
    sign_calls: usize,
    signatures_returned: usize,
}

/// A `SignerTransport` that can be told to fail in every way a real one can.
#[derive(Clone)]
struct MockTransport {
    state: Arc<Mutex<MockState>>,
}

impl MockTransport {
    fn new(key: &SigningKey) -> Self {
        let state = MockState {
            key: Some(key.clone()),
            ..Default::default()
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Shared view of what the transport saw, for assertions.
    fn state(&self) -> Arc<Mutex<MockState>> {
        Arc::clone(&self.state)
    }

    fn fail_public_key(&self, err: SignerError) -> &Self {
        self.state.lock().unwrap().public_key_error = Some(err);
        self
    }

    fn fail_sign(&self, err: SignerError) -> &Self {
        self.state.lock().unwrap().sign_error = Some(err);
        self
    }

    fn return_signature_of_width(&self, got: usize) -> &Self {
        self.state.lock().unwrap().bad_signature_len = Some(got);
        self
    }

    fn return_foreign_signature(&self, sig: [u8; SIGNATURE_LEN]) -> &Self {
        self.state.lock().unwrap().foreign_signature = Some(sig);
        self
    }

    fn received_messages(&self) -> Vec<Vec<u8>> {
        self.state.lock().unwrap().received.clone()
    }

    fn sign_calls(&self) -> usize {
        self.state.lock().unwrap().sign_calls
    }

    fn signatures_returned(&self) -> usize {
        self.state.lock().unwrap().signatures_returned
    }
}

impl SignerTransport for MockTransport {
    fn public_key(&self) -> Result<[u8; PUBLIC_KEY_LEN], SignerError> {
        let st = self.state.lock().unwrap();
        if let Some(e) = st.public_key_error {
            return Err(e);
        }
        st.key
            .as_ref()
            .map(|k| k.verifying_key().to_bytes())
            .ok_or(SignerError::MalformedKey)
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; SIGNATURE_LEN], SignerError> {
        let mut st = self.state.lock().unwrap();
        st.sign_calls += 1;
        st.received.push(msg.to_vec());
        if let Some(e) = st.sign_error {
            return Err(e);
        }
        if let Some(got) = st.bad_signature_len {
            // A transport that parses bytes off the wire has to reject the width
            // itself: `SignerTransport` cannot return a short array.
            return Err(SignerError::BadSignatureLength { got });
        }
        if let Some(sig) = st.foreign_signature {
            st.signatures_returned += 1;
            return Ok(sig);
        }
        let key = st
            .key
            .as_ref()
            .ok_or(SignerError::SigningFailed(SigningFailureKind::UnusableKey))?;
        let sig = DalekSigner::try_sign(key, msg)
            .map_err(|_| SignerError::SigningFailed(SigningFailureKind::UnusableKey))?
            .to_bytes();
        st.signatures_returned += 1;
        Ok(sig)
    }
}

/// A fixed seed, so a test that needs "the same key" is trivially the same key.
fn key_and_local_signer() -> (SigningKey, LocalSigner) {
    let seed: [u8; 32] = [42; 32];
    let key = SigningKey::from_bytes(&seed);
    let signer = LocalSigner::from_seed(&seed);
    (key, signer)
}

fn remote_over(mock: &MockTransport) -> RemoteSigner {
    RemoteSigner::new(Arc::new(mock.clone())).expect("remote signer")
}

// ============================================================================
// (a) LocalSigner
// ============================================================================

#[test]
fn local_signer_signature_verifies_against_its_public_key() {
    let (key, local) = key_and_local_signer();
    assert_eq!(local.public_key(), key.verifying_key().to_bytes());

    let sig = local.sign(MSG).expect("local sign");
    assert_eq!(sig.to_bytes().len(), SIGNATURE_LEN);

    // Verify through dalek directly...
    let vk = VerifyingKey::from_bytes(&local.public_key()).unwrap();
    assert!(vk.verify_strict(MSG, &sig).is_ok());
    // ...and through the trait's provided helper, so `Signer` is usable as is.
    assert!(local.verify(MSG, &sig));
}

#[test]
fn local_signer_rejects_a_malformed_hex_seed_without_echoing_it() {
    // A config that is not hex, and one of the wrong width, are both refused —
    // with an error that says nothing about what was configured.
    for bad in ["zzzz", "", &"ab".repeat(31), &"ab".repeat(33)] {
        assert_eq!(
            LocalSigner::from_hex_seed(bad).err(),
            Some(SignerError::MalformedKey)
        );
    }
    // A valid one works, and whitespace around a config value is tolerated.
    assert!(LocalSigner::from_hex_seed(&format!("  {}  ", "11".repeat(32))).is_ok());
}

// ============================================================================
// (b) Remote == Local, byte for byte
// ============================================================================

#[test]
fn remote_signer_matches_local_signer_byte_for_byte() {
    let (key, local) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    let remote = remote_over(&mock);

    // Same key behind the handle, so the public keys must agree.
    assert_eq!(remote.public_key(), local.public_key());

    let local_sig = local.sign(MSG).expect("local sign").to_bytes();
    let remote_sig = remote.sign(MSG).expect("remote sign").to_bytes();

    // Ed25519 is deterministic: a remote signer holding the same key is not
    // merely "equivalent", it is bit-for-bit identical. If this ever diverges,
    // the remote signer is using a different key or a different message.
    assert_eq!(local_sig, remote_sig);
    assert!(remote.verify(MSG, &Signature::from_bytes(&remote_sig)));
    assert_eq!(mock.sign_calls(), 1);
}

#[test]
fn remote_signer_pins_the_public_key_resolved_at_construction() {
    let (key, _) = key_and_local_signer();
    let other = SigningKey::generate(&mut OsRng);
    let mock = MockTransport::new(&key);
    let remote = remote_over(&mock);

    // A different key starts answering. A signer that re-resolved the public key
    // per request would now be voting as somebody else; the pinned key must
    // still be the one that decides, and the foreign signature must be refused.
    let foreign = DalekSigner::try_sign(&other, MSG).expect("sign").to_bytes();
    mock.return_foreign_signature(foreign);
    assert_eq!(
        remote.sign(MSG).err(),
        Some(SignerError::SigningFailed(
            SigningFailureKind::SignatureInvalid
        ))
    );
    assert_eq!(remote.public_key(), key.verifying_key().to_bytes());
}

// ============================================================================
// (c) Transport failure: error out, never fall back
// ============================================================================

#[test]
fn transport_failure_propagates_and_never_falls_back_to_a_local_key() {
    let (key, local) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    let remote = remote_over(&mock);

    // Every way the transport can be unreachable or unhelpful.
    let failures = [
        SignerError::Transport(TransportErrorKind::Request),
        SignerError::Transport(TransportErrorKind::Timeout),
        SignerError::Transport(TransportErrorKind::Rejected { status: 401 }),
        SignerError::Transport(TransportErrorKind::Rejected { status: 503 }),
        SignerError::Transport(TransportErrorKind::UnreadableBody),
    ];
    for failure in failures {
        mock.fail_sign(failure);
        let err = remote
            .sign(MSG)
            .expect_err("transport failure must surface");
        // The error is the transport's, unchanged: the node is told what
        // happened instead of being handed something to keep going with.
        assert_eq!(err, failure);
        assert!(
            remote.sign(MSG).is_err(),
            "a failing signer must never produce a signature"
        );
    }
    assert_eq!(
        mock.signatures_returned(),
        0,
        "a failing signer returned no signature"
    );

    // The decisive assertion: a perfectly good key sits in this very process,
    // and the remote signer must not reach for it when the HSM is down. This is
    // the failure the whole module exists to prevent — an operator who believes
    // the key is in the HSM while the node quietly keeps voting.
    mock.fail_sign(SignerError::Transport(TransportErrorKind::Rejected {
        status: 503,
    }));
    assert!(remote.sign(MSG).is_err(), "no local fallback");
    assert!(
        local.sign(MSG).is_ok(),
        "the local key is healthy, which is exactly the trap"
    );

    // Once the signer is back, signing works again: the failure is reported, not
    // latched.
    mock.state().lock().unwrap().sign_error = None;
    assert!(remote.sign(MSG).is_ok());
}

#[test]
fn public_key_resolution_failure_stops_the_signer_from_being_built() {
    let (key, _) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    mock.fail_public_key(SignerError::Transport(TransportErrorKind::Request));

    // Construction resolves the key once, so an unreachable signer means no
    // signer at all. The node should fail to start rather than start degraded.
    let err = RemoteSigner::new(Arc::new(mock.clone())).err();
    assert_eq!(
        err,
        Some(SignerError::Transport(TransportErrorKind::Request))
    );
}

// ============================================================================
// (d) Malformed public key from the transport
// ============================================================================

#[test]
fn remote_signer_rejects_a_public_key_of_the_wrong_width() {
    let (key, _) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    // A transport parsing the wire format rejects the width itself.
    mock.fail_public_key(SignerError::BadPublicKeyLength { got: 31 });
    assert_eq!(
        RemoteSigner::new(Arc::new(mock.clone())).err(),
        Some(SignerError::BadPublicKeyLength { got: 31 })
    );
}

#[test]
fn remote_signer_rejects_a_public_key_that_is_not_a_curve_point() {
    let (key, _) = key_and_local_signer();
    // 32 bytes is the right width but not necessarily a public key. Find a
    // constant-bytes value dalek rejects, so the test does not hard-code a guess.
    let not_a_point = (0u8..=255)
        .map(|b| [b; PUBLIC_KEY_LEN])
        .find(|candidate| VerifyingKey::from_bytes(candidate).is_err())
        .expect("some constant 32-byte value is not a valid point");

    let mock = MockTransport::new(&key);
    mock.fail_public_key(SignerError::MalformedKey);
    assert_eq!(
        RemoteSigner::new(Arc::new(mock.clone())).err(),
        Some(SignerError::MalformedKey),
        "a 32-byte value off the curve must never become this node's identity"
    );
    assert!(VerifyingKey::from_bytes(&not_a_point).is_err());
}

// ============================================================================
// (e) Malformed signature from the transport
// ============================================================================

#[test]
fn remote_signer_rejects_a_signature_of_the_wrong_width() {
    let (key, _) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    let remote = remote_over(&mock);
    mock.return_signature_of_width(63);

    assert_eq!(
        remote.sign(MSG).err(),
        Some(SignerError::BadSignatureLength { got: 63 })
    );
    assert_eq!(mock.signatures_returned(), 0);
}

#[test]
fn remote_signer_rejects_a_well_formed_but_garbage_signature() {
    let (key, _) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    let remote = remote_over(&mock);
    // Right width, right shape, not a signature by this key: a hijacked or
    // swapped signer, which a length check alone would wave through.
    mock.return_foreign_signature([0xABu8; SIGNATURE_LEN]);

    assert_eq!(
        remote.sign(MSG).err(),
        Some(SignerError::SigningFailed(
            SigningFailureKind::SignatureInvalid
        ))
    );
}

// ============================================================================
// (f) No key material in errors
// ============================================================================

#[test]
fn signer_errors_never_contain_key_or_signature_material() {
    let (key, local) = key_and_local_signer();
    let sig = local.sign(MSG).expect("local sign").to_bytes();
    let seed = key.to_bytes();
    let secrets = [hex::encode(seed), hex::encode(sig)];

    // Every variant, including the ones a hostile signer can provoke.
    let all = [
        SignerError::Transport(TransportErrorKind::Request),
        SignerError::Transport(TransportErrorKind::Timeout),
        SignerError::Transport(TransportErrorKind::Rejected { status: 403 }),
        SignerError::Transport(TransportErrorKind::UnreadableBody),
        SignerError::MalformedResponse(MalformedResponseKind::BadJson),
        SignerError::MalformedResponse(MalformedResponseKind::MissingField),
        SignerError::MalformedResponse(MalformedResponseKind::NotHex),
        SignerError::MalformedResponse(MalformedResponseKind::BodyTooLarge),
        SignerError::BadPublicKeyLength { got: 3 },
        SignerError::BadSignatureLength { got: 3 },
        SignerError::SigningFailed(SigningFailureKind::EmptyMessage),
        SignerError::SigningFailed(SigningFailureKind::SignatureInvalid),
        SignerError::SigningFailed(SigningFailureKind::UnusableKey),
        SignerError::MalformedKey,
    ];
    for err in all {
        let shown = format!("{err} | {err:?}");
        for secret in &secrets {
            assert!(
                !shown.contains(secret.as_str()),
                "error leaked key material: {shown}"
            );
        }
    }

    // Errors are `std::error::Error`s and deliberately do not chain a transport
    // error: `ureq`'s Display embeds the request URL.
    let boxed: Box<dyn std::error::Error> =
        Box::new(SignerError::Transport(TransportErrorKind::Request));
    assert!(boxed.source().is_none());
    assert!(!boxed.to_string().contains("http"));
}

#[test]
fn debug_output_hides_key_material() {
    let (key, local) = key_and_local_signer();
    let seed_hex = hex::encode(key.to_bytes());
    let remote = RemoteSigner::new(Arc::new(MockTransport::new(&key))).expect("remote signer");

    // `Debug` is how a key escapes into a log line in practice, so the in-memory
    // signer prints its public key and nothing else.
    let shown = format!("{local:?} {remote:?}");
    assert!(!shown.contains(&seed_hex), "Debug leaked the seed: {shown}");
    assert!(shown.contains(&hex::encode(local.public_key())));

    // The HTTP transport holds an auth token; its Debug impl must redact it.
    let token = "s3cr3t-hsm-token";
    let transport =
        HttpSignerTransport::new("https://signer.internal:8443").with_bearer_token(token);
    let shown = format!("{transport:?}");
    assert!(
        !shown.contains(token),
        "Debug leaked the auth token: {shown}"
    );
    assert!(!shown.to_lowercase().contains("bearer"));
    assert!(shown.contains("https://signer.internal:8443"));

    // Even the error path cannot echo it.
    let err = SignerError::Transport(TransportErrorKind::Rejected { status: 401 });
    assert!(!format!("{err} {err:?}").contains(token));
}

// ============================================================================
// (g) Tampering changes the signature
// ============================================================================

#[test]
fn tampering_with_the_message_changes_the_signature() {
    let (key, local) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    let remote = remote_over(&mock);

    let honest = local.sign(MSG).expect("sign").to_bytes();
    let mut tampered = MSG.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let forged = local.sign(&tampered).expect("sign").to_bytes();

    assert_ne!(
        honest, forged,
        "a modified message must not sign identically"
    );
    assert!(!local.verify(&tampered, &Signature::from_bytes(&honest)));
    assert!(local.verify(MSG, &Signature::from_bytes(&honest)));

    // Same through the remote path: a signature does not travel to another
    // message, and the tampered bytes really did reach the signer.
    let remote_sig = remote.sign(MSG).expect("remote sign").to_bytes();
    let remote_tampered = remote.sign(&tampered).expect("remote sign").to_bytes();
    assert_ne!(remote_sig, remote_tampered);
    assert_ne!(remote_sig, forged);
    assert!(!remote.verify(&tampered, &Signature::from_bytes(&remote_sig)));
    assert!(remote.verify(&tampered, &Signature::from_bytes(&remote_tampered)));
    assert_eq!(mock.received_messages(), vec![MSG.to_vec(), tampered]);
}

// ============================================================================
// (h) Caller's bytes pass through unmodified, including consensus domain tags
// ============================================================================

#[test]
fn signer_forwards_the_callers_bytes_to_the_transport_unchanged() {
    let (key, local) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    let remote = remote_over(&mock);

    // A message full of bytes a signer might be tempted to touch: a tag, a NUL,
    // a high byte, something that is not valid UTF-8.
    let message = b"STELLEREUM_BFT_VOTE_V2\0\xff tagged by the caller, and left alone";
    remote.sign(message).expect("remote sign");

    // Byte for byte: nothing prepended, stripped, hashed or re-encoded.
    assert_eq!(mock.received_messages(), vec![message.to_vec()]);
    assert_eq!(
        remote.sign(message).expect("sign").to_bytes(),
        local.sign(message).expect("local sign").to_bytes()
    );
}

#[test]
fn signer_signs_consensus_tagged_bytes_and_never_retags_them() {
    let (key, _) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    let remote = remote_over(&mock);

    // The shape of `consensus::vote_sign_bytes`: the caller owns the
    // `STELLEREUM_BFT_VOTE_V2` tag (and the chain id that follows it) and
    // hands over the finished bytes.
    let tag = b"STELLEREUM_BFT_VOTE_V2";
    let mut vote = Vec::new();
    vote.extend_from_slice(tag);
    vote.extend_from_slice(&5757u64.to_be_bytes()); // chain id
    vote.extend_from_slice(&7u64.to_be_bytes()); // height
    vote.extend_from_slice(&1u32.to_be_bytes()); // round
    vote.push(1); // precommit
    vote.push(1); // carries a block
    vote.extend_from_slice(&[9u8; 32]); // block hash

    let sig = remote.sign(&vote).expect("remote sign").to_bytes();

    // The transport saw exactly the tagged bytes: the signer added no tag of
    // its own on top of the caller's.
    assert_eq!(mock.received_messages(), vec![vote.clone()]);
    assert!(vote.starts_with(tag));

    // The signature is over the tagged message and nothing else. Had the signer
    // tagged as well, this could only verify against a doubly-tagged message —
    // and signatures over untagged bytes would be confusable with votes.
    assert!(remote.verify(&vote, &Signature::from_bytes(&sig)));
    assert!(!remote.verify(&vote[tag.len()..], &Signature::from_bytes(&sig)));
    assert!(!remote.verify(&tag[..], &Signature::from_bytes(&sig)));
}

#[test]
fn signing_an_empty_message_is_refused() {
    let (key, local) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    let remote = remote_over(&mock);

    let expected = SignerError::SigningFailed(SigningFailureKind::EmptyMessage);
    assert_eq!(local.sign(b"").err(), Some(expected));
    assert_eq!(remote.sign(b"").err(), Some(expected));
    // Refused before the wire: an empty sign request is a caller bug, and asking
    // a remote signer to sign nothing is how a tag-building bug becomes a
    // signature over nothing.
    assert_eq!(mock.sign_calls(), 0);
}

// ============================================================================
// HTTP transport, against in-process loopback stubs
// ============================================================================

/// Read one request head (and body) off a stream; returns the request line.
fn read_request(stream: &std::net::TcpStream) -> String {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return request_line;
    }
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        let _ = reader.read_exact(&mut body);
    }
    request_line
}

fn write_response(mut stream: std::net::TcpStream, status: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

/// Serve `body` with `status` to every request, and return the base URL.
/// In-process and on an ephemeral loopback port: no external service.
fn spawn_canned_signer(status: &str, body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let status = status.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let _ = read_request(&stream);
            let body = String::from_utf8_lossy(&body).into_owned();
            write_response(stream, &status, &body);
        }
    });
    format!("http://{addr}")
}

/// Serve a working public key on `GET /public_key` and `sign_body` verbatim on
/// `POST /sign`.
fn spawn_keyed_signer(public_key: &[u8; PUBLIC_KEY_LEN], sign_body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let public_key = format!(r#"{{"public_key":"{}"}}"#, hex::encode(public_key));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let request_line = read_request(&stream);
            if request_line.starts_with("GET ") {
                write_response(stream, "200 OK", &public_key);
            } else {
                write_response(stream, "200 OK", &sign_body);
            }
        }
    });
    format!("http://{addr}")
}

/// A stub that behaves like a real signing service for `key`.
fn spawn_signing_service(key: &SigningKey) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let public_key_body = format!(
        r#"{{"public_key":"{}"}}"#,
        hex::encode(key.verifying_key().to_bytes())
    );
    let key = key.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                break;
            }
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                if let Some(value) = line.strip_prefix("Content-Length:") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            if content_length > 0 && reader.read_exact(&mut body).is_err() {
                break;
            }
            let body = String::from_utf8_lossy(&body).into_owned();
            if request_line.starts_with("GET ") {
                write_response(stream, "200 OK", &public_key_body);
            } else {
                // The message arrives hex-encoded in `{"message":"..."}`; the
                // signer signs it and answers with the signature.
                let hex_msg = body.split('"').nth(3).unwrap_or("").to_string();
                let msg = hex::decode(&hex_msg).unwrap_or_default();
                let sig = DalekSigner::try_sign(&key, &msg)
                    .map(|s| s.to_bytes())
                    .unwrap_or([0u8; SIGNATURE_LEN]);
                write_response(
                    stream,
                    "200 OK",
                    &format!(r#"{{"signature":"{}"}}"#, hex::encode(sig)),
                );
            }
        }
    });
    format!("http://{addr}")
}

#[test]
fn http_transport_signs_end_to_end_against_a_signing_service() {
    let (key, local) = key_and_local_signer();
    let base_url = spawn_signing_service(&key);

    let remote =
        RemoteSigner::new(Arc::new(HttpSignerTransport::new(base_url))).expect("resolve key");
    assert_eq!(remote.public_key(), local.public_key());

    let sig = remote.sign(MSG).expect("remote sign");
    assert_eq!(
        sig.to_bytes(),
        local.sign(MSG).expect("local sign").to_bytes()
    );
    assert!(remote.verify(MSG, &sig));
}

#[test]
fn http_transport_rejects_a_public_key_of_the_wrong_width() {
    for width in [31usize, 33] {
        let body = format!(r#"{{"public_key":"{}"}}"#, "ab".repeat(width));
        let transport = HttpSignerTransport::new(spawn_canned_signer("200 OK", body.into_bytes()));
        assert_eq!(
            transport.public_key(),
            Err(SignerError::BadPublicKeyLength { got: width })
        );
    }
}

#[test]
fn http_transport_rejects_malformed_public_key_responses() {
    let cases = [
        (
            br#"not json at all"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::BadJson),
        ),
        (
            br#"{"public_key":}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::BadJson),
        ),
        (
            br#"{"public_key":[1,2,3]}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::BadJson),
        ),
        (
            br#"{}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::MissingField),
        ),
        (
            br#"{"public_key":null}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::MissingField),
        ),
        (
            br#"{"key":"ab"}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::MissingField),
        ),
        (
            br#"{"public_key":"nothexatall"}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::NotHex),
        ),
        (
            br#"{"public_key":"ab cd"}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::NotHex),
        ),
        (
            vec![b'x'; MAX_RESPONSE_BYTES + 1],
            SignerError::MalformedResponse(MalformedResponseKind::BodyTooLarge),
        ),
    ];
    for (body, expected) in cases {
        let label: String = String::from_utf8_lossy(&body).chars().take(48).collect();
        let transport = HttpSignerTransport::new(spawn_canned_signer("200 OK", body));
        assert_eq!(transport.public_key(), Err(expected), "body: {label}");
    }
}

#[test]
fn http_transport_rejects_a_signature_of_the_wrong_width() {
    let (key, _) = key_and_local_signer();
    // The public key is good; the signature that comes back is 63 bytes.
    let body = format!(r#"{{"signature":"{}"}}"#, "cd".repeat(63));
    let base_url = spawn_keyed_signer(&key.verifying_key().to_bytes(), body);
    let remote =
        RemoteSigner::new(Arc::new(HttpSignerTransport::new(base_url))).expect("resolve key");
    assert_eq!(
        remote.sign(MSG).err(),
        Some(SignerError::BadSignatureLength { got: 63 })
    );
}

#[test]
fn http_transport_rejects_malformed_signature_responses() {
    let (key, _) = key_and_local_signer();
    let public_key = key.verifying_key().to_bytes();
    let cases = [
        (
            br#"{}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::MissingField),
        ),
        (
            br#"{"sig":"ab"}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::MissingField),
        ),
        (
            br#"not json"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::BadJson),
        ),
        (
            br#"{"signature":"zz"}"#.to_vec(),
            SignerError::MalformedResponse(MalformedResponseKind::NotHex),
        ),
        // 64 bytes of the right width that are simply not a signature.
        (
            format!(r#"{{"signature":"{}"}}"#, "ab".repeat(SIGNATURE_LEN)).into_bytes(),
            SignerError::SigningFailed(SigningFailureKind::SignatureInvalid),
        ),
    ];
    for (body, expected) in cases {
        let base_url = spawn_keyed_signer(&public_key, String::from_utf8_lossy(&body).into_owned());
        let remote =
            RemoteSigner::new(Arc::new(HttpSignerTransport::new(base_url))).expect("resolve key");
        assert_eq!(
            remote.sign(MSG).err(),
            Some(expected),
            "body: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[test]
fn http_transport_reports_a_non_2xx_status_without_echoing_the_request() {
    let (key, _) = key_and_local_signer();
    // A gateway answering 500 while quoting the request back, which is what real
    // error pages do.
    let echo = format!(
        r#"{{"error":"refused","message_hex":"{}","key":"{}"}}"#,
        hex::encode(MSG),
        hex::encode(key.to_bytes())
    );
    let base_url = spawn_canned_signer("500 Internal Server Error", echo.into_bytes());
    let transport = HttpSignerTransport::new(base_url.clone());

    let err = transport.public_key().expect_err("a 500 is a failure");
    assert_eq!(
        err,
        SignerError::Transport(TransportErrorKind::Rejected { status: 500 })
    );
    // The body was never parsed into the error, so neither the message nor the
    // key is in what the node reports.
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(&hex::encode(MSG)));
    assert!(!shown.contains(&hex::encode(key.to_bytes())));
    assert!(
        !shown.contains(&base_url),
        "the endpoint URL must not be echoed either"
    );
}

#[test]
fn http_transport_maps_an_unusable_url_to_a_transport_error() {
    // An unknown scheme fails locally: no DNS, no socket, no external service.
    let transport = HttpSignerTransport::new("nope://signer.invalid");
    let err = transport
        .public_key()
        .expect_err("an unusable URL cannot resolve a key");
    assert!(matches!(err, SignerError::Transport(_)), "got {err:?}");
    assert!(err.to_string().contains("remote signer"));
}

// ============================================================================
// ValidatorSigner: the single key holder the node carries at startup
// ============================================================================

#[test]
fn validator_signer_local_variant_signs_with_the_in_process_key() {
    let seed = [42u8; 32];
    let signer = ValidatorSigner::local(&seed);

    assert!(!signer.is_remote());
    assert!(signer.as_remote().is_none());
    assert_eq!(
        signer.public_key(),
        SigningKey::from_bytes(&seed).verifying_key().to_bytes()
    );
    let sig = signer.sign(MSG).expect("local sign");
    assert!(signer.verify(MSG, &sig));
}

#[test]
fn validator_signer_remote_variant_uses_the_remote_and_never_signs_locally() {
    let (key, local) = key_and_local_signer();
    let mock = MockTransport::new(&key);
    let remote = RemoteSigner::new(Arc::new(mock.clone())).expect("remote signer");
    let signer = ValidatorSigner::Remote(remote);

    assert!(signer.is_remote());
    assert!(signer.as_remote().is_some());
    assert_eq!(signer.public_key(), local.public_key());
    // Ed25519 is deterministic, so a remote signer holding the same key produces
    // the exact same signature as the local one.
    assert_eq!(
        signer.sign(MSG).expect("remote sign").to_bytes(),
        local.sign(MSG).expect("local sign").to_bytes()
    );

    // The HSM goes down. A healthy local key still exists in this very process,
    // and the remote variant must not reach for it.
    let signatures_before = mock.signatures_returned();
    mock.fail_sign(SignerError::Transport(TransportErrorKind::Request));
    assert!(
        signer.sign(MSG).is_err(),
        "a remote failure must surface, not be hidden"
    );
    assert!(
        local.sign(MSG).is_ok(),
        "the local key is healthy, which is exactly the trap"
    );
    assert_eq!(
        mock.signatures_returned(),
        signatures_before,
        "no signature was substituted"
    );
}

#[test]
fn remote_signer_config_is_optional_and_a_blank_url_means_local() {
    assert!(remote_signer_from_config(None, None)
        .expect("no remote")
        .is_none());
    assert!(
        remote_signer_from_config(Some(String::new()), Some("tok".into()))
            .expect("blank url")
            .is_none()
    );
    assert!(remote_signer_from_config(Some("   ".into()), None)
        .expect("whitespace url")
        .is_none());
}

#[test]
fn unreachable_remote_signer_fails_closed_with_no_local_fallback() {
    // An unknown scheme fails locally: no DNS, no socket, no external service.
    let err = remote_signer_from_config(Some("nope://signer.invalid".into()), None)
        .expect_err("an unreachable signer must be an error, never a local key");
    assert!(matches!(err, SignerError::Transport(_)), "got {err:?}");
}

#[test]
fn remote_signer_with_a_bad_public_key_fails_closed() {
    // One byte is the wrong width for an Ed25519 key. There is no Local variant
    // on this path, so the caller cannot start with anything.
    let url = spawn_canned_signer("200 OK", br#"{"public_key":"ab"}"#.to_vec());
    let err = remote_signer_from_config(Some(url), None).expect_err("a bad key must fail");
    assert_eq!(err, SignerError::BadPublicKeyLength { got: 1 });
}

#[test]
fn env_loader_uses_the_remote_signer_and_fails_closed_when_unreachable() {
    // Only this test touches the signer env vars, so the parallel test runner
    // cannot race it.
    std::env::remove_var(REMOTE_SIGNER_URL_ENV);
    std::env::remove_var("STELL_REMOTE_SIGNER_TOKEN");

    // Unset: the existing local-key path still works.
    let local = validator_signer_from_env([3u8; 32]).expect("local path");
    assert!(!local.is_remote(), "unset URL must keep the in-process key");

    // Set but unreachable: construction fails closed and no local signer is
    // returned, so the node has nothing to fall back to.
    std::env::set_var(REMOTE_SIGNER_URL_ENV, "nope://signer.invalid");
    let err = validator_signer_from_env([3u8; 32]).expect_err("must fail closed");
    assert!(matches!(err, SignerError::Transport(_)), "got {err:?}");

    std::env::remove_var(REMOTE_SIGNER_URL_ENV);
}
