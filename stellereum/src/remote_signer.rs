//! Remote / HSM-style signing for validator keys.
//!
//! A validator's Ed25519 key is the root of its authority: it signs every BFT
//! vote, so whoever holds it can forge that validator's votes and, with 1/3 of
//! the stake, finalise arbitrary blocks. [`LocalSigner`] keeps that key in the
//! process as a `SigningKey` — a plaintext seed in the node's heap, readable in
//! a core dump, a crash report or a swap file. [`RemoteSigner`] instead holds a
//! *handle*: the key lives in an HSM, a KMS or a remote signing service, and the
//! node only ever learns the public key and sends bytes to be signed.
//!
//! # What is in here
//!
//! - [`Signer`] — the interface consensus code needs: [`Signer::public_key`] and
//!   [`Signer::sign`]. Object-safe, so `Arc<dyn Signer>` can hold either kind.
//! - [`LocalSigner`] — reference implementation, key in memory. Also the oracle
//!   the remote path is tested against.
//! - [`SignerTransport`] — the seam between a [`RemoteSigner`] and the outside
//!   world, so remote signing is testable without a network.
//! - [`HttpSignerTransport`] — JSON-over-HTTP client (built on the existing
//!   `ureq` dependency) with a timeout, a response size cap, no redirect
//!   following and no proxy auto-discovery.
//! - [`SignerError`] — a closed set of failure classes. It carries **no** key
//!   material and no raw transport strings, by construction (see below).
//!
//! # Rules this module enforces
//!
//! 1. **No local fallback, ever.** If the remote signer is unreachable,
//!    misconfigured or refuses, [`RemoteSigner::sign`] returns `Err`. There is
//!    no code path that falls back to a key in the node. A silent fallback is
//!    the classic way a remote-signer rollout fails: the operator believes the
//!    key is in the HSM while the node quietly keeps producing blocks with a
//!    key that is in its heap. The failure must be loud, and the node should
//!    stop voting.
//! 2. **No secrets in errors, logs or `Debug`.** [`SignerError`] variants hold
//!    only enums and lengths, so a seed, a token or a signature cannot be
//!    smuggled into a log line through an error. [`HttpSignerTransport`] holds
//!    an optional auth header and redacts it in its `Debug` impl. Raw transport
//!    error strings and raw response bodies are never copied into a
//!    [`SignerError`]: `ureq`'s `Display`/`Debug` embed the request URL, and a
//!    signer's error document can echo the request — which is the message being
//!    signed. Only the failure *class* and the HTTP status are kept.
//! 3. **Byte-exact signing; no domain separation of our own.** See below.
//! 4. **Pinned public key.** [`RemoteSigner`] resolves the signer's public key
//!    once, at construction, checks it is 32 bytes and a valid curve point, and
//!    then verifies every returned signature against that pinned key. A signer
//!    that returns a well-formed but foreign signature is rejected rather than
//!    handed to consensus.
//!
//! # Domain separation is the caller's job
//!
//! The signer signs **the caller's bytes, verbatim**. It never prepends,
//! appends, hashes, re-encodes or otherwise transforms the message.
//!
//! The consensus domain tags — e.g. `STELLEREUM_BFT_VOTE_V3` in
//! `consensus::vote_sign_bytes` — are applied by the *caller* before the bytes
//! reach a signer. This is deliberate. If a signer added a tag of its own, two
//! tag schemes would meet on the same key: the signatures simply would not
//! verify if both tagged, and worse, if only one tagged, a signature over
//! untagged bytes (say a transaction) would verify as a tagged message, and
//! the two domains would be confusable. Exactly one component owns the tag, and
//! it is the component that knows what the message means.
//!
//! Callers that sign consensus messages must therefore build the tagged bytes
//! first ([`Vote::sign`](crate::consensus::Vote::sign) does) and pass them
//! straight through.
//!
//! # This module does NOT by itself give HSM-grade protection
//!
//! Moving the key out of the process removes it from the node's memory, which
//! is necessary but not sufficient. An operator still has to:
//!
//! - **Authenticate and encrypt the link to the signer.** The bearer token in
//!   [`HttpSignerTransport::with_bearer_token`] is a convenience, not a
//!   defence: put the signer on a linkback interface or a dedicated network
//!   segment, require mutual TLS (a PKI-issued client certificate the node
//!   cannot export, so a stolen config file is not enough), and enable
//!   [`HttpSignerTransport::https_only`] unless the signer is on loopback.
//! - **Restrict what the signer will sign.** The remote signer should be
//!   enrolled for exactly this key with a policy that refuses anything but
//!   consensus vote messages; otherwise a compromised node can still use it as
//!   a signing oracle for arbitrary messages.
//! - **Fail closed on outages.** Configure the node so that a signer that is
//!   unreachable stops it from voting and producing blocks (see rule 1) rather
//!   than degrading to something else.
//! - **Pin the signer's identity out of band.** [`RemoteSigner`] pins the
//!   *public key* it resolved at startup, but the operator should check the
//!   configured endpoint against what they provisioned, or the node will pin
//!   whatever answered.
//! - **Protect the handle.** The URL and the token are still on disk in the
//!   node's config; keep them out of shell history and CI logs, and make the
//!   key handle non-exportable on the signer side.
//! - **Disable core dumps / swap on the node** if the plaintext key path is
//!   still in use anywhere (e.g. for a non-validator hot-wallet key), since
//!   the in-memory signer is only as good as the process's memory hygiene.
//!
//! # Threading
//!
//! [`Signer`] and [`SignerTransport`] are `Send + Sync`; a signer can be shared
//! across consensus tasks. `sign` is *blocking* (it is a network round trip to
//! the signer), so call it off the async runtime's worker threads — e.g.
//! `tokio::task::spawn_blocking` — or accept that consensus is stalled for the
//! duration of the round trip.

use ed25519_dalek::Signer as DalekSigner;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

/// Width of an Ed25519 public key, in bytes (v1 legacy compatibility until R3-F).
pub const PUBLIC_KEY_LEN: usize = 32;
/// Width of an Ed25519 signature, in bytes (v1 legacy compatibility until R3-F).
pub const SIGNATURE_LEN: usize = 64;

/// Width of a Falcon-512 public key, in bytes (`0x09` header + 896-byte encoded `h`).
pub const FALCON_PUBLIC_KEY_LEN: usize = crate::post_quantum::FALCON512_PUBKEY_LEN;
/// Width of a Falcon-512 signature, in bytes.
pub const FALCON_SIGNATURE_LEN: usize = crate::post_quantum::FALCON512_SIG_LEN;

/// Default per-request timeout when talking to a remote signer.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard cap on a response body we will read from a remote signer (`8 KiB`).
/// Covers v2 Falcon-512 JSON responses (`1794` hex chars for public key,
/// `1332` hex chars for signature) while rejecting oversized payloads.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024;

/// Default path (relative to the base URL) that returns the v1 signer's public key.
pub const DEFAULT_PUBLIC_KEY_PATH: &str = "/public_key";
/// Default path (relative to the base URL) that signs a v1 message.
pub const DEFAULT_SIGN_PATH: &str = "/sign";

/// Default v2 path (relative to the base URL) returning the Falcon-512 public key + validator id.
pub const DEFAULT_V2_PUBLIC_KEY_PATH: &str = "/v2/public_key";
/// Default v2 path (relative to the base URL) signing a structured consensus request.
pub const DEFAULT_V2_SIGN_PATH: &str = "/v2/sign";

// ============================================================================
// Errors
// ============================================================================

/// Why a request to the remote signer could not be completed.
///
/// Deliberately closed and payload-free: the only data retained is an HTTP
/// status code, which is not secret, and which is enough to tell "the signer
/// said no" apart from "the signer was never reached".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// The request could not be built or completed: bad URL, DNS failure,
    /// connection refused, TLS failure, socket error.
    Request,
    /// The request, or the read of the response, exceeded the timeout.
    Timeout,
    /// The signer answered with a status outside `2xx` (auth failure, quota,
    /// policy refusal, outage). The body is *not* retained: a signer error
    /// document can echo the request, and the request is the message.
    Rejected { status: u16 },
    /// A `2xx` response arrived but its body could not be read to the end.
    UnreadableBody,
}

/// Why a response from the remote signer could not be turned into a key or a
/// signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MalformedResponseKind {
    /// The body was not the JSON object the protocol calls for.
    BadJson,
    /// The JSON object was well formed but did not carry the expected field.
    MissingField,
    /// The expected field was present but not valid hex.
    NotHex,
    /// The body exceeded [`MAX_RESPONSE_BYTES`].
    BodyTooLarge,
}

/// Why signing itself failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningFailureKind {
    /// The caller handed over zero bytes to sign. Consensus sign bytes are
    /// always tagged and non-empty, so this is treated as a caller bug rather
    /// than a valid message: a remote signer asked to sign "nothing" is far
    /// more likely to be a bug in the tag-building code than an intent.
    EmptyMessage,
    /// The signature the signer returned does not verify under the public key
    /// this signer is pinned to: a foreign key, a corrupt response, or a signer
    /// that is not the one we resolved at construction.
    SignatureInvalid,
    /// The local key could not produce a signature.
    UnusableKey,
    /// Structured consensus request validation failed (anti-oracle: mismatched
    /// or non-consensus preimage, arbitrary bytes, or transaction payload).
    InvalidRequest,
}

/// Every way signing can fail.
///
/// SECURITY: this type carries no key material — no seed, no signature bytes, no
/// token, no URL. The payloads are enums and byte counts, so an error cannot
/// leak a secret into a log line, an RPC response or a crash report, and
/// `source()` deliberately returns `None` rather than wrapping a transport
/// error whose `Display` embeds the request URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerError {
    /// The remote signer could not be reached or would not answer.
    Transport(TransportErrorKind),
    /// The remote signer answered with something we cannot interpret.
    MalformedResponse(MalformedResponseKind),
    /// The public key was not the expected byte width.
    BadPublicKeyLength { got: usize },
    /// The signature was not the expected byte width.
    BadSignatureLength { got: usize },
    /// Signing failed for a reason other than transport or parsing.
    SigningFailed(SigningFailureKind),
    /// Locally configured key material could not be decoded into a key.
    MalformedKey,
    /// Remote signer returned an unsupported or disabled PQ scheme id.
    UnsupportedScheme { scheme_id: u8 },
    /// Remote signer's validator_id does not match the expected validator_id.
    ValidatorIdMismatch,
    /// Remote signer's public key does not match the pinned/expected public key.
    PublicKeyMismatch,
    /// Request violates anti-equivocation safety monotonicity / lock rules.
    SafetyViolation,
    /// Durable safety record store is quarantined or missing initialization.
    SafetyStoreQuarantined,
    /// Plain `http://` is forbidden for non-loopback remote signer endpoints.
    PlainHttpForbiddenOnNonLoopback,
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::Transport(TransportErrorKind::Request) => {
                write!(
                    f,
                    "remote signer transport failed (request could not be completed)"
                )
            }
            SignerError::Transport(TransportErrorKind::Timeout) => {
                write!(f, "remote signer transport failed (timed out)")
            }
            SignerError::Transport(TransportErrorKind::Rejected { status }) => {
                write!(
                    f,
                    "remote signer rejected the request (http status {status})"
                )
            }
            SignerError::Transport(TransportErrorKind::UnreadableBody) => {
                write!(
                    f,
                    "remote signer transport failed (response body unreadable)"
                )
            }
            SignerError::MalformedResponse(MalformedResponseKind::BadJson) => {
                write!(f, "remote signer returned a malformed response (bad json)")
            }
            SignerError::MalformedResponse(MalformedResponseKind::MissingField) => {
                write!(
                    f,
                    "remote signer returned a malformed response (missing field)"
                )
            }
            SignerError::MalformedResponse(MalformedResponseKind::NotHex) => {
                write!(
                    f,
                    "remote signer returned a malformed response (field is not hex)"
                )
            }
            SignerError::MalformedResponse(MalformedResponseKind::BodyTooLarge) => {
                write!(
                    f,
                    "remote signer response exceeded {MAX_RESPONSE_BYTES} bytes"
                )
            }
            SignerError::BadPublicKeyLength { got } => {
                write!(
                    f,
                    "remote signer returned a {got}-byte public key (wrong width)"
                )
            }
            SignerError::BadSignatureLength { got } => {
                write!(
                    f,
                    "remote signer returned a {got}-byte signature (wrong width)"
                )
            }
            SignerError::SigningFailed(SigningFailureKind::EmptyMessage) => {
                write!(f, "refusing to sign an empty message")
            }
            SignerError::SigningFailed(SigningFailureKind::SignatureInvalid) => write!(
                f,
                "signature returned by the remote signer does not verify under its public key"
            ),
            SignerError::SigningFailed(SigningFailureKind::UnusableKey) => {
                write!(f, "local signing key is unusable")
            }
            SignerError::SigningFailed(SigningFailureKind::InvalidRequest) => {
                write!(
                    f,
                    "refusing non-consensus or mismatched preimage signing request"
                )
            }
            SignerError::MalformedKey => {
                write!(
                    f,
                    "signing key material is malformed (bad hex or wrong length)"
                )
            }
            SignerError::UnsupportedScheme { scheme_id } => {
                write!(
                    f,
                    "remote signer returned unsupported scheme_id {scheme_id} (only Falcon-512 0x02 accepted)"
                )
            }
            SignerError::ValidatorIdMismatch => {
                write!(
                    f,
                    "remote signer validator_id does not match expected validator"
                )
            }
            SignerError::PublicKeyMismatch => {
                write!(
                    f,
                    "remote signer public key does not match expected committed key"
                )
            }
            SignerError::SafetyViolation => {
                write!(
                    f,
                    "refusing to sign: consensus safety / anti-equivocation violation"
                )
            }
            SignerError::SafetyStoreQuarantined => {
                write!(
                    f,
                    "refusing to sign: safety record store is quarantined or uninitialized"
                )
            }
            SignerError::PlainHttpForbiddenOnNonLoopback => {
                write!(
                    f,
                    "plain http:// is forbidden for non-loopback remote signer URLs"
                )
            }
        }
    }
}

impl std::error::Error for SignerError {
    /// Always `None`.
    ///
    /// The underlying transport error is deliberately *not* wrapped: `ureq`'s
    /// `Display` and `Debug` embed the request URL, which for a signing endpoint
    /// typically contains the key handle or a token. [`HttpSignerTransport`]
    /// logs the failure class instead, so nothing secret is lost from the
    /// operator's view while nothing secret can reach a caller.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

// ============================================================================
// Signer
// ============================================================================

/// What the node needs from a key holder: its public key, and its ability to
/// sign bytes.
///
/// The contract is deliberately minimal so a `LocalSigner` and a
/// [`RemoteSigner`] are interchangeable: the consensus layer cannot tell which
/// one it holds, and in particular cannot tell that its key is not in memory.
///
/// # Domain separation
///
/// `sign` signs the bytes it is given and nothing else. It must not add, remove
/// or transform a domain tag: the consensus tags (e.g.
/// `STELLEREUM_BFT_VOTE_V3` in `consensus::vote_sign_bytes`) are applied by the
/// caller, so that exactly one component owns the tag scheme. A signer that
/// tagged on top would make the two schemes confusable on the same key.
///
/// # Errors
///
/// Every failure is reported; no implementation of this trait may ever fall
/// back to another key. An error means the caller has no signature, and the
/// node must not act as if it had one.
pub trait Signer: Send + Sync {
    /// The signer's Ed25519 public key.
    fn public_key(&self) -> [u8; PUBLIC_KEY_LEN];

    /// Sign `msg` exactly as given, returning the 64-byte Ed25519 signature.
    fn sign(&self, msg: &[u8]) -> Result<Signature, SignerError>;

    /// Verify `sig` over `msg` against [`Signer::public_key`].
    ///
    /// Provided: implementations get this for free and cannot get it subtly
    /// wrong by verifying against some other key.
    fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.public_key()) else {
            return false;
        };
        vk.verify_strict(msg, sig).is_ok()
    }
}

// ============================================================================
// LocalSigner
// ============================================================================

/// An in-memory Ed25519 signer: the key lives in this process.
///
/// This is the reference implementation of [`Signer`] and the oracle the remote
/// path is tested against (a remote signer holding the same key must produce
/// byte-identical signatures, since Ed25519 is deterministic).
///
/// SECURITY: this is the configuration the remote signer exists to replace. The
/// seed is in the node's memory, so it is extractable from a core dump, a
/// crash report, a swap file or a `/proc/<pid>/mem` read by anything with
/// privileges. The type does not log the key and its `Debug` shows only the
/// public key, but that is hygiene, not protection.
pub struct LocalSigner {
    key: SigningKey,
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl LocalSigner {
    /// Build a signer from a 32-byte seed.
    ///
    /// The caller retains `seed` and MUST wipe its copy after use (this
    /// function copies it into the `SigningKey`); prefer loading through
    /// `node_keys` (`Zeroizing` buffers) over long-lived seed variables.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let public_key = key.verifying_key().to_bytes();
        Self { key, public_key }
    }

    /// Build a signer from a hex-encoded seed, as it appears in a node config.
    pub fn from_hex_seed(hex_seed: &str) -> Result<Self, SignerError> {
        // `hex::decode`'s error Display echoes the offending input, and the
        // input here *is* the key. Drop the error on the floor.
        // The decoded bytes ARE the seed: hold them in `Zeroizing` and wipe
        // before returning, so a heap dump after construction finds no copy.
        let raw = zeroize::Zeroizing::new(
            hex::decode(hex_seed.trim()).map_err(|_| SignerError::MalformedKey)?,
        );
        let mut seed: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| SignerError::MalformedKey)?;
        let signer = Self::from_seed(&seed);
        // Wipe the stack copy; `raw` (also the seed) is wiped by `Zeroizing`
        // on scope exit. The `SigningKey` copy is the signer's by design.
        zeroize::Zeroize::zeroize(&mut seed);
        Ok(signer)
    }

    /// Build a signer from a freshly generated random seed.
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let key = SigningKey::generate(&mut OsRng);
        let public_key = key.verifying_key().to_bytes();
        Self { key, public_key }
    }

    /// The signer's public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key
    }

    /// The verifying half of the key pair, for callers that want dalek's API.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

/// Shows the public key only: the seed must never reach a log line through a
/// `{:?}` in a debugging statement.
impl fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSigner")
            .field("public_key", &hex::encode(self.public_key))
            .finish_non_exhaustive()
    }
}

impl Signer for LocalSigner {
    fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, SignerError> {
        if msg.is_empty() {
            return Err(SignerError::SigningFailed(SigningFailureKind::EmptyMessage));
        }
        DalekSigner::try_sign(&self.key, msg)
            .map_err(|_| SignerError::SigningFailed(SigningFailureKind::UnusableKey))
    }
}

// ============================================================================
// SignerTransport
// ============================================================================

/// The wire between a [`RemoteSigner`] and whatever actually holds the key.
///
/// Splitting this out keeps [`RemoteSigner`] free of I/O and network types, so
/// the whole remote-signing path — including every error path — is testable
/// without a socket, a KMS SDK or an HSM.
///
/// The fixed-width return types are the first line of defence against a
/// malformed signer: a transport cannot hand back a 31-byte key, it has to
/// reject it itself and report [`SignerError::BadPublicKeyLength`]. A transport
/// parsing hex off the wire (see [`HttpSignerTransport`]) does exactly that.
pub trait SignerTransport: Send + Sync {
    /// The public key of the key this transport signs with.
    fn public_key(&self) -> Result<[u8; PUBLIC_KEY_LEN], SignerError>;

    /// Ask the remote signer to sign `msg` and return the 64-byte signature.
    fn sign(&self, msg: &[u8]) -> Result<[u8; SIGNATURE_LEN], SignerError>;
}

// ============================================================================
// RemoteSigner
// ============================================================================

/// A [`Signer`] that keeps no key material, only a handle to a remote signer.
///
/// Construction resolves and pins the remote public key: it must be
/// [`PUBLIC_KEY_LEN`] bytes *and* a valid Ed25519 point, otherwise construction
/// fails. Pinning matters because a node that adopts whatever key answers on
/// each request can be switched to another validator's key by anyone who can
/// answer on the endpoint; a node that pins the key it saw at startup cannot be
/// moved afterwards, only knocked offline.
///
/// # No local fallback
///
/// This type holds no `SigningKey` and offers no way to configure one. When the
/// transport fails, [`RemoteSigner::sign`] returns the error unchanged and no
/// signature is produced. That is the entire point: an operator who has moved a
/// validator key into an HSM must be able to rely on the node *not* being able
/// to sign without it. A "helpful" fallback would let the node keep producing
/// blocks with a key the operator believes is in the HSM, and the whole rollout
/// would be a fiction that only shows up when the incident response needs it.
pub struct RemoteSigner {
    transport: Arc<dyn SignerTransport>,
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl RemoteSigner {
    /// Resolve the remote signer's public key and pin it.
    ///
    /// Fails (returning the transport's error unchanged) if the signer cannot be
    /// reached, answers with a key of the wrong width, or answers with 32 bytes
    /// that are not a point on the curve. A node that cannot resolve its key at
    /// startup should refuse to start rather than start in a degraded mode.
    pub fn new(transport: Arc<dyn SignerTransport>) -> Result<Self, SignerError> {
        let raw = transport.public_key()?;
        // Not just a length check: 32 arbitrary bytes are not a public key, and
        // a signer that hands back garbage should fail loudly at startup
        // instead of at the first vote.
        let vk = VerifyingKey::from_bytes(&raw).map_err(|_| SignerError::MalformedKey)?;
        Ok(Self {
            transport,
            public_key: vk.to_bytes(),
        })
    }

    /// The pinned public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key
    }

    /// The transport, for callers that need to talk to the signer directly
    /// (health checks, key rotation triggered elsewhere).
    pub fn transport(&self) -> &Arc<dyn SignerTransport> {
        &self.transport
    }
}

/// Shows the pinned public key only. There is no secret here to redact, but
/// there is also no handle or token to leak through a stray `{:?}`.
impl fmt::Debug for RemoteSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSigner")
            .field("public_key", &hex::encode(self.public_key))
            .finish_non_exhaustive()
    }
}

impl Signer for RemoteSigner {
    fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, SignerError> {
        if msg.is_empty() {
            return Err(SignerError::SigningFailed(SigningFailureKind::EmptyMessage));
        }

        // The one and only call into the outside world. A transport error
        // propagates as-is; there is nothing else to fall back to and nothing
        // is substituted for the signature.
        let raw = self.transport.sign(msg)?;
        let sig = Signature::from_bytes(&raw);

        // The transport type already guarantees 64 bytes, and it validated the
        // length when it parsed the wire format. Re-verifying here is the
        // stronger check: it rejects a well-formed signature made by a
        // different key, which is what a hijacked endpoint or a swapped signer
        // would produce.
        if !Signer::verify(self, msg, &sig) {
            return Err(SignerError::SigningFailed(
                SigningFailureKind::SignatureInvalid,
            ));
        }
        Ok(sig)
    }
}

// ============================================================================
// HttpSignerTransport
// ============================================================================

/// Wire format of a signing request. `message` is hex so a signing service can
/// log or audit the *digest* of what it signed without holding the plaintext in
/// a URL or a shell-friendly encoding.
#[derive(Serialize)]
struct SignRequestBody<'a> {
    message: &'a str,
}

/// The two response shapes. `Option` rather than a bare field so a missing or
/// `null` field is [`MalformedResponseKind::MissingField`] instead of a
/// confusing serde message.
#[derive(Deserialize)]
struct PublicKeyResponseBody {
    public_key: Option<String>,
}

#[derive(Deserialize)]
struct SignatureResponseBody {
    signature: Option<String>,
}

/// A [`SignerTransport`] that talks JSON over HTTP to a remote signing service.
///
/// # Protocol
///
/// - `GET  {base_url}{public_key_path}` → `{"public_key": "<64 hex chars>"}`
/// - `POST {base_url}{sign_path}`, body `{"message": "<hex>"}` → `{"signature":
///   "<128 hex chars>"}`
///
/// The request body is built and the response is parsed here rather than with
/// ureq's JSON helpers, because the module needs to control exactly what is
/// read off the socket (a size cap) and exactly what an error may contain.
///
/// # Hardening applied by default
///
/// - **Timeout** on connect, write and read, so a wedged signer cannot stall
///   consensus indefinitely ([`DEFAULT_TIMEOUT`]).
/// - **No redirects** followed: a redirect on a signing request is either a
///   misconfiguration or an attempt to move the request somewhere it should not
///   go. ureq also never forwards auth headers across a redirect, but a `3xx`
///   would be a body we cannot parse, so it is better to fail.
/// - **No proxy auto-discovery**, even if another crate in the dependency graph
///   enables ureq's `proxy-from-env`: an ambient `HTTP_PROXY` must not be able
///   to see validator signing traffic, and over plain HTTP it would see the
///   message itself.
/// - **Response size cap** ([`MAX_RESPONSE_BYTES`]).
///
/// # Secrets
///
/// The auth header value is a credential. It is never logged, never included in
/// an error, and is redacted by the `Debug` impl. The URL is equally
/// sensitive — a key handle or a token often ends up in one — so it is not
/// logged either, which is why [`SignerError::Transport`] reports a class and a
/// status code rather than a message.
pub struct HttpSignerTransport {
    base_url: String,
    public_key_path: String,
    sign_path: String,
    auth: Option<(String, String)>,
    timeout: Duration,
    https_only: bool,
    agent: ureq::Agent,
}

impl HttpSignerTransport {
    /// A transport pointed at `base_url`, e.g. `https://signer.internal:8443`.
    pub fn new(base_url: impl Into<String>) -> Self {
        let mut base_url = base_url.into();
        while base_url.ends_with('/') {
            base_url.pop();
        }
        let timeout = DEFAULT_TIMEOUT;
        Self {
            base_url,
            public_key_path: DEFAULT_PUBLIC_KEY_PATH.to_string(),
            sign_path: DEFAULT_SIGN_PATH.to_string(),
            auth: None,
            timeout,
            https_only: false,
            agent: build_agent(timeout, false),
        }
    }

    /// Override the endpoint paths, if the service does not use the defaults.
    ///
    /// Apply this (and the other setters) before the transport is used: they
    /// rebuild the HTTP agent and drop its connection pool.
    pub fn with_paths(
        mut self,
        public_key_path: impl Into<String>,
        sign_path: impl Into<String>,
    ) -> Self {
        self.public_key_path = public_key_path.into();
        self.sign_path = sign_path.into();
        self
    }

    /// Set the per-request timeout. Must be applied before use.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.agent = build_agent(timeout, self.https_only);
        self
    }

    /// Send `Authorization: Bearer <token>` with every request.
    ///
    /// The token is a credential: it is never logged and never appears in an
    /// error or in `Debug`. Prefer a client certificate (mutual TLS) over a
    /// bearer token where the signer supports it — a token has to live in the
    /// node's config, a client key would too, but the signer can then scope it
    /// to one key and one policy.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.auth = Some((
            "Authorization".to_string(),
            format!("Bearer {}", token.into()),
        ));
        self
    }

    /// Send an arbitrary auth header with every request. Must be applied before
    /// use.
    pub fn with_auth_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.auth = Some((name.into(), value.into()));
        self
    }

    /// Refuse plain `http://` URLs. Off by default because a KMS on a linkback
    /// interface is normally plain HTTP on loopback; turn it on for every
    /// off-host signer.
    pub fn https_only(mut self, enforce: bool) -> Self {
        self.https_only = enforce;
        self.agent = build_agent(self.timeout, enforce);
        self
    }

    /// The configured base URL. Public because it is not a secret, unlike the
    /// auth header.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn request(&self, method: &str, path: &str) -> ureq::Request {
        let req = self
            .agent
            .request(method, &format!("{}{}", self.base_url, path));
        match &self.auth {
            Some((name, value)) => req.set(name, value),
            None => req,
        }
    }

    /// Turn a completed request into a size-capped body, mapping every failure
    /// onto a [`SignerError`] class.
    fn finish(&self, result: Result<ureq::Response, ureq::Error>) -> Result<Vec<u8>, SignerError> {
        let resp = result.map_err(map_transport_error)?;
        let status = resp.status();
        if !(200..300).contains(&status) {
            // `ureq` turns 4xx/5xx into `Err`, so this catches 1xx/3xx. The body
            // is dropped unread on purpose: it is unbounded, it is usually an
            // error document from something that is not our signer, and it can
            // echo the request — which is the message.
            return Err(SignerError::Transport(TransportErrorKind::Rejected {
                status,
            }));
        }
        let mut body = Vec::new();
        // `take` bounds the read: a signer that streams forever is cut off at
        // the cap instead of filling the node's heap.
        resp.into_reader()
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    SignerError::Transport(TransportErrorKind::Timeout)
                } else {
                    SignerError::Transport(TransportErrorKind::UnreadableBody)
                }
            })?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(SignerError::MalformedResponse(
                MalformedResponseKind::BodyTooLarge,
            ));
        }
        Ok(body)
    }
}

fn build_agent(timeout: Duration, https_only: bool) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(0)
        .try_proxy_from_env(false)
        .https_only(https_only)
        .build()
}

/// Map a `ureq` failure onto a [`SignerError`].
///
/// `ureq`'s error types embed the request URL in both `Display` and `Debug`, and
/// a URL for a signing endpoint routinely contains the key handle or a token.
/// So nothing is copied out of it: the failure *class* is logged for the
/// operator and the error itself becomes a [`TransportErrorKind`].
fn map_transport_error(e: ureq::Error) -> SignerError {
    let class = e.kind();
    tracing::warn!("[remote-signer] request failed (class={class:?})");
    match &e {
        ureq::Error::Status(status, _) => {
            SignerError::Transport(TransportErrorKind::Rejected { status: *status })
        }
        _ => {
            // Only the *kind* of the underlying I/O error is inspected, never
            // its message: `ureq` reports connect and read timeouts as a plain
            // `Io`, and the distinction is worth making for an operator staring
            // at a stalled validator.
            let timed_out = std::error::Error::source(&e)
                .and_then(|s| s.downcast_ref::<std::io::Error>())
                .map(|io| io.kind() == std::io::ErrorKind::TimedOut)
                .unwrap_or(false);
            if timed_out {
                SignerError::Transport(TransportErrorKind::Timeout)
            } else {
                SignerError::Transport(TransportErrorKind::Request)
            }
        }
    }
}

/// Redacts the auth header, whose value is a credential.
impl fmt::Debug for HttpSignerTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpSignerTransport")
            .field("base_url", &self.base_url)
            .field("public_key_path", &self.public_key_path)
            .field("sign_path", &self.sign_path)
            .field("timeout", &self.timeout)
            .field("https_only", &self.https_only)
            .field("auth_header", &self.auth.as_ref().map(|(name, _)| name))
            .finish_non_exhaustive()
    }
}

impl SignerTransport for HttpSignerTransport {
    fn public_key(&self) -> Result<[u8; PUBLIC_KEY_LEN], SignerError> {
        let body = self.finish(self.request("GET", &self.public_key_path).call())?;
        let parsed: PublicKeyResponseBody = serde_json::from_slice(&body).map_err(|e| {
            // `classify` only, never `e`: a serde error Display quotes the
            // offending input.
            tracing::debug!(
                "[remote-signer] public key response is not the expected json ({:?})",
                e.classify()
            );
            SignerError::MalformedResponse(MalformedResponseKind::BadJson)
        })?;
        let hex_key = parsed.public_key.ok_or(SignerError::MalformedResponse(
            MalformedResponseKind::MissingField,
        ))?;
        let raw = hex::decode(&hex_key)
            .map_err(|_| SignerError::MalformedResponse(MalformedResponseKind::NotHex))?;
        // A key of the wrong width is a configuration error, not a malformed
        // packet, and is worth its own error: the operator needs to be told the
        // signer returned 31 bytes where 32 were expected.
        let got = raw.len();
        let key: [u8; PUBLIC_KEY_LEN] = raw
            .try_into()
            .map_err(|_| SignerError::BadPublicKeyLength { got })?;
        Ok(key)
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; SIGNATURE_LEN], SignerError> {
        let hex_msg = hex::encode(msg);
        let request_body = serde_json::to_string(&SignRequestBody { message: &hex_msg })
            // Unreachable: a `&str` always serialises. Kept explicit so the
            // request cannot be sent half-formed.
            .map_err(|_| SignerError::Transport(TransportErrorKind::Request))?;
        let body = self.finish(
            self.request("POST", &self.sign_path)
                .set("Content-Type", "application/json")
                .send_string(&request_body),
        )?;
        let parsed: SignatureResponseBody = serde_json::from_slice(&body).map_err(|e| {
            tracing::debug!(
                "[remote-signer] signature response is not the expected json ({:?})",
                e.classify()
            );
            SignerError::MalformedResponse(MalformedResponseKind::BadJson)
        })?;
        let hex_sig = parsed.signature.ok_or(SignerError::MalformedResponse(
            MalformedResponseKind::MissingField,
        ))?;
        let raw = hex::decode(&hex_sig)
            .map_err(|_| SignerError::MalformedResponse(MalformedResponseKind::NotHex))?;
        // Same reasoning as the public key: reject a truncated or padded
        // signature here, at the boundary, where the operator can see it.
        let got = raw.len();
        let sig: [u8; SIGNATURE_LEN] = raw
            .try_into()
            .map_err(|_| SignerError::BadSignatureLength { got })?;
        Ok(sig)
    }
}

// ============================================================================
// ValidatorSigner: the one key holder a node carries
// ============================================================================

/// Environment variable naming the remote signer's base URL. When it is set to
/// a non-empty value the node must sign through the remote signer instead of a
/// local key.
pub const REMOTE_SIGNER_URL_ENV: &str = "STELL_REMOTE_SIGNER_URL";
/// Optional bearer token sent to the remote signer.
pub const REMOTE_SIGNER_TOKEN_ENV: &str = "STELL_REMOTE_SIGNER_TOKEN";

/// A validator's key holder: either the in-process key or a remote handle.
///
/// It exists so the "is this node using a remote signer?" decision is made once,
/// at startup, and the rest of the node only ever sees a [`Signer`] — the two
/// operations consensus needs (expose the public key, sign bytes). A value that
/// is `Local` has a plaintext key; a value that is `Remote` has only a pinned
/// public key and no way to sign without the remote service, so a transport
/// failure cannot silently fall back.
///
/// HSM GAP (audit verified-green note): this signer is Ed25519-ONLY. Falcon-512
/// vote halves still come from the local `falcon.key` file — a pure-PQ
/// validator keeps lattice key material on disk even with a remote signer
/// configured. The HSM story is incomplete for pure-PQ until a Falcon-capable
/// remote signer lands; operators MUST keep the `falcon.key` file protections
/// (0600/0700 + passphrase, see `node_keys`) in force on such nodes.
#[allow(clippy::large_enum_variant)] // GATE: boxing Local adds indirection on the hot signing path; size is by design
pub enum ValidatorSigner {
    /// Ed25519 key held in this process. The existing local-key path.
    Local(LocalSigner),
    /// Pinned handle to an out-of-process signer. No key material here.
    Remote(RemoteSigner),
}

impl ValidatorSigner {
    /// Turn a configured REMOTE signer into a shareable handle for the consensus
    /// runtime. `None` for the local variant, which consensus keeps driving from the
    /// in-process `SigningKey`.
    pub fn into_remote(self) -> Option<std::sync::Arc<dyn Signer>> {
        match self {
            Self::Remote(r) => Some(std::sync::Arc::new(r)),
            Self::Local(_) => None,
        }
    }

    /// Wrap a 32-byte seed as the in-process signer.
    pub fn local(seed: &[u8; PUBLIC_KEY_LEN]) -> Self {
        Self::Local(LocalSigner::from_seed(seed))
    }

    /// True when this node signs through a remote signer.
    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote(_))
    }

    /// The bare [`RemoteSigner`], when this node uses one.
    pub fn as_remote(&self) -> Option<&RemoteSigner> {
        match self {
            Self::Remote(r) => Some(r),
            Self::Local(_) => None,
        }
    }

    /// The signer's Ed25519 public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        match self {
            Self::Local(l) => l.public_key(),
            Self::Remote(r) => r.public_key(),
        }
    }

    /// Sign `msg` exactly as given, or fail. A remote failure is propagated
    /// unchanged; it is never satisfied by a local key.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, SignerError> {
        match self {
            Self::Local(l) => l.sign(msg),
            Self::Remote(r) => r.sign(msg),
        }
    }
}

/// Shows only the public key; neither variant has any secret to print.
impl fmt::Debug for ValidatorSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(l) => f.debug_tuple("ValidatorSigner::Local").field(l).finish(),
            Self::Remote(r) => f.debug_tuple("ValidatorSigner::Remote").field(r).finish(),
        }
    }
}

impl Signer for ValidatorSigner {
    fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        ValidatorSigner::public_key(self)
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, SignerError> {
        ValidatorSigner::sign(self, msg)
    }
}

/// Build a [`RemoteSigner`] from a URL and optional bearer token, or `Ok(None)`
/// when no URL is configured.
///
/// Pure over its arguments (it does not read the environment) so the
/// fail-closed behaviour is directly testable. A configured but unreachable
/// signer, a wrong-width key or a value that is not a curve point returns
/// `Err`; this path has no `Local` result, so a caller cannot fall back.
pub fn remote_signer_from_config(
    url: Option<String>,
    token: Option<String>,
) -> Result<Option<RemoteSigner>, SignerError> {
    let Some(url) = url.filter(|u| !u.trim().is_empty()) else {
        return Ok(None);
    };
    let mut transport = HttpSignerTransport::new(url);
    if let Some(token) = token.filter(|t| !t.trim().is_empty()) {
        transport = transport.with_bearer_token(token);
    }
    // Resolves and pins the public key; fails closed if it cannot.
    let remote = RemoteSigner::new(Arc::new(transport))?;
    Ok(Some(remote))
}

/// Read [`REMOTE_SIGNER_URL_ENV`] / [`REMOTE_SIGNER_TOKEN_ENV`] and build this
/// node's [`ValidatorSigner`].
///
/// When no URL is configured, `local_seed` becomes the in-process signer, which
/// keeps the existing local-key path working unchanged. When a URL is
/// configured, an unreachable or unverifiable signer returns `Err` and **no
/// local key is substituted**.
pub fn validator_signer_from_env(
    local_seed: [u8; PUBLIC_KEY_LEN],
) -> Result<ValidatorSigner, SignerError> {
    let url = std::env::var(REMOTE_SIGNER_URL_ENV).ok();
    let token = std::env::var(REMOTE_SIGNER_TOKEN_ENV).ok();
    match remote_signer_from_config(url, token)? {
        Some(remote) => Ok(ValidatorSigner::Remote(remote)),
        None => Ok(ValidatorSigner::local(&local_seed)),
    }
}

// ============================================================================
// Ruleset v7 / W3: FULL-PQ Falcon-512 Remote & Local Consensus Signer (v2)
// ============================================================================

use crate::consensus::{VoteKind, VOTE_SIGN_DOMAIN};
use crate::post_quantum::{verify_pq_signature, FalconKeypair, PqScheme};
use crate::storage::SafetyRecordStore;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Mutex;

const SAFETY_V2_MAGIC: &[u8; 4] = b"SQV2";

/// Reconstruct the exact `STELLEREUM_BFT_VOTE_V3` preimage for an explicit
/// `chain_id`, `shard_id`, `height`, `round`, `kind`, and `block_hash`.
///
/// Matches `crate::consensus::vote_sign_bytes_for_shard` byte-for-byte without
/// relying on process-global `consensus_chain_id()`.
pub fn vote_sign_bytes_with_chain(
    chain_id: u64,
    shard_id: u32,
    height: u64,
    round: u32,
    kind: VoteKind,
    block_hash: &Option<[u8; 32]>,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(88);
    m.extend_from_slice(VOTE_SIGN_DOMAIN);
    m.extend_from_slice(&chain_id.to_be_bytes());
    m.extend_from_slice(&shard_id.to_be_bytes());
    m.extend_from_slice(&height.to_be_bytes());
    m.extend_from_slice(&round.to_be_bytes());
    m.push(match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    });
    match block_hash {
        Some(h) => {
            m.push(1);
            m.extend_from_slice(h);
        }
        None => m.push(0),
    }
    m
}

/// Structured consensus signing request (anti-oracle: never signs arbitrary
/// bytes, transactions, or non-consensus domains).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusSignRequest {
    Vote {
        chain_id: u64,
        shard_id: u32,
        height: u64,
        round: u32,
        kind: VoteKind,
        block_hash: Option<[u8; 32]>,
    },
    Proposal {
        chain_id: u64,
        shard_id: u32,
        height: u64,
        round: u32,
        block_hash: [u8; 32],
    },
}

impl ConsensusSignRequest {
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::Vote { chain_id, .. } | Self::Proposal { chain_id, .. } => *chain_id,
        }
    }

    pub fn shard_id(&self) -> u32 {
        match self {
            Self::Vote { shard_id, .. } | Self::Proposal { shard_id, .. } => *shard_id,
        }
    }

    pub fn height(&self) -> u64 {
        match self {
            Self::Vote { height, .. } | Self::Proposal { height, .. } => *height,
        }
    }

    pub fn round(&self) -> u32 {
        match self {
            Self::Vote { round, .. } | Self::Proposal { round, .. } => *round,
        }
    }

    /// Reconstruct the canonical bytes that must be signed by Falcon-512 for
    /// this consensus message.
    pub fn canonical_signing_bytes(&self) -> Vec<u8> {
        match self {
            Self::Vote {
                chain_id,
                shard_id,
                height,
                round,
                kind,
                block_hash,
            } => {
                vote_sign_bytes_with_chain(*chain_id, *shard_id, *height, *round, *kind, block_hash)
            }
            Self::Proposal { block_hash, .. } => block_hash.to_vec(),
        }
    }

    /// Anti-oracle verification: verifies that `caller_preimage` is non-empty
    /// and matches the canonical bytes reconstructed from `self`.
    pub fn verify_preimage(&self, caller_preimage: &[u8]) -> Result<Vec<u8>, SignerError> {
        if caller_preimage.is_empty() {
            return Err(SignerError::SigningFailed(SigningFailureKind::EmptyMessage));
        }
        let canonical = self.canonical_signing_bytes();
        if caller_preimage != canonical.as_slice() {
            return Err(SignerError::SigningFailed(
                SigningFailureKind::InvalidRequest,
            ));
        }
        Ok(canonical)
    }
}

/// Persisted stamp of the highest signed prevote or precommit at the current height.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedVoteStamp {
    pub height: u64,
    pub round: u32,
    pub target: Option<[u8; 32]>,
}

/// Persisted stamp of the highest signed proposal at the current height.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedProposalStamp {
    pub height: u64,
    pub round: u32,
    pub block_hash: [u8; 32],
}

/// Anti-equivocation watermark and lock state persisted in [`SafetyRecordStore`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusSafetyState {
    pub height: u64,
    pub locked_round: Option<u32>,
    pub locked_value_id: Option<[u8; 32]>,
    pub last_prevote: Option<SignedVoteStamp>,
    pub last_precommit: Option<SignedVoteStamp>,
    pub last_proposal: Option<SignedProposalStamp>,
}

impl ConsensusSafetyState {
    /// Enforce strict height/round monotonicity and lock invariants for `req`.
    pub fn check_and_advance(
        &self,
        req: &ConsensusSignRequest,
        value_id: Option<[u8; 32]>,
    ) -> Result<Self, SignerError> {
        let req_height = req.height();
        if req_height < self.height {
            return Err(SignerError::SafetyViolation);
        }
        let mut next = if req_height > self.height {
            Self {
                height: req_height,
                locked_round: None,
                locked_value_id: None,
                last_prevote: None,
                last_precommit: None,
                last_proposal: None,
            }
        } else {
            self.clone()
        };

        match req {
            ConsensusSignRequest::Vote {
                round,
                kind: VoteKind::Prevote,
                block_hash,
                ..
            } => {
                if let Some(last) = next.last_prevote {
                    if *round <= last.round {
                        return Err(SignerError::SafetyViolation);
                    }
                }
                if block_hash.is_some() {
                    if let (Some(_lr), Some(locked_vid), Some(vid)) =
                        (next.locked_round, next.locked_value_id, value_id)
                    {
                        if vid != locked_vid {
                            return Err(SignerError::SafetyViolation);
                        }
                    }
                }
                next.last_prevote = Some(SignedVoteStamp {
                    height: next.height,
                    round: *round,
                    target: *block_hash,
                });
            }
            ConsensusSignRequest::Vote {
                round,
                kind: VoteKind::Precommit,
                block_hash,
                ..
            } => {
                if let Some(last) = next.last_precommit {
                    if *round <= last.round {
                        return Err(SignerError::SafetyViolation);
                    }
                }
                if block_hash.is_some() {
                    if let (Some(_lr), Some(locked_vid), Some(vid)) =
                        (next.locked_round, next.locked_value_id, value_id)
                    {
                        if vid != locked_vid {
                            return Err(SignerError::SafetyViolation);
                        }
                    }
                }
                next.last_precommit = Some(SignedVoteStamp {
                    height: next.height,
                    round: *round,
                    target: *block_hash,
                });
            }
            ConsensusSignRequest::Proposal {
                round, block_hash, ..
            } => {
                if let Some(last) = next.last_proposal {
                    if *round <= last.round {
                        return Err(SignerError::SafetyViolation);
                    }
                }
                next.last_proposal = Some(SignedProposalStamp {
                    height: next.height,
                    round: *round,
                    block_hash: *block_hash,
                });
            }
        }
        Ok(next)
    }
}

fn encode_safety_state(state: &ConsensusSafetyState) -> Result<Vec<u8>, SignerError> {
    let body = bincode::serialize(state).map_err(|_| SignerError::SafetyStoreQuarantined)?;
    let mut out = Vec::with_capacity(SAFETY_V2_MAGIC.len() + body.len());
    out.extend_from_slice(SAFETY_V2_MAGIC);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_safety_state(bytes: &[u8]) -> Result<ConsensusSafetyState, SignerError> {
    if bytes.len() < SAFETY_V2_MAGIC.len() || &bytes[..SAFETY_V2_MAGIC.len()] != SAFETY_V2_MAGIC {
        return Err(SignerError::SafetyStoreQuarantined);
    }
    bincode::deserialize(&bytes[SAFETY_V2_MAGIC.len()..])
        .map_err(|_| SignerError::SafetyStoreQuarantined)
}

struct SafetyGuardInner {
    store: Option<SafetyRecordStore>,
    generation: u64,
    state: ConsensusSafetyState,
    quarantined: bool,
}

/// Serialized check-persist-then-sign anti-equivocation guard backed by either
/// a durable [`SafetyRecordStore`] or in-memory state (for unit tests).
pub struct ConsensusSafetyGuard {
    inner: Mutex<SafetyGuardInner>,
}

impl ConsensusSafetyGuard {
    /// Ephemeral in-memory guard (for tests or mock signers without sled).
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(SafetyGuardInner {
                store: None,
                generation: 0,
                state: ConsensusSafetyState::default(),
                quarantined: false,
            }),
        }
    }

    /// Open a durable guard backed by [`SafetyRecordStore`].
    ///
    /// Fails closed (`SafetyStoreQuarantined`) on any read/decode/identity error,
    /// or when the record is absent and `allow_fresh_genesis_init == false`.
    pub fn from_durable(
        store: SafetyRecordStore,
        allow_fresh_genesis_init: bool,
    ) -> Result<Self, SignerError> {
        let loaded = store
            .load()
            .map_err(|_| SignerError::SafetyStoreQuarantined)?;
        match loaded {
            None => {
                if !allow_fresh_genesis_init {
                    return Err(SignerError::SafetyStoreQuarantined);
                }
                let state = ConsensusSafetyState::default();
                let encoded = encode_safety_state(&state)?;
                let rec = store
                    .persist(None, encoded)
                    .map_err(|_| SignerError::SafetyStoreQuarantined)?;
                Ok(Self {
                    inner: Mutex::new(SafetyGuardInner {
                        store: Some(store),
                        generation: rec.generation,
                        state,
                        quarantined: false,
                    }),
                })
            }
            Some(rec) => {
                let state = decode_safety_state(&rec.payload)?;
                Ok(Self {
                    inner: Mutex::new(SafetyGuardInner {
                        store: Some(store),
                        generation: rec.generation,
                        state,
                        quarantined: false,
                    }),
                })
            }
        }
    }

    pub fn generation(&self) -> u64 {
        self.inner.lock().map(|g| g.generation).unwrap_or(0)
    }

    pub fn is_quarantined(&self) -> bool {
        self.inner.lock().map(|g| g.quarantined).unwrap_or(true)
    }

    pub fn state_snapshot(&self) -> Result<ConsensusSafetyState, SignerError> {
        let g = self
            .inner
            .lock()
            .map_err(|_| SignerError::SafetyStoreQuarantined)?;
        if g.quarantined {
            return Err(SignerError::SafetyStoreQuarantined);
        }
        Ok(g.state.clone())
    }

    /// Record a lock update durably (advancing generation before returning).
    pub fn set_lock(&self, height: u64, round: u32, value_id: [u8; 32]) -> Result<(), SignerError> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SignerError::SafetyStoreQuarantined)?;
        if g.quarantined {
            return Err(SignerError::SafetyStoreQuarantined);
        }
        if height < g.state.height {
            return Err(SignerError::SafetyViolation);
        }
        let mut next = if height > g.state.height {
            ConsensusSafetyState {
                height,
                ..Default::default()
            }
        } else {
            g.state.clone()
        };
        if next.locked_round.is_some_and(|lr| round <= lr) {
            return Err(SignerError::SafetyViolation);
        }
        next.locked_round = Some(round);
        next.locked_value_id = Some(value_id);
        if let Some(store) = &g.store {
            let encoded = encode_safety_state(&next)?;
            match store.persist(Some(g.generation), encoded) {
                Ok(rec) => {
                    g.generation = rec.generation;
                    g.state = next;
                }
                Err(_) => {
                    g.quarantined = true;
                    return Err(SignerError::SafetyStoreQuarantined);
                }
            }
        } else {
            g.generation = g.generation.saturating_add(1);
            g.state = next;
        }
        Ok(())
    }

    /// Serialized check-persist-then-sign:
    /// 1. Validates safety invariants against current state.
    /// 2. Persists `next_state` atomically BEFORE invoking `sign_fn`.
    /// 3. On persist error, quarantines and returns `SafetyStoreQuarantined`.
    /// 4. If `sign_fn` fails AFTER durable reservation, does NOT roll back.
    pub fn reserve_and_sign<F>(
        &self,
        req: &ConsensusSignRequest,
        value_id: Option<[u8; 32]>,
        sign_fn: F,
    ) -> Result<([u8; FALCON_SIGNATURE_LEN], u64), SignerError>
    where
        F: FnOnce() -> Result<[u8; FALCON_SIGNATURE_LEN], SignerError>,
    {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SignerError::SafetyStoreQuarantined)?;
        if g.quarantined {
            return Err(SignerError::SafetyStoreQuarantined);
        }
        let next = g.state.check_and_advance(req, value_id)?;
        let reserved_gen = if let Some(store) = &g.store {
            let encoded = encode_safety_state(&next)?;
            match store.persist(Some(g.generation), encoded) {
                Ok(rec) => {
                    g.generation = rec.generation;
                    g.state = next;
                    rec.generation
                }
                Err(_) => {
                    g.quarantined = true;
                    return Err(SignerError::SafetyStoreQuarantined);
                }
            }
        } else {
            g.generation = g.generation.saturating_add(1);
            g.state = next;
            g.generation
        };
        let sig = sign_fn()?;
        Ok((sig, reserved_gen))
    }
}

/// Verified public identity returned by `/v2/public_key`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePublicKeyInfo {
    pub scheme: PqScheme,
    pub public_key: [u8; FALCON_PUBLIC_KEY_LEN],
    pub validator_id: [u8; 32],
}

/// JSON payload returned by `GET /v2/public_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyResponseV2 {
    pub scheme_id: u8,
    pub public_key: String,
    pub validator_id: String,
}

/// JSON payload sent to `POST /v2/sign`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequestV2 {
    pub validator_id: [u8; 32],
    pub request: ConsensusSignRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_id: Option<[u8; 32]>,
    pub preimage: String,
}

impl SignRequestV2 {
    /// Construct a canonical wire sign request from `validator_id` and `request`.
    pub fn from_consensus(
        validator_id: [u8; 32],
        request: ConsensusSignRequest,
        value_id: Option<[u8; 32]>,
    ) -> Self {
        let preimage = hex::encode(request.canonical_signing_bytes());
        Self {
            validator_id,
            request,
            value_id,
            preimage,
        }
    }

    /// Anti-oracle validation: verifies `validator_id == expected_validator_id`
    /// and `hex::decode(preimage) == request.canonical_signing_bytes()`.
    pub fn verify_and_extract_preimage(
        &self,
        expected_validator_id: &[u8; 32],
    ) -> Result<Vec<u8>, SignerError> {
        if &self.validator_id != expected_validator_id {
            return Err(SignerError::ValidatorIdMismatch);
        }
        let raw = hex::decode(&self.preimage)
            .map_err(|_| SignerError::SigningFailed(SigningFailureKind::InvalidRequest))?;
        self.request.verify_preimage(&raw)
    }
}

/// JSON payload returned by `POST /v2/sign`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignResponseV2 {
    pub scheme_id: u8,
    pub signature: String,
    pub generation: u64,
}

/// Strictly typed FULL-PQ consensus signer interface (Falcon-512 only).
pub trait PqSigner: Send + Sync {
    fn scheme(&self) -> PqScheme {
        PqScheme::Falcon512
    }

    fn public_key(&self) -> &[u8; FALCON_PUBLIC_KEY_LEN];

    fn validator_id(&self) -> [u8; 32];

    fn sign_consensus(
        &self,
        req: &ConsensusSignRequest,
    ) -> Result<[u8; FALCON_SIGNATURE_LEN], SignerError>;

    /// Verify caller-supplied preimage against `req` before signing (anti-oracle).
    fn sign_consensus_checked(
        &self,
        req: &ConsensusSignRequest,
        caller_preimage: &[u8],
    ) -> Result<[u8; FALCON_SIGNATURE_LEN], SignerError> {
        let _ = req.verify_preimage(caller_preimage)?;
        self.sign_consensus(req)
    }

    /// Verify a 666-byte Falcon-512 signature over `req` against `self.public_key()`.
    fn verify_consensus(
        &self,
        req: &ConsensusSignRequest,
        sig: &[u8; FALCON_SIGNATURE_LEN],
    ) -> bool {
        let pk = self.public_key();
        if pk[0] != 0x09 {
            return false;
        }
        let msg = req.canonical_signing_bytes();
        verify_pq_signature(self.scheme(), pk, &msg, sig)
    }
}

/// Wire transport seam for [`RemotePqSigner`].
pub trait PqSignerTransport: Send + Sync {
    fn public_key_v2(&self) -> Result<RemotePublicKeyInfo, SignerError>;
    fn sign_v2(
        &self,
        req: &SignRequestV2,
    ) -> Result<([u8; FALCON_SIGNATURE_LEN], u64), SignerError>;
}

/// In-process Falcon-512 consensus signer with anti-oracle preimage
/// reconstruction and serialized [`ConsensusSafetyGuard`] enforcement.
pub struct LocalPqSigner {
    keypair: Arc<FalconKeypair>,
    public_key: [u8; FALCON_PUBLIC_KEY_LEN],
    validator_id: [u8; 32],
    safety: ConsensusSafetyGuard,
}

impl LocalPqSigner {
    pub fn new(keypair: FalconKeypair, validator_id: [u8; 32]) -> Result<Self, SignerError> {
        Self::with_safety_guard(keypair, validator_id, ConsensusSafetyGuard::in_memory())
    }

    pub fn with_safety_guard(
        keypair: FalconKeypair,
        validator_id: [u8; 32],
        safety: ConsensusSafetyGuard,
    ) -> Result<Self, SignerError> {
        let pk_slice = keypair.public_key();
        if pk_slice.len() != FALCON_PUBLIC_KEY_LEN {
            return Err(SignerError::BadPublicKeyLength {
                got: pk_slice.len(),
            });
        }
        if pk_slice[0] != 0x09 {
            return Err(SignerError::MalformedKey);
        }
        let mut public_key = [0u8; FALCON_PUBLIC_KEY_LEN];
        public_key.copy_from_slice(pk_slice);
        Ok(Self {
            keypair: Arc::new(keypair),
            public_key,
            validator_id,
            safety,
        })
    }

    pub fn safety_guard(&self) -> &ConsensusSafetyGuard {
        &self.safety
    }

    pub fn sign_consensus_with_generation(
        &self,
        req: &ConsensusSignRequest,
        value_id: Option<[u8; 32]>,
    ) -> Result<([u8; FALCON_SIGNATURE_LEN], u64), SignerError> {
        let msg = req.canonical_signing_bytes();
        self.safety.reserve_and_sign(req, value_id, || {
            let sig_vec = self.keypair.sign(&msg);
            if sig_vec.len() != FALCON_SIGNATURE_LEN {
                return Err(SignerError::SigningFailed(SigningFailureKind::UnusableKey));
            }
            let mut sig = [0u8; FALCON_SIGNATURE_LEN];
            sig.copy_from_slice(&sig_vec);
            if !verify_pq_signature(PqScheme::Falcon512, &self.public_key, &msg, &sig) {
                return Err(SignerError::SigningFailed(
                    SigningFailureKind::SignatureInvalid,
                ));
            }
            Ok(sig)
        })
    }
}

/// Shows only `validator_id` and `public_key` — never secret lattice material.
impl fmt::Debug for LocalPqSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPqSigner")
            .field("validator_id", &hex::encode(self.validator_id))
            .field("public_key", &hex::encode(self.public_key))
            .finish_non_exhaustive()
    }
}

impl PqSigner for LocalPqSigner {
    fn public_key(&self) -> &[u8; FALCON_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    fn validator_id(&self) -> [u8; 32] {
        self.validator_id
    }

    fn sign_consensus(
        &self,
        req: &ConsensusSignRequest,
    ) -> Result<[u8; FALCON_SIGNATURE_LEN], SignerError> {
        let (sig, _gen) = self.sign_consensus_with_generation(req, None)?;
        Ok(sig)
    }
}

/// Remote Falcon-512 consensus signer with pinned public key, validator_id
/// binding, anti-oracle preimage reconstruction, [`ConsensusSafetyGuard`], and
/// **zero local fallback** (no `FalconKeypair`, no `SigningKey`).
pub struct RemotePqSigner {
    transport: Arc<dyn PqSignerTransport>,
    public_key: [u8; FALCON_PUBLIC_KEY_LEN],
    validator_id: [u8; 32],
    safety: ConsensusSafetyGuard,
}

impl RemotePqSigner {
    /// Resolve `/v2/public_key` once, validate `scheme == Falcon512`,
    /// `public_key.len() == 897`, `public_key[0] == 0x09`,
    /// `validator_id == expected_validator_id`, and (when provided)
    /// `public_key == expected_committed_pk`, then pin it.
    pub fn new(
        transport: Arc<dyn PqSignerTransport>,
        expected_validator_id: [u8; 32],
        expected_committed_pk: Option<&[u8]>,
    ) -> Result<Self, SignerError> {
        let info = transport.public_key_v2()?;
        if info.scheme != PqScheme::Falcon512 || info.scheme.is_disabled() {
            return Err(SignerError::UnsupportedScheme {
                scheme_id: info.scheme.id(),
            });
        }
        if info.public_key[0] != 0x09 {
            return Err(SignerError::MalformedKey);
        }
        if info.validator_id != expected_validator_id {
            return Err(SignerError::ValidatorIdMismatch);
        }
        if let Some(expected_pk) = expected_committed_pk {
            if info.public_key.as_slice() != expected_pk {
                return Err(SignerError::PublicKeyMismatch);
            }
        }
        Ok(Self {
            transport,
            public_key: info.public_key,
            validator_id: info.validator_id,
            safety: ConsensusSafetyGuard::in_memory(),
        })
    }

    pub fn with_safety_guard(mut self, safety: ConsensusSafetyGuard) -> Self {
        self.safety = safety;
        self
    }

    pub fn safety_guard(&self) -> &ConsensusSafetyGuard {
        &self.safety
    }

    pub fn transport(&self) -> &Arc<dyn PqSignerTransport> {
        &self.transport
    }

    pub fn sign_consensus_with_value_id(
        &self,
        req: &ConsensusSignRequest,
        value_id: Option<[u8; 32]>,
    ) -> Result<[u8; FALCON_SIGNATURE_LEN], SignerError> {
        let msg = req.canonical_signing_bytes();
        let wire_req = SignRequestV2::from_consensus(self.validator_id, req.clone(), value_id);
        let (sig, _gen) = self.safety.reserve_and_sign(req, value_id, || {
            let (sig, _remote_gen) = self.transport.sign_v2(&wire_req)?;
            if !verify_pq_signature(PqScheme::Falcon512, &self.public_key, &msg, &sig) {
                return Err(SignerError::SigningFailed(
                    SigningFailureKind::SignatureInvalid,
                ));
            }
            Ok(sig)
        })?;
        Ok(sig)
    }
}

impl fmt::Debug for RemotePqSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemotePqSigner")
            .field("validator_id", &hex::encode(self.validator_id))
            .field("public_key", &hex::encode(self.public_key))
            .finish_non_exhaustive()
    }
}

impl PqSigner for RemotePqSigner {
    fn public_key(&self) -> &[u8; FALCON_PUBLIC_KEY_LEN] {
        &self.public_key
    }

    fn validator_id(&self) -> [u8; 32] {
        self.validator_id
    }

    fn sign_consensus(
        &self,
        req: &ConsensusSignRequest,
    ) -> Result<[u8; FALCON_SIGNATURE_LEN], SignerError> {
        self.sign_consensus_with_value_id(req, None)
    }
}

/// Returns `true` iff `base_url` points to a loopback interface
/// (`127.0.0.1`, `[::1]`, or `localhost`).
pub fn is_loopback_base_url(base_url: &str) -> bool {
    let lower = base_url.trim().to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("http://") {
        r
    } else if let Some(r) = lower.strip_prefix("https://") {
        r
    } else {
        return false;
    };
    for host in ["127.0.0.1", "[::1]", "localhost"] {
        if let Some(after) = rest.strip_prefix(host) {
            if after.is_empty() || after.starts_with(':') || after.starts_with('/') {
                return true;
            }
        }
    }
    false
}

/// HTTP v2 client transport speaking `/v2/public_key` and `/v2/sign` with
/// Falcon-512 payloads, `MAX_RESPONSE_BYTES` (`8192`) cap, no redirects, no
/// env proxy discovery, and automatic `https_only(true)` on non-loopback URLs.
pub struct HttpPqSignerTransport {
    base_url: String,
    public_key_path: String,
    sign_path: String,
    auth: Option<(String, String)>,
    timeout: Duration,
    https_only: bool,
    agent: ureq::Agent,
}

impl HttpPqSignerTransport {
    pub fn new(base_url: impl Into<String>) -> Self {
        let mut base_url = base_url.into();
        while base_url.ends_with('/') {
            base_url.pop();
        }
        let timeout = DEFAULT_TIMEOUT;
        let https_only = !is_loopback_base_url(&base_url);
        Self {
            base_url,
            public_key_path: DEFAULT_V2_PUBLIC_KEY_PATH.to_string(),
            sign_path: DEFAULT_V2_SIGN_PATH.to_string(),
            auth: None,
            timeout,
            https_only,
            agent: build_agent(timeout, https_only),
        }
    }

    pub fn with_paths(
        mut self,
        public_key_path: impl Into<String>,
        sign_path: impl Into<String>,
    ) -> Self {
        self.public_key_path = public_key_path.into();
        self.sign_path = sign_path.into();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.agent = build_agent(timeout, self.https_only);
        self
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.auth = Some((
            "Authorization".to_string(),
            format!("Bearer {}", token.into()),
        ));
        self
    }

    pub fn with_auth_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.auth = Some((name.into(), value.into()));
        self
    }

    pub fn https_only(mut self, enforce: bool) -> Self {
        self.https_only = enforce;
        self.agent = build_agent(self.timeout, enforce);
        self
    }

    pub fn is_https_only(&self) -> bool {
        self.https_only
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn check_scheme_policy(&self) -> Result<(), SignerError> {
        if self.https_only
            && self
                .base_url
                .trim()
                .to_ascii_lowercase()
                .starts_with("http://")
        {
            return Err(SignerError::PlainHttpForbiddenOnNonLoopback);
        }
        Ok(())
    }

    fn request(&self, method: &str, path: &str) -> ureq::Request {
        let req = self
            .agent
            .request(method, &format!("{}{}", self.base_url, path));
        match &self.auth {
            Some((name, value)) => req.set(name, value),
            None => req,
        }
    }

    fn finish(&self, result: Result<ureq::Response, ureq::Error>) -> Result<Vec<u8>, SignerError> {
        let resp = result.map_err(map_transport_error)?;
        let status = resp.status();
        if !(200..300).contains(&status) {
            return Err(SignerError::Transport(TransportErrorKind::Rejected {
                status,
            }));
        }
        let mut body = Vec::new();
        resp.into_reader()
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    SignerError::Transport(TransportErrorKind::Timeout)
                } else {
                    SignerError::Transport(TransportErrorKind::UnreadableBody)
                }
            })?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(SignerError::MalformedResponse(
                MalformedResponseKind::BodyTooLarge,
            ));
        }
        Ok(body)
    }
}

impl fmt::Debug for HttpPqSignerTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpPqSignerTransport")
            .field("base_url", &self.base_url)
            .field("public_key_path", &self.public_key_path)
            .field("sign_path", &self.sign_path)
            .field("timeout", &self.timeout)
            .field("https_only", &self.https_only)
            .field("auth_header", &self.auth.as_ref().map(|(name, _)| name))
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct RawPublicKeyResponseV2 {
    scheme_id: Option<u8>,
    public_key: Option<String>,
    validator_id: Option<String>,
}

#[derive(Deserialize)]
struct RawSignResponseV2 {
    scheme_id: Option<u8>,
    signature: Option<String>,
    generation: Option<u64>,
}

impl PqSignerTransport for HttpPqSignerTransport {
    fn public_key_v2(&self) -> Result<RemotePublicKeyInfo, SignerError> {
        self.check_scheme_policy()?;
        let body = self.finish(self.request("GET", &self.public_key_path).call())?;
        let parsed: RawPublicKeyResponseV2 = serde_json::from_slice(&body).map_err(|e| {
            tracing::debug!(
                "[remote-signer-v2] public_key response is not valid json ({:?})",
                e.classify()
            );
            SignerError::MalformedResponse(MalformedResponseKind::BadJson)
        })?;
        let scheme_id = parsed.scheme_id.ok_or(SignerError::MalformedResponse(
            MalformedResponseKind::MissingField,
        ))?;
        let scheme = PqScheme::from_id(scheme_id)
            .map_err(|_| SignerError::UnsupportedScheme { scheme_id })?;
        if scheme != PqScheme::Falcon512 || scheme.is_disabled() {
            return Err(SignerError::UnsupportedScheme { scheme_id });
        }
        let hex_pk = parsed.public_key.ok_or(SignerError::MalformedResponse(
            MalformedResponseKind::MissingField,
        ))?;
        let raw_pk = hex::decode(&hex_pk)
            .map_err(|_| SignerError::MalformedResponse(MalformedResponseKind::NotHex))?;
        let got_pk = raw_pk.len();
        let public_key: [u8; FALCON_PUBLIC_KEY_LEN] = raw_pk
            .try_into()
            .map_err(|_| SignerError::BadPublicKeyLength { got: got_pk })?;
        if public_key[0] != 0x09 {
            return Err(SignerError::MalformedKey);
        }
        let hex_vid = parsed.validator_id.ok_or(SignerError::MalformedResponse(
            MalformedResponseKind::MissingField,
        ))?;
        let raw_vid = hex::decode(&hex_vid)
            .map_err(|_| SignerError::MalformedResponse(MalformedResponseKind::NotHex))?;
        let validator_id: [u8; 32] = raw_vid
            .try_into()
            .map_err(|_| SignerError::ValidatorIdMismatch)?;
        Ok(RemotePublicKeyInfo {
            scheme,
            public_key,
            validator_id,
        })
    }

    fn sign_v2(
        &self,
        req: &SignRequestV2,
    ) -> Result<([u8; FALCON_SIGNATURE_LEN], u64), SignerError> {
        self.check_scheme_policy()?;
        let request_body = serde_json::to_string(req)
            .map_err(|_| SignerError::Transport(TransportErrorKind::Request))?;
        let body = self.finish(
            self.request("POST", &self.sign_path)
                .set("Content-Type", "application/json")
                .send_string(&request_body),
        )?;
        let parsed: RawSignResponseV2 = serde_json::from_slice(&body).map_err(|e| {
            tracing::debug!(
                "[remote-signer-v2] sign response is not valid json ({:?})",
                e.classify()
            );
            SignerError::MalformedResponse(MalformedResponseKind::BadJson)
        })?;
        let scheme_id = parsed.scheme_id.ok_or(SignerError::MalformedResponse(
            MalformedResponseKind::MissingField,
        ))?;
        let scheme = PqScheme::from_id(scheme_id)
            .map_err(|_| SignerError::UnsupportedScheme { scheme_id })?;
        if scheme != PqScheme::Falcon512 || scheme.is_disabled() {
            return Err(SignerError::UnsupportedScheme { scheme_id });
        }
        let hex_sig = parsed.signature.ok_or(SignerError::MalformedResponse(
            MalformedResponseKind::MissingField,
        ))?;
        let raw_sig = hex::decode(&hex_sig)
            .map_err(|_| SignerError::MalformedResponse(MalformedResponseKind::NotHex))?;
        let got_sig = raw_sig.len();
        let signature: [u8; FALCON_SIGNATURE_LEN] = raw_sig
            .try_into()
            .map_err(|_| SignerError::BadSignatureLength { got: got_sig })?;
        let generation = parsed.generation.ok_or(SignerError::MalformedResponse(
            MalformedResponseKind::MissingField,
        ))?;
        Ok((signature, generation))
    }
}

/// Reference HTTP v2 remote signer service enforcing anti-oracle preimage
/// verification and durable/serialized anti-equivocation checks.
pub struct PqSignerService {
    signer: LocalPqSigner,
    expected_bearer_token: Option<String>,
}

impl PqSignerService {
    pub fn new(signer: LocalPqSigner) -> Self {
        Self {
            signer,
            expected_bearer_token: None,
        }
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.expected_bearer_token = Some(token.into());
        self
    }

    pub fn signer(&self) -> &LocalPqSigner {
        &self.signer
    }

    /// Process one v2 HTTP request, returning `(http_status, json_body)`.
    pub fn handle_http_request(
        &self,
        method: &str,
        path: &str,
        auth_header: Option<&str>,
        body: &[u8],
    ) -> (u16, String) {
        if let Some(expected_tok) = &self.expected_bearer_token {
            let expected = format!("Bearer {expected_tok}");
            if auth_header != Some(expected.as_str()) {
                return (401, r#"{"error":"unauthorized"}"#.to_string());
            }
        }
        match (method, path) {
            ("GET", DEFAULT_V2_PUBLIC_KEY_PATH) => {
                let resp = PublicKeyResponseV2 {
                    scheme_id: PqScheme::Falcon512.id(),
                    public_key: hex::encode(self.signer.public_key()),
                    validator_id: hex::encode(self.signer.validator_id()),
                };
                match serde_json::to_string(&resp) {
                    Ok(json) => (200, json),
                    Err(_) => (500, r#"{"error":"serialization_failed"}"#.to_string()),
                }
            }
            ("POST", DEFAULT_V2_SIGN_PATH) => {
                let req: SignRequestV2 = match serde_json::from_slice(body) {
                    Ok(r) => r,
                    Err(_) => return (400, r#"{"error":"bad_json"}"#.to_string()),
                };
                if let Err(err) = req.verify_and_extract_preimage(&self.signer.validator_id()) {
                    let status = match err {
                        SignerError::ValidatorIdMismatch
                        | SignerError::SigningFailed(SigningFailureKind::InvalidRequest)
                        | SignerError::SigningFailed(SigningFailureKind::EmptyMessage) => 400,
                        _ => 400,
                    };
                    return (
                        status,
                        r#"{"error":"invalid_consensus_request"}"#.to_string(),
                    );
                }
                match self
                    .signer
                    .sign_consensus_with_generation(&req.request, req.value_id)
                {
                    Ok((sig, generation)) => {
                        let resp = SignResponseV2 {
                            scheme_id: PqScheme::Falcon512.id(),
                            signature: hex::encode(sig),
                            generation,
                        };
                        match serde_json::to_string(&resp) {
                            Ok(json) => (200, json),
                            Err(_) => (500, r#"{"error":"serialization_failed"}"#.to_string()),
                        }
                    }
                    Err(SignerError::SafetyViolation) => {
                        (409, r#"{"error":"safety_violation"}"#.to_string())
                    }
                    Err(SignerError::SafetyStoreQuarantined) => {
                        (503, r#"{"error":"safety_store_quarantined"}"#.to_string())
                    }
                    Err(_) => (500, r#"{"error":"signing_failed"}"#.to_string()),
                }
            }
            _ => (404, r#"{"error":"not_found"}"#.to_string()),
        }
    }
}

/// Serve a single HTTP/1.1 connection against [`PqSignerService`].
pub fn serve_v2_http_connection(service: &PqSignerService, mut stream: TcpStream) {
    let Ok(cloned) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(cloned);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let mut content_length = 0usize;
    let mut auth_header: Option<String> = None;
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
        if let Some((name, val)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = val.trim().parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("Authorization") {
                auth_header = Some(val.trim().to_string());
            }
        }
    }

    if content_length > 64 * 1024 {
        let body = r#"{"error":"request_too_large"}"#;
        let head = format!(
            "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body.as_bytes());
        let _ = stream.flush();
        return;
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }

    let (status_code, resp_body) =
        service.handle_http_request(method, path, auth_header.as_deref(), &body);
    let reason = match status_code {
        200 => "200 OK",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        404 => "404 Not Found",
        409 => "409 Conflict",
        503 => "503 Service Unavailable",
        _ => "500 Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(resp_body.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod v2_tests {
    use super::*;
    use std::net::TcpListener;

    fn test_falcon_key(seed_byte: u8) -> (FalconKeypair, [u8; 32]) {
        let kp = FalconKeypair::generate_from_seed_bytes(&[seed_byte; 32]);
        let vid = kp.validator_id();
        (kp, vid)
    }

    #[test]
    fn v2_service_handles_http_roundtrip_and_rejects_anti_oracle() {
        let (kp, vid) = test_falcon_key(0x55);
        let expected_pk: [u8; FALCON_PUBLIC_KEY_LEN] =
            kp.public_key().try_into().expect("897B falcon pk");
        let service = Arc::new(PqSignerService::new(
            LocalPqSigner::new(kp, vid).expect("local pq signer"),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let svc = Arc::clone(&service);
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming().take(3).flatten() {
                serve_v2_http_connection(&svc, stream);
            }
        });

        let transport = HttpPqSignerTransport::new(format!("http://{addr}"));
        assert!(!transport.is_https_only(), "loopback permits http");
        let remote = RemotePqSigner::new(Arc::new(transport), vid, Some(&expected_pk))
            .expect("remote pq signer pins key");
        assert_eq!(remote.scheme(), PqScheme::Falcon512);
        assert_eq!(remote.public_key(), &expected_pk);

        let vote_req = ConsensusSignRequest::Vote {
            chain_id: 5757,
            shard_id: 0,
            height: 12,
            round: 1,
            kind: VoteKind::Prevote,
            block_hash: Some([0xAB; 32]),
        };
        let sig = remote.sign_consensus(&vote_req).expect("sign vote");
        assert!(remote.verify_consensus(&vote_req, &sig));

        // Anti-oracle: mismatched preimage (arbitrary tx bytes) refused by service -> 400
        let bad_wire = SignRequestV2 {
            validator_id: vid,
            request: vote_req.clone(),
            value_id: None,
            preimage: hex::encode(b"STELL_ARBITRARY_TX_ORACLE_ATTACK"),
        };
        let bad_transport = HttpPqSignerTransport::new(format!("http://{addr}"));
        assert_eq!(
            bad_transport.sign_v2(&bad_wire).err(),
            Some(SignerError::Transport(TransportErrorKind::Rejected {
                status: 400
            }))
        );

        handle.join().expect("server thread");
    }

    #[test]
    fn non_loopback_http_url_is_refused() {
        let transport = HttpPqSignerTransport::new("http://signer.internal:8443");
        assert!(transport.is_https_only());
        assert_eq!(
            transport.public_key_v2().err(),
            Some(SignerError::PlainHttpForbiddenOnNonLoopback)
        );
        assert!(is_loopback_base_url("http://127.0.0.1:8080"));
        assert!(is_loopback_base_url("http://[::1]:8080"));
        assert!(is_loopback_base_url("http://localhost:8080"));
        assert!(!is_loopback_base_url("http://localhost.evil.com:8080"));
    }
}
