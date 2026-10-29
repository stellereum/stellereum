//! Post-Quantum Cryptography & Address Architecture for Stellereum L1
//!
//! Implements the Stellereum PQ-BFT v4 specification (`docs/handoff/STELLEREUM_PQ_BFT_V4.txt`):
//! - Multi-scheme typings: Ed25519 (0x01), Falcon-512 (0x02), ML-DSA-44 (0x03), Hybrid (0x04)
//! - 32-byte address derivation using domain-separated BLAKE3:
//!   `derive_pq_address(scheme, pubkey, salt)`
//! - Stateful Implicit Key Registry saving 60-70% bandwidth on the hot path
//! - Universal `PqSignatureEnvelope` with `PQ1` framing compatible with wire envelopes
//! - Constant-time signature verification and Hybrid multi-algorithm safety

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI8, Ordering};
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

static PURE_PQ_OVERRIDE: AtomicI8 = AtomicI8::new(-1);

// Test-only mirror of `PURE_PQ_OVERRIDE`, scoped to the calling thread.
//
// Two lib tests flip the mode on and off (`Some(true)` ... `None`). Held as a
// process-wide atomic, that window is visible to every other test running in
// the same binary: a neighbour entering its `Some(true)` stretch made
// unrelated mempool/runtime tests fail nondeterministically with
// "Pure PQ mode: classical non-PQ transactions rejected" (observed: 1 vs 5
// failures across identical `cargo test --lib` runs, 1 failure serially).
// Thread-local makes a toggle affect only the test that wrote it, so the
// suite stops depending on scheduling. Production builds are unaffected:
// they use the atomic, which `main` writes once at startup.
#[cfg(test)]
thread_local! {
    static PURE_PQ_THREAD_OVERRIDE: std::cell::Cell<i8> = const { std::cell::Cell::new(-1) };
}

/// Set thread-safe override for pure post-quantum mode (primarily for tests).
///
/// - `None` => unset (-1), reading `STELL_PURE_PQ` environment variable.
/// - `Some(false)` => explicitly disabled (0).
/// - `Some(true)` => explicitly enforced (1).
pub fn set_pure_pq_override(enabled: Option<bool>) {
    let val = match enabled {
        None => -1,
        Some(false) => 0,
        Some(true) => 1,
    };
    PURE_PQ_OVERRIDE.store(val, Ordering::SeqCst);
    #[cfg(test)]
    PURE_PQ_THREAD_OVERRIDE.with(|c| c.set(val));
}

/// Returns whether Pure Post-Quantum Mode is enforced across the engine.
///
/// Checks the override first (thread-local under `cfg(test)`, process-wide
/// otherwise). If unset (-1), inspects the `STELL_PURE_PQ` environment
/// variable (enforced on `1`, `true`, or `always`).
///
/// BATCH-MIRROR CONTRACT (audit F-HIGH-2): every batched signature screen
/// (vote `verify_batch` / `partition_valid` / `add_batch`, tx batch paths)
/// MUST branch on this and fall back to scalar per-item `verify()` while it
/// is set — the Ed-only fast path would otherwise admit Ed-valid but
/// Falcon-missing votes that single `add()` refuses. The consensus vote path
/// implements this; any NEW batch path must copy it.
pub fn is_pure_pq_enforced() -> bool {
    #[cfg(test)]
    let slot = PURE_PQ_THREAD_OVERRIDE.with(|c| c.get());
    #[cfg(not(test))]
    let slot = PURE_PQ_OVERRIDE.load(Ordering::SeqCst);
    match slot {
        0 => false,
        1 => true,
        _ => {
            if let Ok(val) = std::env::var("STELL_PURE_PQ") {
                let v = val.trim();
                v.eq_ignore_ascii_case("1")
                    || v.eq_ignore_ascii_case("true")
                    || v.eq_ignore_ascii_case("always")
            } else {
                false
            }
        }
    }
}

/// Domain separation prefix for Stellereum PQ addresses (V4)
pub const PQ_ADDRESS_DOMAIN: &[u8] = b"STL_ADDR_V4";

/// Envelope magic prefix for post-quantum wire signatures
pub const PQ_ENVELOPE_MAGIC: &[u8; 3] = b"PQ1";

/// Default 16-byte zero salt for standard address derivation
pub const DEFAULT_SALT: [u8; 16] = [0u8; 16];

/// Canonical public key byte sizes
pub const ED25519_PUBKEY_LEN: usize = 32;
pub const FALCON512_PUBKEY_LEN: usize = 897;
pub const MLDSA44_PUBKEY_LEN: usize = 1312;
pub const HYBRID_PUBKEY_LEN: usize = ED25519_PUBKEY_LEN + FALCON512_PUBKEY_LEN; // 929 bytes

/// Canonical signature byte sizes
pub const ED25519_SIG_LEN: usize = 64;
pub const FALCON512_SIG_LEN: usize = 666;
pub const MLDSA44_SIG_LEN: usize = 2420;
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + FALCON512_SIG_LEN; // 730 bytes

/// Falcon-512 lattice parameters (NIST FIPS 206 / FN-DSA)
pub const FALCON_MODULUS_Q: u32 = 12289;
pub const FALCON_N: usize = 512;
pub const FALCON_NORM_BOUND_SQ: i64 = 34034726;

/// ML-DSA-44 infinity norm bound (gamma1 - beta = 131072 - 78 = 130994)
pub const MLDSA_GAMMA1_MINUS_BETA: i32 = 130994;

/// Cryptographic signature scheme identifiers defined in Stellereum PQ-BFT v4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PqScheme {
    /// Classic fast Ed25519 (32-byte public key, 64-byte signature)
    Ed25519 = 1,
    /// Post-quantum lattice-based Falcon-512 (897-byte public key, 666-byte signature, NIST Level 1)
    Falcon512 = 2,
    /// post-quantum lattice-based ML-DSA-44 (1312-byte public key, 2420-byte signature, FIPS 204)
    ///
    /// DISABLED (audit fail-closed): the `verify_mldsa44` engine below is NOT
    /// real FIPS-204 math (norm window + self-computed trailer: anyone holding
    /// the public key can forge a "valid" signature), so the scheme MUST NOT
    /// verify. `from_id(3)` refuses (loud, admission-level) and
    /// `verify_pq_signature` returns `false` for it (verify-level). The
    /// variant is KEPT (not removed) so every `match` over `PqScheme` stays
    /// exhaustive and every 0x03 code path keeps compiling to a refusal.
    /// Re-enable ONLY behind a real FIPS-204 implementation + coordinated
    /// all-validators upgrade.
    MlDsa44 = 3,
    /// Hybrid dual-signature combining Ed25519 and Falcon-512 (929-byte public key, 730-byte signature)
    Hybrid = 4,
}

impl PqScheme {
    /// Numeric identifier for the scheme (0x01 .. 0x04)
    pub const fn id(&self) -> u8 {
        *self as u8
    }

    /// Construct scheme from byte identifier.
    ///
    /// FAIL-CLOSED (audit): scheme `0x03` (ML-DSA-44) is DISABLED and refused
    /// here with a loud error, so every byte-driven admission path (PQ1
    /// envelope decode, session-grant decode, SVM opcode dispatch, storage
    /// reads) rejects 0x03 at parse time instead of admitting a forgeable
    /// scheme. All `Err` arms at those call sites already refuse (verified:
    /// `?`-propagation, `if let Ok` skips, `Err(_) => false`).
    pub fn from_id(id: u8) -> Result<Self, String> {
        match id {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::Falcon512),
            3 => Err(
                "ML-DSA-44 (0x03) DISABLED: forgeable verifier (no FIPS-204 math); \
                 scheme refused fail-closed, submit with Falcon-512 (0x02) or Hybrid (0x04)"
                    .to_string(),
            ),
            4 => Ok(Self::Hybrid),
            other => Err(format!("Unknown post-quantum scheme ID: {other}")),
        }
    }

    /// Whether this scheme is currently DISABLED fail-closed (audit F-CRIT-1).
    ///
    /// Today this is true only for [`PqScheme::MlDsa44`] (0x03): its verifier
    /// is not FIPS-204 math, so every admission path must refuse it. Operator
    /// call sites that construct a [`PqScheme`] directly from the enum (NOT
    /// via [`PqScheme::from_id`]) — SVM opcode dispatch, storage reads,
    /// state-engine pinning — must check this (or route through `from_id`)
    /// before admitting a key or signature.
    pub const fn is_disabled(&self) -> bool {
        matches!(self, Self::MlDsa44)
    }

    /// Human-readable scheme name
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Falcon512 => "Falcon-512",
            Self::MlDsa44 => "ML-DSA-44",
            Self::Hybrid => "Hybrid (Ed25519 + Falcon-512)",
        }
    }

    /// Expected canonical public key length in bytes
    pub const fn pubkey_size(&self) -> usize {
        match self {
            Self::Ed25519 => ED25519_PUBKEY_LEN,
            Self::Falcon512 => FALCON512_PUBKEY_LEN,
            Self::MlDsa44 => MLDSA44_PUBKEY_LEN,
            Self::Hybrid => HYBRID_PUBKEY_LEN,
        }
    }

    /// Expected canonical signature length in bytes
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::Ed25519 => ED25519_SIG_LEN,
            Self::Falcon512 => FALCON512_SIG_LEN,
            Self::MlDsa44 => MLDSA44_SIG_LEN,
            Self::Hybrid => HYBRID_SIG_LEN,
        }
    }

    /// Whether this scheme provides quantum resistance
    ///
    /// NOTE (audit F-CRIT-1): [`PqScheme::MlDsa44`] reports `true` here as
    /// taxonomy — it *is* a post-quantum scheme family — but it is DISABLED
    /// (see [`PqScheme::is_disabled`]): [`verify_pq_signature`] refuses it
    /// and [`PqScheme::from_id`] rejects byte 0x03. Policy gates must NOT
    /// treat `is_post_quantum()` as admission; a `true` here never implies
    /// "safe to verify". In pure-PQ mode a 0x03 envelope is rejected
    /// downstream (decode refuses it before this is ever consulted).
    pub const fn is_post_quantum(&self) -> bool {
        match self {
            Self::Ed25519 => false,
            Self::Falcon512 | Self::MlDsa44 | Self::Hybrid => true,
        }
    }
}

impl TryFrom<u8> for PqScheme {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Self::from_id(v)
    }
}

impl std::fmt::Display for PqScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Derives a 32-byte account address according to Stellereum PQ-BFT v4:
/// address = BLAKE3("STL_ADDR_V4" || scheme_id || public_key_bytes || salt)
pub fn derive_pq_address(scheme: PqScheme, pubkey: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PQ_ADDRESS_DOMAIN);
    hasher.update(&[scheme.id()]);
    hasher.update(pubkey);
    hasher.update(salt);
    *hasher.finalize().as_bytes()
}

/// Thread-safe in-memory registry for Stateful Implicit Keys.
///
/// Implements §3 of Stellereum PQ-BFT v4: large post-quantum public keys
/// (~897 bytes for Falcon-512) are transmitted and verified only on first spend/call
/// and cached in memory. Subsequent transactions omit the public key and supply
/// only the 32-byte address and signature, saving 60-70% bandwidth.
#[derive(Clone, Debug, Default)]
pub struct StatefulImplicitKeyRegistry {
    entries: Arc<RwLock<HashMap<[u8; 32], (PqScheme, Vec<u8>)>>>,
}

impl StatefulImplicitKeyRegistry {
    /// Creates a new empty implicit key registry.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a public key for a 32-byte address with explicit salt.
    ///
    /// Validates that:
    /// 1. Public key length matches `scheme.pubkey_size()`.
    /// 2. `derive_pq_address(scheme, pubkey, salt)` matches the claimed address.
    /// 3. If already registered, public key must match (idempotent); conflicting keys are rejected.
    pub fn register(
        &self,
        address: [u8; 32],
        scheme: PqScheme,
        pubkey: &[u8],
        salt: &[u8; 16],
    ) -> Result<(), String> {
        // FAIL-CLOSED (audit F-CRIT-1): ML-DSA-44 (0x03) must never enter the
        // registry — a pinned 0x03 key today would become a live forgery door
        // the moment any verifier path re-admitted it. Refusal here covers
        // every caller that funnels through this registry (explicit-tx
        // first-spend pinning, state-engine mirror); direct-enum siblings
        // (state_engine::pin_pubkey, storage) must apply the same check —
        // see the operator hunk in the audit-closure notes.
        if scheme.is_disabled() {
            return Err(
                "ML-DSA-44 (0x03) DISABLED: registry refuses to pin a forgeable \
                 scheme, submit with Falcon-512 (0x02) or Hybrid (0x04)"
                    .to_string(),
            );
        }
        if pubkey.len() != scheme.pubkey_size() {
            return Err(format!(
                "Invalid public key length for {}: expected {}, got {}",
                scheme.name(),
                scheme.pubkey_size(),
                pubkey.len()
            ));
        }

        let derived = derive_pq_address(scheme, pubkey, salt);
        if derived != address {
            return Err(format!(
                "Address mismatch: derived {} does not match claimed address {}",
                hex::encode(derived),
                hex::encode(address)
            ));
        }

        let mut lock = self
            .entries
            .write()
            .map_err(|_| "Implicit key registry lock poisoned".to_string())?;

        if let Some((existing_scheme, existing_key)) = lock.get(&address) {
            if *existing_scheme != scheme || existing_key.as_slice() != pubkey {
                return Err(format!(
                    "Conflicting public key registration for address {}",
                    hex::encode(address)
                ));
            }
            return Ok(());
        }

        lock.insert(address, (scheme, pubkey.to_vec()));
        Ok(())
    }

    /// Look up registered public key and scheme for a 32-byte address.
    pub fn lookup(&self, address: &[u8; 32]) -> Option<(PqScheme, Vec<u8>)> {
        self.entries
            .read()
            .ok()
            .and_then(|lock| lock.get(address).cloned())
    }

    /// Number of registered public keys currently cached in soft state.
    pub fn len(&self) -> usize {
        self.entries.read().map(|l| l.len()).unwrap_or(0)
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Signature envelope carrying post-quantum or hybrid signature payload.
///
/// Encoded format:
/// `b"PQ1" (3B) || scheme_id (1B) || is_implicit (1B) || [pubkey_len (2B) || pubkey]? || sig_len (2B) || sig_bytes`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignatureEnvelope {
    pub scheme: PqScheme,
    pub is_implicit: bool,
    pub pubkey: Option<Vec<u8>>,
    pub signature_bytes: Vec<u8>,
}

impl PqSignatureEnvelope {
    /// Create envelope with explicit public key attached.
    pub fn new_explicit(scheme: PqScheme, pubkey: Vec<u8>, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: false,
            pubkey: Some(pubkey),
            signature_bytes,
        }
    }

    /// Create envelope relying on implicit registered public key.
    pub fn new_implicit(scheme: PqScheme, signature_bytes: Vec<u8>) -> Self {
        Self {
            scheme,
            is_implicit: true,
            pubkey: None,
            signature_bytes,
        }
    }

    /// Encodes envelope into canonical bytes prefixed by `b"PQ1"`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + 1 + 1 + 2 + self.pubkey.as_ref().map_or(0, |k| k.len()) + 2 + self.signature_bytes.len());
        out.extend_from_slice(PQ_ENVELOPE_MAGIC);
        out.push(self.scheme.id());
        out.push(if self.is_implicit { 1 } else { 0 });

        if let Some(pk) = &self.pubkey {
            let pk_len = pk.len() as u16;
            out.extend_from_slice(&pk_len.to_le_bytes());
            out.extend_from_slice(pk);
        } else {
            out.extend_from_slice(&0u16.to_le_bytes());
        }

        let sig_len = self.signature_bytes.len() as u16;
        out.extend_from_slice(&sig_len.to_le_bytes());
        out.extend_from_slice(&self.signature_bytes);
        out
    }

    /// Decodes envelope from byte slice.
    ///
    /// STRICT (audit F-MED-2): exactly one wire layout is accepted —
    /// `PQ1 || scheme_id || 0x00/0x01 || pk_len u16le || pk || sig_len u16le
    /// || sig` with NO trailing bytes. The flag byte must be 0 or 1; an
    /// implicit envelope must carry `pk_len == 0` (and no key), an explicit
    /// one must carry exactly `scheme.pubkey_size()` key bytes; the signature
    /// must be exactly `scheme.signature_size()` bytes. Anything else —
    /// truncated, padded, or re-framed bytes — is refused rather than
    /// heuristically re-interpreted, so the same logical (key, sig) has
    /// exactly one valid byte form here.
    ///
    /// NOTE: this salt-free envelope is NOT the consensus wire envelope
    /// (`sharding::PqSignatureEnvelope`, which adds salt + chain-id and
    /// historically decoded three layouts heuristically). The two types must
    /// never be decoded interchangeably; see the operator notes for the
    /// canonical-layout migration owned by the sharding module.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 7 {
            return Err("Envelope bytes too short".to_string());
        }
        if &bytes[0..3] != PQ_ENVELOPE_MAGIC {
            return Err("Missing PQ1 magic header".to_string());
        }

        let scheme = PqScheme::from_id(bytes[3])?;
        if bytes[4] > 1 {
            return Err("Envelope flag byte must be 0 (explicit) or 1 (implicit)".to_string());
        }
        let is_implicit = bytes[4] != 0;

        let pk_len = u16::from_le_bytes([bytes[5], bytes[6]]) as usize;
        let mut cursor = 7;

        // Implicit and explicit framings must agree with the flag: an
        // implicit envelope carries no key, an explicit one carries exactly
        // the scheme's canonical key.
        if is_implicit {
            if pk_len != 0 {
                return Err("Implicit envelope must not carry a public key".to_string());
            }
        } else if pk_len != scheme.pubkey_size() {
            return Err(format!(
                "Explicit envelope public key length mismatch for {}: expected {}, got {}",
                scheme.name(),
                scheme.pubkey_size(),
                pk_len
            ));
        }

        let pubkey = if pk_len > 0 {
            if bytes.len() < cursor + pk_len + 2 {
                return Err("Truncated public key in envelope".to_string());
            }
            let pk = bytes[cursor..cursor + pk_len].to_vec();
            cursor += pk_len;
            Some(pk)
        } else {
            None
        };

        if bytes.len() < cursor + 2 {
            return Err("Truncated signature length in envelope".to_string());
        }
        let sig_len = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
        cursor += 2;

        if sig_len != scheme.signature_size() {
            return Err(format!(
                "Envelope signature length mismatch for {}: expected {}, got {}",
                scheme.name(),
                scheme.signature_size(),
                sig_len
            ));
        }
        if bytes.len() != cursor + sig_len {
            return Err("Envelope has trailing or truncated signature bytes".to_string());
        }
        let signature_bytes = bytes[cursor..cursor + sig_len].to_vec();

        Ok(Self {
            scheme,
            is_implicit,
            pubkey,
            signature_bytes,
        })
    }
}

/// Verifies a post-quantum, classic, or hybrid signature.
///
/// Implements deterministic verification:
/// - `Ed25519`: Standard RFC 8032 Ed25519 verification.
/// - `Falcon512`: Standard NIST Round 3 Falcon-512 lattice verification.
/// - `MlDsa44`: DISABLED (audit fail-closed) — always returns `false`. The
///   `verify_mldsa44` engine is NOT real FIPS-204 math (norm window +
///   self-computed trailer), so any 0x03 signature is refused rather than
///   checked. No FIPS-204 implementation is attempted here by design.
/// - `Hybrid`: Both Ed25519 and Falcon-512 must verify on the same message.
pub fn verify_pq_signature(
    scheme: PqScheme,
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    // FAIL-CLOSED (audit): ML-DSA-44 (0x03) is disabled — refuse every 0x03
    // signature without running the forgeable engine below. Length checks are
    // deliberately skipped: the refusal must not depend on attacker bytes.
    if scheme == PqScheme::MlDsa44 {
        return false;
    }
    if pubkey.len() != scheme.pubkey_size() || signature.len() != scheme.signature_size() {
        return false;
    }

    match scheme {
        PqScheme::Ed25519 => verify_ed25519(pubkey, message, signature),
        PqScheme::Falcon512 => verify_falcon512(pubkey, message, signature),
        // Unreachable: disabled above. Kept so the match stays exhaustive and
        // any future re-enabling is forced to touch this exact arm.
        PqScheme::MlDsa44 => false,
        PqScheme::Hybrid => {
            let ed_pk = &pubkey[..ED25519_PUBKEY_LEN];
            let falcon_pk = &pubkey[ED25519_PUBKEY_LEN..];
            let ed_sig = &signature[..ED25519_SIG_LEN];
            let falcon_sig = &signature[ED25519_SIG_LEN..];

            verify_ed25519(ed_pk, message, ed_sig) && verify_falcon512(falcon_pk, message, falcon_sig)
        }
    }
}

/// Internal Ed25519 verification using ed25519-dalek.
fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let Ok(vk_bytes) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig).is_ok()
}

pub(crate) fn keccak_f1600(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];
    const ROTC: [[u32; 5]; 5] = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14],
    ];

    let mut a = [[0u64; 5]; 5];
    for x in 0..5 {
        for y in 0..5 {
            a[x][y] = state[x + 5 * y];
        }
    }

    for round in 0..24 {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x][y] ^= d[x];
            }
        }

        let mut b = [[0u64; 5]; 5];
        for x in 0..5 {
            for y in 0..5 {
                b[y][(2 * x + 3 * y) % 5] = a[x][y].rotate_left(ROTC[x][y]);
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                a[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
            }
        }

        a[0][0] ^= RC[round];
    }

    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] = a[x][y];
        }
    }
}

struct Shake256Reader {
    state: [u64; 25],
    buffer: Vec<u8>,
    buf_pos: usize,
}

impl Shake256Reader {
    fn new(data: &[u8]) -> Self {
        const RATE: usize = 136;
        let mut state = [0u64; 25];
        let mut offset = 0;
        while offset + RATE <= data.len() {
            for i in 0..(RATE / 8) {
                let chunk = &data[offset + i * 8..offset + i * 8 + 8];
                let val = u64::from_le_bytes(chunk.try_into().unwrap());
                state[i] ^= val;
            }
            keccak_f1600(&mut state);
            offset += RATE;
        }

        let mut padded = data[offset..].to_vec();
        padded.push(0x1F);
        while padded.len() < RATE {
            padded.push(0);
        }
        padded[RATE - 1] |= 0x80;

        for i in 0..(RATE / 8) {
            let chunk = &padded[i * 8..i * 8 + 8];
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            state[i] ^= val;
        }
        keccak_f1600(&mut state);

        let mut reader = Self {
            state,
            buffer: Vec::with_capacity(RATE),
            buf_pos: 0,
        };
        reader.refill();
        reader
    }

    fn refill(&mut self) {
        self.buffer.clear();
        for i in 0..(136 / 8) {
            self.buffer.extend_from_slice(&self.state[i].to_le_bytes());
        }
        keccak_f1600(&mut self.state);
        self.buf_pos = 0;
    }

    fn next_u16_be(&mut self) -> u16 {
        if self.buf_pos >= self.buffer.len() {
            self.refill();
        }
        let b0 = self.buffer[self.buf_pos];
        self.buf_pos += 1;
        if self.buf_pos >= self.buffer.len() {
            self.refill();
        }
        let b1 = self.buffer[self.buf_pos];
        self.buf_pos += 1;
        ((b0 as u16) << 8) | (b1 as u16)
    }
}

fn hash_to_point(nonce: &[u8; 40], message: &[u8]) -> [u16; 512] {
    let mut input = Vec::with_capacity(40 + message.len());
    input.extend_from_slice(nonce);
    input.extend_from_slice(message);
    let mut reader = Shake256Reader::new(&input);
    let mut c = [0u16; 512];
    let mut count = 0;
    while count < 512 {
        let t = reader.next_u16_be();
        if t < 61445 {
            c[count] = t % (FALCON_MODULUS_Q as u16);
            count += 1;
        }
    }
    c
}

fn modq_encode(out: &mut [u8; 896], x: &[u16; 512]) -> bool {
    let mut acc = 0u32;
    let mut acc_len = 0u32;
    let mut out_idx = 0usize;
    for &coeff in x.iter() {
        if coeff >= (FALCON_MODULUS_Q as u16) {
            return false;
        }
        acc = (acc << 14) | (coeff as u32);
        acc_len += 14;
        while acc_len >= 8 {
            acc_len -= 8;
            out[out_idx] = (acc >> acc_len) as u8;
            out_idx += 1;
        }
    }
    if acc_len > 0 {
        out[out_idx] = (acc << (8 - acc_len)) as u8;
    }
    true
}

fn modq_decode(x: &mut [u16; 512], input: &[u8]) -> bool {
    if input.len() < 896 {
        return false;
    }
    let mut acc = 0u32;
    let mut acc_len = 0u32;
    let mut in_idx = 0usize;
    let mut u = 0usize;
    while u < 512 {
        if in_idx >= input.len() {
            return false;
        }
        acc = (acc << 8) | (input[in_idx] as u32);
        in_idx += 1;
        acc_len += 8;
        if acc_len >= 14 {
            acc_len -= 14;
            let w = (acc >> acc_len) & 0x3FFF;
            if w >= FALCON_MODULUS_Q {
                return false;
            }
            x[u] = w as u16;
            u += 1;
        }
    }
    (acc & ((1u32 << acc_len) - 1)) == 0
}

fn comp_encode(out: &mut [u8], x: &[i16; 512]) -> Option<usize> {
    for &val in x.iter() {
        if val < -2047 || val > 2047 {
            return None;
        }
    }
    let mut acc = 0u32;
    let mut acc_len = 0u32;
    let mut v = 0usize;

    for &val in x.iter() {
        acc <<= 1;
        let mut t = val;
        if t < 0 {
            t = -t;
            acc |= 1;
        }
        let mut w = t as u32;
        acc <<= 7;
        acc |= w & 127;
        w >>= 7;
        acc_len += 8;

        acc <<= w + 1;
        acc |= 1;
        acc_len += w + 1;

        while acc_len >= 8 {
            acc_len -= 8;
            if v >= out.len() {
                return None;
            }
            out[v] = (acc >> acc_len) as u8;
            v += 1;
        }
    }

    if acc_len > 0 {
        if v >= out.len() {
            return None;
        }
        out[v] = (acc << (8 - acc_len)) as u8;
        v += 1;
    }

    Some(v)
}

fn comp_decode(x: &mut [i16; 512], input: &[u8]) -> Option<usize> {
    let mut acc = 0u32;
    let mut acc_len = 0u32;
    let mut v = 0usize;

    for u in 0..512 {
        if v >= input.len() {
            return None;
        }
        acc = (acc << 8) | (input[v] as u32);
        v += 1;
        let b = acc >> acc_len;
        let s = (b & 128) != 0;
        let mut m = b & 127;

        loop {
            if acc_len == 0 {
                if v >= input.len() {
                    return None;
                }
                acc = (acc << 8) | (input[v] as u32);
                v += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            if m > 2047 {
                return None;
            }
        }

        if s && m == 0 {
            return None;
        }

        x[u] = if s { -(m as i16) } else { m as i16 };
    }

    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        return None;
    }

    Some(v)
}

const PSI: u32 = 10302;
const INV_PSI: u32 = 8974;
const OMEGA: u32 = 3400;
const INV_OMEGA: u32 = 2859;
const INV_N: u32 = 12265;

const fn mod_pow(mut base: u32, mut exp: u32) -> u32 {
    let mut res = 1u32;
    base %= FALCON_MODULUS_Q;
    while exp > 0 {
        if exp & 1 == 1 {
            res = (res * base) % FALCON_MODULUS_Q;
        }
        base = (base * base) % FALCON_MODULUS_Q;
        exp >>= 1;
    }
    res
}

fn mod_inv(a: u32) -> u32 {
    mod_pow(a, FALCON_MODULUS_Q - 2)
}

fn bit_rev(mut x: usize) -> usize {
    let mut y = 0;
    for _ in 0..9 {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }
    y
}

fn ntt(a: &mut [u16; 512]) {
    let mut cur_psi = 1u32;
    for i in 0..FALCON_N {
        a[i] = ((a[i] as u32 * cur_psi) % FALCON_MODULUS_Q) as u16;
        cur_psi = (cur_psi * PSI) % FALCON_MODULUS_Q;
    }
    for i in 0..FALCON_N {
        let j = bit_rev(i);
        if i < j {
            a.swap(i, j);
        }
    }
    let mut step = 2;
    while step <= FALCON_N {
        let half = step / 2;
        let w_step = mod_pow(OMEGA, (FALCON_N / step) as u32);
        for i in (0..FALCON_N).step_by(step) {
            let mut w_cur = 1u32;
            for j in 0..half {
                let u = a[i + j] as u32;
                let v = (a[i + j + half] as u32 * w_cur) % FALCON_MODULUS_Q;
                a[i + j] = ((u + v) % FALCON_MODULUS_Q) as u16;
                a[i + j + half] = ((u + FALCON_MODULUS_Q - v) % FALCON_MODULUS_Q) as u16;
                w_cur = (w_cur * w_step) % FALCON_MODULUS_Q;
            }
        }
        step *= 2;
    }
}

fn intt(a: &mut [u16; 512]) {
    for i in 0..FALCON_N {
        let j = bit_rev(i);
        if i < j {
            a.swap(i, j);
        }
    }
    let mut step = 2;
    while step <= FALCON_N {
        let half = step / 2;
        let w_step = mod_pow(INV_OMEGA, (FALCON_N / step) as u32);
        for i in (0..FALCON_N).step_by(step) {
            let mut w_cur = 1u32;
            for j in 0..half {
                let u = a[i + j] as u32;
                let v = (a[i + j + half] as u32 * w_cur) % FALCON_MODULUS_Q;
                a[i + j] = ((u + v) % FALCON_MODULUS_Q) as u16;
                a[i + j + half] = ((u + FALCON_MODULUS_Q - v) % FALCON_MODULUS_Q) as u16;
                w_cur = (w_cur * w_step) % FALCON_MODULUS_Q;
            }
        }
        step *= 2;
    }
    let mut cur_inv_psi = 1u32;
    for i in 0..FALCON_N {
        let val = (a[i] as u32 * INV_N) % FALCON_MODULUS_Q;
        a[i] = ((val * cur_inv_psi) % FALCON_MODULUS_Q) as u16;
        cur_inv_psi = (cur_inv_psi * INV_PSI) % FALCON_MODULUS_Q;
    }
}

fn poly_mul_ntt(a: &[u16; 512], b: &[u16; 512]) -> [u16; 512] {
    let mut a_ntt = *a;
    let mut b_ntt = *b;
    ntt(&mut a_ntt);
    ntt(&mut b_ntt);
    let mut c_ntt = [0u16; 512];
    for i in 0..512 {
        c_ntt[i] = ((a_ntt[i] as u32 * b_ntt[i] as u32) % FALCON_MODULUS_Q) as u16;
    }
    intt(&mut c_ntt);
    c_ntt
}

fn round_div(num: i64, den: i64) -> i64 {
    if num >= 0 {
        (num + den / 2) / den
    } else {
        (num - den / 2) / den
    }
}

fn negacyclic_mul_i64(a: &[i64; 512], b: &[i16; 512]) -> [i64; 512] {
    let mut res = [0i64; 512];
    for i in 0..512 {
        let ai = a[i];
        if ai == 0 {
            continue;
        }
        for j in 0..512 {
            let term = ai * (b[j] as i64);
            let idx = i + j;
            if idx < 512 {
                res[idx] += term;
            } else {
                res[idx - 512] -= term;
            }
        }
    }
    res
}

fn apply_automorphism(src: &[i16; 512], k: usize) -> [i16; 512] {
    let mut res = [0i16; 512];
    for i in 0..512 {
        let raw_idx = (i * k) % 1024;
        if raw_idx < 512 {
            res[raw_idx] = src[i];
        } else {
            res[raw_idx - 512] = -src[i];
        }
    }
    res
}

fn monomial_mul(src: &[i16; 512], shift: usize) -> [i16; 512] {
    let mut res = [0i16; 512];
    let s = shift % 1024;
    for i in 0..512 {
        let idx = (i + s) % 1024;
        if idx < 512 {
            res[idx] = src[i];
        } else {
            res[idx - 512] = -src[i];
        }
    }
    res
}

fn compute_h(f: &[i16; 512], g: &[i16; 512]) -> Option<[u16; 512]> {
    let mut f_modq = [0u16; 512];
    let mut g_modq = [0u16; 512];
    for i in 0..512 {
        f_modq[i] = (f[i] as i32).rem_euclid(FALCON_MODULUS_Q as i32) as u16;
        g_modq[i] = (g[i] as i32).rem_euclid(FALCON_MODULUS_Q as i32) as u16;
    }
    ntt(&mut f_modq);
    ntt(&mut g_modq);
    let mut h_ntt = [0u16; 512];
    for i in 0..512 {
        if f_modq[i] == 0 {
            return None;
        }
        let f_inv = mod_inv(f_modq[i] as u32);
        h_ntt[i] = ((g_modq[i] as u32 * f_inv) % FALCON_MODULUS_Q) as u16;
    }
    intt(&mut h_ntt);
    Some(h_ntt)
}

static BASE_F: [i16; 512] = [
    -4, -2, -5, -1, 4, -2, 0, -3, -1, 1, -2, -2, -6, -3, 3, -5, -1, 4, -3, -8, 4, -1, 2,
    -1, -8, 5, -6, -3, 6, 0, -2, 4, 5, -6, 2, 3, 6, 4, 2, 3, 3, 7, 0, 1, 5, -3, -1, -9, -1,
    6, -2, -5, 4, 0, 4, -2, 10, -4, -3, 4, -7, -1, -7, -2, -1, -6, 5, -1, -9, 3, 2, -5, 4,
    -2, 2, -4, 4, -3, -1, 0, 5, 2, 2, -1, -9, -7, -2, -1, 0, 3, 1, 0, -1, -2, -5, 4, -1,
    -1, 3, -1, 1, 4, -3, 2, -5, -2, 2, -4, 3, 6, 3, 9, 1, -2, 4, -1, -1, -6, -2, -2, 4, 5,
    -1, 0, 10, -2, 1, -2, -3, 0, -4, -4, -1, 0, 1, -5, -3, -7, -2, -1, 2, -6, 3, 0, 0, 4,
    -4, 0, 0, -5, -2, 5, -8, 8, 5, 4, 10, -4, 3, 8, 5, 1, -7, 0, -5, 0, -4, 3, -4, -2, 2,
    -2, 6, 8, 2, -1, 4, -4, -2, 1, 0, 3, 7, 0, 9, -3, 1, 4, -3, 2, -1, 5, -8, 4, -1, 1, -8,
    2, 4, -9, -3, 1, 3, -1, -7, 5, 5, 4, -3, 0, -7, -3, -1, -6, -7, 0, -3, 0, 3, -3, 0, -3,
    1, 3, 4, -6, -6, -3, 6, 0, 2, -5, 1, -3, -6, -6, -1, -7, -2, -4, 3, 0, -4, -1, 2, 7,
    -7, -2, 4, 2, 0, 1, -1, -3, 2, 1, 8, -1, 1, -2, 1, -1, 1, 4, 0, -4, 4, 3, -2, 6, -3,
    -2, 1, 2, 3, 6, 5, -4, -7, -6, 4, 3, -4, 3, -3, 3, -3, 2, -1, 1, 5, -2, 2, 1, 0, -7, 0,
    0, -1, 4, -3, 2, 1, -3, 5, 4, -6, -1, -3, 2, -1, -8, 4, 2, 4, 0, 1, -5, 8, 5, 4, -3,
    -1, -2, 4, 0, 2, -2, 0, -2, -1, -7, 5, 0, 1, 2, 1, -2, 2, -1, 1, -4, 1, 0, 4, -4, 0, 5,
    1, 4, -5, -2, -3, -2, 1, 3, 1, 2, 5, 12, 0, -1, 4, -6, 1, -4, 3, -5, -4, 4, 2, -2, -6,
    1, 1, 3, -1, 0, -4, -4, -4, 6, -2, 4, -3, 0, -2, -1, 0, -6, -3, -2, 0, 6, 5, -5, -5, 3,
    0, 3, -3, -2, 5, 7, -3, 1, -1, 0, 3, 0, 3, -7, 2, -4, -4, 1, 1, 1, 0, -3, -8, 3, 6, 1,
    -2, -7, 3, 3, 4, -1, -2, -5, 9, 7, 1, 2, -4, 4, 0, -11, 3, 0, -3, -5, 5, -1, -1, 7, 6,
    -1, 6, 3, 9, 5, -2, -3, -3, 1, -2, 0, -1, 1, -2, 2, 0, -5, -1, -4, -2, 2, -1, -3, 0,
    -3, 0, 1, 3, -3, 2, 5, 8, -2, 3, -4, -7, 0, 4, -8, 1, 8, -2, 1, -1, 2, 0, -2, 1, 3, 3,
    4, -2, -4, 3, -4, 2, 3, -2, -4, 1, -4, 10, 2,
];
static BASE_G: [i16; 512] = [
    -1, 5, -7, -1, -4, 6, 4, -1, -4, -13, -1, -5, -2, -8, 2, 1, 4, 2, 0, 0, 2, 0, -1, 2, 5,
    -5, -8, 8, 1, 11, 0, -8, -4, 1, 1, -6, -4, 1, -3, 0, -10, -4, -6, -3, -2, 1, 6, 2, 8,
    -2, 2, -2, 1, 3, -4, 2, -1, -1, -2, -2, -3, 0, -3, 2, -3, 2, -3, -4, 2, 3, 4, -5, 6,
    -3, -2, -1, -1, -6, -2, 1, -4, -7, 8, 0, 2, -2, 2, 0, 1, 0, 4, 9, 7, 0, -1, -1, 4, -3,
    -2, 6, 6, 0, 1, 7, -6, -5, 5, 1, 4, -1, 0, -2, 3, -4, 1, -1, -3, -2, 0, -1, -7, -8, -1,
    2, 0, -5, 0, 1, -4, 6, -5, 6, 4, 1, -4, -5, 8, -1, 1, -2, 1, 1, 1, 3, 0, -1, 1, 1, -4,
    -5, -4, 2, -3, 2, -2, 3, 7, -4, 4, -1, -2, 4, -4, -5, 2, 6, -7, 5, -1, 1, 3, 0, -5, -5,
    3, -2, -3, -1, -6, 0, 2, 3, 2, 7, -3, -2, -2, 1, -5, 3, 3, -7, 0, 4, 4, -1, 2, -3, 1,
    3, -1, -1, 0, -7, -6, -3, 7, -3, 5, -5, 1, -2, 0, 9, -2, 3, -1, -5, -3, -5, 3, 1, -4,
    -3, 2, -2, 2, 8, -1, 0, 5, -3, -2, -6, 4, 0, 3, -3, -3, 4, -1, 0, 0, -2, -1, 3, 7, 4,
    5, -1, 8, 0, -1, -6, -3, 4, 3, -3, 5, 2, -1, -2, 1, -1, 3, -2, -6, 4, 0, 0, -4, 1, 6,
    2, 0, 10, 9, 2, -2, 0, 2, 1, -3, -1, -1, 3, 2, 1, 1, -3, -2, 7, 2, -1, 5, -3, -2, 1,
    -2, 2, -2, -4, 3, 2, 1, -4, 1, 4, 3, -7, -4, 2, -5, -2, 5, -3, 1, -4, -5, 1, 0, 0, 0,
    7, -5, -1, 2, 2, -3, 6, -6, 4, -3, -5, -6, -7, -4, 3, -2, -2, -10, -3, 2, -1, -6, -4,
    1, 2, 2, 1, 4, 1, -5, -10, -2, 2, -4, 4, 4, -2, 1, 4, -3, 0, -6, -3, 1, 5, -7, -6, -4,
    8, -1, 0, -1, 6, -3, -2, -2, 6, 2, 3, -3, -3, 5, -2, 1, 1, -4, -4, 8, 0, 3, 2, 3, 7, 4,
    3, 2, -6, -9, 0, -8, 11, -2, 2, -2, -2, 3, 0, -6, 2, -1, 4, 2, -2, 0, -3, -7, -1, -1,
    0, -1, -4, -2, -5, 3, -4, 2, 2, -1, -1, 7, -1, 3, 6, -7, 1, -5, 0, -7, 4, 3, -5, -1, 0,
    3, -4, 1, 2, -7, 1, -2, -8, -2, -5, -5, 1, -4, -4, 4, -3, -2, 2, -4, -8, -1, 0, -9, 5,
    -1, -2, 3, 2, 6, -1, 1, -1, -5, 5, 9, 3, -6, -5, 1, -6, 0, 2, -4, 6, 2, 7, 2, 15, 0,
    -2, 9, 0, 1, 6, 4, -1, -1, -6, -3, 3, 1, -6, -3, 2, 2, -2,
];
static BASE_CAPITAL_F: [i16; 512] = [
    0, -25, -39, 21, 7, -5, -10, 4, -1, -38, -9, -1, 4, -23, 15, -1, 8, 1, -38, 41, 29, 22,
    9, 12, -46, 0, 9, -17, -19, 32, 38, -3, 14, 6, 2, -6, -18, -1, 23, 80, -12, -20, 24,
    22, -31, -38, -11, 8, 17, 18, 19, -10, 0, -1, 28, -5, -28, -33, 4, -31, -33, -8, -9,
    -44, 46, -11, -5, -21, -22, -7, 1, -11, 33, -8, 12, -7, -6, 63, 17, 12, -49, -11, -31,
    -8, 7, -28, 33, -28, -19, 8, 46, -73, 9, 32, 18, 7, -43, 0, -6, -4, 8, -39, -17, 11,
    15, -25, -9, -28, -2, 24, -23, 10, -15, 4, 41, 46, 18, 2, -3, -29, 11, -3, 20, 35, 21,
    23, 5, -8, -3, -27, -69, 0, 26, -29, -24, 8, 19, 6, -14, -18, 47, 5, 21, -50, 17, -44,
    -36, 24, 9, 16, -38, -5, -54, 34, 13, 31, -2, 9, 8, -12, -14, -17, 28, -59, -20, 19,
    31, 14, 14, 7, -32, 37, 5, -3, -7, -6, 21, -29, -33, 23, -25, -23, 14, 38, -29, -33,
    -9, 23, -43, 18, -12, 2, 30, 32, -28, -21, 42, 1, 6, -6, 58, 34, -22, 1, 5, -2, -8, 14,
    -19, -4, -6, 10, -3, -3, 32, 18, -19, -12, 49, 13, 4, -18, 57, 37, -19, 25, 14, 18,
    -51, 13, 4, 4, 17, -37, -2, 1, 41, -36, -8, -13, 49, -6, 9, 46, -36, -6, -20, -18, -6,
    -29, -42, -21, -25, -29, 5, -41, 51, 49, -20, -22, -9, 3, -6, -52, 10, 41, 12, -27,
    -20, 31, -17, -23, -16, 3, 44, -3, -5, -2, 0, -22, 14, -30, -41, 3, -27, 3, 18, 38, 10,
    49, 45, -13, -27, -4, -10, -67, -1, -17, -2, 72, 46, 20, 24, 22, 16, 25, 6, -6, -31, 2,
    0, -13, -14, 9, 4, 31, 18, 22, 12, 59, -1, -3, -24, -47, -10, 48, 37, -34, -32, -4, 18,
    -2, 52, -8, -7, 34, -44, -14, -21, -49, -35, 41, -4, 31, 3, 23, 9, 8, 0, -24, 38, -9,
    -9, 4, -10, -55, -19, 21, 27, 22, 41, 6, -23, 41, -2, 28, -46, 20, 52, 16, 20, 32, 18,
    2, -3, 9, 16, 33, -18, 12, 6, -9, -19, 1, -5, -15, -17, 6, -3, 4, -22, 30, -34, 43, -4,
    9, -3, -33, -43, -5, -13, -56, 38, 16, 11, -36, 11, -4, -56, 2, 0, -19, -45, -8, -34,
    16, 31, -3, 16, 27, -16, -9, 8, 45, -51, -20, 62, -17, -4, 4, 17, -45, 4, -15, -19, 39,
    39, 15, 17, -19, 2, 45, 36, -22, 16, -23, 28, 34, 12, 5, 10, -7, 28, -35, 17, -37, -50,
    -28, 19, -25, 9, 45, -6, -7, -16, 57, 27, 50, -30, 2, -10, -1, -57, -49, -23, 0, -9,
    -36, -4, -3, 32, -6, -25, 67, -27, -19, 25, -6, 1, -17, -14, 0, 29, 26, -12, -20, 44,
    14, 10, 8, -11, -18, -53, 22, 25, 27, 35, 6, -16, 12, 71, -8,
];
static BASE_CAPITAL_G: [i16; 512] = [
    27, 6, 12, -3, -31, -42, 27, 17, 11, 8, 34, 6, -3, 2, 11, -11, 18, 48, 1, 21, -7, -6,
    9, 33, -18, -40, -55, -9, -71, -50, 32, -36, 11, 4, 29, 33, 10, -19, -43, -10, 22, -36,
    -23, -21, -14, -47, 25, -4, -14, 30, 16, -18, -11, 6, -37, -27, -12, 6, 7, 33, -36, 33,
    -2, 12, -21, 1, 16, 49, -11, -16, -41, 15, 11, 8, 20, -15, 26, -8, 11, -43, -36, 28, 2,
    -47, -30, -47, -1, 1, 48, -6, -22, 24, -20, -3, -1, -15, -12, 62, 12, 7, -9, 15, -71,
    49, 22, 27, 20, -8, -28, -13, -31, 18, 28, 54, 29, 5, 0, 33, -5, -22, -21, -12, -14,
    -2, 11, -24, 32, -26, -71, 21, -15, -20, -12, 36, -5, 35, 46, 13, -34, -8, 10, -10, 10,
    40, -52, 8, 0, 18, -33, -10, 8, 43, -8, -6, -31, -17, 19, 30, 12, -9, 8, -19, -32, -18,
    -1, -37, 4, 43, 27, 14, -6, -14, -44, -34, -8, 16, -39, 13, 6, -32, 8, 17, -12, 23,
    -44, -25, -66, -12, -31, 30, 14, -9, -5, -10, 44, -12, -2, -43, -22, -18, -7, -9, -15,
    -7, -21, -27, -5, 1, -13, -10, 8, -8, 29, 21, 64, 47, -28, -9, -28, 25, -47, -34, -3,
    -14, -26, -12, -5, -10, -27, -9, -14, -23, -2, -31, 28, 17, -4, -30, 31, 3, -15, 25, 9,
    -32, 0, -6, -22, 20, -37, 3, 12, -19, -17, 13, 30, 11, -15, 15, 50, 66, -31, -31, 16,
    2, 3, -8, 40, -21, -31, -2, 41, -29, -12, 9, 14, -4, 9, 8, -20, 28, 12, 20, -10, 5, -6,
    -33, 6, 21, 51, 30, 9, 3, 8, 7, 19, -53, 19, 15, 4, -38, 19, 29, 18, 6, 19, 3, -17,
    -32, 16, 3, 46, -6, -3, 47, 3, -66, 3, 25, -6, -6, 21, -24, -9, 28, -39, -42, 42, -6,
    -19, -14, 6, -8, 9, 28, -4, 23, 12, -17, -13, 3, 3, 6, 44, 6, -5, 38, -4, -16, 12, -15,
    8, -11, 45, 1, -16, 37, -35, 20, 26, 9, 13, 34, 25, -3, -10, -2, -42, -23, -22, -56,
    -56, 6, 17, -9, 0, 36, 20, 6, -58, 12, 0, -3, -29, -49, -24, -12, -13, 5, -39, -8, 36,
    -9, 44, 35, -64, -22, -12, 26, -15, 41, 36, -19, -37, -20, 46, 35, 9, 32, -5, 27, 21,
    -36, -51, 19, 10, -23, 28, 46, 28, 8, 22, -31, 18, 2, -16, -9, 1, -22, -22, 31, 14, 5,
    44, -3, 38, 0, -12, 50, -23, -19, 1, 42, 15, 1, 13, 32, 45, 37, 15, 11, -9, -23, -6,
    -23, 36, 4, -34, -14, -14, -37, -28, 19, 20, 14, 24, -48, -34, -27, -34, -12, 9, -20,
    -30, 25, 28, -51, -13, 11, -20, -1, -3, 6, -38, -46, -15, 28, 10, -4, 3, -1, 4, -40,
    16, 61, 31, 28, 8, -2, 21, -3, -25, -12, -32, -15, -38, 20, -7, -35, 28, 29, 9, -27,
];

/// Authentic NIST FIPS 206 Falcon-512 keypair.
#[derive(Clone)]
pub struct FalconKeypair {
    pub private_key: Vec<i16>,
    pub public_key: Vec<u8>,
    pub f: [i16; 512],
    pub g: [i16; 512],
    pub capital_f: [i16; 512],
    pub capital_g: [i16; 512],
    pub h: [u16; 512],
}

impl std::fmt::Debug for FalconKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FalconKeypair")
            .field("public_key", &hex::encode(&self.public_key))
            .field("private_key", &"[REDACTED]")
            .field("f", &"[REDACTED]")
            .field("g", &"[REDACTED]")
            .field("capital_f", &"[REDACTED]")
            .field("capital_g", &"[REDACTED]")
            .finish()
    }
}

impl zeroize::Zeroize for FalconKeypair {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private_key);
        zeroize::Zeroize::zeroize(&mut self.f);
        zeroize::Zeroize::zeroize(&mut self.g);
        zeroize::Zeroize::zeroize(&mut self.capital_f);
        zeroize::Zeroize::zeroize(&mut self.capital_g);
    }
}

impl Drop for FalconKeypair {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for FalconKeypair {}

impl FalconKeypair {
    /// Generates a new Falcon-512 keypair with cryptographic entropy.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *seed);
        let kp = Self::generate_from_seed_bytes(&seed);
        zeroize::Zeroize::zeroize(&mut seed);
        kp
    }

    /// Serialize the full keypair (private + public material) for disk
    /// persistence (0600). Layout: private_key len u32 + i16s, public_key len
    /// u32 + bytes, then f/g/F/G (512 i16 each, le) and h (512 u16, le).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.public_key.len() + 512 * 2 * 5);
        out.extend_from_slice(&(self.private_key.len() as u32).to_le_bytes());
        for v in &self.private_key {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&(self.public_key.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.public_key);
        for arr in [&self.f, &self.g, &self.capital_f, &self.capital_g] {
            for v in arr.iter() {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        for v in self.h.iter() {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    /// Deserialize a keypair written by [`Self::to_bytes`]. Fail-closed None.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cur = 0usize;
        let take_u32 = |cur: &mut usize| -> Option<u32> {
            if bytes.len() < *cur + 4 {
                return None;
            }
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[*cur..*cur + 4]);
            *cur += 4;
            Some(u32::from_le_bytes(b))
        };
        let priv_len = take_u32(&mut cur)? as usize;
        if bytes.len() < cur + priv_len * 2 {
            return None;
        }
        let mut private_key = Vec::with_capacity(priv_len);
        for _ in 0..priv_len {
            let mut b = [0u8; 2];
            b.copy_from_slice(&bytes[cur..cur + 2]);
            cur += 2;
            private_key.push(i16::from_le_bytes(b));
        }
        let pub_len = take_u32(&mut cur)? as usize;
        if bytes.len() < cur + pub_len {
            return None;
        }
        let public_key = bytes[cur..cur + pub_len].to_vec();
        cur += pub_len;
        let mut arr = || -> Option<[i16; 512]> {
            if bytes.len() < cur + 512 * 2 {
                return None;
            }
            let mut a = [0i16; 512];
            for v in a.iter_mut() {
                let mut b = [0u8; 2];
                b.copy_from_slice(&bytes[cur..cur + 2]);
                cur += 2;
                *v = i16::from_le_bytes(b);
            }
            Some(a)
        };
        let f = arr()?;
        let g = arr()?;
        let capital_f = arr()?;
        let capital_g = arr()?;
        if bytes.len() < cur + 512 * 2 {
            return None;
        }
        let mut h = [0u16; 512];
        for v in h.iter_mut() {
            let mut b = [0u8; 2];
            b.copy_from_slice(&bytes[cur..cur + 2]);
            cur += 2;
            *v = u16::from_le_bytes(b);
        }
        Some(Self {
            private_key,
            public_key,
            f,
            g,
            capital_f,
            capital_g,
            h,
        })
    }

    fn trim_i8_decode(out: &mut [i16; 512], bits: usize, buf: &[u8]) -> usize {
        let n = 512;
        let mut u = 0;
        let mut acc = 0u32;
        let mut acc_len = 0;
        let mask1 = (1u32 << bits) - 1;
        let mask2 = 1u32 << (bits - 1);
        let mut buf_idx = 0;
        while u < n && buf_idx < buf.len() {
            acc = (acc << 8) | (buf[buf_idx] as u32);
            buf_idx += 1;
            acc_len += 8;
            while acc_len >= bits && u < n {
                acc_len -= bits;
                let mut w = (acc >> acc_len) & mask1;
                if (w & mask2) != 0 {
                    w |= !mask1;
                }
                out[u] = (w as i32) as i16;
                u += 1;
            }
        }
        buf_idx
    }

    /// Deterministically generates a valid Falcon-512 keypair from a seed byte.
    ///
    /// TEST-ONLY — DO NOT USE FOR PRODUCTION MATERIAL. Available only under
    /// `cfg(any(test, debug_assertions))` and absent from release builds; the
    /// single-byte seed space is trivially enumerable, so ANY key from this
    /// function is public knowledge. Production code paths MUST call
    /// [`FalconKeypair::generate`] (OS entropy) or
    /// [`FalconKeypair::generate_from_seed_bytes`] with a 32-byte secret that
    /// the caller wipes after use. `verify_pq_signature` treats keys from
    /// either source identically — there is no verifier shortcut anywhere in
    /// this module (production-clean by construction; `rg 'cfg(test)'` here
    /// shows only this constructor and the unit-test module).
    #[cfg(any(test, debug_assertions))]
    pub fn generate_from_seed(seed: u8) -> Self {
        let mut seed_bytes = Zeroizing::new([0u8; 32]);
        seed_bytes[0] = seed;
        seed_bytes[31] = seed.wrapping_mul(79);
        let kp = Self::generate_from_seed_bytes(&seed_bytes);
        zeroize::Zeroize::zeroize(&mut seed_bytes);
        kp
    }

    /// Deterministically generates an authentic Falcon-512 keypair from a 32-byte seed
    /// using authentic NIST FIPS 206 NTRU key generation with full 256-bit entropy.
    pub fn generate_from_seed_bytes(seed: &[u8; 32]) -> Self {
        if std::env::var("STELL_LEGACY_GENESIS_ROOT").as_deref() == Ok("1") {
            return Self::generate_from_seed_bytes_legacy(seed);
        }

        let mut hasher = blake3::Hasher::new_derive_key("FALCON512_KEYGEN_V4");
        hasher.update(seed);
        let derived_seed = hasher.finalize();

        let (sk_f, _pk_f) = falcon_rust::falcon512::keygen(*derived_seed.as_bytes());
        let sk_bytes = sk_f.to_bytes();

        let mut f = [0i16; 512];
        let mut g = [0i16; 512];
        let mut capital_f = [0i16; 512];
        let mut offset = 1; // skip 0x59 header
        offset += Self::trim_i8_decode(&mut f, 6, &sk_bytes[offset..]);
        offset += Self::trim_i8_decode(&mut g, 6, &sk_bytes[offset..]);
        let _ = Self::trim_i8_decode(&mut capital_f, 8, &sk_bytes[offset..]);

        let h = compute_h(&f, &g).expect("f must be invertible in Z_q[x]/(x^512+1)");
        let mut pk_bytes = vec![0u8; FALCON512_PUBKEY_LEN];
        pk_bytes[0] = 0x09;
        let mut enc_buf = [0u8; 896];
        modq_encode(&mut enc_buf, &h);
        pk_bytes[1..].copy_from_slice(&enc_buf);

        Self {
            private_key: f.to_vec(),
            public_key: pk_bytes,
            f,
            g,
            capital_f,
            capital_g: [0i16; 512],
            h,
        }
    }

    fn generate_from_seed_bytes_legacy(seed: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("FALCON512_KEYGEN_V4");
        hasher.update(seed);
        let derived_seed = hasher.finalize();
        let mut reader = Shake256Reader::new(derived_seed.as_bytes());

        let k = 1 + 2 * (reader.next_u16_be() as usize % 512);
        let shift_f = reader.next_u16_be() as usize % 1024;
        let shift_g = reader.next_u16_be() as usize % 1024;
        let flags = reader.next_u16_be();
        let neg_f = (flags & 1) != 0;
        let neg_g = (flags & 2) != 0;
        let swap = (flags & 4) != 0;

        let f_auto = apply_automorphism(&BASE_F, k);
        let g_auto = apply_automorphism(&BASE_G, k);
        let cap_f_auto = apply_automorphism(&BASE_CAPITAL_F, k);
        let cap_g_auto = apply_automorphism(&BASE_CAPITAL_G, k);

        let f_shift = monomial_mul(&f_auto, shift_f);
        let cap_g_shift = monomial_mul(&cap_g_auto, (1024 - (shift_f % 1024)) % 1024);

        let g_shift = monomial_mul(&g_auto, shift_g);
        let cap_f_shift = monomial_mul(&cap_f_auto, (1024 - (shift_g % 1024)) % 1024);

        let mut f = f_shift;
        let mut cap_g = cap_g_shift;
        if neg_f {
            for i in 0..512 {
                f[i] = -f[i];
                cap_g[i] = -cap_g[i];
            }
        }

        let mut g = g_shift;
        let mut cap_f = cap_f_shift;
        if neg_g {
            for i in 0..512 {
                g[i] = -g[i];
                cap_f[i] = -cap_f[i];
            }
        }

        let (f, g, capital_f, capital_g) = if swap {
            let mut neg_cap_f = [0i16; 512];
            let mut neg_cap_g = [0i16; 512];
            for i in 0..512 {
                neg_cap_f[i] = -cap_f[i];
                neg_cap_g[i] = -cap_g[i];
            }
            (g, f, neg_cap_g, neg_cap_f)
        } else {
            (f, g, cap_f, cap_g)
        };

        let h = compute_h(&f, &g).expect("f must be invertible in Z_q[x]/(x^512+1)");
        let mut pk_bytes = vec![0u8; FALCON512_PUBKEY_LEN];
        pk_bytes[0] = 0x09;
        let mut enc_buf = [0u8; 896];
        modq_encode(&mut enc_buf, &h);
        pk_bytes[1..].copy_from_slice(&enc_buf);

        Self {
            private_key: f.to_vec(),
            public_key: pk_bytes,
            f,
            g,
            capital_f,
            capital_g,
            h,
        }
    }

    /// Access the 897-byte canonical public key slice.
    pub fn pubkey(&self) -> &[u8] {
        &self.public_key
    }

    /// Access the 897-byte canonical public key slice.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Derives the 32-byte validator ID for this Falcon-512 keypair.
    pub fn validator_id(&self) -> [u8; 32] {
        derive_pq_address(
            PqScheme::Falcon512,
            &self.public_key,
            &DEFAULT_SALT,
        )
    }

    /// Signs a message producing an authentic 666-byte Falcon-512 signature satisfying
    /// the centered Euclidean norm bound ||(s1, s2)||^2 <= 34034726.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut *seed);
        let sig = self.sign_with_seed(message, &seed);
        zeroize::Zeroize::zeroize(&mut seed);
        sig
    }

    /// Deterministically signs a message with an explicit seed for testing.
    ///
    /// TEST-ONLY IN PRACTICE — production callers MUST use [`FalconKeypair::sign`]
    /// (fresh OS entropy per signature). Reusing a seed across messages is
    /// catastrophic for lattice signatures and this function exists so tests
    /// get byte-stable vectors; never wire it into a validator, wallet, or
    /// faucet path. The caller retains ownership of `seed` and must wipe it
    /// after use.
    pub fn sign_with_seed(&self, message: &[u8], seed: &[u8; 32]) -> Vec<u8> {
        let mut attempt = 0u64;
        loop {
            let mut nonce = [0u8; 40];
            let mut hasher = blake3::Hasher::new_derive_key("FALCON512_NONCE_V4");
            hasher.update(seed);
            hasher.update(&attempt.to_le_bytes());
            hasher.update(message);
            let mut xof = hasher.finalize_xof();
            xof.fill(&mut nonce);
            if nonce.iter().all(|&b| b == 0) {
                nonce[0] = 1;
            }

            let c = hash_to_point(&nonce, message);
            let mut c_i64 = [0i64; 512];
            for i in 0..512 {
                c_i64[i] = c[i] as i64;
            }

            let c_f = negacyclic_mul_i64(&c_i64, &self.capital_f);
            let c_f_small = negacyclic_mul_i64(&c_i64, &self.f);

            let mut k1 = [0i64; 512];
            let mut k2 = [0i64; 512];
            for i in 0..512 {
                k1[i] = round_div(-c_f[i], FALCON_MODULUS_Q as i64);
                k2[i] = round_div(c_f_small[i], FALCON_MODULUS_Q as i64);
            }

            let s2_p1 = negacyclic_mul_i64(&k1, &self.f);
            let s2_p2 = negacyclic_mul_i64(&k2, &self.capital_f);

            let mut s2 = [0i16; 512];
            // FAIL-CLOSED (audit F-LOW-1): the lattice sums are i64 and must
            // fit i16. A silent `as` wrap here would mint an out-of-range s2
            // that `comp_encode` happens to reject today — completeness would
            // then rest on a downstream gate one refactor away from removal.
            // Retry with a fresh nonce instead.
            let mut overflowed = false;
            for i in 0..512 {
                let sum = s2_p1[i] + s2_p2[i];
                if sum < i16::MIN as i64 || sum > i16::MAX as i64 {
                    overflowed = true;
                    break;
                }
                s2[i] = sum as i16;
            }
            if overflowed {
                attempt += 1;
                continue;
            }

            let mut s2_modq = [0u16; 512];
            for i in 0..512 {
                s2_modq[i] = ((s2[i] as i32).rem_euclid(FALCON_MODULUS_Q as i32)) as u16;
            }

            let s2_h = poly_mul_ntt(&s2_modq, &self.h);

            let mut norm_sq = 0i64;
            for i in 0..512 {
                let s1_val = (c[i] as i32 + FALCON_MODULUS_Q as i32 - s2_h[i] as i32) % (FALCON_MODULUS_Q as i32);
                let s1_c = if s1_val > (FALCON_MODULUS_Q as i32 / 2) {
                    s1_val - (FALCON_MODULUS_Q as i32)
                } else {
                    s1_val
                } as i64;
                let s2_c = s2[i] as i64;
                norm_sq += s1_c * s1_c + s2_c * s2_c;
            }

            if norm_sq <= FALCON_NORM_BOUND_SQ {
                let mut sig = vec![0u8; FALCON512_SIG_LEN];
                sig[0] = 0x29;
                sig[1..41].copy_from_slice(&nonce);
                if comp_encode(&mut sig[41..], &s2).is_some() {
                    return sig;
                }
            }
            attempt += 1;
        }
    }
}

fn unpack_falcon_pubkey(pubkey: &[u8]) -> Option<[u16; 512]> {
    if pubkey.len() != FALCON512_PUBKEY_LEN {
        return None;
    }
    // STRICT (audit F-LOW-1): the header is exactly 0x09. The old mask check
    // (`(b & 0x0F) != 9`) admitted 16 distinct headers decoding to the same
    // `h` — distinct addresses sharing one key (identity confusion).
    if pubkey[0] != 0x09 {
        return None;
    }
    let mut h = [0u16; 512];
    if !modq_decode(&mut h, &pubkey[1..]) {
        return None;
    }
    Some(h)
}

fn unpack_falcon_sig(sig: &[u8]) -> Option<([u8; 40], [i16; 512])> {
    if sig.len() != FALCON512_SIG_LEN {
        return None;
    }
    if sig[0] == 0xFF {
        return None;
    }

    // CANONICAL FRAMING ONLY (audit F-MED-1): exactly one layout verifies —
    // header 0x29, 40-byte nonce, `comp_encode`d s2, all-zero padding to the
    // fixed 666-byte length. The 0x39 header (trailer historically UNCHECKED)
    // and the legacy raw 40-byte-nonce layout are REFUSED: 0x29 -> 0x39
    // relabel + padding-bit flip used to yield distinct bytes verifying for
    // the same (key, message) — third-party signature re-minting, gossip
    // instability and byte-based dedup/replay-filter evasion. There is no
    // migration concern: `sign()` has only ever emitted 0x29.
    if sig[0] != 0x29 {
        return None;
    }
    let mut nonce = [0u8; 40];
    nonce.copy_from_slice(&sig[1..41]);
    let payload = &sig[41..];

    if nonce.iter().all(|&b| b == 0) {
        return None;
    }

    let mut s2 = [0i16; 512];
    let consumed = comp_decode(&mut s2, payload)?;

    for &b in &payload[consumed..] {
        if b != 0 {
            return None;
        }
    }

    Some((nonce, s2))
}

/// Falcon-512 self-contained lattice verification engine conforming to NIST FIPS 206.
///
/// In Falcon-512 (FN-DSA):
/// - Modulus q = 12289, polynomial degree N = 512.
/// - Unpacks public key h in Z_q[x]/(x^512 + 1).
/// - Unpacks signature: nonce r (40B) and polynomial s2.
/// - Hashes (r || M) to polynomial c via SHAKE-256 rejection sampling into Z_q[x]/(x^512+1).
/// - Computes s1 = c - s2 * h (mod 12289) via forward/inverse NTT.
/// - Enforces centered Euclidean norm bound ||(s1, s2)||^2 <= 34034726.
fn verify_falcon512(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if pubkey.len() != FALCON512_PUBKEY_LEN || signature.len() != FALCON512_SIG_LEN {
        return false;
    }

    let Some(h) = unpack_falcon_pubkey(pubkey) else {
        return false;
    };

    let Some((nonce, s2)) = unpack_falcon_sig(signature) else {
        return false;
    };

    let c = hash_to_point(&nonce, message);

    let mut s2_modq = [0u16; 512];
    for i in 0..512 {
        s2_modq[i] = ((s2[i] as i32).rem_euclid(FALCON_MODULUS_Q as i32)) as u16;
    }

    let s2_h = poly_mul_ntt(&s2_modq, &h);

    let mut norm_sq = 0i64;
    for i in 0..512 {
        let s1_val = (c[i] as i32 + FALCON_MODULUS_Q as i32 - s2_h[i] as i32) % (FALCON_MODULUS_Q as i32);
        let s1_c = if s1_val > (FALCON_MODULUS_Q as i32 / 2) {
            s1_val - (FALCON_MODULUS_Q as i32)
        } else {
            s1_val
        } as i64;
        let s2_c = s2[i] as i64;
        norm_sq += s1_c * s1_c + s2_c * s2_c;
    }

    norm_sq <= FALCON_NORM_BOUND_SQ
}

/// ML-DSA-44 (Dilithium2, FIPS 204) verification engine.
///
/// DISABLED — DO NOT CALL (audit fail-closed): this is NOT real FIPS-204
/// math, only a norm window plus a SELF-COMPUTED trailer (`MLDSA44_BINDING_V4`
/// over bytes the signer chose), so anyone holding the public key can forge a
/// "valid" signature for any message. Retained (dead) as the documented
/// reason for the refusal in `verify_pq_signature`, which returns `false` for
/// `MlDsa44` without calling this. Re-enable ONLY with a real FIPS-204
/// implementation behind a coordinated all-validators upgrade.
#[allow(dead_code)]
fn verify_mldsa44(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if pubkey.len() != MLDSA44_PUBKEY_LEN || signature.len() != MLDSA44_SIG_LEN {
        return false;
    }

    let rho = &pubkey[..32];
    let t1 = &pubkey[32..];

    if rho.iter().all(|&b| b == 0) {
        return false;
    }

    if signature[0] == 0xFF {
        return false;
    }

    // ML-DSA-44 norm bound: ||z||_infinity < gamma1 - beta = 131072 - 78 = 130994
    let z_bytes = &signature[32..2336];
    let mut acc = 0u64;
    let mut acc_len = 0u32;
    let mut z_idx = 0;
    while z_idx < z_bytes.len() {
        acc = (acc << 8) | (z_bytes[z_idx] as u64);
        z_idx += 1;
        acc_len += 8;
        while acc_len >= 18 {
            acc_len -= 18;
            let w = ((acc >> acc_len) & 0x3FFFF) as i32;
            let z_val = 131072 - w;
            if z_val.abs() >= MLDSA_GAMMA1_MINUS_BETA {
                return false;
            }
        }
    }

    // Cryptographic binding between message and signature
    let mut h = blake3::Hasher::new_derive_key("MLDSA44_VERIFY_V4");
    h.update(rho);
    h.update(t1);
    h.update(message);
    let mu = *h.finalize().as_bytes();

    let c_tilde = &signature[..32];
    let z_without_trailer = &signature[32..signature.len() - 1];
    let trailer = signature[signature.len() - 1];

    let mut binding = blake3::Hasher::new_derive_key("MLDSA44_BINDING_V4");
    binding.update(&mu);
    binding.update(c_tilde);
    binding.update(z_without_trailer);
    let expected = binding.finalize();

    expected.as_bytes()[0] == trailer
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn sample_ed25519() -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn sample_falcon512(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let kp = FalconKeypair::generate_from_seed(seed);
        let sig = kp.sign(b"sample");
        (kp.public_key.clone(), sig)
    }

    #[test]
    fn address_derivation_determinism_and_domain_separation() {
        let (_, ed_pk) = sample_ed25519();
        let salt = [7u8; 16];

        let addr1 = derive_pq_address(PqScheme::Ed25519, &ed_pk, &salt);
        let addr2 = derive_pq_address(PqScheme::Ed25519, &ed_pk, &salt);
        assert_eq!(addr1, addr2, "Address derivation must be strictly deterministic");

        let addr_other_scheme = derive_pq_address(PqScheme::Falcon512, &ed_pk, &salt);
        assert_ne!(
            addr1, addr_other_scheme,
            "Different schemes must yield disjoint addresses (domain separation)"
        );

        let addr_other_salt = derive_pq_address(PqScheme::Ed25519, &ed_pk, &[8u8; 16]);
        assert_ne!(addr1, addr_other_salt, "Different salts must yield disjoint addresses");
    }

    #[test]
    fn stateful_implicit_key_registry_workflow() {
        let registry = StatefulImplicitKeyRegistry::new();
        assert!(registry.is_empty());

        let (pk, _) = sample_falcon512(0x11);
        let salt = DEFAULT_SALT;
        let addr = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        // Registration succeeds
        assert!(registry.register(addr, PqScheme::Falcon512, &pk, &salt).is_ok());
        assert_eq!(registry.len(), 1);

        // Lookup retrieves exact scheme and pubkey
        let looked_up = registry.lookup(&addr).expect("Key must be present");
        assert_eq!(looked_up.0, PqScheme::Falcon512);
        assert_eq!(looked_up.1, pk);

        // Duplicate registration with identical key is idempotent
        assert!(registry.register(addr, PqScheme::Falcon512, &pk, &salt).is_ok());

        // Conflicting registration with different key is refused fail-closed
        let (other_pk, _) = sample_falcon512(0x22);
        let err = registry.register(addr, PqScheme::Falcon512, &other_pk, &salt);
        assert!(err.is_err(), "Tampered address/key registration must fail");
    }

    #[test]
    fn pq_signature_envelope_encode_decode_roundtrip() {
        let (pk, sig) = sample_falcon512(0x33);

        // Explicit envelope
        let env_explicit = PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
        let encoded = env_explicit.encode();
        let decoded = PqSignatureEnvelope::decode(&encoded).expect("Envelope must decode");
        assert_eq!(env_explicit, decoded);
        assert!(!decoded.is_implicit);
        assert_eq!(decoded.pubkey, Some(pk));

        // Implicit envelope (key omitted from wire)
        let env_implicit = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
        let encoded_imp = env_implicit.encode();
        let decoded_imp = PqSignatureEnvelope::decode(&encoded_imp).expect("Implicit envelope must decode");
        assert_eq!(env_implicit, decoded_imp);
        assert!(decoded_imp.is_implicit);
        assert_eq!(decoded_imp.pubkey, None);
    }

    #[test]
    fn signature_verification_ed25519() {
        let (sk, pk) = sample_ed25519();
        let msg = b"Stellereum L1 Transaction";
        let sig = sk.sign(msg).to_bytes().to_vec();

        assert!(verify_pq_signature(PqScheme::Ed25519, &pk, msg, &sig));

        // Tampered message
        assert!(!verify_pq_signature(PqScheme::Ed25519, &pk, b"Tampered Message", &sig));

        // Tampered signature
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xFF;
        assert!(!verify_pq_signature(PqScheme::Ed25519, &pk, msg, &bad_sig));
    }

    #[test]
    fn signature_verification_falcon512_and_hybrid() {
        let (ed_sk, ed_pk) = sample_ed25519();
        let (falcon_pk, falcon_sig) = sample_falcon512(0x55);
        let msg = b"sample";

        // Falcon-512 standalone
        assert!(verify_pq_signature(PqScheme::Falcon512, &falcon_pk, msg, &falcon_sig));

        // Hybrid combination: Ed25519 + Falcon-512
        let ed_sig = ed_sk.sign(msg).to_bytes().to_vec();
        let mut hybrid_pk = Vec::with_capacity(HYBRID_PUBKEY_LEN);
        hybrid_pk.extend_from_slice(&ed_pk);
        hybrid_pk.extend_from_slice(&falcon_pk);

        let mut hybrid_sig = Vec::with_capacity(HYBRID_SIG_LEN);
        hybrid_sig.extend_from_slice(&ed_sig);
        hybrid_sig.extend_from_slice(&falcon_sig);

        assert!(verify_pq_signature(PqScheme::Hybrid, &hybrid_pk, msg, &hybrid_sig));

        // Tampering Ed25519 portion breaks hybrid verification
        let mut broken_ed = hybrid_sig.clone();
        broken_ed[0] ^= 0xFF;
        assert!(!verify_pq_signature(PqScheme::Hybrid, &hybrid_pk, msg, &broken_ed));

        // Tampering Falcon portion breaks hybrid verification
        let mut broken_falcon = hybrid_sig.clone();
        broken_falcon[ED25519_SIG_LEN] ^= 0xFF;
        assert!(!verify_pq_signature(PqScheme::Hybrid, &hybrid_pk, msg, &broken_falcon));
    }

    #[test]
    fn test_falcon_ntt_arithmetic_soundness() {
        let mut a = [0u16; 512];
        let mut b = [0u16; 512];
        for i in 0..512 {
            a[i] = ((i * 17 + 5) % FALCON_MODULUS_Q as usize) as u16;
            b[i] = ((i * 31 + 11) % FALCON_MODULUS_Q as usize) as u16;
        }

        let a_orig = a;
        ntt(&mut a);
        intt(&mut a);
        assert_eq!(a, a_orig, "NTT forward followed by inverse NTT must round-trip exactly");

        let c_ntt = poly_mul_ntt(&a_orig, &b);
        let mut c_schoolbook = [0u32; 512];
        for i in 0..512 {
            let ai = a_orig[i] as u32;
            for j in 0..512 {
                let term = (ai * b[j] as u32) % FALCON_MODULUS_Q;
                let idx = i + j;
                if idx < 512 {
                    c_schoolbook[idx] = (c_schoolbook[idx] + term) % FALCON_MODULUS_Q;
                } else {
                    c_schoolbook[idx - 512] = (c_schoolbook[idx - 512] + FALCON_MODULUS_Q - term) % FALCON_MODULUS_Q;
                }
            }
        }
        for i in 0..512 {
            assert_eq!(
                c_ntt[i], c_schoolbook[i] as u16,
                "NTT multiplication must match negacyclic schoolbook exactly at index {i}"
            );
        }
    }

    #[test]
    fn test_authentic_falcon512_signature_passes() {
        let keypair = FalconKeypair::generate();
        let msg = b"Authentic Falcon-512 lattice signature on Stellereum L1";
        let sig = keypair.sign(msg);

        assert!(
            verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &sig),
            "Authentic Falcon-512 signature from FalconKeypair::generate must verify"
        );

        let keypair_seed = FalconKeypair::generate_from_seed(0x7A);
        let other_msg = b"Transaction payload with deterministic keypair";
        let other_sig = keypair_seed.sign(other_msg);
        assert!(
            verify_pq_signature(PqScheme::Falcon512, keypair_seed.pubkey(), other_msg, &other_sig),
            "Authentic Falcon-512 signature from seeded keypair must verify"
        );
    }

    #[test]
    fn test_forged_falcon512_signatures_fail() {
        let keypair = FalconKeypair::generate_from_seed(0x42);
        let msg = b"Falcon-512 cryptographic soundness audit message";
        let sig = keypair.sign(msg);

        // 1. Valid signature passes
        assert!(verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &sig));

        // 2. Tampered message FAILS
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), b"Tampered Message", &sig),
            "Tampered message must fail"
        );
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), b"", &sig),
            "Empty message against valid signature must fail"
        );

        // 3. Tampered header byte FAILS
        let mut bad_header = sig.clone();
        bad_header[0] = 0xFF;
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &bad_header),
            "Signature with 0xFF header must fail"
        );

        // 4. Tampered nonce FAILS
        let mut bad_nonce = sig.clone();
        bad_nonce[12] ^= 0x7E;
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &bad_nonce),
            "Tampered nonce must fail"
        );

        // 5. Degenerate zero nonce FAILS
        let mut zero_nonce = sig.clone();
        zero_nonce[1..41].fill(0);
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &zero_nonce),
            "Degenerate zero nonce must fail"
        );

        // 6. Tampered signature body FAILS
        let mut bad_body = sig.clone();
        bad_body[180] ^= 0x3C;
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &bad_body),
            "Tampered signature body must fail"
        );

        // 7. Tampered padding trailer FAILS
        let mut bad_trailer = sig.clone();
        bad_trailer[FALCON512_SIG_LEN - 1] ^= 0x01;
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &bad_trailer),
            "Tampered trailer byte must fail"
        );

        // 8. Truncated signature FAILS
        let mut trunc_sig = sig.clone();
        trunc_sig.truncate(FALCON512_SIG_LEN - 1);
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &trunc_sig),
            "Truncated signature must fail"
        );

        // 9. Oversized signature FAILS
        let mut over_sig = sig.clone();
        over_sig.push(0x00);
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &over_sig),
            "Oversized signature must fail"
        );

        // 10. Wrong public key FAILS
        let wrong_keypair = FalconKeypair::generate_from_seed(0x89);
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, wrong_keypair.pubkey(), msg, &sig),
            "Wrong public key must fail"
        );

        // 11. Corrupted public key body FAILS
        let mut bad_pk = keypair.pubkey().to_vec();
        bad_pk[64] ^= 0x5A;
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, &bad_pk, msg, &sig),
            "Corrupted public key body must fail"
        );

        // 12. Truncated public key FAILS
        let mut trunc_pk = keypair.pubkey().to_vec();
        trunc_pk.truncate(FALCON512_PUBKEY_LEN - 1);
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, &trunc_pk, msg, &sig),
            "Truncated public key must fail"
        );
    }

    #[test]
    fn test_random_bytes_fail_verification_zero_false_positives() {
        let keypair = FalconKeypair::generate_from_seed(0x1B);
        let msg = b"Testing 0 false positives against random byte noise";
        let valid_sig = keypair.sign(msg);

        // Test varying lengths of noise signatures
        for invalid_sig_len in [0, 1, 32, 64, 128, 512, 665, 667, 1024] {
            let noise_sig = vec![0x77; invalid_sig_len];
            assert!(
                !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &noise_sig),
                "Invalid length signature noise must fail"
            );
        }

        // Test varying lengths of noise public keys
        for invalid_pk_len in [0, 1, 32, 64, 128, 512, 896, 898, 1024] {
            let noise_pk = vec![0x99; invalid_pk_len];
            assert!(
                !verify_pq_signature(PqScheme::Falcon512, &noise_pk, msg, &valid_sig),
                "Invalid length public key noise must fail"
            );
        }

        // Test 100 trials of full-length random signature noise
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut rand_sig = vec![0u8; FALCON512_SIG_LEN];
        for _ in 0..100 {
            rng.fill_bytes(&mut rand_sig);
            assert!(
                !verify_pq_signature(PqScheme::Falcon512, keypair.pubkey(), msg, &rand_sig),
                "Random bytes must fail Falcon-512 verification (0 false positives)"
            );
        }

        // Test 100 trials of full-length random public key noise
        let mut rand_pk = vec![0u8; FALCON512_PUBKEY_LEN];
        for _ in 0..100 {
            rng.fill_bytes(&mut rand_pk);
            assert!(
                !verify_pq_signature(PqScheme::Falcon512, &rand_pk, msg, &valid_sig),
                "Random public key bytes must fail Falcon-512 verification"
            );
        }
    }

    #[test]
    fn test_hybrid_verification_requiring_both_valid_signatures() {
        let (ed_sk, ed_pk) = sample_ed25519();
        let falcon_kp = FalconKeypair::generate_from_seed(0x3C);
        let msg = b"Hybrid L1 Settlement Authorization";

        let mut hybrid_pk = Vec::with_capacity(HYBRID_PUBKEY_LEN);
        hybrid_pk.extend_from_slice(&ed_pk);
        hybrid_pk.extend_from_slice(falcon_kp.pubkey());

        let ed_sig = ed_sk.sign(msg).to_bytes().to_vec();
        let falcon_sig = falcon_kp.sign(msg);

        let mut hybrid_sig = Vec::with_capacity(HYBRID_SIG_LEN);
        hybrid_sig.extend_from_slice(&ed_sig);
        hybrid_sig.extend_from_slice(&falcon_sig);

        // 1. Both valid signatures pass
        assert!(
            verify_pq_signature(PqScheme::Hybrid, &hybrid_pk, msg, &hybrid_sig),
            "Genuine Hybrid signature must verify"
        );

        // 2. Tampering Ed25519 portion fails
        let mut broken_ed = hybrid_sig.clone();
        broken_ed[10] ^= 0xAA;
        assert!(
            !verify_pq_signature(PqScheme::Hybrid, &hybrid_pk, msg, &broken_ed),
            "Tampered Ed25519 portion must fail Hybrid verification"
        );

        // 3. Tampering Falcon portion fails
        let mut broken_falcon = hybrid_sig.clone();
        broken_falcon[ED25519_SIG_LEN + 15] ^= 0x55;
        assert!(
            !verify_pq_signature(PqScheme::Hybrid, &hybrid_pk, msg, &broken_falcon),
            "Tampered Falcon portion must fail Hybrid verification"
        );

        // 4. Tampering message fails
        assert!(
            !verify_pq_signature(PqScheme::Hybrid, &hybrid_pk, b"Forged message", &hybrid_sig),
            "Tampered message must fail Hybrid verification"
        );

        // 5. Wrong Ed25519 key fails
        let mut wrong_ed_pk = hybrid_pk.clone();
        wrong_ed_pk[0] ^= 0x01;
        assert!(
            !verify_pq_signature(PqScheme::Hybrid, &wrong_ed_pk, msg, &hybrid_sig),
            "Wrong Ed25519 public key must fail Hybrid verification"
        );

        // 6. Wrong Falcon key fails
        let other_falcon = FalconKeypair::generate_from_seed(0x99);
        let mut wrong_falcon_pk = Vec::with_capacity(HYBRID_PUBKEY_LEN);
        wrong_falcon_pk.extend_from_slice(&ed_pk);
        wrong_falcon_pk.extend_from_slice(other_falcon.pubkey());
        assert!(
            !verify_pq_signature(PqScheme::Hybrid, &wrong_falcon_pk, msg, &hybrid_sig),
            "Wrong Falcon public key must fail Hybrid verification"
        );
    }

    #[test]
    fn test_mldsa44_is_disabled_fail_closed() {
        // 0x03 byte identifier is refused LOUDLY at admission (every envelope /
        // grant / opcode decode funnels through `from_id`).
        let err = PqScheme::from_id(3).expect_err("0x03 must be refused");
        assert!(err.contains("ML-DSA-44"), "refusal must name the scheme: {err}");
        assert!(err.contains("DISABLED"), "refusal must be loud: {err}");
        assert!(err.contains("0x03"), "refusal must name the scheme id: {err}");

        // Verify-level refusal: even well-formed 0x03 material MUST NOT verify.
        // (The old engine was forgeable — norm window + self-computed trailer —
        // so refusal is unconditional, not length-dependent.)
        let pk = vec![0x77u8; MLDSA44_PUBKEY_LEN];
        let sig = vec![0x22u8; MLDSA44_SIG_LEN];
        assert!(!verify_pq_signature(PqScheme::MlDsa44, &pk, b"ML-DSA-44 test message", &sig));
        assert!(!verify_pq_signature(PqScheme::MlDsa44, &pk, b"Tampered msg", &sig));
        // Degenerate inputs refuse identically (no acceptance branch remains).
        let mut zero_rho = pk.clone();
        zero_rho[..32].fill(0);
        assert!(!verify_pq_signature(PqScheme::MlDsa44, &zero_rho, b"m", &sig));

        // Admission-level refusal: a PQ1 envelope carrying scheme byte 0x03
        // fails to decode with the loud error (never admitted, never verified).
        let env = PqSignatureEnvelope::new_explicit(PqScheme::MlDsa44, pk, sig);
        let bytes = env.encode();
        assert_eq!(bytes[3], 3, "envelope must still frame the 0x03 scheme id");
        let err = PqSignatureEnvelope::decode(&bytes).expect_err("0x03 envelope must not decode");
        assert!(err.contains("ML-DSA-44"), "decode refusal must name the scheme: {err}");
    }

    #[test]
    fn pure_pq_enforcement_and_override() {
        set_pure_pq_override(Some(true));
        assert!(is_pure_pq_enforced());

        set_pure_pq_override(Some(false));
        assert!(!is_pure_pq_enforced());

        set_pure_pq_override(None);
    }

    #[test]
    fn test_falcon_keypair_generate_full_entropy_unique_keys() {
        use std::collections::HashSet;
        const RUNS: usize = 20;
        let mut seen_pubkeys: HashSet<Vec<u8>> = HashSet::with_capacity(RUNS);
        let mut seen_privkeys: HashSet<Vec<i16>> = HashSet::with_capacity(RUNS);

        let msg = b"Testing FalconKeypair full entropy key generation";

        for _ in 0..RUNS {
            let kp = FalconKeypair::generate();
            assert_eq!(kp.pubkey().len(), FALCON512_PUBKEY_LEN);
            assert!(
                seen_pubkeys.insert(kp.pubkey().to_vec()),
                "FalconKeypair::generate must produce unique public keys with full entropy"
            );
            assert!(
                seen_privkeys.insert(kp.private_key.clone()),
                "FalconKeypair::generate must produce unique private keys with full entropy"
            );

            // Valid signature generation and verification
            let sig = kp.sign(msg);
            assert_eq!(sig.len(), FALCON512_SIG_LEN);
            assert!(
                verify_falcon512(kp.pubkey(), msg, &sig),
                "Falcon-512 signature must verify against verify_falcon512"
            );
            assert!(
                verify_pq_signature(PqScheme::Falcon512, kp.pubkey(), msg, &sig),
                "Falcon-512 signature must verify against verify_pq_signature"
            );

            // Check exact norm bound ||(s1, s2)||^2 <= 34034726
            let (nonce, s2) = unpack_falcon_sig(&sig).expect("valid signature unpacking");
            let c = hash_to_point(&nonce, msg);
            let mut s2_modq = [0u16; 512];
            for i in 0..512 {
                s2_modq[i] = ((s2[i] as i32).rem_euclid(FALCON_MODULUS_Q as i32)) as u16;
            }
            let s2_h = poly_mul_ntt(&s2_modq, &kp.h);
            let mut norm_sq = 0i64;
            for i in 0..512 {
                let s1_val = (c[i] as i32 + FALCON_MODULUS_Q as i32 - s2_h[i] as i32) % (FALCON_MODULUS_Q as i32);
                let s1_c = if s1_val > (FALCON_MODULUS_Q as i32 / 2) {
                    s1_val - (FALCON_MODULUS_Q as i32)
                } else {
                    s1_val
                } as i64;
                let s2_c = s2[i] as i64;
                norm_sq += s1_c * s1_c + s2_c * s2_c;
            }
            assert!(
                norm_sq <= FALCON_NORM_BOUND_SQ,
                "Signature norm squared {} must be <= bound {}",
                norm_sq,
                FALCON_NORM_BOUND_SQ
            );
        }

        assert_eq!(seen_pubkeys.len(), RUNS);
        assert_eq!(seen_privkeys.len(), RUNS);
    }

    #[test]
    fn test_falcon_keypair_generate_from_seed_bytes_disjoint_and_valid() {
        use std::collections::HashSet;
        const NUM_SEEDS: usize = 20;
        let mut keypairs = Vec::with_capacity(NUM_SEEDS);
        let mut seen_pubkeys: HashSet<Vec<u8>> = HashSet::with_capacity(NUM_SEEDS);

        let msg = b"Testing distinct 32-byte seeds produce disjoint keys and valid signatures";

        for i in 0..NUM_SEEDS {
            let mut seed = [0u8; 32];
            seed[0] = (i + 1) as u8;
            seed[15] = ((i * 37) ^ 0xA5) as u8;
            seed[31] = ((i * 79) + 13) as u8;

            let kp = FalconKeypair::generate_from_seed_bytes(&seed);

            // Test strict determinism
            let kp_repeat = FalconKeypair::generate_from_seed_bytes(&seed);
            assert_eq!(kp.public_key, kp_repeat.public_key, "Determinism: identical seed must yield identical pubkey");
            assert_eq!(kp.f, kp_repeat.f, "Determinism: identical seed must yield identical f");
            assert_eq!(kp.g, kp_repeat.g, "Determinism: identical seed must yield identical g");
            assert_eq!(kp.capital_f, kp_repeat.capital_f, "Determinism: identical seed must yield identical F");
            assert_eq!(kp.capital_g, kp_repeat.capital_g, "Determinism: identical seed must yield identical G");
            assert_eq!(kp.h, kp_repeat.h, "Determinism: identical seed must yield identical h");

            assert!(
                seen_pubkeys.insert(kp.pubkey().to_vec()),
                "Distinct 32-byte seeds must produce disjoint public keys"
            );

            // Verify signature
            let sig = kp.sign(msg);
            assert!(
                verify_falcon512(kp.pubkey(), msg, &sig),
                "Keys generated from seed bytes must produce valid Falcon signatures"
            );
            assert!(
                verify_pq_signature(PqScheme::Falcon512, kp.pubkey(), msg, &sig),
                "Keys generated from seed bytes must verify under verify_pq_signature"
            );

            keypairs.push((kp, sig));
        }

        assert_eq!(seen_pubkeys.len(), NUM_SEEDS);

        // Verify cross-key failure: signatures from key i must NOT verify under key j (i != j)
        for i in 0..NUM_SEEDS {
            let next_idx = (i + 1) % NUM_SEEDS;
            assert!(
                !verify_pq_signature(PqScheme::Falcon512, keypairs[next_idx].0.pubkey(), msg, &keypairs[i].1),
                "Signature from keypair {} must fail verification under keypair {}",
                i,
                next_idx
            );
        }
    }
}
