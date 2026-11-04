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

// The Falcon-512 reference implementation is reached through the C archive
// that the `pqcrypto-falcon` dependency compiles (see the FIPS 206 signer
// section below). Rust only pulls a dependency's native libraries into the
// final link when the dependency is actually used, so the crate is
// referenced here to guarantee the archive (and the SHAKE256 sponge it
// needs) is linked into every binary that uses this module.
use pqcrypto_falcon as _;

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
/// variable (enforced on `1`, `true`, or `always`; explicitly opted out
/// with `0` / `false` / empty). If the variable is UNSET, enforcement
/// defaults OFF (PQ OPT-IN default — M-01 fallback, 2026-11-04): a
/// PQ-enforced default was verified and REVERTED (155/1104 lib failures;
/// classical suite/sim/wallet/genesis assume dual-stack default — see
/// M-01 fallback note in README/PERF_1K). Operators opt in with
/// `STELL_PURE_PQ=1` (or `--pure-pq`); `STELL_PURE_PQ=0` pins dual-stack.
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
    /// UNKNOWN (KI-01 lead decision, fail-closed): the `verify_mldsa44` stub
    /// was DELETED (it was not real FIPS-204 math), so there is no verifier
    /// for 0x03 in this codebase. `from_id(3)` refuses as unknown
    /// (admission-level) and `verify_pq_signature` returns `false` for it
    /// (verify-level). The variant is KEPT (not removed) so every `match`
    /// over `PqScheme` stays exhaustive and every 0x03 code path keeps
    /// compiling to a refusal — grep shows `MlDsa44` arms in `zkml.rs`,
    /// `wallet_signing.rs`, `state_engine.rs`, plus `is_disabled()` gates in
    /// `consensus.rs`, `staking.rs`, `pq_registry.rs`, `light_client.rs`.
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
    /// FAIL-CLOSED (KI-01): scheme `0x03` has no verifier in this codebase
    /// (stub deleted), so it resolves as UNKNOWN here with the same error as
    /// any unknown id. Every byte-driven admission path (PQ1 envelope decode,
    /// session-grant decode, SVM opcode dispatch, storage reads) rejects 0x03
    /// at parse time. All `Err` arms at those call sites already refuse
    /// (verified: `?`-propagation, `if let Ok` skips, `Err(_) => false`).
    pub fn from_id(id: u8) -> Result<Self, String> {
        match id {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::Falcon512),
            4 => Ok(Self::Hybrid),
            other => Err(format!("Unknown post-quantum scheme ID: {other}")),
        }
    }

    /// Whether this scheme is currently refused fail-closed (KI-01).
    ///
    /// Today this is true only for [`PqScheme::MlDsa44`] (0x03): it has no
    /// verifier (stub deleted, `from_id(3)` is unknown), so every admission
    /// path must refuse it. Operator call sites that construct a
    /// [`PqScheme`] directly from the enum (NOT via [`PqScheme::from_id`]) —
    /// SVM opcode dispatch, storage reads, state-engine pinning — must check
    /// this (or route through `from_id`) before admitting a key or signature.
    /// Kept (not removed): `is_disabled()` gates exist in `consensus.rs`,
    /// `staking.rs`, `pq_registry.rs`, `light_client.rs`, `wallet_signing.rs`,
    /// `state_engine.rs` — deleting this would break those crates.
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
    /// NOTE (KI-01): [`PqScheme::MlDsa44`] reports `true` here as taxonomy —
    /// it *is* a post-quantum scheme family — but it has no verifier (stub
    /// deleted, see [`PqScheme::is_disabled`]): [`verify_pq_signature`]
    /// refuses it and [`PqScheme::from_id`] rejects byte 0x03 as unknown.
    /// Policy gates must NOT treat `is_post_quantum()` as admission; a `true`
    /// here never implies "safe to verify". In pure-PQ mode a 0x03 envelope
    /// is rejected downstream (decode refuses it before this is ever consulted).
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
#[allow(clippy::type_complexity)]
// GATE: registry maps addresses to (scheme, key) pairs behind shared RwLock; the nested tuple is the minimal shape.
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
        // FAIL-CLOSED (KI-01): 0x03 must never enter the registry — it has
        // no verifier (stub deleted, `from_id(3)` is unknown). Refusal here
        // covers every caller that funnels through this registry
        // (explicit-tx first-spend pinning, state-engine mirror);
        // direct-enum siblings (state_engine::pin_pubkey, storage) must apply
        // the same check — see the operator hunk in the audit-closure notes.
        if scheme.is_disabled() {
            return Err(
                "Unknown post-quantum scheme ID: 3 (registry refuses 0x03: no verifier; \
                 submit with Falcon-512 (0x02) or Hybrid (0x04))"
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
        let mut out = Vec::with_capacity(
            3 + 1
                + 1
                + 2
                + self.pubkey.as_ref().map_or(0, |k| k.len())
                + 2
                + self.signature_bytes.len(),
        );
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
/// - `MlDsa44`: UNKNOWN (KI-01, fail-closed) — always returns `false`. The
///   stub verifier was deleted (no FIPS-204 math in this codebase), so any
///   0x03 signature is refused rather than checked.
/// - `Hybrid`: Both Ed25519 and Falcon-512 must verify on the same message.
pub fn verify_pq_signature(
    scheme: PqScheme,
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    if pubkey.len() != scheme.pubkey_size() || signature.len() != scheme.signature_size() {
        return false;
    }

    match scheme {
        PqScheme::Ed25519 => verify_ed25519(pubkey, message, signature),
        PqScheme::Falcon512 => verify_falcon512(pubkey, message, signature),
        // UNKNOWN (KI-01): no verifier — refuse. Kept so the match stays
        // exhaustive (other crates match on `MlDsa44`); any re-enabling is
        // forced to touch this exact arm.
        PqScheme::MlDsa44 => false,
        PqScheme::Hybrid => {
            let ed_pk = &pubkey[..ED25519_PUBKEY_LEN];
            let falcon_pk = &pubkey[ED25519_PUBKEY_LEN..];
            let ed_sig = &signature[..ED25519_SIG_LEN];
            let falcon_sig = &signature[ED25519_SIG_LEN..];

            verify_ed25519(ed_pk, message, ed_sig)
                && verify_falcon512(falcon_pk, message, falcon_sig)
        }
    }
}

/// Internal Ed25519 verification using ed25519-dalek.
fn verify_ed25519(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};

    let Ok(vk_bytes) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&vk_bytes) else {
        return false;
    };
    // Audit HIGH-1: strict verification + small-order refusal. `verify`
    // accepts malleable/small-order signatures that consensus (`verify_strict`)
    // refuses — one path must not accept what the other rejects.
    if vk.is_weak() {
        return false;
    }
    let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(message, &sig).is_ok()
}

pub(crate) fn keccak_f1600(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
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

    for &rc in RC.iter() {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for slot in a[x].iter_mut() {
                *slot ^= d[x];
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

        a[0][0] ^= rc;
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

    /// Squeeze one byte from the sponge (big-endian output order).
    #[cfg(test)]
    fn next_byte(&mut self) -> u8 {
        if self.buf_pos >= self.buffer.len() {
            self.refill();
        }
        let b = self.buffer[self.buf_pos];
        self.buf_pos += 1;
        b
    }

    /// Squeeze `n` bytes from the sponge (test helper).
    #[cfg(test)]
    fn squeeze(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.next_byte());
        }
        out
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
        if !(-2047..=2047).contains(&val) {
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

    for slot in x.iter_mut() {
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

        *slot = if s { -(m as i16) } else { m as i16 };
    }

    let mut pad = (acc & ((1u32 << acc_len).wrapping_sub(1))) as u8;
    for &b in &input[v..] {
        pad |= b;
    }
    if std::hint::black_box(pad) != 0 {
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

/// Test-only: modular inverse for the `compute_h` test helper below.
#[cfg(test)]
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
    for v in a.iter_mut() {
        *v = ((*v as u32 * cur_psi) % FALCON_MODULUS_Q) as u16;
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
    for v in a.iter_mut() {
        let val = (*v as u32 * INV_N) % FALCON_MODULUS_Q;
        *v = ((val * cur_inv_psi) % FALCON_MODULUS_Q) as u16;
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

/// Rounds `num / den` to the nearest integer (ties away from zero).
///
/// Only used by the AUDIT W4.1 regression test that reproduces the removed
/// Babai round-off and asserts the real signature never coincides with it.
#[cfg(test)]
fn round_div(num: i64, den: i64) -> i64 {
    if num >= 0 {
        (num + den / 2) / den
    } else {
        (num - den / 2) / den
    }
}

fn negacyclic_mul_i64(a: &[i64; 512], b: &[i16; 512]) -> [i64; 512] {
    let mut res = [0i64; 512];
    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            let term = ai * (bj as i64);
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

/// Test-only: rebuilds `h` for the pre-FIPS-206 on-disk migration test
/// (`test_legacy_pre_fips206_on_disk_key_loads_signs_and_verifies`).
#[cfg(test)]
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

// ===========================================================================
// FIPS 206 (FN-DSA) COMPLIANT FALCON-512 KEYGEN + SIGNER
// ===========================================================================
//
// AUDIT W4.1 (CRITICAL, private-key leakage): the signer that used to live
// in this module derived `s2` with a DETERMINISTIC BABAI ROUND-OFF
//
//     k1 = round(-c * F / q),  k2 = round(c * f / q),  s2 = k1 * f + k2 * F
//
// Every signature produced that way is the nearest lattice point of the
// *fundamental parallelepiped* of the private basis, so the signatures are
// not distributed as a discrete Gaussian over the coset - they are a
// deterministic function of the nonce. The Nguyen-Regev parallelepiped
// attack recovers `f` and `F` from the covariance of a few hundred to a
// thousand observed signatures (the attack needs no lattice reduction and no
// key compromise), which is a full private-key compromise of every Falcon
// validator key in this chain.
//
// The signer below replaces it with the FIPS 206 (FN-DSA) discrete Gaussian
// sampler: the Falcon-512 C reference implementation (the PQClean port that
// ships inside the `pqcrypto-falcon` dependency, already a direct dependency
// of this crate). It implements the FN-DSA signing algorithm - `ffSampling`
// over the Gram-Schmidt orthogonalized basis of the private key, with the
// `sampler_z` discrete Gaussian sampler - and draws FRESH randomness for
// every signature.
//
// We call the C entry points directly instead of going through
// `pqcrypto_falcon`'s Rust wrapper for two reasons:
//
//   1. the wrapper hard-wires `randombytes()` for both the nonce and the
//      sampler seed, so a caller-supplied seed cannot be honoured at all.
//      The C entry points take an explicit SHAKE256 context, which lets the
//      caller seed be mixed into the per-signature randomizer while the
//      sampler still gets fresh randomness (FIPS 206 requires fresh
//      randomness per signature - a deterministic signer is exactly the
//      defect that was removed here);
//   2. the same C code produces the COMPLETE FN-DSA private key (f, g, F, G)
//      with the true NTRU partner G. The old key path could not populate G
//      at all (`capital_g` stayed `[0i16; 512]`), so the keypair was not a
//      complete FN-DSA key.
//
// The symbols below live in the C archive that `pqcrypto-falcon` compiles
// (`pqclean/crypto_sign/falcon-512/clean/*.c`) plus the SHAKE256 sponge from
// `pqcrypto-internals` (`cfiles/fips202.c`). Both crates are pinned in
// `Cargo.lock`; if a dependency upgrade ever removes a symbol the build
// fails loudly (fail-closed) rather than silently degrading the signer.

/// SHAKE256 incremental sponge context.
///
/// Layout as compiled by `pqcrypto-internals` (`cfiles/fips202.c`):
/// `typedef struct { uint64_t ctx[26]; } shake256incctx;`
#[repr(C)]
struct FalconShake256Ctx {
    state: [u64; 26],
}

/// Scratch buffer for the C code. The reference implementation requires
/// 64-bit alignment for its scratch space.
#[repr(C, align(64))]
struct FalconScratch<const N: usize>([u8; N]);

extern "C" {
    fn shake256_inc_init(state: *mut FalconShake256Ctx);
    fn shake256_inc_absorb(state: *mut FalconShake256Ctx, input: *const u8, inlen: usize);
    fn shake256_inc_finalize(state: *mut FalconShake256Ctx);
    fn shake256_inc_ctx_release(state: *mut FalconShake256Ctx);
    fn PQCLEAN_FALCON512_CLEAN_keygen(
        rng: *mut FalconShake256Ctx,
        f: *mut i8,
        g: *mut i8,
        capital_f: *mut i8,
        capital_g: *mut i8,
        h: *mut u16,
        logn: u32,
        tmp: *mut u8,
    );
    fn PQCLEAN_FALCON512_CLEAN_sign_dyn(
        sig: *mut i16,
        rng: *mut FalconShake256Ctx,
        f: *const i8,
        g: *const i8,
        capital_f: *const i8,
        capital_g: *const i8,
        hm: *const u16,
        logn: u32,
        tmp: *mut u8,
    );
}

/// log2 of the Falcon-512 polynomial degree (n = 512).
const FALCON512_LOGN: u32 = 9;
/// `FALCON_KEYGEN_TEMP_9` from the reference implementation.
const FALCON512_KEYGEN_SCRATCH: usize = 14336;
/// `72 * 2^logn` bytes of scratch for `sign_dyn`.
const FALCON512_SIGN_SCRATCH: usize = 72 * 512;
/// Number of bytes the reference implementation draws from the SHAKE256
/// context to seed the ChaCha20 sampler.
const FALCON512_KEYGEN_SEED_LEN: usize = 48;

/// Builds a seeded, finalized SHAKE256 context for the C code.
fn falcon_shake256_context(seed: &[u8]) -> FalconShake256Ctx {
    let mut ctx = FalconShake256Ctx { state: [0u64; 26] };
    // SAFETY: `ctx` is a correctly laid out `shake256incctx` (208 bytes,
    // 8-byte aligned) and the C code only writes within it.
    unsafe {
        shake256_inc_init(&mut ctx);
        shake256_inc_absorb(&mut ctx, seed.as_ptr(), seed.len());
        shake256_inc_finalize(&mut ctx);
    }
    ctx
}

/// Narrows a coefficient to the 8-bit signed range the reference
/// implementation uses for the private key. Returns `None` when the value
/// does not fit (which would silently corrupt the key if truncated).
fn falcon_i8(value: i16) -> Option<i8> {
    if !(-127..=127).contains(&value) {
        return None;
    }
    Some(value as i8)
}

/// FIPS 206 (FN-DSA) Falcon-512 key generation.
///
/// Returns the complete private key `(f, g, F, G)` - with `G` the true NTRU
/// partner recovered by the reference implementation - together with the
/// public key `h = g * f^-1 mod q`.
#[allow(clippy::type_complexity)]
// GATE: Falcon-512 keygen returns the full (f,g,F,G,h) tuple by algorithm definition; a struct would churn PQ call sites.
fn falcon512_keygen(
    seed: &[u8; FALCON512_KEYGEN_SEED_LEN],
) -> Option<([i16; 512], [i16; 512], [i16; 512], [i16; 512], [u16; 512])> {
    let mut ctx = falcon_shake256_context(seed);
    let mut f = [0i8; 512];
    let mut g = [0i8; 512];
    let mut capital_f = [0i8; 512];
    let mut capital_g = [0i8; 512];
    let mut h = [0u16; 512];
    let mut scratch = FalconScratch::<FALCON512_KEYGEN_SCRATCH>([0u8; FALCON512_KEYGEN_SCRATCH]);
    // SAFETY: all pointers refer to correctly sized, correctly aligned
    // buffers; `scratch` is 64-byte aligned as the C code requires.
    unsafe {
        PQCLEAN_FALCON512_CLEAN_keygen(
            &mut ctx,
            f.as_mut_ptr(),
            g.as_mut_ptr(),
            capital_f.as_mut_ptr(),
            capital_g.as_mut_ptr(),
            h.as_mut_ptr(),
            FALCON512_LOGN,
            scratch.0.as_mut_ptr(),
        );
        shake256_inc_ctx_release(&mut ctx);
    }

    let mut f16 = [0i16; 512];
    let mut g16 = [0i16; 512];
    let mut f16_cap = [0i16; 512];
    let mut g16_cap = [0i16; 512];
    for i in 0..512 {
        f16[i] = f[i] as i16;
        g16[i] = g[i] as i16;
        f16_cap[i] = capital_f[i] as i16;
        g16_cap[i] = capital_g[i] as i16;
    }

    // AUDIT W6.5 (secret hygiene): the C reference implementation leaves the
    // PRIVATE KEY in the scratch buffer it was handed (the Gram-Schmidt
    // orthogonalized basis of `f`/`F`), and the i8 copies of `f`, `g`, `F`,
    // `G` are the private key in its native representation. Wipe all of it
    // before the stack frames are reused: a key left in a stack buffer is a
    // key left in the process image (core dumps, swap, later stack reuse).
    zeroize::Zeroize::zeroize(&mut f);
    zeroize::Zeroize::zeroize(&mut g);
    zeroize::Zeroize::zeroize(&mut capital_f);
    zeroize::Zeroize::zeroize(&mut capital_g);
    zeroize::Zeroize::zeroize(&mut scratch.0);

    Some((f16, g16, f16_cap, g16_cap, h))
}

/// FIPS 206 (FN-DSA) Falcon-512 signing: one discrete Gaussian sample over
/// the Gram-Schmidt orthogonalized basis of the private key.
///
/// `hm` is the FIPS 206 challenge (`c`), `sampler_seed` seeds the ChaCha20
/// stream that drives the Gaussian sampler. Returns `s2`.
fn falcon512_sign_dyn(
    f: &[i16; 512],
    g: &[i16; 512],
    capital_f: &[i16; 512],
    capital_g: &[i16; 512],
    hm: &[u16; 512],
    sampler_seed: &[u8],
) -> Option<[i16; 512]> {
    let mut f8 = [0i8; 512];
    let mut g8 = [0i8; 512];
    let mut f8_cap = [0i8; 512];
    let mut g8_cap = [0i8; 512];
    for i in 0..512 {
        f8[i] = falcon_i8(f[i])?;
        g8[i] = falcon_i8(g[i])?;
        f8_cap[i] = falcon_i8(capital_f[i])?;
        g8_cap[i] = falcon_i8(capital_g[i])?;
    }

    let mut ctx = falcon_shake256_context(sampler_seed);
    let mut s2 = [0i16; 512];
    let mut scratch = FalconScratch::<FALCON512_SIGN_SCRATCH>([0u8; FALCON512_SIGN_SCRATCH]);
    // SAFETY: all pointers refer to correctly sized, correctly aligned
    // buffers; `scratch` is 64-byte aligned as the C code requires.
    unsafe {
        PQCLEAN_FALCON512_CLEAN_sign_dyn(
            s2.as_mut_ptr(),
            &mut ctx,
            f8.as_ptr(),
            g8.as_ptr(),
            f8_cap.as_ptr(),
            g8_cap.as_ptr(),
            hm.as_ptr(),
            FALCON512_LOGN,
            scratch.0.as_mut_ptr(),
        );
        shake256_inc_ctx_release(&mut ctx);
    }

    // AUDIT W6.5 (secret hygiene): the signer's scratch buffer holds the
    // Gram-Schmidt orthogonalized basis of the PRIVATE key (the reference
    // implementation builds it there), and `f8`/`g8`/`f8_cap`/`g8_cap` are
    // the private key in its native 8-bit representation. Both are wiped
    // here: the signature is public, the basis is not.
    zeroize::Zeroize::zeroize(&mut f8);
    zeroize::Zeroize::zeroize(&mut g8);
    zeroize::Zeroize::zeroize(&mut f8_cap);
    zeroize::Zeroize::zeroize(&mut g8_cap);
    zeroize::Zeroize::zeroize(&mut scratch.0);

    Some(s2)
}

/// Checks the NTRU relation `f*G - g*F = q` over `Z[x]/(x^512 + 1)`.
///
/// The FN-DSA signer's Gaussian sampler only terminates - and only produces
/// short, verifiable signatures - when the private key really is an NTRU
/// key, so this is checked before signing. A key that fails the check is
/// refused instead of being handed to the sampler.
fn falcon_ntru_relation_holds(
    f: &[i16; 512],
    g: &[i16; 512],
    capital_f: &[i16; 512],
    capital_g: &[i16; 512],
) -> bool {
    let f64 = to_i64(f);
    let g64 = to_i64(g);
    let fg = negacyclic_mul_i64(&f64, capital_g);
    let gf = negacyclic_mul_i64(&g64, capital_f);
    for i in 0..512 {
        let expected = if i == 0 { FALCON_MODULUS_Q as i64 } else { 0 };
        if fg[i] - gf[i] != expected {
            return false;
        }
    }
    true
}

/// Fast (NTT-based) check that `G` is the NTRU partner of `(f, g, F)`.
///
/// `f*G == g*F (mod q)` is equivalent to `G == g*F*f^-1 == h*F (mod q)`, i.e.
/// to `G` being the reduction of the NTRU partner modulo q - which is the
/// form the reference implementation itself uses when it expands a private
/// key (`G = g*F*f^-1 mod q`, Falcon spec, key expansion). This costs one
/// polynomial multiplication instead of the two `O(n^2)` integer products
/// the exact check needs, which matters because it runs on every signature.
///
/// Used as the signing-time guard: it rejects an incomplete key (the
/// pre-W4.1 `G = [0i16; 512]`) and any key whose `G` does not belong to the
/// lattice of `h` - the two cases in which the Gaussian sampler would not
/// terminate.
fn falcon_ntru_partner_matches(
    capital_f: &[i16; 512],
    capital_g: &[i16; 512],
    h: &[u16; 512],
) -> bool {
    let mut f_modq = [0u16; 512];
    for i in 0..512 {
        f_modq[i] = ((capital_f[i] as i32).rem_euclid(FALCON_MODULUS_Q as i32)) as u16;
    }
    let product = poly_mul_ntt(&f_modq, h);
    for i in 0..512 {
        let g_modq = ((capital_g[i] as i32).rem_euclid(FALCON_MODULUS_Q as i32)) as u16;
        if product[i] != g_modq {
            return false;
        }
    }
    true
}

fn to_i64(x: &[i16; 512]) -> [i64; 512] {
    let mut out = [0i64; 512];
    for i in 0..512 {
        out[i] = x[i] as i64;
    }
    out
}

/// AUDIT W6.1 (live-cluster key migration) — reconstructs the FN-DSA NTRU
/// partner `G` of a legacy private key `(f, g, F)`.
///
/// WHY `G` IS REQUIRED FOR SIGNING (established from the LINKED reference
/// implementation, not from theory: `pqcrypto-falcon`'s PQClean
/// `crypto_sign/falcon-512/clean/sign.c`, `do_sign_dyn`):
///
/// ```text
/// Lattice basis is B = [[g, -f], [G, -F]]. We convert it to FFT.
/// ```
///
/// the Gram matrix `G = B*B*` is built from `f, g, F, G`, and the sampled
/// point is written back as
///
/// ```text
/// s1 = c - (g*u + G*v)      s2 = f*u + F*v
/// ```
///
/// so the verification equation `s1 + s2*h == c (mod q)` holds **only** when
/// `G == h*F (mod q)` — i.e. when `G` is the NTRU partner of `(f, g, F)`.
/// A signature produced with `G = 0` does NOT verify: the missing
/// component is not cosmetic bookkeeping, it is an input of the signing
/// algorithm itself. (The same file shows the second, stronger statement:
/// the sampler only terminates with a short vector when the basis is a
/// genuine NTRU basis.)
///
/// HOW THE PARTNER IS RECOVERED (the reference implementation's key
/// expansion): the partner of `(f, g, F)` is
///
/// ```text
/// G = g*F*f^{-1} == h*F (mod q)
/// ```
///
/// because `h = g*f^{-1}`. We compute `h*F` with this module's NTT and take
/// the centered representative. For a genuine FN-DSA key that
/// representative is BIT-IDENTICAL to the `G` that KEYGEN produced: the
/// true partner satisfies `f*G - g*F = q` over the integers (hence
/// `G == h*F (mod q)`) and its coefficients are far below `q/2`, so the
/// centered representative is unique. The repaired key therefore builds
/// exactly the same Gram matrix as the complete key and produces exactly
/// the same kind of short, verifiable signatures.
///
/// Returns `None` when the recovered partner does not fit the reference
/// implementation's 8-bit coefficient range, or when it does not satisfy
/// the exact NTRU relation `f*G - g*F = q` over the integers. The caller
/// then refuses to sign (fail-closed) instead of emitting a signature that
/// would not verify.
fn reconstruct_ntru_partner(
    f: &[i16; 512],
    g: &[i16; 512],
    capital_f: &[i16; 512],
    h: &[u16; 512],
) -> Option<[i16; 512]> {
    // G = h * F (mod q)
    let mut f_modq = [0u16; 512];
    for i in 0..512 {
        f_modq[i] = ((capital_f[i] as i32).rem_euclid(FALCON_MODULUS_Q as i32)) as u16;
    }
    let product = poly_mul_ntt(&f_modq, h);

    let mut capital_g = [0i16; 512];
    for i in 0..512 {
        let v = product[i] as i32;
        // Centered representative of `v (mod q)`.
        let centered = if v > (FALCON_MODULUS_Q / 2) as i32 {
            v - FALCON_MODULUS_Q as i32
        } else {
            v
        };
        // The reference implementation stores the private key coefficients in
        // `int8_t`; a partner outside that range cannot be handed to the
        // signer at all.
        if !(-127..=127).contains(&centered) {
            return None;
        }
        capital_g[i] = centered as i16;
    }

    // Exact NTRU relation over the integers: f*G - g*F == q. This is the
    // strongest possible check that the recovered partner really is the
    // NTRU partner (and not an unrelated element of the same coset).
    if !falcon_ntru_relation_holds(f, g, capital_f, &capital_g) {
        return None;
    }

    Some(capital_g)
}

/// AUDIT W6.1: emitted ONCE per process when a legacy (pre-FIPS-206) key
/// without the NTRU partner `G` is loaded.
///
/// The key keeps working — the partner is reconstructed in memory, so the
/// validator address does NOT change — but the key file on disk is an
/// incomplete NTRU key and MUST be rotated
/// (`stellereum keys rotate-falcon`).
fn warn_legacy_ntru_key_once(repaired: bool, address: [u8; 32]) {
    static LEGACY_NTRU_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    let first = !LEGACY_NTRU_WARNED.swap(true, std::sync::atomic::Ordering::SeqCst);
    let addr = hex::encode(address);
    if first {
        if repaired {
            tracing::warn!(
                "Falcon-512 LEGACY key loaded (pre-FIPS 206, no NTRU partner G on disk): \
                 the partner was reconstructed from (f, g, F) and the key signs normally, \
                 but the key file is an INCOMPLETE NTRU key and MUST be rotated \
                 (`stellereum keys rotate-falcon`); validator address {} is UNCHANGED",
                addr
            );
            eprintln!(
                "[WARN] Falcon-512 LEGACY key loaded (pre-FIPS 206, no NTRU partner G): \
                 reconstructed in memory, still signing, but ROTATE it \
                 (`stellereum keys rotate-falcon`); validator address {} unchanged",
                addr
            );
        } else {
            tracing::warn!(
                "Falcon-512 LEGACY key loaded (pre-FIPS 206, no NTRU partner G on disk) AND \
                 the partner could NOT be reconstructed: this key CANNOT sign (the FIPS 206 \
                 sampler requires the NTRU partner); rotate it NOW \
                 (`stellereum keys rotate-falcon`); validator address {}",
                addr
            );
            eprintln!(
                "[WARN] Falcon-512 LEGACY key loaded and NOT repairable (no NTRU partner G): \
                 this key cannot sign — rotate it NOW (`stellereum keys rotate-falcon`); \
                 validator address {}",
                addr
            );
        }
    } else {
        tracing::info!(
            "Falcon-512 legacy key (no NTRU partner G) loaded again{repair_note}; \
             validator address {}",
            addr,
            repair_note = if repaired {
                " (partner reconstructed)"
            } else {
                " (NOT repairable)"
            },
        );
    }
}


/// Authentic NIST FIPS 206 Falcon-512 keypair.
#[derive(Clone)]
pub struct FalconKeypair {
    /// AUDIT W6.5: the private key material is NOT public any more. These
    /// fields used to be `pub`, so any module could read (and leak into a
    /// log, an error message or a serialization) the whole FN-DSA private
    /// key. Nothing outside this module needs them: the public half is
    /// [`Self::public_key`], the rest stays here.
    private_key: Vec<i16>,
    pub public_key: Vec<u8>,
    f: [i16; 512],
    g: [i16; 512],
    capital_f: [i16; 512],
    capital_g: [i16; 512],
    pub h: [u16; 512],
    /// AUDIT W6.1 (live-cluster key migration): `true` when this key was
    /// loaded from a PRE-FIPS-206 key file that did not carry the NTRU
    /// partner `G` (the on-disk format written by the pre-FIPS-206 code).
    ///
    /// Such a key is *repaired in memory* at load time (the partner is
    /// reconstructed from `(f, g, F)` exactly as the reference
    /// implementation's key expansion does), so it keeps signing and its
    /// validator address does NOT change. The flag only records that the
    /// key on disk is an incomplete NTRU key: it MUST be rotated
    /// (`stellereum keys rotate-falcon`) at the operator's leisure.
    pub legacy_incomplete_ntru: bool,
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
            .field("legacy_incomplete_ntru", &self.legacy_incomplete_ntru)
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

    /// Generates a COMPLETE FN-DSA (FIPS 206) keypair with OS entropy,
    /// ALWAYS through the authentic reference-implementation key generation.
    ///
    /// Unlike [`FalconKeypair::generate`] this always derives through the
    /// authentic reference-implementation key generation (strict-only: no
    /// legacy branch exists), so the returned key always carries the true
    /// NTRU partner `G`. This is what the key rotation command uses.
    pub fn generate_complete() -> Self {
        use rand::RngCore;
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *seed);
        let mut hasher = blake3::Hasher::new_derive_key("FALCON512_KEYGEN_V5");
        hasher.update(&*seed);
        let mut xof = hasher.finalize_xof();
        let mut keygen_seed = Zeroizing::new([0u8; FALCON512_KEYGEN_SEED_LEN]);
        xof.fill(&mut *keygen_seed);
        zeroize::Zeroize::zeroize(&mut seed);

        let (f, g, capital_f, capital_g, h) = falcon512_keygen(&keygen_seed)
            .expect("Falcon-512 key generation must succeed for any seed");
        zeroize::Zeroize::zeroize(&mut keygen_seed);
        debug_assert!(
            falcon_ntru_relation_holds(&f, &g, &capital_f, &capital_g),
            "the reference key generation must yield a genuine NTRU key (f*G - g*F = q)"
        );

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
            legacy_incomplete_ntru: false,
        }
    }

    /// Whether this key was loaded from a pre-FIPS-206 key file that did not
    /// carry the NTRU partner `G` (see
    /// [`FalconKeypair::legacy_incomplete_ntru`]).
    pub fn is_legacy_incomplete_ntru(&self) -> bool {
        self.legacy_incomplete_ntru
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
        // AUDIT W6.1 (live-cluster key migration, fail-closed but MIGRATION
        // SAFE): a key written by the pre-FIPS-206 code carries no NTRU
        // partner `G` (`G = [0i16; 512]`). Refusing such a key would stop
        // the four live testnet nodes from starting AND would force a
        // validator-address change (the address is derived from the public
        // key `h`), invalidating the on-chain staking set.
        //
        // The partner is therefore RECONSTRUCTED from `(f, g, F)` exactly as
        // the reference implementation's key expansion does
        // (`G = g*F*f^{-1} == h*F (mod q)`), which yields bit-identical
        // material to the `G` that KEYGEN produced, so the key signs with
        // the FIPS 206 sampler and the signatures verify under the EXISTING
        // public key `h`. The public key and `h` are NEVER touched, so the
        // validator address does NOT change.
        //
        // A key that carries a non-zero `G` must still be a consistent NTRU
        // key: an inconsistent one is corrupt and stays refused.
        let mut capital_g = capital_g;
        let mut legacy_incomplete_ntru = false;
        if capital_g.iter().all(|&v| v == 0) {
            legacy_incomplete_ntru = true;
            let address = derive_pq_address(PqScheme::Falcon512, &public_key, &DEFAULT_SALT);
            match reconstruct_ntru_partner(&f, &g, &capital_f, &h) {
                Some(recovered) => {
                    capital_g = recovered;
                    warn_legacy_ntru_key_once(true, address);
                }
                None => {
                    // Loaded, but it cannot sign: the signer refuses loudly
                    // (fail-closed) instead of producing a signature that
                    // would not verify.
                    warn_legacy_ntru_key_once(false, address);
                }
            }
        } else if !falcon_ntru_partner_matches(&capital_f, &capital_g, &h) {
            return None;
        }
        Some(Self {
            private_key,
            public_key,
            f,
            g,
            capital_f,
            capital_g,
            h,
            legacy_incomplete_ntru,
        })
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
    ///
    /// AUDIT W4.1: the key is now produced by the same Falcon-512 reference
    /// implementation that signs with it, so the key material and the signing
    /// basis can never drift apart, and the COMPLETE FN-DSA private key
    /// `(f, g, F, G)` is populated - `G` being the true NTRU partner
    /// (`f*G - g*F = q`), not the zero-filled placeholder the old code left
    /// behind.
    pub fn generate_from_seed_bytes(seed: &[u8; 32]) -> Self {

        // The reference implementation draws 48 bytes of randomness to seed
        // its NTRU key generation; derive them deterministically from the
        // caller's 32-byte seed so the key stays reproducible.
        let mut hasher = blake3::Hasher::new_derive_key("FALCON512_KEYGEN_V5");
        hasher.update(seed);
        let mut xof = hasher.finalize_xof();
        let mut keygen_seed = Zeroizing::new([0u8; FALCON512_KEYGEN_SEED_LEN]);
        xof.fill(&mut *keygen_seed);

        let (f, g, capital_f, capital_g, h) = falcon512_keygen(&keygen_seed)
            .expect("Falcon-512 key generation must succeed for any seed");
        zeroize::Zeroize::zeroize(&mut keygen_seed);
        debug_assert!(
            falcon_ntru_relation_holds(&f, &g, &capital_f, &capital_g),
            "the reference key generation must yield a genuine NTRU key (f*G - g*F = q)"
        );

        // The public key is h = g * f^-1 mod q in the canonical FIPS 206
        // encoding (0x09 header + 14-bit little-endian coefficients).
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
            // A freshly generated key always carries the complete NTRU
            // partner (`capital_g`), so it is never a legacy incomplete key.
            legacy_incomplete_ntru: false,
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
        derive_pq_address(PqScheme::Falcon512, &self.public_key, &DEFAULT_SALT)
    }

    /// Signs a message producing an authentic 666-byte Falcon-512 signature satisfying
    /// the centered Euclidean norm bound ||(s1, s2)||^2 <= 34034726.
    ///
    /// AUDIT W4.1: signing now uses the FIPS 206 (FN-DSA) discrete Gaussian
    /// sampler over the Gram-Schmidt orthogonalized basis of the private key,
    /// with fresh randomness for every signature. The previous deterministic
    /// Babai round-off confined every signature to the fundamental
    /// parallelepiped of the private basis and leaked the private key
    /// (Nguyen-Regev parallelepiped attack).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut *seed);
        let sig = self.sign_with_seed(message, &seed);
        zeroize::Zeroize::zeroize(&mut seed);
        sig
    }

    /// Signs a message with an explicit seed contributing to the per-signature
    /// randomizer.
    ///
    /// AUDIT W4.1 (CRITICAL): the signer used to be a DETERMINISTIC BABAI
    /// ROUND-OFF
    ///
    /// ```text
    /// k1 = round(-c * F / q),  k2 = round(c * f / q),  s2 = k1 * f + k2 * F
    /// ```
    ///
    /// which confines every signature to the fundamental parallelepiped of
    /// the private basis. A few hundred to a thousand such signatures are
    /// enough to recover `f` and `F` from the covariance of the observed
    /// samples (Nguyen-Regev parallelepiped attack) - a full private-key
    /// compromise with no lattice reduction required.
    ///
    /// Signing now runs the FIPS 206 (FN-DSA) discrete Gaussian sampler
    /// (`ffSampling` over the Gram-Schmidt orthogonalized basis, with the
    /// `sampler_z` Gaussian sampler) from the Falcon-512 reference
    /// implementation. Consequences for callers:
    ///
    /// * The signature is NOT reproducible. FIPS 206 requires fresh
    ///   randomness for the Gaussian sampler on every signing operation; a
    ///   deterministic signer is exactly the defect that was removed here.
    ///   Two calls with the same message and the same seed therefore produce
    ///   two DIFFERENT (both valid) signatures.
    /// * `seed` is *additional entropy*: it is mixed with fresh OS entropy
    ///   into the per-signature randomizer that drives both the Falcon nonce
    ///   and the sampler's ChaCha20 stream. The nonce is never reused across
    ///   signatures, so no "same nonce, different sample" pair can be
    ///   produced.
    ///
    /// TEST-ONLY IN PRACTICE - production callers MUST use
    /// [`FalconKeypair::sign`]. Never wire this into a validator, wallet, or
    /// faucet path. The caller retains ownership of `seed` and must wipe it
    /// after use.
    pub fn sign_with_seed(&self, message: &[u8], seed: &[u8; 32]) -> Vec<u8> {
        // Fail closed on a key that is not a real NTRU key: the Gaussian
        // sampler needs `G` to be the NTRU partner of `(f, g, F)` (the
        // reference implementation expands a private key as
        // `G = g*F*f^-1 mod q`) to terminate with a short vector.
        //
        // AUDIT W6.1: a legacy (pre-FIPS 206) key is repaired at LOAD time
        // (`from_bytes` reconstructs the partner), so it passes this check and
        // signs normally. A key whose partner could NOT be reconstructed
        // still has `G = 0` and is refused here — loudly.
        if !falcon_ntru_partner_matches(&self.capital_f, &self.capital_g, &self.h) {
            tracing::warn!(
                "Falcon-512 signing REFUSED: private key does not carry the FN-DSA \
                 component G for this h (f*G != g*F mod q); the key is incomplete or \
                 corrupted, and a compliant FIPS 206 discrete Gaussian sampler cannot \
                 be run on it"
            );
            eprintln!(
                "[WARN] Falcon-512 signing REFUSED: the private key has no usable NTRU \
                 partner G (f*G != g*F mod q) — rotate the validator key \
                 (`stellereum keys rotate-falcon`)"
            );
            return Vec::new();
        }

        // Per-signature randomizer: the caller's seed mixed with fresh OS
        // entropy. 40 bytes become the Falcon nonce, 48 bytes seed the
        // sampler's ChaCha20 stream.
        let mut os_entropy = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut *os_entropy);
        let mut hasher = blake3::Hasher::new_derive_key("FALCON512_SIGN_V5");
        hasher.update(seed);
        hasher.update(&*os_entropy);
        hasher.update(message);
        let mut xof = hasher.finalize_xof();
        let mut randomizer = Zeroizing::new([0u8; 88]);
        xof.fill(&mut *randomizer);
        zeroize::Zeroize::zeroize(&mut os_entropy);

        let mut nonce = [0u8; 40];
        nonce.copy_from_slice(&randomizer[..40]);
        if nonce.iter().all(|&b| b == 0) {
            nonce[0] = 1;
        }
        let sampler_seed = &randomizer[40..];

        // FIPS 206 challenge c = HashToPoint(nonce || message).
        let c = hash_to_point(&nonce, message);

        let Some(s2) = falcon512_sign_dyn(
            &self.f,
            &self.g,
            &self.capital_f,
            &self.capital_g,
            &c,
            sampler_seed,
        ) else {
            tracing::warn!(
                "Falcon-512 signing REFUSED: private key coefficients are out of the \
                 FIPS 206 range; no compliant signature can be produced"
            );
            return Vec::new();
        };

        // Chain-canonical signature framing (pentest P4 F-PQ-1): 0x29 header,
        // 40-byte nonce, compressed s2, zero padding to the fixed 666-byte
        // length. 0x29 is the chain's byte (NOT the PQClean reference's 0x39
        // — see `unpack_falcon_sig`); the lattice math is reference-neutral,
        // the framing byte is consensus.
        let mut sig = vec![0u8; FALCON512_SIG_LEN];
        sig[0] = 0x29;
        sig[1..41].copy_from_slice(&nonce);
        if comp_encode(&mut sig[41..], &s2).is_none() {
            tracing::warn!(
                "Falcon-512 signing REFUSED: compressed signature does not fit the \
                 FIPS 206 frame"
            );
            return Vec::new();
        }

        // Self-check: never hand out a signature this module cannot verify.
        if !verify_falcon512(&self.public_key, message, &sig) {
            tracing::warn!(
                "Falcon-512 signing REFUSED: the produced signature failed the local \
                 FIPS 206 verification self-check"
            );
            return Vec::new();
        }

        sig
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

    // CHAIN-CANONICAL FRAMING ONLY (audit F-MED-1 + pentest P4 F-PQ-1):
    // exactly one layout verifies — header 0x29, 40-byte nonce,
    // `comp_encode`d s2, all-zero padding to the fixed 666-byte length.
    //
    // INTEROP NOTE (do not "fix" by accepting both): the vendored PQClean
    // reference emits header 0x39 for the same math (verified: flipping the
    // header byte both ways verifies under the other implementation's
    // verifier, so samples, codec, norm bound and challenge are all
    // spec-interoperable). 0x29 is therefore the CHAIN's canonical byte, not
    // the reference's: `sign()` has only ever emitted 0x29, every block on
    // disk carries 0x29, and accepting 0x39 as well would create two valid
    // byte forms for one (key, message) — the third-party re-minting /
    // dedup-evasion malleability F-MED-1 closed. A migration to the reference
    // header is a coordinated hard-fork item (all validators + all stored
    // signatures), never a silent verifier relaxation.
    //
    // The legacy raw 40-byte-nonce layout is likewise REFUSED.
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

    let mut pad = 0u8;
    for &b in &payload[consumed..] {
        pad |= b;
    }
    if std::hint::black_box(pad) != 0 {
        return None;
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
        let s1_val =
            (c[i] as i32 + FALCON_MODULUS_Q as i32 - s2_h[i] as i32) % (FALCON_MODULUS_Q as i32);
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

    /// AUDIT W6.5: the hand-rolled SHAKE256 in this module must be a REAL
    /// SHAKE256.
    ///
    /// The FIPS 206 challenge `c = HashToPoint(nonce || message)` is computed
    /// with it, and `c` is what binds the signature to the message. If the
    /// sponge were wrong (or subtly non-uniform), every signature in the
    /// chain would be computed over a challenge that is not the FIPS 206
    /// one — and the "rejection sampling" that makes `c` uniform would be
    /// sampling over the wrong distribution. This pins the sponge against
    /// the NIST published test vectors.
    #[test]
    fn test_shake256_matches_the_nist_test_vectors() {
        // SHAKE256("") , 32 bytes out (NIST ShortMsgKAT).
        let mut empty = Shake256Reader::new(b"");
        assert_eq!(
            hex::encode(empty.squeeze(32)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        );
        // SHAKE256("abc"), 32 bytes out (NIST ShortMsgKAT).
        let mut abc = Shake256Reader::new(b"abc");
        assert_eq!(
            hex::encode(abc.squeeze(32)),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        );
        // SHAKE256(""), 64 bytes out — the squeeze must continue across the
        // 136-byte rate boundary.
        let mut empty64 = Shake256Reader::new(b"");
        assert_eq!(
            hex::encode(empty64.squeeze(64)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
                .replace(['\n', ' '], "")
        );
        // A message longer than the rate (136 bytes) exercises the multi-block
        // absorb path.
        let long = vec![0xABu8; 200];
        let mut reader = Shake256Reader::new(&long);
        let a = reader.squeeze(32);
        let mut reader2 = Shake256Reader::new(&long);
        let b = reader2.squeeze(32);
        assert_eq!(a, b, "the sponge must be deterministic");
        assert_ne!(a, Shake256Reader::new(&[0xABu8; 199]).squeeze(32));
    }

    /// AUDIT W6.5: the wire format of a Falcon-512 signature is FIXED and
    /// the signer must produce EXACTLY it.
    ///
    /// `0x29 || nonce(40) || comp(s2) || zero-pad` to 666 bytes. A signer
    /// that produced a different framing would break EVERY signature
    /// silently (the verifier would refuse them all), so the framing is
    /// pinned here byte for byte.
    #[test]
    fn test_falcon_signature_wire_format_is_exactly_666_bytes() {
        let kp = FalconKeypair::generate_from_seed(0x61);
        let msg = b"Falcon-512 wire format contract";
        let sig = kp.sign(msg);
        assert_eq!(sig.len(), FALCON512_SIG_LEN);
        assert_eq!(sig.len(), 666);
        // Header.
        // (Chain-canonical 0x29 — the PQClean reference emits 0x39 for the
        // same math; see F-PQ-1 in `unpack_falcon_sig`.)
        assert_eq!(sig[0], 0x29, "the chain-canonical header is 0x29");
        // The nonce is 40 bytes and is not all-zero.
        let nonce = &sig[1..41];
        assert_ne!(nonce, &[0u8; 40]);
        // The compressed s2 payload is followed by ZERO padding only: the
        // decoder refuses a non-zero pad, so the signer must not emit one.
        let (decoded_nonce, s2) = unpack_falcon_sig(&sig).expect("the signature must unpack");
        assert_eq!(decoded_nonce, nonce);
        assert!(
            s2.iter().any(|&v| v != 0),
            "the compressed payload must carry the signature"
        );
        // Re-encoding the decoded s2 must reproduce the payload EXACTLY
        // (canonical encoding, no alternative byte forms).
        let mut re_encoded = vec![0u8; FALCON512_SIG_LEN];
        re_encoded[0] = 0x29;
        re_encoded[1..41].copy_from_slice(nonce);
        let written = comp_encode(&mut re_encoded[41..], &s2).expect("s2 must re-encode");
        assert_eq!(&re_encoded[41..41 + written], &sig[41..41 + written]);
        assert!(
            sig[41 + written..].iter().all(|&b| b == 0),
            "the signature must be zero-padded to 666 bytes"
        );
        // ... and it verifies.
        assert!(verify_falcon512(kp.pubkey(), msg, &sig));
    }

    /// AUDIT W6.5: the SHAKE256 context that drives the FIPS 206 sampler
    /// must be seeded with the FULL sampler entropy — a different sampler
    /// seed must produce a DIFFERENT sample for the SAME challenge.
    ///
    /// If the seed were dropped (or the context were seeded with a constant),
    /// the sampler would be deterministic again: every signature would be the
    /// same discrete Gaussian sample for its challenge, which is exactly the
    /// "one sample, many signatures" structure the parallelepiped attack
    /// needs.
    #[test]
    fn test_falcon_sampler_context_is_seeded_with_the_full_sampler_seed() {
        let kp = FalconKeypair::generate_from_seed(0x62);
        let nonce = [0x7Cu8; 40];
        let msg = b"sampler seed sensitivity";
        let c = hash_to_point(&nonce, msg);

        let seed_a = [0xA1u8; 48];
        let seed_b = [0xB2u8; 48];
        let s2_a = falcon512_sign_dyn(&kp.f, &kp.g, &kp.capital_f, &kp.capital_g, &c, &seed_a)
            .expect("signing with seed A");
        let s2_b = falcon512_sign_dyn(&kp.f, &kp.g, &kp.capital_f, &kp.capital_g, &c, &seed_b)
            .expect("signing with seed B");
        assert_ne!(
            s2_a, s2_b,
            "the sampler must consume its seed: identical samples for different seeds mean \
             the SHAKE256 context was not seeded with the sampler randomness"
        );
    }

    /// AUDIT W6.5: the PRODUCTION verifier must have no test-only shortcut.
    ///
    /// A `cfg(test)` branch in the verification path used to accept a
    /// BLAKE3 "check-digest" pseudo-signature (a digest, not a lattice
    /// signature) for any public key. `verify_pq_signature` is the
    /// production entry point and MUST reject that format — and every
    /// other byte pattern that is not a real FIPS 206 signature.
    #[test]
    fn test_production_verifier_has_no_test_only_shortcut() {
        let kp = FalconKeypair::generate_from_seed(0x63);
        let msg = b"no shortcut in the production verifier";
        let pk = kp.pubkey();

        // The pseudo-signature the test-only branch used to accept.
        let mut h = blake3::Hasher::new_derive_key("FALCON512_VERIFY_V4");
        h.update(pk);
        h.update(msg);
        let commitment = *h.finalize().as_bytes();
        let mut checker = blake3::Hasher::new_derive_key("FALCON512_SIG_CHECK_V4");
        checker.update(&commitment);
        checker.update(&[0x11u8; 40]);
        checker.update(&[0x22u8; FALCON512_SIG_LEN - 1 - 40]);
        let check_digest = checker.finalize();
        let mut fake = vec![0x11u8; FALCON512_SIG_LEN];
        fake[FALCON512_SIG_LEN - 1] = check_digest.as_bytes()[0];
        assert!(
            !verify_pq_signature(PqScheme::Falcon512, pk, msg, &fake),
            "the production verifier must reject a non-lattice pseudo-signature"
        );
        // ... and the same for the hybrid path.
        let mut hybrid_pk = Vec::with_capacity(HYBRID_PUBKEY_LEN);
        hybrid_pk.extend_from_slice(&[0u8; 32]);
        hybrid_pk.extend_from_slice(pk);
        let mut hybrid_sig = Vec::with_capacity(HYBRID_SIG_LEN);
        hybrid_sig.extend_from_slice(&[0u8; 64]);
        hybrid_sig.extend_from_slice(&fake);
        assert!(!verify_pq_signature(
            PqScheme::Hybrid,
            &hybrid_pk,
            msg,
            &hybrid_sig
        ));

        // The REAL signature verifies, so the check above is not vacuous.
        let real = kp.sign(msg);
        assert!(verify_pq_signature(PqScheme::Falcon512, pk, msg, &real));
    }

    /// AUDIT W6.5: the private key material must be wipeable (and is wiped
    /// on drop).
    #[test]
    fn test_falcon_private_key_material_is_zeroized() {
        let mut kp = FalconKeypair::generate_from_seed(0x64);
        assert!(kp.f.iter().any(|&v| v != 0));
        assert!(kp.g.iter().any(|&v| v != 0));
        assert!(kp.capital_f.iter().any(|&v| v != 0));
        assert!(kp.capital_g.iter().any(|&v| v != 0));
        assert!(!kp.private_key.is_empty());
        zeroize::Zeroize::zeroize(&mut kp);
        assert!(kp.f.iter().all(|&v| v == 0), "f must be wiped");
        assert!(kp.g.iter().all(|&v| v == 0), "g must be wiped");
        assert!(kp.capital_f.iter().all(|&v| v == 0), "F must be wiped");
        assert!(kp.capital_g.iter().all(|&v| v == 0), "G must be wiped");
        assert!(
            kp.private_key.iter().all(|&v| v == 0),
            "the private key must be wiped"
        );
        // The public half survives (it is not secret).
        assert!(!kp.public_key.is_empty());
    }

    /// AUDIT W6.5: the nonce must never repeat across signatures, whatever
    /// the caller-supplied seed.
    ///
    /// A reused Falcon nonce with a DIFFERENT Gaussian sample leaks the
    /// difference of two short vectors (and is the classic way to recover a
    /// Falcon key). The nonce is derived from the caller's seed MIXED WITH
    /// fresh OS entropy, so it is fresh per call.
    #[test]
    fn test_falcon_nonces_never_repeat() {
        let kp = FalconKeypair::generate_from_seed(0x65);
        let msg = b"nonce freshness";
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..32 {
            let sig = kp.sign(msg);
            assert_eq!(sig.len(), FALCON512_SIG_LEN);
            assert!(
                nonces.insert(sig[1..41].to_vec()),
                "a Falcon nonce repeated"
            );
        }
        // Even with a FIXED caller seed the nonce must move (the OS entropy
        // is mixed in).
        let seed = [0x77u8; 32];
        let mut seeded_nonces = std::collections::HashSet::new();
        for _ in 0..16 {
            let sig = kp.sign_with_seed(msg, &seed);
            assert!(seeded_nonces.insert(sig[1..41].to_vec()));
        }
    }

    #[test]
    fn address_derivation_determinism_and_domain_separation() {
        let (_, ed_pk) = sample_ed25519();
        let salt = [7u8; 16];

        let addr1 = derive_pq_address(PqScheme::Ed25519, &ed_pk, &salt);
        let addr2 = derive_pq_address(PqScheme::Ed25519, &ed_pk, &salt);
        assert_eq!(
            addr1, addr2,
            "Address derivation must be strictly deterministic"
        );

        let addr_other_scheme = derive_pq_address(PqScheme::Falcon512, &ed_pk, &salt);
        assert_ne!(
            addr1, addr_other_scheme,
            "Different schemes must yield disjoint addresses (domain separation)"
        );

        let addr_other_salt = derive_pq_address(PqScheme::Ed25519, &ed_pk, &[8u8; 16]);
        assert_ne!(
            addr1, addr_other_salt,
            "Different salts must yield disjoint addresses"
        );
    }

    #[test]
    fn stateful_implicit_key_registry_workflow() {
        let registry = StatefulImplicitKeyRegistry::new();
        assert!(registry.is_empty());

        let (pk, _) = sample_falcon512(0x11);
        let salt = DEFAULT_SALT;
        let addr = derive_pq_address(PqScheme::Falcon512, &pk, &salt);

        // Registration succeeds
        assert!(registry
            .register(addr, PqScheme::Falcon512, &pk, &salt)
            .is_ok());
        assert_eq!(registry.len(), 1);

        // Lookup retrieves exact scheme and pubkey
        let looked_up = registry.lookup(&addr).expect("Key must be present");
        assert_eq!(looked_up.0, PqScheme::Falcon512);
        assert_eq!(looked_up.1, pk);

        // Duplicate registration with identical key is idempotent
        assert!(registry
            .register(addr, PqScheme::Falcon512, &pk, &salt)
            .is_ok());

        // Conflicting registration with different key is refused fail-closed
        let (other_pk, _) = sample_falcon512(0x22);
        let err = registry.register(addr, PqScheme::Falcon512, &other_pk, &salt);
        assert!(err.is_err(), "Tampered address/key registration must fail");
    }

    #[test]
    fn pq_signature_envelope_encode_decode_roundtrip() {
        let (pk, sig) = sample_falcon512(0x33);

        // Explicit envelope
        let env_explicit =
            PqSignatureEnvelope::new_explicit(PqScheme::Falcon512, pk.clone(), sig.clone());
        let encoded = env_explicit.encode();
        let decoded = PqSignatureEnvelope::decode(&encoded).expect("Envelope must decode");
        assert_eq!(env_explicit, decoded);
        assert!(!decoded.is_implicit);
        assert_eq!(decoded.pubkey, Some(pk));

        // Implicit envelope (key omitted from wire)
        let env_implicit = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig);
        let encoded_imp = env_implicit.encode();
        let decoded_imp =
            PqSignatureEnvelope::decode(&encoded_imp).expect("Implicit envelope must decode");
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
        assert!(!verify_pq_signature(
            PqScheme::Ed25519,
            &pk,
            b"Tampered Message",
            &sig
        ));

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
        assert!(verify_pq_signature(
            PqScheme::Falcon512,
            &falcon_pk,
            msg,
            &falcon_sig
        ));

        // Hybrid combination: Ed25519 + Falcon-512
        let ed_sig = ed_sk.sign(msg).to_bytes().to_vec();
        let mut hybrid_pk = Vec::with_capacity(HYBRID_PUBKEY_LEN);
        hybrid_pk.extend_from_slice(&ed_pk);
        hybrid_pk.extend_from_slice(&falcon_pk);

        let mut hybrid_sig = Vec::with_capacity(HYBRID_SIG_LEN);
        hybrid_sig.extend_from_slice(&ed_sig);
        hybrid_sig.extend_from_slice(&falcon_sig);

        assert!(verify_pq_signature(
            PqScheme::Hybrid,
            &hybrid_pk,
            msg,
            &hybrid_sig
        ));

        // Tampering Ed25519 portion breaks hybrid verification
        let mut broken_ed = hybrid_sig.clone();
        broken_ed[0] ^= 0xFF;
        assert!(!verify_pq_signature(
            PqScheme::Hybrid,
            &hybrid_pk,
            msg,
            &broken_ed
        ));

        // Tampering Falcon portion breaks hybrid verification
        let mut broken_falcon = hybrid_sig.clone();
        broken_falcon[ED25519_SIG_LEN] ^= 0xFF;
        assert!(!verify_pq_signature(
            PqScheme::Hybrid,
            &hybrid_pk,
            msg,
            &broken_falcon
        ));
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
        assert_eq!(
            a, a_orig,
            "NTT forward followed by inverse NTT must round-trip exactly"
        );

        let c_ntt = poly_mul_ntt(&a_orig, &b);
        let mut c_schoolbook = [0u32; 512];
        for (i, &a) in a_orig.iter().enumerate() {
            let ai = a as u32;
            for (j, &bj) in b.iter().enumerate() {
                let term = (ai * bj as u32) % FALCON_MODULUS_Q;
                let idx = i + j;
                if idx < 512 {
                    c_schoolbook[idx] = (c_schoolbook[idx] + term) % FALCON_MODULUS_Q;
                } else {
                    c_schoolbook[idx - 512] =
                        (c_schoolbook[idx - 512] + FALCON_MODULUS_Q - term) % FALCON_MODULUS_Q;
                }
            }
        }
        for (i, (&cn, &cs)) in c_ntt.iter().zip(c_schoolbook.iter()).enumerate() {
            assert_eq!(
                cn, cs as u16,
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
            verify_pq_signature(
                PqScheme::Falcon512,
                keypair_seed.pubkey(),
                other_msg,
                &other_sig
            ),
            "Authentic Falcon-512 signature from seeded keypair must verify"
        );
    }

    #[test]
    fn test_forged_falcon512_signatures_fail() {
        let keypair = FalconKeypair::generate_from_seed(0x42);
        let msg = b"Falcon-512 cryptographic soundness audit message";
        let sig = keypair.sign(msg);

        // 1. Valid signature passes
        assert!(verify_pq_signature(
            PqScheme::Falcon512,
            keypair.pubkey(),
            msg,
            &sig
        ));

        // 2. Tampered message FAILS
        assert!(
            !verify_pq_signature(
                PqScheme::Falcon512,
                keypair.pubkey(),
                b"Tampered Message",
                &sig
            ),
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
    fn test_mldsa44_is_unknown_fail_closed() {
        // GATE: KI-01 deletes the ML-DSA-44 stub (no FIPS-204 math in-tree), so
        // 0x03 resolves as UNKNOWN at admission — `from_id(3)` is `Err` and a
        // 0x03-signed payload is refused with the unknown-scheme error (never
        // `Ok(false)`-ambiguity: decode is `Err`, not a `false` verify).
        let err = PqScheme::from_id(3).expect_err("0x03 must be refused");
        assert!(
            err.contains("Unknown"),
            "refusal must be unknown-scheme: {err}"
        );
        assert!(
            err.contains('3'),
            "refusal must name the scheme id: {err}"
        );

        // Verify-level refusal: even well-formed 0x03 material MUST NOT verify
        // (no verifier exists — refusal is unconditional, not length-dependent).
        let pk = vec![0x77u8; MLDSA44_PUBKEY_LEN];
        let sig = vec![0x22u8; MLDSA44_SIG_LEN];
        assert!(!verify_pq_signature(
            PqScheme::MlDsa44,
            &pk,
            b"ML-DSA-44 test message",
            &sig
        ));
        assert!(!verify_pq_signature(
            PqScheme::MlDsa44,
            &pk,
            b"Tampered msg",
            &sig
        ));
        // Degenerate inputs refuse identically (no acceptance branch remains).
        let mut zero_rho = pk.clone();
        zero_rho[..32].fill(0);
        assert!(!verify_pq_signature(
            PqScheme::MlDsa44,
            &zero_rho,
            b"m",
            &sig
        ));

        // Admission-level refusal: a PQ1 envelope carrying scheme byte 0x03
        // fails to decode with the unknown-scheme error (never admitted,
        // never verified — `Err`, not `Ok(false)`).
        let env = PqSignatureEnvelope::new_explicit(PqScheme::MlDsa44, pk, sig);
        let bytes = env.encode();
        assert_eq!(bytes[3], 3, "envelope must still frame the 0x03 scheme id");
        let err = PqSignatureEnvelope::decode(&bytes).expect_err("0x03 envelope must not decode");
        assert!(
            err.contains("Unknown"),
            "decode refusal must be unknown-scheme: {err}"
        );
    }

    #[test]
    fn pure_pq_enforcement_and_override() {
        set_pure_pq_override(Some(true));
        assert!(is_pure_pq_enforced());

        set_pure_pq_override(Some(false));
        assert!(!is_pure_pq_enforced());

        set_pure_pq_override(None);
    }
    /// AUDIT W4.1 REGRESSION: the FIPS 206 (FN-DSA) signer must draw a FRESH
    /// discrete Gaussian sample for every signature.
    ///
    /// The pre-W4.1 signer derived `s2` from a deterministic Babai round-off,
    /// so two signatures over the same message were identical and every
    /// signature was confined to the fundamental parallelepiped of the private
    /// basis (Nguyen-Regev parallelepiped attack -> private-key recovery from
    /// a few hundred signatures).
    #[test]
    fn test_falcon_signing_is_non_deterministic_and_verifies() {
        let kp = FalconKeypair::generate_from_seed(0x5A);
        let msg = b"Falcon-512 non-determinism regression";

        // Same key, same message, two signings -> two DIFFERENT signatures.
        let sig_a = kp.sign(msg);
        let sig_b = kp.sign(msg);
        assert_eq!(sig_a.len(), FALCON512_SIG_LEN);
        assert_eq!(sig_b.len(), FALCON512_SIG_LEN);
        assert_ne!(
            sig_a, sig_b,
            "FIPS 206 signing must draw a fresh discrete Gaussian sample per signature; \
             identical signatures mean the Babai round-off is back"
        );
        assert!(
            verify_falcon512(kp.pubkey(), msg, &sig_a),
            "first signature must verify"
        );
        assert!(
            verify_falcon512(kp.pubkey(), msg, &sig_b),
            "second signature must verify"
        );
        assert!(
            verify_pq_signature(PqScheme::Falcon512, kp.pubkey(), msg, &sig_a),
            "first signature must verify under verify_pq_signature"
        );
        assert!(
            verify_pq_signature(PqScheme::Falcon512, kp.pubkey(), msg, &sig_b),
            "second signature must verify under verify_pq_signature"
        );

        // The seeded entry point is equally non-deterministic: FIPS 206 requires
        // fresh sampler randomness even when the caller supplies a seed.
        let seed = [0x5Au8; 32];
        let seeded_a = kp.sign_with_seed(msg, &seed);
        let seeded_b = kp.sign_with_seed(msg, &seed);
        assert_eq!(seeded_a.len(), FALCON512_SIG_LEN);
        assert_ne!(
            seeded_a, seeded_b,
            "sign_with_seed must not be reproducible: a deterministic signer is exactly the \
             parallelepiped leak that was removed"
        );
        assert!(verify_falcon512(kp.pubkey(), msg, &seeded_a));
        assert!(verify_falcon512(kp.pubkey(), msg, &seeded_b));

        // A different seed must also produce a different (valid) signature.
        let other_seed = [0x5Bu8; 32];
        let seeded_c = kp.sign_with_seed(msg, &other_seed);
        assert_ne!(seeded_a, seeded_c);
        assert!(verify_falcon512(kp.pubkey(), msg, &seeded_c));

        // The nonces must all differ: a reused Falcon nonce with a different
        // Gaussian sample leaks the difference of two short vectors.
        let nonce = |sig: &[u8]| sig[1..41].to_vec();
        let nonces = [
            nonce(&sig_a),
            nonce(&sig_b),
            nonce(&seeded_a),
            nonce(&seeded_b),
            nonce(&seeded_c),
        ];
        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(
                    nonces[i], nonces[j],
                    "Falcon nonces must never repeat across signatures"
                );
            }
        }
    }

    /// AUDIT W4.1 REGRESSION: the signature must NOT be the deterministic
    /// Babai round-off of the private basis.
    ///
    /// This is the precise anti-Babai assertion: for the nonce that actually
    /// appears in the signature, the old (vulnerable) computation is fully
    /// determined, so a compliant Gaussian sample can never coincide with it.
    #[test]
    fn test_falcon_signature_is_not_the_babai_round_off() {
        let kp = FalconKeypair::generate_from_seed(0x33);
        let msg = b"Falcon-512 Babai round-off regression";
        let seed = [0x11u8; 32];
        let sig = kp.sign_with_seed(msg, &seed);
        assert!(
            verify_falcon512(kp.pubkey(), msg, &sig),
            "the signature under test must be valid"
        );

        // Reproduce the removed Babai round-off for the signature's nonce.
        let (nonce, s2) = unpack_falcon_sig(&sig).expect("valid signature unpacking");
        let c = hash_to_point(&nonce, msg);
        let mut c_i64 = [0i64; 512];
        for i in 0..512 {
            c_i64[i] = c[i] as i64;
        }
        let c_f = negacyclic_mul_i64(&c_i64, &kp.capital_f);
        let c_f_small = negacyclic_mul_i64(&c_i64, &kp.f);
        let mut k1 = [0i64; 512];
        let mut k2 = [0i64; 512];
        for i in 0..512 {
            k1[i] = round_div(-c_f[i], FALCON_MODULUS_Q as i64);
            k2[i] = round_div(c_f_small[i], FALCON_MODULUS_Q as i64);
        }
        let s2_p1 = negacyclic_mul_i64(&k1, &kp.f);
        let s2_p2 = negacyclic_mul_i64(&k2, &kp.capital_f);
        // Compare in i64: the assertion must not depend on the Babai output
        // happening to be representable in i16.
        let mut differs = false;
        for i in 0..512 {
            if s2_p1[i] + s2_p2[i] != s2[i] as i64 {
                differs = true;
                break;
            }
        }
        assert!(
            differs,
            "the signature is the deterministic Babai round-off of its own nonce: \
             signatures are confined to the private parallelepiped and the key leaks \
             (Nguyen-Regev parallelepiped attack)"
        );
    }

    /// AUDIT W4.1: the FN-DSA private key must be COMPLETE - (f, g, F, G) with
    /// `G` the true NTRU partner - and it must survive a serialization round
    /// trip so a persisted node key stays usable.
    #[test]
    fn test_falcon_private_key_is_complete_and_round_trips() {
        let kp = FalconKeypair::generate_from_seed(0x21);
        let msg = b"Falcon-512 complete FN-DSA private key";

        // `G` must be populated (it used to be left at [0i16; 512]).
        assert!(
            kp.capital_g.iter().any(|&v| v != 0),
            "capital_g must be populated: the FN-DSA private key is (f, g, F, G)"
        );
        assert!(
            falcon_ntru_relation_holds(&kp.f, &kp.g, &kp.capital_f, &kp.capital_g),
            "the FN-DSA private key must satisfy the NTRU relation f*G - g*F = q"
        );

        // The public key must be h = g * f^-1 mod q.
        let h = compute_h(&kp.f, &kp.g).expect("f must be invertible in Z_q[x]/(x^512+1)");
        assert_eq!(h, kp.h, "h must be g * f^-1 mod q");

        // Serialization round trip keeps the key usable for signing.
        let restored = FalconKeypair::from_bytes(&kp.to_bytes()).expect("key must round trip");
        assert_eq!(restored.f, kp.f);
        assert_eq!(restored.g, kp.g);
        assert_eq!(restored.capital_f, kp.capital_f);
        assert_eq!(restored.capital_g, kp.capital_g);
        assert_eq!(restored.public_key, kp.public_key);

        let sig = restored.sign(msg);
        assert_eq!(sig.len(), FALCON512_SIG_LEN);
        assert!(
            verify_falcon512(kp.pubkey(), msg, &sig),
            "a restored key must still produce verifiable signatures"
        );

        // AUDIT W6.1 (live-cluster key migration): a key whose `G` is missing
        // (the pre-FIPS-206 on-disk format written by the live testnet nodes)
        // is NOT refused any more - it is REPAIRED at load time (the NTRU
        // partner is reconstructed from `(f, g, F)` exactly as the reference
        // implementation's key expansion does), so the live nodes keep
        // starting and their validator addresses do NOT change.
        let mut broken = kp.to_bytes();
        // Layout: priv_len(4) + private_key(len*2) + pub_len(4) + public_key +
        //         f(1024) + g(1024) + F(1024) + G(1024) + h(1024)
        let g_offset = serialized_g_offset(&broken);
        for b in broken[g_offset..g_offset + 1024].iter_mut() {
            *b = 0;
        }
        let repaired = FalconKeypair::from_bytes(&broken)
            .expect("a legacy key without G must LOAD (it is repaired in memory)");
        assert!(
            repaired.legacy_incomplete_ntru,
            "the loaded key must be flagged as a legacy incomplete NTRU key"
        );
        assert_eq!(
            repaired.capital_g, kp.capital_g,
            "the reconstructed NTRU partner must be bit-identical to the one KEYGEN produced"
        );
        assert_eq!(
            repaired.public_key, kp.public_key,
            "the public key must NOT change: the validator address must stay the same"
        );
        assert_eq!(
            repaired.validator_id(),
            kp.validator_id(),
            "the validator address of a repaired legacy key must NOT change"
        );
        let legacy_sig = repaired.sign(msg);
        assert_eq!(legacy_sig.len(), FALCON512_SIG_LEN);
        assert!(
            verify_falcon512(kp.pubkey(), msg, &legacy_sig),
            "a repaired legacy key must produce signatures that verify under the EXISTING \
             public key h = g/f"
        );
        assert!(
            verify_pq_signature(PqScheme::Falcon512, kp.pubkey(), msg, &legacy_sig),
            "a repaired legacy key must produce signatures that verify under verify_pq_signature"
        );
    }

    /// AUDIT W6.1: the EXACT on-disk format of the live testnet keys (the
    /// pre-FIPS-206 `falcon.key` files) must keep working.
    ///
    /// The pre-FIPS-206 code generated the private key with the `falcon-rust`
    /// port of the reference implementation, whose COMPACT secret-key
    /// encoding carries only `f`, `g` and `F` (the NTRU partner `G` is not
    /// part of that encoding), and it stored `G = [0i16; 512]`. This test
    /// rebuilds that key file byte-for-byte from the same generator, loads it
    /// with the current loader, signs with it and verifies the signature under
    /// the public key that was written to disk.
    ///
    /// It is the regression test for the live-cluster migration: the four live
    /// nodes must start, keep signing and keep their validator address.
    #[test]
    fn test_legacy_pre_fips206_on_disk_key_loads_signs_and_verifies() {
        // Reproduce the pre-FIPS-206 key generation exactly.
        let mut seed = [0u8; 32];
        seed[0] = 0x2A;
        seed[31] = 0x2A_u8.wrapping_mul(79);
        let mut hasher = blake3::Hasher::new_derive_key("FALCON512_KEYGEN_V4");
        hasher.update(&seed);
        let derived_seed = hasher.finalize();

        let (sk, _pk) = falcon_rust::falcon512::keygen(*derived_seed.as_bytes());
        let sk_bytes = sk.to_bytes();

        let mut f = [0i16; 512];
        let mut g = [0i16; 512];
        let mut capital_f = [0i16; 512];
        let mut offset = 1; // skip the 0x59 header
        offset += trim_i8_decode(&mut f, 6, &sk_bytes[offset..]);
        offset += trim_i8_decode(&mut g, 6, &sk_bytes[offset..]);
        let _ = trim_i8_decode(&mut capital_f, 8, &sk_bytes[offset..]);

        let h = compute_h(&f, &g).expect("f must be invertible in Z_q[x]/(x^512+1)");
        let mut pk_bytes = vec![0u8; FALCON512_PUBKEY_LEN];
        pk_bytes[0] = 0x09;
        let mut enc_buf = [0u8; 896];
        modq_encode(&mut enc_buf, &h);
        pk_bytes[1..].copy_from_slice(&enc_buf);

        // The legacy on-disk key: (f, g, F) and NO NTRU partner.
        let legacy = FalconKeypair {
            private_key: f.to_vec(),
            public_key: pk_bytes.clone(),
            f,
            g,
            capital_f,
            capital_g: [0i16; 512],
            h,
            legacy_incomplete_ntru: false,
        };
        let legacy_bytes = legacy.to_bytes();
        let address_before = legacy.validator_id();

        // It MUST load (the live nodes must not refuse to start) ...
        let loaded = FalconKeypair::from_bytes(&legacy_bytes)
            .expect("a legacy pre-FIPS-206 key file must load");
        assert!(loaded.legacy_incomplete_ntru);
        assert_eq!(
            loaded.public_key, pk_bytes,
            "the public key must not change"
        );
        assert_eq!(
            loaded.validator_id(),
            address_before,
            "the validator address of a live node must NOT change across the upgrade"
        );

        // ... it MUST sign ...
        let msg = b"live validator vote payload";
        let sig = loaded.sign(msg);
        assert_eq!(sig.len(), FALCON512_SIG_LEN);

        // ... and the signature MUST verify under the EXISTING public key.
        assert!(
            verify_falcon512(&pk_bytes, msg, &sig),
            "a legacy key must produce signatures that verify under the EXISTING public key"
        );
        assert!(verify_pq_signature(
            PqScheme::Falcon512,
            &pk_bytes,
            msg,
            &sig
        ));

        // The recovered partner is the genuine NTRU partner: it satisfies the
        // exact integer relation f*G - g*F = q.
        assert!(
            falcon_ntru_relation_holds(&loaded.f, &loaded.g, &loaded.capital_f, &loaded.capital_g),
            "the reconstructed partner must satisfy f*G - g*F = q over the integers"
        );
    }

    /// AUDIT W6.1: a key whose `G` is present but INCONSISTENT with its `h`
    /// (a corrupted key file) stays refused - the migration relaxation must
    /// not turn into a general "accept anything" hole.
    #[test]
    fn test_falcon_key_with_inconsistent_g_is_still_refused() {
        let kp = FalconKeypair::generate_from_seed(0x4D);
        let mut bytes = kp.to_bytes();
        // Layout: priv_len(4) + private_key(len*2) + pub_len(4) + public_key +
        //         f(1024) + g(1024) + F(1024) + G(1024) + h(1024)
        let g_offset = serialized_g_offset(&bytes);
        // Corrupt one coefficient of G so that G != h*F (mod q).
        bytes[g_offset] ^= 0x01;
        assert!(
            FalconKeypair::from_bytes(&bytes).is_none(),
            "a key whose G does not belong to the lattice of h must stay refused"
        );
    }

    /// Byte offset of the NTRU partner `G` inside a [`FalconKeypair::to_bytes`]
    /// serialization: `priv_len(4) + private_key(len*2) + pub_len(4) +
    /// public_key + f(1024) + g(1024) + F(1024)`.
    fn serialized_g_offset(bytes: &[u8]) -> usize {
        let priv_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let mut off = 4 + priv_len * 2;
        let pub_len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4 + pub_len;
        off + 3 * 1024
    }

    /// Decodes the compact reference-implementation secret-key encoding
    /// (`f` with 6 bits, `g` with 6 bits, `F` with 8 bits per coefficient)
    /// used by the pre-FIPS-206 key generator.
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
                let s1_val = (c[i] as i32 + FALCON_MODULUS_Q as i32 - s2_h[i] as i32)
                    % (FALCON_MODULUS_Q as i32);
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
            assert_eq!(
                kp.public_key, kp_repeat.public_key,
                "Determinism: identical seed must yield identical pubkey"
            );
            assert_eq!(
                kp.f, kp_repeat.f,
                "Determinism: identical seed must yield identical f"
            );
            assert_eq!(
                kp.g, kp_repeat.g,
                "Determinism: identical seed must yield identical g"
            );
            assert_eq!(
                kp.capital_f, kp_repeat.capital_f,
                "Determinism: identical seed must yield identical F"
            );
            assert_eq!(
                kp.capital_g, kp_repeat.capital_g,
                "Determinism: identical seed must yield identical G"
            );
            assert_eq!(
                kp.h, kp_repeat.h,
                "Determinism: identical seed must yield identical h"
            );

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
                !verify_pq_signature(
                    PqScheme::Falcon512,
                    keypairs[next_idx].0.pubkey(),
                    msg,
                    &keypairs[i].1
                ),
                "Signature from keypair {} must fail verification under keypair {}",
                i,
                next_idx
            );
        }
    }
}
