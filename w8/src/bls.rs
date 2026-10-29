//! Real pair-based BLS12-381 aggregate signatures, and the soft-fork spec (P1-c).
//!
//! # Why this exists
//! Baseline certificates carry N individual Ed25519 signatures
//! (`QuorumCertificate.signatures: Vec<(ValidatorId, Signature)>`). With 100+
//! validators that is 100+ signatures per block, per round, replicated to everyone.
//! BLS aggregate signatures replace them with ONE 96-byte signature plus a
//! [`SignerBitVector`], and the bitvector is not a side effect: `apply_downtime_slashes`
//! derives the signer set from `cert.signatures` today, which is exactly what stops
//! working once signatures aggregate.
//!
//! # This is genuine BLS, not a Schnorr look-alike
//! It uses the `bls12_381` crate's pairing (pure Rust, no C toolchain -- `blst` was
//! avoided deliberately so the build stays portable). Scheme: minimal-pubkey-size,
//! public keys in G1 (48 bytes), signatures in G2 (96 bytes), hash-to-curve with the
//! standard ciphersuite domain separation tag. A single signature verifies by
//! `e(sig, G1) == e(H(m), pk)`, which is one pairing after moving to the GT group;
//! an aggregate over distinct keys on the SAME message verifies by
//! `e(agg_sig, G1) == e(H(m), agg_pk)` -- that is the whole point of BLS and it
//! cannot be done without pairings.
//!
//! Note honestly what a same-message aggregate does and does not give you: it proves
//! a set of keys all signed the same bytes, which is what a consensus certificate
//! needs. It does not, on its own, prove *which* keys without the bitvector (a rogue
//! -key attack can otherwise forge an aggregate), which is why [`SignerBitVector`]
//! is mandatory in [`BlsAggregateSignature`] and the verifier is handed the full
//! validator set plus the bitvector rather than a bare key list.
//!
//! # Soft-fork activation
//! `ValidatorId = [u8; 32]` lives inside the staking ledger, which is inside the
//! commitment, which is inside the state root. So an aggregate-only release cannot
//! start on existing data directories. [`HybridCertificate`] and
//! [`is_bls_active`] model the transition: Ed25519 below the activation height,
//! BLS aggregate at or above it.

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fmt;

/// Ciphersuite DST. Changing this changes every signature, so it is frozen.
const DST: &[u8] = b"STELL_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

/// Compressed G1 point, the public key size.
pub const PUBLIC_KEY_LEN: usize = 48;
/// Compressed G2 point, the signature size.
pub const SIGNATURE_LEN: usize = 96;

/// Default height at which BLS aggregation is activated in consensus.
pub const DEFAULT_BLS_ACTIVATION_HEIGHT: u64 = 10_000;

/// Returns true if BLS aggregate verification is active for the given block height.
pub fn is_bls_active(height: u64, activation_height: u64) -> bool {
    height >= activation_height
}

/// BLS secret scalar. Not `Clone` by accident: every clone is another copy of the key.
///
/// SECRET — wiped on drop. The inner [`Scalar`] has no `Zeroize` impl of its
/// own (bls12_381 0.9), so `zeroize` overwrites it with the zero scalar and
/// `Drop` calls it: a moved-or-dropped key leaves no scalar behind in memory
/// beyond what the allocator itself retains. Do NOT derive `Clone`/`Debug`
/// on this type (both would copy or print the scalar).
pub struct BlsSecretKey(Scalar);

impl zeroize::Zeroize for BlsSecretKey {
    fn zeroize(&mut self) {
        self.0 = Scalar::from(0u64);
    }
}

impl Drop for BlsSecretKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

/// BLS public key: a compressed G1 point.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlsPublicKey([u8; PUBLIC_KEY_LEN]);

impl fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsPublicKey({})", hex::encode(&self.0[..8]))
    }
}

impl BlsPublicKey {
    /// Raw compressed bytes, for a `ValidatorId`-shaped slot or the wire.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }

    /// Parse a compressed G1 point. Rejects anything not on the curve, and rejects
    /// the identity: the identity would make an aggregate verify for free.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Option<Self> {
        let pt: Option<G1Affine> = Option::from(G1Affine::from_compressed(bytes));
        let pt = pt?;
        if bool::from(pt.is_identity()) {
            return None;
        }
        Some(Self(*bytes))
    }

    fn point(&self) -> Option<G1Affine> {
        Option::from(G1Affine::from_compressed(&self.0))
    }
}

/// A single BLS signature: a compressed G2 point.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct BlsSignature(pub [u8; SIGNATURE_LEN]);

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlsSignature({})", hex::encode(&self.0[..8]))
    }
}

impl BlsSignature {
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Option<Self> {
        let pt: Option<G2Affine> = Option::from(G2Affine::from_compressed(bytes));
        let pt = pt?;
        // FAIL-CLOSED (audit F-HIGH-1): reject the identity signature exactly
        // like `BlsPublicKey::from_bytes` rejects the identity key. An
        // identity aggregate element contributes nothing to the sum, and an
        // all-identity aggregate must never parse into something verifiable.
        if bool::from(pt.is_identity()) {
            return None;
        }
        Some(Self(*bytes))
    }
}

impl BlsSecretKey {
    /// Fresh random key.
    pub fn generate() -> Self {
        // `Scalar::random` is behind an off-by-default feature, so draw 64 bytes
        // from the OS and reduce. This is uniformly distributed because
        // `from_bytes_wide` reduces mod r over a 2^512 input.
        let mut wide = [0u8; 64];
        OsRng.fill_bytes(&mut wide);
        Self(Scalar::from_bytes_wide(&wide))
    }

    /// Deterministic key from a 32-byte seed, for a node config.
    ///
    /// The seed is run through SHA-256 first so a seed with bias does not become a
    /// biased scalar, and the domain tag keeps this from colliding with any other
    /// use of the same seed elsewhere in the node.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(b"STELLEREUM_BLS_KEY_V1");
        h.update(seed);
        let d = h.finalize();
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&d);
        // A second hash for the high half, so the wide reduction is not dominated
        // by zeroes.
        let mut h2 = Sha256::new();
        h2.update(b"STELLEREUM_BLS_KEY_V1_HI");
        h2.update(seed);
        wide[32..].copy_from_slice(&h2.finalize());
        Self(Scalar::from_bytes_wide(&wide))
    }

    pub fn public_key(&self) -> BlsPublicKey {
        let pk = G1Projective::generator() * self.0;
        BlsPublicKey(G1Affine::from(pk).to_compressed())
    }

    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        let h = hash_to_g2(msg);
        let sig = G2Affine::from(h * self.0);
        BlsSignature(sig.to_compressed())
    }
}

/// Hash an arbitrary message to a G2 point (the signature group).
fn hash_to_g2(msg: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&[msg], DST)
}

impl BlsPublicKey {
    /// Verify a single signature. One pairing identity: `e(G1, sig) == e(pk, H(m))`.
    pub fn verify(&self, msg: &[u8], sig: &BlsSignature) -> bool {
        let (Some(pk), Some(sig_pt)) = (self.point(), sig_point(sig)) else {
            return false;
        };
        let h = G2Affine::from(hash_to_g2(msg));
        pairing(&G1Affine::generator(), &sig_pt) == pairing(&pk, &h)
    }
}

fn sig_point(sig: &BlsSignature) -> Option<G2Affine> {
    Option::from(G2Affine::from_compressed(&sig.0))
}

/// Bitvector identifying validator participation in an aggregate signature.
/// Bit `i` set means the validator at canonical index `i` signed.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SignerBitVector {
    bitmask: Vec<u8>,
    total_validators: usize,
}

impl SignerBitVector {
    pub fn new(total_validators: usize) -> Self {
        Self {
            bitmask: vec![0u8; total_validators.div_ceil(8)],
            total_validators,
        }
    }

    /// Rebuild a bitvector from wire bytes (the QC envelope decodes one).
    /// Fails closed on a bitmask whose length does not match
    /// `total_validators`, so a truncated or padded envelope can never be
    /// interpreted as a participant set.
    pub fn from_bitmask(bitmask: Vec<u8>, total_validators: usize) -> Option<Self> {
        if bitmask.len() != total_validators.div_ceil(8) {
            return None;
        }
        Some(Self { bitmask, total_validators })
    }

    pub fn total_validators(&self) -> usize {
        self.total_validators
    }

    pub fn bitmask(&self) -> &[u8] {
        &self.bitmask
    }

    pub fn set(&mut self, index: usize, signed: bool) {
        if index >= self.total_validators {
            return;
        }
        let byte = index / 8;
        let bit = index % 8;
        if signed {
            self.bitmask[byte] |= 1 << bit;
        } else {
            self.bitmask[byte] &= !(1 << bit);
        }
    }

    pub fn is_set(&self, index: usize) -> bool {
        if index >= self.total_validators {
            return false;
        }
        self.bitmask[index / 8] & (1 << (index % 8)) != 0
    }

    pub fn signed_count(&self) -> usize {
        (0..self.total_validators).filter(|&i| self.is_set(i)).count()
    }

    /// Validator indices absent from this certificate. This is the downtime-slash
    /// input: it answers "who did not sign" without needing N signatures present.
    pub fn absent_indices(&self) -> Vec<usize> {
        (0..self.total_validators)
            .filter(|&i| !self.is_set(i))
            .collect()
    }
}

/// An aggregate signature over one message from a set of validators.
///
/// `signature` is a single 96-byte G2 point; `participants` says which canonical
/// validator indices contributed. Both are required: see the module docs on the
/// rogue-key caveat.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsAggregateSignature {
    pub signature: BlsSignature,
    pub participants: SignerBitVector,
}

impl BlsAggregateSignature {
    pub fn to_bytes(&self) -> ([u8; SIGNATURE_LEN], &[u8]) {
        (self.signature.0, self.participants.bitmask())
    }
}

/// Aggregate signatures from multiple validators over the same message.
///
/// Returns an error on an out-of-range or duplicate index, or a signature that is
/// not a curve point, rather than silently producing an aggregate that will not
/// verify -- a malformed aggregate that verifies would be far worse than a rejection.
pub fn aggregate_signatures(
    signatures: &[(usize, BlsSignature)],
    total_validators: usize,
) -> Result<BlsAggregateSignature, String> {
    if signatures.is_empty() {
        return Err("cannot aggregate zero signatures".into());
    }

    let mut participants = SignerBitVector::new(total_validators);
    let mut sum = G2Projective::identity();

    for (idx, sig) in signatures {
        if *idx >= total_validators {
            return Err(format!("validator index {idx} out of range"));
        }
        if participants.is_set(*idx) {
            return Err(format!("validator {idx} appears twice in one aggregate"));
        }
        let Some(pt) = sig_point(sig) else {
            return Err("aggregate member is not a valid G2 point".into());
        };
        participants.set(*idx, true);
        sum += pt;
    }

    // FAIL-CLOSED: an aggregate that sums to the identity (e.g. crafted
    // cancelling members) must never reach the wire — like the identity key
    // and identity signature, it is refused at construction.
    if bool::from(G2Affine::from(sum).is_identity()) {
        return Err("aggregate sums to the identity; refused".into());
    }

    Ok(BlsAggregateSignature {
        signature: BlsSignature(G2Affine::from(sum).to_compressed()),
        participants,
    })
}

/// Verify an aggregate signature over a message against the FULL validator key list.
///
/// `validator_keys` is the whole set in canonical order and `participants` selects
/// from it, so an attacker cannot choose the key set the signature is measured
/// against -- the same reason the consensus side stopped taking a caller-supplied
/// validator set.
pub fn verify_aggregate_signature(
    validator_keys: &[BlsPublicKey],
    msg: &[u8],
    agg: &BlsAggregateSignature,
) -> bool {
    if agg.participants.total_validators() != validator_keys.len() {
        return false;
    }
    if agg.participants.signed_count() == 0 {
        return false;
    }
    let Some(sig_pt) = sig_point(&agg.signature) else {
        return false;
    };
    // AUDIT W6.5 (defence in depth): refuse the IDENTITY aggregate
    // explicitly. `BlsSignature::from_bytes` and `aggregate_signatures`
    // already refuse it, but `BlsAggregateSignature` has PUBLIC fields, so a
    // hand-built certificate can carry one. The pairing would then read
    // `e(G1, O) == 1`, and the check would only fail because the honest key
    // sum is non-trivial — an identity aggregate must never get that far.
    if bool::from(sig_pt.is_identity()) {
        return false;
    }

    // Sum the participating public keys. Any unparseable key fails closed.
    let mut sum_pk = G1Projective::identity();
    for (i, pk) in validator_keys.iter().enumerate() {
        if !agg.participants.is_set(i) {
            continue;
        }
        let Some(pt) = pk.point() else {
            return false;
        };
        sum_pk += pt;
    }

    let h = G2Affine::from(hash_to_g2(msg));
    pairing(&G1Affine::generator(), &sig_pt)
        == pairing(&G1Affine::from(sum_pk), &h)
}

/// Hybrid consensus certificate supporting the soft-fork transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HybridCertificate {
    /// Pre-activation: the existing Ed25519 signature list.
    Ed25519 {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        signatures: Vec<([u8; 32], [u8; 64])>,
    },
    /// Post-activation: one BLS aggregate plus the signer bitvector.
    BlsAggregate {
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        aggregate: BlsAggregateSignature,
    },
}

impl HybridCertificate {
    pub fn height(&self) -> u64 {
        match self {
            Self::Ed25519 { height, .. } | Self::BlsAggregate { height, .. } => *height,
        }
    }

    pub fn round(&self) -> u32 {
        match self {
            Self::Ed25519 { round, .. } | Self::BlsAggregate { round, .. } => *round,
        }
    }

    pub fn block_hash(&self) -> [u8; 32] {
        match self {
            Self::Ed25519 { block_hash, .. } | Self::BlsAggregate { block_hash, .. } => *block_hash,
        }
    }

    /// Whether this certificate's FORMAT is legal at the soft-fork height.
    ///
    /// This is deliberately a separate question from "does the quorum verify": a
    /// pre-activation block must be Ed25519 and a post-activation block must be BLS,
    /// and mixing them would let a node accept a format the rest of the network has
    /// stopped producing (or has not started producing yet).
    pub fn is_format_valid(&self, activation_height: u64) -> bool {
        let active = is_bls_active(self.height(), activation_height);
        match self {
            Self::Ed25519 { .. } => !active,
            Self::BlsAggregate { .. } => active,
        }
    }
}

// ============================================================================
// QC-BLS activation: env/config flag + validator key registry
// ============================================================================
//
// Quorum certificates carry the BLS aggregate as an envelope INSIDE the
// existing `signatures` list (see `consensus::BLS_QC_MARKER_ID`), so the
// bincode layout of `QuorumCertificate` — and therefore every persisted block —
// is unchanged. What decides whether the aggregate may COUNT signature power
// is this configuration:
//
// * `STELL_BLS_QC=1`              — enable the BLS path (default: OFF).
// * `STELL_BLS_KEYS_FILE=<path>`   — registry of `<ed25519_hex> <bls_pk_hex>`
//   lines (or `STELL_BLS_KEYS` inline, comma-separated `<ed>:<bls>` pairs).
//   The registry is what makes the aggregate meaningful: verification maps
//   bitvector indices to the FULL validator set in canonical order and looks
//   each member's BLS key up here. A missing member disables the BLS path for
//   that certificate (fall back to the Ed25519 list) rather than failing it.
// * `STELL_BLS_SK_SEED=<64 hex>`   — this node's BLS secret seed, so its votes
//   can carry a BLS half (`BlsSecretKey::from_seed`).
//
// BOTH SIDES MUST ENABLE TOGETHER for the aggregate to ever be *counted*:
// with the flag off (the default, and the state of the live stand) a
// certificate's aggregate is ignored and verification is exactly the Ed25519
// baseline. Because production NEVER strips the Ed25519 list, a flag-off node
// still accepts flag-on nodes' certificates through the fallback — mixed
// configurations do not fork. The stripping that would realize the wire-space
// saving is deferred until the network is uniformly enabled.

/// Registry: validator Ed25519 identity -> that validator's BLS public key.
pub type BlsKeyRegistry = std::collections::BTreeMap<[u8; 32], BlsPublicKey>;

/// Environment variable that enables the BLS path in certificate verification
/// and vote signing.
pub const BLS_QC_ENV: &str = "STELL_BLS_QC";
/// Environment variable pointing at the validator BLS key registry file.
pub const BLS_KEYS_FILE_ENV: &str = "STELL_BLS_KEYS_FILE";
/// Environment variable with the registry inline: `ed_hex:bls_hex,...`.
pub const BLS_KEYS_INLINE_ENV: &str = "STELL_BLS_KEYS";
/// Environment variable with this node's BLS secret seed (64 hex chars).
pub const BLS_SK_SEED_ENV: &str = "STELL_BLS_SK_SEED";

/// Fail-closed startup gate for the QC-BLS path (audit-pq-crypto HIGH).
///
/// DECISION (documented per the audit bundle): the registry
/// (`STELL_BLS_KEYS_FILE` / `STELL_BLS_KEYS`) carries bare `<ed> <bls>` pairs
/// with NO proof-of-possession — `parse_registry_entries` below accepts any
/// non-identity G1 point. Without a PoP, a rogue-key attacker can register a
/// key crafted against honest keys and forge same-message aggregates, so
/// counting BLS power (`STELL_BLS_QC=1`) is unsound on this registry format.
/// A real PoP is STRUCTURALLY INFEASIBLE in one session: it changes the
/// registry wire format (every entry gains a signature), the env/file
/// plumbing, and requires every operator to re-register with proofs — while
/// the default-off path (Ed25519 baseline, aggregate ignored) is exactly as
/// safe as before.
///
/// So the fail-closed alternative ships: enabling `STELL_BLS_QC=1` is a LOUD
/// startup refusal (called from the `run` startup gates in `main.rs`), never
/// a silent fallback. Default-off nodes are unaffected: the flag unset (or
/// anything but `1`/`true`/`on`) starts exactly as before, and certificates
/// keep verifying through the Ed25519 baseline. When a PoP-carrying registry
/// lands, this gate is the line to delete — not to weaken.
///
/// Parses the flag EXACTLY like [`QcBlsConfig::from_env`] (`1` or
/// case-insensitive `true`/`on`): anything else is OFF.
pub fn refuse_bls_qc_if_enabled() -> Result<(), String> {
    let enabled = std::env::var(BLS_QC_ENV).map(|v| bls_flag_on(&v)).unwrap_or(false);
    if !enabled {
        return Ok(());
    }
    let msg = format!(
        "[bls] REFUSING: {env}=1 requests the BLS QC path, but the validator BLS key \
         registry carries NO proof-of-possession (bare <ed25519> <bls-pubkey> pairs) — \
         a rogue-key attacker could forge quorum aggregates. Counting BLS power is \
         therefore hard-refused until a PoP-carrying registry lands. Recovery: unset \
         {env} (default OFF: Ed25519 baseline verification, byte-identical behavior) \
         and restart. Do NOT work around this gate without adding PoP at registration.",
        env = BLS_QC_ENV
    );
    eprintln!("{msg}");
    tracing::error!("{msg}");
    Err(msg)
}

/// Single source of truth for "is the BLS flag ON" (audit F-HIGH-1).
///
/// Shared by [`refuse_bls_qc_if_enabled`] and [`QcBlsConfig::from_env`] so the
/// startup refusal gate and the runtime config can never disagree about what
/// "enabled" means. Literals are exact (`1`, case-sensitive `true`/`TRUE`,
/// `on`/`ON` after trimming): anything else — including `True`, `On`,
/// `yes`, or `1\n`-with-garbage — is OFF. Case-insensitivity is deliberately
/// NOT extended: widening the match would silently enable an experimental
/// path for operators who today run flag-off.
fn bls_flag_on(raw: &str) -> bool {
    matches!(raw.trim(), "1" | "true" | "TRUE" | "on" | "ON")
}

/// Process configuration for the QC-BLS path. Built once from the environment
/// (or directly in tests, via [`set_qc_bls_for_tests`]).
///
/// SECRET HYGIENE: `local_vote_seed` is key material. The manual `Debug` impl
/// below prints only its presence — never the bytes. (The previous derived
/// `Debug` printed the seed into any log line holding the config.)
#[derive(Clone, Default)]
pub struct QcBlsConfig {
    /// Flag (`STELL_BLS_QC`). Default OFF: the stand keeps verifying exactly
    /// as before.
    pub enabled: bool,
    /// Validator id -> BLS public key. Consensus-critical once enabled: every
    /// verifier must hold the same registry, or the aggregate simply fails to
    /// pair and falls back to Ed25519 (no fork either way).
    pub registry: BlsKeyRegistry,
    /// Seed for THIS node's BLS key; present only on a node that signs votes
    /// with a BLS half.
    ///
    /// SECRET: wiped on drop (see `Zeroize` below); never logged (see the
    /// manual `Debug` impl). Cloning this config copies the seed — keep clones
    /// short-lived and never place them in logs, errors, or RPC responses.
    pub local_vote_seed: Option<[u8; 32]>,
}

impl std::fmt::Debug for QcBlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QcBlsConfig")
            .field("enabled", &self.enabled)
            .field("registry_len", &self.registry.len())
            .field("local_vote_seed", &self.local_vote_seed.map(|_| "[redacted]"))
            .finish_non_exhaustive()
    }
}

impl zeroize::Zeroize for QcBlsConfig {
    fn zeroize(&mut self) {
        if let Some(seed) = self.local_vote_seed.as_mut() {
            zeroize::Zeroize::zeroize(seed.as_mut_slice());
        }
        self.local_vote_seed = None;
    }
}

impl Drop for QcBlsConfig {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl QcBlsConfig {
    /// Build from the environment. Malformed entries are skipped with a
    /// warning — a partial registry disables the BLS path per certificate
    /// (missing member => fallback), which is the safe direction.
    pub fn from_env() -> Self {
        let enabled = std::env::var(BLS_QC_ENV).map(|v| bls_flag_on(&v)).unwrap_or(false);
        let mut registry = BlsKeyRegistry::new();
        if let Ok(path) = std::env::var(BLS_KEYS_FILE_ENV) {
            match std::fs::read_to_string(&path) {
                Ok(text) => parse_registry_entries(&text, &mut registry),
                Err(e) => {
                    tracing::warn!(%e, path, "bls: cannot read BLS key registry file; BLS path disabled");
                }
            }
        }
        if let Ok(inline) = std::env::var(BLS_KEYS_INLINE_ENV) {
            parse_registry_entries(&inline, &mut registry);
        }
        let local_vote_seed = std::env::var(BLS_SK_SEED_ENV)
            .ok()
            .and_then(|s| hex::decode(s.trim()).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        Self { enabled, registry, local_vote_seed }
    }

    /// Canonical BLS public keys for `validators`, in the set's canonical
    /// (sorted) order — the order `SignerBitVector` indices refer to.
    ///
    /// Returns `None` if ANY member of the set is missing from the registry:
    /// a partial key list cannot be summed for the pairing check, so the
    /// caller falls back to the Ed25519 list instead of guessing.
    pub fn canonical_keys(
        &self,
        validators: &crate::consensus::ValidatorSet,
    ) -> Option<Vec<BlsPublicKey>> {
        // Explicit sort: HashMap iteration order differs between processes, and
        // the bitvector-index <-> key binding must be identical on every node
        // (matches the sort_unstable() hardening in consensus F8).
        let mut ids: Vec<_> = validators.validators.keys().collect();
        ids.sort_unstable();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(*self.registry.get(id)?);
        }
        Some(out)
    }

    /// This node's local BLS signing key, when configured.
    pub fn local_vote_key(&self) -> Option<BlsSecretKey> {
        self.local_vote_seed.as_ref().map(BlsSecretKey::from_seed)
    }
}

fn parse_registry_entries(text: &str, out: &mut BlsKeyRegistry) {
    // Entries may be newline-separated (file) or comma/semicolon-separated
    // (inline env var); inside an entry, `ed bls`, `ed:bls` and `ed=bls` all
    // separate the two keys.
    //
    // NO PROOF-OF-POSSESSION is requested or verified here (audit F-HIGH-1):
    // entries are bare `<ed25519> <bls-pubkey>` pairs. That is WHY counting
    // BLS power is hard-refused at startup by `refuse_bls_qc_if_enabled`.
    // When a PoP-carrying format lands, THIS function is where verification
    // must happen (refuse entries without a valid PoP) — not at verify time.
    for raw in text.split(|c: char| c == '\n' || c == ',' || c == ';') {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> =
            line.split(|c: char| c.is_whitespace() || c == ':' || c == '=').collect();
        if parts.len() < 2 {
            tracing::warn!(line, "bls: registry entry malformed; skipped");
            continue;
        }
        let (Ok(ed), Ok(bls)) = (hex::decode(parts[0]), hex::decode(parts[1])) else {
            tracing::warn!(line, "bls: registry entry is not hex; skipped");
            continue;
        };
        let (Ok(ed), Ok(bls)) = (<[u8; 32]>::try_from(ed), <[u8; PUBLIC_KEY_LEN]>::try_from(bls))
        else {
            tracing::warn!(line, "bls: registry entry has wrong length; skipped");
            continue;
        };
        match BlsPublicKey::from_bytes(&bls) {
            Some(pk) => {
                out.insert(ed, pk);
            }
            None => tracing::warn!(line, "bls: registry BLS key is not a valid G1 point; skipped"),
        }
    }
}

static QC_BLS: std::sync::OnceLock<std::sync::RwLock<std::sync::Arc<QcBlsConfig>>> =
    std::sync::OnceLock::new();

fn qc_bls_cell() -> &'static std::sync::RwLock<std::sync::Arc<QcBlsConfig>> {
    QC_BLS.get_or_init(|| std::sync::RwLock::new(std::sync::Arc::new(QcBlsConfig::from_env())))
}

/// Current QC-BLS configuration (env-derived on first use).
pub fn qc_bls() -> std::sync::Arc<QcBlsConfig> {
    qc_bls_cell()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Is the BLS path enabled? Gates vote-BLS attachment, certificate aggregate
/// production, and counting BLS power at verification. Default: OFF.
pub fn qc_bls_enabled() -> bool {
    qc_bls().enabled
}

/// Sign `msg` with this node's local BLS key when the QC-BLS path is enabled.
/// Returns the 96-byte signature, or `None` (no envelope) when disabled or
/// unconfigured — vote bytes are then byte-identical to the pre-BLS format.
pub fn local_vote_bls_sign(msg: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
    let cfg = qc_bls();
    if !cfg.enabled {
        return None;
    }
    Some(cfg.local_vote_key()?.sign(msg).to_bytes())
}

/// Test-only override for the process-global QC-BLS configuration.
///
/// The returned guard HOLDS a process-wide gate for its lifetime, so every
/// test that observes BLS configuration (enabled or disabled) must take it;
/// dropping the guard restores the previous configuration. Tests that never
/// touch BLS configuration are unaffected either way: the default config has
/// no registry and the flag off, and a certificate without a BLS envelope
/// never consults any of it.
#[cfg(any(test, debug_assertions))]
pub fn set_qc_bls_for_tests(cfg: QcBlsConfig) -> QcBlsGuard {
    static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let gate = GATE.lock().unwrap_or_else(|e| e.into_inner());
    let mut cell = qc_bls_cell().write().unwrap_or_else(|e| e.into_inner());
    let prev = std::mem::replace(&mut *cell, std::sync::Arc::new(cfg));
    drop(cell);
    QcBlsGuard { prev, _gate: gate }
}

/// Guard returned by [`set_qc_bls_for_tests`]; restores the previous config
/// (and releases the test gate) on drop.
#[cfg(any(test, debug_assertions))]
pub struct QcBlsGuard {
    prev: std::sync::Arc<QcBlsConfig>,
    _gate: std::sync::MutexGuard<'static, ()>,
}

#[cfg(any(test, debug_assertions))]
impl Drop for QcBlsGuard {
    fn drop(&mut self) {
        let mut cell = qc_bls_cell().write().unwrap_or_else(|e| e.into_inner());
        *cell = self.prev.clone();
    }
}

#[cfg(test)]
mod internal_tests {
    use super::*;

    fn keys(n: usize) -> Vec<BlsSecretKey> {
        (0..n).map(|_| BlsSecretKey::generate()).collect()
    }

    #[test]
    fn identity_public_key_is_rejected() {
        // The identity would make an aggregate verify for free, so it must not parse.
        let id = G1Affine::identity().to_compressed();
        assert!(BlsPublicKey::from_bytes(&id).is_none());
    }

    #[test]
    fn a_signature_is_not_a_public_key_and_vice_versa() {
        let sk = BlsSecretKey::generate();
        let sig = sk.sign(b"m");
        // 96 bytes truncated/padded into a key slot must not parse as a point.
        let mut fake_key = [0u8; PUBLIC_KEY_LEN];
        fake_key.copy_from_slice(&sig.to_bytes()[..PUBLIC_KEY_LEN]);
        assert!(BlsPublicKey::from_bytes(&fake_key).is_none());
    }

    #[test]
    fn aggregate_over_distinct_keys_is_not_the_identity() {
        let ks = keys(4);
        let mut sigs = Vec::new();
        for (i, k) in ks.iter().enumerate() {
            sigs.push((i, k.sign(b"same")));
        }
        let agg = aggregate_signatures(&sigs, 4).unwrap();
        assert!(!bool::from(sig_point(&agg.signature).unwrap().is_identity()));
        let pks: Vec<BlsPublicKey> = ks.iter().map(|k| k.public_key()).collect();
        assert!(verify_aggregate_signature(&pks, b"same", &agg));
    }

    /// AUDIT W6.5: the aggregate verifier must refuse every degenerate
    /// certificate, not only the ones the constructor rejects.
    ///
    /// `BlsAggregateSignature` has PUBLIC fields, so an attacker-supplied
    /// certificate is not necessarily one that `aggregate_signatures`
    /// produced — the verifier is the last line of defence.
    #[test]
    fn aggregate_verification_refuses_degenerate_certificates() {
        let ks = keys(4);
        let pks: Vec<BlsPublicKey> = ks.iter().map(|k| k.public_key()).collect();
        let sigs: Vec<(usize, BlsSignature)> = ks
            .iter()
            .enumerate()
            .map(|(i, k)| (i, k.sign(b"same")))
            .collect();
        let agg = aggregate_signatures(&sigs, 4).unwrap();
        assert!(verify_aggregate_signature(&pks, b"same", &agg));

        // The identity aggregate is refused.
        let mut identity = agg.clone();
        identity.signature = BlsSignature(G2Affine::identity().to_compressed());
        assert!(!verify_aggregate_signature(&pks, b"same", &identity));

        // A bitvector that does not describe THIS key list is refused (the
        // attacker must not choose the key set the aggregate is measured
        // against).
        assert!(!verify_aggregate_signature(&pks[..3], b"same", &agg));

        // A different message is refused.
        assert!(!verify_aggregate_signature(&pks, b"other", &agg));

        // An empty participant set is refused.
        let mut none = agg.clone();
        none.participants = SignerBitVector::new(4);
        assert!(!verify_aggregate_signature(&pks, b"same", &none));

        // A bitmask whose length does not match the validator count cannot
        // even be parsed.
        assert!(SignerBitVector::from_bitmask(vec![0u8; 2], 4).is_none());
        assert!(SignerBitVector::from_bitmask(vec![0u8; 1], 4).is_some());
    }
}
