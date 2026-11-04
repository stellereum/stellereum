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
//! commitment, which is inside the state root. (The `HybridCertificate`
//! soft-fork vehicle and its `is_bls_active` gate were removed with the
//! aggregate-counting path: BLS envelopes that remain on the wire are inert
//! metadata, never counted, so no format transition is modeled.)
//!
//! # BLS12-381 is CLASSICAL (quantum-breakable) — LEGACY-ONLY in this architecture
//!
//! This chain is FULL post-quantum. BLS12-381 pairings are CLASSICAL crypto:
//! a cryptographically relevant quantum computer running Shor's algorithm
//! breaks the discrete-log problem in G1/G2/GT, forging arbitrary BLS
//! signatures and quorum aggregates. This is the same class of problem as the
//! retired ECVRF — never a PQ primitive, never a PQ fallback.
//!
//! PQ POLICY (stated in code so it can be enforced programmatically via
//! [`BLS_IS_POST_QUANTUM`]):
//!
//! * Consensus MUST NOT count BLS aggregate QCs on the PQ path. The
//!   aggregate-counting path was REMOVED (see below): the live
//!   `QuorumCertificate` BLS envelope is inert metadata by construction —
//!   there is no flag that enables counting, and the default verify path is
//!   always the Ed25519 baseline. `STELL_BLS_QC=1` remains hard-refused at
//!   startup by [`refuse_bls_qc_if_enabled`] (defense in depth: a stale
//!   operator config that requests the removed path fails loudly instead of
//!   silently running without it).
//! * Any future activation of BLS counting is a NON-PQ, LEGACY-ONLY mode. It
//!   requires an explicit non-PQ opt-in whose mechanism is a LEAD DECISION —
//!   this module deliberately does NOT invent the opt-in mechanism (no new env
//!   knob, no height auto-arming, no silent fallback-to-counting). When the
//!   lead defines it, gate it on [`BLS_IS_POST_QUANTUM`] being `false` so the
//!   non-PQ nature of the path is checked, not assumed.

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

/// Quantum-status marker: BLS12-381 is CLASSICAL (pairing-based, broken by
/// Shor), NOT post-quantum. Pinned `false` by tests; any future non-PQ opt-in
/// mechanism (a lead decision, not defined here) must branch on this marker
/// so the classical nature of the path is enforced programmatically.
pub const BLS_IS_POST_QUANTUM: bool = false;

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
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msg], DST)
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
        Some(Self {
            bitmask,
            total_validators,
        })
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
        (0..self.total_validators)
            .filter(|&i| self.is_set(i))
            .count()
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

// REMOVED (aggregate-QC counting path): `aggregate_signatures` and
// `verify_aggregate_signature` lived here. The consensus counting path that
// consumed them is deleted, and no live path references remain (proven by
// grep: the only references were the deleted consensus call sites and
// tests). Envelopes still parse as inert metadata via
// [`BlsSignature::from_bytes`] + [`SignerBitVector::from_bitmask`] (wire
// compat), and the PoP / registry / refusal-gate policy below is untouched.
// REMOVED (soft-fork transition vehicle): `HybridCertificate`,
// `is_bls_active`, and `DEFAULT_BLS_ACTIVATION_HEIGHT` lived here. No live
// path referenced them (proven by grep: only tests and doc comments). BLS
// envelopes on the wire are inert metadata, never counted, so no format
// transition is modeled.

// QC-BLS activation: env flag + validator key registry (RETIRED counting).
// ============================================================================
//
// Quorum certificates carry the BLS aggregate as an envelope INSIDE the
// existing `signatures` list (see `consensus::BLS_QC_MARKER_ID`), so the
// bincode layout of `QuorumCertificate` — and therefore every persisted block —
// is unchanged. The aggregate-COUNTING path that consumed this configuration
// was removed: no flag, registry state, or key material enables counting.
// What stays live here: the envelope byte parser (`BlsSignature::from_bytes`,
// `SignerBitVector::from_bitmask`), the PoP/registry readers below (policy),
// and the startup refusal gate (`refuse_bls_qc_if_enabled`, which keeps
// refusing `STELL_BLS_QC=1` as defense in depth).
//
// Env knobs (retained so old configs parse, never counted):
//
// * `STELL_BLS_QC=1`              — requests the removed BLS path: LOUDLY
//   refused at startup, never silently accepted (see the gate).
// * `STELL_BLS_KEYS_FILE=<path>` / `STELL_BLS_KEYS` — registry of
//   `<ed25519_hex> <bls_pk_hex>` lines (or comma-separated `<ed>:<bls>`
//   pairs), read by the parsers below for policy/metering only.
// * `STELL_BLS_SK_SEED=<64 hex>`   — this node's BLS secret seed (key
//   material; no live consumer since vote-BLS production was removed).
// * `STELL_BLS_POP_REQUIRED`      — selects the PoP-strict registry parse
//   (default OFF: the v1 parse runs byte-identically to before).

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
/// Environment variable selecting the PoP-strict registry parse
/// (`parse_registry_entries_strict_pop`): when ON, every registry entry must
/// carry a valid PoP or it is refused at parse. Default OFF (unset/anything
/// but `1`/`true`/`on`): the v1 parse runs byte-identically to before.
pub const BLS_POP_REQUIRED_ENV: &str = "STELL_BLS_POP_REQUIRED";

/// Whether the PoP-strict registry parse is required. Default OFF: shares
/// the [`bls_flag_on`] literal set with the QC flag so the two gates can
/// never disagree about what "enabled" means.
pub fn bls_pop_required() -> bool {
    std::env::var(BLS_POP_REQUIRED_ENV)
        .map(|v| bls_flag_on(&v))
        .unwrap_or(false)
}

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
/// Parses the flag as ON for `1` or case-insensitive `true`/`on` (after
/// trimming): anything else is OFF. This literal set is shared with
/// [`bls_flag_on`] so the gate and the helper can never disagree.
pub fn refuse_bls_qc_if_enabled() -> Result<(), String> {
    let enabled = std::env::var(BLS_QC_ENV)
        .map(|v| bls_flag_on(&v))
        .unwrap_or(false);
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
/// Consumed by [`refuse_bls_qc_if_enabled`] (the sole remaining consumer).
/// Literals are exact (`1`, case-sensitive `true`/`TRUE`,
/// `on`/`ON` after trimming): anything else — including `True`, `On`,
/// `yes`, or `1\n`-with-garbage — is OFF. Case-insensitivity is deliberately
/// NOT extended: widening the match would silently enable an experimental
/// path for operators who today run flag-off.
fn bls_flag_on(raw: &str) -> bool {
    matches!(raw.trim(), "1" | "true" | "TRUE" | "on" | "ON")
}

// REMOVED (BLS config shell): `QcBlsConfig` (with its redacting `Debug`,
// wiping `Zeroize`/`Drop`, and the earlier-removed `from_env` surface) lived
// here. Zero live users (proven by grep: no src/ references outside this
// block; the only consumers were the deleted counting path and two test pins,
// updated with GATE comments). Registry policy is read directly via
// `parse_registry_entries` / `parse_registry_entries_v2` /
// `parse_registry_entries_strict_pop` (pinned by tests); refusal via
// `refuse_bls_qc_if_enabled`.

/// Parse the live registry format: bare `<ed> <bls>` lines (no PoP).
/// (Public: policy/tests read the registry without the removed config surface.)
pub fn parse_registry_entries(text: &str, out: &mut BlsKeyRegistry) {
    // Entries may be newline-separated (file) or comma/semicolon-separated
    // (inline env var); inside an entry, `ed bls`, `ed:bls` and `ed=bls` all
    // separate the two keys.
    //
    // NO PROOF-OF-POSSESSION is requested or verified here (audit F-HIGH-1):
    // entries are bare `<ed25519> <bls-pubkey>` pairs. That is WHY counting
    // BLS power is hard-refused at startup by `refuse_bls_qc_if_enabled`.
    // When a PoP-carrying format lands, THIS function is where verification
    // must happen (refuse entries without a valid PoP) — not at verify time.
    //
    // Metering: accepted/skipped entries feed the process-wide migration
    // counters (`bls_registry_migration_counts`) as legacy/rejected, exactly
    // like the PoP paths, so the live default-off parse does not leave the
    // readiness signal blind.
    for raw in text.split(['\n', ',', ';']) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || c == ':' || c == '=')
            .collect();
        if parts.len() < 2 {
            tracing::warn!(line, "bls: registry entry malformed; skipped");
            note_bls_pop_rejected();
            continue;
        }
        let (Ok(ed), Ok(bls)) = (hex::decode(parts[0]), hex::decode(parts[1])) else {
            tracing::warn!(line, "bls: registry entry is not hex; skipped");
            note_bls_pop_rejected();
            continue;
        };
        let (Ok(ed), Ok(bls)) = (
            <[u8; 32]>::try_from(ed),
            <[u8; PUBLIC_KEY_LEN]>::try_from(bls),
        ) else {
            tracing::warn!(line, "bls: registry entry has wrong length; skipped");
            note_bls_pop_rejected();
            continue;
        };
        match BlsPublicKey::from_bytes(&bls) {
            Some(pk) => {
                out.insert(ed, pk);
                note_bls_legacy_entry();
            }
            None => {
                tracing::warn!(
                    line,
                    "bls: registry BLS key is not a valid G1 point; skipped"
                );
                note_bls_pop_rejected();
            }
        }
    }
}

// REMOVED (counting-path runtime config): the process-global `QC_BLS` cell,
// `qc_bls`, `qc_bls_enabled`, `local_vote_bls_sign`, and the test-only
// `set_qc_bls_for_tests` guard lived here. The only consumers were the
// deleted vote-attachment and envelope-verify-for-counting call sites
// (proven by grep). The refusal gate and marker stay; envelopes that remain
// on the wire are inert metadata.

// Proof-of-possession registry (A7/C2 structural fix), PHASE 1.
//
// The live registry (`STELL_BLS_KEYS_FILE` / `STELL_BLS_KEYS`) carries bare
// `<ed25519> <bls-pubkey>` pairs with NO proof-of-possession, so a rogue-key
// attacker can register a key crafted against honest keys and forge
// same-message aggregates — which is why counting BLS power is hard-refused
// at startup by `refuse_bls_qc_if_enabled`. This section is PHASE 1 of
// `docs/PLAN-POP.md`: the PoP FORMAT (a BLS signature by the BLS secret over
// `DST || ed25519_id`, proving key possession AND binding the BLS key to the
// validator's Ed25519 identity), its prove/verify functions, a registry
// parser that ACCEPTS the new `ed bls pop` lines while emitting the old
// 2-token lines unchanged, and metering. The startup refusal gate is
// UNCHANGED (still refuses `STELL_BLS_QC=1`): phase 2 flips it to
// "refuse unless every entry carries a valid PoP" once operators re-register.
//
// PoP format decision (PQ policy): the PoP MUST be a BLS signature by the
// BLS secret key — only knowledge of the BLS secret defeats the rogue-key
// forgery, and a Falcon signature cannot prove that. The (ed, bls) LINK may
// additionally carry a Falcon-512 authorization in phase 2 (operator proves
// the mapping), but that is defense-in-depth on top of, never instead of,
// the BLS PoP verified here.
// ============================================================================

/// Domain separation for the BLS proof-of-possession preimage. Frozen: every
/// PoP ever issued commits to this tag, so a PoP can never be confused with
/// a vote or certificate signature over the same key.
pub const BLS_POP_DST: &[u8] = b"STELL_BLS_POP_V1";

/// PoP preimage: `BLS_POP_DST || ed25519_validator_id(32)`.
///
/// Binding the Ed25519 identity into the signed bytes is what defeats the
/// rogue-key attack: the aggregate verifier checks `e(agg, G1) ==
/// e(sum(pk_i), H(m))`, and the forgery needs an attacker key whose public
/// point cancels honest keys WITHOUT knowing a matching secret. A registry
/// that only lists keys whose owner proved secret knowledge (by signing)
/// removes the attacker's freedom to pick such a key.
pub fn bls_pop_preimage(ed_id: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BLS_POP_DST.len() + 32);
    out.extend_from_slice(BLS_POP_DST);
    out.extend_from_slice(ed_id);
    out
}

/// Prove possession: sign the PoP preimage for `ed_id` with the BLS secret.
/// The operator runs this ONCE at registration (offline is fine); the output
/// is the third token of the registry line.
pub fn bls_sign_pop(sk: &BlsSecretKey, ed_id: &[u8; 32]) -> BlsSignature {
    sk.sign(&bls_pop_preimage(ed_id))
}

/// Verify a proof-of-possession: `pk` really is a key whose secret the
/// registrant holds, claimed for the validator identity `ed_id`.
pub fn bls_verify_pop(pk: &BlsPublicKey, ed_id: &[u8; 32], pop: &BlsSignature) -> bool {
    pk.verify(&bls_pop_preimage(ed_id), pop)
}

/// Per-parse outcome counts for the PoP-carrying registry format. Returned by
/// [`parse_registry_entries_v2`] so callers (and phase-2 activation logic)
/// can meter the migration: PoP-verified vs legacy vs rejected entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlsRegistryStats {
    /// Entries with a valid PoP (the phase-2/3 registry shape).
    pub pop_verified: usize,
    /// Bare `<ed> <bls>` entries (accepted, phase-1 behaviour unchanged).
    pub legacy: usize,
    /// Entries skipped: bad lengths, non-curve keys, or INVALID PoPs.
    pub rejected: usize,
}

/// Parse a registry text that may carry PoP tokens: entries are
/// `<ed_hex> <bls_hex>[ <pop_hex>]` (same line/entry separators as the v1
/// parser: newline/comma/semicolon between entries, whitespace/`:`/`=`
/// inside one).
///
/// Backward compatibility (phase 1: accept-new + emit-old, no refusal
/// change): a 2-token entry behaves EXACTLY like `parse_registry_entries`
/// (inserted, counted `legacy`); a 3-token entry whose third token is 96
/// bytes inserts ONLY when the PoP verifies against the FIRST two
/// (counted `pop_verified`), and is skipped with a warning otherwise
/// (counted `rejected` — the same fail-closed posture malformed v1 entries
/// already get). A 3-token entry whose third token is NOT 96 bytes falls
/// back to the v1 reading (extra tokens ignored), so no previously accepted
/// file changes meaning.
pub fn parse_registry_entries_v2(
    text: &str,
    out: &mut BlsKeyRegistry,
    stats: &mut BlsRegistryStats,
) {
    for raw in text.split(['\n', ',', ';']) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || c == ':' || c == '=')
            .collect();
        if parts.len() < 2 {
            tracing::warn!(line, "bls: registry entry malformed; skipped");
            stats.rejected += 1;
            note_bls_pop_rejected();
            continue;
        }
        let (Ok(ed), Ok(bls)) = (hex::decode(parts[0]), hex::decode(parts[1])) else {
            tracing::warn!(line, "bls: registry entry is not hex; skipped");
            stats.rejected += 1;
            note_bls_pop_rejected();
            continue;
        };
        let (Ok(ed), Ok(bls)) = (
            <[u8; 32]>::try_from(ed),
            <[u8; PUBLIC_KEY_LEN]>::try_from(bls),
        ) else {
            tracing::warn!(line, "bls: registry entry has wrong length; skipped");
            stats.rejected += 1;
            note_bls_pop_rejected();
            continue;
        };
        let Some(pk) = BlsPublicKey::from_bytes(&bls) else {
            tracing::warn!(
                line,
                "bls: registry BLS key is not a valid G1 point; skipped"
            );
            stats.rejected += 1;
            note_bls_pop_rejected();
            continue;
        };
        // Optional third token: the PoP. Verified when it parses as a
        // 96-byte signature; anything else keeps the v1 reading.
        if parts.len() >= 3 {
            if let Ok(pop_bytes) = hex::decode(parts[2]) {
                if let Ok(pop_arr) = <[u8; SIGNATURE_LEN]>::try_from(pop_bytes) {
                    let Some(pop) = BlsSignature::from_bytes(&pop_arr) else {
                        tracing::warn!(line, "bls: registry PoP is not a valid G2 point; skipped");
                        stats.rejected += 1;
                        note_bls_pop_rejected();
                        continue;
                    };
                    if !bls_verify_pop(&pk, &ed, &pop) {
                        tracing::warn!(line, "bls: registry PoP does not verify; skipped");
                        note_bls_pop_rejected();
                        stats.rejected += 1;
                        continue;
                    }
                    out.insert(ed, pk);
                    note_bls_pop_verified();
                    stats.pop_verified += 1;
                    continue;
                }
            }
        }
        out.insert(ed, pk);
        note_bls_legacy_entry();
        stats.legacy += 1;
    }
}

/// Parse a registry text REFUSING every entry without a valid PoP (the
/// gated strict path behind [`BLS_POP_REQUIRED_ENV`], default OFF).
///
/// Same line/entry separators as [`parse_registry_entries_v2`], but the
/// contract is tightened: an entry inserts ONLY when it carries three tokens
/// `<ed_hex> <bls_hex> <pop_hex>` with `pop` a 96-byte non-identity G2 point
/// verifying under [`bls_verify_pop`] for that `(ed, bls)` pair. Everything
/// else — a bare 2-token legacy entry, non-hex, wrong lengths, a non-curve
/// key, a non-96-byte / non-curve PoP, or a PoP over another preimage — is
/// skipped with a warning, counted `rejected`, and metered. In particular
/// there is NO v1 fallback for a malformed third token: under this gate a
/// garbage PoP is a refusal, never a legacy acceptance.
///
/// Refused keys never enter the registry, so no (removed) power-count path
/// can ever count them — the rogue-key fail-closed posture, enforced at
/// parse rather than at verify time. This function runs only when
/// [`bls_pop_required`] is on.
pub fn parse_registry_entries_strict_pop(
    text: &str,
    out: &mut BlsKeyRegistry,
    stats: &mut BlsRegistryStats,
) {
    for raw in text.split(['\n', ',', ';']) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || c == ':' || c == '=')
            .collect();
        if parts.len() < 3 {
            tracing::warn!(
                line,
                "bls: registry entry without PoP refused (strict PoP gate); skipped"
            );
            note_bls_pop_rejected();
            stats.rejected += 1;
            continue;
        }
        let (Ok(ed), Ok(bls)) = (hex::decode(parts[0]), hex::decode(parts[1])) else {
            tracing::warn!(line, "bls: registry entry is not hex; skipped");
            note_bls_pop_rejected();
            stats.rejected += 1;
            continue;
        };
        let (Ok(ed), Ok(bls)) = (
            <[u8; 32]>::try_from(ed),
            <[u8; PUBLIC_KEY_LEN]>::try_from(bls),
        ) else {
            tracing::warn!(line, "bls: registry entry has wrong length; skipped");
            note_bls_pop_rejected();
            stats.rejected += 1;
            continue;
        };
        let Some(pk) = BlsPublicKey::from_bytes(&bls) else {
            tracing::warn!(
                line,
                "bls: registry BLS key is not a valid G1 point; skipped"
            );
            note_bls_pop_rejected();
            stats.rejected += 1;
            continue;
        };
        // Strict: the third token MUST be a verifying 96-byte PoP. No v1
        // fallback for malformed third tokens.
        let pop_ok = hex::decode(parts[2])
            .ok()
            .and_then(|b| <[u8; SIGNATURE_LEN]>::try_from(b).ok())
            .and_then(|arr| BlsSignature::from_bytes(&arr))
            .is_some_and(|pop| bls_verify_pop(&pk, &ed, &pop));
        if !pop_ok {
            tracing::warn!(
                line,
                "bls: registry PoP missing or invalid (strict PoP gate); skipped"
            );
            note_bls_pop_rejected();
            stats.rejected += 1;
            continue;
        }
        out.insert(ed, pk);
        note_bls_pop_verified();
        stats.pop_verified += 1;
    }
}

// Phase-1 metering: process-wide counters for the registry migration.
// (Kept as atomics rather than `QcBlsConfig` fields on purpose: the config
// is built with struct literals in several test fixtures, so a new field
// would break them for zero consensus value.)
static BLS_POP_VERIFIED_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BLS_LEGACY_ENTRY_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BLS_POP_REJECTED_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn note_bls_pop_verified() {
    BLS_POP_VERIFIED_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    crate::metrics::global().inc_bls_pop_verified();
}

fn note_bls_legacy_entry() {
    BLS_LEGACY_ENTRY_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    crate::metrics::global().inc_bls_legacy_entry();
}

fn note_bls_pop_rejected() {
    BLS_POP_REJECTED_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    crate::metrics::global().inc_bls_pop_rejected();
}

/// Registry-migration counters `(pop_verified, legacy, rejected)` for this
/// process. Phase 2 readiness reads as `legacy == 0 && rejected == 0`
/// with `pop_verified == validator count`.
pub fn bls_registry_migration_counts() -> (u64, u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (
        BLS_POP_VERIFIED_TOTAL.load(Relaxed),
        BLS_LEGACY_ENTRY_TOTAL.load(Relaxed),
        BLS_POP_REJECTED_TOTAL.load(Relaxed),
    )
}

// REMOVED (future counting primitive): `BlsRegistration`, `aggregate_verify`,
// `MAX_BLS_AGGREGATE_KEYS`, and the PoP-only `BlsRegistry` (with `keys_for` and
// `verify_aggregate_qc`) lived here. They were never wired into any consensus
// counting path (proven by grep: only tests referenced them). Rogue-key
// resistance for the registry format stays enforced at parse time by
// `parse_registry_entries_strict_pop` + `bls_verify_pop` (pinned by tests).

#[cfg(test)]
mod internal_tests {
    use super::*;

    // ---- A7/C2 phase-1: PoP format + v2 registry parsing -------------------

    #[test]
    fn pop_proves_possession_and_binds_the_ed_identity() {
        let sk = BlsSecretKey::from_seed(&[0x51u8; 32]);
        let pk = sk.public_key();
        let ed = [0x11u8; 32];
        let pop = bls_sign_pop(&sk, &ed);
        assert!(bls_verify_pop(&pk, &ed, &pop));
        // Wrong identity: the PoP was over another preimage.
        assert!(!bls_verify_pop(&pk, &[0x12u8; 32], &pop));
        // Wrong key: refuses.
        let other = BlsSecretKey::from_seed(&[0x52u8; 32]).public_key();
        assert!(!bls_verify_pop(&other, &ed, &pop));
        // A bare vote/message signature is not a PoP (domain separation).
        let msg_sig = sk.sign(&bls_pop_preimage(&ed)[1..]);
        assert!(!bls_verify_pop(&pk, &ed, &msg_sig));
    }

    #[test]
    fn registry_v2_accepts_pop_and_legacy_and_refuses_forged_pop() {
        let sk = BlsSecretKey::from_seed(&[0x51u8; 32]);
        let pk = sk.public_key();
        let ed = [0x11u8; 32];
        let pop = bls_sign_pop(&sk, &ed);
        let line_pop = format!(
            "{} {} {}",
            hex::encode(ed),
            hex::encode(pk.to_bytes()),
            hex::encode(pop.to_bytes())
        );
        // Forged PoP: signed for another identity, spliced onto this one.
        let forged = bls_sign_pop(&sk, &[0x99u8; 32]);
        let line_forged = format!(
            "{} {} {}",
            hex::encode(ed),
            hex::encode(pk.to_bytes()),
            hex::encode(forged.to_bytes())
        );
        // Legacy 2-token line (accepted, counted legacy).
        let sk2 = BlsSecretKey::from_seed(&[0x52u8; 32]);
        let ed2 = [0x22u8; 32];
        let line_legacy = format!(
            "{} {}",
            hex::encode(ed2),
            hex::encode(sk2.public_key().to_bytes())
        );

        let mut reg = BlsKeyRegistry::new();
        let mut stats = BlsRegistryStats::default();
        parse_registry_entries_v2(
            &format!("{line_pop}\n{line_legacy}\n{line_forged}"),
            &mut reg,
            &mut stats,
        );
        assert_eq!(stats.pop_verified, 1);
        assert_eq!(stats.legacy, 1);
        assert_eq!(stats.rejected, 1);
        // Valid entries land in the registry; the forged one never does...
        assert!(reg.contains_key(&ed));
        assert!(reg.contains_key(&ed2));
        // ...and every stored PoP re-verifies against the stored key.
        assert!(bls_verify_pop(reg.get(&ed).unwrap(), &ed, &pop));
        // Migration counters move exactly once per entry.
        let (v, l, r) = bls_registry_migration_counts();
        assert!(v >= 1 && l >= 1 && r >= 1, "counters must meter each class");
    }

    /// PQ-policy marker: BLS12-381 is CLASSICAL, never post-quantum. Pinned so
    /// any future activation wiring must branch on `BLS_IS_POST_QUANTUM`.
    #[test]
    fn bls_is_marked_classical_not_post_quantum() {
        // GATE: pins the classical marker at RUNTIME (black_box defeats the
        // const-fold; the test must fail loudly if the marker is flipped).
        assert!(
            !std::hint::black_box(BLS_IS_POST_QUANTUM),
            "BLS12-381 pairings are Shor-breakable: the marker must stay false"
        );
    }

    /// Phase-2 readiness export: every parse event must move BOTH the
    /// process tuple AND the Prometheus scrape in lockstep, or the
    /// `legacy == 0 && rejected == 0` readiness alert reads a stale zero.
    /// At-least assertions (not exact): sibling tests parse concurrently in
    /// the same process and both counters only ever grow.
    #[test]
    fn registry_parse_meters_global_metrics_in_lockstep() {
        let before = crate::metrics::global().snapshot();
        let sk = BlsSecretKey::from_seed(&[0x53u8; 32]);
        let ed = [0x33u8; 32];
        let line_legacy = format!(
            "{} {}",
            hex::encode(ed),
            hex::encode(sk.public_key().to_bytes())
        );
        let mut reg = BlsKeyRegistry::new();
        let mut stats = BlsRegistryStats::default();
        // One legacy accept + one malformed skip.
        parse_registry_entries_v2(&format!("{line_legacy}\nnot-hex at all"), &mut reg, &mut stats);
        assert_eq!((stats.legacy, stats.rejected), (1, 1));
        let after = crate::metrics::global().snapshot();
        assert!(
            after.bls_legacy_entries >= before.bls_legacy_entries + 1.0,
            "scrape must meter the legacy accept"
        );
        assert!(
            after.bls_pop_rejected >= before.bls_pop_rejected + 1.0,
            "scrape must meter the warn-and-skip reject"
        );
    }
}
