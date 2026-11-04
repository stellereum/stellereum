//! VRF sortition scaffolding (A6/C1 structural fix), PHASE 1.
//!
//! # Status: types + beacon math + metering ONLY — no consensus change
//!
//! The live committee election ([`crate::consensus::derive_sortition_committee`])
//! is seeded by the parent block hash, which the parent's proposer chooses.
//! That is documented grindable (see the `RESIDUAL RISK` note on the draw
//! function): every candidate parent hash is a fresh sortition draw, so a
//! proposer can search for a favourable committee. The network-anchored quorum
//! is the current mitigation; the structural fix is a VRF lottery where each
//! validator's ticket is keyed by its OWN secret (ungrindable by anyone else).
//!
//! This module is PHASE 1 of `docs/PLAN-VRF.md`: it introduces the key record,
//! the Falcon-signed key binding (the VRF key lives alongside the validator's
//! PQ Falcon key — see the construction choice below), the beacon-chaining
//! math, the lottery-threshold math and the grinding-cost analysis — all as
//! PURE functions with tests. It is NOT wired into election, votes, blocks or
//! certificates: [`crate::consensus::derive_sortition_committee`] behaves
//! byte-identically with or without this module.
//!
//! # Construction choice: ECVRF over Edwards25519 (RFC 9381), beacon math now
//!
//! Chosen: per-validator ECVRF (RFC 9381 `ECVRF-EDWARDS25519-SHA512-Elligator2`,
//! `suite_string = 0x04`) over the Edwards25519 group, with the VRF public key
//! bound to the validator id by a Falcon-512 signature ([`VrfBinding`]).
//!
//! Why not a hash-chained beacon alone: a beacon `b_h = H(b_{h-1} || ...)`
//! whose update input the block proposer chooses is grindable by exactly the
//! same search the parent hash allows — it moves the grinding surface without
//! removing it. A VRF lottery removes it: ticket `y = VRF_sk(seed_h)` is
//! unpredictable to everyone but the key holder and unforgeable by the
//! proposer, so no amount of parent-hash search changes anyone else's ticket.
//!
//! Why Edwards25519 (classical) alongside PQ Falcon keys: there is no
//! standardized PQ VRF over Falcon lattices (a Falcon signature is
//! randomized, not verifiably pseudorandom, and proving "this output is THE
//! VRF output for this input" needs DLEQ-style proofs lattices do not give
//! us). The VRF key is therefore a SECOND, classical key — but it never
//! stands alone: [`VrfBinding`] is a Falcon-512 signature by the validator's
//! registered PQ key over `(validator_id || vrf_pk)`, i.e. the binding is
//! PQ-authenticated and rotates with the Falcon key. Compromise of the VRF
//! key alone buys bias for ONE validator's OWN ticket (selfish, visible,
//! slashable); forging someone else's ticket still needs their VRF secret.
//! A PQ-native VRF (e.g. hash-based, NIST-standardized) can replace the group
//! without changing the binding/seed/threshold layers specified here.
//!
//! RETIRED: the ECVRF prove/verify bodies (and their field/Elligator2/
//! hash-to-curve helpers, plus the `tests/vrf_ecvrf_tests.rs` vectors that
//! validated them) were removed — ECVRF-Edwards25519 is classical
//! (Shor-breakable), and this chain is FULL post-quantum. Sortition stays on
//! the canonical parent-hash draw; election math below is untouched.
//! See `docs/PLAN-VRF.md`.
//!
//! # ECVRF-EDWARDS25519 is CLASSICAL (quantum-breakable) — LEGACY/OFF-ONLY
//! # in this FULL-PQ architecture
//!
//! This chain is FULL post-quantum. ECVRF over Edwards25519 is CLASSICAL
//! crypto: a cryptographically relevant quantum computer running Shor's
//! algorithm breaks the Edwards25519 discrete-log problem, forging arbitrary
//! VRF proofs and outputs. Same class as BLS12-381 (see [`crate::bls`]:
//! never a PQ primitive, never a PQ fallback.
//!
//! PQ POLICY (stated in code so it can be enforced programmatically via
//! [`VRF_IS_POST_QUANTUM`]):
//!
//! * Sortition MUST NOT consume ECVRF output on the PQ path while this module
//!   is marked classical. The live [`crate::consensus::derive_sortition_committee`]
//!   draw stays on the parent-hash seed by default; VRF stays default-off
//!   (`VrfActivation::Disabled`), and any future activation of the VRF lottery
//!   on the PQ path requires this marker to read `true` first.
//! * Any use of ECVRF output while marked classical is therefore a NON-PQ,
//!   LEGACY-ONLY mode. It requires an explicit non-PQ opt-in whose mechanism
//!   is a LEAD DECISION — this module deliberately does NOT invent the opt-in
//!   mechanism (no new env knob, no height auto-arming, no silent
//!   fallback-to-consuming). When the lead defines it, gate it on
//!   [`VRF_IS_POST_QUANTUM`] being `false` so the non-PQ nature of the path
//!   is checked, not assumed.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};

// ============================================================================
// Domains
// ============================================================================

/// Domain tag for the beacon chain update `beacon_h = H(prev || vrf_output)`.
pub const VRF_BEACON_DOMAIN: &str = "STELL_VRF_BEACON_V1";

/// Domain tag for the legacy secret -> scalar derivation.
///
/// Retained for API/test compatibility. ECVRF key expansion follows
/// RFC 8032 §5.1.5 exactly (`SHA-512(seed)`, clamped) with no extra domain,
/// so that the RFC 9381 Appendix B test vectors reproduce byte-for-byte.
pub const VRF_SCALAR_DOMAIN: &[u8] = b"STELL_VRF_SCALAR_V1";

/// Domain tag for the Falcon-signed VRF key binding.
pub const VRF_BINDING_DST: &[u8] = b"STELL_VRF_BINDKEY_V1";

/// Domain tag for the legacy Schnorr proof hashes (nonce + challenge).
///
/// Retained for API/test compatibility. The ECVRF construction below does
/// NOT use this tag: challenge generation follows RFC 9381 §5.4.3 with the
/// suite-separated `SHA-512(suite || 0x02 || ... || 0x00)` hash.
pub const VRF_PROOF_DOMAIN: &[u8] = b"STELL_VRF_PROOF_V1";

/// Domain tag for the legacy Schnorr VRF output hash.
///
/// Retained for API/test compatibility. The ECVRF beta follows RFC 9381
/// §5.2 (`SHA-512(suite || 0x03 || cofactor*Gamma || 0x00)`, 64 bytes); the
/// `VrfProof.output` ticket is its leading 32 bytes.
pub const VRF_OUTPUT_DOMAIN: &str = "STELL_VRF_OUTPUT_V1";

/// Domain tag for the post-activation election seed
/// `seed = BLAKE3(domain || vrf_output || height || round)`.
/// Distinct from `STELL_SORTITION_V5` so a VRF seed can never collide with a
/// parent-hash seed.
pub const VRF_ELECTION_DOMAIN: &str = "STELL_SORTITION_VRF_V1";

/// Environment variable naming the VRF sortition activation height
/// (mirrors `STELL_XPC_ACTIVATION_HEIGHT`).
///
/// RETIRED (lead decision): setting it warns loudly and is ignored —
/// `vrf_activation_from_env` always returns `Disabled`. Retained so old
/// configs keep parsing without panicking.
pub const VRF_ACTIVATION_HEIGHT_ENV: &str = "STELL_VRF_ACTIVATION_HEIGHT";

/// Environment variable carrying the operator-configured VRF key registry
/// (mirrors `STELL_PEER_PQ_KEYS` in `main.rs`):
/// `validatorEdHex:vrfPubHex,...` — the validator's ed25519 id (hex of the
/// 32 consensus-identity bytes) mapped to its VRF public key (hex of the 32
/// proof-key bytes the operator collected from the validator's
/// `[vrf] VRF secret provisioned` startup line).
pub const VRF_KEYS_ENV: &str = "STELL_VRF_KEYS";

/// Domain tag for the operator-local VRF subseed derivation:
/// `vrf_seed = BLAKE3("VRF_SUBSEED_V1" || ed_seed_32)`.
pub const VRF_SUBSEED_DOMAIN: &[u8] = b"VRF_SUBSEED_V1";

/// Length of a serialised ECVRF proof (RFC 9381 §5.1, step 8):
/// `Gamma (32B) || c (16B, little-endian) || s (32B, little-endian)`.
///
/// 80 bytes, not 64: the phase-1 Schnorr envelope (`R || z`) is replaced by
/// the ECVRF envelope. Carriers (`VrfProof`, `VrfBeaconSeal`) size
/// themselves from this constant, so no call-site change is needed.
pub const VRF_PROOF_LEN: usize = 80;

/// Quantum-status marker: ECVRF-EDWARDS25519 is CLASSICAL (discrete-log over
/// Edwards25519, broken by Shor), NOT post-quantum. Pinned `false` by tests;
/// sortition MUST NOT consume ECVRF output on the PQ path while this reads
/// `false`, and any future non-PQ opt-in mechanism (a lead decision, not
/// defined here) must branch on this marker so the classical nature of the
/// path is enforced programmatically.
pub const VRF_IS_POST_QUANTUM: bool = false;

// ============================================================================
// Activation gate (XPC-activation-height pattern)
// ============================================================================

/// Height gate for VRF sortition.
///
/// `Disabled` (the default) keeps the parent-hash draw byte-identical to
/// today; `FromHeight(h)` switches the election seed to the verified VRF
/// output for heights `>= h`. Consensus-visible boundary: every node of a
/// deployment must configure the same value, like `XpcActivation`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VrfActivation {
    /// VRF sortition off — parent-hash election only.
    #[default]
    Disabled,
    /// VRF seed active for heights >= the boundary.
    FromHeight(u64),
}

impl VrfActivation {
    /// True when a block at `height` must elect via the verified VRF seed.
    pub fn is_active_at(&self, height: u64) -> bool {
        match *self {
            VrfActivation::Disabled => false,
            VrfActivation::FromHeight(h) => height >= h,
        }
    }

    /// The activation boundary height, if VRF sortition is on.
    pub fn boundary(&self) -> Option<u64> {
        match *self {
            VrfActivation::Disabled => None,
            VrfActivation::FromHeight(h) => Some(h),
        }
    }
}

/// Read the gate from the environment (mirrors `xpc_activation_from_env` in
/// `main.rs`, which this module cannot call — threading CLI plumbing is
/// phase-3 work outside this scope).
///
/// RETIRED (lead decision): the parent-hash draw is THE canonical sortition
/// mechanism and VRF arming is removed. This function ALWAYS returns
/// `Disabled`: a configured value is IGNORED (never parsed into an
/// activation) with a loud warning so stale deployments notice. Missing or
/// empty values stay `Disabled` silently; nothing here ever panics. `VrfActivation::FromHeight` is retained so old
/// configs and downstream crates keep compiling, but nothing live arms it
/// from the environment anymore.
pub fn vrf_activation_from_env() -> VrfActivation {
    let raw = std::env::var(VRF_ACTIVATION_HEIGHT_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    match raw {
        None => VrfActivation::Disabled,
        Some(v) => {
            let msg = format!(
                "[vrf] {VRF_ACTIVATION_HEIGHT_ENV}={v:?} is RETIRED and IGNORED \
                 (VRF arming removed): parent-hash draw is canonical, \
                 VRF sortition stays INACTIVE"
            );
            eprintln!("{msg}");
            tracing::warn!("{msg}");
            VrfActivation::Disabled
        }
    }
}

/// Derive this validator's VRF secret seed from its ed25519 seed.
///
/// `BLAKE3("VRF_SUBSEED_V1" || ed_seed_32)` — deterministic (the same ed seed
/// derives the same VRF key forever, across restarts, with no new secret to
/// distribute), and a DISTINCT keypair from the ed key: ed25519 derives its
/// scalar via SHA-512 over the seed while the VRF scalar goes through the
/// separate `VRF_SCALAR_DOMAIN`-tagged derivation over this subseed, so the
/// two scalars (and keypairs) never coincide. Same secrecy level as the ed
/// seed itself: derived directly from it and stored alongside it (`VrfSecret`
/// wipes on drop).
pub fn derive_vrf_secret_seed(ed_seed: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(VRF_SUBSEED_DOMAIN);
    h.update(ed_seed);
    *h.finalize().as_bytes()
}

/// Parse a `STELL_VRF_KEYS` registry value (`validatorEdHex:vrfPubHex,...`).
///
/// Entry shape mirrors the `STELL_PEER_PQ_KEYS` parse in `main.rs`
/// (comma-separated, colon-separated hex pair). Fail-closed per entry, never
/// panics: garbage entries (malformed shape, bad hex, wrong lengths, or a vrf
/// key that is not a valid non-identity curve point) are skipped with a loud
/// stderr warning and contribute nothing. Empty input ⇒ empty registry (the
/// legacy fallback everywhere).
pub fn parse_vrf_keys_config(raw: &str) -> VrfRegistry {
    let mut reg = VrfRegistry::new();
    let raw = raw.trim();
    if raw.is_empty() {
        return reg;
    }
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.split(':');
        let (ed_hex, vrf_hex) = match (parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), None) => (a.trim(), b.trim()),
            _ => {
                eprintln!(
                    "[vrf] {VRF_KEYS_ENV} entry {entry:?} malformed (want validatorEdHex:vrfPubHex): skipped"
                );
                continue;
            }
        };
        let ed_bytes = match hex::decode(ed_hex) {
            Ok(b) => b,
            Err(_) => {
                eprintln!(
                    "[vrf] {VRF_KEYS_ENV} entry {entry:?}: validator id is not hex: skipped"
                );
                continue;
            }
        };
        let vrf_bytes = match hex::decode(vrf_hex) {
            Ok(b) => b,
            Err(_) => {
                eprintln!(
                    "[vrf] {VRF_KEYS_ENV} entry {entry:?}: vrf key is not hex: skipped"
                );
                continue;
            }
        };
        let ed_id: [u8; 32] = match ed_bytes.try_into() {
            Ok(a) => a,
            Err(_) => {
                eprintln!(
                    "[vrf] {VRF_KEYS_ENV} entry {entry:?}: validator id is not 32 bytes: skipped"
                );
                continue;
            }
        };
        let vrf_pk: [u8; 32] = match vrf_bytes.try_into() {
            Ok(a) => a,
            Err(_) => {
                eprintln!(
                    "[vrf] {VRF_KEYS_ENV} entry {entry:?}: vrf key is not 32 bytes: skipped"
                );
                continue;
            }
        };
        if !reg.insert_config_key(ed_id, vrf_pk) {
            eprintln!(
                "[vrf] {VRF_KEYS_ENV} entry {entry:?}: vrf key is not a valid curve point: skipped"
            );
        }
    }
    reg
}

/// Read the VRF key registry from the environment (startup seam).
///
/// Missing/empty ⇒ empty registry (legacy fallback everywhere — the
/// default-off path). Garbage entries are skipped entry-wise (see
/// [`parse_vrf_keys_config`]), never fatal to startup.
pub fn vrf_registry_from_env() -> VrfRegistry {
    match std::env::var(VRF_KEYS_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        None => VrfRegistry::new(),
        Some(v) => parse_vrf_keys_config(&v),
    }
}

// ============================================================================
// Secret provisioning (startup seam: file > inline env > derived subseed)
// ============================================================================

/// Environment variable carrying this validator's VRF secret seed inline
/// (64-char hex, cleartext in the process environment — prefer
/// [`VRF_SECRET_FILE_ENV`]).
pub const VRF_SECRET_ENV: &str = "STELL_VRF_SECRET";

/// Environment variable naming a FILE that carries this validator's VRF
/// secret seed (hex, first line). The file MUST be owner-only (`0600`) or
/// loading fails closed for that source (see [`load_vrf_secret_from_file`]).
pub const VRF_SECRET_FILE_ENV: &str = "STELL_VRF_SECRET_FILE";

/// Parse one VRF secret seed from hex text (trims whitespace, accepts an
/// optional `0x` prefix). The input buffer is zeroized before returning
/// (mirrors `parse_faucet_seed_hex` in `rpc.rs`).
pub fn parse_vrf_secret_hex(raw: &str) -> Result<[u8; 32], String> {
    let owned = zeroize::Zeroizing::new(raw.trim().to_string());
    let hex_part: &str = owned.strip_prefix("0x").unwrap_or(owned.as_str()).trim();
    let mut bytes = zeroize::Zeroizing::new(
        hex::decode(hex_part).map_err(|e| format!("[vrf] invalid VRF secret hex: {e}"))?,
    );
    if bytes.len() != 32 {
        return Err(format!(
            "[vrf] invalid VRF secret length: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    zeroize::Zeroize::zeroize(&mut *bytes);
    Ok(seed)
}

/// Load a VRF secret seed from a file: 0600-checked (owner-only, fail-closed
/// for this source), first non-empty line, hex. File bytes are zeroized
/// after parsing (mirrors `load_faucet_seed_from_file` in `rpc.rs`).
pub fn load_vrf_secret_from_file(path: &std::path::Path) -> Result<[u8; 32], String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| {
            format!(
                "[vrf] cannot stat VRF secret file {}: {e}",
                path.display()
            )
        })?;
        if !meta.is_file() {
            return Err(format!(
                "[vrf] REFUSING: VRF secret path {} is not a file",
                path.display()
            ));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "[vrf] REFUSING: VRF secret file {} has insecure permissions 0o{:03o} \
                 (group/other must have NO access — chmod 0600 {})",
                path.display(),
                mode,
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        if !path.is_file() {
            return Err(format!(
                "[vrf] REFUSING: VRF secret path {} is not a file",
                path.display()
            ));
        }
    }
    let mut raw = zeroize::Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        format!(
            "[vrf] cannot read VRF secret file {}: {e}",
            path.display()
        )
    })?);
    let line = zeroize::Zeroizing::new(
        raw.lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("")
            .to_string(),
    );
    zeroize::Zeroize::zeroize(&mut *raw);
    if line.is_empty() {
        return Err(format!(
            "[vrf] REFUSING: VRF secret file {} is empty",
            path.display()
        ));
    }
    parse_vrf_secret_hex(&line)
        .map_err(|e| format!("{e} (in {})", path.display()))
}

/// Resolve this validator's VRF secret seed: the testable core of startup
/// provisioning (explicit inputs — reads no process environment).
///
/// Precedence (first hit wins):
/// 1. `file_env` (`STELL_VRF_SECRET_FILE` value, a path): 0600-checked file.
///    A broken file (missing / bad perms / bad hex / empty) warns LOUDLY
///    (stderr + `tracing`) and falls through — never fatal to startup.
/// 2. `inline_env` (`STELL_VRF_SECRET` value, hex): bad hex warns loudly and
///    falls through.
/// 3. `ed_seed` (the local validator ed25519 seed): derive deterministically
///    via [`derive_vrf_secret_seed`].
/// 4. `None` (remote-signer deployments hold no local seed, and no explicit
///    source was set): `None` + loud warn — the caller keeps the legacy
///    fallback (`vrf_beacon_seal_for` returns `None`, parent-hash election).
pub fn resolve_vrf_secret_seed(
    ed_seed: Option<&[u8; 32]>,
    file_env: Option<&str>,
    inline_env: Option<&str>,
) -> Option<[u8; 32]> {
    if let Some(path) = file_env.filter(|s| !s.trim().is_empty()) {
        match load_vrf_secret_from_file(std::path::Path::new(path.trim())) {
            Ok(seed) => return Some(seed),
            Err(e) => {
                eprintln!("{e} (falling through to the next VRF secret source)");
                tracing::warn!("{e} (falling through to the next VRF secret source)");
            }
        }
    }
    if let Some(hex_str) = inline_env.filter(|s| !s.trim().is_empty()) {
        match parse_vrf_secret_hex(hex_str) {
            Ok(seed) => return Some(seed),
            Err(e) => {
                eprintln!("{e} (falling through to the next VRF secret source)");
                tracing::warn!("{e} (falling through to the next VRF secret source)");
            }
        }
    }
    match ed_seed {
        Some(seed) => Some(derive_vrf_secret_seed(seed)),
        None => {
            let msg = "[vrf] no local VRF seed provisioned (remote-signer deployment \
                 with no STELL_VRF_SECRET_FILE/STELL_VRF_SECRET): VRF proofs \
                 unavailable, legacy parent-hash election on every height";
            eprintln!("{msg}");
            tracing::warn!("{msg}");
            None
        }
    }
}

/// Provision this validator's VRF secret seed from the live process
/// environment (startup seam — called once from `main.rs`).
///
/// Pass `None` for `ed_seed` on remote-signer deployments (no local seed);
/// otherwise pass the local validator ed25519 seed for the derived fallback.
/// See [`resolve_vrf_secret_seed`] for the precedence matrix.
pub fn provision_vrf_secret_seed(ed_seed: Option<&[u8; 32]>) -> Option<[u8; 32]> {
    let file_val = std::env::var(VRF_SECRET_FILE_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty());
    let mut inline_val = std::env::var(VRF_SECRET_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty());
    let out = resolve_vrf_secret_seed(ed_seed, file_val.as_deref(), inline_val.as_deref());
    // The inline hex is secret material: wipe the owned copy (the file value
    // is only a path — nothing to wipe). Parsing already wiped its buffers.
    if let Some(mut s) = inline_val.take() {
        zeroize::Zeroize::zeroize(&mut s);
    }
    out
}

/// Voting-power coverage of the VRF registry: `(registered_power,
/// total_power)` over `validators` (`(validator_id, power)` pairs).
///
/// Only registry-known keys count; zero-power entries contribute nothing.
/// Saturating: absurd totals clamp instead of wrapping.
pub fn vrf_registered_power(
    registry: &VrfRegistry,
    validators: &[([u8; 32], u64)],
) -> (u64, u64) {
    let mut total = 0u64;
    let mut registered = 0u64;
    for (id, power) in validators {
        total = total.saturating_add(*power);
        if *power > 0 && registry.get(id).is_some() {
            registered = registered.saturating_add(*power);
        }
    }
    (registered, total)
}

/// Readiness helper: true when EVERY validator with nonzero voting power has
/// a key in the registry — i.e. the VRF seed could elect the whole set.
///
/// Advisory ONLY (tests and the startup warn path query it): power without a
/// registry key stays on the legacy parent-hash draw per certificate — no
/// global height `H` is set here, and this never gates startup. Empty power
/// (no validators) reads as ready (nothing to cover).
pub fn vrf_registry_ready_for_power(
    registry: &VrfRegistry,
    validators: &[([u8; 32], u64)],
) -> bool {
    validators
        .iter()
        .all(|(id, power)| *power == 0 || registry.get(id).is_some())
}

// ============================================================================
// Keys (live alongside the validator's Falcon key)
// ============================================================================

/// A validator's VRF public key: an Edwards25519 compressed point (32 bytes,
/// RFC 8032 §5.1.2 encoding).
///
/// Registered alongside — never instead of — the validator's PQ Falcon key.
/// See [`VrfBinding`] for the authorization that ties the two together.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct VrfPublicKey(pub [u8; 32]);

impl VrfPublicKey {
    /// Parse and apply the RFC 9381 validate-key rule (§5.4.5 with
    /// `validate_key = TRUE`): the bytes must decompress to a curve point
    /// whose cofactor multiple is not the identity — i.e. identity AND every
    /// low-order point refuse. Edwards25519 (unlike Ristretto) admits
    /// low-order encodings, so parsing alone cannot exclude them.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let pt = decompress_canonical(bytes)?;
        if pt.mul_by_cofactor().is_identity() {
            return None;
        }
        Some(Self(*bytes))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A validator's VRF secret: a 32-byte seed. The secret scalar is derived
/// on demand per RFC 8032 §5.1.5 (`SHA-512(seed)`, clamped — see
/// [`ecvrf_secret_scalar`]); only the seed is stored, and it is wiped on drop.
pub struct VrfSecret([u8; 32]);

impl VrfSecret {
    /// Derive from a caller-held 32-byte seed (node config / tests).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(*seed)
    }

    // REMOVED (VRF key minting): `VrfSecret::generate` (fresh OS-random secret)
    // lived here. Zero users (proven by grep: no src/ or test callers; secrets
    // arrive via `from_seed` over provisioned seeds). No live writer removed.

    fn scalar(&self) -> Scalar {
        ecvrf_secret_scalar(&self.0)
    }

    /// The public key for this secret.
    pub fn public_key(&self) -> VrfPublicKey {
        VrfPublicKey(
            EdwardsPoint::mul_base(&self.scalar())
                .compress()
                .to_bytes(),
        )
    }
}

impl Drop for VrfSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

// ============================================================================
// Falcon-signed key binding (the VRF key's PoP-equivalent)
// ============================================================================

/// Preimage the validator's Falcon key signs to authorize a VRF key:
/// `VRF_BINDING_DST || validator_id(32) || vrf_pk(32)`.
///
/// Proves the holder of the registered PQ key authorized THIS VRF key for
/// THIS validator id — a rogue VRF key (bound to someone else's id, or
/// invented for a non-validator) cannot be registered without that validator's
/// Falcon signature. Rotates with the Falcon key by construction.
pub fn vrf_binding_preimage(validator_id: &[u8; 32], vrf_pk: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(VRF_BINDING_DST.len() + 64);
    out.extend_from_slice(VRF_BINDING_DST);
    out.extend_from_slice(validator_id);
    out.extend_from_slice(vrf_pk);
    out
}

/// Verify a VRF key binding against the validator's registered Falcon public
/// key bytes. Thin alias over the FIPS 206 path — no test shortcut.
pub fn verify_vrf_binding(
    falcon_pk: &[u8],
    validator_id: &[u8; 32],
    vrf_pk: &[u8; 32],
    falcon_sig: &[u8],
) -> bool {
    crate::post_quantum::verify_pq_signature(
        crate::post_quantum::PqScheme::Falcon512,
        falcon_pk,
        &vrf_binding_preimage(validator_id, vrf_pk),
        falcon_sig,
    )
}

/// A registered VRF key: which validator id it belongs to, the key, and the
/// Falcon-512 authorization by that validator's PQ key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfBinding {
    pub validator_id: [u8; 32],
    pub vrf_pk: [u8; 32],
    pub falcon_sig: Vec<u8>,
}

impl VrfBinding {
    /// Fail-closed: bad curve point, wrong length, or a Falcon signature that
    /// does not verify against `falcon_pk` all refuse.
    pub fn verify(&self, falcon_pk: &[u8]) -> bool {
        if self.falcon_sig.len() != crate::post_quantum::FALCON512_SIG_LEN {
            return false;
        }
        if VrfPublicKey::from_bytes(&self.vrf_pk).is_none() {
            return false;
        }
        verify_vrf_binding(
            falcon_pk,
            &self.validator_id,
            &self.vrf_pk,
            &self.falcon_sig,
        )
    }
}

/// Phase-1 registry: validator id -> VRF public key, populated ONLY through
/// [`VrfRegistry::register`] (binding verified). NOT consulted by election
/// (phase 3 wires it); present so phase-2 gossip has a verified key to check
/// proofs against, and so operators can pre-register during phase 1.
#[derive(Clone, Debug, Default)]
pub struct VrfRegistry {
    keys: BTreeMap<[u8; 32], [u8; 32]>,
}

impl VrfRegistry {
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Register a VRF key. Refuses unknown-curve keys and bindings whose
    /// Falcon signature does not verify — fail closed, never store-and-hope.
    pub fn register(&mut self, binding: &VrfBinding, falcon_pk: &[u8]) -> Result<(), String> {
        if !binding.verify(falcon_pk) {
            return Err("vrf: binding Falcon signature does not verify".to_string());
        }
        self.keys.insert(binding.validator_id, binding.vrf_pk);
        note_vrf_binding_registered();
        Ok(())
    }

    /// Insert an operator-configured key (startup `STELL_VRF_KEYS` trust).
    ///
    /// Unlike [`Self::register`], this takes no Falcon binding: the
    /// operator's own config file/env IS the trust root here (same posture as
    /// the `STELL_PEER_PQ_KEYS` peer-key map in `main.rs`). The curve point is
    /// still validated — identity and non-decompressible bytes refuse
    /// (`false`, nothing stored) — so garbage config can never mint a key the
    /// verifier would choke on.
    pub fn insert_config_key(&mut self, validator_id: [u8; 32], vrf_pk: [u8; 32]) -> bool {
        if VrfPublicKey::from_bytes(&vrf_pk).is_none() {
            return false;
        }
        self.keys.insert(validator_id, vrf_pk);
        true
    }

    pub fn get(&self, validator_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.keys.get(validator_id).copied()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ============================================================================
// ECVRF-EDWARDS25519-SHA512-Elligator2 (RFC 9381 §5.5) — RETIRED.
//
// The proving/verification bodies lived here with their field layer,
// Elligator2 maps, and hash-to-curve helpers (all removed: classical crypto,
// FULL-PQ architecture). What stays in this section: the canonical-decoding
// helper for key parsing and the RFC 8032 key-derivation helper — both still
// consumed by live code (`VrfPublicKey::from_bytes`, `VrfSecret`).
// Admission stays enforced at parse/registration time (`VrfRegistry`,
// `parse_vrf_keys_config`, `VrfBinding::verify`).

/// Edwards decompress with a canonical-encoding requirement: the bytes must
/// be the RFC 8032 compression of the point they decode to. This rejects
/// non-canonical encodings (`y >= p`, which dalek's equation check alone
/// would reduce mod p and accept) so every point has exactly one accepted
/// byte form in this system — malleability between alias encodings cannot
/// cross the parse boundary, and garbage like `[0xFF; 32]` refuses.
fn decompress_canonical(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let pt = CompressedEdwardsY(*bytes).decompress()?;
    if pt.compress().to_bytes() != *bytes {
        return None;
    }
    Some(pt)
}
// REMOVED (ECVRF hash-to-curve): the suite DST, `expand_message_xmd_48`, and
// `ecvrf_encode_to_curve` lived here — consumed only by the removed prove /
// verify bodies (proven by grep).

/// Secret scalar + public key per RFC 8032 §5.1.5: `x = clamp(SHA-512(seed))`.
/// The clamped 32 bytes are reduced mod q for dalek arithmetic — the same
/// point and the same `(k + c*x) mod q`, since `q*B = O`.
fn ecvrf_secret_scalar(seed: &[u8; 32]) -> Scalar {
    let h = Sha512::digest(seed);
    let mut x = [0u8; 32];
    x.copy_from_slice(&h[..32]);
    x[0] &= 0xF8;
    x[31] &= 0x7F;
    x[31] |= 0x40;
    Scalar::from_bytes_mod_order(x)
}

// REMOVED (ECVRF prove/verify helpers): `ecvrf_nonce`, `ecvrf_challenge`, and
// `ecvrf_proof_to_hash` lived here — consumed only by the removed
// `vrf_prove` / `vrf_verify` bodies (proven by grep). The `VrfProof` envelope
// type + serde below stay for wire compat (the `VrfBeaconSeal` carrier).

/// A VRF proof envelope: the output bound to the proof that produced it.
///
/// Carried by the caller (phase-3 gossip); the verifier MUST re-derive the
/// output from the proof bytes — a `VrfProof` whose `output` field does not
/// match its `proof` bytes is refused.
///
/// `Serialize`/`Deserialize` are implemented (manually — `serde` only
/// provides array impls up to 32 elements, while the proof is 80 bytes) so
/// phase-3 certificate seals can carry this envelope verbatim (see
/// `consensus::VrfBeaconSeal`): the proof bytes the verifier checks are
/// exactly the bytes the prover minted — no re-encoding, no field dropped.
/// This is a format change only; the prove/verify math below is untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfProof {
    pub output: [u8; 32],
    pub proof: [u8; VRF_PROOF_LEN],
}

impl serde::Serialize for VrfProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        // The VRF_PROOF_LEN proof bytes go out as an explicit sequence (positional for
        // bincode, an array for JSON): `serde` has no `[u8; 80]` impl, and a
        // `&[u8]` would serialize as opaque bytes, which JSON cannot read
        // back. A sequence round-trips through both.
        struct ProofSeq<'a>(&'a [u8; VRF_PROOF_LEN]);
        impl serde::Serialize for ProofSeq<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(VRF_PROOF_LEN))?;
                for b in self.0.iter() {
                    seq.serialize_element(b)?;
                }
                seq.end()
            }
        }
        let mut st = serializer.serialize_struct("VrfProof", 2)?;
        st.serialize_field("output", &self.output)?;
        st.serialize_field("proof", &ProofSeq(&self.proof))?;
        st.end()
    }
}

impl<'de> serde::Deserialize<'de> for VrfProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ProofVisitor;
        impl<'de> serde::de::Visitor<'de> for ProofVisitor {
            type Value = VrfProof;
            fn expecting(
                &self,
                f: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                write!(f, "a VRF proof envelope (output + 64 proof bytes)")
            }
            // Positional formats (bincode): `(output, proof-bytes…)`.
            fn visit_seq<A>(self, mut seq: A) -> Result<VrfProof, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error;
                let output: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(0, &self))?;
                let bytes: Vec<u8> = seq
                    .next_element()?
                    .ok_or_else(|| Error::invalid_length(1, &self))?;
                let proof: [u8; VRF_PROOF_LEN] = bytes
                    .try_into()
                    .map_err(|_| Error::invalid_length(VRF_PROOF_LEN, &self))?;
                Ok(VrfProof { output, proof })
            }
            // Self-describing formats (JSON): `{"output":[…],"proof":[…]}`.
            fn visit_map<A>(self, mut map: A) -> Result<VrfProof, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error;
                let mut output: Option<[u8; 32]> = None;
                let mut proof: Option<[u8; VRF_PROOF_LEN]> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "output" => output = Some(map.next_value()?),
                        "proof" => {
                            let bytes: Vec<u8> = map.next_value()?;
                            proof = Some(
                                bytes
                                    .try_into()
                                    .map_err(|_| Error::invalid_length(VRF_PROOF_LEN, &self))?,
                            );
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                let output =
                    output.ok_or_else(|| Error::missing_field("output"))?;
                let proof = proof.ok_or_else(|| Error::missing_field("proof"))?;
                Ok(VrfProof { output, proof })
            }
        }
        deserializer.deserialize_struct("VrfProof", &["output", "proof"], ProofVisitor)
    }
}

// REMOVED (ECVRF bodies): `vrf_prove`, `vrf_verify`, and
// `verify_vrf_seed_for_validator` lived here. ECVRF-Edwards25519 is classical
// (Shor-breakable) and retired from this FULL-PQ architecture: the callers
// were default-off paths, rewired to the canonical parent-hash draw or
// `Disabled` (mirroring the `vrf_canonical_draw_tests` pin). Removals are
// justified as dead: with flags off/default no live path references remain
// (proven by grep). The envelope type, registry, binding, provisioning, and
// election-math layers below are untouched.

/// Post-activation election seed:
/// `BLAKE3(domain || vrf_output || height || round)`.
///
/// Binding height+round keeps every (height, round) draw distinct even if a
/// VRF output ever repeated; `VRF_ELECTION_DOMAIN` keeps VRF seeds disjoint
/// from `STELL_SORTITION_V5` parent-hash seeds.
pub fn vrf_election_seed(vrf_output: &[u8; 32], height: u64, round: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(VRF_ELECTION_DOMAIN);
    hasher.update(vrf_output);
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// ============================================================================
// Beacon chain (seed evolution)
// ============================================================================

/// Genesis beacon for a deployment: `BLAKE3(domain || "genesis" || chain_id)`.
///
/// Phase 3 starts the VRF seed chain here; every height then chains the
/// previous beacon with that height's winning VRF output. Binding the genesis
/// to the chain id keeps testnet/mainnet seed chains disjoint from block 0.
pub fn beacon_genesis(chain_id: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(VRF_BEACON_DOMAIN);
    hasher.update(b"genesis");
    hasher.update(&chain_id.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Beacon update: `beacon_h = BLAKE3(domain || prev || vrf_output_h)`.
///
/// `vrf_output_h` is the phase-3 winning ticket's VRF output for height `h`
/// (phase 2 gossips it; phase 1 takes it as an opaque 32-byte input). Chaining
/// — rather than replacing — means a proposer who withholds their reveal
/// stalls that height instead of choosing the next seed: the seed only
/// advances on published, verified VRF outputs.
pub fn beacon_next(prev_beacon: &[u8; 32], vrf_output: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(VRF_BEACON_DOMAIN);
    hasher.update(prev_beacon);
    hasher.update(vrf_output);
    *hasher.finalize().as_bytes()
}

// ============================================================================
// Lottery threshold math (phase-3 election rule, pure)
// ============================================================================

/// Lottery threshold for a stake-weighted VRF draw over a 128-bit ticket.
///
/// A validator holding `stake` of `total_stake` is elected when its ticket
/// `y` (uniform in `[0, 2^128)`) satisfies `y < threshold`, with
/// `threshold = floor(2^128 * stake * expected_seats / total_stake)`
/// (saturating at `u128::MAX`). Expected committee size is then
/// `expected_seats` regardless of stake distribution — the same mean as the
/// current stake-weighted draw, but each ticket is keyed and ungrindable.
pub fn lottery_threshold(stake: u64, total_stake: u64, expected_seats: u64) -> u128 {
    if stake == 0 || total_stake == 0 || expected_seats == 0 {
        return 0;
    }
    let num = (stake as u128) * (expected_seats as u128);
    let frac_num = num / (total_stake as u128);
    let frac_rem = num % (total_stake as u128);
    // floor(2^128 * (frac_num + frac_rem/total)) saturating at 2^128 - 1.
    if frac_num >= 1 {
        // stake*expected >= total: threshold covers the whole range.
        return u128::MAX;
    }
    // frac_num == 0: threshold = floor(2^128 * frac_rem / total).
    if frac_rem == 0 {
        return 0;
    }
    // 2^128 * r / total without overflow: split 2^128 = 2^64 * 2^64.
    const HI: u128 = 1u128 << 64;
    let t = total_stake as u128;
    let r = frac_rem;
    let hi = (r * HI) / t; // < 2^64, exact
    let rem = (r * HI) % t;
    let lo = (rem * HI) / t;
    hi * HI + lo
}

// ============================================================================
// Grinding analysis (why phase 1 does NOT close A6/C1 — quantified)
// ============================================================================

/// Expected parent-hash draws to get ONE chosen member elected (uniform set
/// of `n` validators, committee `k`): each candidate parent is an independent
/// draw with `P = k/n`, so `E[draws] = n/k`.
///
/// At BLAKE3 speeds (~1e9 draws/s per GPU) this is seconds for any `k >= 1` —
/// the number that proves the parent hash is unknowability, not
/// unforgeability, and why phase 3 (keyed tickets) is the structural fix.
pub fn expected_draws_to_include_member(n: u64, k: u64) -> f64 {
    if k == 0 || n == 0 {
        return f64::INFINITY;
    }
    n as f64 / k as f64
}

/// Expected parent-hash draws to capture EXACTLY a chosen `s`-seat subset of
/// the committee (uniform `n`, committee `k`): `C(n,s)/C(k,s)`. Computed in
/// log-space so large sets do not overflow.
pub fn expected_draws_to_capture_seats(n: u64, k: u64, s: u64) -> f64 {
    if s > k || s > n || k > n {
        return f64::INFINITY;
    }
    if s == 0 {
        return 1.0;
    }
    let mut log_c = 0.0f64;
    for i in 0..s {
        log_c += ((n - i) as f64).ln() - ((k - i) as f64).ln();
    }
    log_c.exp()
}

// ============================================================================
// Phase-1 metering (acceptance counters; election untouched)
// ============================================================================

static VRF_BINDINGS_REGISTERED: AtomicU64 = AtomicU64::new(0);

fn note_vrf_binding_registered() {
    VRF_BINDINGS_REGISTERED.fetch_add(1, Ordering::Relaxed);
}

/// How many VRF bindings this process has verified-and-registered (phase 1).
pub fn vrf_bindings_registered() -> u64 {
    VRF_BINDINGS_REGISTERED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_keypair_derives_deterministically_and_rejects_identity() {
        let sk = VrfSecret::from_seed(&[0x42u8; 32]);
        let pk = sk.public_key();
        let sk2 = VrfSecret::from_seed(&[0x42u8; 32]);
        assert_eq!(pk, sk2.public_key(), "same seed => same key");
        let other = VrfSecret::from_seed(&[0x43u8; 32]).public_key();
        assert_ne!(pk, other, "different seed => different key");
        // Compressed point parses (non-identity with overwhelming probability).
        assert!(VrfPublicKey::from_bytes(&pk.to_bytes()).is_some());
        // Identity is refused (Edwards encoding of (0, 1)).
        let mut id_pt = [0u8; 32];
        id_pt[0] = 0x01;
        assert!(VrfPublicKey::from_bytes(&id_pt).is_none());
        // The all-zero encoding is an order-4 point: refused by validate-key.
        assert!(VrfPublicKey::from_bytes(&[0u8; 32]).is_none());
    }

    #[test]
    fn falcon_signed_binding_verifies_and_wrong_id_fails() {
        let falcon = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
        let vrf = VrfSecret::from_seed(&[0x42u8; 32]);
        let vrf_pk = vrf.public_key().to_bytes();
        let validator_id = [0x11u8; 32];
        let sig = falcon.sign(&vrf_binding_preimage(&validator_id, &vrf_pk));
        let binding = VrfBinding {
            validator_id,
            vrf_pk,
            falcon_sig: sig,
        };
        assert!(binding.verify(falcon.public_key()));
        // Wrong validator id: the Falcon signature was over another preimage.
        let mut wrong = binding.clone();
        wrong.validator_id = [0x12u8; 32];
        assert!(!wrong.verify(falcon.public_key()));
        // Wrong Falcon key: refuses.
        let other = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x78u8; 32]);
        assert!(!binding.verify(other.public_key()));
        // Truncated signature: refuses (length-pinned).
        let mut trunc = binding.clone();
        trunc
            .falcon_sig
            .truncate(crate::post_quantum::FALCON512_SIG_LEN - 1);
        assert!(!trunc.verify(falcon.public_key()));
    }

    #[test]
    fn registry_only_stores_verified_bindings() {
        let falcon = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
        let vrf = VrfSecret::from_seed(&[0x42u8; 32]);
        let vrf_pk = vrf.public_key().to_bytes();
        let validator_id = [0x11u8; 32];
        let sig = falcon.sign(&vrf_binding_preimage(&validator_id, &vrf_pk));
        let mut reg = VrfRegistry::new();
        assert!(reg
            .register(
                &VrfBinding {
                    validator_id,
                    vrf_pk,
                    falcon_sig: sig
                },
                falcon.public_key()
            )
            .is_ok());
        assert_eq!(reg.get(&validator_id), Some(vrf_pk));
        // Forged binding (signed by nobody) never stores.
        let forged = VrfBinding {
            validator_id: [0x22u8; 32],
            vrf_pk,
            falcon_sig: vec![0u8; crate::post_quantum::FALCON512_SIG_LEN],
        };
        assert!(reg.register(&forged, falcon.public_key()).is_err());
        assert!(reg.get(&[0x22u8; 32]).is_none());
    }

    #[test]
    fn beacon_chain_is_deterministic_and_chain_id_separated() {
        let g_main = beacon_genesis(5757);
        assert_eq!(g_main, beacon_genesis(5757));
        assert_ne!(
            g_main,
            beacon_genesis(5758),
            "chain ids must separate seed chains"
        );
        let out = [0xabu8; 32];
        let b1 = beacon_next(&g_main, &out);
        assert_eq!(b1, beacon_next(&g_main, &out));
        assert_ne!(
            b1,
            beacon_next(&g_main, &[0xacu8; 32]),
            "output must move the beacon"
        );
        assert_ne!(
            b1,
            beacon_next(&beacon_genesis(5758), &out),
            "prev must move the beacon"
        );
        assert_ne!(b1, g_main, "update must advance the chain");
    }

    #[test]
    fn lottery_threshold_math_is_pinned() {
        // Full stake, one expected seat: the whole ticket range.
        assert_eq!(lottery_threshold(4, 4, 1), u128::MAX);
        // Zero stake / zero total / zero seats: never elected.
        assert_eq!(lottery_threshold(0, 4, 1), 0);
        assert_eq!(lottery_threshold(1, 0, 1), 0);
        assert_eq!(lottery_threshold(1, 4, 0), 0);
        // Half the stake, one seat: half the range (exact: 2^127).
        assert_eq!(lottery_threshold(1, 2, 1), 1u128 << 127);
        // Quarter stake, four seats: the whole range (mean 1 seat).
        assert_eq!(lottery_threshold(1, 4, 4), u128::MAX);
        // Quarter stake, one seat: quarter of the range.
        assert_eq!(lottery_threshold(1, 4, 1), 1u128 << 126);
    }

    #[test]
    fn grinding_cost_proves_parent_hash_is_not_a_security_boundary() {
        // Live shape (N=4, full-set committee): one draw includes anyone.
        assert_eq!(expected_draws_to_include_member(4, 4), 1.0);
        // N=100 uniform, 64-seat committee: ~1.56 draws per target inclusion.
        let d = expected_draws_to_include_member(100, 64);
        assert!((d - 1.5625).abs() < 1e-9);
        // At 1e9 draws/s that is ~2ns: grinding one seat is free.
        assert!(
            d / 1e9 < 1e-6,
            "one-seat bias must cost microseconds, not years"
        );
        // Capturing an EXACT 33-seat slice of a 64-committee from 100
        // validators costs ~1.66e8 draws — 0.17 s on one GPU. Even the
        // "expensive end" of grinding is interactive, not prohibitive.
        let capture = expected_draws_to_capture_seats(100, 64, 33);
        assert!(capture.is_finite() && capture > 1e6 && capture < 1e12);
        assert!((capture - 165_828_638.0).abs() / capture < 1e-6);
        // Degenerate inputs fail closed, never NaN-panic.
        assert!(expected_draws_to_include_member(10, 0).is_infinite());
        assert!(expected_draws_to_capture_seats(4, 4, 5).is_infinite());
        assert_eq!(expected_draws_to_capture_seats(4, 4, 0), 1.0);
    }

    /// PLAN-VRF phase-1 boundary: the sortition election does NOT consult the
    /// VRF registry — the committee is fully determined by (parent hash,
    /// height, round, stake). Registering verified VRF keys must not move any
    /// election outcome. This pins the "planned, NOT live" status: if phase 3
    /// ever wires the lottery in, THIS test must be updated deliberately, not
    /// silently broken.
    #[test]
    fn phase1_sortition_election_ignores_vrf_registry() {
        use crate::consensus::{derive_sortition_committee, sortition_seed, ValidatorSet};
        let ids: Vec<[u8; 32]> = (1u8..=4).map(|i| [i; 32]).collect();
        let vs = ValidatorSet::from_list(ids.iter().map(|id| (*id, 10)).collect());
        let parent = [0x5Au8; 32];
        let before = derive_sortition_committee(&vs, 9, 2, 2, &parent);
        assert_eq!(before.len(), 2, "fixture must elect two of four");
        // Register a verified VRF key for every validator...
        let mut reg = VrfRegistry::new();
        for id in &ids {
            let falcon = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(id);
            let vrf_pk = VrfSecret::from_seed(id).public_key().to_bytes();
            let sig = falcon.sign(&vrf_binding_preimage(id, &vrf_pk));
            reg.register(
                &VrfBinding {
                    validator_id: *id,
                    vrf_pk,
                    falcon_sig: sig,
                },
                falcon.public_key(),
            )
            .expect("honest binding registers");
        }
        assert_eq!(reg.len(), 4);
        // ...and the election is byte-identical: VRF not consulted.
        let after = derive_sortition_committee(&vs, 9, 2, 2, &parent);
        assert_eq!(
            before, after,
            "phase 1: VRF registry contents must not move the committee"
        );
        // The parent hash is still the only entropy (grindable until phase 3).
        assert_ne!(
            sortition_seed(&parent, 9, 2),
            sortition_seed(&[0x6Bu8; 32], 9, 2),
            "a new parent must re-draw the seed"
        );
    }

    // REMOVED (ECVRF-body tests): `vrf_prove_is_deterministic_and_verifies`,
    // `vrf_verify_refuses_forgeries_fail_closed`, and
    // `vrf_registry_binding_gates_seed_minting` tested the removed prove/verify
    // bodies — deleted with the code they pinned (reported).

    #[test]
    fn vrf_activation_gate_follows_xpc_pattern() {
        assert!(!VrfActivation::Disabled.is_active_at(0));
        assert!(!VrfActivation::Disabled.is_active_at(u64::MAX));
        assert_eq!(VrfActivation::Disabled.boundary(), None);
        let a = VrfActivation::FromHeight(100);
        assert!(!a.is_active_at(99));
        assert!(a.is_active_at(100));
        assert!(a.is_active_at(101));
        assert_eq!(a.boundary(), Some(100));
        assert_eq!(VrfActivation::default(), VrfActivation::Disabled);
        // Env parsing (RETIRED): missing/empty/garbage/a height ALL read
        // `Disabled` — a configured value is ignored with a loud warning,
        // never armed, never a panic.
        let key = VRF_ACTIVATION_HEIGHT_ENV;
        let saved = std::env::var(key).ok();
        std::env::remove_var(key);
        assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
        std::env::set_var(key, "500");
        assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
        assert_eq!(vrf_activation_from_env().boundary(), None);
        std::env::set_var(key, "not-a-height");
        assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
        match saved {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn vrf_election_seed_is_deterministic_and_domain_separated() {
        let out = [0xabu8; 32];
        assert_eq!(vrf_election_seed(&out, 7, 0), vrf_election_seed(&out, 7, 0));
        assert_ne!(
            vrf_election_seed(&out, 7, 0),
            vrf_election_seed(&[0xacu8; 32], 7, 0)
        );
        assert_ne!(
            vrf_election_seed(&out, 7, 0),
            vrf_election_seed(&out, 8, 0),
            "height must move the seed"
        );
        assert_ne!(
            vrf_election_seed(&out, 7, 0),
            vrf_election_seed(&out, 7, 1),
            "round must move the seed"
        );
    }

    /// PQ-policy marker: ECVRF-EDWARDS25519 is CLASSICAL, never post-quantum.
    /// Pinned so sortition wiring must branch on `VRF_IS_POST_QUANTUM`.
    #[test]
    fn vrf_is_marked_classical_not_post_quantum() {
        // GATE: pins the classical marker at RUNTIME (black_box defeats the
        // const-fold; the test must fail loudly if the marker is flipped).
        assert!(
            !std::hint::black_box(VRF_IS_POST_QUANTUM),
            "ECVRF-Edwards25519 is Shor-breakable: the marker must stay false"
        );
    }
}
