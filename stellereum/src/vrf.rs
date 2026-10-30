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
//! # Construction choice: ECVRF over Ristretto255 (phases 2–3), beacon math now
//!
//! Chosen: per-validator ECVRF (RFC 9381 `ECVRF-EDWARDS25519-SHA512-Elligator2`
//! family) over the Ristretto255 group, with the VRF public key bound to the
//! validator id by a Falcon-512 signature ([`VrfBinding`]).
//!
//! Why not a hash-chained beacon alone: a beacon `b_h = H(b_{h-1} || ...)`
//! whose update input the block proposer chooses is grindable by exactly the
//! same search the parent hash allows — it moves the grinding surface without
//! removing it. A VRF lottery removes it: ticket `y = VRF_sk(seed_h)` is
//! unpredictable to everyone but the key holder and unforgeable by the
//! proposer, so no amount of parent-hash search changes anyone else's ticket.
//!
//! Why Ristretto (classical) alongside PQ Falcon keys: there is no
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
//! Phase 2 implements prove/verify against an audited ECVRF crate (NOT
//! hand-rolled here — hand-rolling DLEQ/Elligator2 in one change is exactly
//! the unsafe shortcut this plan refuses) and gossips proofs beside votes;
//! phase 3 switches election to the lottery. See `docs/PLAN-VRF.md`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};

// ============================================================================
// Domains
// ============================================================================

/// Domain tag for the beacon chain update `beacon_h = H(prev || vrf_output)`.
pub const VRF_BEACON_DOMAIN: &str = "STELL_VRF_BEACON_V1";

/// Domain tag for the VRF secret -> scalar derivation.
pub const VRF_SCALAR_DOMAIN: &[u8] = b"STELL_VRF_SCALAR_V1";

/// Domain tag for the Falcon-signed VRF key binding.
pub const VRF_BINDING_DST: &[u8] = b"STELL_VRF_BINDKEY_V1";

/// Domain tag for the Schnorr-derived VRF proof hashes (nonce + challenge).
pub const VRF_PROOF_DOMAIN: &[u8] = b"STELL_VRF_PROOF_V1";

/// Domain tag for the VRF output hash `output = BLAKE3(domain || R || pk || seed)`.
pub const VRF_OUTPUT_DOMAIN: &str = "STELL_VRF_OUTPUT_V1";

/// Domain tag for the post-activation election seed
/// `seed = BLAKE3(domain || vrf_output || height || round)`.
/// Distinct from `STELL_SORTITION_V5` so a VRF seed can never collide with a
/// parent-hash seed.
pub const VRF_ELECTION_DOMAIN: &str = "STELL_SORTITION_VRF_V1";

/// Environment variable naming the VRF sortition activation height
/// (mirrors `STELL_XPC_ACTIVATION_HEIGHT`).
pub const VRF_ACTIVATION_HEIGHT_ENV: &str = "STELL_VRF_ACTIVATION_HEIGHT";

/// Length of a serialised VRF proof: `R (32B) || z (32B)`.
pub const VRF_PROOF_LEN: usize = 64;

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
/// phase-3 work outside this scope). Missing or unparsable ⇒ `Disabled`.
pub fn vrf_activation_from_env() -> VrfActivation {
    let raw = std::env::var(VRF_ACTIVATION_HEIGHT_ENV)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    match raw {
        None => VrfActivation::Disabled,
        Some(v) => match v.parse::<u64>() {
            Ok(h) => VrfActivation::FromHeight(h),
            Err(_) => {
                eprintln!(
                    "[vrf] {VRF_ACTIVATION_HEIGHT_ENV}={v:?} is not a height: \
                     VRF sortition stays INACTIVE"
                );
                VrfActivation::Disabled
            }
        },
    }
}

// ============================================================================
// Keys (live alongside the validator's Falcon key)
// ============================================================================

/// A validator's VRF public key: a compressed Ristretto255 point (32 bytes).
///
/// Registered alongside — never instead of — the validator's PQ Falcon key.
/// See [`VrfBinding`] for the authorization that ties the two together.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct VrfPublicKey(pub [u8; 32]);

impl VrfPublicKey {
    /// Parse and reject the identity point (it would make every ticket zero).
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let pt = curve25519_dalek::ristretto::CompressedRistretto(*bytes).decompress()?;
        if pt.is_identity() {
            return None;
        }
        Some(Self(*bytes))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A validator's VRF secret: a 32-byte seed. The Ristretto scalar is derived
/// on demand (`SHA-512(seed || domain)` reduced wide — uniform over the
/// scalar field); only the seed is stored, and it is wiped on drop.
pub struct VrfSecret([u8; 32]);

impl VrfSecret {
    /// Derive from a caller-held 32-byte seed (node config / tests).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(*seed)
    }

    /// Fresh random secret from the OS.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self(seed)
    }

    fn scalar(&self) -> Scalar {
        let mut h = Sha512::new();
        h.update(VRF_SCALAR_DOMAIN);
        h.update(self.0);
        let digest = h.finalize();
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&digest[..32]);
        let mut h2 = Sha512::new();
        h2.update(VRF_SCALAR_DOMAIN);
        h2.update(b"hi");
        h2.update(self.0);
        let d2 = h2.finalize();
        wide[32..].copy_from_slice(&d2[..32]);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    /// The public key for this secret.
    pub fn public_key(&self) -> VrfPublicKey {
        VrfPublicKey(
            RistrettoPoint::mul_base(&self.scalar())
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
// Phase-1 wiring VRF: deterministic Schnorr-derived prove/verify
// ============================================================================
//
// SECURITY SCOPE (read before auditing): this is a deterministic Schnorr
// signature over the seed input used AS a VRF
// (`output = BLAKE3(R || pk || seed)`, proof = `(R, z)`), NOT an audited
// RFC 9381 ECVRF. It gives exactly what the height-gated wiring needs —
// unforgeability without the signer's secret, determinism across nodes
// (derived nonce, no wall clock, no OS randomness in the election path),
// and verification against the Falcon-bound registry key — but it has NOT
// had ECVRF review (ciphersuite separation, hash-to-curve,
// batch-verification rules). Phase 2 replaces the `vrf_prove`/`vrf_verify`
// bodies with an audited ECVRF crate behind these SAME signatures; the
// activation gate, registry binding and election-seed layers are unchanged
// by that swap.

/// A VRF proof envelope: the output bound to the proof that produced it.
///
/// Carried by the caller (phase-3 gossip); the verifier MUST re-derive the
/// output from the proof bytes — a `VrfProof` whose `output` field does not
/// match its `proof` bytes is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfProof {
    pub output: [u8; 32],
    pub proof: [u8; VRF_PROOF_LEN],
}

fn vrf_scalar(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    h.update(VRF_PROOF_DOMAIN);
    for p in parts {
        h.update(p);
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&digest[..32]);
    let mut h2 = Sha512::new();
    h2.update(VRF_PROOF_DOMAIN);
    h2.update(b"wide-hi");
    for p in parts {
        h2.update(p);
    }
    let digest2 = h2.finalize();
    wide[32..].copy_from_slice(&digest2[..32]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn vrf_output_bytes(
    r_bytes: &[u8; 32],
    pk_bytes: &[u8; 32],
    seed_input: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(VRF_OUTPUT_DOMAIN);
    hasher.update(r_bytes);
    hasher.update(pk_bytes);
    hasher.update(seed_input);
    *hasher.finalize().as_bytes()
}

/// Prove: deterministically derive `(output, proof)` for `seed_input`.
///
/// Pure: same secret + same seed ⇒ same bytes on every node (the nonce is
/// derived from the secret seed and the input, never OS randomness).
pub fn vrf_prove(secret: &VrfSecret, seed_input: &[u8; 32]) -> VrfProof {
    let s = secret.scalar();
    let pk = secret.public_key().to_bytes();
    let k = vrf_scalar(&[b"nonce", &secret.0, seed_input]);
    let r_bytes = RistrettoPoint::mul_base(&k).compress().to_bytes();
    let c = vrf_scalar(&[b"challenge", &r_bytes, &pk, seed_input]);
    let z = k + c * s;
    let mut proof = [0u8; VRF_PROOF_LEN];
    proof[..32].copy_from_slice(&r_bytes);
    proof[32..].copy_from_slice(&z.to_bytes());
    let output = vrf_output_bytes(&r_bytes, &pk, seed_input);
    VrfProof { output, proof }
}

/// Verify a proof against the RAW registered VRF public key bytes.
///
/// Returns the verified output on success, `None` (fail-closed, no panic) on
/// any failure: bad curve point, identity key, non-canonical `z`, Schnorr
/// equation miss, or an `output` field that does not match the proof bytes.
pub fn vrf_verify(
    vrf_pk: &[u8; 32],
    seed_input: &[u8; 32],
    proof: &VrfProof,
) -> Option<[u8; 32]> {
    let pk_point =
        curve25519_dalek::ristretto::CompressedRistretto(*vrf_pk).decompress()?;
    if pk_point.is_identity() {
        return None;
    }
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&proof.proof[..32]);
    let mut z_bytes = [0u8; 32];
    z_bytes.copy_from_slice(&proof.proof[32..]);
    let r_point =
        curve25519_dalek::ristretto::CompressedRistretto(r_bytes).decompress()?;
    let z: Scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(z_bytes))?;
    let pk_bytes = pk_point.compress().to_bytes();
    let c = vrf_scalar(&[b"challenge", &r_bytes, &pk_bytes, seed_input]);
    let c_p = pk_point * c;
    if RistrettoPoint::mul_base(&z) != r_point + c_p {
        return None;
    }
    let expected = vrf_output_bytes(&r_bytes, &pk_bytes, seed_input);
    if expected != proof.output {
        return None;
    }
    Some(expected)
}

/// Verify a VRF proof against the REGISTRY-bound key for `validator_id`.
///
/// The two refusals that make this "registry-bound": unknown validator
/// (never registered) ⇒ `None`; registered-but-bad proof ⇒ `None`. Only a
/// proof that verifies under the Falcon-authorized key mints a `Some(output)`,
/// and only that `Some` may feed the post-activation election seed.
pub fn verify_vrf_seed_for_validator(
    registry: &VrfRegistry,
    validator_id: &[u8; 32],
    seed_input: &[u8; 32],
    proof: &VrfProof,
) -> Option<[u8; 32]> {
    let vrf_pk = registry.get(validator_id)?;
    vrf_verify(&vrf_pk, seed_input, proof)
}

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
        // Identity is refused.
        assert!(VrfPublicKey::from_bytes(&[0u8; 32]).is_none());
        let id_pt = RistrettoPoint::mul_base(&Scalar::from(0u64))
            .compress()
            .to_bytes();
        assert!(VrfPublicKey::from_bytes(&id_pt).is_none());
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

    #[test]
    fn vrf_prove_is_deterministic_and_verifies() {
        let sk = VrfSecret::from_seed(&[0x42u8; 32]);
        let pk = sk.public_key().to_bytes();
        let seed = [0x5Au8; 32];
        let a = vrf_prove(&sk, &seed);
        let b = vrf_prove(&sk, &seed);
        assert_eq!(a, b, "same secret + seed => same proof bytes on every node");
        assert_eq!(
            vrf_verify(&pk, &seed, &a),
            Some(a.output),
            "honest proof verifies under the registered key"
        );
        // Different seed => different output (height/round binding is real).
        let other = vrf_prove(&sk, &[0x5Bu8; 32]);
        assert_ne!(a.output, other.output);
    }

    #[test]
    fn vrf_verify_refuses_forgeries_fail_closed() {
        let sk = VrfSecret::from_seed(&[0x42u8; 32]);
        let pk = sk.public_key().to_bytes();
        let seed = [0x5Au8; 32];
        let good = vrf_prove(&sk, &seed);
        // Flipped proof byte refuses.
        let mut bad_byte = good.clone();
        bad_byte.proof[7] ^= 0x01;
        assert_eq!(vrf_verify(&pk, &seed, &bad_byte), None);
        // Swapped output refuses (output is bound to the proof bytes).
        let mut bad_out = good.clone();
        bad_out.output[0] ^= 0x01;
        assert_eq!(vrf_verify(&pk, &seed, &bad_out), None);
        // Wrong seed input refuses.
        assert_eq!(vrf_verify(&pk, &[0x5Bu8; 32], &good), None);
        // Wrong key refuses.
        let other_pk = VrfSecret::from_seed(&[0x43u8; 32]).public_key().to_bytes();
        assert_eq!(vrf_verify(&other_pk, &seed, &good), None);
        // Identity key refuses.
        let id_pt = RistrettoPoint::mul_base(&Scalar::from(0u64))
            .compress()
            .to_bytes();
        assert_eq!(vrf_verify(&id_pt, &seed, &good), None);
        // Non-canonical z refuses.
        let mut bad_z = good.clone();
        bad_z.proof[32..].copy_from_slice(&[0xFFu8; 32]);
        assert_eq!(vrf_verify(&pk, &seed, &bad_z), None);
    }

    #[test]
    fn vrf_registry_binding_gates_seed_minting() {
        let falcon = crate::post_quantum::FalconKeypair::generate_from_seed_bytes(&[0x77u8; 32]);
        let sk = VrfSecret::from_seed(&[0x42u8; 32]);
        let vrf_pk = sk.public_key().to_bytes();
        let validator_id = [0x11u8; 32];
        let sig = falcon.sign(&vrf_binding_preimage(&validator_id, &vrf_pk));
        let mut reg = VrfRegistry::new();
        reg.register(
            &VrfBinding {
                validator_id,
                vrf_pk,
                falcon_sig: sig,
            },
            falcon.public_key(),
        )
        .expect("honest binding registers");
        let seed = [0x5Au8; 32];
        let proof = vrf_prove(&sk, &seed);
        assert_eq!(
            verify_vrf_seed_for_validator(&reg, &validator_id, &seed, &proof),
            Some(proof.output),
            "registered validator mints a verified seed"
        );
        // Unregistered validator refuses (never stored, never minted).
        assert_eq!(
            verify_vrf_seed_for_validator(&reg, &[0x22u8; 32], &seed, &proof),
            None
        );
        // Registered id but foreign proof refuses.
        let foreign = vrf_prove(&VrfSecret::from_seed(&[0x99u8; 32]), &seed);
        assert_eq!(
            verify_vrf_seed_for_validator(&reg, &validator_id, &seed, &foreign),
            None
        );
    }

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
        // Env parsing: missing => Disabled; valid => FromHeight; garbage => Disabled.
        let key = VRF_ACTIVATION_HEIGHT_ENV;
        let saved = std::env::var(key).ok();
        std::env::remove_var(key);
        assert_eq!(vrf_activation_from_env(), VrfActivation::Disabled);
        std::env::set_var(key, "500");
        assert_eq!(
            vrf_activation_from_env(),
            VrfActivation::FromHeight(500)
        );
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
}
