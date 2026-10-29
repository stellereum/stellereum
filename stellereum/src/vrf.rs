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
}
