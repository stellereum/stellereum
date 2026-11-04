//! Confidentiality module: Pedersen Commitments & Stealth Addresses
//! Selective confidentiality using curve25519-dalek.
//! Allows hiding order/transfer amounts, single-use stealth addresses,
//! viewing audit keys for compliance/fund management, and homomorphic balance verification.
//!
//! PQ ENFORCEMENT (live-path gate — this module is NOT experimental):
//! Ristretto is classical group crypto (Shor-breakable). Inventory:
//! `docs/CLASSICAL_INVENTORY.md` row 82 (HOLE: no pure-PQ gate before this
//! change). Live callers (prove live, not dead): `svm.rs`
//! `SysCallConfidentialTransfer2`/`Shield`/`Unshield` handlers,
//! `state_engine.rs` shielded state + parallel preverify,
//! `commitment.rs` confidential domain, `mempool.rs` proof-unit accounting,
//! `native_api.rs` shield/stealth builders, `wallet.rs` stealth fields,
//! `sharding.rs:3497` stealth-sig fallback. Gating this module breaks
//! shielded transfers in pure-PQ mode BY DESIGN (they revert fail-closed).
//! When `crate::post_quantum::is_pure_pq_enforced()` (`STELL_PURE_PQ=1` /
//! `--pure-pq`) every fallible Ristretto verifier/applier below refuses
//! fail-closed (`false` / `None` / `Err(PurePqRefused)` / all-`false` batch)
//! with NO silent fallback to classical. Default behavior (gate off) is
//! byte-identical: existing privacy tests pin it unmodified.
//! Infallible constructors/provers (`commit`, `RangeProof::prove`,
//! `sign_one_time`, key generators) keep their signatures for stability and
//! stay usable offline; chain safety comes from verifier refusal, mirroring
//! the consensus dual-stack precedent (sign side allowed, verify side gated).
//!
//! PQ MIGRATION PATH (reference only — NOT implemented here):
//! replace Pedersen `v*G + r*H` with a hash-based commitment (e.g.
//! SHA-256/BLAKE3/SHAKE `C = Hash(value || blinding || domain)`, Grover-only
//! so still fine) with hash-opening proofs instead of discrete-log range
//! proofs, and replace the Ristretto Schnorr stealth auth with Falcon-512
//! signatures via `crate::post_quantum` (the PQ signer already used for votes
//! and faucet drips). Stealth-address DH (`r*ViewPub`) needs a PQ KEM
//! (ML-KEM — none wired in-tree yet). See `docs/CLASSICAL_INVENTORY.md`
//! Phase-3 item 12 and `docs/program/CLASSICAL_REMOVAL_PHASE23.md`.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Pure-PQ refusal flag for this module: true exactly when
/// `crate::post_quantum::is_pure_pq_enforced()` holds (`STELL_PURE_PQ=1` /
/// `--pure-pq`, thread-local override under `cfg(test)`).
/// Every fallible Ristretto op below consults this and refuses fail-closed.
pub fn privacy_pq_refused() -> bool {
    crate::post_quantum::is_pure_pq_enforced()
}

/// Fail-closed guard for `Result<_, ConfidentialError>` entry points.
/// No secret material is touched or reported: the refusal carries no
/// commitment bytes, blindings, or keys.
fn ensure_classical_allowed() -> Result<(), ConfidentialError> {
    if privacy_pq_refused() {
        return Err(ConfidentialError::PurePqRefused);
    }
    Ok(())
}

// §9 MSM batching: N sequential scalar folds → one `vartime_multiscalar_mul` call.
// Backend fact (measured): dalek 4.x has no `simd_backend` feature; AVX2 picked at RUNTIME
// via CPUID, zero RUSTFLAGS. Consensus-safe: per-item bools bit-identical to scalar (pinned
// by tests/privacy_onchain_tests.rs); framing untouched; scalar below MSM_FOLD_CUTOFF.

lazy_static::lazy_static! {
    /// Independent generator H for Pedersen commitments: H = hash_to_point(G)
    pub static ref GENERATOR_H: RistrettoPoint = {
        let hash = Sha256::digest(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
        let mut uniform = [0u8; 64];
        uniform[..32].copy_from_slice(&hash);
        let hash2 = Sha256::digest(&uniform[..32]);
        uniform[32..].copy_from_slice(&hash2);
        RistrettoPoint::from_uniform_bytes(&uniform)
    };
}

/// Pedersen Commitment: C = v*G + r*H
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub commitment: [u8; 32],
}

impl PedersenCommitment {
    /// Commit to a 64-bit value with a blinding factor (scalar)
    pub fn commit(value: u64, blinding: &Scalar) -> Self {
        let v_scalar = Scalar::from(value);
        // C = v*G + r*H
        let point = (RISTRETTO_BASEPOINT_POINT * v_scalar) + (*GENERATOR_H * blinding);
        Self {
            commitment: point.compress().to_bytes(),
        }
    }

    /// Generate random blinding scalar
    pub fn random_blinding() -> Scalar {
        let mut rng = OsRng;
        Scalar::random(&mut rng)
    }

    /// Verify opening of commitment.
    ///
    /// Pure-PQ: refuses (`false`) when [`privacy_pq_refused`].
    pub fn verify(&self, value: u64, blinding: &Scalar) -> bool {
        if privacy_pq_refused() {
            return false;
        }
        let expected = Self::commit(value, blinding);
        self.commitment == expected.commitment
    }

    /// Batched opening verification (thin batch API).
    ///
    /// Returns one bool per `(commitment, value, blinding)` triple, in order;
    /// element `i` is BIT-IDENTICAL to `openings[i].0.verify(openings[i].1,
    /// &openings[i].2)`, always — this is literally the same per-element
    /// recompute-and-compare, sharing one call and one allocation.
    ///
    /// Deliberately NOT a single merged MSM: the per-opening equations
    /// `C_i - v_i*G - r_i*H == 0` cannot be folded into one MSM without a
    /// random linear combination, which would make the result probabilistic
    /// rather than bit-identical to the scalar reference. The MSM wins live
    /// in the weighted sums (`BitProof` t-pairs, `2^i*C_i` reconstruction),
    /// not here. Measured: no gap here, so no cleverness here.
    ///
    /// Pure-PQ: all-`false` when [`privacy_pq_refused`] (inherited from
    /// `verify`, made explicit so the batch cannot verify while scalar cannot).
    pub fn batch_verify(openings: &[(PedersenCommitment, u64, Scalar)]) -> Vec<bool> {
        if privacy_pq_refused() {
            return vec![false; openings.len()];
        }
        openings.iter().map(|(c, v, r)| c.verify(*v, r)).collect()
    }

    /// Add two commitments homomorphically: C1 + C2 = Commit(v1 + v2, r1 + r2).
    ///
    /// Pure-PQ: `None` when [`privacy_pq_refused`].
    pub fn add(&self, other: &Self) -> Option<Self> {
        if privacy_pq_refused() {
            return None;
        }
        let p1 = CompressedRistretto(self.commitment).decompress()?;
        let p2 = CompressedRistretto(other.commitment).decompress()?;
        let sum = p1 + p2;
        Some(Self {
            commitment: sum.compress().to_bytes(),
        })
    }

    /// Subtract two commitments homomorphically: C1 - C2.
    ///
    /// Pure-PQ: `None` when [`privacy_pq_refused`].
    pub fn sub(&self, other: &Self) -> Option<Self> {
        if privacy_pq_refused() {
            return None;
        }
        let p1 = CompressedRistretto(self.commitment).decompress()?;
        let p2 = CompressedRistretto(other.commitment).decompress()?;
        let diff = p1 - p2;
        Some(Self {
            commitment: diff.compress().to_bytes(),
        })
    }
}

/// Stealth address generator and viewer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthAddress {
    /// One-time destination address (public key)
    pub one_time_pub: [u8; 32],
    /// Ephemeral public key sent in tx for receiver to derive one-time private key
    pub ephemeral_pub: [u8; 32],
}

impl StealthAddress {
    /// Sender generates stealth address using recipient's view pubkey and spend pubkey.
    ///
    /// Pure-PQ: `None` when [`privacy_pq_refused`] (ECDH over Ristretto).
    pub fn generate(recipient_view_pub: &[u8; 32], recipient_spend_pub: &[u8; 32]) -> Option<Self> {
        if privacy_pq_refused() {
            return None;
        }
        let view_pt = CompressedRistretto(*recipient_view_pub).decompress()?;
        let spend_pt = CompressedRistretto(*recipient_spend_pub).decompress()?;

        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let ephemeral_pt = RISTRETTO_BASEPOINT_POINT * r;

        // Shared secret = r * ViewPub
        let shared_secret = view_pt * r;
        let s_hash = Sha256::digest(shared_secret.compress().as_bytes());
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&s_hash);
        let s_scalar = Scalar::from_bytes_mod_order(s_bytes);

        // One-time public key P = SpendPub + H(r*ViewPub)*G
        let one_time_pt = spend_pt + (RISTRETTO_BASEPOINT_POINT * s_scalar);

        Some(Self {
            one_time_pub: one_time_pt.compress().to_bytes(),
            ephemeral_pub: ephemeral_pt.compress().to_bytes(),
        })
    }

    /// Recipient checks if the stealth address belongs to them using view private key.
    ///
    /// Pure-PQ: `None` when [`privacy_pq_refused`].
    pub fn is_for_recipient(&self, view_priv: &Scalar, spend_pub: &[u8; 32]) -> Option<bool> {
        if privacy_pq_refused() {
            return None;
        }
        let ephem_pt = CompressedRistretto(self.ephemeral_pub).decompress()?;
        let spend_pt = CompressedRistretto(*spend_pub).decompress()?;

        // Shared secret = ViewPriv * EphemPub
        let shared_secret = ephem_pt * view_priv;
        let s_hash = Sha256::digest(shared_secret.compress().as_bytes());
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&s_hash);
        let s_scalar = Scalar::from_bytes_mod_order(s_bytes);

        let expected_pt = spend_pt + (RISTRETTO_BASEPOINT_POINT * s_scalar);
        Some(expected_pt.compress().to_bytes() == self.one_time_pub)
    }

    /// Recipient derives the one-time private key using their view private key and spend private key:
    /// one_time_priv = spend_priv + H(view_priv * ephemeral_pub)
    ///
    /// AUDIT W6.5 (fail closed): the derived key is CHECKED against this
    /// stealth address's `one_time_pub` before it is handed out. Without the
    /// check, a caller that passes a mismatched view key or a mismatched spend
    /// key received a perfectly usable private key — for a DIFFERENT address
    /// than the one it believes it is spending from, i.e. funds that go to an
    /// address nobody controls. A mismatch now yields `None`.
    ///
    /// Pure-PQ: `None` when [`privacy_pq_refused`].
    pub fn derive_one_time_private_key(
        &self,
        view_priv: &Scalar,
        spend_priv: &Scalar,
    ) -> Option<Scalar> {
        if privacy_pq_refused() {
            return None;
        }
        let ephem_pt = CompressedRistretto(self.ephemeral_pub).decompress()?;
        let shared_secret = ephem_pt * view_priv;
        let s_hash = Sha256::digest(shared_secret.compress().as_bytes());
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&s_hash);
        let s_scalar = Scalar::from_bytes_mod_order(s_bytes);
        let one_time_priv = spend_priv + s_scalar;
        // The derived key must correspond to THIS address.
        let derived_pub = (RISTRETTO_BASEPOINT_POINT * one_time_priv)
            .compress()
            .to_bytes();
        if derived_pub != self.one_time_pub {
            return None;
        }
        Some(one_time_priv)
    }

    /// Sign a message using the derived one-time private key via Schnorr signature on Ristretto255.
    pub fn sign_one_time(one_time_priv: &Scalar, message: &[u8]) -> [u8; 64] {
        let pub_pt = RISTRETTO_BASEPOINT_POINT * one_time_priv;
        let pub_bytes = pub_pt.compress().to_bytes();

        let mut rng = OsRng;
        let k = Scalar::random(&mut rng);
        let r_pt = RISTRETTO_BASEPOINT_POINT * k;
        let r_bytes = r_pt.compress().to_bytes();

        let e = challenge_scalar(&[b"STELL_STEALTH_SCHNORR_V1", &pub_bytes, &r_bytes, message]);
        let s = k + e * one_time_priv;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice(&s.to_bytes());
        sig
    }

    /// Sign a message using this stealth address's one-time private key.
    pub fn sign(&self, one_time_priv: &Scalar, message: &[u8]) -> [u8; 64] {
        Self::sign_one_time(one_time_priv, message)
    }

    /// Alias for sign_one_time.
    pub fn sign_message(one_time_priv: &Scalar, message: &[u8]) -> [u8; 64] {
        Self::sign_one_time(one_time_priv, message)
    }

    /// Verify a Schnorr signature against a one-time public key.
    ///
    /// Pure-PQ: `false` when [`privacy_pq_refused`] (Ristretto Schnorr).
    pub fn verify_one_time_signature(
        one_time_pub: &[u8; 32],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        if privacy_pq_refused() {
            return false;
        }
        if signature.len() != 64 {
            return false;
        }
        let pub_pt = match CompressedRistretto(*one_time_pub).decompress() {
            Some(pt) => pt,
            None => return false,
        };

        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature[..32]);
        let r_pt = match CompressedRistretto(r_bytes).decompress() {
            Some(pt) => pt,
            None => return false,
        };

        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature[32..64]);
        let s = match Scalar::from_canonical_bytes(s_bytes).into_option() {
            Some(s) => s,
            None => return false,
        };

        let e = challenge_scalar(&[b"STELL_STEALTH_SCHNORR_V1", one_time_pub, &r_bytes, message]);

        let sg = RISTRETTO_BASEPOINT_POINT * s;
        let r_ep = r_pt + (pub_pt * e);
        sg == r_ep
    }

    /// Verify a signature against this stealth address instance.
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        Self::verify_one_time_signature(&self.one_time_pub, message, signature)
    }

    /// Alias for verify_signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify_signature(message, signature)
    }
}

/// Sign a message using a one-time private key (Schnorr signature over Ristretto255).
pub fn sign_stealth_message(one_time_priv: &Scalar, message: &[u8]) -> [u8; 64] {
    StealthAddress::sign_one_time(one_time_priv, message)
}

/// Verify a stealth signature against a one-time public key.
pub fn verify_stealth_signature(one_time_pub: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    StealthAddress::verify_one_time_signature(one_time_pub, message, signature)
}

/// Encrypted amount payload for Viewing Key audit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedViewingPayload {
    pub ephemeral_pub: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
}

/// Selective Disclosure Viewing Key for compliance audits and autonomous funds
///
/// SECRET: `view_priv` is the viewing PRIVATE key. The manual `Debug` impl
/// below prints only its presence — never the bytes. (The previous derived
/// `Debug` printed the whole private key into every log line, error and
/// `assert!` message that happened to hold a `ViewingKey`.)
#[derive(Clone, Serialize, Deserialize)]
pub struct ViewingKey {
    pub view_priv: [u8; 32],
    pub view_pub: [u8; 32],
}

impl fmt::Debug for ViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ViewingKey")
            .field("view_priv", &"[REDACTED]")
            .field("view_pub", &hex::encode(self.view_pub))
            .finish()
    }
}

impl ViewingKey {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let priv_scalar = Scalar::random(&mut rng);
        let pub_point = RISTRETTO_BASEPOINT_POINT * priv_scalar;
        Self {
            view_priv: priv_scalar.to_bytes(),
            view_pub: pub_point.compress().to_bytes(),
        }
    }

    /// Derive viewing key deterministically from a 32-byte master seed.
    pub fn derive_from_seed(seed: &[u8; 32]) -> Self {
        let mut view_hasher = Sha256::new();
        view_hasher.update(seed);
        view_hasher.update(b"VIEWING_KEY_DERIVE");
        let view_scalar_bytes: [u8; 32] = view_hasher.finalize().into();
        let view_priv = Scalar::from_bytes_mod_order(view_scalar_bytes);
        let view_pub = (RISTRETTO_BASEPOINT_POINT * view_priv)
            .compress()
            .to_bytes();
        Self {
            view_priv: view_priv.to_bytes(),
            view_pub,
        }
    }

    /// Alias for derive_from_seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::derive_from_seed(seed)
    }

    /// Construct viewing key from an explicit private scalar.
    pub fn from_scalar(priv_scalar: &Scalar) -> Self {
        let pub_point = RISTRETTO_BASEPOINT_POINT * priv_scalar;
        Self {
            view_priv: priv_scalar.to_bytes(),
            view_pub: pub_point.compress().to_bytes(),
        }
    }

    /// Deterministic derivation of spend key (Scalar, Compressed pubkey bytes) from seed.
    pub fn derive_spend_key(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
        let mut spend_hasher = Sha256::new();
        spend_hasher.update(seed);
        spend_hasher.update(b"SPEND_KEY_DERIVE");
        let spend_scalar_bytes: [u8; 32] = spend_hasher.finalize().into();
        let spend_priv = Scalar::from_bytes_mod_order(spend_scalar_bytes);
        let spend_pub = (RISTRETTO_BASEPOINT_POINT * spend_priv)
            .compress()
            .to_bytes();
        (spend_priv, spend_pub)
    }

    /// Returns the viewing private key as a Dalek Scalar.
    pub fn private_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.view_priv)
    }

    /// Check if a stealth address belongs to this viewing key given recipient's spend pubkey.
    ///
    /// Pure-PQ: `None` when [`privacy_pq_refused`].
    pub fn is_for_recipient(&self, stealth: &StealthAddress, spend_pub: &[u8; 32]) -> Option<bool> {
        if privacy_pq_refused() {
            return None;
        }
        let view_priv = self.private_scalar();
        stealth.is_for_recipient(&view_priv, spend_pub)
    }

    /// Derive one-time private key using this viewing key and recipient's spend private key.
    ///
    /// Pure-PQ: `None` when [`privacy_pq_refused`].
    pub fn derive_one_time_private_key(
        &self,
        stealth: &StealthAddress,
        spend_priv: &Scalar,
    ) -> Option<Scalar> {
        if privacy_pq_refused() {
            return None;
        }
        let view_priv = self.private_scalar();
        stealth.derive_one_time_private_key(&view_priv, spend_priv)
    }

    /// Encrypt amount and blinding factor for an auditor holding `view_pub`.
    ///
    /// Pure-PQ: `Err` (static refusal, no secret material) when
    /// [`privacy_pq_refused`] — the ECDH runs over Ristretto.
    pub fn encrypt_amount_for_auditor(
        view_pub_bytes: &[u8; 32],
        value: u64,
        blinding: &Scalar,
    ) -> Result<EncryptedViewingPayload, String> {
        if privacy_pq_refused() {
            return Err(
                "Ristretto privacy refused under STELL_PURE_PQ=1 (pure-PQ mode)".to_string(),
            );
        }
        let view_pt = CompressedRistretto(*view_pub_bytes)
            .decompress()
            .ok_or_else(|| "Invalid view pubkey".to_string())?;

        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let ephemeral_pt = RISTRETTO_BASEPOINT_POINT * r;

        // Shared secret = r * view_pt
        let shared_secret = view_pt * r;
        let sym_key: [u8; 32] = Sha256::digest(shared_secret.compress().as_bytes()).into();

        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(&value.to_be_bytes());
        payload.extend_from_slice(&blinding.to_bytes());

        let cipher = XChaCha20Poly1305::new((&sym_key).into());
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let xnonce = XNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(xnonce, payload.as_ref())
            .map_err(|e| format!("Encryption error: {:?}", e))?;

        Ok(EncryptedViewingPayload {
            ephemeral_pub: ephemeral_pt.compress().to_bytes(),
            ciphertext,
            nonce,
        })
    }

    /// Auditor decrypts value and blinding factor using their viewing key.
    ///
    /// Pure-PQ: `Err` (static refusal, no secret material) when
    /// [`privacy_pq_refused`].
    pub fn decrypt_amount(
        &self,
        payload: &EncryptedViewingPayload,
    ) -> Result<(u64, Scalar), String> {
        if privacy_pq_refused() {
            return Err(
                "Ristretto privacy refused under STELL_PURE_PQ=1 (pure-PQ mode)".to_string(),
            );
        }
        let ephem_pt = CompressedRistretto(payload.ephemeral_pub)
            .decompress()
            .ok_or_else(|| "Invalid ephemeral pubkey".to_string())?;

        let priv_scalar = Scalar::from_bytes_mod_order(self.view_priv);
        let shared_secret = ephem_pt * priv_scalar;
        let sym_key: [u8; 32] = Sha256::digest(shared_secret.compress().as_bytes()).into();

        let cipher = XChaCha20Poly1305::new((&sym_key).into());
        let xnonce = XNonce::from_slice(&payload.nonce);

        let plain = cipher
            .decrypt(xnonce, payload.ciphertext.as_ref())
            .map_err(|e| format!("Decryption error: {:?}", e))?;

        if plain.len() != 40 {
            return Err("Invalid decrypted payload length".to_string());
        }

        let value = u64::from_be_bytes(plain[..8].try_into().unwrap());
        let mut blind_bytes = [0u8; 32];
        blind_bytes.copy_from_slice(&plain[8..40]);
        let blinding = Scalar::from_bytes_mod_order(blind_bytes);

        Ok((value, blinding))
    }
}

/// Confidential Balance Transfer with Homomorphic Conservation Check
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfidentialTransfer {
    pub input_commitments: Vec<PedersenCommitment>,
    pub output_commitments: Vec<PedersenCommitment>,
    pub fee: u64,
}

/// One coin revealed for an unshield exit: the commitment plus its full
/// opening. Revealing the opening is what makes the exit auditable — the
/// verifier recomputes the commitment exactly, so the credited native value
/// is proven, not claimed. (Privacy ends at exit by design, like transparent
/// deposits into a shielded pool elsewhere.)
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnshieldInput {
    pub commitment: [u8; 32],
    pub amount: u64,
    pub blinding: [u8; 32],
}

impl fmt::Debug for UnshieldInput {
    /// SECRET HYGIENE (pentest P4): `blinding` is the coin's secret opening.
    /// The derived `Debug` printed it into every log/error/assert string
    /// holding an `UnshieldInput`. The commitment and amount are
    /// public-by-design at exit (the verifier recomputes the commitment and
    /// the amount is credited natively); the blinding is never shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnshieldInput")
            .field("commitment", &hex::encode(self.commitment))
            .field("amount", &self.amount)
            .field("blinding", &"[REDACTED]")
            .finish()
    }
}

impl ConfidentialTransfer {
    pub fn new(
        input_commitments: Vec<PedersenCommitment>,
        output_commitments: Vec<PedersenCommitment>,
        fee: u64,
    ) -> Self {
        Self {
            input_commitments,
            output_commitments,
            fee,
        }
    }

    /// Verify homomorphic conservation of value: sum(C_in) - sum(C_out) == fee * G.
    ///
    /// Pure-PQ: `false` when [`privacy_pq_refused`].
    pub fn verify_balance_conservation(&self) -> bool {
        if privacy_pq_refused() {
            return false;
        }
        if self.input_commitments.is_empty() || self.output_commitments.is_empty() {
            return false;
        }

        // Sum input points
        let mut sum_in =
            match CompressedRistretto(self.input_commitments[0].commitment).decompress() {
                Some(p) => p,
                None => return false,
            };
        for c in &self.input_commitments[1..] {
            let p = match CompressedRistretto(c.commitment).decompress() {
                Some(p) => p,
                None => return false,
            };
            sum_in += p;
        }

        // Sum output points
        let mut sum_out =
            match CompressedRistretto(self.output_commitments[0].commitment).decompress() {
                Some(p) => p,
                None => return false,
            };
        for c in &self.output_commitments[1..] {
            let p = match CompressedRistretto(c.commitment).decompress() {
                Some(p) => p,
                None => return false,
            };
            sum_out += p;
        }

        // Expected difference is fee * G
        let fee_scalar = Scalar::from(self.fee);
        let expected_fee_point = RISTRETTO_BASEPOINT_POINT * fee_scalar;

        (sum_in - sum_out) == expected_fee_point
    }

    /// A5: verified conservation WITH range proofs on every input and output.
    /// This closes the inflation hole: a bare `verify_balance_conservation` only
    /// checks the group equation, so a prover could commit to values outside any
    /// sane range. With a range proof per commitment, every committed value is
    /// provably in [0, 2^bits).
    ///
    /// The range checks go through the §9 batch verifier (one call per side);
    /// the boolean result is identical to checking each proof in a loop.
    pub fn verify_balanced_with_ranges(
        &self,
        input_ranges: &[RangeProof],
        output_ranges: &[RangeProof],
    ) -> bool {
        if privacy_pq_refused() {
            return false;
        }
        if !self.verify_balance_conservation() {
            return false;
        }
        if input_ranges.len() != self.input_commitments.len()
            || output_ranges.len() != self.output_commitments.len()
        {
            return false;
        }
        let in_pairs: Vec<(&PedersenCommitment, &RangeProof)> = self
            .input_commitments
            .iter()
            .zip(input_ranges.iter())
            .collect();
        let out_pairs: Vec<(&PedersenCommitment, &RangeProof)> = self
            .output_commitments
            .iter()
            .zip(output_ranges.iter())
            .collect();
        RangeProof::batch_verify(&in_pairs).iter().all(|&b| b)
            && RangeProof::batch_verify(&out_pairs).iter().all(|&b| b)
    }

    /// Fail-closed per-commitment non-negativity check (F-A solvency fix).
    ///
    /// Every input AND every output must carry its positional range proof,
    /// each proving its commitment opens to a value in [0, 2^bits) (hence in
    /// [0, 2^64)). A count mismatch is [`ConfidentialError::MissingRangeProof`]
    /// — never a fallback to the equation-only check; a failed proof is
    /// [`ConfidentialError::InvalidRangeProof`] carrying the offending
    /// commitment bytes. Per-item verdicts go through
    /// [`RangeProof::batch_verify`], so each is bit-identical to
    /// [`RangeProof::verify`].
    pub fn verify_ranges(
        &self,
        input_ranges: &[RangeProof],
        output_ranges: &[RangeProof],
    ) -> Result<(), ConfidentialError> {
        ensure_classical_allowed()?;
        if input_ranges.len() != self.input_commitments.len()
            || output_ranges.len() != self.output_commitments.len()
        {
            return Err(ConfidentialError::MissingRangeProof);
        }
        let in_pairs: Vec<(&PedersenCommitment, &RangeProof)> = self
            .input_commitments
            .iter()
            .zip(input_ranges.iter())
            .collect();
        for ((c, _), ok) in self
            .input_commitments
            .iter()
            .zip(input_ranges.iter())
            .zip(RangeProof::batch_verify(&in_pairs).iter())
        {
            if !ok {
                return Err(ConfidentialError::InvalidRangeProof(c.commitment));
            }
        }
        let out_pairs: Vec<(&PedersenCommitment, &RangeProof)> = self
            .output_commitments
            .iter()
            .zip(output_ranges.iter())
            .collect();
        for ((c, _), ok) in self
            .output_commitments
            .iter()
            .zip(output_ranges.iter())
            .zip(RangeProof::batch_verify(&out_pairs).iter())
        {
            if !ok {
                return Err(ConfidentialError::InvalidRangeProof(c.commitment));
            }
        }
        Ok(())
    }

    /// Canonical, length-prefixed byte encoding of the transfer.
    ///
    /// This is the COMMITTED representation: it commits to the exact commitment
    /// points, their order and the fee, and to nothing else. It deliberately
    /// contains no blinding factors and no plaintext values, so publishing it (or
    /// its digest) reveals nothing about the transferred amount. Every field is
    /// framed with an explicit length so two different transfers cannot encode to
    /// the same bytes (a one-input/one-output transfer cannot collide with a
    /// two-input/zero-output one).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            8 + self.input_commitments.len() * 32 + 8 + self.output_commitments.len() * 32 + 8,
        );
        out.extend_from_slice(&(self.input_commitments.len() as u64).to_be_bytes());
        for c in &self.input_commitments {
            out.extend_from_slice(&c.commitment);
        }
        out.extend_from_slice(&(self.output_commitments.len() as u64).to_be_bytes());
        for c in &self.output_commitments {
            out.extend_from_slice(&c.commitment);
        }
        out.extend_from_slice(&self.fee.to_be_bytes());
        out
    }

    /// Domain-separated digest of [`Self::encode`]. Deterministic: the same
    /// transfer always digests identically, and any mutation (a flipped
    /// commitment byte, a reordered input, a changed fee) changes the digest.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"STELL_CONFIDENTIAL_TRANSFER_V1");
        h.update(self.encode());
        h.finalize().into()
    }
}

/// Domain-separated digest of one `SysCallConfidentialTransfer2` proof bundle:
/// the transfer plus its per-commitment range proofs, in order.
///
/// This is the KEY of the block-path range-proof pre-verification cache (see
/// `InMemoryStateEngine::apply_block_parallel_fees`): range-proof verification
/// is a pure function of exactly these bytes (no state, no clock), so two
/// bundles with the same digest verify identically on every node. The encoding
/// is manual (length-framed, field-ordered) so it cannot drift with a
/// serializer version; any mutation — a flipped proof byte, a reordered
/// input, a changed fee or width — changes the digest.
pub fn confidential_transfer2_preverify_digest(
    transfer: &ConfidentialTransfer,
    input_ranges: &[RangeProof],
    output_ranges: &[RangeProof],
) -> [u8; 32] {
    fn put_proof(h: &mut Sha256, p: &RangeProof) {
        h.update([p.bits]);
        h.update((p.bit_commitments.len() as u64).to_be_bytes());
        for c in &p.bit_commitments {
            h.update(c.commitment);
        }
        h.update((p.bit_proofs.len() as u64).to_be_bytes());
        for b in &p.bit_proofs {
            h.update(b.e0);
            h.update(b.s0);
            h.update(b.e1);
            h.update(b.s1);
        }
    }
    let mut h = Sha256::new();
    h.update(b"STELL_CONFIDENTIAL_TRANSFER2_PREVERIFY_V1");
    h.update(transfer.encode());
    h.update((input_ranges.len() as u64).to_be_bytes());
    for p in input_ranges {
        put_proof(&mut h, p);
    }
    h.update((output_ranges.len() as u64).to_be_bytes());
    for p in output_ranges {
        put_proof(&mut h, p);
    }
    h.finalize().into()
}

// ============================================================================
// Range proofs (A5) — bit decomposition with Schnorr OR-proofs
// ============================================================================

fn challenge_scalar(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    Scalar::from_bytes_mod_order(h.finalize().into())
}

/// OR-proof that a commitment opens to 0 or 1 (both witnesses w.r.t. H).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitProof {
    pub e0: [u8; 32],
    pub s0: [u8; 32],
    pub e1: [u8; 32],
    pub s1: [u8; 32],
}

impl BitProof {
    /// Prove that `commitment` commits to `bit` (0 or 1) with `blinding`.
    pub fn prove(commitment: &PedersenCommitment, bit: bool, blinding: &Scalar) -> Self {
        let c = CompressedRistretto(commitment.commitment)
            .decompress()
            .expect("valid commitment point");
        let p0 = c; // claim: opens to 0  => C = r*H
        let p1 = c - RISTRETTO_BASEPOINT_POINT; // claim: opens to 1 => C-G = r*H
        let (_p_true, p_false) = if bit { (p1, p0) } else { (p0, p1) };

        let mut rng = OsRng;
        // Simulate the false branch.
        let e_false = Scalar::random(&mut rng);
        let s_false = Scalar::random(&mut rng);
        let t_false = s_false * (*GENERATOR_H) - e_false * p_false;
        // Real nonce for the true branch.
        let k = Scalar::random(&mut rng);
        let t_true = k * (*GENERATOR_H);

        let (t0, t1) = if bit {
            (t_false, t_true)
        } else {
            (t_true, t_false)
        };
        let e = challenge_scalar(&[
            b"STELL_BIT_OR_V1",
            &p0.compress().to_bytes(),
            &p1.compress().to_bytes(),
            &t0.compress().to_bytes(),
            &t1.compress().to_bytes(),
        ]);
        let e_true = e - e_false;
        let s_true = k + e_true * blinding;

        let (e0, s0, e1, s1) = if bit {
            (e_false, s_false, e_true, s_true)
        } else {
            (e_true, s_true, e_false, s_false)
        };
        Self {
            e0: e0.to_bytes(),
            s0: s0.to_bytes(),
            e1: e1.to_bytes(),
            s1: s1.to_bytes(),
        }
    }

    pub fn verify(commitment: &PedersenCommitment, proof: &BitProof) -> bool {
        if privacy_pq_refused() {
            return false;
        }
        let c = match CompressedRistretto(commitment.commitment).decompress() {
            Some(p) => p,
            None => return false,
        };
        let p0 = c;
        let p1 = c - RISTRETTO_BASEPOINT_POINT;
        let e0 = Scalar::from_bytes_mod_order(proof.e0);
        let e1 = Scalar::from_bytes_mod_order(proof.e1);
        let s0 = Scalar::from_bytes_mod_order(proof.s0);
        let s1 = Scalar::from_bytes_mod_order(proof.s1);
        // §9: each `s*H - e*p` pair is one 2-term MSM instead of two
        // variable-base muls (measured ~1.7x; `benches/privacy_batch.rs`).
        // Same group arithmetic, bit-identical to the scalar twin below.
        // `vartime_` is safe here: every input (commitment, proof bytes) is
        // public — the verifier holds no secrets. `prove` is untouched.
        let t0 = RistrettoPoint::vartime_multiscalar_mul(&[s0, -e0], &[(*GENERATOR_H), p0]);
        let t1 = RistrettoPoint::vartime_multiscalar_mul(&[s1, -e1], &[(*GENERATOR_H), p1]);
        let e = challenge_scalar(&[
            b"STELL_BIT_OR_V1",
            &p0.compress().to_bytes(),
            &p1.compress().to_bytes(),
            &t0.compress().to_bytes(),
            &t1.compress().to_bytes(),
        ]);
        e0 + e1 == e
    }

    /// Scalar reference twin of [`Self::verify`]: the original two-muls-per-t
    /// formulation, kept verbatim as the consensus fallback and the
    /// differential-test oracle. Always agrees with `verify` bit-for-bit.
    ///
    /// Pure-PQ: `false` when [`privacy_pq_refused`].
    pub fn verify_scalar(commitment: &PedersenCommitment, proof: &BitProof) -> bool {
        if privacy_pq_refused() {
            return false;
        }
        let c = match CompressedRistretto(commitment.commitment).decompress() {
            Some(p) => p,
            None => return false,
        };
        let p0 = c;
        let p1 = c - RISTRETTO_BASEPOINT_POINT;
        let e0 = Scalar::from_bytes_mod_order(proof.e0);
        let e1 = Scalar::from_bytes_mod_order(proof.e1);
        let s0 = Scalar::from_bytes_mod_order(proof.s0);
        let s1 = Scalar::from_bytes_mod_order(proof.s1);
        let t0 = s0 * (*GENERATOR_H) - e0 * p0;
        let t1 = s1 * (*GENERATOR_H) - e1 * p1;
        let e = challenge_scalar(&[
            b"STELL_BIT_OR_V1",
            &p0.compress().to_bytes(),
            &p1.compress().to_bytes(),
            &t0.compress().to_bytes(),
            &t1.compress().to_bytes(),
        ]);
        e0 + e1 == e
    }
}

/// Bit-decomposition range proof: `commitment` opens to a value in [0, 2^bits).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeProof {
    pub bits: u8,
    pub bit_commitments: Vec<PedersenCommitment>,
    pub bit_proofs: Vec<BitProof>,
}

impl RangeProof {
    /// Width class for a value: 32 bits below 2^32, 64 above (audit: speed —
    /// sub-2^32 values are ~all normal payments; 64-bit proofs cost double
    /// bytes and verify work). Only these two classes in production (never
    /// 0/1 — avoids dust fingerprinting and keeps gas legible).
    pub fn bits_for_value(value: u64) -> u8 {
        if value < (1u64 << 32) {
            32
        } else {
            64
        }
    }

    /// Prove with automatic width selection (see `bits_for_value`).
    /// Cannot panic on size (the width always fits by construction).
    pub fn prove_auto(commitment: &PedersenCommitment, value: u64, blinding: &Scalar) -> Self {
        Self::prove(commitment, value, blinding, Self::bits_for_value(value))
    }

    /// Prove that `commitment = value*G + blinding*H` with `value < 2^bits`.
    pub fn prove(commitment: &PedersenCommitment, value: u64, blinding: &Scalar, bits: u8) -> Self {
        assert!((1..=64).contains(&bits), "bits must be in 1..=64");
        assert!(
            bits == 64 || (value >> bits) == 0,
            "value does not fit in the requested range"
        );
        let n = bits as usize;
        let mut rng = OsRng;

        // Choose r_0..r_{n-2} at random, then derive r_{n-1} so that
        // sum_i 2^i * C_i == commitment.
        let mut blindings: Vec<Scalar> = Vec::with_capacity(n);
        let mut partial = Scalar::ZERO;
        for i in 0..n - 1 {
            let ri = Scalar::random(&mut rng);
            blindings.push(ri);
            partial += Scalar::from(1u64 << i) * ri;
        }
        let pow = Scalar::from(1u64 << (n - 1));
        let r_last = (blinding - partial) * pow.invert();
        blindings.push(r_last);

        let mut bit_commitments = Vec::with_capacity(n);
        let mut bit_proofs = Vec::with_capacity(n);
        for (i, blinding) in blindings.iter().enumerate().take(n) {
            let b = (value >> i) & 1 == 1;
            let ci = PedersenCommitment::commit(b as u64, blinding);
            bit_proofs.push(BitProof::prove(&ci, b, blinding));
            bit_commitments.push(ci);
        }
        // Sanity: the decomposition must reconstruct the commitment exactly.
        debug_assert!(Self::verify_reconstruction(commitment, &bit_commitments, n));
        Self {
            bits,
            bit_commitments,
            bit_proofs,
        }
    }

    fn verify_reconstruction(
        commitment: &PedersenCommitment,
        bits: &[PedersenCommitment],
        n: usize,
    ) -> bool {
        let mut points = Vec::with_capacity(n);
        let mut scalars = Vec::with_capacity(n);
        for (i, c) in bits.iter().enumerate().take(n) {
            let pt = match CompressedRistretto(c.commitment).decompress() {
                Some(p) => p,
                None => return false,
            };
            points.push(pt);
            scalars.push(Scalar::from(1u64 << i));
        }
        // §9: the same `sum_i 2^i * C_i` fold, via the backend-selected MSM.
        // Below the cutoff `msm_sum` IS the scalar fold above; at/above it
        // Pippenger computes the identical sum. Bit-identical either way.
        msm_sum(&points, &scalars).compress().to_bytes() == commitment.commitment
    }

    pub fn verify(commitment: &PedersenCommitment, proof: &RangeProof) -> bool {
        if privacy_pq_refused() {
            return false;
        }
        if proof.bits == 0 || proof.bits > 64 {
            return false;
        }
        let n = proof.bits as usize;
        if proof.bit_commitments.len() != n || proof.bit_proofs.len() != n {
            return false;
        }
        for (c, p) in proof.bit_commitments.iter().zip(proof.bit_proofs.iter()) {
            if !BitProof::verify(c, p) {
                return false;
            }
        }
        Self::verify_reconstruction(commitment, &proof.bit_commitments, n)
    }

    /// Batched range-proof verification.
    ///
    /// Returns one bool per `(commitment, proof)` pair, in order; element `i`
    /// is BIT-IDENTICAL to `RangeProof::verify(pairs[i].0, pairs[i].1)`,
    /// always — the same per-bit checks and the same [`msm_sum`]
    /// reconstruction as the scalar path, sharing one call and one
    /// allocation across the batch.
    ///
    /// Parallelism (audit: speed): pairs verify independently (pure function,
    /// no shared state), so at/above `PAR_VERIFY_MIN_PAIRS` they run across
    /// cores via rayon with an order-preserving collect — deterministic
    /// bit-identically on every node. Below the threshold the scalar loop
    /// wins (pool round-trip dominates microsecond verifies).
    ///
    /// Pure-PQ: all-`false` when [`privacy_pq_refused`].
    pub fn batch_verify(pairs: &[(&PedersenCommitment, &RangeProof)]) -> Vec<bool> {
        if privacy_pq_refused() {
            return vec![false; pairs.len()];
        }
        const PAR_VERIFY_MIN_PAIRS: usize = 4;
        if pairs.len() >= PAR_VERIFY_MIN_PAIRS {
            use rayon::prelude::*;
            pairs.par_iter().map(|(c, p)| Self::verify(c, p)).collect()
        } else {
            pairs.iter().map(|(c, p)| Self::verify(c, p)).collect()
        }
    }
}

// ============================================================================
// §9 Batched verification over `vartime_multiscalar_mul` (MSM throughput layer)
// ============================================================================
//
// Backend selection, such as it is. Selection is by WEIGHT SHAPE, not by
// compile-time target features — that is the measured finding:
//
// * weighted sums with nontrivial scalars (`2^i*C_i` reconstruction, the
//   `s*H - e*p` pairs in `BitProof::verify`) go to `vartime_multiscalar_mul`
//   at/above [`MSM_FOLD_CUTOFF`] terms and win at every size (up to ~4.6x at
//   64 terms; the 2-term MSM beats two direct muls ~1.7x);
// * unit-coefficient sums (conservation inputs/outputs, `sum_points`) stay
//   plain point additions: additions beat Pippenger-with-ones ~8x at 64
//   terms, so routing them through an MSM would be a pessimization;
// * per-opening recomputes (`v*G + r*H`) cannot merge into one MSM without a
//   random linear combination, which would trade determinism for speed — so
//   `PedersenCommitment::batch_verify` is a thin batch API (~1x, honestly).
//
// Either way the arithmetic underneath is curve25519-dalek's, which on x86_64
// ALSO re-dispatches serial-vs-AVX2 at runtime via CPUID — the `cfg` gates
// here only label the build (see `msm_backend_name`), they never change the
// result. Measurement on the reference host (x86_64, AVX2 silicon;
// `benches/privacy_batch.rs`): fold and MSM agree byte-for-byte at every
// size. No raw `core::arch` kernels exist in this crate, deliberately: the
// library already saturates that layer, and the crossover measured identical
// with and without `RUSTFLAGS="-C target-feature=+avx2"`.

/// Below this many (point, scalar) terms the plain scalar fold is used.
/// At or above it the sum goes to `RistrettoPoint::vartime_multiscalar_mul`
/// (AVX2 Pippenger on capable x86_64 via dalek's runtime dispatch). Both
/// compute the identical group sum, so the choice never affects consensus
/// bytes.
///
/// A single value, deliberately NOT split by `cfg(target_feature)`: the
/// crossover was measured in both a portable build and an
/// `RUSTFLAGS="-C target-feature=+avx2"` build and is identical (MSM wins
/// for nontrivial scalars at every n ≥ 1 in both; additions crush
/// unit-scalar MSM ~8x in both), because the field arithmetic lives inside
/// curve25519-dalek either way. The `cfg(target_feature)` gates in this
/// module therefore only label the build ([`msm_backend_name`]) — there is
/// no compile-time-SIMD-dependent branch, by measurement, not by omission.
pub const MSM_FOLD_CUTOFF: usize = 2;

/// Build-time SIMD capability label for this crate's compilation.
///
/// Informational only (bench logs, operator visibility): the actual
/// vectorized field arithmetic lives inside curve25519-dalek 4.x, which needs
/// no cargo feature and no RUSTFLAGS — on x86_64 it runtime-dispatches to
/// AVX2 via CPUID. A `portable-build` label therefore does NOT mean "no
/// SIMD": it means this crate added no further compile-time vectorization on
/// top, because measurement showed dalek already saturates that layer.
pub fn msm_backend_name() -> &'static str {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    return "dalek-pippenger/avx2-build";
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    return "dalek-pippenger/neon-build";
    #[allow(unreachable_code)]
    "dalek-pippenger/portable-build (dalek still runtime-dispatches AVX2 on x86_64)"
}

/// Weighted Ristretto sum with backend selection.
///
/// Computes `sum_i scalars[i] * points[i]`, via the scalar fold below
/// [`MSM_FOLD_CUTOFF`] terms and via `vartime_multiscalar_mul` at or above
/// it. The two are the identical group sum (exact arithmetic, deterministic
/// encoding) — throughput only, never consensus-affecting. Panics on length
/// mismatch in debug; truncates to the shorter slice in release (all internal
/// callers pass equal lengths).
fn msm_sum(points: &[RistrettoPoint], scalars: &[Scalar]) -> RistrettoPoint {
    debug_assert_eq!(points.len(), scalars.len());
    let n = points.len().min(scalars.len());
    if n < MSM_FOLD_CUTOFF {
        let mut acc = RistrettoPoint::identity();
        for i in 0..n {
            acc += points[i] * scalars[i];
        }
        return acc;
    }
    RistrettoPoint::vartime_multiscalar_mul(&scalars[..n], &points[..n])
}

impl ConfidentialTransfer {
    /// Batched conservation check over many transfers.
    ///
    /// Returns one bool per transfer, in order; element `i` is BIT-IDENTICAL
    /// to `transfers[i].verify_balance_conservation()`, always — one call,
    /// one allocation, same equation per element.
    ///
    /// Deliberately NOT a merged MSM: a conservation sum has unit
    /// coefficients, and point additions beat Pippenger-with-ones ~8x at 64
    /// terms (measured; see the §9 note). A random linear combination across
    /// transfers could share one MSM but would make the result probabilistic,
    /// which the consensus rule forbids. Thin batch API, honestly ~1x.
    ///
    /// Pure-PQ: all-`false` when [`privacy_pq_refused`].
    pub fn batch_verify_balance_conservation(transfers: &[ConfidentialTransfer]) -> Vec<bool> {
        if privacy_pq_refused() {
            return vec![false; transfers.len()];
        }
        transfers
            .iter()
            .map(ConfidentialTransfer::verify_balance_conservation)
            .collect()
    }

    /// Batched conservation-plus-range verification over many proof bundles.
    ///
    /// Returns one bool per bundle, in order; element `i` is BIT-IDENTICAL to
    /// `bundles[i].0.verify_balanced_with_ranges(bundles[i].1, bundles[i].2)`,
    /// always — the same equation, the same count checks and the same
    /// [`RangeProof::batch_verify`] calls per bundle as the scalar path.
    ///
    /// Parallelism (audit: speed): bundles verify independently (pure function
    /// of the bundle bytes, no shared state), so at/above
    /// `PAR_BALANCED_VERIFY_MIN_BUNDLES` they run across cores via rayon with
    /// an order-preserving collect — deterministic bit-identically on every
    /// node. Below the threshold the sequential loop wins (the pool
    /// round-trip dominates microsecond verifies). This is the primitive the
    /// block-path range-proof pre-pass is built on.
    ///
    /// Pure-PQ: all-`false` when [`privacy_pq_refused`].
    pub fn batch_verify_balanced_with_ranges(
        bundles: &[(&ConfidentialTransfer, &[RangeProof], &[RangeProof])],
    ) -> Vec<bool> {
        if privacy_pq_refused() {
            return vec![false; bundles.len()];
        }
        const PAR_BALANCED_VERIFY_MIN_BUNDLES: usize = 4;
        if bundles.len() >= PAR_BALANCED_VERIFY_MIN_BUNDLES {
            use rayon::prelude::*;
            bundles
                .par_iter()
                .map(|(t, i, o)| t.verify_balanced_with_ranges(i, o))
                .collect()
        } else {
            bundles
                .iter()
                .map(|(t, i, o)| t.verify_balanced_with_ranges(i, o))
                .collect()
        }
    }
}

// ============================================================================
// §9 Confidential on-chain engine: shielded state + a committed domain
// ============================================================================
//
// This is the ENGINE/API layer for confidential transfers. It is deliberately
// pure and deterministic: no clock, no randomness, `BTreeMap`/`BTreeSet` only,
// every length written explicitly. The coordinator folds
// `write_confidential_domain` into `commitment::commitment_digest` later and
// wires the opcode handler that calls `apply_transfer`; neither of those lives
// here, so this file can be tested (and reasoned about) in isolation.

/// The all-zero Ristretto encoding is the identity point, i.e. a commitment to
/// zero with zero blinding. An account with no shielded history has this balance.
pub const ZERO_COMMITMENT: PedersenCommitment = PedersenCommitment {
    commitment: [0u8; 32],
};

/// Why a confidential transfer could not be applied to shielded state.
///
/// Every variant is a pure, deterministic rejection: `apply_transfer` is
/// all-or-nothing, so on error the state is byte-for-byte what it was before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfidentialError {
    /// A transfer must consume at least one input and create at least one output.
    EmptyTransfer,
    /// A commitment field did not decode to a valid Ristretto point.
    InvalidCommitment([u8; 32]),
    /// `sum(C_in) - sum(C_out) != fee*G`: the transfer invents or destroys value.
    ConservationViolated,
    /// The same input commitment appears twice inside one transfer.
    DuplicateInput([u8; 32]),
    /// An input commitment was already spent by an earlier applied transfer.
    DoubleSpend([u8; 32]),
    /// Accumulating the fee would overflow `u64`.
    FeeOverflow,
    /// An input names a commitment the sender does not own (audit 2026-10-06,
    /// F-A fix: first-spender-wins spending of anyone's commitments).
    NotOwner([u8; 32]),
    /// A shield/unshield opening does not recompute to the commitment.
    BadOpening([u8; 32]),
    /// Range-proof count does not match the commitment count (fail-closed:
    /// a confidential input/output without its positional proof is
    /// unspendable — there is no fallback, no skipping, no equation-only
    /// path).
    MissingRangeProof,
    /// A range proof failed verification: the commitment is NOT proven in
    /// [0, 2^bits) and may encode a negative/wrapped value. Carries the
    /// commitment bytes whose proof failed.
    InvalidRangeProof([u8; 32]),
    /// Pure-PQ enforcement refused a classical Ristretto op: the chain runs
    /// with `STELL_PURE_PQ=1` / `--pure-pq` and shielded (Ristretto) crypto
    /// is Shor-breakable. No fallback was attempted; resubmit on a PQ path
    /// once the hash-commitment + Falcon migration lands (see module header).
    /// Carries no secret material by construction (unit variant).
    PurePqRefused,
}

impl std::fmt::Display for ConfidentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfidentialError::EmptyTransfer => write!(f, "transfer has no inputs or no outputs"),
            ConfidentialError::InvalidCommitment(c) => {
                write!(
                    f,
                    "commitment is not a valid Ristretto point: {}",
                    hex::encode(c)
                )
            }
            ConfidentialError::ConservationViolated => {
                write!(f, "input and output commitments do not balance to fee*G")
            }
            ConfidentialError::DuplicateInput(c) => {
                write!(
                    f,
                    "input commitment repeated in one transfer: {}",
                    hex::encode(c)
                )
            }
            ConfidentialError::DoubleSpend(c) => {
                write!(f, "input commitment already spent: {}", hex::encode(c))
            }
            ConfidentialError::FeeOverflow => write!(f, "accumulated fees overflow u64"),
            ConfidentialError::NotOwner(c) => {
                write!(
                    f,
                    "input commitment not owned by sender: {}",
                    hex::encode(c)
                )
            }
            ConfidentialError::BadOpening(c) => {
                write!(f, "commitment opening does not match: {}", hex::encode(c))
            }
            ConfidentialError::MissingRangeProof => {
                write!(
                    f,
                    "missing range proof: every confidential input and output \
                     must carry its positional range proof (fail-closed)"
                )
            }
            ConfidentialError::InvalidRangeProof(c) => {
                write!(
                    f,
                    "range proof failed: commitment {} not proven in [0, 2^bits) \
                     (possible negative/wrapped value)",
                    hex::encode(c)
                )
            }
            ConfidentialError::PurePqRefused => {
                write!(
                    f,
                    "Ristretto privacy refused under STELL_PURE_PQ=1 (pure-PQ mode)"
                )
            }
        }
    }
}

impl std::error::Error for ConfidentialError {}

/// Deterministic shielded-balance ledger.
///
/// * `balances` — account -> commitment to its shielded balance (`v*G + r*H`).
///   A missing account is the identity ([`ZERO_COMMITMENT`]).
/// * `spent` — the set of input-commitment encodings already consumed. This is
///   the double-spend nullifier set; membership is by exact commitment bytes.
/// * `total_fees` — the transparent fee total the pool has burned. A u64, so it
///   is committed exactly.
///
/// Every container is ordered by its contents, so two nodes with identical
/// shielded state iterate in identical order and the committed digest below is
/// a pure function of the state, never of insertion or hashing order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialState {
    pub balances: BTreeMap<[u8; 32], PedersenCommitment>,
    pub spent: BTreeSet<[u8; 32]>,
    pub total_fees: u64,
    /// Output commitment -> owning account (audit 2026-10-06, F-A fix).
    /// Every shielded output is recorded here at creation (shield entry or
    /// transfer output); spending deletes the entry. Inputs must name
    /// commitments owned by the SENDER — without this, any signer could
    /// spend anyone's commitments (first-spender-wins) and mint from nothing.
    /// Committed + digested like the other fields (conditional empty).
    pub owned: BTreeMap<[u8; 32], [u8; 32]>,
}

/// Pre-ownership snapshot shape (no `owned` map). Kept ONLY for reading old
/// snapshots; `upgrade` starts with no ownership records. On a chain with
/// pre-fix shielded activity the old outputs are unattributed — they can
/// only be spent via... nothing: unowned inputs are rejected, so pre-fix
/// coins are FROZEN (not stealable, not spendable) until an explicit
/// migration. On a fresh/test chain the map starts empty and exact.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfidentialStateV1 {
    pub balances: BTreeMap<[u8; 32], PedersenCommitment>,
    pub spent: BTreeSet<[u8; 32]>,
    pub total_fees: u64,
}

impl ConfidentialStateV1 {
    pub fn upgrade(self) -> ConfidentialState {
        ConfidentialState {
            balances: self.balances,
            spent: self.spent,
            total_fees: self.total_fees,
            owned: BTreeMap::new(),
        }
    }
}

impl ConfidentialState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty = contributes nothing to a parent digest. An empty shielded ledger
    /// is indistinguishable from "this chain has never used confidential
    /// transfers", which is what keeps the genesis root unchanged.
    pub fn is_empty(&self) -> bool {
        self.balances.is_empty()
            && self.spent.is_empty()
            && self.total_fees == 0
            && self.owned.is_empty()
    }

    pub fn len(&self) -> usize {
        self.balances.len()
    }

    /// The account's shielded balance commitment, or the zero commitment if it
    /// has none. Consensus reads must not distinguish "absent" from "committed
    /// to zero with zero blinding": both are the identity point.
    pub fn balance(&self, account: &[u8; 32]) -> PedersenCommitment {
        self.balances
            .get(account)
            .copied()
            .unwrap_or(ZERO_COMMITMENT)
    }

    pub fn is_spent(&self, commitment: &[u8; 32]) -> bool {
        self.spent.contains(commitment)
    }

    /// True when the commitment is currently recorded as someone's unspent coin.
    pub fn is_owned(&self, commitment: &[u8; 32]) -> bool {
        self.owned.contains_key(commitment)
    }

    /// Apply a confidential transfer from `sender` to `recipient`.
    ///
    /// Checks, in order, all before touching state:
    /// 1. non-empty input and output sets;
    /// 2. every commitment decodes to a valid Ristretto point;
    /// 3. no input is repeated within this transfer;
    /// 4. every input is recorded as OWNED by the sender (audit 2026-10-06:
    ///    without this any signer could spend anyone's commitments);
    /// 5. no input is already in the spent set (double-spend);
    /// 6. value conservation: `sum(C_in) - sum(C_out) == fee*G` (range
    ///    soundness itself is enforced by the opcode handler, which requires
    ///    per-commitment range proofs — see `verify_balanced_with_ranges` —
    ///    or, for direct pool callers, by `apply_transfer_with_ranges`, which
    ///    is the ONLY fail-closed entry point: this bare method checks the
    ///    equation only and MUST NOT be used as a solvency gate);
    /// 7. the fee total does not overflow.
    ///
    /// On success the sender's commitment is debited by `sum(C_in)`, the
    /// recipient's is credited by `sum(C_out)` (combined correctly when
    /// `sender == recipient`), every input joins the spent set AND leaves
    /// the ownership map, every output is recorded as owned by the
    /// recipient, and the fee total advances.
    pub fn apply_transfer(
        &mut self,
        sender: &[u8; 32],
        recipient: &[u8; 32],
        tx: &ConfidentialTransfer,
    ) -> Result<(), ConfidentialError> {
        ensure_classical_allowed()?;
        if tx.input_commitments.is_empty() || tx.output_commitments.is_empty() {
            return Err(ConfidentialError::EmptyTransfer);
        }

        let sum_in = sum_points(&tx.input_commitments)?;
        let sum_out = sum_points(&tx.output_commitments)?;

        // Intra-transfer duplicate inputs: a multiset is required for the sum to
        // mean anything, and rejecting them early keeps the spent set exact.
        for (i, c) in tx.input_commitments.iter().enumerate() {
            if tx.input_commitments[..i]
                .iter()
                .any(|p| p.commitment == c.commitment)
            {
                return Err(ConfidentialError::DuplicateInput(c.commitment));
            }
        }

        for c in &tx.input_commitments {
            if self.spent.contains(&c.commitment) {
                return Err(ConfidentialError::DoubleSpend(c.commitment));
            }
        }

        // Ownership: every input must be recorded as the sender's. The map
        // is populated at output creation (shield entry or transfer output
        // to this sender) and cleared at spend, so only the funded owner
        // can move a commitment — and unowned/fresh commitments are
        // unspendable, which is what makes the pool closed under the
        // conservation equation (no minting from nothing).
        for c in &tx.input_commitments {
            match self.owned.get(&c.commitment) {
                Some(owner) if owner == sender => {}
                _ => return Err(ConfidentialError::NotOwner(c.commitment)),
            }
        }

        let fee_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(tx.fee);
        if sum_in - sum_out != fee_point {
            return Err(ConfidentialError::ConservationViolated);
        }

        let new_fees = self
            .total_fees
            .checked_add(tx.fee)
            .ok_or(ConfidentialError::FeeOverflow)?;

        // All checks passed: mutate. Decode the touched balances only now.
        if sender == recipient {
            let combined = decode_commitment(&self.balance(sender))? - sum_in + sum_out;
            self.balances.insert(*sender, encode_point(combined));
        } else {
            let new_sender = decode_commitment(&self.balance(sender))? - sum_in;
            let new_recipient = decode_commitment(&self.balance(recipient))? + sum_out;
            self.balances.insert(*sender, encode_point(new_sender));
            self.balances
                .insert(*recipient, encode_point(new_recipient));
        }
        for c in &tx.input_commitments {
            self.spent.insert(c.commitment);
            self.owned.remove(&c.commitment);
        }
        for c in &tx.output_commitments {
            self.owned.insert(c.commitment, *recipient);
        }
        self.total_fees = new_fees;
        Ok(())
    }

    /// Read-only, fail-closed solvency gate (F-A fix): the balance equation
    /// AND per-input/per-output non-negativity (positional range proofs, each
    /// proving [0, 2^bits) hence [0, 2^64)) AND spent-set/ownership membership,
    /// checked atomically — any single failure rejects the whole transfer and
    /// nothing is accepted partially. Pure: never mutates.
    ///
    /// Check order mirrors [`Self::apply_transfer`] (duplicates, spent,
    /// ownership, conservation, fee overflow) with the range-shape check
    /// FIRST, before any state read: a missing proof is
    /// [`ConfidentialError::MissingRangeProof`], a failed proof is
    /// [`ConfidentialError::InvalidRangeProof`]. There is no fallback — an
    /// input that cannot prove non-negativity is unspendable, full stop.
    pub fn verify_transfer_with_ranges(
        &self,
        sender: &[u8; 32],
        tx: &ConfidentialTransfer,
        input_ranges: &[RangeProof],
        output_ranges: &[RangeProof],
    ) -> Result<(), ConfidentialError> {
        ensure_classical_allowed()?;
        if tx.input_commitments.is_empty() || tx.output_commitments.is_empty() {
            return Err(ConfidentialError::EmptyTransfer);
        }
        // 1. Non-negativity first, fail-closed (no equation-only fallback).
        tx.verify_ranges(input_ranges, output_ranges)?;
        // 2. Intra-transfer duplicate inputs.
        for (i, c) in tx.input_commitments.iter().enumerate() {
            if tx.input_commitments[..i]
                .iter()
                .any(|p| p.commitment == c.commitment)
            {
                return Err(ConfidentialError::DuplicateInput(c.commitment));
            }
        }
        // 3. Spent set (double-spend) before ownership, like apply_transfer.
        for c in &tx.input_commitments {
            if self.spent.contains(&c.commitment) {
                return Err(ConfidentialError::DoubleSpend(c.commitment));
            }
        }
        // 4. Ownership: every input recorded as the sender's.
        for c in &tx.input_commitments {
            match self.owned.get(&c.commitment) {
                Some(owner) if owner == sender => {}
                _ => return Err(ConfidentialError::NotOwner(c.commitment)),
            }
        }
        // 5. Conservation (same equation as apply_transfer, surfacing
        //    InvalidCommitment for undecodable points exactly like it).
        let sum_in = sum_points(&tx.input_commitments)?;
        let sum_out = sum_points(&tx.output_commitments)?;
        let fee_point = RISTRETTO_BASEPOINT_POINT * Scalar::from(tx.fee);
        if sum_in - sum_out != fee_point {
            return Err(ConfidentialError::ConservationViolated);
        }
        // 6. Fee total must not overflow (checked, not mutated).
        self.total_fees
            .checked_add(tx.fee)
            .ok_or(ConfidentialError::FeeOverflow)?;
        Ok(())
    }

    /// Fail-closed shielded transfer (F-A fix): runs
    /// [`Self::verify_transfer_with_ranges`] first — balance equation,
    /// per-commitment range proofs, spent-set and ownership, atomically —
    /// and only then delegates to [`Self::apply_transfer`], which re-checks
    /// the state predicates and mutates only on full success. New pool
    /// callers (including any unshield/entry-exit feature) MUST use this,
    /// never the bare `apply_transfer`.
    ///
    /// SVM-PATH EQUIVALENCE (audit C1, verified — no exploit gap): the live
    /// `SysCallConfidentialTransfer2` handler runs
    /// `verify_balanced_with_ranges` (equation + positional range proofs,
    /// fail-closed on count/mismatch) BEFORE `apply_transfer`
    /// (points/duplicates/spent/ownership/conservation/fee-overflow) in the
    /// same synchronous handler with no interleaving, and its preverify
    /// cache skips ONLY the stateless range part — so the two-step verdict
    /// is identical to this atomic call on every input. The residual risk is
    /// direct pool callers reaching the bare method (whose own docs forbid
    /// it as a solvency gate). HARDENING PRECONDITION (deferred, one line):
    /// switch that handler to this single call — same verdict, removes the
    /// only bare-`apply_transfer` call on a money path; it lives in
    /// `src/svm.rs`, outside this module.
    pub fn apply_transfer_with_ranges(
        &mut self,
        sender: &[u8; 32],
        recipient: &[u8; 32],
        tx: &ConfidentialTransfer,
        input_ranges: &[RangeProof],
        output_ranges: &[RangeProof],
    ) -> Result<(), ConfidentialError> {
        self.verify_transfer_with_ranges(sender, tx, input_ranges, output_ranges)?;
        self.apply_transfer(sender, recipient, tx)
    }

    /// Record a shielded output as owned by `owner` (shield entry: native
    /// funds enter the pool and become a spendable commitment).
    pub fn note_shielded_output(&mut self, owner: &[u8; 32], commitment: [u8; 32]) {
        self.owned.insert(commitment, *owner);
    }

    /// Verify that `(amount, blinding)` opens `commitment`, i.e.
    /// `commit(amount, blinding) == commitment`. The exact check behind both
    /// shield entry and unshield exit (no range proof can bind a VALUE —
    /// only an opening can).
    ///
    /// Pure-PQ: `false` when [`privacy_pq_refused`].
    pub fn verify_opening(commitment: &[u8; 32], amount: u64, blinding: &[u8; 32]) -> bool {
        if privacy_pq_refused() {
            return false;
        }
        let b = match Scalar::from_canonical_bytes(*blinding).into_option() {
            Some(b) => b,
            None => return false,
        };
        let expect = PedersenCommitment::commit(amount, &b);
        expect.commitment == *commitment
    }

    /// Retire owned inputs for an unshield exit: each must be owned by the
    /// sender, unspent, and open to its declared amount. Returns the total
    /// native value to release. Mutates only on full success (checked first,
    /// applied after — same discipline as `apply_transfer`).
    ///
    /// Non-negativity needs no range proof here (F-A note): the opening
    /// recompute binds a `u64` amount, so negative/wrapped values are
    /// unrepresentable by construction — unlike blind transfers, where only
    /// `verify_transfer_with_ranges`/`apply_transfer_with_ranges` close that
    /// hole.
    pub fn retire_for_unshield(
        &mut self,
        sender: &[u8; 32],
        inputs: &[UnshieldInput],
    ) -> Result<u64, ConfidentialError> {
        ensure_classical_allowed()?;
        if inputs.is_empty() {
            return Err(ConfidentialError::EmptyTransfer);
        }
        // Duplicate inputs would double-count the same coin (audit 2026-10-06:
        // CRITICAL — one owned coin listed twice paid out 2X from escrow).
        // Mirror apply_transfer: reject before totaling, before mutating.
        for (i, inp) in inputs.iter().enumerate() {
            if inputs[..i].iter().any(|p| p.commitment == inp.commitment) {
                return Err(ConfidentialError::DuplicateInput(inp.commitment));
            }
        }
        let mut total = 0u64;
        for inp in inputs {
            if !Self::verify_opening(&inp.commitment, inp.amount, &inp.blinding) {
                return Err(ConfidentialError::BadOpening(inp.commitment));
            }
            match self.owned.get(&inp.commitment) {
                Some(owner) if owner == sender => {}
                _ => return Err(ConfidentialError::NotOwner(inp.commitment)),
            }
            if self.spent.contains(&inp.commitment) {
                return Err(ConfidentialError::DoubleSpend(inp.commitment));
            }
            total = total
                .checked_add(inp.amount)
                .ok_or(ConfidentialError::FeeOverflow)?;
        }
        for inp in inputs {
            self.spent.insert(inp.commitment);
            self.owned.remove(&inp.commitment);
        }
        Ok(total)
    }
}

fn decode_commitment(c: &PedersenCommitment) -> Result<RistrettoPoint, ConfidentialError> {
    CompressedRistretto(c.commitment)
        .decompress()
        .ok_or(ConfidentialError::InvalidCommitment(c.commitment))
}

fn encode_point(p: RistrettoPoint) -> PedersenCommitment {
    PedersenCommitment {
        commitment: p.compress().to_bytes(),
    }
}

/// Variable-base fold for commitment summation: the engine folds
/// input/output commitments through here. Stays a plain addition fold —
/// measured ~8x faster than Pippenger-with-unit-scalars at 64 terms
/// (additions are ns, variable-base muls are us; no MSM can beat adding).
/// See the §9 note: MSM applies to weighted sums, not unit sums.
fn sum_points(commitments: &[PedersenCommitment]) -> Result<RistrettoPoint, ConfidentialError> {
    let mut acc = RistrettoPoint::identity();
    for c in commitments {
        acc += decode_commitment(c)?;
    }
    Ok(acc)
}

/// Domain tag for the committed shielded-balance domain.
pub const CONFIDENTIAL_DOMAIN_TAG: &[u8] = b"STELL_CONFIDENTIAL_STATE_V1";

/// Native escrow backing the shielded pool (audit 2026-10-06, F-A fix):
/// every shield entry debits the sender and credits this account; every
/// unshield exit debits it and credits the exitor. The account is therefore
/// an auditable conservation check — its balance must always equal total
/// shielded outstanding minus burned fees. Distinct from STAKING_POOL (0x53)
/// and BRIDGE_ESCROW (0xB7) by construction.
pub const SHIELD_ESCROW: [u8; 32] = [0xC0; 32];

fn put_bytes<S: crate::commitment::PreimageSink>(h: &mut S, tag: &[u8], bytes: &[u8]) {
    h.push_preimage(&(tag.len() as u64).to_be_bytes());
    h.push_preimage(tag);
    h.push_preimage(&(bytes.len() as u64).to_be_bytes());
    h.push_preimage(bytes);
}

fn put_u64<S: crate::commitment::PreimageSink>(h: &mut S, tag: &[u8], v: u64) {
    put_bytes(h, tag, &v.to_be_bytes());
}

fn put_addr<S: crate::commitment::PreimageSink>(h: &mut S, tag: &[u8], v: &[u8; 32]) {
    put_bytes(h, tag, v);
}

/// Fold the shielded-balance domain into an existing hasher.
///
/// CONDITIONAL, exactly like the session-key domain: an EMPTY state writes
/// zero bytes, so `commitment_digest` can append this unconditionally and a
/// chain that has never used a confidential transfer keeps the byte-identical
/// genesis root (COMMITMENT_VERSION stays 4). Inside the domain nothing is
/// conditional: balances are walked in `BTreeMap` (key) order, the spent set in
/// `BTreeSet` order, and every collection's length is written so two different
/// states cannot encode to the same preimage.
pub fn write_confidential_domain<S: crate::commitment::PreimageSink>(
    h: &mut S,
    state: &ConfidentialState,
) {
    if state.is_empty() {
        return;
    }
    put_bytes(h, b"confidential_domain", CONFIDENTIAL_DOMAIN_TAG);
    put_u64(h, b"confidential_balances_len", state.balances.len() as u64);
    for (account, c) in &state.balances {
        put_addr(h, b"confidential_account", account);
        put_bytes(h, b"confidential_balance", &c.commitment);
    }
    put_u64(h, b"confidential_spent_len", state.spent.len() as u64);
    for c in &state.spent {
        put_bytes(h, b"confidential_spent", c);
    }
    put_u64(h, b"confidential_total_fees", state.total_fees);
    // Ownership map (F-A): SELF-CONDITIONAL — written only when non-empty.
    // A bare len:0 would still change the preimage for pre-ownership
    // snapshots (non-empty balances, no owned map), breaking restore-root
    // verification on upgrade (observed live: node refused to start). With
    // the gate, old states digest BYTE-IDENTICALLY and new ones include it.
    if !state.owned.is_empty() {
        put_u64(h, b"confidential_owned_len", state.owned.len() as u64);
        for (commitment, owner) in &state.owned {
            put_bytes(h, b"confidential_owned_commitment", commitment);
            put_addr(h, b"confidential_owned_owner", owner);
        }
    }
}

/// Standalone digest of the shielded-balance domain.
///
/// Two identical states digest identically and any mutation (a balance flip, a
/// new spent input, a changed fee total) changes the digest. This is the value
/// the coordinator appends to the consensus commitment.
pub fn confidential_digest(state: &ConfidentialState) -> [u8; 32] {
    let mut h = Sha256::new();
    write_confidential_domain(&mut h, state);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_range_proof_verifies() {
        let r = PedersenCommitment::random_blinding();
        let v = 123_456u64;
        let c = PedersenCommitment::commit(v, &r);
        let proof = RangeProof::prove(&c, v, &r, 32);
        assert!(RangeProof::verify(&c, &proof));
    }

    #[test]
    fn range_proof_rejects_wrong_commitment() {
        let r = PedersenCommitment::random_blinding();
        let c = PedersenCommitment::commit(100, &r);
        let proof = RangeProof::prove(&c, 100, &r, 32);
        let other = PedersenCommitment::commit(101, &r);
        assert!(!RangeProof::verify(&other, &proof));
    }

    #[test]
    fn tampered_bit_commitment_rejected() {
        let r = PedersenCommitment::random_blinding();
        let c = PedersenCommitment::commit(5, &r);
        let mut proof = RangeProof::prove(&c, 5, &r, 8);
        proof.bit_commitments[0] =
            PedersenCommitment::commit(1, &PedersenCommitment::random_blinding());
        assert!(!RangeProof::verify(&c, &proof));
    }

    #[test]
    #[should_panic(expected = "value does not fit")]
    fn out_of_range_value_cannot_be_proven() {
        let r = PedersenCommitment::random_blinding();
        let v = 1u64 << 8; // needs 9 bits
        let c = PedersenCommitment::commit(v, &r);
        let _ = RangeProof::prove(&c, v, &r, 8);
    }

    #[test]
    fn confidential_transfer_with_range_proofs_is_sound() {
        let r1 = PedersenCommitment::random_blinding();
        let r2 = PedersenCommitment::random_blinding();
        let c1 = PedersenCommitment::commit(1_000, &r1);
        let c2 = PedersenCommitment::commit(500, &r2);
        let c_out = PedersenCommitment::commit(1_480, &(r1 + r2));
        let tx = ConfidentialTransfer::new(vec![c1, c2], vec![c_out], 20);
        // The group equation alone holds...
        assert!(tx.verify_balance_conservation());
        // ...and with range proofs the transfer is sound.
        let in_ranges = vec![
            RangeProof::prove(&c1, 1_000, &r1, 32),
            RangeProof::prove(&c2, 500, &r2, 32),
        ];
        let out_ranges = vec![RangeProof::prove(&c_out, 1_480, &(r1 + r2), 32)];
        assert!(tx.verify_balanced_with_ranges(&in_ranges, &out_ranges));
        // Missing proofs are rejected.
        assert!(!tx.verify_balanced_with_ranges(&in_ranges, &[]));
    }

    /// §9 differential: the backend-selected sum is the scalar fold,
    /// byte-for-byte, at every size including both sides of the cutoff.
    #[test]
    fn msm_sum_matches_scalar_fold_byte_for_byte() {
        let mut rng = OsRng;
        for n in [0usize, 1, 2, 3, 4, 5, 7, 8, 9, 16, 33, 64] {
            let points: Vec<RistrettoPoint> = (0..n)
                .map(|_| RISTRETTO_BASEPOINT_POINT * Scalar::random(&mut rng))
                .collect();
            let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let mut expected = RistrettoPoint::identity();
            for (p, s) in points.iter().zip(scalars.iter()) {
                expected += p * s;
            }
            assert_eq!(
                msm_sum(&points, &scalars).compress().to_bytes(),
                expected.compress().to_bytes(),
                "fold/MSM diverged at n={n} (backend={})",
                msm_backend_name(),
            );
        }
    }

    /// §9 differential: the batched conservation entry point agrees with the
    /// scalar equation on valid, forged, empty and malformed inputs.
    #[test]
    fn conservation_batch_matches_scalar_equation() {
        let r = Scalar::from(0x5EED_u64);
        let good = ConfidentialTransfer::new(
            vec![PedersenCommitment::commit(1_000, &r)],
            vec![PedersenCommitment::commit(980, &r)],
            20,
        );
        let forged = ConfidentialTransfer::new(
            vec![PedersenCommitment::commit(100, &r)],
            vec![PedersenCommitment::commit(1_000, &r)],
            0,
        );
        let empty = ConfidentialTransfer::new(vec![], vec![], 0);
        let junk = ConfidentialTransfer::new(
            vec![PedersenCommitment {
                commitment: [0xFF; 32],
            }],
            vec![PedersenCommitment::commit(0, &Scalar::from(1u64))],
            0,
        );
        let txs = vec![good, forged, empty, junk];
        let scalar: Vec<bool> = txs
            .iter()
            .map(|t| t.verify_balance_conservation())
            .collect();
        assert_eq!(scalar, vec![true, false, false, false]);
        assert_eq!(
            ConfidentialTransfer::batch_verify_balance_conservation(&txs),
            scalar
        );
    }

    /// §9 differential: the MSM `BitProof::verify` agrees with the scalar
    /// reference twin on honest proofs, wrong-commitment proofs and garbage.
    #[test]
    fn bitproof_msm_matches_scalar_twin() {
        let r = Scalar::random(&mut OsRng);
        for bit in [false, true] {
            let c = PedersenCommitment::commit(bit as u64, &r);
            let proof = BitProof::prove(&c, bit, &r);
            assert!(BitProof::verify(&c, &proof));
            assert!(BitProof::verify_scalar(&c, &proof));
        }
        // Wrong commitment, tampered proof bytes, undecodable commitment.
        let r2 = Scalar::random(&mut OsRng);
        let c = PedersenCommitment::commit(1, &r2);
        let proof = BitProof::prove(&c, true, &r2);
        let other = PedersenCommitment::commit(0, &r2);
        assert!(!BitProof::verify(&other, &proof));
        assert!(!BitProof::verify_scalar(&other, &proof));
        let mut bad = proof.clone();
        bad.s0[0] ^= 0xFF;
        // Tampering may or may not flip the verdict, but both paths agree.
        assert_eq!(
            BitProof::verify(&c, &bad),
            BitProof::verify_scalar(&c, &bad)
        );
        let junk = PedersenCommitment {
            commitment: [0xFF; 32],
        };
        assert!(!BitProof::verify(&junk, &proof));
        assert!(!BitProof::verify_scalar(&junk, &proof));
    }

    #[test]
    fn test_full_stealth_payment_cycle() {
        let mut rng = OsRng;

        // Bob's viewing key and spend key
        let bob_view_priv = Scalar::random(&mut rng);
        let bob_view_pub = (RISTRETTO_BASEPOINT_POINT * bob_view_priv)
            .compress()
            .to_bytes();
        let bob_spend_priv = Scalar::random(&mut rng);
        let bob_spend_pub = (RISTRETTO_BASEPOINT_POINT * bob_spend_priv)
            .compress()
            .to_bytes();

        // Charlie's viewing key and spend key
        let charlie_view_priv = Scalar::random(&mut rng);
        let charlie_spend_priv = Scalar::random(&mut rng);
        let charlie_spend_pub = (RISTRETTO_BASEPOINT_POINT * charlie_spend_priv)
            .compress()
            .to_bytes();

        // Alice generates StealthAddress for Bob using Bob's view_pub and spend_pub
        let stealth = StealthAddress::generate(&bob_view_pub, &bob_spend_pub)
            .expect("StealthAddress generation should succeed");

        // Bob verifies stealth.is_for_recipient(&bob_view_priv, &bob_spend_pub) == Some(true)
        assert_eq!(
            stealth.is_for_recipient(&bob_view_priv, &bob_spend_pub),
            Some(true),
            "Bob must identify stealth address as his"
        );

        // Charlie verifies stealth.is_for_recipient(&charlie_view_priv, &charlie_spend_pub) == Some(false)
        assert_eq!(
            stealth.is_for_recipient(&charlie_view_priv, &charlie_spend_pub),
            Some(false),
            "Charlie must not identify Bob's stealth address as his"
        );

        // Bob derives one_time_priv = stealth.derive_one_time_private_key(&bob_view_priv, &bob_spend_priv).unwrap()
        let one_time_priv = stealth
            .derive_one_time_private_key(&bob_view_priv, &bob_spend_priv)
            .expect("Bob should derive one-time private key");

        // Assert that RISTRETTO_BASEPOINT_POINT * one_time_priv matches stealth.one_time_pub!
        assert_eq!(
            (RISTRETTO_BASEPOINT_POINT * one_time_priv)
                .compress()
                .to_bytes(),
            stealth.one_time_pub,
            "Compressed point of one_time_priv must match stealth.one_time_pub"
        );
        assert_eq!(
            RISTRETTO_BASEPOINT_POINT * one_time_priv,
            CompressedRistretto(stealth.one_time_pub)
                .decompress()
                .unwrap(),
            "Ristretto point of one_time_priv must match decompressed stealth.one_time_pub"
        );

        // Bob signs a message with one_time_priv, verifies signature against stealth.one_time_pub
        let message = b"Confidential stealth payment payload authorization";
        let sig = stealth.sign(&one_time_priv, message);

        assert!(
            StealthAddress::verify_one_time_signature(&stealth.one_time_pub, message, &sig),
            "Signature must verify against stealth.one_time_pub"
        );
        assert!(
            stealth.verify_signature(message, &sig),
            "Signature must verify via stealth.verify_signature"
        );
        assert!(
            verify_stealth_signature(&stealth.one_time_pub, message, &sig),
            "Signature must verify via verify_stealth_signature"
        );

        // Tampered message rejected
        assert!(
            !stealth.verify_signature(b"Forged message payload", &sig),
            "Tampered message must fail verification"
        );

        // Tampered signature rejected
        let mut tampered_sig = sig;
        tampered_sig[0] ^= 0x42;
        assert!(
            !stealth.verify_signature(message, &tampered_sig),
            "Tampered signature must fail verification"
        );

        // Wrong public key rejected
        assert!(
            !StealthAddress::verify_one_time_signature(&bob_spend_pub, message, &sig),
            "Signature must not verify against Bob's base spend pubkey"
        );
        assert!(
            !StealthAddress::verify_one_time_signature(&charlie_spend_pub, message, &sig),
            "Signature must not verify against Charlie's spend pubkey"
        );
    }

    /// AUDIT W6.5: the viewing key is a SECRET and must never be printed.
    #[test]
    fn viewing_key_debug_never_prints_the_private_key() {
        let vk = ViewingKey::derive_from_seed(&[0x7Bu8; 32]);
        let printed = format!("{vk:?}");
        assert!(
            !printed.contains(&hex::encode(vk.view_priv)),
            "the viewing PRIVATE key must not appear in the Debug output: {printed}"
        );
        assert!(!printed.contains(&hex::encode(vk.view_priv)[..16]));
        assert!(printed.contains("REDACTED"));
        // The public half is fine to show.
        assert!(printed.contains(&hex::encode(vk.view_pub)[..16]));
    }

    /// AUDIT W6.5 (fail closed): the derived one-time key must belong to the
    /// stealth address it is derived from.
    ///
    /// A mismatched view key (or spend key) used to yield a usable private
    /// key for a DIFFERENT address — the caller would sign with it and the
    /// funds would go to an address nobody controls.
    #[test]
    fn one_time_private_key_derivation_is_bound_to_the_address() {
        let bob_seed = [0x42u8; 32];
        let bob_vk = ViewingKey::derive_from_seed(&bob_seed);
        let (bob_spend_priv, bob_spend_pub) = ViewingKey::derive_spend_key(&bob_seed);
        let charlie_seed = [0x99u8; 32];
        let charlie_vk = ViewingKey::derive_from_seed(&charlie_seed);
        let (charlie_spend_priv, _charlie_spend_pub) = ViewingKey::derive_spend_key(&charlie_seed);

        let stealth = StealthAddress::generate(&bob_vk.view_pub, &bob_spend_pub).unwrap();

        // The honest derivation still works.
        assert!(stealth
            .derive_one_time_private_key(&bob_vk.private_scalar(), &bob_spend_priv)
            .is_some());

        // The WRONG view key must NOT produce a key for this address.
        assert!(
            stealth
                .derive_one_time_private_key(&charlie_vk.private_scalar(), &bob_spend_priv)
                .is_none(),
            "a mismatched view key must not yield a one-time key for this address"
        );
        // The WRONG spend key must not either.
        assert!(
            stealth
                .derive_one_time_private_key(&bob_vk.private_scalar(), &charlie_spend_priv)
                .is_none(),
            "a mismatched spend key must not yield a one-time key for this address"
        );
    }

    #[test]
    fn test_viewing_key_derivation_and_stealth_lifecycle() {
        let bob_seed = [0x42u8; 32];
        let bob_vk = ViewingKey::derive_from_seed(&bob_seed);
        let (bob_spend_priv, bob_spend_pub) = ViewingKey::derive_spend_key(&bob_seed);

        // Check deterministic alias
        assert_eq!(ViewingKey::from_seed(&bob_seed).view_pub, bob_vk.view_pub);
        assert_eq!(
            ViewingKey::from_scalar(&bob_vk.private_scalar()).view_pub,
            bob_vk.view_pub
        );

        let charlie_seed = [0x99u8; 32];
        let charlie_vk = ViewingKey::derive_from_seed(&charlie_seed);
        let (_charlie_spend_priv, charlie_spend_pub) = ViewingKey::derive_spend_key(&charlie_seed);

        // Alice generates stealth address for Bob
        let stealth = StealthAddress::generate(&bob_vk.view_pub, &bob_spend_pub)
            .expect("Stealth address generation succeeds");

        // Bob identifies it via ViewingKey helper
        assert_eq!(
            bob_vk.is_for_recipient(&stealth, &bob_spend_pub),
            Some(true)
        );
        // Charlie does not
        assert_eq!(
            charlie_vk.is_for_recipient(&stealth, &charlie_spend_pub),
            Some(false)
        );

        // Bob derives one-time private key via ViewingKey helper
        let one_time_priv = bob_vk
            .derive_one_time_private_key(&stealth, &bob_spend_priv)
            .expect("Derived one-time private key");

        // Verification equation holds
        assert_eq!(
            (RISTRETTO_BASEPOINT_POINT * one_time_priv)
                .compress()
                .to_bytes(),
            stealth.one_time_pub
        );
        assert_eq!(
            RISTRETTO_BASEPOINT_POINT * one_time_priv,
            CompressedRistretto(stealth.one_time_pub)
                .decompress()
                .unwrap()
        );

        // Bob signs and verifies
        let memo = b"Audited fund transfer transaction";
        let sig = sign_stealth_message(&one_time_priv, memo);
        assert!(verify_stealth_signature(&stealth.one_time_pub, memo, &sig));
        assert!(!verify_stealth_signature(
            &stealth.one_time_pub,
            b"Altered memo",
            &sig
        ));
    }
}
#[cfg(test)]
mod auto_bits_tests {
    use super::*;

    #[test]
    fn bits_for_value_boundary() {
        assert_eq!(RangeProof::bits_for_value(0), 32);
        assert_eq!(RangeProof::bits_for_value(1), 32);
        assert_eq!(RangeProof::bits_for_value((1u64 << 32) - 1), 32);
        assert_eq!(RangeProof::bits_for_value(1u64 << 32), 64);
        assert_eq!(RangeProof::bits_for_value(u64::MAX), 64);
    }

    #[test]
    fn prove_auto_round_trips_both_widths() {
        for v in [
            0u64,
            1,
            100,
            (1u64 << 32) - 1,
            1u64 << 32,
            5_000_000_000,
            u64::MAX >> 1,
        ] {
            let r = Scalar::from(v.wrapping_add(7));
            let c = PedersenCommitment::commit(v, &r);
            let p = RangeProof::prove_auto(&c, v, &r);
            assert_eq!(p.bits, RangeProof::bits_for_value(v));
            assert!(RangeProof::verify(&c, &p), "auto proof must verify for {v}");
        }
    }

    #[test]
    fn batch_verify_is_deterministic_across_widths() {
        // Same verdicts as scalar loop, mixed 32/64 in one batch.
        let r = Scalar::from(99u64);
        let c1 = PedersenCommitment::commit(100, &r);
        let c2 = PedersenCommitment::commit(1u64 << 40, &r);
        let p1 = RangeProof::prove_auto(&c1, 100, &r);
        let p2 = RangeProof::prove_auto(&c2, 1u64 << 40, &r);
        assert_eq!(p1.bits, 32);
        assert_eq!(p2.bits, 64);
        let pairs = [(&c1, &p1), (&c2, &p2)];
        let got = RangeProof::batch_verify(&pairs);
        let want: Vec<bool> = pairs
            .iter()
            .map(|(c, p)| RangeProof::verify(c, p))
            .collect();
        assert_eq!(got, want);
        assert_eq!(got, vec![true, true]);
    }
}
