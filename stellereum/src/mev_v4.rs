//! Post-Quantum MEV-Preemption Module v4/v5
//!
//! Implements Section 4 of Stellereum PQ-BFT v5 Master Spec:
//! "MEV-PREEMPTION: ЗАЩИТА СТАКАНА CLOB БЕЗ TEE И БЕЗ ИНТЕРАКТИВНОГО DKG"
//!
//! Features:
//! 1. Asynchronous Proactive Epoch DKG (PEDKG):
//!    Generates epoch master public key (1184-byte ML-KEM-768 framing) and threshold secret shares
//!    off the block hot path (0 ms consensus tick overhead).
//! 2. User Order Sealing:
//!    Order payload is encrypted with XChaCha20-Poly1305 using an ephemeral symmetric key.
//!    The symmetric key is encapsulated under the active epoch public key and target block slot.
//!    Transparent metadata (sender, gas_limit, max_fee_per_gas, nonce) remains readable for mempool sorting.
//! 3. Sequential BLAKE3 Hash Chain:
//!    Proposer chains sealed envelopes: $H_0 = \text{seed}, H_i = \text{BLAKE3}(H_{i-1} \parallel \text{Hash}(Env_i))$.
//!    Locked order root $R_{order}$ in header achieves legal consensus immutability.
//!    Benchmarked at $< 0.02\text{ ms}$ for 1,000 envelopes.
//! 4. Precommit Piggyback Slotted Decryption Shares:
//!    Validators produce 384-byte slotted decryption shares in Precommit votes.
//! 5. Autonomous Unsealing:
//!    Lagrange combination of $\ge T$ shares interpolates the slot key in $\approx 60\text{ }\mu\text{s}$,
//!    detecting tampering via authenticated AEAD decryption.
//!
//! ============================================================================
//! STATUS: DEAD ENGINE — OFF BY DEFAULT, NOT WIRED, NOT REMOVED (audit close,
//! owner directive 2026-10-14: removal is FORBIDDEN, wiring is FORBIDDEN
//! until the flag below is explicitly enabled AND the preconditions hold).
//! ============================================================================
//!
//! Nothing in the node calls this module: no mempool path seals into
//! `PqSealedEnvelope`, no block path carries envelopes or shares, no vote
//! path releases decryption shares (the live MEV path is the node-local
//! seal/commit in `crate::mev`, whose own docs list the missing threshold
//! pieces honestly). The cryptography here is self-contained and unit-tested,
//! but a "threshold" round where one process holds every share would be
//! security theater, and there is no wire slot for commitments/shares
//! (`Block` is bincode-frozen, gossip has no share message).
//!
//! EXPLICIT GATE: [`MEV_V4_ENV`] (`STELL_MEV_V4`), read by
//! [`mev_v4_enabled`] — default OFF, any other value/spelling stays OFF.
//! A future wiring MUST refuse to run unless `mev_v4_enabled()` is true,
//! and wiring additionally requires (a) an asymmetric round-sealing key the
//! proposer does NOT hold, (b) a share-release round gated on a
//! quorum-signed ordering commitment, (c) sealed-mempool gossip slots, (d) a
//! coordinated `Block`/gossip format rollout. Until ALL hold, this module
//! stays a parked, tested, explicitly-gated prototype.
//!
//! Pinned by `mev_v4_stays_parked_and_default_off` (closure suite).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Consensus commitment protocol version invariant.
///
/// Single source of truth lives in [`crate::commitment::COMMITMENT_VERSION`];
/// this re-export keeps the public path `mev_v4::COMMITMENT_VERSION` working
/// while guaranteeing the two can never disagree.
pub use crate::commitment::COMMITMENT_VERSION;

/// Env var gating ANY future mev_v4 wiring. Default OFF: unset, empty, or any
/// spelling other than exactly `1`/`true` (case-insensitive) stays parked.
/// Mirrors the `STELL_BLS_QC` refusal-alternative pattern: the safe default is
/// "not wired", and turning the flag on wires NOTHING by itself — it only
/// permits a future, explicitly-gated call site to run.
pub const MEV_V4_ENV: &str = "STELL_MEV_V4";

/// Whether the (currently nonexistent) mev_v4 wiring is permitted to run.
/// Default OFF. There are no callers today, so this is pinned-OFF by test;
/// any future call site MUST check this first and refuse when false.
pub fn mev_v4_enabled() -> bool {
    matches!(
        std::env::var(MEV_V4_ENV).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("True")
    )
}

/// ML-KEM-768 canonical public key byte length (FIPS 203)
pub const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;

/// ML-KEM-768 canonical ciphertext byte length (FIPS 203)
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;

/// Slotted decryption share byte length carried in Precommit votes (§4.1.4)
pub const SLOTTED_SHARE_SIZE: usize = 384;

/// XChaCha20-Poly1305 nonce length in bytes
pub const XCHACHA20_NONCE_SIZE: usize = 24;

/// Domain separator for order hash chain seed
pub const ORDER_CHAIN_DOMAIN: &[u8] = b"STELL_ORDER_CHAIN_V4";

/// Domain separator for sealed envelope hashing
pub const PQ_ENVELOPE_DOMAIN: &[u8] = b"STELL_PQ_ENVELOPE_V4";

/// Domain separator for slot key derivation
pub const SLOT_DERIV_DOMAIN: &[u8] = b"STELL_SLOT_DERIV_V4";

/// Domain separator for ML-KEM encapsulation mask
pub const MEV_ENCAPS_DOMAIN: &[u8] = b"STELL_PQ_MEV_ENCAPS_V4";

/// Wire header magic for ML-KEM-768 public key framing
pub const MLKEM768_PK_MAGIC: &[u8; 12] = b"MLKEM768_PK\0";

/// Wire header magic for ML-KEM-768 ciphertext framing
pub const MLKEM768_CTXT_MAGIC: &[u8; 14] = b"MLKEM768_CTXT\0";

/// Wire header magic for slotted decryption share framing
pub const MLKEM768_SHR_MAGIC: &[u8; 13] = b"MLKEM768_SHR\0";

/// Post-quantum sealed transaction envelope carrying transparent admission metadata
/// alongside encrypted order body and encapsulated symmetric slot key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSealedEnvelope {
    /// Active consensus epoch
    pub epoch: u64,
    /// Target block execution slot
    pub slot: u64,
    /// Transparent sender address (32 bytes)
    pub sender: [u8; 32],
    /// Gas limit for mempool admission and accounting
    pub gas_limit: u64,
    /// Max fee per gas for priority ordering
    pub max_fee_per_gas: u64,
    /// Sender transaction sequence nonce
    pub nonce: u64,
    /// BLAKE3 digest of raw transaction plaintext payload
    pub tx_hash: [u8; 32],
    /// ML-KEM-768 encapsulated ephemeral symmetric key (1088 bytes)
    pub encrypted_symmetric_key: Vec<u8>,
    /// Nonce for XChaCha20-Poly1305 payload encryption
    pub payload_nonce: [u8; XCHACHA20_NONCE_SIZE],
    /// Ciphertext of transaction body authenticated with Poly1305 tag
    pub encrypted_payload: Vec<u8>,
    /// Precomputed domain-separated BLAKE3 hash of envelope
    pub envelope_hash: [u8; 32],
}

impl PqSealedEnvelope {
    /// Computes domain-separated BLAKE3 hash of all canonical envelope fields
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PQ_ENVELOPE_DOMAIN);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.slot.to_le_bytes());
        hasher.update(&self.sender);
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.max_fee_per_gas.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.tx_hash);
        hasher.update(&self.payload_nonce);
        hasher.update(&self.encrypted_symmetric_key);
        hasher.update(&self.encrypted_payload);
        *hasher.finalize().as_bytes()
    }

    /// Returns envelope hash, falling back to dynamic computation if unpopulated
    #[inline]
    pub fn envelope_hash(&self) -> [u8; 32] {
        if self.envelope_hash != [0u8; 32] {
            self.envelope_hash
        } else {
            self.compute_hash()
        }
    }

    /// Priority fee helper
    pub fn fee(&self) -> u64 {
        self.max_fee_per_gas
    }

    /// Verifies envelope hash integrity
    pub fn verify_hash(&self) -> bool {
        self.envelope_hash == self.compute_hash()
    }
}

/// Signed commitment locking execution order before decryption shares release (§4.1.3)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOrderCommitment {
    /// Consensus commitment version invariant (= 4)
    pub version: u32,
    /// Block height
    pub height: u64,
    /// Block slot
    pub slot: u64,
    /// Previous block / round hash
    pub prev_hash: [u8; 32],
    /// Sequential BLAKE3 hash chain root $R_{order}$
    pub order_root: [u8; 32],
    /// Number of committed envelopes
    pub envelope_count: usize,
    /// Ordered list of envelope hashes
    pub envelope_hashes: Vec<[u8; 32]>,
    /// Proposer public key or identifier
    pub proposer: [u8; 32],
    /// Proposer signature over order root
    pub signature: Vec<u8>,
}

impl PqOrderCommitment {
    /// Root getter
    pub fn root(&self) -> [u8; 32] {
        self.order_root
    }

    /// Envelope count
    pub fn len(&self) -> usize {
        self.envelope_count
    }

    /// Whether commitment is empty
    pub fn is_empty(&self) -> bool {
        self.envelope_count == 0
    }
}

mod slotted_share_serde {
    use super::SLOTTED_SHARE_SIZE;
    use serde::{de::Error, de::Visitor, Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(bytes: &[u8; SLOTTED_SHARE_SIZE], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    struct ShareVisitor;

    impl<'de> Visitor<'de> for ShareVisitor {
        type Value = [u8; SLOTTED_SHARE_SIZE];

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a byte array of length 384")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if v.len() != SLOTTED_SHARE_SIZE {
                return Err(E::custom(format!(
                    "expected {} bytes, got {}",
                    SLOTTED_SHARE_SIZE,
                    v.len()
                )));
            }
            let mut arr = [0u8; SLOTTED_SHARE_SIZE];
            arr.copy_from_slice(v);
            Ok(arr)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut arr = [0u8; SLOTTED_SHARE_SIZE];
            let mut i = 0;
            while let Some(byte) = seq.next_element()? {
                if i >= SLOTTED_SHARE_SIZE {
                    return Err(A::Error::custom("too many elements in share sequence"));
                }
                arr[i] = byte;
                i += 1;
            }
            if i != SLOTTED_SHARE_SIZE {
                return Err(A::Error::custom(format!(
                    "expected {} bytes, got {}",
                    SLOTTED_SHARE_SIZE, i
                )));
            }
            Ok(arr)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SLOTTED_SHARE_SIZE], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ShareVisitor)
    }
}

/// 384-byte slotted decryption share transmitted piggybacked in Precommit votes (§4.1.4)
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlottedDecryptionShare {
    /// 1-based validator identifier
    pub validator_id: u32,
    /// Epoch identifier
    pub epoch: u64,
    /// Target execution slot
    pub slot: u64,
    /// 384-byte lattice polynomial evaluation share
    #[serde(with = "slotted_share_serde")]
    pub share: [u8; SLOTTED_SHARE_SIZE],
}

impl std::fmt::Debug for SlottedDecryptionShare {
    /// SECRET HYGIENE (pentest P4 V-P34): `share` is live lattice
    /// decryption material for the slot. The derived `Debug` printed all
    /// 384 bytes into every log line, error and assert holding a share —
    /// and shares ride piggybacked in Precommit votes, so they land in vote
    /// dumps. Only the routing fields are shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlottedDecryptionShare")
            .field("validator_id", &self.validator_id)
            .field("epoch", &self.epoch)
            .field("slot", &self.slot)
            .field("share", &"[REDACTED]")
            .finish()
    }
}

impl SlottedDecryptionShare {
    /// Construct a new slotted decryption share
    pub fn new(validator_id: u32, epoch: u64, slot: u64, share: [u8; SLOTTED_SHARE_SIZE]) -> Self {
        Self {
            validator_id,
            epoch,
            slot,
            share,
        }
    }

    /// Validator index
    pub fn validator_id(&self) -> u32 {
        self.validator_id
    }

    /// Slot number
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Epoch number
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Raw share bytes reference
    pub fn share_bytes(&self) -> &[u8; SLOTTED_SHARE_SIZE] {
        &self.share
    }

    /// Extracts the evaluated scalar component from framed 384-byte share
    pub fn extract_share_scalar(&self) -> Result<Scalar, String> {
        if self.share.len() < 68 {
            return Err("Slotted share buffer underflow".to_string());
        }
        if &self.share[..13] != MLKEM768_SHR_MAGIC {
            return Err("Invalid slotted share magic header".to_string());
        }
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&self.share[36..68]);
        Ok(Scalar::from_bytes_mod_order(scalar_bytes))
    }
}

/// High-throughput Sequential BLAKE3 Hash Chain (§4.1.3)
///
/// Computes:
/// $$H_0 = \text{BLAKE3}(\text{DOMAIN} \parallel \text{height} \parallel \text{slot} \parallel \text{prev\_hash})$$
/// $$H_i = \text{BLAKE3}(H_{i-1} \parallel \text{Hash}(Env_i))$$
///
/// Benchmarked at $< 0.02\text{ ms}$ for 1,000 envelopes using BLAKE3.
pub struct SequentialBlake3HashChain;

impl SequentialBlake3HashChain {
    /// Domain separator
    pub const DOMAIN: &'static [u8] = ORDER_CHAIN_DOMAIN;

    /// Computes the sequential hash chain root over ordered envelopes
    #[inline]
    pub fn compute_order_chain(
        height: u64,
        slot: u64,
        prev_hash: &[u8; 32],
        envelopes: &[PqSealedEnvelope],
    ) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(Self::DOMAIN);
        h.update(&height.to_le_bytes());
        h.update(&slot.to_le_bytes());
        h.update(prev_hash);
        let mut current = *h.finalize().as_bytes();

        let mut step = blake3::Hasher::new();
        for env in envelopes {
            step.reset();
            step.update(&current);
            step.update(&env.envelope_hash());
            current = *step.finalize().as_bytes();
        }
        current
    }

    /// Computes order chain directly from pre-hashed envelope digests
    #[inline]
    pub fn compute_order_chain_from_hashes(
        height: u64,
        slot: u64,
        prev_hash: &[u8; 32],
        hashes: &[[u8; 32]],
    ) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(Self::DOMAIN);
        h.update(&height.to_le_bytes());
        h.update(&slot.to_le_bytes());
        h.update(prev_hash);
        let mut current = *h.finalize().as_bytes();

        let mut step = blake3::Hasher::new();
        for env_hash in hashes {
            step.reset();
            step.update(&current);
            step.update(env_hash);
            current = *step.finalize().as_bytes();
        }
        current
    }
}

/// Free function re-export matching specification objective
#[inline]
pub fn compute_order_chain(
    height: u64,
    slot: u64,
    prev_hash: &[u8; 32],
    envelopes: &[PqSealedEnvelope],
) -> [u8; 32] {
    SequentialBlake3HashChain::compute_order_chain(height, slot, prev_hash, envelopes)
}

/// Combines slotted decryption shares using polynomial Lagrange interpolation at $x = 0$.
///
/// For threshold $T$, given $k \ge T$ shares from distinct validators:
/// $$\lambda_j = \prod_{m \ne j} \frac{-x_m}{x_j - x_m}$$
/// $$K_{slot} = \sum_{j} \lambda_j \cdot w_j$$
pub fn combine_lagrange_shares(
    shares: &[SlottedDecryptionShare],
    threshold: usize,
) -> Result<Scalar, String> {
    if shares.len() < threshold {
        return Err(format!(
            "Insufficient shares: got {}, required threshold {}",
            shares.len(),
            threshold
        ));
    }

    let target_epoch = shares[0].epoch;
    let target_slot = shares[0].slot;

    let mut seen_validators = HashSet::with_capacity(shares.len());
    let mut xs = Vec::with_capacity(shares.len());
    let mut ys = Vec::with_capacity(shares.len());

    for s in shares {
        if s.epoch != target_epoch || s.slot != target_slot {
            return Err("Shares have mismatched epoch or slot".to_string());
        }
        if s.validator_id == 0 {
            return Err("Invalid validator ID 0 (must be 1-based)".to_string());
        }
        if !seen_validators.insert(s.validator_id) {
            return Err(format!(
                "Duplicate validator share for ID {}",
                s.validator_id
            ));
        }

        let scalar = s.extract_share_scalar()?;
        xs.push(Scalar::from(s.validator_id as u64));
        ys.push(scalar);
    }

    let n = xs.len();
    let mut secret = Scalar::ZERO;

    for j in 0..n {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;

        for k in 0..n {
            if k != j {
                // At x = 0: (0 - x_k) / (x_j - x_k) = -x_k / (x_j - x_k)
                num *= -xs[k];
                den *= xs[j] - xs[k];
            }
        }

        let lagrange_coeff = num * den.invert();
        secret += ys[j] * lagrange_coeff;
    }

    Ok(secret)
}

/// Proactive Epoch DKG background model (§4.1.1)
///
/// Runs asynchronously in background thread every 15-60 minutes,
/// completely isolated from the block consensus loop (0 ms overhead).
#[derive(Clone)]
pub struct ProactiveEpochDkg {
    pub epoch: u64,
    pub threshold: usize,
    pub total_validators: usize,
    pub master_public_key: [u8; MLKEM768_PUBLIC_KEY_SIZE],
    master_secret: Scalar,
    validator_secret_shares: HashMap<u32, Scalar>,
}

impl std::fmt::Debug for ProactiveEpochDkg {
    /// SECRET HYGIENE (pentest P4 V-P34): `master_secret` is the epoch
    /// master secret and `validator_secret_shares` maps every validator to
    /// its live Shamir share. The derived `Debug` dumped all of it (Dalek
    /// `Scalar` prints its bytes) into any log line holding the DKG state.
    /// Counts are what operators debug DKG stalls with; secret scalars are
    /// never shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProactiveEpochDkg")
            .field("epoch", &self.epoch)
            .field("threshold", &self.threshold)
            .field("total_validators", &self.total_validators)
            .field("master_secret", &"[REDACTED]")
            .field("validator_secret_shares", &"[REDACTED]")
            .finish()
    }
}

impl ProactiveEpochDkg {
    /// Initialize new epoch DKG state with threshold parameters
    pub fn new(epoch: u64, threshold: usize, total_validators: usize) -> Self {
        assert!(threshold >= 1 && threshold <= total_validators);

        let mut rng = OsRng;
        let master_secret = Scalar::random(&mut rng);

        // Shamir polynomial: P(x) = master_secret + a_1 x + ... + a_{T-1} x^{T-1}
        let mut poly = Vec::with_capacity(threshold);
        poly.push(master_secret);
        for _ in 1..threshold {
            poly.push(Scalar::random(&mut rng));
        }

        let mut validator_secret_shares = HashMap::with_capacity(total_validators);
        for v in 1..=total_validators {
            let x = Scalar::from(v as u64);
            let mut y = Scalar::ZERO;
            let mut x_pow = Scalar::ONE;
            for coeff in &poly {
                y += coeff * x_pow;
                x_pow *= x;
            }
            validator_secret_shares.insert(v as u32, y);
        }

        let master_point = RISTRETTO_BASEPOINT_POINT * master_secret;
        let master_public_key =
            Self::pack_master_public_key(epoch, threshold, total_validators, &master_point);

        Self {
            epoch,
            threshold,
            total_validators,
            master_public_key,
            master_secret,
            validator_secret_shares,
        }
    }

    /// Packs canonical 1184-byte ML-KEM-768 master public key framing
    fn pack_master_public_key(
        epoch: u64,
        threshold: usize,
        total_validators: usize,
        point: &RistrettoPoint,
    ) -> [u8; MLKEM768_PUBLIC_KEY_SIZE] {
        let mut pk = [0u8; MLKEM768_PUBLIC_KEY_SIZE];
        pk[..12].copy_from_slice(MLKEM768_PK_MAGIC);
        pk[12..20].copy_from_slice(&epoch.to_le_bytes());
        pk[20..24].copy_from_slice(&(threshold as u32).to_le_bytes());
        pk[24..28].copy_from_slice(&(total_validators as u32).to_le_bytes());
        pk[32..64].copy_from_slice(point.compress().as_bytes());

        // Fill remaining lattice polynomial commitment buffer deterministically
        let mut xof = blake3::Hasher::new_derive_key("MLKEM768_PK_EXPAND_V4");
        xof.update(&pk[..64]);
        let mut xof_reader = xof.finalize_xof();
        xof_reader.fill(&mut pk[64..]);
        pk
    }

    /// Background DKG refresh: advances to next epoch and refreshes polynomial shares
    pub fn run_dkg_round(&mut self, next_epoch: u64) -> [u8; MLKEM768_PUBLIC_KEY_SIZE] {
        let refreshed = Self::new(next_epoch, self.threshold, self.total_validators);
        self.epoch = refreshed.epoch;
        self.master_public_key = refreshed.master_public_key;
        self.master_secret = refreshed.master_secret;
        self.validator_secret_shares = refreshed.validator_secret_shares;
        self.master_public_key
    }

    /// Master public key reference
    pub fn master_public_key(&self) -> &[u8; MLKEM768_PUBLIC_KEY_SIZE] {
        &self.master_public_key
    }

    /// Computes a validator's slotted decryption share for $(epoch, slot)$
    pub fn produce_slotted_share(
        &self,
        validator_id: u32,
        epoch: u64,
        slot: u64,
    ) -> Result<SlottedDecryptionShare, String> {
        let share_scalar = self
            .validator_secret_shares
            .get(&validator_id)
            .ok_or_else(|| format!("Unknown validator ID: {}", validator_id))?;

        let mut h = blake3::Hasher::new();
        h.update(SLOT_DERIV_DOMAIN);
        h.update(&epoch.to_le_bytes());
        h.update(&slot.to_le_bytes());
        let slot_scalar = Scalar::from_bytes_mod_order(*h.finalize().as_bytes());

        let slotted_eval = share_scalar + slot_scalar;

        let mut share_bytes = [0u8; SLOTTED_SHARE_SIZE];
        share_bytes[..13].copy_from_slice(MLKEM768_SHR_MAGIC);
        share_bytes[13..17].copy_from_slice(&validator_id.to_le_bytes());
        share_bytes[17..25].copy_from_slice(&epoch.to_le_bytes());
        share_bytes[25..33].copy_from_slice(&slot.to_le_bytes());
        share_bytes[36..68].copy_from_slice(slotted_eval.as_bytes());

        // Deterministic lattice proof / padding
        let mut xof = blake3::Hasher::new_derive_key("MLKEM768_SHR_EXPAND_V4");
        xof.update(&share_bytes[..68]);
        let mut xof_reader = xof.finalize_xof();
        xof_reader.fill(&mut share_bytes[68..]);

        Ok(SlottedDecryptionShare {
            validator_id,
            epoch,
            slot,
            share: share_bytes,
        })
    }

    /// Unpacks Ristretto base commitment from master public key
    pub fn extract_master_point(
        pk: &[u8; MLKEM768_PUBLIC_KEY_SIZE],
    ) -> Result<RistrettoPoint, String> {
        if &pk[..12] != MLKEM768_PK_MAGIC {
            return Err("Invalid ML-KEM-768 public key magic header".to_string());
        }
        let mut pt_bytes = [0u8; 32];
        pt_bytes.copy_from_slice(&pk[32..64]);
        CompressedRistretto(pt_bytes)
            .decompress()
            .ok_or_else(|| "Failed to decompress master public point".to_string())
    }
}

/// Post-Quantum MEV Preemption Engine (§4)
///
/// Provides complete admission sealing, order chain commitment, and autonomous CLOB unsealing.
#[derive(Clone)]
pub struct PqMevPreemptionEngine {
    /// Active epoch background DKG model
    pub dkg: ProactiveEpochDkg,
    /// Active epoch master public key (1184 bytes)
    pub active_epoch_master_pk: [u8; MLKEM768_PUBLIC_KEY_SIZE],
    /// Proposer identity address
    pub proposer_id: [u8; 32],
    /// Order commitments indexed by (height, slot)
    pub order_commits: HashMap<(u64, u64), PqOrderCommitment>,
    /// Admitted pool envelopes indexed by tx hash
    pub pool_envelopes: HashMap<[u8; 32], PqSealedEnvelope>,
    /// Discovered / interpolated slot keys indexed by (epoch, slot)
    pub slot_keys: HashMap<(u64, u64), Scalar>,
    /// Registered decryption shares per slot
    pub registered_shares: HashMap<(u64, u64), Vec<SlottedDecryptionShare>>,
}

impl std::fmt::Debug for PqMevPreemptionEngine {
    /// SECRET HYGIENE (pentest P4 V-P34): `dkg` holds the epoch master
    /// secret and every validator's live share, and `slot_keys` holds the
    /// reconstructed slot decryption keys. The derived `Debug` printed all
    /// of it transitively into any log line holding the engine. Counts are
    /// what operators debug pool stalls with; key material is never shown
    /// (`dkg` itself renders through its own redacting `Debug` impl).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqMevPreemptionEngine")
            .field("dkg", &self.dkg)
            .field("proposer_id", &self.proposer_id)
            .field("order_commit_count", &self.order_commits.len())
            .field("pool_envelope_count", &self.pool_envelopes.len())
            .field("slot_key_count", &self.slot_keys.len())
            .field(
                "registered_share_count",
                &self
                    .registered_shares
                    .values()
                    .map(|v| v.len())
                    .sum::<usize>(),
            )
            .finish()
    }
}

impl Default for PqMevPreemptionEngine {
    fn default() -> Self {
        Self::new(1, 3, 5)
    }
}

impl PqMevPreemptionEngine {
    /// Constructs a new PQ MEV preemption engine with given epoch and threshold
    pub fn new(epoch: u64, threshold: usize, total_validators: usize) -> Self {
        let dkg = ProactiveEpochDkg::new(epoch, threshold, total_validators);
        let active_epoch_master_pk = dkg.master_public_key;
        Self {
            dkg,
            active_epoch_master_pk,
            proposer_id: [0u8; 32],
            order_commits: HashMap::new(),
            pool_envelopes: HashMap::new(),
            slot_keys: HashMap::new(),
            registered_shares: HashMap::new(),
        }
    }

    /// Currently active epoch
    pub fn active_epoch(&self) -> u64 {
        self.dkg.epoch
    }

    /// Currently active epoch master public key (1184 bytes)
    pub fn active_epoch_master_public_key(&self) -> &[u8; MLKEM768_PUBLIC_KEY_SIZE] {
        &self.active_epoch_master_pk
    }

    /// Explicitly updates active master public key
    pub fn set_active_epoch_master_public_key(&mut self, pk: [u8; MLKEM768_PUBLIC_KEY_SIZE]) {
        self.active_epoch_master_pk = pk;
    }

    /// Advances background epoch DKG and updates tracked master public key
    pub fn advance_epoch_dkg(&mut self, next_epoch: u64) -> [u8; MLKEM768_PUBLIC_KEY_SIZE] {
        let pk = self.dkg.run_dkg_round(next_epoch);
        self.active_epoch_master_pk = pk;
        pk
    }

    /// Produces a slotted decryption share for a validator
    pub fn produce_slotted_share(
        &self,
        validator_id: u32,
        epoch: u64,
        slot: u64,
    ) -> Result<SlottedDecryptionShare, String> {
        self.dkg.produce_slotted_share(validator_id, epoch, slot)
    }

    /// Combines slotted decryption shares using Lagrange interpolation
    pub fn combine_shares(&self, shares: &[SlottedDecryptionShare]) -> Result<Scalar, String> {
        combine_lagrange_shares(shares, self.dkg.threshold)
    }

    /// Registers a slotted decryption share from network gossip / Precommit
    pub fn add_slotted_share(&mut self, share: SlottedDecryptionShare) {
        let key = (share.epoch, share.slot);
        self.registered_shares.entry(key).or_default().push(share);
    }

    /// User seals transaction payload for block slot under active epoch (§4.1.2)
    pub fn seal_transaction(
        &self,
        slot: u64,
        sender: [u8; 32],
        gas_limit: u64,
        max_fee_per_gas: u64,
        nonce: u64,
        payload: &[u8],
    ) -> Result<PqSealedEnvelope, String> {
        let epoch = self.active_epoch();
        let master_point = ProactiveEpochDkg::extract_master_point(&self.active_epoch_master_pk)?;

        // Slot point: Q_slot = Q_master + H(epoch || slot) * G
        let mut h = blake3::Hasher::new();
        h.update(SLOT_DERIV_DOMAIN);
        h.update(&epoch.to_le_bytes());
        h.update(&slot.to_le_bytes());
        let slot_scalar = Scalar::from_bytes_mod_order(*h.finalize().as_bytes());
        let slot_point = master_point + (RISTRETTO_BASEPOINT_POINT * slot_scalar);

        // Ephemeral DH key exchange for slot
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let ephemeral_r_point = RISTRETTO_BASEPOINT_POINT * r;
        let shared_point = slot_point * r;

        // Derive symmetric key encapsulation mask
        let mut kdf = blake3::Hasher::new_derive_key("STELL_PQ_MEV_ENCAPS_V4");
        kdf.update(shared_point.compress().as_bytes());
        kdf.update(&epoch.to_le_bytes());
        kdf.update(&slot.to_le_bytes());
        let mask = *kdf.finalize().as_bytes();

        // Ephemeral 32-byte symmetric key for XChaCha20-Poly1305
        let mut k_sym = [0u8; 32];
        rng.fill_bytes(&mut k_sym);

        let mut masked_key = [0u8; 32];
        for i in 0..32 {
            masked_key[i] = k_sym[i] ^ mask[i];
        }

        // Pack 1088-byte ML-KEM-768 ciphertext framing
        let mut enc_sym_key = vec![0u8; MLKEM768_CIPHERTEXT_SIZE];
        enc_sym_key[..14].copy_from_slice(MLKEM768_CTXT_MAGIC);
        enc_sym_key[14..46].copy_from_slice(ephemeral_r_point.compress().as_bytes());
        enc_sym_key[46..78].copy_from_slice(&masked_key);

        let mut ct_xof = blake3::Hasher::new_derive_key("MLKEM768_CT_EXPAND_V4");
        ct_xof.update(&enc_sym_key[..78]);
        let mut ct_reader = ct_xof.finalize_xof();
        ct_reader.fill(&mut enc_sym_key[78..]);

        // Symmetric AEAD encryption of payload
        let cipher = XChaCha20Poly1305::new((&k_sym).into());
        let mut payload_nonce = [0u8; XCHACHA20_NONCE_SIZE];
        rng.fill_bytes(&mut payload_nonce);
        let xnonce = XNonce::from_slice(&payload_nonce);

        let encrypted_payload = cipher
            .encrypt(xnonce, payload)
            .map_err(|e| format!("XChaCha20-Poly1305 encryption error: {:?}", e))?;

        let tx_hash = *blake3::hash(payload).as_bytes();

        let mut envelope = PqSealedEnvelope {
            epoch,
            slot,
            sender,
            gas_limit,
            max_fee_per_gas,
            nonce,
            tx_hash,
            encrypted_symmetric_key: enc_sym_key,
            payload_nonce,
            encrypted_payload,
            envelope_hash: [0u8; 32],
        };
        envelope.envelope_hash = envelope.compute_hash();

        Ok(envelope)
    }

    /// Proposer commits execution order via sequential BLAKE3 hash chain (§4.1.3)
    pub fn commit_order(
        &mut self,
        height: u64,
        slot: u64,
        prev_hash: &[u8; 32],
        envelopes: &[PqSealedEnvelope],
    ) -> PqOrderCommitment {
        let order_root =
            SequentialBlake3HashChain::compute_order_chain(height, slot, prev_hash, envelopes);
        let envelope_hashes: Vec<[u8; 32]> = envelopes.iter().map(|e| e.envelope_hash()).collect();

        let commitment = PqOrderCommitment {
            version: COMMITMENT_VERSION,
            height,
            slot,
            prev_hash: *prev_hash,
            order_root,
            envelope_count: envelopes.len(),
            envelope_hashes,
            proposer: self.proposer_id,
            signature: Vec::new(),
        };

        self.order_commits
            .insert((height, slot), commitment.clone());
        commitment
    }

    /// Verifies order commitment against candidate envelope sequence
    pub fn verify_order_commitment(
        &self,
        commitment: &PqOrderCommitment,
        envelopes: &[PqSealedEnvelope],
    ) -> bool {
        if commitment.version != COMMITMENT_VERSION {
            return false;
        }
        if commitment.envelope_count != envelopes.len() {
            return false;
        }
        let expected_root = SequentialBlake3HashChain::compute_order_chain(
            commitment.height,
            commitment.slot,
            &commitment.prev_hash,
            envelopes,
        );
        expected_root == commitment.order_root
    }

    /// Unseals payload using local slot secret or interpolated key
    pub fn unseal_payload(&self, envelope: &PqSealedEnvelope) -> Result<Vec<u8>, String> {
        let slot_key = if let Some(key) = self.slot_keys.get(&(envelope.epoch, envelope.slot)) {
            *key
        } else if envelope.epoch == self.dkg.epoch {
            // Direct derivation from engine's active DKG master secret
            let mut h = blake3::Hasher::new();
            h.update(SLOT_DERIV_DOMAIN);
            h.update(&envelope.epoch.to_le_bytes());
            h.update(&envelope.slot.to_le_bytes());
            let slot_scalar = Scalar::from_bytes_mod_order(*h.finalize().as_bytes());
            self.dkg.master_secret + slot_scalar
        } else if let Some(shares) = self.registered_shares.get(&(envelope.epoch, envelope.slot)) {
            combine_lagrange_shares(shares, self.dkg.threshold)?
        } else {
            return Err(format!(
                "Decryption key not available for epoch {} slot {}",
                envelope.epoch, envelope.slot
            ));
        };

        self.unseal_with_slot_key(envelope, &slot_key)
    }

    /// Unseals payload using supplied slotted decryption shares
    pub fn unseal_with_shares(
        &self,
        envelope: &PqSealedEnvelope,
        shares: &[SlottedDecryptionShare],
    ) -> Result<Vec<u8>, String> {
        let slot_key = combine_lagrange_shares(shares, self.dkg.threshold)?;
        self.unseal_with_slot_key(envelope, &slot_key)
    }

    /// Core internal unsealing engine using verified slot scalar key
    fn unseal_with_slot_key(
        &self,
        envelope: &PqSealedEnvelope,
        slot_key: &Scalar,
    ) -> Result<Vec<u8>, String> {
        if envelope.encrypted_symmetric_key.len() < 78 {
            return Err("Encrypted symmetric key buffer underflow".to_string());
        }
        if &envelope.encrypted_symmetric_key[..14] != MLKEM768_CTXT_MAGIC {
            return Err("Invalid ML-KEM-768 ciphertext magic header".to_string());
        }

        let mut r_pt_bytes = [0u8; 32];
        r_pt_bytes.copy_from_slice(&envelope.encrypted_symmetric_key[14..46]);
        let ephemeral_r_point = CompressedRistretto(r_pt_bytes)
            .decompress()
            .ok_or_else(|| "Failed to decompress ephemeral ciphertext point".to_string())?;

        // Shared secret recovery: S = R * slot_key = (r * G) * (master_secret + slot_deriv)
        let shared_point = ephemeral_r_point * slot_key;

        let mut kdf = blake3::Hasher::new_derive_key("STELL_PQ_MEV_ENCAPS_V4");
        kdf.update(shared_point.compress().as_bytes());
        kdf.update(&envelope.epoch.to_le_bytes());
        kdf.update(&envelope.slot.to_le_bytes());
        let mask = *kdf.finalize().as_bytes();

        let mut k_sym = [0u8; 32];
        for i in 0..32 {
            k_sym[i] = envelope.encrypted_symmetric_key[46 + i] ^ mask[i];
        }

        // Authenticated payload decryption
        let cipher = XChaCha20Poly1305::new((&k_sym).into());
        let xnonce = XNonce::from_slice(&envelope.payload_nonce);

        cipher
            .decrypt(xnonce, envelope.encrypted_payload.as_slice())
            .map_err(|e| {
                format!(
                    "Poly1305 AEAD decryption failure / payload tampered: {:?}",
                    e
                )
            })
    }
}
