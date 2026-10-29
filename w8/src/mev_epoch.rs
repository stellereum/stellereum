//! EPOCH SEAL (ES1) — asymmetric, threshold-sealed transaction gossip.
//!
//! This module replaces the node-local "blind round" of [`crate::mev`] (whose
//! key lives in ONE process, so it hides nothing from that process) with a
//! scheme whose secret is SHARED by the validator committee:
//!
//! * **Epoch key.** Every epoch (128 blocks) has an X25519-family *epoch
//!   public key* `P_e` (a Ristretto255 point) and a matching secret `x_e`
//!   that is split with Shamir over the epoch committee. The public key is
//!   the AGGREGATE of the committee members' public key material: every
//!   member contributes a Feldman commitment to its share polynomial, and
//!   `P_e` is the sum of the constant-term commitments.
//! * **Sealing.** A wallet encrypts its transaction to `P_e` (an ephemeral
//!   Diffie-Hellman + XChaCha20-Poly1305). The ciphertext — not the
//!   plaintext — is what the mempool stores and what the gossip carries.
//! * **Ordering first, reveal second.** The proposer commits to the ORDER of
//!   the sealed transactions (an order Merkle root over the sealed
//!   transaction hashes) BEFORE any decryption material is released. Only
//!   after that commitment do the committee members release their
//!   *decryption partials* for that round.
//! * **Threshold.** A decryption partial is `C^x_i` for the sealed
//!   ciphertext's ephemeral point `C`. Any `t` partials reconstruct the
//!   Diffie-Hellman secret (Lagrange interpolation in the exponent), so a
//!   member that withholds its partial cannot stall the round: `t < n`
//!   partials still unseal, and if fewer than `t` arrive the sealed
//!   transaction is DROPPED with its fee charged (fail-closed, never a stall).
//!
//! # Why Ristretto255 and not raw X25519
//!
//! X25519 clamps its scalar input, and clamping is NOT a linear map: the
//! Shamir reconstruction `sum(lambda_i * x_i)` would not survive it. The
//! threshold arithmetic therefore runs in the prime-order Ristretto255 group
//! (the cofactorless group underlying Ed25519), where scalar multiplication
//! is exactly linear. X25519 is still used for the one place that needs a
//! raw Diffie-Hellman (the encrypted key-share packages of the DKG).
//!
//! # What this does and does not protect against
//!
//! See `docs/MEV.md` for the full statement. In short: it hides the
//! transaction CONTENT from a passive network observer and from a mempool
//! snooper until the ordering is committed. It does NOT hide the ordering
//! (the block lists the transactions in order), it does not stop a malicious
//! proposer from withholding its reveal, and it does not stop a malicious
//! proposer from front-running with its OWN transaction.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

/// Blocks per MEV epoch. The epoch key rotates every this many blocks.
pub const EPOCH_BLOCKS: u64 = 128;

/// Domain separator of the epoch committee hash.
pub const COMMITTEE_DOMAIN: &[u8; 22] = b"STELL_MEV_COMMITTEE_V1";
/// Domain separator of the epoch seed (the DKG's public randomness).
pub const EPOCH_SEED_DOMAIN: &[u8; 23] = b"STELL_MEV_EPOCH_SEED_V1";
/// Domain separator of the per-validator share polynomial.
pub const DKG_POLY_DOMAIN: &[u8; 21] = b"STELL_MEV_DKG_POLY_V1";
/// Domain separator of the payload key-derivation function.
pub const SEAL_KDF_DOMAIN: &[u8; 21] = b"STELL_MEV_SEAL_KDF_V1";
/// Domain separator of the sealed-payload associated data.
pub const SEAL_AAD_DOMAIN: &[u8; 21] = b"STELL_MEV_SEAL_AAD_V1";
/// Domain separator of the epoch-key announcement signature.
pub const EPOCH_ANNOUNCE_SIG_DOMAIN: &[u8; 29] = b"STELL_MEV_EPOCH_ANNOUNCE_SIG1";
/// Domain separator of the round order-commitment signature.
pub const ORDER_COMMIT_SIG_DOMAIN: &[u8; 27] = b"STELL_MEV_ORDER_COMMIT_SIG1";
/// Domain separator of the DKG transcript root.
pub const TRANSCRIPT_DOMAIN: &[u8; 23] = b"STELL_MEV_TRANSCRIPT_V1";

/// Maximum size of a sealed payload (ciphertext) accepted from the wire.
pub const MAX_SEALED_PAYLOAD: usize = 1 << 20; // 1 MiB

/// The MEV epoch a height belongs to.
#[inline]
pub fn epoch_of_height(height: u64) -> u64 {
    height / EPOCH_BLOCKS
}

/// The threshold of a committee of `n` members.
///
/// `t` is the number of decryption partials needed to unseal. The formula
/// keeps `t < n` for every `n >= 3`, so ONE member may withhold its partial
/// without stalling the round (the proposer unseals with the others). For
/// `n <= 2` the threshold is `n`: a two-member committee has no majority
/// that tolerates a withholding member, and dropping to `t = 1` would let a
/// single member read every sealed transaction. The timeout path (drop the
/// transaction, charge the fee) is the fallback there.
pub fn threshold_for(n: usize) -> usize {
    match n {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => {
            // floor(2*(n-1)/3) + 1: strictly below n for n >= 3.
            let t = (2 * (n - 1)) / 3 + 1;
            t.clamp(2, n - 1)
        }
    }
}

/// Hash-to-scalar over a domain-separated message (modulo the group order).
fn hash_to_scalar(domain: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    Scalar::from_bytes_mod_order(*hasher.finalize().as_bytes())
}

/// BLAKE3 domain-separated digest of the parts.
fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

/// Decompress a Ristretto point, rejecting anything that is not a valid
/// group element (fail closed: a malformed point must never be accepted
/// as a key or a partial).
fn decompress_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).ok().and_then(|c| c.decompress())
}

// ===========================================================================
// Committee
// ===========================================================================

/// One member of an epoch committee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMember {
    /// The validator's consensus identity (its Ed25519 public key).
    pub validator_id: [u8; 32],
    /// The member's X25519 encryption key (the DKG share packages are
    /// encrypted to it). Derived deterministically from the validator's
    /// long-term Ed25519 secret; published in the DKG contribution.
    pub enc_pk: [u8; 32],
}

/// The ordered committee of one MEV epoch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochCommittee {
    pub epoch: u64,
    /// Members in the CANONICAL order (ascending `validator_id`): the index
    /// of a member (1-based) is its Shamir abscissa, so the order MUST be
    /// the same on every node or the shares would not line up.
    pub members: Vec<CommitteeMember>,
    /// Number of decryption partials needed to unseal.
    pub threshold: usize,
    /// BLAKE3 digest of the committee (epoch + members). Bound into the
    /// sealed payload's associated data, so a ciphertext sealed for one
    /// committee can never be replayed into another epoch.
    pub hash: [u8; 32],
}

impl EpochCommittee {
    /// Build a committee from `(validator_id, enc_pk)` pairs.
    ///
    /// The pairs are SORTED by `validator_id` so every node derives the same
    /// committee (and therefore the same Shamir abscissae) from the same
    /// validator set.
    pub fn build(epoch: u64, mut members: Vec<CommitteeMember>) -> EpochCommittee {
        members.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        members.dedup_by(|a, b| a.validator_id == b.validator_id);
        let threshold = threshold_for(members.len());
        let epoch_bytes = epoch.to_be_bytes();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + members.len() * 2);
        parts.push(&epoch_bytes);
        for m in &members {
            parts.push(&m.validator_id);
            parts.push(&m.enc_pk);
        }
        let hash = hash_parts(COMMITTEE_DOMAIN, &parts);
        EpochCommittee {
            epoch,
            members,
            threshold,
            hash,
        }
    }

    /// The 1-based index of a member (its Shamir abscissa).
    pub fn index_of(&self, validator_id: &[u8; 32]) -> Option<u32> {
        self.members
            .iter()
            .position(|m| &m.validator_id == validator_id)
            .map(|i| i as u32 + 1)
    }

    /// The member at a 1-based index.
    pub fn member_at(&self, index: u32) -> Option<&CommitteeMember> {
        if index == 0 {
            return None;
        }
        self.members.get(index as usize - 1)
    }
}

// ===========================================================================
// Epoch key material
// ===========================================================================

/// The epoch public key: what a wallet encrypts to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochPublicKey {
    pub epoch: u64,
    /// The compressed Ristretto255 epoch public key (the aggregate of the
    /// committee members' constant-term commitments).
    pub public_key: [u8; 32],
    /// The committee hash (bound into the sealed payload's AAD).
    pub committee_hash: [u8; 32],
    /// The number of decryption partials needed to unseal.
    pub threshold: usize,
}

/// The epoch key material a committee member holds after the DKG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochKeyMaterial {
    pub epoch: u64,
    /// The epoch public key (same for every member).
    pub public_key: [u8; 32],
    /// THIS member's Shamir share of the epoch secret (a canonical scalar).
    pub share: [u8; 32],
    /// The committee hash.
    pub committee_hash: [u8; 32],
    /// The root of the DKG transcript (binds every contribution).
    pub transcript_root: [u8; 32],
    /// The threshold.
    pub threshold: usize,
}

impl EpochKeyMaterial {
    /// The public half of the key material (what a wallet encrypts to).
    pub fn public_key(&self) -> EpochPublicKey {
        EpochPublicKey {
            epoch: self.epoch,
            public_key: self.public_key,
            committee_hash: self.committee_hash,
            threshold: self.threshold,
        }
    }
}

// ===========================================================================
// DKG
// ===========================================================================

/// One encrypted key-share package of the DKG.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedShare {
    /// The 1-based committee index of the recipient.
    pub recipient_index: u32,
    /// The ephemeral X25519 public key of the package.
    pub ephemeral_pk: [u8; 32],
    /// The XChaCha20-Poly1305 nonce.
    pub nonce: [u8; 24],
    /// The encrypted Shamir evaluation (32 bytes + 16 bytes of tag).
    pub ciphertext: Vec<u8>,
}

/// One member's DKG contribution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgContribution {
    pub epoch: u64,
    /// The contributor's consensus identity.
    pub validator_id: [u8; 32],
    /// The contributor's 1-based committee index (its Shamir abscissa).
    pub index: u32,
    /// The contributor's X25519 encryption key.
    pub enc_pk: [u8; 32],
    /// Feldman commitments to the contributor's share polynomial:
    /// `commitments[k] = a_k * B`, for `k` in `0..threshold`.
    pub commitments: Vec<[u8; 32]>,
    /// The encrypted evaluation packages, one per OTHER committee member.
    pub packages: Vec<EncryptedShare>,
}

impl DkgContribution {
    /// Canonical bytes of the contribution (for the transcript root).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.packages.len() * 96);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.validator_id);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.enc_pk);
        out.extend_from_slice(&(self.commitments.len() as u32).to_be_bytes());
        for c in &self.commitments {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&(self.packages.len() as u32).to_be_bytes());
        for p in &self.packages {
            out.extend_from_slice(&p.recipient_index.to_be_bytes());
            out.extend_from_slice(&p.ephemeral_pk);
            out.extend_from_slice(&p.nonce);
            out.extend_from_slice(&(p.ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&p.ciphertext);
        }
        out
    }
}

/// The DKG state of one epoch.
///
/// The key generation is DEALER-FREE and verifiable: every member derives a
/// share polynomial deterministically from the epoch seed and its own
/// long-term secret, publishes the Feldman commitments of that polynomial,
/// and sends each member its (encrypted) evaluation of it. Every recipient
/// checks the evaluation against the commitments (a real verifiable secret
/// sharing), so a dishonest member can only make the epoch FAIL (a
/// liveness loss, detected and attributable) — it can never bias the key
/// towards a value it knows, and it never learns anybody else's share.
#[derive(Clone, Debug)]
pub struct EpochDkg {
    pub committee: EpochCommittee,
    /// Our committee identity (the validator id we hold the key for).
    our_validator_id: [u8; 32],
    /// Our 1-based committee index (the Shamir abscissa of our share).
    our_index: Option<u32>,
    /// Accepted contributions, keyed by the contributor's committee index.
    contributions: std::collections::BTreeMap<u32, DkgContribution>,
    /// The evaluation of each accepted contribution AT OUR INDEX (the
    /// contributor's index -> `f_j(our_index)`).
    evaluations: std::collections::BTreeMap<u32, Scalar>,
    /// Our own contribution (published to the network).
    own: Option<DkgContribution>,
    /// Our own polynomial evaluated at OUR index: the share we hold of our
    /// OWN contribution. Kept so the aggregate share covers EVERY
    /// contribution (ours included) — the epoch key must be the aggregate
    /// over the WHOLE committee, not over "the others".
    own_eval: Option<Scalar>,
    /// The finalized key material.
    material: Option<EpochKeyMaterial>,
}

impl EpochDkg {
    /// Start a DKG for the given committee, as the member identified by
    /// `our_validator_id`.
    pub fn new(committee: EpochCommittee, our_validator_id: [u8; 32]) -> EpochDkg {
        let our_index = committee.index_of(&our_validator_id);
        EpochDkg {
            committee,
            our_validator_id,
            our_index,
            contributions: std::collections::BTreeMap::new(),
            evaluations: std::collections::BTreeMap::new(),
            own: None,
            own_eval: None,
            material: None,
        }
    }

    /// The epoch seed: public, deterministic, and bound to the committee.
    fn epoch_seed(&self) -> [u8; 32] {
        hash_parts(
            EPOCH_SEED_DOMAIN,
            &[
                &self.committee.epoch.to_be_bytes(),
                &self.committee.hash,
            ],
        )
    }

    /// Derive our share polynomial's coefficients.
    ///
    /// `a_k = H(domain || seed || index || k || long_term_secret)`.
    ///
    /// The polynomial is DETERMINISTIC (no fresh randomness), so every node
    /// derives the same epoch key from the same committee and the same
    /// long-term secrets — and the coefficients are SECRET, because they
    /// depend on the long-term key that only the member holds.
    fn polynomial(&self, long_term_secret: &[u8; 32]) -> Vec<Scalar> {
        let seed = self.epoch_seed();
        let index = self.our_index.unwrap_or(0).to_be_bytes();
        (0..self.committee.threshold)
            .map(|k| {
                hash_to_scalar(
                    DKG_POLY_DOMAIN,
                    &[
                        &seed,
                        &index,
                        &k.to_be_bytes(),
                        long_term_secret,
                    ],
                )
            })
            .collect()
    }

    /// Build our DKG contribution.
    ///
    /// `long_term_secret` is the member's Ed25519 secret key (32 bytes);
    /// `enc_secret` is its X25519 encryption secret (32 bytes), derived by
    /// [`encryption_secret_from_ed25519`].
    pub fn contribution(
        &mut self,
        validator_id: [u8; 32],
        long_term_secret: &[u8; 32],
        enc_secret: &[u8; 32],
    ) -> Result<DkgContribution, String> {
        let index = self
            .committee
            .index_of(&validator_id)
            .ok_or_else(|| "validator is not a member of this epoch committee".to_string())?;
        if self.committee.threshold == 0 {
            return Err("committee has no threshold (empty committee)".to_string());
        }
        let coeffs = self.polynomial(long_term_secret);
        let mut commitments = Vec::with_capacity(coeffs.len());
        for c in &coeffs {
            commitments.push((RISTRETTO_BASEPOINT_POINT * c).compress().to_bytes());
        }
        // The evaluation of our polynomial at every OTHER member's index,
        // encrypted to that member's X25519 key.
        let mut packages = Vec::new();
        for (i, member) in self.committee.members.iter().enumerate() {
            let recipient_index = i as u32 + 1;
            if recipient_index == index {
                continue;
            }
            let eval = eval_polynomial(&coeffs, recipient_index as u64);
            let package = encrypt_share_package(enc_secret, &member.enc_pk, &eval.to_bytes())?;
            packages.push(EncryptedShare {
                recipient_index,
                ephemeral_pk: package.0,
                nonce: package.1,
                ciphertext: package.2,
            });
        }
        let contribution = DkgContribution {
            epoch: self.committee.epoch,
            validator_id,
            index,
            enc_pk: self
                .committee
                .member_at(index)
                .map(|m| m.enc_pk)
                .unwrap_or([0u8; 32]),
            commitments,
            packages,
        };
        // Remember our own evaluation: the aggregate share must include our
        // own contribution.
        self.own_eval = Some(eval_polynomial(&coeffs, index as u64));
        self.own = Some(contribution.clone());
        Ok(contribution)
    }

    /// Ingest and VERIFY a contribution from the network.
    ///
    /// Fails closed: the contributor must be a committee member at the index
    /// it claims, its encryption key must match the committee's, it must
    /// publish exactly `threshold` commitments, it must send exactly one
    /// package to every other member, and the package addressed to US must
    /// decrypt to an evaluation consistent with the published commitments.
    pub fn ingest(
        &mut self,
        contribution: DkgContribution,
        enc_secret: &[u8; 32],
    ) -> Result<(), String> {
        if contribution.epoch != self.committee.epoch {
            return Err(format!(
                "dkg contribution for epoch {} does not match epoch {}",
                contribution.epoch, self.committee.epoch
            ));
        }
        if self.contributions.contains_key(&contribution.index) {
            return Err(format!(
                "duplicate dkg contribution for committee index {}",
                contribution.index
            ));
        }
        let contribution_index = contribution.index;
        let member = self
            .committee
            .member_at(contribution.index)
            .ok_or_else(|| "dkg contribution claims an index outside the committee".to_string())?;
        if member.validator_id != contribution.validator_id {
            return Err("dkg contribution identity does not match the committee".to_string());
        }
        let is_own = contribution.index == self.our_index.unwrap_or(0);
        if is_own && contribution.validator_id != self.our_validator_id {
            return Err("dkg contribution claims our committee index".to_string());
        }
        if member.enc_pk != contribution.enc_pk {
            return Err("dkg contribution encryption key does not match the committee".to_string());
        }
        if contribution.commitments.len() != self.committee.threshold {
            return Err(format!(
                "dkg contribution has {} commitments, expected {}",
                contribution.commitments.len(),
                self.committee.threshold
            ));
        }
        // Every commitment must be a valid group element.
        let mut commitment_points = Vec::with_capacity(contribution.commitments.len());
        for c in &contribution.commitments {
            let point = decompress_point(c)
                .ok_or_else(|| "dkg commitment is not a valid curve point".to_string())?;
            commitment_points.push(point);
        }
        // Exactly one package per other member, and one for us.
        let mut seen = std::collections::HashSet::new();
        let mut our_package: Option<&EncryptedShare> = None;
        for p in &contribution.packages {
            if !seen.insert(p.recipient_index) {
                return Err("duplicate dkg share package".to_string());
            }
            let target = self
                .committee
                .member_at(p.recipient_index)
                .ok_or_else(|| "dkg share package targets a non-member".to_string())?;
            if target.validator_id == contribution.validator_id {
                return Err("dkg share package targets the contributor itself".to_string());
            }
            if p.recipient_index == contribution.index {
                return Err("dkg share package targets the contributor itself".to_string());
            }
            if p.ciphertext.len() != 48 {
                return Err("dkg share package has the wrong ciphertext length".to_string());
            }
            if self.our_index() == Some(p.recipient_index) {
                our_package = Some(p);
            }
        }
        // Every other member must have received a package.
        for i in 1..=self.committee.members.len() as u32 {
            if i == contribution.index {
                continue;
            }
            if !seen.contains(&i) {
                return Err(format!(
                    "dkg contribution is missing the share package for committee index {}",
                    i
                ));
            }
        }
        if is_own {
            // Our OWN contribution: the evaluation is the one we computed
            // from our own polynomial (we do not send ourselves a package).
            // It is still VERIFIED against the published commitments, so a
            // contribution that does not match what we published is refused.
            let eval = self
                .own_eval
                .ok_or_else(|| "dkg contribution for our index arrived before ours".to_string())?;
            let expected = eval_point(&commitment_points, contribution.index as u64);
            if expected != RISTRETTO_BASEPOINT_POINT * eval {
                return Err(
                    "our own dkg contribution does not match the commitments we published"
                        .to_string(),
                );
            }
            self.contributions.insert(contribution.index, contribution);
            self.evaluations.insert(contribution_index, eval);
            return Ok(());
        }
        let Some(package) = our_package else {
            // A contribution that does not include our package is still
            // structurally valid, but we cannot use it: our share would be
            // incomplete. Refuse it (the epoch needs every member's
            // evaluation to reconstruct our own share).
            return Err("dkg contribution does not carry our share package".to_string());
        };
        let our_index = self
            .our_index
            .ok_or_else(|| "this node is not a member of the epoch committee".to_string())?;
        let eval_bytes = decrypt_share_package(enc_secret, package)?;
        let eval = Option::<Scalar>::from(Scalar::from_canonical_bytes(eval_bytes))
            .ok_or_else(|| "dkg share evaluation is not a canonical scalar".to_string())?;
        // VERIFIABLE SECRET SHARING CHECK: the decrypted evaluation must
        // match the published commitments at our index.
        let expected = eval_point(&commitment_points, our_index as u64);
        if expected != RISTRETTO_BASEPOINT_POINT * eval {
            return Err("dkg share evaluation does not match the published commitments".to_string());
        }
        self.contributions.insert(contribution.index, contribution);
        self.evaluations.insert(contribution_index, eval);
        Ok(())
    }

    /// Our own 1-based committee index (if we are a member).
    pub fn our_index(&self) -> Option<u32> {
        self.our_index
    }

    /// Our committee identity.
    pub fn our_validator_id(&self) -> [u8; 32] {
        self.our_validator_id
    }

    /// Record our own contribution (so it can be gossiped).
    pub fn set_own(&mut self, contribution: DkgContribution) {
        self.own = Some(contribution);
    }

    /// The number of accepted contributions.
    pub fn contribution_count(&self) -> usize {
        self.contributions.len()
    }

    /// Whether the DKG has enough contributions to finalize.
    pub fn can_finalize(&self) -> bool {
        self.contributions.len() >= self.committee.threshold
            && self.committee.threshold > 0
    }

    /// Finalize the DKG: derive our Shamir share and the epoch public key.
    ///
    /// Fails closed unless every accepted contribution has been verified
    /// (the VSS check in [`Self::ingest`]) and the aggregate check holds:
    /// our share's group element must equal the sum of the aggregate
    /// commitments evaluated at our index.
    pub fn finalize(&mut self) -> Result<EpochKeyMaterial, String> {
        if !self.can_finalize() {
            return Err(format!(
                "dkg needs at least {} contributions, have {}",
                self.committee.threshold,
                self.contributions.len()
            ));
        }
        let our_index = self
            .our_index()
            .ok_or_else(|| "this node is not a member of the epoch committee".to_string())?;
        // Our share: the sum of every contributor's evaluation at our index.
        let mut share = Scalar::ZERO;
        let mut aggregate_commitments: Vec<RistrettoPoint> = Vec::new();
        for (index, contribution) in &self.contributions {
            let eval = self
                .evaluations
                .get(index)
                .ok_or_else(|| "missing dkg evaluation".to_string())?;
            share += eval;
            let mut points = Vec::with_capacity(contribution.commitments.len());
            for c in &contribution.commitments {
                points.push(
                    decompress_point(c)
                        .ok_or_else(|| "dkg commitment is not a valid curve point".to_string())?,
                );
            }
            aggregate_commitments.push(eval_point(&points, our_index as u64));
        }
        // AGGREGATE VSS CHECK: our share must match the aggregate of the
        // published commitments evaluated at our index.
        let expected = aggregate_commitments
            .iter()
            .fold(RistrettoPoint::default(), |acc, p| acc + p);
        if expected != RISTRETTO_BASEPOINT_POINT * share {
            return Err("dkg aggregate share does not match the published commitments".to_string());
        }
        // The epoch public key: the aggregate of the constant-term
        // commitments (the Shamir secret's commitment).
        let mut public_key = RistrettoPoint::default();
        for contribution in self.contributions.values() {
            let c0 = decompress_point(&contribution.commitments[0])
                .ok_or_else(|| "dkg commitment is not a valid curve point".to_string())?;
            public_key += c0;
        }
        // The transcript root: binds every accepted contribution.
        let epoch_bytes = self.committee.epoch.to_be_bytes();
        let mut canonical: Vec<Vec<u8>> = Vec::with_capacity(self.contributions.len());
        for contribution in self.contributions.values() {
            canonical.push(contribution.canonical_bytes());
        }
        let mut transcript_parts: Vec<&[u8]> = Vec::with_capacity(canonical.len() + 1);
        transcript_parts.push(&epoch_bytes);
        for c in &canonical {
            transcript_parts.push(c);
        }
        let transcript_root = hash_parts(TRANSCRIPT_DOMAIN, &transcript_parts);
        let material = EpochKeyMaterial {
            epoch: self.committee.epoch,
            public_key: public_key.compress().to_bytes(),
            share: share.to_bytes(),
            committee_hash: self.committee.hash,
            transcript_root,
            threshold: self.committee.threshold,
        };
        self.material = Some(material.clone());
        Ok(material)
    }

    /// The finalized key material (if the DKG completed).
    pub fn material(&self) -> Option<&EpochKeyMaterial> {
        self.material.as_ref()
    }

    /// Our own contribution (to be gossiped).
    pub fn own_contribution(&self) -> Option<&DkgContribution> {
        self.own.as_ref()
    }
}

/// Evaluate a share polynomial at `x`.
fn eval_polynomial(coeffs: &[Scalar], x: u64) -> Scalar {
    let mut acc = Scalar::ZERO;
    let mut x_pow = Scalar::ONE;
    let x_scalar = Scalar::from(x);
    for c in coeffs {
        acc += *c * x_pow;
        x_pow *= x_scalar;
    }
    acc
}

/// Evaluate the COMMITMENT polynomial at `x` (in the group).
fn eval_point(commitments: &[RistrettoPoint], x: u64) -> RistrettoPoint {
    let mut acc = RistrettoPoint::default();
    let mut x_pow = Scalar::ONE;
    let x_scalar = Scalar::from(x);
    for c in commitments {
        acc += *c * x_pow;
        x_pow *= x_scalar;
    }
    acc
}

/// Derive the X25519 encryption secret from an Ed25519 long-term SEED.
///
/// The standard Ed25519 -> X25519 conversion: the Ed25519 secret scalar is
/// `SHA512(seed)[0..32]`, clamped exactly as Ed25519 and X25519 clamp it.
/// The conversion is the one NaCl/libsodium use, so the resulting X25519
/// key pair is a genuine Diffie-Hellman pair AND its public half is
/// derivable from the Ed25519 public key alone (see
/// [`encryption_public_key_from_ed25519`]).
///
/// WHY THIS MATTERS: the committee's encryption keys must be known BEFORE
/// the DKG starts, otherwise the key-share packages would have nowhere to
/// be addressed. Deriving them from the PUBLIC validator keys keeps the
/// whole DKG to ONE round (no separate key announcement round).
pub fn encryption_secret_from_ed25519(ed25519_seed: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(ed25519_seed);
    let out = hasher.finalize();
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&out[..32]);
    // The Ed25519/X25519 clamp (idempotent: x25519-dalek clamps again).
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    secret
}

/// The X25519 public key of an Ed25519 public key (the birational map).
///
/// Returns `None` for a public key that is not a valid Ed25519 point (or
/// the exceptional identity), so a malformed validator key is refused
/// instead of producing an unusable encryption key.
pub fn encryption_public_key_from_ed25519(ed25519_public: &[u8; 32]) -> Option<[u8; 32]> {
    let point = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(ed25519_public)
        .ok()?
        .decompress()?;
    Some(point.to_montgomery().to_bytes())
}

/// The X25519 public key of an encryption secret.
pub fn encryption_public_key(enc_secret: &[u8; 32]) -> [u8; 32] {
    let secret = XStaticSecret::from(*enc_secret);
    XPublicKey::from(&secret).to_bytes()
}

/// Encrypt one DKG share package to a recipient's X25519 key.
fn encrypt_share_package(
    enc_secret: &[u8; 32],
    recipient_pk: &[u8; 32],
    plaintext: &[u8; 32],
) -> Result<([u8; 32], [u8; 24], Vec<u8>), String> {
    let secret = XStaticSecret::from(*enc_secret);
    let ephemeral = XStaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = XPublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&XPublicKey::from(*recipient_pk));
    let key = derive_seal_key(shared.as_bytes(), &[0u8; 32], 0);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("seal cipher init failed: {e}"))?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|e| format!("share package encryption failed: {e}"))?;
    Ok((ephemeral_pk, nonce, ciphertext))
}

/// Decrypt one DKG share package.
fn decrypt_share_package(
    enc_secret: &[u8; 32],
    package: &EncryptedShare,
) -> Result<[u8; 32], String> {
    let secret = XStaticSecret::from(*enc_secret);
    let shared = secret.diffie_hellman(&XPublicKey::from(package.ephemeral_pk));
    let key = derive_seal_key(shared.as_bytes(), &[0u8; 32], 0);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("seal cipher init failed: {e}"))?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&package.nonce),
            package.ciphertext.as_ref(),
        )
        .map_err(|_| "share package decryption failed".to_string())?;
    if plaintext.len() != 32 {
        return Err("share package plaintext has the wrong length".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Ok(out)
}

// ===========================================================================
// Sealed envelopes
// ===========================================================================

/// The TRANSPARENT part of a sealed transaction: the fields the mempool
/// needs for ordering and admission, and nothing about the transfer itself.
///
/// The amount, the recipient and the SVM program stay hidden. The sender, the
/// nonce and the fee are visible: without them the pool could not order or
/// deduplicate the transaction at all, and every serious encrypted-mempool
/// design keeps the same fields visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentMeta {
    pub from: [u8; 32],
    pub nonce: u64,
    pub gas_limit: u64,
    pub priority_fee_per_gas: u64,
    pub source_shard: u32,
    pub target_shard: u32,
}

/// A sealed transaction: the ciphertext the network carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEnvelope {
    /// The MEV epoch the ciphertext is sealed to.
    pub epoch: u64,
    /// The canonical transaction hash of the SEALED transaction. The order
    /// commitment is computed over these hashes, so it can be committed to
    /// BEFORE the plaintext is known.
    pub tx_hash: [u8; 32],
    /// The ephemeral public key of the sealing wallet (compressed Ristretto).
    pub ephemeral_pk: [u8; 32],
    /// The XChaCha20-Poly1305 nonce.
    pub nonce: [u8; 24],
    /// The ciphertext of the serialized transaction.
    pub ciphertext: Vec<u8>,
    /// The transparent ordering metadata.
    pub meta: TransparentMeta,
}

impl SealedEnvelope {
    /// The wire size of the envelope.
    pub fn wire_len(&self) -> usize {
        8 + 32 + 32 + 24 + 8 + self.ciphertext.len() + 32 + 8 + 8 + 8 + 4 + 4
    }

    /// Structural validation of an envelope received from the wire.
    ///
    /// Fail closed: a malformed envelope is refused at admission rather
    /// than stored, so it can never occupy pool space or stall a proposer.
    pub fn validate(&self) -> Result<(), String> {
        if self.ciphertext.is_empty() {
            return Err("sealed envelope has an empty payload".to_string());
        }
        if self.ciphertext.len() > MAX_SEALED_PAYLOAD {
            return Err(format!(
                "sealed envelope payload is too large: {} > {}",
                self.ciphertext.len(),
                MAX_SEALED_PAYLOAD
            ));
        }
        if self.tx_hash == [0u8; 32] {
            return Err("sealed envelope has the reserved all-zero tx hash".to_string());
        }
        decompress_point(&self.ephemeral_pk)
            .ok_or_else(|| "sealed envelope has an invalid ephemeral public key".to_string())?;
        Ok(())
    }
}

/// Derive the payload key from the Diffie-Hellman shared secret.
fn derive_seal_key(shared: &[u8], tx_hash: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEAL_KDF_DOMAIN);
    hasher.update(&(shared.len() as u32).to_be_bytes());
    hasher.update(shared);
    hasher.update(&epoch.to_be_bytes());
    hasher.update(tx_hash);
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// The associated data bound into every sealed payload.
fn seal_aad(epoch: u64, tx_hash: &[u8; 32], committee_hash: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SEAL_AAD_DOMAIN.len() + 8 + 32 + 32);
    aad.extend_from_slice(SEAL_AAD_DOMAIN);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(tx_hash);
    aad.extend_from_slice(committee_hash);
    aad
}

/// Seal a transaction to the epoch public key (the WALLET side).
///
/// The plaintext never leaves this function: only the ciphertext, the
/// ephemeral public key and the transparent metadata are published.
pub fn seal_transaction(
    epoch_key: &EpochPublicKey,
    plaintext: &[u8],
    tx_hash: [u8; 32],
    meta: TransparentMeta,
) -> Result<SealedEnvelope, String> {
    let public_point = decompress_point(&epoch_key.public_key)
        .ok_or_else(|| "epoch public key is not a valid curve point".to_string())?;
    // Fresh ephemeral key: the wallet never reuses an ephemeral scalar.
    let mut eph_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut eph_bytes);
    let ephemeral = Scalar::from_bytes_mod_order(eph_bytes);
    // The Diffie-Hellman shared point: e * P_e.
    let shared = public_point * ephemeral;
    let shared_bytes = shared.compress().to_bytes();
    let key = derive_seal_key(&shared_bytes, &tx_hash, epoch_key.epoch);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let aad = seal_aad(epoch_key.epoch, &tx_hash, &epoch_key.committee_hash);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("seal cipher init failed: {e}"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| format!("sealing failed: {e}"))?;
    Ok(SealedEnvelope {
        epoch: epoch_key.epoch,
        tx_hash,
        ephemeral_pk: (RISTRETTO_BASEPOINT_POINT * ephemeral).compress().to_bytes(),
        nonce,
        ciphertext,
        meta,
    })
}

/// Decrypt a sealed envelope with the RECONSTRUCTED shared point.
fn decrypt_with_shared_point(
    envelope: &SealedEnvelope,
    shared_point: &[u8; 32],
    committee_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let key = derive_seal_key(shared_point, &envelope.tx_hash, envelope.epoch);
    let aad = seal_aad(envelope.epoch, &envelope.tx_hash, committee_hash);
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| format!("seal cipher init failed: {e}"))?;
    cipher
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: envelope.ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| "sealed payload did not authenticate".to_string())
}

/// One member's decryption partial for one sealed ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionPartial {
    /// The 1-based committee index of the member that produced it.
    pub validator_index: u32,
    /// The group element `C^x_i`.
    pub point: [u8; 32],
}

/// Compute our decryption partial for a sealed ciphertext.
///
/// `C^x_i` is a group element: publishing it does NOT reveal our share
/// (discrete log) and does NOT let anyone decrypt a DIFFERENT ciphertext
/// (the partial is bound to that ciphertext's ephemeral point).
pub fn compute_partial(
    share: &[u8; 32],
    ephemeral_pk: &[u8; 32],
) -> Result<[u8; 32], String> {
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*share))
        .ok_or_else(|| "epoch share is not a canonical scalar".to_string())?;
    let point = decompress_point(ephemeral_pk)
        .ok_or_else(|| "sealed envelope has an invalid ephemeral public key".to_string())?;
    Ok((point * scalar).compress().to_bytes())
}

/// Combine decryption partials into the Diffie-Hellman shared point.
///
/// Lagrange interpolation IN THE EXPONENT: with `x_i` the committee index
/// (the Shamir abscissa) and `partial_i = C^x_i`,
/// `prod(partial_i ^ lambda_i) = C ^ (sum(lambda_i * x_i)) = C ^ secret`,
/// where the `lambda_i` are the Lagrange basis polynomials at zero over the
/// participating subset. Any subset of at least `threshold` distinct
/// members yields the SAME shared point — so a member that withholds its
/// partial cannot change the outcome, it can only delay it.
pub fn combine_partials(
    partials: &[DecryptionPartial],
    threshold: usize,
) -> Result<[u8; 32], String> {
    if partials.len() < threshold {
        return Err(format!(
            "not enough decryption partials: have {}, need {}",
            partials.len(),
            threshold
        ));
    }
    if threshold == 0 {
        return Err("threshold must be positive".to_string());
    }
    // Distinct abscissae only: a duplicate index makes the Lagrange
    // denominator zero, and the reconstruction would be silently wrong.
    let mut seen = std::collections::HashSet::new();
    for p in partials {
        if p.validator_index == 0 {
            return Err("decryption partial has the reserved index 0".to_string());
        }
        if !seen.insert(p.validator_index) {
            return Err(format!(
                "duplicate decryption partial for committee index {}",
                p.validator_index
            ));
        }
    }
    let mut points = Vec::with_capacity(partials.len());
    let mut xs = Vec::with_capacity(partials.len());
    for p in partials {
        let point = decompress_point(&p.point)
            .ok_or_else(|| "decryption partial is not a valid curve point".to_string())?;
        points.push(point);
        xs.push(Scalar::from(p.validator_index as u64));
    }
    let mut shared = RistrettoPoint::default();
    for j in 0..points.len() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for k in 0..points.len() {
            if k != j {
                // Lagrange basis at x = 0: (-x_k) / (x_j - x_k)
                num *= -xs[k];
                den *= xs[j] - xs[k];
            }
        }
        let lagrange = num * den.invert();
        shared += points[j] * lagrange;
    }
    Ok(shared.compress().to_bytes())
}

/// Unseal a transaction from the combined decryption partials.
pub fn unseal_transaction(
    envelope: &SealedEnvelope,
    partials: &[DecryptionPartial],
    threshold: usize,
    committee_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let shared = combine_partials(partials, threshold)?;
    decrypt_with_shared_point(envelope, &shared, committee_hash)
}

// ===========================================================================
// Wire messages
// ===========================================================================

/// The order commitment of a round: the proposer's signed promise about the
/// ORDER of the sealed transactions it is about to reveal.
///
/// This is the gate on the share release: a member releases its decryption
/// partials only after it has seen this commitment, so the ordering is
/// fixed before anybody can read the transactions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderCommitment {
    pub epoch: u64,
    pub height: u64,
    pub round: u32,
    /// The order Merkle root over the sealed transaction hashes, in order.
    pub order_root: [u8; 32],
    /// The committed transaction hashes, in order.
    pub tx_hashes: Vec<[u8; 32]>,
    /// The proposer's validator identity.
    pub proposer: [u8; 32],
    /// The proposer's signature over [`order_commitment_signing_message`].
    pub signature: Vec<u8>,
}

/// The exact bytes a proposer signs to commit to a round's order.
pub fn order_commitment_signing_message(
    epoch: u64,
    height: u64,
    round: u32,
    order_root: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ORDER_COMMIT_SIG_DOMAIN.len() + 8 + 8 + 4 + 32);
    msg.extend_from_slice(ORDER_COMMIT_SIG_DOMAIN);
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.extend_from_slice(&round.to_be_bytes());
    msg.extend_from_slice(order_root);
    msg
}

impl OrderCommitment {
    /// Sign a round's order commitment with the proposer's key.
    pub fn sign(
        epoch: u64,
        height: u64,
        round: u32,
        tx_hashes: Vec<[u8; 32]>,
        signer: &SigningKey,
    ) -> OrderCommitment {
        let order_root = crate::mev::order_merkle_root_of_hashes(&tx_hashes);
        let msg = order_commitment_signing_message(epoch, height, round, &order_root);
        let signature = signer.sign(&msg).to_bytes().to_vec();
        OrderCommitment {
            epoch,
            height,
            round,
            order_root,
            tx_hashes,
            proposer: signer.verifying_key().to_bytes(),
            signature,
        }
    }

    /// Verify the commitment's signature and its internal consistency.
    pub fn verify(&self) -> Result<(), String> {
        if self.order_root != crate::mev::order_merkle_root_of_hashes(&self.tx_hashes) {
            return Err("order commitment does not match its transaction list".to_string());
        }
        let msg = order_commitment_signing_message(
            self.epoch,
            self.height,
            self.round,
            &self.order_root,
        );
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&self.proposer)
            .map_err(|e| format!("order commitment proposer key is invalid: {e}"))?;
        let sig = Signature::from_slice(&self.signature)
            .map_err(|e| format!("order commitment signature is malformed: {e}"))?;
        pk.verify(&msg, &sig)
            .map_err(|e| format!("order commitment signature does not verify: {e}"))
    }
}

/// The share release: the decryption partials of one round.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRelease {
    pub epoch: u64,
    pub height: u64,
    pub round: u32,
    /// The order commitment the partials are released AGAINST. A receiver
    /// refuses partials that do not match the commitment it has seen, so a
    /// release can never be replayed into a different ordering.
    pub order_root: [u8; 32],
    /// The released partials: `(tx_hash, partial)`.
    pub partials: Vec<([u8; 32], DecryptionPartial)>,
}

/// The epoch key announcement: the committee's agreement on the epoch key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochKeyAnnouncement {
    pub epoch: u64,
    /// The epoch public key (the aggregate of the members' commitments).
    pub public_key: [u8; 32],
    /// The committee hash.
    pub committee_hash: [u8; 32],
    /// The DKG transcript root: binds every contribution.
    pub transcript_root: [u8; 32],
    /// The threshold.
    pub threshold: usize,
    /// The committee members that contributed, with their indices.
    pub contributors: Vec<(u32, [u8; 32])>,
    /// The member signatures over [`epoch_announcement_signing_message`].
    pub signatures: Vec<([u8; 32], Vec<u8>)>,
}

/// The exact bytes a committee member signs to announce the epoch key.
pub fn epoch_announcement_signing_message(
    epoch: u64,
    public_key: &[u8; 32],
    committee_hash: &[u8; 32],
    transcript_root: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(EPOCH_ANNOUNCE_SIG_DOMAIN.len() + 8 + 32 + 32 + 32);
    msg.extend_from_slice(EPOCH_ANNOUNCE_SIG_DOMAIN);
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(public_key);
    msg.extend_from_slice(committee_hash);
    msg.extend_from_slice(transcript_root);
    msg
}

impl EpochKeyAnnouncement {
    /// Sign an announcement with a committee member's key.
    pub fn sign(
        epoch: u64,
        public_key: [u8; 32],
        committee_hash: [u8; 32],
        transcript_root: [u8; 32],
        threshold: usize,
        contributors: Vec<(u32, [u8; 32])>,
        signer: &SigningKey,
    ) -> EpochKeyAnnouncement {
        let msg = epoch_announcement_signing_message(
            epoch,
            &public_key,
            &committee_hash,
            &transcript_root,
        );
        let signature = signer.sign(&msg).to_bytes().to_vec();
        EpochKeyAnnouncement {
            epoch,
            public_key,
            committee_hash,
            transcript_root,
            threshold,
            contributors,
            signatures: vec![(signer.verifying_key().to_bytes(), signature)],
        }
    }

    /// Add a member's signature to the announcement.
    pub fn add_signature(&mut self, signer: &SigningKey) {
        let msg = epoch_announcement_signing_message(
            self.epoch,
            &self.public_key,
            &self.committee_hash,
            &self.transcript_root,
        );
        let signature = signer.sign(&msg).to_bytes().to_vec();
        let pk = signer.verifying_key().to_bytes();
        if !self.signatures.iter().any(|(p, _)| *p == pk) {
            self.signatures.push((pk, signature));
        }
    }

    /// Count the DISTINCT members whose signature verifies.
    ///
    /// Duplicates never count twice: a repeated signer must not be able to
    /// fake a quorum.
    pub fn valid_signature_count(&self) -> usize {
        let msg = epoch_announcement_signing_message(
            self.epoch,
            &self.public_key,
            &self.committee_hash,
            &self.transcript_root,
        );
        let mut seen = std::collections::HashSet::new();
        let mut count = 0usize;
        for (pk, sig) in &self.signatures {
            if !seen.insert(*pk) {
                continue;
            }
            if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(pk) {
                if let Ok(sig) = Signature::from_slice(sig) {
                    if vk.verify(&msg, &sig).is_ok() {
                        count += 1;
                    }
                }
            }
        }
        count
    }

    /// Whether the announcement carries a quorum of member signatures.
    pub fn has_quorum(&self, quorum: usize) -> bool {
        self.valid_signature_count() >= quorum
    }
}

// ===========================================================================
// Wire framing
// ===========================================================================

/// Magic prefix of a sealed-payload wire frame.
///
/// The plain transaction encoding is UNCHANGED, so a node that predates the
/// epoch-seal path still decodes every plain transaction it receives; a
/// sealed frame is simply refused by such a node (fail-closed, and the
/// sender's transaction is re-submitted in the plain form).
pub const SEALED_PAYLOAD_MAGIC: &[u8; 4] = b"STX1";
/// Magic prefix of a DKG-contribution frame.
pub const DKG_PAYLOAD_MAGIC: &[u8; 4] = b"STD1";
/// Magic prefix of an order-commitment frame.
pub const ORDER_COMMIT_PAYLOAD_MAGIC: &[u8; 4] = b"STC1";
/// Magic prefix of a share-release frame.
pub const SHARE_RELEASE_PAYLOAD_MAGIC: &[u8; 4] = b"STR1";
/// Magic prefix of an epoch-key-announcement frame.
pub const EPOCH_ANNOUNCE_PAYLOAD_MAGIC: &[u8; 4] = b"STE1";

/// One frame of the epoch-seal gossip.
///
/// Every frame is magic-prefixed, so the plain transaction encoding stays
/// byte-identical and a node that predates this feature decodes every plain
/// transaction exactly as before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MevFrame {
    /// A sealed transaction (the ciphertext only).
    Sealed(SealedEnvelope),
    /// A DKG contribution (the key-share packages).
    Dkg(DkgContribution),
    /// A round's order commitment (the gate on the share release).
    OrderCommit(OrderCommitment),
    /// A share release (the decryption partials).
    Release(ShareRelease),
    /// The epoch key announcement.
    Announcement(EpochKeyAnnouncement),
}

impl MevFrame {
    /// The magic prefix of this frame kind.
    pub fn magic(&self) -> &'static [u8; 4] {
        match self {
            MevFrame::Sealed(_) => SEALED_PAYLOAD_MAGIC,
            MevFrame::Dkg(_) => DKG_PAYLOAD_MAGIC,
            MevFrame::OrderCommit(_) => ORDER_COMMIT_PAYLOAD_MAGIC,
            MevFrame::Release(_) => SHARE_RELEASE_PAYLOAD_MAGIC,
            MevFrame::Announcement(_) => EPOCH_ANNOUNCE_PAYLOAD_MAGIC,
        }
    }

    /// Encode the frame: `MAGIC || bincode(body)`.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let body = match self {
            MevFrame::Sealed(v) => bincode::serialize(v),
            MevFrame::Dkg(v) => bincode::serialize(v),
            MevFrame::OrderCommit(v) => bincode::serialize(v),
            MevFrame::Release(v) => bincode::serialize(v),
            MevFrame::Announcement(v) => bincode::serialize(v),
        }
        .map_err(|e| format!("mev frame serialize error: {e}"))?;
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(self.magic());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode a frame (fail-closed: an unknown magic or a malformed body is
    /// refused, never guessed at).
    pub fn decode(bytes: &[u8]) -> Result<MevFrame, String> {
        if bytes.len() <= 4 {
            return Err("mev frame is too short".to_string());
        }
        let magic = &bytes[..4];
        let body = &bytes[4..];
        let frame = match magic {
            m if m == SEALED_PAYLOAD_MAGIC => MevFrame::Sealed(
                bincode::deserialize(body)
                    .map_err(|e| format!("sealed envelope decode error: {e}"))?,
            ),
            m if m == DKG_PAYLOAD_MAGIC => MevFrame::Dkg(
                bincode::deserialize(body)
                    .map_err(|e| format!("dkg contribution decode error: {e}"))?,
            ),
            m if m == ORDER_COMMIT_PAYLOAD_MAGIC => MevFrame::OrderCommit(
                bincode::deserialize(body)
                    .map_err(|e| format!("order commitment decode error: {e}"))?,
            ),
            m if m == SHARE_RELEASE_PAYLOAD_MAGIC => MevFrame::Release(
                bincode::deserialize(body)
                    .map_err(|e| format!("share release decode error: {e}"))?,
            ),
            m if m == EPOCH_ANNOUNCE_PAYLOAD_MAGIC => MevFrame::Announcement(
                bincode::deserialize(body)
                    .map_err(|e| format!("epoch announcement decode error: {e}"))?,
            ),
            _ => return Err("mev frame has an unknown magic prefix".to_string()),
        };
        Ok(frame)
    }
}

/// Encode a sealed envelope for the wire: `MAGIC || bincode(envelope)`.
pub fn encode_sealed_payload(envelope: &SealedEnvelope) -> Result<Vec<u8>, String> {
    MevFrame::Sealed(envelope.clone()).encode()
}

/// Whether a wire frame is a sealed payload.
pub fn is_sealed_payload(bytes: &[u8]) -> bool {
    bytes.len() > SEALED_PAYLOAD_MAGIC.len()
        && &bytes[..SEALED_PAYLOAD_MAGIC.len()] == SEALED_PAYLOAD_MAGIC
}

/// Decode a sealed payload from the wire (fail-closed).
pub fn decode_sealed_payload(bytes: &[u8]) -> Result<SealedEnvelope, String> {
    match MevFrame::decode(bytes)? {
        MevFrame::Sealed(envelope) => {
            envelope.validate()?;
            Ok(envelope)
        }
        _ => Err("wire frame is not a sealed payload".to_string()),
    }
}

/// Whether a wire frame is ANY epoch-seal frame (sealed, DKG, commitment,
/// release or announcement).
pub fn is_mev_frame(bytes: &[u8]) -> bool {
    if bytes.len() <= 4 {
        return false;
    }
    let magic = &bytes[..4];
    magic == SEALED_PAYLOAD_MAGIC
        || magic == DKG_PAYLOAD_MAGIC
        || magic == ORDER_COMMIT_PAYLOAD_MAGIC
        || magic == SHARE_RELEASE_PAYLOAD_MAGIC
        || magic == EPOCH_ANNOUNCE_PAYLOAD_MAGIC
}

// ===========================================================================
// The proposer-side helper
// ===========================================================================

/// The result of trying to unseal a round's sealed transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsealOutcome {
    /// The transaction was unsealed.
    Unsealed(Vec<u8>),
    /// Not enough decryption partials arrived before the deadline.
    NotEnoughShares { have: usize, need: usize },
    /// The ciphertext did not authenticate (tampered, or sealed to another
    /// epoch / committee).
    Undecryptable,
}

/// A bounded, fail-closed unseal attempt.
///
/// The attempt is bounded on purpose: a sealed transaction that cannot be
/// unsealed (a malformed seal, a wrong epoch, a member that withheld its
/// partial) must never be able to stall the proposer. It is dropped, and
/// its fee is charged.
pub fn try_unseal(
    envelope: &SealedEnvelope,
    partials: &[(DecryptionPartial)],
    threshold: usize,
    committee_hash: &[u8; 32],
) -> UnsealOutcome {
    if partials.len() < threshold {
        return UnsealOutcome::NotEnoughShares {
            have: partials.len(),
            need: threshold,
        };
    }
    match unseal_transaction(envelope, partials, threshold, committee_hash) {
        Ok(plain) => UnsealOutcome::Unsealed(plain),
        Err(_) => UnsealOutcome::Undecryptable,
    }
}

// ===========================================================================
// The node-local protocol state
// ===========================================================================

/// The node-local state of the epoch-seal protocol.
///
/// It owns the epoch's DKG, the epoch key material, the order commitments
/// the node has seen, and the decryption partials it has released and
/// received.
///
/// THE GATING RULE (the whole point of the scheme): a node releases its
/// decryption partial for a sealed transaction ONLY after it has seen the
/// proposer's signed order commitment for that round. The commitment fixes
/// the order, so the reveal that follows cannot be used to reorder.
#[derive(Clone, Debug, Default)]
pub struct EpochSealManager {
    /// The epoch the manager is currently working on.
    pub epoch: u64,
    /// The committee of the current epoch.
    committee: Option<EpochCommittee>,
    /// The DKG of the current epoch.
    dkg: Option<EpochDkg>,
    /// Our key material for the current epoch (once the DKG completed).
    material: Option<EpochKeyMaterial>,
    /// The order commitments we have seen, keyed by `(height, round)`.
    commitments: std::collections::HashMap<(u64, u32), OrderCommitment>,
    /// The decryption partials we received from the peers:
    /// `(tx hash, committee index) -> partial`.
    received: std::collections::HashMap<([u8; 32], u32), DecryptionPartial>,
    /// The decryption partials we released ourselves.
    released: std::collections::HashMap<([u8; 32], u32), DecryptionPartial>,
    /// The epoch key announcement we signed.
    announcement: Option<EpochKeyAnnouncement>,
    /// Our 1-based committee index in the current epoch.
    our_index: Option<u32>,
    /// The order commitment of the CURRENT height.
    ///
    /// The commitment is per HEIGHT, not per round: the order a proposer
    /// commits to must not change between the rounds of the same height.
    /// A second commitment for the same height with a DIFFERENT root is
    /// refused (it is the proposer's equivocation).
    height_commitment: Option<(u64, OrderCommitment)>,
    /// How many sealed transactions we unsealed (metrics).
    pub unsealed: u64,
    /// How many sealed transactions we dropped because they could not be
    /// unsealed (metrics).
    pub unseal_failures: u64,
}

impl EpochSealManager {
    /// A manager with no epoch set up yet.
    pub fn new() -> EpochSealManager {
        EpochSealManager::default()
    }

    /// Build the committee of an epoch from the validator set.
    ///
    /// The committee is derived from the validator ids ALONE (the encryption
    /// keys are derived from the public Ed25519 keys), so every node builds
    /// the SAME committee — and therefore the same epoch seed, the same
    /// Shamir abscissae and the same epoch key.
    pub fn committee_for(epoch: u64, validator_ids: &[[u8; 32]]) -> Result<EpochCommittee, String> {
        let mut members = Vec::with_capacity(validator_ids.len());
        for id in validator_ids {
            let enc_pk = encryption_public_key_from_ed25519(id)
                .ok_or_else(|| "validator public key is not a valid curve point".to_string())?;
            members.push(CommitteeMember {
                validator_id: *id,
                enc_pk,
            });
        }
        Ok(EpochCommittee::build(epoch, members))
    }

    /// Move the manager to `epoch`, starting the DKG when the epoch changed.
    ///
    /// Returns our own DKG contribution when there is one to publish (the
    /// first call for an epoch), and `None` afterwards.
    pub fn sync_epoch(
        &mut self,
        epoch: u64,
        validator_ids: &[[u8; 32]],
        our_id: [u8; 32],
        our_seed: &[u8; 32],
    ) -> Result<Option<DkgContribution>, String> {
        if self.epoch == epoch && self.dkg.is_some() {
            return Ok(None);
        }
        self.epoch = epoch;
        self.commitments.clear();
        self.received.clear();
        self.released.clear();
        self.material = None;
        self.announcement = None;
        let committee = Self::committee_for(epoch, validator_ids)?;
        if committee.index_of(&our_id).is_none() {
            // We are not a member of this epoch's committee: no DKG, no
            // share, no release. The plain path keeps working.
            self.committee = Some(committee);
            self.dkg = None;
            return Ok(None);
        }
        let mut dkg = EpochDkg::new(committee.clone(), our_id);
        let enc_secret = encryption_secret_from_ed25519(our_seed);
        let contribution = dkg.contribution(our_id, our_seed, &enc_secret)?;
        self.our_index = committee.index_of(&our_id);
        self.committee = Some(committee);
        self.dkg = Some(dkg);
        Ok(Some(contribution))
    }

    /// The committee of the current epoch.
    pub fn committee(&self) -> Option<&EpochCommittee> {
        self.committee.as_ref()
    }

    /// Our key material for the current epoch (once the DKG completed).
    pub fn material(&self) -> Option<&EpochKeyMaterial> {
        self.material.as_ref()
    }

    /// The epoch public key a wallet encrypts to (once the DKG completed).
    pub fn public_key(&self) -> Option<EpochPublicKey> {
        self.material.as_ref().map(|m| m.public_key())
    }

    /// Ingest a DKG contribution from the network.
    ///
    /// Returns `true` when the contribution was accepted. A malformed or
    /// inconsistent contribution is REFUSED (fail-closed) — it can never
    /// become a share.
    pub fn ingest_contribution(
        &mut self,
        contribution: DkgContribution,
        our_seed: &[u8; 32],
    ) -> Result<bool, String> {
        let Some(dkg) = self.dkg.as_mut() else {
            return Err("no dkg in progress for this epoch".to_string());
        };
        if contribution.epoch != self.epoch {
            return Err("dkg contribution is for another epoch".to_string());
        }
        let enc_secret = encryption_secret_from_ed25519(our_seed);
        dkg.ingest(contribution, &enc_secret)?;
        self.try_finalize();
        Ok(true)
    }

    /// Try to finalize the DKG once enough contributions have arrived.
    fn try_finalize(&mut self) {
        let Some(dkg) = self.dkg.as_mut() else {
            return;
        };
        if dkg.material().is_some() {
            return;
        }
        if !dkg.can_finalize() {
            return;
        }
        if let Ok(material) = dkg.finalize() {
            self.material = Some(material);
        }
    }

    /// Commit to the order of the sealed transactions for this height.
    ///
    /// The FIRST commitment for a height wins: a later commitment with a
    /// different order is REFUSED (the proposer's equivocation), and the
    /// same commitment is returned again (idempotent).
    pub fn commit_order(
        &mut self,
        height: u64,
        round: u32,
        tx_hashes: Vec<[u8; 32]>,
        signer: &SigningKey,
    ) -> Result<OrderCommitment, String> {
        if let Some((h, existing)) = &self.height_commitment {
            if *h == height {
                let candidate = OrderCommitment::sign(self.epoch, height, round, tx_hashes, signer);
                if candidate.order_root == existing.order_root {
                    return Ok(existing.clone());
                }
                return Err(format!(
                    "the order for height {height} was already committed to a different root"
                ));
            }
        }
        let commitment = OrderCommitment::sign(self.epoch, height, round, tx_hashes, signer);
        self.height_commitment = Some((height, commitment.clone()));
        self.commitments.insert((height, round), commitment.clone());
        Ok(commitment)
    }

    /// Record an order commitment we have seen.
    ///
    /// A commitment that does not verify is refused. A valid commitment is
    /// stored, and the caller may then release the partials for the
    /// committed transactions.
    pub fn note_commitment(&mut self, commitment: OrderCommitment) -> Result<(), String> {
        commitment.verify()?;
        self.commitments
            .insert((commitment.height, commitment.round), commitment);
        Ok(())
    }

    /// The order commitment for a round, if we have seen one.
    pub fn commitment(&self, height: u64, round: u32) -> Option<&OrderCommitment> {
        self.commitments.get(&(height, round))
    }

    /// Release our decryption partial for a sealed transaction.
    ///
    /// REFUSED unless the round's order commitment has been seen: the
    /// release is what makes the content readable, so it must never happen
    /// before the order is fixed.
    pub fn release_partial(
        &mut self,
        height: u64,
        round: u32,
        envelope: &SealedEnvelope,
    ) -> Result<DecryptionPartial, String> {
        let commitment = self
            .commitments
            .get(&(height, round))
            .ok_or_else(|| "no order commitment for this round: the release is refused".to_string())?;
        if !commitment.tx_hashes.contains(&envelope.tx_hash) {
            return Err("the sealed transaction is not part of the committed order".to_string());
        }
        let Some(material) = self.material.as_ref() else {
            return Err("no epoch key material for this epoch".to_string());
        };
        let index = self.our_index.unwrap_or(0);
        if index == 0 {
            return Err("this node has no committee index in this epoch".to_string());
        }
        let _ = material;
        let point = compute_partial(&material.share, &envelope.ephemeral_pk)?;
        let partial = DecryptionPartial {
            validator_index: index,
            point,
        };
        self.released
            .insert((envelope.tx_hash, index), partial);
        Ok(partial)
    }

    /// Ingest a share release from a peer.
    ///
    /// The partials are accepted only if they match an order commitment we
    /// have seen: a release for an unknown ordering is refused, so a
    /// malicious peer cannot make us accept decryption material for a
    /// transaction that was never committed to.
    pub fn ingest_release(&mut self, release: ShareRelease) -> Result<usize, String> {
        let known = self
            .commitments
            .values()
            .any(|c| c.order_root == release.order_root && c.epoch == release.epoch);
        if !known {
            return Err("share release does not match any order commitment we know".to_string());
        }
        let mut accepted = 0usize;
        for (tx_hash, partial) in &release.partials {
            if partial.validator_index == 0 {
                continue;
            }
            self.received.insert((*tx_hash, partial.validator_index), *partial);
            accepted += 1;
        }
        Ok(accepted)
    }

    /// The decryption partials we hold for a sealed transaction (ours plus
    /// the peers').
    pub fn partials_for(&self, tx_hash: &[u8; 32]) -> Vec<DecryptionPartial> {
        let mut out: Vec<DecryptionPartial> = Vec::new();
        for ((hash, _), partial) in self.released.iter().chain(self.received.iter()) {
            if hash == tx_hash {
                out.push(*partial);
            }
        }
        out.sort_by_key(|p| p.validator_index);
        out.dedup_by_key(|p| p.validator_index);
        out
    }

    /// The number of partials we hold for a sealed transaction.
    pub fn partial_count(&self, tx_hash: &[u8; 32]) -> usize {
        self.partials_for(tx_hash).len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::Transaction;

    /// One test committee member: an Ed25519 identity (the validator id) and
    /// the matching long-term secret.
    struct TestMember {
        id: [u8; 32],
        secret: [u8; 32],
        enc_secret: [u8; 32],
        enc_pk: [u8; 32],
    }

    fn test_member() -> TestMember {
        let signing = SigningKey::generate(&mut OsRng);
        let secret = signing.to_bytes();
        let enc_secret = encryption_secret_from_ed25519(&secret);
        // The encryption public key is derivable from the PUBLIC validator
        // key alone: that is what keeps the DKG to a single round.
        let enc_pk = encryption_public_key_from_ed25519(&signing.verifying_key().to_bytes())
            .expect("a valid ed25519 public key converts");
        assert_eq!(
            enc_pk,
            encryption_public_key(&enc_secret),
            "the derived public key must match the secret"
        );
        TestMember {
            id: signing.verifying_key().to_bytes(),
            secret,
            enc_secret,
            enc_pk,
        }
    }

    fn test_committee(epoch: u64, n: usize) -> (EpochCommittee, Vec<TestMember>) {
        let members: Vec<TestMember> = (0..n).map(|_| test_member()).collect();
        (build_committee(epoch, &members), members)
    }

    fn build_committee(epoch: u64, members: &[TestMember]) -> EpochCommittee {
        EpochCommittee::build(
            epoch,
            members
                .iter()
                .map(|m| CommitteeMember {
                    validator_id: m.id,
                    enc_pk: m.enc_pk,
                })
                .collect(),
        )
    }

    /// Run the full DKG exchange and return every member's key material.
    fn run_dkg(
        committee: &EpochCommittee,
        members: &[TestMember],
    ) -> Vec<EpochKeyMaterial> {
        let mut dkgs: Vec<EpochDkg> = members
            .iter()
            .map(|m| EpochDkg::new(committee.clone(), m.id))
            .collect();
        let mut contributions = Vec::with_capacity(members.len());
        for (i, m) in members.iter().enumerate() {
            let c = dkgs[i]
                .contribution(m.id, &m.secret, &m.enc_secret)
                .expect("contribution");
            dkgs[i].set_own(c.clone());
            contributions.push(c);
        }
        // Every member ingests EVERY contribution, its own included: the
        // epoch key is the aggregate over the WHOLE committee.
        for i in 0..members.len() {
            for j in 0..members.len() {
                dkgs[i]
                    .ingest(contributions[j].clone(), &members[i].enc_secret)
                    .unwrap_or_else(|e| panic!("member {i} must accept member {j}: {e}"));
            }
        }
        dkgs.into_iter()
            .map(|mut d| d.finalize().expect("finalize"))
            .collect()
    }

    fn meta() -> TransparentMeta {
        TransparentMeta {
            from: [7u8; 32],
            nonce: 3,
            gas_limit: 21_000,
            priority_fee_per_gas: 5,
            source_shard: 0,
            target_shard: 0,
        }
    }

    fn tx_bytes() -> Vec<u8> {
        let sk = SigningKey::generate(&mut OsRng);
        let tx = Transaction::sign(&sk, [1u8; 32], 10, 0, 0, 1, 1);
        bincode::serialize(&tx).unwrap()
    }

    /// THE DKG PRODUCES ONE KEY FOR THE WHOLE COMMITTEE.
    ///
    /// Every member must end up with the SAME epoch public key (the
    /// aggregate of the members' constant-term commitments) and with a
    /// DIFFERENT share. If the members disagreed on the key, a sealed
    /// transaction would be unsealable by some of them and not by others.
    #[test]
    fn dkg_produces_one_shared_epoch_key() {
        let (committee, members) = test_committee(9, 4);
        let materials = run_dkg(&committee, &members);
        assert_eq!(materials.len(), 4);
        for m in &materials {
            assert_eq!(m.public_key, materials[0].public_key, "one epoch key");
            assert_eq!(m.committee_hash, committee.hash);
            assert_eq!(m.transcript_root, materials[0].transcript_root);
            assert_eq!(m.threshold, committee.threshold);
        }
        // The shares are DISTINCT (otherwise the sharing is degenerate).
        let mut shares: Vec<[u8; 32]> = materials.iter().map(|m| m.share).collect();
        shares.sort();
        shares.dedup();
        assert_eq!(shares.len(), 4, "every member must hold a different share");
        // The threshold leaves room for ONE withholding member (n = 4).
        assert_eq!(committee.threshold, 3);
        assert!(committee.threshold < committee.members.len());
    }

    /// A THRESHOLD of shares unseals the transaction — the remaining
    /// validator is not needed.
    #[test]
    fn threshold_of_shares_unseals_without_all_validators() {
        let (committee, members) = test_committee(3, 4);
        let materials = run_dkg(&committee, &members);
        let key = materials[0].public_key();
        let plaintext = tx_bytes();
        let envelope = seal_transaction(&key, &plaintext, [9u8; 32], meta()).unwrap();

        let partials: Vec<DecryptionPartial> = members
            .iter()
            .enumerate()
            .map(|(i, m)| DecryptionPartial {
                validator_index: committee.index_of(&m.id).unwrap(),
                point: compute_partial(&materials[i].share, &envelope.ephemeral_pk).unwrap(),
            })
            .collect();

        // Three of four: the fourth withholds.
        let unsealed = unseal_transaction(
            &envelope,
            &partials[..committee.threshold],
            committee.threshold,
            &committee.hash,
        )
        .expect("a threshold of partials must unseal");
        assert_eq!(unsealed, plaintext);

        // Two of four is NOT enough: the round cannot be unsealed, and the
        // caller must drop the transaction rather than stall.
        assert!(unseal_transaction(
            &envelope,
            &partials[..committee.threshold - 1],
            committee.threshold,
            &committee.hash,
        )
        .is_err());
    }

    /// ANY subset of at least `t` partials yields the SAME shared point:
    /// the reconstruction is subset-independent, so a withholding member
    /// cannot change the outcome — only delay it.
    #[test]
    fn any_threshold_subset_reconstructs_the_same_secret() {
        let (committee, members) = test_committee(4, 4);
        let materials = run_dkg(&committee, &members);
        let key = materials[0].public_key();
        let envelope = seal_transaction(&key, b"payload", [3u8; 32], meta()).unwrap();
        let partials: Vec<DecryptionPartial> = members
            .iter()
            .enumerate()
            .map(|(i, m)| DecryptionPartial {
                validator_index: committee.index_of(&m.id).unwrap(),
                point: compute_partial(&materials[i].share, &envelope.ephemeral_pk).unwrap(),
            })
            .collect();
        let a = combine_partials(&partials[..3], 3).unwrap();
        let b = combine_partials(&partials[1..4], 3).unwrap();
        assert_eq!(a, b, "the shared point must not depend on the subset");
    }

    /// THE CIPHERTEXT NEVER CONTAINS THE PLAINTEXT.
    ///
    /// This is the property the whole scheme exists for: what the network
    /// carries is the ciphertext.
    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        let (committee, members) = test_committee(5, 4);
        let materials = run_dkg(&committee, &members);
        let key = materials[0].public_key();
        let plaintext = b"THE-PLAINTEXT-MARKER-0123456789".to_vec();
        let envelope = seal_transaction(&key, &plaintext, [1u8; 32], meta()).unwrap();
        let wire = bincode::serialize(&envelope).unwrap();
        assert!(
            !wire.windows(plaintext.len()).any(|w| w == plaintext.as_slice()),
            "the sealed wire bytes must not contain the plaintext"
        );
        assert!(!envelope.ciphertext.windows(plaintext.len()).any(|w| w == plaintext.as_slice()));
    }

    /// A WALLET (or any holder) of the epoch-e key material CANNOT decrypt a
    /// transaction sealed for a DIFFERENT epoch.
    #[test]
    fn a_transaction_sealed_for_another_epoch_cannot_be_decrypted() {
        let (committee_e, members_e) = test_committee(11, 4);
        let (committee_e2, members_e2) = test_committee(12, 4);
        let materials = run_dkg(&committee_e, &members_e);
        assert_ne!(
            committee_e.hash, committee_e2.hash,
            "different epochs must have different committees"
        );
        let key = materials[0].public_key();
        let envelope = seal_transaction(&key, b"epoch-11 payload", [2u8; 32], meta()).unwrap();

        // The right shares but the WRONG committee (another epoch): the
        // associated data binds the committee, so the payload fails to
        // authenticate.
        let partials: Vec<DecryptionPartial> = members_e
            .iter()
            .enumerate()
            .map(|(i, m)| DecryptionPartial {
                validator_index: committee_e.index_of(&m.id).unwrap(),
                point: compute_partial(&materials[i].share, &envelope.ephemeral_pk).unwrap(),
            })
            .collect();
        assert!(
            unseal_transaction(
                &envelope,
                &partials[..committee_e.threshold],
                committee_e.threshold,
                &committee_e2.hash,
            )
            .is_err(),
            "a ciphertext sealed for epoch 11 must not unseal under epoch 12's committee"
        );
        // And the epoch public keys themselves differ: a transaction sealed
        // for epoch 11 is sealed to a key the epoch 12 committee cannot open.
        let materials_e2 = run_dkg(&committee_e2, &members_e2);
        assert_ne!(materials[0].public_key, materials_e2[0].public_key);
    }

    /// A MALFORMED SEAL is refused fail-closed, both at the envelope level
    /// and at the DKG level (a tampered contribution never becomes a share).
    #[test]
    fn malformed_seals_are_refused_fail_closed() {
        let (committee, members) = test_committee(6, 4);
        let materials = run_dkg(&committee, &members);
        let key = materials[0].public_key();

        // Structural validation.
        let mut broken = seal_transaction(&key, b"x", [5u8; 32], meta()).unwrap();
        broken.ephemeral_pk = [0xffu8; 32];
        assert!(broken.validate().is_err(), "an invalid ephemeral key is refused");
        let mut empty = broken.clone();
        empty.ephemeral_pk = materials[0].public_key;
        empty.ciphertext.clear();
        assert!(empty.validate().is_err(), "an empty payload is refused");
        let mut zero_hash = empty.clone();
        zero_hash.ciphertext = vec![1, 2, 3];
        zero_hash.tx_hash = [0u8; 32];
        assert!(zero_hash.validate().is_err(), "the reserved tx hash is refused");

        // A tampered DKG contribution is refused (the VSS check fails).
        let mut dkgs: Vec<EpochDkg> = members
            .iter()
            .map(|m| EpochDkg::new(committee.clone(), m.id))
            .collect();
        let mut contributions = Vec::new();
        for (i, m) in members.iter().enumerate() {
            let c = dkgs[i]
                .contribution(m.id, &m.secret, &m.enc_secret)
                .unwrap();
            contributions.push(c);
        }
        let mut tampered = contributions[1].clone();
        tampered.commitments[0] = materials[0].public_key; // a bogus commitment
        assert!(
            dkgs[0]
                .ingest(tampered, &members[0].enc_secret)
                .is_err(),
            "a contribution whose evaluation does not match its commitments is refused"
        );

        // A ciphertext that was tampered with in transit does not
        // authenticate: the unseal fails instead of returning garbage.
        let envelope = seal_transaction(&key, b"payload", [6u8; 32], meta()).unwrap();
        let mut tampered_envelope = envelope.clone();
        tampered_envelope.ciphertext[0] ^= 0xff;
        let partials: Vec<DecryptionPartial> = members
            .iter()
            .enumerate()
            .map(|(i, m)| DecryptionPartial {
                validator_index: committee.index_of(&m.id).unwrap(),
                point: compute_partial(&materials[i].share, &envelope.ephemeral_pk).unwrap(),
            })
            .collect();
        assert!(matches!(
            try_unseal(
                &tampered_envelope,
                &partials[..committee.threshold],
                committee.threshold,
                &committee.hash
            ),
            UnsealOutcome::Undecryptable
        ));
    }

    /// The bounded unseal attempt reports "not enough shares" instead of
    /// stalling, so the proposer can drop the transaction and charge the fee.
    #[test]
    fn a_withholding_member_cannot_stall_the_round() {
        let (committee, members) = test_committee(8, 4);
        let materials = run_dkg(&committee, &members);
        let key = materials[0].public_key();
        let envelope = seal_transaction(&key, b"payload", [8u8; 32], meta()).unwrap();
        let partials: Vec<DecryptionPartial> = members
            .iter()
            .enumerate()
            .map(|(i, m)| DecryptionPartial {
                validator_index: committee.index_of(&m.id).unwrap(),
                point: compute_partial(&materials[i].share, &envelope.ephemeral_pk).unwrap(),
            })
            .collect();
        // Only two of the three required partials arrived.
        let outcome = try_unseal(
            &envelope,
            &partials[..2],
            committee.threshold,
            &committee.hash,
        );
        assert!(matches!(
            outcome,
            UnsealOutcome::NotEnoughShares { have: 2, need: 3 }
        ));
    }

    /// Duplicate partial indices are refused: the Lagrange denominator would
    /// be zero and the reconstruction silently wrong.
    #[test]
    fn duplicate_partial_indices_are_refused() {
        let (committee, members) = test_committee(2, 4);
        let materials = run_dkg(&committee, &members);
        let key = materials[0].public_key();
        let envelope = seal_transaction(&key, b"payload", [4u8; 32], meta()).unwrap();
        let p0 = DecryptionPartial {
            validator_index: 1,
            point: compute_partial(&materials[0].share, &envelope.ephemeral_pk).unwrap(),
        };
        let mut dup = p0;
        dup.point = compute_partial(&materials[1].share, &envelope.ephemeral_pk).unwrap();
        assert!(combine_partials(&[p0, dup], 2).is_err());
    }

    /// The order commitment is signed over a domain-separated, round-bound
    /// message and is refused when its list does not match its root.
    #[test]
    fn the_order_commitment_is_signed_and_round_bound() {
        let signer = SigningKey::generate(&mut OsRng);
        let commit = OrderCommitment::sign(2, 100, 3, vec![[1u8; 32], [2u8; 32]], &signer);
        assert!(commit.verify().is_ok());
        let mut relabelled = commit.clone();
        relabelled.round = 4;
        assert!(relabelled.verify().is_err(), "the round is bound");
        let mut tampered = commit.clone();
        tampered.tx_hashes.push([9u8; 32]);
        assert!(tampered.verify().is_err(), "the list must match the root");
    }

    /// The epoch key announcement needs a quorum of DISTINCT member
    /// signatures: a repeated signer must not be able to fake it.
    #[test]
    fn the_epoch_announcement_counts_distinct_signers() {
        let signer = SigningKey::generate(&mut OsRng);
        let mut ann = EpochKeyAnnouncement::sign(
            4,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            3,
            vec![(1, [4u8; 32])],
            &signer,
        );
        assert_eq!(ann.valid_signature_count(), 1);
        assert!(!ann.has_quorum(2));
        ann.signatures.push(ann.signatures[0].clone());
        assert_eq!(ann.valid_signature_count(), 1, "duplicates never count twice");
        let other = SigningKey::generate(&mut OsRng);
        ann.add_signature(&other);
        assert_eq!(ann.valid_signature_count(), 2);
        assert!(ann.has_quorum(2));
    }

    /// THE ENCRYPTION KEY PAIR IS A REAL DIFFIE-HELLMAN PAIR.
    ///
    /// The committee's encryption keys are derived from the validators'
    /// PUBLIC Ed25519 keys, so a peer that knows only the validator set can
    /// address a key-share package to any member. The conversion must be a
    /// genuine birational map: both sides must agree on the shared secret.
    #[test]
    fn the_derived_encryption_keys_agree_on_a_shared_secret() {
        let a = test_member();
        let b = test_member();
        let sa = XStaticSecret::from(a.enc_secret);
        let sb = XStaticSecret::from(b.enc_secret);
        let ab = sa.diffie_hellman(&XPublicKey::from(b.enc_pk));
        let ba = sb.diffie_hellman(&XPublicKey::from(a.enc_pk));
        assert_eq!(ab.as_bytes(), ba.as_bytes());
        // And it is NOT the trivial value: the two sides differ.
        assert_ne!(ab.as_bytes(), &a.enc_secret[..]);
    }

    /// The committee is order-independent: the same validator set always
    /// yields the same committee (and therefore the same Shamir abscissae
    /// and the same epoch key on every node).
    #[test]
    fn the_committee_is_derived_deterministically() {
        let members: Vec<TestMember> = (0..4).map(|_| test_member()).collect();
        let a = build_committee(1, &members);
        let b = build_committee(1, &members);
        assert_eq!(a.hash, b.hash, "the same validator set yields the same committee");
        assert_eq!(a.threshold, b.threshold);
        // The epoch number is bound into the committee hash.
        let c = build_committee(2, &members);
        assert_ne!(a.hash, c.hash);
    }
}
