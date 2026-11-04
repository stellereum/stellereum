//! Zero-Overhead MEV-Preemption (Threshold Encryption / Blind Pre-Rounds)
//! Prevents front-running and sandwich attacks without TEE/SGX hardware.
//! Transactions are encrypted using an ephemeral round key before entering mempool.
//! The key is split via Shamir's Secret Sharing across validators (threshold T-of-N).
//! Validators sign the blind round commitment; once the transaction ordering is locked,
//! validators release their shares, reconstructing the round key and executing txs.
//!
//! # What is wired on the REAL path, and what is deferred
//!
//! The threshold protocol above needs two things the node/network does not have
//! yet, so this module ships only what can actually be enforced end to end:
//!
//! * **Sealed at admission, unsealed at block build** (wired): every transaction
//!   admitted through `Mempool::insert` is sealed under a node-local round key
//!   and kept as an envelope keyed by tx hash. The block build re-opens each
//!   selected envelope and requires an exact byte match against the pool copy
//!   before the transaction may enter a block (`verify_pool_tx`), and the build
//!   records a signed commitment of the exact execution order
//!   (`commit_block_order`).
//!
//! * **Order commitment is CONSENSUS-ENFORCED** (wired): the block itself
//!   carries the order commitment — the order Merkle root over the exact
//!   ordered transaction list ([`compute_order_merkle_root`]) — in
//!   `Block::order_merkle_root`, and the root is inside the signed block hash
//!   (see `Block::compute_hash`). A validator RE-COMPUTES the root from the
//!   proposed body and REFUSES the proposal when it does not match, so the
//!   BFT quorum signs the ordering and a proposer cannot reorder a block after
//!   it has been voted on. The node-local `order_commits` map
//!   (`commit_block_order` / `verify_block_order`) is kept as an OPTIMIZATION
//!   and extra evidence: the consensus check is the authority.
//!   Mutating a pooled transaction between admission and build, or executing an
//!   order this node never committed, is refused.
//!
//! # THE PRIVATE PATH IS `crate::mev_epoch`, NOT THIS MODULE
//!
//! The node-local round key of this module lives in ONE process, so it hides
//! nothing from that process: it is a TAMPER CHECK on the pool copy, not a
//! privacy mechanism. The ASYMMETRIC, threshold-sealed path — an epoch public
//! key the wallet encrypts to, a committee that shares the epoch secret, sealed
//! gossip, a share release that follows the order commitment, and the epoch key
//! committed to the block — lives in [`crate::mev_epoch`] and is wired into
//! the mempool, the gossip channel, the proposer path and the RPC. The
//! threat model (what it protects against and what it does NOT) is written
//! down in `docs/MEV.md`; read it before claiming that this chain hides
//! anything from a mempool snooper.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdKeyShare {
    pub validator_id: u32,
    pub share_lo: [u8; 32],
    pub share_hi: [u8; 32],
}

impl std::fmt::Debug for ThresholdKeyShare {
    /// SECRET HYGIENE (pentest P4): the two halves are Shamir shares of the
    /// round key — any threshold of them decrypts every transaction sealed
    /// for the round. The derived `Debug` printed both into logs/errors.
    /// Only the (public) owner id is shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdKeyShare")
            .field("validator_id", &self.validator_id)
            .field("share_lo", &"[REDACTED]")
            .field("share_hi", &"[REDACTED]")
            .finish()
    }
}

/// Shamir's Secret Sharing over Curve25519 scalar field
pub struct ShamirSecretSharing;

impl ShamirSecretSharing {
    /// Split a 32-byte symmetric key into `total_shares` shares with reconstruction `threshold`
    pub fn split(key: &[u8; 32], threshold: usize, total_shares: usize) -> Vec<ThresholdKeyShare> {
        assert!(threshold >= 1 && threshold <= total_shares);

        let mut lo_bytes = [0u8; 32];
        lo_bytes[..16].copy_from_slice(&key[..16]);
        let s_lo = Scalar::from_bytes_mod_order(lo_bytes);

        let mut hi_bytes = [0u8; 32];
        hi_bytes[..16].copy_from_slice(&key[16..]);
        let s_hi = Scalar::from_bytes_mod_order(hi_bytes);

        let mut rng = OsRng;
        let mut poly_lo = vec![s_lo];
        let mut poly_hi = vec![s_hi];

        for _ in 1..threshold {
            poly_lo.push(Scalar::random(&mut rng));
            poly_hi.push(Scalar::random(&mut rng));
        }

        let mut shares = Vec::with_capacity(total_shares);
        for x_idx in 1..=total_shares {
            let x = Scalar::from(x_idx as u64);
            let mut y_lo = Scalar::ZERO;
            let mut y_hi = Scalar::ZERO;
            let mut x_pow = Scalar::ONE;

            for coeff in &poly_lo {
                y_lo += coeff * x_pow;
                x_pow *= x;
            }

            x_pow = Scalar::ONE;
            for coeff in &poly_hi {
                y_hi += coeff * x_pow;
                x_pow *= x;
            }

            shares.push(ThresholdKeyShare {
                validator_id: x_idx as u32,
                share_lo: y_lo.to_bytes(),
                share_hi: y_hi.to_bytes(),
            });
        }

        shares
    }

    /// Reconstruct 32-byte secret key from at least `threshold` shares using Lagrange interpolation at x = 0
    ///
    /// AUDIT W6.5 (fail-closed on a malformed share set): the share
    /// identifiers are the ABSCISSAE of the Lagrange interpolation, so two
    /// shares with the same `validator_id` make the interpolation
    /// denominator zero. `Scalar::invert()` maps zero to zero (it is a
    /// total function, not a partial one), so the old code silently
    /// returned a WRONG key instead of an error — the caller then failed to
    /// decrypt with it and could not tell "not enough shares" from "the
    /// share set is forged". Duplicate identifiers are now refused.
    pub fn reconstruct(shares: &[ThresholdKeyShare]) -> Result<[u8; 32], String> {
        if shares.is_empty() {
            return Err("No shares provided for reconstruction".to_string());
        }

        // Distinct abscissae are required: a duplicate x makes the Lagrange
        // denominator zero and the reconstruction silently wrong.
        let mut seen = std::collections::HashSet::with_capacity(shares.len());
        for s in shares {
            if !seen.insert(s.validator_id) {
                return Err(format!(
                    "Duplicate share identifier {}: the reconstruction would be ill-defined",
                    s.validator_id
                ));
            }
            if s.validator_id == 0 {
                return Err("Share identifier 0 is reserved (the secret's abscissa)".to_string());
            }
        }

        let mut xs = Vec::with_capacity(shares.len());
        let mut ys_lo = Vec::with_capacity(shares.len());
        let mut ys_hi = Vec::with_capacity(shares.len());

        for s in shares {
            xs.push(Scalar::from(s.validator_id as u64));
            ys_lo.push(Scalar::from_bytes_mod_order(s.share_lo));
            ys_hi.push(Scalar::from_bytes_mod_order(s.share_hi));
        }

        let mut secret_lo = Scalar::ZERO;
        let mut secret_hi = Scalar::ZERO;

        for j in 0..shares.len() {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;

            for k in 0..shares.len() {
                if k != j {
                    // For x = 0: (0 - x_k) / (x_j - x_k) = -x_k / (x_j - x_k)
                    num *= -xs[k];
                    den *= xs[j] - xs[k];
                }
            }

            let lagrange_coeff = num * den.invert();
            secret_lo += ys_lo[j] * lagrange_coeff;
            secret_hi += ys_hi[j] * lagrange_coeff;
        }

        let lo_bytes = secret_lo.to_bytes();
        let hi_bytes = secret_hi.to_bytes();

        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&lo_bytes[..16]);
        key[16..].copy_from_slice(&hi_bytes[..16]);

        Ok(key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindTransactionEnvelope {
    pub round_number: u64,
    pub tx_hash: [u8; 32],
    pub encrypted_payload: Vec<u8>,
    pub nonce: [u8; 24],
    pub sender_ephemeral_pub: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindRoundCommitment {
    pub round_number: u64,
    pub tx_hashes: Vec<[u8; 32]>,
    pub merkle_root: [u8; 32],
    pub validator_shares: Vec<([u8; 32], Vec<u8>)>,
}

/// Result of checking a mempool transaction against the envelope sealed for it
/// at admission (`MevPreemptionEngine::verify_pool_tx`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealVerdict {
    /// No envelope exists for this transaction (admitted before the engine was
    /// attached, or restored from a persisted pool — envelopes are node-local
    /// and in-memory only). Nothing to check; the transaction is admitted as-is.
    NotSealed,
    /// The envelope unseals to exactly the bytes of the pool transaction.
    Match,
    /// The envelope unseals, but to DIFFERENT bytes than the pool transaction:
    /// the pool copy was mutated after admission. Fail closed.
    Mismatch,
    /// The envelope does not unseal (tampered or truncated ciphertext, wrong
    /// round key). Fail closed.
    UnsealFailed,
}

/// Result of checking a block's execution order against the order committed at
/// block build (`MevPreemptionEngine::verify_block_order`).
///
/// The LOCAL witness. The AUTHORITY is the consensus check: the block carries
/// the order root itself (`Block::order_merkle_root`) and the root is inside
/// the signed block hash, so every validator re-computes it from the proposed
/// body and refuses a proposal that does not match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderVerdict {
    /// This node committed no order for this `(height, block hash)` (it did
    /// not build this block, or the node restarted — commitments are
    /// in-memory). Nothing to enforce locally; the CONSENSUS check (the order
    /// root inside the block) is the authority and runs on every node.
    NoCommit,
    /// The block executes exactly the order this node committed when it built
    /// this block hash.
    Match,
    /// This node built this block hash, but the transactions about to execute
    /// are not the ones it committed (the body was reordered/edited after the
    /// build). Refuse to execute it.
    Mismatch,
    /// The commitment for this block exists but does not carry a valid
    /// distinct-signer signature (the commitment itself was tampered with).
    BadCommitment,
}

/// Cap on how far behind the current height order commitments are retained.
/// A decide can only happen at the height being worked, so entries older than
/// this are dead evidence; dropping them keeps the map bounded without ever
/// evicting a live commitment (which would turn a decided-earlier-build into a
/// false gate failure).
const ORDER_COMMIT_LOOKBACK: u64 = 4;

/// Domain separator of the ORDER commitment (the order Merkle root).
///
/// Every hash of the construction below is mixed with this tag and a role
/// byte, so a leaf can never be read as an inner node, and the construction
/// can never collide with any other hash the node computes.
pub const ORDER_ROOT_DOMAIN: &[u8; 17] = b"STELL_ORDER_ROOT1";

/// Domain separator of the ORDER-COMMITMENT SIGNATURE.
///
/// AUDIT W6.5: the commitment used to be signed as the BARE 32-byte order
/// root. The same bytes are a public value that other parts of the node
/// compute and hash, so a signature over them was not bound to the
/// commitment protocol at all, and it did not commit to the ROUND the
/// ordering was for: a commitment produced for round R could be replayed
/// into a commitment claiming round R' (the round is an UNSIGNED field of
/// the commitment). The signed message is now domain-separated and binds
/// the round.
pub const ORDER_COMMIT_SIG_DOMAIN: &[u8; 23] = b"STELL_ORDER_COMMIT_SIG1";

/// The exact bytes a validator signs to commit to an execution order.
///
/// `ORDER_COMMIT_SIG_DOMAIN || round (u64 BE) || order_root`
pub fn order_commitment_signing_message(round: u64, merkle_root: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ORDER_COMMIT_SIG_DOMAIN.len() + 8 + 32);
    msg.extend_from_slice(ORDER_COMMIT_SIG_DOMAIN);
    msg.extend_from_slice(&round.to_be_bytes());
    msg.extend_from_slice(merkle_root);
    msg
}

/// The order Merkle root over an ORDERED list of transaction hashes.
///
/// CONSTRUCTION (deterministic, length-prefixed, BLAKE3):
///
/// ```text
/// leaf(i)  = BLAKE3(DOMAIN || 0x00 || hash_i)
/// node(l,r) = BLAKE3(DOMAIN || 0x01 || l || r)
/// tree      = pairwise fold of the leaves; an ODD trailing node is PROMOTED
///             (carried up unchanged) — never duplicated, so two different
///             lists can never share a tree shape
/// root      = BLAKE3(DOMAIN || 0x02 || len_u64_be || tree)
/// ```
///
/// The length is bound into the root, so the commitment is unambiguous about
/// how many transactions it covers.
///
/// The EMPTY list has NO order to commit and therefore the ALL-ZERO root —
/// the one value that cannot be produced by the construction above (a
/// non-empty list is re-hashed with a counter until its root is non-zero), so
/// "no commitment" and "a commitment over some list" can never be confused.
pub fn order_merkle_root_of_hashes(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = hashes
        .iter()
        .map(|h| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ORDER_ROOT_DOMAIN);
            hasher.update(&[0x00u8]);
            hasher.update(h);
            *hasher.finalize().as_bytes()
        })
        .collect();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut pair = level.chunks_exact(2);
        for c in pair.by_ref() {
            let mut hasher = blake3::Hasher::new();
            hasher.update(ORDER_ROOT_DOMAIN);
            hasher.update(&[0x01u8]);
            hasher.update(&c[0]);
            hasher.update(&c[1]);
            next.push(*hasher.finalize().as_bytes());
        }
        // Odd trailing node: PROMOTED unchanged (never duplicated — a
        // duplicated last leaf is the classic CVE-2012-2459 ambiguity).
        if let Some(last) = pair.remainder().first() {
            next.push(*last);
        }
        level = next;
    }
    let tree = level[0];
    let mut hasher = blake3::Hasher::new();
    hasher.update(ORDER_ROOT_DOMAIN);
    hasher.update(&[0x02u8]);
    hasher.update(&(hashes.len() as u64).to_be_bytes());
    hasher.update(&tree);
    let mut root = *hasher.finalize().as_bytes();
    // Guarantee the non-empty root is never the all-zero "no commitment"
    // value: re-hash with a counter until it is non-zero (cryptographically
    // unreachable in practice, but the invariant must not depend on that).
    let mut counter: u8 = 0;
    while root == [0u8; 32] {
        counter = counter.wrapping_add(1);
        let mut retry = blake3::Hasher::new();
        retry.update(ORDER_ROOT_DOMAIN);
        retry.update(&[0x03u8]);
        retry.update(&counter.to_be_bytes());
        retry.update(&tree);
        root = *retry.finalize().as_bytes();
    }
    root
}

/// The order Merkle root over an ORDERED list of transactions: the
/// commitment every block carries in `Block::order_merkle_root` and every
/// validator re-computes before it accepts a proposal.
///
/// PURE: a function of the transaction list alone (no state, no clock, no
/// node-local key), so the proposer and every validator derive the SAME root
/// from the SAME body — that is what makes it a consensus commitment rather
/// than a local opinion.
///
/// The empty list yields the all-zero root (there is no order to commit).
pub fn compute_order_merkle_root(txs: &[crate::sharding::Transaction]) -> [u8; 32] {
    if txs.is_empty() {
        return [0u8; 32];
    }
    let hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.compute_tx_hash()).collect();
    order_merkle_root_of_hashes(&hashes)
}

#[derive(Clone)]
pub struct MevPreemptionEngine {
    pub round_keys: std::collections::HashMap<u64, [u8; 32]>,
    pub round_commits: std::collections::HashMap<u64, BlindRoundCommitment>,
    pub threshold_shares: std::collections::HashMap<u64, Vec<ThresholdKeyShare>>,
    /// Sealed copy of every transaction admitted to the local mempool, keyed by
    /// tx hash. The pool keeps the plaintext (fee order and nonce filters need
    /// it); this envelope is the admission-time binding that the block build
    /// re-opens and compares against before executing (see `verify_pool_tx`).
    ///
    /// In-memory only: `Mempool` serializes with `#[serde(skip)]` on the engine,
    /// so persisted pools stay byte-identical and a restart simply starts with
    /// `SealVerdict::NotSealed` for restored transactions.
    pub pool_envelopes: std::collections::HashMap<[u8; 32], BlindTransactionEnvelope>,
    /// Per-`(height, block hash)` order commitments this node made at block
    /// build, each signed by the node's validator key. Consumed by
    /// `verify_block_order` right before a locally-built block is executed.
    ///
    /// Keyed by the voted block hash rather than height alone: a proposer may
    /// legitimately rebuild at its own height (fresh body per round it owns),
    /// and whichever build the network decides must still find ITS commitment
    /// — evicting an earlier build's root would refuse a perfectly honest
    /// finalize.
    pub order_commits: std::collections::HashMap<(u64, [u8; 32]), BlindRoundCommitment>,
}

impl std::fmt::Debug for MevPreemptionEngine {
    /// SECRET HYGIENE (pentest P4): `round_keys` holds LIVE round keys and
    /// `threshold_shares` their Shamir shares — the derived `Debug` printed
    /// all of them into any log line holding the engine (and `Mempool`
    /// derives `Debug` with the engine inside). Counts are what operators
    /// debug pool stalls with; key material is never shown.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MevPreemptionEngine")
            .field("round_key_count", &self.round_keys.len())
            .field("round_commit_count", &self.round_commits.len())
            .field("threshold_share_rounds", &self.threshold_shares.len())
            .field("pool_envelope_count", &self.pool_envelopes.len())
            .field("order_commit_count", &self.order_commits.len())
            .finish()
    }
}

impl Default for MevPreemptionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MevPreemptionEngine {
    pub fn new() -> Self {
        Self {
            round_keys: std::collections::HashMap::new(),
            round_commits: std::collections::HashMap::new(),
            threshold_shares: std::collections::HashMap::new(),
            pool_envelopes: std::collections::HashMap::new(),
            order_commits: std::collections::HashMap::new(),
        }
    }

    /// Generate an ephemeral round key for the upcoming blind round
    pub fn prepare_round(&mut self, round: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        self.round_keys.insert(round, key);
        key
    }

    /// Prepare round with Shamir threshold secret sharing
    pub fn prepare_threshold_round(
        &mut self,
        round: u64,
        threshold: usize,
        total_validators: usize,
    ) -> ([u8; 32], Vec<ThresholdKeyShare>) {
        let key = self.prepare_round(round);
        let shares = ShamirSecretSharing::split(&key, threshold, total_validators);
        self.threshold_shares.insert(round, shares.clone());
        (key, shares)
    }

    /// User/Bot encrypts transaction to the current round key (blind pre-round)
    pub fn seal_transaction(
        round: u64,
        round_key: &[u8; 32],
        raw_tx_bytes: &[u8],
    ) -> Result<BlindTransactionEnvelope, String> {
        let cipher = XChaCha20Poly1305::new(round_key.into());
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let xnonce = XNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(xnonce, raw_tx_bytes)
            .map_err(|e| format!("Encryption error: {:?}", e))?;

        let tx_hash: [u8; 32] = Sha256::digest(raw_tx_bytes).into();

        Ok(BlindTransactionEnvelope {
            round_number: round,
            tx_hash,
            encrypted_payload: ciphertext,
            nonce,
            sender_ephemeral_pub: [0u8; 32],
        })
    }

    /// Validators commit to the order of sealed transactions before decryption key release
    pub fn commit_blind_round(
        &mut self,
        round: u64,
        envelopes: &[BlindTransactionEnvelope],
        validators: &[SigningKey],
    ) -> BlindRoundCommitment {
        let tx_hashes: Vec<[u8; 32]> = envelopes.iter().map(|e| e.tx_hash).collect();

        let merkle_root: [u8; 32] = order_merkle_root_of_hashes(&tx_hashes);

        // Sign committed ordering (domain-separated, round-bound: see
        // `order_commitment_signing_message`).
        let sign_msg = order_commitment_signing_message(round, &merkle_root);
        let mut shares = Vec::new();
        for val_key in validators {
            let sig = val_key.sign(&sign_msg);
            shares.push((val_key.verifying_key().to_bytes(), sig.to_vec()));
        }

        let commitment = BlindRoundCommitment {
            round_number: round,
            tx_hashes,
            merkle_root,
            validator_shares: shares,
        };

        self.round_commits.insert(round, commitment.clone());
        commitment
    }

    /// Reveal round key and unseal transaction after ordering commitment is signed
    pub fn unseal_transaction(
        &self,
        envelope: &BlindTransactionEnvelope,
    ) -> Result<Vec<u8>, String> {
        let round_key = self
            .round_keys
            .get(&envelope.round_number)
            .ok_or_else(|| "Round key not revealed or not found".to_string())?;

        let cipher = XChaCha20Poly1305::new(round_key.into());
        let xnonce = XNonce::from_slice(&envelope.nonce);

        let plaintext = cipher
            .decrypt(xnonce, envelope.encrypted_payload.as_ref())
            .map_err(|e| format!("Decryption error: {:?}", e))?;

        Ok(plaintext)
    }

    /// Unseal transaction using threshold revealed validator shares
    pub fn unseal_with_shares(
        &self,
        envelope: &BlindTransactionEnvelope,
        shares: &[ThresholdKeyShare],
    ) -> Result<Vec<u8>, String> {
        let reconstructed_key = ShamirSecretSharing::reconstruct(shares)?;
        let cipher = XChaCha20Poly1305::new((&reconstructed_key).into());
        let xnonce = XNonce::from_slice(&envelope.nonce);

        let plaintext = cipher
            .decrypt(xnonce, envelope.encrypted_payload.as_ref())
            .map_err(|e| format!("Decryption error: {:?}", e))?;

        Ok(plaintext)
    }

    /// Verify a blind-round commitment carries a real quorum.
    /// SECURITY: counts each DISTINCT validator at most once — otherwise a single
    /// key signing the same commitment N times would fake a quorum and let one
    /// party control the pre-round ordering (front-running / censorship).
    ///
    /// AUDIT W6.5: the commitment is now checked for INTERNAL consistency
    /// too — the signed order root must be the root of the transaction list
    /// the commitment carries, and the signatures are over the
    /// domain-separated, round-bound message
    /// ([`order_commitment_signing_message`]). A commitment whose `tx_hashes`
    /// do not match its `merkle_root` is refused: the root is the thing the
    /// quorum actually voted for, and a list that does not hash to it is a
    /// different (unchecked) claim.
    pub fn verify_round_commitment(
        commitment: &BlindRoundCommitment,
        quorum_needed: usize,
    ) -> bool {
        // The committed list must hash to the committed root.
        if commitment.merkle_root != order_merkle_root_of_hashes(&commitment.tx_hashes) {
            return false;
        }
        let sign_msg =
            order_commitment_signing_message(commitment.round_number, &commitment.merkle_root);
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut valid_count = 0;
        for (pubkey, sig_bytes) in &commitment.validator_shares {
            if !seen.insert(*pubkey) {
                continue; // duplicate signer
            }
            if let Ok(vk) = VerifyingKey::from_bytes(pubkey) {
                if let Ok(sig) = Signature::from_slice(sig_bytes) {
                    if vk.verify(&sign_msg, &sig).is_ok() {
                        valid_count += 1;
                    }
                }
            }
        }
        valid_count >= quorum_needed
    }

    // ------------------------------------------------------------------
    // Real-path wiring: mempool admission sealing + block-build commitments
    // ------------------------------------------------------------------

    /// The blind round used for mempool admission sealing. Node-local and
    /// single-round for this phase: the key lives only in this process, and
    /// envelopes are dropped with their transactions. A real multi-round
    /// scheme (per-height keys released through threshold shares) needs the
    /// share-release protocol that is explicitly deferred — see the module
    /// docs.
    const POOL_ROUND: u64 = 0;

    /// Seal `tx_bytes` at mempool admission, keyed by `tx_hash`.
    ///
    /// This is the "seal at admission" half of the preemption pipeline, wired
    /// into `Mempool::insert`: from here on the pool's plaintext copy is bound
    /// to this ciphertext, and `verify_pool_tx` must unseal an exact byte
    /// match before the transaction may be selected into a block.
    pub fn seal_admitted(&mut self, tx_hash: &[u8; 32], tx_bytes: &[u8]) {
        let key = match self.round_keys.get(&Self::POOL_ROUND) {
            Some(k) => *k,
            None => self.prepare_round(Self::POOL_ROUND),
        };
        match Self::seal_transaction(Self::POOL_ROUND, &key, tx_bytes) {
            Ok(env) => {
                self.pool_envelopes.insert(*tx_hash, env);
            }
            // XChaCha20Poly1305 encryption cannot fail with a random nonce; if
            // it somehow does, admitting WITHOUT an envelope is the safe
            // direction (`NotSealed` is checked, `UnsealFailed` would drop a
            // healthy transaction).
            Err(e) => {
                tracing::warn!(%e, "mev: failed to seal transaction at admission; admitted unsealed");
            }
        }
    }

    /// Drop the sealed envelope for a transaction leaving the pool.
    pub fn drop_envelope(&mut self, tx_hash: &[u8; 32]) {
        self.pool_envelopes.remove(tx_hash);
    }

    /// Check the pool's copy of `tx` against the envelope sealed at admission.
    ///
    /// Called by the block build for every selected transaction: a transaction
    /// whose ciphertext no longer decrypts to exactly its pool bytes never
    /// reaches a block (mutated pool copy, corrupted envelope, wrong key).
    pub fn verify_pool_tx(&self, tx: &crate::sharding::Transaction) -> SealVerdict {
        let hash = tx.compute_tx_hash();
        let Some(env) = self.pool_envelopes.get(&hash) else {
            return SealVerdict::NotSealed;
        };
        let plaintext = match self.unseal_transaction(env) {
            Ok(p) => p,
            Err(_) => return SealVerdict::UnsealFailed,
        };
        match bincode::serialize(tx) {
            Ok(bytes) if bytes == plaintext => SealVerdict::Match,
            _ => SealVerdict::Mismatch,
        }
    }

    /// Commit the execution order of the block this node just built at
    /// `height`, identified by `block_hash`, signed by `signers`.
    ///
    /// The commitment is created at BUILD time — before consensus, before the
    /// block is proposed or voted on — and is what `verify_block_order` checks
    /// at apply time.
    ///
    /// It uses the SAME construction as the block's own order commitment
    /// (`Block::order_merkle_root`, see [`compute_order_merkle_root`]), so the
    /// local evidence and the consensus commitment are directly comparable:
    /// the root this node signed at build time is the root the quorum signed
    /// in the block hash.
    ///
    /// This map is an OPTIMIZATION and extra evidence, NOT the authority: the
    /// authority is the consensus check every validator runs on the proposed
    /// body (the block carries the root and the root is inside the signed
    /// block hash).
    pub fn commit_block_order(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        signers: &[SigningKey],
    ) -> BlindRoundCommitment {
        let tx_hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.compute_tx_hash()).collect();
        let merkle_root = order_merkle_root_of_hashes(&tx_hashes);
        let sign_msg = order_commitment_signing_message(height, &merkle_root);
        let mut validator_shares = Vec::with_capacity(signers.len());
        for key in signers {
            let sig = key.sign(&sign_msg);
            validator_shares.push((key.verifying_key().to_bytes(), sig.to_vec()));
        }
        let commitment = BlindRoundCommitment {
            round_number: height,
            tx_hashes,
            merkle_root,
            validator_shares,
        };
        // Re-committing the same (height, hash) is the same body — replace.
        // Different builds of the same height are different keys and coexist.
        self.order_commits
            .insert((height, block_hash), commitment.clone());
        // Bound memory: heights only move forward, so commitments below the
        // lookback can never be consulted again.
        let min_height = height.saturating_sub(ORDER_COMMIT_LOOKBACK);
        self.order_commits.retain(|&(h, _), _| h >= min_height);
        commitment
    }

    /// Check a block's transaction order against the order committed at build
    /// time for exactly this `(height, block hash)`. See [`OrderVerdict`] for
    /// the verdicts.
    ///
    /// STANCE (audit F-08, closed): the seal half is ENFORCED at build
    /// (`verify_pool_tx` drops mutated copies fail-closed) and the ORDER half
    /// is now ENFORCED BY CONSENSUS: the block itself carries the order root
    /// (`Block::order_merkle_root`) inside the signed block hash, and every
    /// validator re-computes it from the proposed body and refuses a proposal
    /// that does not match.
    ///
    /// This local check remains as an OPTIMIZATION and as extra evidence: it
    /// catches a body that was tampered with between the build and the decide
    /// even on a node that never re-validates the proposal. A `Mismatch` here
    /// is a hard refusal (the finalize path refuses to execute the block);
    /// the consensus check is the authority, this one is the local witness.
    pub fn verify_block_order(
        &self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
    ) -> OrderVerdict {
        let Some(commit) = self.order_commits.get(&(height, block_hash)) else {
            return OrderVerdict::NoCommit;
        };
        let tx_hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.compute_tx_hash()).collect();
        let root = order_merkle_root_of_hashes(&tx_hashes);
        if commit.merkle_root != root {
            return OrderVerdict::Mismatch;
        }
        // The matching root alone is not enough: a tampered commitment could
        // have the right bytes and no real signature over them.
        if commit.round_number != height || !Self::verify_round_commitment(commit, 1) {
            return OrderVerdict::BadCommitment;
        }
        OrderVerdict::Match
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// AUDIT W6.5: a malformed share set must be REFUSED, not silently
    /// reconstructed into a wrong key.
    ///
    /// Two shares with the same identifier make the Lagrange denominator
    /// zero; `Scalar::invert()` maps zero to zero, so the old code returned
    /// `Ok(<garbage key>)` — the caller could not tell a forged share set
    /// from an under-determined one.
    #[test]
    fn duplicate_share_identifiers_are_refused() {
        let key = [0x5Au8; 32];
        let shares = ShamirSecretSharing::split(&key, 2, 3);
        assert_eq!(shares.len(), 3);
        // Sanity: the honest reconstruction works.
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[..2]).expect("honest shares");
        assert_eq!(reconstructed, key);

        // A duplicate identifier is refused (it would be ill-defined).
        let mut forged = shares.clone();
        forged[1].validator_id = forged[0].validator_id;
        assert!(
            ShamirSecretSharing::reconstruct(&forged).is_err(),
            "duplicate share identifiers must be refused, not silently mis-reconstructed"
        );

        // The reserved abscissa 0 is refused too.
        let mut zeroed = shares.clone();
        zeroed[0].validator_id = 0;
        assert!(ShamirSecretSharing::reconstruct(&zeroed).is_err());
    }

    /// AUDIT W6.5: the order commitment is signed over a DOMAIN-SEPARATED,
    /// ROUND-BOUND message.
    ///
    /// The old code signed the bare 32-byte order root, and the round was an
    /// UNSIGNED field of the commitment: a commitment produced for round R
    /// could be re-labelled as round R' and still carry a "valid" quorum.
    #[test]
    fn order_commitment_signature_binds_the_round_and_the_domain() {
        let mut engine = MevPreemptionEngine::new();
        let (key, _shares) = engine.prepare_threshold_round(1, 2, 3);
        let env = MevPreemptionEngine::seal_transaction(1, &key, b"tx").unwrap();
        let signers = vec![
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        ];
        let commit = engine.commit_blind_round(1, &[env], &signers);
        assert!(MevPreemptionEngine::verify_round_commitment(&commit, 2));

        // Re-labelling the round invalidates the signatures.
        let mut relabelled = commit.clone();
        relabelled.round_number = 2;
        assert!(
            !MevPreemptionEngine::verify_round_commitment(&relabelled, 2),
            "an order commitment must be bound to its round"
        );

        // A commitment whose transaction list does not hash to its root is
        // refused: the root is what the quorum voted for.
        let mut inconsistent = commit.clone();
        inconsistent.tx_hashes.push([0xEEu8; 32]);
        assert!(
            !MevPreemptionEngine::verify_round_commitment(&inconsistent, 2),
            "a commitment whose list does not match its root must be refused"
        );

        // The signed message is domain separated: it is NOT the bare root.
        let msg = order_commitment_signing_message(1, &commit.merkle_root);
        assert_ne!(msg, commit.merkle_root.to_vec());
        assert!(msg.starts_with(ORDER_COMMIT_SIG_DOMAIN));
        assert!(msg.ends_with(&commit.merkle_root));
    }

    #[test]
    fn duplicate_signers_cannot_fake_round_quorum() {
        let mut engine = MevPreemptionEngine::new();
        let (key, _shares) = engine.prepare_threshold_round(1, 2, 3);
        let env = MevPreemptionEngine::seal_transaction(1, &key, b"tx").unwrap();
        let signers = vec![
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        ];
        let commit = engine.commit_blind_round(1, &[env], &signers);
        assert!(MevPreemptionEngine::verify_round_commitment(&commit, 2));

        // Forged: one honest signer's (pubkey, sig) repeated twice must NOT reach
        // the 2-of-3 quorum.
        let mut forged = commit.clone();
        let (pk, sig) = commit.validator_shares[0].clone();
        forged.validator_shares = vec![(pk, sig.clone()), (pk, sig)];
        assert!(!MevPreemptionEngine::verify_round_commitment(&forged, 2));
    }

    fn tx_pair() -> (crate::sharding::Transaction, crate::sharding::Transaction) {
        let sk = SigningKey::generate(&mut OsRng);
        let a = crate::sharding::Transaction::sign(&sk, [1u8; 32], 10, 0, 0, 1, 1);
        let b = crate::sharding::Transaction::sign(&sk, [2u8; 32], 20, 0, 1, 1, 1);
        (a, b)
    }

    /// The ORDER is part of the commitment: the same transactions in a
    /// different order produce a different root. This is what makes the root
    /// an ordering commitment and not a set commitment.
    #[test]
    fn order_root_changes_when_the_order_changes() {
        let (a, b) = tx_pair();
        let root_ab = compute_order_merkle_root(&[a.clone(), b.clone()]);
        let root_ba = compute_order_merkle_root(&[b.clone(), a.clone()]);
        assert_ne!(
            root_ab, root_ba,
            "reordering the transactions must change the order root"
        );
        // Deterministic: the same list always yields the same root.
        assert_eq!(root_ab, compute_order_merkle_root(&[a.clone(), b.clone()]));
        // The LENGTH is bound in, so a prefix of the list is a different
        // commitment (no length-extension ambiguity).
        assert_ne!(root_ab, compute_order_merkle_root(std::slice::from_ref(&a)));
        // A commitment over a non-empty list is never the "no commitment"
        // value, so "absent" and "present" can never be confused.
        assert_ne!(root_ab, [0u8; 32]);
    }

    /// A block with NO transactions has no order to commit: the root is the
    /// all-zero value, deterministically, on every node.
    #[test]
    fn order_root_is_zero_for_a_block_with_no_transactions() {
        assert_eq!(compute_order_merkle_root(&[]), [0u8; 32]);
        assert_eq!(order_merkle_root_of_hashes(&[]), [0u8; 32]);
        // ... and a non-empty list never collides with it.
        let (a, _) = tx_pair();
        assert_ne!(compute_order_merkle_root(&[a]), [0u8; 32]);
    }

    /// The block-build commitment and the block's own order root are the SAME
    /// value, so the local witness and the consensus commitment are directly
    /// comparable.
    #[test]
    fn build_commitment_root_matches_the_block_order_root() {
        let (a, b) = tx_pair();
        let txs = vec![a, b];
        let mut engine = MevPreemptionEngine::new();
        let signers = vec![SigningKey::generate(&mut OsRng)];
        let commit = engine.commit_block_order(7, [0x11; 32], &txs, &signers);
        assert_eq!(commit.merkle_root, compute_order_merkle_root(&txs));
        assert_eq!(
            engine.verify_block_order(7, [0x11; 32], &txs),
            OrderVerdict::Match
        );
        // The same transactions in another order are a DIFFERENT commitment.
        let mut reordered = txs.clone();
        reordered.swap(0, 1);
        assert_eq!(
            engine.verify_block_order(7, [0x11; 32], &reordered),
            OrderVerdict::Mismatch
        );
    }
}
