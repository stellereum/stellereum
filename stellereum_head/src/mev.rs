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
//!   (`commit_block_order`) which the local finalize path re-verifies before
//!   executing (`verify_block_order`). Mutating a pooled transaction between
//!   admission and build, or executing an order this node never committed, is
//!   refused.
//! * **Deferred — threshold preemption proper**: the round key is node-local,
//!   so this phase does NOT hide transactions from the proposer itself. Doing
//!   that needs (a) asymmetric round sealing — submitters encrypt to a round
//!   PUBLIC key (`seal_transaction` is symmetric, so sharing its key with
//!   submitters would share it with every observer), (b) a share-release round
//!   where validators release their Shamir shares only after a quorum-signed
//!   ordering commitment, and (c) sealed mempool gossip. None of these have a
//!   wire slot today: `Block` cannot gain a field (bincode verdict) and the
//!   gossip layer has no commitment/share message. They are deliberately left
//!   unwired rather than simulated — a node-local "threshold" where one process
//!   holds every share would be security theater.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdKeyShare {
    pub validator_id: u32,
    pub share_lo: [u8; 32],
    pub share_hi: [u8; 32],
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
    pub fn reconstruct(shares: &[ThresholdKeyShare]) -> Result<[u8; 32], String> {
        if shares.is_empty() {
            return Err("No shares provided for reconstruction".to_string());
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderVerdict {
    /// This node committed no order for this `(height, block hash)` (it did
    /// not build this block, or the node restarted — commitments are
    /// in-memory). Nothing to enforce; consensus decides the block.
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

/// Order-merkle root over a list of transaction hashes: SHA-256 of the
/// concatenated hashes in order. Shared by the blind-round commitment and the
/// block-build commitment so both commit to ordering identically.
fn order_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for h in tx_hashes {
        hasher.update(h);
    }
    hasher.finalize().into()
}

#[derive(Clone, Debug)]
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

        let merkle_root: [u8; 32] = order_root(&tx_hashes);

        // Sign committed ordering
        let mut shares = Vec::new();
        for val_key in validators {
            let sig = val_key.sign(&merkle_root);
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
    pub fn verify_round_commitment(
        commitment: &BlindRoundCommitment,
        quorum_needed: usize,
    ) -> bool {
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut valid_count = 0;
        for (pubkey, sig_bytes) in &commitment.validator_shares {
            if !seen.insert(*pubkey) {
                continue; // duplicate signer
            }
            if let Ok(vk) = VerifyingKey::from_bytes(pubkey) {
                if let Ok(sig) = Signature::from_slice(sig_bytes) {
                    if vk.verify(&commitment.merkle_root, &sig).is_ok() {
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
    /// at apply time. This is the enforceable core of the order-commitment
    /// discipline on the current wire format: `Block` cannot gain a field
    /// (bincode verdict), so the commitment stays node-local evidence rather
    /// than a gossiped artifact.
    pub fn commit_block_order(
        &mut self,
        height: u64,
        block_hash: [u8; 32],
        txs: &[crate::sharding::Transaction],
        signers: &[SigningKey],
    ) -> BlindRoundCommitment {
        let tx_hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.compute_tx_hash()).collect();
        let merkle_root = order_root(&tx_hashes);
        let mut validator_shares = Vec::with_capacity(signers.len());
        for key in signers {
            let sig = key.sign(&merkle_root);
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
        self.order_commits.insert((height, block_hash), commitment.clone());
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
    /// STANCE (audit F-08, verified current): the seal half is ENFORCED at
    /// build (`verify_pool_tx` drops mutated copies fail-closed); the ORDER
    /// half is DETECTION ONLY — the finalize path (`try_finalize`) treats
    /// `Mismatch` as warn-and-converge, never refuse (execution is
    /// deterministic from the voted body, so every node reaches the same root
    /// either way; refusing would stall ONLY the builder while everyone else
    /// moves on). A proposer therefore reorders for profit today with zero
    /// protocol consequence beyond its own logs. VOTE-GATE STAYS DEFERRED:
    /// enforcing order at finalize would need (a) the commitment ON THE WIRE
    /// (a `Block`/gossip field — bincode-frozen, coordinated rollout), so
    /// every validator checks the SAME commitment instead of its own
    /// in-process map, AND (b) a quorum-signed threshold round (the deferred
    /// share-release protocol in the module docs) so the gate cannot be
    /// forged by the proposer alone. Until both ship, warn-only is the
    /// correct call — a local refuse would be a self-DoS, not enforcement.
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
        let root = order_root(&tx_hashes);
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
}
