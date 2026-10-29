//! Light client (P1-b): follow the chain from signed checkpoints and answer
//! balance queries by walking proofs, without ever holding state.
//!
//! # ⛔ EXPLICITLY NON-LIVE (audit 2026-10-14: dead-code decision)
//!
//! This module is a self-contained verification library: it is compiled,
//! unit-tested, and importable — but NOTHING in the node calls into it. No
//! sync path, RPC method, explorer route, or consensus task depends on it
//! (pinned by `tests/audit_rpc_evm_closeout.rs::light_client_not_wired_into_sync`,
//! which fails if `sync.rs` / `main.rs` ever reference it). Owner direction:
//! do NOT delete it (removal is forbidden), do NOT silently wire it in.
//!
//! ## Wiring precondition (why flipping this live is a hardfork-grade change)
//!
//! Making the node *depend* on this client (e.g. serving `stell_getBalanceSpv`
//! only for quorum-anchored roots, or gating sync on light verification)
//! requires, at minimum: (1) a validator-set rotation story (`LightClient`
//! has no way to update its set once constructed — see limitation 1 below);
//! (2) checkpoint provisioning + eclipse/partition handling (limitation 5 —
//! this module fetches nothing); (3) fork-choice agreement across all nodes
//! about which roots are trustworthy (a consensus rule change, i.e. a
//! hardfork); (4) absence-proof support for balance-0 answers (limitation 4).
//! Until those land as an explicit, versioned proposal, this stays library-only.
//!
//! # The gap this fills
//!
//! The RPC layer can already answer `stell_getBalanceSpv` and
//! `stell_tokenBalanceSpv`: it walks a `PatriciaTrie` and hands back the
//! account value, the state root and a Merkle inclusion proof. What it cannot
//! do is say *whose* state that is. Every one of those proofs verifies against
//! whatever root the caller supplies, so a caller has no way to tell a real
//! chain from a peer's invented one. The caller has to take a full node's word
//! for the root, which is the entire trust assumption an SPV client is supposed
//! to remove.
//!
//! This module is the missing half. It keeps:
//!
//!   * a [`ValidatorSet`] it was configured with,
//!   * one trusted recent [`Checkpoint`], and
//!   * a **bounded** window of [`LightHeader`]s above it.
//!
//! A state root only becomes trustworthy when it is attached to a block hash
//! that a quorum of validators precommitted to. So every root this client will
//! verify a proof against is a root it saw committed by a finalized header, and
//! every balance answer comes back with the height that root belongs to.
//!
//! # What finality means here
//!
//! [`Checkpoint::verify`] and [`LightClient::apply_header`] both require a
//! *precommit* quorum certificate. A prevote quorum is deliberately refused: it
//! only says a supermajority saw the value and nothing was locked against it,
//! which is not finality. An earlier version of the adopt path in the engine
//! accepted any precommit quorum without requiring a matching prevote quorum,
//! and a prevote quorum on its own is exactly the kind of thing that let a peer
//! hand a node a block nobody agreed on. Re-check the kind, always.
//!
//! Quorum is counted by *power* over the configured validator set, with each
//! signer counted at most once (a key that signs ten times carries one key's
//! power, not ten), and non-members contribute nothing however well their
//! signature verifies. An empty / zero-power validator set is unreachable for
//! quorum and therefore fails closed rather than degenerating into "one
//! signature is enough".
//!
//! # Bounded by construction
//!
//! The header window is capped (default [`DEFAULT_MAX_HEADERS`]). Once the cap
//! is reached the client refuses further headers and says so: a light client
//! that could walk forever is a light client that has to be told to stop, and
//! "stop and ask for a fresh checkpoint" is the correct stop. The cap is also
//! what bounds the non-reversion check below and the set of roots the client
//! will treat as trusted.
//!
//! # What this does NOT do
//!
//! Stated plainly, because a light client that overstates its guarantees is
//! worse than none:
//!
//! 1. **It does not check that the validator set was ever legitimately
//!    elected.** The set is whatever the operator configured. There is no
//!    staking-ledger audit, no election certificate, no rotation handling —
//!    `LightClient` has no way to update its set once constructed. If the
//!    configured set is wrong, or a quorum of it is Byzantine, then everything
//!    this client concludes is wrong, and it will conclude it confidently. The
//!    set is the entire trust anchor.
//! 2. **It does not verify the trie's internal node hashing.** Proof
//!    verification is delegated to `PatriciaTrie::verify_merkle_proof` (and
//!    through it to `cpat2::CompressedTrie::verify`). The blake3 leaf/branch
//!    hashes are re-used as-is, not re-derived here, so a bug in the trie's
//!    hashing is a bug in this client too.
//! 3. **It does not verify that a header's `state_root` was computed from the
//!    block body.** It cannot: that needs execution. The block hash is opaque
//!    to it, so the binding between "this root" and "this state" is inherited
//!    from the quorum — full nodes are the ones that check a header's root
//!    against the state they applied. What is enforced here is narrower: the
//!    root must travel with a finalized header at a known height, and it must
//!    not roll back to a root an earlier finalized header already superseded.
//! 4. **It has no non-inclusion (absence) proofs.** The trie only emits
//!    inclusion proofs, so absence is not provable. Every failure is reported
//!    as a typed error; nothing here ever turns into "balance 0".
//! 5. **It does not fetch anything.** No gossip, no retry, no peer scoring, no
//!    eclipse or partition detection. Transport is the caller's problem; this
//!    module only decides what to believe once a header or a proof is in hand.
//!    A client that cannot reach an honest full node will simply stop advancing.
//! 6. **The non-reversion check is only as deep as the retained window.** It
//!    sees the checkpoint and the retained headers, and forgets older roots as
//!    they age out. It is a cheap backstop, not a substitute for the quorum.

use crate::cell::{CellHash, MerkleProof, PatriciaTrie};
use crate::consensus::{BlockHash, QuorumCertificate, ValidatorId, ValidatorSet, VoteKind};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fmt;

/// Default number of headers retained above the trusted checkpoint.
///
/// Generous enough that a light client following the tip does not need a
/// checkpoint on every block, small enough that the retained state is a fixed
/// few tens of kilobytes no matter how long the client runs.
pub const DEFAULT_MAX_HEADERS: usize = 2_048;

/// Upper bound on the number of branch points in a Merkle proof path.
///
/// The trie walks one bit of the 32-byte key per branch and refuses to
/// descend past depth 256, so a genuine path has at most 256 steps. Accepting
/// more than that only ever admits a forged path, and each extra step is a
/// blake3 hash an attacker gets to make us compute.
pub const MAX_MERKLE_PATH_STEPS: usize = 256;

/// Value length of a native account leaf: `balance(8, BE) || nonce(8, BE)`.
///
/// Matches `state_engine::InMemoryStateEngine::update_account`, and therefore
/// matches what `Wallet::verify_spv_balance` and
/// `CrossShardMessage::verify_inclusion` already assume.
pub const ACCOUNT_VALUE_LEN: usize = 16;

/// Value length of a token-balance leaf: `balance(8, BE)`.
pub const TOKEN_BALANCE_VALUE_LEN: usize = 8;

// ============================================================================
// Errors
// ============================================================================

/// Why a balance query failed.
///
/// The three cases are kept apart on purpose, because collapsing them is how an
/// SPV client ends up reporting a balance it never proved:
///
///  * [`LightError::RootUntrusted`] — we have no grounds to believe the supplied
///    state root at all, so nothing about the claim can be assessed.
///  * [`LightError::InvalidProof`] — the proof is not something a genuine trie
///    proof could be. This is a protocol violation by whoever produced it.
///    An **empty proof lands here, never in `NotIncluded`**: "here is nothing"
///    is a claim, and treating it as evidence of absence would let any server
///    answer "this account does not exist" by omitting the proof.
///  * [`LightError::NotIncluded`] — the proof is well formed but does not
///    authenticate at the state root this client trusts. The key is not
///    provably part of the state we trust. It is not a balance, and it is not
///    zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LightError {
    /// The supplied state root is not one this client ever finalized.
    RootUntrusted { root: CellHash },
    /// The proof cannot be a genuine trie proof.
    InvalidProof(String),
    /// Well-formed, but it does not authenticate against the trusted root.
    NotIncluded { height: u64, state_root: CellHash },
}

impl fmt::Display for LightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LightError::RootUntrusted { root } => write!(
                f,
                "state root {} was never finalized by this light client",
                hex::encode(root)
            ),
            LightError::InvalidProof(m) => write!(f, "invalid proof: {m}"),
            LightError::NotIncluded { height, state_root } => write!(
                f,
                "key is not provably included in the state committed at height {height} (root {})",
                hex::encode(state_root)
            ),
        }
    }
}

impl std::error::Error for LightError {}

// ============================================================================
// Checkpoint
// ============================================================================

/// A finalized block a light client can trust, with the evidence.
///
/// This is the unit a light client actually believes. The four fields are the
/// facts, and `cert` is the proof that the validators agreed on them: a
/// precommit quorum certificate over `(height, round, block_hash)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Height of the finalized block.
    pub height: u64,
    /// `Block::compute_hash` of the finalized block.
    pub block_hash: BlockHash,
    /// Hash of its parent. This is what makes a checkpoint self-describing: a
    /// peer cannot present an unrelated chain's final block without also
    /// naming where it came from.
    pub parent_hash: BlockHash,
    /// The state root committed by that block.
    pub state_root: CellHash,
    /// Precommit quorum certificate for `block_hash` at `height`.
    pub cert: QuorumCertificate,
}

impl Checkpoint {
    pub fn new(
        height: u64,
        block_hash: BlockHash,
        parent_hash: BlockHash,
        state_root: CellHash,
        cert: QuorumCertificate,
    ) -> Self {
        Self { height, block_hash, parent_hash, state_root, cert }
    }

    /// Derive a checkpoint from an already-verified header.
    pub fn of(header: &LightHeader) -> Self {
        Self {
            height: header.height,
            block_hash: header.block_hash,
            parent_hash: header.prev_hash,
            state_root: header.state_root,
            cert: header.cert.clone(),
        }
    }

    /// Verify the finality claim, and nothing else.
    ///
    /// Refuses, in order:
    ///  * a certificate that is not a **precommit** quorum (a prevote quorum
    ///    is not proof of finality);
    ///  * a certificate bound to a different height or a different block hash
    ///    than the one this checkpoint claims;
    ///  * a validator set with no power, which could otherwise reach quorum
    ///    vacuously;
    ///  * too little power from *distinct validator* signers;
    ///  * signatures that do not verify.
    pub fn verify(&self, validators: &ValidatorSet) -> Result<(), String> {
        verify_finality(&self.cert, self.height, self.block_hash, validators)
            .map_err(|e| format!("checkpoint at height {} rejected: {e}", self.height))
    }

    /// A checkpoint self-referential on its own hash would mean a block hashes
    /// to its parent, which is not something the chain can produce.
    pub fn is_self_referential(&self) -> bool {
        self.block_hash == self.parent_hash
    }
}

/// Shared finality gate: a precommit quorum for exactly this (height, hash).
fn verify_finality(
    cert: &QuorumCertificate,
    height: u64,
    block_hash: BlockHash,
    validators: &ValidatorSet,
) -> Result<(), String> {
    // A prevote quorum is not finality. A supermajority can prevote a value
    // that a minority then locks against in a way that never gets decided, and
    // nothing in a prevote certificate says the value survived that. Only a
    // precommit quorum is the engine's "this block is decided" statement.
    if cert.kind != VoteKind::Precommit {
        return Err(format!(
            "certificate is a {:?} quorum, not a precommit quorum; a prevote quorum is not proof of finality",
            cert.kind
        ));
    }
    // Bound to the claim. A certificate for another height, or for a nil
    // target, proves nothing about this block.
    if cert.height != height {
        return Err(format!(
            "certificate is bound to height {}, not {height}",
            cert.height
        ));
    }
    if cert.block_hash != Some(block_hash) {
        return Err("certificate does not name this block hash".to_string());
    }

    // An empty / zero-power set must never reach quorum.
    let required = validators.quorum_power();
    if required == u64::MAX {
        return Err("validator set has no power; no certificate can ever be final".to_string());
    }

    // Membership and distinctness are counted BEFORE signature verification, so
    // the failure is reported for the reason it actually is. This is an upper
    // bound on the power that could possibly verify, so failing here is sound.
    let mut seen: HashSet<ValidatorId> = HashSet::new();
    let mut members = 0usize;
    let mut outsiders = 0usize;
    let mut power = 0u64;
    for (voter, _) in &cert.signatures {
        if !seen.insert(*voter) {
            continue; // one key cannot be counted twice
        }
        let p = validators.power_of(voter);
        if p == 0 {
            outsiders += 1;
            continue; // not a member: a valid signature proves nothing
        }
        members += 1;
        power = power.saturating_add(p);
    }
    if power < required {
        if members == 0 {
            return Err(format!(
                "certificate carries no validator power: all {outsiders} signer(s) are outside the validator set (needs {required} of {} power)",
                validators.total_power()
            ));
        }
        return Err(format!(
            "certificate carries {power} of the {required} power required, from {members} distinct validator signer(s)"
        ));
    }

    // Signature check is delegated to the engine so there is exactly one
    // definition of the bytes a validator signs. `vote_sign_bytes` is private
    // to `crate::consensus`; re-deriving it here would be a second definition
    // that could drift from the first.
    if !cert.verify(validators) {
        return Err("certificate signatures did not verify against the validator set".to_string());
    }
    Ok(())
}

// ============================================================================
// Light header
// ============================================================================

/// A block header as a light client sees it: no body, no transactions.
///
/// `block_hash` is opaque. A light client cannot recompute
/// `Block::compute_hash` without the transactions, so it treats the hash as a
/// label and leans entirely on the certificate to decide who stands behind it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightHeader {
    pub height: u64,
    pub prev_hash: BlockHash,
    /// State root this block commits to.
    pub state_root: CellHash,
    /// Opaque block identity; what the certificate is over.
    pub block_hash: BlockHash,
    pub timestamp: u64,
    /// Carried for attribution only. NOT verified here: a light client has no
    /// stake in who proposed (the certificate already carries a power quorum
    /// regardless of the proposer), and it has no way to reproduce a proposer
    /// rotation it was not configured for. Recorded, not trusted.
    pub proposer: ValidatorId,
    /// Precommit quorum certificate for `block_hash` at `height`. This is what
    /// makes the header final rather than merely claimed.
    pub cert: QuorumCertificate,
    /// Optional block-level validator signatures over `block_hash`, the header
    /// analogue of `Block::validator_signatures`. When present they must
    /// independently reach a power-weighted quorum: two attestations of the
    /// same fact, and a certificate that cannot be forged still has to get
    /// past both.
    #[serde(default)]
    pub signatures: Vec<(ValidatorId, Vec<u8>)>,
}

impl LightHeader {
    /// Verify the header's finality evidence against a validator set.
    pub fn verify(&self, validators: &ValidatorSet) -> Result<(), String> {
        verify_finality(&self.cert, self.height, self.block_hash, validators)
            .map_err(|e| format!("header at height {} rejected: {e}", self.height))?;
        self.verify_validator_quorum(validators)
    }

    /// Power-weighted quorum over the block hash, membership-checked and with
    /// each signer counted once.
    ///
    /// An empty `signatures` list is accepted: the certificate is already a
    /// finality proof, and the two layers are independent rather than additive.
    /// A non-empty list that fails is refused, because a header carrying
    /// signatures which do not add up is a header making a claim it cannot back.
    pub fn verify_validator_quorum(&self, validators: &ValidatorSet) -> Result<(), String> {
        if self.signatures.is_empty() {
            return Ok(());
        }
        let required = validators.quorum_power();
        if required == u64::MAX {
            return Err("validator set has no power; refusing to count signatures".to_string());
        }
        let mut seen: HashSet<ValidatorId> = HashSet::new();
        let mut members = 0usize;
        let mut power = 0u64;
        for (pubkey, sig_bytes) in &self.signatures {
            if !seen.insert(*pubkey) {
                continue; // one key cannot be counted twice
            }
            let vp = validators.power_of(pubkey);
            if vp == 0 {
                continue; // membership first: a valid signature is not evidence
            }
            if let Ok(vk) = VerifyingKey::from_bytes(pubkey) {
                if let Ok(sig) = Signature::from_slice(sig_bytes) {
                    // `verify_strict` rejects small-order and non-canonically
                    // encoded signatures, which is the same bar the consensus
                    // engine sets on votes. A block signature checked with the
                    // lax variant would accept a different set of keys.
                    if vk.verify_strict(&self.block_hash, &sig).is_ok() {
                        members += 1;
                        power = power.saturating_add(vp);
                    }
                }
            }
        }
        if power < required {
            return Err(format!(
                "block signatures carry {power} of the {required} power required, from {members} distinct validator signer(s)"
            ));
        }
        Ok(())
    }

    /// Add this validator's signature over the block hash (mirrors
    /// `Block::sign_block`, which signs the same 32 bytes).
    pub fn sign_with(&mut self, key: &SigningKey) {
        let sig = key.sign(&self.block_hash);
        self.signatures.push((key.verifying_key().to_bytes(), sig.to_vec()));
    }

    /// The checkpoint this header would become, once verified.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint::of(self)
    }
}

// ============================================================================
// Proven values
// ============================================================================

/// A native account, proven against a state root this client trusts.
///
/// Every field here came out of a verified leaf. There is no `Option` and no
/// "unknown" here on purpose: the only way to get one of these is to have
/// checked the proof, so holding one means the balance was proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenAccount {
    pub address: [u8; 32],
    pub balance: u64,
    pub nonce: u64,
    /// Height at which this client finalized `state_root`.
    pub height: u64,
    pub state_root: CellHash,
}

/// A token balance, proven against a state root this client trusts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenTokenBalance {
    pub token_id: [u8; 32],
    pub account: [u8; 32],
    pub balance: u64,
    pub height: u64,
    pub state_root: CellHash,
}

// ============================================================================
// Light client
// ============================================================================

/// A light client: a validator set, one trusted checkpoint, and a bounded
/// window of headers above it.
///
/// Holds no state, no block bodies and no proof cache. Its whole memory is the
/// header window, which is capped, so its footprint does not grow with uptime.
#[derive(Clone, Debug)]
pub struct LightClient {
    pub validators: ValidatorSet,
    /// The most recent verified checkpoint. Never regressed.
    pub checkpoint: Checkpoint,
    /// Headers accepted above the checkpoint, oldest first. Bounded.
    headers: VecDeque<LightHeader>,
    max_headers: usize,
}

impl LightClient {
    /// Create a client trusting `checkpoint`, with the default header cap.
    ///
    /// The initial checkpoint is verified like any other rather than being
    /// waved through: the only trust anchor this design has is the configured
    /// validator set, and an unverified first checkpoint would turn "trust the
    /// set" into "trust whoever handed us the first packet".
    pub fn new(validators: ValidatorSet, checkpoint: Checkpoint) -> Result<Self, String> {
        Self::with_max_headers(validators, checkpoint, DEFAULT_MAX_HEADERS)
    }

    /// As [`LightClient::new`], with an explicit cap on the header window.
    pub fn with_max_headers(
        validators: ValidatorSet,
        checkpoint: Checkpoint,
        max_headers: usize,
    ) -> Result<Self, String> {
        if max_headers == 0 {
            return Err("light client: header cap must be at least 1".to_string());
        }
        checkpoint.verify(&validators)?;
        Ok(Self {
            validators,
            checkpoint,
            headers: VecDeque::new(),
            max_headers,
        })
    }

    // ---------- chain position ----------

    /// Height of the most recent finalized block this client knows.
    pub fn tip_height(&self) -> u64 {
        self.headers.back().map_or(self.checkpoint.height, |h| h.height)
    }

    /// Hash of the most recent finalized block this client knows.
    pub fn tip_hash(&self) -> BlockHash {
        self.headers
            .back()
            .map_or(self.checkpoint.block_hash, |h| h.block_hash)
    }

    /// State root committed by the tip.
    pub fn state_root(&self) -> CellHash {
        self.headers
            .back()
            .map_or(self.checkpoint.state_root, |h| h.state_root)
    }

    /// State root this client finalized at `height`, if it still remembers it.
    pub fn state_root_at(&self, height: u64) -> Option<CellHash> {
        if height == self.checkpoint.height {
            return Some(self.checkpoint.state_root);
        }
        self.headers
            .iter()
            .find(|h| h.height == height)
            .map(|h| h.state_root)
    }

    /// Whether this client has grounds to believe `root`.
    pub fn trusts_root(&self, root: &CellHash) -> bool {
        root == &self.checkpoint.state_root || self.headers.iter().any(|h| &h.state_root == root)
    }

    /// The highest height at which this client finalized `root`.
    pub fn trusted_height_of_root(&self, root: &CellHash) -> Option<u64> {
        let mut best: Option<u64> = None;
        if root == &self.checkpoint.state_root {
            best = Some(self.checkpoint.height);
        }
        for h in &self.headers {
            if &h.state_root == root {
                best = Some(match best {
                    Some(b) => b.max(h.height),
                    None => h.height,
                });
            }
        }
        best
    }

    /// The retained header window, oldest first.
    pub fn headers(&self) -> &VecDeque<LightHeader> {
        &self.headers
    }

    /// How many headers are currently retained.
    pub fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// The configured cap on the header window.
    pub fn max_headers(&self) -> usize {
        self.max_headers
    }

    // ---------- accepting the chain ----------

    /// Accept one header on top of the current tip.
    ///
    /// Refuses, rather than guessing, when the header:
    ///  * is not the tip's immediate successor (gap above, or rewind/replay);
    ///  * names a different parent than the tip (a fork);
    ///  * comes with the window already full;
    ///  * lacks a precommit quorum of real validator power at its own height;
    ///  * carries block signatures that do not add up; or
    ///  * commits a state root an earlier finalized header already superseded.
    pub fn apply_header(&mut self, header: LightHeader) -> Result<(), String> {
        // --- shape: no gaps, no rewinds -------------------------------------
        let expected_height = self
            .tip_height()
            .checked_add(1)
            .ok_or_else(|| "light client: height overflow".to_string())?;
        if header.height > expected_height {
            return Err(format!(
                "light client: header at height {} leaves a gap; expected {}",
                header.height, expected_height
            ));
        }
        if header.height < expected_height {
            return Err(format!(
                "light client: header at height {} is not the tip's successor; tip is at {}",
                header.height,
                self.tip_height()
            ));
        }

        // --- shape: no forks -------------------------------------------------
        let expected_parent = self.tip_hash();
        if header.prev_hash != expected_parent {
            return Err(format!(
                "light client: header at height {} forks; parent {} is not the tip {}",
                header.height,
                hex::encode(header.prev_hash),
                hex::encode(expected_parent)
            ));
        }

        // --- bounded: refuse to grow past the cap ---------------------------
        // Checked before the expensive signature work, so a full window costs
        // nothing to say "full".
        if self.headers.len() >= self.max_headers {
            return Err(format!(
                "light client: header window is full ({} headers); a newer checkpoint is required before more can be accepted",
                self.max_headers
            ));
        }

        // --- finality --------------------------------------------------------
        header.verify(&self.validators)?;

        // --- state root consistency -----------------------------------------
        if let Some(rolled_back_to) = self.superseded_root(&header) {
            return Err(format!(
                "light client: header at height {} commits state root {}, which an earlier finalized header already superseded; the state would roll back",
                header.height,
                hex::encode(rolled_back_to)
            ));
        }

        self.headers.push_back(header);
        Ok(())
    }

    /// The root this header would be rolling the state back to, if any.
    ///
    /// A header may legitimately carry its parent's own root: an empty block
    /// does not move the state, and refusing that would wedge a client on a
    /// chain of no-op blocks. What it may not do is reach further back than
    /// that — reintroducing a root some earlier finalized height had already
    /// moved past is a rollback (or a collision), and BFT finality says it
    /// cannot happen honestly.
    fn superseded_root(&self, header: &LightHeader) -> Option<CellHash> {
        let parent_height = header.height.checked_sub(1)?;
        if header.state_root == self.state_root() {
            return None;
        }
        if self.checkpoint.height < parent_height && header.state_root == self.checkpoint.state_root
        {
            return Some(self.checkpoint.state_root);
        }
        self.headers
            .iter()
            .find(|h| h.height < parent_height && h.state_root == header.state_root)
            .map(|h| h.state_root)
    }

    /// Re-anchor onto a newer checkpoint, after verifying it.
    ///
    /// The header window is reset, because everything in it was accepted under
    /// the old anchor and the new one is the authority from here on.
    ///
    /// Refuses to:
    ///  * move backwards (below the current checkpoint, or below the tip we
    ///    already accepted), since that would discard finalized blocks;
    ///  * contradict the current checkpoint at the same height, or the same
    ///    block at a different height;
    ///  * contradict a header already in the window. A peer must not be able to
    ///    walk us back to a fork by handing us a "checkpoint".
    pub fn advance_to_checkpoint(&mut self, cp: Checkpoint) -> Result<(), String> {
        cp.verify(&self.validators)
            .map_err(|e| format!("light client: refusing to re-anchor: {e}"))?;

        if cp.height < self.checkpoint.height {
            return Err(format!(
                "light client: checkpoint at height {} is older than the trusted checkpoint at {}",
                cp.height, self.checkpoint.height
            ));
        }
        if cp.height == self.checkpoint.height {
            if cp.block_hash != self.checkpoint.block_hash {
                return Err(format!(
                    "light client: conflicting checkpoint at height {} ({} vs trusted {})",
                    cp.height,
                    hex::encode(cp.block_hash),
                    hex::encode(self.checkpoint.block_hash)
                ));
            }
            if cp.state_root != self.checkpoint.state_root {
                return Err(format!(
                    "light client: checkpoint at height {} names a different state root for a block already trusted",
                    cp.height
                ));
            }
        }
        let tip = self.tip_height();
        if cp.height < tip {
            return Err(format!(
                "light client: checkpoint at height {} is older than the accepted tip {}",
                cp.height, tip
            ));
        }
        for h in &self.headers {
            if h.height == cp.height {
                if h.block_hash != cp.block_hash {
                    return Err(format!(
                        "light client: checkpoint at height {} conflicts with a header already accepted at that height",
                        cp.height
                    ));
                }
                if h.state_root != cp.state_root {
                    return Err(format!(
                        "light client: checkpoint at height {} names a different state root than the header already accepted for it",
                        cp.height
                    ));
                }
            }
            if h.block_hash == cp.block_hash && h.height != cp.height {
                return Err(format!(
                    "light client: checkpoint claims height {} for a block already accepted at height {}",
                    cp.height, h.height
                ));
            }
        }

        self.checkpoint = cp;
        self.headers.clear();
        Ok(())
    }

    // ---------- balance queries ----------

    /// Verify a native balance + nonce from a `stell_getBalanceSpv` answer.
    ///
    /// `value` is the leaf the server claims, and is checked against the proof
    /// before any of it is read — which is what this does: nothing is returned
    /// from an unverified claim.
    pub fn verify_account(
        &self,
        address: &[u8; 32],
        value: &[u8],
        proof: &MerkleProof,
        state_root: CellHash,
    ) -> Result<ProvenAccount, LightError> {
        if value.len() != ACCOUNT_VALUE_LEN && value.len() != crate::cpat2::ACCOUNT_LEAF_LEN_PQ {
            return Err(LightError::InvalidProof(format!(
                "account leaf is {} bytes, expected {ACCOUNT_VALUE_LEN} or {}",
                value.len(),
                crate::cpat2::ACCOUNT_LEAF_LEN_PQ
            )));
        }
        let height = self.verify_inclusion(address, value, proof, state_root)?;
        let mut balance = [0u8; 8];
        balance.copy_from_slice(&value[..8]);
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&value[8..16]);
        Ok(ProvenAccount {
            address: *address,
            balance: u64::from_be_bytes(balance),
            nonce: u64::from_be_bytes(nonce),
            height,
            state_root,
        })
    }

    /// Verify a native balance from a `stell_getBalanceSpv` answer whose proof
    /// field may be absent.
    ///
    /// `None` is the full node *asserting* the account is not in the trie. That
    /// is reported as [`LightError::NotIncluded`] — never as balance zero,
    /// because the client cannot tell an honest absence from a server that
    /// simply declined to answer. A `Some` proof is the server claiming it *is*
    /// there, so an empty or malformed one is [`LightError::InvalidProof`]:
    /// silence and an unverifiable claim are different failures and are kept
    /// apart.
    pub fn verify_account_answer(
        &self,
        address: &[u8; 32],
        value: &[u8],
        proof: Option<&MerkleProof>,
        state_root: CellHash,
    ) -> Result<ProvenAccount, LightError> {
        match proof {
            None => {
                let height = self
                    .trusted_height_of_root(&state_root)
                    .ok_or(LightError::RootUntrusted { root: state_root })?;
                Err(LightError::NotIncluded { height, state_root })
            }
            Some(p) => self.verify_account(address, value, p, state_root),
        }
    }

    /// Verify an STS token balance from a `stell_tokenBalanceSpv` answer.
    pub fn verify_token_balance(
        &self,
        token_id: &[u8; 32],
        account: &[u8; 32],
        value: &[u8],
        proof: &MerkleProof,
        state_root: CellHash,
    ) -> Result<ProvenTokenBalance, LightError> {
        if value.len() != TOKEN_BALANCE_VALUE_LEN {
            return Err(LightError::InvalidProof(format!(
                "token balance leaf is {} bytes, expected {TOKEN_BALANCE_VALUE_LEN}",
                value.len()
            )));
        }
        // The namespaced key is recomputed here rather than taken from the
        // server, so a proof for some other key cannot be passed off as this
        // account's holding.
        let key = crate::state_engine::token_balance_key(token_id, account);
        let height = self.verify_inclusion(&key, value, proof, state_root)?;
        let mut balance = [0u8; 8];
        balance.copy_from_slice(value);
        Ok(ProvenTokenBalance {
            token_id: *token_id,
            account: *account,
            balance: u64::from_be_bytes(balance),
            height,
            state_root,
        })
    }

    /// Core inclusion check: is `key == value` part of the state committed at
    /// `state_root`, and did *we* finalize that root?
    fn verify_inclusion(
        &self,
        key: &[u8; 32],
        value: &[u8],
        proof: &MerkleProof,
        state_root: CellHash,
    ) -> Result<u64, LightError> {
        // Trust first: with an untrusted root there is nothing to check against.
        let height = self
            .trusted_height_of_root(&state_root)
            .ok_or(LightError::RootUntrusted { root: state_root })?;

        // Structural checks next, and they are checked BEFORE the proof is
        // accepted, so that a malformed proof is reported as malformed rather
        // than being laundered into "not included". The empty-proof case is the
        // important one: a server that omits the proof must not be able to
        // produce an absence out of it.
        if proof.key != *key {
            return Err(LightError::InvalidProof(format!(
                "proof is for key {}, not the queried key {}",
                hex::encode(proof.key),
                hex::encode(key)
            )));
        }
        if proof.path.len() > MAX_MERKLE_PATH_STEPS {
            return Err(LightError::InvalidProof(format!(
                "proof path has {} steps, more than the {MAX_MERKLE_PATH_STEPS} a 32-byte key can need",
                proof.path.len()
            )));
        }
        if proof.path.is_empty() && proof.leaf_hash == [0u8; 32] {
            return Err(LightError::InvalidProof(
                "empty proof: a missing inclusion proof is not evidence that a key is absent".to_string(),
            ));
        }

        if !PatriciaTrie::verify_merkle_proof(&state_root, key, value, proof) {
            // Well-formed but it does not authenticate here. Either the key is
            // genuinely not in this state, or the server is serving a proof from
            // some other root. Both mean the same thing to us: not provable
            // against the state we trust.
            return Err(LightError::NotIncluded { height, state_root });
        }
        Ok(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Vote, VoteKind};

    #[test]
    fn test_spv_verification_succeeds_on_49_byte_pinned_account_leaf() {
        let signer = SigningKey::from_bytes(&[0x11u8; 32]);
        let val_id = signer.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(val_id, 1)]);

        let address = [0x55u8; 32];
        let balance: u64 = 42_000_000;
        let nonce: u64 = 9;
        let scheme = crate::post_quantum::PqScheme::Falcon512.id();
        let pubkey_hash = [0x77u8; 32];

        let pinned_leaf = crate::cpat2::AccountLeaf::new_pinned(balance, nonce, scheme, pubkey_hash).encode();
        assert_eq!(pinned_leaf.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);

        let mut trie = PatriciaTrie::new();
        trie.insert(&address, &pinned_leaf);
        let state_root = trie.root_hash();
        let proof = trie.generate_merkle_proof(&address).expect("merkle proof");

        let block_hash = [0x22u8; 32];
        let vote = Vote::sign(&signer, 1, 0, VoteKind::Precommit, Some(block_hash));
        let cert = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block_hash),
            signatures: vec![(vote.voter, vote.signature)],
        };
        let checkpoint = Checkpoint::new(1, block_hash, [0u8; 32], state_root, cert);
        let lc = LightClient::new(validators, checkpoint).expect("light client init");

        // Verify SPV account query against 49-byte leaf
        let proven = lc
            .verify_account(&address, &pinned_leaf, &proof, state_root)
            .expect("49-byte pinned account SPV verification must succeed");

        assert_eq!(proven.address, address);
        assert_eq!(proven.balance, balance);
        assert_eq!(proven.nonce, nonce);
        assert_eq!(proven.height, 1);
        assert_eq!(proven.state_root, state_root);

        // Also test verify_account_answer with Some(proof)
        let proven_ans = lc
            .verify_account_answer(&address, &pinned_leaf, Some(&proof), state_root)
            .expect("verify_account_answer on 49-byte pinned account leaf must succeed");
        assert_eq!(proven_ans.balance, balance);
        assert_eq!(proven_ans.nonce, nonce);

        // Negative check: wrong leaf data or altered balance fails
        let tampered_leaf = crate::cpat2::AccountLeaf::new_pinned(balance + 1, nonce, scheme, pubkey_hash).encode();
        assert!(lc.verify_account(&address, &tampered_leaf, &proof, state_root).is_err());
    }

    #[test]
    fn test_spv_verification_succeeds_on_16_byte_legacy_leaf() {
        let signer = SigningKey::from_bytes(&[0x22u8; 32]);
        let val_id = signer.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(val_id, 1)]);

        let address = [0x66u8; 32];
        let balance: u64 = 10_000;
        let nonce: u64 = 2;

        let legacy_leaf = crate::cpat2::AccountLeaf::new_unpinned(balance, nonce).encode();
        assert_eq!(legacy_leaf.len(), ACCOUNT_VALUE_LEN);

        let mut trie = PatriciaTrie::new();
        trie.insert(&address, &legacy_leaf);
        let state_root = trie.root_hash();
        let proof = trie.generate_merkle_proof(&address).expect("merkle proof");

        let block_hash = [0x33u8; 32];
        let vote = Vote::sign(&signer, 1, 0, VoteKind::Precommit, Some(block_hash));
        let cert = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block_hash),
            signatures: vec![(vote.voter, vote.signature)],
        };
        let checkpoint = Checkpoint::new(1, block_hash, [0u8; 32], state_root, cert);
        let lc = LightClient::new(validators, checkpoint).expect("light client init");

        let proven = lc
            .verify_account(&address, &legacy_leaf, &proof, state_root)
            .expect("16-byte legacy leaf verification must succeed");
        assert_eq!(proven.balance, balance);
        assert_eq!(proven.nonce, nonce);
    }
}
