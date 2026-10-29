//! Light client: follow the chain from quorum-certified anchors and answer
//! balance queries by walking proofs, without ever holding state.
//!
//! # LIVE (audit W8.3 / production blocker A10)
//!
//! This module used to be library-only: it was compiled and unit-tested, but
//! nothing called it, so "the node hands out the root it believes in" was
//! still the only thing an outside verifier could get. It is now WIRED IN:
//!
//! * the node keeps a [`LightClient`] anchored at its OWN finalized head
//!   (the header that carries the precommit quorum certificate that decided
//!   it), and every block it accepts from a peer during a sync is routed
//!   through [`crate::sync::verify_synced_blocks_against_anchor`] — a peer
//!   chain is accepted only if it extends a quorum-certified anchor;
//! * the node SERVES its anchor and its finalized headers over RPC
//!   (`stell_getFinalizedCheckpoint`, `stell_getFinalizedHeader`), so an
//!   external verifier can check a proof against a root that a QUORUM
//!   committed to, not against a root the server merely asserted;
//! * `stellereum light-client --from <rpc> --verify <account>` is that
//!   external verifier: it fetches a proof, verifies the anchoring header's
//!   quorum certificate against an OUT-OF-BAND validator set, and only then
//!   checks the proof.
//!
//! # ⛔ WHAT A NODE STILL CANNOT DO
//!
//! A node can still lie about a state it has not been told about: the
//! validator set is the trust anchor, and a light client that takes its
//! validator set from the server it is verifying has no anchor at all. The
//! CLI therefore REQUIRES an out-of-band validator set (`--validators`), and
//! the honest statement of the residual is unchanged: the set is the entire
//! trust anchor (see "What this does NOT do" below).
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
//!   * one trusted anchor — a [`Checkpoint`] (a finalized header with its
//!     quorum certificate) or the chain's [`GenesisAnchor`], and
//!   * a **bounded** window of [`LightHeader`]s above it.
//!
//! A state root only becomes trustworthy when it is attached to a block hash
//! that a quorum of validators precommitted to. So every root this client will
//! verify a proof against is a root it saw committed by a finalized header, and
//! every balance answer comes back with the height that root belongs to.
//!
//! # ⚠️ THE CHAIN'S ROOT CONVENTION (read this before reading a height)
//!
//! A Stellereum block header commits to the state BEFORE its own block — the
//! state it BUILDS ON (`runtime::validate_proposal` compares
//! `block.state_root` with the node's root *before* applying the block). So
//! the root carried by the header at height `H` is the root of the state as
//! of height `H-1`.
//!
//! Consequence for an integrator: the root a light client ends up trusting is
//! the root of the state at height `H-1`, where `H` is the height of the
//! anchoring header. The node's live proofs are served against the CURRENT
//! state root, so they are committed by the header at height `H+1` — which is
//! exactly why the CLI anchors a served proof with the header at `h+1` and
//! not with the header at `h`.
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
//!    verification is delegated to the trie — `PatriciaTrie::verify_merkle_proof`
//!    for the legacy answer shape, `cpat2::verify_proof` /
//!    `cpat2::verify_exclusion_proof` for the `stell_getProof` wire form. The
//!    blake3 leaf/branch hashes are re-used as-is, not re-derived here, so a
//!    bug in the trie's hashing is a bug in this client too.
//! 3. **It does not verify that a header's `state_root` was computed from the
//!    block body.** It cannot: that needs execution. The block hash is opaque
//!    to it, so the binding between "this root" and "this state" is inherited
//!    from the quorum — full nodes are the ones that check a header's root
//!    against the state they applied. What is enforced here is narrower: the
//!    root must travel with a finalized header at a known height, and it must
//!    not roll back to a root an earlier finalized header already superseded.
//! 4. **It does not fetch anything.** No gossip, no retry, no peer scoring, no
//!    eclipse or partition detection. Transport is the caller's problem; this
//!    module only decides what to believe once a header or a proof is in hand.
//!    A client that cannot reach an honest full node will simply stop advancing.
//! 5. **The non-reversion check is only as deep as the retained window.** It
//!    sees the checkpoint and the retained headers, and forgets older roots as
//!    they age out. It is a cheap backstop, not a substitute for the quorum.
//!
//! # Absence is provable now
//!
//! Limitation 4 of the original audit ("no non-inclusion proofs") is closed:
//! `cpat2` gained exclusion proofs, `stell_getProof` serves them, and
//! [`LightClient::verify_proof_answer`] verifies them. A client can therefore
//! prove that a key is *absent* from a state it trusts — which is a stronger
//! statement than "the server found nothing", and the only kind of answer
//! that survives a hostile server. What remains true is that a proof of
//! absence still says nothing about *when* the key was absent: the client
//! learns "not in the state committed at height H", not "never existed".

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
    ///
    /// ⚠️ CHAIN CONVENTION: a block commits to the state BEFORE its own
    /// block, so this is the root of the state as of `height - 1`.
    pub state_root: CellHash,
    /// Precommit quorum certificate for `block_hash` at `height`.
    pub cert: QuorumCertificate,
}

/// The GENESIS anchor of a light client: the chain's root.
///
/// The genesis block is not DECIDED by a vote — it IS the root everything
/// else is measured against — so there is no quorum certificate for it and
/// none can be checked. It is trusted **by construction**: the operator's
/// genesis configuration (the node's own genesis state root, or a genesis
/// root an operator pinned out of band).
///
/// Every header ABOVE the anchor must carry a real precommit quorum
/// certificate ([`LightHeader::verify`]), so the first unverified link never
/// exists: the light client's trust reduces to "the genesis root is right",
/// and everything after it is quorum-proved.
///
/// The height-1 block of this chain links to the ZERO prev-hash sentinel
/// (the genesis block is not part of the hash chain — see
/// `runtime::ValidatorRuntime::propose`), so the genesis anchor's
/// `block_hash` is that sentinel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAnchor {
    /// The genesis height (0 in this chain).
    pub height: u64,
    /// The hash the first real block links to (the zero sentinel).
    pub block_hash: BlockHash,
    /// The genesis block's own parent (the zero sentinel).
    pub parent_hash: BlockHash,
    /// The genesis state root.
    pub state_root: CellHash,
}

/// What a light client is anchored on.
///
/// Either the chain's GENESIS (trusted by construction) or a finalized block
/// with the quorum certificate that decided it (trusted by a quorum).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LightAnchor {
    /// The chain's root. No quorum evidence exists (and none is needed).
    Genesis(GenesisAnchor),
    /// A quorum-certified finalized block.
    Checkpoint(Checkpoint),
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

    /// The light header a FINALIZED (or adopted, or walked) block corresponds to.
    ///
    /// `None` when the block carries no precommit quorum certificate: a body
    /// without one was never DECIDED, so there is nothing to anchor on and
    /// nothing to trust. The caller must treat that as "no anchor", never as
    /// "an anchor without evidence".
    ///
    /// NOTE the chain convention: `block.state_root` is the state BEFORE the
    /// block (the state it builds on), so the header's root is the state at
    /// `height - 1`.
    pub fn of_block(block: &crate::sharding::Block) -> Option<Self> {
        let cert = block.precommit_qc.clone()?;
        Some(Self {
            height: block.height,
            prev_hash: block.prev_hash,
            state_root: block.state_root,
            block_hash: block.compute_hash(),
            timestamp: block.timestamp,
            proposer: block.proposer,
            cert,
            signatures: block.validator_signatures.clone(),
        })
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
// `stell_getProof` answers
// ============================================================================

/// One storage proof from a `stell_getProof` answer.
///
/// `exists: false` carries an *exclusion* proof: the key is provably absent
/// from the state committed at the root, which is a stronger statement than
/// "the server did not find it".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageProofAnswer {
    /// The state-trie key the proof is about.
    pub key: [u8; 32],
    /// The proven value (`None` when the key is proven absent).
    #[serde(default)]
    pub value: Option<Vec<u8>>,
    /// Whether the key is in the state.
    pub exists: bool,
    /// The Merkle proof, in `cpat2` wire form (hex nodes, leaf first).
    pub proof: Vec<String>,
}

/// A `stell_getProof` answer, as served by a full node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAnswer {
    /// The account the proof is about.
    pub address: [u8; 32],
    /// The balance the server claims.
    pub balance: u64,
    /// The nonce the server claims.
    pub nonce: u64,
    /// The account's Merkle proof, in `cpat2` wire form.
    pub account_proof: Vec<String>,
    /// One proof per requested storage key.
    #[serde(default)]
    pub storage_proofs: Vec<StorageProofAnswer>,
    /// The state root the proofs are anchored to.
    pub state_root: CellHash,
    /// The height the server says the root belongs to. Recorded, not trusted:
    /// the root is the authority, and the height this client reports is the
    /// one *it* finalized that root at.
    #[serde(default)]
    pub height: Option<u64>,
}

/// A storage slot, proven against a state root this client trusts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenStorage {
    pub key: [u8; 32],
    /// The proven value (`None` when the key is proven absent).
    pub value: Option<Vec<u8>>,
    /// Whether the key is in the state.
    pub exists: bool,
}

/// The result of verifying a `stell_getProof` answer.
///
/// Every field here was read out of a *verified* leaf. The balance and nonce
/// come from the leaf the proof commits to, not from the server's claim — the
/// claim is only ever compared against the proof, never believed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenProof {
    pub address: [u8; 32],
    pub balance: u64,
    pub nonce: u64,
    /// Whether the account is in the state at all.
    pub exists: bool,
    /// The proven storage slots.
    pub storage: Vec<ProvenStorage>,
    /// Height at which this client finalized `state_root`.
    pub height: u64,
    pub state_root: CellHash,
}

/// Parse a 32-byte hex string (with or without `0x`).
fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() != 64 {
        return Err(format!("expected 32 bytes (64 hex characters), got {}", s.len()));
    }
    let b = hex::decode(s).map_err(|e| format!("bad hex: {e}"))?;
    b.try_into().map_err(|_| "expected 32 bytes".to_string())
}

/// Parse a `u64` that a JSON server may have written as a number or a string.
fn parse_u64_field(v: Option<&serde_json::Value>) -> Result<u64, String> {
    match v {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| "balance/nonce is not an unsigned integer".to_string()),
        Some(serde_json::Value::String(s)) => s
            .parse::<u64>()
            .map_err(|_| format!("balance/nonce {s:?} is not an unsigned integer")),
        _ => Err("missing balance/nonce".to_string()),
    }
}

/// Parse the hex-node list of a proof.
fn parse_proof_nodes(v: Option<&serde_json::Value>) -> Result<Vec<String>, String> {
    match v {
        Some(serde_json::Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len());
            for n in arr {
                match n.as_str() {
                    Some(s) => out.push(s.to_string()),
                    None => return Err("proof node is not a hex string".to_string()),
                }
            }
            Ok(out)
        }
        Some(serde_json::Value::Null) | None => Ok(Vec::new()),
        Some(_) => Err("proof is not an array of hex strings".to_string()),
    }
}

impl ProofAnswer {
    /// Parse a `stell_getProof` JSON response.
    ///
    /// The parsing is strict about what it cannot make sense of (a missing
    /// address, a malformed hex) and lenient about the rest, because the
    /// verification that follows is where a claim is either proved or
    /// refused.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let address = parse_hex32(
            v.get("address")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "proof answer has no address".to_string())?,
        )?;
        let state_root = parse_hex32(
            v.get("state_root")
                .or_else(|| v.get("stateRoot"))
                .and_then(|x| x.as_str())
                .ok_or_else(|| "proof answer has no state root".to_string())?,
        )?;
        let account_proof = parse_proof_nodes(v.get("account_proof"))?;
        let mut storage_proofs = Vec::new();
        if let Some(arr) = v.get("storage_proofs").and_then(|x| x.as_array()) {
            for sp in arr {
                let key = parse_hex32(
                    sp.get("key")
                        .and_then(|x| x.as_str())
                        .ok_or_else(|| "storage proof has no key".to_string())?,
                )?;
                let value = match sp.get("value") {
                    Some(serde_json::Value::String(s)) => Some(hex::decode(s).map_err(|e| format!("bad storage value hex: {e}"))?),
                    _ => None,
                };
                let exists = sp.get("exists").and_then(|x| x.as_bool()).unwrap_or(value.is_some());
                let proof = parse_proof_nodes(sp.get("proof"))?;
                storage_proofs.push(StorageProofAnswer { key, value, exists, proof });
            }
        }
        Ok(ProofAnswer {
            address,
            balance: parse_u64_field(v.get("balance"))?,
            nonce: parse_u64_field(v.get("nonce"))?,
            account_proof,
            storage_proofs,
            state_root,
            height: v.get("height").and_then(|x| x.as_u64()),
        })
    }
}

// ============================================================================
// Light client
// ============================================================================

/// A light client: a validator set, one trusted anchor, and a bounded
/// window of headers above it.
///
/// Holds no state, no block bodies and no proof cache. Its whole memory is the
/// header window, which is capped, so its footprint does not grow with uptime.
#[derive(Clone, Debug)]
pub struct LightClient {
    pub validators: ValidatorSet,
    /// What this client is anchored on: the chain's GENESIS (trusted by
    /// construction) or a quorum-certified finalized block.
    pub anchor: LightAnchor,
    /// Headers accepted above the anchor, oldest first. Bounded.
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
            anchor: LightAnchor::Checkpoint(checkpoint),
            headers: VecDeque::new(),
            max_headers,
        })
    }

    /// Create a client anchored at the chain's GENESIS.
    ///
    /// The genesis root is trusted BY CONSTRUCTION (the operator's genesis
    /// configuration), so there is no quorum certificate to check — but every
    /// header above the anchor must carry one, and [`LightClient::apply_header`]
    /// refuses a header that does not.
    ///
    /// This is how a NODE anchors its own light client: at start-up it knows
    /// the genesis state root, and every block it later accepts from a peer
    /// has to carry a quorum certificate on top of it.
    pub fn with_genesis_anchor(
        validators: ValidatorSet,
        genesis: GenesisAnchor,
    ) -> Result<Self, String> {
        Self::with_genesis_anchor_and_max_headers(validators, genesis, DEFAULT_MAX_HEADERS)
    }

    /// As [`LightClient::with_genesis_anchor`], with an explicit cap on the
    /// header window.
    pub fn with_genesis_anchor_and_max_headers(
        validators: ValidatorSet,
        genesis: GenesisAnchor,
        max_headers: usize,
    ) -> Result<Self, String> {
        if max_headers == 0 {
            return Err("light client: header cap must be at least 1".to_string());
        }
        if validators.quorum_power() == u64::MAX {
            return Err(
                "light client: validator set has no power; no certificate can ever be final"
                    .to_string(),
            );
        }
        Ok(Self {
            validators,
            anchor: LightAnchor::Genesis(genesis),
            headers: VecDeque::new(),
            max_headers,
        })
    }

    /// What this client is anchored on.
    pub fn anchor(&self) -> &LightAnchor {
        &self.anchor
    }

    /// The quorum-certified checkpoint this client is anchored on, if it has
    /// one (a client still on the GENESIS anchor has none).
    pub fn checkpoint(&self) -> Option<&Checkpoint> {
        match &self.anchor {
            LightAnchor::Checkpoint(cp) => Some(cp),
            LightAnchor::Genesis(_) => None,
        }
    }

    /// The GENESIS anchor this client was created on, if it still has one.
    pub fn genesis_anchor(&self) -> Option<&GenesisAnchor> {
        match &self.anchor {
            LightAnchor::Genesis(g) => Some(g),
            LightAnchor::Checkpoint(_) => None,
        }
    }

    // ---------- chain position ----------

    /// Height of the most recent finalized block this client knows.
    pub fn tip_height(&self) -> u64 {
        self.headers.back().map_or(self.anchor_height(), |h| h.height)
    }

    /// The height of the anchor itself.
    pub fn anchor_height(&self) -> u64 {
        match &self.anchor {
            LightAnchor::Checkpoint(cp) => cp.height,
            LightAnchor::Genesis(g) => g.height,
        }
    }

    /// The state root the anchor commits to.
    pub fn anchor_state_root(&self) -> CellHash {
        match &self.anchor {
            LightAnchor::Checkpoint(cp) => cp.state_root,
            LightAnchor::Genesis(g) => g.state_root,
        }
    }

    /// The block hash the anchor names.
    pub fn anchor_hash(&self) -> BlockHash {
        match &self.anchor {
            LightAnchor::Checkpoint(cp) => cp.block_hash,
            LightAnchor::Genesis(g) => g.block_hash,
        }
    }

    /// Hash of the most recent finalized block this client knows.
    pub fn tip_hash(&self) -> BlockHash {
        self.headers
            .back()
            .map_or(self.anchor_hash(), |h| h.block_hash)
    }

    /// State root committed by the tip.
    pub fn state_root(&self) -> CellHash {
        self.headers
            .back()
            .map_or(self.anchor_state_root(), |h| h.state_root)
    }

    /// State root this client finalized at `height`, if it still remembers it.
    pub fn state_root_at(&self, height: u64) -> Option<CellHash> {
        if height == self.anchor_height() {
            return Some(self.anchor_state_root());
        }
        self.headers
            .iter()
            .find(|h| h.height == height)
            .map(|h| h.state_root)
    }

    /// Whether this client has grounds to believe `root`.
    pub fn trusts_root(&self, root: &CellHash) -> bool {
        root == &self.anchor_state_root() || self.headers.iter().any(|h| &h.state_root == root)
    }

    /// The highest height at which this client finalized `root`.
    pub fn trusted_height_of_root(&self, root: &CellHash) -> Option<u64> {
        let mut best: Option<u64> = None;
        if root == &self.anchor_state_root() {
            best = Some(self.anchor_height());
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
        if self.anchor_height() < parent_height
            && header.state_root == self.anchor_state_root()
        {
            return Some(self.anchor_state_root());
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
    ///  * move backwards (below the current anchor, or below the tip we
    ///    already accepted), since that would discard finalized blocks;
    ///  * contradict the current anchor at the same height, or the same
    ///    block at a different height;
    ///  * contradict a header already in the window. A peer must not be able to
    ///    walk us back to a fork by handing us a "checkpoint".
    pub fn advance_to_checkpoint(&mut self, cp: Checkpoint) -> Result<(), String> {
        cp.verify(&self.validators)
            .map_err(|e| format!("light client: refusing to re-anchor: {e}"))?;

        let anchor_height = self.anchor_height();
        let anchor_hash = self.anchor_hash();
        let anchor_root = self.anchor_state_root();
        if cp.height < anchor_height {
            return Err(format!(
                "light client: checkpoint at height {} is older than the trusted anchor at {}",
                cp.height, anchor_height
            ));
        }
        if cp.height == anchor_height {
            if cp.block_hash != anchor_hash {
                return Err(format!(
                    "light client: conflicting checkpoint at height {} ({} vs trusted {})",
                    cp.height,
                    hex::encode(cp.block_hash),
                    hex::encode(anchor_hash)
                ));
            }
            if cp.state_root != anchor_root {
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

        self.anchor = LightAnchor::Checkpoint(cp);
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

    // ---------- `stell_getProof` answers ----------

    /// Verify a `stell_getProof` answer against the root this client trusts.
    ///
    /// This is the SPV path for the full proof endpoint: the account's
    /// inclusion *or* exclusion proof and every requested storage proof are
    /// checked against a state root this client finalized, and the balance
    /// and nonce reported back are the ones the proof commits to — the
    /// server's own numbers are only ever compared against the proof.
    ///
    /// The three failure modes stay apart:
    ///
    ///  * [`LightError::RootUntrusted`] — the answer names a root this client
    ///    never finalized, so there is nothing to check it against;
    ///  * [`LightError::InvalidProof`] — the answer is internally
    ///    inconsistent (malformed proof, proof for another key, a claimed
    ///    balance that contradicts the proven leaf);
    ///  * [`LightError::NotIncluded`] — the proof is well formed but does not
    ///    authenticate at the trusted root.
    pub fn verify_proof_answer(&self, answer: &ProofAnswer) -> Result<ProvenProof, LightError> {
        // Trust first: an untrusted root makes every other check moot.
        let height = self
            .trusted_height_of_root(&answer.state_root)
            .ok_or(LightError::RootUntrusted { root: answer.state_root })?;

        // The account proof.
        let proof = crate::cpat2::MerkleProof::from_nodes(&answer.account_proof)
            .map_err(|e| LightError::InvalidProof(e))?;
        if proof.key != answer.address {
            return Err(LightError::InvalidProof(format!(
                "account proof is for key {}, not the queried address {}",
                hex::encode(proof.key),
                hex::encode(answer.address)
            )));
        }

        let (balance, nonce, exists) = match proof.kind {
            crate::cpat2::ProofKind::Inclusion => {
                if !crate::cpat2::verify_proof(
                    &answer.state_root,
                    &answer.address,
                    &proof.value,
                    &proof,
                ) {
                    return Err(LightError::NotIncluded { height, state_root: answer.state_root });
                }
                if proof.value.len() < ACCOUNT_VALUE_LEN {
                    return Err(LightError::InvalidProof(format!(
                        "account leaf is {} bytes, expected at least {ACCOUNT_VALUE_LEN}",
                        proof.value.len()
                    )));
                }
                let (b, n) = decode_balance_nonce(&proof.value);
                // The server's claim must match the leaf the proof commits to.
                if b != answer.balance || n != answer.nonce {
                    return Err(LightError::InvalidProof(format!(
                        "answer claims balance {} / nonce {}, the proven leaf commits to balance {b} / nonce {n}",
                        answer.balance, answer.nonce
                    )));
                }
                (b, n, true)
            }
            crate::cpat2::ProofKind::Exclusion => {
                if !crate::cpat2::verify_exclusion_proof(&answer.state_root, &answer.address, &proof) {
                    return Err(LightError::NotIncluded { height, state_root: answer.state_root });
                }
                if answer.balance != 0 || answer.nonce != 0 {
                    return Err(LightError::InvalidProof(
                        "answer claims a balance for a key it proves is absent".to_string(),
                    ));
                }
                (0u64, 0u64, false)
            }
        };

        // The storage proofs.
        let mut storage = Vec::with_capacity(answer.storage_proofs.len());
        for sp in &answer.storage_proofs {
            let sp_proof = crate::cpat2::MerkleProof::from_nodes(&sp.proof)
                .map_err(|e| LightError::InvalidProof(e))?;
            if sp_proof.key != sp.key {
                return Err(LightError::InvalidProof(format!(
                    "storage proof is for key {}, not the claimed key {}",
                    hex::encode(sp_proof.key),
                    hex::encode(sp.key)
                )));
            }
            match sp_proof.kind {
                crate::cpat2::ProofKind::Inclusion => {
                    if !crate::cpat2::verify_proof(
                        &answer.state_root,
                        &sp.key,
                        &sp_proof.value,
                        &sp_proof,
                    ) {
                        return Err(LightError::NotIncluded { height, state_root: answer.state_root });
                    }
                    match &sp.value {
                        Some(v) if *v == sp_proof.value => {}
                        _ => {
                            return Err(LightError::InvalidProof(format!(
                                "storage value for key {} does not match the proven leaf",
                                hex::encode(sp.key)
                            )))
                        }
                    }
                    if !sp.exists {
                        return Err(LightError::InvalidProof(format!(
                            "storage key {} is proven present but the answer says it does not exist",
                            hex::encode(sp.key)
                        )));
                    }
                    storage.push(ProvenStorage {
                        key: sp.key,
                        value: Some(sp_proof.value.clone()),
                        exists: true,
                    });
                }
                crate::cpat2::ProofKind::Exclusion => {
                    if !crate::cpat2::verify_exclusion_proof(&answer.state_root, &sp.key, &sp_proof) {
                        return Err(LightError::NotIncluded { height, state_root: answer.state_root });
                    }
                    if sp.value.is_some() {
                        return Err(LightError::InvalidProof(format!(
                            "storage key {} is proven absent but the answer carries a value for it",
                            hex::encode(sp.key)
                        )));
                    }
                    storage.push(ProvenStorage { key: sp.key, value: None, exists: false });
                }
            }
        }

        Ok(ProvenProof {
            address: answer.address,
            balance,
            nonce,
            exists,
            storage,
            height,
            state_root: answer.state_root,
        })
    }

    /// Verify a raw `stell_getProof` JSON response.
    pub fn verify_proof_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<ProvenProof, LightError> {
        let answer = ProofAnswer::from_json(value).map_err(LightError::InvalidProof)?;
        self.verify_proof_answer(&answer)
    }
}

/// Decode `balance` and `nonce` out of a committed account leaf.
///
/// The leaf is `balance(8, BE) || nonce(8, BE)` for a dormant account and
/// `balance(8) || nonce(8) || scheme(1) || pubkey_hash(32)` for a pinned
/// post-quantum one; both start with the same 16 bytes.
fn decode_balance_nonce(value: &[u8]) -> (u64, u64) {
    if value.len() < ACCOUNT_VALUE_LEN {
        return (0, 0);
    }
    let mut balance = [0u8; 8];
    balance.copy_from_slice(&value[..8]);
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&value[8..16]);
    (u64::from_be_bytes(balance), u64::from_be_bytes(nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Vote, VoteKind};

    /// A light client anchored at a checkpoint over `state_root`.
    fn client_for(state_root: CellHash) -> LightClient {
        let signer = SigningKey::from_bytes(&[0x33u8; 32]);
        let val_id = signer.verifying_key().to_bytes();
        let validators = ValidatorSet::from_list(vec![(val_id, 1)]);
        let block_hash = [0x44u8; 32];
        let vote = Vote::sign(&signer, 1, 0, VoteKind::Precommit, Some(block_hash));
        let cert = QuorumCertificate {
            height: 1,
            round: 0,
            kind: VoteKind::Precommit,
            block_hash: Some(block_hash),
            signatures: vec![(vote.voter, vote.signature)],
        };
        let checkpoint = Checkpoint::new(1, block_hash, [0u8; 32], state_root, cert);
        LightClient::new(validators, checkpoint).expect("light client init")
    }

    fn account_leaf(balance: u64, nonce: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&balance.to_be_bytes());
        v.extend_from_slice(&nonce.to_be_bytes());
        v
    }

    /// Build the `stell_getProof` answer a node would serve for `trie`.
    fn answer_for(
        trie: &crate::cpat2::CompressedTrie,
        address: &[u8; 32],
        storage: &[([u8; 32], Option<Vec<u8>>)],
    ) -> ProofAnswer {
        let account_proof = trie
            .generate_proof(address)
            .or_else(|| trie.generate_exclusion_proof(address))
            .expect("account proof");
        let (balance, nonce, exists) = match account_proof.kind {
            crate::cpat2::ProofKind::Inclusion => {
                let v = &account_proof.value;
                let b = u64::from_be_bytes(v[..8].try_into().unwrap());
                let n = u64::from_be_bytes(v[8..16].try_into().unwrap());
                (b, n, true)
            }
            crate::cpat2::ProofKind::Exclusion => (0, 0, false),
        };
        let storage_proofs = storage
            .iter()
            .map(|(k, want)| {
                let p = trie
                    .generate_proof(k)
                    .or_else(|| trie.generate_exclusion_proof(k))
                    .expect("storage proof");
                StorageProofAnswer {
                    key: *k,
                    value: want.clone(),
                    exists: want.is_some(),
                    proof: p.to_nodes(),
                }
            })
            .collect();
        ProofAnswer {
            address: *address,
            balance,
            nonce,
            account_proof: account_proof.to_nodes(),
            storage_proofs,
            state_root: trie.root_hash(),
            height: Some(1),
        }
    }

    #[test]
    fn test_get_proof_answer_verifies_an_inclusion_proof() {
        let mut trie = crate::cpat2::CompressedTrie::new();
        let address = [0xABu8; 32];
        let slot = [0xCDu8; 32];
        trie.insert(&address, &account_leaf(1_000_000, 7));
        trie.insert(&slot, b"slot-value");
        let root = trie.root_hash();
        let lc = client_for(root);

        let answer = answer_for(&trie, &address, &[(slot, Some(b"slot-value".to_vec()))]);
        let proven = lc.verify_proof_answer(&answer).expect("answer must verify");

        assert_eq!(proven.address, address);
        assert_eq!(proven.balance, 1_000_000);
        assert_eq!(proven.nonce, 7);
        assert!(proven.exists);
        assert_eq!(proven.height, 1);
        assert_eq!(proven.state_root, root);
        assert_eq!(proven.storage.len(), 1);
        assert!(proven.storage[0].exists);
        assert_eq!(proven.storage[0].value.as_deref(), Some(&b"slot-value"[..]));
    }

    #[test]
    fn test_get_proof_answer_verifies_an_exclusion_proof() {
        // An account that is NOT in the state gets an exclusion proof, and a
        // light client can prove the absence instead of taking the server's
        // word for it.
        let mut trie = crate::cpat2::CompressedTrie::new();
        let present = [0xABu8; 32];
        trie.insert(&present, &account_leaf(5, 1));
        let root = trie.root_hash();
        let lc = client_for(root);

        let missing = [0xEEu8; 32];
        let answer = answer_for(&trie, &missing, &[]);
        let proven = lc.verify_proof_answer(&answer).expect("exclusion answer must verify");
        assert!(!proven.exists);
        assert_eq!(proven.balance, 0);
        assert_eq!(proven.nonce, 0);
    }

    #[test]
    fn test_get_proof_answer_rejects_a_tampered_balance() {
        let mut trie = crate::cpat2::CompressedTrie::new();
        let address = [0xABu8; 32];
        trie.insert(&address, &account_leaf(1_000_000, 7));
        let root = trie.root_hash();
        let lc = client_for(root);

        let mut answer = answer_for(&trie, &address, &[]);
        answer.balance = 2_000_000;
        assert!(matches!(
            lc.verify_proof_answer(&answer),
            Err(LightError::InvalidProof(_))
        ));
    }

    #[test]
    fn test_get_proof_answer_rejects_an_untrusted_root() {
        let mut trie = crate::cpat2::CompressedTrie::new();
        let address = [0xABu8; 32];
        trie.insert(&address, &account_leaf(1, 1));
        let lc = client_for(trie.root_hash());

        let mut answer = answer_for(&trie, &address, &[]);
        answer.state_root = [0x99u8; 32];
        assert!(matches!(
            lc.verify_proof_answer(&answer),
            Err(LightError::RootUntrusted { .. })
        ));
    }

    #[test]
    fn test_get_proof_answer_rejects_a_proof_for_another_address() {
        let mut trie = crate::cpat2::CompressedTrie::new();
        let address = [0xABu8; 32];
        let other = [0xBBu8; 32];
        trie.insert(&address, &account_leaf(1_000_000, 7));
        trie.insert(&other, &account_leaf(3, 1));
        let lc = client_for(trie.root_hash());

        let mut answer = answer_for(&trie, &address, &[]);
        answer.address = other;
        assert!(matches!(
            lc.verify_proof_answer(&answer),
            Err(LightError::InvalidProof(_))
        ));
    }

    #[test]
    fn test_get_proof_answer_rejects_a_storage_value_that_contradicts_the_proof() {
        let mut trie = crate::cpat2::CompressedTrie::new();
        let address = [0xABu8; 32];
        let slot = [0xCDu8; 32];
        trie.insert(&address, &account_leaf(1, 1));
        trie.insert(&slot, b"real");
        let lc = client_for(trie.root_hash());

        let mut answer = answer_for(&trie, &address, &[(slot, Some(b"real".to_vec()))]);
        answer.storage_proofs[0].value = Some(b"fake".to_vec());
        assert!(matches!(
            lc.verify_proof_answer(&answer),
            Err(LightError::InvalidProof(_))
        ));
    }

    #[test]
    fn test_get_proof_json_parses_and_verifies() {
        let mut trie = crate::cpat2::CompressedTrie::new();
        let address = [0xABu8; 32];
        trie.insert(&address, &account_leaf(42, 3));
        let root = trie.root_hash();
        let lc = client_for(root);

        let answer = answer_for(&trie, &address, &[]);
        let json = serde_json::json!({
            "address": hex::encode(address),
            "balance": 42u64,
            "nonce": 3u64,
            "account_proof": answer.account_proof,
            "storage_proofs": [],
            "state_root": hex::encode(root),
            "height": 1u64,
        });
        let proven = lc.verify_proof_json(&json).expect("json answer must verify");
        assert_eq!(proven.balance, 42);
        assert_eq!(proven.nonce, 3);
    }

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
