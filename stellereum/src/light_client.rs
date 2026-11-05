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
//!    elected.** The set is whatever the operator configured, plus whatever
//!    the operator later rotated in (see "Validator-set rotation" below).
//!    There is no staking-ledger audit and no election certificate: the block
//!    hash carries no commitment to the NEXT validator set, so a rotation's
//!    new-set CONTENTS are pinned out-of-band exactly like the genesis set
//!    (never taken from the server being verified). If the configured set is
//!    wrong, or a quorum of it is Byzantine, then everything this client
//!    concludes is wrong, and it will conclude it confidently. The set is the
//!    entire trust anchor.
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
        Self {
            height,
            block_hash,
            parent_hash,
            state_root,
            cert,
        }
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

    /// Build the checkpoint a `stell_getHistoricalRoot` answer authenticates.
    ///
    /// The answer names the post-`height` state root and the anchoring
    /// finalized block (`height + 1`) with its precommit QC. The caller
    /// verifies the result with `Checkpoint::verify` against its OWN
    /// validator set and, on success, adopts the root (e.g. via
    /// `LightClient::advance_to_checkpoint`, then `verify_archive_proof`).
    /// A `finalized: false` answer is refused: only a finalized anchor is
    /// evidence.
    pub fn from_historical_root_json(v: &serde_json::Value) -> Result<Self, String> {
        if !v
            .get("finalized")
            .and_then(|x| x.as_bool())
            .unwrap_or(false)
        {
            return Err("historical root is not marked finalized: refusing".to_string());
        }
        let height = v
            .get("height")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "historical root has no height".to_string())?;
        let state_root = parse_hex32(
            v.get("state_root")
                .or_else(|| v.get("stateRoot"))
                .and_then(|x| x.as_str())
                .ok_or_else(|| "historical root has no state root".to_string())?,
        )?;
        let anchor_height = v
            .get("anchor_height")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "historical root has no anchor height".to_string())?;
        if anchor_height
            != height
                .checked_add(1)
                .ok_or_else(|| "height overflows".to_string())?
        {
            return Err(format!(
                "historical root anchor {anchor_height} is not the successor of height {height}: refusing"
            ));
        }
        let anchor_hash = parse_hex32(
            v.get("anchor_hash")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "historical root has no anchor hash".to_string())?,
        )?;
        let parent_hash = parse_hex32(
            v.get("prev_hash")
                .or_else(|| v.get("anchor_prev_hash"))
                .and_then(|x| x.as_str())
                .ok_or_else(|| "historical root has no parent hash".to_string())?,
        )?;
        let cert_value = v
            .get("cert")
            .ok_or_else(|| "historical root carries no quorum certificate".to_string())?;
        let kind = match cert_value
            .get("kind")
            .and_then(|x| x.as_str())
            .ok_or_else(|| "historical root certificate has no kind".to_string())?
        {
            "Precommit" => VoteKind::Precommit,
            "Prevote" => VoteKind::Prevote,
            other => {
                return Err(format!(
                    "historical root certificate has unknown kind {other}"
                ))
            }
        };
        let cert_height = cert_value
            .get("height")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "historical root certificate has no height".to_string())?;
        let cert_round = cert_value
            .get("round")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "historical root certificate has no round".to_string())?
            as u32;
        let cert_block = match cert_value.get("block_hash") {
            Some(serde_json::Value::String(s)) => Some(parse_hex32(s)?),
            _ => None,
        };
        let mut signatures = Vec::new();
        if let Some(arr) = cert_value.get("signatures").and_then(|x| x.as_array()) {
            for sig in arr {
                let validator =
                    parse_hex32(sig.get("validator").and_then(|x| x.as_str()).ok_or_else(
                        || "historical root certificate signature has no validator".to_string(),
                    )?)?;
                let signature =
                    hex::decode(sig.get("signature").and_then(|x| x.as_str()).ok_or_else(
                        || "historical root certificate signature has no signature".to_string(),
                    )?)
                    .map_err(|e| format!("bad historical root certificate signature hex: {e}"))?;
                signatures.push((validator, signature));
            }
        }
        Ok(Self {
            height: anchor_height,
            block_hash: anchor_hash,
            parent_hash,
            state_root,
            cert: QuorumCertificate {
                height: cert_height,
                round: cert_round,
                kind,
                block_hash: cert_block,
                signatures,
            },
        })
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
    ///
    /// GATE-FIRST P2-16 (pure-PQ fail-closed): when
    /// [`crate::post_quantum::is_pure_pq_enforced`] is on, only power
    /// attested by a REGISTERED post-quantum key (verified via
    /// `verify_pq_signature` against the block hash) counts — classical-only
    /// quorums are refused. With enforcement off the ed path below runs
    /// exactly as before (dual-read: a registered PQ signature also counts,
    /// mirroring the tx-verifier precedent in `sharding.rs`).
    pub fn verify_validator_quorum(&self, validators: &ValidatorSet) -> Result<(), String> {
        if self.signatures.is_empty() {
            return Ok(());
        }
        let required = validators.quorum_power();
        if required == u64::MAX {
            return Err("validator set has no power; refusing to count signatures".to_string());
        }
        let pure_pq = crate::post_quantum::is_pure_pq_enforced();
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
            if let Some((scheme, pk)) = crate::consensus::get_validator_pq_key(pubkey) {
                if pure_pq && (!scheme.is_post_quantum() || scheme.is_disabled()) {
                    continue; // classical/disabled registration lends no power in pure-PQ
                }
                if crate::post_quantum::verify_pq_signature(scheme, &pk, &self.block_hash, sig_bytes)
                {
                    members += 1;
                    power = power.saturating_add(vp);
                    continue;
                }
                if pure_pq {
                    continue; // registered key but bad PQ signature: no ed fallthrough in pure-PQ
                }
                // Not enforced: fall through to the classical check below so a
                // validator mid-rotation still counts its ed attestation.
            } else if pure_pq {
                continue; // no registered PQ key: classical attestation refused in pure-PQ
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
        self.signatures
            .push((key.verifying_key().to_bytes(), sig.to_vec()));
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
// Epoch-key verification (the LIGHT-CLIENT side of the MEV protection)
// ============================================================================

/// Verify an MEV epoch public key against a block.
///
/// Recomputes `epoch_key_commitment(epoch, public_key, committee_hash,
/// threshold)` (see [`crate::mev_epoch::epoch_key_commitment`]) and checks
/// it against `block.epoch_key_commitment`, and checks the key's epoch is
/// the block's epoch (`height / EPOCH_BLOCKS`). Every mismatch is refused
/// with a clear reason; a block that carries NO commitment (the all-zero
/// value — no DKG completed for that epoch, or a pre-commitment block) is
/// refused too: "no commitment" must never read as "any key goes".
///
/// # TRUST ASSUMPTION — read before relying on this
///
/// This function checks the key against the BLOCK, not against the chain.
/// A full node that hands you an UNVERIFIED block can hand you any
/// commitment it likes, so only call this with a block you verified
/// yourself: recompute `block.compute_hash()`, verify the precommit QC
/// against an OUT-OF-BAND validator set (see [`LightHeader::verify`]), and
/// only then check the epoch key. With an unverified block this degrades to
/// trust-in-the-serving-node — exactly the failure the `stell_epochKey`
/// `commitment` field exists to remove.
///
/// A LIGHT client that cannot fetch full blocks checks the same condition
/// one level removed: it fetches `stell_epochKey` (which carries the
/// `commitment`), fetches the block's `epoch_key_commitment` (which is
/// inside the quorum-signed block hash), and refuses to seal unless the two
/// are equal.
pub fn verify_epoch_key_against_block(
    block: &crate::sharding::Block,
    key: &crate::mev_epoch::EpochPublicKey,
) -> Result<(), String> {
    if block.epoch_key_commitment == [0u8; 32] {
        return Err(
            "block carries no epoch-key commitment: the epoch key cannot be checked against it"
                .to_string(),
        );
    }
    let block_epoch = crate::mev_epoch::epoch_of_height(block.height);
    if key.epoch != block_epoch {
        return Err(format!(
            "epoch key is for epoch {} but the block is in epoch {}",
            key.epoch, block_epoch
        ));
    }
    let recomputed = crate::mev_epoch::epoch_key_commitment(
        key.epoch,
        &key.public_key,
        &key.committee_hash,
        key.threshold,
    );
    if recomputed != block.epoch_key_commitment {
        return Err(
            "epoch key does not match the block's epoch-key commitment: \
             the network never committed to this key"
                .to_string(),
        );
    }
    Ok(())
}

// ============================================================================
// Epoch-MMR verification (the LIGHT-CLIENT side of the V5 Tier-2 commitment)
// ============================================================================

/// A `stell_getEpochRoot` answer, as served by a full node.
///
/// The full node derives it from its finalized headers (one MMR over the
/// epoch's 128 finalized block hashes); the light client checks it against
/// the epoch root the quorum signed (the `mmr_epoch_root` of the first
/// masterchain block of the NEXT epoch) and then verifies inclusion proofs
/// against it — reusing the RPC answer instead of trusting a bare root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRootAnswer {
    /// The epoch this root covers.
    pub epoch: u64,
    /// First height of the epoch (`epoch * 128`).
    pub start_height: u64,
    /// Last height of the epoch (`start + 127`).
    pub end_height: u64,
    /// The MMR root over the epoch's finalized block hashes.
    pub mmr_root: BlockHash,
    /// The mountain peaks, left-to-right (hex in the wire JSON).
    pub peaks: Vec<BlockHash>,
    /// True when the answer covers the WHOLE epoch (all 128 heights
    /// finalized on the serving node). A partial (in-progress) epoch still
    /// has a root, but it is not THE epoch root — proofs against it are
    /// refused until the epoch completes.
    #[serde(default)]
    pub complete: bool,
    /// How many finalized leaves the serving node folded into the root.
    #[serde(default)]
    pub leaves: u64,
}

impl EpochRootAnswer {
    /// Parse a `stell_getEpochRoot` JSON response.
    ///
    /// The parsing is strict about the range: `start_height`/`end_height`
    /// must be exactly the epoch's range, otherwise the answer is refused —
    /// a server that names a wrong range for an epoch is misdescribing what
    /// the root covers. Internal consistency (the bag of the peaks equals
    /// the root) is checked by [`verify_epoch_root_answer`], not here.
    pub fn from_json(v: &serde_json::Value) -> Result<Self, String> {
        let epoch = v
            .get("epoch")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "epoch root answer has no epoch".to_string())?;
        let start_height = v
            .get("start_height")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "epoch root answer has no start_height".to_string())?;
        let end_height = v
            .get("end_height")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| "epoch root answer has no end_height".to_string())?;
        let mmr_root = parse_hex32(
            v.get("mmr_root")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "epoch root answer has no mmr_root".to_string())?,
        )?;
        let mut peaks = Vec::new();
        for p in v
            .get("peaks")
            .and_then(|x| x.as_array())
            .ok_or_else(|| "epoch root answer has no peaks".to_string())?
        {
            peaks.push(parse_hex32(p.as_str().ok_or_else(|| {
                "epoch root peak is not a hex string".to_string()
            })?)?);
        }
        Ok(Self {
            epoch,
            start_height,
            end_height,
            mmr_root,
            peaks,
            // Absent means "the server did not claim completeness" — fail
            // closed: only an explicit `true` counts.
            complete: v.get("complete").and_then(|x| x.as_bool()).unwrap_or(false),
            leaves: v.get("leaves").and_then(|x| x.as_u64()).unwrap_or(0),
        })
    }

    /// The wire JSON of this answer (what `stell_getEpochRoot` serves).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "mmr_root": hex::encode(self.mmr_root),
            "peaks": self.peaks.iter().map(hex::encode).collect::<Vec<_>>(),
            "complete": self.complete,
            "leaves": self.leaves,
        })
    }
}

/// Verify a `stell_getEpochRoot` answer's INTERNAL consistency.
///
/// Checks, in order: the range is exactly the epoch's range, the peaks are
/// non-empty, the bag of the peaks equals the claimed root, the answer is
/// marked complete, and the root is not the all-zero "no commitment"
/// sentinel. Every violation is refused with a clear reason.
///
/// # TRUST ASSUMPTION — read before relying on this
///
/// This checks the answer against ITSELF, not against the chain. A full node
/// that invents peaks bags a root for them just fine. Only call this with
/// an answer whose root you ALSO checked against a quorum-signed boundary
/// block (`Block::mmr_epoch_root` of the first masterchain block of epoch
/// + 1, with the block hash recomputed and its QC verified against an
///   out-of-band validator set). With an unchecked root this degrades to
///   trust-in-the-serving-node.
pub fn verify_epoch_root_answer(answer: &EpochRootAnswer) -> Result<(), String> {
    let expect_start = crate::mmr::epoch_start(answer.epoch);
    let expect_end = crate::mmr::epoch_end(answer.epoch);
    if answer.start_height != expect_start || answer.end_height != expect_end {
        return Err(format!(
            "epoch root answer names range {}..={} but epoch {} covers {}..={}: refusing",
            answer.start_height, answer.end_height, answer.epoch, expect_start, expect_end
        ));
    }
    if answer.peaks.is_empty() {
        return Err("epoch root answer carries no peaks: refusing".to_string());
    }
    let bagged = crate::mmr::bag_peaks(&answer.peaks);
    if bagged != answer.mmr_root {
        return Err(
            "epoch root answer is internally inconsistent: the bag of the peaks \
             does not equal the claimed root"
                .to_string(),
        );
    }
    if !answer.complete {
        return Err(
            "epoch root answer is for an incomplete epoch: the root is not the epoch root yet"
                .to_string(),
        );
    }
    if answer.mmr_root == [0u8; 32] {
        return Err(
            "epoch root answer claims a complete epoch with the all-zero root: refusing"
                .to_string(),
        );
    }
    Ok(())
}

/// Verify an MMR inclusion proof against a `stell_getEpochRoot` answer.
///
/// The answer must first pass [`verify_epoch_root_answer`]; the proof must
/// be for a full epoch (`num_leaves == 128`) and must verify against the
/// answer's root. On success the caller knows the proven block hash is part
/// of the finalized chain of `answer.epoch` — provided the answer's root
/// itself was anchored to a quorum-signed boundary block (see
/// [`verify_epoch_root_answer`'s trust assumption][verify_epoch_root_answer]).
pub fn verify_mmr_inclusion(
    answer: &EpochRootAnswer,
    proof: &crate::mmr::MmrProof,
) -> Result<(), String> {
    verify_epoch_root_answer(answer)?;
    if proof.num_leaves != crate::mmr::MMR_EPOCH_BLOCKS {
        return Err(format!(
            "MMR proof is for {} leaves, not a full {}-leaf epoch: refusing",
            proof.num_leaves,
            crate::mmr::MMR_EPOCH_BLOCKS
        ));
    }
    if !proof.verify(&answer.mmr_root) {
        return Err("MMR inclusion proof does not verify against the epoch root".to_string());
    }
    Ok(())
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
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() != 64 {
        return Err(format!(
            "expected 32 bytes (64 hex characters), got {}",
            s.len()
        ));
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
                    Some(serde_json::Value::String(s)) => {
                        Some(hex::decode(s).map_err(|e| format!("bad storage value hex: {e}"))?)
                    }
                    _ => None,
                };
                let exists = sp
                    .get("exists")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(value.is_some());
                let proof = parse_proof_nodes(sp.get("proof"))?;
                storage_proofs.push(StorageProofAnswer {
                    key,
                    value,
                    exists,
                    proof,
                });
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
// Validator-set rotation
// ============================================================================

/// Evidence that the validator set changes at one rotation point.
///
/// The chain carries NO set-transition signal in its own types: a block hash
/// commits to shard/height/parent/state-root/transactions and a handful of
/// commitments, but NOT to the next validator set (see
/// `Block::compute_hash`), so there is no in-band "epoch boundary" record for
/// a light client to read. The rotation point is therefore an ordinary
/// finalized header — the first header the NEW set is in force for — and the
/// evidence is its finality proof under the OLD set.
///
/// The rotation rule is deliberately narrow and fail-closed:
///
/// * the rotation header must chain normally onto the tip (height `tip + 1`,
///   parent = tip hash, window not full) — a rotation cannot skip, rewind,
///   or fork the chain it rotates on;
/// * the rotation header's precommit quorum certificate (and any block
///   signatures it carries) must verify under the CURRENT (old) validator
///   set — i.e. a supermajority of OLD power signed the rotation point;
/// * the replacement set must carry power of its own (non-empty, reachable
///   quorum), or no certificate could ever verify under it again.
///
/// What the rule does and does not prove: the OLD-set quorum authenticates
/// the rotation POINT (this height, this block hash, this state root) — the
/// same finality the client demands of every other header. It does NOT
/// authenticate the new set's CONTENTS, because the chain never commits to
/// them: the replacement set must be pinned out-of-band (the same file the
/// operator pinned at genesis, refreshed) or cross-checked across independent
/// nodes — never taken from the server being verified. A rotation whose QC
/// fails under the old set, a rotation to a powerless set, and any header
/// certified only by the superseded set after the rotation are all refused.
///
/// New subtype only: no existing wire type changes shape for this. The proof
/// travels as a [`LightHeader`] (served by `stell_getFinalizedHeader`) plus a
/// [`ValidatorSet`] (pinned out-of-band, cross-checked against
/// `stell_getValidators` from independent nodes).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSetRotation {
    /// The first header the new set is in force for: chained onto the tip,
    /// finalized by a quorum of the CURRENT set.
    pub rotation: LightHeader,
    /// The set that takes effect AT `rotation.height`.
    pub next_set: ValidatorSet,
}

impl ValidatorSetRotation {
    /// Bundle a rotation point with its successor set. Nothing is verified
    /// here: verification happens in [`LightClient::rotate_validator_set`],
    /// which is the only thing that may install the set.
    pub fn new(rotation: LightHeader, next_set: ValidatorSet) -> Self {
        Self {
            rotation,
            next_set,
        }
    }

    /// The height the new set takes effect at (the rotation header's height).
    pub fn effective_height(&self) -> u64 {
        self.rotation.height
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
///
/// The validator set is versioned by height: [`LightClient::set_height`]
/// names the height the current [`LightClient::validators`] took effect at,
/// so a verifier can always say which set certified which header. Rotation
/// (see [`LightClient::rotate_validator_set`]) is the only thing that moves
/// it.
#[derive(Clone, Debug)]
pub struct LightClient {
    pub validators: ValidatorSet,
    /// Height the current `validators` took effect at: the anchor height at
    /// construction, the rotation header's height after each rotation.
    set_height: u64,
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
        let set_height = checkpoint.height;
        Ok(Self {
            validators,
            set_height,
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
        let set_height = genesis.height;
        Ok(Self {
            validators,
            set_height,
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
        self.headers
            .back()
            .map_or(self.anchor_height(), |h| h.height)
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
        self.check_header_shape(&header)?;
        // --- finality --------------------------------------------------------
        header.verify(&self.validators)?;
        self.check_no_rollback(&header)?;
        self.headers.push_back(header);
        Ok(())
    }

    /// Accept one header on finality evidence alone, WITHOUT the
    /// block-signature quorum [`Self::verify_validator_quorum`] demands.
    ///
    /// The body-walk anchor probe (sync) needs this: walked bodies carry only
    /// the proposer's block signature — consensus votes sign
    /// `vote_sign_bytes`, never the block hash — so demanding a quorum of
    /// block-hash signatures refuses every legitimate tail block (live
    /// 2026-10-25: B/D walked tails refused with 1999 of 2332 power from the
    /// single proposer). An EMPTY signature list passes the strict check,
    /// which shows the layer adds nothing the finality proof does not
    /// already carry. Finality — the precommit QC, verified by the caller
    /// under the set in force at the header's height — is the trust here;
    /// the block body's own validity (proposer schedule/signature, linkage,
    /// gas) is enforced by the body path that calls the probe.
    pub fn apply_header_without_block_signatures(
        &mut self,
        header: LightHeader,
    ) -> Result<(), String> {
        self.check_header_shape(&header)?;
        // --- finality (QC quorum) WITHOUT the block-signature quorum -------
        verify_finality(
            &header.cert,
            header.height,
            header.block_hash,
            &self.validators,
        )
        .map_err(|e| format!("header at height {} rejected: {e}", header.height))?;
        self.check_no_rollback(&header)?;
        self.headers.push_back(header);
        Ok(())
    }

    /// Shape gate shared by both header-accept paths: no gaps, no rewinds,
    /// no forks, bounded window. Runs before any signature work.
    fn check_header_shape(&self, header: &LightHeader) -> Result<(), String> {
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
        let expected_parent = self.tip_hash();
        if header.prev_hash != expected_parent {
            return Err(format!(
                "light client: header at height {} forks; parent {} is not the tip {}",
                header.height,
                hex::encode(header.prev_hash),
                hex::encode(expected_parent)
            ));
        }
        if self.headers.len() >= self.max_headers {
            return Err(format!(
                "light client: header window is full ({} headers); a newer checkpoint is required before more can be accepted",
                self.max_headers
            ));
        }
        Ok(())
    }

    /// Rollback gate shared by both header-accept paths.
    fn check_no_rollback(&self, header: &LightHeader) -> Result<(), String> {
        if let Some(rolled_back_to) = self.superseded_root(header) {
            return Err(format!(
                "light client: header at height {} commits state root {}, which an earlier finalized header already superseded; the state would roll back",
                header.height,
                hex::encode(rolled_back_to)
            ));
        }
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
        if self.anchor_height() < parent_height && header.state_root == self.anchor_state_root() {
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

    // ---------- validator-set rotation ----------

    /// Height the current validator set took effect at.
    ///
    /// Every header at or above this height was (or will be) verified against
    /// [`LightClient::validators`]; headers below it were verified against a
    /// superseded set. A third party replaying the chain from genesis replays
    /// the same sequence: set changes only move this marker forward, through
    /// [`LightClient::rotate_validator_set`].
    pub fn validator_set_height(&self) -> u64 {
        self.set_height
    }

    /// Rotate to a successor validator set at a quorum-certified rotation point.
    ///
    /// The anchor is `(set, height)`: a header at `h + 1` verifies against the
    /// set in force at `h + 1`, and the set in force changes only here. The
    /// `proof.rotation` header must chain normally onto the tip (height
    /// `tip + 1`, parent = tip hash, window not full) AND carry a precommit
    /// quorum — plus any block-signature quorum it claims — from the CURRENT
    /// (old) set: a supermajority of OLD power must have signed the rotation
    /// point. The rotation header is retained in the window, and from its
    /// height on the NEW set is the only authority.
    ///
    /// Refuses, fail-closed, when:
    /// * the replacement set has no power (nothing could ever verify under
    ///   it again — the client would be bricking itself into trust-nothing);
    /// * the rotation header does not chain onto the tip (gap, rewind, fork,
    ///   or a full window — same shape gate as [`Self::apply_header`]);
    /// * the rotation header's finality evidence does not verify under the
    ///   CURRENT set (forged rotation, or a header certified by some other
    ///   set — including the NEW set signing its own adoption);
    /// * the rotation header would roll state back to a superseded root.
    ///
    /// After a rotation, headers certified only by the superseded set are
    /// refused: [`Self::apply_header`] verifies against the NEW set, and the
    /// shape gate additionally pins every new header to the rotated tip, so a
    /// stale-set header is either uncertified under the set in force or a
    /// replay of a height already taken.
    ///
    /// TRUST ASSUMPTION (not checked here — see [`ValidatorSetRotation`]): the
    /// old-set quorum authenticates the rotation POINT, not the replacement
    /// set's contents. Pass a set you pinned out-of-band, not one the server
    /// you are verifying handed you.
    pub fn rotate_validator_set(&mut self, proof: ValidatorSetRotation) -> Result<(), String> {
        if proof.next_set.quorum_power() == u64::MAX {
            return Err(
                "light client: refusing rotation to a validator set with no power; \
                 no certificate could ever verify under it"
                    .to_string(),
            );
        }
        // The rotation point is a normal successor header: no gaps, no
        // rewinds, no forks, bounded window. Runs before any signature work.
        self.check_header_shape(&proof.rotation)?;
        // Finality under the CURRENT (old) set. A rotation the old quorum did
        // not sign is not a rotation — including a header the NEW set signed
        // for itself, which verifies here only if the old set also backs it.
        proof
            .rotation
            .verify(&self.validators)
            .map_err(|e| format!("light client: refusing rotation: {e}"))?;
        self.check_no_rollback(&proof.rotation)?;
        let effective = proof.rotation.height;
        self.headers.push_back(proof.rotation);
        self.validators = proof.next_set;
        self.set_height = effective;
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
                "empty proof: a missing inclusion proof is not evidence that a key is absent"
                    .to_string(),
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
        let height =
            self.trusted_height_of_root(&answer.state_root)
                .ok_or(LightError::RootUntrusted {
                    root: answer.state_root,
                })?;

        // The account proof.
        let proof = crate::cpat2::MerkleProof::from_nodes(&answer.account_proof)
            .map_err(LightError::InvalidProof)?;
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
                    return Err(LightError::NotIncluded {
                        height,
                        state_root: answer.state_root,
                    });
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
                if !crate::cpat2::verify_exclusion_proof(
                    &answer.state_root,
                    &answer.address,
                    &proof,
                ) {
                    return Err(LightError::NotIncluded {
                        height,
                        state_root: answer.state_root,
                    });
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
                .map_err(LightError::InvalidProof)?;
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
                        return Err(LightError::NotIncluded {
                            height,
                            state_root: answer.state_root,
                        });
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
                    if !crate::cpat2::verify_exclusion_proof(&answer.state_root, &sp.key, &sp_proof)
                    {
                        return Err(LightError::NotIncluded {
                            height,
                            state_root: answer.state_root,
                        });
                    }
                    if sp.value.is_some() {
                        return Err(LightError::InvalidProof(format!(
                            "storage key {} is proven absent but the answer carries a value for it",
                            hex::encode(sp.key)
                        )));
                    }
                    storage.push(ProvenStorage {
                        key: sp.key,
                        value: None,
                        exists: false,
                    });
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
    pub fn verify_proof_json(&self, value: &serde_json::Value) -> Result<ProvenProof, LightError> {
        let answer = ProofAnswer::from_json(value).map_err(LightError::InvalidProof)?;
        self.verify_proof_answer(&answer)
    }

    // ---------- per-key ARCHIVE proofs ----------

    /// Verify a per-key archive proof (`stell_getArchiveProof`) against a
    /// HISTORICAL state root this client trusts.
    ///
    /// The proof itself is checked with `cpat2::ArchiveProof::verify`
    /// (inclusion: `key == value` is in the trie at the root; exclusion: the
    /// key is provably absent). The root is checked the same way every other
    /// proof is: it must be one this client FINALIZED (via a quorum-certified
    /// header or checkpoint — see `stell_getHistoricalRoot` and
    /// `Checkpoint::from_historical_root_json`). The three failure modes
    /// stay apart exactly like `verify_proof_answer`'s: `RootUntrusted`
    /// (never finalized this root), `InvalidProof` (malformed or
    /// self-contradictory), `NotIncluded` (well-formed but not about the
    /// trusted state — e.g. a proof replayed under the wrong root label).
    pub fn verify_archive_proof(
        &self,
        proof: &crate::cpat2::ArchiveProof,
    ) -> Result<ProvenArchiveProof, LightError> {
        // Trust first: with an untrusted root there is nothing to check against.
        let height =
            self.trusted_height_of_root(&proof.state_root)
                .ok_or(LightError::RootUntrusted {
                    root: proof.state_root,
                })?;
        // Replay guard: the proof must be ABOUT the trusted root, not merely
        // accompanied by it.
        if !proof.verify() {
            // Well-formed but not authenticating here (or malformed): either
            // way it is not evidence about the state we trust.
            return Err(LightError::NotIncluded {
                height,
                state_root: proof.state_root,
            });
        }
        let (value, exists) = match proof.proof_type {
            crate::cpat2::ArchiveProofType::Inclusion => match &proof.value {
                Some(v) => (Some(v.clone()), true),
                None => {
                    return Err(LightError::InvalidProof(
                        "archive proof claims inclusion but carries no value".to_string(),
                    ))
                }
            },
            crate::cpat2::ArchiveProofType::Exclusion => (None, false),
        };
        Ok(ProvenArchiveProof {
            key: proof.key,
            value,
            exists,
            archive_height: proof.height,
            height,
            state_root: proof.state_root,
        })
    }

    /// Verify a raw `stell_getArchiveProof` JSON response.
    pub fn verify_archive_proof_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<ProvenArchiveProof, LightError> {
        let proof =
            crate::cpat2::ArchiveProof::from_json(value).map_err(LightError::InvalidProof)?;
        self.verify_archive_proof(&proof)
    }
}

/// A per-key archive proof, verified against a historical state root this
/// client finalized.
///
/// Every field here came out of a verified proof against a trusted root:
/// holding one means the key held this value (or provably held nothing) at
/// `archive_height`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenArchiveProof {
    /// The state-trie key the proof was about.
    pub key: [u8; 32],
    /// The proven value (`None` when the key is proven absent).
    pub value: Option<Vec<u8>>,
    /// Whether the key is in the state at `archive_height`.
    pub exists: bool,
    /// The height the proof is about.
    pub archive_height: u64,
    /// Height at which this client finalized `state_root`.
    pub height: u64,
    pub state_root: CellHash,
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
    use crate::consensus::{FalconKeypair, Vote, VoteKind};

    /// FULL-PQ fixture (mirrors `consensus::tests::fvote` + `VoteSet::certificate`
    /// idiom): Ed ids with registered Falcon-512 keys, Falcon-signed votes,
    /// QC compiled via `VoteSet` so it carries the Ed list (membership/power)
    /// plus the Falcon µQC envelope (crypto) — exactly what `verify_finality`
    /// + `QuorumCertificate::verify` require.
    fn pq_singleton(seed: u8) -> (ValidatorSet, SigningKey, FalconKeypair) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let fk = FalconKeypair::generate_from_seed(seed);
        let id = sk.verifying_key().to_bytes();
        crate::consensus::register_validator_pq_key(
            id,
            crate::post_quantum::PqScheme::Falcon512,
            fk.public_key.clone(),
        );
        let vs = ValidatorSet::from_list(vec![(id, 1)]);
        (vs, sk, fk)
    }

    fn pq_cert_for(
        height: u64,
        round: u32,
        block_hash: [u8; 32],
        parent: [u8; 32],
        vs: &ValidatorSet,
        keys: &[(SigningKey, FalconKeypair)],
    ) -> QuorumCertificate {
        let mut set = crate::consensus::VoteSet::new();
        for (sk, fk) in keys {
            let v = Vote::sign_with_falcon(sk, fk, height, round, VoteKind::Precommit, Some(block_hash));
            set.add(v, vs, height, round, VoteKind::Precommit)
                .expect("falcon vote must ingest");
        }
        set.certificate_with_parent(Some(block_hash), vs, Some(&parent))
            .expect("quorum must compile a Falcon µQC")
    }

    /// A light client anchored at a checkpoint over `state_root`.
    fn client_for(state_root: CellHash) -> LightClient {
        let (validators, sk, fk) = pq_singleton(0x33);
        let block_hash = [0x44u8; 32];
        let parent = [0x99u8; 32];
        let cert = pq_cert_for(1, 0, block_hash, parent, &validators, &[(sk, fk)]);
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
        let (balance, nonce, _exists) = match account_proof.kind {
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
        let proven = lc
            .verify_proof_answer(&answer)
            .expect("exclusion answer must verify");
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
        let proven = lc
            .verify_proof_json(&json)
            .expect("json answer must verify");
        assert_eq!(proven.balance, 42);
        assert_eq!(proven.nonce, 3);
    }

    #[test]
    fn test_spv_verification_succeeds_on_49_byte_pinned_account_leaf() {
        let (validators, sk, fk) = pq_singleton(0x11);

        let address = [0x55u8; 32];
        let balance: u64 = 42_000_000;
        let nonce: u64 = 9;
        let scheme = crate::post_quantum::PqScheme::Falcon512.id();
        let pubkey_hash = [0x77u8; 32];

        let pinned_leaf =
            crate::cpat2::AccountLeaf::new_pinned(balance, nonce, scheme, pubkey_hash).encode();
        assert_eq!(pinned_leaf.len(), crate::cpat2::ACCOUNT_LEAF_LEN_PQ);

        let mut trie = PatriciaTrie::new();
        trie.insert(&address, &pinned_leaf);
        let state_root = trie.root_hash();
        let proof = trie.generate_merkle_proof(&address).expect("merkle proof");

        let block_hash = [0x22u8; 32];
        let cert = pq_cert_for(1, 0, block_hash, [0x99u8; 32], &validators, &[(sk, fk)]);
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
        let tampered_leaf =
            crate::cpat2::AccountLeaf::new_pinned(balance + 1, nonce, scheme, pubkey_hash).encode();
        assert!(lc
            .verify_account(&address, &tampered_leaf, &proof, state_root)
            .is_err());
    }

    #[test]
    fn test_spv_verification_succeeds_on_16_byte_legacy_leaf() {
        let (validators, sk, fk) = pq_singleton(0x22);

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
        let cert = pq_cert_for(1, 0, block_hash, [0x99u8; 32], &validators, &[(sk, fk)]);
        let checkpoint = Checkpoint::new(1, block_hash, [0u8; 32], state_root, cert);
        let lc = LightClient::new(validators, checkpoint).expect("light client init");

        let proven = lc
            .verify_account(&address, &legacy_leaf, &proof, state_root)
            .expect("16-byte legacy leaf verification must succeed");
        assert_eq!(proven.balance, balance);
        assert_eq!(proven.nonce, nonce);
    }

    /// A test-only epoch key over a fixed (valid) curve point.
    fn test_epoch_key(epoch: u64, committee_hash: [u8; 32]) -> crate::mev_epoch::EpochPublicKey {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::scalar::Scalar;
        let point = (RISTRETTO_BASEPOINT_POINT * Scalar::from(11u64))
            .compress()
            .to_bytes();
        crate::mev_epoch::EpochPublicKey {
            epoch,
            public_key: point,
            committee_hash,
            threshold: 2,
        }
    }

    /// A test-only block carrying an epoch-key commitment.
    fn block_with_epoch_commitment(height: u64, commitment: [u8; 32]) -> crate::sharding::Block {
        crate::sharding::Block {
            height,
            epoch_key_commitment: commitment,
            ..Default::default()
        }
    }

    /// THE LIGHT CLIENT CHECKS THE EPOCH KEY AGAINST THE BLOCK: a key the
    /// chain committed to passes; anything else is refused fail-closed.
    #[test]
    fn verify_epoch_key_against_block_accepts_the_committed_key() {
        let key = test_epoch_key(1, [0xCDu8; 32]);
        let block = block_with_epoch_commitment(
            crate::mev_epoch::EPOCH_BLOCKS + 7, // epoch 1
            crate::mev_epoch::epoch_key_commitment(
                key.epoch,
                &key.public_key,
                &key.committee_hash,
                key.threshold,
            ),
        );
        assert!(verify_epoch_key_against_block(&block, &key).is_ok());
    }

    /// No commitment in the block means no check is possible: the key is
    /// refused rather than trusted blindly.
    #[test]
    fn verify_epoch_key_against_block_refuses_a_block_without_commitment() {
        let key = test_epoch_key(0, [0xCDu8; 32]);
        let block = block_with_epoch_commitment(3, [0u8; 32]);
        assert!(
            verify_epoch_key_against_block(&block, &key).is_err(),
            "a block with no epoch-key commitment cannot vouch for any key"
        );
    }

    /// A key for ANOTHER epoch is refused, even when the commitment is
    /// well-formed: the commitment binds the epoch number.
    #[test]
    fn verify_epoch_key_against_block_refuses_a_key_for_another_epoch() {
        let key = test_epoch_key(2, [0xCDu8; 32]);
        let block = block_with_epoch_commitment(
            5, // epoch 0
            crate::mev_epoch::epoch_key_commitment(
                1u64,
                &key.public_key,
                &key.committee_hash,
                key.threshold,
            ),
        );
        assert!(
            verify_epoch_key_against_block(&block, &key).is_err(),
            "an epoch-2 key must not verify against an epoch-0 block"
        );
    }

    /// A key the chain never committed to (a different public key under the
    /// same epoch) is refused: this is the whole check.
    #[test]
    fn verify_epoch_key_against_block_refuses_an_uncommitted_key() {
        let key = test_epoch_key(0, [0xCDu8; 32]);
        let mut other = key.clone();
        other.public_key[0] ^= 0x01;
        // Keep it a valid point is unnecessary here: the commitment binds
        // the raw bytes, so ANY difference fails the comparison.
        let block = block_with_epoch_commitment(
            5,
            crate::mev_epoch::epoch_key_commitment(
                key.epoch,
                &key.public_key,
                &key.committee_hash,
                key.threshold,
            ),
        );
        assert!(
            verify_epoch_key_against_block(&block, &other).is_err(),
            "a key the chain never committed to must be refused"
        );
    }

    // ------------------------------------------------------------------
    // Epoch-MMR answers (`stell_getEpochRoot`)
    // ------------------------------------------------------------------

    /// A complete epoch-0 answer over deterministic leaves, with one proof.
    fn epoch_answer_fixture() -> (EpochRootAnswer, crate::mmr::MmrProof, [u8; 32]) {
        let leaves: Vec<[u8; 32]> = (0..crate::mmr::MMR_EPOCH_BLOCKS)
            .map(|i| {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&i.to_be_bytes());
                b
            })
            .collect();
        let m = crate::mmr::Mmr::of(&leaves);
        let (root, peaks) = crate::mmr::mmr_root_for_leaves(&leaves);
        let answer = EpochRootAnswer {
            epoch: 0,
            start_height: 0,
            end_height: 127,
            mmr_root: root,
            peaks,
            complete: true,
            leaves: 128,
        };
        let proof = m.prove(41).expect("leaf 41 proves");
        (answer, proof, root)
    }

    /// A well-formed, complete answer verifies, round-trips through JSON,
    /// and carries a proof for every leaf.
    #[test]
    fn verify_epoch_root_answer_accepts_a_consistent_complete_answer() {
        let (answer, proof, root) = epoch_answer_fixture();
        assert!(verify_epoch_root_answer(&answer).is_ok());
        let json = answer.to_json();
        let parsed = EpochRootAnswer::from_json(&json).expect("the served JSON parses");
        assert_eq!(parsed, answer);
        assert!(verify_epoch_root_answer(&parsed).is_ok());
        assert!(verify_mmr_inclusion(&parsed, &proof).is_ok());
        // The proven leaf is the block hash at start_height + leaf_index.
        assert_eq!(proof.leaf_index, 41);
        let _ = root;
    }

    /// An answer whose range does not match its epoch is refused: the root
    /// would be misdescribed.
    #[test]
    fn verify_epoch_root_answer_refuses_a_misranged_answer() {
        let (mut answer, _, _) = epoch_answer_fixture();
        answer.end_height = 128;
        assert!(verify_epoch_root_answer(&answer).is_err());
        let (mut answer, _, _) = epoch_answer_fixture();
        answer.epoch = 1;
        assert!(verify_epoch_root_answer(&answer).is_err());
    }

    /// An answer whose peaks do not bag to the claimed root is refused.
    #[test]
    fn verify_epoch_root_answer_refuses_an_inconsistent_bag() {
        let (mut answer, _, _) = epoch_answer_fixture();
        answer.peaks[0][0] ^= 0x01;
        assert!(verify_epoch_root_answer(&answer).is_err());
        let (mut answer, _, _) = epoch_answer_fixture();
        answer.mmr_root = [0xAAu8; 32];
        assert!(verify_epoch_root_answer(&answer).is_err());
    }

    /// An incomplete epoch has no epoch root yet: proofs against it are
    /// refused, even when the partial bag is internally consistent.
    #[test]
    fn verify_mmr_inclusion_refuses_an_incomplete_epoch() {
        let (mut answer, proof, _) = epoch_answer_fixture();
        answer.complete = false;
        assert!(verify_epoch_root_answer(&answer).is_err());
        assert!(verify_mmr_inclusion(&answer, &proof).is_err());
    }

    /// A proof for a different tree (or a tampered proof) does not verify
    /// against the answer.
    #[test]
    fn verify_mmr_inclusion_refuses_a_foreign_or_tampered_proof() {
        let (answer, mut proof, _) = epoch_answer_fixture();
        proof.leaf[0] ^= 0xFF;
        assert!(verify_mmr_inclusion(&answer, &proof).is_err());
        let (answer, _, _) = epoch_answer_fixture();
        let short = crate::mmr::Mmr::of(&[[0x11u8; 32]]);
        let short_proof = short.prove(0).expect("proves");
        assert!(verify_mmr_inclusion(&answer, &short_proof).is_err());
    }

    // ------------------------------------------------------------------
    // Per-key ARCHIVE proofs
    // ------------------------------------------------------------------

    /// A historical trie with one present key and room for an absent one.
    fn archive_trie() -> (crate::cpat2::CompressedTrie, CellHash, [u8; 32], [u8; 32]) {
        let mut trie = crate::cpat2::CompressedTrie::new();
        let present = [0xABu8; 32];
        trie.insert(&present, &account_leaf(1_000_000, 7));
        trie.insert(&[0xCDu8; 32], b"neighbour");
        let missing = [0xEEu8; 32];
        let root = trie.root_hash();
        (trie, root, present, missing)
    }

    /// A `stell_getHistoricalRoot`-style answer anchoring `root` at
    /// `archive_height + 1` with a Falcon µQC, and the matching checkpoint.
    fn historical_root_fixture(
        archive_height: u64,
        root: CellHash,
        vs: &ValidatorSet,
        keys: &[(SigningKey, FalconKeypair)],
    ) -> (serde_json::Value, Checkpoint, [u8; 32]) {
        let anchor_height = archive_height + 1;
        let anchor_hash = [0xB0u8; 32];
        let parent_hash = [0xA0u8; 32];
        let cert = pq_cert_for(anchor_height, 0, anchor_hash, parent_hash, vs, keys);
        let answer = serde_json::json!({
            "height": archive_height,
            "state_root": hex::encode(root),
            "anchor_height": anchor_height,
            "anchor_hash": hex::encode(anchor_hash),
            "prev_hash": hex::encode(parent_hash),
            "cert": {
                "height": cert.height,
                "round": cert.round,
                "kind": format!("{:?}", cert.kind),
                "block_hash": cert.block_hash.map(hex::encode),
                "signatures": cert.signatures.iter().map(|(v, s)| serde_json::json!({
                    "validator": hex::encode(v),
                    "signature": hex::encode(s),
                })).collect::<Vec<_>>(),
            },
            "finalized": true,
        });
        let cp = Checkpoint::new(anchor_height, anchor_hash, parent_hash, root, cert);
        (answer, cp, anchor_hash)
    }

    #[test]
    fn test_archive_proof_verifies_against_a_finalized_historical_root() {
        let (trie, root, present, missing) = archive_trie();
        let lc = client_for(root);

        // Inclusion.
        let trie_proof = trie.generate_proof(&present).expect("proof");
        let incl =
            crate::cpat2::ArchiveProof::inclusion(7, root, present, &trie_proof).expect("archive");
        let proven = lc
            .verify_archive_proof(&incl)
            .expect("inclusion must verify");
        assert_eq!(proven.key, present);
        assert!(proven.exists);
        assert_eq!(
            proven.value.as_deref(),
            Some(&account_leaf(1_000_000, 7)[..])
        );
        assert_eq!(proven.state_root, root);
        assert_eq!(proven.archive_height, incl.height);

        // Exclusion.
        let trie_excl = trie
            .generate_exclusion_proof(&missing)
            .expect("exclusion proof");
        let excl =
            crate::cpat2::ArchiveProof::exclusion(7, root, missing, &trie_excl).expect("archive");
        let proven = lc
            .verify_archive_proof(&excl)
            .expect("exclusion must verify");
        assert!(!proven.exists);
        assert_eq!(proven.value, None);

        // The JSON wire form verifies too.
        let proven = lc
            .verify_archive_proof_json(&incl.to_json())
            .expect("json must verify");
        assert!(proven.exists);
    }

    #[test]
    fn test_archive_proof_rejects_an_untrusted_historical_root() {
        let (trie, root, present, _) = archive_trie();
        let lc = client_for(root);
        let proof = trie.generate_proof(&present).expect("proof");
        let mut archive =
            crate::cpat2::ArchiveProof::inclusion(41, root, present, &proof).expect("archive");
        // Mismatched kind: an exclusion wrapper around an inclusion proof.
        archive.proof_type = crate::cpat2::ArchiveProofType::Exclusion;
        archive.value = None;
        assert!(matches!(
            lc.verify_archive_proof(&archive),
            Err(LightError::NotIncluded { .. })
        ));

        // A proof against a root this client never finalized is untrusted,
        // even though the proof itself is genuine.
        let mut other_trie = crate::cpat2::CompressedTrie::new();
        other_trie.insert(&present, &account_leaf(9, 9));
        let other_root = other_trie.root_hash();
        assert_ne!(other_root, root);
        let other_proof = other_trie.generate_proof(&present).expect("proof");
        let other_archive =
            crate::cpat2::ArchiveProof::inclusion(41, other_root, present, &other_proof)
                .expect("archive");
        assert!(other_archive.verify(), "genuine proof, wrong root");
        assert!(matches!(
            lc.verify_archive_proof(&other_archive),
            Err(LightError::RootUntrusted { .. })
        ));
    }

    #[test]
    fn test_archive_proof_rejects_tampered_proof_nodes_fail_closed() {
        // Fail-closed pin at the light-client layer: a proof that is genuine
        // except for tampered wire nodes (or a mismatched value) is about a
        // trusted root yet does not authenticate there, so it is refused as
        // `NotIncluded` — never verified, never trusted.
        let (trie, root, present, missing) = archive_trie();
        let lc = client_for(root);

        // Inclusion: flip a byte in the last wire node.
        let trie_proof = trie.generate_proof(&present).expect("proof");
        let mut tampered =
            crate::cpat2::ArchiveProof::inclusion(7, root, present, &trie_proof).expect("archive");
        assert!(
            lc.verify_archive_proof(&tampered).is_ok(),
            "sanity: untampered verifies"
        );
        let last = tampered.proof_nodes.len() - 1;
        let mut raw = hex::decode(&tampered.proof_nodes[last]).expect("nodes are hex");
        raw[0] ^= 0xFF;
        tampered.proof_nodes[last] = hex::encode(raw);
        assert!(
            !tampered.verify(),
            "sanity: tampered nodes break the proof itself"
        );
        assert!(matches!(
            lc.verify_archive_proof(&tampered),
            Err(LightError::NotIncluded { .. })
        ));
        assert!(lc.verify_archive_proof_json(&tampered.to_json()).is_err());

        // Inclusion with genuine nodes but a mismatched value.
        let mut wrong_value =
            crate::cpat2::ArchiveProof::inclusion(7, root, present, &trie_proof).expect("archive");
        wrong_value.value = Some(b"something-else".to_vec());
        assert!(!wrong_value.verify());
        assert!(matches!(
            lc.verify_archive_proof(&wrong_value),
            Err(LightError::NotIncluded { .. })
        ));

        // Exclusion: tampered nodes fail closed too.
        let trie_excl = trie
            .generate_exclusion_proof(&missing)
            .expect("exclusion proof");
        let mut tampered_excl =
            crate::cpat2::ArchiveProof::exclusion(7, root, missing, &trie_excl).expect("archive");
        assert!(
            lc.verify_archive_proof(&tampered_excl).is_ok(),
            "sanity: untampered exclusion verifies"
        );
        let last = tampered_excl.proof_nodes.len() - 1;
        let mut raw = hex::decode(&tampered_excl.proof_nodes[last]).expect("nodes are hex");
        raw[0] ^= 0xFF;
        tampered_excl.proof_nodes[last] = hex::encode(raw);
        assert!(!tampered_excl.verify());
        assert!(matches!(
            lc.verify_archive_proof(&tampered_excl),
            Err(LightError::NotIncluded { .. })
        ));

        // Garbage nodes fail closed, never as an empty proof.
        let mut garbage =
            crate::cpat2::ArchiveProof::inclusion(7, root, present, &trie_proof).expect("archive");
        garbage.proof_nodes = vec!["zz".to_string()];
        assert!(!garbage.verify());
        assert!(lc.verify_archive_proof(&garbage).is_err());
    }

    #[test]
    fn test_historical_root_answer_becomes_a_trusted_checkpoint() {
        // End to end: the client follows a QC-anchored chain from its trusted
        // anchor, then verifies an archive proof against the adopted root.
        let (validators, sk, fk) = pq_singleton(0x77);
        let keys = vec![(sk.clone(), fk.clone())];

        let (trie, root, present, _) = archive_trie();
        let archive_height = 5u64;

        // The client's trusted anchor: the finalized block AT the archive
        // height, committing to the historical root.
        let anchor_hash = [0xA0u8; 32];
        let anchor_parent = [0x99u8; 32];
        let anchor_cert = pq_cert_for(
            archive_height,
            0,
            anchor_hash,
            anchor_parent,
            &validators,
            &keys,
        );
        let anchor = Checkpoint::new(archive_height, anchor_hash, [0u8; 32], root, anchor_cert);
        let mut lc = LightClient::new(validators.clone(), anchor).expect("anchor");

        // The historical-root answer for the SAME height, anchored at
        // height+1 with a fresh QC: parse, verify, adopt.
        let (answer, cp, _) = historical_root_fixture(archive_height, root, &validators, &keys);
        let parsed = Checkpoint::from_historical_root_json(&answer).expect("parse");
        assert_eq!(parsed, cp);
        parsed
            .verify(&validators)
            .expect("the QC must verify under our own set");
        lc.advance_to_checkpoint(parsed)
            .expect("adopt the newer anchor");

        // Now the archive proof verifies against the adopted root.
        let proof = trie.generate_proof(&present).expect("proof");
        let archive = crate::cpat2::ArchiveProof::inclusion(archive_height, root, present, &proof)
            .expect("archive");
        let proven = lc.verify_archive_proof(&archive).expect("must verify");
        assert!(proven.exists);
        assert_eq!(proven.archive_height, archive_height);

        // A non-finalized answer is refused, not adopted.
        let mut draft = answer.clone();
        draft["finalized"] = serde_json::json!(false);
        assert!(Checkpoint::from_historical_root_json(&draft).is_err());
    }
}
