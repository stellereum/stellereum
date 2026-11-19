use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use super::qc_split::produce_decision_certificate_with_schedule;
use super::rotation::pq_key_at_height;
use super::sortition::{committee_for_height, micro_committee_size, pq_micro_required_power};
use super::types::{
    note_validator_set_for_vote_cache, verify_proposer_signature, BlockHash, CommitteeSchedule,
    Height, PqMicroCertificate, QuorumCertificate, Round, ShardId, ValidatorId, ValidatorSet, Vote,
    VoteKind, MASTERCHAIN_SHARD,
};

/// Anti-DoS bound: ignore votes for rounds more than this far ahead of ours.
pub const MAX_ROUND_AHEAD: Round = 1_000;

/// How far a single peer message may drag our round counter forward.
///
/// This is deliberately 1. Tendermint semantics: a node moves to the next round
/// on its OWN timeout, so a message may nudge us into the round we are about to
/// enter anyway, but never beyond it.
///
/// The looser `MAX_ROUND_AHEAD` (1000) above only decides whether a *claim* is
/// absurd enough to reject outright. Using it as the advance step was a live
/// liveness bug, measured on the two-machine stand: a fresh node at height 1
/// round 0 received a vote claiming round 57 and jumped straight there in
/// 100 ms. The proposer for a round is hash-scheduled (`proposer_for`), so the
/// round counter also decides WHO must propose. Two nodes inflating each
/// other's round therefore end up expecting proposers nobody serves, reject
/// every proposal as "wrong proposer", and sit in view changes forever -- the
/// exact wedge that made a healed partition unrecoverable.
pub const MAX_ROUND_ADVANCE_PER_MESSAGE: Round = 1;

/// Lookback window (rounds) for inspecting late votes, and the per-message cap
/// on how far `sync_round_to` may drag the local round forward.
///
/// This is the tighter of the two candidate caps for the peer-round-sync DoS
/// (audit F2). `MAX_ROUND_AHEAD` (1000) is only an absurdity gate, and
/// `MAX_ROUND_ADVANCE_PER_MESSAGE` (1) is too tight to be useful here: a peer
/// advancing one round per timeout would outpace a genuine laggard, so it could
/// never catch up by votes at all. Eight is tight enough that a Batch of 32
/// authenticated far-round votes can buy at most 256 rounds (previously 2048),
/// while still letting genuine far catch-up work in a few messages. Catch-up
/// beyond that window is carried by proposal acceptance, which aligns to the
/// proposer's near round in `on_proposal` and is independent of this counter.
pub const ROUND_LOOKBACK: Round = 8;

// ============================================================================
// Block-carried equivocation evidence (deterministic slashing input)
// ============================================================================
//
// EVIDENCE CARRIER CONTRACT (audit O1/F4 wiring).
//
// A double-sign is two fully-signed votes by one validator for the same
// (height, round, kind) with different targets. Gossip observations of such
// pairs are node-local (F4): two nodes that decide the same block by
// different routes observe different pairs, so slashing from `VoteSet` /
// `HeightConsensus::equivocations()` directly forks the state root.
//
// The wired path therefore slashes ONLY from evidence that travels INSIDE
// the decided block as verifiable content:
//
//   * carrier: the block BODY, as `OpCode::SysCallReportEquivocation`
//     (appended terminal variant — the codebase-blessed proof-in-opcode
//     pattern, cf. `SysCallSubmitPriceFeed` / zkML / PQ-verify opcodes).
//     The transaction hash commits the payload and the block hash commits
//     the transaction, so every node that applies the block verifies the
//     SAME bytes. Old nodes fail closed on the unknown discriminant
//     (bincode rejects the whole block) instead of misreading it.
//   * content: BOTH conflicting votes FULLY included (`vote_a`, `vote_b`),
//     so verification needs no external data beyond the validator set
//     every node derives identically from its staking ledger.
//   * verification: [`verify_equivocation_evidence`] — fail-closed. Same
//     height/round/kind, differing targets, voter matches both votes,
//     voter is a member, and BOTH Ed25519/Falcon signatures verify. Any
//     doubt (forged vote, same target, cross-kind pair, unknown voter,
//     oversize envelope) refuses with `false` and the caller logs loudly.
//     This closes hunt Finding 12 in the wired path: the legacy
//     `StakingLedger::slash_equivocation` trusts caller tuples (pinned by
//     `hunt_finding_12_*` — DO NOT change it); the wired primitive
//     re-verifies everything.
//   * dedup: [`EquivocationEvidence::offense_key`] —
//     `BLAKE3(domain ‖ voter ‖ height ‖ round ‖ kind ‖ target_lo ‖
//     target_hi)` with canonical target order. Same offense (either vote
//     order, any number of rebroadcasts or re-inclusions) keys identically,
//     so it is slashed exactly once per chain. `kind` is part of the key:
//     a prevote-pair and a precommit-pair at the same height/round are two
//     distinct offenses (separate quorums attacked); without it the second
//     would be wrongly swallowed.
//   * order: [`canonicalize_equivocation_evidence`] verifies, sorts by
//     offense key and dedupes. Sequential 5% burns for one offender do NOT
//     commute (each burn is a fraction of the remainder), so canonical
//     order is what makes every node compute the same remainder.
//
// Stay-out note: this section is evidence SHAPE/VERIFY only. Quorum,
// schedule, lock and certificate code below is untouched.

/// Domain separator for [`EquivocationEvidence::offense_key`].
///
/// Bumped `V1 -> V2` with the shard binding: an offense is now scoped to ONE
/// shard, and its key commits to that shard.
pub const EQUIVOCATION_OFFENSE_DOMAIN: &[u8] = b"STELLEREUM_EQUIVOCATION_OFFENSE_V2";

/// Hard cap on one evidence envelope's wire size (fail-closed: larger is
/// refused, never truncated). Two Falcon-enveloped votes fit comfortably;
/// anything bigger is a DoS probe, not evidence.
pub const MAX_EQUIVOCATION_EVIDENCE_BYTES: usize = 2_048;

/// Hard cap on evidences slashed per block (fail-closed: extras are
/// skipped loudly and may be resubmitted in a later block). Bounds the
/// per-block verification work; honest chains never approach it (each
/// offense needs a distinct double-signer).
pub const MAX_BLOCK_EQUIVOCATION_EVIDENCES: usize = 64;

/// Block-carried proof that `voter` double-signed: two fully-signed,
/// conflicting votes. Transported opaquely by
/// `OpCode::SysCallReportEquivocation`; verified by
/// [`verify_equivocation_evidence`] on every node from block bytes alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// The accused validator (must equal both votes' `voter`).
    pub voter: ValidatorId,
    /// The shard the offense happened in. A validator running several shards
    /// with one key legitimately signs different targets in each at the same
    /// (height, round, kind), so an offense is only ever WITHIN one shard.
    pub shard_id: ShardId,
    /// First conflicting vote (fully signed).
    pub vote_a: Vote,
    /// Second conflicting vote (fully signed).
    pub vote_b: Vote,
}

impl EquivocationEvidence {
    /// Build the envelope from a recorded pair. No verification here —
    /// call [`verify_equivocation_evidence`] (fail-closed) before trusting it.
    ///
    /// The envelope's shard is taken from `vote_a`; the verifier requires it
    /// to equal BOTH votes' shard, so a mismatched pair is refused rather than
    /// silently re-scoped.
    pub fn new(voter: ValidatorId, vote_a: Vote, vote_b: Vote) -> Self {
        Self {
            voter,
            shard_id: vote_a.shard_id,
            vote_a,
            vote_b,
        }
    }

    /// The per-offense dedup key (also the slash-evidence digest): a
    /// canonical commitment to everything that makes this offense unique.
    /// Swapping the two votes, rebroadcasting, or re-including the same
    /// pair keys identically.
    pub fn offense_key(&self) -> [u8; 32] {
        equivocation_offense_key(
            &self.voter,
            self.shard_id,
            self.vote_a.height,
            self.vote_a.round,
            self.vote_a.kind,
            &self.vote_a.block_hash,
            &self.vote_b.block_hash,
        )
    }

    /// Alias for [`Self::offense_key`]: the digest a block carrier commits
    /// to for this offense.
    pub fn digest(&self) -> [u8; 32] {
        self.offense_key()
    }

    /// Bincode wire size of the envelope (gas accounting + DoS cap).
    /// Unmeasurable (should be impossible) reads as `usize::MAX` so the
    /// size cap below refuses it instead of admitting it.
    pub fn wire_len(&self) -> usize {
        bincode::serialized_size(self)
            .map(|n| n as usize)
            .unwrap_or(usize::MAX)
    }
}

/// Canonical per-offense key:
/// `BLAKE3(domain ‖ voter ‖ height ‖ round ‖ kind ‖ target_lo ‖ target_hi)`,
/// with the two targets in canonical (lexicographic) order so vote order
/// never matters. `None` (nil) encodes as `0x00`, `Some(h)` as `0x01 ‖ h`,
/// so nil-vs-value counts as conflicting while nil-vs-nil does not.
pub fn equivocation_offense_key(
    voter: &ValidatorId,
    shard_id: ShardId,
    height: Height,
    round: Round,
    kind: VoteKind,
    hash_a: &Option<BlockHash>,
    hash_b: &Option<BlockHash>,
) -> [u8; 32] {
    fn enc(h: &Option<BlockHash>, out: &mut Vec<u8>) {
        match h {
            None => out.push(0x00),
            Some(hh) => {
                out.push(0x01);
                out.extend_from_slice(hh);
            }
        }
    }
    let mut ta = Vec::with_capacity(33);
    let mut tb = Vec::with_capacity(33);
    enc(hash_a, &mut ta);
    enc(hash_b, &mut tb);
    let (lo, hi) = if ta <= tb { (ta, tb) } else { (tb, ta) };
    let mut hasher = blake3::Hasher::new();
    hasher.update(EQUIVOCATION_OFFENSE_DOMAIN);
    hasher.update(voter);
    // SHARD SCOPE: one offense per (shard, voter, height, round, kind, pair).
    // The same key double-voting on two shards is two different offenses (and
    // an honest multi-shard validator produces neither).
    hasher.update(&shard_id.to_be_bytes());
    hasher.update(&height.to_be_bytes());
    hasher.update(&round.to_be_bytes());
    hasher.update(&[match kind {
        VoteKind::Prevote => 0,
        VoteKind::Precommit => 1,
    }]);
    hasher.update(&lo);
    hasher.update(&hi);
    *hasher.finalize().as_bytes()
}

/// Fail-closed verification of block-carried equivocation evidence.
///
/// Every refusal returns `false` (never panics, never errors): the caller
/// skips the evidence and logs loudly. Checks, in cheap-first order:
///  1. envelope size cap (DoS bound);
///  2. same height/round/kind, DIFFERING targets (a nil-vs-value pair is a
///     genuine double-sign — two different statements for one round; a
///     same-target or cross-kind pair is not, cf. HUNT13/HUNT19);
///  3. `voter` matches BOTH votes' `voter` (framing with another
///     validator's vote is refused — hunt Finding 12);
///  4. voter membership via `is_validator` (unknown keys are refused);
///  5. BOTH signatures verify via [`Vote::verify`] (Ed25519 strict;
///     Falcon/PQ halves and pure-PQ mode handled inside — unsigned or
///     forged votes are refused).
pub fn verify_equivocation_evidence(
    ev: &EquivocationEvidence,
    is_validator: &dyn Fn(&ValidatorId) -> bool,
) -> bool {
    if ev.wire_len() > MAX_EQUIVOCATION_EVIDENCE_BYTES {
        return false;
    }
    let (a, b) = (&ev.vote_a, &ev.vote_b);
    // SAME SHARD FIRST (false-slash primitive). One validator key may run on
    // several shards at once, and each shard has its own block space, so two
    // votes at one (height, round, kind) from different shards are NORMAL, not
    // a double-sign. The shard is inside the V3 signed preimage
    // (`vote_sign_bytes_for_shard`), so a relabelled copy cannot pass: the
    // signature only verifies under the shard it was produced for.
    if a.shard_id != b.shard_id || ev.shard_id != a.shard_id {
        return false;
    }
    if a.height != b.height || a.round != b.round || a.kind != b.kind {
        return false;
    }
    if a.block_hash == b.block_hash {
        return false;
    }
    if ev.voter != a.voter || ev.voter != b.voter {
        return false;
    }
    if !is_validator(&ev.voter) {
        return false;
    }
    if !a.verify() || !b.verify() {
        return false;
    }
    true
}

/// Deterministic shaping of candidate evidences: keep only what
/// [`verify_equivocation_evidence`] accepts, sort by offense key, drop
/// key-duplicates (same offense submitted twice, votes swapped, or
/// rebroadcast). Pure function of the inputs: every node that feeds it
/// the same candidates slashes in the same order. Order matters because
/// sequential 5% burns do not commute for one offender.
pub fn canonicalize_equivocation_evidence(
    items: Vec<EquivocationEvidence>,
    is_validator: &dyn Fn(&ValidatorId) -> bool,
) -> Vec<EquivocationEvidence> {
    let mut verified: Vec<(EquivocationEvidence, [u8; 32])> = items
        .into_iter()
        .filter(|ev| verify_equivocation_evidence(ev, is_validator))
        .map(|ev| {
            let k = ev.offense_key();
            (ev, k)
        })
        .collect();
    verified.sort_by(|a, b| a.1.cmp(&b.1));
    let mut out = Vec::with_capacity(verified.len());
    let mut last: Option<[u8; 32]> = None;
    for (ev, k) in verified {
        if last == Some(k) {
            continue;
        }
        last = Some(k);
        out.push(ev);
    }
    out
}

// ============================================================================
// Block-carried PROPOSAL equivocation evidence (deterministic slashing input)
// ============================================================================
//
// P3-EQ-ESCAPE variant 2 (double-propose). The vote envelope
// (`EquivocationEvidence`) covers Vote pairs only: a scheduled proposer that
// signs two different blocks for the same height leaves no Vote pair behind,
// so the vote-slash path is inapplicable by construction (pinned by
// `p3_eq_double_propose_escapes_vote_slash_path`). This section is the
// proposal mirror of the vote wiring above — but it is DISABLED behind
// [`PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT`] (Finding B, false-slash): a
// block carries no SIGNED round, so an honest cross-round re-proposal is
// indistinguishable from a double-propose, and refusing to slash is strictly
// safer than burning an honest proposer. The contract below is kept for the
// activation and is not reachable while the sentinel is `u64::MAX`:
//
//   * carrier: the block BODY, as `OpCode::SysCallReportProposalEquivocation`
//     (appended terminal variant — the codebase-blessed proof-in-opcode
//     pattern). The transaction hash commits the payload and the block hash
//     commits the transaction, so every node applies the SAME bytes. Old
//     nodes fail closed on the unknown discriminant instead of misreading it.
//   * content: BOTH conflicting blocks FULLY included (`block_a`,
//     `block_b`), so verification needs no external data beyond the
//     validator set every node derives identically from its staking ledger.
//     The offense is "same proposer, same shard, same height, same ROUND,
//     two different bodies". The envelope carries the claimed round so the
//     evidence shape is ready, but the round is NOT signed by the block yet;
//     that is exactly why the wired gate stays at `u64::MAX` until `Block`
//     commits one (see `proposal_equivocation_offense_rule`).
//   * verification: [`verify_proposal_equivocation_evidence`] — fail-closed.
//     Same height, differing block hashes, `proposer` matches both blocks'
//     `proposer`, membership, and BOTH proposer signatures verify (Ed25519
//     strict; Falcon/PQ halves handled inside
//     [`verify_proposer_signature`], exactly like the vote path's
//     `Vote::verify`). A same-body pair (one block repeated) is not an
//     offense; a forged signature is refused.
//   * dedup: [`ProposalEquivocationEvidence::offense_key`] —
//     `BLAKE3(domain ‖ proposer ‖ shard ‖ height ‖ round ‖ hash_lo ‖ hash_hi)`
//     with canonical body order. Either block order, any number of
//     rebroadcasts or re-inclusions key identically.
//   * order: [`canonicalize_proposal_equivocation_evidence`] verifies, sorts
//     by offense key and dedupes. Sequential 5% burns do NOT commute, so
//     canonical order is what makes every node compute the same remainder.
//
// Stay-out note: the VOTE shape/verify above is untouched. The cross-round
// vote pair (P3-EQ-ESCAPE variant 1, lock violation across rounds) stays
// DOCUMENTED-OPEN by design: different rounds fail the same-(h,r,kind) vote
// gate and no slash fires — only same-height double-signs are punishable,
// for votes and (from here) for proposals alike.

/// Domain separator for [`ProposalEquivocationEvidence::offense_key`].
pub const PROPOSAL_EQUIVOCATION_OFFENSE_DOMAIN: &[u8] =
    b"STELLEREUM_PROPOSAL_EQUIVOCATION_OFFENSE_V2";

/// Activation height of the PROPOSAL-equivocation slash.
///
/// DISABLED (`u64::MAX`) — the compiled-in sentinel. Rationale (false-slash
/// primitive, Finding B): the wire `Block` carries no ROUND, so two honest
/// proposals of DIFFERENT bodies at the same height (one per round, exactly
/// what a view change produces) are indistinguishable from a double-propose.
/// Slashing that pair burns an honest proposer, which is strictly worse than
/// not slashing at all, so the wired gate refuses every proposal evidence
/// until blocks commit a SIGNED round.
///
/// The same-shard/same-round rule is implemented and tested behind this gate
/// ([`proposal_equivocation_offense_rule`]); activation is a one-line change
/// to this constant AFTER `Block` gains a signed `round` and this verifier
/// reads it. Until then the sentinel makes a false slash impossible.
pub const PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT: Height = u64::MAX;

/// Hard cap on one proposal-evidence envelope's wire size (fail-closed:
/// larger is refused, never truncated). Two full blocks ride inside, so the
/// bound is orders of magnitude above the vote envelope's — yet still far
/// below the block wire cap (`MAX_BLOCK_WIRE_BYTES`), so packable evidence
/// exists. Anything bigger is a DoS probe, not evidence.
pub const MAX_PROPOSAL_EQUIVOCATION_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;

/// Hard cap on proposal evidences slashed per block (fail-closed: extras are
/// skipped loudly and may be resubmitted in a later block). Each evidence
/// carries two full blocks, so the cap is deliberately smaller than the
/// vote path's: honest chains never approach it (each offense needs a
/// distinct double-signing proposer at one height).
pub const MAX_BLOCK_PROPOSAL_EQUIVOCATION_EVIDENCES: usize = 8;

/// Block-carried proof that `proposer` double-proposed: two fully-signed,
/// conflicting blocks at one height. Transported opaquely by
/// `OpCode::SysCallReportProposalEquivocation`; verified by
/// [`verify_proposal_equivocation_evidence`] on every node from block bytes
/// alone.
///
/// NOTE: deliberately NO `PartialEq`/`Eq` — `Block` does not implement them,
/// and evidence equality is always decided through [`Self::offense_key`],
/// never through structural comparison.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalEquivocationEvidence {
    /// The accused proposer (must equal both blocks' `proposer`).
    pub proposer: ValidatorId,
    /// The round both proposals are claimed to belong to.
    ///
    /// REPORTED, NOT YET SIGNED: `Block` does not commit a round, so this is
    /// envelope metadata and the verifier stays behind the
    /// [`PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT`] sentinel — a reporter could
    /// otherwise claim one round for two honest cross-round proposals. The
    /// field exists so the evidence shape already carries the round when the
    /// signed-round block change lands (no half-change: the wired gate stays
    /// shut until then).
    pub round: Round,
    /// First conflicting block (fully signed by `proposer`).
    pub block_a: crate::sharding::Block,
    /// Second conflicting block (fully signed by `proposer`).
    pub block_b: crate::sharding::Block,
}

impl ProposalEquivocationEvidence {
    /// Build the envelope from a recorded pair with round `0` (unknown). No
    /// verification here — call [`verify_proposal_equivocation_evidence`]
    /// (fail-closed) before trusting it.
    pub fn new(
        proposer: ValidatorId,
        block_a: crate::sharding::Block,
        block_b: crate::sharding::Block,
    ) -> Self {
        Self::new_at_round(proposer, 0, block_a, block_b)
    }

    /// Build the envelope for an explicit claimed round.
    pub fn new_at_round(
        proposer: ValidatorId,
        round: Round,
        block_a: crate::sharding::Block,
        block_b: crate::sharding::Block,
    ) -> Self {
        Self {
            proposer,
            round,
            block_a,
            block_b,
        }
    }

    /// The per-offense dedup key: a canonical commitment to everything that
    /// makes this offense unique. Swapping the two blocks, rebroadcasting,
    /// or re-including the same pair keys identically.
    pub fn offense_key(&self) -> [u8; 32] {
        proposal_offense_key(
            &self.proposer,
            self.block_a.shard_id,
            self.block_a.height,
            self.round,
            &self.block_a.compute_hash(),
            &self.block_b.compute_hash(),
        )
    }

    /// Alias for [`Self::offense_key`]: the digest a block carrier commits
    /// to for this offense.
    pub fn digest(&self) -> [u8; 32] {
        self.offense_key()
    }

    /// Bincode wire size of the envelope (gas accounting + DoS cap).
    /// Unmeasurable (should be impossible) reads as `usize::MAX` so the
    /// size cap below refuses it instead of admitting it.
    pub fn wire_len(&self) -> usize {
        bincode::serialized_size(self)
            .map(|n| n as usize)
            .unwrap_or(usize::MAX)
    }
}

/// Canonical per-offense key:
/// `BLAKE3(domain ‖ proposer ‖ shard ‖ height ‖ round ‖ hash_lo ‖ hash_hi)`,
/// with the two block hashes in canonical (lexicographic) order so block
/// order never matters. The envelope's claimed round is part of the key so
/// the same blocks re-slid under a different claimed round are a different
/// offense — which is exactly why the wired verifier stays behind
/// [`PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT`] until that round is SIGNED by
/// the block: an unsigned round is reporter metadata, not a proof.
pub fn proposal_offense_key(
    proposer: &ValidatorId,
    shard_id: ShardId,
    height: Height,
    round: Round,
    hash_a: &BlockHash,
    hash_b: &BlockHash,
) -> [u8; 32] {
    let (lo, hi) = if hash_a <= hash_b {
        (hash_a, hash_b)
    } else {
        (hash_b, hash_a)
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROPOSAL_EQUIVOCATION_OFFENSE_DOMAIN);
    hasher.update(proposer);
    hasher.update(&shard_id.to_be_bytes());
    hasher.update(&height.to_be_bytes());
    hasher.update(&round.to_be_bytes());
    hasher.update(lo);
    hasher.update(hi);
    *hasher.finalize().as_bytes()
}

/// The proposal-equivocation RULE, parameterized by the rounds of the two
/// proposals. Same shard, same height, same ROUND, different signed bodies.
///
/// This is the rule that must gate the wired slash: an honest proposer that
/// proposes A in round r and B in r+1 at the same height (normal after a view
/// change) fails it because `round_a != round_b`. The wired verifier cannot
/// read a SIGNED round off `Block` yet, so it stays behind
/// [`PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT`]; this function is the tested,
/// ready rule behind that gate.
#[allow(clippy::too_many_arguments)]
// GATE: the four identity pairs ARE the rule's inputs; grouping them into a
// struct would hide that each block contributes its own shard/height/round/hash
// (the whole point of the check is that they must MATCH).
pub fn proposal_equivocation_offense_rule(
    shard_a: ShardId,
    shard_b: ShardId,
    height_a: Height,
    height_b: Height,
    round_a: Round,
    round_b: Round,
    hash_a: &BlockHash,
    hash_b: &BlockHash,
) -> bool {
    shard_a == shard_b && height_a == height_b && round_a == round_b && hash_a != hash_b
}

/// Fail-closed verification of block-carried proposal-equivocation evidence.
///
/// Every refusal returns `false` (never panics, never errors): the caller
/// skips the evidence and logs loudly. Checks, in cheap-first order:
///  1. envelope size cap (DoS bound);
///  2. activation sentinel: while [`PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT`]
///     is `u64::MAX` (no signed block round yet) every evidence is refused;
///  3. same shard/height/round, DIFFERING block hashes (one block repeated,
///     cross-round re-proposals and cross-shard proposals are not offenses);
///  4. `proposer` matches BOTH blocks' `proposer` (framing another
///     validator's block is refused);
///  4. proposer membership via `is_validator` (unknown keys are refused);
///  5. BOTH proposer signatures verify via [`verify_proposer_signature`]
///     (Ed25519 strict; Falcon/PQ halves handled inside — forged blocks
///     are refused).
pub fn verify_proposal_equivocation_evidence(
    ev: &ProposalEquivocationEvidence,
    is_validator: &dyn Fn(&ValidatorId) -> bool,
) -> bool {
    if ev.wire_len() > MAX_PROPOSAL_EQUIVOCATION_EVIDENCE_BYTES {
        return false;
    }
    let (a, b) = (&ev.block_a, &ev.block_b);
    // FALSE-SLASH SENTINEL (Finding B). Blocks carry no SIGNED round, so a
    // cross-round pair of honest proposals (different bodies, one per round,
    // same height) is indistinguishable from a double-propose. Slashing on
    // that would burn an honest proposer, and no slashing is strictly better
    // than a false one — so every proposal evidence refuses until `Block`
    // commits a signed round and this verifier can read it. The same-shard /
    // same-round rule lives in [`proposal_equivocation_offense_rule`] and is
    // exercised by tests behind this gate.
    if a.height < PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT {
        return false;
    }
    // SAME SHARD, not just the same height. A validator is scheduled per
    // shard and may legitimately propose one block per shard at the same
    // height (every workchain reads the masterchain validator set), so two
    // different-shard blocks are not a double-propose. The blocks carry
    // their shard id, so this is cheap and unambiguous.
    if a.shard_id != b.shard_id {
        return false;
    }
    if a.height != b.height {
        return false;
    }
    if !proposal_equivocation_offense_rule(
        a.shard_id,
        b.shard_id,
        a.height,
        b.height,
        ev.round,
        ev.round,
        &a.compute_hash(),
        &b.compute_hash(),
    ) {
        return false;
    }
    if ev.proposer != a.proposer || ev.proposer != b.proposer {
        return false;
    }
    if !is_validator(&ev.proposer) {
        return false;
    }
    if !verify_proposer_signature(a) || !verify_proposer_signature(b) {
        return false;
    }
    true
}

/// Deterministic shaping of candidate proposal evidences: keep only what
/// [`verify_proposal_equivocation_evidence`] accepts, sort by offense key,
/// drop key-duplicates (same offense submitted twice, blocks swapped, or
/// rebroadcast). Pure function of the inputs: every node that feeds it the
/// same candidates slashes in the same order. Order matters because
/// sequential 5% burns do not commute for one offender.
pub fn canonicalize_proposal_equivocation_evidence(
    items: Vec<ProposalEquivocationEvidence>,
    is_validator: &dyn Fn(&ValidatorId) -> bool,
) -> Vec<ProposalEquivocationEvidence> {
    let mut verified: Vec<(ProposalEquivocationEvidence, [u8; 32])> = items
        .into_iter()
        .filter(|ev| verify_proposal_equivocation_evidence(ev, is_validator))
        .map(|ev| {
            let k = ev.offense_key();
            (ev, k)
        })
        .collect();
    verified.sort_by(|a, b| a.1.cmp(&b.1));
    let mut out = Vec::with_capacity(verified.len());
    let mut last: Option<[u8; 32]> = None;
    for (ev, k) in verified {
        if last == Some(k) {
            continue;
        }
        last = Some(k);
        out.push(ev);
    }
    out
}

// ============================================================================
// Vote set (per height+round+kind): aggregation, quorum, equivocation
// ============================================================================

#[derive(Clone, Debug, Default)]
pub struct VoteSet {
    /// voter -> vote (at most one accepted per voter)
    votes: HashMap<ValidatorId, Vote>,
    /// power accumulated per target (None = nil)
    power: HashMap<Option<BlockHash>, u64>,
    /// equivocation evidence: (voter, first vote, conflicting vote)
    equivocations: Vec<(ValidatorId, Vote, Vote)>,
}

impl VoteSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a vote. Returns Err on invalid signature / non-validator / wrong scope.
    /// A second, DIFFERENT vote by the same validator is recorded as equivocation
    /// (the first one is kept for quorum accounting).
    pub fn add(
        &mut self,
        vote: Vote,
        validators: &ValidatorSet,
        height: Height,
        round: Round,
        kind: VoteKind,
    ) -> Result<(), String> {
        // Trigger-1 invalidation BEFORE any cached verdict is consulted: a
        // validator-set change clears stale verdicts (miss = full verify).
        // Membership itself is re-checked per-admit in `add_verified`,
        // outside the cache, so the set change can never admit a non-member.
        note_validator_set_for_vote_cache(validators);
        if vote.height != height || vote.round != round || vote.kind != kind {
            return Err("vote out of scope".to_string());
        }
        if !vote.verify() {
            return Err("bad vote signature".to_string());
        }
        self.add_verified(vote, validators)
    }

    /// Admit a vote whose signature was ALREADY verified (single or batch).
    /// Scope, membership, dedup and equivocation handling are exactly the
    /// second half of [`VoteSet::add`]; factored out so batch ingestion pays
    /// the signature check once per batch instead of once per vote.
    fn add_verified(&mut self, vote: Vote, validators: &ValidatorSet) -> Result<(), String> {
        let power = validators.power_of(&vote.voter);
        if power == 0 {
            return Err("vote from non-validator".to_string());
        }
        // ONE SHARD PER SET. A certificate aggregates the votes of exactly one
        // shard (each was signed over that shard's preimage), so a set that
        // mixed shards could never produce a certificate that verifies — and
        // keeping the invariant here is what lets `shard()` be a single value.
        if let Some(first) = self.votes.values().next() {
            if first.shard_id != vote.shard_id {
                return Err("vote from another shard".to_string());
            }
        }
        if let Some(existing) = self.votes.get(&vote.voter) {
            if existing.block_hash != vote.block_hash {
                // SECURITY: record each equivocation ONCE, keyed by the pair of
                // conflicting targets rather than by voter.
                //
                // The evidence list was never deduplicated and never cleared, so
                // re-sending the same second vote N times appended N evidence
                // tuples for one equivocation, and the caller slashes 5% per
                // tuple. That compounds to `total * 0.95^N`: about 200 rebroadcasts
                // of a single honestly-signed vote pair confiscated an entire bond
                // in one height, against a 5% design intent.
                //
                // The real exploit is targeted rather than total — rebroadcast just
                // enough against one victim to strip exactly the stake that flips
                // proposer selection — so the bound has to be one slash per pair.
                let already = self.equivocations.iter().any(|(v, a, b)| {
                    *v == vote.voter
                        && ((a.block_hash == existing.block_hash
                            && b.block_hash == vote.block_hash)
                            || (b.block_hash == existing.block_hash
                                && a.block_hash == vote.block_hash))
                });
                if !already {
                    self.equivocations
                        .push((vote.voter, existing.clone(), vote));
                }
            }
            return Ok(()); // keep the first vote
        }
        // PENTEST F-5 (LOW): saturating like every other consensus sum
        // (`total_power`, `qc_signed_power`, the verifiers). The raw `+=`
        // panicked in debug and wrapped in release for absurd configured
        // powers; a wrapped account can understate a quorum (liveness stall)
        // or, worse, clear one it never reached. Saturation can only
        // undercount, and `ValidatorSet::qc_meets_quorum` now refuses a set
        // whose true total is unrepresentable (PENTEST F-6).
        let entry = self.power.entry(vote.block_hash).or_insert(0);
        *entry = entry.saturating_add(power);
        self.votes.insert(vote.voter, vote);
        Ok(())
    }

    pub fn power_for(&self, target: Option<BlockHash>) -> u64 {
        self.power.get(&target).copied().unwrap_or(0)
    }

    /// Batch-ingest many votes with one Ed25519 batch verification.
    ///
    /// Hot path for prevote/precommit ingestion: gossip and catch-up deliver
    /// votes in bursts, and verifying them one by one is Ed25519-bound
    /// (23K vote/s stand ceiling). The whole batch is verified at once with
    /// [`Vote::partition_valid`]; per-vote scope/membership/equivocation
    /// handling then reuses the same code as [`VoteSet::add`], so the final
    /// set state is identical to adding the same votes one by one in canonical
    /// order — with one batch verify instead of N scalar ones.
    ///
    /// Fallback semantics (VOTES — keep the good ones): a batch rejection
    /// falls back to scalar [`Vote::verify`] per vote, so one forged vote
    /// never drops honest votes — dropping the whole batch would lose
    /// quorum-forming votes to a single bad neighbor. The returned vector
    /// aligns with the INPUT order: element `i` is the `add` result for
    /// `votes[i]`.
    ///
    /// Determinism: admission runs in STABLE order — votes are admitted sorted
    /// by `(voter, block_hash)` so the outcome (which duplicate is "first",
    /// which equivocation pair is recorded) does not depend on network arrival
    /// order — while the returned per-input results map back to the caller's
    /// order. Verification itself is order-independent.
    pub fn add_batch(
        &mut self,
        votes: Vec<Vote>,
        validators: &ValidatorSet,
        height: Height,
        round: Round,
        kind: VoteKind,
    ) -> Vec<Result<(), String>> {
        // Trigger-1 invalidation once per batch (same guarantee as `add`).
        note_validator_set_for_vote_cache(validators);
        // Votes live in movable slots: the signature screen borrows them, and
        // admission MOVES the admitted vote into the set. Previously the
        // screen cloned every in-scope vote into a scratch `Vec<Vote>` and
        // admission cloned each accepted vote again, so one batch paid two
        // full signature-vector allocations per vote for no new information.
        let mut slots: Vec<Option<Vote>> = votes.into_iter().map(Some).collect();
        let len = slots.len();
        // Canonical admission order: sorted by (voter, block_hash). `sort_by`
        // is stable and the keys are fully ordered, so every permutation of
        // the same input admits in the same order.
        let mut order: Vec<usize> = (0..len).collect();
        order.sort_by(|&a, &b| {
            let va = slots[a]
                .as_ref()
                .expect("slot present while ordering the batch");
            let vb = slots[b]
                .as_ref()
                .expect("slot present while ordering the batch");
            va.voter
                .cmp(&vb.voter)
                .then_with(|| va.block_hash.cmp(&vb.block_hash))
        });
        // One signature screen over the in-scope votes in admission order.
        // Out-of-scope votes skip the screen; the scope check in the admit
        // loop below reports their error exactly as `add` would.
        let mut screen_indices: Vec<usize> = Vec::new();
        for &i in &order {
            let v = slots[i]
                .as_ref()
                .expect("slot present while screening the batch");
            if v.height == height && v.round == round && v.kind == kind {
                screen_indices.push(i);
            }
        }
        let screen_flags = Vote::partition_valid_slots(&slots, &screen_indices);
        let mut sig_ok = vec![true; len];
        for (pos, &i) in screen_indices.iter().enumerate() {
            sig_ok[i] = screen_flags[pos];
        }
        // Admit in canonical order; results stored per INPUT index.
        let mut out: Vec<Option<Result<(), String>>> = (0..len).map(|_| None).collect();
        for &i in &order {
            let v = slots[i]
                .take()
                .expect("every slot is admitted exactly once");
            if v.height != height || v.round != round || v.kind != kind {
                out[i] = Some(Err("vote out of scope".to_string()));
                continue;
            }
            if !sig_ok[i] {
                out[i] = Some(Err("bad vote signature".to_string()));
                continue;
            }
            out[i] = Some(self.add_verified(v, validators));
        }
        out.into_iter()
            .map(|r| r.expect("every input index is admitted exactly once"))
            .collect()
    }

    pub fn quorum_reached(&self, target: Option<BlockHash>, validators: &ValidatorSet) -> bool {
        // PENTEST F-6: an unrepresentable power total has no representable
        // quorum; a saturated account must never clear a saturated threshold.
        validators.power_total_representable()
            && self.power_for(target) >= validators.quorum_power()
    }

    /// If any single target reached quorum, return it (nil is a valid outcome).
    pub fn quorum_target(&self, validators: &ValidatorSet) -> Option<Option<BlockHash>> {
        // PENTEST F-6: same fail-closed rule as `quorum_reached`.
        if !validators.power_total_representable() {
            return None;
        }
        let q = validators.quorum_power();
        for (target, p) in &self.power {
            if *p >= q {
                return Some(*target);
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.votes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }

    pub fn equivocations(&self) -> &[(ValidatorId, Vote, Vote)] {
        &self.equivocations
    }

    /// Return the count of collected votes in this set carrying Falcon signatures.
    pub fn falcon_votes_count(&self) -> usize {
        self.votes
            .values()
            .filter(|v| v.falcon_signature().is_some())
            .count()
    }

    /// Return collected Falcon-512 signatures for votes matching `target`.
    pub fn collect_falcon_signatures(
        &self,
        target: Option<BlockHash>,
    ) -> Vec<(ValidatorId, Vec<u8>)> {
        self.votes
            .values()
            .filter(|v| v.block_hash == target)
            .filter_map(|v| v.falcon_signature().map(|sig| (v.voter, sig.to_vec())))
            .collect()
    }

    /// The `(height, round, kind)` scope shared by every admitted vote.
    ///
    /// Admission (`add` / `add_verified`) refuses out-of-scope votes, so the
    /// whole set has exactly one scope; `None` only for an empty set. The
    /// field values are identical across votes, so picking any entry is
    /// deterministic even though the backing map's iteration order is not.
    pub fn scope(&self) -> Option<(Height, Round, VoteKind)> {
        self.votes
            .values()
            .next()
            .map(|v| (v.height, v.round, v.kind))
    }

    /// The shard shared by every admitted vote, if any.
    ///
    /// Admission refuses a vote from another shard (see `add_verified`), so
    /// the value is single even though the backing map's order is not.
    pub fn shard(&self) -> Option<ShardId> {
        self.votes.values().next().map(|v| v.shard_id)
    }

    /// Falcon-512 signatures of the votes for `target`, in CANONICAL order.
    ///
    /// Sorted by voter id (the same order the epoch/CEC certificate
    /// canonicalizes its full-set bitmask in), so building a certificate from
    /// this list is byte-identical across nodes regardless of the order votes
    /// arrived in. The unsorted [`Self::collect_falcon_signatures`] is kept
    /// for callers that only inspect the set.
    pub fn falcon_signatures_for_target(
        &self,
        target: Option<BlockHash>,
    ) -> Vec<(ValidatorId, Vec<u8>)> {
        let mut out: Vec<(ValidatorId, Vec<u8>)> = self
            .votes
            .values()
            .filter(|v| v.block_hash == target)
            .filter_map(|v| v.falcon_signature().map(|sig| (v.voter, sig.to_vec())))
            .collect();
        out.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        out
    }

    /// Build a quorum certificate for `target` from the collected votes.
    ///
    /// The Ed25519 list carries BARE 64-byte signatures (any vote-envelope
    /// half is stripped). That is the format every verifier understands,
    /// and it is what the certificate format keeps promising.
    ///
    /// `parent_hash` is the hash of the block at `height - 1` — the parent
    /// committed in the header of the block this height decides. It is the
    /// entropy the sortition committee of this height is elected with, so
    /// every builder of this certificate MUST pass the same value (the one
    /// from the chain) or the signers and the verifiers would elect different
    /// committees.
    pub fn certificate(
        &self,
        target: Option<BlockHash>,
        validators: &ValidatorSet,
        parent_hash: &[u8; 32],
    ) -> Option<QuorumCertificate> {
        self.certificate_with_parent(target, validators, Some(parent_hash))
    }

    /// Same as [`Self::certificate`], but the sortition parent may be
    /// UNKNOWN.
    ///
    /// `parent_hash: None` means "the parent block hash of this height is not
    /// known here" — no committee can then be elected honestly, so NO
    /// micro-certificate is compiled and the classical (full validator set)
    /// certificate stays authoritative. Under Pure-PQ enforcement that is
    /// fail-closed: the node cannot finalize on a committee nobody else
    /// elected (audit W6.4b).
    ///
    /// Canonical parent-hash draw byte-for-byte.
    pub fn certificate_with_parent(
        &self,
        target: Option<BlockHash>,
        validators: &ValidatorSet,
        parent_hash: Option<&[u8; 32]>,
    ) -> Option<QuorumCertificate> {
        self.certificate_with_schedule(
            target,
            validators,
            parent_hash,
            CommitteeSchedule::ParentHash,
        )
    }

    /// [`Self::certificate_with_parent`] under an explicit
    /// [`CommitteeSchedule`] — the ONE producer side of "who signs at height H".
    ///
    /// * [`CommitteeSchedule::ParentHash`]: the canonical v5 parent-hash draw,
    ///   byte-identical to [`Self::certificate`].
    /// * [`CommitteeSchedule::Beacon`]: the CN-VRF v3 epoch-beacon draw
    ///   (`sortition::committee_for_height`), the same draw
    ///   `QuorumCertificate::verify_with_schedule` re-derives. Without this the
    ///   finalize gate attributes the µQC through the beacon, finds no committee
    ///   match and refuses the node's OWN decision certificate (review F2).
    ///
    /// `parent_hash` is still required (and still stored as
    /// `sortition_parent`) on BOTH branches: it is the chain binding
    /// `binds_to_parent` checks, and an unknown parent means no honest verifier
    /// can bind this height, so no µQC is compiled (fail closed).
    #[allow(clippy::unnecessary_unwrap)]
    // GATE: is_some guard plus expect keeps parent-hash handling explicit on the consensus path; restructuring risks quorum logic.
    pub fn certificate_with_schedule(
        &self,
        target: Option<BlockHash>,
        validators: &ValidatorSet,
        parent_hash: Option<&[u8; 32]>,
        schedule: CommitteeSchedule,
    ) -> Option<QuorumCertificate> {
        if !self.quorum_reached(target, validators) {
            return None;
        }
        // REMOVED (aggregate-QC production): the per-vote classical-half
        // collection and the marker aggregate attach lived here.
        // Certificates now always carry the Ed25519 list only.
        let mut signatures = Vec::new();
        for v in self.votes.values() {
            if v.block_hash == target {
                signatures.push((v.voter, v.ed25519_signature().to_vec()));
            }
        }
        let mut qc = QuorumCertificate {
            height: self.votes.values().next()?.height,
            round: self.votes.values().next()?.round,
            kind: self.votes.values().next()?.kind,
            block_hash: target,
            signatures,
            // The certificate inherits the shard its votes were signed in, so
            // verification reconstructs the same V3 preimage. Admission keeps
            // one shard per set (see `VoteSet::add_verified`), so any entry is
            // the set's shard.
            shard_id: self.shard().unwrap_or(MASTERCHAIN_SHARD),
        };

        // Post-Quantum Micro-Certificate (µQC) compilation:
        // When collected votes carry Falcon-512 signatures, compile PqMicroCertificate
        // and attach PQ_UQC_MARKER_ID to the resulting QuorumCertificate.
        let mut falcon_sigs: HashMap<ValidatorId, Vec<u8>> = HashMap::new();
        for v in self.votes.values() {
            if v.block_hash == target {
                if let Some(fsig) = v.falcon_signature() {
                    falcon_sigs.insert(v.voter, fsig.to_vec());
                }
            }
        }

        // The committee is elected from the PARENT BLOCK HASH. When the
        // parent is UNKNOWN (a node that has not established the block hash
        // at `height - 1` yet) no committee can be derived honestly, so NO
        // micro-certificate is compiled: the classical full-set certificate
        // stays authoritative. Under Pure-PQ enforcement that is fail-closed
        // (the node cannot finalize on a committee nobody else elected)
        // instead of silently certifying against a committee of its own
        // making (audit W6.4b).
        if !falcon_sigs.is_empty() && !validators.is_empty() && parent_hash.is_some() {
            let parent_hash = parent_hash.expect("checked above");
            let committee_size = micro_committee_size(validators.len());
            if committee_size > 0 {
                // The ONE committee rule: parent-hash draw below activation,
                // epoch-beacon draw at/after it. The verifier re-derives the
                // SAME committee for this certificate.
                let committee = committee_for_height(
                    validators,
                    qc.height,
                    qc.round,
                    committee_size,
                    Some(parent_hash),
                    schedule,
                );
                // No seal ever travels with the certificate: verifiers resolve
                // the same legacy committee, so embedding anything would only
                // risk divergence.
                let get_sig_for_committee_member = |val_id: &ValidatorId| -> Option<Vec<u8>> {
                    if let Some(sig) = falcon_sigs.get(val_id) {
                        return Some(sig.clone());
                    }
                    if let Some((scheme, pk)) = pq_key_at_height(val_id, qc.height) {
                        let addr = crate::post_quantum::derive_pq_address(
                            scheme,
                            &pk,
                            &crate::post_quantum::DEFAULT_SALT,
                        );
                        if let Some(sig) = falcon_sigs.get(&addr) {
                            return Some(sig.clone());
                        }
                    }
                    for (voter, sig) in &falcon_sigs {
                        if let Some((scheme, pk)) = pq_key_at_height(voter, qc.height) {
                            let addr = crate::post_quantum::derive_pq_address(
                                scheme,
                                &pk,
                                &crate::post_quantum::DEFAULT_SALT,
                            );
                            if addr == *val_id {
                                return Some(sig.clone());
                            }
                        }
                    }
                    None
                };

                let bitmask_len = (committee_size as usize).div_ceil(8);
                let mut bitmask = vec![0u8; bitmask_len];
                let mut uqc_signatures = Vec::new();

                for (i, val_id) in committee.iter().enumerate() {
                    if let Some(sig) = get_sig_for_committee_member(val_id) {
                        bitmask[i / 8] |= 1 << (i % 8);
                        uqc_signatures.push(sig);
                    }
                }

                // Power-weighted µQC quorum, anchored to the NETWORK: sum the
                // voting powers of the committee members that actually signed
                // and require [`pq_micro_required_power`] — the max of the
                // committee's own 2/3 and the network's 2/3 BFT floor
                // (`2t − W > B_w`, never the `W/2+1` majority that two
                // conflicting certs can both clear). On uniform power the
                // whole-set rule equals the legacy head-count floor(2*k/3)+1,
                // so old certificates keep verifying; on a skewed set (e.g.
                // N=3 with A+B covering quorum) 2 signers now suffice instead
                // of a fragile 3/3 unanimous.
                let committee_total: u64 = committee.iter().map(|id| validators.power_of(id)).sum();
                if committee_total == 0 {
                    // Fail-closed: empty committee / zero weight never compiles.
                    return Some(qc);
                }
                let quorum_power =
                    pq_micro_required_power(committee_total, validators.total_power());
                let signed_power: u64 = committee
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| (bitmask[i / 8] & (1 << (i % 8))) != 0)
                    .map(|(_, id)| validators.power_of(id))
                    .sum();
                if signed_power >= quorum_power {
                    let uqc = PqMicroCertificate {
                        scheme: crate::post_quantum::PqScheme::Falcon512,
                        height: qc.height,
                        round: qc.round,
                        committee_size,
                        signers_bitmask: bitmask,
                        signatures: uqc_signatures,
                        // The parent hash the committee was elected with: a
                        // verifier re-derives the committee from it, and the
                        // block-apply path pins it to the block's own parent.
                        sortition_parent: *parent_hash,
                    };
                    qc.attach_pq_micro_certificate(&uqc);
                }
            }
        }

        Some(qc)
    }
}

// ============================================================================
// Consensus step
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

/// What the engine wants the caller to do after processing an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    /// Broadcast our prevote for this target (None = nil)
    Prevote(Option<BlockHash>),
    /// Broadcast our precommit for this target
    Precommit(Option<BlockHash>),
    /// Height is decided on this block hash
    Commit(BlockHash),
    /// Move to a new round (view change)
    NewRound(Round),
}

// ============================================================================
// Per-height consensus state machine
// ============================================================================

#[derive(Clone, Debug)]
pub struct HeightConsensus {
    pub height: Height,
    pub round: Round,
    pub step: Step,
    pub validators: ValidatorSet,
    /// The PARENT BLOCK HASH of this height — the hash of the block at
    /// `height - 1`, i.e. the `prev_hash` committed in the header of the
    /// block this height decides.
    ///
    /// It is the entropy the sortition committee of this height is elected
    /// with (see [`derive_sortition_committee`]), so every node of the network
    /// MUST hold the same value here. A node that elected its committee from
    /// a different parent would disagree with the rest of the network about
    /// who is on the committee and could never assemble a certificate the
    /// others accept.
    ///
    /// Defaults to the all-zero hash (the genesis parent). The runtime sets it
    /// from the finalized head whenever it (re-)anchors consensus on a height
    /// — see [`Self::set_parent_hash`].
    pub parent_hash: [u8; 32],
    /// True when `parent_hash` is KNOWN to be the block hash at `height - 1`.
    ///
    /// The committee is elected from that hash, so a node that does not know
    /// it elects a DIFFERENT committee than the network — and can never
    /// assemble a certificate the others accept. Height 1 is known by
    /// definition (the chain roots at the zero prev-hash sentinel); every
    /// other height needs the parent's hash to be established.
    ///
    /// An UNKNOWN parent is not a wrong parent: the µQC path then simply
    /// compiles no micro-certificate, and the classical (full validator set)
    /// certificate remains authoritative. Under Pure-PQ enforcement that is
    /// fail-closed — the node cannot finalize until it learns its parent,
    /// which is strictly better than finalizing on a committee nobody else
    /// elected.
    parent_hash_known: bool,
    /// THE schedule this height produces and verifies under (review F2).
    ///
    /// Defaults to [`CommitteeSchedule::ParentHash`] — the canonical v5 draw,
    /// byte-identical to the pre-activation code — so a `HeightConsensus`
    /// built directly (every test, every pre-activation node) is unchanged.
    /// The runtime installs [`CommitteeSchedule::Beacon`] for a height at or
    /// above its CN-VRF v3 activation (see
    /// `ValidatorRuntime::install_committee_schedule`), and the decision
    /// certificates this height produces are then drawn from the SAME epoch
    /// beacon its own verifier attributes them with.
    pub committee_schedule: CommitteeSchedule,
    /// (proposer, block_hash) proposed this round
    pub proposal: Option<(ValidatorId, BlockHash)>,
    /// The round `proposal` was accepted in. A vote must name the CURRENT
    /// round's value: voting a stale-held body with a fresh round number can
    /// never meet a quorum (the peer holds something else) and poisons the
    /// round -- observed live as nodes voting different bodies at the same
    /// round for hundreds of rounds. `has_live_proposal` gates voting on it.
    pub proposal_round: Option<Round>,
    /// locked value: (block_hash, round at which we locked)
    pub locked: Option<(BlockHash, Round)>,
    /// votes keyed by (round, kind)
    pub(super) prevotes: HashMap<Round, VoteSet>,
    pub(super) precommits: HashMap<Round, VoteSet>,
    pub decided: Option<BlockHash>,
    /// prevote QC per round (needed for locking)
    pub prevote_qc: HashMap<Round, QuorumCertificate>,
    pub precommit_qc: Option<QuorumCertificate>,
    /// Anti-runaway budget for peer-driven round jumps (audit 2026-10-06):
    /// each verified vote could previously move us +8 with no rate limit, so
    /// a burst of messages ratcheted rounds without bound (r9700, zero QCs).
    /// At most this many jumps per ROUND (the budget resets on a view
    /// change); honest catch-up (a few jumps, then landing near stops
    /// further syncing) never notices.
    ///
    /// PENTEST F-9: the per-round reset is NOT the lifetime bound — see
    /// [`Self::peer_round_advance_used`] and
    /// [`MAX_PEER_ROUND_ADVANCE_PER_HEIGHT`].
    sync_jumps_used: u32,
    /// Cumulative peer-driven round advance consumed at THIS height, in
    /// rounds (PENTEST F-9).
    ///
    /// `sync_jumps_used` bounds a burst inside one round; this bounds the
    /// LIFETIME of the height, because the per-round budget refills on every
    /// `next_round`. Every forward move made by [`Self::sync_round_to`] —
    /// the single choke point for peer round-following (vote path, drain,
    /// phase alignment, deadlock bookkeeping) — consumes it, and
    /// `next_round` never resets it. When the budget is exhausted, peer
    /// votes stop moving the round; the node's own timeout path and the
    /// corroborated deadlock breaker still can.
    peer_round_advance_used: Round,
    /// Best-known round per peer at THIS height, learned from verified votes
    /// even when the vote itself is not votable (stale far-behind or absurd
    /// far-ahead). Voting still requires an exact-round vote in `VoteSet`;
    /// this map is ONLY a round counter for sync and the deadlock breaker, so
    /// a 1200-round desync collapses instead of growing (live 2026-10-14:
    /// A r1550 vs B r318, each dropping the other's votes forever).
    pub peer_rounds: HashMap<ValidatorId, Round>,
    /// How many rounds of vote history the quorum scan covers and the vote
    /// history KEEPS.
    ///
    /// [`ROUND_LOOKBACK`] (8) in the normal case: a quorum can only ever
    /// form at or below our round, and the last few rounds are exactly the
    /// ones finalization can still decide.
    ///
    /// A deadlock re-phase WIDENS it to [`REPHASE_SCAN_WINDOW`] so a node
    /// that fell out of phase with the network can still find — and COMMIT —
    /// the quorum the network formed in the round it is actually in. Widening
    /// the WINDOW (rather than moving the round counter backwards) is what
    /// makes the re-phase effective without breaking the never-rewind
    /// invariant.
    pub scan_lookback: Round,
    /// Set once a deadlock re-phase has run at this height.
    ///
    /// The re-phase must be IDEMPOTENT: it widens the scan window and clears
    /// a stale lock, both of which happen once. Re-firing it on every
    /// timeout window would only advance the round by one (which the round
    /// timer does anyway) and change nothing else — a no-op that looks like
    /// progress.
    rephase_applied: bool,
    /// How many rounds at THIS HEIGHT ended in a VIEW CHANGE (a timeout).
    ///
    /// This is the honest "how much trouble is this height is in" counter, and
    /// it is NOT the round number: the round counter also moves when the node
    /// FOLLOWS a peer (see [`Self::sync_round_to`]) or when it is restored
    /// from a checkpoint, and a node that joins a chain at round 285027 has
    /// failed NOTHING at that height. Basing the view-change backoff on the
    /// round number therefore gave a freshly-synced node the maximum timeout
    /// (13.5 s with a 3.5 s base) before it had even tried — on a WAN, where
    /// the round timeout is what decides how fast the network reacts, that is
    /// the difference between a 3.5 s and a 27 s round.
    pub timeouts: u32,
    /// THE OBSERVED POLKA: the newest **quorum of prevotes FOR A BLOCK** this
    /// height has seen, as `(round, block_hash)`.
    ///
    /// WHY IT IS A LEDGER AND NOT A SCAN (liveness fix, live 2026-10-19 →
    /// 2026-10-21: the masterchain sat at height 285027 for three days with a
    /// full prevote QC formed and NO precommit QC):
    ///
    /// A polka is a FACT about the network, not a property of the local round
    /// counter. The old code only ever looked for one by SCANNING the rounds
    /// around the local round (`rounds_to_inspect`), so a polka whose
    /// quorum-completing prevote arrived after this node had raced ahead of
    /// the network (the WAN round-skew shape) was INVISIBLE: the node never
    /// precommitted it, so the precommit quorum never formed, and the height
    /// was parked forever. The live cluster showed exactly that: the prevote
    /// quorum for one block formed in every validator's vote set, and only
    /// ONE of them ever cast a precommit.
    ///
    /// The ledger is written the moment the quorum-completing prevote is
    /// admitted (`add_prevote` → `note_polka`) — the Tendermint rule "if you
    /// see a polka, precommit it", with no dependence on where the local
    /// round counter happens to be. It is a pure cache of a fact that the
    /// vote set already proves, so it can never make a node vote for
    /// something the network did not certify.
    pub observed_polka: Option<(Round, BlockHash)>,
    // --- C2 observability (local only, never on the wire) ---
    /// Meter: total rounds at this height that ended nil (≥1 nil prevote or
    /// no block QC). Monotonic within the height; alertable via
    /// [`crate::metrics`] (`nil_rounds_total`). Never reset except by height
    /// advance (a fresh `HeightConsensus` starts at 0).
    pub nil_rounds_total: u64,
    /// Consecutive nil-rounds ending at the CURRENT round (resets on any
    /// round that forms a block prevote QC). Drives the circuit breaker.
    pub consecutive_nil_rounds: u32,
    /// The breaker fired for the CURRENT consecutive-nil streak and its
    /// one-shot convergence action was already applied. Reset when the streak
    /// breaks (a block QC forms). Guarantees "widen once, then resume normal
    /// timing" instead of widening forever.
    pub nil_breaker_fired_this_streak: bool,
    /// Consecutive missed proposals per scheduled proposer (observability
    /// only — no protocol punishment). Incremented when a round ends with no
    /// accepted proposal from its scheduled proposer; reset to 0 the moment
    /// that proposer gets a proposal accepted. Entries for validators with a
    /// zero streak are removed, so the map stays bounded by the set size.
    pub missed_proposals: HashMap<ValidatorId, u32>,
    /// Meter: total proposer-miss observations at this height (every increment
    /// of any entry in `missed_proposals`).
    pub missed_proposals_total: u64,
}

/// Peer-driven round jumps allowed per ROUND (each jumps at most
/// ROUND_LOOKBACK). Generous for honest catch-up, fatal for runaway sync.
///
/// The budget was per WALL-CLOCK second, which put a wall clock inside the
/// consensus state machine: the catch-up behaviour then depended on how fast
/// the host happened to be, and it could not be exercised deterministically
/// (a virtual-clock harness has no wall second to expire, so a node that
/// needed to follow the network could not). It is now per ROUND — the budget
/// resets on a view change — which makes the state machine clock-free and
/// deterministic.
///
/// It is also STRICTER than the wall-clock budget it replaces: a round lasts
/// at least the round timeout (3.5 s on the live cluster), so the old budget
/// allowed 32 rounds of movement per second while this allows
/// `8 * ROUND_LOOKBACK = 64` rounds per round — under 5 rounds per second at
/// the live timeout. The runaway is bounded just as tightly, and the honest
/// catch-up (a node ~30 rounds behind needs 4 jumps) still completes inside a
/// single round's budget.
pub const MAX_SYNC_JUMPS_PER_ROUND: u32 = 8;

/// Cumulative peer-driven round advance allowed at ONE HEIGHT, in rounds.
///
/// PENTEST F-9 (HIGH liveness): the per-round budget above is reset by every
/// local view change, so one Byzantine validator could ratchet an honest node
/// by `MAX_SYNC_JUMPS_PER_ROUND * ROUND_LOOKBACK = 64` rounds per timeout,
/// refill on `next_round`, and repeat for as long as it liked — after 100
/// timeouts the node sat at round ~6500 against a network at ~100, far
/// outside even [`REPHASE_SCAN_WINDOW`] (4096), with a forward-only counter
/// and no way back except a restart.
///
/// This is the missing LIFETIME bound: peer-driven movement (every
/// `sync_round_to` from a verified vote, phase alignment, or
/// `observe_peer_round`) is capped cumulatively per height. The own-timeout
/// path (`next_round`) does NOT consume this budget and is never blocked by
/// it.
///
/// The value is HALF the widest re-phase scan window: the maximum peer-induced
/// drift plus the node's own timeout drift still fits comfortably inside
/// [`REPHASE_SCAN_WINDOW`], so the network's actual round remains visible to
/// the widened quorum scan (`apply_deadlock_local_reset`) and can be
/// committed without rewinding the round counter (rewinding would re-vote a
/// round — a slashable self-equivocation). Honest catch-up is unaffected: the
/// largest live desync this budget must cover is ~1232 rounds, and the
/// corroborated deadlock breaker ([`MAX_DEADLOCK_JUMP`], 65 536) remains the
/// escape hatch for anything larger.
pub const MAX_PEER_ROUND_ADVANCE_PER_HEIGHT: Round = REPHASE_SCAN_WINDOW / 2;

/// Absolute bound on ONE deadlock-breaker jump, in rounds.
///
/// The breaker's whole job is to close a LARGE desync in ONE step (live
/// 2026-10-14: A r1550 vs B r318 — a gap of 1232 rounds), so the bound must
/// be far larger than any realistic gap. It is deliberately NOT
/// `MAX_ROUND_AHEAD` (1000): that constant is the *vote-acceptance* window,
/// and a desync the breaker cannot close in one step is a desync the breaker
/// cannot close at all (the round counter only moves forward).
///
/// It bounds the JUMP SIZE, not the peer's claim: the target is additionally
/// CORROBORATED by validators holding more than one third of the network's
/// power (see [`HeightConsensus::deadlock_breaker_target`]), so a sub-one-
/// third Byzantine coalition cannot drag this node off the network.
pub const MAX_DEADLOCK_JUMP: Round = 65_536;

/// The round window a deadlock re-phase installs: how far back the quorum
/// scan and the vote history reach once the node has re-phased.
///
/// A node that fell out of phase with the network holds the network's votes
/// — but only for the round the network is ACTUALLY in, which can be far
/// behind the round counter this node wandered into. The normal window
/// ([`ROUND_LOOKBACK`], 8 rounds) cannot see them, so the node never finds
/// the quorum it already holds and never converges.
///
/// The re-phase therefore WIDENS the window instead of moving the round
/// counter backwards (rewinding would make the node re-vote in a round it
/// already voted in — a self-equivocation, which gets the node slashed).
/// With a wide window the node COMMITS the old round's quorum, which is
/// exactly the Tendermint rule "a node must still commit a round it has
/// left if the quorum turns up".
pub const REPHASE_SCAN_WINDOW: Round = 4_096;

/// Hard cap on the number of vote rounds retained inside ONE height.
///
/// The vote sets of the CURRENT height are kept as a whole (a late vote must
/// still be able to complete the quorum of the round it belongs to — see
/// [`HeightConsensus::prune_old_rounds`]), so this cap is what bounds the
/// memory of a height that never decides. It is generous enough to cover a
/// pathological height (the live cluster spent 380 rounds in one height) and
/// small enough that the retained votes stay in the low megabytes. The
/// OLDEST (lowest) rounds are evicted first when it is hit.
pub const MAX_RETAINED_VOTE_ROUNDS: usize = 4_096;

/// Hard cap on how far BACK the quorum scan may reach, in rounds.
///
/// The scan window is anchored on the network's round so that a node which
/// drifted ahead of the network can still find the polka the network formed
/// (see [`HeightConsensus::rounds_to_inspect`]). Without a cap, one peer
/// claiming an ancient round would make every tick scan — and every prune
/// retain — an unbounded number of rounds, which is a denial-of-service
/// primitive. The cap is far larger than any realistic WAN round skew (the
/// live cluster drifted ~30 rounds) and far smaller than the round counter.
pub const MAX_SCAN_SPAN: Round = 4_096;

// ============================================================================
// C2 SLOW-VALIDATOR / NIL-STORM / PROPOSER-LIVENESS (Enterprise Testnet grade)
// ============================================================================
//
// All items in this section are LOCAL POLICY + OBSERVABILITY ONLY: no
// wire-format change, no new consensus fields on the wire, no fork. The
// structs below (`HeightConsensus`) are never serialized to the network
// (only `Vote`, `QuorumCertificate`, `Block`, `ConsensusMsg` travel), so the
// new counters/maps change zero bytes on the wire.

/// Consecutive nil-rounds that trip the nil-storm circuit breaker (K ≤ 5).
///
/// Small enough to matter (a 3.5s base round trips the breaker in ~10s, long
/// before a round-200+ storm), large enough that one slow round never fires
/// it. Pinned by test.
pub const NIL_CIRCUIT_BREAKER_K: u32 = 3;

impl HeightConsensus {
    pub fn new(height: Height, validators: ValidatorSet) -> Self {
        Self {
            height,
            round: 0,
            step: Step::Propose,
            validators,
            parent_hash: [0u8; 32],
            parent_hash_known: height <= 1,
            committee_schedule: CommitteeSchedule::ParentHash,
            proposal: None,
            proposal_round: None,
            locked: None,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            decided: None,
            prevote_qc: HashMap::new(),
            precommit_qc: None,
            sync_jumps_used: 0,
            peer_round_advance_used: 0,
            peer_rounds: HashMap::new(),
            scan_lookback: ROUND_LOOKBACK,
            rephase_applied: false,
            timeouts: 0,
            observed_polka: None,
            nil_rounds_total: 0,
            consecutive_nil_rounds: 0,
            nil_breaker_fired_this_streak: false,
            missed_proposals: HashMap::new(),
            missed_proposals_total: 0,
        }
    }

    /// Anchor this height on its parent block hash.
    ///
    /// The parent hash is the sortition entropy of the height (see
    /// [`derive_sortition_committee`]), so it MUST be the hash the chain
    /// committed for `height - 1` — the finalized head when the runtime
    /// (re-)anchors consensus on this height. Re-anchoring on a height
    /// WITHOUT setting it leaves the zero (genesis) parent in place, which
    /// elects a different committee than the rest of the network.
    pub fn set_parent_hash(&mut self, parent_hash: [u8; 32]) {
        self.parent_hash = parent_hash;
        self.parent_hash_known = true;
    }

    /// True when the sortition parent of this height is known.
    pub fn parent_hash_known(&self) -> bool {
        self.parent_hash_known
    }

    /// Install the committee/proposer schedule of this height (review F2).
    ///
    /// The runtime calls this with [`CommitteeSchedule::Beacon`] at/after its
    /// CN-VRF v3 activation height and with
    /// [`CommitteeSchedule::ParentHash`] before it, so the certificates this
    /// height PRODUCES are drawn from exactly the schedule its own verifier
    /// (`QuorumCertificate::verify_with_schedule`) attributes them with.
    pub fn set_committee_schedule(&mut self, schedule: CommitteeSchedule) {
        self.committee_schedule = schedule;
    }

    /// The sortition parent of this height, or `None` when it is UNKNOWN.
    ///
    /// `None` means "no honest committee can be derived" — the caller must
    /// not elect one (see [`VoteSet::certificate`]).
    pub fn sortition_parent(&self) -> Option<&[u8; 32]> {
        if self.parent_hash_known {
            Some(&self.parent_hash)
        } else {
            None
        }
    }

    pub fn proposer(&self) -> Option<ValidatorId> {
        // THE schedule of this height (review F2): parent-hash draw below
        // CN-VRF v3 activation, epoch beacon at/after it. The runtime installs
        // it via `set_committee_schedule`; a bare `HeightConsensus` keeps the
        // byte-identical parent-hash default.
        self.validators
            .proposer_for_with_schedule(self.height, self.round, self.committee_schedule)
    }

    /// Accept a proposal for the current round from the correct proposer.
    pub fn receive_proposal(
        &mut self,
        proposer: ValidatorId,
        block_hash: BlockHash,
    ) -> Result<(), String> {
        let expected = self.proposer();
        self.receive_proposal_for(proposer, block_hash, expected)
    }

    /// [`Self::receive_proposal`] with an EXPLICIT expected proposer.
    ///
    /// The parent-hash schedule is not the only legal one: from
    /// `CNVRF_V3_ACTIVATION_HEIGHT` on, the epoch-beacon schedule names the
    /// proposer (`ValidatorSet::proposer_for_with_beacon`), and this struct's
    /// own `proposer()` (parent-hash draw) would then disagree with the
    /// network and refuse the caller's OWN honest proposals. The caller passes
    /// the schedule it actually validates against; every other rule (propose
    /// step, one value per round) is unchanged.
    pub fn receive_proposal_for(
        &mut self,
        proposer: ValidatorId,
        block_hash: BlockHash,
        expected: Option<ValidatorId>,
    ) -> Result<(), String> {
        if self.step != Step::Propose {
            return Err("not in propose step".to_string());
        }
        if Some(proposer) != expected {
            return Err("wrong proposer".to_string());
        }
        // Audit F1: one value per round. A second DISTINCT proposal in the
        // same round (equivocating proposer) must not overwrite the first —
        // mid-round flips split prevotes. Re-receipt of the IDENTICAL body
        // (rebroadcast) stays Ok (idempotent).
        if let Some((p, h)) = &self.proposal {
            if *p == proposer && *h == block_hash && self.proposal_round == Some(self.round) {
                return Ok(());
            }
            return Err("proposal already recorded for this round".to_string());
        }
        self.proposal = Some((proposer, block_hash));
        self.proposal_round = Some(self.round);
        Ok(())
    }

    /// True only when we hold a proposal accepted in the CURRENT round. Voting
    /// a stale-held body with a fresh round number is worse than not voting:
    /// it spends our one vote for the round on a value no quorum can ever form
    /// around, while skipping lets the current proposal (or a timeout-nil)
    /// decide the round. Callers must check this instead of `proposal.is_some()`.
    pub fn has_live_proposal(&self) -> bool {
        self.proposal.is_some() && self.proposal_round == Some(self.round)
    }

    /// Compute our prevote for the current round, applying the lock rule.
    /// Returns the target to prevote (None = nil).
    pub fn decide_prevote(&self) -> Option<BlockHash> {
        match (&self.proposal, &self.locked) {
            // If locked on a value, only prevote that value (if it matches proposal)
            (Some((_, proposed)), Some((locked, _))) => {
                if proposed == locked {
                    Some(*proposed)
                } else {
                    None // locked on a different value -> prevote nil
                }
            }
            (Some((_, proposed)), None) => Some(*proposed),
            (None, _) => None, // no proposal -> nil
        }
    }

    /// Compute our precommit target after a prevote QC exists.
    pub fn decide_precommit(&self, prevote_qc: &QuorumCertificate) -> Option<BlockHash> {
        prevote_qc.block_hash
    }

    pub fn add_prevote(&mut self, vote: Vote) -> Result<(), String> {
        // Anti-DoS: reject votes for rounds absurdly far ahead of ours.
        if vote.round > self.round.saturating_add(MAX_ROUND_AHEAD) {
            return Err("prevote round too far ahead".to_string());
        }
        // Fail-closed admission: a refused vote must leave no trace. The
        // bucket below is created on first use, so checking scope first keeps
        // a wrong-height/wrong-kind vote from materializing an empty VoteSet
        // that counts toward the retained-round cap and scan window.
        if vote.height != self.height || vote.kind != VoteKind::Prevote {
            return Err("vote out of scope".to_string());
        }
        // A refused vote must not materialize a round bucket either:
        // `VoteSet::add` would create the empty set via `entry(..).or_default()`
        // and then reject the vote, leaving a trace that counts toward
        // `MAX_RETAINED_VOTE_ROUNDS` (and can evict real votes). Admission is
        // therefore completed BEFORE the bucket is created; the vote is moved
        // into the set's already-verified path so the signature is checked
        // exactly once.
        note_validator_set_for_vote_cache(&self.validators);
        if self.validators.power_of(&vote.voter) == 0 {
            return Err("vote from non-validator".to_string());
        }
        if !vote.verify() {
            return Err("bad vote signature".to_string());
        }
        let round = vote.round;
        let res = {
            let set = self.prevotes.entry(round).or_default();
            set.add_verified(vote, &self.validators)
        };
        // THE POLKA LEDGER (liveness fix, live 2026-10-21: the masterchain
        // parked at height 285027 with a prevote QC and NO precommit QC).
        // The moment the quorum-completing prevote is admitted, the polka
        // EXISTS — record it, whatever the local round is. The scan-window
        // lookup cannot do this: a polka whose votes arrive after the node
        // has raced ahead of the network is outside the window, so the node
        // never precommits it and the precommit quorum never forms.
        self.note_polka(round);
        res
    }

    pub fn add_precommit(&mut self, vote: Vote) -> Result<(), String> {
        if vote.round > self.round.saturating_add(MAX_ROUND_AHEAD) {
            return Err("precommit round too far ahead".to_string());
        }
        // Same fail-closed admission as `add_prevote`: refuse before the
        // bucket is materialized so refused votes leave no empty VoteSet.
        if vote.height != self.height || vote.kind != VoteKind::Precommit {
            return Err("vote out of scope".to_string());
        }
        // Same fail-closed admission as `add_prevote`: a refused signature or
        // a non-member must not leave an empty round bucket behind. Scope,
        // membership and signature are checked before the bucket; the moved
        // vote then uses the already-verified path.
        note_validator_set_for_vote_cache(&self.validators);
        if self.validators.power_of(&vote.voter) == 0 {
            return Err("vote from non-validator".to_string());
        }
        if !vote.verify() {
            return Err("bad vote signature".to_string());
        }
        let round = vote.round;
        let set = self.precommits.entry(round).or_default();
        set.add_verified(vote, &self.validators)
    }

    pub fn prevote_set(&self, round: Round) -> Option<&VoteSet> {
        self.prevotes.get(&round)
    }

    pub fn precommit_set(&self, round: Round) -> Option<&VoteSet> {
        self.precommits.get(&round)
    }

    /// Return the count of collected votes carrying Falcon signatures in a given round and kind.
    pub fn falcon_votes_count(&self, round: Round, kind: VoteKind) -> usize {
        let set_opt = match kind {
            VoteKind::Prevote => self.prevotes.get(&round),
            VoteKind::Precommit => self.precommits.get(&round),
        };
        set_opt.map_or(0, |s| s.falcon_votes_count())
    }

    /// Return collected Falcon-512 vote signatures for a target in a given round and kind.
    pub fn collect_falcon_signatures(
        &self,
        round: Round,
        kind: VoteKind,
        target: Option<BlockHash>,
    ) -> Vec<(ValidatorId, Vec<u8>)> {
        let set_opt = match kind {
            VoteKind::Prevote => self.prevotes.get(&round),
            VoteKind::Precommit => self.precommits.get(&round),
        };
        set_opt.map_or_else(Vec::new, |s| s.collect_falcon_signatures(target))
    }

    /// The rounds worth inspecting, newest first.
    ///
    /// A quorum can only ever form in a round at or below ours, and a LATE vote for a
    /// round we have already left still counts -- that is the whole reason votes are
    /// stored per round instead of overwritten. Only looking at `self.round` was the
    /// deadlock: node A accepted the proposal and prevote for height 488 round 0, then
    /// took its 3s timeout into round 1, and the peer's precommit for round 0 arrived
    /// 3 seconds later. The votes for round 0 were all present and still stored, but no
    /// code path ever looked at round 0 again, so the pair sat in view changes forever
    /// until an operator wiped both data directories. This is the Tendermint rule that
    /// a node must still commit a round it has left if the quorum turns up.
    ///
    /// The window is [`Self::scan_lookback`] rounds wide: the normal
    /// [`ROUND_LOOKBACK`], widened by a deadlock re-phase so a node that fell
    /// out of phase with the network can still reach the round the network
    /// is actually in. Only rounds that actually carry votes are returned —
    /// probing thousands of empty rounds on every tick is work a peer could
    /// trigger, and the callers skip empty rounds anyway.
    ///
    /// NETWORK ANCHOR (liveness fix, live 2026-10-21: the masterchain parked at
    /// height 285027 with a full prevote QC formed and NO precommit QC): the
    /// window used to be anchored on OUR round alone. A node that had drifted
    /// AHEAD of the network (per-node round-timeout skew on a WAN) therefore
    /// could not see the round the network was actually in: the polka the
    /// network formed sat outside `[our_round - 8, our_round]`, so the node
    /// never found it, never precommitted, and the chain never finalized. The
    /// window is now anchored on the LOWEST of (our round, the highest round
    /// any peer has been observed in), so a node that is ahead still scans the
    /// network's round. The anchor is the MAXIMUM peer round, so a Byzantine
    /// peer cannot narrow the window, and [`MAX_SCAN_SPAN`] caps how far back
    /// the scan may reach, so no peer can force unbounded per-tick work.
    fn rounds_to_inspect(&self) -> Vec<Round> {
        // Bounded: an unbounded scan would let a peer force O(rounds) work per tick.
        // Looking back a fixed window covers any realistic message delay, and a vote
        // older than that is a message whose sender has long since moved on.
        let low = self.scan_floor();
        let mut rounds: Vec<Round> = Vec::new();
        for r in (low..=self.round).rev() {
            if self.prevotes.contains_key(&r) || self.precommits.contains_key(&r) {
                rounds.push(r);
            }
        }
        rounds
    }

    /// The OLDEST round the quorum scan may look at.
    ///
    /// Normally `our_round - scan_lookback`. When the network has been observed
    /// in a LOWER round than ours (we are ahead of it — the WAN round-skew
    /// shape), the floor drops to `network_round - scan_lookback` so the polka
    /// the network formed stays visible. Two hard bounds apply:
    ///
    /// * the floor never goes below `our_round - MAX_SCAN_SPAN`, so a peer
    ///   cannot make us scan (or retain) an unbounded number of rounds;
    /// * the anchor is the MAXIMUM observed peer round, so a peer claiming a
    ///   LOW round cannot narrow the window (it would only ever make `min`
    ///   pick our own round) and a peer claiming an absurdly high round
    ///   cannot widen it either (`min` picks our own round).
    fn scan_floor(&self) -> Round {
        let anchor = self.max_peer_round().unwrap_or(self.round).min(self.round);
        let floor = anchor.saturating_sub(self.scan_lookback);
        let hard = self.round.saturating_sub(MAX_SCAN_SPAN);
        floor.max(hard).min(self.round)
    }

    /// True when the quorum scan currently reaches `round`, i.e. a vote set
    /// retained at that round would be inspected by [`Self::rounds_to_inspect`].
    ///
    /// Read-only observability used by the liveness/residue tests and the
    /// operator readout: after a re-phase it answers "can this node still see
    /// the round the network is actually in?" without exposing the scan
    /// internals. Never mutates consensus state.
    pub fn scan_reaches(&self, round: Round) -> bool {
        round >= self.scan_floor() && round <= self.round
    }

    /// Human-readable reasons finalization is currently blocked. Called when
    /// `try_finalize` yields nothing despite precommit activity: a silent
    /// `None` there once cost hours of live debugging (both nodes precommitting
    /// the same hash every round with no finalize and no log line). Reports the
    /// first round with a precommit QC and exactly which gate holds it back
    /// (prevote-QC mismatch with per-side vote presence, lock refusal naming
    /// hashes and rounds). Pure readout, no state change.
    pub fn finalize_blockers(&self) -> Option<String> {
        let short = |h: &[u8; 32]| hex::encode(&h[..4]);
        for r in self.rounds_to_inspect() {
            let Some(pset) = self.precommits.get(&r) else {
                continue;
            };
            let Some(ptarget) = pset.quorum_target(&self.validators) else {
                continue;
            };
            let Some(block) = ptarget else {
                return Some(format!("h={} r={r}: precommit QC is nil", self.height));
            };
            let pv = self
                .prevotes
                .get(&r)
                .and_then(|s| s.quorum_target(&self.validators))
                .flatten();
            if pv != Some(block) {
                let have: Vec<String> = self
                    .prevotes
                    .get(&r)
                    .map(|s| {
                        let mut v: Vec<String> = s.votes.keys().map(&short).collect();
                        v.sort();
                        v
                    })
                    .unwrap_or_default();
                return Some(format!(
                    "h={} r={r}: precommit QC -> {} but prevote QC -> {} (prevoters: {:?})",
                    self.height,
                    short(&block),
                    pv.map(|b| short(&b)).unwrap_or_else(|| "none".into()),
                    have
                ));
            }
            if let Some((locked_block, locked_round)) = self.locked {
                if locked_round <= r && locked_block != block {
                    return Some(format!(
                        "h={} r={r}: lock ({}, r{locked_round}) refuses {}",
                        self.height,
                        short(&locked_block),
                        short(&block)
                    ));
                }
            }
            return Some(format!(
                "h={} r={r}: QCs agree on {} but finalize still fails (missing body?)",
                self.height,
                short(&block)
            ));
        }
        None
    }

    /// Try to form a prevote QC. Returns the QC target.
    /// Like [`Self::try_prevote_quorum`] but also returns the ROUND the polka
    /// belongs to. Callers that must cast a follow-up vote (precommit) need
    /// that round: stamping their own `hc.round` instead put the two nodes'
    /// precommits into different VoteSet buckets whenever they were one round
    /// apart, so a full prevote QC never became a decision (31 of 180 wasted
    /// rounds on the live stand).
    pub fn try_prevote_quorum_at(&mut self) -> Option<(Round, Option<BlockHash>)> {
        // Newest-wins (audit-consensus F7 hardening 2026-10-14): the scan runs
        // newest-first, but the OLD code unlocked on EVERY round above the
        // lock — so an OLDER conflicting polka unlocked even when a NEWER
        // polka re-confirmed the locked value (extra rounds: unlock, nil,
        // re-lock — liveness only, never a fork). Only the NEWEST polka in
        // the window may unlock: it is the network's latest word, and an
        // older quorum is stale evidence the newer one already superseded.
        let mut found: Option<(Round, Option<BlockHash>)> = None;
        // The newest POLKA (a quorum of prevotes FOR A BLOCK). A nil quorum
        // is NOT a polka - see `try_polka_at` - and it must not shadow a real
        // polka for the unlock decision either: a nil quorum says "no block
        // was agreed in THAT round", nothing about the earlier round the
        // network DID agree on a block in.
        let mut polka: Option<(Round, BlockHash)> = None;
        for round in self.rounds_to_inspect() {
            let Some(set) = self.prevotes.get(&round) else {
                continue;
            };
            let Some(target) = set.quorum_target(&self.validators) else {
                continue;
            };
            if found.is_none() {
                if let Some(qc) = produce_decision_certificate_with_schedule(
                    set,
                    target,
                    &self.validators,
                    self.sortition_parent(),
                    self.committee_schedule,
                ) {
                    self.prevote_qc.insert(round, qc);
                }
                found = Some((round, target));
            }
            if polka.is_none() {
                if let Some(block) = target {
                    polka = Some((round, block));
                }
            }
        }
        // THE LEDGER WINS OVER THE WINDOW (liveness fix, live 2026-10-21: the
        // masterchain parked at height 285027 with a prevote QC and NO
        // precommit QC). The scan only sees the rounds around the local
        // counter; the ledger remembers the newest polka the node has
        // OBSERVED, wherever it formed. A polka the window cannot see is
        // still a polka, and it is still the network's latest word when it is
        // NEWER than anything the window holds.
        let polka = match (self.observed_polka, polka) {
            (Some((r1, b1)), Some((r2, b2))) => Some(if r1 >= r2 { (r1, b1) } else { (r2, b2) }),
            (a, None) => a,
            (None, b) => b,
        };
        // Polka unlock (BFT liveness): a quorum for a different value -- or
        // for nil -- at a HIGHER round than our lock proves the network
        // moved on without us (we locked on a QC the peer never saw, after
        // a single lost vote). Keeping the old lock would nil every future
        // proposal while the network can never come back: observed live as
        // a permanent stall with one node voting nil forever. Unlock; the
        // normal path re-locks when we precommit again. A quorum for our
        // own value changes nothing.
        //
        // Newest-wins: `polka` is the NEWEST polka (scan order above), so an
        // older conflicting quorum no longer unlocks past a newer confirming
        // one.
        // Polka unlock (BFT safety & liveness, audit F-01): in Tendermint, a
        // node ONLY unlocks when observing a prevote quorum for a DIFFERENT
        // non-nil block (`Some(other_block)`). A nil polka (`found == (r, None)`)
        // forms on timeouts and must NEVER unlock — otherwise honest nodes that
        // timed out in round 1 would drop their locks on a block finalized in
        // round 0 and finalize a conflicting block in round 2 (safety violation).
        if let (Some((locked_block, locked_round)), Some((polka_round, other_block))) =
            (self.locked, polka)
        {
            if polka_round > locked_round && other_block != locked_block {
                self.locked = None;
            }
        }
        found
    }

    /// The newest **POLKA** in the scan window: a round whose prevote set
    /// holds quorum power FOR A BLOCK, together with the round it formed in.
    ///
    /// A NIL quorum is not a polka. Tendermint's rule: a nil quorum means
    /// "no block was agreed in that round"; it never masks a polka from an
    /// earlier round, and it never unlocks a lock. The precommit path must
    /// therefore follow the newest POLKA, not the newest quorum of any kind.
    ///
    /// WHY THIS MATTERS (liveness fix, live 2026-10-21: the masterchain parked
    /// at height 285027 with a full prevote QC formed and NO precommit QC): the
    /// scan used to return the newest quorum, nil included. A node that had
    /// moved on to a later round collected a NIL quorum there (the network
    /// timed out) and that nil quorum SHADOWED the real polka one round
    /// earlier: the node produced a NIL precommit for the newer round instead
    /// of a precommit for the block the network had actually certified, and
    /// the `last_precommitted` dedup key then suppressed the correct precommit
    /// on every later tick. The polka stayed masked for as long as the nil
    /// quorum stayed in the window - i.e. forever. A nil quorum is now
    /// invisible to the precommit decision.
    ///
    /// The certificate for the polka is recorded in `prevote_qc` so the caller
    /// can attach it to the precommit.
    pub fn try_polka_at(&mut self) -> Option<(Round, BlockHash)> {
        for round in self.rounds_to_inspect() {
            let Some(set) = self.prevotes.get(&round) else {
                continue;
            };
            let Some(Some(target)) = set.quorum_target(&self.validators) else {
                continue;
            };
            if let Some(qc) = produce_decision_certificate_with_schedule(
                set,
                Some(target),
                &self.validators,
                self.sortition_parent(),
                self.committee_schedule,
            ) {
                self.prevote_qc.insert(round, qc);
            }
            return Some((round, target));
        }
        None
    }

    /// Record the polka of `round`, if that round's prevote set now holds a
    /// quorum FOR A BLOCK.
    ///
    /// This is the WRITE side of the polka ledger (see
    /// [`Self::observed_polka`]). It is called the moment a prevote is
    /// admitted, so a polka is recorded the instant it becomes true — even
    /// when the round is far behind the local round counter (the live WAN
    /// round-skew shape) or far ahead of it.
    ///
    /// NEWEST WINS: an older polka never supersedes a newer one. A polka is
    /// the network's word for THAT round; the newest polka is the network's
    /// latest word, and the precommit must follow it.
    ///
    /// The certificate is built and stored at the same time, so the precommit
    /// that follows the polka carries the proof of the quorum it certifies.
    fn note_polka(&mut self, round: Round) {
        let Some(set) = self.prevotes.get(&round) else {
            return;
        };
        // A NIL quorum is not a polka: "no block was agreed in that round"
        // says nothing about any block.
        let Some(Some(target)) = set.quorum_target(&self.validators) else {
            return;
        };
        if self.observed_polka.map(|(r, _)| r > round).unwrap_or(false) {
            return; // an older polka never supersedes a newer one
        }
        let qc = produce_decision_certificate_with_schedule(
            set,
            Some(target),
            &self.validators,
            self.sortition_parent(),
            self.committee_schedule,
        );
        if let Some(qc) = qc {
            self.prevote_qc.insert(round, qc);
        }
        self.observed_polka = Some((round, target));
    }

    /// The polka this node has OBSERVED (the ledger), if any.
    pub fn observed_polka(&self) -> Option<(Round, BlockHash)> {
        self.observed_polka
    }

    /// The newest polka this node knows about: the one it OBSERVED (the
    /// ledger) or the newest one inside the scan window — whichever is newer.
    ///
    /// The ledger covers the polkas the window cannot see (a late polka, a
    /// polka of a round this node has already left); the window covers the
    /// polkas the ledger does not know about yet (a node that joined the
    /// height late and never saw the quorum-completing prevote arrive).
    pub fn best_polka(&mut self) -> Option<(Round, BlockHash)> {
        let scanned = self.try_polka_at();
        match (self.observed_polka, scanned) {
            (Some((r1, b1)), Some((r2, b2))) => Some(if r1 >= r2 { (r1, b1) } else { (r2, b2) }),
            (a, None) => a,
            (None, b) => b,
        }
    }

    /// Target-only view of [`Self::try_prevote_quorum_at`] (kept for the many
    /// call sites and tests that do not care which round the polka formed in).
    pub fn try_prevote_quorum(&mut self) -> Option<Option<BlockHash>> {
        self.try_prevote_quorum_at().map(|(_, target)| target)
    }

    /// Try to form a precommit QC (finality). On success, lock and decide.
    ///
    /// Inspects the recent rounds, not just the current one, so a quorum that formed
    /// in a round we have since left still decides. See `rounds_to_inspect`.
    ///
    /// THE POLKA'S ROUND IS A CANDIDATE EVEN OUTSIDE THE WINDOW (liveness fix,
    /// live 2026-10-21: the masterchain parked at height 285027 with a prevote
    /// QC and NO precommit QC). The precommits are cast for the round of the
    /// polka they follow, so the precommit quorum forms in THAT round — and
    /// when the polka arrived late that round can be far outside the window
    /// around the local counter. Without this candidate the height could never
    /// be decided even though every validator had precommitted it.
    pub fn try_precommit_quorum(&mut self) -> Option<BlockHash> {
        let mut candidates = self.rounds_to_inspect();
        if let Some((r, _)) = self.observed_polka {
            if !candidates.contains(&r) {
                candidates.push(r);
            }
        }
        // THE WHOLE CANDIDATE LIST IS TESTED (liveness, WAN skew). The scan
        // used to stop at the NEWEST round carrying a non-nil precommit
        // quorum. That round may be undecidable here for a reason that says
        // nothing about an older round: this node may have received the
        // precommits but not the prevotes of the newer round (a partial
        // delivery), or the newer certificate may contradict our lock. The
        // old code returned `None` on the first such miss and never looked at
        // an OLDER round that is fully proven locally (prevote QC AND
        // precommit QC for the same block, consistent with the lock) — the
        // height parked although it was decidable.
        let mut chosen: Option<(Round, BlockHash)> = None;
        for round in candidates {
            let Some(target) = self
                .precommits
                .get(&round)
                .and_then(|s| s.quorum_target(&self.validators))
            else {
                continue;
            };
            // A nil precommit quorum decides no block; keep looking.
            let Some(block) = target else {
                continue;
            };
            // SAFETY: a block may only be decided on a prevote quorum for the
            // SAME block. Without this, any precommit quorum alone finalises
            // whatever it names, and a peer can hand us precommits for a block
            // nobody prevoted for. The two quorums have to agree on the target,
            // otherwise a pre-vote-certified block A and a precommit-certified
            // block B could both reach quorum and the node would pick whichever
            // it checked first.
            let prevoted = self
                .prevotes
                .get(&round)
                .and_then(|s| s.quorum_target(&self.validators));
            if prevoted.flatten() != Some(block) {
                continue;
            }
            // And a locked validator must not decide a block that contradicts
            // its own lock: that is what makes a reorg past a locked round
            // impossible. A FULLY PROVEN newer round for another block is a
            // deliberate refusal, not a reason to fall back: the network may
            // have certified a conflicting value and this node may only leave
            // its lock through the higher-round polka path (handled by the
            // precommit producer via `try_prevote_quorum_at`). Refuse the
            // whole scan, exactly as before.
            if let Some((locked_block, _)) = self.locked {
                if locked_block != block {
                    return None;
                }
            }
            chosen = Some((round, block));
            break;
        }
        let (round, block) = chosen?;
        let set = self.precommits.get(&round)?;
        let target = set.quorum_target(&self.validators)?;

        if let Some(qc) = produce_decision_certificate_with_schedule(
            set,
            target,
            &self.validators,
            self.sortition_parent(),
            self.committee_schedule,
        ) {
            self.precommit_qc = Some(qc);
        }
        // Lock monotonicity (safety): the lock round only moves forward. A
        // decision for the SAME value at an OLDER round (a late quorum for a
        // round we already locked past) must not regress the lock, or stale
        // evidence could unlock past the newer lock (newest-wins). A
        // conflicting value never reaches here (refused above).
        if self.locked.map(|(_, lr)| round > lr).unwrap_or(true) {
            self.locked = Some((block, round));
        }
        self.decided = Some(block);
        self.step = Step::Commit;
        // A decided height is the end of every nil streak at this height: the
        // next height starts fresh (its own `HeightConsensus` starts at 0
        // anyway; this clears the readout for any same-height inspection).
        self.consecutive_nil_rounds = 0;
        self.nil_breaker_fired_this_streak = false;
        Some(block)
    }

    /// Move to a round a peer is in, for round-phase synchronisation.
    ///
    /// Unlike `advance_to_round` (capped at +1 per call as a round-DoS guard), this
    /// may move further, because it exists to fix a specific deadlock: with an even
    /// validator count the proposer alternates by round PARITY, so two nodes that
    /// walk their rounds independently sit at an odd offset and are permanently in
    /// opposite phases -- each waits for the other and every proposal is rejected as
    /// "wrong proposer". Catching up one round at a time cannot fix that, because the
    /// parity of the offset is preserved.
    ///
    /// Still bounded and still forward-only:
    ///   * never moves backwards, so a node cannot be dragged into re-voting a round
    ///     it already left;
    ///   * the jump is capped, so a peer cannot shove us arbitrarily far ahead.
    ///
    /// The caller is responsible for having a reason to move (a signed vote from a
    /// validator in that round), which is what makes the cap safe.
    pub fn sync_round_to(&mut self, round: Round) {
        // SECURITY (audit F2): a single peer message may move us forward by at
        // most ROUND_LOOKBACK rounds. The old cap was 64, so a Batch of 32
        // (previously unauthenticated) votes bought 2048 rounds; now it is 256,
        // and the caller only reaches this after the vote has verified.
        //
        // RATE LIMIT (audit 2026-10-06): the per-call cap alone does not stop
        // a MESSAGE BURST from ratcheting +8 per message without bound. Past
        // the per-round jump budget the sync is refused; the caller's own
        // view change advances us anyway and refills the budget.
        //
        // LIFETIME LIMIT (PENTEST F-9): the per-round budget above refills on
        // every view change, so on its own it let one Byzantine validator
        // ratchet an honest node +64 per timeout forever, off the end of every
        // scan window. The cumulative per-height budget bounds the whole
        // peer-driven drift; it is never reset by `next_round`.
        if self.sync_jumps_used >= MAX_SYNC_JUMPS_PER_ROUND {
            return;
        }
        let remaining =
            MAX_PEER_ROUND_ADVANCE_PER_HEIGHT.saturating_sub(self.peer_round_advance_used);
        if remaining == 0 {
            return;
        }
        let target = round
            .min(self.round.saturating_add(ROUND_LOOKBACK))
            .min(self.round.saturating_add(remaining));
        if target > self.round {
            self.peer_round_advance_used = self
                .peer_round_advance_used
                .saturating_add(target - self.round);
            self.round = target;
            self.step = Step::Propose;
            self.proposal = None;
            self.proposal_round = None;
            self.sync_jumps_used += 1;
            self.prune_old_rounds();
        }
    }

    /// Drop per-round vote sets that can no longer matter.
    ///
    /// **THE VOTE SETS OF THE CURRENT HEIGHT ARE KEPT** (liveness fix, live
    /// 2026-10-21: the masterchain sat at height 285027 for three days with a
    /// full prevote QC formed and NO precommit QC).
    ///
    /// The old prune dropped everything older than the finalization lookback
    /// window, on the assumption that "rounds inside the lookback are exactly
    /// what finalization can still decide". **That assumption IS the bug**:
    /// the quorum-COMPLETING prevote of a round routinely arrives long after
    /// the round it belongs to (a stalled WAN path, the round skew between
    /// nodes, a peer's own lag), and by then the set for that round has been
    /// emptied — so the quorum can never complete, the polka never forms, the
    /// precommit is never cast, and the height is parked forever. Tendermint
    /// keeps the vote sets of the whole height for exactly this reason.
    ///
    /// The memory is bounded twice over: the HEIGHT is the unit (a new height
    /// starts with empty maps — see `HeightConsensus::new`) and
    /// [`MAX_RETAINED_VOTE_ROUNDS`] caps the rounds kept inside one height.
    /// The quorum SCAN is unaffected: it still walks the window around the
    /// local round (plus the observed polka's round), so the per-tick cost
    /// does not grow with the height.
    ///
    /// The polka's own round is never evicted: it is the round the decision
    /// is made in, and its prevote set is the proof that the decided block
    /// was certified.
    fn prune_old_rounds(&mut self) {
        // The floor is the height's first round: every round of this height
        // can still receive the vote that completes its quorum.
        let floor = 0;
        self.prevotes.retain(|&r, _| r >= floor);
        self.precommits.retain(|&r, _| r >= floor);
        self.prevote_qc.retain(|&r, _| r >= floor);
        // Enforce the cap by evicting the OLDEST rounds — but never the polka's
        // round (its prevote set is the proof of the decision). The old loop
        // `break`-ed as soon as the oldest retained round WAS the polka, which
        // left every newer round in place: once a height had lived through the
        // cap with a low-round polka, the retention cap stopped enforcing at
        // all, and one accepted vote per round grew the maps without bound.
        let polka_round = self.observed_polka.map(|(r, _)| r);
        let mut rounds: Vec<Round> = self
            .prevotes
            .keys()
            .chain(self.precommits.keys())
            .copied()
            .collect();
        rounds.sort_unstable();
        rounds.dedup();
        let mut excess = rounds.len().saturating_sub(MAX_RETAINED_VOTE_ROUNDS);
        for round in rounds {
            if excess == 0 {
                break;
            }
            if Some(round) == polka_round {
                continue;
            }
            self.prevotes.remove(&round);
            self.precommits.remove(&round);
            self.prevote_qc.remove(&round);
            excess -= 1;
        }
    }

    /// View change: advance to the next round, resetting per-round proposal state.
    ///
    /// C2: the round being LEFT is classified first — a round with no block
    /// prevote QC (nil quorum or no quorum) is a NIL round: `nil_rounds_total`
    /// increments and `consecutive_nil_rounds` grows, else the streak resets
    /// (and the breaker's one-shot flag clears). The scheduled proposer of
    /// the left round is also charged with a MISSED proposal when no proposal
    /// from it was accepted that round (observability only).
    pub fn next_round(&mut self) {
        // Classify the round we are leaving BEFORE wiping its proposal state.
        let left = self.round;
        let had_block_qc = self
            .prevotes
            .get(&left)
            .and_then(|s| s.quorum_target(&self.validators))
            .flatten()
            .is_some();
        self.note_round_outcome(!had_block_qc);
        // Proposer-skip accountability (observability only): a scheduled
        // proposer that never got its proposal accepted this round misses.
        // `proposal_round == Some(left)` means WE accepted its proposal; any
        // other state (none, or a stale round) means the slot went empty.
        if let Some(sched) =
            self.validators
                .proposer_for_with_schedule(self.height, left, self.committee_schedule)
        {
            let proposed =
                self.proposal_round == Some(left) && self.proposal.map(|(p, _)| p) == Some(sched);
            self.note_proposer_missed(sched, proposed);
        }
        // SECURITY: saturate rather than `+= 1`, which panicked in debug and
        // wrapped to 0 in release at u32::MAX (audit F2/overflow).
        self.round = self.round.saturating_add(1);
        // A view change is a FAILED round at this height: count it, so the
        // view-change backoff grows with the trouble this height is in (and
        // not with the absolute round number).
        self.timeouts = self.timeouts.saturating_add(1);
        // A new round refills the per-round peer-driven jump budget (see
        // `MAX_SYNC_JUMPS_PER_ROUND`): the runaway it guards is a burst
        // inside ONE round, and a node that has view-changed is starting a
        // fresh round in which following the network is exactly what it
        // should do.
        //
        // PENTEST F-9: the LIFETIME bound (`peer_round_advance_used`, see
        // `MAX_PEER_ROUND_ADVANCE_PER_HEIGHT`) is deliberately NOT reset
        // here. Resetting both budgets on every timeout is exactly the
        // ratchet: one liar buys +64 per view change, forever, and the
        // round counter never comes back.
        self.sync_jumps_used = 0;
        self.step = Step::Propose;
        self.proposal = None;
        self.proposal_round = None;
        self.prune_old_rounds();
    }

    /// Record one round's outcome for the nil-storm meter.
    ///
    /// `was_nil == true`: the round formed no block prevote QC (≥1 nil
    /// prevote, or no QC at all). Counts + meters (`nil_rounds_total`,
    /// alertable). `false` (a block QC formed): the streak breaks and the
    /// breaker's one-shot flag clears so the next storm can fire again.
    /// Pure state transition, no votes cast, no rewind.
    pub fn note_round_outcome(&mut self, was_nil: bool) {
        if was_nil {
            self.nil_rounds_total = self.nil_rounds_total.saturating_add(1);
            self.consecutive_nil_rounds = self.consecutive_nil_rounds.saturating_add(1);
            crate::metrics::global().inc_nil_round();
        } else {
            self.consecutive_nil_rounds = 0;
            self.nil_breaker_fired_this_streak = false;
        }
    }

    /// True when the nil-storm circuit breaker must fire: K consecutive
    /// nil-rounds reached and the one-shot action for this streak not yet
    /// applied. K = [`NIL_CIRCUIT_BREAKER_K`] (≤5 by construction).
    pub fn nil_breaker_due(&self) -> bool {
        self.consecutive_nil_rounds >= NIL_CIRCUIT_BREAKER_K && !self.nil_breaker_fired_this_streak
    }

    /// Newest QC-backed block hash this node knows (the convergence target).
    ///
    /// Preference order: the observed polka (newest quorum of prevotes FOR A
    /// BLOCK), else the newest prevote QC in the scan window. `None` when no
    /// block QC exists anywhere — then there is nothing to re-broadcast and
    /// the breaker only widens the window.
    pub fn highest_qc_backed_hash(&self) -> Option<BlockHash> {
        if let Some((_, h)) = self.observed_polka {
            return Some(h);
        }
        let mut best: Option<(Round, BlockHash)> = None;
        for (r, qc) in &self.prevote_qc {
            if let Some(h) = qc.block_hash {
                if best.map(|(br, _)| *r > br).unwrap_or(true) {
                    best = Some((*r, h));
                }
            }
        }
        best.map(|(_, h)| h)
    }

    /// One-shot nil-storm convergence action. SAFE by construction:
    /// * never double-votes (casts no vote, moves no step — only widens the
    ///   vote-COLLECTION window and reports the hash the CALLER may
    ///   re-broadcast from its already-held bodies);
    /// * never rewinds (touches no round/height/decided/lock — only
    ///   `scan_lookback`, once per streak);
    /// * then resumes normal timing (the flag guarantees exactly one widen
    ///   per streak; the next block QC clears it).
    ///
    /// Returns the QC-backed hash to re-broadcast, if any. The caller must
    /// re-broadcast ONLY a body it already holds (never synthesize one) and
    /// must widen the vote-collection window exactly once (done here).
    pub fn apply_nil_convergence(&mut self) -> Option<BlockHash> {
        if !self.nil_breaker_due() {
            return None;
        }
        self.nil_breaker_fired_this_streak = true;
        // Widen the vote-collection window ONCE per streak so late votes for
        // the network's round become committable. Idempotent: already-wide
        // stays wide; normal timing resumes because nothing else changes.
        if self.scan_lookback < REPHASE_SCAN_WINDOW {
            self.scan_lookback = REPHASE_SCAN_WINDOW;
        }
        crate::metrics::global().inc_nil_breaker_fire();
        self.highest_qc_backed_hash()
    }

    /// Track one scheduled proposer's slot outcome (observability only).
    ///
    /// `proposed == false`: consecutive-miss counter for `proposer` grows
    /// (and the height meter grows). `true`: the proposer is re-admitted on
    /// the fast path — its streak resets to 0 with NO punishment in protocol
    /// (no slashing invented here; the existing downtime-slash path from
    /// block content is untouched). Zero-streak entries are removed so the
    /// map never exceeds the validator-set size.
    pub fn note_proposer_missed(&mut self, proposer: ValidatorId, proposed: bool) {
        if proposed {
            self.missed_proposals.remove(&proposer);
            return;
        }
        let e = self.missed_proposals.entry(proposer).or_insert(0);
        *e = e.saturating_add(1);
        self.missed_proposals_total = self.missed_proposals_total.saturating_add(1);
        crate::metrics::global().inc_proposer_miss();
    }

    /// Consecutive missed proposals counted for `proposer` (0 when none).
    pub fn proposer_missed_streak(&self, proposer: &ValidatorId) -> u32 {
        self.missed_proposals.get(proposer).copied().unwrap_or(0)
    }

    /// Jump to a specific (higher) round, e.g. when a peer is ahead. This keeps
    /// validators round-synchronized so proposals are accepted rather than dropped.
    pub fn advance_to_round(&mut self, round: Round) {
        // SECURITY: a peer message may move us forward by at most one round. See
        // MAX_ROUND_ADVANCE_PER_MESSAGE for why a larger step is a liveness bug and
        // not just a sloppy bound.
        let target = round.min(self.round.saturating_add(MAX_ROUND_ADVANCE_PER_MESSAGE));
        if target > self.round {
            self.round = target;
            self.step = Step::Propose;
            self.proposal = None;
            self.proposal_round = None;
            self.prune_old_rounds();
        }
    }

    /// Record a verified peer round WITHOUT voting (deadlock fix 2026-10-14).
    ///
    /// The caller must have verified the vote (signature + validator membership)
    /// and checked `vote.height == self.height`. The vote itself is NOT admitted
    /// to any `VoteSet` here — a stale far-behind vote can never form a quorum
    /// and an absurd far-ahead vote is outside `MAX_ROUND_AHEAD` — but the
    /// peer's round counter is still true information: it tells us where the
    /// network is. The counter is stored per voter (monotonic per voter, so a
    /// delayed old vote never rewinds it) and a bounded `sync_round_to` chase
    /// is attempted. Returns true when our round moved.
    pub fn observe_peer_round(&mut self, voter: ValidatorId, round: Round) -> bool {
        self.note_peer_round(voter, round);
        if round <= self.round {
            return false;
        }
        // Audit F3: a SINGLE far-future vote never moves us (trickle-drag:
        // one dribbled vote per timeout would ratchet +8/timeout and silence
        // us). Corroboration re-opens the chase: TWO DISTINCT validators at
        // the same far round is the network's real position, not one peer's
        // claim (a lone Byzantine cannot fake corroboration within <1/3).
        // Near chase (<= LOOKBACK) is unchanged (1-round-offset deadlock fix).
        if round > self.round.saturating_add(ROUND_LOOKBACK)
            && self.supporting_peers_count(round) < 2
        {
            return false;
        }
        let before = self.round;
        self.sync_round_to(round);
        self.round != before
    }

    /// Record a verified peer's round WITHOUT moving ours.
    ///
    /// This is the "where is the network" bookkeeping, kept SEPARATE from the
    /// chase ([`Self::observe_peer_round`]) on purpose: a peer round is true
    /// information even when the vote that carried it was NOT votable (stale
    /// far-behind, absurd far-ahead), and it is needed for two things that
    /// used to be blind:
    ///
    /// * the deadlock breaker's corroboration ([`Self::corroborated_peer_round`])
    ///   — it only ever saw REJECTED votes, so the breaker was effectively
    ///   dead code on a healthy network;
    /// * the quorum-scan anchor ([`Self::scan_floor`]) — a node that is ahead
    ///   of the network needs to know which round the network is in, or it
    ///   can never see the polka the network formed.
    ///
    /// The counter is per voter and monotonic, so a delayed old vote never
    /// rewinds it.
    pub fn note_peer_round(&mut self, voter: ValidatorId, round: Round) {
        let entry = self.peer_rounds.entry(voter).or_insert(round);
        if round > *entry {
            *entry = round;
        }
    }

    /// Count how many distinct validators have reported being at or above `round`.
    pub fn supporting_peers_count(&self, round: Round) -> usize {
        self.peer_rounds.values().filter(|&&r| r >= round).count()
    }

    /// Voting power of the validators that have reported being at or above
    /// `round`. This is the quantity the deadlock breaker corroborates with:
    /// under the BFT threat model fewer than one third of the POWER is
    /// Byzantine, so a round is network evidence only when its reporters carry
    /// MORE than one third of the power. A fixed count of two validator ids is
    /// not enough on a set of seven or more: two colluding validators (2/7 of
    /// the power) are a sub-one-third coalition and could otherwise steer the
    /// forward-only breaker with a fabricated round.
    pub fn supporting_peer_power(&self, round: Round) -> u128 {
        self.peer_rounds
            .iter()
            .filter(|(_, &r)| r >= round)
            .map(|(voter, _)| self.validators.power_of(voter) as u128)
            .sum::<u128>()
    }

    /// True when `round` is reported by validators holding MORE than one third
    /// of the network's total power (strictly more, so the BFT floor
    /// `B_w < W/3` guarantees at least one honest reporter).
    fn corroborated_round(&self, round: Round) -> bool {
        let total = self.validators.total_power_exact();
        total > 0 && self.supporting_peer_power(round).saturating_mul(3) > total
    }

    /// The highest peer round that is CORROBORATED by more than one third of
    /// the network's voting power, if any.
    ///
    /// `peer_rounds` records what each peer CLAIMED, and a Byzantine
    /// validator can claim any round — including `u32::MAX`. A round only a
    /// sub-one-third coalition reports is therefore not evidence of where the
    /// network is, and neither the deadlock breaker nor the local re-phase may
    /// act on it.
    ///
    /// With a uniform two-member set the single peer holds half the power, so
    /// it clears the one-third floor on its own (a 2-member set is 50%
    /// Byzantine by construction).
    pub fn corroborated_peer_round(&self) -> Option<Round> {
        let mut rounds: Vec<Round> = self.peer_rounds.values().copied().collect();
        rounds.sort_unstable_by(|a, b| b.cmp(a));
        rounds.dedup();
        rounds.into_iter().find(|r| self.corroborated_round(*r))
    }

    /// Highest verified peer round seen at this height, if any. Drives the
    /// deadlock circuit breaker (`apply_deadlock_jump`).
    pub fn max_peer_round(&self) -> Option<Round> {
        self.peer_rounds.values().copied().max()
    }

    /// Deadlock-breaker timeout in seconds (`STELL_DEADLOCK_TIMEOUT_SECS`,
    /// default 300). Pure and env-driven so tests can pin it without sleeping.
    pub fn deadlock_timeout_secs() -> u64 {
        std::env::var("STELL_DEADLOCK_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(300)
    }

    /// Pure breaker decision: `Some(target)` iff we have been stuck
    /// `no_progress_secs >= timeout_secs` AND a verified peer is ahead of us.
    /// Fail-safe is enforced by the caller + `apply_deadlock_jump` (forward
    /// only); this only computes the target.
    ///
    /// CORROBORATION (audit W6.4b, power-weighted): the round we jump to must
    /// be reported by validators holding MORE THAN ONE THIRD of the network's
    /// voting power. `peer_rounds` records what each peer CLAIMED, and a
    /// Byzantine validator can claim any round at all — including
    /// `u32::MAX`. Without corroboration, a sub-one-third coalition could drag
    /// this node off the network permanently: the round counter only moves
    /// forward, so a node that jumped to a bogus round can never come back.
    ///
    /// A *count* of two is not that rule on a set of seven or more: two
    /// Byzantine validators out of seven are below one third of the power and
    /// must not corroborate anything. The power floor is also why a 2-member
    /// set still works: its single peer holds half the power.
    ///
    /// The JUMP SIZE is bounded by [`MAX_DEADLOCK_JUMP`] — deliberately much
    /// larger than `MAX_ROUND_AHEAD` (1000), because the breaker exists
    /// precisely for the desyncs that are LARGER than the vote-acceptance
    /// window (live: a 1232-round gap). Clamping it to `MAX_ROUND_AHEAD`
    /// silently defeated the breaker: it could never close the very gap it
    /// was built for.
    pub fn deadlock_breaker_target(
        &self,
        no_progress_secs: u64,
        timeout_secs: u64,
    ) -> Option<Round> {
        if no_progress_secs < timeout_secs {
            return None;
        }
        // CORROBORATED round only: a sub-one-third coalition must not steer
        // this node. `corroborated_peer_round` returns the highest round
        // reported by validators holding more than one third of the power.
        let target = self.corroborated_peer_round()?;
        if target <= self.round {
            return None;
        }
        Some(target.min(self.round.saturating_add(MAX_DEADLOCK_JUMP)))
    }

    /// One-shot bounded jump to a breaker target (deadlock fix 2026-10-14).
    ///
    /// Fail-safe: forward-only (`target > self.round` required), height-scoped
    /// (the caller owns progress/rate-limit checks: only on no-progress, at
    /// most once per timeout). Bypasses the `+8`/per-second `sync_round_to`
    /// caps on purpose — that is what makes a 1200-round desync (live
    /// 2026-10-14: A r1550 vs B r318) converge instead of chasing at 32
    /// rounds/s forever behind a moving target. Resets step/proposal state
    /// like every other round move and prunes undecidable history.
    pub fn apply_deadlock_jump(&mut self, target: Round) -> bool {
        if target <= self.round {
            return false;
        }
        self.round = target;
        self.step = Step::Propose;
        self.proposal = None;
        self.proposal_round = None;
        self.prune_old_rounds();
        true
    }

    /// Pure no-progress local-reset decision (deadlock fix 2026-10-14 follow-up:
    /// A r1595 vs B r412 with EMPTY peer rounds, mutually deaf forever).
    ///
    /// Returns true iff we have been stuck `no_progress_secs >= timeout_secs`
    /// AND no verified peer is ahead of us (`max_peer_round` is `None` or
    /// `<= self.round`). This is the complement of `deadlock_breaker_target`:
    /// when a peer IS ahead the jump path owns the breaker (existing behavior
    /// untouched); when nobody is ahead — empty peer set, or only stale
    /// behind/default rounds — the local reset owns it. Pure: no mutation.
    pub fn deadlock_local_reset_due(&self, no_progress_secs: u64, timeout_secs: u64) -> bool {
        if no_progress_secs < timeout_secs {
            return false;
        }
        // The SAME corroboration rule as the breaker: a round reported only by
        // a sub-one-third coalition is not evidence of where the network is.
        // Without this the two paths could BOTH be dead: such a coalition
        // claiming a huge round would keep the breaker from firing (no
        // corroboration) AND keep the local re-phase from firing (a peer is
        // "ahead"), so the node would wedge with no way out (audit W6.4b).
        !matches!(self.corroborated_peer_round(), Some(p) if p > self.round)
    }

    /// True when a non-nil precommit quorum is observable right now: either we
    /// banked the deciding QC (`precommit_qc`), or some retained round's
    /// precommit set holds quorum power for a block. Pure readout, no state
    /// change. This is the reset gate below: a QC means someone may have
    /// finalized (bodies deliver partially — a bodyless node sees votes, not
    /// bodies — while progress stamps only on execution, so "QC observed but
    /// no progress" is exactly the fork window).
    ///
    /// Approximation, stated honestly: vote sets older than `ROUND_LOOKBACK`
    /// are pruned, so a QC observed long ago is invisible; and a QC that
    /// formed elsewhere but was never delivered to us is invisible by
    /// definition. Both leave the old drop in place — local policy cannot see
    /// what the network never sent it.
    pub fn precommit_qc_observed(&self) -> bool {
        if self
            .precommit_qc
            .as_ref()
            .is_some_and(|qc| qc.block_hash.is_some())
        {
            return true;
        }
        self.precommits
            .values()
            .any(|s| s.quorum_target(&self.validators).flatten().is_some())
    }

    /// Bounded local RE-PHASE of the SAME height (deadlock fix 2026-10-14
    /// follow-up).
    ///
    /// Fail-safe: NEVER touches `height`, `validators`, `decided`,
    /// `precommit_qc`, or any vote set contents beyond the standard prune —
    /// only round/step/proposal state, the (conditionally dropped) lock and
    /// the scan window.
    ///
    /// NEVER REWIND (BFT safety). Re-entering a round the node already voted
    /// in at this height is a SELF-EQUIVOCATION: two different statements
    /// for one `(height, round, kind)` are slashable evidence, and a peer
    /// that kept the old vote can prove it. The round counter therefore only
    /// ever moves FORWARD here. (The old "rewind to round 0" behaviour broke
    /// exactly that invariant.)
    ///
    /// WHAT MAKES THE RE-PHASE EFFECTIVE (audit W6.4b): advancing the round
    /// by one is a NO-OP — the round timer advances it anyway, and a node
    /// that is out of phase with the network stays out of phase. The re-phase
    /// therefore also WIDENS the quorum-scan / vote-history window
    /// ([`Self::scan_lookback`], [`REPHASE_SCAN_WINDOW`]). The node then
    /// finds — and COMMITS — the quorum the network formed in the round the
    /// network is actually in, instead of re-voting in it. That is the
    /// Tendermint rule "a node must still commit a round it has left if the
    /// quorum turns up", with a window wide enough to cover a real desync.
    ///
    /// LOCK RULE (audit-consensus hardening 2026-10-14): the lock is dropped
    /// ONLY for a bodyless lock with NO precommit QC observed
    /// (`precommit_qc_observed()` false). In every other case the lock is
    /// kept, and it still clears only through the normal lifecycle — QC
    /// finalize (`try_precommit_quorum`) or a same-height polka for another
    /// value (`try_prevote_quorum_at`) — both untouched by this function.
    /// Dropping a QC-backed bodyless lock is the fork primitive: holders that
    /// received the body finalize A while the reset node drops its A-lock
    /// and finalizes B.
    ///
    /// LOUD LIVENESS CAVEAT: keeping the lock CAN re-stall the exact
    /// A-r1595/B-r412 deaf deadlock this reset was built for, WHENEVER a
    /// precommit QC was observed but no progress followed (bodyless + QC):
    /// the node stays locked, `decide_prevote` then emits nil for every
    /// foreign proposal, and the lock only clears via a higher-round non-nil
    /// polka (`round > locked_round`) or arrival of the locked body. The
    /// gate above is the deliberate trade: the observed deaf deadlock had NO
    /// votes at all (gate passes, lock drops, immediate recovery preserved),
    /// while any hint that value was certified (QC observed) pays stall
    /// instead of risking a fork. Safety over liveness, explicitly.
    ///
    /// IDEMPOTENT: the re-phase widens the window and clears a stale lock —
    /// both happen ONCE per height. Re-firing it on every timeout window
    /// would only advance the round by one (which the round timer does
    /// anyway) and change nothing else: a no-op dressed up as progress.
    /// Returns false when there is nothing left to do, so the caller can
    /// skip stamping/logging.
    pub fn apply_deadlock_local_reset(&mut self, locked_body_present: bool) -> bool {
        // The ONLY case that drops: bodyless AND no QC backing the lock.
        let drop_lock = !locked_body_present && !self.precommit_qc_observed();
        let needs_work = !self.rephase_applied
            || self.proposal.is_some()
            || self.proposal_round.is_some()
            || self.locked.is_some() && drop_lock;
        if !needs_work {
            return false;
        }
        if drop_lock {
            self.locked = None;
        }
        // BFT Safety: NEVER rewind the round at the same height — re-voting a
        // round is a self-equivocation. Move forward monotonically instead.
        self.round = self.round.saturating_add(1);
        self.step = Step::Propose;
        self.proposal = None;
        self.proposal_round = None;
        // RE-PHASE: widen the scan / retention window so the quorum the
        // network formed in ITS round becomes visible (and committable) to a
        // node whose round counter wandered off.
        self.scan_lookback = REPHASE_SCAN_WINDOW;
        self.rephase_applied = true;
        self.prune_old_rounds();
        // NOTE (C6 clippy): this used to be
        // `debug_assert!(self.decided.is_none() || true, ...)` — the
        // `|| true` made the assertion vacuous (deny-by-default
        // `overly_complex_bool_expr`). The property that matters is
        // structural: this function never assigns `self.decided`, so a
        // decided value survives the reset by construction; asserting
        // `is_none()` here would forbid the legitimate
        // decided-then-rephase path, so the check is a comment, not code.
        true
    }

    /// Aggregate all equivocation evidence seen so far (for slashing).
    pub fn equivocations(&self) -> Vec<(ValidatorId, Vote, Vote)> {
        let mut out = Vec::new();
        for s in self.prevotes.values() {
            out.extend(s.equivocations().iter().cloned());
        }
        for s in self.precommits.values() {
            out.extend(s.equivocations().iter().cloned());
        }
        out
    }
}

// ============================================================================
// Multi-height driver (pipelined)
// ============================================================================

/// Drives consensus across heights. A single engine per height is created on
/// demand; once decided, the driver records finality and can advance.
#[derive(Clone, Debug, Default)]
pub struct ConsensusDriver {
    pub validators: ValidatorSet,
    pub current: Option<HeightConsensus>,
    pub finalized: BTreeMap<Height, BlockHash>,
    pub start_height: Height,
}

impl ConsensusDriver {
    pub fn new(validators: ValidatorSet, start_height: Height) -> Self {
        let current = HeightConsensus::new(start_height, validators.clone());
        Self {
            validators,
            current: Some(current),
            finalized: BTreeMap::new(),
            start_height,
        }
    }

    /// Finalize the current height and advance to the next.
    ///
    /// The next height's sortition parent is the block hash this height just
    /// decided (the `prev_hash` its children commit), so it is installed
    /// explicitly. A bare `HeightConsensus::new` would leave
    /// `parent_hash_known == false` for every height above 1: no µQC could be
    /// compiled (fail-closed) and a producer would derive no committee its
    /// peers agree with.
    pub fn advance(&mut self) {
        if let Some(cur) = &self.current {
            if let Some(block) = cur.decided {
                self.finalized.insert(cur.height, block);
                let next = cur.height + 1;
                let mut fresh = HeightConsensus::new(next, self.validators.clone());
                fresh.set_parent_hash(block);
                self.current = Some(fresh);
            }
        }
    }

    pub fn is_final(&self, height: Height, block: BlockHash) -> bool {
        self.finalized.get(&height) == Some(&block)
    }
}
