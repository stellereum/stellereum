//! Protocol versioning, fork identity and capability negotiation.
//!
//! # What this module owns
//!
//! * [`PROTOCOL_VERSION`] — the semver-ish wire/consensus protocol version.
//! * [`FORK_ID`] — a constant-derived identifier of the CONSENSUS RULESET.
//! * [`Capabilities`] — the peer capability bitflags (`COMPACT_GOSSIP`,
//!   `MESH_DIRECT`, ...).
//! * [`Hello`] — the post-handshake control message carrying all three.
//! * [`negotiate`] — the whole decision table (pure, no I/O).
//!
//! The transport mechanics live in [`infnode::proto`] (the control frame
//! kind, the wire codec and the per-peer state record); this module is the
//! CHAIN identity installed into that layer and the consensus-side helpers
//! that consult it.
//!
//! # What `FORK_ID` is derived from (and what it is NOT)
//!
//! `FORK_ID` is a compile-time FNV-1a-32 fold over the consensus ruleset
//! inputs listed in [`derive_fork_id`]: the chain id, the signature/domain
//! strings, and the consensus bound/round constants. It changes when a
//! consensus rule changes and is stable across rebuilds. It is deliberately
//! NOT a hash of the binary: two builds of the same ruleset must agree.
//!
//! [`CONSENSUS_RULESET_VERSION`] is the escape hatch for a rule change that is
//! not captured by one of the hashed constants (for example a change to the
//! quorum formula's logic). Bump it in the same commit as such a change.
//!
//! # Compatibility rules (enforced by [`negotiate`])
//!
//! * different `fork_id` -> consensus participation REFUSED, loudly (DHT/blob
//!   services remain available);
//! * equal protocol version -> capability intersection;
//! * one minor apart -> capability intersection, one advisory log line;
//! * two or more minors apart -> consensus participation REFUSED, loudly;
//! * different major -> consensus participation REFUSED, loudly.

use crate::sharding::Block;

pub use infnode::proto::{
    classify_peer, decode_control, fnv1a32, kind as control_kind, negotiate, Agreement,
    Capabilities, ControlMessage, Hello, NegotiationRefusal, PeerProtocolState, ProtocolIdentity,
    ProtocolVersion,
};

/// Semver-ish MAJOR of the consensus/control protocol.
///
/// Bump on an incompatible change that cannot be expressed as a compatible
/// additive minor step. Peers with a different major are refused for
/// consensus.
pub const PROTOCOL_MAJOR: u16 = 1;

/// Semver-ish MINOR of the consensus/control protocol.
///
/// Bump for an additive, backward-compatible wire/control change. A peer one
/// minor behind (or ahead) is accepted with the capability intersection; a
/// peer two or more minors away is refused for consensus.
pub const PROTOCOL_MINOR: u16 = 0;

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(PROTOCOL_MAJOR, PROTOCOL_MINOR);

/// Version of the consensus RULE LOGIC that is not already captured by a
/// hashed numeric constant (quorum formula semantics, vote validation order,
/// lock/finality predicates, ...).
///
/// Bump this in the SAME commit as any such change; the fork id then moves
/// and mixed fleets fail closed at handshake instead of silently diverging.
///
/// RULESET v2 (2026-11-19): the height-based consensus windows were rescaled
/// for the ~240 ms tempo (deliberate new genesis). See `docs/RULESET_V2.md`.
///
/// RULESET v3 (2026-11-19): the vote preimage gained the shard id
/// ([`crate::consensus::VOTE_SIGN_DOMAIN`] = `STELLEREUM_BFT_VOTE_V3`), so the
/// domain set and the vote domain moved the fork id. The proposal-slashing
/// activation sentinel is folded as its own rule. See `docs/RULESET_V3.md`.
///
/// RULESET v4 (2026-11-19): the block gained a SIGNED `round` (mixed into the
/// block hash whenever non-zero), proposal-equivocation slashing is ACTIVE
/// (`PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT = 0`), and the block timestamp
/// gained a deterministic parent-relative bound
/// ([`MAX_BLOCK_TIMESTAMP_DRIFT_MS`]). This is a hard fork / new genesis. See
/// `docs/RULESET_V4.md`.
///
/// RULESET v5 (2026-11-20): the 1B supply cap became CHAIN-WIDE. The two new
/// rules are [`crate::tokenomics::CHAIN_SUPPLY_PARTITION_VERSION`] and
/// [`crate::tokenomics::TOTAL_SUPPLY_CAP`]; the shard header commitment gained
/// `minted_total_nano`, so the block-hash domain set moved
/// ([`DOMAIN_SET_VERSION`] = 3). Hard fork / new genesis; fork id
/// `0x9d59096b`. See `docs/RULESET_V5.md` and `docs/SUPPLY_CAP.md`.
///
/// RULESET v6 (2026-11-20): LOCK COMPARISONS ARE BY ROUND-FREE VALUE IDENTITY.
/// A locked/demanded body is RE-STAMPED at the proposer's current round and
/// re-signed on rescue, so the prevote names the current round instead of an
/// older signed round that the fsynced vote watermark may already refuse.
/// `HeightConsensus` compares locks with `Block::value_id` (the block hash
/// with `round := 0`) via `same_value`, while votes/QCs/signatures keep the
/// real signed hash. Fork id `0x0f584a46`. See `docs/RULESET_V6.md`.
///
/// RULESET v7 (2026-11-22): UNIFIED ACTIVATION OF R1..R4 HARDENING & ECONOMICS.
/// Activates from height `0` all 8 Ruleset v7 gates:
///   - R1 (`EXEC_HARDENING_V1`, `WASM_XSHARD_PMM_HARDENING`)
///   - R2 (`HEADER_COMMIT` two-level `BlockHeader` v4, `EVM_BINDINGS_STATE`)
///   - R3 (`PQ_LIFECYCLE` 3-key validator separation + PoP + 720k evidence retention)
///   - R4 (`BRIDGE_V2` release receipt authorization & V2 headers,
///     `FEE_MARKET_V2` priority debit & burn/proposer/staking split,
///     `SUB_NANO_STRICT` exact EVM/mint/reward/emission carry).
///
/// Folds the 9 new rule constants and 9 new domain-separation strings into
/// [`FORK_ID`], bumps [`DOMAIN_SET_VERSION`] to `4`, and requires a new v7
/// genesis. See `docs/RULESET_V7.md`.
pub const CONSENSUS_RULESET_VERSION: u32 = 7;

/// Version of the set of domain-separation strings folded into [`FORK_ID`].
/// Bump when a domain string is added/renamed without changing a hashed
/// constant's value.
pub const DOMAIN_SET_VERSION: u32 = 4;

/// Deterministic ceiling for a block timestamp ahead of its parent, in
/// MILLISECONDS (ruleset v4, S8).
///
/// Block timestamps are `u64` SECONDS (the same unit as
/// [`crate::zkml::now_secs`]); this rule is stated in milliseconds because the
/// ~240 ms tempo is sub-second and an operator reading the rule needs the
/// resolution to reason about it: one hour is ~15,000 tempo slots, which is the
/// envelope this repo's own suites use for operational gaps and catch-up
/// (single-step jumps of ~1000s), while still refusing a validator that tries
/// to poison every timestamp-driven rule (session expiry, unbonding maturity,
/// order stamps) for days or years.
///
/// The verdict is a PURE function of `(parent.timestamp, block.timestamp)`:
/// no wall-clock read, no node-local state (see [`timestamp_within_bounds`]
/// and `runtime::consensus_step::check_block_timestamp`). Both validators and
/// the honest proposer use this SAME constant, so a fast local clock can
/// never build a body its peers must refuse.
pub const MAX_BLOCK_TIMESTAMP_DRIFT_MS: u64 = 60 * 60 * 1_000;

/// True when `block_ts` is a deterministic extension of `parent_ts`:
/// monotone and at most [`MAX_BLOCK_TIMESTAMP_DRIFT_MS`] ahead.
///
/// Pure and constant-only, so every validator derives the same verdict from the
/// same two headers (S8). Height 0/genesis is handled by the caller: genesis
/// carries no parent and keeps its fixed timestamp.
pub const fn timestamp_within_bounds(parent_ts: u64, block_ts: u64) -> bool {
    block_ts >= parent_ts
        && block_ts <= parent_ts.saturating_add(MAX_BLOCK_TIMESTAMP_DRIFT_MS / 1_000)
}

/// The consensus rule constants folded into [`FORK_ID`] after the domain
/// strings. Keeping the list in one place lets the fork-id test derive the
/// exact same value instead of duplicating a fragile literal list.
///
/// The first six entries are the v1 bound/round constants; the rest are the
/// height-based consensus windows (re)scaled by ruleset v2 plus the VDF step
/// count, so a future edit to any of them is provably visible in the fork id.
/// The 20th entry (appended by ruleset v3, keeping the first 19 in the SAME
/// order) is the proposal-equivocation activation height — now `0` (ACTIVE),
/// so it changes the fork id exactly like every other rule. The 21st
/// (ruleset v4) is the deterministic block-timestamp drift bound. The 22nd and
/// 23rd (ruleset v5) are the chain-wide supply partition version and the cap
/// itself, so a change to either is visible in the fork id.
pub const FORK_ID_RULES: &[u64] = &[
    crate::consensus::MAX_COMMIT_CERT_SIGNERS as u64,
    crate::consensus::MAX_ROUND_AHEAD as u64,
    crate::consensus::MAX_ROUND_ADVANCE_PER_MESSAGE as u64,
    crate::consensus::MAX_SYNC_JUMPS_PER_ROUND as u64,
    crate::consensus::FROZEN_ROUND_TIMEOUT_BASE_MS,
    crate::consensus::MICRO_COMMITTEE_MAX_SIZE as u64,
    crate::staking::DOWNTIME_MISS_THRESHOLD as u64,
    crate::staking::DOWNTIME_PENALTY_COOLDOWN,
    crate::staking::JAIL_RELEASE_DELAY_HEIGHTS,
    crate::staking::COMMISSION_EFFECT_DELAY_HEIGHTS,
    crate::staking::COMMISSION_CHANGE_COOLDOWN_HEIGHTS,
    crate::cn_vrf::EPOCH_LEN,
    crate::cn_vrf::V3_SEGMENT_LEN,
    crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS,
    crate::pq_registry::PQ_ROTATION_DELAY_HEIGHTS,
    crate::mev_kem_registry::MEV_KEM_ROTATION_DELAY_HEIGHTS,
    crate::mev_epoch::EPOCH_BLOCKS,
    crate::mmr::MMR_EPOCH_BLOCKS,
    crate::minroot_vdf::DEFAULT_VDF_STEPS_PER_EPOCH,
    crate::consensus::PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT,
    MAX_BLOCK_TIMESTAMP_DRIFT_MS,
    crate::tokenomics::CHAIN_SUPPLY_PARTITION_VERSION,
    crate::tokenomics::TOTAL_SUPPLY_CAP,
    // Ruleset v7 (R1..R4 unified activation gates + 720k PQ evidence retention):
    crate::chain_spec::EXEC_HARDENING_V1_ACTIVATION_HEIGHT,
    crate::chain_spec::WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT,
    crate::sharding::HEADER_COMMIT_ACTIVATION_HEIGHT,
    crate::state_engine::EVM_BINDINGS_STATE_ACTIVATION_HEIGHT,
    crate::pq_registry::PQ_LIFECYCLE_ACTIVATION_HEIGHT,
    crate::pq_registry::PQ_EVIDENCE_RETENTION_HEIGHTS,
    crate::bridge::BRIDGE_V2_ACTIVATION_HEIGHT,
    crate::tokenomics::FEE_MARKET_V2_ACTIVATION_HEIGHT,
    crate::tokenomics::SUB_NANO_STRICT_ACTIVATION_HEIGHT,
];

const fn fold_u64(h: u32, v: u64) -> u32 {
    fnv1a32(h, &v.to_le_bytes())
}

/// Pure derivation of a fork id from a chain id, a ruleset version and the
/// consensus bound constants. Kept `pub` and taking explicit inputs so a test
/// can prove that changing an input changes the id (and so an operator can
/// compute a candidate id before shipping a rules change).
///
/// Inputs (all constant at compile time in [`FORK_ID`]):
///
/// * `chain_id` — [`crate::zkml::DEFAULT_CHAIN_ID`] (chain identity);
/// * `ruleset_version` — [`CONSENSUS_RULESET_VERSION`];
/// * `rules` — the consensus rule constants in [`FORK_ID_RULES`] (the v1
///   bound/round constants, the height-based windows, the VDF step count and
///   the proposal-slashing activation sentinel).
///
/// The signature/domain strings folded in below are the consensus wire
/// domains (`SORTITION_DRAW_DOMAIN`, `EQUIVOCATION_OFFENSE_DOMAIN`,
/// `PROPOSAL_EQUIVOCATION_OFFENSE_DOMAIN`, `VOTE_SIGN_DOMAIN`,
/// `VOTE_FALCON_MAGIC`, `QC_UQC_MAGIC`, `QC_PQ_MAGIC`). A change to any of
/// them changes the fork id, exactly like a changed numeric rule.
pub const fn derive_fork_id(chain_id: u64, ruleset_version: u32, rules: &[u64]) -> u32 {
    let mut h = fnv1a32(0x811c_9dc5, b"STELL_FORK_ID_V1");
    h = fnv1a32(h, &DOMAIN_SET_VERSION.to_le_bytes());
    h = fold_u64(h, chain_id);
    h = fnv1a32(h, &ruleset_version.to_le_bytes());
    // Consensus wire/signature domains (domain separation is part of the
    // ruleset: changing one redefines what a valid vote/QC is).
    h = fnv1a32(h, crate::consensus::SORTITION_DRAW_DOMAIN.as_bytes());
    h = fnv1a32(h, crate::consensus::EQUIVOCATION_OFFENSE_DOMAIN);
    h = fnv1a32(h, crate::consensus::PROPOSAL_EQUIVOCATION_OFFENSE_DOMAIN);
    h = fnv1a32(h, crate::consensus::VOTE_SIGN_DOMAIN);
    h = fnv1a32(h, crate::consensus::VOTE_FALCON_MAGIC);
    h = fnv1a32(h, crate::consensus::QC_UQC_MAGIC);
    h = fnv1a32(h, crate::consensus::QC_PQ_MAGIC);
    // Ruleset v7 domains: v4 block header/body commitment, PQ validator PoP
    // and ID derivation, and Bridge V2 payout/header/relayer domains.
    h = fnv1a32(h, crate::sharding::BODY_COMMITMENT_V4_DOMAIN);
    h = fnv1a32(h, crate::sharding::HEADER_COMMIT_V4_DOMAIN);
    h = fnv1a32(h, crate::pq_registry::PQ_KEY_POP_DST);
    h = fnv1a32(h, crate::pq_registry::PQ_VAL_ID_DST);
    h = fnv1a32(h, crate::bridge::BRIDGE_RELEASE_RECEIPT_DOMAIN_V2);
    h = fnv1a32(
        h,
        crate::bridge::bridge_adapters::BRIDGE_HEADER_SIGN_DOMAIN_V2,
    );
    h = fnv1a32(h, b"TON_MULTISIG_RELEASE_V2");
    h = fnv1a32(h, b"EVM_TELEPORT_RELEASE_V2");
    h = fnv1a32(h, b"STELLEREUM_MULTISIG_RELAYER_MODEL_RELEASE_V2");
    let mut i = 0;
    while i < rules.len() {
        h = fold_u64(h, rules[i]);
        i += 1;
    }
    h
}

/// The consensus ruleset identifier this build implements.
///
/// Derivation is documented on [`derive_fork_id`]; the inputs are exactly the
/// constants below. Changing a consensus rule (one of these constants or the
/// ruleset version) changes the value; rebuilding the same source does not.
pub const FORK_ID: u32 = derive_fork_id(
    crate::zkml::DEFAULT_CHAIN_ID,
    CONSENSUS_RULESET_VERSION,
    FORK_ID_RULES,
);

/// Capabilities advertised by this build.
pub const CAPABILITIES: Capabilities = Capabilities::ALL;

/// The complete local identity (version + fork id + capabilities).
pub const CHAIN_IDENTITY: ProtocolIdentity = ProtocolIdentity {
    protocol_version: PROTOCOL_VERSION,
    fork_id: FORK_ID,
    capabilities: CAPABILITIES,
};

/// Install this chain's identity into the transport layer.
///
/// MUST be called once at process startup, before any node handshake. It is
/// idempotent for the exact same identity and refuses to replace a different
/// one (a process must never silently run with a stale fork id).
pub fn install_chain_identity() -> Result<(), String> {
    infnode::proto::install_local_identity(CHAIN_IDENTITY)
}

/// One-line startup banner carrying the identity operators need.
pub fn startup_line() -> String {
    format!(
        "[protocol] version {} fork_id 0x{:08x} capabilities 0x{:016x} ({:?}) ruleset_version {}",
        PROTOCOL_VERSION,
        FORK_ID,
        CAPABILITIES.bits(),
        capability_names(CAPABILITIES),
        CONSENSUS_RULESET_VERSION,
    )
}

/// Machine-readable view for one RPC read (the infnode `core.status` read
/// already embeds this shape; a chain RPC can call it directly).
pub fn version_info() -> serde_json::Value {
    serde_json::json!({
        "protocol_version": PROTOCOL_VERSION.to_string(),
        "protocol_version_raw": PROTOCOL_VERSION.0,
        "protocol_major": PROTOCOL_MAJOR,
        "protocol_minor": PROTOCOL_MINOR,
        "fork_id": FORK_ID,
        "fork_id_hex": format!("0x{FORK_ID:08x}"),
        "capabilities": CAPABILITIES.bits(),
        "capabilities_names": capability_names(CAPABILITIES),
        "consensus_ruleset_version": CONSENSUS_RULESET_VERSION,
        "domain_set_version": DOMAIN_SET_VERSION,
    })
}

/// Capability names in a stable order (unknown bits are not named).
pub fn capability_names(caps: Capabilities) -> Vec<&'static str> {
    let mut out = Vec::new();
    if caps.contains(Capabilities::COMPACT_GOSSIP) {
        out.push("COMPACT_GOSSIP");
    }
    if caps.contains(Capabilities::MESH_DIRECT) {
        out.push("MESH_DIRECT");
    }
    out
}

/// Capabilities assumed for a peer that has NOT negotiated yet.
///
/// Legacy v2 peers never send `Hello`; assuming the pre-negotiation capability
/// set keeps their wire behaviour byte-identical. A peer that DOES negotiate
/// and advertises a smaller set is honoured exactly (see
/// [`peer_receives_compact`]).
pub const fn unnegotiated_capabilities() -> Capabilities {
    Capabilities::ALL
}

/// True when a compact proposal may be sent to a peer with `caps`.
///
/// This is the single gate the sender consults; a peer that does not advertise
/// `COMPACT_GOSSIP` must receive the full [`ConsensusMsg::Proposal`] instead.
pub const fn peer_receives_compact(caps: Capabilities) -> bool {
    caps.contains(Capabilities::COMPACT_GOSSIP)
}

/// True when the direct validator mesh may replace the overlay broadcast for
/// a peer-set whose intersection is `caps`. Advisory: the overlay fallback is
/// always kept, so a peer without `MESH_DIRECT` still receives everything.
pub const fn mesh_may_use_direct(caps: Capabilities) -> bool {
    caps.contains(Capabilities::MESH_DIRECT)
}

/// Classify one peer Hello against this chain's identity.
pub fn classify(hello: Hello) -> PeerProtocolState {
    classify_peer(CHAIN_IDENTITY, hello)
}

/// Emit the proposal representation a peer can decode: the compact form when
/// the peer advertises `COMPACT_GOSSIP` (and the block compresses), otherwise
/// the full `Proposal` (the dual-emit contract).
pub fn proposal_for_peer(
    block: &Block,
    round: u32,
    caps: Capabilities,
) -> crate::consensus_net::ConsensusMsg {
    if peer_receives_compact(caps) {
        crate::consensus_net::compact_proposal_from_block(block, round).unwrap_or_else(|| {
            crate::consensus_net::ConsensusMsg::Proposal {
                height: block.height,
                round,
                block: block.clone(),
            }
        })
    } else {
        crate::consensus_net::ConsensusMsg::Proposal {
            height: block.height,
            round,
            block: block.clone(),
        }
    }
}
