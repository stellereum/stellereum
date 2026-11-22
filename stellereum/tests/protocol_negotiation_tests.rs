//! Protocol versioning, fork id and capability negotiation.
//!
//! Pinned guarantees:
//! * a different `fork_id` is refused for CONSENSUS with a specific error
//!   (DHT/blobs stay allowed);
//! * an N-1 protocol version connects with the capability INTERSECTION;
//! * two versions behind (and two ahead) are refused;
//! * a peer without `COMPACT_GOSSIP` receives the full `Proposal`
//!   (dual-emit), while a capable peer receives the compact announcement and
//!   both decode to the SAME block;
//! * unknown control messages are ignored and the stream stays usable;
//! * `FORK_ID` is constant-derived: stable for equal inputs, changed by any
//!   ruleset input change.

use stellereum::consensus_net::compact_prop::Resolution;
use stellereum::consensus_net::{
    compact_proposal_from_block, open_compact_proposal, short_id_index_for, ConsensusMsg,
};
use stellereum::protocol::{
    capability_names, classify, classify_peer, control_kind, decode_control, derive_fork_id,
    negotiate, peer_receives_compact, proposal_for_peer, version_info, Capabilities,
    ControlMessage, Hello, NegotiationRefusal, ProtocolIdentity, ProtocolVersion, CHAIN_IDENTITY,
    CONSENSUS_RULESET_VERSION, CONSENSUS_RULESET_VERSION as RULESET_VERSION, FORK_ID,
    FORK_ID_RULES, PROTOCOL_MINOR, PROTOCOL_VERSION,
};
use stellereum::sharding::{Block, Transaction};

fn tx(seed: u64) -> Transaction {
    Transaction {
        from: [seed as u8; 32],
        to: [0xAAu8; 32],
        amount: 1_000 + seed,
        gas_limit: 21_000,
        nonce: seed,
        source_shard: 0,
        target_shard: 0,
        signature: vec![0u8; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
}

fn block_with(n: u64, height: u64) -> Block {
    Block::new_for_test(
        0,
        height,
        [0x11u8; 32],
        [0x22u8; 32],
        (0..n).map(tx).collect(),
    )
    .with_proposer([0x33u8; 32])
    .with_timestamp(1_700_000_000 + height)
}

/// A local identity at `version` with the REAL chain fork id.
fn identity_at(version: ProtocolVersion) -> ProtocolIdentity {
    ProtocolIdentity {
        protocol_version: version,
        fork_id: FORK_ID,
        capabilities: Capabilities::ALL,
    }
}

// ---------------------------------------------------------------------------
// 1. Fork mismatch: refused for consensus, specific error, DHT still allowed.
// ---------------------------------------------------------------------------

#[test]
fn fork_mismatch_is_refused_for_consensus_with_specific_error() {
    let peer = Hello::new(PROTOCOL_VERSION, FORK_ID ^ 0x8000_0000, Capabilities::ALL);
    let err = negotiate(CHAIN_IDENTITY, peer).expect_err("fork mismatch must be refused");
    match err {
        NegotiationRefusal::ForkMismatch { local, peer: p } => {
            assert_eq!(local, FORK_ID);
            assert_eq!(p, FORK_ID ^ 0x8000_0000);
        }
        other => panic!("expected ForkMismatch, got {other:?}"),
    }
    let text = err.to_string();
    assert!(
        text.contains("CONSENSUS REFUSED") && text.contains("fork_id"),
        "the refusal must be loud and name the fork id: {text}"
    );

    let state = classify(peer);
    assert!(!state.consensus_eligible());
    assert_eq!(state.capabilities(), Capabilities::NONE);
    assert!(state.may_serve_non_consensus());
}

// ---------------------------------------------------------------------------
// 2. N-1 connects with the intersection of capabilities.
// ---------------------------------------------------------------------------

#[test]
fn one_minor_behind_connects_with_capability_intersection() {
    let local = identity_at(ProtocolVersion::new(1, 2));
    let peer = Hello::new(
        ProtocolVersion::new(1, 1),
        FORK_ID,
        Capabilities::COMPACT_GOSSIP,
    );
    let agreement = negotiate(local, peer).expect("N-1 must connect");
    assert!(agreement.advisory, "N-1 must be logged once as advisory");
    assert_eq!(
        agreement.capabilities,
        Capabilities::COMPACT_GOSSIP,
        "only the intersection may be assumed active"
    );
    let state = classify_peer(local, peer);
    assert!(state.consensus_eligible());
    assert_eq!(state.capabilities(), Capabilities::COMPACT_GOSSIP);
}

#[test]
fn n_plus_one_is_accepted_with_intersection() {
    let local = identity_at(ProtocolVersion::new(1, PROTOCOL_MINOR));
    let peer = Hello::new(
        ProtocolVersion::new(1, PROTOCOL_MINOR + 1),
        FORK_ID,
        Capabilities::MESH_DIRECT,
    );
    let agreement = negotiate(local, peer).expect("N+1 must connect");
    assert!(agreement.advisory);
    assert_eq!(agreement.capabilities, Capabilities::MESH_DIRECT);
}

// ---------------------------------------------------------------------------
// 3. Two versions behind / ahead is refused.
// ---------------------------------------------------------------------------

#[test]
fn two_minors_behind_is_refused() {
    let local = identity_at(ProtocolVersion::new(1, 2));
    let old = Hello::new(ProtocolVersion::new(1, 0), FORK_ID, Capabilities::ALL);
    let err = negotiate(local, old).expect_err("N-2 must be refused");
    assert!(matches!(err, NegotiationRefusal::VersionTooOld { .. }));
    assert!(err.to_string().contains("CONSENSUS REFUSED"));
    assert!(!classify_peer(local, old).consensus_eligible());
}

#[test]
fn two_minors_ahead_is_refused() {
    let local = identity_at(ProtocolVersion::new(1, 0));
    let ahead = Hello::new(ProtocolVersion::new(1, 2), FORK_ID, Capabilities::ALL);
    let err = negotiate(local, ahead).expect_err("N+2 must be refused");
    assert!(matches!(err, NegotiationRefusal::VersionTooNew { .. }));
}

// ---------------------------------------------------------------------------
// 4. Dual-emit: a non-capable peer gets a FULL Proposal; a capable peer gets
//    the compact frame, and both decode to the identical block.
// ---------------------------------------------------------------------------

#[test]
fn peer_without_compact_gossip_receives_a_full_proposal() {
    let block = block_with(40, 9);
    assert!(!peer_receives_compact(Capabilities::NONE));

    // Non-capable peer: FULL proposal on the wire.
    let full = proposal_for_peer(&block, 3, Capabilities::NONE);
    let full_wire = full.encode().expect("full proposal encodes");
    match ConsensusMsg::decode(&full_wire).expect("full proposal decodes") {
        ConsensusMsg::Proposal {
            height,
            round,
            block: decoded,
        } => {
            assert_eq!(height, block.height);
            assert_eq!(round, 3);
            assert_eq!(
                decoded.compute_hash(),
                block.compute_hash(),
                "the dual-emit full proposal must be the SAME block"
            );
            assert_eq!(decoded.transactions.len(), 40);
        }
        other => panic!("non-capable peer must receive Proposal, got {other:?}"),
    }

    // Capable peer: COMPACT announcement, resolved back to the same block.
    let compact = proposal_for_peer(&block, 3, Capabilities::ALL);
    let compact_wire = compact.encode().expect("compact proposal encodes");
    let proposal = match ConsensusMsg::decode(&compact_wire).expect("compact decodes") {
        ConsensusMsg::CompactProposal { proposal } => proposal,
        other => panic!("capable peer must receive CompactProposal, got {other:?}"),
    };
    let mut resolver = open_compact_proposal(proposal).expect("resolver opens");
    let index = short_id_index_for(
        &resolver.proposal().header,
        block.transactions.iter().cloned(),
    );
    match resolver.resolve_against(&index).expect("resolve") {
        Resolution::Complete(rebuilt) => assert_eq!(
            rebuilt.compute_hash(),
            block.compute_hash(),
            "compact resolution must yield the same block"
        ),
        other => panic!("expected a complete body, got {other:?}"),
    }

    // The production compact emitter really is the compact branch.
    assert!(matches!(
        compact_proposal_from_block(&block, 3),
        Some(ConsensusMsg::CompactProposal { .. })
    ));

    // The BROADCAST layer's dual-emit: the production emitter caches the full
    // body, so a compact chunk can be re-encoded as a full Proposal for the
    // peers that cannot decode it.
    let emitted = stellereum::consensus_net::proposal_gossip_msg(&block, 3);
    assert!(matches!(emitted, ConsensusMsg::CompactProposal { .. }));
    let full_form = stellereum::consensus_net::full_proposal_for_compact(&emitted)
        .expect("emitter caches the body for dual-emit");
    match full_form {
        ConsensusMsg::Proposal {
            block: b, round, ..
        } => {
            assert_eq!(round, 3);
            assert_eq!(b.compute_hash(), block.compute_hash());
            assert_eq!(b.transactions.len(), 40);
        }
        other => panic!("dual-emit must produce a full Proposal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 5. Unknown control messages are ignored; the stream stays usable.
// ---------------------------------------------------------------------------

#[test]
fn unknown_control_message_is_ignored_and_stream_stays_usable() {
    assert_eq!(decode_control(0x7e, b"a-future-control-message"), None);
    assert_eq!(decode_control(control_kind::HELLO, b"truncated"), None);

    let hello = CHAIN_IDENTITY.hello();
    assert_eq!(
        decode_control(control_kind::HELLO, &hello.encode()),
        Some(ControlMessage::Hello(hello)),
        "a known control frame after an ignored one still decodes"
    );
    assert_eq!(
        decode_control(control_kind::HELLO, &[]),
        None,
        "empty payload is ignored, never a panic"
    );
}

// ---------------------------------------------------------------------------
// 6. Fork id / version visibility and constant derivation.
// ---------------------------------------------------------------------------

#[test]
fn fork_id_is_stable_for_equal_inputs_and_changes_with_the_ruleset() {
    let rules = FORK_ID_RULES;
    let base = derive_fork_id(
        stellereum::zkml::DEFAULT_CHAIN_ID,
        CONSENSUS_RULESET_VERSION,
        rules,
    );
    assert_eq!(base, FORK_ID, "FORK_ID must be the documented fold");
    assert_eq!(
        base,
        derive_fork_id(
            stellereum::zkml::DEFAULT_CHAIN_ID,
            CONSENSUS_RULESET_VERSION,
            rules
        ),
        "equal inputs must produce an equal fork id (no binary hash)"
    );
    assert_ne!(
        base,
        derive_fork_id(
            stellereum::zkml::DEFAULT_CHAIN_ID + 1,
            CONSENSUS_RULESET_VERSION,
            rules
        ),
        "a chain-id change must move the fork id"
    );
    assert_ne!(
        base,
        derive_fork_id(
            stellereum::zkml::DEFAULT_CHAIN_ID,
            RULESET_VERSION + 1,
            rules
        ),
        "a consensus-rule version bump must move the fork id"
    );
    // Every rule constant must be load-bearing: flipping any one of them
    // changes the fork id (provable, not just asserted by inspection).
    for i in 0..rules.len() {
        let mut changed = rules.to_vec();
        changed[i] ^= 1;
        assert_ne!(
            base,
            derive_fork_id(
                stellereum::zkml::DEFAULT_CHAIN_ID,
                CONSENSUS_RULESET_VERSION,
                &changed
            ),
            "changed rule constant at index {i} must move the fork id"
        );
    }
}

/// Ruleset v7 pin: the SDKs ship `FORK_ID = 0x3ae00ebc` (protocol 1.0,
/// `CONSENSUS_RULESET_VERSION = 7`, `DOMAIN_SET_VERSION = 4`) from the same
/// 32-entry rules list and 16 consensus/wire domains. The node MUST produce
/// exactly that value or every SDK builder refuses to sign. See `docs/RULESET_V7.md`.
#[test]
fn fork_id_v7_is_pinned_and_matches_the_sdk_guard() {
    /// The value pinned by `stellereum-sdk/src/protocol.rs` and
    /// `sdk-js/src/protocol.ts` (`FORK_ID_HEX === "0x3ae00ebc"`).
    const SDK_FORK_ID: u32 = 0x3ae0_0ebc;

    assert_eq!(FORK_ID, SDK_FORK_ID);
    assert_eq!(CONSENSUS_RULESET_VERSION, 7);
    assert_eq!(FORK_ID_RULES.len(), 32, "SDKs fold 32 rules");

    // Exact order matters: the fold is sequential. This is the SDK list,
    // constant-for-constant. The first 23 keep the v6 order; entries 23..32
    // are the 8 Ruleset v7 activation heights (all 0) plus the 720k PQ evidence
    // retention window.
    let expected: [u64; 32] = [
        stellereum::consensus::MAX_COMMIT_CERT_SIGNERS as u64,
        stellereum::consensus::MAX_ROUND_AHEAD as u64,
        stellereum::consensus::MAX_ROUND_ADVANCE_PER_MESSAGE as u64,
        stellereum::consensus::MAX_SYNC_JUMPS_PER_ROUND as u64,
        stellereum::consensus::FROZEN_ROUND_TIMEOUT_BASE_MS,
        stellereum::consensus::MICRO_COMMITTEE_MAX_SIZE as u64,
        stellereum::staking::DOWNTIME_MISS_THRESHOLD as u64,
        stellereum::staking::DOWNTIME_PENALTY_COOLDOWN,
        stellereum::staking::JAIL_RELEASE_DELAY_HEIGHTS,
        stellereum::staking::COMMISSION_EFFECT_DELAY_HEIGHTS,
        stellereum::staking::COMMISSION_CHANGE_COOLDOWN_HEIGHTS,
        stellereum::cn_vrf::EPOCH_LEN,
        stellereum::cn_vrf::V3_SEGMENT_LEN,
        stellereum::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS,
        stellereum::pq_registry::PQ_ROTATION_DELAY_HEIGHTS,
        stellereum::mev_kem_registry::MEV_KEM_ROTATION_DELAY_HEIGHTS,
        stellereum::mev_epoch::EPOCH_BLOCKS,
        stellereum::mmr::MMR_EPOCH_BLOCKS,
        stellereum::minroot_vdf::DEFAULT_VDF_STEPS_PER_EPOCH,
        stellereum::consensus::PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT,
        stellereum::protocol::MAX_BLOCK_TIMESTAMP_DRIFT_MS,
        stellereum::tokenomics::CHAIN_SUPPLY_PARTITION_VERSION,
        stellereum::tokenomics::TOTAL_SUPPLY_CAP,
        stellereum::chain_spec::EXEC_HARDENING_V1_ACTIVATION_HEIGHT,
        stellereum::chain_spec::WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT,
        stellereum::sharding::HEADER_COMMIT_ACTIVATION_HEIGHT,
        stellereum::state_engine::EVM_BINDINGS_STATE_ACTIVATION_HEIGHT,
        stellereum::pq_registry::PQ_LIFECYCLE_ACTIVATION_HEIGHT,
        stellereum::pq_registry::PQ_EVIDENCE_RETENTION_HEIGHTS,
        stellereum::bridge::BRIDGE_V2_ACTIVATION_HEIGHT,
        stellereum::tokenomics::FEE_MARKET_V2_ACTIVATION_HEIGHT,
        stellereum::tokenomics::SUB_NANO_STRICT_ACTIVATION_HEIGHT,
    ];
    assert_eq!(
        FORK_ID_RULES, &expected,
        "node rules list must mirror the SDK"
    );
    assert_eq!(
        derive_fork_id(
            stellereum::zkml::DEFAULT_CHAIN_ID,
            CONSENSUS_RULESET_VERSION,
            &expected
        ),
        SDK_FORK_ID,
        "the SDK-pinned fold must reproduce the pinned value"
    );
    // The V3 vote domain is load-bearing: it is folded beside the other
    // consensus domains, so the preimage change is visible in the fork id.
    assert_eq!(
        stellereum::consensus::VOTE_SIGN_DOMAIN,
        b"STELLEREUM_BFT_VOTE_V3"
    );
    assert_eq!(stellereum::protocol::DOMAIN_SET_VERSION, 4);
    // Ruleset v4 & v7 are ACTIVE from genesis (`0`).
    assert_eq!(
        stellereum::consensus::PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT,
        0
    );
    assert_eq!(
        stellereum::protocol::MAX_BLOCK_TIMESTAMP_DRIFT_MS,
        3_600_000
    );
}

/// Historical ruleset v2: version 2, domain set 1, the 19 v2 rules and the
/// V2 domains fold to the value the old SDKs pinned. Ruleset v3 must move it.
#[test]
fn fork_id_v3_differs_from_the_v2_value() {
    const V2_FORK_ID: u32 = 0x3b76_8f7a;

    fn fnv1a32(mut h: u32, bytes: &[u8]) -> u32 {
        for &b in bytes {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
        h
    }
    fn fold(h: u32, v: u64) -> u32 {
        fnv1a32(h, &v.to_le_bytes())
    }
    let mut h = fnv1a32(0x811c_9dc5, b"STELL_FORK_ID_V1");
    h = fnv1a32(h, &1u32.to_le_bytes()); // DOMAIN_SET_VERSION (v2)
    h = fnv1a32(h, &stellereum::zkml::DEFAULT_CHAIN_ID.to_le_bytes());
    h = fnv1a32(h, &2u32.to_le_bytes()); // ruleset v2
    for domain in [
        b"STELL_SORTITION_V5".as_slice(),
        b"STELLEREUM_EQUIVOCATION_OFFENSE_V2".as_slice(),
        b"STELLEREUM_PROPOSAL_EQUIVOCATION_OFFENSE_V2".as_slice(),
        b"STELL_VOTEFAL_V1".as_slice(),
        b"STELL_UQC_PQ_V5_".as_slice(),
        b"STELL_QC_PQ_V5__".as_slice(),
    ] {
        h = fnv1a32(h, domain);
    }
    for rule in &FORK_ID_RULES[..19] {
        h = fold(h, *rule);
    }
    assert_eq!(h, V2_FORK_ID, "the historical v2 fork id");
    assert_ne!(
        FORK_ID, h,
        "ruleset v3 MUST change the fork id so old/new binaries refuse consensus"
    );
}

/// Historical ruleset v1: version 1, the six bound/round constants, and the
/// V1 equivocation domains. It must not collide with ruleset v3 either.
#[test]
fn fork_id_v3_differs_from_the_historical_v1() {
    fn fnv1a32(mut h: u32, bytes: &[u8]) -> u32 {
        for &b in bytes {
            h ^= b as u32;
            h = h.wrapping_mul(0x0100_0193);
        }
        h
    }
    let mut h = fnv1a32(0x811c_9dc5, b"STELL_FORK_ID_V1");
    h = fnv1a32(h, &1u32.to_le_bytes()); // DOMAIN_SET_VERSION
    h = fnv1a32(h, &stellereum::zkml::DEFAULT_CHAIN_ID.to_le_bytes());
    h = fnv1a32(h, &1u32.to_le_bytes()); // ruleset v1
    for domain in [
        b"STELL_SORTITION_V5".as_slice(),
        b"STELLEREUM_EQUIVOCATION_OFFENSE_V1".as_slice(),
        b"STELLEREUM_PROPOSAL_EQUIVOCATION_OFFENSE_V1".as_slice(),
        b"STELL_VOTEFAL_V1".as_slice(),
        b"STELL_UQC_PQ_V5_".as_slice(),
        b"STELL_QC_PQ_V5__".as_slice(),
    ] {
        h = fnv1a32(h, domain);
    }
    for rule in [
        stellereum::consensus::MAX_COMMIT_CERT_SIGNERS as u64,
        stellereum::consensus::MAX_ROUND_AHEAD as u64,
        stellereum::consensus::MAX_ROUND_ADVANCE_PER_MESSAGE as u64,
        stellereum::consensus::MAX_SYNC_JUMPS_PER_ROUND as u64,
        stellereum::consensus::FROZEN_ROUND_TIMEOUT_BASE_MS,
        stellereum::consensus::MICRO_COMMITTEE_MAX_SIZE as u64,
    ] {
        h = fnv1a32(h, &rule.to_le_bytes());
    }
    assert_eq!(h, 0xc5dd_b707, "the historical v1 fork id");
    assert_ne!(
        FORK_ID, h,
        "ruleset v3 MUST differ from the historical v1 fork id"
    );
}

#[test]
fn version_and_fork_are_visible_in_one_read() {
    let info = version_info();
    assert_eq!(info["protocol_version"], PROTOCOL_VERSION.to_string());
    assert_eq!(info["fork_id"], FORK_ID);
    assert_eq!(info["capabilities"], CHAIN_IDENTITY.capabilities.bits());
    assert_eq!(info["consensus_ruleset_version"], CONSENSUS_RULESET_VERSION);
    assert_eq!(
        capability_names(Capabilities::ALL),
        vec!["COMPACT_GOSSIP", "MESH_DIRECT"]
    );
    assert_eq!(CHAIN_IDENTITY.fork_id, FORK_ID);
}
