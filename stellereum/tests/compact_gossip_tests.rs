//! Compact PROPOSAL gossip on the LIVE consensus path
//! (`ConsensusMsg::{CompactProposal,BodyPull,Body}`).
//!
//! Every test drives the REAL emitter (`compact_proposal_from_block`), the
//! REAL wire codec (`ConsensusMsg::encode`/`decode`) and the REAL receiver
//! state machine (`CompactReceiver` / `CompactResolver`). The production gate
//! is `COMPACT_GOSSIP_ACTIVATION_HEIGHT = 0` (active from genesis); the
//! below-gate contract is pinned by installing a temporary concrete gate
//! through `with_compact_gossip_gate`.
//!
//! Pinned guarantees:
//! * a full mempool round-trips with ZERO pulls;
//! * a partial mempool pulls ONLY the misses, then completes;
//! * a cold (zero) mempool falls back to the full-proposal fetch;
//! * a body that does not hash to the announced header is REFUSED;
//! * oversized id lists / pulls / duplicates / mismatched bodies are REFUSED;
//! * a colliding short id resolves to a MISS (pull), never to a different tx;
//! * a 400-tx proposal is announced at >90% fewer bytes than the full body.

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use stellereum::consensus::ValidatorSet;
use stellereum::consensus_net::compact_prop::{
    salt_for_header, short_id, Body, BodyPull, CompactProposal, CompactRefusal, FallbackReason,
    Resolution, ShortIdIndex, COMPACT_MAX_IDS, COMPACT_PULL_MAX_ATTEMPTS, COMPACT_PULL_MAX_IDS,
    SHORT_ID_LEN,
};
use stellereum::consensus_net::{
    compact_gossip_active, compact_proposal_from_block, compact_proposal_from_block_with_full,
    is_superseded_proposal, open_compact_proposal, proposal_gossip_height_round,
    proposal_gossip_msg, short_id_index_for, with_compact_gossip_gate, CompactBodyServer,
    CompactInbound, CompactReceiver, ConsensusMsg, COMPACT_GOSSIP_ACTIVATION_HEIGHT,
    COMPACT_MAX_PARKED,
};
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

#[path = "support/falcon_votes.rs"]
#[allow(dead_code)] // GATE: shared helper — this suite uses only `falcon_set`.
mod falcon_votes;

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

fn block_with(txs: Vec<Transaction>, height: u64) -> Block {
    Block::new_for_test(0, height, [0x11u8; 32], [0x22u8; 32], txs)
        .with_proposer([0x33u8; 32])
        .with_timestamp(1_700_000_000 + height)
}

fn decode_proposal(bytes: &[u8]) -> CompactProposal {
    match ConsensusMsg::decode(bytes).expect("compact frame must decode when active") {
        ConsensusMsg::CompactProposal { proposal } => proposal,
        other => panic!("expected CompactProposal, got {other:?}"),
    }
}

fn expect_pull(res: Resolution) -> BodyPull {
    match res {
        Resolution::Pull(pull) => pull,
        other => panic!("expected a bounded pull, got {other:?}"),
    }
}

fn expect_complete(res: Resolution) -> Block {
    match res {
        Resolution::Complete(block) => *block,
        other => panic!("expected a complete body, got {other:?}"),
    }
}

fn body_for(pull: &BodyPull, block: &Block, salt: &[u8; 32]) -> Body {
    let mut txs = Vec::with_capacity(pull.ids.len());
    for id in &pull.ids {
        let found = block
            .transactions
            .iter()
            .find(|tx| short_id(&tx.compute_tx_hash(), salt) == *id)
            .expect("pull must name a tx of the announced block");
        txs.push((*id, found.clone()));
    }
    Body {
        height: pull.height,
        round: pull.round,
        block_hash: pull.block_hash,
        txs,
    }
}

// ---------------------------------------------------------------------------
// 0. Activation gate: OFF by default, ON only through the override.
// ---------------------------------------------------------------------------

#[test]
fn compact_gate_is_active_from_genesis_and_below_gate_refuses() {
    // Production: ACTIVE from genesis (new chain, no pre-activation peers).
    assert_eq!(COMPACT_GOSSIP_ACTIVATION_HEIGHT, 0);
    assert!(compact_gossip_active(0));
    assert!(compact_gossip_active(1));
    assert!(compact_gossip_active(1_000_000));

    let block = block_with((0..8).map(tx).collect(), 5);
    assert!(
        compact_proposal_from_block(&block, 0).is_some(),
        "genesis-height block must gossip compactly"
    );

    // Below a temporary non-zero gate the SAME emitter, wire and receiver
    // refuse: the below-gate path stays fail-closed and byte-identical.
    let frame = with_compact_gossip_gate(1_000, || {
        assert!(!compact_gossip_active(5));
        assert!(compact_proposal_from_block(&block, 0).is_none());
        let proposal = CompactProposal::for_block(&block, 0, &[]).expect("codec is ungated");
        let wire = ConsensusMsg::CompactProposal { proposal }
            .encode()
            .expect("encode");
        assert!(
            ConsensusMsg::decode(&wire).is_err(),
            "compact frames must be refused below the activation height"
        );
        let proposal = CompactProposal::for_block(&block, 0, &[]).expect("codec is ungated");
        assert!(open_compact_proposal(proposal).is_err());
        wire
    });

    // The `u64::MAX` sentinel height is never admitted, even at the live
    // gate: `compact_gossip_active` uses `>=`, so admission excludes the
    // sentinel explicitly (no real block ever has that height).
    let mut sentinel = block_with(Vec::new(), 0);
    sentinel.height = u64::MAX;
    assert!(compact_proposal_from_block(&sentinel, 0).is_none());
    let sentinel_proposal =
        CompactProposal::for_block(&sentinel, 0, &[]).expect("codec is ungated");
    let sentinel_wire = ConsensusMsg::CompactProposal {
        proposal: sentinel_proposal,
    }
    .encode()
    .expect("encode");
    assert!(
        ConsensusMsg::decode(&sentinel_wire).is_err(),
        "the frozen-gate sentinel height must never be admitted"
    );

    // Once the live gate is in force the pre-built frame decodes.
    assert!(
        ConsensusMsg::decode(&frame).is_ok(),
        "an active gate must admit a structurally valid frame"
    );
}

#[test]
fn compact_gate_arms_through_the_test_override() {
    with_compact_gossip_gate(0, || {
        assert!(compact_gossip_active(0));
        assert!(compact_gossip_active(42));
        let block = block_with((0..4).map(tx).collect(), 42);
        assert!(compact_proposal_from_block(&block, 1).is_some());
    });
    // Restored: the LIVE const (0, active from genesis) is back in force.
    with_compact_gossip_gate(u64::MAX, || {
        assert_eq!(COMPACT_GOSSIP_ACTIVATION_HEIGHT, 0);
        assert!(compact_gossip_active(0));
    });
}

// ---------------------------------------------------------------------------
// 1. Round trip with a FULL mempool: zero pulls, exact body.
// ---------------------------------------------------------------------------

#[test]
fn round_trip_full_mempool_needs_no_pull() {
    with_compact_gossip_gate(0, || {
        let block = block_with((0..400).map(tx).collect(), 7);
        let msg = compact_proposal_from_block(&block, 2).expect("armed emitter");
        let wire = msg.encode().expect("encode");
        let proposal = decode_proposal(&wire);
        let header = proposal.header.clone();

        let mut resolver = open_compact_proposal(proposal).expect("receiver open");
        let index = short_id_index_for(&header, block.transactions.clone());
        let resolved = expect_complete(resolver.resolve_against(&index).expect("resolve"));

        assert_eq!(resolver.attempts(), 0, "a full mempool must never pull");
        assert_eq!(resolved.transactions.len(), 400);
        assert_eq!(
            resolved.compute_hash(),
            block.compute_hash(),
            "resolved body must be the announced block, byte for byte"
        );
        // The header is the signed object: every non-body field survives.
        assert_eq!(resolved.prev_hash, block.prev_hash);
        assert_eq!(resolved.state_root, block.state_root);
        assert_eq!(resolved.order_merkle_root, block.order_merkle_root);
    });
}

// ---------------------------------------------------------------------------
// 2. Partial mempool: pull ONLY the misses, complete from the bounded body.
// ---------------------------------------------------------------------------

#[test]
fn partial_mempool_pulls_only_the_misses() {
    with_compact_gossip_gate(0, || {
        let block = block_with((0..40).map(tx).collect(), 9);
        let msg = compact_proposal_from_block(&block, 3).expect("armed emitter");
        let wire = msg.encode().expect("encode");
        let proposal = decode_proposal(&wire);
        let salt = salt_for_header(&proposal.header);

        // Mempool holds the first 37 txs; the last 3 are the misses.
        let held: Vec<Transaction> = block.transactions[..37].to_vec();
        let missing_ids: Vec<[u8; SHORT_ID_LEN]> = block.transactions[37..]
            .iter()
            .map(|tx| short_id(&tx.compute_tx_hash(), &salt))
            .collect();

        let mut resolver = open_compact_proposal(proposal).expect("receiver open");
        let header = resolver.proposal().header.clone();
        let index = short_id_index_for(&header, held);
        let pull = expect_pull(resolver.resolve_against(&index).expect("resolve"));
        assert_eq!(pull.ids, missing_ids, "pull must carry exactly the misses");
        assert_eq!(pull.attempt, 1);
        assert!(pull.ids.len() <= COMPACT_PULL_MAX_IDS);

        // The pull crosses the wire under the same gate.
        let pull_wire = ConsensusMsg::BodyPull { pull: pull.clone() }
            .encode()
            .expect("encode pull");
        let pull = match ConsensusMsg::decode(&pull_wire).expect("decode pull") {
            ConsensusMsg::BodyPull { pull } => pull,
            other => panic!("expected BodyPull, got {other:?}"),
        };

        let body = body_for(&pull, &block, &salt);
        let body_wire = ConsensusMsg::Body { body: body.clone() }
            .encode()
            .expect("encode body");
        let body = match ConsensusMsg::decode(&body_wire).expect("decode body") {
            ConsensusMsg::Body { body } => body,
            other => panic!("expected Body, got {other:?}"),
        };
        assert_eq!(body.txs.len(), 3, "body carries only the requested txs");

        let resolved = expect_complete(
            resolver
                .accept_body(&body, &index)
                .expect("partial body must complete"),
        );
        assert_eq!(resolved.compute_hash(), block.compute_hash());
        assert_eq!(resolver.attempts(), 1);
    });
}

// ---------------------------------------------------------------------------
// 3. Zero mempool: do NOT amplify into pulls, fall back to the full proposal.
// ---------------------------------------------------------------------------

#[test]
fn zero_mempool_falls_back_to_full_proposal() {
    with_compact_gossip_gate(0, || {
        let block = block_with((0..400).map(tx).collect(), 11);
        let msg = compact_proposal_from_block(&block, 4).expect("armed emitter");
        let wire = msg.encode().expect("encode");
        let proposal = decode_proposal(&wire);
        let mut resolver = open_compact_proposal(proposal).expect("receiver open");
        let header = resolver.proposal().header.clone();
        let empty = short_id_index_for(&header, Vec::new());

        match resolver.resolve_against(&empty).expect("resolve") {
            Resolution::FullProposal(FallbackReason::TooManyMissing { missing }) => {
                assert_eq!(missing, 400);
                assert!(missing > COMPACT_PULL_MAX_IDS);
            }
            other => panic!("a cold mempool must fall back to the full proposal, got {other:?}"),
        }
        assert_eq!(
            resolver.attempts(),
            0,
            "fallback must not burn pull attempts"
        );

        // The fallback path is the untouched full `Proposal`, whose hash is
        // the same block the compact frame announced.
        let full = ConsensusMsg::Proposal {
            height: block.height,
            round: 4,
            block: block.clone(),
        };
        let full = ConsensusMsg::decode(&full.encode().expect("encode full")).expect("decode full");
        match full {
            ConsensusMsg::Proposal { block: b, .. } => {
                assert_eq!(b.compute_hash(), block.compute_hash())
            }
            other => panic!("expected Proposal, got {other:?}"),
        }
    });
}

// ---------------------------------------------------------------------------
// 4. Tampered header / body ⇒ REFUSED (never prevote).
// ---------------------------------------------------------------------------

#[test]
fn tampered_header_hash_is_refused() {
    with_compact_gossip_gate(0, || {
        let block = block_with((0..20).map(tx).collect(), 13);
        let msg = compact_proposal_from_block(&block, 5).expect("armed emitter");
        let wire = msg.encode().expect("encode");

        // (a) announced block hash flipped: the resolved body is fine but no
        // longer equals the announcement.
        let mut proposal = decode_proposal(&wire);
        proposal.block_hash[0] ^= 0x01;
        let index = short_id_index_for(&proposal.header, block.transactions.clone());
        let mut resolver = open_compact_proposal(proposal).expect("open");
        let err = resolver
            .resolve_against(&index)
            .expect_err("tampered block hash must be refused");
        assert_eq!(err, CompactRefusal::BlockHashMismatch);

        // (b) header field flipped (state root) with the announced hash left
        // untouched: the rebuilt block no longer hashes to the announcement.
        let mut proposal = decode_proposal(&wire);
        proposal.header.state_root[0] ^= 0x01;
        let index = short_id_index_for(&proposal.header, block.transactions.clone());
        let mut resolver = open_compact_proposal(proposal).expect("open");
        let err = resolver
            .resolve_against(&index)
            .expect_err("body/header binding must refuse");
        assert_eq!(err, CompactRefusal::BlockHashMismatch);

        // (c) same, but the BODY is tampered after announcement: a body tx is
        // replaced by a different (still well-formed) tx. The id binding
        // refuses it before any hash work.
        let proposal = decode_proposal(&wire);
        let salt = salt_for_header(&proposal.header);
        let index = short_id_index_for(&proposal.header, block.transactions[..19].to_vec());
        let mut resolver = open_compact_proposal(proposal).expect("open");
        let pull = expect_pull(resolver.resolve_against(&index).expect("resolve"));
        let mut body = body_for(&pull, &block, &salt);
        body.txs[0].1 = tx(8_888);
        assert!(matches!(
            resolver.accept_body(&body, &index),
            Err(CompactRefusal::BodyIdMismatch(_))
        ));
    });
}

// ---------------------------------------------------------------------------
// 5. Oversized structures refused (bounded id list, bounded pull).
// ---------------------------------------------------------------------------

#[test]
fn oversized_id_list_is_refused() {
    with_compact_gossip_gate(0, || {
        let header = block_with(Vec::new(), 15);
        let proposal = CompactProposal {
            height: 15,
            round: 0,
            header,
            block_hash: [0xCDu8; 32],
            short_ids: vec![[0u8; SHORT_ID_LEN]; COMPACT_MAX_IDS + 1],
            full_txs: Vec::new(),
        };
        assert_eq!(
            proposal.validate(),
            Err(CompactRefusal::TooManyIds {
                ids: COMPACT_MAX_IDS + 1,
                max: COMPACT_MAX_IDS,
            })
        );
        // The wire codec refuses it too, before any allocation downstream.
        let wire = ConsensusMsg::CompactProposal { proposal }
            .encode()
            .expect("bincode can encode it");
        assert!(ConsensusMsg::decode(&wire).is_err());

        // A pull may not ask for more than the bounded id count either.
        let pull = BodyPull {
            height: 15,
            round: 0,
            block_hash: [0u8; 32],
            ids: vec![[0u8; SHORT_ID_LEN]; COMPACT_PULL_MAX_IDS + 1],
            attempt: 1,
        };
        assert_eq!(
            pull.validate(),
            Err(CompactRefusal::PullTooManyIds {
                ids: COMPACT_PULL_MAX_IDS + 1,
                max: COMPACT_PULL_MAX_IDS,
            })
        );
        // And a pull attempt outside the bounded attempt count.
        let late = BodyPull {
            height: 15,
            round: 0,
            block_hash: [0u8; 32],
            ids: vec![[7u8; SHORT_ID_LEN]],
            attempt: COMPACT_PULL_MAX_ATTEMPTS + 1,
        };
        assert_eq!(
            late.validate(),
            Err(CompactRefusal::PullAttemptOutOfRange(
                COMPACT_PULL_MAX_ATTEMPTS + 1
            ))
        );
    });
}

// ---------------------------------------------------------------------------
// 6. Duplicate / mismatched / replayed bodies refused.
// ---------------------------------------------------------------------------

#[test]
fn duplicate_and_mismatched_bodies_are_refused() {
    with_compact_gossip_gate(0, || {
        let block = block_with((0..6).map(tx).collect(), 17);
        let msg = compact_proposal_from_block(&block, 6).expect("armed emitter");
        let wire = msg.encode().expect("encode");
        let proposal = decode_proposal(&wire);
        let salt = salt_for_header(&proposal.header);
        let held = block.transactions[..4].to_vec();
        let index = short_id_index_for(&proposal.header, held);

        // Get a real pull first (2 misses).
        let mut resolver = open_compact_proposal(proposal.clone()).expect("open");
        let pull = expect_pull(resolver.resolve_against(&index).expect("resolve"));
        assert_eq!(pull.ids.len(), 2);

        // (a) duplicate id inside one body.
        let mut duplicate = body_for(&pull, &block, &salt);
        let first = duplicate.txs[0].clone();
        duplicate.txs.push(first);
        assert!(matches!(
            duplicate.validate(&salt),
            Err(CompactRefusal::BodyDuplicateId(_))
        ));
        assert!(matches!(
            resolver.accept_body(&duplicate, &index),
            Err(CompactRefusal::BodyDuplicateId(_))
        ));

        // (b) id claimed by a DIFFERENT tx (hash binding).
        let mut mismatched = body_for(&pull, &block, &salt);
        mismatched.txs[0].1 = tx(9_999);
        assert!(matches!(
            mismatched.validate(&salt),
            Err(CompactRefusal::BodyIdMismatch(_))
        ));
        assert!(matches!(
            resolver.accept_body(&mismatched, &index),
            Err(CompactRefusal::BodyIdMismatch(_))
        ));

        // (c) body answering a different proposal (wrong block hash).
        let mut wrong_proposal = body_for(&pull, &block, &salt);
        wrong_proposal.block_hash[0] ^= 0x01;
        assert!(matches!(
            resolver.accept_body(&wrong_proposal, &index),
            Err(CompactRefusal::BodyWrongProposal)
        ));

        // (d) an id the proposal DID name but that is already resolved is a
        // duplicate answer, not a fresh one.
        let mut unknown = body_for(&pull, &block, &salt);
        unknown.txs.push((
            short_id(&block.transactions[0].compute_tx_hash(), &salt),
            block.transactions[0].clone(),
        ));
        assert!(matches!(
            resolver.accept_body(&unknown, &index),
            Err(CompactRefusal::BodyUnknownId(_))
        ));

        // The good body still completes after every refusal.
        let good = body_for(&pull, &block, &salt);
        let resolved = expect_complete(resolver.accept_body(&good, &index).expect("good body"));
        assert_eq!(resolved.compute_hash(), block.compute_hash());

        // (e) a REPLAY of the same body after completion is refused.
        assert!(matches!(
            resolver.accept_body(&good, &index),
            Err(CompactRefusal::BodyUnknownId(_))
        ));

        // (f) an EMPTY body is refused.
        let empty = Body {
            height: pull.height,
            round: pull.round,
            block_hash: pull.block_hash,
            txs: Vec::new(),
        };
        assert_eq!(empty.validate(&salt), Err(CompactRefusal::BodyEmpty));
    });
}

// ---------------------------------------------------------------------------
// 7. Collision ⇒ MISS (pull), never a different transaction.
// ---------------------------------------------------------------------------

#[test]
fn colliding_short_id_is_treated_as_a_miss() {
    with_compact_gossip_gate(0, || {
        let block = block_with((0..3).map(tx).collect(), 19);
        let msg = compact_proposal_from_block(&block, 7).expect("armed emitter");
        let proposal = decode_proposal(&msg.encode().expect("encode"));
        let salt = salt_for_header(&proposal.header);
        let announced_id = short_id(&block.transactions[0].compute_tx_hash(), &salt);

        // Simulate the ambiguity a real 48-bit collision would create: a
        // second DISTINCT tx installed under the announced id, on top of the
        // real mempool. The index must not pick either one.
        let mut index = ShortIdIndex::from_txs(salt, block.transactions.clone());
        index.insert_with_id_for_tests(announced_id, tx(424_242));
        assert!(
            index.resolve(&announced_id).is_none(),
            "an ambiguous id must resolve to a MISS"
        );

        let mut resolver = open_compact_proposal(proposal).expect("open");
        // Slot 0 is ambiguous; the other two resolve. The receiver pulls, it
        // never completes with a guessed tx.
        let pull = expect_pull(resolver.resolve_against(&index).expect("resolve"));
        assert_eq!(pull.ids, vec![announced_id]);

        // The proposer's answer pins the exact tx; completion then verifies
        // against the announced hash.
        let body = body_for(&pull, &block, &salt);
        let resolved = expect_complete(resolver.accept_body(&body, &index).expect("complete"));
        assert_eq!(resolved.compute_hash(), block.compute_hash());
        assert_eq!(
            resolved.transactions[0].compute_tx_hash(),
            block.transactions[0].compute_tx_hash()
        );
    });
}

// ---------------------------------------------------------------------------
// 8. Inline bodies (sealed/private slots) + per-height salt.
// ---------------------------------------------------------------------------

#[test]
fn inline_full_slots_complete_without_pulling_them() {
    with_compact_gossip_gate(0, || {
        let block = block_with((0..5).map(tx).collect(), 21);
        // Slot 2 is a private/sealed tx a peer cannot have: it travels full.
        let msg = compact_proposal_from_block_with_full(&block, 8, &[2]).expect("armed emitter");
        let proposal = decode_proposal(&msg.encode().expect("encode"));
        assert_eq!(proposal.full_txs.len(), 1);
        assert_eq!(proposal.full_txs[0].0, 2);

        let salt = salt_for_header(&proposal.header);
        // Mempool holds slots 0,1,3,4 (not the inline one).
        let held: Vec<Transaction> = block
            .transactions
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 2)
            .map(|(_, tx)| tx.clone())
            .collect();
        let index = ShortIdIndex::from_txs(salt, held);

        let mut resolver = open_compact_proposal(proposal).expect("open");
        let resolved = expect_complete(resolver.resolve_against(&index).expect("resolve"));
        assert_eq!(resolved.compute_hash(), block.compute_hash());
        assert_eq!(resolver.attempts(), 0);
    });
}

#[test]
fn short_ids_are_bound_to_one_height() {
    with_compact_gossip_gate(0, || {
        // Same prev_hash, different height: the salt MUST differ, so an id
        // ground for one height never resolves at another.
        let a = block_with((0..2).map(tx).collect(), 30);
        let b = block_with((0..2).map(tx).collect(), 31);
        let salt_a = salt_for_header(&a);
        let salt_b = salt_for_header(&b);
        assert_ne!(salt_a, salt_b);
        assert_ne!(
            short_id(&a.transactions[0].compute_tx_hash(), &salt_a),
            short_id(&a.transactions[0].compute_tx_hash(), &salt_b)
        );

        // With the RIGHT salt but the OTHER height's transactions, nothing
        // resolves: ids are height-bound, so a cross-height index cannot
        // silently satisfy a slot.
        let msg = compact_proposal_from_block(&a, 0).expect("armed emitter");
        let proposal = decode_proposal(&msg.encode().expect("encode"));
        let mut resolver = open_compact_proposal(proposal).expect("open");
        // An index built for ANOTHER height has a different salt and is
        // refused outright: the caller must derive the salt from the
        // announcement.
        let wrong_salt = ShortIdIndex::from_txs(salt_b, b.transactions.clone());
        assert!(matches!(
            resolver.resolve_against(&wrong_salt),
            Err(CompactRefusal::IndexSaltMismatch)
        ));

        // Height binding at the id level: no height-30 short id equals the
        // height-31 id of the same transaction.
        let a_ids: Vec<_> = a
            .transactions
            .iter()
            .map(|tx| short_id(&tx.compute_tx_hash(), &salt_a))
            .collect();
        for tx in &b.transactions {
            let other = short_id(&tx.compute_tx_hash(), &salt_b);
            assert!(
                !a_ids.contains(&other),
                "ids must not be reusable across heights"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// 9. Measured byte saving on a 400-tx proposal.
// ---------------------------------------------------------------------------

#[test]
fn four_hundred_tx_proposal_is_over_90_percent_smaller() {
    with_compact_gossip_gate(0, || {
        let block = block_with((0..400).map(tx).collect(), 23);
        let full = ConsensusMsg::Proposal {
            height: block.height,
            round: 0,
            block: block.clone(),
        };
        let compact = compact_proposal_from_block(&block, 0).expect("armed emitter");
        let full_bytes = full.encode().expect("encode full").len();
        let compact_bytes = compact.encode().expect("encode compact").len();

        assert!(
            compact_bytes * 10 < full_bytes,
            "compact announcement must save >90%: compact={compact_bytes} B, \
             full={full_bytes} B"
        );
        // The measured shape: ~366 B fixed + 6 B per short id (bincode tag and
        // vector prefixes included). Guard the arithmetic against drift.
        assert!(
            compact_bytes < 3_500,
            "400 short ids + header must stay under 3.5 kB, got {compact_bytes} B"
        );
        assert!(
            full_bytes > 60_000,
            "full body baseline sanity: {full_bytes} B"
        );

        // Round-trip the measured frame and confirm the body still resolves.
        let proposal = decode_proposal(&compact.encode().expect("encode"));
        let index = short_id_index_for(&proposal.header, block.transactions.clone());
        let mut resolver = open_compact_proposal(proposal).expect("open");
        let resolved = expect_complete(resolver.resolve_against(&index).expect("resolve"));
        assert_eq!(resolved.compute_hash(), block.compute_hash());

        eprintln!(
            "[compact-gossip] 400-tx proposal: full={full_bytes} B compact={compact_bytes} B \
             saving={:.1}%",
            100.0 - (compact_bytes as f64 * 100.0 / full_bytes as f64)
        );
    });
}

// ---------------------------------------------------------------------------
// 10. Wire compatibility: pre-existing variant tags are untouched, and the new
//     variants are appended (so old peers keep parsing old frames).
// ---------------------------------------------------------------------------

#[test]
fn legacy_variant_tags_and_proposal_bytes_are_unchanged() {
    // Below the gate the plain Proposal path is byte-identical: decode the
    // exact frame the emitter produced.
    with_compact_gossip_gate(u64::MAX, || {
        let block = block_with((0..3).map(tx).collect(), 27);
        let msg = ConsensusMsg::Proposal {
            height: block.height,
            round: 1,
            block: block.clone(),
        };
        let wire = msg.encode().expect("encode");
        assert_eq!(&wire[..4], &[0, 0, 0, 0], "Proposal must stay tag 0");
        let back = ConsensusMsg::decode(&wire).expect("legacy proposal decodes");
        match back {
            ConsensusMsg::Proposal {
                block: b, round, ..
            } => {
                assert_eq!(round, 1);
                assert_eq!(b.compute_hash(), block.compute_hash());
            }
            other => panic!("expected Proposal, got {other:?}"),
        }

        // Batch keeps tag 3; the bincode anti-recursion pre-check depends on
        // it, and old peers parse batches by that tag.
        let batch = ConsensusMsg::Batch(vec![msg]);
        assert_eq!(&batch.encode().expect("encode batch")[..4], &[3, 0, 0, 0]);
    });

    // The compact variants are APPENDED after Batch: tags 4, 5, 6.
    with_compact_gossip_gate(0, || {
        let block = block_with((0..2).map(tx).collect(), 29);
        let proposal = compact_proposal_from_block(&block, 0).expect("armed emitter");
        assert_eq!(&proposal.encode().expect("encode")[..4], &[4, 0, 0, 0]);
        let pull = ConsensusMsg::BodyPull {
            pull: BodyPull {
                height: 29,
                round: 0,
                block_hash: block.compute_hash(),
                ids: vec![[1u8; SHORT_ID_LEN]],
                attempt: 1,
            },
        };
        assert_eq!(&pull.encode().expect("encode")[..4], &[5, 0, 0, 0]);
        let body = ConsensusMsg::Body {
            body: Body {
                height: 29,
                round: 0,
                block_hash: block.compute_hash(),
                txs: vec![([1u8; SHORT_ID_LEN], tx(0))],
            },
        };
        assert_eq!(&body.encode().expect("encode")[..4], &[6, 0, 0, 0]);
    });
}

// ---------------------------------------------------------------------------
// 11. Determinism: the same announcement + the same mempool always resolves
//     to the same bytes (no ordering/entropy dependence).
// ---------------------------------------------------------------------------

#[test]
fn resolution_is_deterministic() {
    with_compact_gossip_gate(0, || {
        let block = block_with((0..32).map(tx).collect(), 25);
        let msg = compact_proposal_from_block(&block, 9).expect("armed emitter");
        let wire = msg.encode().expect("encode");

        let run = || {
            let proposal = decode_proposal(&wire);
            let index = short_id_index_for(&proposal.header, block.transactions.clone());
            let mut resolver = open_compact_proposal(proposal).expect("open");
            let resolved = expect_complete(resolver.resolve_against(&index).expect("resolve"));
            resolved.compute_hash()
        };
        assert_eq!(run(), run());
        assert_eq!(run(), block.compute_hash());
    });
}

// ---------------------------------------------------------------------------
// 12. Sender selector: compact above the gate, full `Proposal` below it, and
//     the same `(height, round)` key for outbox dedupe / supersede pruning.
// ---------------------------------------------------------------------------

#[test]
fn sender_selector_is_compact_active_and_full_below_gate() {
    let block = block_with((0..4).map(tx).collect(), 33);

    // Live gate: the gossip path uses the compact form.
    let msg = proposal_gossip_msg(&block, 2);
    match &msg {
        ConsensusMsg::CompactProposal { proposal } => {
            assert_eq!(proposal.height, block.height);
            assert_eq!(proposal.round, 2);
            assert_eq!(proposal.short_ids.len(), block.transactions.len());
        }
        other => panic!("expected CompactProposal, got {other:?}"),
    }
    assert_eq!(proposal_gossip_height_round(&msg), Some((33, 2)));

    // Below a non-zero gate the selector falls back to the full proposal,
    // byte-identical to the pre-compact path.
    with_compact_gossip_gate(1_000, || {
        let full = proposal_gossip_msg(&block, 2);
        match &full {
            ConsensusMsg::Proposal {
                height,
                round,
                block: b,
            } => {
                assert_eq!(*height, 33);
                assert_eq!(*round, 2);
                assert_eq!(b.compute_hash(), block.compute_hash());
            }
            other => panic!("expected Proposal below the gate, got {other:?}"),
        }
        assert_eq!(proposal_gossip_height_round(&full), Some((33, 2)));
    });

    // Supersede rule covers BOTH representations: a compact proposal two
    // rounds behind (or at another height) is pruned exactly like a full one.
    assert!(!is_superseded_proposal(&msg, 33, 2));
    assert!(!is_superseded_proposal(&msg, 33, 3));
    assert!(is_superseded_proposal(&msg, 33, 4));
    assert!(is_superseded_proposal(&msg, 34, 2));
}

// ---------------------------------------------------------------------------
// 13. Receiver state machine: local mempool => Ready, misses => one bounded
//     pull => Body => Ready, cold mempool => full-proposal fallback.
// ---------------------------------------------------------------------------

#[test]
fn receiver_resolves_full_mempool_and_falls_back_when_cold() {
    let block = block_with((0..8).map(tx).collect(), 35);
    let msg = compact_proposal_from_block(&block, 1).expect("active emitter");
    let wire = msg.encode().expect("encode");

    // Full mempool: Ready with no pull and no parked state.
    let proposal = decode_proposal(&wire);
    let mut receiver = CompactReceiver::new();
    match receiver.on_proposal(proposal, block.transactions.clone()) {
        CompactInbound::Ready { round, block: got } => {
            assert_eq!(round, 1);
            assert_eq!(got.compute_hash(), block.compute_hash());
        }
        other => panic!("full mempool must complete, got {other:?}"),
    }
    assert_eq!(receiver.parked_len(), 0);

    // Cold mempool (400 slots): never amplify into pulls, fetch the full
    // proposal through the existing path instead.
    let big = block_with((0..400).map(tx).collect(), 36);
    let big_msg = compact_proposal_from_block(&big, 2).expect("active emitter");
    let proposal = decode_proposal(&big_msg.encode().expect("encode"));
    match receiver.on_proposal(proposal, Vec::new()) {
        CompactInbound::FetchFull {
            height,
            round,
            reason: FallbackReason::TooManyMissing { missing },
            ..
        } => {
            assert_eq!(height, 36);
            assert_eq!(round, 2);
            assert_eq!(missing, 400);
        }
        other => panic!("cold mempool must fall back, got {other:?}"),
    }
    assert_eq!(receiver.parked_len(), 0, "fallback must not park state");
}

#[test]
fn receiver_pulls_misses_then_completes_from_a_bounded_body() {
    let block = block_with((0..5).map(tx).collect(), 37);
    let msg = compact_proposal_from_block(&block, 3).expect("active emitter");
    let proposal = decode_proposal(&msg.encode().expect("encode"));
    let held: Vec<Transaction> = block.transactions[..3].to_vec();

    let mut receiver = CompactReceiver::new();
    let pull = match receiver.on_proposal(proposal, held.clone()) {
        CompactInbound::Pull(pull) => pull,
        other => panic!("partial mempool must pull, got {other:?}"),
    };
    assert_eq!(pull.ids.len(), 2);
    assert_eq!(pull.attempt, 1);
    assert_eq!(receiver.parked_len(), 1);

    // The proposer serves exactly the requested ids from its own mempool.
    let mut server = CompactBodyServer::new();
    server.remember(&block, 3);
    let body = server
        .serve(&pull, block.transactions.clone())
        .expect("pull is structurally valid")
        .expect("proposer must answer a resolvable pull");
    assert_eq!(body.txs.len(), 2);

    // A tampered body is refused but the proposal stays parked for an honest
    // retry.
    let mut bad = body.clone();
    bad.txs[0].1 = tx(7_777);
    assert!(matches!(
        receiver.on_body(&bad, held.clone()),
        CompactInbound::Refused(_)
    ));
    assert_eq!(
        receiver.parked_len(),
        1,
        "a bad body must not drop the proposal"
    );

    match receiver.on_body(&body, held) {
        CompactInbound::Ready { block: got, .. } => {
            assert_eq!(got.compute_hash(), block.compute_hash());
        }
        other => panic!("bounded body must complete, got {other:?}"),
    }
    assert_eq!(receiver.parked_len(), 0);

    // A pull for a tx the responder no longer holds in its mempool is NOT
    // answered (no private/inline leak, no fabricated body).
    assert!(server
        .serve(&pull, Vec::new())
        .expect("structurally valid")
        .is_none());
}

#[test]
fn receiver_refuses_body_without_a_parked_proposal() {
    let block = block_with((0..2).map(tx).collect(), 39);
    let mut receiver = CompactReceiver::new();
    let body = Body {
        height: block.height,
        round: 0,
        block_hash: block.compute_hash(),
        txs: vec![(
            short_id(
                &block.transactions[0].compute_tx_hash(),
                &salt_for_header(&block),
            ),
            block.transactions[0].clone(),
        )],
    };
    match receiver.on_body(&body, block.transactions.clone()) {
        CompactInbound::Refused(message) => assert!(message.contains("no parked proposal")),
        other => panic!("unexpected body without a proposal: {other:?}"),
    }
}

#[test]
fn receiver_park_budget_is_bounded() {
    let mut receiver = CompactReceiver::new();
    for i in 0..(COMPACT_MAX_PARKED as u64 + 2) {
        let block = block_with(vec![tx(100 + i)], 100 + i);
        let msg = compact_proposal_from_block(&block, 0).expect("active emitter");
        let proposal = decode_proposal(&msg.encode().expect("encode"));
        match receiver.on_proposal(proposal, Vec::new()) {
            CompactInbound::Pull(_) => {}
            other => panic!("a single miss must pull, got {other:?}"),
        }
    }
    assert_eq!(
        receiver.parked_len(),
        COMPACT_MAX_PARKED,
        "parked resolutions must stay within the bounded queue"
    );
}

// ---------------------------------------------------------------------------
// 14. END TO END: propose -> compact gossip -> mempool resolution (and one
//     bounded pull) -> prevote -> precommit -> finalize, on three real
//     validators (quorum 3 of 4; the fourth is offline).
// ---------------------------------------------------------------------------

/// A FULL-PQ transfer signed by `fk` (Falcon-512 envelope, derived `from`).
fn pq_transfer(
    fk: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
) -> Transaction {
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        fk.public_key.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        to,
        amount,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        Vec::new(),
        &DEFAULT_SALT,
    );
    let signature = fk.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        fk.public_key.clone(),
        signature,
        to,
        amount,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        Vec::new(),
        &DEFAULT_SALT,
    )
}

fn e2e_node(
    key: &SigningKey,
    falcon: &FalconKeypair,
    validators: &ValidatorSet,
    state: Arc<InMemoryStateEngine>,
) -> ValidatorRuntime {
    ValidatorRuntime::new(key.clone(), validators.clone(), state, 1).with_falcon_key(falcon.clone())
}

#[tokio::test]
async fn compact_proposal_end_to_end_votes_and_finalizes() {
    let (keys, falcons) = falcon_votes::falcon_set(4);
    let validators = ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    );
    assert_eq!(
        validators.quorum_power(),
        3,
        "3 of 4 validators must decide"
    );

    // A FULL-PQ sender (the mempool refuses Ed-only transactions). Use the
    // offline validator's Falcon key so the sender's address is derived the
    // same way the mempool derives it.
    let sender_fk = falcons[3].clone();
    let sender = derive_pq_address(PqScheme::Falcon512, &sender_fk.public_key, &DEFAULT_SALT);
    let recipient = [0xAAu8; 32];
    let genesis_balance = 1_000_000_000_000_000u64;

    let states: Vec<Arc<InMemoryStateEngine>> = (0..3)
        .map(|_| Arc::new(InMemoryStateEngine::new()))
        .collect();
    for state in &states {
        fund_genesis(state, &validators, genesis_balance).await;
        state
            .update_account(AccountState::new(sender, genesis_balance))
            .await;
        state
            .update_account(AccountState::new(recipient, genesis_balance))
            .await;
    }

    let mut nodes = Vec::with_capacity(3);
    for i in 0..3 {
        nodes.push(e2e_node(
            &keys[i],
            &falcons[i],
            &validators,
            states[i].clone(),
        ));
    }

    // The proposer and the first receiver hold the tx; the second receiver's
    // mempool is cold, so it must go through the bounded body pull.
    // A raw-key PQ envelope pays the ~45k activation surcharge, so the
    // declared gas limit must clear that floor (21k would be `FeeTooLow`).
    let tx = pq_transfer(&sender_fk, recipient, 1_000, 200_000, 0);
    let admitted = nodes[0].mempool.write().await.add(tx.clone());
    assert!(admitted.is_ok(), "node 0 mempool must admit: {admitted:?}");
    let admitted = nodes[1].mempool.write().await.add(tx.clone());
    assert!(admitted.is_ok(), "node 1 mempool must admit: {admitted:?}");
    assert_eq!(nodes[0].mempool.read().await.len(), 1);
    assert_eq!(nodes[1].mempool.read().await.len(), 1);
    assert_eq!(nodes[2].mempool.read().await.len(), 0);

    // Phase-align all three to a round owned by validator 0.
    let proposer = keys[0].verifying_key().to_bytes();
    // Proposer selection is hash-based (`STELL_PROPOSER_V1` over height and
    // round), so walk rounds until validator 0 owns one (a 4-seat set hits it
    // with overwhelming probability well before 64; the bound is the test's,
    // not consensus's).
    for _ in 0..64 {
        if nodes[0].hc.proposer() == Some(proposer) {
            break;
        }
        for node in nodes.iter_mut() {
            node.hc.next_round();
        }
    }
    assert_eq!(nodes[0].hc.proposer(), Some(proposer));
    let round = nodes[0].hc.round;
    let height = nodes[0].hc.height;

    // 1. PROPOSE.
    let block = nodes[0]
        .propose(1_000)
        .await
        .expect("scheduled proposer must build a block");
    assert_eq!(block.transactions.len(), 1, "the seeded tx must be packed");
    let block_hash = block.compute_hash();

    // 2. COMPACT GOSSIP: the sender selector emits the compact form, the
    //    wire codec round-trips it, and the pull responder remembers the body.
    let msg = proposal_gossip_msg(&block, round);
    let wire = msg.encode().expect("compact gossip must encode");
    let announcement = match ConsensusMsg::decode(&wire).expect("compact gossip must decode") {
        ConsensusMsg::CompactProposal { proposal } => proposal,
        other => panic!("expected CompactProposal, got {other:?}"),
    };
    assert_eq!(announcement.height, height);
    assert_eq!(announcement.block_hash, block_hash);
    assert_eq!(announcement.short_ids.len(), 1);
    let full_len = ConsensusMsg::Proposal {
        height,
        round,
        block: block.clone(),
    }
    .encode()
    .expect("full proposal encodes")
    .len();
    assert!(
        wire.len() < full_len,
        "the compact announcement ({}) must be smaller than the full body ({full_len})",
        wire.len()
    );
    let mut server = CompactBodyServer::new();
    server.remember(&block, round);

    // 3. RESOLVE: receiver 1 has the tx (zero pulls); receiver 2 misses it,
    //    pulls it with one bounded BodyPull and completes from the Body.
    let mut receivers = [CompactReceiver::new(), CompactReceiver::new()];
    let held_1 = nodes[1].mempool.read().await.all();
    let resolved_1 = match receivers[0].on_proposal(announcement.clone(), held_1) {
        CompactInbound::Ready { round: r, block: b } => {
            assert_eq!(r, round);
            b
        }
        other => panic!("warm mempool must resolve without a pull, got {other:?}"),
    };
    assert_eq!(resolved_1.compute_hash(), block_hash);

    let held_2 = nodes[2].mempool.read().await.all();
    let pull = match receivers[1].on_proposal(announcement, held_2.clone()) {
        CompactInbound::Pull(pull) => pull,
        other => panic!("cold receiver must issue a bounded pull, got {other:?}"),
    };
    assert_eq!(pull.ids.len(), 1);
    assert!(pull.ids.len() <= COMPACT_PULL_MAX_IDS);
    assert_eq!(pull.attempt, 1);
    let body = server
        .serve(&pull, nodes[0].mempool.read().await.all())
        .expect("bounded pull is valid")
        .expect("proposer must serve the missing tx");
    let resolved_2 = match receivers[1].on_body(&body, held_2) {
        CompactInbound::Ready { round: r, block: b } => {
            assert_eq!(r, round);
            b
        }
        other => panic!("body must complete the parked resolution, got {other:?}"),
    };
    assert_eq!(resolved_2.compute_hash(), block_hash);

    // 4. on_proposal with the FULL block, exactly like the full-Proposal arm.
    for (i, resolved) in [resolved_1, resolved_2].into_iter().enumerate() {
        let node = &mut nodes[i + 1];
        let accepted = node
            .on_proposal(proposer, *resolved, round)
            .await
            .expect("a fully resolved, hash-verified block must be accepted");
        assert_eq!(accepted, block_hash);
        assert!(node.hc.has_live_proposal());
    }

    // 5. VOTE: three prevotes, then three precommits; every node sees all.
    let prevotes: Vec<_> = nodes
        .iter()
        .map(|node| node.make_prevote().expect("every node must prevote"))
        .collect();
    for vote in &prevotes {
        assert_eq!(vote.block_hash, Some(block_hash));
        assert_eq!(vote.round, round);
    }
    for node in nodes.iter_mut() {
        for vote in &prevotes {
            node.on_prevote(vote.clone()).expect("prevote must verify");
        }
    }
    let precommits: Vec<_> = nodes
        .iter_mut()
        .map(|node| {
            node.make_precommit()
                .expect("polka must produce a precommit")
        })
        .collect();
    for vote in &precommits {
        assert_eq!(vote.block_hash, Some(block_hash));
    }
    for node in nodes.iter_mut() {
        for vote in &precommits {
            node.on_precommit(vote.clone())
                .expect("precommit must verify");
        }
    }

    // 6. FINALIZE: every node commits the announced block and advances.
    for (i, node) in nodes.iter_mut().enumerate() {
        assert_eq!(
            node.try_finalize().await,
            Some(block_hash),
            "node {i} must finalize the compactly gossiped block"
        );
        assert_eq!(node.hc.height, height + 1);
        assert!(node
            .finalized
            .iter()
            .any(|(h, bh)| *h == height && *bh == block_hash));
    }
    let root = nodes[0].state.get_state_root().await;
    for node in &nodes {
        assert_eq!(
            node.state.get_state_root().await,
            root,
            "every validator must commit the same state root"
        );
    }
}
