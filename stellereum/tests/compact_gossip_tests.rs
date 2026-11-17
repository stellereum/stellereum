//! Compact PROPOSAL gossip on the LIVE consensus path
//! (`ConsensusMsg::{CompactProposal,BodyPull,Body}`).
//!
//! Every test drives the REAL emitter (`compact_proposal_from_block`), the
//! REAL wire codec (`ConsensusMsg::encode`/`decode`) and the REAL receiver
//! state machine (`open_compact_proposal` + `CompactResolver`) through the
//! test-only activation override. `COMPACT_GOSSIP_ACTIVATION_HEIGHT` itself
//! stays `u64::MAX`, so the live wire is unchanged.
//!
//! Pinned guarantees:
//! * a full mempool round-trips with ZERO pulls;
//! * a partial mempool pulls ONLY the misses, then completes;
//! * a cold (zero) mempool falls back to the full-proposal fetch;
//! * a body that does not hash to the announced header is REFUSED;
//! * oversized id lists / pulls / duplicates / mismatched bodies are REFUSED;
//! * a colliding short id resolves to a MISS (pull), never to a different tx;
//! * a 400-tx proposal is announced at >90% fewer bytes than the full body.

use stellereum::consensus_net::compact_prop::{
    salt_for_header, short_id, Body, BodyPull, CompactProposal, CompactRefusal, FallbackReason,
    Resolution, ShortIdIndex, COMPACT_MAX_IDS, COMPACT_PULL_MAX_ATTEMPTS, COMPACT_PULL_MAX_IDS,
    SHORT_ID_LEN,
};
use stellereum::consensus_net::{
    compact_gossip_active, compact_proposal_from_block, compact_proposal_from_block_with_full,
    open_compact_proposal, short_id_index_for, with_compact_gossip_gate, ConsensusMsg,
    COMPACT_GOSSIP_ACTIVATION_HEIGHT,
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
fn compact_gate_is_off_until_the_const_is_flipped() {
    // Build a compact frame ONCE through the override (the override is a
    // non-reentrant gate lock, so the two phases are separate calls).
    let block = block_with((0..8).map(tx).collect(), 5);
    let frame = with_compact_gossip_gate(0, || {
        let msg = compact_proposal_from_block(&block, 0).expect("armed emitter");
        msg.encode().expect("encode")
    });

    // `u64::MAX` override == "unset": exercises the frozen production const
    // while holding the process-wide gate lock (other tests in this binary
    // arm the gate through the same helper).
    with_compact_gossip_gate(u64::MAX, || {
        assert_eq!(COMPACT_GOSSIP_ACTIVATION_HEIGHT, u64::MAX);
        assert!(!compact_gossip_active(0));
        assert!(!compact_gossip_active(1_000_000));
        assert!(!compact_gossip_active(u64::MAX - 1));

        // Emitter: no compact frame below the gate.
        assert!(compact_proposal_from_block(&block, 0).is_none());

        // The frozen-gate sentinel height itself is never admitted: `>=`
        // keeps `compact_gossip_active(u64::MAX)` true for the predicate
        // (post-flip comparison), but FRAMES named `u64::MAX` are refused.
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

        // The frozen gate refuses the pre-built compact frame on decode and on
        // receiver open.
        assert!(
            ConsensusMsg::decode(&frame).is_err(),
            "compact frames must be refused below the activation height"
        );
        let proposal = CompactProposal::for_block(&block, 0, &[]).expect("codec is ungated");
        assert!(open_compact_proposal(proposal).is_err());
    });
}

#[test]
fn compact_gate_arms_through_the_test_override() {
    with_compact_gossip_gate(0, || {
        assert!(compact_gossip_active(0));
        assert!(compact_gossip_active(42));
        let block = block_with((0..4).map(tx).collect(), 42);
        assert!(compact_proposal_from_block(&block, 1).is_some());
    });
    // Restored: the frozen const is back in force.
    with_compact_gossip_gate(u64::MAX, || assert!(!compact_gossip_active(0)));
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
