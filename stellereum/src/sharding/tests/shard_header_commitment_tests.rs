// ==================== TON `shard_hashes`: shard-head commitments ====================

/// Tests for the shard-head commitment published by a masterchain block.
use super::*;
use crate::cell::CellHash;
use crate::post_quantum::{FalconKeypair, PqScheme};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

fn head(shard_id: ShardId, height: u64, tag: u8) -> ShardHeaderCommitment {
    ShardHeaderCommitment {
        shard_id,
        height,
        block_hash: [tag; 32],
        state_root: [tag.wrapping_add(1); 32],
        timestamp: 1_700_000_000 + height,
    }
}

fn block_with(headers: Vec<ShardHeaderCommitment>) -> Block {
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 10,
        prev_hash: [0xAB; 32],
        state_root: [0xCD; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_500,
        proposer: [0xEF; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        shard_headers: headers,
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
    }
}

#[test]
fn block_hash_commits_the_shard_heads() {
    let a = block_with(vec![head(1, 5, 0x01)]);
    let b = block_with(vec![head(1, 5, 0x01)]);
    assert_eq!(a.compute_hash(), b.compute_hash(), "same head => same hash");

    // Every field of the commitment is bound: a different height, hash,
    // root or timestamp MUST move the block hash.
    let mut other_height = a.clone();
    other_height.shard_headers[0].height += 1;
    assert_ne!(a.compute_hash(), other_height.compute_hash());

    let mut other_hash = a.clone();
    other_hash.shard_headers[0].block_hash = [0x77; 32];
    assert_ne!(a.compute_hash(), other_hash.compute_hash());

    let mut other_root = a.clone();
    other_root.shard_headers[0].state_root = [0x78; 32];
    assert_ne!(a.compute_hash(), other_root.compute_hash());

    let mut other_time = a.clone();
    other_time.shard_headers[0].timestamp += 1;
    assert_ne!(a.compute_hash(), other_time.compute_hash());

    // An extra shard head is bound too (the set is length-prefixed).
    let mut two = a.clone();
    two.shard_headers.push(head(2, 6, 0x02));
    assert_ne!(a.compute_hash(), two.compute_hash());
}

#[test]
fn a_block_without_shard_heads_keeps_its_legacy_hash() {
    // The commitment is mixed in ONLY for a non-empty set, so a block that
    // publishes no shard head hashes exactly as it did before the field
    // existed (legacy chains keep their block hashes byte-for-byte).
    let legacy = block_with(vec![]);
    let mut with_empty = legacy.clone();
    with_empty.shard_headers = vec![];
    assert_eq!(legacy.compute_hash(), with_empty.compute_hash());

    // ...and adding a head MUST change it, otherwise the quorum would
    // sign a block whose shard roots are not covered.
    let mut with_head = legacy.clone();
    with_head.shard_headers.push(head(1, 5, 0x01));
    assert_ne!(legacy.compute_hash(), with_head.compute_hash());
}

/// FORK COMPATIBILITY (V5 Tier-2 MMR): the epoch-MMR trailing field does
/// not move any pre-existing block hash, and a new block that commits to
/// no epoch (zero root) hashes identically to a legacy block — so old
/// signatures over the parts old nodes understand keep verifying.
/// A non-zero root MUST move the hash (otherwise the quorum would sign a
/// root it is not bound to), and the commitment must survive the bincode
/// round-trip.
#[test]
fn epoch_mmr_root_keeps_legacy_hashes_and_moves_hash_when_set() {
    let legacy = block_with(vec![]);
    assert_eq!(
        legacy.mmr_epoch_root, [0u8; 32],
        "a pre-MMR block commits to no epoch"
    );
    let legacy_hash = legacy.compute_hash();

    // A new block with a ZERO root is hash-identical to the legacy
    // block: an old node verifies its proposer signature against the
    // same preimage it always did.
    let mut zero = legacy.clone();
    zero.mmr_epoch_root = [0u8; 32];
    assert_eq!(zero.compute_hash(), legacy_hash);

    // The signature made over the legacy shape verifies on the zero-root
    // block (same hash, same preimage).
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut signed = legacy.clone();
    signed.proposer = sk.verifying_key().to_bytes();
    signed.sign_block(&sk);
    let mut signed_zero = signed.clone();
    signed_zero.mmr_epoch_root = [0u8; 32];
    assert!(signed_zero.verify_proposer_signature());

    // A NON-ZERO root moves the hash (the quorum signs the root too) and
    // two different roots are two different blocks.
    let mut committed = legacy.clone();
    committed.mmr_epoch_root = [0x42; 32];
    assert_ne!(committed.compute_hash(), legacy_hash);
    let mut other = legacy.clone();
    other.mmr_epoch_root = [0x43; 32];
    assert_ne!(committed.compute_hash(), other.compute_hash());

    // The commitment survives the bincode round-trip (strict wire path:
    // no tolerance needed for a complete body).
    let bytes = bincode::serialize(&committed).expect("must encode");
    let decoded: Block = bincode::deserialize(&bytes).expect("must decode");
    assert_eq!(decoded.mmr_epoch_root, [0x42; 32]);
    assert_eq!(decoded.compute_hash(), committed.compute_hash());

    // A legacy byte stream (field absent) still decodes tolerantly to
    // the zero root — and therefore to the legacy hash.
    let legacy_shaped = Block {
        shard_id: legacy.shard_id,
        height: legacy.height,
        prev_hash: legacy.prev_hash,
        state_root: legacy.state_root,
        transactions: legacy.transactions.clone(),
        cross_shard_out: legacy.cross_shard_out.clone(),
        timestamp: legacy.timestamp,
        proposer: legacy.proposer,
        validator_signatures: legacy.validator_signatures.clone(),
        precommit_qc: legacy.precommit_qc.clone(),
        last_qc: legacy.last_qc.clone(),
        shard_headers: legacy.shard_headers.clone(),
        order_merkle_root: legacy.order_merkle_root,
        epoch_key_commitment: legacy.epoch_key_commitment,
        mmr_epoch_root: [0u8; 32],
    };
    assert_eq!(legacy_shaped.compute_hash(), legacy_hash);
}

#[test]
fn canonical_shard_head_sets_are_ascending_and_never_self_referential() {
    assert!(block_with(vec![head(1, 5, 0x01), head(2, 6, 0x02)]).shard_headers_canonical());
    assert!(block_with(vec![]).shard_headers_canonical());

    // Descending order is NOT canonical (the set is hashed as a sequence,
    // so two orders would be two different block hashes).
    assert!(!block_with(vec![head(2, 6, 0x02), head(1, 5, 0x01)]).shard_headers_canonical());
    // Duplicates are not canonical either.
    assert!(!block_with(vec![head(1, 5, 0x01), head(1, 6, 0x02)]).shard_headers_canonical());
    // A block never commits to its own head.
    assert!(!block_with(vec![head(MASTERCHAIN_SHARD, 5, 0x01)]).shard_headers_canonical());
}

#[test]
fn shard_head_lookup_by_shard_id() {
    let b = block_with(vec![head(1, 5, 0x01), head(2, 6, 0x02)]);
    assert_eq!(b.shard_head(2).map(|h| h.height), Some(6));
    assert!(b.shard_head(3).is_none());
}

/// CROSS-CHAIN REPLAY: the block hash — and therefore every signature over
/// it — is bound to the chain id. A block signed on the testnet does not
/// verify on the mainnet, with the very same validator key.
#[test]
fn block_hash_and_signature_are_bound_to_chain_id() {
    const TESTNET: u64 = 999_001;
    const MAINNET: u64 = 5757;

    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut block = block_with(vec![]);
    block.proposer = key.verifying_key().to_bytes();

    // Sign on the TESTNET.
    crate::consensus::set_consensus_chain_id_for_tests(TESTNET);
    block.sign_block(&key);
    let testnet_hash = block.compute_hash();
    assert!(
        block.verify_proposer_signature(),
        "the signature verifies on its own chain"
    );

    // On the MAINNET the very same body has a different hash...
    crate::consensus::set_consensus_chain_id_for_tests(MAINNET);
    assert_ne!(
        testnet_hash,
        block.compute_hash(),
        "the block hash must commit to the chain id"
    );
    // ... and the testnet signature does not verify there.
    assert!(
        !block.verify_proposer_signature(),
        "a testnet block signature must NOT verify under a different chain id"
    );

    // Restore the frozen default for the rest of this thread.
    crate::consensus::set_consensus_chain_id_for_tests(0);
}

/// `sign_block_with_falcon` round-trips through the Falcon-only proposal
/// verifier. The caller registers the Falcon key first (the helper does
/// not); the Ed-only refusal is pinned in `consensus.rs`
/// (`proposer_signature_refuses_ed_only_no_classical_fallback`) and is
/// not re-asserted here.
#[test]
fn sign_block_with_falcon_round_trips_through_proposal_verifier() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let fk = FalconKeypair::generate_from_seed(0xB1);
    let proposer = sk.verifying_key().to_bytes();
    crate::consensus::register_validator_pq_key(
        proposer,
        PqScheme::Falcon512,
        fk.public_key.clone(),
    );
    let mut block = block_with(vec![]);
    block.proposer = proposer;
    block.sign_block_with_falcon(&sk, &fk);
    assert_eq!(
        block.validator_signatures.len(),
        2,
        "propose shape: (ed_id, ed_sig) then (falcon_id, falcon_sig)"
    );
    assert_eq!(block.validator_signatures[0].0, proposer);
    assert_eq!(block.validator_signatures[1].0, fk.validator_id());
    assert!(
        crate::consensus::verify_proposer_signature(&block),
        "Falcon-signed block must verify under the registered key"
    );
}

#[test]
fn verify_signatures_verifies_falcon_proposer_without_ed25519_bypass() {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk2 = SigningKey::generate(&mut rand::rngs::OsRng);
    let fk = FalconKeypair::generate_from_seed(0xB2);
    let proposer = sk.verifying_key().to_bytes();
    crate::consensus::register_validator_pq_key(
        proposer,
        PqScheme::Falcon512,
        fk.public_key.clone(),
    );

    // Pure Falcon-512 proposer signature (no Ed25519 signature at all).
    let mut pure_falcon = block_with(vec![]);
    pure_falcon.proposer = proposer;
    let hash = pure_falcon.compute_hash();
    pure_falcon
        .validator_signatures
        .push((fk.validator_id(), fk.sign(&hash)));
    assert!(
        pure_falcon.verify_signatures(1),
        "pure Falcon-512 proposer signature must verify for quorum 1"
    );
    assert!(
        !pure_falcon.verify_signatures(2),
        "single Falcon-512 proposer must not satisfy quorum 2"
    );

    // Dual-signed (Ed25519 + Falcon-512): proposer still counts once, and
    // tampering the Falcon signature fails closed (no Ed25519 bypass).
    let mut dual = block_with(vec![]);
    dual.proposer = proposer;
    dual.sign_block_with_falcon(&sk, &fk);
    assert!(dual.verify_signatures(1));
    assert!(
        !dual.verify_signatures(2),
        "Ed25519 + Falcon-512 from the same proposer must count as 1 distinct signer"
    );

    let mut tampered = dual.clone();
    tampered.validator_signatures[1].1[0] ^= 0xFF;
    assert!(
        !tampered.verify_signatures(1),
        "tampered Falcon-512 signature must fail even if Ed25519 signature is valid"
    );

    // Adding a second distinct validator satisfies quorum 2.
    dual.sign_block(&sk2);
    assert!(dual.verify_signatures(2));
}

/// Backward compatibility: a block persisted BEFORE the shard-head field
/// existed (its byte stream ends right after `precommit_qc`) must still
/// decode — as a block with NO shard heads.
#[test]
fn legacy_block_bytes_still_decode() {
    #[derive(serde::Serialize)]
    struct LegacyBlock {
        shard_id: ShardId,
        height: u64,
        prev_hash: [u8; 32],
        state_root: CellHash,
        transactions: Vec<Transaction>,
        cross_shard_out: Vec<CrossShardMessage>,
        timestamp: u64,
        proposer: [u8; 32],
        validator_signatures: Vec<([u8; 32], Vec<u8>)>,
        precommit_qc: Option<crate::consensus::QuorumCertificate>,
    }

    let legacy = LegacyBlock {
        shard_id: MASTERCHAIN_SHARD,
        height: 3,
        prev_hash: [0x11; 32],
        state_root: [0x22; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 42,
        proposer: [0x33; 32],
        validator_signatures: vec![],
        precommit_qc: None,
    };
    let bytes = bincode::serialize(&legacy).expect("legacy block must encode");
    let bytes_len_legacy = bytes.len();
    // The LEGACY shape is tolerated on the STORE path only; the wire
    // decodes strictly (audit W6.4b).
    let decoded: Block = with_legacy_block_tolerance(|| bincode::deserialize(&bytes))
        .expect("legacy block must decode");
    assert_eq!(decoded.height, 3);
    assert_eq!(decoded.state_root, [0x22; 32]);
    assert!(
        decoded.shard_headers.is_empty(),
        "a legacy block commits to no shard heads"
    );
    assert_eq!(
        decoded.order_merkle_root, [0u8; 32],
        "a legacy block commits to no transaction order"
    );
    assert!(
        decoded.last_qc.is_none(),
        "a legacy block carries no canonical downtime evidence"
    );
    assert_eq!(
        decoded.mmr_epoch_root, [0u8; 32],
        "a legacy block commits to no epoch MMR root"
    );
    // The block HASH is untouched by the extension: a legacy block still
    // rehashes to the hash it had before the field existed (this is what
    // keeps an existing chain valid).
    let rebuilt = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: 3,
        prev_hash: [0x11; 32],
        state_root: [0x22; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 42,
        proposer: [0x33; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32], // MMR: zero commits to no epoch; the legacy hash is preserved (see Block::mmr_epoch_root docs).
    };
    assert_eq!(decoded.compute_hash(), rebuilt.compute_hash());

    // A block WITH the field round-trips through bincode.
    let modern = block_with(vec![head(1, 5, 0x01)]);
    let bytes = bincode::serialize(&modern).expect("modern block must encode");
    let decoded: Block = bincode::deserialize(&bytes).expect("modern block must decode");
    assert_eq!(decoded.shard_headers, modern.shard_headers);
    assert_eq!(decoded.compute_hash(), modern.compute_hash());

    // The legacy bytes are a PREFIX of the new encoding: the only
    // difference is the trailing shard-head set (empty => 8 bytes), the
    // trailing order commitment (32 bytes), the trailing epoch-key
    // commitment (32 bytes), the trailing canonical-evidence QC
    // (`None` => 1-byte option tag) and the trailing epoch-MMR root
    // (32 bytes).
    let empty = block_with(vec![]);
    let empty_bytes = bincode::serialize(&empty).expect("empty encodes");
    assert_eq!(
        empty_bytes.len(),
        bytes_len_legacy + 8 + 32 + 32 + 1 + 32,
        "the shard-head set adds its (empty) length prefix, the order root adds 32 bytes, \
         the epoch-key commitment adds 32 bytes, the absent evidence QC adds its 1-byte tag \
         and the zero epoch-MMR root adds 32 bytes"
    );
}

/// The transaction-ORDER commitment is inside the block hash: the quorum
/// that signs the block hash signs the ORDER, so a proposer cannot change
/// the order of a block that has already been voted on.
#[test]
fn block_hash_commits_the_transaction_order() {
    let base = block_with(vec![]);
    // The all-zero root (no commitment) is the legacy/empty shape: it is
    // NOT mixed into the hash, so legacy blocks keep their hash.
    assert_eq!(base.order_merkle_root, [0u8; 32]);

    let mut committed = base.clone();
    committed.order_merkle_root = [0x42; 32];
    assert_ne!(
        base.compute_hash(),
        committed.compute_hash(),
        "the order commitment must be inside the signed block hash"
    );

    // Two different commitments are two different blocks.
    let mut other = base.clone();
    other.order_merkle_root = [0x43; 32];
    assert_ne!(committed.compute_hash(), other.compute_hash());

    // The commitment survives the bincode round-trip.
    let bytes = bincode::serialize(&committed).expect("must encode");
    let decoded: Block = bincode::deserialize(&bytes).expect("must decode");
    assert_eq!(decoded.order_merkle_root, [0x42; 32]);
    assert_eq!(decoded.compute_hash(), committed.compute_hash());
}

/// The registry remembers the newest finalized header per shard and
/// publishes only the WORKCHAIN ones, in ascending shard order.
#[test]
fn registry_publishes_the_latest_workchain_head() {
    let mut reg = FinalizedHeaderRegistry::default();
    reg.note_finalized_commitment(head(1, 5, 0x01));
    reg.note_finalized_commitment(head(2, 3, 0x02));
    // The masterchain's own head is never published (a block cannot
    // commit to its own head).
    reg.note_finalized_commitment(head(MASTERCHAIN_SHARD, 9, 0x03));

    let published = reg.workchain_headers();
    assert_eq!(published.len(), 2);
    assert_eq!(published[0].shard_id, 1);
    assert_eq!(published[1].shard_id, 2, "ascending shard order");

    // A NEWER header replaces the old one...
    reg.note_finalized_commitment(head(1, 6, 0x04));
    assert_eq!(reg.latest_header(1).map(|h| h.height), Some(6));

    // ...and an OLDER one never rolls the published head back.
    reg.note_finalized_commitment(head(1, 2, 0x05));
    assert_eq!(reg.latest_header(1).map(|h| h.height), Some(6));

    // The anchor map is updated as well (cross-shard inclusion anchoring).
    assert!(reg.anchor_holds(1, &[0x04; 32], &[0x05; 32]));
}

// -----------------------------------------------------------------------
// TAIL-1: batched receipt hashing.
//
// `compute_tx_hashes_batched` must be byte-identical to mapping
// `compute_tx_hash` (same per-transaction update sequence, `finalize_reset`
// restarts the hasher to the same initial state). No wire-format, quorum
// or state-transition change: the hashes ARE the transaction identities
// the receipts file, and these tests pin them equal.
// -----------------------------------------------------------------------

fn batch_test_txs(n: usize) -> Vec<Transaction> {
    use crate::svm::OpCode;
    let mut txs = Vec::with_capacity(n);
    for i in 0..n {
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&(i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_be_bytes());
        seed[8] = 0xB7;
        let sk = SigningKey::from_bytes(&seed);
        // Vary the payload shape (empty / small / multi-op) and the bid
        // so every conditional commitment arm is covered.
        let payload = match i % 4 {
            0 => vec![],
            1 => vec![OpCode::Push(i as u64), OpCode::Push(1), OpCode::Add],
            2 => vec![OpCode::Transfer {
                recipient: [i as u8; 32],
                amount: i as u64,
            }],
            _ => vec![OpCode::Nop, OpCode::Push(i as u64), OpCode::Pop],
        };
        let bid = if i % 5 == 0 { i as u64 } else { 0 };
        txs.push(Transaction::sign_with_payload_and_priority(
            &sk,
            [(i as u8).wrapping_add(1); 32],
            i as u64 * 3,
            21_000 + (i as u64 % 7),
            i as u64,
            0,
            0,
            payload,
            bid,
        ));
    }
    txs
}

#[test]
fn batched_hashes_equal_single_hashes() {
    let txs = batch_test_txs(512);
    let batched = Transaction::compute_tx_hashes_batched(&txs);
    assert_eq!(batched.len(), txs.len());
    for (i, tx) in txs.iter().enumerate() {
        assert_eq!(
            batched[i],
            tx.compute_tx_hash(),
            "batched hash of tx {i} must equal its single hash"
        );
    }
    // Empty input hashes to an empty output (no panic, no allocation).
    assert!(Transaction::compute_tx_hashes_batched(&[]).is_empty());
}

// -----------------------------------------------------------------------
// XSHARD INTEGRITY: msg_id recompute at every untrusted boundary +
// full-message commitment in the block hash.
//
// The carried `msg_id` is assigned at construction and never recomputed
// on decode/apply, so every boundary recomputes it (domain-aware) and
// refuses a mismatch. The block hash binds the full message bytes
// alongside the `msg_id` list — for message-carrying blocks only, so
// empty-cross-shard blocks hash byte-identically to before.
// -----------------------------------------------------------------------

fn xshard_test_tx() -> Transaction {
    Transaction {
        from: [0x11u8; 32],
        to: [0x22u8; 32],
        amount: 1_000,
        gas_limit: 21_000,
        nonce: 7,
        source_shard: 1,
        target_shard: 2,
        signature: vec![0x5Au8; 64],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    }
}

#[test]
fn xshard_msg_id_matches_recompute_for_every_constructor() {
    let tx = xshard_test_tx();
    let root = [0x33u8; 32];
    let anchor = [0x44u8; 32];

    // Legacy wire constructor.
    let m = CrossShardMessage::new(1, 2, tx.clone(), root, anchor, None);
    assert!(m.verify_msg_id(), "new() id must match the recompute");
    assert_eq!(m.msg_id, m.expected_msg_id());

    // Locally-trusted constructor assigns the same construction id.
    let t = CrossShardMessage::new_trusted(1, 2, tx.clone(), root, anchor);
    assert!(
        t.verify_msg_id(),
        "new_trusted() id must match the recompute"
    );
    assert!(
        t.trusted,
        "new_trusted is the ONLY constructor that sets trust"
    );

    // Every 2PC phase uses the XPC2 domain with its phase byte.
    for phase in [
        crate::xshard2pc::XPC_PREPARE,
        crate::xshard2pc::XPC_PREPARE_ACK,
        crate::xshard2pc::XPC_COMMIT,
        crate::xshard2pc::XPC_ABORT_REQUEST,
        crate::xshard2pc::XPC_ABORT_ACK,
    ] {
        let x = CrossShardMessage::new_xpc(phase, 1, 2, tx.clone(), root, anchor, None);
        assert!(
            x.verify_msg_id(),
            "new_xpc() id must match the recompute for phase {phase}"
        );
        // The phased id can never alias the legacy id of the same body.
        assert_ne!(
            x.msg_id, m.msg_id,
            "a 2PC record must never share the legacy id"
        );
    }

    // Ack/bounce linkage records use the legacy domain.
    let ack = CrossShardMessage::new_ack(tx.clone(), anchor);
    assert!(ack.verify_msg_id(), "new_ack() id must match the recompute");
    let bounce = CrossShardMessage::new_bounce(tx.clone(), anchor);
    assert!(
        bounce.verify_msg_id(),
        "new_bounce() id must match the recompute"
    );

    // No other constructor sets trust: the wire always arrives untrusted.
    assert!(!m.trusted && !ack.trusted && !bounce.trusted);
}

#[test]
fn xshard_rebound_msg_id_is_refused() {
    let tx = xshard_test_tx();
    let root = [0x33u8; 32];
    let anchor = [0x44u8; 32];

    // A forged id (bit flip) fails the recompute ...
    let mut forged = CrossShardMessage::new(1, 2, tx.clone(), root, anchor, None);
    forged.msg_id[0] ^= 0xFF;
    assert!(!forged.verify_msg_id(), "a forged msg_id must be refused");
    // ... and therefore fails the proof check too, even with no proof to
    // evaluate: the id gate runs first.
    assert!(
        !forged.verify_inclusion_strict(),
        "a forged id must fail strict inclusion"
    );
    assert!(
        !forged.verify_xpc_proof(&[crate::xshard2pc::XpcPhase::Prepared]),
        "a forged id must fail the XPC proof check"
    );

    // A body swap under the original id (amount changed after
    // construction) also fails the recompute.
    let mut swapped = CrossShardMessage::new(1, 2, tx.clone(), root, anchor, None);
    swapped.tx.amount += 1;
    assert!(
        !swapped.verify_msg_id(),
        "a body swapped under a stale id must be refused"
    );

    // A phase flip (legacy <-> 2PC) fails: the recompute follows the
    // carried phase while construction followed the original domain.
    let mut flipped = CrossShardMessage::new(1, 2, tx.clone(), root, anchor, None);
    flipped.xpc_phase = crate::xshard2pc::XPC_PREPARE;
    assert!(
        !flipped.verify_msg_id(),
        "a flipped phase must fail the recompute"
    );
    let mut flipped_back = CrossShardMessage::new_xpc(
        crate::xshard2pc::XPC_PREPARE,
        1,
        2,
        tx.clone(),
        root,
        anchor,
        None,
    );
    flipped_back.xpc_phase = crate::xshard2pc::XPC_LEGACY;
    assert!(
        !flipped_back.verify_msg_id(),
        "a zeroed phase must fail the recompute"
    );
}

#[test]
fn xshard_empty_block_hash_is_byte_identical_to_the_legacy_preimage() {
    // VERSION RULE proof: an empty-`cross_shard_out` block must hash
    // EXACTLY as it did before the full-message commitment existed. The
    // legacy preimage is hashed manually here (no call into the new
    // section), so equality proves byte-identity, not self-consistency.
    let block = Block {
        shard_id: 1,
        height: 42,
        prev_hash: [0xABu8; 32],
        state_root: [0xCDu8; 32],
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_700_000_500,
        proposer: [0xEFu8; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
    };
    let mut legacy = Sha256::new();
    legacy.update(b"STELLEREUM_BLOCK_V3");
    legacy.update(crate::consensus::consensus_chain_id().to_be_bytes());
    legacy.update(block.shard_id.to_be_bytes());
    legacy.update(block.height.to_be_bytes());
    legacy.update(block.prev_hash);
    legacy.update(block.state_root);
    legacy.update(0u32.to_be_bytes());
    legacy.update(0u32.to_be_bytes());
    legacy.update(block.timestamp.to_be_bytes());
    legacy.update(block.proposer);
    let expected: [u8; 32] = legacy.finalize().into();
    assert_eq!(
        block.compute_hash(),
        expected,
        "an empty-cross-shard block must hash byte-identically to the legacy preimage"
    );
}

#[test]
fn xshard_full_message_commitment_binds_the_body_beyond_msg_id() {
    let tx = xshard_test_tx();
    let msg = CrossShardMessage::new(1, 2, tx, [0x33u8; 32], [0x44u8; 32], None);
    let block = Block {
        shard_id: 1,
        height: 9,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: vec![],
        cross_shard_out: vec![msg.clone()],
        timestamp: 1,
        proposer: [0u8; 32],
        validator_signatures: vec![],
        precommit_qc: None,
        last_qc: None,
        shard_headers: vec![],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
    };
    let honest_hash = block.compute_hash();

    // A body swap that keeps the stale `msg_id` MUST move the block hash:
    // the commitment binds the body, not just the id.
    let mut tampered = block.clone();
    tampered.cross_shard_out[0].tx.amount += 1;
    assert_ne!(
        tampered.compute_hash(),
        honest_hash,
        "a message body swapped under a stale id must move the block hash"
    );
    assert_ne!(
        tampered.cross_shard_out[0].message_commitment(),
        msg.message_commitment(),
        "the per-message commitment must bind the body"
    );

    // The commitment is deterministic: same body, same digest.
    assert_eq!(
        msg.message_commitment(),
        msg.message_commitment(),
        "the commitment must be a pure function of the body"
    );
    assert_eq!(
        msg.commitment_bytes(),
        CrossShardMessage::new(1, 2, xshard_test_tx(), [0x33u8; 32], [0x44u8; 32], None)
            .commitment_bytes(),
        "identical bodies commit identically"
    );
}

#[test]
fn xshard_commitment_ignores_the_local_trusted_flag() {
    // Consensus-safety: the producer holds `trusted == true` in-process
    // while every adopter holds `false` for the same body. Covering the
    // flag would fork the block hash between honest nodes, so it must be
    // excluded — while verification still ignores it on untrusted paths.
    let tx = xshard_test_tx();
    let mut msg = CrossShardMessage::new(1, 2, tx, [0x33u8; 32], [0x44u8; 32], None);
    let untrusted_commitment = msg.message_commitment();
    msg.trusted = true;
    assert_eq!(
        msg.message_commitment(),
        untrusted_commitment,
        "the local trusted flag must not move the commitment"
    );
    // ... but the flag itself round-trips on the wire (decode sites and
    // the adoption boundary force it false; see sync.rs).
    let bytes = bincode::serialize(&msg).expect("message must encode");
    let decoded: CrossShardMessage = bincode::deserialize(&bytes).expect("must decode");
    assert!(
        decoded.trusted,
        "wire bytes preserve the bit (clearing is the boundary's job)"
    );
    assert!(
        decoded.verify_msg_id(),
        "the id survives the round-trip (it covers no wire-mutable bit)"
    );
}

/// Perf: single vs batched hashing over a block-sized batch. Prints
/// measured ms for the report; the hard assertion is byte equality.
#[test]
fn perf_batched_vs_single_hashing() {
    let txs = batch_test_txs(20_000);
    // Warm up, then measure the per-transaction path.
    let t0 = std::time::Instant::now();
    let mut single = Vec::with_capacity(txs.len());
    for tx in &txs {
        single.push(tx.compute_tx_hash());
    }
    let single_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let t0 = std::time::Instant::now();
    let batched = Transaction::compute_tx_hashes_batched(&txs);
    let batched_ms = t0.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(batched, single, "batched output must equal single output");
    eprintln!(
        "[perf] tx hashing 20k txs: single={single_ms:.2}ms batched={batched_ms:.2}ms speedup={:.2}x",
        if batched_ms > 0.0 { single_ms / batched_ms } else { f64::INFINITY },
    );
}

#[test]
fn block_compute_hash_matches_single_tx_hash_reference() {
    for count in [0usize, 1, 32] {
        let txs = batch_test_txs(count);
        let block = Block::new_for_test(1, 42, [0xAAu8; 32], [0xBBu8; 32], txs);
        let mut ref_hasher = Sha256::new();
        ref_hasher.update(b"STELLEREUM_BLOCK_V3");
        ref_hasher.update(crate::consensus::consensus_chain_id().to_be_bytes());
        ref_hasher.update(block.shard_id.to_be_bytes());
        ref_hasher.update(block.height.to_be_bytes());
        ref_hasher.update(block.prev_hash);
        ref_hasher.update(block.state_root);
        ref_hasher.update((block.transactions.len() as u32).to_be_bytes());
        for tx in &block.transactions {
            ref_hasher.update(tx.compute_tx_hash());
        }
        if block.order_merkle_root != [0u8; 32] {
            ref_hasher.update(ORDER_MERKLE_COMMITMENT_TAG);
            ref_hasher.update(block.order_merkle_root);
        }
        ref_hasher.update((block.cross_shard_out.len() as u32).to_be_bytes());
        ref_hasher.update(block.timestamp.to_be_bytes());
        ref_hasher.update(block.proposer);
        let expected: [u8; 32] = ref_hasher.finalize().into();
        assert_eq!(
            block.compute_hash(),
            expected,
            "Block::compute_hash must stay byte-identical for {count} txs"
        );
    }
}
