//! Differential tests cross-checking `stellereum-verifier` against `stellereum`.

use stellereum::cn_vrf::CommitCarrierV3;
use stellereum::consensus::{consensus_chain_id, QuorumCertificate, VoteKind};
use stellereum::mev::compute_order_merkle_root as ref_order_merkle_root;
use stellereum::minroot_vdf::MinRootProof;
use stellereum::post_quantum::{
    derive_pq_address as ref_derive_pq_address, verify_pq_signature as ref_verify_pq_signature,
    FalconKeypair, PqScheme, DEFAULT_SALT,
};
use stellereum::protocol::timestamp_within_bounds as ref_timestamp_within_bounds;
use stellereum::sharding::{
    set_header_commit_activation_override, Block, CnVrfV3BlockPayload, CrossShardMessage,
    EpochVdfBeacon, ShardHeaderCommitment, Transaction,
};
use stellereum::svm::OpCode;

use stellereum_verifier::block_hash::{
    body_commitment, compute_block_hash, compute_block_hash_at, compute_order_merkle_root,
    timestamp_within_bounds, value_id, value_id_at, verify_cross_shard_msg_ids,
    verify_order_merkle_root,
};
use stellereum_verifier::falcon512::{
    derive_pq_address, verify_falcon512, FALCON512_SCHEME_ID, FALCON512_SIG_LEN,
};
use stellereum_verifier::wire::{
    decode_block_v7_strict, encode_block_v7_canonical, MAX_BLOCK_BYTES,
};

struct HeaderCommitOverrideGuard;

impl Drop for HeaderCommitOverrideGuard {
    fn drop(&mut self) {
        set_header_commit_activation_override(None);
    }
}

fn build_pq_tx(
    kp: &FalconKeypair,
    nonce: u64,
    amount: u64,
    payload: Vec<OpCode>,
    priority_fee_per_gas: u64,
    chain_id: Option<u64>,
) -> Transaction {
    let pk = kp.public_key().to_vec();
    let msg = format!("diff-tx-{nonce}-{amount}-{priority_fee_per_gas}").into_bytes();
    let sig = kp.sign(&msg);
    let mut tx = match chain_id {
        Some(cid) => Transaction::new_pq_explicit_with_chain(
            PqScheme::Falcon512,
            pk,
            sig,
            [0x42u8; 32],
            amount,
            50_000,
            nonce,
            0,
            1,
            payload,
            &DEFAULT_SALT,
            cid,
        ),
        None => Transaction::new_pq_explicit(
            PqScheme::Falcon512,
            pk,
            sig,
            [0x42u8; 32],
            amount,
            50_000,
            nonce,
            0,
            1,
            payload,
            &DEFAULT_SALT,
        ),
    };
    tx.priority_fee_per_gas = priority_fee_per_gas;
    tx
}

fn round_trip_block(ref_block: &Block) -> stellereum_verifier::wire::Block {
    let wire_bytes = bincode::serialize(ref_block).expect("stellereum Block::serialize");
    let decoded = decode_block_v7_strict(&wire_bytes).expect("decode_block_v7_strict");
    let reencoded = encode_block_v7_canonical(&decoded).expect("encode_block_v7_canonical");
    assert_eq!(
        reencoded, wire_bytes,
        "clean-room re-encode must match stellereum bytes"
    );
    decoded
}

#[test]
fn diff_falcon512_sign_and_rejections() {
    let kp = FalconKeypair::generate_from_seed_bytes(&[0x41u8; 32]);
    let pk = kp.public_key();
    let msg = b"Stellereum Wave 15 Falcon-512 clean-room differential test";
    let sig = kp.sign(msg);
    assert_eq!(sig.len(), FALCON512_SIG_LEN);
    assert_eq!(sig[0], 0x29);

    // Address derivation parity.
    assert_eq!(
        derive_pq_address(FALCON512_SCHEME_ID, pk, &DEFAULT_SALT),
        ref_derive_pq_address(PqScheme::Falcon512, pk, &DEFAULT_SALT)
    );
    let custom_salt = [0xA5u8; 16];
    assert_eq!(
        derive_pq_address(FALCON512_SCHEME_ID, pk, &custom_salt),
        ref_derive_pq_address(PqScheme::Falcon512, pk, &custom_salt)
    );

    // Valid 0x29 signature passes both.
    assert!(ref_verify_pq_signature(PqScheme::Falcon512, pk, msg, &sig));
    assert!(verify_falcon512(pk, msg, &sig));

    // Tampered message rejected by both.
    let tampered_msg = b"Stellereum Wave 15 Falcon-512 clean-room differential TEST";
    assert!(!ref_verify_pq_signature(
        PqScheme::Falcon512,
        pk,
        tampered_msg,
        &sig
    ));
    assert!(!verify_falcon512(pk, tampered_msg, &sig));

    // PQClean 0x39 header rejected by both.
    let mut pqclean_sig = sig.clone();
    pqclean_sig[0] = 0x39;
    assert!(!ref_verify_pq_signature(
        PqScheme::Falcon512,
        pk,
        msg,
        &pqclean_sig
    ));
    assert!(!verify_falcon512(pk, msg, &pqclean_sig));

    // Bad trailing pad rejected by both.
    let mut bad_pad_sig = sig.clone();
    bad_pad_sig[FALCON512_SIG_LEN - 1] ^= 0x01;
    assert!(!ref_verify_pq_signature(
        PqScheme::Falcon512,
        pk,
        msg,
        &bad_pad_sig
    ));
    assert!(!verify_falcon512(pk, msg, &bad_pad_sig));

    // All-zero nonce rejected by both.
    let mut zero_nonce_sig = sig.clone();
    zero_nonce_sig[1..41].fill(0);
    assert!(!ref_verify_pq_signature(
        PqScheme::Falcon512,
        pk,
        msg,
        &zero_nonce_sig
    ));
    assert!(!verify_falcon512(pk, msg, &zero_nonce_sig));

    // Non-canonical pubkey header rejected by both.
    let mut bad_pk = pk.to_vec();
    bad_pk[0] = 0x19;
    assert!(!ref_verify_pq_signature(
        PqScheme::Falcon512,
        &bad_pk,
        msg,
        &sig
    ));
    assert!(!verify_falcon512(&bad_pk, msg, &sig));
}

#[test]
fn diff_block_v7_strict_wire_roundtrip_and_rejections() {
    let kp = FalconKeypair::generate_from_seed_bytes(&[0x42u8; 32]);
    let tx = build_pq_tx(
        &kp,
        1,
        1_000,
        vec![OpCode::Push(7), OpCode::Halt],
        25,
        Some(consensus_chain_id()),
    );
    let mut block = Block {
        shard_id: 0,
        height: 12,
        prev_hash: [0x11u8; 32],
        state_root: [0x22u8; 32],
        ..Block::default()
    }
    .with_transactions(vec![tx])
    .with_timestamp(1_700_000_012)
    .with_proposer([0x33u8; 32])
    .with_round(2)
    .with_shard_headers(vec![ShardHeaderCommitment {
        shard_id: 1,
        height: 11,
        block_hash: [0x44u8; 32],
        state_root: [0x55u8; 32],
        timestamp: 1_700_000_010,
        minted_total_nano: 999_000,
    }]);
    block.epoch_key_commitment = [0x66u8; 32];
    block.mmr_epoch_root = [0x77u8; 32];

    let bytes = bincode::serialize(&block).unwrap();
    let decoded = round_trip_block(&block);
    assert_eq!(decoded.height, 12);
    assert_eq!(decoded.round, 2);
    assert_eq!(decoded.transactions[0].priority_fee_per_gas, 25);

    // Reject empty.
    assert!(decode_block_v7_strict(&[]).is_err());

    // Reject truncated (including missing trailing `round` u32 — no legacy tolerance).
    assert!(decode_block_v7_strict(&bytes[..bytes.len() - 1]).is_err());
    assert!(decode_block_v7_strict(&bytes[..bytes.len() - 4]).is_err());

    // Reject trailing bytes.
    let mut with_trailing = bytes.clone();
    with_trailing.push(0x00);
    assert!(decode_block_v7_strict(&with_trailing).is_err());

    // Reject oversized > 32 MiB.
    assert_eq!(MAX_BLOCK_BYTES, 32 * 1024 * 1024);

    // Reject non-canonical shard_headers (unsorted / duplicate / masterchain shard_id == 0).
    let mut unsorted = block.clone();
    unsorted.shard_headers = vec![
        ShardHeaderCommitment {
            shard_id: 2,
            height: 1,
            block_hash: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: 10,
            minted_total_nano: 0,
        },
        ShardHeaderCommitment {
            shard_id: 1,
            height: 1,
            block_hash: [3u8; 32],
            state_root: [4u8; 32],
            timestamp: 10,
            minted_total_nano: 0,
        },
    ];
    let unsorted_bytes = bincode::serialize(&unsorted).unwrap();
    assert!(decode_block_v7_strict(&unsorted_bytes).is_err());

    let mut master_sh = block.clone();
    master_sh.shard_headers[0].shard_id = 0;
    let master_bytes = bincode::serialize(&master_sh).unwrap();
    assert!(decode_block_v7_strict(&master_bytes).is_err());
}

#[test]
fn diff_block_hashes_value_id_commitments_v4_and_v3() {
    let _guard = HeaderCommitOverrideGuard;
    let chain_id = consensus_chain_id();
    let kp = FalconKeypair::generate_from_seed_bytes(&[0x43u8; 32]);

    // 1. Empty block (v4 and v3).
    let empty_block = Block::default();
    let empty_v = round_trip_block(&empty_block);
    set_header_commit_activation_override(None);
    assert_eq!(
        compute_block_hash(&empty_v, chain_id),
        empty_block.compute_hash()
    );
    assert_eq!(value_id(&empty_v, chain_id), empty_block.value_id());
    assert_eq!(body_commitment(&empty_v), empty_block.body_commitment());
    assert_eq!(
        empty_v.header().compute_hash(chain_id),
        empty_block.header().compute_hash()
    );

    set_header_commit_activation_override(Some(u64::MAX));
    assert_eq!(
        compute_block_hash_at(&empty_v, chain_id, u64::MAX),
        empty_block.compute_hash()
    );
    assert_eq!(
        value_id_at(&empty_v, chain_id, u64::MAX),
        empty_block.value_id()
    );

    // 2. Populated transactions (plain PQ1, SVM OpCode payload, non-zero priority fee) + order_merkle_root.
    let tx1 = build_pq_tx(&kp, 0, 500, Vec::new(), 0, None);
    let tx2 = build_pq_tx(
        &kp,
        1,
        1_500,
        vec![
            OpCode::Push(42),
            OpCode::Transfer {
                recipient: [0x99u8; 32],
                amount: 100,
            },
            OpCode::Halt,
        ],
        77,
        Some(chain_id),
    );
    let tx_list = vec![tx1.clone(), tx2.clone()];

    // 3. Cross-shard outbound messages (legacy + 2PC phase != 0).
    let xshard_legacy = CrossShardMessage::new(0, 1, tx1.clone(), [0x12u8; 32], [0x34u8; 32], None)
        .with_source_balance(10_000);
    let xshard_xpc = CrossShardMessage::new_xpc(
        stellereum::xshard2pc::XPC_COMMIT,
        0,
        1,
        tx2.clone(),
        [0x56u8; 32],
        [0x78u8; 32],
        None,
    );

    // 4. Shard headers (both minted_total_nano == 0 and != 0).
    let shard_headers = vec![
        ShardHeaderCommitment {
            shard_id: 1,
            height: 41,
            block_hash: [0xA1u8; 32],
            state_root: [0xA2u8; 32],
            timestamp: 1_700_000_041,
            minted_total_nano: 0,
        },
        ShardHeaderCommitment {
            shard_id: 2,
            height: 19,
            block_hash: [0xB1u8; 32],
            state_root: [0xB2u8; 32],
            timestamp: 1_700_000_040,
            minted_total_nano: 123_456_789,
        },
    ];

    // 5. last_qc with unsorted signatures (tests canonical sorting in both v4 & v3).
    let last_qc = QuorumCertificate {
        height: 41,
        round: 3,
        kind: VoteKind::Precommit,
        block_hash: Some([0xC3u8; 32]),
        signatures: vec![
            ([0xF0u8; 32], vec![1u8; 64]),
            ([0x10u8; 32], vec![2u8; 64]),
            ([0x10u8; 32], vec![1u8; 64]),
        ],
        shard_id: 0,
    };

    // 6. cnvrf_v3 payload with reveal, unsorted commits, and epoch VDF beacon.
    let carrier_b = CommitCarrierV3 {
        validator_id: [0xE2u8; 32],
        epoch_n: 5,
        anchors: [[0x22u8; 48]; 16],
        sig: [0x29u8; 666],
    };
    let carrier_a = CommitCarrierV3 {
        validator_id: [0xE1u8; 32],
        epoch_n: 5,
        anchors: [[0x11u8; 48]; 16],
        sig: [0x29u8; 666],
    };
    let cnvrf = CnVrfV3BlockPayload {
        reveal: Some([0x5Au8; 48]),
        commits: vec![carrier_b, carrier_a],
        epoch_vdf: Some(EpochVdfBeacon {
            epoch: 4,
            raw_seed: [0x6Bu8; 48],
            proof: MinRootProof {
                steps: 100,
                final_xy: ([0x7Cu8; 32], [0x8Du8; 32]),
                checkpoints: vec![(50, [0x9Eu8; 32], [0xAFu8; 32])],
            },
        }),
    };

    // 7. Full block with non-zero round, epoch_key_commitment, mmr_epoch_root.
    let mut full_block = Block {
        shard_id: 0,
        height: 42,
        prev_hash: [0x01u8; 32],
        state_root: [0x02u8; 32],
        ..Block::default()
    }
    .with_transactions(tx_list.clone())
    .with_cross_shard_out(vec![xshard_legacy, xshard_xpc])
    .with_shard_headers(shard_headers)
    .with_timestamp(1_700_000_042)
    .with_proposer([0x03u8; 32])
    .with_round(7)
    .with_epoch_mmr_root([0x04u8; 32]);
    full_block.epoch_key_commitment = [0x05u8; 32];
    full_block.last_qc = Some(last_qc);
    full_block.cnvrf_v3 = Some(cnvrf);

    let full_v = round_trip_block(&full_block);

    // Order Merkle root parity.
    assert_eq!(
        compute_order_merkle_root(&full_v.transactions),
        ref_order_merkle_root(&full_block.transactions)
    );
    assert!(verify_order_merkle_root(&full_v));

    // Cross-shard msg_id & message_commitment parity.
    assert!(verify_cross_shard_msg_ids(&full_v));
    for (v_msg, r_msg) in full_v
        .cross_shard_out
        .iter()
        .zip(full_block.cross_shard_out.iter())
    {
        assert_eq!(v_msg.message_commitment(), r_msg.message_commitment());
    }

    // v4 / Ruleset v7 parity (active at height 42).
    set_header_commit_activation_override(None);
    let v4_hash_verifier = compute_block_hash(&full_v, chain_id);
    let v4_hash_ref = full_block.compute_hash();
    assert_eq!(v4_hash_verifier, v4_hash_ref);

    let v4_vid_verifier = value_id(&full_v, chain_id);
    let v4_vid_ref = full_block.value_id();
    assert_eq!(v4_vid_verifier, v4_vid_ref);
    assert_ne!(
        v4_hash_verifier, v4_vid_verifier,
        "non-zero round must distinguish compute_hash from value_id"
    );
    assert_eq!(body_commitment(&full_v), full_block.body_commitment());
    assert_eq!(
        full_v.header().compute_hash(chain_id),
        full_block.header().compute_hash()
    );

    // v3 fallback parity (`HEADER_COMMIT_ACTIVATION_HEIGHT = u64::MAX`).
    set_header_commit_activation_override(Some(u64::MAX));
    let v3_hash_verifier = compute_block_hash_at(&full_v, chain_id, u64::MAX);
    let v3_hash_ref = full_block.compute_hash();
    assert_eq!(v3_hash_verifier, v3_hash_ref);
    assert_ne!(
        v3_hash_verifier, v4_hash_verifier,
        "v3 and v4 block hashes must differ"
    );

    let v3_vid_verifier = value_id_at(&full_v, chain_id, u64::MAX);
    let v3_vid_ref = full_block.value_id();
    assert_eq!(v3_vid_verifier, v3_vid_ref);
    assert_ne!(v3_hash_verifier, v3_vid_verifier);
}

#[test]
fn diff_timestamp_within_bounds() {
    let cases = [
        (1_000, 999),
        (1_000, 1_000),
        (1_000, 4_600),
        (1_000, 4_601),
        (u64::MAX - 10, u64::MAX),
        (u64::MAX, u64::MAX - 1),
    ];
    for (parent_ts, block_ts) in cases {
        assert_eq!(
            timestamp_within_bounds(parent_ts, block_ts),
            ref_timestamp_within_bounds(parent_ts, block_ts),
            "mismatch for ({parent_ts}, {block_ts})"
        );
    }
}

fn make_validator(seed: u8) -> (FalconKeypair, [u8; 32]) {
    let kp = FalconKeypair::generate_from_seed_bytes(&[seed; 32]);
    let id = derive_pq_address(FALCON512_SCHEME_ID, kp.public_key(), &DEFAULT_SALT);
    (kp, id)
}

fn make_uqc(
    kp: &FalconKeypair,
    chain_id: u64,
    shard_id: u32,
    height: u64,
    round: u32,
    kind: stellereum_verifier::wire::VoteKind,
    block_hash: [u8; 32],
) -> stellereum_verifier::wire::QuorumCertificate {
    use stellereum_verifier::consensus::vote_sign_bytes_for_shard;
    use stellereum_verifier::wire::{
        PqMicroCertificate, PqScheme, QuorumCertificate, PQ_UQC_MARKER_ID,
    };

    let msg = vote_sign_bytes_for_shard(chain_id, shard_id, height, round, kind, &Some(block_hash));
    let sig = kp.sign(&msg);
    let mut cert = PqMicroCertificate::new(
        PqScheme::Falcon512,
        height,
        round,
        1,
        vec![0u8; 1],
        vec![sig],
        [0x88u8; 32],
    );
    cert.set_signer(0, true);
    QuorumCertificate {
        height,
        round,
        kind,
        block_hash: Some(block_hash),
        signatures: vec![(PQ_UQC_MARKER_ID, cert.encode())],
        shard_id,
    }
}

fn sign_verifier_block(
    block: &mut stellereum_verifier::wire::Block,
    kp: &FalconKeypair,
    chain_id: u64,
) {
    block.order_merkle_root = compute_order_merkle_root(&block.transactions);
    let bh = compute_block_hash_at(
        block,
        chain_id,
        stellereum_verifier::block_hash::HEADER_COMMIT_ACTIVATION_HEIGHT,
    );
    block.validator_signatures = vec![(block.proposer, kp.sign(&bh))];
}

#[test]
fn verify_block_enforces_last_qc_and_rejects_trusted_xshard() {
    use stellereum_verifier::consensus::{
        verify_block_with_context, BlockVerifyContext, CommitteeSchedule, ConsensusConfig,
        StaticPqKeyRegistry, ValidatorSet,
    };
    use stellereum_verifier::wire::{Block as VBlock, PqScheme, VoteKind};

    let config = ConsensusConfig::default();
    let (kp, val_id) = make_validator(0x61);
    let validators = ValidatorSet::from_list(vec![(val_id, 1_000_000)]);
    let mut keys = StaticPqKeyRegistry::new();
    keys.insert(val_id, PqScheme::Falcon512, kp.public_key().to_vec());

    let prev_hash = [0x11u8; 32];
    let valid_lqc = make_uqc(
        &kp,
        config.chain_id,
        0,
        4,
        0,
        VoteKind::Precommit,
        prev_hash,
    );

    let mut base = VBlock {
        shard_id: 0,
        height: 5,
        prev_hash,
        timestamp: 1_700_000_010,
        proposer: val_id,
        last_qc: Some(valid_lqc.clone()),
        ..VBlock::default()
    };
    sign_verifier_block(&mut base, &kp, config.chain_id);

    let mut ctx = BlockVerifyContext {
        validators: &validators,
        keys: &keys,
        schedule: CommitteeSchedule::ParentHash,
        config,
        expected_prev_hash: Some(prev_hash),
        parent_timestamp: Some(1_700_000_005),
        require_qc: false,
        verify_txs: false,
        require_tx_chain_id: false,
        implicit_registry: None,
    };
    verify_block_with_context(&base, None, &mut ctx).expect("valid last_qc must verify");

    // 1. Wrong last_qc height.
    let mut bad_h = base.clone();
    bad_h.last_qc = Some(make_uqc(
        &kp,
        config.chain_id,
        0,
        3,
        0,
        VoteKind::Precommit,
        prev_hash,
    ));
    sign_verifier_block(&mut bad_h, &kp, config.chain_id);
    assert!(verify_block_with_context(&bad_h, None, &mut ctx).is_err());

    // 2. Wrong last_qc block_hash (does not match prev_hash).
    let mut bad_bh = base.clone();
    bad_bh.last_qc = Some(make_uqc(
        &kp,
        config.chain_id,
        0,
        4,
        0,
        VoteKind::Precommit,
        [0x99u8; 32],
    ));
    sign_verifier_block(&mut bad_bh, &kp, config.chain_id);
    assert!(verify_block_with_context(&bad_bh, None, &mut ctx).is_err());

    // 3. Wrong last_qc kind (Prevote instead of Precommit).
    let mut bad_kind = base.clone();
    bad_kind.last_qc = Some(make_uqc(
        &kp,
        config.chain_id,
        0,
        4,
        0,
        VoteKind::Prevote,
        prev_hash,
    ));
    sign_verifier_block(&mut bad_kind, &kp, config.chain_id);
    assert!(verify_block_with_context(&bad_kind, None, &mut ctx).is_err());

    // 4. Wrong last_qc shard_id.
    let mut bad_shard = base.clone();
    bad_shard.last_qc = Some(make_uqc(
        &kp,
        config.chain_id,
        1,
        4,
        0,
        VoteKind::Precommit,
        prev_hash,
    ));
    sign_verifier_block(&mut bad_shard, &kp, config.chain_id);
    assert!(verify_block_with_context(&bad_shard, None, &mut ctx).is_err());

    // 5. Cryptographically invalid last_qc (signed by a different key).
    let (other_kp, _) = make_validator(0x62);
    let mut bad_sig = base.clone();
    bad_sig.last_qc = Some(make_uqc(
        &other_kp,
        config.chain_id,
        0,
        4,
        0,
        VoteKind::Precommit,
        prev_hash,
    ));
    sign_verifier_block(&mut bad_sig, &kp, config.chain_id);
    assert!(verify_block_with_context(&bad_sig, None, &mut ctx).is_err());

    // 6. Block height 0 must reject non-None last_qc.
    let mut h0 = base.clone();
    h0.height = 0;
    h0.last_qc = Some(make_uqc(
        &kp,
        config.chain_id,
        0,
        0,
        0,
        VoteKind::Precommit,
        prev_hash,
    ));
    sign_verifier_block(&mut h0, &kp, config.chain_id);
    let mut ctx0 = BlockVerifyContext {
        validators: &validators,
        keys: &keys,
        schedule: CommitteeSchedule::ParentHash,
        config,
        expected_prev_hash: None,
        parent_timestamp: None,
        require_qc: false,
        verify_txs: false,
        require_tx_chain_id: false,
        implicit_registry: None,
    };
    assert!(verify_block_with_context(&h0, None, &mut ctx0).is_err());

    // 7. Reject cross-shard message with trusted == true.
    let ref_tx = build_pq_tx(&kp, 1, 100, Vec::new(), 0, Some(config.chain_id));
    let mut ref_xmsg = CrossShardMessage::new(0, 1, ref_tx, [0x12u8; 32], [0x34u8; 32], None);
    ref_xmsg.trusted = true;
    let mut ref_blk = Block {
        shard_id: 0,
        height: 5,
        prev_hash,
        timestamp: 1_700_000_010,
        proposer: val_id,
        ..Block::default()
    }
    .with_cross_shard_out(vec![ref_xmsg]);
    let mut wire_trusted_blk = round_trip_block(&ref_blk);
    sign_verifier_block(&mut wire_trusted_blk, &kp, config.chain_id);
    assert!(verify_block_with_context(&wire_trusted_blk, None, &mut ctx).is_err());
    // Same message with trusted == false passes.
    ref_blk.cross_shard_out[0].trusted = false;
    let mut wire_untrusted_blk = round_trip_block(&ref_blk);
    sign_verifier_block(&mut wire_untrusted_blk, &kp, config.chain_id);
    verify_block_with_context(&wire_untrusted_blk, None, &mut ctx)
        .expect("untrusted cross-shard message must verify");
}

#[test]
fn verify_chain_enforces_require_tx_chain_id() {
    use stellereum::sharding::PqSignatureEnvelope;
    use stellereum_verifier::consensus::{
        verify_chain, CommitteeSchedule, ConsensusConfig, StaticPqKeyRegistry, ValidatorSet,
    };
    use stellereum_verifier::wire::{decode_transaction_v7_strict, Block as VBlock, PqScheme};

    let config = ConsensusConfig::default();
    let (kp, val_id) = make_validator(0x63);
    let validators = ValidatorSet::from_list(vec![(val_id, 1_000_000)]);
    let mut keys = StaticPqKeyRegistry::new();
    keys.insert(val_id, PqScheme::Falcon512, kp.public_key().to_vec());

    let pk = kp.public_key().to_vec();
    let mut unbound_ref = Transaction::new_pq_explicit(
        stellereum::post_quantum::PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        [0x42u8; 32],
        100,
        50_000,
        0,
        0,
        0,
        Vec::new(),
        &DEFAULT_SALT,
    );
    let msg = unbound_ref.signing_message();
    unbound_ref.signature = PqSignatureEnvelope::new_explicit_with_salt(
        stellereum::post_quantum::PqScheme::Falcon512,
        pk.clone(),
        kp.sign(&msg),
        DEFAULT_SALT,
    )
    .encode();
    let unbound_wire =
        decode_transaction_v7_strict(&bincode::serialize(&unbound_ref).unwrap()).unwrap();

    let mut bound_ref = Transaction::new_pq_explicit_with_chain(
        stellereum::post_quantum::PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        [0x42u8; 32],
        100,
        50_000,
        1,
        0,
        0,
        Vec::new(),
        &DEFAULT_SALT,
        config.chain_id,
    );
    let msg2 = bound_ref.signing_message();
    bound_ref.signature = PqSignatureEnvelope::new_explicit_with_chain(
        stellereum::post_quantum::PqScheme::Falcon512,
        pk,
        kp.sign(&msg2),
        DEFAULT_SALT,
        config.chain_id,
    )
    .encode();
    let bound_wire =
        decode_transaction_v7_strict(&bincode::serialize(&bound_ref).unwrap()).unwrap();

    let mut blk_unbound = VBlock {
        shard_id: 0,
        height: 1,
        timestamp: 1_700_000_001,
        proposer: val_id,
        transactions: vec![unbound_wire],
        ..VBlock::default()
    };
    sign_verifier_block(&mut blk_unbound, &kp, config.chain_id);

    // Unbound tx passes when require_tx_chain_id = false, fails when true.
    verify_chain(
        std::slice::from_ref(&blk_unbound),
        &validators,
        &keys,
        CommitteeSchedule::ParentHash,
        config,
        false,
        true,
        false,
    )
    .expect("unbound tx accepted when require_tx_chain_id=false");
    assert!(verify_chain(
        &[blk_unbound],
        &validators,
        &keys,
        CommitteeSchedule::ParentHash,
        config,
        false,
        true,
        true,
    )
    .is_err());

    let mut blk_bound = VBlock {
        shard_id: 0,
        height: 1,
        timestamp: 1_700_000_001,
        proposer: val_id,
        transactions: vec![bound_wire],
        ..VBlock::default()
    };
    sign_verifier_block(&mut blk_bound, &kp, config.chain_id);
    verify_chain(
        &[blk_bound],
        &validators,
        &keys,
        CommitteeSchedule::ParentHash,
        config,
        false,
        true,
        true,
    )
    .expect("chain-bound tx accepted when require_tx_chain_id=true");
}
