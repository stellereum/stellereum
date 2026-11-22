//! R2-A tests for two-level [`BlockHeader`] + [`Block::body_commitment`]
//! gated by [`HEADER_COMMIT_ACTIVATION_HEIGHT`].
//!
//! Verifies:
//! 1. Default `u64::MAX` gate keeps `header_commit_active_at(0) == false` and
//!    `header_commit_active_at(u64::MAX) == false`.
//! 2. At `H - 1` (with RAII `set_header_commit_activation_override(Some(10))`),
//!    `Block::compute_hash()` and `Block::value_id()` match the legacy
//!    `"STELLEREUM_BLOCK_V3"` preimage byte-for-byte.
//! 3. At `H` (10) and `H + 1` (11), `block.compute_hash() == block.header().compute_hash()`
//!    and `block.value_id() == BlockHeader { round: 0, ..block.header() }.compute_hash()`,
//!    matching the `"STELLEREUM_HDR_V4\0"` / `"STELLEREUM_BODY_V4\0"` spec.
//! 4. Mutating any of the 15 committed fields (9 header fields + 6 body fields)
//!    changes `compute_hash()`.
//! 5. Mutating `validator_signatures` or `precommit_qc` does NOT change
//!    `compute_hash()`, `value_id()`, or `body_commitment()`.
//! 6. Re-stamping `round` changes `compute_hash()`, while preserving
//!    `body_commitment()` and `value_id()`.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use stellereum::cn_vrf::cnvrf_v3_commit;
use stellereum::consensus::{consensus_chain_id, QuorumCertificate, VoteKind};
use stellereum::minroot_vdf::MinRootProof;
use stellereum::post_quantum::FalconKeypair;
use stellereum::sharding::{
    effective_header_commit_activation_height, header_commit_active_at,
    set_header_commit_activation_override, Block, BlockHeader, CnVrfV3BlockPayload,
    CrossShardMessage, EpochVdfBeacon, ShardHeaderCommitment, Transaction,
    BODY_COMMITMENT_V4_DOMAIN, CNVRF_V3_COMMITMENT_TAG, EPOCH_KEY_COMMITMENT_TAG,
    HEADER_COMMIT_ACTIVATION_HEIGHT, HEADER_COMMIT_V4_DOMAIN, LAST_QC_COMMITMENT_TAG,
    MMR_EPOCH_COMMITMENT_TAG, ORDER_MERKLE_COMMITMENT_TAG, ROUND_COMMITMENT_TAG,
    SHARD_HEADERS_COMMITMENT_TAG, XSHARD_FULL_COMMITMENT_TAG,
};

struct HeaderCommitOverrideGuard;

impl HeaderCommitOverrideGuard {
    fn new(height: Option<u64>) -> Self {
        set_header_commit_activation_override(height);
        Self
    }
}

impl Drop for HeaderCommitOverrideGuard {
    fn drop(&mut self) {
        set_header_commit_activation_override(None);
    }
}

fn legacy_v3_hash_with_round(block: &Block, round: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"STELLEREUM_BLOCK_V3");
    hasher.update(consensus_chain_id().to_be_bytes());
    hasher.update(block.shard_id.to_be_bytes());
    hasher.update(block.height.to_be_bytes());
    if round != 0 {
        hasher.update(ROUND_COMMITMENT_TAG);
        hasher.update(round.to_be_bytes());
    }
    hasher.update(block.prev_hash);
    hasher.update(block.state_root);
    hasher.update((block.transactions.len() as u32).to_be_bytes());
    if !block.transactions.is_empty() {
        let mut tx_batch = Transaction::batch_hasher();
        for tx in &block.transactions {
            hasher.update(tx_batch.hash_one(tx));
        }
    }
    if block.order_merkle_root != [0u8; 32] {
        hasher.update(ORDER_MERKLE_COMMITMENT_TAG);
        hasher.update(block.order_merkle_root);
    }
    hasher.update((block.cross_shard_out.len() as u32).to_be_bytes());
    for m in &block.cross_shard_out {
        hasher.update(m.msg_id);
    }
    if !block.cross_shard_out.is_empty() {
        hasher.update(XSHARD_FULL_COMMITMENT_TAG);
        hasher.update((block.cross_shard_out.len() as u32).to_be_bytes());
        for m in &block.cross_shard_out {
            hasher.update(m.message_commitment());
        }
    }
    if !block.shard_headers.is_empty() {
        hasher.update(SHARD_HEADERS_COMMITMENT_TAG);
        hasher.update((block.shard_headers.len() as u32).to_be_bytes());
        for h in &block.shard_headers {
            hasher.update(h.commitment_bytes());
        }
    }
    if block.epoch_key_commitment != [0u8; 32] {
        hasher.update(EPOCH_KEY_COMMITMENT_TAG);
        hasher.update(block.epoch_key_commitment);
    }
    if let Some(qc) = &block.last_qc {
        hasher.update(LAST_QC_COMMITMENT_TAG);
        hasher.update(qc.height.to_be_bytes());
        hasher.update(qc.round.to_be_bytes());
        hasher.update([match qc.kind {
            VoteKind::Prevote => 0u8,
            VoteKind::Precommit => 1u8,
        }]);
        if let Some(bh) = &qc.block_hash {
            hasher.update([1u8]);
            hasher.update(bh);
        } else {
            hasher.update([0u8]);
        }
        let mut sigs = qc.signatures.clone();
        sigs.sort_by(|a, b| a.0.cmp(&b.0));
        hasher.update((sigs.len() as u32).to_be_bytes());
        for (voter, sig) in &sigs {
            hasher.update(voter);
            hasher.update((sig.len() as u32).to_be_bytes());
            hasher.update(sig);
        }
    }
    if block.mmr_epoch_root != [0u8; 32] {
        hasher.update(MMR_EPOCH_COMMITMENT_TAG);
        hasher.update(block.mmr_epoch_root);
    }
    if let Some(payload) = &block.cnvrf_v3 {
        hasher.update(CNVRF_V3_COMMITMENT_TAG);
        hasher.update(payload.canonical_bytes());
    }
    hasher.update(block.timestamp.to_be_bytes());
    hasher.update(block.proposer);
    hasher.finalize().into()
}

fn spec_v4_body_commitment(block: &Block) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"STELLEREUM_BODY_V4\0");
    h.update((block.transactions.len() as u32).to_be_bytes());
    let mut tx_batch = Transaction::batch_hasher();
    for tx in &block.transactions {
        h.update(tx_batch.hash_one(tx));
    }
    h.update(block.order_merkle_root);
    h.update((block.cross_shard_out.len() as u32).to_be_bytes());
    for m in &block.cross_shard_out {
        h.update(m.msg_id);
        h.update(m.message_commitment());
    }
    h.update((block.shard_headers.len() as u32).to_be_bytes());
    for sh in &block.shard_headers {
        let sb = sh.commitment_bytes();
        h.update((sb.len() as u32).to_be_bytes());
        h.update(&sb);
    }
    match &block.last_qc {
        None => h.update([0u8]),
        Some(qc) => {
            h.update([1u8]);
            h.update(qc.shard_id.to_be_bytes());
            h.update(qc.height.to_be_bytes());
            h.update(qc.round.to_be_bytes());
            h.update([match qc.kind {
                VoteKind::Prevote => 0u8,
                VoteKind::Precommit => 1u8,
            }]);
            match &qc.block_hash {
                Some(bh) => {
                    h.update([1u8]);
                    h.update(bh);
                }
                None => h.update([0u8]),
            }
            let mut sigs: Vec<(&[u8; 32], &[u8])> = qc
                .signatures
                .iter()
                .map(|(v, s)| (v, s.as_slice()))
                .collect();
            sigs.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));
            h.update((sigs.len() as u32).to_be_bytes());
            for (v, s) in sigs {
                h.update(v);
                h.update((s.len() as u32).to_be_bytes());
                h.update(s);
            }
        }
    }
    match &block.cnvrf_v3 {
        None => h.update([0u8]),
        Some(p) => {
            h.update([1u8]);
            let cb = p.canonical_bytes();
            h.update((cb.len() as u32).to_be_bytes());
            h.update(&cb);
        }
    }
    h.finalize().into()
}

fn spec_v4_header_hash_with_round(block: &Block, round: u32) -> [u8; 32] {
    let body_commitment = spec_v4_body_commitment(block);
    let mut h = Sha256::new();
    h.update(b"STELLEREUM_HDR_V4\0");
    h.update(consensus_chain_id().to_be_bytes());
    h.update(block.shard_id.to_be_bytes());
    h.update(block.height.to_be_bytes());
    h.update(round.to_be_bytes());
    h.update(block.prev_hash);
    h.update(block.state_root);
    h.update(body_commitment);
    h.update(block.mmr_epoch_root);
    h.update(block.epoch_key_commitment);
    h.update(block.timestamp.to_be_bytes());
    h.update(block.proposer);
    h.finalize().into()
}

fn build_populated_block(height: u64) -> Block {
    let sk1 = SigningKey::from_bytes(&[0x11u8; 32]);
    let sk2 = SigningKey::from_bytes(&[0x22u8; 32]);
    let tx1 = Transaction::sign(&sk1, [0xA1u8; 32], 1_000, 21_000, 1, 0, 0);
    let tx2 = Transaction::sign(&sk2, [0xA2u8; 32], 2_500, 25_000, 2, 0, 1);

    let xmsg = CrossShardMessage::new(0, 1, tx2.clone(), [0x31u8; 32], [0x32u8; 32], None);

    let shard_hdr = ShardHeaderCommitment {
        shard_id: 1,
        height: height.saturating_sub(1),
        block_hash: [0x41u8; 32],
        state_root: [0x42u8; 32],
        timestamp: 1_700_000_005,
        minted_total_nano: 777,
    };

    let last_qc = QuorumCertificate {
        height: height.saturating_sub(1),
        round: 2,
        kind: VoteKind::Precommit,
        block_hash: Some([0x51u8; 32]),
        signatures: vec![
            ([0xBBu8; 32], vec![0x02u8; 64]),
            ([0xAAu8; 32], vec![0x01u8; 64]),
        ],
        shard_id: 0,
    };

    let fk1 = FalconKeypair::generate_from_seed(0xC1);
    let fk2 = FalconKeypair::generate_from_seed(0xC2);
    let c1 = cnvrf_v3_commit(&fk1, 0, &[0x61u8; 32], 1, &[0x71u8; 48]);
    let c2 = cnvrf_v3_commit(&fk2, 0, &[0x62u8; 32], 1, &[0x72u8; 48]);
    let cnvrf = CnVrfV3BlockPayload {
        reveal: Some([0x81u8; 48]),
        commits: vec![c2, c1],
        epoch_vdf: Some(EpochVdfBeacon {
            epoch: 1,
            raw_seed: [0x82u8; 48],
            proof: MinRootProof {
                steps: 4,
                final_xy: ([0x83u8; 32], [0x84u8; 32]),
                checkpoints: vec![(2, [0x85u8; 32], [0x86u8; 32])],
            },
        }),
    };

    let mut b = Block {
        shard_id: 0,
        height,
        prev_hash: [0x91u8; 32],
        state_root: [0x92u8; 32],
        transactions: vec![tx1, tx2],
        cross_shard_out: vec![xmsg],
        timestamp: 1_700_000_123,
        proposer: [0x93u8; 32],
        validator_signatures: vec![([0x94u8; 32], vec![0x95u8; 64])],
        precommit_qc: Some(QuorumCertificate {
            height,
            round: 3,
            kind: VoteKind::Precommit,
            block_hash: Some([0x96u8; 32]),
            signatures: vec![([0x97u8; 32], vec![0x98u8; 64])],
            shard_id: 0,
        }),
        shard_headers: vec![shard_hdr],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0x99u8; 32],
        last_qc: Some(last_qc),
        mmr_epoch_root: [0x9Au8; 32],
        cnvrf_v3: Some(cnvrf),
        round: 3,
    };
    b.recompute_order_commitment();
    b
}

#[test]
fn default_v7_activates_header_commit_and_u64_max_override_preserves_legacy() {
    let _guard = HeaderCommitOverrideGuard::new(Some(u64::MAX));
    assert_eq!(HEADER_COMMIT_ACTIVATION_HEIGHT, 0);
    assert_eq!(effective_header_commit_activation_height(), u64::MAX);
    assert!(!header_commit_active_at(0));
    assert!(!header_commit_active_at(1));
    assert!(!header_commit_active_at(u64::MAX - 1));
    assert!(!header_commit_active_at(u64::MAX));

    for &h in &[0u64, 10, u64::MAX] {
        let b = build_populated_block(h);
        assert_eq!(b.compute_hash(), legacy_v3_hash_with_round(&b, b.round));
        assert_eq!(b.value_id(), legacy_v3_hash_with_round(&b, 0));
    }
}

#[test]
fn activation_boundary_h_minus_1_h_and_h_plus_1() {
    const H: u64 = 10;
    let _guard = HeaderCommitOverrideGuard::new(Some(H));

    assert_eq!(BODY_COMMITMENT_V4_DOMAIN, b"STELLEREUM_BODY_V4\0");
    assert_eq!(HEADER_COMMIT_V4_DOMAIN, b"STELLEREUM_HDR_V4\0");
    assert_eq!(effective_header_commit_activation_height(), H);
    assert!(!header_commit_active_at(H - 1));
    assert!(header_commit_active_at(H));
    assert!(header_commit_active_at(H + 1));

    // H - 1 (height 9): byte-for-byte identical to legacy "STELLEREUM_BLOCK_V3".
    let pre_empty = Block {
        height: H - 1,
        ..Block::default()
    };
    assert_eq!(
        pre_empty.compute_hash(),
        legacy_v3_hash_with_round(&pre_empty, pre_empty.round)
    );
    assert_eq!(
        pre_empty.value_id(),
        legacy_v3_hash_with_round(&pre_empty, 0)
    );

    let pre_full = build_populated_block(H - 1);
    assert_eq!(
        pre_full.compute_hash(),
        legacy_v3_hash_with_round(&pre_full, pre_full.round)
    );
    assert_eq!(pre_full.value_id(), legacy_v3_hash_with_round(&pre_full, 0));

    // H (10) and H + 1 (11): two-level BlockHeader v4 scheme.
    for h in [H, H + 1] {
        let block = build_populated_block(h);
        let hdr = block.header();
        assert_eq!(hdr.body_commitment, block.body_commitment());
        assert_eq!(hdr.body_commitment, spec_v4_body_commitment(&block));
        assert_eq!(block.compute_hash(), hdr.compute_hash());
        assert_eq!(
            block.compute_hash(),
            spec_v4_header_hash_with_round(&block, block.round)
        );
        assert_eq!(
            block.value_id(),
            BlockHeader { round: 0, ..hdr }.compute_hash()
        );
        assert_eq!(block.value_id(), spec_v4_header_hash_with_round(&block, 0));
        assert_ne!(
            block.compute_hash(),
            legacy_v3_hash_with_round(&block, block.round)
        );
    }
}

#[test]
fn all_15_committed_fields_affect_compute_hash_above_activation() {
    const H: u64 = 10;
    let _guard = HeaderCommitOverrideGuard::new(Some(H));

    let base = build_populated_block(H);
    let base_hash = base.compute_hash();
    let base_body = base.body_commitment();

    // 1. shard_id
    let mut b = base.clone();
    b.shard_id += 1;
    assert_ne!(b.compute_hash(), base_hash);
    assert_eq!(b.body_commitment(), base_body);

    // 2. height
    let mut b = base.clone();
    b.height += 1;
    assert_ne!(b.compute_hash(), base_hash);
    assert_eq!(b.body_commitment(), base_body);

    // 3. round
    let mut b = base.clone();
    b.round += 1;
    assert_ne!(b.compute_hash(), base_hash);
    assert_eq!(b.body_commitment(), base_body);

    // 4. prev_hash
    let mut b = base.clone();
    b.prev_hash[0] ^= 0x01;
    assert_ne!(b.compute_hash(), base_hash);
    assert_eq!(b.body_commitment(), base_body);

    // 5. state_root
    let mut b = base.clone();
    b.state_root[31] ^= 0x01;
    assert_ne!(b.compute_hash(), base_hash);
    assert_eq!(b.body_commitment(), base_body);

    // 6. mmr_epoch_root
    let mut b = base.clone();
    b.mmr_epoch_root[0] ^= 0x01;
    assert_ne!(b.compute_hash(), base_hash);
    assert_eq!(b.body_commitment(), base_body);

    // 7. epoch_key_commitment
    let mut b = base.clone();
    b.epoch_key_commitment[0] ^= 0x01;
    assert_ne!(b.compute_hash(), base_hash);
    assert_eq!(b.body_commitment(), base_body);

    // 8. timestamp
    let mut b = base.clone();
    b.timestamp += 1;
    assert_ne!(b.compute_hash(), base_hash);
    assert_eq!(b.body_commitment(), base_body);

    // 9. proposer
    let mut b = base.clone();
    b.proposer[0] ^= 0x01;
    assert_ne!(b.compute_hash(), base_hash);
    assert_eq!(b.body_commitment(), base_body);

    // 10. transactions
    let mut b = base.clone();
    b.transactions[0].amount += 1;
    assert_ne!(b.body_commitment(), base_body);
    assert_ne!(b.compute_hash(), base_hash);

    // 11. order_merkle_root
    let mut b = base.clone();
    b.order_merkle_root[0] ^= 0x01;
    assert_ne!(b.body_commitment(), base_body);
    assert_ne!(b.compute_hash(), base_hash);

    // 12. cross_shard_out (mutating message body without changing msg_id)
    let mut b = base.clone();
    b.cross_shard_out[0].source_balance += 1;
    assert_ne!(b.body_commitment(), base_body);
    assert_ne!(b.compute_hash(), base_hash);

    // 13. shard_headers (including optional minted_total_nano)
    let mut b = base.clone();
    b.shard_headers[0].minted_total_nano += 1;
    assert_ne!(b.body_commitment(), base_body);
    assert_ne!(b.compute_hash(), base_hash);

    // 14. last_qc (mutating field + canonical signature order invariance)
    let mut b = base.clone();
    b.last_qc.as_mut().unwrap().shard_id += 1;
    assert_ne!(b.body_commitment(), base_body);
    assert_ne!(b.compute_hash(), base_hash);

    let mut b_qc_reordered = base.clone();
    b_qc_reordered
        .last_qc
        .as_mut()
        .unwrap()
        .signatures
        .reverse();
    assert_eq!(b_qc_reordered.body_commitment(), base_body);
    assert_eq!(b_qc_reordered.compute_hash(), base_hash);

    let mut b_no_qc = base.clone();
    b_no_qc.last_qc = None;
    assert_ne!(b_no_qc.body_commitment(), base_body);
    assert_ne!(b_no_qc.compute_hash(), base_hash);

    // 15. cnvrf_v3 (mutating payload + canonical commit order invariance)
    let mut b = base.clone();
    b.cnvrf_v3.as_mut().unwrap().reveal.as_mut().unwrap()[0] ^= 0x01;
    assert_ne!(b.body_commitment(), base_body);
    assert_ne!(b.compute_hash(), base_hash);

    let mut b_cnvrf_reordered = base.clone();
    b_cnvrf_reordered
        .cnvrf_v3
        .as_mut()
        .unwrap()
        .commits
        .reverse();
    assert_eq!(b_cnvrf_reordered.body_commitment(), base_body);
    assert_eq!(b_cnvrf_reordered.compute_hash(), base_hash);

    let mut b_no_cnvrf = base.clone();
    b_no_cnvrf.cnvrf_v3 = None;
    assert_ne!(b_no_cnvrf.body_commitment(), base_body);
    assert_ne!(b_no_cnvrf.compute_hash(), base_hash);
}

#[test]
fn signatures_and_precommit_qc_are_excluded_from_hash_and_body_commitment() {
    const H: u64 = 10;
    let _guard = HeaderCommitOverrideGuard::new(Some(H));

    let base = build_populated_block(H + 1);
    let base_hash = base.compute_hash();
    let base_value_id = base.value_id();
    let base_body = base.body_commitment();

    let mut mutated_sigs = base.clone();
    mutated_sigs.validator_signatures.clear();
    mutated_sigs
        .validator_signatures
        .push(([0xFEu8; 32], vec![0xEDu8; 64]));
    assert_eq!(mutated_sigs.compute_hash(), base_hash);
    assert_eq!(mutated_sigs.value_id(), base_value_id);
    assert_eq!(mutated_sigs.body_commitment(), base_body);

    let mut no_qc = base.clone();
    no_qc.precommit_qc = None;
    assert_eq!(no_qc.compute_hash(), base_hash);
    assert_eq!(no_qc.value_id(), base_value_id);
    assert_eq!(no_qc.body_commitment(), base_body);

    let mut altered_qc = base.clone();
    altered_qc.precommit_qc = Some(QuorumCertificate {
        height: H + 1,
        round: 99,
        kind: VoteKind::Precommit,
        block_hash: Some([0xDDu8; 32]),
        signatures: vec![([0xCCu8; 32], vec![0xBBu8; 64])],
        shard_id: 7,
    });
    assert_eq!(altered_qc.compute_hash(), base_hash);
    assert_eq!(altered_qc.value_id(), base_value_id);
    assert_eq!(altered_qc.body_commitment(), base_body);
}

#[test]
fn round_restamp_changes_compute_hash_but_preserves_value_id_and_body_commitment() {
    const H: u64 = 10;
    let _guard = HeaderCommitOverrideGuard::new(Some(H));

    let mut r0 = build_populated_block(H);
    r0.round = 0;

    let mut r1 = r0.clone();
    r1.round = 1;

    let mut r7 = r0.clone();
    r7.round = 7;

    assert_eq!(r0.compute_hash(), r0.value_id());
    assert_ne!(r1.compute_hash(), r0.compute_hash());
    assert_ne!(r7.compute_hash(), r0.compute_hash());
    assert_ne!(r7.compute_hash(), r1.compute_hash());

    assert_eq!(r1.value_id(), r0.value_id());
    assert_eq!(r7.value_id(), r0.value_id());

    assert_eq!(r1.body_commitment(), r0.body_commitment());
    assert_eq!(r7.body_commitment(), r0.body_commitment());

    // BlockHeader serde roundtrip preserves header identity and compute_hash.
    let hdr = r7.header();
    let encoded = bincode::serialize(&hdr).expect("bincode serialize BlockHeader");
    let decoded: BlockHeader =
        bincode::deserialize(&encoded).expect("bincode deserialize BlockHeader");
    assert_eq!(decoded, hdr);
    assert_eq!(decoded.compute_hash(), r7.compute_hash());
}
