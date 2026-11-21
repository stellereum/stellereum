//! R2-C tests for v4 two-level header commitment binding in [`stellereum::light_client`]
//! and [`stellereum::light_client_cli`].
//!
//! Verifies:
//! 1. With the default `u64::MAX` gate (and at `height < H`), legacy v3 checkpoints,
//!    `LightHeader`s without `body_commitment`, `stell_getHistoricalRoot` JSON, and
//!    `ServedHeader`s continue to verify cleanly.
//! 2. At `H` and `H + 1` (with RAII reset of `set_header_commit_activation_override`):
//!    - Valid `LightHeader::of_block`, `Checkpoint::of`, `Checkpoint::from_block_header`,
//!      `stell_getHistoricalRoot` JSON, and `stell_getFinalizedHeader` JSON pass,
//!      and `LightClient::apply_header` / `apply_header_without_block_signatures`
//!      trust `block.state_root` and retain `block.mmr_epoch_root`.
//!    - Forged `state_root`, forged `prev_hash`, missing `body_commitment`, or wrong
//!      `shard_id` are rejected fail-closed by ALL of:
//!      * `Checkpoint::verify_with_schedule`
//!      * `LightHeader::verify_with_schedule`
//!      * `LightClient::apply_header_without_block_signatures`
//!      * `Checkpoint::from_historical_root_json`
//!      * `light_client_cli::check_anchoring_header`
//!        even when carrying a **genuine** `precommit_qc`!
//!    - Returning to an earlier state root (`A -> B -> A`) remains accepted across
//!      activation when height and `prev_hash` chain strictly.

use ed25519_dalek::SigningKey;
use stellereum::consensus::{
    CommitteeSchedule, QuorumCertificate, ValidatorSet, VoteKind, VoteSet,
};
use stellereum::light_client::{Checkpoint, LightClient, LightHeader};
use stellereum::light_client_cli::{check_anchoring_header, parse_served_header, ServedHeader};
use stellereum::post_quantum::FalconKeypair;
use stellereum::sharding::{
    header_commit_active_at, set_header_commit_activation_override, Block, Transaction,
    HEADER_COMMIT_ACTIVATION_HEIGHT, MASTERCHAIN_SHARD,
};

#[path = "support/falcon_votes.rs"]
mod falcon_votes;

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

fn validator_set_from(keys: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(
        keys.iter()
            .map(|k| (k.verifying_key().to_bytes(), 1))
            .collect(),
    )
}

fn build_qc(
    keys: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
    height: u64,
    round: u32,
    block_hash: [u8; 32],
    prev_hash: [u8; 32],
) -> QuorumCertificate {
    let mut set = VoteSet::new();
    for (sk, fk) in keys.iter().zip(fks.iter()).take(3) {
        let v = falcon_votes::fvote(sk, fk, height, round, VoteKind::Precommit, Some(block_hash));
        set.add(v, vs, height, round, VoteKind::Precommit)
            .expect("falcon vote must ingest");
    }
    set.certificate_with_parent(Some(block_hash), vs, Some(&prev_hash))
        .expect("quorum must compile a Falcon µQC")
}

#[allow(clippy::too_many_arguments)]
// GATE: test fixture builder takes explicit block/chain fields to test exact boundary
// heights (H-1, H, H+1) with genuine QCs without hiding state transitions.
fn make_finalized_block(
    height: u64,
    round: u32,
    prev_hash: [u8; 32],
    state_root: [u8; 32],
    mmr_epoch_root: [u8; 32],
    epoch_key_commitment: [u8; 32],
    keys: &[SigningKey],
    fks: &[FalconKeypair],
    vs: &ValidatorSet,
) -> Block {
    let tx = Transaction {
        from: [0x11u8; 32],
        to: [0x22u8; 32],
        amount: 100 + height,
        gas_limit: 50_000,
        nonce: height,
        source_shard: MASTERCHAIN_SHARD,
        target_shard: MASTERCHAIN_SHARD,
        signature: vec![0xAAu8; 4],
        payload: Vec::new(),
        priority_fee_per_gas: 0,
    };
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash,
        state_root,
        transactions: vec![tx],
        timestamp: 1_700_000_000 + height,
        proposer: keys[0].verifying_key().to_bytes(),
        order_merkle_root: [0x42u8; 32],
        epoch_key_commitment,
        mmr_epoch_root,
        round,
        ..Default::default()
    };
    let bh = b.compute_hash();
    b.precommit_qc = Some(build_qc(keys, fks, vs, height, round, bh, prev_hash));
    b
}

fn historical_root_json_from_block(archive_height: u64, anchor: &Block) -> serde_json::Value {
    let cert = anchor
        .precommit_qc
        .as_ref()
        .expect("anchor block must have precommit_qc");
    let body_commitment = if header_commit_active_at(anchor.height) {
        Some(hex::encode(anchor.body_commitment()))
    } else {
        None
    };
    serde_json::json!({
        "height": archive_height,
        "state_root": hex::encode(anchor.state_root),
        "anchor_height": anchor.height,
        "anchor_hash": hex::encode(anchor.compute_hash()),
        "prev_hash": hex::encode(anchor.prev_hash),
        "shard_id": anchor.shard_id,
        "round": anchor.round,
        "body_commitment": body_commitment,
        "mmr_epoch_root": hex::encode(anchor.mmr_epoch_root),
        "epoch_key_commitment": hex::encode(anchor.epoch_key_commitment),
        "timestamp": anchor.timestamp,
        "proposer": hex::encode(anchor.proposer),
        "cert": {
            "height": cert.height,
            "round": cert.round,
            "kind": format!("{:?}", cert.kind),
            "block_hash": cert.block_hash.map(hex::encode),
            "shard_id": cert.shard_id,
            "signatures": cert.signatures.iter().map(|(v, s)| serde_json::json!({
                "validator": hex::encode(v),
                "signature": hex::encode(s),
            })).collect::<Vec<_>>(),
        },
        "finalized": true,
    })
}

fn finalized_header_json_from_block(block: &Block) -> serde_json::Value {
    let cert = block
        .precommit_qc
        .as_ref()
        .expect("block must have precommit_qc");
    let body_commitment = if header_commit_active_at(block.height) {
        Some(hex::encode(block.body_commitment()))
    } else {
        None
    };
    serde_json::json!({
        "height": block.height,
        "block_hash": hex::encode(block.compute_hash()),
        "prev_hash": hex::encode(block.prev_hash),
        "state_root": hex::encode(block.state_root),
        "shard_id": block.shard_id,
        "round": block.round,
        "body_commitment": body_commitment,
        "mmr_epoch_root": hex::encode(block.mmr_epoch_root),
        "epoch_key_commitment": hex::encode(block.epoch_key_commitment),
        "timestamp": block.timestamp,
        "proposer": hex::encode(block.proposer),
        "cert": {
            "height": cert.height,
            "round": cert.round,
            "kind": format!("{:?}", cert.kind),
            "block_hash": cert.block_hash.map(hex::encode),
            "shard_id": cert.shard_id,
            "signatures": cert.signatures.iter().map(|(v, s)| serde_json::json!({
                "validator": hex::encode(v),
                "signature": hex::encode(s),
            })).collect::<Vec<_>>(),
        },
    })
}

#[test]
fn v3_legacy_checkpoints_and_headers_without_body_commitment_pass_at_default_and_below_h() {
    assert_eq!(HEADER_COMMIT_ACTIVATION_HEIGHT, u64::MAX);
    assert!(!header_commit_active_at(0));
    assert!(!header_commit_active_at(100));

    let (keys, fks) = falcon_votes::falcon_set(4);
    let vs = validator_set_from(&keys);

    // 1. Default u64::MAX gate: v3 Checkpoint and LightHeader without body_commitment verify.
    let b1 = make_finalized_block(
        1,
        0,
        [0u8; 32],
        [0x1Au8; 32],
        [0x2Au8; 32],
        [0x3Au8; 32],
        &keys,
        &fks,
        &vs,
    );
    let b2 = make_finalized_block(
        2,
        0,
        b1.compute_hash(),
        [0x1Bu8; 32],
        [0x2Bu8; 32],
        [0x3Bu8; 32],
        &keys,
        &fks,
        &vs,
    );

    let hdr1 = LightHeader::of_block(&b1).expect("precommit_qc present");
    assert_eq!(hdr1.body_commitment, None);
    let cp1 = Checkpoint::of(&hdr1);
    assert_eq!(cp1.body_commitment, None);
    cp1.verify_with_schedule(&vs, CommitteeSchedule::ParentHash)
        .expect("v3 checkpoint must verify under default gate");
    hdr1.verify_with_schedule(&vs, CommitteeSchedule::ParentHash)
        .expect("v3 header must verify under default gate");

    let mut lc = LightClient::new(vs.clone(), cp1).expect("client init");
    let hdr2 = LightHeader::of_block(&b2).expect("precommit_qc present");
    assert_eq!(hdr2.body_commitment, None);
    lc.apply_header_without_block_signatures(hdr2.clone())
        .expect("v3 apply_header_without_block_signatures must pass");
    assert_eq!(lc.state_root(), b2.state_root);

    let hr_json = historical_root_json_from_block(1, &b2);
    let hr_cp = Checkpoint::from_historical_root_json(&hr_json)
        .expect("v3 historical root without body_commitment must parse");
    hr_cp
        .verify(&vs)
        .expect("v3 historical root checkpoint must verify");

    let served = parse_served_header(&finalized_header_json_from_block(&b2))
        .expect("v3 served header parses");
    assert_eq!(served.body_commitment, None);
    check_anchoring_header(&served, 2, None)
        .expect("v3 served header passes check_anchoring_header");

    // 2. Explicit activation H = 10: height 9 (< H) still allows legacy v3 without body_commitment.
    let _guard = HeaderCommitOverrideGuard::new(Some(10));
    assert!(!header_commit_active_at(9));
    assert!(header_commit_active_at(10));

    let b8 = make_finalized_block(
        8,
        0,
        [0x08u8; 32],
        [0x88u8; 32],
        [0u8; 32],
        [0u8; 32],
        &keys,
        &fks,
        &vs,
    );
    let b9 = make_finalized_block(
        9,
        0,
        b8.compute_hash(),
        [0x99u8; 32],
        [0u8; 32],
        [0u8; 32],
        &keys,
        &fks,
        &vs,
    );

    let hdr8 = LightHeader::of_block(&b8).expect("qc");
    let hdr9 = LightHeader::of_block(&b9).expect("qc");
    assert_eq!(hdr9.body_commitment, None);
    let cp9 = Checkpoint::of(&hdr9);
    cp9.verify_with_schedule(&vs, CommitteeSchedule::ParentHash)
        .expect("H-1 checkpoint without body_commitment must pass");
    hdr9.verify_with_schedule(&vs, CommitteeSchedule::ParentHash)
        .expect("H-1 header without body_commitment must pass");

    let mut lc_pre = LightClient::new(vs.clone(), Checkpoint::of(&hdr8)).expect("anchor at H-2");
    lc_pre
        .apply_header_without_block_signatures(hdr9)
        .expect("H-1 apply_header_without_block_signatures must pass");

    let hr9 = Checkpoint::from_historical_root_json(&historical_root_json_from_block(8, &b9))
        .expect("H-1 historical root without body_commitment must parse");
    hr9.verify(&vs).expect("H-1 historical root verifies");

    let served9 = parse_served_header(&finalized_header_json_from_block(&b9))
        .expect("H-1 served header parses");
    check_anchoring_header(&served9, 9, None)
        .expect("H-1 served header without body_commitment passes");
}

#[test]
fn v4_valid_headers_checkpoints_and_historical_root_pass_at_h_and_h_plus_1() {
    let h = 10u64;
    let _guard = HeaderCommitOverrideGuard::new(Some(h));

    let (keys, fks) = falcon_votes::falcon_set(4);
    let vs = validator_set_from(&keys);

    let b_pre = make_finalized_block(
        h - 1,
        0,
        [0x09u8; 32],
        [0x90u8; 32],
        [0x11u8; 32],
        [0x22u8; 32],
        &keys,
        &fks,
        &vs,
    );
    let b_h = make_finalized_block(
        h,
        2,
        b_pre.compute_hash(),
        [0xA0u8; 32],
        [0xB0u8; 32],
        [0xC0u8; 32],
        &keys,
        &fks,
        &vs,
    );
    let b_h1 = make_finalized_block(
        h + 1,
        1,
        b_h.compute_hash(),
        [0xA1u8; 32],
        [0xB1u8; 32],
        [0xC1u8; 32],
        &keys,
        &fks,
        &vs,
    );

    let hdr_h = LightHeader::of_block(&b_h).expect("H carries precommit_qc");
    assert_eq!(hdr_h.body_commitment, Some(b_h.body_commitment()));
    assert_eq!(hdr_h.shard_id, b_h.shard_id);
    assert_eq!(hdr_h.round, b_h.round);
    assert_eq!(hdr_h.mmr_epoch_root, b_h.mmr_epoch_root);
    assert_eq!(hdr_h.epoch_key_commitment, b_h.epoch_key_commitment);
    hdr_h
        .verify_with_schedule(&vs, CommitteeSchedule::ParentHash)
        .expect("valid v4 LightHeader at H must verify");

    let cp_h = Checkpoint::of(&hdr_h);
    cp_h.verify_with_schedule(&vs, CommitteeSchedule::ParentHash)
        .expect("valid v4 Checkpoint::of at H must verify");

    let cp_from_hdr =
        Checkpoint::from_block_header(b_h.header(), b_h.precommit_qc.clone().expect("qc"));
    assert_eq!(cp_from_hdr, cp_h);
    cp_from_hdr
        .verify(&vs)
        .expect("valid v4 Checkpoint::from_block_header at H must verify");

    let hdr_h1 = LightHeader::of_block(&b_h1).expect("H+1 carries precommit_qc");
    assert_eq!(hdr_h1.body_commitment, Some(b_h1.body_commitment()));
    hdr_h1
        .verify_with_schedule(&vs, CommitteeSchedule::ParentHash)
        .expect("valid v4 LightHeader at H+1 must verify");

    // LightClient::apply_header trusts block.state_root and retains mmr_epoch_root.
    let mut lc = LightClient::new(vs.clone(), cp_h.clone()).expect("anchor at H");
    lc.apply_header(hdr_h1.clone())
        .expect("valid v4 LightHeader at H+1 must apply");
    assert_eq!(lc.tip_height(), h + 1);
    assert_eq!(lc.state_root(), b_h1.state_root);
    assert!(lc.trusts_root(&b_h1.state_root));
    assert_eq!(
        lc.headers().back().expect("header retained").mmr_epoch_root,
        b_h1.mmr_epoch_root
    );

    // LightClient::apply_header_without_block_signatures also accepts valid v4 header.
    let mut lc_no_sigs = LightClient::new(vs.clone(), cp_h).expect("anchor at H");
    lc_no_sigs
        .apply_header_without_block_signatures(hdr_h1)
        .expect("valid v4 apply_header_without_block_signatures at H+1 must pass");
    assert_eq!(lc_no_sigs.state_root(), b_h1.state_root);
    assert_eq!(
        lc_no_sigs
            .headers()
            .back()
            .expect("header retained")
            .mmr_epoch_root,
        b_h1.mmr_epoch_root
    );

    // Historical root JSON at H and H+1 parse, verify, and advance LightClient.
    let cp_hr_h =
        Checkpoint::from_historical_root_json(&historical_root_json_from_block(h - 1, &b_h))
            .expect("valid v4 historical root at H must parse");
    cp_hr_h.verify(&vs).expect("historical root at H verifies");

    let cp_hr_h1 =
        Checkpoint::from_historical_root_json(&historical_root_json_from_block(h, &b_h1))
            .expect("valid v4 historical root at H+1 must parse");
    cp_hr_h1
        .verify(&vs)
        .expect("historical root at H+1 verifies");
    lc.advance_to_checkpoint(cp_hr_h1)
        .expect("advance_to_checkpoint at H+1 succeeds");
    assert_eq!(lc.state_root(), b_h1.state_root);

    // ServedHeader CLI checks pass at H and H+1.
    let served_h = parse_served_header(&finalized_header_json_from_block(&b_h))
        .expect("served header at H parses");
    check_anchoring_header(&served_h, h, Some(h - 1)).expect("served header at H verifies");

    let served_h1 = parse_served_header(&finalized_header_json_from_block(&b_h1))
        .expect("served header at H+1 parses");
    check_anchoring_header(&served_h1, h + 1, Some(h)).expect("served header at H+1 verifies");
}

#[derive(Clone, Copy)]
enum ForgeKind {
    StateRoot,
    PrevHash,
    MissingBodyCommitment,
    WrongShardId,
}

fn assert_all_v4_paths_reject_forged(
    target_height: u64,
    anchor_cp: &Checkpoint,
    honest_block: &Block,
    vs: &ValidatorSet,
    kind: ForgeKind,
) {
    let honest_hdr = LightHeader::of_block(honest_block).expect("precommit_qc present");
    let mut forged_hdr = honest_hdr.clone();
    let mut forged_cp = Checkpoint::of(&honest_hdr);
    let mut forged_hr_json = historical_root_json_from_block(target_height - 1, honest_block);
    let mut forged_served: ServedHeader =
        parse_served_header(&finalized_header_json_from_block(honest_block))
            .expect("honest served header parses");

    match kind {
        ForgeKind::StateRoot => {
            forged_hdr.state_root[0] ^= 0xFF;
            forged_cp.state_root[0] ^= 0xFF;
            forged_hr_json["state_root"] = serde_json::json!(hex::encode(forged_cp.state_root));
            forged_served.state_root[0] ^= 0xFF;
        }
        ForgeKind::PrevHash => {
            forged_hdr.prev_hash[0] ^= 0xFF;
            forged_cp.parent_hash[0] ^= 0xFF;
            forged_hr_json["prev_hash"] = serde_json::json!(hex::encode(forged_cp.parent_hash));
            forged_served.prev_hash[0] ^= 0xFF;
        }
        ForgeKind::MissingBodyCommitment => {
            forged_hdr.body_commitment = None;
            forged_cp.body_commitment = None;
            forged_hr_json["body_commitment"] = serde_json::Value::Null;
            forged_served.body_commitment = None;
        }
        ForgeKind::WrongShardId => {
            forged_hdr.shard_id = 1;
            forged_cp.shard_id = 1;
            forged_hr_json["shard_id"] = serde_json::json!(1u32);
            forged_served.shard_id = 1;
        }
    }

    assert!(
        forged_cp
            .verify_with_schedule(vs, CommitteeSchedule::ParentHash)
            .is_err(),
        "Checkpoint::verify_with_schedule must reject forged header at height {target_height}"
    );
    assert!(
        forged_hdr
            .verify_with_schedule(vs, CommitteeSchedule::ParentHash)
            .is_err(),
        "LightHeader::verify_with_schedule must reject forged header at height {target_height}"
    );

    // Note: for PrevHash, check_header_shape would also catch parent mismatch against tip;
    // for StateRoot / MissingBodyCommitment / WrongShardId, prev_hash still matches tip!
    let mut lc = LightClient::new(vs.clone(), anchor_cp.clone()).expect("valid anchor");
    assert!(
        lc.apply_header_without_block_signatures(forged_hdr)
            .is_err(),
        "apply_header_without_block_signatures must reject forged header at height {target_height}"
    );
    assert_eq!(lc.tip_height(), anchor_cp.height);

    assert!(
        Checkpoint::from_historical_root_json(&forged_hr_json).is_err(),
        "Checkpoint::from_historical_root_json must reject forged header at height {target_height}"
    );

    assert!(
        check_anchoring_header(&forged_served, target_height, None).is_err(),
        "light_client_cli::check_anchoring_header must reject forged header at height {target_height}"
    );
}

#[test]
fn v4_forged_fields_with_genuine_precommit_qc_are_rejected_at_h_and_h_plus_1() {
    let h = 10u64;
    let _guard = HeaderCommitOverrideGuard::new(Some(h));

    let (keys, fks) = falcon_votes::falcon_set(4);
    let vs = validator_set_from(&keys);

    let b_pre = make_finalized_block(
        h - 1,
        0,
        [0x09u8; 32],
        [0x90u8; 32],
        [0x11u8; 32],
        [0x22u8; 32],
        &keys,
        &fks,
        &vs,
    );
    let cp_pre = Checkpoint::of(&LightHeader::of_block(&b_pre).expect("pre qc"));

    let b_h = make_finalized_block(
        h,
        1,
        b_pre.compute_hash(),
        [0xA0u8; 32],
        [0xB0u8; 32],
        [0xC0u8; 32],
        &keys,
        &fks,
        &vs,
    );
    let cp_h = Checkpoint::of(&LightHeader::of_block(&b_h).expect("H qc"));

    let b_h1 = make_finalized_block(
        h + 1,
        2,
        b_h.compute_hash(),
        [0xA1u8; 32],
        [0xB1u8; 32],
        [0xC1u8; 32],
        &keys,
        &fks,
        &vs,
    );

    for kind in [
        ForgeKind::StateRoot,
        ForgeKind::PrevHash,
        ForgeKind::MissingBodyCommitment,
        ForgeKind::WrongShardId,
    ] {
        assert_all_v4_paths_reject_forged(h, &cp_pre, &b_h, &vs, kind);
        assert_all_v4_paths_reject_forged(h + 1, &cp_h, &b_h1, &vs, kind);
    }
}

#[test]
fn v4_revisiting_earlier_state_root_a_b_a_succeeds_across_activation() {
    let h = 10u64;
    let _guard = HeaderCommitOverrideGuard::new(Some(h));

    let (keys, fks) = falcon_votes::falcon_set(4);
    let vs = validator_set_from(&keys);

    let root_a = [0xAAu8; 32];
    let root_b = [0xBBu8; 32];

    let b_pre = make_finalized_block(
        h - 1,
        0,
        [0x09u8; 32],
        root_a,
        [0x10u8; 32],
        [0x20u8; 32],
        &keys,
        &fks,
        &vs,
    );
    let b_h = make_finalized_block(
        h,
        0,
        b_pre.compute_hash(),
        root_b,
        [0x11u8; 32],
        [0x21u8; 32],
        &keys,
        &fks,
        &vs,
    );
    let b_h1 = make_finalized_block(
        h + 1,
        0,
        b_h.compute_hash(),
        root_a, // valid A -> B -> A return to earlier root
        [0x12u8; 32],
        [0x22u8; 32],
        &keys,
        &fks,
        &vs,
    );

    let cp_pre = Checkpoint::of(&LightHeader::of_block(&b_pre).expect("H-1 qc"));
    let hdr_h = LightHeader::of_block(&b_h).expect("H qc");
    let hdr_h1 = LightHeader::of_block(&b_h1).expect("H+1 qc");

    let mut lc = LightClient::new(vs, cp_pre).expect("anchor at H-1");
    lc.apply_header(hdr_h)
        .expect("transition A -> B at H must succeed");
    lc.apply_header(hdr_h1)
        .expect("transition B -> A at H+1 must succeed without superseded_root rejection");

    assert_eq!(lc.tip_height(), h + 1);
    assert_eq!(lc.state_root(), root_a);
    assert_eq!(
        lc.headers().back().expect("tip header").mmr_epoch_root,
        b_h1.mmr_epoch_root
    );
}
