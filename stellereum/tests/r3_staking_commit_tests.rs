//! R3-B: `ValidatorStake::withdrawal_address`, owner authorization,
//! height-/retention-aware `slash_pq_equivocation_at_height`, conditional
//! `STAKING_WITHDRAWAL_V1` + `Domain::PqRegistry` commitment preimages, and
//! `COMMITMENT_VERSION == 5` preservation.

use std::collections::HashMap;

use stellereum::commitment::{
    assemble_cached_digest_with_all_domains,
    assemble_cached_digest_with_cnvrf_minted_and_evm_bindings, books_preimage, bridge_preimage,
    cnvrf_v3_preimage, commitment_digest, commitment_digest_with_all_domains,
    commitment_digest_with_zkml_cnvrf_minted_and_evm_bindings, contracts_preimage,
    cross_shard_preimage, escrow_preimage, evm_bindings_preimage, governance_preimage,
    oracle_preimage, pmm_preimage, pq_registry_digest, pq_registry_preimage, session_keys_preimage,
    staking_preimage, tokens_preimage, xpc_preimage, zkml_preimage, CommitmentSnapshot, Domain,
    DomainCache, DomainGenerations, COMMITMENT_VERSION,
};
use stellereum::consensus::{vote_sign_bytes, ValidatorId, VoteKind};
use stellereum::post_quantum::{FalconKeypair, PqScheme};
use stellereum::pq_registry::{
    pq_voting_key_pop_preimage, set_pq_lifecycle_activation_override, PqRegistry,
    PQ_EVIDENCE_RETENTION_HEIGHTS, PQ_ROTATION_DELAY_HEIGHTS,
};
use stellereum::staking::{
    pq_claim_withdrawal_preimage, required_bond_floor_nano, CompactPqEquivocationEvidence,
    StakingError, StakingLedger, ValidatorStake, DEFAULT_COMMISSION_BPS, EQUIVOCATION_SLASH_BPS,
};
use stellereum::state_engine::{CnVrfV3EngineSnapshot, EvmBindingsState};

const CHAIN_ID: u64 = 1;

struct PqLifecycleGateGuard;

impl PqLifecycleGateGuard {
    fn at(height: u64) -> Self {
        set_pq_lifecycle_activation_override(Some(height));
        Self
    }
}

impl Drop for PqLifecycleGateGuard {
    fn drop(&mut self) {
        set_pq_lifecycle_activation_override(None);
    }
}

fn falcon(seed: u8) -> FalconKeypair {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = seed.wrapping_mul(73).wrapping_add(1);
    FalconKeypair::generate_from_seed_bytes(&s)
}

fn empty_snapshot() -> CommitmentSnapshot {
    CommitmentSnapshot {
        tokens: stellereum::token::TokenRegistry::new(),
        staking: StakingLedger::new(),
        orderbooks: stellereum::orderbook::OrderbookManager::new(),
        order_escrow: HashMap::new(),
        pmm: stellereum::pmm::PrimaryMarketMaker::new(),
        pmm_usdt_token: None,
        pmm_treasury: [0u8; 32],
        contracts: stellereum::contract::ContractRegistry::new(),
        governance: stellereum::governance::Governance::new(),
        oracle: stellereum::oracle::OracleState::default(),
        session_keys: stellereum::zkml::SessionKeyRegistry::default(),
        bridge: stellereum::bridge::BridgeState::default(),
        cross_shard_consumed: Vec::new(),
        cross_shard_produced: Vec::new(),
        cross_shard_completed: Vec::new(),
        cross_shard_xpc: Vec::new(),
    }
}

fn sign_pop(
    kp: &FalconKeypair,
    chain_id: u64,
    validator_id: &ValidatorId,
    withdrawal_address: &[u8; 32],
    rotation_seq: u64,
) -> Vec<u8> {
    let preimage = pq_voting_key_pop_preimage(
        chain_id,
        validator_id,
        withdrawal_address,
        rotation_seq,
        PqScheme::Falcon512,
        kp.public_key(),
    );
    kp.sign(&preimage)
}

fn domain_preimages_13<'a>(
    s: &'a CommitmentSnapshot,
    zkml: &'a stellereum::zkml::ZkMlModelRegistry,
) -> [Vec<u8>; 13] {
    [
        tokens_preimage(&s.tokens),
        staking_preimage(&s.staking),
        pmm_preimage(&s.pmm, &s.pmm_usdt_token, &s.pmm_treasury),
        contracts_preimage(&s.contracts),
        escrow_preimage(&s.order_escrow),
        governance_preimage(&s.governance),
        oracle_preimage(&s.oracle),
        session_keys_preimage(&s.session_keys),
        books_preimage(&s.orderbooks),
        bridge_preimage(&s.bridge),
        cross_shard_preimage(
            &s.cross_shard_consumed,
            &s.cross_shard_produced,
            &s.cross_shard_completed,
        ),
        xpc_preimage(&s.cross_shard_xpc),
        zkml_preimage(zkml),
    ]
}

#[test]
fn empty_withdrawal_and_pq_registry_preserve_v5_commitment_byte_for_byte() {
    assert_eq!(COMMITMENT_VERSION, 5);

    let mut snap = empty_snapshot();
    let v1 = [0x11u8; 32];
    snap.staking
        .bond(v1, required_bond_floor_nano(), DEFAULT_COMMISSION_BPS)
        .unwrap();
    assert_eq!(snap.staking.validators[&v1].withdrawal_address, None);

    // Explicit struct with withdrawal_address: None produces identical preimage.
    let mut snap_manual = empty_snapshot();
    snap_manual.staking.validators.insert(
        v1,
        ValidatorStake {
            self_bond: required_bond_floor_nano(),
            delegated: 0,
            commission_bps: DEFAULT_COMMISSION_BPS,
            pending_rewards: 0,
            total_slashed: 0,
            missed: 0,
            last_downtime_penalty: 0,
            withdrawal_address: None,
        },
    );
    assert_eq!(
        staking_preimage(&snap.staking),
        staking_preimage(&snap_manual.staking)
    );

    let zkml = stellereum::zkml::ZkMlModelRegistry::default();
    let cnvrf = CnVrfV3EngineSnapshot::default();
    let evm = EvmBindingsState::default();
    let empty_pq = PqRegistry::default();

    assert!(pq_registry_preimage(&empty_pq).is_empty());

    let d_base = commitment_digest(&snap);
    let d_r2 =
        commitment_digest_with_zkml_cnvrf_minted_and_evm_bindings(&snap, &zkml, &cnvrf, 0, &evm);
    let d_all = commitment_digest_with_all_domains(&snap, &zkml, &cnvrf, 0, &evm, &empty_pq);

    assert_eq!(d_base, d_r2);
    assert_eq!(d_r2, d_all);

    let p = domain_preimages_13(&snap, &zkml);
    let refs: [&[u8]; 13] = [
        &p[0], &p[1], &p[2], &p[3], &p[4], &p[5], &p[6], &p[7], &p[8], &p[9], &p[10], &p[11],
        &p[12],
    ];
    let cnvrf_bytes = cnvrf_v3_preimage(&cnvrf);
    let evm_bytes = evm_bindings_preimage(&evm);
    let pq_bytes = pq_registry_preimage(&empty_pq);

    let cached_r2 = assemble_cached_digest_with_cnvrf_minted_and_evm_bindings(
        refs,
        &cnvrf_bytes,
        0,
        &evm_bytes,
    );
    let cached_all =
        assemble_cached_digest_with_all_domains(refs, &cnvrf_bytes, 0, &evm_bytes, &pq_bytes);

    assert_eq!(cached_r2, d_all);
    assert_eq!(cached_all, d_all);

    // Unused empty snapshot matches the pinned EMPTY_SNAPSHOT_DIGEST contract.
    let pure_empty = empty_snapshot();
    assert_eq!(
        commitment_digest(&pure_empty),
        commitment_digest_with_all_domains(&pure_empty, &zkml, &cnvrf, 0, &evm, &empty_pq)
    );
}

#[test]
fn withdrawal_address_and_pq_registry_move_digest_deterministically() {
    let zkml = stellereum::zkml::ZkMlModelRegistry::default();
    let cnvrf = CnVrfV3EngineSnapshot::default();
    let evm = EvmBindingsState::default();
    let empty_pq = PqRegistry::default();

    let v1 = [0x11u8; 32];
    let v2 = [0x22u8; 32];
    let w1 = [0xA1u8; 32];
    let w2 = [0xB2u8; 32];

    let mut base = empty_snapshot();
    base.staking
        .bond(v1, required_bond_floor_nano(), DEFAULT_COMMISSION_BPS)
        .unwrap();
    let d_none = commitment_digest_with_all_domains(&base, &zkml, &cnvrf, 0, &evm, &empty_pq);

    // Setting withdrawal_address changes staking_preimage & commitment_digest.
    let mut with_w = base.clone();
    with_w
        .staking
        .validators
        .get_mut(&v1)
        .unwrap()
        .withdrawal_address = Some(w1);
    let d_w1 = commitment_digest_with_all_domains(&with_w, &zkml, &cnvrf, 0, &evm, &empty_pq);
    assert_ne!(d_w1, d_none);

    // Changing withdrawal_address changes the digest again.
    let mut with_w2 = base.clone();
    with_w2
        .staking
        .validators
        .get_mut(&v1)
        .unwrap()
        .withdrawal_address = Some(w2);
    let d_w2 = commitment_digest_with_all_domains(&with_w2, &zkml, &cnvrf, 0, &evm, &empty_pq);
    assert_ne!(d_w2, d_w1);

    // Clearing back to None restores exact pre-withdrawal digest.
    let mut cleared = with_w.clone();
    cleared
        .staking
        .validators
        .get_mut(&v1)
        .unwrap()
        .withdrawal_address = None;
    assert_eq!(
        commitment_digest_with_all_domains(&cleared, &zkml, &cnvrf, 0, &evm, &empty_pq),
        d_none
    );

    // Insertion-order independence across HashMap insertion orders.
    let mut ord_a = empty_snapshot();
    ord_a
        .staking
        .bond_with_withdrawal(v1, required_bond_floor_nano(), DEFAULT_COMMISSION_BPS, w1)
        .unwrap();
    ord_a
        .staking
        .bond_with_withdrawal(v2, required_bond_floor_nano(), DEFAULT_COMMISSION_BPS, w2)
        .unwrap();
    let mut ord_b = empty_snapshot();
    ord_b
        .staking
        .bond_with_withdrawal(v2, required_bond_floor_nano(), DEFAULT_COMMISSION_BPS, w2)
        .unwrap();
    ord_b
        .staking
        .bond_with_withdrawal(v1, required_bond_floor_nano(), DEFAULT_COMMISSION_BPS, w1)
        .unwrap();
    assert_eq!(
        staking_preimage(&ord_a.staking),
        staking_preimage(&ord_b.staking)
    );

    // PqRegistry commits all fields: activated_at, next_seq, pending, history.
    let kp1 = falcon(1);
    let kp2 = falcon(2);
    let kp3 = falcon(3);
    let mut reg1 = PqRegistry::new();
    reg1.register_with_seq(
        v1,
        PqScheme::Falcon512,
        kp1.public_key().to_vec(),
        10,
        10,
        0,
        true,
    )
    .unwrap();
    let d_reg1 = commitment_digest_with_all_domains(&base, &zkml, &cnvrf, 0, &evm, &reg1);
    assert_ne!(d_reg1, d_none);
    assert_ne!(pq_registry_digest(&reg1), pq_registry_digest(&empty_pq));

    // Pending rotation moves digest and bumps next_seq.
    let mut reg_pending = reg1.clone();
    reg_pending
        .announce_rotation_seq(
            v1,
            PqScheme::Falcon512,
            kp2.public_key().to_vec(),
            100,
            1,
            true,
        )
        .unwrap();
    let d_pending = commitment_digest_with_all_domains(&base, &zkml, &cnvrf, 0, &evm, &reg_pending);
    assert_ne!(d_pending, d_reg1);

    // Applying rotation moves pending -> history and changes digest again.
    let mut reg_applied = reg_pending.clone();
    reg_applied
        .apply_rotation(v1, 100 + PQ_ROTATION_DELAY_HEIGHTS, true)
        .unwrap();
    let d_applied = commitment_digest_with_all_domains(&base, &zkml, &cnvrf, 0, &evm, &reg_applied);
    assert_ne!(d_applied, d_pending);

    // Next rotation (next_seq = 2) moves digest further.
    let mut reg_next = reg_applied.clone();
    reg_next
        .announce_rotation_seq(
            v1,
            PqScheme::Falcon512,
            kp3.public_key().to_vec(),
            200 + PQ_ROTATION_DELAY_HEIGHTS,
            2,
            true,
        )
        .unwrap();
    let d_next = commitment_digest_with_all_domains(&base, &zkml, &cnvrf, 0, &evm, &reg_next);
    assert_ne!(d_next, d_applied);

    // Streaming == Cached assembly for non-empty withdrawal + PqRegistry.
    let p = domain_preimages_13(&ord_a, &zkml);
    let refs: [&[u8]; 13] = [
        &p[0], &p[1], &p[2], &p[3], &p[4], &p[5], &p[6], &p[7], &p[8], &p[9], &p[10], &p[11],
        &p[12],
    ];
    let cnvrf_bytes = cnvrf_v3_preimage(&cnvrf);
    let evm_bytes = evm_bindings_preimage(&evm);
    let pq_bytes = pq_registry_preimage(&reg_next);
    let streaming_full =
        commitment_digest_with_all_domains(&ord_a, &zkml, &cnvrf, 42, &evm, &reg_next);
    let cached_full =
        assemble_cached_digest_with_all_domains(refs, &cnvrf_bytes, 42, &evm_bytes, &pq_bytes);
    assert_eq!(streaming_full, cached_full);

    // DomainCache silent slot & DomainGenerations tracking.
    assert_eq!(Domain::ALL.len(), 13);
    assert_eq!(Domain::PqRegistry.name(), "pq_registry");
    let gens = DomainGenerations::default();
    assert_eq!(gens.load(Domain::PqRegistry), 0);
    gens.bump(Domain::PqRegistry);
    assert_eq!(gens.load(Domain::PqRegistry), 1);
    let gens_copy = DomainGenerations::default();
    gens.copy_values_into(&gens_copy);
    assert_eq!(gens_copy.load(Domain::PqRegistry), 1);
    gens.bump_all();
    assert_eq!(gens.load(Domain::PqRegistry), 2);

    let mut cache = DomainCache::default();
    assert_eq!(cache.get_pq_registry_silent(1), None);
    cache.put_pq_registry_silent(1, pq_bytes.clone());
    assert_eq!(cache.get_pq_registry_silent(1), Some(pq_bytes));
    assert_eq!(cache.hits, 0);
    assert_eq!(cache.misses, 0);
    assert_eq!(cache.slots_filled(), 1);
}

#[test]
fn slash_pq_equivocation_at_height_supports_5_rotations_within_retention_and_fails_closed_outside()
{
    let _gate = PqLifecycleGateGuard::at(100);

    let mut ledger = StakingLedger::new();
    let mut reg = PqRegistry::new();
    let withdrawal = [0x41u8; 32];

    let kps = [
        falcon(10),
        falcon(11),
        falcon(12),
        falcon(13),
        falcon(14),
        falcon(15),
    ];

    let val_id = ledger
        .pq_register_validator_with_withdrawal(
            &mut reg,
            CHAIN_ID,
            10_000 * 1_000_000_000,
            DEFAULT_COMMISSION_BPS,
            withdrawal,
            PqScheme::Falcon512.id(),
            kps[0].public_key(),
            &sign_pop(
                &kps[0],
                CHAIN_ID,
                &stellereum::pq_registry::derive_validator_id(
                    CHAIN_ID,
                    &withdrawal,
                    kps[0].public_key(),
                ),
                &withdrawal,
                0,
            ),
            100,
        )
        .unwrap();

    // Perform 5 sequential rotations inside the 720,000-block window.
    let mut h = 100u64;
    for (seq, kp) in kps.iter().enumerate().skip(1) {
        let pop = sign_pop(kp, CHAIN_ID, &val_id, &withdrawal, seq as u64);
        ledger
            .pq_announce_rotation_with_seq(
                &mut reg,
                CHAIN_ID,
                val_id,
                withdrawal,
                seq as u64,
                PqScheme::Falcon512.id(),
                kp.public_key(),
                &pop,
                h,
            )
            .unwrap();
        h += PQ_ROTATION_DELAY_HEIGHTS;
        let applied = ledger.pq_apply_due_rotations(&mut reg, h);
        assert_eq!(applied, vec![val_id]);
    }
    // 1st key was superseded at height 100 + 30_000 = 30_100; head key is now kps[5].
    let first_superseded_at = 100 + PQ_ROTATION_DELAY_HEIGHTS;
    assert_eq!(
        ledger.get_pq_key(&val_id),
        Some((PqScheme::Falcon512, kps[5].public_key().to_vec()))
    );
    assert_eq!(reg.history_of(&val_id).unwrap().len(), 5);

    // Build equivocation evidence signed by the 1st key at height 500 (within [100, 30_100)).
    let ev_height = 500u64;
    let msg_a = vote_sign_bytes(ev_height, 0, VoteKind::Prevote, &Some([0xAAu8; 32]));
    let msg_b = vote_sign_bytes(ev_height, 0, VoteKind::Prevote, &Some([0xBBu8; 32]));
    let ev_first = CompactPqEquivocationEvidence::new(
        val_id,
        ev_height,
        0,
        VoteKind::Prevote,
        Some([0xAAu8; 32]),
        kps[0].sign(&msg_a),
        Some([0xBBu8; 32]),
        kps[0].sign(&msg_b),
    );

    // Evidence signed by the head key kps[5] for height 500 must be rejected (wrong key for height 500).
    let ev_wrong_epoch = CompactPqEquivocationEvidence::new(
        val_id,
        ev_height,
        1,
        VoteKind::Prevote,
        Some([0xAAu8; 32]),
        kps[5].sign(&vote_sign_bytes(
            ev_height,
            1,
            VoteKind::Prevote,
            &Some([0xAAu8; 32]),
        )),
        Some([0xBBu8; 32]),
        kps[5].sign(&vote_sign_bytes(
            ev_height,
            1,
            VoteKind::Prevote,
            &Some([0xBBu8; 32]),
        )),
    );
    assert_eq!(
        ledger.slash_pq_equivocation_at_height(&reg, &ev_wrong_epoch, false, 200_000),
        Err(StakingError::InvalidSignature)
    );

    // Within 720,000 blocks of first_superseded_at: slashes 5% using the 1st key!
    let stake_before = ledger.total_stake(&val_id);
    let burned = ledger
        .slash_pq_equivocation_at_height(&reg, &ev_first, false, 200_000)
        .unwrap();
    let expected_burn = (stake_before as u128 * EQUIVOCATION_SLASH_BPS as u128 / 10_000) as u64;
    assert_eq!(burned, expected_burn);
    assert_eq!(ledger.total_stake(&val_id), stake_before - burned);

    // Outside 720,000 blocks (`now_height - first_superseded_at >= PQ_EVIDENCE_RETENTION_HEIGHTS`):
    // fails closed with InvalidSignature (never falls back to head key).
    let ev_expired = CompactPqEquivocationEvidence::new(
        val_id,
        ev_height,
        2,
        VoteKind::Prevote,
        Some([0xCCu8; 32]),
        kps[0].sign(&vote_sign_bytes(
            ev_height,
            2,
            VoteKind::Prevote,
            &Some([0xCCu8; 32]),
        )),
        Some([0xDDu8; 32]),
        kps[0].sign(&vote_sign_bytes(
            ev_height,
            2,
            VoteKind::Prevote,
            &Some([0xDDu8; 32]),
        )),
    );
    let expired_now = first_superseded_at + PQ_EVIDENCE_RETENTION_HEIGHTS;
    let stake_mid = ledger.total_stake(&val_id);
    assert_eq!(
        ledger.slash_pq_equivocation_at_height(&reg, &ev_expired, false, expired_now),
        Err(StakingError::InvalidSignature)
    );
    assert_eq!(ledger.total_stake(&val_id), stake_mid);
}

#[test]
fn slash_pq_equivocation_at_height_pre_w3_fallback_and_post_w3_strict_fail_closed() {
    let _gate = PqLifecycleGateGuard::at(1_000);

    let mut ledger = StakingLedger::new();
    let empty_reg = PqRegistry::new();
    let kp = falcon(21);
    let val_id = [0x51u8; 32];
    ledger
        .bond(val_id, required_bond_floor_nano(), DEFAULT_COMMISSION_BPS)
        .unwrap();
    ledger
        .register_pq_key(val_id, PqScheme::Falcon512, kp.public_key().to_vec())
        .unwrap();

    let ev_h = 50u64;
    let ev_pre = CompactPqEquivocationEvidence::new(
        val_id,
        ev_h,
        0,
        VoteKind::Prevote,
        Some([0x01u8; 32]),
        kp.sign(&vote_sign_bytes(
            ev_h,
            0,
            VoteKind::Prevote,
            &Some([0x01u8; 32]),
        )),
        Some([0x02u8; 32]),
        kp.sign(&vote_sign_bytes(
            ev_h,
            0,
            VoteKind::Prevote,
            &Some([0x02u8; 32]),
        )),
    );

    // Post-W3 (`now_height == 1_000`) with empty PqRegistry: MUST fail closed, never fallback.
    assert_eq!(
        ledger.slash_pq_equivocation_at_height(&empty_reg, &ev_pre, false, 1_000),
        Err(StakingError::InvalidSignature)
    );

    // Pre-W3 (`now_height == 500 < 1_000`) with key not yet in PqRegistry: fallback works.
    let burned = ledger
        .slash_pq_equivocation_at_height(&empty_reg, &ev_pre, false, 500)
        .unwrap();
    assert!(burned > 0);
}

#[test]
fn authorize_validator_owner_enforces_withdrawal_address_post_w3() {
    let mut ledger = StakingLedger::new();
    let val_legacy = [0x31u8; 32];
    let val_w3 = [0x32u8; 32];
    let withdrawal = [0x77u8; 32];
    let outsider = [0x88u8; 32];

    ledger
        .bond(
            val_legacy,
            required_bond_floor_nano(),
            DEFAULT_COMMISSION_BPS,
        )
        .unwrap();
    ledger
        .bond_with_withdrawal(
            val_w3,
            required_bond_floor_nano(),
            DEFAULT_COMMISSION_BPS,
            withdrawal,
        )
        .unwrap();

    assert_eq!(ledger.withdrawal_address_of(&val_legacy), None);
    assert_eq!(ledger.withdrawal_address_of(&val_w3), Some(withdrawal));

    // Pre-W3 (`post_w3 == false`): legacy rule `sender == validator`.
    assert_eq!(
        ledger.authorize_validator_owner(&val_w3, &val_w3, false),
        Ok(())
    );
    assert_eq!(
        ledger.authorize_validator_owner(&val_w3, &withdrawal, false),
        Err(StakingError::Unauthorized)
    );

    // Post-W3 (`post_w3 == true`): strictly `withdrawal_address == Some(sender)`.
    assert_eq!(
        ledger.authorize_validator_owner(&val_w3, &val_w3, true),
        Err(StakingError::Unauthorized)
    );
    assert_eq!(
        ledger.authorize_validator_owner(&val_w3, &outsider, true),
        Err(StakingError::Unauthorized)
    );
    assert_eq!(
        ledger.authorize_validator_owner(&val_w3, &[0u8; 32], true),
        Err(StakingError::Unauthorized)
    );
    assert_eq!(
        ledger.authorize_validator_owner(&val_w3, &withdrawal, true),
        Ok(())
    );

    // Unclaimed legacy validator (`withdrawal_address == None`) fails closed on post-W3.
    assert_eq!(
        ledger.authorize_validator_owner(&val_legacy, &val_legacy, true),
        Err(StakingError::Unauthorized)
    );

    // Zero withdrawal address rejected on bond_with_withdrawal & set_withdrawal_address.
    assert_eq!(
        ledger.bond_with_withdrawal(
            [0x33u8; 32],
            required_bond_floor_nano(),
            DEFAULT_COMMISSION_BPS,
            [0u8; 32]
        ),
        Err(StakingError::ZeroAddress)
    );

    // set_withdrawal_address checks current owner and rejects zero / same address.
    let new_w = [0x99u8; 32];
    assert_eq!(
        ledger.set_withdrawal_address(val_w3, val_w3, new_w),
        Err(StakingError::Unauthorized)
    );
    assert_eq!(
        ledger.set_withdrawal_address(val_w3, withdrawal, [0u8; 32]),
        Err(StakingError::ZeroAddress)
    );
    assert_eq!(
        ledger.set_withdrawal_address(val_w3, withdrawal, withdrawal),
        Err(StakingError::WithdrawalAlreadySet)
    );
    ledger
        .set_withdrawal_address(val_w3, withdrawal, new_w)
        .unwrap();
    assert_eq!(ledger.withdrawal_address_of(&val_w3), Some(new_w));
    assert_eq!(
        ledger.authorize_validator_owner(&val_w3, &withdrawal, true),
        Err(StakingError::Unauthorized)
    );
    assert_eq!(
        ledger.authorize_validator_owner(&val_w3, &new_w, true),
        Ok(())
    );
}

#[test]
fn pq_claim_withdrawal_and_cancel_rotation_enforce_auth_and_one_time_claim() {
    let mut ledger = StakingLedger::new();
    let mut reg = PqRegistry::new();

    let legacy_id = [0x61u8; 32];
    let kp_legacy = falcon(30);
    let kp_next = falcon(31);
    let claimed_w = [0x71u8; 32];

    ledger
        .bond(
            legacy_id,
            required_bond_floor_nano(),
            DEFAULT_COMMISSION_BPS,
        )
        .unwrap();
    ledger
        .register_pq_key(
            legacy_id,
            PqScheme::Falcon512,
            kp_legacy.public_key().to_vec(),
        )
        .unwrap();
    assert_eq!(ledger.pq_adopt_legacy_keys_at(&mut reg, 0), 1);

    // Claim withdrawal with wrong chain_id fails.
    let bad_sig = kp_legacy.sign(&pq_claim_withdrawal_preimage(999, &legacy_id, &claimed_w));
    assert_eq!(
        ledger.pq_claim_withdrawal(&reg, CHAIN_ID, legacy_id, claimed_w, claimed_w, &bad_sig, 5),
        Err(StakingError::InvalidSignature)
    );

    // Valid one-time claim succeeds; second attempt fails with WithdrawalAlreadySet.
    let good_sig = kp_legacy.sign(&pq_claim_withdrawal_preimage(
        CHAIN_ID, &legacy_id, &claimed_w,
    ));
    ledger
        .pq_claim_withdrawal(
            &reg, CHAIN_ID, legacy_id, claimed_w, claimed_w, &good_sig, 5,
        )
        .unwrap();
    assert_eq!(ledger.withdrawal_address_of(&legacy_id), Some(claimed_w));
    assert_eq!(
        ledger.pq_claim_withdrawal(
            &reg,
            CHAIN_ID,
            legacy_id,
            claimed_w,
            [0x72u8; 32],
            &good_sig,
            6
        ),
        Err(StakingError::WithdrawalAlreadySet)
    );

    // Announce and cancel rotation by withdrawal_address (hot validator id rejected).
    let pop = sign_pop(&kp_next, CHAIN_ID, &legacy_id, &claimed_w, 1);
    assert_eq!(
        ledger.pq_announce_rotation_with_seq(
            &mut reg,
            CHAIN_ID,
            legacy_id,
            legacy_id,
            1,
            PqScheme::Falcon512.id(),
            kp_next.public_key(),
            &pop,
            10,
        ),
        Err(StakingError::Unauthorized)
    );
    ledger
        .pq_announce_rotation_with_seq(
            &mut reg,
            CHAIN_ID,
            legacy_id,
            claimed_w,
            1,
            PqScheme::Falcon512.id(),
            kp_next.public_key(),
            &pop,
            10,
        )
        .unwrap();
    assert!(reg.pending_of(&legacy_id).is_some());

    // Cancel from hot validator id fails; cancel from withdrawal_address at seq=2 succeeds.
    assert_eq!(
        ledger.pq_cancel_rotation(&mut reg, legacy_id, legacy_id, 2, 20),
        Err(StakingError::Unauthorized)
    );
    ledger
        .pq_cancel_rotation(&mut reg, legacy_id, claimed_w, 2, 20)
        .unwrap();
    assert!(reg.pending_of(&legacy_id).is_none());
    assert_eq!(reg.record_of(&legacy_id).unwrap().next_seq, 3);
}
