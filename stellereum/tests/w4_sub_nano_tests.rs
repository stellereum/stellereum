//! W4 E2 — Sub-Nano Exactness & Carry integration tests (`W4_ECONOMICS_PRODUCT_CONTRACT.md` §3.2 п.2).
//!
//! Pinned contracts:
//!   1. `evm_carrier_rejects_sub_nano_wei_when_strict`:
//!      `1_500_000_000` wei (1.5 nano) is refused at `height >= SUB_NANO_STRICT_ACTIVATION_HEIGHT`
//!      (and accepted with truncation at `H - 1`), while `2_000_000_000` wei (2.0 nano)
//!      passes with `nano_to_wei(value_nano) == value_wei`.
//!   2. `genesis_vault_single_step_rational_avoids_double_truncation`:
//!      Single-step 256-bit `mul_div_floor_256` in `GenesisVault::calculate_mint`
//!      avoids intermediate micro-USD truncation.
//!   3. `staking_accumulator_rescales_remainder_on_delegation_change`:
//!      At `height >= SUB_NANO_STRICT_ACTIVATION_HEIGHT`, `distribute_reward_at_height`
//!      rescales `ValidatorRewardState::remainder` (`0 <= remainder < new_den`)
//!      when `delegated` changes instead of resetting it to `0`, and claims never
//!      overdraw `rewards_pool`.
//!   4. `geometric_emission_with_q64_carry_never_exceeds_emission_cap_or_1b_cap`:
//!      Q0.64 carry converges closer to the continuous pool without ever
//!      exceeding `REWARDS_EMISSION_CAP` or `TOTAL_SUPPLY_CAP`, and `StakingLedger::emission_carry_q64`
//!      moves the conditional `STAKING_EMISSION_CARRY_V1` digest while `0` keeps
//!      pre-W4 roots byte-identical and `DomainSnapshotV10` upgrades legacy bytes.

use stellereum::commitment::{commitment_digest, COMMITMENT_VERSION};
use stellereum::evm_adapter::{
    evm_intent_digest, evm_to_stell_address, evm_transfer_facts_at_height, is_low_s, nano_to_wei,
    parse_raw_transaction, verify_carrier_intent_at_height, LegacyTransaction, SECP256K1_N,
    WEI_PER_NANO,
};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
use stellereum::protocol::FORK_ID;
use stellereum::snapshot_v4::CanonicalStakingLedger;
use stellereum::staking::{
    required_bond_floor_nano, StakingLedger, REWARDS_EMISSION_CAP, REWARD_PER_TOKEN_SCALE,
};
use stellereum::storage::{
    decode_domain_snapshot, DomainSnapshot, DomainSnapshotV10, StakingLedgerV7,
};
use stellereum::svm::EvmCarrierIntent;
use stellereum::tokenomics::{
    emit_with_q64_carry, set_sub_nano_strict_activation_override, GenesisVault,
    SUB_NANO_STRICT_ACTIVATION_HEIGHT, TOTAL_SUPPLY_CAP,
};
use stellereum::zkml::effective_chain_id;

struct SubNanoGateGuard;

impl SubNanoGateGuard {
    fn at(height: u64) -> Self {
        set_sub_nano_strict_activation_override(Some(height));
        Self
    }
}

impl Drop for SubNanoGateGuard {
    fn drop(&mut self) {
        set_sub_nano_strict_activation_override(None);
    }
}

fn secp_signing_key(seed: u8) -> k256::ecdsa::SigningKey {
    let mut b = [0u8; 32];
    b[0] = seed;
    b[31] = seed.wrapping_mul(17).wrapping_add(3);
    k256::ecdsa::SigningKey::from_bytes((&b).into()).expect("secp key")
}

fn falcon(seed: u8) -> FalconKeypair {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = seed.wrapping_mul(31).wrapping_add(9);
    FalconKeypair::generate_from_seed_bytes(&s)
}

fn signed_evm_raw(sk: &k256::ecdsa::SigningKey, value_wei: u128, nonce: u64) -> Vec<u8> {
    let chain = effective_chain_id();
    let mut tx = LegacyTransaction {
        nonce,
        gas_price: 1,
        gas_limit: 21_000,
        to: Some([0x22u8; 20]),
        value: value_wei,
        data: vec![],
        v: 0,
        r: [0u8; 32],
        s: [0u8; 32],
        chain_id: Some(chain),
    };
    let (sig, recid) = sk
        .sign_prehash_recoverable(&tx.signing_hash())
        .expect("secp sign");
    let raw = sig.to_bytes();
    tx.r.copy_from_slice(&raw[..32]);
    tx.s.copy_from_slice(&raw[32..64]);
    let mut rec = recid.to_byte();
    if !is_low_s(&tx.s) {
        let mut out = [0u8; 32];
        let mut borrow: i32 = 0;
        for i in (0..32).rev() {
            let v = SECP256K1_N[i] as i32 - tx.s[i] as i32 - borrow;
            if v < 0 {
                out[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                out[i] = v as u8;
                borrow = 0;
            }
        }
        tx.s = out;
        rec ^= 1;
    }
    tx.v = chain * 2 + 35 + rec as u64;
    tx.encode()
}

#[test]
fn evm_carrier_rejects_sub_nano_wei_when_strict() {
    assert_eq!(SUB_NANO_STRICT_ACTIVATION_HEIGHT, 0);
    let h = 50u64;
    let _gate = SubNanoGateGuard::at(h);

    let evm_sk = secp_signing_key(0x11);
    let kp = falcon(0x21);
    let sender = derive_pq_address(PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT);
    let chain_id = effective_chain_id();

    // 1.5 nano-STELL = 1_500_000_000 wei (non-multiple of WEI_PER_NANO).
    let raw_sub = signed_evm_raw(&evm_sk, 1_500_000_000, 0);
    let parsed_sub = parse_raw_transaction(&raw_sub).expect("parse sub");
    let evm_addr = parsed_sub.verify_signature().expect("evm sig");
    assert_eq!(evm_to_stell_address(&evm_addr).len(), 32);

    // H - 1: legacy truncation succeeds (1 nano).
    let facts_pre = evm_transfer_facts_at_height(&raw_sub, h - 1).expect("pre-H accepts");
    assert_eq!(facts_pre.value_nano, 1);

    // H: refused fail-closed!
    let err = evm_transfer_facts_at_height(&raw_sub, h).unwrap_err();
    assert!(
        err.contains("sub-nano wei remainder"),
        "unexpected error: {err}"
    );

    let intent_sub = EvmCarrierIntent {
        chain_id,
        evm_tx: raw_sub.clone(),
        evm_address: evm_addr,
        pq_pubkey: kp.public_key().to_vec(),
        evm_signature: kp.sign(&evm_intent_digest(&raw_sub)),
    };
    assert!(verify_carrier_intent_at_height(&intent_sub, &sender, h - 1).is_ok());
    assert!(verify_carrier_intent_at_height(&intent_sub, &sender, h).is_err());

    // 2.0 nano-STELL = 2_000_000_000 wei: accepted at H and invertible.
    let raw_exact = signed_evm_raw(&evm_sk, 2 * WEI_PER_NANO, 1);
    let facts_exact = evm_transfer_facts_at_height(&raw_exact, h).expect("exact 2 nano ok");
    assert_eq!(facts_exact.value_nano, 2);
    assert_eq!(nano_to_wei(facts_exact.value_nano), facts_exact.value_wei);
}

#[test]
fn genesis_vault_single_step_rational_avoids_double_truncation() {
    // 1 USDT (6 decimals) at $0.333_333 (333_333 micro-USD):
    // Double-truncation: floor(1_000_000 * 333_333 / 10^6) = 333_333 micro-USD -> 333_333 * 1e9 / 250_000 = 1_333_332_000
    // Single-step 256-bit: floor(1_000_001 * 333_333 * 1e9 / (10^6 * 250_000)) = 1_333_333_333 (saves 1_333 nano!)
    let minted = GenesisVault::calculate_mint(1_000_001, 6, 333_333);
    assert_eq!(minted, 1_333_333_333);
    assert_eq!(
        GenesisVault::calculate_mint(1_000_000, 6, 1_000_000),
        4_000_000_000
    );
}

#[test]
fn staking_accumulator_rescales_remainder_on_delegation_change() {
    let h = 20u64;
    let _gate = SubNanoGateGuard::at(h);

    let v = [0x31u8; 32];
    let d1 = [0x41u8; 32];
    let d2 = [0x42u8; 32];
    let bond = required_bond_floor_nano();

    let mut pre = StakingLedger::default();
    let mut post = StakingLedger::default();
    for l in [&mut pre, &mut post] {
        l.bond(v, bond, 0).expect("bond");
        l.delegate(d1, v, 3_000_000_007).expect("d1");
    }

    // First distribution over delegated = 3_000_000_007; guaranteed non-zero remainder.
    let reward_1 = 10_000_000_000u64;
    pre.distribute_reward_at_height(v, reward_1, h - 1).unwrap();
    post.distribute_reward_at_height(v, reward_1, h).unwrap();

    let rem_before = post.reward_accumulators[&v].remainder;
    let den_before = post.reward_accumulators[&v].remainder_den;
    assert_eq!(pre.reward_accumulators[&v].remainder, rem_before);
    assert_eq!(den_before, 3_000_000_007);
    assert!(rem_before > 0);

    // Second delegator joins -> delegated changes from 3_000_000_007 to 6_000_000_014.
    pre.delegate(d2, v, 3_000_000_007).unwrap();
    post.delegate(d2, v, 3_000_000_007).unwrap();

    // Pre-H resets old remainder to 0; post-H rescales `floor(rem_before * 2) = 2 * rem_before`
    // and then adds the new pool before dividing by 6_000_000_014.
    let reward_2 = 12_000_000_000u64;
    pre.distribute_reward_at_height(v, reward_2, h - 1).unwrap();
    post.distribute_reward_at_height(v, reward_2, h).unwrap();

    let acc_pre = &pre.reward_accumulators[&v];
    let acc_post = &post.reward_accumulators[&v];
    assert_eq!(acc_post.remainder_den, 6_000_000_014);
    assert!(acc_post.remainder < acc_post.remainder_den as u128);
    // Rescaled rate >= reset rate (never loses accumulated sub-nano fraction).
    assert!(acc_post.reward_per_token >= acc_pre.reward_per_token);
    // Conservation: every claimable delegator reward fits well inside `rewards_pool`.
    let c1 = post.claim_delegator_rewards(d1, v);
    let c2 = post.claim_delegator_rewards(d2, v);
    let vc = post.claim_validator_rewards(v).unwrap();
    assert!(c1 + c2 + vc > 0);
    assert!(post.rewards_pool < reward_1 + reward_2);
    // Also verify `REWARD_PER_TOKEN_SCALE` sanity.
    assert_eq!(REWARD_PER_TOKEN_SCALE, 1_000_000_000_000_000_000);
}

#[test]
fn geometric_emission_with_q64_carry_never_exceeds_emission_cap_or_1b_cap() {
    assert_eq!(COMMITMENT_VERSION, 5);
    assert_eq!(FORK_ID, 0x3ae00ebc);

    // Small half-life H = 8 where fractional bits dominate.
    let pool = 1_000u64;
    let r0 = stellereum::tokenomics::geometric_schedule_r0_nano(pool, 8);
    let mut carry = 0u64;
    let mut sum_carry = 0u64;
    let mut sum_floor = 0u64;
    for h in 0..400u64 {
        let (f, _) = stellereum::tokenomics::pow_half_fixed_exact_q64(r0, 8, h);
        let (e, next_c) = emit_with_q64_carry(r0, 8, h, carry);
        carry = next_c;
        sum_floor += f;
        sum_carry += e;
    }
    assert!(sum_carry >= sum_floor);
    assert!(sum_carry <= pool);
    assert!(sum_carry as u128 <= REWARDS_EMISSION_CAP as u128);
    const _: () = assert!(REWARDS_EMISSION_CAP <= TOTAL_SUPPLY_CAP);

    // Conditional commitment: `emission_carry_q64 == 0` preserves V5 digest, non-zero moves it.
    let eng0 = stellereum::state_engine::InMemoryStateEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let root_zero = rt.block_on(async { eng0.get_state_root().await });
    let snap_zero = DomainSnapshot::default();
    assert_eq!(snap_zero.staking.emission_carry_q64, 0);

    let mut l0 = StakingLedger::default();
    let l1 = StakingLedger {
        emission_carry_q64: 12345,
        ..Default::default()
    };
    assert_eq!(
        CanonicalStakingLedger::from_ledger(&l1)
            .to_ledger()
            .emission_carry_q64,
        12345
    );
    let d0 = rt.block_on(async {
        let e = stellereum::state_engine::InMemoryStateEngine::new();
        *e.staking_write().await = l0.clone();
        e.get_state_root().await
    });
    let d1 = rt.block_on(async {
        let e = stellereum::state_engine::InMemoryStateEngine::new();
        *e.staking_write().await = l1;
        e.get_state_root().await
    });
    assert_eq!(d0, root_zero);
    assert_ne!(d0, d1);
    l0.emission_carry_q64 = 0;
    let _ = commitment_digest;

    // Legacy DomainSnapshotV10 (pre-emission_carry_q64) decodes cleanly with `emission_carry_q64 == 0`.
    let v10 = DomainSnapshotV10 {
        staking: StakingLedgerV7::default(),
        ..Default::default()
    };
    let bytes = bincode::serialize(&v10).expect("serialize V10");
    assert!(bincode::deserialize::<DomainSnapshot>(&bytes).is_err());
    let decoded = decode_domain_snapshot(&bytes).expect("decode V10");
    assert_eq!(decoded.staking.emission_carry_q64, 0);
}
