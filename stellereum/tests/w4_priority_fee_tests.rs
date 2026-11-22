//! W4 E1 & OPT-PARALLEL-WAVE integration tests (`W4_ECONOMICS_PRODUCT_CONTRACT.md` §3.2 п.1,
//! `SECURITY_HARDENING_FIXES_CONTRACT.md` §2.5.3).
//!
//! Pinned contracts:
//!   1. `mempool_fee_density_orders_small_high_density_ahead_of_bloated_low_density`:
//!      MP04 ranks a small high-density tx ahead of a bloated low-density tx
//!      with a larger raw bid in `select_for_block_multi`.
//!   2. `fee_market_v2_pre_activation_byte_identical`:
//!      At `FEE_MARKET_V2_ACTIVATION_HEIGHT == u64::MAX`, `priority_fee_per_gas`
//!      leaves `state_root` and `tx_fees` byte-identical to pre-W4 behavior.
//!   3. `fee_market_v2_charges_priority_fee_at_apply_and_parallel_parity`:
//!      At `height >= H`, `priority_fee_per_gas` is debited on both sequential
//!      and parallel plain-wave paths (`parallel_root == sequential_root`,
//!      including `OPT-PARALLEL-WAVE` inline `[;3]` writes, `sponsor == to`,
//!      selective vesting & consensus-penalty floors).
//!   4. `fee_split_burn_proposer_staking_exact_conservation_and_1b_cap`:
//!      `burn + proposer + staking == fees` with zero nano lost; at
//!      `TOTAL_SUPPLY_CAP` and `REWARDS_EMISSION_CAP`, fee transfers succeed
//!      without unlocking burned headroom in `total_minted_nano`.

use stellereum::mempool::Mempool;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::sharding::{
    Block, SponsorAuthorization, Transaction, MASTERCHAIN_SHARD, SPONSOR_SIG_TAG,
};
use stellereum::staking::{
    required_bond_floor_nano, REWARDS_EMISSION_CAP, REWARDS_POOL, STAKING_POOL,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_BASIC_TRANSFER};
use stellereum::tokenomics::{
    set_fee_market_v2_activation_override, TeamVestingSchedule, DEFAULT_FEE_BURN_BPS,
    DEFAULT_FEE_PROPOSER_BPS, DEFAULT_FEE_STAKING_BPS, FEE_MARKET_V2_ACTIVATION_HEIGHT,
    TOTAL_SUPPLY_CAP,
};
use stellereum::zkml::effective_chain_id;

const TS: u64 = 1_760_000_000;
const BAL: u64 = 100_000_000_000_000;

struct FeeMarketGateGuard;

impl FeeMarketGateGuard {
    fn at(height: u64) -> Self {
        set_fee_market_v2_activation_override(Some(height));
        Self
    }
}

impl Drop for FeeMarketGateGuard {
    fn drop(&mut self) {
        set_fee_market_v2_activation_override(None);
    }
}

fn falcon(seed: u8) -> FalconKeypair {
    let mut s = [0u8; 32];
    s[0] = seed;
    s[31] = seed.wrapping_mul(29).wrapping_add(7);
    FalconKeypair::generate_from_seed_bytes(&s)
}

fn pq_addr(kp: &FalconKeypair) -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, kp.public_key(), &DEFAULT_SALT)
}

fn register_implicit(kp: &FalconKeypair) -> [u8; 32] {
    let addr = pq_addr(kp);
    let _ = Transaction::global_implicit_registry().register(
        addr,
        PqScheme::Falcon512,
        kp.public_key(),
        &DEFAULT_SALT,
    );
    addr
}

fn signed_plain_tx(
    kp: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    priority_fee_per_gas: u64,
) -> Transaction {
    let from = register_implicit(kp);
    let chain_id = effective_chain_id();
    let mut probe = Transaction::new_pq_implicit_with_chain(
        from,
        PqScheme::Falcon512,
        vec![0u8; FALCON512_SIG_LEN],
        to,
        amount,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![],
        chain_id,
    );
    probe.priority_fee_per_gas = priority_fee_per_gas;
    let sig = kp.sign(&probe.signing_message());
    let mut tx = Transaction::new_pq_implicit_with_chain(
        from,
        PqScheme::Falcon512,
        sig,
        to,
        amount,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![],
        chain_id,
    );
    tx.priority_fee_per_gas = priority_fee_per_gas;
    tx
}

fn signed_sponsored_plain_tx(
    user_kp: &FalconKeypair,
    sponsor_kp: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    nonce: u64,
    priority_fee_per_gas: u64,
) -> Transaction {
    let from = register_implicit(user_kp);
    let chain_id = effective_chain_id();
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit,
        nonce,
        source_shard: MASTERCHAIN_SHARD,
        target_shard: MASTERCHAIN_SHARD,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas,
    };
    let mut auth = SponsorAuthorization {
        sponsor: pq_addr(sponsor_kp),
        max_fee_per_tx: 100_000_000,
        valid_until: TS + 1_000_000,
        allowed_targets: vec![to],
        chain_id,
        sponsor_sig: Vec::new(),
        sponsor_scheme: Some(PqScheme::Falcon512),
        sponsor_pubkey: Some(sponsor_kp.public_key().to_vec()),
        sponsor_salt: Some(DEFAULT_SALT),
    };
    auth.sponsor_sig = sponsor_kp.sign(&tx.sponsor_message(&auth));
    let suffix = {
        let body = bincode::serialize(&auth).expect("grant serializes");
        let mut out = Vec::with_capacity(body.len() + 7);
        out.extend_from_slice(&body);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(SPONSOR_SIG_TAG);
        out
    };
    tx.signature = Transaction::new_pq_implicit_with_chain(
        from,
        PqScheme::Falcon512,
        vec![0u8; FALCON512_SIG_LEN],
        to,
        amount,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![],
        chain_id,
    )
    .signature;
    tx.signature.extend_from_slice(&suffix);
    let user_sig = user_kp.sign(&tx.signing_message());
    tx.signature = Transaction::new_pq_implicit_with_chain(
        from,
        PqScheme::Falcon512,
        user_sig,
        to,
        amount,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        vec![],
        chain_id,
    )
    .signature;
    tx.signature.extend_from_slice(&suffix);
    assert!(!tx.is_pq_activation(), "must take plan_plain_tx");
    tx
}

fn signed_nop_tx(
    kp: &FalconKeypair,
    gas_limit: u64,
    nonce: u64,
    priority_fee_per_gas: u64,
) -> Transaction {
    let pk = kp.public_key().to_vec();
    let chain_id = effective_chain_id();
    let payload = vec![OpCode::Nop];
    let mut probe = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        pk.clone(),
        vec![0u8; FALCON512_SIG_LEN],
        [0u8; 32],
        0,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload.clone(),
        &DEFAULT_SALT,
        chain_id,
    );
    probe.priority_fee_per_gas = priority_fee_per_gas;
    let sig = kp.sign(&probe.signing_message());
    let mut tx = Transaction::new_pq_explicit_with_chain(
        PqScheme::Falcon512,
        pk,
        sig,
        [0u8; 32],
        0,
        gas_limit,
        nonce,
        MASTERCHAIN_SHARD,
        MASTERCHAIN_SHARD,
        payload,
        &DEFAULT_SALT,
        chain_id,
    );
    tx.priority_fee_per_gas = priority_fee_per_gas;
    tx
}

fn make_block(height: u64, proposer: [u8; 32], txs: Vec<Transaction>) -> Block {
    let order_merkle_root = stellereum::mev::compute_order_merkle_root(&txs);
    Block {
        shard_id: MASTERCHAIN_SHARD,
        height,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        transactions: txs,
        cross_shard_out: vec![],
        timestamp: TS + height,
        proposer,
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        order_merkle_root,
        epoch_key_commitment: [0u8; 32],
        mmr_epoch_root: [0u8; 32],
        cnvrf_v3: None,
        round: 0,
    }
}

#[test]
fn mempool_fee_density_orders_small_high_density_ahead_of_bloated_low_density() {
    let small_kp = falcon(0x01);
    let bloated_kp = falcon(0x02);
    let small_to = [0x11u8; 32];

    // Small 280k gas with priority 50_000 (density ~ 0.1785) vs bloated 10M gas with priority 100_000 (density = 0.01).
    let small_tx = signed_plain_tx(
        &small_kp,
        small_to,
        10,
        GAS_BASIC_TRANSFER + 50_000,
        0,
        50_000,
    );
    let bloated_tx = signed_nop_tx(&bloated_kp, 10_000_000, 0, 100_000);

    assert!(Mempool::fee_density(&small_tx) > Mempool::fee_density(&bloated_tx));

    let mut pool = Mempool::new(1024, 64);
    pool.add_checked(bloated_tx.clone(), BAL)
        .expect("admit bloated");
    pool.add_checked(small_tx.clone(), BAL)
        .expect("admit small");

    let selected = pool.select_for_block_multi(10, 20_000_000, |_| true);
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].compute_tx_hash(), small_tx.compute_tx_hash());
    assert_eq!(selected[1].compute_tx_hash(), bloated_tx.compute_tx_hash());
}

#[tokio::test]
async fn fee_market_v2_pre_activation_byte_identical() {
    assert_eq!(FEE_MARKET_V2_ACTIVATION_HEIGHT, 0);
    let _pre_v7 = FeeMarketGateGuard::at(u64::MAX);

    let sender_kp = falcon(0x03);
    let sender = pq_addr(&sender_kp);
    let recipient = [0x33u8; 32];
    let proposer = [0x99u8; 32];

    let tx_with_tip = signed_plain_tx(
        &sender_kp,
        recipient,
        1_000,
        Mempool::FROZEN_MIN_GAS_FLOOR + 50_000,
        0,
        50_000,
    );
    let tx_no_tip = signed_plain_tx(
        &sender_kp,
        recipient,
        1_000,
        Mempool::FROZEN_MIN_GAS_FLOOR + 50_000,
        0,
        0,
    );

    let e1 = InMemoryStateEngine::new();
    let e2 = InMemoryStateEngine::new();
    for eng in [&e1, &e2] {
        eng.update_account(AccountState::new(sender, BAL)).await;
    }

    let out1 = e1
        .apply_block_transition(&make_block(1, proposer, vec![tx_with_tip]), 0)
        .await;
    let out2 = e2
        .apply_block_transition(&make_block(1, proposer, vec![tx_no_tip]), 0)
        .await;

    assert_eq!(out1.status, vec![true]);
    assert_eq!(out2.status, vec![true]);
    // Pre-activation: priority bid is NOT charged (only intrinsic gas = 280_000).
    assert_eq!(out1.tx_fees, vec![GAS_BASIC_TRANSFER]);
    assert_eq!(out1.tx_fees, out2.tx_fees);
    assert_eq!(e1.get_state_root().await, e2.get_state_root().await);
    assert_eq!(
        e1.get_account(&proposer).await.unwrap().balance,
        GAS_BASIC_TRANSFER
    );
}

#[tokio::test]
async fn fee_market_v2_charges_priority_fee_at_apply_and_parallel_parity() {
    let h = 100u64;
    let _gate = FeeMarketGateGuard::at(h);

    let proposer = [0xAAu8; 32];
    let mut txs = Vec::new();
    let mut senders = Vec::new();
    // 52 disjoint implicit senders (> PARALLEL_WAVE_MIN_TX) so the concurrent rayon wave runs `plan_plain_tx`.
    for i in 0..52u8 {
        let kp = falcon(0x10 + i);
        let addr = pq_addr(&kp);
        let to = [0xB0u8.wrapping_add(i); 32];
        let bid = 1_000 + (i as u64) * 500;
        let tx = signed_plain_tx(&kp, to, 10_000, GAS_BASIC_TRANSFER + bid, 0, bid);
        assert!(!tx.is_pq_activation());
        senders.push((addr, bid));
        txs.push(tx);
    }
    // Add a sponsored plain tx where sponsor == recipient (OPT-PARALLEL-WAVE + FEE_MARKET_V2).
    let user_kp = falcon(0x70);
    let sponsor_kp = falcon(0x71);
    let user_addr = pq_addr(&user_kp);
    let sponsor_addr = pq_addr(&sponsor_kp);
    let sponsor_bid = 25_000u64;
    let sponsored_tx = signed_sponsored_plain_tx(
        &user_kp,
        &sponsor_kp,
        sponsor_addr,
        50_000,
        GAS_BASIC_TRANSFER + sponsor_bid,
        0,
        sponsor_bid,
    );
    txs.push(sponsored_tx);

    // Add a vested sender whose balance allows value+fee (tests selective vesting load).
    let vested_kp = falcon(0x72);
    let vested_addr = pq_addr(&vested_kp);
    let vested_tx = signed_plain_tx(
        &vested_kp,
        [0xE1u8; 32],
        5_000,
        GAS_BASIC_TRANSFER + 3_000,
        0,
        3_000,
    );
    txs.push(vested_tx);

    let seq = InMemoryStateEngine::new().with_parallel_exec(false);
    let par = InMemoryStateEngine::new().with_parallel_exec(true);
    for eng in [&seq, &par] {
        for (addr, _) in &senders {
            eng.update_account(AccountState::new(*addr, BAL)).await;
        }
        eng.update_account(AccountState::new(user_addr, BAL)).await;
        eng.update_account(AccountState::new(sponsor_addr, BAL))
            .await;
        eng.update_account(AccountState::new(vested_addr, BAL))
            .await;
        eng.staking_write().await.vesting_schedules.insert(
            vested_addr,
            TeamVestingSchedule {
                total_allocation: 1_000_000,
                start_timestamp: TS,
                cliff_duration_secs: 0,
                vesting_duration_secs: 10_000,
                claimed_amount: 0,
            },
        );
    }

    // H - 1: priority fee NOT charged; parallel == sequential.
    let blk_pre = make_block(h - 1, proposer, txs.clone());
    let out_seq_pre = seq.apply_block_transition(&blk_pre, 0).await;
    let out_par_pre = par.apply_block_transition(&blk_pre, 0).await;
    assert_eq!(out_seq_pre.tx_fees, vec![GAS_BASIC_TRANSFER; txs.len()]);
    assert_eq!(out_par_pre.tx_fees, out_seq_pre.tx_fees);
    assert_eq!(seq.get_state_root().await, par.get_state_root().await);

    // Fresh engines for H: priority fee IS charged; parallel == sequential.
    let seq_h = InMemoryStateEngine::new().with_parallel_exec(false);
    let par_h = InMemoryStateEngine::new().with_parallel_exec(true);
    for eng in [&seq_h, &par_h] {
        for (addr, _) in &senders {
            eng.update_account(AccountState::new(*addr, BAL)).await;
        }
        eng.update_account(AccountState::new(user_addr, BAL)).await;
        eng.update_account(AccountState::new(sponsor_addr, BAL))
            .await;
        eng.update_account(AccountState::new(vested_addr, BAL))
            .await;
        eng.staking_write().await.vesting_schedules.insert(
            vested_addr,
            TeamVestingSchedule {
                total_allocation: 1_000_000,
                start_timestamp: TS,
                cliff_duration_secs: 0,
                vesting_duration_secs: 10_000,
                claimed_amount: 0,
            },
        );
    }

    let blk_h = make_block(h, proposer, txs);
    let out_seq = seq_h.apply_block_transition(&blk_h, 0).await;
    let out_par = par_h.apply_block_transition(&blk_h, 0).await;

    assert!(out_seq.status.iter().all(|&ok| ok));
    assert_eq!(out_par.status, out_seq.status);
    assert_eq!(out_par.tx_fees, out_seq.tx_fees);
    assert_eq!(out_par.fees_collected, out_seq.fees_collected);
    assert_eq!(seq_h.get_state_root().await, par_h.get_state_root().await);
    for (i, (_, bid)) in senders.iter().enumerate() {
        assert_eq!(out_seq.tx_fees[i], GAS_BASIC_TRANSFER + *bid);
    }
    assert_eq!(
        out_seq.tx_fees[senders.len()],
        GAS_BASIC_TRANSFER + sponsor_bid
    );
    // Sponsor == recipient: final balance = (BAL - fee) + 50_000.
    assert_eq!(
        seq_h.get_account(&sponsor_addr).await.unwrap().balance,
        BAL - (GAS_BASIC_TRANSFER + sponsor_bid) + 50_000
    );
}

#[tokio::test]
async fn fee_split_burn_proposer_staking_exact_conservation_and_1b_cap() {
    let h = 10u64;
    let _gate = FeeMarketGateGuard::at(h);

    assert_eq!(
        DEFAULT_FEE_BURN_BPS + DEFAULT_FEE_PROPOSER_BPS + DEFAULT_FEE_STAKING_BPS,
        10_000
    );

    let sender_kp = falcon(0x80);
    let sender = pq_addr(&sender_kp);
    let proposer = [0x88u8; 32];
    let recipient = [0x89u8; 32];

    let eng = InMemoryStateEngine::new();
    // Put TOTAL_SUPPLY_CAP at full saturation AND REWARDS_EMISSION_CAP at full saturation.
    eng.set_chain_mint_limit_nano(TOTAL_SUPPLY_CAP);
    eng.mint_native(&sender, TOTAL_SUPPLY_CAP - 10_000_000_000_000)
        .await
        .expect("mint near cap");
    // Bond proposer + give it a delegator so staking share splits across validator + delegator.
    let bond = required_bond_floor_nano();
    eng.mint_native(&STAKING_POOL, bond + 500_000_000_000)
        .await
        .expect("mint pool");
    // Fill remaining supply headroom completely so remaining_mint_headroom_nano == 0.
    let rem = eng.remaining_mint_headroom_nano();
    if rem > 0 {
        eng.mint_native(&recipient, rem)
            .await
            .expect("fill exact 1B cap");
    }
    assert_eq!(eng.remaining_mint_headroom_nano(), 0);
    assert_eq!(eng.total_minted_nano(), TOTAL_SUPPLY_CAP);
    // Confirm a new mint fails closed at cap.
    assert!(eng.mint_native(&proposer, 1).await.is_err());

    {
        let mut l = eng.staking_write().await;
        l.bond(proposer, bond, 1_000).expect("bond proposer");
        l.delegate([0x77u8; 32], proposer, 500_000_000_000)
            .expect("delegate");
        l.rewards_minted = REWARDS_EMISSION_CAP;
    }

    // Odd fee sum (e.g. 280_000 + 17_777 = 297_777) tests exact nano remainder conservation.
    let bid = 17_777u64;
    let tx = signed_plain_tx(
        &sender_kp,
        recipient,
        1_000,
        GAS_BASIC_TRANSFER + bid,
        0,
        bid,
    );
    let blk = make_block(h, proposer, vec![tx]);

    let pre_sender = eng.get_account(&sender).await.unwrap().balance;
    let pre_pool = eng
        .get_account(&REWARDS_POOL)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);
    let pre_proposer = eng
        .get_account(&proposer)
        .await
        .map(|a| a.balance)
        .unwrap_or(0);

    let out = eng.apply_block_transition(&blk, 0).await;
    assert_eq!(out.status, vec![true]);
    let fees = out.fees_collected;
    assert_eq!(fees, GAS_BASIC_TRANSFER + bid);

    let expected_burn = ((fees as u128) * (DEFAULT_FEE_BURN_BPS as u128) / 10_000) as u64;
    let expected_staking = ((fees as u128) * (DEFAULT_FEE_STAKING_BPS as u128) / 10_000) as u64;
    let expected_proposer = fees - expected_burn - expected_staking;
    assert_eq!(expected_burn + expected_staking + expected_proposer, fees);

    let post_sender = eng.get_account(&sender).await.unwrap().balance;
    let post_pool = eng.get_account(&REWARDS_POOL).await.unwrap().balance;
    let post_proposer = eng.get_account(&proposer).await.unwrap().balance;

    assert_eq!(pre_sender - post_sender, 1_000 + fees);
    assert_eq!(post_pool - pre_pool, expected_staking);
    assert_eq!(post_proposer - pre_proposer, expected_proposer);

    // Hard 1B cap invariant: burning fees MUST NOT free mint headroom, and
    // fee transfer MUST NOT bump `rewards_minted`.
    assert_eq!(eng.total_minted_nano(), TOTAL_SUPPLY_CAP);
    assert_eq!(eng.remaining_mint_headroom_nano(), 0);
    assert!(eng.mint_native(&proposer, 1).await.is_err());
    assert_eq!(
        eng.staking_read().await.rewards_minted,
        REWARDS_EMISSION_CAP
    );
}
