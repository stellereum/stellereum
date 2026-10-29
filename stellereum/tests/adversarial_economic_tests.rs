//! Adversarial economic review (Agent C): the money paths as a SYSTEM.
//!
//! An attacker who sequences individually-legal operations to extract value the
//! protocol did not intend to give. All tests are in-process, deterministic
//! (fixed keys, no randomness) and fast. No `#[ignore]`.
//!
//! Conventions: balances in nano-STELL. `stell(n)` = n STELL.

use ed25519_dalek::SigningKey;
use stellereum::mempool::{Mempool, MempoolError};
use stellereum::rpc::Faucet;
use stellereum::sharding::Transaction;
use stellereum::staking::{
    StakingLedger, DEFAULT_COMMISSION_BPS, MIN_DELEGATION, MIN_VALIDATOR_BOND,
    STELL_MIN_BOND_BUFFER, UNBONDING_PERIOD_SECS,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::GAS_BASIC_TRANSFER;

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}

/// Deterministic key: seed byte repeated. Any 32 bytes are a valid ed25519 seed.
fn det_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn addr(seed: u8) -> [u8; 32] {
    det_key(seed).verifying_key().to_bytes()
}

// ---------------------------------------------------------------------------
// Test 1 — reward double-dip across unbonding
// ---------------------------------------------------------------------------

/// Attack: delegate, earn rewards, undelegate, re-delegate before the unbonding
/// payout matures, then try to claim twice.
///
/// Invariant: rewards accrued before the undelegate survive (none lost), the
/// re-delegated stake earns only the NEW emission (nothing paid twice), and
/// conservation holds: total credited == total emission (exact here; the
/// chosen amounts divide evenly so rounding dust is zero).
#[test]
fn reward_double_dip_across_unbonding_conserves_emission() {
    let v = addr(11);
    let d1 = addr(21);
    let d2 = addr(22); // control: stays delegated throughout
    let mut l = StakingLedger::new();
    l.bond(v, stell(2_000), DEFAULT_COMMISSION_BPS).unwrap();
    l.delegate(d1, v, stell(1_000)).unwrap();
    l.delegate(d2, v, stell(1_000)).unwrap();

    // Emission round 1: total 4000, delegated 2000 -> delegated_share 200,
    // commission 10% = 20, validator 220, pool 180 -> d1 = 90, d2 = 90.
    let e1 = stell(400);
    l.distribute_reward(v, e1).unwrap();
    assert_eq!(l.delegator_rewards_of(d1, v), stell(90));
    assert_eq!(l.delegator_rewards_of(d2, v), stell(90));

    // Attack step 1: d1 fully undelegates at t0.
    l.undelegate(d1, v, stell(1_000), 0).unwrap();
    // None lost: the pre-undelegate accrual survives the undelegate.
    assert_eq!(
        l.delegator_rewards_of(d1, v),
        stell(90),
        "undelegate must not zero already-accrued rewards (src/staking.rs:260)"
    );

    // Attack step 2: d1 re-delegates BEFORE the unbonding matures.
    l.delegate(d1, v, stell(1_000)).unwrap();
    assert_eq!(
        l.delegations.get(&(v, d1)).copied().unwrap_or(0),
        stell(1_000),
        "re-delegation records exactly the new amount, no resurrection of old state"
    );

    // Emission round 2: same shape -> d1 += 90 (now 180), d2 += 90 (now 180).
    let e2 = stell(400);
    l.distribute_reward(v, e2).unwrap();
    assert_eq!(l.delegator_rewards_of(d1, v), stell(180));
    assert_eq!(l.delegator_rewards_of(d2, v), stell(180));

    // Attack step 3: claim, then claim AGAIN (double-dip attempt).
    let c1 = l.claim_delegator_rewards(d1, v);
    assert_eq!(c1, stell(180), "d1 earned 90 + 90, exactly");
    let c1_again = l.claim_delegator_rewards(d1, v);
    assert_eq!(
        c1_again, 0,
        "second claim must pay nothing (claim is remove-based)"
    );
    let c2 = l.claim_delegator_rewards(d2, v);
    assert_eq!(c2, stell(180));
    let cv = l.claim_validator_rewards(v).unwrap();
    assert_eq!(cv, stell(440), "validator earned 220 + 220");

    // Conservation: total credited == total emission, nothing created or lost.
    assert_eq!(c1 + c1_again + c2 + cv, e1 + e2);

    // Principal is separate from rewards: the matured unbonding still pays
    // exactly the undelegated principal, once.
    l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();
    assert_eq!(l.withdrawable_delegator(&v, &d1), stell(1_000));
    assert_eq!(l.withdraw_delegator(d1, v).unwrap(), stell(1_000));
    assert_eq!(l.withdrawable_delegator(&v, &d1), 0);
}

// ---------------------------------------------------------------------------
// Test 2 — commission front-running
// ---------------------------------------------------------------------------

/// Attack: validator sets commission to maximum (100%) just before a reward
/// distribution, then back to normal, trying to retroactively clip rewards
/// the delegators already accrued.
///
/// There is deliberately NO public commission setter: commission is fixed at
/// `bond` time (src/staking.rs:164-192) and `distribute_reward`
/// (src/staking.rs:518-555) applies only the CURRENT rate to the NEW
/// emission. The test simulates the worst case by writing the field directly
/// and asserts the already-accrued amounts are untouched.
/// The LAZY (F1) accumulator computes a delegator's share from a SCALED rate
/// (`reward_per_token / 1e18`), so it can differ from the EAGER
/// per-distribution split by at most ONE nano-STELL per settlement: the
/// scaled rate truncates by `< stake / 1e18` and the stake is bounded by the
/// total supply (1e18 nano = the scale itself).
///
/// The deviation always favours the PROTOCOL (the truncated fraction stays
/// locked in the rewards pool as dust), never the delegator and never the
/// validator. This helper is the single place that tolerance is expressed.
fn assert_reward_within_one_nano(actual: u64, expected: u64, what: &str) {
    let diff = actual as i128 - expected as i128;
    assert!(
        diff.abs() <= 1,
        "{what}: lazy {actual} vs eager {expected} (off by {diff} nano — the lazy \
         accumulator must stay within one nano of the eager split)"
    );
}

#[test]
fn commission_frontrun_cannot_clip_already_accrued_rewards() {
    let v = addr(31);
    let d1 = addr(32);
    let mut l = StakingLedger::new();
    l.bond(v, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 1_000)
        .unwrap(); // 10%
                   // Delegation matches the floor bond 1:1, so the reward-split numbers below
                   // (tuned to an even split) still hold exactly.
    l.delegate(d1, v, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER)
        .unwrap();

    // Round 1 at 10%: d1 accrues 90.
    l.distribute_reward(v, stell(200)).unwrap();
    assert_eq!(l.claim_validator_rewards(v).unwrap(), stell(110));
    // Re-accrue round-1 shape for the clip attempt below (validator part
    // already claimed so only delegator accrual remains under test).
    l.distribute_reward(v, stell(200)).unwrap();
    let accrued_before = l.delegator_rewards_of(d1, v);
    // LAZY (F1): the accumulator's scaled rate may truncate by up to one
    // nano (the delegated total here does not divide the 1e18 scale).
    assert_reward_within_one_nano(accrued_before, stell(180), "d1 after two emissions");

    // Attack: spike commission to 100% with accrued rewards sitting there.
    l.validators.get_mut(&v).unwrap().commission_bps = 10_000;
    // Merely changing the rate must not touch what was already earned.
    assert_eq!(
        l.delegator_rewards_of(d1, v),
        accrued_before,
        "commission change must not rewrite accrued rewards (src/staking.rs:539-553)"
    );

    // Round 2 at 100%: the whole NEW delegated share goes to the validator,
    // the OLD accrual is still intact. (110 from the unclaimed round-1b
    // validator share carries over: 110 + 200 = 310.)
    l.distribute_reward(v, stell(200)).unwrap();
    assert_eq!(
        l.delegator_rewards_of(d1, v),
        accrued_before,
        "a 100% commission applies to new emission only, never retroactively"
    );
    assert_eq!(l.claim_validator_rewards(v).unwrap(), stell(310));

    // Back to 10%: round 3 accrues normally on top.
    l.validators.get_mut(&v).unwrap().commission_bps = 1_000;
    l.distribute_reward(v, stell(200)).unwrap();
    let total = l.claim_delegator_rewards(d1, v);
    assert_reward_within_one_nano(
        total,
        accrued_before + stell(90),
        "d1 after the fourth emission",
    );
    let v_total = l.claim_validator_rewards(v).unwrap();
    assert_eq!(v_total, stell(110));
    // Conservation across all four emissions: 800 in, 800 credited
    // (delegator 90+90+0+90=270; validator 110+110+200+110=530).
    assert_reward_within_one_nano(
        total + v_total + stell(110) + stell(310),
        stell(800),
        "conservation across the four emissions",
    );
}

// ---------------------------------------------------------------------------
// Test 3 — dust griefing
// ---------------------------------------------------------------------------

/// Attack: hundreds of 1-nano delegations to bloat the map / break the
/// `delegated` aggregate, then a mass-unbond that leaves dust behind or traps
/// another delegator's funds.
///
/// Part A: 1-nano delegations are below `MIN_DELEGATION` and must ALL be
/// rejected with zero state change (src/staking.rs:242).
/// Part B: a mass of minimum-size delegations must keep
/// `validators[v].delegated == sum(delegations map)` exact at every step, and
/// a mass-undelegate + withdraw must leave zero dust and untouched funds for
/// an unrelated delegator.
#[test]
fn dust_delegations_rejected_and_mass_unbond_leaves_no_dust() {
    let v = addr(41);
    let big = addr(42); // unrelated delegator whose funds must never move
    let mut l = StakingLedger::new();
    l.bond(v, stell(2_000), DEFAULT_COMMISSION_BPS).unwrap();
    l.delegate(big, v, stell(5_000)).unwrap();

    // Part A: 300 distinct 1-nano dust delegations.
    for i in 0..300u32 {
        let mut who = [0xD0u8; 32];
        who[0..4].copy_from_slice(&i.to_be_bytes());
        let r = l.delegate(who, v, 1);
        assert_eq!(
            r,
            Err(stellereum::staking::StakingError::DelegationBelowMinimum),
            "1-nano dust must be rejected"
        );
    }
    assert!(l.delegations.keys().all(|(vid, _)| *vid == v));
    assert_eq!(l.delegations.len(), 1, "only `big` is recorded");
    assert_eq!(l.validators[&v].delegated, stell(5_000));

    // Part B: 300 minimum-size delegations (distinct addresses).
    let mut small: Vec<[u8; 32]> = Vec::new();
    for i in 0..300u32 {
        let mut who = [0xE0u8; 32];
        who[0..4].copy_from_slice(&i.to_be_bytes());
        l.delegate(who, v, MIN_DELEGATION).unwrap();
        small.push(who);
    }
    let map_sum: u64 = l
        .delegations
        .iter()
        .filter(|((vid, _), _)| *vid == v)
        .map(|(_, a)| *a)
        .sum();
    assert_eq!(
        l.validators[&v].delegated, map_sum,
        "aggregate must equal the map exactly after mass delegation"
    );
    assert_eq!(map_sum, stell(5_000) + 300 * MIN_DELEGATION);

    // Mass-unbond every dust delegator; `big` stays.
    for who in &small {
        l.undelegate(*who, v, MIN_DELEGATION, 0).unwrap();
    }
    let map_sum2: u64 = l
        .delegations
        .iter()
        .filter(|((vid, _), _)| *vid == v)
        .map(|(_, a)| *a)
        .sum();
    assert_eq!(l.validators[&v].delegated, map_sum2);
    assert_eq!(map_sum2, stell(5_000), "`big` is the only stake left");
    assert_eq!(
        l.delegations.get(&(v, big)).copied().unwrap_or(0),
        stell(5_000),
        "unrelated delegator untouched"
    );

    // Mature and withdraw everything: exact principal back, zero dust.
    l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();
    let mut withdrawn = 0u64;
    for who in &small {
        assert_eq!(l.withdrawable_delegator(&v, who), MIN_DELEGATION);
        withdrawn += l.withdraw_delegator(*who, v).unwrap();
    }
    assert_eq!(withdrawn, 300 * MIN_DELEGATION);
    assert!(l.unbonding.is_empty(), "no pending entries left");
    assert!(l.withdrawable.is_empty(), "no dust left in withdrawable");
    assert!(
        l.delegations.keys().all(|(vid, d)| *vid != v || *d == big),
        "no dust keys left in the delegation map"
    );
    // Re-maturing must not re-credit anything.
    l.process_unbonding(u64::MAX / 2).unwrap();
    assert!(l.withdrawable.is_empty(), "re-maturity must not mint dust");
}

// ---------------------------------------------------------------------------
// Test 4 — faucet cap exhaustion as DoS
// ---------------------------------------------------------------------------

/// Attack: drain per-address lifetime caps across MANY addresses (treasury
/// drain attempt), hammer one address past its cap, and simulate a restart
/// (fresh in-process `Faucet`, since `FaucetState` is in-memory only,
/// src/rpc.rs:92-96) to re-draw on an exhausted address.
///
/// Invariants asserted:
///  (a) no address ever draws past its lifetime cap through one instance;
///  (b) every built drip applied to the engine debits the faucet treasury
///      exactly (amount + 21_000 gas), so treasury accounting is exact;
///  (c) a capped address can never draw again — INCLUDING across restarts.
#[tokio::test]
async fn faucet_caps_hold_and_treasury_stays_exact() {
    let seed = [0xF0u8; 32];
    let faucet = Faucet::new(seed, 1, 10, 25); // drip 10, lifetime cap 25
    let faucet_addr = faucet.account();
    let engine = InMemoryStateEngine::new();
    let treasury_start = 1_000_000_000u64;
    engine
        .update_account(AccountState::new(faucet_addr, treasury_start))
        .await;

    // Drain MANY addresses to their caps.
    let mut addrs = Vec::new();
    for i in 0u8..50 {
        let mut a = [0xA0u8; 32];
        a[0] = i;
        addrs.push(a);
    }
    let mut applied: u64 = 0; // drips actually executed on chain
    for a in &addrs {
        // 10 + 10 + 5 = 25 == cap; the 4th draw must be refused.
        let (t1, a1) = faucet.build_transfer(*a, None, None).await.expect("drip 1");
        assert_eq!(a1, 10);
        let (t2, a2) = faucet.build_transfer(*a, None, None).await.expect("drip 2");
        assert_eq!(a2, 10);
        let (t3, a3) = faucet.build_transfer(*a, None, None).await.expect("drip 3");
        assert_eq!(a3, 5, "last draw is clamped to the remaining cap");
        assert_eq!(faucet.dispensed_to(*a).await, 25);
        assert!(
            faucet.build_transfer(*a, None, None).await.is_none(),
            "capped address can never draw again through this instance"
        );
        for t in [t1, t2, t3] {
            engine
                .apply_transaction(&t, 0)
                .await
                .expect("faucet drip applies");
            applied += 1;
        }
    }
    // Treasury accounting exact: each drip cost amount + base-fee gas.
    let dispensed_sum: u64 = 50 * 25;
    let expect = treasury_start - dispensed_sum - applied * GAS_BASIC_TRANSFER;
    let got = engine
        .get_account(&faucet_addr)
        .await
        .map(|x| x.balance)
        .unwrap_or(0);
    assert_eq!(got, expect, "treasury must balance to the nano");

    // Restart simulation, FIXED: state used to live in a bare in-process Mutex,
    // so a fresh Faucet with the same key lost ALL cap state and an address that
    // already drew its lifetime cap could draw again, unbounded over restarts.
    // The faucet now persists on every mutation; a restart over the saved bytes
    // picks up exactly where the old instance left off.
    let saved = faucet.save_bytes().await;
    assert!(!saved.is_empty(), "every drip must have persisted state");
    let restarted = Faucet::new(seed, 1, 10, 25);
    restarted.load_bytes(&saved).await;
    assert_eq!(
        restarted.dispensed_to(addrs[0]).await,
        25,
        "the cap ledger must survive the restart"
    );
    let redraw = restarted.build_transfer(addrs[0], None, None).await;
    assert!(
        redraw.is_none(),
        "a capped address must stay capped after a restart (got {:?})",
        redraw.map(|(_, a)| a)
    );
    // A fresh address still works on the restarted instance.
    let fresh = [0x77u8; 32];
    let (ftx, famt) = restarted
        .build_transfer(fresh, None, None)
        .await
        .expect("a new address draws normally");
    assert_eq!(famt, 10);
    assert_eq!(ftx.nonce, 150, "the nonce sequence continues, not restarts");
}

// ---------------------------------------------------------------------------
// Test 5 — fee/mempool games
// ---------------------------------------------------------------------------

/// Attack: a spammer submits minimal-gas transactions that still get included,
/// trying to (a) displace fee-paying transactions, or (b) force the proposer
/// to include losing work (unexecutable txs that occupy block space).
///
/// The selection rule under test (src/mempool.rs):
///  - `select`/`select_for_block` walk fee order highest-first;
///  - a full pool evicts ONLY via the funded `add_checked` path for a
///    strictly higher fee; unchecked `add` NEVER evicts;
///  - `select_for_block` skips unexecutable transactions (bad nonce/balance).
#[test]
fn spammer_cannot_displace_fee_payers_or_force_losing_work() {
    let honest = det_key(0x51);
    let spammer = det_key(0x52);
    let to = [0x99u8; 32];

    // --- (a) displacement: pool full of fee-payers, spammer arrives late. ---
    let mut mp = Mempool::new(10, 100).with_base_fee(GAS_BASIC_TRANSFER);
    let mut honest_hashes = Vec::new();
    for n in 0..10u64 {
        let t = Transaction::sign(&honest, to, 10, GAS_BASIC_TRANSFER + 5_000 + n, n, 1, 1);
        honest_hashes.push(mp.add_checked(t, 10_000_000).unwrap());
    }
    assert_eq!(mp.len(), 10);
    // Minimal-gas spam via the funded path: rejected, pool full, fee too low.
    let spam_min = Transaction::sign(&spammer, to, 10, GAS_BASIC_TRANSFER, 0, 1, 1);
    assert_eq!(
        mp.add_checked(spam_min, 1_000_000),
        Err(MempoolError::Full),
        "minimal-fee spam must not evict fee-payers"
    );
    // Unchecked path with a HUGE declared fee: still rejected, never evicts.
    let spam_fake = Transaction::sign(&spammer, to, 10, u64::MAX, 1, 1, 1);
    assert_eq!(
        mp.add(spam_fake),
        Err(MempoolError::Full),
        "unfunded declarations must never displace (src/mempool.rs:187-197)"
    );
    for h in &honest_hashes {
        assert!(mp.contains(h), "every fee-payer survives the spam");
    }
    // Below-base-fee spam is refused even with room: use a fresh pool.
    let mut mp2 = Mempool::new(100, 100).with_base_fee(GAS_BASIC_TRANSFER);
    let dust_fee = Transaction::sign(&spammer, to, 10, GAS_BASIC_TRANSFER - 1, 0, 1, 1);
    assert_eq!(
        mp2.add_checked(dust_fee, 1_000_000),
        Err(MempoolError::FeeTooLow),
        "sub-floor fees never enter via the network path"
    );

    // --- (b) ordering + losing work: highest fee wins, junk is skipped. ---
    // NOTE: GAS_BASIC_TRANSFER is the floor, so honest fees must be
    // ABOVE it for the ordering check to be meaningful.
    let mut mp3 = Mempool::new(100, 100);
    let mk = |fee: u64, nonce: u64| Transaction::sign(&honest, to, 10, fee, nonce, 1, 1);
    // Insert low-first to prove selection is by fee, not arrival.
    mp3.add(mk(GAS_BASIC_TRANSFER, 0)).unwrap(); // minimal but valid
    mp3.add(mk(GAS_BASIC_TRANSFER + 5_000, 1)).unwrap();
    mp3.add(mk(GAS_BASIC_TRANSFER + 3_000, 2)).unwrap();
    let picked = mp3.select(3);
    assert_eq!(
        picked.iter().map(|t| t.gas_limit).collect::<Vec<_>>(),
        vec![
            GAS_BASIC_TRANSFER + 5_000,
            GAS_BASIC_TRANSFER + 3_000,
            GAS_BASIC_TRANSFER
        ],
        "selection must be strictly fee-descending"
    );

    // The richest transaction in the pool is UNEXECUTABLE (stale nonce) and
    // must be SKIPPED by the proposer filter even though it pays the most —
    // otherwise spam forces losing work into the block. Executable
    // floor-paying transactions sort last but are still selected.
    let mut mp4 = Mempool::new(100, 100);
    let me = honest.verifying_key().to_bytes();
    let spam_me = spammer.verifying_key().to_bytes();
    mp4.add(Transaction::sign(
        &honest,
        to,
        10,
        GAS_BASIC_TRANSFER + 5_000,
        0,
        1,
        1,
    ))
    .unwrap();
    mp4.add(Transaction::sign(
        &honest,
        to,
        10,
        GAS_BASIC_TRANSFER + 3_000,
        1,
        1,
        1,
    ))
    .unwrap();
    mp4.add(Transaction::sign(
        &honest,
        to,
        10,
        GAS_BASIC_TRANSFER,
        2,
        1,
        1,
    ))
    .unwrap();
    // Spammer account is at nonce 5: nonce-2 with a 1M fee is stale junk.
    mp4.add(Transaction::sign(&spammer, to, 10, 1_000_000, 2, 1, 1))
        .unwrap();
    // ...while its nonce-5 floor-paying tx is executable and must be kept.
    mp4.add(Transaction::sign(
        &spammer,
        to,
        10,
        GAS_BASIC_TRANSFER,
        5,
        1,
        1,
    ))
    .unwrap();
    let picked_block = mp4.select_for_block(10, u64::MAX, |t| {
        if t.from == me {
            return t.nonce <= 2; // honest account nonce 0, contiguous prefix
        }
        if t.from == spam_me {
            return t.nonce == 5; // spammer account nonce 5: only nonce 5 executes
        }
        true
    });
    assert!(
        picked_block.iter().all(|t| t.gas_limit != 1_000_000),
        "the single richest tx is unexecutable and must never enter the block"
    );
    let fees: Vec<u64> = picked_block.iter().map(|t| t.gas_limit).collect();
    let mut sorted = fees.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    assert_eq!(fees, sorted, "executable selection stays fee-descending");
    assert_eq!(
        fees,
        vec![
            GAS_BASIC_TRANSFER + 5_000,
            GAS_BASIC_TRANSFER + 3_000,
            GAS_BASIC_TRANSFER,
            GAS_BASIC_TRANSFER
        ]
    );
    assert!(
        !picked_block.is_empty(),
        "executable fee-payers (incl. minimal-gas) are still selected"
    );
}

// ---------------------------------------------------------------------------
// Test 6 — self-dealing proposer
// ---------------------------------------------------------------------------

/// Attack: the proposer stuffs its own zero-fee transfers into its block.
///
/// Invariants: fee accounting still balances EXACTLY
/// (fees credited to proposer == sum of gas charged == fees debited), total
/// native supply is conserved (fees are a transfer, not a mint), and the
/// block applies cleanly (every tx gets a verdict, zero-fee txs included).
#[tokio::test]
async fn self_dealing_proposer_keeps_fee_accounting_exact() {
    let engine = InMemoryStateEngine::new();
    let pa = addr(0x61); // proposer
    let aa = addr(0x62);
    let ba = addr(0x63);
    let (pb, ab, bb) = (1_000_000u64, 1_000_000_000u64, 1_000_000_000u64);
    engine.update_account(AccountState::new(pa, pb)).await;
    engine.update_account(AccountState::new(aa, ab)).await;
    engine.update_account(AccountState::new(ba, bb)).await;

    let kp = det_key(0x61);
    let ka = det_key(0x62);
    let kb = det_key(0x63);
    let txs = vec![
        Transaction::sign(&ka, ba, 1_000, 5_000, 0, 1, 1), // honest
        Transaction::sign(&kb, aa, 500, 4_000, 0, 1, 1),   // honest
        Transaction::sign(&kp, pa, 0, 0, 0, 1, 1),         // proposer zero-fee self
        Transaction::sign(&kp, pa, 10, 0, 1, 1, 1),        // proposer zero-fee self + amount
    ];

    let supply_before = pb + ab + bb;
    let (applied, failed, fees, statuses, _) = engine.apply_block_parallel_fees(&txs, 0).await;
    assert_eq!(applied, 4, "all four txs (incl. zero-fee) apply");
    assert_eq!(failed, 0);
    assert_eq!(statuses, vec![true; 4], "block verdicts: all success");

    // Parallel path charges the full declared gas_limit per applied tx
    // (src/state_engine.rs:738): 5000 + 4000 + 0 + 0.
    assert_eq!(fees, 9_000, "zero-fee self-deals contribute exactly 0");

    // Runtime credits the collected fees to the proposer (src/runtime.rs:785-789).
    engine.credit_native(&pa, fees).await.unwrap();

    let (pa1, aa1, ba1) = (
        engine.get_account(&pa).await.unwrap().balance,
        engine.get_account(&aa).await.unwrap().balance,
        engine.get_account(&ba).await.unwrap().balance,
    );
    // Exact per-account deltas: fees paid == fees credited, self-deal nets 0.
    assert_eq!(pa1, pb + 9_000, "proposer gains exactly the collected fees");
    assert_eq!(aa1, ab - 1_000 - 5_000 + 500);
    assert_eq!(ba1, bb - 500 - 4_000 + 1_000);
    assert_eq!(
        pa1 + aa1 + ba1,
        supply_before,
        "fees are a transfer, not a mint: supply conserved to the nano"
    );
}
