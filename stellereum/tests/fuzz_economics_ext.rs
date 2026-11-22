//! Deterministic economics fuzz battery (wave-4 QA, extends the audit suite
//! in `staking_economics_audit_tests.rs` / `mempool_econ_tests.rs`).
//!
//! Coverage:
//!  1. `fuzz_staking_ops_conserve_stake_every_n` — randomized staking ops
//!     (delegations / slashes / unbonds / undelegations / redelegations /
//!     rewards / claims / withdrawals interleaved) with the stake-conservation
//!     equation asserted every `CONSERVATION_EVERY_N` ops against
//!     [`StakingLedger::ledger_stake_supply`] plus the rewards and
//!     map/aggregate invariants, then a deterministic full-lifecycle tail
//!     (delegate → slash → unbond → mature → withdraw) and fail-closed probes.
//!  2. `fuzz_mempool_admission_orderings_preserve_fee_invariants` — the same
//!     funded transaction multiset admitted in three xorshift-shuffled orders;
//!     pool caps, per-sender quotas, F-03 reservation exactness, and
//!     `select()` price ordering must hold under every ordering, and replaying
//!     an order must reproduce the identical pool (determinism pin).
//!  3. `fuzz_mempool_full_pool_churn_stays_linear` — randomized eviction bids
//!     against a full pool: every successful displacement must pay at least
//!     the [`Mempool::eviction_premium`] over the displaced floor, the floor
//!     ratchets monotonically, and the final floor stays within the range of
//!     bids actually paid (no exponential ratchet).
//!
//! Determinism: xorshift64 with fixed `*_SEED` constants, bounded iteration
//! counts, fixed admission clocks (`AdmissionCtx::new`). No wall-clock reads,
//! no OS randomness, no new dependencies.

use stellereum::mempool::{AdmissionCtx, Mempool, MempoolError};
use stellereum::post_quantum::{derive_pq_address, PqScheme, PqSignatureEnvelope, DEFAULT_SALT};
use stellereum::sharding::Transaction;
use stellereum::staking::{
    StakingLedger, DEFAULT_COMMISSION_BPS, DOWNTIME_SLASH_BPS, EQUIVOCATION_SLASH_BPS,
    MIN_DELEGATION, MIN_VALIDATOR_BOND, UNBONDING_PERIOD_SECS,
};

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64): reproducible on every machine.
// ---------------------------------------------------------------------------

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next() % n
    }
}

// ---------------------------------------------------------------------------
// 1. Randomized staking ops with conservation asserted every N ops.
// ---------------------------------------------------------------------------

const STAKING_FUZZ_SEED: u64 = 0x5EED_1A11_CA4E_0042;
const STAKING_FUZZ_OPS: usize = 600;
const CONSERVATION_EVERY_N: usize = 25;
const N_VAL: u8 = 4;
const N_DEL: u8 = 6;

fn stell(n: u64) -> u64 {
    n * 1_000_000_000
}
fn vid(n: u8) -> [u8; 32] {
    [n; 32]
}
fn del(n: u8) -> [u8; 32] {
    [0xD0u8.wrapping_add(n); 32]
}

fn active_stake(l: &StakingLedger) -> u128 {
    l.validators
        .values()
        .map(|v| v.self_bond as u128 + v.delegated as u128)
        .sum()
}
fn unbonding_sum(l: &StakingLedger) -> u128 {
    l.unbonding.iter().map(|e| e.amount as u128).sum()
}
fn withdrawable_sum(l: &StakingLedger) -> u128 {
    l.withdrawable.values().map(|a| *a as u128).sum()
}
fn delegations_map_sum(l: &StakingLedger) -> u128 {
    l.delegations.values().map(|a| *a as u128).sum()
}
fn delegated_aggregate_sum(l: &StakingLedger) -> u128 {
    l.validators.values().map(|v| v.delegated as u128).sum()
}

fn assert_full_conservation(
    l: &StakingLedger,
    bonded_in: u128,
    withdrawn_out: u128,
    burned_expected: u128,
    claimed_out: u128,
    step: usize,
) {
    let active = active_stake(l);
    let unbond = unbonding_sum(l);
    let wd = withdrawable_sum(l);
    assert_eq!(
        active + unbond + wd + burned_expected,
        bonded_in - withdrawn_out,
        "step {step}: STAKE CONSERVATION BROKEN (active {active} + unbond {unbond} + wd {wd} + burned {burned_expected} != in {bonded_in} - out {withdrawn_out})"
    );
    assert_eq!(
        l.total_burned as u128,
        burned_expected.min(u64::MAX as u128),
        "step {step}: total_burned counter diverged"
    );
    assert_eq!(
        l.rewards_pool as u128 + claimed_out,
        l.rewards_minted as u128,
        "step {step}: REWARDS CONSERVATION BROKEN"
    );
    assert_eq!(
        delegations_map_sum(l),
        delegated_aggregate_sum(l),
        "step {step}: delegation map drifted from aggregate"
    );
}

#[test]
fn fuzz_staking_ops_conserve_stake_every_n() {
    let floor = stellereum::staking::required_bond_floor_nano();
    let edge: Vec<u64> = vec![
        0,
        1,
        2,
        7,
        MIN_DELEGATION - 1,
        MIN_DELEGATION,
        MIN_DELEGATION + 1,
        MIN_VALIDATOR_BOND - 1,
        MIN_VALIDATOR_BOND,
        MIN_VALIDATOR_BOND + 1,
        floor - 1,
        floor,
        floor + 1,
        stell(1),
        stell(500),
        stell(1100),
        stell(50_000),
        u64::MAX,
        u64::MAX - 1,
        u64::MAX / 2,
    ];

    let mut rng = XorShift(STAKING_FUZZ_SEED);
    let mut l = StakingLedger::new();
    // Deterministic bootstrap: 4 funded validators so every op arm is live.
    let mut bonded_in: u128 = 0;
    for i in 1..=N_VAL {
        l.bond(vid(i), floor + stell(100), DEFAULT_COMMISSION_BPS)
            .expect("bootstrap bond");
        bonded_in += (floor + stell(100)) as u128;
    }
    let mut withdrawn_out: u128 = 0;
    let mut burned_expected: u128 = 0;
    let mut claimed_out: u128 = 0;
    let mut now: u64 = 1_000_000;
    let mut saw_delegate_ok = false;
    let mut saw_slash_burn = false;
    let mut saw_fail_closed = false;

    for step in 0..STAKING_FUZZ_OPS {
        now = now.saturating_add(rng.below(200_000));
        let v = vid(1 + (rng.below(u64::from(N_VAL)) as u8));
        let d = del(rng.below(u64::from(N_DEL)) as u8);
        let amount = edge[(rng.below(edge.len() as u64)) as usize];
        match rng.below(100) {
            0..=29 => {
                // DELEGATE (or fail closed on minimum/jail/overflow).
                match l.delegate(d, v, amount) {
                    Ok(()) => {
                        bonded_in += amount as u128;
                        saw_delegate_ok = true;
                    }
                    Err(_) => saw_fail_closed = true,
                }
            }
            30..=44 => {
                // UNDELEGATE (or fail closed on shortfall/lock).
                if l.undelegate(d, v, amount, now).is_err() {
                    saw_fail_closed = true;
                }
            }
            45..=54 => {
                // UNBOND self-bond (or fail closed on floor/over-draw).
                if l.unbond(v, amount, now).is_err() {
                    saw_fail_closed = true;
                }
            }
            55..=64 => {
                // SLASH: protocol-realistic bps plus the downtime path.
                if rng.below(4) == 0 {
                    match l.slash_downtime(v) {
                        Ok(b) => {
                            burned_expected += b as u128;
                            if b > 0 {
                                saw_slash_burn = true;
                            }
                        }
                        Err(_) => saw_fail_closed = true,
                    }
                } else {
                    let bps = [
                        0,
                        1,
                        DOWNTIME_SLASH_BPS,
                        100,
                        EQUIVOCATION_SLASH_BPS,
                        5000,
                        10_000,
                    ][(rng.below(7)) as usize];
                    match l.slash(v, bps) {
                        Ok(b) => {
                            burned_expected += b as u128;
                            if b > 0 {
                                saw_slash_burn = true;
                            }
                        }
                        Err(_) => saw_fail_closed = true,
                    }
                }
            }
            65..=69 => {
                // MATURE unbondings (fail-closed overflow refusal keeps entries).
                if l.process_unbonding(now).is_err() {
                    saw_fail_closed = true;
                }
            }
            70..=79 => {
                // WITHDRAW self-bond (or fail closed on empty).
                match l.withdraw(v) {
                    Ok(a) => withdrawn_out += a as u128,
                    Err(_) => saw_fail_closed = true,
                }
            }
            80..=84 => {
                // WITHDRAW delegator (or fail closed on empty/zero address).
                match l.withdraw_delegator(d, v) {
                    Ok(a) => withdrawn_out += a as u128,
                    Err(_) => saw_fail_closed = true,
                }
            }
            85..=89 => {
                // ADD_BOND top-up (or fail closed on overflow/unknown).
                match l.add_bond(v, amount) {
                    Ok(()) => bonded_in += amount as u128,
                    Err(_) => saw_fail_closed = true,
                }
            }
            90..=94 => {
                // REDELEGATE between live validators (or fail closed).
                let to = vid(1 + (rng.below(u64::from(N_VAL)) as u8));
                if l.redelegate(d, v, to, amount, now).is_err() {
                    saw_fail_closed = true;
                }
            }
            _ => {
                // DISTRIBUTE a small reward, then sweep one claim leg.
                match l.distribute_reward(v, rng.below(stell(10) + 1)) {
                    Ok(()) => (),
                    Err(_) => saw_fail_closed = true,
                }
                match l.claim_validator_rewards(v) {
                    Ok(a) => claimed_out += a as u128,
                    Err(_) => saw_fail_closed = true,
                }
                claimed_out += l.claim_delegator_rewards(d, v) as u128;
            }
        }

        if step % CONSERVATION_EVERY_N == 0 {
            assert_full_conservation(
                &l,
                bonded_in,
                withdrawn_out,
                burned_expected,
                claimed_out,
                step,
            );
        }
    }

    // Fuzz-loop coverage pins (asserted BEFORE the deterministic tail so the
    // tail cannot mask a loop that never covered these paths).
    assert!(saw_delegate_ok, "fuzz must include successful delegations");
    assert!(saw_slash_burn, "fuzz must include nonzero slashes");
    assert!(saw_fail_closed, "fuzz must include fail-closed refusals");

    // Deterministic full-lifecycle tail on a fresh validator: delegate,
    // slash, exit both legs, mature past the unbonding period, withdraw both
    // legs. Guarantees withdraw + nonzero-slash coverage by construction.
    let tv = vid(0xA0);
    let td = del(0x40);
    let seed_bond = floor + stell(500);
    l.bond(tv, seed_bond, DEFAULT_COMMISSION_BPS)
        .expect("tail bond");
    bonded_in += seed_bond as u128;
    let dlg = stell(50);
    l.delegate(td, tv, dlg).expect("tail delegate");
    bonded_in += dlg as u128;
    let burn = l.slash(tv, 500).expect("tail slash");
    assert!(burn > 0, "tail slash on funded validator must burn");
    burned_expected += burn as u128;
    // Exit everything: undelegate the (slashed) position, unbond all self.
    let held = l.delegations.get(&(tv, td)).copied().unwrap_or(0);
    if held > 0 {
        l.undelegate(td, tv, held, now).expect("tail undelegate");
    }
    let self_bond = l.validators.get(&tv).map(|x| x.self_bond).unwrap_or(0);
    l.unbond(tv, self_bond, now).expect("tail unbond");
    now = now.saturating_add(UNBONDING_PERIOD_SECS + 1);
    l.process_unbonding(now).expect("tail mature");
    withdrawn_out += l.withdraw(tv).expect("tail withdraw self") as u128;
    withdrawn_out += l
        .withdraw_delegator(td, tv)
        .expect("tail withdraw delegator") as u128;

    // Fail-closed probes (never panic, always Err).
    assert!(l.delegate(td, tv, MIN_DELEGATION - 1).is_err());
    assert!(l.slash(vid(0xFE), 100).is_err());
    assert!(l.bond(tv, seed_bond, DEFAULT_COMMISSION_BPS).is_err());

    assert_full_conservation(
        &l,
        bonded_in,
        withdrawn_out,
        burned_expected,
        claimed_out,
        STAKING_FUZZ_OPS,
    );
}

// ---------------------------------------------------------------------------
// 2. Randomized mempool admission orderings.
// ---------------------------------------------------------------------------

const MEMPOOL_FUZZ_SEED: u64 = 0x9E37_79B9_8A53_F007;
const MEMPOOL_SHUFFLE_SEED: u64 = 0xC10C_4E55_1234_ABCD;
const ADMISSION_NOW: u64 = 1_700_000_000;
const POOL_CAP: usize = 64;
const PER_SENDER: usize = 16;

/// PQ fixture address for a deterministic `u8` seed, pre-registered in the
/// global implicit-key registry so the implicit envelope verifies. The
/// registry is keyed by address; re-registration of the same seed is
/// idempotent, and distinct seeds map to distinct addresses.
fn pq_from(seed: u8) -> ([u8; 32], Vec<u8>) {
    let pk = Transaction::sample_falcon512_pubkey(seed);
    let from = derive_pq_address(PqScheme::Falcon512, &pk, &DEFAULT_SALT);
    Transaction::global_implicit_registry()
        .register(from, PqScheme::Falcon512, &pk, &DEFAULT_SALT)
        .expect("PQ fixture registration must succeed");
    (from, pk)
}

/// PQ replacement for `Transaction::sign` / `sign_with_priority`: identical
/// `to / amount / gas / nonce / shards / priority` commitment, Falcon-512
/// implicit envelope. Implicit (not activation), so `tx_cost` stays
/// `amount + gas` — pool caps, quotas, F-03 reservation exactness and the
/// eviction-premium arithmetic are byte-for-byte the legacy thresholds.
#[allow(clippy::too_many_arguments)] // GATE: test-only PQ fixture mirrors the 8-field legacy sign() shape it replaces; splitting the ctor would drift from the committed envelope.
fn pq_sign(
    seed: u8,
    to: [u8; 32],
    amount: u64,
    gas: u64,
    nonce: u64,
    source_shard: u32,
    target_shard: u32,
    priority: u64,
) -> Transaction {
    let (from, pk) = pq_from(seed);
    let mut tx = Transaction {
        from,
        to,
        amount,
        gas_limit: gas,
        nonce,
        source_shard,
        target_shard,
        signature: Vec::new(),
        payload: Vec::new(),
        priority_fee_per_gas: priority,
    };
    let msg = tx.signing_message();
    let sig = Transaction::create_falcon512_test_signature(&pk, &msg, seed);
    tx.signature = PqSignatureEnvelope::new_implicit(PqScheme::Falcon512, sig).encode();
    assert!(tx.is_pq(), "PQ fixture must build the PQ envelope");
    assert!(
        !tx.is_pq_activation(),
        "implicit fixture must not pay the activation surcharge"
    );
    assert!(tx.verify_signature(), "PQ fixture signature must verify");
    tx
}

struct Candidate {
    tx: Transaction,
    balance: u64,
}

/// 8 senders x 15 sequential nonces with xorshift fees/priorities/amounts.
/// Balances cover every candidate so refusals come only from pool pressure.
fn build_candidates(seed: u64) -> (Vec<Candidate>, Vec<[u8; 32]>) {
    let mut rng = XorShift(seed);
    let mut out = Vec::new();
    let mut senders = Vec::new();
    for s in 0..8u8 {
        // Deterministic per-sender Falcon seed (0x20..0x27); the sender
        // address is the derived PQ address, pre-registered above.
        let seed = 0x20u8.wrapping_add(s);
        let (from, _) = pq_from(seed);
        senders.push(from);
        let mut cost: u64 = 0;
        let mut txs = Vec::new();
        for n in 0..15u64 {
            let fee_base = 100 + rng.below(2000);
            let priority = if rng.below(3) == 0 {
                rng.below(fee_base + 1)
            } else {
                0
            };
            let gas = fee_base + priority;
            let amount = rng.below(500);
            txs.push(pq_sign(seed, [0xBBu8; 32], amount, gas, n, 1, 1, priority));
            cost = cost.saturating_add(amount.saturating_add(gas));
        }
        let balance = cost.saturating_add(1_000_000);
        for tx in txs {
            out.push(Candidate { tx, balance });
        }
    }
    (out, senders)
}

fn shuffled_order(rng: &mut XorShift, n: usize) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (rng.below((i + 1) as u64)) as usize;
        idx.swap(i, j);
    }
    idx
}

fn admit_in_order(cands: &[Candidate], order: &[usize]) -> Mempool {
    let mut mp = Mempool::new(POOL_CAP, PER_SENDER);
    for &i in order {
        let c = &cands[i];
        let _ = mp.add_checked_ctx(c.tx.clone(), c.balance, AdmissionCtx::new(ADMISSION_NOW));
    }
    mp
}

fn pool_snapshot(mp: &Mempool) -> Vec<([u8; 32], u64, u64)> {
    let mut v: Vec<([u8; 32], u64, u64)> = mp
        .all()
        .iter()
        .map(|t| (t.from, t.nonce, t.gas_limit))
        .collect();
    v.sort();
    v
}

fn assert_pool_invariants(mp: &Mempool, senders: &[[u8; 32]], tag: &str) {
    assert!(
        mp.len() <= POOL_CAP,
        "{tag}: pool len {} exceeds cap {POOL_CAP}",
        mp.len()
    );
    for s in senders {
        // Per-sender quota pin via the public pool snapshot (`count_for_account`
        // lives on the pending activation buffer, not on `Mempool`).
        let n = mp.all().iter().filter(|t| t.from == *s).count();
        assert!(
            n <= PER_SENDER,
            "{tag}: sender over per-sender quota: {n} > {PER_SENDER}"
        );
        // F-03 reservation exactness: reserved == sum of pooled tx costs.
        let mut expect: u64 = 0;
        for t in mp.all().iter().filter(|t| &t.from == s) {
            expect = expect.saturating_add(Mempool::tx_cost(t));
        }
        assert_eq!(
            mp.reserved_for(s),
            expect,
            "{tag}: reservation mismatch for sender"
        );
    }
    // select() returns non-increasing (priority, fee) price order.
    let sel = mp.select(usize::MAX);
    assert_eq!(sel.len(), mp.len(), "{tag}: select must return the pool");
    for w in sel.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        assert!(
            (a.priority_fee_per_gas, a.gas_limit) >= (b.priority_fee_per_gas, b.gas_limit),
            "{tag}: select price order violated"
        );
    }
}

#[test]
fn fuzz_mempool_admission_orderings_preserve_fee_invariants() {
    let (cands, senders) = build_candidates(MEMPOOL_FUZZ_SEED);
    let n = cands.len();
    assert_eq!(n, 120, "battery shape: 8 senders x 15 nonces");

    let identity: Vec<usize> = (0..n).collect();
    let mut rng = XorShift(MEMPOOL_SHUFFLE_SEED);
    let shuffled = shuffled_order(&mut rng, n);
    let mut reversed = identity.clone();
    reversed.reverse();

    let mp_a = admit_in_order(&cands, &identity);
    let mp_b = admit_in_order(&cands, &shuffled);
    let mp_c = admit_in_order(&cands, &reversed);

    assert_pool_invariants(&mp_a, &senders, "identity");
    assert_pool_invariants(&mp_b, &senders, "shuffled");
    assert_pool_invariants(&mp_c, &senders, "reversed");

    // Eviction pressure is real: 120 funded candidates into a 64-slot pool.
    assert_eq!(mp_a.len(), POOL_CAP, "pool must be full under pressure");
    assert_eq!(mp_b.len(), POOL_CAP, "pool must be full under pressure");
    assert_eq!(mp_c.len(), POOL_CAP, "pool must be full under pressure");

    // Determinism pin: replaying the same order reproduces the same pool.
    let mp_b2 = admit_in_order(&cands, &shuffled);
    assert_eq!(
        pool_snapshot(&mp_b),
        pool_snapshot(&mp_b2),
        "same seed order must admit the identical pool"
    );
}

// ---------------------------------------------------------------------------
// 3. Full-pool churn stays linear (anti exponential-ratchet pin).
// ---------------------------------------------------------------------------

const CHURN_SEED: u64 = 0xA11C_E8BA_DF00_0042;

#[test]
fn fuzz_mempool_full_pool_churn_stays_linear() {
    const CAP: usize = 16;
    const HONEST_FEE: u64 = 1000;
    let mut mp = Mempool::new(CAP, 100);
    for s in 0..CAP {
        // Deterministic per-sender Falcon seed (0xC0..0xCF).
        let seed = 0xC0u8.wrapping_add(s as u8);
        mp.add_checked_ctx(
            pq_sign(seed, [1u8; 32], 10, HONEST_FEE, 0, 1, 1, 0),
            1_000_000,
            AdmissionCtx::new(ADMISSION_NOW),
        )
        .expect("honest fill");
    }
    assert_eq!(mp.len(), CAP);

    // Deterministic Falcon attacker seed; bids identical to the legacy run.
    let attacker_seed = 0xEEu8;
    let mut rng = XorShift(CHURN_SEED);
    let mut successes = 0u32;
    let mut floor = HONEST_FEE;
    // Bids in [1001, 3000]: every bid above the gentle premium must displace.
    for nonce in 0..60u64 {
        let fee = 1001 + rng.below(2000);
        let pre_min: u64 = mp.all().iter().map(|t| t.gas_limit).min().unwrap();
        let res = mp.add_checked_ctx(
            pq_sign(attacker_seed, [2u8; 32], 10, fee, nonce, 1, 1, 0),
            10_000_000,
            AdmissionCtx::new(ADMISSION_NOW),
        );
        match res {
            Ok(_) => {
                successes += 1;
                if mp.len() == CAP {
                    // Mechanism pin: a displacement paid the premium.
                    assert!(
                        fee >= pre_min + Mempool::eviction_premium(pre_min),
                        "eviction at fee {fee} below premium over displaced {pre_min}"
                    );
                }
                let post_min: u64 = mp.all().iter().map(|t| t.gas_limit).min().unwrap();
                assert!(
                    post_min >= floor,
                    "fee floor must ratchet monotonically, not drop"
                );
                floor = post_min;
            }
            Err(MempoolError::Full) => (),
            Err(e) => panic!("unexpected admission error: {e:?}"),
        }
        assert_eq!(mp.len(), CAP, "pool stays full through churn");
    }

    assert!(
        successes >= 30,
        "linear premium must keep admitting honest-range bids, got {successes}"
    );
    let final_min: u64 = mp.all().iter().map(|t| t.gas_limit).min().unwrap();
    assert!(
        final_min > HONEST_FEE,
        "floor must ratchet above the honest fee under attack"
    );
    assert!(
        final_min <= 3000,
        "floor {final_min} overshoots every bid paid (exponential ratchet)"
    );
}
