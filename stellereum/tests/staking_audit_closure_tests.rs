//! Staking + slashing audit closure (audit-staking.md / mission bundle).
//!
//! Pins every finding in the mission scope that was NOT already pinned by a
//! sibling suite, closing it fail-closed where true and documenting the
//! proven-false/product-decision remainder:
//!
//! * M2 pool symmetry (`stake_bond` failure refund, delegate escrow +
//!   failure unwind, both withdraw helpers debit-first with ledger restore,
//!   supply conservation end to end);
//! * M3 elected-only downtime (unelected sub-MIN record never bleeds while a
//!   same-streak elected peer slashes; cooldown/threshold math intact);
//! * commission rounding exactness (validator leg exact, dust locks in the
//!   pool — L1) + commission immutability after bond (I3 product decision);
//! * L1 slash-side dust (stays staked, favors the slashed party);
//! * L2 zero-address delegator refused at create AND withdraw;
//! * L3 overflow refuses instead of saturating;
//! * floor/buffer/grandfathered bare-MIN behavior; dust-leaving partial
//!   unbonds refused; unbonding maturity enforced; rotation safety;
//! * rewards pool backing + cap/shortfall fail-closed, never principal;
//! * equivocation 5% primitive exactness (wiring stays parked per the
//!   documented product decision — primitive math only here).
//!
//! Deliberately NOT duplicated here (covered by sibling suites, referenced
//! in the final report): M1 opcode end-to-end (`vuln_bundle_tests`),
//! floor/bond_genesis/re-entry watch (`staking_reentry_tests`),
//! F4 determinism (`f4_equivocation_determinism_tests`), rewards mint/cap
//! (`staking_rewards_pool_tests`), rotation liveness (`slashing_rotation`).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::sync::Arc;

use stellereum::consensus::{QuorumCertificate, ValidatorId, ValidatorSet, Vote, VoteKind};
use stellereum::runtime::{fund_genesis, ValidatorRuntime};
use stellereum::sharding::{Block, MASTERCHAIN_SHARD};
use stellereum::staking::{
    StakingError, StakingLedger, DOWNTIME_MISS_THRESHOLD, MIN_VALIDATOR_BOND, REWARDS_EMISSION_CAP,
    STAKING_POOL, STELL_MIN_BOND_BUFFER, UNBONDING_PERIOD_SECS,
};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

const STELL: u64 = 1_000_000_000;
/// New-bond floor: bare MIN is refused, MIN+buffer is accepted.
fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}
fn stell(n: u64) -> u64 {
    n * STELL
}
fn key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}
fn id(k: &SigningKey) -> ValidatorId {
    k.verifying_key().to_bytes()
}

/// A runtime whose own identity account is funded with `balance`.
async fn funded_runtime(k: &SigningKey, balance: u64) -> ValidatorRuntime {
    let me = id(k);
    let vs = ValidatorSet::from_list(vec![(me, 1)]);
    let st = Arc::new(InMemoryStateEngine::new());
    st.update_account(AccountState::new(me, balance)).await;
    ValidatorRuntime::new(k.clone(), vs, st, 1)
}

async fn pool_of(st: &Arc<InMemoryStateEngine>) -> u64 {
    st.get_account(&STAKING_POOL)
        .await
        .map(|a| a.balance)
        .unwrap_or(0)
}
async fn bal(st: &Arc<InMemoryStateEngine>, a: &[u8; 32]) -> u64 {
    st.get_account(a).await.map(|x| x.balance).unwrap_or(0)
}

// ============================================================================
// M2 — pool symmetry
// ============================================================================

/// A refused bond moves nothing: thin-bond AND double-register failures
/// refund in full AND remove the pool credit (no mint, no drift).
#[tokio::test]
async fn m2_bond_failure_leaves_pool_and_sender_untouched() {
    let k = key();
    let me = id(&k);
    // Funded for TWO full bonds: the double-register attempt must clear the
    // native debit so the LEDGER refusal (not a balance failure) is what we
    // unwind from — otherwise we would only test the debit gate.
    let initial = 2 * floor() + 50_000;
    let mut rt = funded_runtime(&k, initial).await;
    let st = rt.state.clone();

    // Thin bond (bare MIN, below MIN+buffer): ledger refuses.
    let r = rt.stake_bond(me, MIN_VALIDATOR_BOND, 1_000).await;
    assert_eq!(r, Err(StakingError::BondBelowMinimum));
    assert_eq!(
        pool_of(&st).await,
        0,
        "failed bond must not inflate the pool"
    );
    assert_eq!(bal(&st, &me).await, initial, "failed bond refunds in full");

    // Good bond, then double-register: the second attempt unwinds fully.
    rt.stake_bond(me, floor(), 1_000).await.unwrap();
    assert_eq!(pool_of(&st).await, floor());
    let r2 = rt.stake_bond(me, floor(), 1_000).await;
    assert_eq!(r2, Err(StakingError::AlreadyValidator));
    assert_eq!(
        pool_of(&st).await,
        floor(),
        "double-register must remove its own pool credit"
    );
    assert_eq!(
        bal(&st, &me).await,
        initial - floor(),
        "double-register refunds the second debit in full"
    );
}

/// Delegation is escrowed into the pool like a bond; a refused delegation
/// (unknown validator) unwinds every native leg; the zero delegator is
/// refused before any coin moves (L2 at the helper layer).
#[tokio::test]
async fn m2_delegate_escrows_pool_and_failure_unwinds() {
    let v = key();
    let vid = id(&v);
    let mut rt = funded_runtime(&v, floor() + 10 * STELL).await;
    let st = rt.state.clone();
    rt.stake_bond(vid, floor(), 1_000).await.unwrap();

    let d = key();
    let delegator = id(&d);
    st.update_account(AccountState::new(delegator, 5 * STELL))
        .await;

    rt.stake_delegate(delegator, vid, 2 * STELL).await.unwrap();
    assert_eq!(
        pool_of(&st).await,
        floor() + 2 * STELL,
        "delegation must be pool-backed (escrowed like a bond)"
    );
    assert_eq!(bal(&st, &delegator).await, 3 * STELL);

    // Unknown validator: full unwind.
    let ghost = [0x99u8; 32];
    let r = rt.stake_delegate(delegator, ghost, STELL).await;
    assert_eq!(r, Err(StakingError::NotValidator));
    assert_eq!(
        pool_of(&st).await,
        floor() + 2 * STELL,
        "pool untouched by failure"
    );
    assert_eq!(
        bal(&st, &delegator).await,
        3 * STELL,
        "delegator refunded in full"
    );

    // Zero delegator: refused before any coin moves.
    let z = rt.stake_delegate([0u8; 32], vid, STELL).await;
    assert_eq!(z, Err(StakingError::ZeroAddress));
    assert_eq!(pool_of(&st).await, floor() + 2 * STELL);
}

/// Self-bond withdrawal pays OUT OF the pool, never mints: pool + account
/// balances are jointly conserved across the whole bond→unbond→withdraw
/// cycle (helpers charge no gas, so conservation is exact).
#[tokio::test]
async fn m2_withdraw_pays_from_pool_supply_conserved() {
    let k = key();
    let me = id(&k);
    let initial = floor() + 7_000;
    let mut rt = funded_runtime(&k, initial).await;
    let st = rt.state.clone();

    rt.stake_bond(me, floor(), 0).await.unwrap();
    rt.stake_unbond(me, floor(), 0).await.unwrap();
    rt.process_unbonding(UNBONDING_PERIOD_SECS + 1).await;
    let paid = rt.stake_withdraw(me).await.expect("matured withdraw pays");
    assert_eq!(paid, floor());

    assert_eq!(pool_of(&st).await, 0, "pool debited 1:1, nothing minted");
    assert_eq!(
        bal(&st, &me).await,
        initial,
        "principal returns home exactly (helpers charge no gas)"
    );
    // Replay is a clean refusal that moves nothing.
    assert_eq!(
        rt.stake_withdraw(me).await,
        Err(StakingError::NothingToWithdraw)
    );
    assert_eq!(pool_of(&st).await, 0);
}

/// Pool shortfall fails CLOSED with the ledger entry restored: nothing is
/// paid, nothing is lost, and the later funded withdrawal pays exactly once.
#[tokio::test]
async fn m2_withdraw_shortfall_restores_ledger_entry() {
    let k = key();
    let me = id(&k);
    let mut rt = funded_runtime(&k, floor() + 7_000).await;
    let st = rt.state.clone();

    rt.stake_bond(me, floor(), 0).await.unwrap();
    rt.stake_unbond(me, floor(), 0).await.unwrap();
    rt.process_unbonding(UNBONDING_PERIOD_SECS + 1).await;

    // Simulate a pool shortfall (pool holds the backing; drain it out of band).
    st.debit_native(&STAKING_POOL, floor()).await.unwrap();
    assert_eq!(pool_of(&st).await, 0);
    assert_eq!(
        rt.stake_withdraw(me).await,
        Err(StakingError::NothingToWithdraw),
        "shortfall must fail closed, not mint"
    );
    assert_eq!(
        st.staking_read().await.withdrawable_of(&me),
        floor(),
        "consumed entry restored on debit failure"
    );

    // Re-fund and withdraw: pays exactly once, no duplication from restore.
    st.credit_native(&STAKING_POOL, floor()).await.unwrap();
    assert_eq!(rt.stake_withdraw(me).await.unwrap(), floor());
    assert_eq!(st.staking_read().await.withdrawable_of(&me), 0);
    assert_eq!(
        rt.stake_withdraw(me).await,
        Err(StakingError::NothingToWithdraw)
    );
}

/// Delegator cycle is pool-backed too: withdraw pays from the pool with the
/// same debit-first/restore discipline, and supply is conserved.
#[tokio::test]
async fn m2_delegator_cycle_pays_from_pool() {
    let v = key();
    let vid = id(&v);
    let mut rt = funded_runtime(&v, floor() + 50_000).await;
    let st = rt.state.clone();
    rt.stake_bond(vid, floor(), 1_000).await.unwrap();

    let d = key();
    let delegator = id(&d);
    st.update_account(AccountState::new(delegator, 4 * STELL))
        .await;
    rt.stake_delegate(delegator, vid, 2 * STELL).await.unwrap();
    rt.stake_undelegate(delegator, vid, 2 * STELL, 0)
        .await
        .unwrap();
    rt.process_unbonding(UNBONDING_PERIOD_SECS + 1).await;

    let pool_before = pool_of(&st).await;
    let paid: u64 = rt
        .stake_withdraw_delegator(delegator, vid)
        .await
        .expect("matured delegator withdraw pays");
    assert_eq!(paid, 2 * STELL);
    assert_eq!(
        pool_of(&st).await,
        pool_before - 2 * STELL,
        "delegator withdraw debits the pool (never mints)"
    );
    assert_eq!(
        bal(&st, &delegator).await,
        4 * STELL,
        "delegator made whole"
    );
}

// ============================================================================
// M3 — downtime is elected-only (end to end through finalize)
// ============================================================================

fn cluster_keys() -> Vec<SigningKey> {
    (0..4).map(|_| SigningKey::generate(&mut OsRng)).collect()
}
fn vset(ks: &[SigningKey]) -> ValidatorSet {
    ValidatorSet::from_list(ks.iter().map(|k| (id(k), 1)).collect())
}
fn mkblock(pkey: &SigningKey, h: u64, prev: [u8; 32], root: [u8; 32]) -> Block {
    let mut b = Block {
        shard_id: MASTERCHAIN_SHARD,
        height: h,
        prev_hash: prev,
        state_root: root,
        transactions: vec![],
        cross_shard_out: vec![],
        timestamp: 1_000,
        proposer: id(pkey),
        validator_signatures: vec![],
        shard_headers: vec![],
        precommit_qc: None,
        last_qc: None,
        mmr_epoch_root: [0u8; 32],
        order_merkle_root: [0u8; 32],
        epoch_key_commitment: [0u8; 32],
    };
    b.sign_block(pkey);
    b
}

/// An unelected sub-MIN record with the same missed streak as an elected
/// peer must NOT bleed: no `missed` increment, no cooldown-stamp move, no
/// slash — while the elected peer slashes and the pool debit equals the
/// burn. Cooldown/threshold math is otherwise untouched (the peer fires on
/// exactly threshold misses with a zero stamp).
///
/// POLICY (W10.5 canonical downtime evidence): attribution reads
/// `block.last_qc` (the QC for height-1 carried by the height-H block), never
/// the just-formed QC for H. Height 1 therefore carries no evidence (genesis
/// child) and cannot slash; the height-1 QC omitting the silent peer becomes
/// the evidence the height-2 block carries, and the slash lands there.
#[tokio::test]
async fn m3_downtime_skips_unelected_while_elected_slashes() {
    let ks = cluster_keys();
    let vs = vset(&ks);
    let ids: Vec<ValidatorId> = ks.iter().map(id).collect();
    let silent_elected = ids[3];

    let st = Arc::new(InMemoryStateEngine::new());
    fund_genesis(&st, &vs, 10_000 * STELL).await;
    let mut rt = ValidatorRuntime::new(ks[0].clone(), vs.clone(), st.clone(), 1);

    // Unelected record: sub-MIN self-bond via the genesis-only path (it can
    // never be created or elected through `bond`, which refuses < floor).
    let ghost = [0x77u8; 32];
    st.staking_write()
        .await
        .bond_genesis(ghost, stell(500), 0)
        .unwrap();
    assert!(
        !st.staking_read()
            .await
            .to_validator_set()
            .validators
            .contains_key(&ghost),
        "precondition: sub-MIN record is unelected"
    );

    // Same streak on both: one miss from the threshold, clean stamp.
    {
        let mut l = st.staking_write().await;
        for v in [silent_elected, ghost] {
            let rec = l.validators.get_mut(&v).unwrap();
            rec.missed = DOWNTIME_MISS_THRESHOLD - 1;
            rec.last_downtime_penalty = 0;
        }
    }
    // Fund the pool so the slash debit is observable.
    st.credit_native(&STAKING_POOL, 10 * MIN_VALIDATOR_BOND)
        .await
        .unwrap();
    let pool_before = pool_of(&st).await;
    let burn_before = st.staking_read().await.total_burned;

    // Genuine QC: every elected member EXCEPT the silent one signs.
    let root = st.get_state_root().await;
    let want = vs.proposer_for(1, 0).expect("schedule has a proposer");
    let pkey = ks.iter().find(|k| id(k) == want).unwrap().clone();
    let block = mkblock(&pkey, 1, [0u8; 32], root);
    let bh = block.compute_hash();
    for k in ks.iter().take(3) {
        rt.on_prevote(Vote::sign(k, 1, 0, VoteKind::Prevote, Some(bh)))
            .unwrap();
        rt.on_precommit(Vote::sign(k, 1, 0, VoteKind::Precommit, Some(bh)))
            .unwrap();
    }
    assert_eq!(rt.hc.try_precommit_quorum(), Some(bh));
    let cert: QuorumCertificate = rt.hc.precommit_qc.clone().expect("QC exists");
    assert!(cert.verify(&vs), "precondition: QC is genuine");
    rt.blocks.insert(bh, block);
    assert_eq!(rt.try_finalize().await, Some(bh), "must finalize height 1");

    // Height 1 carries no downtime evidence (genesis child, last_qc None), so
    // no slash can have fired yet — the streaks are untouched.
    {
        let l = st.staking_read().await;
        assert_eq!(
            l.total_burned, burn_before,
            "height 1 carries no evidence: no slash yet"
        );
        assert_eq!(
            l.validators[&silent_elected].missed,
            DOWNTIME_MISS_THRESHOLD - 1
        );
        assert_eq!(l.validators[&ghost].missed, DOWNTIME_MISS_THRESHOLD - 1);
    }

    // Height 2 carries the height-1 QC (which omits the silent elected peer)
    // as canonical evidence: finalizing it fires the elected peer's 10th-miss
    // slash while the unelected ghost stays untouched.
    let root2 = st.get_state_root().await;
    let want2 = vs.proposer_for(2, 0).expect("schedule has a proposer");
    let pkey2 = ks.iter().find(|k| id(k) == want2).unwrap().clone();
    let mut block2 = mkblock(&pkey2, 2, bh, root2);
    block2.last_qc = Some(cert.clone());
    block2.validator_signatures.clear();
    block2.sign_block(&pkey2);
    let bh2 = block2.compute_hash();
    for k in ks.iter().take(3) {
        rt.on_prevote(Vote::sign(k, 2, 0, VoteKind::Prevote, Some(bh2)))
            .unwrap();
        rt.on_precommit(Vote::sign(k, 2, 0, VoteKind::Precommit, Some(bh2)))
            .unwrap();
    }
    assert_eq!(rt.hc.try_precommit_quorum(), Some(bh2));
    rt.blocks.insert(bh2, block2);
    assert_eq!(rt.try_finalize().await, Some(bh2), "must finalize height 2");

    let l = st.staking_read().await;
    let burned = l.total_burned - burn_before;
    assert!(burned > 0, "elected peer at threshold must slash");
    assert_eq!(
        l.validators[&silent_elected].missed, 0,
        "slash resets the elected peer's streak"
    );
    // The unelected record: completely untouched.
    assert_eq!(
        l.validators[&ghost].missed,
        DOWNTIME_MISS_THRESHOLD - 1,
        "unelected record accumulates no misses"
    );
    assert_eq!(
        l.validators[&ghost].self_bond,
        stell(500),
        "unelected record loses no stake"
    );
    assert_eq!(
        l.validators[&ghost].last_downtime_penalty, 0,
        "unelected record takes no cooldown stamp"
    );
    drop(l);
    assert_eq!(
        pool_before - pool_of(&st).await,
        burned,
        "live slash debits the pool by exactly the burn"
    );
}

// ============================================================================
// Commission rounding (L1) + immutability (I3)
// ============================================================================

/// Validator leg is exact (`reward − share + commission`); per-delegator
/// floors leave `< n_delegators` nanos locked in the pool — favoring the
/// protocol, never the operator. Two uneven delegators force real dust.
#[tokio::test]
async fn commission_rounding_exact_and_dust_locks_in_pool() {
    let mut l = StakingLedger::new();
    let v = [0x11u8; 32];
    let (d1, d2) = ([0x21u8; 32], [0x22u8; 32]);
    l.bond(v, stell(1100), 1_000).unwrap();
    l.delegate(d1, v, stell(600)).unwrap();
    l.delegate(d2, v, stell(400)).unwrap();

    let reward = stell(1000);
    l.distribute_reward(v, reward).unwrap();

    // Exact integer math: total 2100, delegated_share = 1000*1000/2100,
    // commission = share/10, validator = reward − share + commission.
    let dshare = reward as u128 * 1000 / 2100;
    let commission = dshare * 1000 / 10_000;
    let expect_val = reward - dshare as u64 + commission as u64;
    assert_eq!(l.validators[&v].pending_rewards, expect_val);

    let c1 = l.claim_delegator_rewards(d1, v);
    let c2 = l.claim_delegator_rewards(d2, v);
    let cv = l.claim_validator_rewards(v).unwrap();
    assert_eq!(cv, expect_val);
    let dust = reward - cv - c1 - c2;
    assert!(
        dust < 2,
        "per-delegator floors leave < n_delegators nanos, got {dust}"
    );
    assert_eq!(
        l.rewards_pool, dust,
        "dust stays locked in the pool (no sweep path, unexploitable)"
    );
}

/// Commission never moves after bond: top-ups and distributions leave the
/// rate byte-identical, so delegators earn at the genesis-advertised rate.
#[tokio::test]
async fn commission_immutable_across_topups() {
    let mut l = StakingLedger::new();
    let v = [0x13u8; 32];
    let d = [0x23u8; 32];
    l.bond(v, stell(1100), 1_000).unwrap();
    l.add_bond(v, stell(500)).unwrap();
    assert_eq!(l.validators[&v].commission_bps, 1_000);
    l.delegate(d, v, stell(1000)).unwrap();
    l.distribute_reward(v, stell(2600)).unwrap();
    assert_eq!(
        l.validators[&v].commission_bps, 1_000,
        "distribution must not move the rate"
    );
    // Total 2600 (1600 self + 1000 delegated): dshare=1000, commission=100,
    // validator leg = 2600−1000+100 = 1700, delegator = 900.
    assert_eq!(l.claim_validator_rewards(v).unwrap(), stell(1700));
    assert_eq!(l.claim_delegator_rewards(d, v), stell(900));
}

// ============================================================================
// L1 slash side / L2 / L3
// ============================================================================

/// Slash dust favors the slashed party: map and aggregate move together by
/// the floored total, and the unfloorable remainder stays staked (never
/// burned, never leaked). Three uneven delegators force real floor dust.
#[tokio::test]
async fn l1_slash_dust_stays_staked_and_consistent() {
    let mut l = StakingLedger::new();
    let v = [0x31u8; 32];
    let (d1, d2, d3) = ([0x41u8; 32], [0x42u8; 32], [0x43u8; 32]);
    l.bond(v, stell(1100), 0).unwrap();
    l.delegate(d1, v, stell(1000)).unwrap();
    l.delegate(d2, v, stell(1000)).unwrap();
    l.delegate(d3, v, stell(1001)).unwrap();

    // 50% of 4101 STELL = 2050.5 STELL: self covers 1100, 950.5 STELL falls
    // on 3001 STELL of delegations — per-delegator floors cannot split it
    // evenly, so dust must remain.
    let burn_target = (stell(4101) as u128 * 5000 / 10_000) as u64;
    let burned = l.slash(v, 5000).unwrap();
    let map_sum: u64 = l.delegations.values().copied().sum();
    assert_eq!(
        map_sum, l.validators[&v].delegated,
        "map and aggregate stay mutually consistent"
    );
    assert!(
        burned <= burn_target,
        "never burns more than the floored math"
    );
    assert!(burned < burn_target, "uneven splits leave real floor dust");
    assert_eq!(
        l.total_burned, burned,
        "ledger burn counter tracks exactly what left stake"
    );
    assert_eq!(
        l.total_stake(&v),
        stell(4101) - burned,
        "unburned dust remains staked (favors the slashed party)"
    );
}

/// The zero address can never delegate and can never withdraw as a
/// delegator — even with a matured self-bond sitting under the same key,
/// which stays exclusive to `withdraw`.
#[tokio::test]
async fn l2_zero_address_never_delegates_nor_withdraws() {
    let mut l = StakingLedger::new();
    let v = [0x51u8; 32];
    l.bond(v, stell(1100), 0).unwrap();
    assert_eq!(
        l.delegate([0u8; 32], v, stell(1)),
        Err(StakingError::ZeroAddress)
    );
    assert!(
        !l.delegations.contains_key(&(v, [0u8; 32])),
        "refused delegation creates no position"
    );

    // Mature the self-bond under (v, [0;32]), then prove the delegator path
    // cannot touch it while the validator path still can.
    l.unbond(v, stell(1100), 0).unwrap();
    l.process_unbonding(UNBONDING_PERIOD_SECS + 1).unwrap();
    assert_eq!(l.withdrawable_of(&v), stell(1100));
    assert_eq!(
        l.withdraw_delegator([0u8; 32], v),
        Err(StakingError::ZeroAddress)
    );
    assert_eq!(l.withdrawable_of(&v), stell(1100), "guard consumes nothing");
    assert_eq!(l.withdraw(v).unwrap(), stell(1100));
}

/// Overflow refuses instead of saturating: stake accounting never silently
/// caps at u64::MAX.
#[tokio::test]
async fn l3_overflow_refuses_instead_of_saturating() {
    let mut l = StakingLedger::new();
    let v = [0x61u8; 32];
    l.bond(v, stell(1100), 0).unwrap();
    l.validators.get_mut(&v).unwrap().self_bond = u64::MAX;
    assert_eq!(l.add_bond(v, 1), Err(StakingError::ArithmeticOverflow));
    assert_eq!(
        l.validators[&v].self_bond,
        u64::MAX,
        "refused top-up changes nothing"
    );

    l.validators.get_mut(&v).unwrap().delegated = u64::MAX;
    assert_eq!(
        l.delegate([0x71u8; 32], v, stell(1)),
        Err(StakingError::ArithmeticOverflow)
    );
    assert_eq!(l.validators[&v].delegated, u64::MAX);
}

// ============================================================================
// Floor / buffer / grandfathering / dust unbonds / maturity / rotation
// ============================================================================

/// Floor matrix: sub-MIN, bare MIN and MIN+99 refuse; MIN+100 bonds;
/// genesis-only path grandfathers bare MIN; a slashed-ejected record
/// top-ups back over MIN and re-elects.
#[tokio::test]
async fn floor_buffer_grandfather_and_topup_reentry() {
    let mut l = StakingLedger::new();
    assert_eq!(
        l.bond([1u8; 32], stell(999), 0),
        Err(StakingError::BondBelowMinimum)
    );
    assert_eq!(
        l.bond([2u8; 32], MIN_VALIDATOR_BOND, 0),
        Err(StakingError::BondBelowMinimum),
        "bare MIN cannot be created (one slash from ejection)"
    );
    assert_eq!(
        l.bond([3u8; 32], MIN_VALIDATOR_BOND + stell(99), 0),
        Err(StakingError::BondBelowMinimum)
    );
    let v = [4u8; 32];
    l.bond(v, MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER, 0)
        .unwrap();
    assert!(l.to_validator_set().validators.contains_key(&v));

    // Grandfathered bare-MIN genesis entry: creatable ONLY via bond_genesis,
    // and elected (filter is >= MIN).
    let g = [5u8; 32];
    l.bond_genesis(g, MIN_VALIDATOR_BOND, 0).unwrap();
    assert!(l.to_validator_set().validators.contains_key(&g));

    // Eject by slash, re-elect by top-up (fail-open re-entry, WARN-covered).
    l.slash(v, 1_000).unwrap(); // 10% of 1100 = 110 → 990 < MIN
    assert!(!l.to_validator_set().validators.contains_key(&v));
    l.add_bond(v, stell(200)).unwrap();
    assert!(l.to_validator_set().validators.contains_key(&v));
}

/// Partial unbonds that would leave dust below MIN are refused; full exit
/// to zero is always allowed.
#[tokio::test]
async fn unbond_dust_remainder_refused_full_exit_allowed() {
    let mut l = StakingLedger::new();
    let v = [0x81u8; 32];
    l.bond(v, stell(1500), 0).unwrap();
    assert_eq!(
        l.unbond(v, stell(600), 0),
        Err(StakingError::BondBelowMinimum),
        "900 remainder is dust below MIN"
    );
    l.unbond(v, stell(400), 0).unwrap();
    assert_eq!(l.validators[&v].self_bond, stell(1100));
    // Full exit from 1100: allowed.
    l.unbond(v, stell(1100), 0).unwrap();
    assert_eq!(l.validators[&v].self_bond, 0);
}

/// Cooldown is timestamp-enforced: immature entries neither mature nor pay;
/// matured entries pay exactly once.
#[tokio::test]
async fn unbonding_matures_only_after_period() {
    let mut l = StakingLedger::new();
    let v = [0x91u8; 32];
    l.bond(v, stell(1100), 0).unwrap();
    l.unbond(v, stell(1100), 1_000).unwrap();
    l.process_unbonding(1_000 + UNBONDING_PERIOD_SECS - 1).unwrap();
    assert_eq!(l.withdrawable_of(&v), 0, "one second early is still locked");
    assert_eq!(l.withdraw(v), Err(StakingError::NothingToWithdraw));
    l.process_unbonding(1_000 + UNBONDING_PERIOD_SECS).unwrap();
    assert_eq!(l.withdrawable_of(&v), stell(1100));
    assert_eq!(l.withdraw(v).unwrap(), stell(1100));
    assert_eq!(l.withdraw(v), Err(StakingError::NothingToWithdraw));
}

/// Rotation moves the whole record (slash history included — no
/// laundering), and never merges or self-rotates.
#[tokio::test]
async fn rotation_carries_history_refuses_merge() {
    let mut l = StakingLedger::new();
    let (a, b, c) = ([0xA1u8; 32], [0xB1u8; 32], [0xC1u8; 32]);
    l.bond(a, stell(1100), 0).unwrap();
    l.bond(c, stell(1100), 0).unwrap();
    l.delegate([0xD1u8; 32], a, stell(100)).unwrap();
    l.slash_downtime(a).unwrap();
    l.validators.get_mut(&a).unwrap().missed = 7;
    let (missed, slashed) = (l.validators[&a].missed, l.validators[&a].total_slashed);

    assert_eq!(l.rotate_key(a, a), Err(StakingError::AlreadyValidator));
    assert_eq!(l.rotate_key(a, c), Err(StakingError::AlreadyValidator));
    l.rotate_key(a, b).unwrap();
    assert!(!l.validators.contains_key(&a), "old key is gone");
    assert_eq!(
        l.validators[&b].missed, missed,
        "downtime record carries over"
    );
    assert_eq!(
        l.validators[&b].total_slashed, slashed,
        "slash history carries over"
    );
    assert_eq!(
        l.delegations.get(&(b, [0xD1u8; 32])).copied(),
        Some(stell(100)),
        "delegations follow the record"
    );
    assert_eq!(
        l.rotate_key(a, [0xEBu8; 32]),
        Err(StakingError::NotValidator),
        "old key is gone: rotating FROM it (to a fresh key) finds nothing"
    );
}

// ============================================================================
// Rewards backing
// ============================================================================

/// Pool shortfall refuses WITHOUT touching principal: the pending entry and
/// the self-bond survive intact, and the later funded claim pays once.
#[tokio::test]
async fn rewards_shortfall_never_touches_principal() {
    let mut l = StakingLedger::new();
    let v = [0xE1u8; 32];
    l.bond(v, stell(1100), 0).unwrap();
    l.distribute_reward(v, stell(10)).unwrap();
    let owed = l.validators[&v].pending_rewards;
    assert!(owed > 0);

    // Drain the backing out of band (native-side loss, ledger entry intact).
    l.rewards_pool = 0;
    assert_eq!(
        l.claim_validator_rewards(v),
        Err(StakingError::RewardsPoolShortfall)
    );
    assert_eq!(l.validators[&v].pending_rewards, owed, "entry left intact");
    assert_eq!(
        l.validators[&v].self_bond,
        stell(1100),
        "principal untouched"
    );

    // Cap is fail-closed too: nothing credited past the ceiling.
    l.rewards_minted = REWARDS_EMISSION_CAP - 50;
    let pool_before = l.rewards_pool;
    assert_eq!(
        l.distribute_reward(v, 100),
        Err(StakingError::RewardsCapExceeded)
    );
    assert_eq!(l.validators[&v].pending_rewards, owed, "no phantom credit");
    assert_eq!(l.rewards_pool, pool_before);
}

// ============================================================================
// Equivocation primitive (5%): exactness at the ledger layer.
// Wiring stays parked per the documented product decision (O1):
// gossip-observed evidence is non-deterministic, so no live transition calls
// it until block-carried evidence + a pool debit at the call site both land.
// ============================================================================

/// Conflicting votes burn exactly 5% of total (self-bond-first); anything
/// non-conflicting burns 0 and moves nothing.
#[tokio::test]
async fn equivocation_primitive_burns_5pct_on_conflict_only() {
    use ed25519_dalek::SigningKey as SK;
    let sk = SK::generate(&mut OsRng);
    let voter = sk.verifying_key().to_bytes();
    let mut l = StakingLedger::new();
    l.bond(voter, stell(1100), 0).unwrap();
    l.delegate([0xF1u8; 32], voter, stell(1000)).unwrap();

    // Same height/round/kind, different target → 5% of 2100 = 105.
    let a = Vote::sign(&sk, 7, 0, VoteKind::Prevote, Some([1u8; 32]));
    let b = Vote::sign(&sk, 7, 0, VoteKind::Prevote, Some([2u8; 32]));
    assert_eq!(l.slash_equivocation(&(voter, a, b)).unwrap(), stell(105));
    assert_eq!(l.total_burned, stell(105));
    assert_eq!(l.total_stake(&voter), stell(2100) - stell(105));

    // Same target → not equivocation. Different round → not equivocation.
    let c = Vote::sign(&sk, 7, 0, VoteKind::Prevote, Some([1u8; 32]));
    let c2 = Vote::sign(&sk, 7, 0, VoteKind::Prevote, Some([1u8; 32]));
    assert_eq!(l.slash_equivocation(&(voter, c.clone(), c2)).unwrap(), 0);
    let e = Vote::sign(&sk, 7, 1, VoteKind::Prevote, Some([9u8; 32]));
    assert_eq!(l.slash_equivocation(&(voter, c, e)).unwrap(), 0);
    assert_eq!(l.total_burned, stell(105), "non-conflicts move nothing");
}
