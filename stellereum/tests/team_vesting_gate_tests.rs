//! Team vesting claim gate: spending from a vesting-tracked account above the
//! unlocked amount FAILS closed.
//!
//! Assessment (pinned here): NO team-vested allocations exist on-chain —
//! `fund_genesis` credits validator accounts only (plus bare-MIN bonds) and
//! `TokenAllocation`/`TeamVestingSchedule` are never written to any ledger
//! (the only reader is a CLI display). The gate below therefore ships as the
//! correct default: with zero tracked accounts it is a no-op, and every
//! tracked account enforces `balance_after >= locked` on ALL spend paths
//! (`commit_native` for payload/sequential/block commits, plus the parallel
//! plain fast path that bypasses it).
//!
//! Fail-closed, ships coordinated: a refusal moves nothing (B1 rollback) and
//! touches no committed shape when the registry is empty.

use ed25519_dalek::SigningKey;
use stellereum::sharding::Transaction;
use stellereum::staking::StakingLedger;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::tokenomics::TeamVestingSchedule;

const STELL: u64 = 1_000_000_000;
const T0: u64 = 1_700_000_000;

fn team_key() -> SigningKey {
    SigningKey::from_bytes(&[0x71; 32])
}
fn team_addr() -> [u8; 32] {
    team_key().verifying_key().to_bytes()
}
fn other_key() -> SigningKey {
    SigningKey::from_bytes(&[0x72; 32])
}

/// Small deterministic schedule: 1000s cliff, 2000s linear, total 2000 nano.
fn sched(total: u64) -> TeamVestingSchedule {
    TeamVestingSchedule {
        total_allocation: total,
        start_timestamp: T0,
        cliff_duration_secs: 1_000,
        vesting_duration_secs: 2_000,
        claimed_amount: 0,
    }
}

fn plain(key: &SigningKey, to: [u8; 32], amount: u64, gas: u64, nonce: u64) -> Transaction {
    Transaction::sign(key, to, amount, gas, nonce, 1, 1)
}

// ===========================================================================
// 1. Schedule math: cliff / linear boundaries exact.
// ===========================================================================

#[test]
fn cliff_boundary_is_exact() {
    let s = sched(2_000);
    // Before start: nothing unlocked.
    assert_eq!(s.unlocked_amount(T0 - 1), 0);
    assert_eq!(s.unlocked_amount(T0), 0);
    // One second before the cliff: still zero.
    assert_eq!(s.unlocked_amount(T0 + 999), 0);
    // At the cliff: linear vesting starts at zero and climbs.
    assert_eq!(s.unlocked_amount(T0 + 1_000), 0);
    assert_eq!(s.locked_amount(T0 + 1_000), 2_000);
    assert_eq!(s.claimable_amount(T0 + 999), 0);
}

#[test]
fn linear_vesting_boundaries_are_exact() {
    let s = sched(2_000);
    // Halfway through the linear window: exactly half unlocked.
    assert_eq!(s.unlocked_amount(T0 + 1_000 + 1_000), 1_000);
    assert_eq!(s.locked_amount(T0 + 1_000 + 1_000), 1_000);
    // One second before full vesting: total - 1.
    assert_eq!(s.unlocked_amount(T0 + 1_000 + 1_999), 1_999);
    // At and past the end: fully unlocked.
    assert_eq!(s.unlocked_amount(T0 + 1_000 + 2_000), 2_000);
    assert_eq!(s.unlocked_amount(T0 + 1_000 + 2_000 + 1), 2_000);
    assert_eq!(s.unlocked_amount(u64::MAX), 2_000);
    assert_eq!(s.locked_amount(u64::MAX), 0);
    // locked + unlocked == total at every sampled point.
    for t in [
        T0,
        T0 + 999,
        T0 + 1_000,
        T0 + 1_500,
        T0 + 2_999,
        T0 + 3_000,
        T0 + 99_999,
    ] {
        assert_eq!(
            s.locked_amount(t) + s.unlocked_amount(t),
            2_000,
            "complement violated at {t}"
        );
    }
}

#[test]
fn default_schedule_has_the_documented_shape() {
    let s = TeamVestingSchedule::default();
    assert_eq!(s.total_allocation, 100_000_000 * STELL);
    assert_eq!(s.cliff_duration_secs, 12 * 30 * 86400);
    assert_eq!(s.vesting_duration_secs, 24 * 30 * 86400);
    assert_eq!(
        s.unlocked_amount(s.start_timestamp + s.cliff_duration_secs - 1),
        0
    );
    assert_eq!(
        s.unlocked_amount(s.start_timestamp + s.cliff_duration_secs + s.vesting_duration_secs),
        s.total_allocation
    );
}

#[test]
fn spend_and_claim_helpers_fail_closed() {
    let mut s = sched(2_000);
    let half = T0 + 1_000 + 1_000; // unlocked == 1_000
                                   // Spending within claimable passes; above it fails and changes nothing.
    assert!(s.check_spend_allowed(half, 1_000).is_ok());
    assert!(s.check_spend_allowed(half, 1_001).is_err());
    assert!(s.check_balance_floor(half, 1_000).is_ok());
    assert!(s.check_balance_floor(half, 999).is_err());
    // Claim advances the counter; over-claim is refused atomically.
    s.record_claim(half, 400).expect("claim within unlocked");
    assert_eq!(s.claimed_amount, 400);
    assert_eq!(s.claimable_amount(half), 600);
    assert!(s.record_claim(half, 601).is_err());
    assert_eq!(
        s.claimed_amount, 400,
        "failed claim must not advance the counter"
    );
    s.record_claim(half, 600).expect("exact claimable");
    assert_eq!(s.claimable_amount(half), 0);
}

// ===========================================================================
// 2. Registry: registration validation + floor lookup.
// ===========================================================================

#[test]
fn registry_validation_is_fail_closed() {
    let mut l = StakingLedger::new();
    // Zero address and zero allocation are refused.
    assert!(l.register_team_vesting([0u8; 32], sched(1_000)).is_err());
    let mut zero = sched(1_000);
    zero.total_allocation = 0;
    assert!(l.register_team_vesting(team_addr(), zero).is_err());
    // First registration succeeds; a duplicate is refused (rotate via unregister).
    l.register_team_vesting(team_addr(), sched(2_000))
        .expect("register");
    assert!(l.register_team_vesting(team_addr(), sched(2_000)).is_err());
    assert!(l.vesting_schedule_of(&team_addr()).is_some());
    assert!(l.vesting_schedule_of(&[9u8; 32]).is_none());
    // Untracked accounts floor at zero (no gate).
    assert_eq!(l.vesting_locked_floor_of(&[9u8; 32], T0), 0);
    assert!(l.check_vesting_balance_floor(&[9u8; 32], T0, 0).is_ok());
    // Tracked floor follows the schedule.
    assert_eq!(l.vesting_locked_floor_of(&team_addr(), T0), 2_000);
    assert!(l
        .check_vesting_balance_floor(&team_addr(), T0, 2_000)
        .is_ok());
    assert!(l
        .check_vesting_balance_floor(&team_addr(), T0, 1_999)
        .is_err());
    // Unregister is idempotent and removes the gate.
    assert!(l.unregister_team_vesting(&team_addr()));
    assert!(!l.unregister_team_vesting(&team_addr()));
    assert!(l.check_vesting_balance_floor(&team_addr(), T0, 0).is_ok());
}

// ===========================================================================
// 3. Spend path: locked spend refused, unlocked spend passes.
// ===========================================================================

async fn funded_tracked_engine(total: u64) -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    e.credit_native(&team_addr(), total)
        .await
        .expect("fund team");
    e.credit_native(&other_key().verifying_key().to_bytes(), 10 * STELL)
        .await
        .expect("fund other");
    e.staking_write()
        .await
        .register_team_vesting(team_addr(), sched(total))
        .expect("track team");
    e
}

#[tokio::test]
async fn locked_spend_is_refused_and_moves_nothing() {
    let e = funded_tracked_engine(2_000).await;
    // Pre-cliff: locked == total, so ANY debit (here 100 nano + 0 fee) fails.
    let tx = plain(&team_key(), [0xABu8; 32], 100, 0, 0);
    let err = e
        .apply_transaction(&tx, T0)
        .await
        .expect_err("locked spend must fail");
    assert!(
        err.contains("vesting"),
        "fail-closed reason must name the lock: {err}"
    );
    let sender = e.get_account(&team_addr()).await.expect("sender exists");
    assert_eq!(sender.balance, 2_000, "refused spend moves no funds");
    assert_eq!(sender.nonce, 0, "refused spend consumes no nonce");
}

#[tokio::test]
async fn unlocked_spend_passes_after_full_vesting() {
    let e = funded_tracked_engine(2_000).await;
    let done = T0 + 1_000 + 2_000;
    let tx = plain(&team_key(), [0xABu8; 32], 1_500, 0, 0);
    e.apply_transaction(&tx, done)
        .await
        .expect("fully unlocked spend passes");
    assert_eq!(e.get_account(&team_addr()).await.unwrap().balance, 500);
}

#[tokio::test]
async fn partial_unlock_boundary_is_exact_and_cumulative() {
    let e = funded_tracked_engine(2_000).await;
    let half = T0 + 1_000 + 1_000; // unlocked == 1_000, locked == 1_000
                                   // Spend exactly the unlocked half: balance_after == locked passes.
    e.apply_transaction(&plain(&team_key(), [0xABu8; 32], 1_000, 0, 0), half)
        .await
        .expect("exact-unlocked spend passes");
    assert_eq!(e.get_account(&team_addr()).await.unwrap().balance, 1_000);
    // The SAME unlocked amount again would exceed the cumulative unlocked
    // total (floor check, not per-spend check): one more nano fails.
    let err = e
        .apply_transaction(&plain(&team_key(), [0xABu8; 32], 1, 0, 1), half)
        .await
        .expect_err("cumulative overspend must fail");
    assert!(err.contains("vesting"), "{err}");
    assert_eq!(e.get_account(&team_addr()).await.unwrap().balance, 1_000);
    assert_eq!(e.get_account(&team_addr()).await.unwrap().nonce, 1);
}

#[tokio::test]
async fn fees_count_toward_the_locked_floor() {
    let e = funded_tracked_engine(2_000).await;
    let half = T0 + 1_000 + 1_000; // locked == 1_000
                                   // Amount alone fits, but amount + fee would breach the floor: refused.
    let err = e
        .apply_transaction(&plain(&team_key(), [0xABu8; 32], 1_000, 10, 0), half)
        .await
        .expect_err("fee pushing below the floor must fail");
    assert!(err.contains("vesting"), "{err}");
}

#[tokio::test]
async fn untracked_accounts_are_unaffected() {
    let e = funded_tracked_engine(2_000).await;
    let other = other_key().verifying_key().to_bytes();
    e.apply_transaction(&plain(&other_key(), [0xCDu8; 32], 1_000, 0, 0), T0)
        .await
        .expect("untracked spend always passes");
    assert_eq!(
        e.get_account(&other).await.unwrap().balance,
        10 * STELL - 1_000
    );
}

#[tokio::test]
async fn block_path_refuses_locked_spend() {
    let e = funded_tracked_engine(2_000).await;
    let tx = plain(&team_key(), [0xABu8; 32], 100, 0, 0);
    let (applied, failed, _fees, status, _) = e.apply_block_parallel_fees(&[tx], T0).await;
    assert_eq!((applied, failed), (0, 1));
    assert_eq!(status, vec![false]);
    assert_eq!(e.get_account(&team_addr()).await.unwrap().balance, 2_000);
}

#[tokio::test]
async fn parallel_plain_fast_path_refuses_locked_spend() {
    // Two chained plain transfers (A -> B, then B -> C) schedule into two
    // waves; with parallel execution on, each plain wave commits through the
    // fast path that bypasses `commit_native` — the gate must hold there too.
    let e = InMemoryStateEngine::new().with_parallel_exec(true);
    let a_key = SigningKey::from_bytes(&[0xA0; 32]);
    let b_key = team_key(); // B is the vesting-tracked account.
    let (a, b) = (a_key.verifying_key().to_bytes(), team_addr());
    e.credit_native(&a, 50 * STELL).await.expect("fund A");
    e.credit_native(&b, 2_000).await.expect("fund B");
    e.staking_write()
        .await
        .register_team_vesting(b, sched(2_000))
        .expect("track B");
    let c = [0xCCu8; 32];
    let tx0 = Transaction::sign(&a_key, b, 500, 0, 0, 1, 1); // inbound to B: allowed
    let tx1 = Transaction::sign(&b_key, c, 1_500, 0, 0, 1, 1); // B spends locked funds: refused
    let (applied, failed, _fees, status, _) = e.apply_block_parallel_fees(&[tx0, tx1], T0).await;
    assert_eq!(
        status,
        vec![true, false],
        "inbound applies, locked spend refused"
    );
    assert_eq!((applied, failed), (1, 1));
    assert_eq!(
        e.get_account(&b).await.unwrap().balance,
        2_500,
        "B keeps its allocation plus the inbound transfer"
    );
}
