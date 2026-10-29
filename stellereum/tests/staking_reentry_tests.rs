//! Re-entry hysteresis (validator C incident): MIN+buffer entry floor plus
//! visibility-only re-entry/liveness warnings.
//!
//! Covers:
//!   1. `bond` at exactly MIN is REFUSED with an error naming the required
//!      MIN+buffer minimum; below MIN too; just under the floor too.
//!   2. `bond` at exactly MIN+buffer is ACCEPTED and elected.
//!   3. Top-ups below the cushion stay accepted (fail-open) but the buffer
//!      WARN path fires.
//!   4. Ledger-level incident replay: slash-eject -> top-up -> silent
//!      re-election, and [`validator_set_gains`] flags exactly the re-entrant.
//!   5. Runtime refresh: a gained member emits a LOUD re-entry WARN (member,
//!      power, height), bumps the node-local counter, enters the liveness
//!      watch — and the derived set itself is installed UNALTERED.
//!   6. A watched re-entrant with no votes for N heights emits the repeating
//!      liveness-risk WARN; a voting one leaves the watch.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellereum::consensus::ValidatorSet;
use stellereum::runtime::ValidatorRuntime;
use stellereum::staking::{
    self, StakingError, StakingLedger, DEFAULT_COMMISSION_BPS, MIN_VALIDATOR_BOND,
    REENTRY_LIVENESS_WINDOW_HEIGHTS, STELL_MIN_BOND_BUFFER,
};
use stellereum::state_engine::InMemoryStateEngine;

const STELL: u64 = 1_000_000_000;

fn vid(n: u8) -> [u8; 32] {
    [n; 32]
}

fn floor() -> u64 {
    MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER
}

/// Capture WARN+ logs emitted by `f` on THIS thread (scoped default
/// subscriber, so parallel tests are unaffected).
fn capture_warns(f: impl FnOnce()) -> String {
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::writer::MakeWriter;

    #[derive(Clone)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);
    struct BufGuard(Arc<Mutex<Vec<u8>>>);
    impl<'a> MakeWriter<'a> for BufWriter {
        type Writer = BufGuard;
        fn make_writer(&'a self) -> Self::Writer {
            BufGuard(self.0.clone())
        }
    }
    impl std::io::Write for BufGuard {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sub = tracing_subscriber::fmt()
        .with_writer(BufWriter(buf.clone()))
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(sub, f);
    let data = buf.lock().unwrap().clone();
    String::from_utf8(data).unwrap_or_default()
}

#[test]
fn bond_at_min_is_rejected_and_names_the_required_minimum() {
    assert_eq!(
        STELL_MIN_BOND_BUFFER,
        100 * STELL,
        "buffer default is 100 STELL"
    );
    assert_eq!(floor(), 1100 * STELL);

    let mut l = StakingLedger::new();
    // Exactly MIN: refused (one downtime slash from ejection).
    assert_eq!(
        l.bond(vid(1), MIN_VALIDATOR_BOND, DEFAULT_COMMISSION_BPS),
        Err(StakingError::BondBelowMinimum)
    );
    // Below MIN: refused.
    assert_eq!(
        l.bond(vid(1), 999 * STELL, DEFAULT_COMMISSION_BPS),
        Err(StakingError::BondBelowMinimum)
    );
    // One nano under the floor: refused.
    assert_eq!(
        l.bond(vid(1), floor() - 1, DEFAULT_COMMISSION_BPS),
        Err(StakingError::BondBelowMinimum)
    );
    // The error names the required minimum (operator must see the number).
    let msg = format!("{}", StakingError::BondBelowMinimum);
    assert!(
        msg.contains(&floor().to_string()),
        "error must name the floor, got: {msg}"
    );
    assert!(
        msg.contains("MIN+buffer"),
        "error must say MIN+buffer, got: {msg}"
    );
    // Nothing was created by the refusals.
    assert!(!l.validators.contains_key(&vid(1)));
}

#[test]
fn bond_at_min_plus_buffer_is_accepted_and_elected() {
    let mut l = StakingLedger::new();
    l.bond(vid(2), floor(), DEFAULT_COMMISSION_BPS).unwrap();
    assert_eq!(l.validators[&vid(2)].self_bond, floor());
    let vs = l.to_validator_set();
    assert_eq!(vs.power_of(&vid(2)), floor(), "floor bond must be elected");
}

#[test]
fn top_up_below_buffer_is_accepted_but_warns_loudly() {
    // Pure builder: below MIN+buffer warns, at/above it does not.
    let buf = STELL_MIN_BOND_BUFFER;
    assert!(staking::buffer_warn_message_for(floor() - 1, buf).is_some());
    assert!(staking::buffer_warn_message_for(floor(), buf).is_none());

    // Live: the top-up lands (fail-open) but WARNs on the buffer channel.
    let logs = capture_warns(|| {
        let mut l = StakingLedger::new();
        l.bond(vid(3), floor(), DEFAULT_COMMISSION_BPS).unwrap();
        l.slash(vid(3), 500).unwrap(); // 5% of 1100 = 55 -> 1045 (no cushion)
        assert!(l.add_bond(vid(3), 50 * STELL).is_ok()); // 1095 < 1100
        assert_eq!(l.validators[&vid(3)].self_bond, 1095 * STELL);
    });
    assert!(
        logs.contains("MIN-BOND-BUFFER"),
        "thin top-up must WARN, got: {logs}"
    );
}

/// Validator C replay at ledger level: a floored bond, a slash that ejects,
/// a top-up back over MIN — and the re-entrant is exactly what
/// `validator_set_gains` reports (the chain-halt precursor, now visible).
#[test]
fn slash_eject_then_top_up_rejoins_and_gains_detects_it() {
    let c = vid(0xC);
    let mut l = StakingLedger::new();
    l.bond(vid(0xA), floor(), DEFAULT_COMMISSION_BPS).unwrap();
    l.bond(c, floor(), DEFAULT_COMMISSION_BPS).unwrap();

    // Eject C: 10% of 1100 = 110 -> 990 < MIN.
    let burned = l.slash(c, 1_000).unwrap();
    assert_eq!(burned, 110 * STELL);
    let without_c = l.to_validator_set();
    assert!(!without_c.validators.contains_key(&c), "C must be ejected");
    assert!(without_c.validators.contains_key(&vid(0xA)));

    // Top-up back over MIN (e.g. re-staked rewards): silently re-elected by
    // the filter — power is self_bond+delegated, the filter is self_bond.
    l.add_bond(c, 200 * STELL).unwrap(); // 990 + 200 = 1190
    let with_c = l.to_validator_set();
    assert!(with_c.validators.contains_key(&c), "top-up re-elects C");

    // The hysteresis input flags exactly C — never A.
    let gains = staking::validator_set_gains(&without_c, &with_c);
    assert_eq!(gains, vec![(c, 1190 * STELL)]);
    assert!(
        staking::validator_set_gains(&with_c, &with_c).is_empty(),
        "no gains, no warn"
    );

    // The WARN text carries member, power and height.
    let msg = staking::reentry_warn_message_for(&c, 1190 * STELL, 77);
    assert!(msg.contains(&hex::encode(c)), "must name the member: {msg}");
    assert!(
        msg.contains(&(1190 * STELL).to_string()),
        "must name the power: {msg}"
    );
    assert!(msg.contains("77"), "must name the height: {msg}");
    assert!(msg.contains("VALIDATOR-RE-ENTRY"), "must be LOUD: {msg}");
}

#[test]
fn reentry_liveness_predicate_needs_window_plus_missed_streak() {
    // Inside the window: no risk yet (grace to come online and vote).
    assert!(!staking::reentry_liveness_risk(100, 100, 5));
    assert!(!staking::reentry_liveness_risk(
        100,
        100 + REENTRY_LIVENESS_WINDOW_HEIGHTS - 1,
        9
    ));
    // Past the window with a missed streak: risk.
    assert!(staking::reentry_liveness_risk(
        100,
        100 + REENTRY_LIVENESS_WINDOW_HEIGHTS,
        1
    ));
    // Past the window but voting (streak forgiven): no risk.
    assert!(!staking::reentry_liveness_risk(
        100,
        100 + REENTRY_LIVENESS_WINDOW_HEIGHTS,
        0
    ));
    assert!(!staking::reentry_liveness_risk(100, 10_000, 0));

    let msg = staking::reentry_liveness_warn_message_for(&vid(9), 1190 * STELL, 100, 110, 4);
    assert!(
        msg.contains("VALIDATOR-LIVENESS-RISK"),
        "must be LOUD: {msg}"
    );
    assert!(
        msg.contains(&hex::encode(vid(9))),
        "must name the member: {msg}"
    );
}

/// Runtime refresh: gaining a member emits the LOUD re-entry WARN (member,
/// power, height), bumps the node-local counter, watches the member — and
/// installs the derived set UNALTERED (no consensus change).
///
/// Multi-thread flavor: the refresh is driven under log capture via
/// `block_in_place`, which the current-thread runtime refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_refresh_warns_counts_and_watches_reentrants_without_altering_the_set() {
    let ka = SigningKey::generate(&mut OsRng);
    let a = ka.verifying_key().to_bytes();
    let b = vid(0xB);
    let mut ledger = StakingLedger::new();
    ledger.bond(a, floor(), DEFAULT_COMMISSION_BPS).unwrap();

    let engine = Arc::new(InMemoryStateEngine::new());
    let mut rt =
        ValidatorRuntime::new(ka, ValidatorSet::from_list(vec![(a, 1)]), engine.clone(), 1)
            .with_staking(ledger);
    assert_eq!(rt.validator_reentry_warns_total, 0);

    // First refresh installs {A: floor} — A was already present, so no gain.
    assert!(rt.refresh_validator_set_from_staking().await);
    assert_eq!(rt.validator_reentry_warns_total, 0);
    assert!(rt.reentry_watch.is_empty());

    // Bond B, then refresh under log capture: B is gained with a LOUD WARN.
    engine
        .staking_write()
        .await
        .bond(b, floor(), DEFAULT_COMMISSION_BPS)
        .unwrap();
    let mut changed = false;
    let logs = capture_warns(|| {
        tokio::task::block_in_place(|| {
            changed =
                tokio::runtime::Handle::current().block_on(rt.refresh_validator_set_from_staking());
        })
    });
    assert!(changed, "set must gain B");
    assert!(
        logs.contains("VALIDATOR-RE-ENTRY"),
        "gain must WARN loudly, got: {logs}"
    );
    assert!(
        logs.contains(&hex::encode(b)),
        "WARN must name the member, got: {logs}"
    );
    assert!(
        logs.contains(&floor().to_string()),
        "WARN must name the power, got: {logs}"
    );
    assert_eq!(rt.validator_reentry_warns_total, 1);
}

/// Same as above but without the log-capture borrow dance: drive the refresh
/// directly and assert state (counter, watch, unaltered set).
///
/// POLICY (W10.5 activation boundary): a derived set takes effect at ledger
/// height + 1, never immediately — the refresh STAGES it and it installs when
/// the node reaches the activation height. The test therefore drives the
/// activation (height 1 -> 2) before asserting the installed set.
#[tokio::test]
async fn runtime_refresh_gain_state_is_counted_watched_and_unaltered() {
    let ka = SigningKey::generate(&mut OsRng);
    let a = ka.verifying_key().to_bytes();
    let b = vid(0xB);
    let mut ledger = StakingLedger::new();
    ledger.bond(a, floor(), DEFAULT_COMMISSION_BPS).unwrap();

    let engine = Arc::new(InMemoryStateEngine::new());
    let mut rt =
        ValidatorRuntime::new(ka, ValidatorSet::from_list(vec![(a, 1)]), engine.clone(), 1)
            .with_staking(ledger);

    assert!(rt.refresh_validator_set_from_staking().await);
    assert_eq!(rt.validator_reentry_warns_total, 0);

    engine
        .staking_write()
        .await
        .bond(b, floor(), DEFAULT_COMMISSION_BPS)
        .unwrap();
    assert!(
        rt.refresh_validator_set_from_staking().await,
        "set must gain B"
    );
    assert_eq!(rt.validator_reentry_warns_total, 1, "one gain -> one count");
    assert_eq!(
        rt.reentry_watch.get(&b),
        Some(&1),
        "B watched from height 1"
    );
    // W10.5: the gain is STAGED (activation height 2), not yet in force.
    // Drive the activation before asserting the installed set.
    rt.hc.height = 2;
    assert!(
        rt.install_due_validator_set(),
        "staged set installs at activation"
    );
    // NO consensus change: the derived set is installed verbatim.
    assert!(rt.validators.validators.contains_key(&b));
    assert_eq!(rt.validators.power_of(&b), floor());
    assert_eq!(rt.hc.validators.power_of(&b), floor());

    // No further gains -> counter stays; B's streak is clean (missed == 0),
    // so it is healthy and leaves the watch.
    assert!(!rt.refresh_validator_set_from_staking().await);
    assert_eq!(rt.validator_reentry_warns_total, 1);
    assert!(
        !rt.reentry_watch.contains_key(&b),
        "voting B leaves the watch"
    );
}

/// Liveness watch: a watched re-entrant with no votes for N heights trips the
/// repeating liveness-risk WARN; once it votes (streak forgiven) it leaves
/// the watch.
///
/// POLICY (W10.5 activation boundary): the first refresh STAGES the gain
/// (activation 2); the test installs it before moving into the liveness
/// window so the later refresh is a no-change sweep (no recount), not a
/// second gain.
#[tokio::test]
async fn runtime_liveness_watch_rewarns_until_the_reentrant_votes() {
    let ka = SigningKey::generate(&mut OsRng);
    let a = ka.verifying_key().to_bytes();
    let b = vid(0xB);
    let mut ledger = StakingLedger::new();
    ledger.bond(a, floor(), DEFAULT_COMMISSION_BPS).unwrap();
    ledger.bond(b, floor(), DEFAULT_COMMISSION_BPS).unwrap();

    let engine = Arc::new(InMemoryStateEngine::new());
    // Config set holds only A: the first refresh gains B as a re-entrant.
    let mut rt =
        ValidatorRuntime::new(ka, ValidatorSet::from_list(vec![(a, 1)]), engine.clone(), 1)
            .with_staking(ledger);
    assert!(rt.refresh_validator_set_from_staking().await);
    assert_eq!(rt.validator_reentry_warns_total, 1);
    assert_eq!(rt.reentry_watch.get(&b), Some(&1));
    // W10.5: install the staged gain before entering the liveness window.
    rt.hc.height = 2;
    assert!(
        rt.install_due_validator_set(),
        "staged set installs at activation"
    );

    // B goes dark: missed streak grows, heights pass the window.
    engine
        .staking_write()
        .await
        .validators
        .get_mut(&b)
        .unwrap()
        .missed = 4;
    rt.hc.height = 1 + REENTRY_LIVENESS_WINDOW_HEIGHTS;
    assert!(staking::reentry_liveness_risk(1, rt.hc.height, 4));
    // Refresh with no set change still sweeps the watch (repeating WARN path).
    rt.refresh_validator_set_from_staking().await;
    assert!(rt.reentry_watch.contains_key(&b), "dark B stays watched");
    assert_eq!(
        rt.validator_reentry_warns_total, 1,
        "liveness WARNs do not recount gains"
    );

    // B votes again (streak forgiven): next refresh unwatches it.
    engine
        .staking_write()
        .await
        .validators
        .get_mut(&b)
        .unwrap()
        .missed = 0;
    rt.refresh_validator_set_from_staking().await;
    assert!(
        !rt.reentry_watch.contains_key(&b),
        "voting B leaves the watch"
    );
}
