//! Heal-failure fail-closed regression tests.
//!
//! Root cause (audited live): the startup-heal path in `src/main.rs` retried
//! `heal_engine_to_head` 3 times and, on final failure, labelled the UNHEALED
//! engine state with the finalized height (`snapshot_state(&rt.state, fh)`)
//! and joined consensus. The next boot then loaded "state at F" that was
//! really S, saw `S == F`, skipped healing, and voted from stale state while
//! reporting healthy.
//!
//! The fix refuses instead: loud error + `process::exit(1)` (matching the
//! restore-refusal pattern), so supervisors restart into a clean retry and no
//! poisoned label is ever written. These tests pin both halves:
//! 1. the source no longer contains the mislabelling line and does refuse;
//! 2. the storage mechanism: a snapshot labelled at F with S-bytes makes the
//!    next boot skip healing (`S == F`), which is why the removed line was
//!    fatal and must never return.

use stellereum::governance::Governance;
use stellereum::staking::StakingLedger;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::storage::{DomainSnapshot, Storage};

// The binary's heal loop lives in `src/main.rs` (not importable from an
// integration test), so the decision itself is pinned by source: the failure
// branch must refuse via `process::exit(1)` and must never snapshot the
// unhealed engine under the finalized height.
#[test]
fn heal_failure_path_refuses_instead_of_mislabeling() {
    let src = include_str!("../src/main.rs");

    // The fail-closed decision helper drives the failure branch.
    assert!(
        src.contains("heal_failure_should_exit"),
        "heal loop must gate the failure branch on heal_failure_should_exit"
    );
    // Loud refusal + nonzero exit, matching the restore-refusal pattern.
    assert!(
        src.contains("REFUSING to join consensus on unhealed state"),
        "heal failure must loudly refuse to join consensus"
    );
    // The exact mislabelling poison must be gone: snapshotting the unhealed
    // engine (`rt.state` at S) under the finalized height (`fh`) is what made
    // the next boot skip healing (S == F) and vote from stale state.
    assert!(
        !src.contains("snapshot_state(&rt.state, fh)"),
        "poison line snapshot_state(&rt.state, fh) must not exist: \
         labelling unhealed state with the finalized height skips healing on reboot"
    );
    assert!(
        !src.contains("anchoring engine state to finalized head"),
        "the old anchor-and-join comment must be gone with the poison branch"
    );
}

#[tokio::test]
async fn mislabelled_snapshot_skips_healing_next_boot() {
    // Mechanism proof for why the removed line was fatal: with the engine at
    // S and the finalized head at F > S, a snapshot of S-bytes labelled F
    // makes the restart see restored == finalized and skip the heal gate
    // (`restored_state_height < fh`), i.e. it would vote from stale state.
    let dir = std::env::temp_dir().join(format!(
        "stell-heal-fail-closed-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let store = Storage::open(&dir).unwrap();

    let engine = InMemoryStateEngine::new();
    engine
        .update_account(AccountState::new([0xA1u8; 32], 50_000))
        .await;
    let snap = engine.create_snapshot().await;
    let dom = DomainSnapshot::capture(&engine, &StakingLedger::new(), &Governance::new()).await;
    let dbytes = bincode::serialize(&dom).unwrap();

    // Honest state: snapshot at S = 100, finalized head at F = 101.
    store.put_state(100, &snap).unwrap();
    store.put_domains(100, &dbytes).unwrap();
    store.set_finalized(101, &[0xABu8; 32]).unwrap();

    let (restored, _) = store.latest_state().unwrap().expect("snapshot present");
    let (fh, _) = store.finalized().unwrap().expect("finalized present");
    assert!(
        restored < fh,
        "honest labels must trigger healing (restored {restored} < head {fh})"
    );

    // What the old poison branch wrote: the SAME unhealed bytes under F.
    store.put_state(101, &snap).unwrap();
    store.put_domains(101, &dbytes).unwrap();

    let (restored, _) = store.latest_state().unwrap().expect("snapshot present");
    assert_eq!(
        restored, fh,
        "mislabelled snapshot makes the next boot see S == F and skip healing"
    );

    std::fs::remove_dir_all(&dir).ok();
}
