//! Broadcast fast-quorum / straggler-grace regressions.
//!
//! Pins [`join_with_quorum_or_timeout`](stellereum::consensus_net::join_with_quorum_or_timeout)
//! and [`BROADCAST_STRAGGLER_GRACE_MS_DEFAULT`](stellereum::consensus_net::BROADCAST_STRAGGLER_GRACE_MS_DEFAULT):
//! * once `fast_target` peers answer, a single straggler gets only
//!   `straggler_grace` (35 ms) before being detached (not cancelled — it
//!   finishes sending and recording `peer_health` in the background);
//! * when fewer than `fast_target` peers finish, the waiter honestly holds out
//!   up to `hard_budget` (or until `fast_target` is reached).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stellereum::consensus_net::{
    join_with_quorum_or_timeout, BROADCAST_STRAGGLER_GRACE_MS_DEFAULT,
};

#[tokio::test]
async fn join_with_quorum_or_timeout_detaches_single_slow_peer_after_grace() {
    assert_eq!(BROADCAST_STRAGGLER_GRACE_MS_DEFAULT, 35);

    let slow_finished = Arc::new(AtomicBool::new(false));
    let slow_flag = Arc::clone(&slow_finished);

    let fast1 = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        1u32
    });
    let fast2 = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        2u32
    });
    let slow = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        slow_flag.store(true, Ordering::Release);
        3u32
    });

    let t0 = Instant::now();
    let (mut done, detached) = join_with_quorum_or_timeout(
        vec![fast1, fast2, slow],
        2,
        Duration::from_millis(BROADCAST_STRAGGLER_GRACE_MS_DEFAULT),
        Duration::from_millis(500),
    )
    .await;
    let elapsed = t0.elapsed();

    done.sort_unstable();
    assert_eq!(done, vec![1u32, 2u32], "both fast peers must be collected");
    assert_eq!(detached, 1, "the single slow peer must be detached");
    assert!(
        elapsed < Duration::from_millis(150),
        "must return after ~35ms straggler grace instead of 500ms hard_budget (took {elapsed:?})"
    );
    assert!(
        !slow_finished.load(Ordering::Acquire),
        "slow peer must still be running in the background at detach time"
    );

    // Verify the detached task is NOT cancelled and completes in the background.
    let deadline = Instant::now() + Duration::from_millis(2500);
    while !slow_finished.load(Ordering::Acquire) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        slow_finished.load(Ordering::Acquire),
        "detached slow peer task must continue running and complete in the background"
    );
}

#[tokio::test]
async fn join_with_quorum_or_timeout_waits_full_budget_if_quorum_not_reached() {
    let fast = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        1u32
    });
    let slow1 = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        2u32
    });
    let slow2 = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        3u32
    });

    let hard_budget = Duration::from_millis(250);
    let t0 = Instant::now();
    let (done, detached) = join_with_quorum_or_timeout(
        vec![fast, slow1, slow2],
        2,
        Duration::from_millis(BROADCAST_STRAGGLER_GRACE_MS_DEFAULT),
        hard_budget,
    )
    .await;
    let elapsed = t0.elapsed();

    assert_eq!(done, vec![1u32], "only the fast peer completed in time");
    assert_eq!(detached, 2, "both slow peers must detach after hard_budget");
    assert!(
        elapsed >= Duration::from_millis(220),
        "must wait full hard_budget when fast_target is not reached (took {elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "must not wait beyond hard_budget (took {elapsed:?})"
    );

    // Subcase: when the 2nd task completes before hard_budget, grace arms then.
    let p1 = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        10u32
    });
    let p2 = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        20u32
    });
    let p3 = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        30u32
    });

    let t1 = Instant::now();
    let (mut done2, detached2) = join_with_quorum_or_timeout(
        vec![p1, p2, p3],
        2,
        Duration::from_millis(BROADCAST_STRAGGLER_GRACE_MS_DEFAULT),
        Duration::from_millis(450),
    )
    .await;
    let elapsed2 = t1.elapsed();
    done2.sort_unstable();
    assert_eq!(done2, vec![10u32, 20u32]);
    assert_eq!(detached2, 1);
    assert!(
        elapsed2 >= Duration::from_millis(95) && elapsed2 < Duration::from_millis(300),
        "must wait until 2nd peer finishes (~100ms) then detach 3rd after ~35ms grace (took {elapsed2:?})"
    );
}
