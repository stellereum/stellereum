//! Supermajority restart gate: fork/protocol/presence matrix and bounded wait.
//!
//! The gate's decision core is exercised directly (the real
//! `src/node/upgrade_halt.rs` module is included by path), so these tests pin
//! exactly the property an operator relies on during a coordinated restart:
//! a node with a different fork id or protocol version is REFUSED consensus
//! weight, a missing peer contributes nothing, and the threshold is the same
//! STRICTLY-more-than-2/3 quorum consensus uses.

use std::time::{Duration, Instant};

#[path = "../src/node/upgrade_halt.rs"]
#[allow(dead_code)]
mod upgrade_halt;

use upgrade_halt::{
    evaluate_supermajority_gate, parse_wait_supermajority_height, parse_wait_supermajority_timeout,
    wait_for_supermajority, GatePeerReport, SupermajorityEvaluation,
};

const FORK_A: u32 = 0x0f58_4a46;
const FORK_B: u32 = 0xdead_beef;
const PROTOCOL: (u16, u16) = (1, 0);

fn id(n: u8) -> [u8; 32] {
    [n; 32]
}

fn report(
    validator: [u8; 32],
    power: u64,
    present: bool,
    fork_id: Option<u32>,
    protocol_version: Option<(u16, u16)>,
) -> GatePeerReport {
    GatePeerReport {
        validator,
        power,
        present,
        fork_id,
        protocol_version,
    }
}

fn matching(validator: [u8; 32], power: u64) -> GatePeerReport {
    report(validator, power, true, Some(FORK_A), Some(PROTOCOL))
}

fn evaluate(reports: &[GatePeerReport]) -> SupermajorityEvaluation {
    // 3 equal-power validators => strict >2/3 quorum is all three.
    evaluate_supermajority_gate(FORK_A, PROTOCOL, 3, 3, reports)
}

#[test]
fn fork_mismatch_is_refused_and_two_node_side_waits_for_the_third() {
    let a1 = id(1);
    let a2 = id(2);
    let b = id(3);

    // Node A's view before the third validator is upgraded: A + A match,
    // B is on another fork. Two of three is EXACTLY 2/3, which the consensus
    // quorum (strictly more than 2/3) does NOT accept.
    let before = evaluate(&[
        matching(a1, 1),
        matching(a2, 1),
        report(b, 1, true, Some(FORK_B), Some(PROTOCOL)),
    ]);
    assert!(!before.eligible, "2-of-3 must not reach the strict quorum");
    assert_eq!(before.matching_power, 2);
    assert_eq!(before.required_power, 3);
    assert_eq!(before.mismatched, vec![b]);

    // The misconfigured node B sees only itself on its fork: it is refused.
    let b_view = evaluate_supermajority_gate(
        FORK_B,
        PROTOCOL,
        3,
        3,
        &[
            report(a1, 1, true, Some(FORK_A), Some(PROTOCOL)),
            report(a2, 1, true, Some(FORK_A), Some(PROTOCOL)),
            report(b, 1, true, Some(FORK_B), Some(PROTOCOL)),
        ],
    );
    assert!(!b_view.eligible, "the fork-B node must be refused consensus");
    assert_eq!(b_view.matching_power, 1);

    // The third is upgraded: both sides now see the whole committed set on
    // fork A, so the cluster may start/finalize.
    let after_a = evaluate(&[matching(a1, 1), matching(a2, 1), matching(b, 1)]);
    assert!(after_a.eligible);
    assert_eq!(after_a.matching_power, 3);
    assert!(after_a.mismatched.is_empty() && after_a.missing.is_empty());

    let after_b = evaluate(&[matching(a1, 1), matching(a2, 1), matching(b, 1)]);
    assert!(after_b.eligible);
}

#[test]
fn protocol_version_mismatch_never_contributes_power() {
    let a1 = id(1);
    let a2 = id(2);
    let a3 = id(3);
    let eval = evaluate(&[
        matching(a1, 1),
        report(a2, 1, true, Some(FORK_A), Some((1, 1))),
        matching(a3, 1),
    ]);
    assert!(
        !eval.eligible,
        "a different protocol version must not be allowed to vote"
    );
    assert_eq!(eval.matching_power, 2);
    assert_eq!(eval.mismatched, vec![a2]);
}

#[test]
fn missing_or_unnegotiated_peer_does_not_count() {
    let a1 = id(1);
    let a2 = id(2);
    let a3 = id(3);
    let eval = evaluate(&[
        matching(a1, 1),
        matching(a2, 1),
        report(a3, 1, false, None, None),
    ]);
    assert!(!eval.eligible);
    assert_eq!(eval.matching_power, 2);
    assert_eq!(eval.missing, vec![a3]);
}

#[test]
fn threshold_is_strictly_more_than_two_thirds_of_stake() {
    let a = id(1);
    let b = id(2);
    let c = id(3);
    // Equal stake: 2/4 is exactly half; 3/4 is strictly above 2/3.
    let two = evaluate_supermajority_gate(
        FORK_A,
        PROTOCOL,
        4,
        3,
        &[matching(a, 1), matching(b, 1), report(c, 1, false, None, None)],
    );
    assert!(!two.eligible);
    let three = evaluate_supermajority_gate(
        FORK_A,
        PROTOCOL,
        4,
        3,
        &[matching(a, 1), matching(b, 1), matching(c, 1)],
    );
    assert!(three.eligible);
    assert_eq!(three.matching_power, 3);
    // A duplicate report cannot inflate the power.
    let duplicate = evaluate_supermajority_gate(
        FORK_A,
        PROTOCOL,
        4,
        3,
        &[matching(a, 1), matching(a, 1), matching(b, 1)],
    );
    assert_eq!(duplicate.matching_power, 2);
    assert!(!duplicate.eligible);
}

#[test]
fn weighted_stake_uses_power_not_validator_count() {
    let a = id(1);
    let b = id(2);
    let small = id(3);
    // A holds 70 power, B 20, small 10; total 100, quorum 67.
    let eval = evaluate_supermajority_gate(
        FORK_A,
        PROTOCOL,
        100,
        67,
        &[
            matching(a, 70),
            report(b, 20, true, Some(FORK_B), Some(PROTOCOL)),
            matching(small, 10),
        ],
    );
    assert!(
        eval.eligible,
        "70 + 10 = 80 is above the 67 quorum even though the 20-power validator is on another fork"
    );
    assert_eq!(eval.matching_power, 80);
    // Remove the small validator and the same 20-power mismatch leaves only
    // 70... which is still above 67. Use a 60/40 split instead to prove that
    // a mismatched validator can be the difference between passing and not.
    let a60 = evaluate_supermajority_gate(
        FORK_A,
        PROTOCOL,
        100,
        67,
        &[matching(a, 60), report(b, 40, true, Some(FORK_B), Some(PROTOCOL))],
    );
    assert!(!a60.eligible);
    assert_eq!(a60.matching_power, 60);
    let a60_plus_small = evaluate_supermajority_gate(
        FORK_A,
        PROTOCOL,
        100,
        67,
        &[
            matching(a, 60),
            report(b, 30, true, Some(FORK_B), Some(PROTOCOL)),
            matching(small, 10),
        ],
    );
    assert!(a60_plus_small.eligible);
    assert_eq!(a60_plus_small.matching_power, 70);
}

#[test]
fn environment_parsing_is_fail_closed() {
    assert_eq!(parse_wait_supermajority_height(None).unwrap(), None);
    assert_eq!(parse_wait_supermajority_height(Some("  ")).unwrap(), None);
    assert_eq!(parse_wait_supermajority_height(Some(" 4242 ")).unwrap(), Some(4242));
    assert_eq!(parse_wait_supermajority_height(Some("0")).unwrap(), Some(0));
    assert!(
        parse_wait_supermajority_height(Some("not-a-height")).is_err(),
        "a typo must not silently disable the gate"
    );
    assert_eq!(
        parse_wait_supermajority_timeout(None).unwrap(),
        Duration::from_secs(upgrade_halt::DEFAULT_WAIT_SUPERMAJORITY_TIMEOUT_SECS)
    );
    assert_eq!(
        parse_wait_supermajority_timeout(Some("5")).unwrap(),
        Duration::from_secs(5)
    );
    assert!(parse_wait_supermajority_timeout(Some("garbage")).is_err());
    assert!(parse_wait_supermajority_timeout(Some("86401")).is_err());
}

#[tokio::test]
async fn bounded_wait_returns_eligible_once_the_third_arrives() {
    let a1 = id(1);
    let a2 = id(2);
    let a3 = id(3);
    let mut attempt = 0u64;
    let evaluation = wait_for_supermajority(
        FORK_A,
        PROTOCOL,
        3,
        3,
        Duration::from_secs(5),
        Duration::from_millis(10),
        || {
            attempt += 1;
            if attempt < 3 {
                vec![
                    matching(a1, 1),
                    matching(a2, 1),
                    report(a3, 1, true, Some(FORK_B), Some(PROTOCOL)),
                ]
            } else {
                vec![matching(a1, 1), matching(a2, 1), matching(a3, 1)]
            }
        },
    )
    .await;
    assert!(evaluation.eligible);
    assert_eq!(evaluation.matching_power, 3);
    assert_eq!(attempt, 3);
}

#[tokio::test]
async fn bounded_wait_times_out_to_observer_instead_of_hanging() {
    let a1 = id(1);
    let a2 = id(2);
    let a3 = id(3);
    let started = Instant::now();
    let evaluation = wait_for_supermajority(
        FORK_A,
        PROTOCOL,
        3,
        3,
        Duration::from_millis(40),
        Duration::from_millis(10),
        || {
            vec![
                matching(a1, 1),
                report(a2, 1, true, Some(FORK_B), Some(PROTOCOL)),
                report(a3, 1, false, None, None),
            ]
        },
    )
    .await;
    assert!(!evaluation.eligible);
    assert_eq!(evaluation.matching_power, 1);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the gate must return at its bounded deadline"
    );
}

#[test]
fn committed_set_requires_an_exact_snapshot_instead_of_guessing() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "stell-gate-committed-set-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let store = stellereum::storage::Storage::open(&dir.join("store")).expect("open store");
    let err = upgrade_halt::committed_validator_set_at(&store, 12)
        .expect_err("a missing committed snapshot must fail closed");
    assert!(err.contains("no committed domain snapshot at height 12"), "{err}");
    drop(store);
    std::fs::remove_dir_all(&dir).ok();
}
