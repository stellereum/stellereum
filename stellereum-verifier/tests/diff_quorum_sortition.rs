//! Differential parity for quorum math and sortition against `stellereum`.
//!
//! Covers `N = 1..=250`, skewed stake, the `191/192` C1 split cliff, both the
//! parent-hash and CN-VRF v3 beacon schedules, and the biased/unbiased height
//! gates. Every comparison is ours-vs-`stellereum` on identical inputs.

use stellereum::chain_spec::set_sortition_unbiased_activation_override;
use stellereum::consensus as reference;
use stellereum::consensus::set_qc_split_activation_override;
use stellereum_verifier::consensus as verifier;

const MAX_N: usize = 250;
const PARENT: [u8; 32] = [0x5Au8; 32];
const HEIGHTS: [u64; 4] = [0, 1, 42, 30_001];
const ROUNDS: [u32; 3] = [0, 1, 7];
const COMMITTEE_SIZES: [u32; 6] = [0, 1, 2, 8, 64, 128];

/// A deterministic, deliberately skewed validator set: most validators have a
/// few hundred units of power, every 17th has exactly one, and the rest spread
/// over a wide range so the weighted draw is actually exercised.
fn validator_list(n: usize) -> Vec<([u8; 32], u64)> {
    (0..n)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            id[31] = (i % 251) as u8;
            let power = if i % 17 == 0 {
                1
            } else {
                ((i as u64 * 7_919 + 13) % 100_000) + 1
            };
            (id, power)
        })
        .collect()
}

fn ours(n: usize) -> verifier::ValidatorSet {
    verifier::ValidatorSet::from_list(validator_list(n))
}

fn theirs(n: usize) -> reference::ValidatorSet {
    reference::ValidatorSet::from_list(validator_list(n))
}

fn beacons(epoch: u64) -> (verifier::EpochBeacon, reference::EpochBeacon) {
    let output = [0x3Cu8; 48];
    (
        verifier::EpochBeacon { epoch, output },
        reference::EpochBeacon { epoch, output },
    )
}

#[test]
fn quorum_math_parity_n_1_to_250() {
    let committee_powers = [0u64, 1, 2, 3, 7, 1_000, u64::MAX / 3];
    for n in 1..=MAX_N {
        assert_eq!(
            verifier::consensus_quorum_min(n as u64),
            reference::consensus_quorum_min(n as u64),
            "consensus_quorum_min({n})"
        );
        assert_eq!(
            verifier::micro_committee_size(n),
            reference::micro_committee_size(n),
            "micro_committee_size({n})"
        );

        let a = ours(n);
        let b = theirs(n);
        assert_eq!(a.len(), b.len(), "validator count at N={n}");
        assert_eq!(a.total_power(), b.total_power(), "total_power at N={n}");
        assert_eq!(
            a.total_power_exact(),
            b.total_power_exact(),
            "total_power_exact at N={n}"
        );
        assert_eq!(a.quorum_power(), b.quorum_power(), "quorum_power at N={n}");
        assert_eq!(
            a.fingerprint(),
            b.fingerprint(),
            "validator-set fingerprint at N={n}"
        );

        for &size in &COMMITTEE_SIZES {
            assert_eq!(
                verifier::pq_micro_quorum_threshold(size),
                reference::pq_micro_quorum_threshold(size),
                "pq_micro_quorum_threshold({size})"
            );
        }
        for &power in &committee_powers {
            assert_eq!(
                verifier::pq_micro_quorum_power(power),
                reference::pq_micro_quorum_power(power),
                "pq_micro_quorum_power({power})"
            );
            assert_eq!(
                verifier::pq_micro_advisory_power(power),
                reference::pq_micro_advisory_power(power),
                "pq_micro_advisory_power({power})"
            );
            assert_eq!(
                verifier::pq_full_required_power(power),
                reference::pq_full_required_power(power),
                "pq_full_required_power({power})"
            );
        }
    }
}

#[test]
fn mixed_quorum_pair_safe_parity() {
    let total = 1_000_000u64;
    let cases = [
        (0u64, 0u64),
        (666_667, 333_333),
        (666_667, 333_334),
        (700_000, 300_000),
        (u64::MAX, 0),
        (0, u64::MAX),
        (500_000, 500_000),
    ];
    for (t_micro, t_full) in cases {
        assert_eq!(
            verifier::mixed_quorum_pair_safe(t_micro, t_full, total),
            reference::mixed_quorum_pair_safe(t_micro, t_full, total),
            "mixed_quorum_pair_safe({t_micro}, {t_full}, {total})"
        );
    }
    for (t_micro, t_full) in cases {
        assert_eq!(
            verifier::mixed_quorum_pair_safe(t_micro, t_full, 0),
            reference::mixed_quorum_pair_safe(t_micro, t_full, 0),
            "zero-total mixed_quorum_pair_safe({t_micro}, {t_full})"
        );
    }
}

#[test]
fn sortition_seed_parity() {
    for height in HEIGHTS {
        for round in ROUNDS {
            assert_eq!(
                verifier::sortition_seed(&PARENT, height, round),
                reference::sortition_seed(&PARENT, height, round),
                "sortition_seed at ({height}, {round})"
            );
        }
    }
}

#[test]
fn committee_parity_parent_hash_unbiased_on_off() {
    let seed = [0x11u8; 32];
    for n in 1..=MAX_N {
        let a = ours(n);
        let b = theirs(n);

        for height in HEIGHTS {
            for round in ROUNDS {
                for &size in &COMMITTEE_SIZES {
                    // Biased (pre-activation) draw.
                    set_sortition_unbiased_activation_override(Some(u64::MAX));
                    let biased = verifier::derive_sortition_committee_at(
                        &a,
                        height,
                        round,
                        size,
                        &PARENT,
                        u64::MAX,
                    );
                    let ref_biased =
                        reference::derive_sortition_committee(&b, height, round, size, &PARENT);
                    assert_eq!(
                        biased, ref_biased,
                        "biased draw N={n} h={height} r={round} k={size}"
                    );

                    // Unbiased (W6-A7-7) draw.
                    set_sortition_unbiased_activation_override(Some(0));
                    let unbiased = verifier::derive_sortition_committee_at(
                        &a, height, round, size, &PARENT, 0,
                    );
                    let ref_unbiased =
                        reference::derive_sortition_committee(&b, height, round, size, &PARENT);
                    assert_eq!(
                        unbiased, ref_unbiased,
                        "unbiased draw N={n} h={height} r={round} k={size}"
                    );

                    // Same height gate, but drawn from an explicit seed/domain.
                    let direct = verifier::select_committee_from_seed_at(
                        &a,
                        size,
                        verifier::SORTITION_DRAW_DOMAIN,
                        &seed,
                        height,
                        0,
                    );
                    let ref_direct = reference::select_committee_from_seed_at(
                        &b,
                        size,
                        reference::SORTITION_DRAW_DOMAIN,
                        &seed,
                        height,
                    );
                    assert_eq!(direct, ref_direct, "seeded draw N={n} h={height} k={size}");
                }
            }
        }
    }
    set_sortition_unbiased_activation_override(None);
}

#[test]
fn committee_parity_beacon_schedule() {
    // Beacon draws delegate to the same seeded lottery; keep it on the
    // unbiased path so the seed framing is covered end-to-end.
    set_sortition_unbiased_activation_override(Some(0));
    for n in 1..=MAX_N {
        let a = ours(n);
        let b = theirs(n);
        for height in HEIGHTS {
            let epoch = verifier::cnvrf_v3_epoch_of_height(height);
            let (vb, rb) = beacons(epoch);
            for round in ROUNDS {
                for &size in &COMMITTEE_SIZES {
                    let got = verifier::committee_for_height_at(
                        &a,
                        height,
                        round,
                        size,
                        Some(&PARENT),
                        verifier::CommitteeSchedule::Beacon(Some(vb)),
                        0,
                    );
                    let expected = reference::committee_for_height(
                        &b,
                        height,
                        round,
                        size,
                        Some(&PARENT),
                        reference::CommitteeSchedule::Beacon(Some(rb)),
                    );
                    assert_eq!(
                        got, expected,
                        "beacon draw N={n} h={height} r={round} k={size}"
                    );
                }
            }
        }
    }

    // Activation in force but the beacon is unknown: both fail closed (no
    // parent-hash fallback).
    let a = ours(32);
    let b = theirs(32);
    let (vb, _) = beacons(1);
    assert!(verifier::committee_for_height_at(
        &a,
        42,
        0,
        8,
        Some(&PARENT),
        verifier::CommitteeSchedule::Beacon(None),
        0,
    )
    .is_empty());
    assert!(reference::committee_for_height(
        &b,
        42,
        0,
        8,
        Some(&PARENT),
        reference::CommitteeSchedule::Beacon(None),
    )
    .is_empty());
    // Wrong epoch also fails closed even with an output.
    let wrong_epoch = verifier::EpochBeacon {
        epoch: vb.epoch + 1,
        output: vb.output,
    };
    assert!(verifier::committee_for_height_at(
        &a,
        42,
        0,
        8,
        Some(&PARENT),
        verifier::CommitteeSchedule::Beacon(Some(wrong_epoch)),
        0,
    )
    .is_empty());

    set_sortition_unbiased_activation_override(None);
}

#[test]
fn proposer_parity_unbiased_on_off() {
    for n in 1..=MAX_N {
        let a = ours(n);
        let b = theirs(n);

        set_sortition_unbiased_activation_override(Some(u64::MAX));
        for height in HEIGHTS {
            for round in ROUNDS {
                assert_eq!(
                    a.proposer_for_at(height, round, u64::MAX),
                    b.proposer_for(height, round),
                    "biased proposer N={n} h={height} r={round}"
                );
            }
        }

        set_sortition_unbiased_activation_override(Some(0));
        for height in HEIGHTS {
            for round in ROUNDS {
                assert_eq!(
                    a.proposer_for_at(height, round, 0),
                    b.proposer_for(height, round),
                    "unbiased proposer N={n} h={height} r={round}"
                );
            }
        }
    }
    set_sortition_unbiased_activation_override(None);
}

#[test]
fn qc_split_191_192_cliff() {
    for &n in &[0usize, 1, 100, 190, 191, 192, 193, 250] {
        for &height in &[0u64, 9, 10, 11, 1_000_000, u64::MAX] {
            // Rollout gate at height 10.
            set_qc_split_activation_override(Some(10));
            assert_eq!(
                verifier::qc_split_required_at(height, n, 10),
                reference::qc_split_required(height, n),
                "split-at-10 N={n} h={height}"
            );

            // Frozen rollout gate (`u64::MAX`); only the size leg can fire.
            set_qc_split_activation_override(None);
            assert_eq!(
                verifier::qc_split_required(height, n),
                reference::qc_split_required(height, n),
                "frozen split N={n} h={height}"
            );
        }

        // The exact size cliff: 191 is below, 192 is at/above.
        set_qc_split_activation_override(None);
        assert_eq!(n >= 192, verifier::qc_split_required(0, n));
        assert_eq!(n >= 192, reference::qc_split_required(0, n));
        set_qc_split_activation_override(Some(10));
        assert!(verifier::qc_split_required_at(10, n, 10));
        assert!(reference::qc_split_required(10, n));
    }
    set_qc_split_activation_override(None);
}
