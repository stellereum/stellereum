//! Protocol-freeze pins (lead decision 2026-11-03).
//!
//! Regression-only: pins the VALUES of every frozen consensus-critical param
//! so an accidental value change fails loudly here instead of silently
//! shifting consensus behavior. Asserts values only; no logic, quorum-math,
//! timeout, vote-path, or serialization changes. Values wrapped in
//! `std::hint::black_box` so the pins cannot be optimized into tautologies.
//!
//! # Freeze table (param | old env knob | frozen value | kept-env-why)
//!
//! | Param (const) | Old env knob | Frozen value | Note |
//! |---|---|---|
//! | `consensus::FROZEN_ROUND_TIMEOUT_BASE_MS` | `STELL_ROUND_TIMEOUT_MS` (was default 3000, clamp 200..=3.6M) | `3_000` ms | FROZEN: base feeds the same-on-all-nodes ladder (spec 04_PHASE2 §2), must-match (consensus.rs). Env knob REMOVED. |
//! | `mempool::Mempool::FROZEN_MIN_GAS_FLOOR` | `STELL_MIN_GAS_LIMIT` (was default `GAS_BASIC_TRANSFER`) | `280_000` gas | FROZEN: admission floor must-match on all validators (main.rs `[config]` log). Env knob REMOVED; effective floor = max(frozen, governed). |
//! | `governance::MAX_MIN_GAS_LIMIT` | — (never env; governance bound) | `2_800_000` (= 10x base transfer) | FROZEN: cap on the governed half of the floor. |
//! | `consensus_quorum_min` (fn, floor(2n/3)+1) | — (never env) | formula | FROZEN: BFT safety curve (spec 04_PHASE2, quorum §). N=4 live => 3. |
//! | `pq_micro_quorum_threshold` / `pq_micro_quorum_power` | — (never env) | same curve / power variant | FROZEN: live µQC rule. |
//! | `ValidatorSet::quorum_power` | — (never env) | same curve, empty set => u64::MAX | FROZEN: quorum accounting (fail-closed on empty). |
//! | `staking::EQUIVOCATION_SLASH_BPS` | — (never env) | `500` (= 5%) | FROZEN slash BPS. |
//! | `staking::MICRO_COMMITTEE_SLASH_BPS` | — (never env) | `10_000` (= 100%) | FROZEN slash BPS. |
//! | `staking::DOWNTIME_SLASH_BPS` | — (never env) | `10` (= 0.1%) | FROZEN slash BPS. |
//! | `staking::DOWNTIME_MISS_THRESHOLD` | — (never env) | `42` heights (= 10.08 s @ 240 ms) | FROZEN: slash + down-proposer gate input. |
//! | `staking::DOWNTIME_PENALTY_COOLDOWN` | — (never env) | `500` heights (= 2 min @ 240 ms) | FROZEN: bounds repeat-slash drain. |
//! | `staking::BPS_DENOMINATOR` | — (never env) | `10_000` | FROZEN divisor. |
//! | `staking::DEFAULT_COMMISSION_BPS` | — (never env) | `1_000` (= 10%) | FROZEN default commission. |
//! | `staking::MIN_VALIDATOR_BOND` | — (never env) | `1_000_000_000_000` nano (= 1,000 STELL) | FROZEN set-membership floor. |
//! | `staking::STELL_MIN_BOND_BUFFER` | `STELL_MIN_BOND_BUFFER` WARN threshold (log-only, NOT this const) | `100_000_000_000` nano (= 100 STELL) | FROZEN admission buffer; the env var of the same name only tunes a WARN, never admission. |
//! | `staking::MAX_ACTIVE_VALIDATORS` | — (never env) | `250` | FROZEN set-size cap (quorum-math input). |
//! | `staking::UNBONDING_PERIOD_SECS` | — (never env) | `172_800` s (= 2 days) | FROZEN unbonding delay. |
//! | `staking::JAIL_RELEASE_DELAY_HEIGHTS` | — (never env) | `4_000` heights (= 16 min @ 240 ms) | FROZEN jail delay (> penalty cooldown by design). |
//! | `staking::COMMISSION_MAX_DELTA_BPS` | — (never env) | `500` (= 5 pp) | FROZEN commission step bound. |
//! | `staking::COMMISSION_EFFECT_DELAY_HEIGHTS` | — (never env) | `30_000` heights (= 2 h @ 240 ms) | FROZEN delegator-exit window. |
//! | `staking::COMMISSION_CHANGE_COOLDOWN_HEIGHTS` | — (never env) | `30_000` heights (= 2 h @ 240 ms) | FROZEN commission cooldown. |
//! | `staking::REENTRY_LIVENESS_WINDOW_HEIGHTS` | — (derived) | `42` (= DOWNTIME_MISS_THRESHOLD) | FROZEN by construction (derived const). |
//! | `pq_registry::PQ_ROTATION_DELAY_HEIGHTS` | — (never env) | `30_000` heights (= 2 h @ 240 ms) | FROZEN rotation delay (spec 02_PHASE2 §6, == EPOCH_LEN). |
//! | `cn_vrf::EPOCH_LEN` | — (never env) | `30_000` heights (= 2 h @ 240 ms) | FROZEN epoch length (spec 02_PHASE2 §6, O1). |
//! | `cn_vrf::V3_SEGMENT_LEN` | — (derived) | `1_875` slots (= EPOCH_LEN / 16) | FROZEN v3 hash-chain segment. |
//! | `cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS` | — (never env) | `682` heights (= 163.68 s @ 240 ms) | FROZEN VDF dispatch lead (measured; docs/RULESET_V2.md §VDF). |
//! | `mev_kem_registry::MEV_KEM_ROTATION_DELAY_HEIGHTS` | — (never env) | `30_000` heights (= 2 h @ 240 ms) | FROZEN MEV KEM rotation delay. |
//! | `mev_epoch::EPOCH_BLOCKS` | — (never env) | `500` blocks (= 2 min @ 240 ms) | FROZEN MEV epoch (== MMR_EPOCH_BLOCKS). |
//! | `mev_epoch::ORDER_COMMITMENT_LOOKBACK` | — (never env) | `50` heights (= 12 s @ 240 ms) | FROZEN node-local order-commitment retention. |
//! | `mmr::MMR_EPOCH_BLOCKS` | — (never env) | `500` blocks (= 2 min @ 240 ms) | FROZEN MMR epoch (== MEV EPOCH_BLOCKS, compile-asserted). |
//!
//! ## Kept-env (ops-only, one-line each; NOT pinned here — readers live in the
//! ## binary or depend on ambient env, and several have override unit tests
//! ## that go red if the knob is removed)
//!
//! | Env knob | Default | Kept-env why |
//! |---|---|---|
//! | `STELL_TICK_MS` | 50 | Local loop quantum; timeout VALUES come from the frozen base — heterogeneous ticks cannot fork. |
//! | `STELL_MIN_BLOCK_MS` | 50 | Local proposal-pacing floor; a slow node just proposes later — cannot fork (default already pinned by `floors_pinned_until_live_remeasurement`). |
//! | `STELL_DOWN_PROPOSER_TIMEOUT_MS` | 800 | Node-local liveness policy; override covered by unit tests (removal = red suite). |
//! | `STELL_ROUND_ZERO_TIMEOUT_MS` | 650 | Local propose-wait cap; heterogeneous caps are normal async drift — cannot fork. |
//! | `STELL_STRAGGLER_{GRACE,CAP,FRESHNESS}_MS` | 0/30000/5x-base | Experimental local holds outside the deterministic core; default-off = frozen behavior. |
//! | `STELL_DEADLOCK_TIMEOUT_SECS` | 300 | Local deadlock-breaker; override covered by `deadlock_breaker_tests` (removal = red suite). |
//! | `STELL_CATCHUP_BUDGET_MS` / `STELL_CATCHUP_INTERVAL_MS` | 2000/30000 | Node-local catch-up policy; nodes MAY differ (interval is now a backstop; catch-up is event-driven and the budget is the at-tip floor, gap-scaled). |
//! | `STELL_RETRO_PUBLISH_INTERVAL_MS` / `STELL_RETRO_BEHIND_WINDOW_SECS` | 30000/120 | Node-local DHT republication; nodes MAY differ (override unit tests exist). |
//! | `STELL_SNAPSHOT_INTERVAL` | 1000 (min 50) | Local snapshot cadence/availability, not consensus validity. |
//! | `STELL_SEND_TIMEOUT_MS` / `STELL_BROADCAST_JOIN_MS` / `STELL_CONS_BCAST_*` / `STELL_CONS_PROBE_*` / `STELL_INBOUND_*` / `STELL_REPL_*` / `STELL_PROBE_EVICT_AFTER` / `STELL_DIAL_*` / `STELL_LIVENESS_ALARM_MS` / `STELL_CATCHUP_BUDGET_MS` | various | Transport-local policy; nodes MAY differ; none feed the deterministic timeout ladder. |
//! | `STELL_SLASH_EJECT_WARN_GAP` / `STELL_MIN_BOND_BUFFER` | 100 STELL each | WARN-log-only thresholds, explicitly node-local (staking.rs); never admission. |
//! | `STELL_VALIDATOR_SET_MAX_LAG` (+ alias) | 300 | Restore-path freshness gate, fail-closed either way; local policy. |
//!
//! ## Enumerated but out of scope (activation gates, not params — untouched)
//!
//! `STELL_XPC_ACTIVATION_HEIGHT` (parked workchain; unset = single-shard
//! canon), `STELL_VRF_ACTIVATION_HEIGHT` (retired, inert + WARN),
//! `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` (default never), PQ flag-H heights
//! (`PQ_CLASSICAL_REFUSE_AFTER_HEIGHT`, `PQ_TRANSPORT_H_ACTIVATION_HEIGHT`:
//! const + env-override-for-tests per gap doc §1 — H chosen by lead).

use std::hint::black_box;
use stellereum::cn_vrf::{EPOCH_LEN, V3_COMMIT_LOOKAHEAD_BLOCKS, V3_SEGMENTS, V3_SEGMENT_LEN};
use stellereum::consensus::{
    consensus_quorum_min, deterministic_round_timeout_ms, pq_micro_quorum_power,
    pq_micro_quorum_threshold, FROZEN_ROUND_TIMEOUT_BASE_MS,
};
use stellereum::governance::MAX_MIN_GAS_LIMIT;
use stellereum::mempool::Mempool;
use stellereum::mev_epoch::{EPOCH_BLOCKS, ORDER_COMMITMENT_LOOKBACK};
use stellereum::mev_kem_registry::MEV_KEM_ROTATION_DELAY_HEIGHTS;
use stellereum::minroot_vdf::DEFAULT_VDF_STEPS_PER_EPOCH;
use stellereum::mmr::MMR_EPOCH_BLOCKS;
use stellereum::pq_registry::PQ_ROTATION_DELAY_HEIGHTS;
use stellereum::staking::{
    required_bond_floor_nano, BPS_DENOMINATOR, COMMISSION_CHANGE_COOLDOWN_HEIGHTS,
    COMMISSION_EFFECT_DELAY_HEIGHTS, COMMISSION_MAX_DELTA_BPS, DEFAULT_COMMISSION_BPS,
    DOWNTIME_MISS_THRESHOLD, DOWNTIME_PENALTY_COOLDOWN, DOWNTIME_SLASH_BPS, EQUIVOCATION_SLASH_BPS,
    JAIL_RELEASE_DELAY_HEIGHTS, MAX_ACTIVE_VALIDATORS, MICRO_COMMITTEE_SLASH_BPS,
    MIN_VALIDATOR_BOND, REENTRY_LIVENESS_WINDOW_HEIGHTS, STELL_MIN_BOND_BUFFER,
    UNBONDING_PERIOD_SECS,
};
use stellereum::svm::GAS_BASIC_TRANSFER;

#[test]
fn frozen_base_timeout_is_pinned() {
    assert_eq!(black_box(FROZEN_ROUND_TIMEOUT_BASE_MS), 3_000);
    // The frozen base reproduces the canonical ladder rungs (geometric ×2,
    // papers/02_liveness.md §7 rec 1 — r1 doubles the base, cap unchanged).
    assert_eq!(
        black_box(deterministic_round_timeout_ms(
            FROZEN_ROUND_TIMEOUT_BASE_MS,
            0,
            0
        )),
        3_000
    );
    assert_eq!(
        black_box(deterministic_round_timeout_ms(
            FROZEN_ROUND_TIMEOUT_BASE_MS,
            1,
            0
        )),
        6_000
    );
}

#[test]
fn frozen_fee_floor_is_pinned() {
    assert_eq!(black_box(Mempool::FROZEN_MIN_GAS_FLOOR), 280_000);
    assert_eq!(
        black_box(Mempool::FROZEN_MIN_GAS_FLOOR),
        black_box(GAS_BASIC_TRANSFER)
    );
    assert_eq!(
        black_box(Mempool::frozen_base_fee_floor()),
        black_box(Mempool::FROZEN_MIN_GAS_FLOOR)
    );
    assert_eq!(
        black_box(MAX_MIN_GAS_LIMIT),
        10 * black_box(GAS_BASIC_TRANSFER)
    );
    assert_eq!(black_box(MAX_MIN_GAS_LIMIT), 2_800_000);
}

#[test]
fn frozen_quorum_formulas_are_pinned() {
    assert_eq!(black_box(consensus_quorum_min(1)), 1);
    assert_eq!(black_box(consensus_quorum_min(3)), 3);
    assert_eq!(black_box(consensus_quorum_min(4)), 3);
    assert_eq!(black_box(consensus_quorum_min(6)), 5);
    assert_eq!(black_box(consensus_quorum_min(250)), 167);
    assert_eq!(black_box(pq_micro_quorum_threshold(4)), 3);
    assert_eq!(black_box(pq_micro_quorum_threshold(16)), 11);
    assert_eq!(black_box(pq_micro_quorum_threshold(0)), usize::MAX);
    assert_eq!(black_box(pq_micro_quorum_power(300)), 201);
    assert_eq!(black_box(pq_micro_quorum_power(0)), u64::MAX);
}

#[test]
fn frozen_slash_bps_are_pinned() {
    assert_eq!(black_box(EQUIVOCATION_SLASH_BPS), 500);
    assert_eq!(black_box(MICRO_COMMITTEE_SLASH_BPS), 10_000);
    assert_eq!(black_box(DOWNTIME_SLASH_BPS), 10);
    assert_eq!(black_box(DOWNTIME_MISS_THRESHOLD), 42);
    assert_eq!(black_box(DOWNTIME_PENALTY_COOLDOWN), 500);
    assert_eq!(black_box(BPS_DENOMINATOR), 10_000);
    assert_eq!(black_box(DEFAULT_COMMISSION_BPS), 1_000);
}

#[test]
fn frozen_bond_and_set_bounds_are_pinned() {
    assert_eq!(black_box(MIN_VALIDATOR_BOND), 1_000_000_000_000);
    assert_eq!(black_box(STELL_MIN_BOND_BUFFER), 100_000_000_000);
    assert_eq!(
        black_box(required_bond_floor_nano()),
        black_box(MIN_VALIDATOR_BOND.saturating_add(STELL_MIN_BOND_BUFFER))
    );
    assert_eq!(black_box(required_bond_floor_nano()), 1_100_000_000_000);
    assert_eq!(black_box(MAX_ACTIVE_VALIDATORS), 250);
    assert_eq!(black_box(UNBONDING_PERIOD_SECS), 172_800);
}

#[test]
fn frozen_jail_and_commission_delays_are_pinned() {
    assert_eq!(black_box(JAIL_RELEASE_DELAY_HEIGHTS), 4_000);
    assert_eq!(black_box(COMMISSION_MAX_DELTA_BPS), 500);
    assert_eq!(black_box(COMMISSION_EFFECT_DELAY_HEIGHTS), 30_000);
    assert_eq!(black_box(COMMISSION_CHANGE_COOLDOWN_HEIGHTS), 30_000);
    assert_eq!(black_box(REENTRY_LIVENESS_WINDOW_HEIGHTS), 42);
}

#[test]
fn frozen_rotation_and_epoch_lengths_are_pinned() {
    assert_eq!(black_box(PQ_ROTATION_DELAY_HEIGHTS), 30_000);
    assert_eq!(black_box(MEV_KEM_ROTATION_DELAY_HEIGHTS), 30_000);
    assert_eq!(black_box(EPOCH_LEN), 30_000);
    assert_eq!(black_box(EPOCH_LEN), black_box(PQ_ROTATION_DELAY_HEIGHTS));
    assert_eq!(
        black_box(V3_SEGMENTS as u64 * V3_SEGMENT_LEN),
        black_box(EPOCH_LEN)
    );
    assert_eq!(black_box(V3_SEGMENT_LEN), 1_875);
    assert_eq!(black_box(V3_COMMIT_LOOKAHEAD_BLOCKS), 682);
    assert_eq!(black_box(MMR_EPOCH_BLOCKS), 500);
    assert_eq!(black_box(EPOCH_BLOCKS), 500);
    assert_eq!(black_box(MMR_EPOCH_BLOCKS), black_box(EPOCH_BLOCKS));
    assert_eq!(black_box(ORDER_COMMITMENT_LOOKBACK), 50);
    assert_eq!(black_box(DEFAULT_VDF_STEPS_PER_EPOCH), 3_000_000);
}

/// Ruleset v2 rounding rule: `heights = ceil(duration_ms / 240)`, i.e. the
/// pinned windows are the smallest whole-block count that is NOT shorter
/// than the wall-clock intent. This pins both directions of the arithmetic
/// so a bad edit cannot silently shrink a window.
#[test]
fn ruleset_v2_wall_clock_mapping_is_pinned() {
    const BLOCK_MS: u64 = 240;
    let ceil_blocks = |ms: u64| ms.div_ceil(BLOCK_MS);
    let wall_ms = |heights: u64| heights * BLOCK_MS;

    // Duration intents from the ruleset-v2 task.
    let intents = [
        (DOWNTIME_MISS_THRESHOLD as u64, 10_000u64),
        (DOWNTIME_PENALTY_COOLDOWN, 120_000),
        (JAIL_RELEASE_DELAY_HEIGHTS, 960_000),
        (COMMISSION_EFFECT_DELAY_HEIGHTS, 7_200_000),
        (COMMISSION_CHANGE_COOLDOWN_HEIGHTS, 7_200_000),
        (PQ_ROTATION_DELAY_HEIGHTS, 7_200_000),
        (MEV_KEM_ROTATION_DELAY_HEIGHTS, 7_200_000),
        (EPOCH_LEN, 7_200_000),
        (EPOCH_BLOCKS, 120_000),
        (MMR_EPOCH_BLOCKS, 120_000),
        (ORDER_COMMITMENT_LOOKBACK, 12_000),
    ];
    for (heights, intent_ms) in intents {
        assert_eq!(
            heights,
            ceil_blocks(intent_ms),
            "heights must be ceil(intent_ms / 240)"
        );
        assert!(
            wall_ms(heights) >= intent_ms,
            "the window must never be shorter than its intent"
        );
        assert!(
            wall_ms(heights) - intent_ms < BLOCK_MS,
            "ceiling must not add a whole extra block"
        );
    }

    // The VDF lookahead is derived from the measured 20.455 s evaluation
    // with a 4x weak-host allowance and 2x scheduling headroom.
    assert_eq!(
        V3_COMMIT_LOOKAHEAD_BLOCKS,
        ceil_blocks(20_455 * 8),
        "lookahead = ceil(measured_eval_ms * 4 * 2 / 240)"
    );
    assert_eq!(wall_ms(V3_COMMIT_LOOKAHEAD_BLOCKS), 163_680);
    assert!(
        wall_ms(V3_COMMIT_LOOKAHEAD_BLOCKS) >= 20_455 * 8,
        "VDF budget must fit even at 4x slower with 2x headroom"
    );
    assert!(
        black_box(V3_COMMIT_LOOKAHEAD_BLOCKS) < black_box(EPOCH_LEN),
        "the lookahead must leave a positive commit window"
    );
}
