//! Frozen-core constant pins (CONSENSUS audit).
//!
//! Regression-only: pins the VALUES of every timeout/quorum/power bound this
//! agent cited, so an accidental value change fails loudly here instead of
//! silently shifting consensus behavior. Asserts values only; no logic,
//! timeout, quorum-math, vote-path, or serialization changes.

use stellereum::consensus::{
    consensus_quorum_min, deterministic_round_timeout_ms, pq_micro_quorum_threshold,
    ADAPTIVE_EXTENSION_CAP_MS, ADAPTIVE_EXTENSION_PER_MISS_MS, DETERMINISTIC_BACKOFF_CAP_MS,
    DETERMINISTIC_BACKOFF_PER_ROUND_MS, MAX_COMMIT_CERT_SIGNERS, MAX_DEADLOCK_JUMP,
    MAX_RETAINED_VOTE_ROUNDS, MAX_ROUND_ADVANCE_PER_MESSAGE, MAX_ROUND_AHEAD, MAX_SCAN_SPAN,
    MAX_SYNC_JUMPS_PER_ROUND, MICRO_COMMITTEE_MAX_SIZE, NIL_CIRCUIT_BREAKER_K,
    PROPOSER_MISS_THRESHOLD_M, REPHASE_SCAN_WINDOW, ROUND_LOOKBACK,
};
use stellereum::consensus_net::{
    BROADCAST_JOIN_TIMEOUT_MS_DEFAULT, CONS_BCAST_MIN_INTERVAL_MS_DEFAULT,
    CONS_PROBE_MIN_INTERVAL_MS_DEFAULT, INBOUND_BULK_BURST_BYTES_DEFAULT,
    INBOUND_BULK_BYTES_PER_SEC_DEFAULT, INBOUND_MAX_DEFER_WAIT_MS, INBOUND_MAX_TRACKED_PEERS,
    MAX_BATCH_BYTES, MAX_BATCH_ITEMS, MAX_CONSENSUS_MSG, MAX_TX_MSG, PROBE_EVICT_AFTER_DEFAULT,
    VOTE_SEND_DEDUP_TTL_MS,
};
use stellereum::mempool::PendingActivationBuffer;
use stellereum::runtime::{
    MAX_BLOCK_GAS, MAX_BLOCK_TXS, MAX_TIMESTAMP_JUMP_SECS, PROPOSAL_ALIGN_WINDOW_ROUNDS,
};

#[test]
fn quorum_math_is_pinned() {
    // floor(2n/3)+1 across the live-relevant range (N=4 live => 3).
    assert_eq!(consensus_quorum_min(1), 1);
    assert_eq!(consensus_quorum_min(3), 3);
    assert_eq!(consensus_quorum_min(4), 3);
    assert_eq!(pq_micro_quorum_threshold(4), 3);
    assert_eq!(pq_micro_quorum_threshold(16), 11);
    assert_eq!(pq_micro_quorum_threshold(0), usize::MAX);
}

#[test]
fn round_sync_and_scan_bounds_are_pinned() {
    assert_eq!(MAX_ROUND_AHEAD, 1_000);
    assert_eq!(MAX_ROUND_ADVANCE_PER_MESSAGE, 1);
    assert_eq!(ROUND_LOOKBACK, 8);
    assert_eq!(MAX_SYNC_JUMPS_PER_ROUND, 8);
    assert_eq!(MAX_DEADLOCK_JUMP, 65_536);
    assert_eq!(REPHASE_SCAN_WINDOW, 4_096);
    assert_eq!(MAX_RETAINED_VOTE_ROUNDS, 4_096);
    assert_eq!(MAX_SCAN_SPAN, 4_096);
    assert_eq!(MAX_COMMIT_CERT_SIGNERS, 4_096);
    assert_eq!(MICRO_COMMITTEE_MAX_SIZE, 64);
}

#[test]
fn timeout_ladder_values_are_pinned() {
    assert_eq!(NIL_CIRCUIT_BREAKER_K, 3);
    assert_eq!(DETERMINISTIC_BACKOFF_PER_ROUND_MS, 500);
    assert_eq!(DETERMINISTIC_BACKOFF_CAP_MS, 10_000);
    assert_eq!(ADAPTIVE_EXTENSION_PER_MISS_MS, 500);
    assert_eq!(ADAPTIVE_EXTENSION_CAP_MS, 5_000);
    assert_eq!(PROPOSER_MISS_THRESHOLD_M, 3);
    // Base 3500 live default: r0 => base, r1 => +500, adaptive still capped.
    assert_eq!(deterministic_round_timeout_ms(3500, 0, 0), 3500);
    assert_eq!(deterministic_round_timeout_ms(3500, 1, 0), 4000);
    assert_eq!(
        deterministic_round_timeout_ms(3500, 0, 1_000_000),
        3500 + ADAPTIVE_EXTENSION_CAP_MS
    );
}

#[test]
fn transport_and_block_bounds_are_pinned() {
    assert_eq!(MAX_CONSENSUS_MSG, 32 * 1024 * 1024);
    assert_eq!(MAX_TX_MSG, 1024 * 1024);
    assert_eq!(MAX_BATCH_ITEMS, 32);
    assert_eq!(MAX_BATCH_BYTES, 512 * 1024);
    assert_eq!(VOTE_SEND_DEDUP_TTL_MS, 200);
    assert_eq!(BROADCAST_JOIN_TIMEOUT_MS_DEFAULT, 500);
    assert_eq!(PROBE_EVICT_AFTER_DEFAULT, 3);
    assert_eq!(CONS_BCAST_MIN_INTERVAL_MS_DEFAULT, 25);
    assert_eq!(CONS_PROBE_MIN_INTERVAL_MS_DEFAULT, 5_000);
    assert_eq!(INBOUND_BULK_BYTES_PER_SEC_DEFAULT, 512 * 1024);
    assert_eq!(INBOUND_BULK_BURST_BYTES_DEFAULT, 1024 * 1024);
    assert_eq!(INBOUND_MAX_DEFER_WAIT_MS, 5_000);
    assert_eq!(INBOUND_MAX_TRACKED_PEERS, 1024);
    assert_eq!(MAX_BLOCK_TXS, 10_000);
    assert_eq!(MAX_BLOCK_GAS, 500_000_000);
    assert_eq!(MAX_TIMESTAMP_JUMP_SECS, 3_600);
    assert_eq!(PROPOSAL_ALIGN_WINDOW_ROUNDS, 8);
    assert_eq!(PendingActivationBuffer::MAX_GLOBAL_BUFFERED_TXS, 2048);
    assert_eq!(PendingActivationBuffer::MAX_NONCES_PER_ACCOUNT, 4);
}
