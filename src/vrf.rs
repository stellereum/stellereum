//! Sortition math helpers (canonical parent-hash draw is the election).
//!
//! # Status: math ONLY — no key material, no registry, no provisioning
//!
//! The live committee election (`crate::consensus::derive_sortition_committee`)
//! is seeded by the parent block hash. That draw is documented grindable (see
//! the `RESIDUAL RISK` note on the draw function): every candidate parent
//! hash is a fresh sortition draw. The network-anchored quorum is the current
//! mitigation.
//!
//! This module keeps ONLY pure stake-math helpers used to reason about that
//! draw. Nothing here mints, stores, verifies, or provisions any key
//! material; nothing here reads the environment, the filesystem, or any
//! registry; nothing here is consulted by election (election lives in
//! `consensus.rs` and takes only the parent hash, height, round, and stake).
//!
//! RETIRED and deleted (nodes wiped, no history compat, no live callers —
//! callers rewired to the canonical parent-hash draw per
//! `tests/vrf_canonical_draw_tests.rs`):
//! key types and curve helpers, key-binding helpers, secret-provisioning
//! helpers and their env names, activation-gate helpers and their env name,
//! election-seed and beacon helpers keyed by retired ticket bytes, and their
//! domain tags and policy marker. Election math is untouched.

/// Lottery threshold for a stake-weighted draw over a 128-bit ticket.
///
/// A validator holding `stake` of `total_stake` is elected when its ticket
/// `y` (uniform in `[0, 2^128)`) satisfies `y < threshold`, with
/// `threshold = floor(2^128 * stake * expected_seats / total_stake)`
/// (saturating at `u128::MAX`). Expected committee size is then
/// `expected_seats` regardless of stake distribution — the same mean as the
/// current stake-weighted draw.
pub fn lottery_threshold(stake: u64, total_stake: u64, expected_seats: u64) -> u128 {
    if stake == 0 || total_stake == 0 || expected_seats == 0 {
        return 0;
    }
    let num = (stake as u128) * (expected_seats as u128);
    let frac_num = num / (total_stake as u128);
    let frac_rem = num % (total_stake as u128);
    // floor(2^128 * (frac_num + frac_rem/total)) saturating at 2^128 - 1.
    if frac_num >= 1 {
        // stake*expected >= total: threshold covers the whole range.
        return u128::MAX;
    }
    // frac_num == 0: threshold = floor(2^128 * frac_rem / total).
    if frac_rem == 0 {
        return 0;
    }
    // 2^128 * r / total without overflow: split 2^128 = 2^64 * 2^64.
    const HI: u128 = 1u128 << 64;
    let t = total_stake as u128;
    let r = frac_rem;
    let hi = (r * HI) / t; // < 2^64, exact
    let rem = (r * HI) % t;
    let lo = (rem * HI) / t;
    hi * HI + lo
}

/// Expected parent-hash draws to get ONE chosen member elected (uniform set
/// of `n` validators, committee `k`): each candidate parent is an independent
/// draw with `P = k/n`, so `E[draws] = n/k`.
///
/// At BLAKE3 speeds (~1e9 draws/s per GPU) this is seconds for any `k >= 1` —
/// the number that proves the parent hash is unknowability, not
/// unforgeability.
pub fn expected_draws_to_include_member(n: u64, k: u64) -> f64 {
    if k == 0 || n == 0 {
        return f64::INFINITY;
    }
    n as f64 / k as f64
}

/// Expected parent-hash draws to capture EXACTLY a chosen `s`-seat subset of
/// the committee (uniform `n`, committee `k`): `C(n,s)/C(k,s)`. Computed in
/// log-space so large sets do not overflow.
pub fn expected_draws_to_capture_seats(n: u64, k: u64, s: u64) -> f64 {
    if s > k || s > n || k > n {
        return f64::INFINITY;
    }
    if s == 0 {
        return 1.0;
    }
    let mut log_c = 0.0f64;
    for i in 0..s {
        log_c += ((n - i) as f64).ln() - ((k - i) as f64).ln();
    }
    log_c.exp()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lottery_threshold_math_is_pinned() {
        // Full stake, one expected seat: the whole ticket range.
        assert_eq!(lottery_threshold(4, 4, 1), u128::MAX);
        // Zero stake / zero total / zero seats: never elected.
        assert_eq!(lottery_threshold(0, 4, 1), 0);
        assert_eq!(lottery_threshold(1, 0, 1), 0);
        assert_eq!(lottery_threshold(1, 4, 0), 0);
        // Half the stake, one seat: half the range (exact: 2^127).
        assert_eq!(lottery_threshold(1, 2, 1), 1u128 << 127);
        // Quarter stake, four seats: the whole range (mean 1 seat).
        assert_eq!(lottery_threshold(1, 4, 4), u128::MAX);
        // Quarter stake, one seat: quarter of the range.
        assert_eq!(lottery_threshold(1, 4, 1), 1u128 << 126);
    }

    #[test]
    fn grinding_cost_proves_parent_hash_is_not_a_security_boundary() {
        // Live shape (N=4, full-set committee): one draw includes anyone.
        assert_eq!(expected_draws_to_include_member(4, 4), 1.0);
        // N=100 uniform, 64-seat committee: ~1.56 draws per target inclusion.
        let d = expected_draws_to_include_member(100, 64);
        assert!((d - 1.5625).abs() < 1e-9);
        // At 1e9 draws/s that is ~2ns: grinding one seat is free.
        assert!(
            d / 1e9 < 1e-6,
            "one-seat bias must cost microseconds, not years"
        );
        // Capturing an EXACT 33-seat slice of a 64-committee from 100
        // validators costs ~1.66e8 draws — 0.17 s on one GPU. Even the
        // "expensive end" of grinding is interactive, not prohibitive.
        let capture = expected_draws_to_capture_seats(100, 64, 33);
        assert!(capture.is_finite() && capture > 1e6 && capture < 1e12);
        assert!((capture - 165_828_638.0).abs() / capture < 1e-6);
        // Degenerate inputs fail closed, never NaN-panic.
        assert!(expected_draws_to_include_member(10, 0).is_infinite());
        assert!(expected_draws_to_capture_seats(4, 4, 5).is_infinite());
        assert_eq!(expected_draws_to_capture_seats(4, 4, 0), 1.0);
    }
}
