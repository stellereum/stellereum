//! STATUS:
//! - Legacy packed-`i64` entrypoints (`deposit`, `withdraw`, `shares_of`):
//!   DEMO-GRADE compatibility shims (`caller_is` binds integer `user_id` to
//!   canonical zero-padded `host.caller` addresses; kept for backwards
//!   compatibility with legacy tests). Swaps are permissionless AMM mechanics
//!   by design (curve-priced, no victim).
//! - PQ entrypoints (`deposit_pq`, `withdraw_pq`, `shares_of_pq`): authenticate
//!   full 32-byte post-quantum `host.caller` LP addresses via `caller()` +
//!   `calldata()` with deterministic `blake3`-keyed share slots.
//! DO NOT deploy with value without a full audit.
//!
//! Automated Market Maker (AMM) Constant Product Liquidity Pool (Hardened)
//!
//! Features:
//! - Complete Bidirectional Swaps: Token A -> Token B (`swap_a_for_b`) and Token B -> Token A (`swap_b_for_a`).
//! - Constant Product formula (x * y = k) calculated with 128-bit integer safety (zero overflow).
//! - Proportional liquidity deposit and withdrawal with LP share tracking (both legacy and 32-byte PQ).
//! - Exact integer swap quote calculation with zero rounding exploit vectors.
//! - Slippage protection and re-initialization guards.

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use stellereum_contract_sdk::{
    blake3, calldata, caller, caller_is, emit, return_data, setup_wasm_panic_handler, sload,
    sstore, ERR_ALREADY_EXISTS, ERR_INSUFFICIENT_BALANCE, ERR_INVALID_ARGUMENT, ERR_OVERFLOW,
    ERR_UNAUTHORIZED, SUCCESS,
};

setup_wasm_panic_handler!();

const SLOT_INITIALIZED: i64 = 0;
const SLOT_TOTAL_SHARES: i64 = 1;
const SLOT_RESERVE_A: i64 = 2;
const SLOT_RESERVE_B: i64 = 3;
const SLOT_FEE_BPS: i64 = 4;
const SLOT_PQ_MODE: i64 = 5;

const USER_SHARES_OFFSET: i64 = 10_000;

// Event Topics
const TOPIC_DEPOSIT: i64 = 10;
const TOPIC_WITHDRAW: i64 = 11;
const TOPIC_SWAP_A_FOR_B: i64 = 12;
const TOPIC_SWAP_B_FOR_A: i64 = 13;

#[inline(always)]
fn user_slot(user_id: i64) -> Result<i64, i64> {
    if user_id < 0 {
        return Err(ERR_INVALID_ARGUMENT);
    }
    USER_SHARES_OFFSET
        .checked_add(user_id)
        .ok_or(ERR_INVALID_ARGUMENT)
}

/// Initialize pool once with fee in basis points (e.g. 30 = 0.3%)
#[no_mangle]
pub extern "C" fn init(fee_bps: i64) -> i64 {
    if !(0..10_000).contains(&fee_bps) {
        return ERR_INVALID_ARGUMENT;
    }
    if sload(SLOT_INITIALIZED) != 0 {
        return ERR_ALREADY_EXISTS;
    }

    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_TOTAL_SHARES, 0);
    sstore(SLOT_RESERVE_A, 0);
    sstore(SLOT_RESERVE_B, 0);
    sstore(SLOT_FEE_BPS, fee_bps);
    fee_bps
}

#[no_mangle]
pub extern "C" fn get_reserve_a(_arg: i64) -> i64 {
    sload(SLOT_RESERVE_A)
}

#[no_mangle]
pub extern "C" fn get_reserve_b(_arg: i64) -> i64 {
    sload(SLOT_RESERVE_B)
}

#[no_mangle]
pub extern "C" fn get_total_shares(_arg: i64) -> i64 {
    sload(SLOT_TOTAL_SHARES)
}

#[no_mangle]
pub extern "C" fn shares_of(user_id: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if user_id == 0 {
        return 0;
    }
    let u_slot = match user_slot(user_id) {
        Ok(s) => s,
        Err(rc) => return rc,
    };
    sload(u_slot)
}

/// Deposit liquidity: deposit(packed_arg) -> minted_shares
/// packed_arg: (user_id * 10,000,000,000) + (amount_a * 100,000) + amount_b
#[no_mangle]
pub extern "C" fn deposit(packed: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 || sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if packed <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let user_id = packed / 10_000_000_000;
    let rem1 = packed % 10_000_000_000;
    let amount_a = rem1 / 100_000;
    let amount_b = rem1 % 100_000;

    if user_id <= 0 || amount_a <= 0 || amount_b <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    // CT-P0: shares are minted to the authenticated caller only — a forged
    // user_id never matches the stranger's caller address.
    if !caller_is(user_id) {
        return ERR_UNAUTHORIZED;
    }

    let total_shares = sload(SLOT_TOTAL_SHARES);
    let res_a = sload(SLOT_RESERVE_A);
    let res_b = sload(SLOT_RESERVE_B);

    let minted_shares: i64 = if total_shares == 0 {
        // Initial deposit shares
        (amount_a + amount_b) / 2
    } else {
        if res_a <= 0 || res_b <= 0 {
            return ERR_INVALID_ARGUMENT;
        }
        let share_a = match i64::try_from((amount_a as u128) * (total_shares as u128) / (res_a as u128))
        {
            Ok(v) => v,
            Err(_) => return ERR_OVERFLOW,
        };
        let share_b = match i64::try_from((amount_b as u128) * (total_shares as u128) / (res_b as u128))
        {
            Ok(v) => v,
            Err(_) => return ERR_OVERFLOW,
        };
        if share_a < share_b {
            share_a
        } else {
            share_b
        }
    };

    if minted_shares <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    // Audit 6.0->8.0: checked reserve/share accounting — fail closed with
    // ERR_OVERFLOW instead of trapping on i64 overflow.
    let new_total = match total_shares.checked_add(minted_shares) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_res_a = match res_a.checked_add(amount_a) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_res_b = match res_b.checked_add(amount_b) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let u_slot = match user_slot(user_id) {
        Ok(s) => s,
        Err(rc) => return rc,
    };
    let current_shares = sload(u_slot);
    let new_user_shares = match current_shares.checked_add(minted_shares) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    sstore(SLOT_TOTAL_SHARES, new_total);
    sstore(SLOT_RESERVE_A, new_res_a);
    sstore(SLOT_RESERVE_B, new_res_b);
    sstore(u_slot, new_user_shares);

    emit(TOPIC_DEPOSIT, minted_shares);
    minted_shares
}

/// Withdraw liquidity: withdraw(packed_arg) -> payout_a
/// packed_arg: (user_id * 1,000,000) + shares_to_burn
#[no_mangle]
pub extern "C" fn withdraw(packed: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 || sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if packed <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let user_id = packed / 1_000_000;
    let shares = packed % 1_000_000;

    if user_id <= 0 || shares <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    // CT-P0: only the share owner (host.caller bound) may burn their shares.
    if !caller_is(user_id) {
        return ERR_UNAUTHORIZED;
    }

    let u_slot = match user_slot(user_id) {
        Ok(s) => s,
        Err(rc) => return rc,
    };
    let user_shares = sload(u_slot);
    if user_shares < shares {
        return ERR_INSUFFICIENT_BALANCE;
    }

    let total_shares = sload(SLOT_TOTAL_SHARES);
    if total_shares <= 0 {
        return ERR_OVERFLOW;
    }
    let res_a = sload(SLOT_RESERVE_A);
    let res_b = sload(SLOT_RESERVE_B);

    let payout_a =
        match i64::try_from(((shares as u128) * (res_a as u128)) / (total_shares as u128)) {
            Ok(v) => v,
            Err(_) => return ERR_OVERFLOW,
        };
    let payout_b =
        match i64::try_from(((shares as u128) * (res_b as u128)) / (total_shares as u128)) {
            Ok(v) => v,
            Err(_) => return ERR_OVERFLOW,
        };

    // P1: refuse dust redemptions that would burn shares for ~nothing (floor
    // legs paying 0 of a non-empty reserve). Same fail-closed convention as
    // `deposit` (zero-share mint) and the swap legs (zero-amount quote):
    // ERR_INVALID_ARGUMENT, shares and reserves untouched.
    if (res_a > 0 && payout_a == 0) || (res_b > 0 && payout_b == 0) {
        return ERR_INVALID_ARGUMENT;
    }

    // Audit 6.0->8.0: checked close-out — payouts are floored proportions so
    // `payout <= reserve` holds by construction; any violation (or a
    // corrupted total) fails closed instead of wrapping.
    let new_total = match total_shares.checked_sub(shares) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_res_a = match res_a.checked_sub(payout_a) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_res_b = match res_b.checked_sub(payout_b) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    sstore(u_slot, user_shares - shares);
    sstore(SLOT_TOTAL_SHARES, new_total);
    sstore(SLOT_RESERVE_A, new_res_a);
    sstore(SLOT_RESERVE_B, new_res_b);

    emit(TOPIC_WITHDRAW, payout_a);
    payout_a
}

#[inline(always)]
fn mul_u128_wide(a: u128, b: u128) -> (u128, u128) {
    let mask = u64::MAX as u128;
    let a_lo = a & mask;
    let a_hi = a >> 64;
    let b_lo = b & mask;
    let b_hi = b >> 64;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    let mid = (p0 >> 64) + (p1 & mask) + (p2 & mask);
    let lo = (p0 & mask) | (mid << 64);
    let hi = p3 + (p1 >> 64) + (p2 >> 64) + (mid >> 64);
    (hi, lo)
}

/// Exact `floor((a * b) / denom)` with full 256-bit intermediate product (`no_std`).
/// Returns `None` on division by zero or when the quotient overflows `u128`.
fn mul_div_u128(a: u128, b: u128, denom: u128) -> Option<u128> {
    if denom == 0 {
        return None;
    }
    let (hi, mut lo) = mul_u128_wide(a, b);
    if hi >= denom {
        return None;
    }
    if hi == 0 {
        return Some(lo / denom);
    }

    let mut rem = hi;
    let mut q = 0u128;
    for _ in 0..128 {
        let bit = lo >> 127;
        lo <<= 1;
        let carry = rem >> 127;
        let shifted = (rem << 1) | bit;
        q <<= 1;
        if carry != 0 || shifted >= denom {
            rem = shifted.wrapping_sub(denom);
            q |= 1;
        } else {
            rem = shifted;
        }
    }
    Some(q)
}

/// Exact integer square root `floor(sqrt(n))` for `u128` (`no_std`).
fn isqrt_u128(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let shift = (128 - n.leading_zeros()).div_ceil(2);
    let mut x = 1u128 << shift;
    let mut y = (x + n / x) >> 1;
    while y < x {
        x = y;
        y = (x + n / x) >> 1;
    }
    x
}

fn compute_swap_quote(reserve_in: i64, reserve_out: i64, amount_in: i64, fee_i64: i64) -> i64 {
    if amount_in <= 0 {
        return 0;
    }
    if reserve_in < 0 || reserve_out < 0 || !(0..10_000).contains(&fee_i64) {
        return ERR_INVALID_ARGUMENT;
    }
    let x = reserve_in as u128;
    let y = reserve_out as u128;
    let multiplier = (10_000 - fee_i64) as u128;
    let dx = amount_in as u128;

    let x_scaled = match x.checked_mul(10_000) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let dx_scaled = match dx.checked_mul(multiplier) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let denominator = match x_scaled.checked_add(dx_scaled) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    if denominator == 0 {
        return 0;
    }
    let Some(out) = mul_div_u128(y, dx_scaled, denominator) else {
        return ERR_OVERFLOW;
    };
    match i64::try_from(out) {
        Ok(v) => v,
        Err(_) => ERR_OVERFLOW,
    }
}

/// Calculate swap quote Token A -> Token B using exact 256-bit mul-div math
#[no_mangle]
pub extern "C" fn swap_quote(dx: i64) -> i64 {
    compute_swap_quote(
        sload(SLOT_RESERVE_A),
        sload(SLOT_RESERVE_B),
        dx,
        sload(SLOT_FEE_BPS),
    )
}

/// Calculate reverse swap quote Token B -> Token A using exact 256-bit mul-div math
#[no_mangle]
pub extern "C" fn swap_quote_b_for_a(dy: i64) -> i64 {
    compute_swap_quote(
        sload(SLOT_RESERVE_B),
        sload(SLOT_RESERVE_A),
        dy,
        sload(SLOT_FEE_BPS),
    )
}

/// Execute Swap Token A -> Token B: swap_a_for_b(dx) -> dy
#[no_mangle]
pub extern "C" fn swap_a_for_b(dx: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 || sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    let dy = swap_quote(dx);
    if dy == ERR_OVERFLOW {
        return ERR_OVERFLOW;
    }
    if dy <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let x = sload(SLOT_RESERVE_A);
    let y = sload(SLOT_RESERVE_B);

    // Audit 6.0->8.0: `dx` is an unbounded caller-supplied i64 — `x + dx`
    // must not wrap. `dy <= y` holds by quote construction; a violation fails
    // closed as invalid rather than wrapping the reserve.
    let new_x = match x.checked_add(dx) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_y = match y.checked_sub(dy) {
        Some(v) => v,
        None => return ERR_INVALID_ARGUMENT,
    };
    sstore(SLOT_RESERVE_A, new_x);
    sstore(SLOT_RESERVE_B, new_y);

    emit(TOPIC_SWAP_A_FOR_B, dy);
    dy
}

/// Execute Swap Token B -> Token A: swap_b_for_a(dy) -> dx
#[no_mangle]
pub extern "C" fn swap_b_for_a(dy: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 || sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    let dx = swap_quote_b_for_a(dy);
    if dx == ERR_OVERFLOW {
        return ERR_OVERFLOW;
    }
    if dx <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let x = sload(SLOT_RESERVE_A);
    let y = sload(SLOT_RESERVE_B);

    // Audit 6.0->8.0: same unbounded-input guard as the A->B leg.
    let new_y = match y.checked_add(dy) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_x = match x.checked_sub(dx) {
        Some(v) => v,
        None => return ERR_INVALID_ARGUMENT,
    };
    sstore(SLOT_RESERVE_B, new_y);
    sstore(SLOT_RESERVE_A, new_x);

    emit(TOPIC_SWAP_B_FOR_A, dx);
    dx
}

// ============================================================================
// Production 32-Byte Post-Quantum (Falcon-512) LP Entrypoints
// ============================================================================

#[inline(always)]
fn pq_user_slot(addr: &[u8; 32]) -> i64 {
    let mut preimage = [0u8; 48];
    preimage[..16].copy_from_slice(b"POOL_PQ_SHR_V1__");
    preimage[16..48].copy_from_slice(addr);
    let digest = blake3(&preimage);
    let raw = u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    (raw | (1u64 << 63)) as i64
}

#[inline(always)]
fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Initialize pool once in PQ mode with fee in basis points (e.g. 30 = 0.3%).
/// `calldata()`: `fee_bps (8B LE i64)`.
#[no_mangle]
pub extern "C" fn init_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 0 {
        return ERR_ALREADY_EXISTS;
    }
    if caller() == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 {
        return ERR_INVALID_ARGUMENT;
    }
    let fee_bps = i64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    if !(0..10_000).contains(&fee_bps) {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_PQ_MODE, 1);
    sstore(SLOT_TOTAL_SHARES, 0);
    sstore(SLOT_RESERVE_A, 0);
    sstore(SLOT_RESERVE_B, 0);
    sstore(SLOT_FEE_BPS, fee_bps);
    return_data(&fee_bps.to_le_bytes());
    SUCCESS
}

/// Query LP shares owned by a 32-byte PQ address.
/// `calldata()`: `owner (32B)`.
#[no_mangle]
pub extern "C" fn shares_of_pq(_arg: i64) -> i64 {
    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 32 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&buf[..32]);
    let shares = if addr == [0u8; 32] {
        0
    } else {
        sload(pq_user_slot(&addr))
    };
    return_data(&shares.to_le_bytes());
    shares
}

/// Deposit liquidity authenticated as 32-byte PQ `caller()`.
/// `calldata()`: `amount_a (8B LE u64) || amount_b (8B LE u64)`.
#[no_mangle]
pub extern "C" fn deposit_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 {
        return ERR_UNAUTHORIZED;
    }
    let lp = caller();
    if lp == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 16 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(amount_a) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    let Ok(amount_b) = i64::try_from(read_u64_le(&buf[8..16])) else {
        return ERR_OVERFLOW;
    };
    if amount_a <= 0 || amount_b <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let total_shares = sload(SLOT_TOTAL_SHARES);
    let res_a = sload(SLOT_RESERVE_A);
    let res_b = sload(SLOT_RESERVE_B);

    let minted_shares: i64 = if total_shares == 0 {
        let initial = isqrt_u128((amount_a as u128) * (amount_b as u128));
        match i64::try_from(initial) {
            Ok(v) => v,
            Err(_) => return ERR_OVERFLOW,
        }
    } else {
        if res_a <= 0 || res_b <= 0 {
            return ERR_INVALID_ARGUMENT;
        }
        let share_a_u128 = (amount_a as u128) * (total_shares as u128) / (res_a as u128);
        let share_b_u128 = (amount_b as u128) * (total_shares as u128) / (res_b as u128);
        let min_share = if share_a_u128 < share_b_u128 {
            share_a_u128
        } else {
            share_b_u128
        };
        match i64::try_from(min_share) {
            Ok(v) => v,
            Err(_) => return ERR_OVERFLOW,
        }
    };

    if minted_shares <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let new_total = match total_shares.checked_add(minted_shares) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_res_a = match res_a.checked_add(amount_a) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_res_b = match res_b.checked_add(amount_b) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let u_slot = pq_user_slot(&lp);
    let current_shares = sload(u_slot);
    let new_user_shares = match current_shares.checked_add(minted_shares) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    sstore(SLOT_TOTAL_SHARES, new_total);
    sstore(SLOT_RESERVE_A, new_res_a);
    sstore(SLOT_RESERVE_B, new_res_b);
    sstore(u_slot, new_user_shares);

    emit(TOPIC_DEPOSIT, minted_shares);
    return_data(&minted_shares.to_le_bytes());
    minted_shares
}

/// Withdraw liquidity authenticated as 32-byte PQ `caller()`.
/// `calldata()`: `shares (8B LE u64)`. Returns `payout_a` and writes
/// `payout_a (8B LE) || payout_b (8B LE)` to `return_data`.
#[no_mangle]
pub extern "C" fn withdraw_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 {
        return ERR_UNAUTHORIZED;
    }
    let lp = caller();
    if lp == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(shares) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if shares <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let u_slot = pq_user_slot(&lp);
    let user_shares = sload(u_slot);
    if user_shares < shares {
        return ERR_INSUFFICIENT_BALANCE;
    }

    let total_shares = sload(SLOT_TOTAL_SHARES);
    if total_shares <= 0 {
        return ERR_OVERFLOW;
    }
    let res_a = sload(SLOT_RESERVE_A);
    let res_b = sload(SLOT_RESERVE_B);

    let payout_a =
        match i64::try_from(((shares as u128) * (res_a as u128)) / (total_shares as u128)) {
            Ok(v) => v,
            Err(_) => return ERR_OVERFLOW,
        };
    let payout_b =
        match i64::try_from(((shares as u128) * (res_b as u128)) / (total_shares as u128)) {
            Ok(v) => v,
            Err(_) => return ERR_OVERFLOW,
        };

    if (res_a > 0 && payout_a == 0) || (res_b > 0 && payout_b == 0) {
        return ERR_INVALID_ARGUMENT;
    }

    let new_total = match total_shares.checked_sub(shares) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_res_a = match res_a.checked_sub(payout_a) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_res_b = match res_b.checked_sub(payout_b) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    sstore(u_slot, user_shares - shares);
    sstore(SLOT_TOTAL_SHARES, new_total);
    sstore(SLOT_RESERVE_A, new_res_a);
    sstore(SLOT_RESERVE_B, new_res_b);

    emit(TOPIC_WITHDRAW, payout_a);
    let mut ret = [0u8; 16];
    ret[..8].copy_from_slice(&payout_a.to_le_bytes());
    ret[8..16].copy_from_slice(&payout_b.to_le_bytes());
    return_data(&ret);
    payout_a
}

/// Execute Swap Token A -> Token B authenticated as 32-byte PQ `caller()` with slippage guard.
/// `calldata()`: `amount_in (8B LE i64) || min_out (8B LE i64)`.
#[no_mangle]
pub extern "C" fn swap_a_for_b_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 {
        return ERR_UNAUTHORIZED;
    }
    if caller() == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 16 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(amount_in) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    let Ok(min_out) = i64::try_from(read_u64_le(&buf[8..16])) else {
        return ERR_OVERFLOW;
    };
    if amount_in <= 0 || min_out < 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let dy = swap_quote(amount_in);
    if dy == ERR_OVERFLOW {
        return ERR_OVERFLOW;
    }
    if dy <= 0 || dy < min_out {
        return ERR_INVALID_ARGUMENT;
    }

    let x = sload(SLOT_RESERVE_A);
    let y = sload(SLOT_RESERVE_B);
    let new_x = match x.checked_add(amount_in) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_y = match y.checked_sub(dy) {
        Some(v) => v,
        None => return ERR_INVALID_ARGUMENT,
    };
    let k_before = (x as u128) * (y as u128);
    let k_after = (new_x as u128) * (new_y as u128);
    if k_after < k_before {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(SLOT_RESERVE_A, new_x);
    sstore(SLOT_RESERVE_B, new_y);

    emit(TOPIC_SWAP_A_FOR_B, dy);
    return_data(&dy.to_le_bytes());
    dy
}

/// Execute Swap Token B -> Token A authenticated as 32-byte PQ `caller()` with slippage guard.
/// `calldata()`: `amount_in (8B LE i64) || min_out (8B LE i64)`.
#[no_mangle]
pub extern "C" fn swap_b_for_a_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 {
        return ERR_UNAUTHORIZED;
    }
    if caller() == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 16 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(amount_in) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    let Ok(min_out) = i64::try_from(read_u64_le(&buf[8..16])) else {
        return ERR_OVERFLOW;
    };
    if amount_in <= 0 || min_out < 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let dx = swap_quote_b_for_a(amount_in);
    if dx == ERR_OVERFLOW {
        return ERR_OVERFLOW;
    }
    if dx <= 0 || dx < min_out {
        return ERR_INVALID_ARGUMENT;
    }

    let x = sload(SLOT_RESERVE_A);
    let y = sload(SLOT_RESERVE_B);
    let new_y = match y.checked_add(amount_in) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_x = match x.checked_sub(dx) {
        Some(v) => v,
        None => return ERR_INVALID_ARGUMENT,
    };
    let k_before = (x as u128) * (y as u128);
    let k_after = (new_x as u128) * (new_y as u128);
    if k_after < k_before {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(SLOT_RESERVE_B, new_y);
    sstore(SLOT_RESERVE_A, new_x);

    emit(TOPIC_SWAP_B_FOR_A, dx);
    return_data(&dx.to_le_bytes());
    dx
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum_contract_sdk::{
        get_mock_return_data, id_to_caller, reset_mock_state, set_mock_calldata, set_mock_caller,
    };

    #[test]
    fn test_amm_pool_lifecycle() {
        reset_mock_state();
        assert_eq!(init(30), 30); // 0.3% fee
        assert_eq!(init(30), ERR_ALREADY_EXISTS); // Double init rejected

        // Initial deposit from User 1: 10,000 Token A and 40,000 Token B
        // (authenticated as user 1).
        set_mock_caller(id_to_caller(1));
        let dep1 = 10_000_000_000 + 10_000 * 100_000 + 40_000;
        let minted1 = deposit(dep1);
        assert_eq!(minted1, 25_000); // (10_000 + 40_000) / 2
        assert_eq!(get_reserve_a(0), 10_000);
        assert_eq!(get_reserve_b(0), 40_000);
        assert_eq!(shares_of(1), 25_000);

        // Swap Quote A -> B for 1,000 Token A
        let quote_ab = swap_quote(1_000);
        assert_eq!(quote_ab, 3_626);
        let dy = swap_a_for_b(1_000);
        assert_eq!(dy, 3_626);
        assert_eq!(get_reserve_a(0), 11_000);
        assert_eq!(get_reserve_b(0), 40_000 - 3_626);
        // Constant-product invariant: the fee stays in the pool, so k grows.
        let k_after_ab = 11_000i64 * (40_000 - 3_626) as i64;
        assert_eq!(k_after_ab, 400_114_000);
        assert!(
            k_after_ab > 10_000i64 * 40_000,
            "k must grow by the fee leg"
        );

        // Swap B -> A (Reverse Swap): sell 3,000 Token B
        let quote_ba = swap_quote_b_for_a(3_000);
        assert_eq!(quote_ba, 835);
        let dx_back = swap_b_for_a(3_000);
        assert_eq!(dx_back, quote_ba);
        assert_eq!(get_reserve_a(0), 11_000 - 835);
        assert_eq!(get_reserve_b(0), (40_000 - 3_626) + 3_000);
        assert_eq!(get_total_shares(0), 25_000, "swaps must not mint shares");
        let k_after_ba = (11_000 - 835) as i64 * ((40_000 - 3_626) + 3_000) as i64;
        assert_eq!(k_after_ba, 400_236_710);
        assert!(
            k_after_ba > k_after_ab,
            "k must grow monotonically across fee swaps"
        );

        // Withdraw half shares
        let with_arg = 1_000_000 + 5_000;
        let payout_a = withdraw(with_arg);
        assert_eq!(payout_a, 2_033, "5k/25k of 10_165 reserve A");
        assert_eq!(shares_of(1), 20_000);
        assert_eq!(get_total_shares(0), 20_000, "burned shares leave supply");
        assert_eq!(get_reserve_a(0), 10_165 - 2_033);
        assert_eq!(get_reserve_b(0), 39_374 - 7_874);
    }

    #[test]
    fn test_pq_pool_deposit_withdraw_and_auth() {
        reset_mock_state();
        assert_eq!(init(30), 30);

        let lp1 = [0x11u8; 32];
        let attacker = [0x99u8; 32];

        // Zero caller refused
        let mut dep_data = [0u8; 16];
        dep_data[..8].copy_from_slice(&100_000u64.to_le_bytes());
        dep_data[8..16].copy_from_slice(&400_000u64.to_le_bytes());
        set_mock_calldata(&dep_data);
        assert_eq!(deposit_pq(0), ERR_UNAUTHORIZED);

        // LP1 deposits 100k A, 400k B -> isqrt(100k * 400k) = 200k shares
        set_mock_caller(lp1);
        set_mock_calldata(&dep_data);
        assert_eq!(deposit_pq(0), 200_000);
        set_mock_calldata(&lp1);
        assert_eq!(shares_of_pq(0), 200_000);
        assert_eq!(get_reserve_a(0), 100_000);
        assert_eq!(get_reserve_b(0), 400_000);

        // Attacker cannot withdraw LP1's shares
        set_mock_caller(attacker);
        set_mock_calldata(&50_000u64.to_le_bytes());
        assert_eq!(withdraw_pq(0), ERR_INSUFFICIENT_BALANCE);

        // LP1 withdraws 50_000 shares (25%) -> 25_000 A, 100_000 B
        set_mock_caller(lp1);
        set_mock_calldata(&50_000u64.to_le_bytes());
        assert_eq!(withdraw_pq(0), 25_000);
        let ret = get_mock_return_data();
        assert_eq!(ret.len(), 16);
        assert_eq!(read_u64_le(&ret[..8]), 25_000);
        assert_eq!(read_u64_le(&ret[8..16]), 100_000);

        set_mock_calldata(&lp1);
        assert_eq!(shares_of_pq(0), 150_000);
        assert_eq!(get_reserve_a(0), 75_000);
        assert_eq!(get_reserve_b(0), 300_000);
    }

    #[test]
    fn test_legacy_deposit_rejects_zero_reserve_and_share_overflow() {
        reset_mock_state();
        assert_eq!(init(30), 30);
        sstore(SLOT_TOTAL_SHARES, i64::MAX);
        sstore(SLOT_RESERVE_A, 0);
        sstore(SLOT_RESERVE_B, 100);
        set_mock_caller(id_to_caller(1));
        assert_eq!(deposit(1 * 10_000_000_000 + 10 * 100_000 + 10), ERR_INVALID_ARGUMENT);

        sstore(SLOT_RESERVE_A, 1);
        sstore(SLOT_RESERVE_B, 1);
        assert_eq!(deposit(1 * 10_000_000_000 + 10 * 100_000 + 10), ERR_OVERFLOW);
    }

    #[test]
    fn test_pq_init_locks_legacy_and_swaps_with_slippage() {
        reset_mock_state();
        let lp = [0x11u8; 32];
        let trader = [0x22u8; 32];

        // Zero caller refused on init_pq.
        set_mock_calldata(&30i64.to_le_bytes());
        assert_eq!(init_pq(0), ERR_UNAUTHORIZED);

        // Invalid fee_bps refused.
        set_mock_caller(lp);
        set_mock_calldata(&10_000i64.to_le_bytes());
        assert_eq!(init_pq(0), ERR_INVALID_ARGUMENT);
        set_mock_calldata(&(-1i64).to_le_bytes());
        assert_eq!(init_pq(0), ERR_INVALID_ARGUMENT);

        // Valid init_pq(30 bps).
        set_mock_calldata(&30i64.to_le_bytes());
        assert_eq!(init_pq(0), SUCCESS);
        assert_eq!(get_mock_return_data(), 30i64.to_le_bytes());
        assert_eq!(init_pq(0), ERR_ALREADY_EXISTS);

        // Legacy deposit / withdraw / shares_of / swaps refused in PQ mode.
        set_mock_caller(id_to_caller(1));
        assert_eq!(shares_of(1), ERR_UNAUTHORIZED);
        assert_eq!(
            deposit(10_000_000_000 + 10_000 * 100_000 + 40_000),
            ERR_UNAUTHORIZED
        );
        assert_eq!(withdraw(1_000_000 + 1_000), ERR_UNAUTHORIZED);
        assert_eq!(swap_a_for_b(1_000), ERR_UNAUTHORIZED);
        assert_eq!(swap_b_for_a(1_000), ERR_UNAUTHORIZED);

        // Deposit 10_000 A and 40_000 B -> isqrt(10_000 * 40_000) = 20_000 shares.
        set_mock_caller(lp);
        let mut dep_cd = [0u8; 16];
        dep_cd[..8].copy_from_slice(&10_000u64.to_le_bytes());
        dep_cd[8..16].copy_from_slice(&40_000u64.to_le_bytes());
        set_mock_calldata(&dep_cd);
        assert_eq!(deposit_pq(0), 20_000);

        // Legacy swaps remain locked out even with active reserves in PQ mode.
        assert_eq!(swap_a_for_b(1_000), ERR_UNAUTHORIZED);
        assert_eq!(swap_b_for_a(1_000), ERR_UNAUTHORIZED);
        assert_eq!(get_reserve_a(0), 10_000);
        assert_eq!(get_reserve_b(0), 40_000);

        // Slippage check: quote for 1_000 A is 3_626 B; min_out=3_627 must fail!
        set_mock_caller(trader);
        let mut swap_cd = [0u8; 16];
        swap_cd[..8].copy_from_slice(&1_000u64.to_le_bytes());
        swap_cd[8..16].copy_from_slice(&3_627u64.to_le_bytes());
        set_mock_calldata(&swap_cd);
        assert_eq!(swap_a_for_b_pq(0), ERR_INVALID_ARGUMENT);
        assert_eq!(get_reserve_a(0), 10_000);
        assert_eq!(get_reserve_b(0), 40_000);

        // Exact min_out=3_626 succeeds and grows k.
        swap_cd[8..16].copy_from_slice(&3_626u64.to_le_bytes());
        set_mock_calldata(&swap_cd);
        assert_eq!(swap_a_for_b_pq(0), 3_626);
        assert_eq!(get_mock_return_data(), 3_626i64.to_le_bytes());
        assert_eq!(get_reserve_a(0), 11_000);
        assert_eq!(get_reserve_b(0), 36_374);

        // Reverse swap B -> A: quote for 3_000 B is 835 A. min_out=836 fails; min_out=835 succeeds.
        let mut rev_cd = [0u8; 16];
        rev_cd[..8].copy_from_slice(&3_000u64.to_le_bytes());
        rev_cd[8..16].copy_from_slice(&836u64.to_le_bytes());
        set_mock_calldata(&rev_cd);
        assert_eq!(swap_b_for_a_pq(0), ERR_INVALID_ARGUMENT);

        rev_cd[8..16].copy_from_slice(&835u64.to_le_bytes());
        set_mock_calldata(&rev_cd);
        assert_eq!(swap_b_for_a_pq(0), 835);
        assert_eq!(get_mock_return_data(), 835i64.to_le_bytes());
        assert_eq!(get_reserve_a(0), 10_165);
        assert_eq!(get_reserve_b(0), 39_374);
    }

    #[test]
    fn test_user_slot_bounds_and_legacy_withdraw_guards() {
        reset_mock_state();
        assert_eq!(init(30), 30);

        // Negative or overflowing user_id in user_slot / shares_of returns ERR_INVALID_ARGUMENT.
        assert_eq!(user_slot(-1), Err(ERR_INVALID_ARGUMENT));
        assert_eq!(user_slot(i64::MAX), Err(ERR_INVALID_ARGUMENT));
        assert_eq!(shares_of(-1), ERR_INVALID_ARGUMENT);
        assert_eq!(shares_of(i64::MAX), ERR_INVALID_ARGUMENT);

        // Legacy withdraw rejects corrupted total_shares <= 0 without panicking/div-by-zero.
        set_mock_caller(id_to_caller(1));
        let u1_slot = user_slot(1).unwrap();
        sstore(u1_slot, 100);
        sstore(SLOT_TOTAL_SHARES, 0);
        assert_eq!(withdraw(1_000_000 + 10), ERR_OVERFLOW);
        assert_eq!(sload(u1_slot), 100);
    }

    #[test]
    fn test_swap_quote_high_reserves_no_overflow() {
        reset_mock_state();
        let lp = [0x11u8; 32];
        let trader = [0x22u8; 32];
        set_mock_caller(lp);
        set_mock_calldata(&30i64.to_le_bytes());
        assert_eq!(init_pq(0), SUCCESS);

        // 500M STELL reserves (1 STELL = 10^9 nano-STELL).
        let res_500m: i64 = 500_000_000 * 1_000_000_000;
        let dx_100m: i64 = 100_000_000 * 1_000_000_000;
        let expected_out: i64 = 83_124_895_781_223_945;

        let mut dep_cd = [0u8; 16];
        dep_cd[..8].copy_from_slice(&(res_500m as u64).to_le_bytes());
        dep_cd[8..16].copy_from_slice(&(res_500m as u64).to_le_bytes());
        set_mock_calldata(&dep_cd);
        assert_eq!(deposit_pq(0), res_500m);

        // Without 256-bit mul_div_u128, y * dx * 9970 = 4.985e38 > u128::MAX (~3.402e38).
        assert_eq!(swap_quote(dx_100m), expected_out);
        assert_eq!(swap_quote_b_for_a(dx_100m), expected_out);

        set_mock_caller(trader);
        let mut swap_cd = [0u8; 16];
        swap_cd[..8].copy_from_slice(&(dx_100m as u64).to_le_bytes());
        swap_cd[8..16].copy_from_slice(&(expected_out as u64).to_le_bytes());
        set_mock_calldata(&swap_cd);
        assert_eq!(swap_a_for_b_pq(0), expected_out);
        assert_eq!(get_reserve_a(0), res_500m + dx_100m);
        assert_eq!(get_reserve_b(0), res_500m - expected_out);
    }

    #[test]
    fn test_deposit_pq_isqrt_initial_shares_prevents_skew_and_math_helpers() {
        assert_eq!(isqrt_u128(0), 0);
        assert_eq!(isqrt_u128(1), 1);
        assert_eq!(isqrt_u128(2), 1);
        assert_eq!(isqrt_u128(3), 1);
        assert_eq!(isqrt_u128(4), 2);
        assert_eq!(isqrt_u128(15), 3);
        assert_eq!(isqrt_u128(16), 4);
        assert_eq!(isqrt_u128(u128::MAX), u64::MAX as u128);

        assert_eq!(
            mul_div_u128(u128::MAX, u128::MAX - 1, u128::MAX),
            Some(u128::MAX - 1)
        );
        assert_eq!(mul_div_u128(u128::MAX, 2, 1), None);
        assert_eq!(mul_div_u128(10, 20, 0), None);

        reset_mock_state();
        let lp1 = [0x11u8; 32];
        let lp2 = [0x22u8; 32];
        set_mock_caller(lp1);
        set_mock_calldata(&30i64.to_le_bytes());
        assert_eq!(init_pq(0), SUCCESS);

        // Asymmetric initial deposit (1_000, 1_000_000_000) mints geometric mean 1_000_000,
        // not arithmetic mean 500_000_500.
        let mut dep_cd = [0u8; 16];
        dep_cd[..8].copy_from_slice(&1_000u64.to_le_bytes());
        dep_cd[8..16].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        set_mock_calldata(&dep_cd);
        assert_eq!(deposit_pq(0), 1_000_000);

        // Matching proportional deposit mints exact same 1_000_000 shares.
        set_mock_caller(lp2);
        set_mock_calldata(&dep_cd);
        assert_eq!(deposit_pq(0), 1_000_000);
        assert_eq!(get_total_shares(0), 2_000_000);
    }
}
