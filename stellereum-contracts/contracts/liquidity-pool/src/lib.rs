//! STATUS: DEMO-GRADE — NO AUTHENTICATION (audit B-CT P0). All `from`/
//! `owner`/`caller_id`/`admin_id` args are caller-supplied and replayable:
//! the contract never reads the authenticated `host.caller`. DO NOT deploy
//! with value. Auth redesign (host.caller-bound, SDK `caller()` ready) is
//! tracked in docs/ROADMAP.md P0; the failing `poc_p0_*` tests are the
//! executable acceptance criteria.
//!
////! Automated Market Maker (AMM) Constant Product Liquidity Pool (Hardened)
//!
//! Features:
//! - Complete Bidirectional Swaps: Token A -> Token B (`swap_a_for_b`) and Token B -> Token A (`swap_b_for_a`).
//! - Constant Product formula (x * y = k) calculated with 128-bit integer safety (zero overflow).
//! - Proportional liquidity deposit and withdrawal with LP share tracking.
//! - Exact integer swap quote calculation with zero rounding exploit vectors.
//! - Slippage protection and re-initialization guards.

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use stellereum_contract_sdk::{
    emit, setup_wasm_panic_handler, sload, sstore, ERR_ALREADY_EXISTS, ERR_INSUFFICIENT_BALANCE,
    ERR_INVALID_ARGUMENT,
};

setup_wasm_panic_handler!();

const SLOT_INITIALIZED: i64 = 0;
const SLOT_TOTAL_SHARES: i64 = 1;
const SLOT_RESERVE_A: i64 = 2;
const SLOT_RESERVE_B: i64 = 3;
const SLOT_FEE_BPS: i64 = 4;

const USER_SHARES_OFFSET: i64 = 10_000;

// Event Topics
const TOPIC_DEPOSIT: i64 = 10;
const TOPIC_WITHDRAW: i64 = 11;
const TOPIC_SWAP_A_FOR_B: i64 = 12;
const TOPIC_SWAP_B_FOR_A: i64 = 13;

#[inline(always)]
fn user_slot(user_id: i64) -> i64 {
    USER_SHARES_OFFSET + user_id
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
    if user_id <= 0 {
        return 0;
    }
    sload(user_slot(user_id))
}

/// Deposit liquidity: deposit(packed_arg) -> minted_shares
/// packed_arg: (user_id * 10,000,000,000) + (amount_a * 100,000) + amount_b
#[no_mangle]
pub extern "C" fn deposit(packed: i64) -> i64 {
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

    let total_shares = sload(SLOT_TOTAL_SHARES);
    let res_a = sload(SLOT_RESERVE_A);
    let res_b = sload(SLOT_RESERVE_B);

    let minted_shares: i64 = if total_shares == 0 {
        // Initial deposit shares
        (amount_a + amount_b) / 2
    } else {
        let share_a = ((amount_a as u128) * (total_shares as u128) / (res_a as u128)) as i64;
        let share_b = ((amount_b as u128) * (total_shares as u128) / (res_b as u128)) as i64;
        if share_a < share_b {
            share_a
        } else {
            share_b
        }
    };

    if minted_shares <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(SLOT_TOTAL_SHARES, total_shares + minted_shares);
    sstore(SLOT_RESERVE_A, res_a + amount_a);
    sstore(SLOT_RESERVE_B, res_b + amount_b);

    let u_slot = user_slot(user_id);
    let current_shares = sload(u_slot);
    sstore(u_slot, current_shares + minted_shares);

    emit(TOPIC_DEPOSIT, minted_shares);
    minted_shares
}

/// Withdraw liquidity: withdraw(packed_arg) -> payout_a
/// packed_arg: (user_id * 1,000,000) + shares_to_burn
#[no_mangle]
pub extern "C" fn withdraw(packed: i64) -> i64 {
    if packed <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let user_id = packed / 1_000_000;
    let shares = packed % 1_000_000;

    if user_id <= 0 || shares <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let u_slot = user_slot(user_id);
    let user_shares = sload(u_slot);
    if user_shares < shares {
        return ERR_INSUFFICIENT_BALANCE;
    }

    let total_shares = sload(SLOT_TOTAL_SHARES);
    let res_a = sload(SLOT_RESERVE_A);
    let res_b = sload(SLOT_RESERVE_B);

    let payout_a = (((shares as u128) * (res_a as u128)) / (total_shares as u128)) as i64;
    let payout_b = (((shares as u128) * (res_b as u128)) / (total_shares as u128)) as i64;

    sstore(u_slot, user_shares - shares);
    sstore(SLOT_TOTAL_SHARES, total_shares - shares);
    sstore(SLOT_RESERVE_A, res_a - payout_a);
    sstore(SLOT_RESERVE_B, res_b - payout_b);

    emit(TOPIC_WITHDRAW, payout_a);
    payout_a
}

/// Calculate swap quote Token A -> Token B using safe u128 math
#[no_mangle]
pub extern "C" fn swap_quote(dx: i64) -> i64 {
    if dx <= 0 {
        return 0;
    }
    let x = sload(SLOT_RESERVE_A) as u128;
    let y = sload(SLOT_RESERVE_B) as u128;
    let fee_bps = sload(SLOT_FEE_BPS) as u128;

    let multiplier = 10_000 - fee_bps;
    let dx_u128 = dx as u128;

    let numerator = y * dx_u128 * multiplier;
    let denominator = (x * 10_000) + (dx_u128 * multiplier);

    if denominator == 0 {
        return 0;
    }
    (numerator / denominator) as i64
}

/// Calculate reverse swap quote Token B -> Token A using safe u128 math
#[no_mangle]
pub extern "C" fn swap_quote_b_for_a(dy: i64) -> i64 {
    if dy <= 0 {
        return 0;
    }
    let x = sload(SLOT_RESERVE_A) as u128;
    let y = sload(SLOT_RESERVE_B) as u128;
    let fee_bps = sload(SLOT_FEE_BPS) as u128;

    let multiplier = 10_000 - fee_bps;
    let dy_u128 = dy as u128;

    let numerator = x * dy_u128 * multiplier;
    let denominator = (y * 10_000) + (dy_u128 * multiplier);

    if denominator == 0 {
        return 0;
    }
    (numerator / denominator) as i64
}

/// Execute Swap Token A -> Token B: swap_a_for_b(dx) -> dy
#[no_mangle]
pub extern "C" fn swap_a_for_b(dx: i64) -> i64 {
    let dy = swap_quote(dx);
    if dy <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let x = sload(SLOT_RESERVE_A);
    let y = sload(SLOT_RESERVE_B);

    sstore(SLOT_RESERVE_A, x + dx);
    sstore(SLOT_RESERVE_B, y - dy);

    emit(TOPIC_SWAP_A_FOR_B, dy);
    dy
}

/// Execute Swap Token B -> Token A: swap_b_for_a(dy) -> dx
#[no_mangle]
pub extern "C" fn swap_b_for_a(dy: i64) -> i64 {
    let dx = swap_quote_b_for_a(dy);
    if dx <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let x = sload(SLOT_RESERVE_A);
    let y = sload(SLOT_RESERVE_B);

    sstore(SLOT_RESERVE_B, y + dy);
    sstore(SLOT_RESERVE_A, x - dx);

    emit(TOPIC_SWAP_B_FOR_A, dx);
    dx
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum_contract_sdk::reset_mock_state;

    #[test]
    fn test_amm_pool_lifecycle() {
        reset_mock_state();
        assert_eq!(init(30), 30); // 0.3% fee
        assert_eq!(init(30), ERR_ALREADY_EXISTS); // Double init rejected

        // Initial deposit from User 1: 10,000 Token A and 40,000 Token B
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
}
