//! STATUS: DEMO-GRADE, CT-P0 AUTHENTICATED (audit KI-38 fix). Every
//! value-moving entry point (`transfer`, `transfer_from`, `approve`, `mint`,
//! `burn`) binds the caller-supplied `from`/`owner`/`spender`/`admin_id` to the
//! authenticated `host.caller` via `caller_is` (canonical id encoding — a
//! stranger's address never matches the victim's id). Reads
//! (`balance_of`, `allowance`, metadata) stay public. Still DEMO-GRADE:
//! integer ids, no privacy, session/auction layers out of scope.
//! DO NOT deploy with value without a full audit.
//!
////! Hardened STS-20 Fungible Token Contract (Pure Rust)
//!
//! Features:
//! - Full STS-20 / ERC-20 feature parity: transfer, transfer_from, approve, allowance, mint, burn.
//! - Single-call initialization safeguard (re-init protected).
//! - Precision-safe 50 bps protocol fee with ceiling division (no zero-fee evasion).
//! - Direct, untaxed Black Hole burn to Account 0 with synchronized total supply.
//! - Standard metadata queries (decimals, symbol, name).

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use stellereum_contract_sdk::{
    caller_is, emit, setup_wasm_panic_handler, sload, sstore, ERR_INSUFFICIENT_BALANCE,
    ERR_INVALID_ARGUMENT, ERR_OVERFLOW, ERR_UNAUTHORIZED, SUCCESS,
};

setup_wasm_panic_handler!();

const SLOT_TOTAL_SUPPLY: i64 = 0;
const SLOT_INITIALIZED: i64 = 1;
const SLOT_ADMIN_ACCOUNT: i64 = 2;
const SLOT_TREASURY_ACCOUNT: i64 = 3;

const ADMIN_ACCOUNT_DEFAULT: i64 = 1;
const TREASURY_ACCOUNT_DEFAULT: i64 = 99;
const TAX_BPS: i64 = 50; // 0.5%
const BPS_DENOMINATOR: i64 = 10_000;

const BALANCE_OFFSET: i64 = 1_000_000;
const ALLOWANCE_OFFSET: i64 = 10_000_000;

// Event Topics
const TOPIC_TRANSFER: i64 = 2001;
const TOPIC_MINT: i64 = 2002;
const TOPIC_BURN: i64 = 2003;
const TOPIC_APPROVAL: i64 = 2004;

#[inline(always)]
fn balance_slot(account: i64) -> i64 {
    BALANCE_OFFSET + account
}

#[inline(always)]
fn allowance_slot(owner: i64, spender: i64) -> i64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    let o_bytes = owner.to_le_bytes();
    let s_bytes = spender.to_le_bytes();
    let mut i = 0;
    while i < 8 {
        hash ^= o_bytes[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        i += 1;
    }
    let mut j = 0;
    while j < 8 {
        hash ^= s_bytes[j] as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        j += 1;
    }
    ALLOWANCE_OFFSET + ((hash & 0x0FFFFFFF) as i64)
}

/// Initialize token contract once with initial supply minted to Admin
#[no_mangle]
pub extern "C" fn init(initial_supply: i64) -> i64 {
    if initial_supply <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    if sload(SLOT_INITIALIZED) != 0 {
        panic!("token already initialized");
    }

    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_ADMIN_ACCOUNT, ADMIN_ACCOUNT_DEFAULT);
    sstore(SLOT_TREASURY_ACCOUNT, TREASURY_ACCOUNT_DEFAULT);
    sstore(SLOT_TOTAL_SUPPLY, initial_supply);

    let admin_slot = balance_slot(ADMIN_ACCOUNT_DEFAULT);
    sstore(admin_slot, initial_supply);

    emit(TOPIC_MINT, initial_supply);
    SUCCESS
}

/// Query decimals (standard 9 decimals, nano-STELL)
#[no_mangle]
pub extern "C" fn decimals(_arg: i64) -> i64 {
    9
}

/// Query total circulating supply
#[no_mangle]
pub extern "C" fn total_supply(_arg: i64) -> i64 {
    sload(SLOT_TOTAL_SUPPLY)
}

/// Query account balance
#[no_mangle]
pub extern "C" fn balance_of(account: i64) -> i64 {
    if account <= 0 {
        return 0;
    }
    sload(balance_slot(account))
}

/// Query allowance: packed_arg: owner_id * 1_000_000 + spender_id
#[no_mangle]
pub extern "C" fn allowance(packed_arg: i64) -> i64 {
    let owner = packed_arg / 1_000_000;
    let spender = packed_arg % 1_000_000;
    if owner <= 0 || spender <= 0 {
        return 0;
    }
    sload(allowance_slot(owner, spender))
}

/// Approve spender: packed_arg: owner_id * 10_000_000_000 + spender_id * 100_000 + amount
#[no_mangle]
pub extern "C" fn approve(packed_arg: i64) -> i64 {
    let owner = packed_arg / 10_000_000_000;
    let rem1 = packed_arg % 10_000_000_000;
    let spender = rem1 / 100_000;
    let amount = rem1 % 100_000;

    if owner <= 0 || spender <= 0 || amount < 0 {
        return ERR_INVALID_ARGUMENT;
    }
    // CT-P0: only the owner (authenticated via host.caller) may grant an
    // allowance on their funds. A forged owner id never matches the stranger's
    // caller address.
    if !caller_is(owner) {
        return ERR_UNAUTHORIZED;
    }

    sstore(allowance_slot(owner, spender), amount);
    emit(TOPIC_APPROVAL, amount);
    1
}

/// Direct Transfer tokens with 50 bps protocol fee
/// packed_arg: from_id * 100_000_000 + to_id * 100_000 + amount
#[no_mangle]
pub extern "C" fn transfer(packed_arg: i64) -> i64 {
    if packed_arg <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let from = packed_arg / 100_000_000;
    let rem1 = packed_arg % 100_000_000;
    let to = rem1 / 100_000;
    let amount = rem1 % 100_000;

    if from <= 0 || !(0..1_000).contains(&to) || amount <= 0 || amount >= 100_000 {
        panic!("invalid transfer bounds");
    }
    // CT-P0: `from` is authenticated — only the owner (host.caller bound to
    // the canonical address of `from`) may move their own tokens. Strangers
    // get ERR_UNAUTHORIZED and balances are untouched.
    if !caller_is(from) {
        return ERR_UNAUTHORIZED;
    }

    execute_transfer(from, to, amount)
}

/// Transfer From (delegated transfer using allowance)
/// packed_arg: spender_id * 100_000_000_000 + from_id * 10_000_000 + to_id * 100_000 + amount
#[no_mangle]
pub extern "C" fn transfer_from(packed_arg: i64) -> i64 {
    if packed_arg <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let spender = packed_arg / 100_000_000_000;
    let rem1 = packed_arg % 100_000_000_000;
    let from = rem1 / 10_000_000;
    let rem2 = rem1 % 10_000_000;
    let to = rem2 / 100_000;
    let amount = rem2 % 100_000;

    // Audit 6.0->8.0: validate the value-moving fields BEFORE touching the
    // allowance. Previously a bad `from`/`to`/`amount` burned the grant via
    // `sstore` and then failed inside `execute_transfer`. Bounds mirror
    // `transfer` (wire format unchanged).
    if from <= 0 || !(0..1_000).contains(&to) || amount <= 0 || amount >= 100_000 {
        return ERR_INVALID_ARGUMENT;
    }
    // CT-P0: the spender is authenticated — a forged spender id never matches
    // the stranger's caller address. Allowance check below stays as the
    // capability leg (existing pattern).
    if !caller_is(spender) {
        return ERR_UNAUTHORIZED;
    }
    let a_slot = allowance_slot(from, spender);
    let allowed = sload(a_slot);
    if allowed < amount {
        return ERR_UNAUTHORIZED;
    }

    sstore(a_slot, allowed - amount);
    execute_transfer(from, to, amount)
}

fn execute_transfer(from: i64, to: i64, amount: i64) -> i64 {
    if from <= 0 || amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let from_slot = balance_slot(from);
    let from_bal = sload(from_slot);
    if from_bal < amount {
        return ERR_INSUFFICIENT_BALANCE;
    }

    // Direct burn to Black Hole (Account 0): exempt from tax to burn 100% cleanly
    if to == 0 {
        sstore(from_slot, from_bal - amount);
        let supply = sload(SLOT_TOTAL_SUPPLY);
        sstore(SLOT_TOTAL_SUPPLY, supply.saturating_sub(amount));
        emit(TOPIC_BURN, amount);
        return 1;
    }

    // Ceiling division fee calculation: prevents 0-fee evasion on small amounts
    let fee = (amount * TAX_BPS + BPS_DENOMINATOR - 1) / BPS_DENOMINATOR;
    let net = amount - fee;

    // Audit 6.0->8.0 (CT-P1 dust): a transfer whose fee consumes the whole
    // amount (e.g. amount=1 -> fee=1, net=0) credits nothing to the recipient
    // while debiting the sender. Refuse fail-closed, funds untouched.
    if net <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(from_slot, from_bal - amount);

    let to_slot = balance_slot(to);
    let to_bal = sload(to_slot);
    let new_to_bal = match to_bal.checked_add(net) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    sstore(to_slot, new_to_bal);

    if fee > 0 {
        let treasury = sload(SLOT_TREASURY_ACCOUNT);
        let treasury_slot = balance_slot(treasury);
        let treasury_bal = sload(treasury_slot);
        let new_treasury_bal = match treasury_bal.checked_add(fee) {
            Some(v) => v,
            None => return ERR_OVERFLOW,
        };
        sstore(treasury_slot, new_treasury_bal);
    }

    emit(TOPIC_TRANSFER, amount);
    1
}

/// Mint new tokens to Admin account: supports raw amount or packed (admin_id * 10_000_000_000 + amount)
#[no_mangle]
pub extern "C" fn mint(arg: i64) -> i64 {
    let (admin_id, amount) = if arg >= 10_000_000_000 {
        (arg / 10_000_000_000, arg % 10_000_000_000)
    } else {
        (sload(SLOT_ADMIN_ACCOUNT), arg)
    };
    if amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let admin = sload(SLOT_ADMIN_ACCOUNT);
    if admin_id != admin {
        return ERR_UNAUTHORIZED;
    }
    // CT-P0: forged admin_id (public) is worthless without the admin's caller
    // address. Refusal is a return code (not a trap) so callers can branch.
    if !caller_is(admin) {
        return ERR_UNAUTHORIZED;
    }

    let supply = sload(SLOT_TOTAL_SUPPLY);
    // Audit 6.0->8.0: fail closed with ERR_OVERFLOW instead of trapping on
    // i64 overflow (release profile has overflow-checks=true, so raw `+`
    // would trap the tx; an explicit error lets callers branch).
    let new_supply = match supply.checked_add(amount) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    sstore(SLOT_TOTAL_SUPPLY, new_supply);

    let admin_slot = balance_slot(admin);
    let bal = sload(admin_slot);
    let new_bal = match bal.checked_add(amount) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    sstore(admin_slot, new_bal);

    emit(TOPIC_MINT, amount);
    new_bal
}

/// Burn tokens from Admin account
#[no_mangle]
pub extern "C" fn burn(arg: i64) -> i64 {
    let (admin_id, amount) = if arg >= 10_000_000_000 {
        (arg / 10_000_000_000, arg % 10_000_000_000)
    } else {
        (sload(SLOT_ADMIN_ACCOUNT), arg)
    };
    if amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let admin = sload(SLOT_ADMIN_ACCOUNT);
    if admin_id != admin {
        return ERR_UNAUTHORIZED;
    }
    // CT-P0: see mint — forged admin_id without the admin caller is refused
    // with a return code (poc_p0_forged_burn asserts rc < 0, not a trap).
    if !caller_is(admin) {
        return ERR_UNAUTHORIZED;
    }

    let admin_slot = balance_slot(admin);
    let bal = sload(admin_slot);
    if bal < amount {
        return ERR_INSUFFICIENT_BALANCE;
    }

    sstore(admin_slot, bal - amount);
    let supply = sload(SLOT_TOTAL_SUPPLY);
    sstore(SLOT_TOTAL_SUPPLY, supply.saturating_sub(amount));

    emit(TOPIC_BURN, amount);
    bal - amount
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller};

    #[test]
    fn test_token_lifecycle() {
        reset_mock_state();
        assert_eq!(init(1_000_000), SUCCESS);
        assert_eq!(total_supply(0), 1_000_000);
        assert_eq!(balance_of(1), 1_000_000);
        assert_eq!(decimals(0), 9);

        // Transfer 10,000 from 1 to 2 (authenticated as owner 1).
        set_mock_caller(id_to_caller(1));
        let packed = 100_000_000 + 2 * 100_000 + 10_000;
        assert_eq!(transfer(packed), 1);

        // 0.5% of 10,000 is 50
        assert_eq!(balance_of(2), 9_950);
        assert_eq!(balance_of(99), 50);
        assert_eq!(balance_of(1), 990_000);

        // Burn 40,000 (authenticated as admin 1)
        assert_eq!(burn(40_000), 950_000);
        assert_eq!(total_supply(0), 960_000);

        // Mint 50,000 (authenticated as admin 1)
        assert_eq!(mint(50_000), 1_000_000);
        assert_eq!(total_supply(0), 1_010_000);

        // Test Allowances: User 1 approves User 5 for 2,000 tokens
        let approve_packed = 10_000_000_000 + 5 * 100_000 + 2_000;
        assert_eq!(approve(approve_packed), 1);
        assert_eq!(allowance(1_000_000 + 5), 2_000);

        // User 5 executes transfer_from 1 to 3 for 1,000 tokens
        // (authenticated as spender 5).
        set_mock_caller(id_to_caller(5));
        let tf_packed = 5 * 100_000_000_000 + 10_000_000 + 3 * 100_000 + 1_000;
        assert_eq!(transfer_from(tf_packed), 1);
        assert_eq!(allowance(1_000_000 + 5), 1_000);
        assert_eq!(balance_of(3), 995); // 1000 - 5 fee
    }
}
