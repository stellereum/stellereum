//! STATUS:
//! - Legacy packed-`i64` entrypoints (`init`, `transfer`, `transfer_from`,
//!   `approve`, `mint`, `burn`, `balance_of`, `allowance`): DEMO-GRADE
//!   compatibility shims (`caller_is` binds integer ids to canonical
//!   zero-padded `host.caller` addresses; integer ids only, kept for backwards
//!   compatibility with legacy tests).
//! - PQ entrypoints (`init_pq`, `balance_of_pq`, `allowance_pq`, `transfer_pq`,
//!   `approve_pq`, `transfer_from_pq`, `mint_pq`, `burn_pq`): authenticate full
//!   32-byte post-quantum `host.caller` addresses via `caller()` + `calldata()`
//!   with deterministic `blake3`-keyed storage slots.
//! DO NOT deploy with value without a full audit.
//!
//! Hardened STS-20 Fungible Token Contract (Pure Rust)
//!
//! Features:
//! - Full STS-20 / ERC-20 feature parity: transfer, transfer_from, approve, allowance, mint, burn.
//! - Full 32-byte Falcon-512 PQ wallet authentication (`*_pq` entrypoints).
//! - Single-call initialization safeguard (re-init protected).
//! - Precision-safe 50 bps protocol fee with ceiling division (no zero-fee evasion).
//! - Direct, untaxed Black Hole burn to `[0u8; 32]` / Account 0 with synchronized total supply.
//! - Standard metadata queries (decimals, symbol, name).

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

const SLOT_TOTAL_SUPPLY: i64 = 0;
const SLOT_INITIALIZED: i64 = 1;
const SLOT_ADMIN_ACCOUNT: i64 = 2;
const SLOT_TREASURY_ACCOUNT: i64 = 3;
const SLOT_PQ_MODE: i64 = 4;

const ADMIN_ACCOUNT_DEFAULT: i64 = 1;
const TREASURY_ACCOUNT_DEFAULT: i64 = 99;
const TAX_BPS: i64 = 50; // 0.5%
const BPS_DENOMINATOR: i64 = 10_000;

const BALANCE_OFFSET: i64 = 1_000_000;
const MAX_ACCOUNT_ID: i64 = 1_000_000_000_000;
const ALLOWANCE_OFFSET: i64 = 1i64 << 60;

// Event Topics
const TOPIC_TRANSFER: i64 = 2001;
const TOPIC_MINT: i64 = 2002;
const TOPIC_BURN: i64 = 2003;
const TOPIC_APPROVAL: i64 = 2004;

#[inline(always)]
fn balance_slot(account: i64) -> i64 {
    BALANCE_OFFSET
        .checked_add(account)
        .expect("balance slot overflow")
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
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if account <= 0 || account >= MAX_ACCOUNT_ID {
        return 0;
    }
    sload(balance_slot(account))
}

/// Query allowance: packed_arg: owner_id * 1_000_000 + spender_id
#[no_mangle]
pub extern "C" fn allowance(packed_arg: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if packed_arg <= 0 {
        return 0;
    }
    let owner = packed_arg / 1_000_000;
    let spender = packed_arg % 1_000_000;
    if owner <= 0 || owner >= MAX_ACCOUNT_ID || spender <= 0 {
        return 0;
    }
    sload(allowance_slot(owner, spender))
}

/// Approve spender: packed_arg: owner_id * 10_000_000_000 + spender_id * 100_000 + amount
#[no_mangle]
pub extern "C" fn approve(packed_arg: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if packed_arg <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let owner = packed_arg / 10_000_000_000;
    let rem1 = packed_arg % 10_000_000_000;
    let spender = rem1 / 100_000;
    let amount = rem1 % 100_000;

    if owner <= 0 || owner >= MAX_ACCOUNT_ID || spender <= 0 || amount < 0 {
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
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
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
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
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

    // R2-X: never consume the grant for a transfer that FAILED. `execute_transfer`
    // can still refuse after this point (owner balance below `amount`, fee
    // dust with net == 0, or an overflowing credit) and host writes are
    // immediate — debiting first burned the owner's allowance while moving
    // nothing. Spend it only when the transfer actually applies.
    let rc = execute_transfer(from, to, amount);
    if rc == 1 {
        sstore(a_slot, allowed - amount);
    }
    rc
}

fn execute_transfer(from: i64, to: i64, amount: i64) -> i64 {
    if from <= 0 || from >= MAX_ACCOUNT_ID || !(0..MAX_ACCOUNT_ID).contains(&to) || amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let from_slot = balance_slot(from);
    let from_bal = sload(from_slot);
    if from_bal < amount {
        return ERR_INSUFFICIENT_BALANCE;
    }

    // Direct burn to Black Hole (Account 0): exempt from tax to burn 100% cleanly
    if to == 0 {
        let supply = sload(SLOT_TOTAL_SUPPLY);
        let new_supply = match supply.checked_sub(amount).filter(|&v| v >= 0) {
            Some(v) => v,
            None => return ERR_OVERFLOW,
        };
        sstore(from_slot, from_bal - amount);
        sstore(SLOT_TOTAL_SUPPLY, new_supply);
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

    let new_from_bal = from_bal - amount;

    let to_slot = balance_slot(to);
    let to_bal = if to_slot == from_slot {
        new_from_bal
    } else {
        sload(to_slot)
    };
    let new_to_bal = match to_bal.checked_add(net) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    let treasury_update = if fee > 0 {
        let treasury = sload(SLOT_TREASURY_ACCOUNT);
        let treasury_slot = balance_slot(treasury);
        let treasury_bal = if treasury_slot == to_slot {
            new_to_bal
        } else if treasury_slot == from_slot {
            new_from_bal
        } else {
            sload(treasury_slot)
        };
        let new_treasury_bal = match treasury_bal.checked_add(fee) {
            Some(v) => v,
            None => return ERR_OVERFLOW,
        };
        Some((treasury_slot, new_treasury_bal))
    } else {
        None
    };

    sstore(from_slot, new_from_bal);
    sstore(to_slot, new_to_bal);
    if let Some((treasury_slot, new_treasury_bal)) = treasury_update {
        sstore(treasury_slot, new_treasury_bal);
    }

    emit(TOPIC_TRANSFER, amount);
    1
}

/// Mint new tokens to Admin account: supports raw amount or packed (admin_id * 10_000_000_000 + amount)
#[no_mangle]
pub extern "C" fn mint(arg: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
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
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
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

    let supply = sload(SLOT_TOTAL_SUPPLY);
    let new_supply = match supply.checked_sub(amount).filter(|&v| v >= 0) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    sstore(admin_slot, bal - amount);
    sstore(SLOT_TOTAL_SUPPLY, new_supply);

    emit(TOPIC_BURN, amount);
    bal - amount
}

// ============================================================================
// Production 32-Byte Post-Quantum (Falcon-512) Address Entrypoints
// ============================================================================

#[inline(always)]
fn pq_slot_from_digest(digest: [u8; 32]) -> i64 {
    let raw = u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    // Force bit 63 = 1 so every PQ slot is strictly negative (< 0) and can
    // never collide with non-negative legacy integer-id slots.
    (raw | (1u64 << 63)) as i64
}

#[inline(always)]
fn pq_balance_slot(addr: &[u8; 32]) -> i64 {
    let mut preimage = [0u8; 48];
    preimage[..16].copy_from_slice(b"STS20_PQ_BAL_V1_");
    preimage[16..48].copy_from_slice(addr);
    pq_slot_from_digest(blake3(&preimage))
}

#[inline(always)]
fn pq_allowance_slot(owner: &[u8; 32], spender: &[u8; 32]) -> i64 {
    let mut preimage = [0u8; 80];
    preimage[..16].copy_from_slice(b"STS20_PQ_ALW_V1_");
    preimage[16..48].copy_from_slice(owner);
    preimage[48..80].copy_from_slice(spender);
    pq_slot_from_digest(blake3(&preimage))
}

#[inline(always)]
fn pq_meta_slot(tag: &[u8; 8], limb: u8) -> i64 {
    let mut preimage = [0u8; 25];
    preimage[..16].copy_from_slice(b"STS20_PQ_MET_V1_");
    preimage[16..24].copy_from_slice(tag);
    preimage[24] = limb;
    pq_slot_from_digest(blake3(&preimage))
}

fn store_addr32(tag: &[u8; 8], addr: &[u8; 32]) {
    let mut limb = 0usize;
    while limb < 4 {
        let start = limb * 8;
        let word = i64::from_le_bytes([
            addr[start],
            addr[start + 1],
            addr[start + 2],
            addr[start + 3],
            addr[start + 4],
            addr[start + 5],
            addr[start + 6],
            addr[start + 7],
        ]);
        sstore(pq_meta_slot(tag, limb as u8), word);
        limb += 1;
    }
}

fn load_addr32(tag: &[u8; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut limb = 0usize;
    while limb < 4 {
        let word = sload(pq_meta_slot(tag, limb as u8));
        let bytes = word.to_le_bytes();
        let start = limb * 8;
        out[start..start + 8].copy_from_slice(&bytes);
        limb += 1;
    }
    out
}

#[inline(always)]
fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Initialize token contract once with 32-byte PQ `caller()` as admin and treasury.
/// `calldata()`: `initial_supply (8B LE u64)`.
#[no_mangle]
pub extern "C" fn init_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 0 {
        return ERR_ALREADY_EXISTS;
    }
    let admin = caller();
    if admin == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(initial_supply) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if initial_supply <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_PQ_MODE, 1);
    sstore(SLOT_TOTAL_SUPPLY, initial_supply);
    store_addr32(b"ADMIN___", &admin);
    store_addr32(b"TREASURY", &admin);
    sstore(pq_balance_slot(&admin), initial_supply);

    emit(TOPIC_MINT, initial_supply);
    return_data(&initial_supply.to_le_bytes());
    SUCCESS
}

/// Query balance of a 32-byte PQ address.
/// `calldata()`: `account (32B)`.
#[no_mangle]
pub extern "C" fn balance_of_pq(_arg: i64) -> i64 {
    if sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 32 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&buf[..32]);
    let bal = if addr == [0u8; 32] {
        0
    } else {
        sload(pq_balance_slot(&addr))
    };
    return_data(&bal.to_le_bytes());
    bal
}

/// Query allowance for `(owner, spender)` 32-byte PQ addresses.
/// `calldata()`: `owner (32B) || spender (32B)`.
#[no_mangle]
pub extern "C" fn allowance_pq(_arg: i64) -> i64 {
    if sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let mut buf = [0u8; 96];
    let n = calldata(&mut buf);
    if n != 64 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut owner = [0u8; 32];
    let mut spender = [0u8; 32];
    owner.copy_from_slice(&buf[..32]);
    spender.copy_from_slice(&buf[32..64]);
    let allowed = if owner == [0u8; 32] || spender == [0u8; 32] {
        0
    } else {
        sload(pq_allowance_slot(&owner, &spender))
    };
    return_data(&allowed.to_le_bytes());
    allowed
}

/// Approve 32-byte `spender` to spend `amount` from authenticated 32-byte `caller()`.
/// `calldata()`: `spender (32B) || amount (8B LE u64)`.
#[no_mangle]
pub extern "C" fn approve_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let owner = caller();
    if owner == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 40 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut spender = [0u8; 32];
    spender.copy_from_slice(&buf[..32]);
    if spender == [0u8; 32] {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(amount) = i64::try_from(read_u64_le(&buf[32..40])) else {
        return ERR_OVERFLOW;
    };

    sstore(pq_allowance_slot(&owner, &spender), amount);
    emit(TOPIC_APPROVAL, amount);
    return_data(&amount.to_le_bytes());
    SUCCESS
}

/// Direct transfer from authenticated 32-byte `caller()` with 50 bps protocol fee.
/// `calldata()`: `to (32B) || amount (8B LE u64)`.
#[no_mangle]
pub extern "C" fn transfer_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let from = caller();
    if from == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 40 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut to = [0u8; 32];
    to.copy_from_slice(&buf[..32]);
    let Ok(amount) = i64::try_from(read_u64_le(&buf[32..40])) else {
        return ERR_OVERFLOW;
    };

    execute_transfer_pq(&from, &to, amount)
}

/// Delegated transfer by authenticated 32-byte `caller()` spender using PQ allowance.
/// `calldata()`: `from (32B) || to (32B) || amount (8B LE u64)`.
#[no_mangle]
pub extern "C" fn transfer_from_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let spender = caller();
    if spender == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 96];
    let n = calldata(&mut buf);
    if n != 72 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut from = [0u8; 32];
    let mut to = [0u8; 32];
    from.copy_from_slice(&buf[..32]);
    to.copy_from_slice(&buf[32..64]);
    let Ok(amount) = i64::try_from(read_u64_le(&buf[64..72])) else {
        return ERR_OVERFLOW;
    };
    if from == [0u8; 32] || amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let a_slot = pq_allowance_slot(&from, &spender);
    let allowed = sload(a_slot);
    if allowed < amount {
        return ERR_UNAUTHORIZED;
    }

    let rc = execute_transfer_pq(&from, &to, amount);
    if rc == SUCCESS {
        sstore(a_slot, allowed - amount);
    }
    rc
}

fn execute_transfer_pq(from: &[u8; 32], to: &[u8; 32], amount: i64) -> i64 {
    if *from == [0u8; 32] || amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let from_slot = pq_balance_slot(from);
    let from_bal = sload(from_slot);
    if from_bal < amount {
        return ERR_INSUFFICIENT_BALANCE;
    }

    // Direct burn to Black Hole ([0u8; 32]): exempt from tax.
    if *to == [0u8; 32] {
        let supply = sload(SLOT_TOTAL_SUPPLY);
        let new_supply = match supply.checked_sub(amount).filter(|&v| v >= 0) {
            Some(v) => v,
            None => return ERR_OVERFLOW,
        };
        sstore(from_slot, from_bal - amount);
        sstore(SLOT_TOTAL_SUPPLY, new_supply);
        emit(TOPIC_BURN, amount);
        return_data(&amount.to_le_bytes());
        return SUCCESS;
    }

    let treasury = load_addr32(b"TREASURY");
    if treasury == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    // Ceiling division 50 bps fee in u128 so large u64 transfers never overflow.
    let fee = (((amount as u128) * (TAX_BPS as u128) + (BPS_DENOMINATOR as u128) - 1)
        / (BPS_DENOMINATOR as u128)) as i64;
    let net = amount - fee;
    if net <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let new_from_bal = from_bal - amount;
    let to_slot = pq_balance_slot(to);
    let to_bal = if to_slot == from_slot {
        new_from_bal
    } else {
        sload(to_slot)
    };
    let new_to_bal = match to_bal.checked_add(net) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    let treasury_update = if fee > 0 {
        let treasury_slot = pq_balance_slot(&treasury);
        let treasury_bal = if treasury_slot == to_slot {
            new_to_bal
        } else if treasury_slot == from_slot {
            new_from_bal
        } else {
            sload(treasury_slot)
        };
        let new_treasury_bal = match treasury_bal.checked_add(fee) {
            Some(v) => v,
            None => return ERR_OVERFLOW,
        };
        Some((treasury_slot, new_treasury_bal))
    } else {
        None
    };

    sstore(from_slot, new_from_bal);
    sstore(to_slot, new_to_bal);
    if let Some((treasury_slot, new_treasury_bal)) = treasury_update {
        sstore(treasury_slot, new_treasury_bal);
    }

    emit(TOPIC_TRANSFER, amount);
    return_data(&net.to_le_bytes());
    SUCCESS
}

/// Mint tokens to PQ admin account (only authenticated PQ admin `caller()`).
/// `calldata()`: `amount (8B LE u64)`.
#[no_mangle]
pub extern "C" fn mint_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let admin = load_addr32(b"ADMIN___");
    if admin == [0u8; 32] || caller() != admin {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(amount) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let supply = sload(SLOT_TOTAL_SUPPLY);
    let new_supply = match supply.checked_add(amount) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let admin_slot = pq_balance_slot(&admin);
    let bal = sload(admin_slot);
    let new_bal = match bal.checked_add(amount) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    sstore(SLOT_TOTAL_SUPPLY, new_supply);
    sstore(admin_slot, new_bal);
    emit(TOPIC_MINT, amount);
    return_data(&new_bal.to_le_bytes());
    new_bal
}

/// Burn tokens from authenticated 32-byte `caller()`.
/// `calldata()`: `amount (8B LE u64)`.
#[no_mangle]
pub extern "C" fn burn_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    if who == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(amount) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let slot = pq_balance_slot(&who);
    let bal = sload(slot);
    if bal < amount {
        return ERR_INSUFFICIENT_BALANCE;
    }
    let supply = sload(SLOT_TOTAL_SUPPLY);
    let new_supply = match supply.checked_sub(amount).filter(|&v| v >= 0) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    let new_bal = bal - amount;
    sstore(slot, new_bal);
    sstore(SLOT_TOTAL_SUPPLY, new_supply);
    emit(TOPIC_BURN, amount);
    return_data(&new_bal.to_le_bytes());
    new_bal
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum_contract_sdk::{
        get_mock_return_data, id_to_caller, reset_mock_state, set_mock_calldata, set_mock_caller,
    };

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

    #[test]
    fn test_pq_token_lifecycle_and_auth() {
        reset_mock_state();
        let alice = [0xA1u8; 32];
        let bob = [0xB2u8; 32];
        let charlie = [0xC3u8; 32];
        let attacker = [0xE4u8; 32];

        // Zero caller cannot initialize
        set_mock_calldata(&1_000_000u64.to_le_bytes());
        assert_eq!(init_pq(0), ERR_UNAUTHORIZED);

        // Alice initializes with 1_000_000
        set_mock_caller(alice);
        set_mock_calldata(&1_000_000u64.to_le_bytes());
        assert_eq!(init_pq(0), SUCCESS);
        assert_eq!(init_pq(0), ERR_ALREADY_EXISTS);
        assert_eq!(total_supply(0), 1_000_000);

        set_mock_calldata(&alice);
        assert_eq!(balance_of_pq(0), 1_000_000);

        // Alice transfers 10_000 to Bob (50 bps fee = 50 goes back to Alice/treasury)
        let mut tf_data = [0u8; 40];
        tf_data[..32].copy_from_slice(&bob);
        tf_data[32..40].copy_from_slice(&10_000u64.to_le_bytes());
        set_mock_caller(alice);
        set_mock_calldata(&tf_data);
        assert_eq!(transfer_pq(0), SUCCESS);

        set_mock_calldata(&bob);
        assert_eq!(balance_of_pq(0), 9_950);
        set_mock_calldata(&alice);
        assert_eq!(balance_of_pq(0), 990_050); // 1_000_000 - 10_000 + 50 fee

        // Attacker with zero balance cannot transfer
        let mut steal = [0u8; 40];
        steal[..32].copy_from_slice(&attacker);
        steal[32..40].copy_from_slice(&1_000u64.to_le_bytes());
        set_mock_caller(attacker);
        set_mock_calldata(&steal);
        assert_eq!(transfer_pq(0), ERR_INSUFFICIENT_BALANCE);

        // Attacker cannot mint
        set_mock_calldata(&5_000u64.to_le_bytes());
        assert_eq!(mint_pq(0), ERR_UNAUTHORIZED);

        // Alice approves Charlie for 2_000
        let mut ap_data = [0u8; 40];
        ap_data[..32].copy_from_slice(&charlie);
        ap_data[32..40].copy_from_slice(&2_000u64.to_le_bytes());
        set_mock_caller(alice);
        set_mock_calldata(&ap_data);
        assert_eq!(approve_pq(0), SUCCESS);

        let mut alw_q = [0u8; 64];
        alw_q[..32].copy_from_slice(&alice);
        alw_q[32..64].copy_from_slice(&charlie);
        set_mock_calldata(&alw_q);
        assert_eq!(allowance_pq(0), 2_000);

        // Attacker cannot spend Alice's allowance for Charlie
        let mut tf_from = [0u8; 72];
        tf_from[..32].copy_from_slice(&alice);
        tf_from[32..64].copy_from_slice(&attacker);
        tf_from[64..72].copy_from_slice(&1_000u64.to_le_bytes());
        set_mock_caller(attacker);
        set_mock_calldata(&tf_from);
        assert_eq!(transfer_from_pq(0), ERR_UNAUTHORIZED);

        // Charlie spends 1_000 from Alice to Bob
        tf_from[32..64].copy_from_slice(&bob);
        set_mock_caller(charlie);
        set_mock_calldata(&tf_from);
        assert_eq!(transfer_from_pq(0), SUCCESS);

        set_mock_calldata(&alw_q);
        assert_eq!(allowance_pq(0), 1_000);
        set_mock_calldata(&bob);
        assert_eq!(balance_of_pq(0), 9_950 + 995);
    }

    #[test]
    fn test_pq_init_blocks_legacy_entrypoints_and_burn_pq_checked_sub() {
        reset_mock_state();
        let alice = [0xA1u8; 32];
        let bob = [0xB2u8; 32];

        set_mock_caller(alice);
        set_mock_calldata(&100_000u64.to_le_bytes());
        assert_eq!(init_pq(0), SUCCESS);

        // Legacy entrypoints must all refuse under PQ mode.
        set_mock_caller(id_to_caller(1));
        assert_eq!(balance_of(1), ERR_UNAUTHORIZED);
        assert_eq!(allowance(1_000_000 + 2), ERR_UNAUTHORIZED);
        assert_eq!(
            approve(10_000_000_000 + 2 * 100_000 + 50),
            ERR_UNAUTHORIZED
        );
        assert_eq!(transfer(100_000_000 + 2 * 100_000 + 50), ERR_UNAUTHORIZED);
        assert_eq!(
            transfer_from(2 * 100_000_000_000 + 10_000_000 + 3 * 100_000 + 50),
            ERR_UNAUTHORIZED
        );
        assert_eq!(mint(500), ERR_UNAUTHORIZED);
        assert_eq!(burn(500), ERR_UNAUTHORIZED);

        // burn_pq succeeds and updates total_supply and return_data.
        set_mock_caller(alice);
        set_mock_calldata(&25_000u64.to_le_bytes());
        assert_eq!(burn_pq(0), 75_000);
        assert_eq!(get_mock_return_data(), 75_000i64.to_le_bytes());
        assert_eq!(total_supply(0), 75_000);
        set_mock_calldata(&alice);
        assert_eq!(balance_of_pq(0), 75_000);

        // Bob with 0 balance cannot burn.
        set_mock_caller(bob);
        set_mock_calldata(&100u64.to_le_bytes());
        assert_eq!(burn_pq(0), ERR_INSUFFICIENT_BALANCE);

        // Underflow on SLOT_TOTAL_SUPPLY returns ERR_OVERFLOW without debiting Alice.
        sstore(SLOT_TOTAL_SUPPLY, 100);
        set_mock_caller(alice);
        set_mock_calldata(&1_000u64.to_le_bytes());
        assert_eq!(burn_pq(0), ERR_OVERFLOW);
        set_mock_calldata(&alice);
        assert_eq!(balance_of_pq(0), 75_000);
        assert_eq!(total_supply(0), 100);
    }

    #[test]
    fn test_legacy_burn_checked_sub_overflow() {
        reset_mock_state();
        assert_eq!(init(1_000), SUCCESS);
        sstore(SLOT_TOTAL_SUPPLY, 10);
        set_mock_caller(id_to_caller(1));
        assert_eq!(burn(50), ERR_OVERFLOW);
        assert_eq!(balance_of(1), 1_000);
        assert_eq!(total_supply(0), 10);
    }

    #[test]
    fn test_legacy_init_blocks_pq_entrypoints() {
        reset_mock_state();
        assert_eq!(init(1_000_000), SUCCESS);

        let alice = [0xA1u8; 32];
        let bob = [0xB2u8; 32];
        set_mock_caller(alice);

        set_mock_calldata(&alice);
        assert_eq!(balance_of_pq(0), ERR_UNAUTHORIZED);

        let mut alw_cd = [0u8; 64];
        alw_cd[..32].copy_from_slice(&alice);
        alw_cd[32..64].copy_from_slice(&bob);
        set_mock_calldata(&alw_cd);
        assert_eq!(allowance_pq(0), ERR_UNAUTHORIZED);

        let mut ap_tf_cd = [0u8; 40];
        ap_tf_cd[..32].copy_from_slice(&bob);
        ap_tf_cd[32..40].copy_from_slice(&1_000u64.to_le_bytes());
        set_mock_calldata(&ap_tf_cd);
        assert_eq!(approve_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(transfer_pq(0), ERR_UNAUTHORIZED);

        let mut tf_from_cd = [0u8; 72];
        tf_from_cd[..32].copy_from_slice(&alice);
        tf_from_cd[32..64].copy_from_slice(&bob);
        tf_from_cd[64..72].copy_from_slice(&1_000u64.to_le_bytes());
        set_mock_calldata(&tf_from_cd);
        assert_eq!(transfer_from_pq(0), ERR_UNAUTHORIZED);

        set_mock_calldata(&1_000u64.to_le_bytes());
        assert_eq!(mint_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(burn_pq(0), ERR_UNAUTHORIZED);
    }
}
