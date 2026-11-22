//! STATUS: DEMO-GRADE, CT-P0 AUTHENTICATED (audit KI-38 fix). `transfer`
//! and `set_target` bind the caller-supplied `caller_id` to the authenticated
//! `host.caller` via `caller_is` (existing owner/treasury checks kept, now
//! forgery-proof: public owner ids replay nothing). Auth refusal is the
//! existing `ERR_UNAUTHORIZED` return (set_target precedent). Auction
//! mechanics (`start_auction`/`place_bid`/`finalize_auction`) move no funds
//! and stay permissionless (residual). DO NOT deploy with value without a
//! full audit.
//!
////! Stellereum Name Service (SNS / STL-DNS) Contract (Hardened)
//!
//! Features:
//! - TON-style progressive auction price grid based on domain name length.
//! - Strict domain name validation (4..=126 characters, fail-closed for shorter).
//! - System reserved names (`burn.stl`, `trash.stl`) locked permanently to Account 0 (Black Hole).
//! - Protocol reserved names (`vault.stl`, `stake.stl`, `bridge.stl`, `oracle.stl`,
//!   `dns.stl`, `stl.stl`, `dex.stl`, `dao.stl`, `mail.stl`, `infmail.stl`,
//!   `stellereum.stl`, `stell.stl`) assigned to Treasury and locked from public auctions.
//! - Non-system domains like `blackhole.stl` and user names are fully auctionable.
//! - Re-initialization guard, storage isolation, and authenticated transfers.
//! - Deterministic NFT card hue calculation: `(domain_id * 137) % 360`.
//! - Outbidding with 10% minimum increase and auction finalization.

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use stellereum_contract_sdk::address::{
    is_any_reserved, is_system_burn, PROTOCOL_RESERVED_DOMAINS, SYSTEM_BURN_DOMAINS,
};
use stellereum_contract_sdk::{
    caller_is, emit, setup_wasm_panic_handler, sload, sstore, ERR_ALREADY_EXISTS,
    ERR_INVALID_ARGUMENT, ERR_UNAUTHORIZED, SUCCESS,
};

setup_wasm_panic_handler!();

// Global Storage Slots
const SLOT_TREASURY: i64 = 0;
const SLOT_DOMAIN_COUNT: i64 = 1;
const SLOT_INITIALIZED: i64 = 2;

// Offset domain slots above global slots to eliminate slot 0 collisions
const DOMAIN_SLOT_OFFSET: i64 = 1000;
const DOMAIN_STRIDE: i64 = 10;

// Per-domain offsets:
// +0: State (0 = Available, 1 = Auction Active, 2 = Finalized / Registered)
// +1: Owner / Highest Bidder
// +2: Highest Bid (in STELL)
// +3: Reserved Flag (0 = Normal, 1 = Permanent System Burn, 2 = Protocol Reserved)
// +4: Target Address (Resolved target)

const STATE_AVAILABLE: i64 = 0;
const STATE_AUCTION: i64 = 1;
const STATE_REGISTERED: i64 = 2;

// Event Topics (Canonical)
const TOPIC_AUCTION_STARTED: i64 = 30;
const TOPIC_BID_PLACED: i64 = 32;
const TOPIC_AUCTION_FINALIZED: i64 = 33;
const TOPIC_TARGET_UPDATED: i64 = 34;
const TOPIC_DOMAIN_TRANSFERRED: i64 = 35;

#[inline(always)]
fn domain_base(domain_id: i64) -> i64 {
    DOMAIN_SLOT_OFFSET + domain_id * DOMAIN_STRIDE
}

/// Calculate starting bid floor based on TON-style length curve
#[no_mangle]
pub extern "C" fn get_min_bid(name_len: i64) -> i64 {
    match name_len {
        4 => 200,      // 4 chars: 200 STELL
        5 => 75,       // 5 chars: 75 STELL
        6 => 50,       // 6 chars: 50 STELL
        7 => 25,       // 7 chars: 25 STELL
        8 => 20,       // 8 chars: 20 STELL
        9 => 15,       // 9 chars: 15 STELL
        10 => 10,      // 10 chars: 10 STELL
        11..=126 => 5, // 11+ chars: 5 STELL
        _ => -1,       // < 4 or > 126: fail-closed
    }
}

/// Initialize registry once with treasury address and auto-register system & protocol domains
#[no_mangle]
pub extern "C" fn init(treasury_account: i64) -> i64 {
    if treasury_account <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    if sload(SLOT_INITIALIZED) != 0 {
        panic!("already initialized");
    }

    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_TREASURY, treasury_account);

    // 1. Hardcode Black Hole domains (burn.stl, trash.stl -> 0)
    for &id in SYSTEM_BURN_DOMAINS.iter() {
        let base = domain_base(id);
        sstore(base, STATE_REGISTERED);
        sstore(base + 1, 0); // Account 0 = Black Hole
        sstore(base + 2, 0);
        sstore(base + 3, 1); // 1 = Permanent System Burn
        sstore(base + 4, 0); // Target = 0
    }

    // 2. Reserve Protocol domains for Treasury
    for &id in PROTOCOL_RESERVED_DOMAINS.iter() {
        let base = domain_base(id);
        sstore(base, STATE_REGISTERED);
        sstore(base + 1, treasury_account);
        sstore(base + 2, 0);
        sstore(base + 3, 2); // 2 = Protocol Reserved
        sstore(base + 4, treasury_account); // Default target = Treasury
    }

    let initial_count = (SYSTEM_BURN_DOMAINS.len() + PROTOCOL_RESERVED_DOMAINS.len()) as i64;
    sstore(SLOT_DOMAIN_COUNT, initial_count);

    SUCCESS
}

/// Optical hue shift (0..359) with overflow safety
#[no_mangle]
pub extern "C" fn get_hue(domain_id: i64) -> i64 {
    let unsigned_id = (domain_id as u64) & 0x7FFF_FFFF_FFFF_FFFF;
    ((unsigned_id * 137) % 360) as i64
}

/// Start an auction for a domain
/// packed_arg: domain_id * 10_000_000_000 + bidder_id * 100_000 + length
#[no_mangle]
pub extern "C" fn start_auction(packed_arg: i64) -> i64 {
    if packed_arg <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let domain_id = packed_arg / 10_000_000_000;
    let rem1 = packed_arg % 10_000_000_000;
    let bidder_id = rem1 / 100_000;
    let name_len = rem1 % 100_000;

    if domain_id <= 0 || bidder_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let min_bid = get_min_bid(name_len);
    if min_bid <= 0 {
        panic!("invalid domain length: must be between 4 and 126 characters");
    }

    let base = domain_base(domain_id);

    // Reject if domain is reserved as burn/trash or protocol domain
    if is_any_reserved(domain_id) || sload(base + 3) != 0 {
        panic!("unauthorized: domain is reserved or active");
    }

    let state = sload(base);
    if state != STATE_AVAILABLE {
        return ERR_ALREADY_EXISTS;
    }

    sstore(base, STATE_AUCTION);
    sstore(base + 1, bidder_id);
    sstore(base + 2, min_bid);
    sstore(base + 4, bidder_id); // Default target = bidder

    emit(TOPIC_AUCTION_STARTED, domain_id);
    domain_id
}

/// Place a counter-bid in an active auction
/// packed_arg: domain_id * 10_000_000_000 + bidder_id * 10_000 + step
#[no_mangle]
pub extern "C" fn place_bid(packed_arg: i64) -> i64 {
    if packed_arg <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let domain_id = packed_arg / 10_000_000_000;
    let rem1 = packed_arg % 10_000_000_000;
    let bidder_id = rem1 / 10_000;

    if domain_id <= 0 || bidder_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let base = domain_base(domain_id);
    let state = sload(base);
    if state != STATE_AUCTION {
        return ERR_INVALID_ARGUMENT;
    }

    let current_bid = sload(base + 2);
    // Minimum 10% raise
    let min_increase = if current_bid / 10 > 0 {
        current_bid / 10
    } else {
        1
    };
    let new_bid = current_bid + min_increase;

    sstore(base + 1, bidder_id);
    sstore(base + 2, new_bid);
    sstore(base + 4, bidder_id); // Update default target to highest bidder

    emit(TOPIC_BID_PLACED, domain_id);
    new_bid
}

/// Finalize auction and transfer domain ownership to winning bidder
#[no_mangle]
pub extern "C" fn finalize_auction(domain_id: i64) -> i64 {
    if domain_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let base = domain_base(domain_id);
    let state = sload(base);
    if state != STATE_AUCTION {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(base, STATE_REGISTERED);
    let count = sload(SLOT_DOMAIN_COUNT);
    sstore(SLOT_DOMAIN_COUNT, count + 1);

    emit(TOPIC_AUCTION_FINALIZED, domain_id);
    1
}

/// Resolve domain to target address.
/// Returns 0 if unfinalized, unregistered, or reserved burn.
#[no_mangle]
pub extern "C" fn resolve(domain_id: i64) -> i64 {
    if domain_id <= 0 {
        return 0;
    }
    let base = domain_base(domain_id);
    // System burn domains permanently resolve to 0
    if is_system_burn(domain_id) || sload(base + 3) == 1 {
        return 0;
    }
    let state = sload(base);
    if state != STATE_REGISTERED {
        return 0;
    }
    let target = sload(base + 4);
    if target != 0 {
        target
    } else {
        sload(base + 1) // Fallback to owner
    }
}

/// Update domain resolution target address independently of ownership
/// packed_arg: domain_id * 10_000_000_000 + caller_id * 100_000 + new_target
#[no_mangle]
pub extern "C" fn set_target(packed_arg: i64) -> i64 {
    if packed_arg <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let domain_id = packed_arg / 10_000_000_000;
    let rem1 = packed_arg % 10_000_000_000;
    let caller_id = rem1 / 100_000;
    let new_target = rem1 % 100_000;

    // Audit 6.0->8.0: explicit domain guard (defense in depth — the packed>0
    // gate already forces domain_id >= 0, but a zero/negative domain must
    // never reach storage math).
    if domain_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let base = domain_base(domain_id);
    if is_system_burn(domain_id) || sload(base + 3) == 1 {
        return ERR_UNAUTHORIZED;
    }
    let state = sload(base);
    if state != STATE_REGISTERED {
        return ERR_INVALID_ARGUMENT;
    }

    let owner = sload(base + 1);
    let reserved_flag = sload(base + 3);

    // Enforce authorization (CT-P0: public ids replay nothing — the live
    // host.caller must own the claimed caller_id):
    // If protocol reserved (flag 2), only Treasury can set target
    if reserved_flag == 2 {
        let treasury = sload(SLOT_TREASURY);
        if caller_id != treasury || !caller_is(caller_id) {
            return ERR_UNAUTHORIZED;
        }
    } else if caller_id != owner || !caller_is(caller_id) {
        return ERR_UNAUTHORIZED;
    }

    sstore(base + 4, new_target);
    emit(TOPIC_TARGET_UPDATED, new_target);
    SUCCESS
}

/// Transfer domain ownership
/// packed_arg: domain_id * 10_000_000_000 + caller_id * 100_000 + new_owner
#[no_mangle]
pub extern "C" fn transfer(packed_arg: i64) -> i64 {
    if packed_arg <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let domain_id = packed_arg / 10_000_000_000;
    let rem1 = packed_arg % 10_000_000_000;
    let caller_id = rem1 / 100_000;
    let new_owner = rem1 % 100_000;

    // Audit 6.0->8.0: explicit domain guard (see set_target) plus a
    // fail-closed floor on the new owner. Owner 0 is the black hole: no
    // caller ever authenticates as id 0 (caller_is(0) is false), so a
    // zero-owner transfer would lock the domain forever with no recovery.
    if domain_id <= 0 || new_owner <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let base = domain_base(domain_id);

    // System burn domains can never be transferred
    if is_system_burn(domain_id) || sload(base + 3) == 1 {
        return ERR_UNAUTHORIZED;
    }

    let state = sload(base);
    if state != STATE_REGISTERED {
        return ERR_INVALID_ARGUMENT;
    }

    let owner = sload(base + 1);
    let reserved_flag = sload(base + 3);

    // Strict caller authentication (CT-P0: public owner/treasury ids replay
    // nothing — the live host.caller must own the claimed caller_id).
    // Refusal is ERR_UNAUTHORIZED (the set_target precedent), so forged
    // transfers fail closed without moving the domain.
    if reserved_flag == 2 {
        let treasury = sload(SLOT_TREASURY);
        if caller_id != treasury || !caller_is(caller_id) {
            return ERR_UNAUTHORIZED;
        }
    } else if caller_id != owner || !caller_is(caller_id) {
        return ERR_UNAUTHORIZED;
    }

    sstore(base + 1, new_owner);
    // If target was default owner, update target too
    sstore(base + 4, new_owner);

    emit(TOPIC_DOMAIN_TRANSFERRED, domain_id);
    SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum_contract_sdk::address::{DOMAIN_BURN, DOMAIN_STAKE, DOMAIN_TRASH, DOMAIN_VAULT};
    use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller};

    #[test]
    fn test_length_price_grid() {
        assert_eq!(get_min_bid(3), -1, "< 4 letters must fail closed");
        assert_eq!(get_min_bid(4), 200, "4 letters = 200 STELL");
        assert_eq!(get_min_bid(5), 75, "5 letters = 75 STELL");
        assert_eq!(get_min_bid(6), 50, "6 letters = 50 STELL");
        assert_eq!(get_min_bid(7), 25, "7 letters = 25 STELL");
        assert_eq!(get_min_bid(8), 20, "8 letters = 20 STELL");
        assert_eq!(get_min_bid(9), 15, "9 letters = 15 STELL");
        assert_eq!(get_min_bid(10), 10, "10 letters = 10 STELL");
        assert_eq!(get_min_bid(11), 5, "11+ letters = 5 STELL");
        assert_eq!(get_min_bid(126), 5);
        assert_eq!(get_min_bid(127), -1, "> 126 letters must fail closed");
    }

    #[test]
    fn test_auction_and_resolution_lifecycle() {
        reset_mock_state();
        assert_eq!(init(99), SUCCESS);

        // Start auction for 4-letter domain 'star.stl' (domain_id = 1, bidder = 10, len = 4)
        let start_arg = 10_000_000_000 + 10 * 100_000 + 4;
        assert_eq!(start_auction(start_arg), 1);
        assert_eq!(get_hue(1), 137);

        // Before finalization, resolve must return 0
        assert_eq!(resolve(1), 0);

        // Counter-bid from User 20: 200 + 10% = 220
        let bid_arg = 10_000_000_000 + 20 * 10_000 + 1;
        assert_eq!(place_bid(bid_arg), 220);

        // Finalize
        assert_eq!(finalize_auction(1), 1);

        // Winner is User 20
        assert_eq!(resolve(1), 20);

        // Set separate target to 555 by owner User 20 (authenticated).
        set_mock_caller(id_to_caller(20));
        assert_eq!(set_target(10_000_000_000 + 20 * 100_000 + 555), SUCCESS);
        assert_eq!(resolve(1), 555);

        // Transfer to user 33 by owner User 20 (authenticated).
        assert_eq!(transfer(10_000_000_000 + 20 * 100_000 + 33), SUCCESS);
        assert_eq!(resolve(1), 33);
    }

    #[test]
    fn test_protocol_and_burn_reservations() {
        reset_mock_state();
        init(99); // Treasury is Account 99

        // burn.stl and trash.stl permanently resolve to 0
        assert_eq!(resolve(DOMAIN_BURN), 0);
        assert_eq!(resolve(DOMAIN_TRASH), 0);

        // vault.stl and stake.stl resolve to Treasury 99
        assert_eq!(resolve(DOMAIN_VAULT), 99);
        assert_eq!(resolve(DOMAIN_STAKE), 99);

        // Protocol domain can be updated by treasury to new address 777
        // (authenticated as treasury 99).
        set_mock_caller(id_to_caller(99));
        assert_eq!(
            transfer(DOMAIN_STAKE * 10_000_000_000 + 99 * 100_000 + 777),
            SUCCESS
        );
        assert_eq!(resolve(DOMAIN_STAKE), 777);
    }

    #[test]
    fn test_blackhole_domain_is_auctionable() {
        reset_mock_state();
        init(99);
        let blackhole_id = 8888;
        let start_arg = blackhole_id * 10_000_000_000 + 55 * 100_000 + 9;
        assert_eq!(
            start_auction(start_arg),
            blackhole_id,
            "blackhole.stl must be auctionable"
        );

        let bid_arg = blackhole_id * 10_000_000_000 + 77 * 10_000 + 1;
        assert_eq!(place_bid(bid_arg), 16);

        assert_eq!(finalize_auction(blackhole_id), 1);
        assert_eq!(resolve(blackhole_id), 77);
    }
}
