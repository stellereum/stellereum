//! STATUS:
//! - Legacy packed-`i64` entrypoints (`init`, `start_auction`, `place_bid`,
//!   `finalize_auction`, `resolve`, `set_target`, `transfer`): DEMO-GRADE
//!   compatibility shims (`transfer` and `set_target` bind `caller_id` via
//!   `caller_is`; legacy auctions move no funds and have no duration gate for
//!   backwards compatibility with existing tests).
//! - PQ entrypoints (`init_pq`, `start_auction_pq`, `place_bid_pq`,
//!   `finalize_auction_pq`, `resolve_pq`, `set_target_pq`, `transfer_pq`):
//!   authenticate full 32-byte post-quantum `host.caller` addresses via
//!   `caller()` + `calldata()` with `blake3`-keyed slots and enforce a real
//!   `block_time()` auction duration (`AUCTION_DURATION_SECS = 3600`).
//! DO NOT deploy with value without a full audit.
//!
//! Stellereum Name Service (SNS / STL-DNS) Contract (Hardened)
//!
//! Features:
//! - TON-style progressive auction price grid based on domain name length.
//! - Strict domain name validation (4..=126 characters, fail-closed for shorter).
//! - System reserved names (`burn.stl`, `trash.stl`) locked permanently to Account 0 / `[0u8; 32]`.
//! - Protocol reserved names (`vault.stl`, `stake.stl`, `bridge.stl`, `oracle.stl`,
//!   `dns.stl`, `stl.stl`, `dex.stl`, `dao.stl`, `mail.stl`, `infmail.stl`,
//!   `stellereum.stl`, `stell.stl`) assigned to Treasury and locked from public auctions.
//! - Non-system domains like `blackhole.stl` and user names are fully auctionable.
//! - Re-initialization guard, storage isolation, and authenticated transfers.
//! - Deterministic NFT card hue calculation: `(domain_id * 137) % 360`.
//! - Outbidding with 10% minimum increase, `block_time()` auction duration, and finalization.

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use stellereum_contract_sdk::address::{
    is_any_reserved, is_protocol_reserved, is_system_burn, PROTOCOL_RESERVED_DOMAINS,
    SYSTEM_BURN_DOMAINS,
};
use stellereum_contract_sdk::{
    blake3, block_time, calldata, caller, caller_is, emit, return_data, setup_wasm_panic_handler,
    sload, sstore, ERR_ALREADY_EXISTS, ERR_EXPIRED, ERR_INVALID_ARGUMENT, ERR_OVERFLOW,
    ERR_UNAUTHORIZED, SUCCESS,
};

setup_wasm_panic_handler!();

// Global Storage Slots
const SLOT_TREASURY: i64 = 0;
const SLOT_DOMAIN_COUNT: i64 = 1;
const SLOT_INITIALIZED: i64 = 2;
const SLOT_PQ_MODE: i64 = 3;
const MAX_TREASURY_ACCOUNT: i64 = 100_000;

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
fn domain_base(domain_id: i64) -> Option<i64> {
    if domain_id < 0 {
        return None;
    }
    let scaled = domain_id.checked_mul(DOMAIN_STRIDE)?;
    let base = DOMAIN_SLOT_OFFSET.checked_add(scaled)?;
    if base > i64::MAX - DOMAIN_STRIDE {
        return None;
    }
    Some(base)
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
    if sload(SLOT_INITIALIZED) != 0 {
        panic!("already initialized");
    }
    if treasury_account <= 0 || treasury_account >= MAX_TREASURY_ACCOUNT {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_TREASURY, treasury_account);

    // 1. Hardcode Black Hole domains (burn.stl, trash.stl -> 0)
    for &id in SYSTEM_BURN_DOMAINS.iter() {
        let Some(base) = domain_base(id) else {
            return ERR_OVERFLOW;
        };
        sstore(base, STATE_REGISTERED);
        sstore(base + 1, 0); // Account 0 = Black Hole
        sstore(base + 2, 0);
        sstore(base + 3, 1); // 1 = Permanent System Burn
        sstore(base + 4, 0); // Target = 0
    }

    // 2. Reserve Protocol domains for Treasury
    for &id in PROTOCOL_RESERVED_DOMAINS.iter() {
        let Some(base) = domain_base(id) else {
            return ERR_OVERFLOW;
        };
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
    let unsigned_id = ((domain_id as u64) & 0x7FFF_FFFF_FFFF_FFFF) as u128;
    ((unsigned_id * 137) % 360) as i64
}

/// Start an auction for a domain
/// packed_arg: domain_id * 10_000_000_000 + bidder_id * 100_000 + length
#[no_mangle]
pub extern "C" fn start_auction(packed_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 || sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
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

    let Some(base) = domain_base(domain_id) else {
        return ERR_INVALID_ARGUMENT;
    };

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
    if sload(SLOT_INITIALIZED) != 1 || sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if packed_arg <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let domain_id = packed_arg / 10_000_000_000;
    let rem1 = packed_arg % 10_000_000_000;
    let bidder_id = rem1 / 10_000;

    if domain_id <= 0 || bidder_id <= 0 || bidder_id >= 100_000 {
        return ERR_INVALID_ARGUMENT;
    }

    let Some(base) = domain_base(domain_id) else {
        return ERR_INVALID_ARGUMENT;
    };
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
    let new_bid = match current_bid.checked_add(min_increase) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    sstore(base + 1, bidder_id);
    sstore(base + 2, new_bid);
    sstore(base + 4, bidder_id); // Update default target to highest bidder

    emit(TOPIC_BID_PLACED, domain_id);
    new_bid
}

/// Finalize auction and transfer domain ownership to winning bidder
#[no_mangle]
pub extern "C" fn finalize_auction(domain_id: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 || sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if domain_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let Some(base) = domain_base(domain_id) else {
        return ERR_INVALID_ARGUMENT;
    };
    let state = sload(base);
    if state != STATE_AUCTION {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(base, STATE_REGISTERED);
    let count = sload(SLOT_DOMAIN_COUNT);
    let next_count = match count.checked_add(1) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    sstore(SLOT_DOMAIN_COUNT, next_count);

    emit(TOPIC_AUCTION_FINALIZED, domain_id);
    1
}

/// Resolve domain to target address.
/// Returns 0 if unfinalized, unregistered, or reserved burn.
#[no_mangle]
pub extern "C" fn resolve(domain_id: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if domain_id <= 0 {
        return 0;
    }
    let Some(base) = domain_base(domain_id) else {
        return ERR_INVALID_ARGUMENT;
    };
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
    if sload(SLOT_INITIALIZED) != 1 || sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
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
    let Some(base) = domain_base(domain_id) else {
        return ERR_INVALID_ARGUMENT;
    };
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
    if sload(SLOT_INITIALIZED) != 1 || sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
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
    let Some(base) = domain_base(domain_id) else {
        return ERR_INVALID_ARGUMENT;
    };

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

// ============================================================================
// Production 32-Byte Post-Quantum (Falcon-512) DNS Entrypoints
// ============================================================================

/// Real wall-clock auction duration enforced via `host.block_time` (1 hour).
pub const AUCTION_DURATION_SECS: i64 = 3600;

const PQ_DOM_STATE: u8 = 0;
const PQ_DOM_HIGHEST_BID: u8 = 1;
const PQ_DOM_RESERVED: u8 = 2;
const PQ_DOM_END_TIME: u8 = 3;

#[inline(always)]
fn pq_slot_from_digest(digest: [u8; 32]) -> i64 {
    let raw = u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    (raw | (1u64 << 63)) as i64
}

#[inline(always)]
fn pq_meta_slot(limb: u8) -> i64 {
    let mut preimage = [0u8; 17];
    preimage[..16].copy_from_slice(b"DNS_PQ_TRSY_V1__");
    preimage[16] = limb;
    pq_slot_from_digest(blake3(&preimage))
}

#[inline(always)]
fn pq_domain_field_slot(domain_id: i64, field: u8) -> i64 {
    let mut preimage = [0u8; 25];
    preimage[..16].copy_from_slice(b"DNS_PQ_DOMF_V1__");
    preimage[16..24].copy_from_slice(&domain_id.to_le_bytes());
    preimage[24] = field;
    pq_slot_from_digest(blake3(&preimage))
}

#[inline(always)]
fn pq_domain_addr_slot(tag: &[u8; 4], domain_id: i64, limb: u8) -> i64 {
    let mut preimage = [0u8; 29];
    preimage[..16].copy_from_slice(b"DNS_PQ_ADDR_V1__");
    preimage[16..20].copy_from_slice(tag);
    preimage[20..28].copy_from_slice(&domain_id.to_le_bytes());
    preimage[28] = limb;
    pq_slot_from_digest(blake3(&preimage))
}

fn store_pq_treasury(addr: &[u8; 32]) {
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
        sstore(pq_meta_slot(limb as u8), word);
        limb += 1;
    }
}

fn load_pq_treasury() -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut limb = 0usize;
    while limb < 4 {
        let word = sload(pq_meta_slot(limb as u8));
        let start = limb * 8;
        out[start..start + 8].copy_from_slice(&word.to_le_bytes());
        limb += 1;
    }
    out
}

fn store_domain_addr(tag: &[u8; 4], domain_id: i64, addr: &[u8; 32]) {
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
        sstore(pq_domain_addr_slot(tag, domain_id, limb as u8), word);
        limb += 1;
    }
}

fn load_domain_addr(tag: &[u8; 4], domain_id: i64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut limb = 0usize;
    while limb < 4 {
        let word = sload(pq_domain_addr_slot(tag, domain_id, limb as u8));
        let start = limb * 8;
        out[start..start + 8].copy_from_slice(&word.to_le_bytes());
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

/// Initialize STL-DNS registry once with 32-byte PQ `caller()` as treasury.
#[no_mangle]
pub extern "C" fn init_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 0 {
        return ERR_ALREADY_EXISTS;
    }
    let treasury = caller();
    if treasury == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_PQ_MODE, 1);
    store_pq_treasury(&treasury);

    let initial_count = (SYSTEM_BURN_DOMAINS.len() + PROTOCOL_RESERVED_DOMAINS.len()) as i64;
    sstore(SLOT_DOMAIN_COUNT, initial_count);
    return_data(&treasury);
    SUCCESS
}

/// Start an auction for a domain authenticated by 32-byte PQ `caller()`.
/// Enforces `AUCTION_DURATION_SECS` (3600s) on `host.block_time`.
/// `calldata()`: `domain_id (8B LE u64) || name_len (8B LE u64)`.
#[no_mangle]
pub extern "C" fn start_auction_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 {
        return ERR_UNAUTHORIZED;
    }
    let bidder = caller();
    if bidder == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 16 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(domain_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    let Ok(name_len) = i64::try_from(read_u64_le(&buf[8..16])) else {
        return ERR_OVERFLOW;
    };
    if domain_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    let min_bid = get_min_bid(name_len);
    if min_bid <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    if is_any_reserved(domain_id) || sload(pq_domain_field_slot(domain_id, PQ_DOM_RESERVED)) != 0 {
        return ERR_UNAUTHORIZED;
    }

    if sload(pq_domain_field_slot(domain_id, PQ_DOM_STATE)) != STATE_AVAILABLE {
        return ERR_ALREADY_EXISTS;
    }

    let now = block_time();
    if now < 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let end_time = match now.checked_add(AUCTION_DURATION_SECS) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    sstore(pq_domain_field_slot(domain_id, PQ_DOM_STATE), STATE_AUCTION);
    sstore(pq_domain_field_slot(domain_id, PQ_DOM_HIGHEST_BID), min_bid);
    sstore(pq_domain_field_slot(domain_id, PQ_DOM_END_TIME), end_time);
    store_domain_addr(b"OWN_", domain_id, &bidder);
    store_domain_addr(b"TGT_", domain_id, &bidder);

    emit(TOPIC_AUCTION_STARTED, domain_id);
    return_data(&end_time.to_le_bytes());
    domain_id
}

/// Place a counter-bid in an active PQ auction before `end_time`.
/// `calldata()`: `domain_id (8B LE u64)` (auto +10% step) OR
/// `domain_id (8B LE u64) || bid_amount (8B LE u64)` (explicit bid >= +10%).
#[no_mangle]
pub extern "C" fn place_bid_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 {
        return ERR_UNAUTHORIZED;
    }
    let bidder = caller();
    if bidder == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 && n != 16 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(domain_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if domain_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    if sload(pq_domain_field_slot(domain_id, PQ_DOM_STATE)) != STATE_AUCTION {
        return ERR_INVALID_ARGUMENT;
    }

    let now = block_time();
    let end_time = sload(pq_domain_field_slot(domain_id, PQ_DOM_END_TIME));
    if now < 0 || now >= end_time {
        return ERR_EXPIRED;
    }

    let current_bid = sload(pq_domain_field_slot(domain_id, PQ_DOM_HIGHEST_BID));
    let min_increase = if current_bid / 10 > 0 {
        current_bid / 10
    } else {
        1
    };
    let min_next_bid = match current_bid.checked_add(min_increase) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    let new_bid = if n == 16 {
        let Ok(explicit_bid) = i64::try_from(read_u64_le(&buf[8..16])) else {
            return ERR_OVERFLOW;
        };
        if explicit_bid < min_next_bid {
            return ERR_INVALID_ARGUMENT;
        }
        explicit_bid
    } else {
        min_next_bid
    };

    sstore(pq_domain_field_slot(domain_id, PQ_DOM_HIGHEST_BID), new_bid);
    store_domain_addr(b"OWN_", domain_id, &bidder);
    store_domain_addr(b"TGT_", domain_id, &bidder);

    emit(TOPIC_BID_PLACED, domain_id);
    return_data(&new_bid.to_le_bytes());
    new_bid
}

/// Finalize a PQ auction once `block_time() >= end_time` (`AUCTION_DURATION_SECS = 3600`).
/// `calldata()`: `domain_id (8B LE u64)`.
#[no_mangle]
pub extern "C" fn finalize_auction_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(domain_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if domain_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    if sload(pq_domain_field_slot(domain_id, PQ_DOM_STATE)) != STATE_AUCTION {
        return ERR_INVALID_ARGUMENT;
    }

    let now = block_time();
    let end_time = sload(pq_domain_field_slot(domain_id, PQ_DOM_END_TIME));
    if now < end_time {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(
        pq_domain_field_slot(domain_id, PQ_DOM_STATE),
        STATE_REGISTERED,
    );
    let count = sload(SLOT_DOMAIN_COUNT);
    let next_count = match count.checked_add(1) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    sstore(SLOT_DOMAIN_COUNT, next_count);

    let winner = load_domain_addr(b"OWN_", domain_id);
    emit(TOPIC_AUCTION_FINALIZED, domain_id);
    return_data(&winner);
    SUCCESS
}

/// Resolve a domain to its 32-byte PQ target (written to `return_data`).
/// Returns `1` if resolved to a non-zero 32-byte target, `0` otherwise.
/// `calldata()`: `domain_id (8B LE u64)`.
#[no_mangle]
pub extern "C" fn resolve_pq(_arg: i64) -> i64 {
    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(domain_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };

    if domain_id <= 0
        || is_system_burn(domain_id)
        || sload(pq_domain_field_slot(domain_id, PQ_DOM_RESERVED)) == 1
    {
        return_data(&[0u8; 32]);
        return 0;
    }

    if is_protocol_reserved(domain_id) {
        let resolved = if sload(pq_domain_field_slot(domain_id, PQ_DOM_STATE)) == STATE_REGISTERED {
            let target = load_domain_addr(b"TGT_", domain_id);
            if target != [0u8; 32] {
                target
            } else {
                load_domain_addr(b"OWN_", domain_id)
            }
        } else {
            load_pq_treasury()
        };
        return_data(&resolved);
        return if resolved == [0u8; 32] { 0 } else { 1 };
    }

    if sload(pq_domain_field_slot(domain_id, PQ_DOM_STATE)) != STATE_REGISTERED {
        return_data(&[0u8; 32]);
        return 0;
    }

    let target = load_domain_addr(b"TGT_", domain_id);
    let resolved = if target != [0u8; 32] {
        target
    } else {
        load_domain_addr(b"OWN_", domain_id)
    };
    return_data(&resolved);
    if resolved == [0u8; 32] {
        0
    } else {
        1
    }
}

/// Update domain target address authenticated as 32-byte PQ `caller()` owner (or treasury).
/// `calldata()`: `domain_id (8B LE u64) || new_target (32B)`.
#[no_mangle]
pub extern "C" fn set_target_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    if who == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 40 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(domain_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if domain_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut new_target = [0u8; 32];
    new_target.copy_from_slice(&buf[8..40]);
    if new_target == [0u8; 32] {
        return ERR_INVALID_ARGUMENT;
    }

    if is_system_burn(domain_id) || sload(pq_domain_field_slot(domain_id, PQ_DOM_RESERVED)) == 1 {
        return ERR_UNAUTHORIZED;
    }

    if is_protocol_reserved(domain_id) {
        let existing_owner = load_domain_addr(b"OWN_", domain_id);
        let auth_owner = if existing_owner != [0u8; 32] {
            existing_owner
        } else {
            load_pq_treasury()
        };
        if auth_owner == [0u8; 32] || who != auth_owner {
            return ERR_UNAUTHORIZED;
        }
        if existing_owner == [0u8; 32] {
            store_domain_addr(b"OWN_", domain_id, &auth_owner);
        }
        sstore(
            pq_domain_field_slot(domain_id, PQ_DOM_STATE),
            STATE_REGISTERED,
        );
        sstore(pq_domain_field_slot(domain_id, PQ_DOM_RESERVED), 2);
    } else {
        if sload(pq_domain_field_slot(domain_id, PQ_DOM_STATE)) != STATE_REGISTERED {
            return ERR_INVALID_ARGUMENT;
        }
        let owner = load_domain_addr(b"OWN_", domain_id);
        if owner == [0u8; 32] || who != owner {
            return ERR_UNAUTHORIZED;
        }
    }

    store_domain_addr(b"TGT_", domain_id, &new_target);
    emit(TOPIC_TARGET_UPDATED, domain_id);
    return_data(&new_target);
    SUCCESS
}

/// Transfer domain ownership authenticated as 32-byte PQ `caller()` owner (or treasury).
/// `calldata()`: `domain_id (8B LE u64) || new_owner (32B)`.
#[no_mangle]
pub extern "C" fn transfer_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 1 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    if who == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 40 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(domain_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    let mut new_owner = [0u8; 32];
    new_owner.copy_from_slice(&buf[8..40]);
    if domain_id <= 0 || new_owner == [0u8; 32] {
        return ERR_INVALID_ARGUMENT;
    }

    if is_system_burn(domain_id) || sload(pq_domain_field_slot(domain_id, PQ_DOM_RESERVED)) == 1 {
        return ERR_UNAUTHORIZED;
    }

    if is_protocol_reserved(domain_id) {
        let existing_owner = load_domain_addr(b"OWN_", domain_id);
        let auth_owner = if existing_owner != [0u8; 32] {
            existing_owner
        } else {
            load_pq_treasury()
        };
        if auth_owner == [0u8; 32] || who != auth_owner {
            return ERR_UNAUTHORIZED;
        }
        sstore(
            pq_domain_field_slot(domain_id, PQ_DOM_STATE),
            STATE_REGISTERED,
        );
        sstore(pq_domain_field_slot(domain_id, PQ_DOM_RESERVED), 2);
    } else {
        if sload(pq_domain_field_slot(domain_id, PQ_DOM_STATE)) != STATE_REGISTERED {
            return ERR_INVALID_ARGUMENT;
        }
        let owner = load_domain_addr(b"OWN_", domain_id);
        if owner == [0u8; 32] || who != owner {
            return ERR_UNAUTHORIZED;
        }
    }

    store_domain_addr(b"OWN_", domain_id, &new_owner);
    store_domain_addr(b"TGT_", domain_id, &new_owner);
    emit(TOPIC_DOMAIN_TRANSFERRED, domain_id);
    return_data(&new_owner);
    SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum_contract_sdk::address::{DOMAIN_BURN, DOMAIN_STAKE, DOMAIN_TRASH, DOMAIN_VAULT};
    use stellereum_contract_sdk::{
        get_mock_return_data, id_to_caller, reset_mock_state, set_mock_block_time,
        set_mock_calldata, set_mock_caller,
    };

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

    #[test]
    fn test_pq_dns_auction_timelock_and_auth() {
        reset_mock_state();
        let treasury = [0x99u8; 32];
        let alice = [0xA1u8; 32];
        let bob = [0xB2u8; 32];
        let target = [0x77u8; 32];
        let attacker = [0xE4u8; 32];

        set_mock_caller(treasury);
        assert_eq!(init_pq(0), SUCCESS);
        assert_eq!(init_pq(0), ERR_ALREADY_EXISTS);

        // Burn domain stays 0, protocol domain resolves to PQ treasury
        set_mock_calldata(&DOMAIN_BURN.to_le_bytes());
        assert_eq!(resolve_pq(0), 0);
        assert_eq!(get_mock_return_data(), [0u8; 32]);

        set_mock_calldata(&DOMAIN_VAULT.to_le_bytes());
        assert_eq!(resolve_pq(0), 1);
        assert_eq!(get_mock_return_data(), treasury);

        // Start auction for domain 42 (len 4) at t = 1_750_000_000
        let t0 = 1_750_000_000i64;
        set_mock_block_time(t0);
        set_mock_caller(alice);
        let mut start_cd = [0u8; 16];
        start_cd[..8].copy_from_slice(&42u64.to_le_bytes());
        start_cd[8..16].copy_from_slice(&4u64.to_le_bytes());
        set_mock_calldata(&start_cd);
        assert_eq!(start_auction_pq(0), 42);

        // Bob places counter-bid (+10% -> 220) before end_time
        set_mock_block_time(t0 + 100);
        set_mock_caller(bob);
        set_mock_calldata(&42u64.to_le_bytes());
        assert_eq!(place_bid_pq(0), 220);

        // Premature finalization before AUCTION_DURATION_SECS (3600) MUST fail
        set_mock_block_time(t0 + AUCTION_DURATION_SECS - 1);
        set_mock_calldata(&42u64.to_le_bytes());
        assert_eq!(finalize_auction_pq(0), ERR_INVALID_ARGUMENT);

        // After AUCTION_DURATION_SECS, bidding is expired and finalize succeeds
        set_mock_block_time(t0 + AUCTION_DURATION_SECS);
        set_mock_caller(alice);
        set_mock_calldata(&42u64.to_le_bytes());
        assert_eq!(place_bid_pq(0), ERR_EXPIRED);

        assert_eq!(finalize_auction_pq(0), SUCCESS);
        assert_eq!(get_mock_return_data(), bob);

        set_mock_calldata(&42u64.to_le_bytes());
        assert_eq!(resolve_pq(0), 1);
        assert_eq!(get_mock_return_data(), bob);

        // Attacker cannot set target or transfer
        let mut tgt_cd = [0u8; 40];
        tgt_cd[..8].copy_from_slice(&42u64.to_le_bytes());
        tgt_cd[8..40].copy_from_slice(&attacker);
        set_mock_caller(attacker);
        set_mock_calldata(&tgt_cd);
        assert_eq!(set_target_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(transfer_pq(0), ERR_UNAUTHORIZED);

        // Bob sets target, then transfers to Alice
        tgt_cd[8..40].copy_from_slice(&target);
        set_mock_caller(bob);
        set_mock_calldata(&tgt_cd);
        assert_eq!(set_target_pq(0), SUCCESS);
        set_mock_calldata(&42u64.to_le_bytes());
        assert_eq!(resolve_pq(0), 1);
        assert_eq!(get_mock_return_data(), target);

        tgt_cd[8..40].copy_from_slice(&alice);
        set_mock_caller(bob);
        set_mock_calldata(&tgt_cd);
        assert_eq!(transfer_pq(0), SUCCESS);
        set_mock_calldata(&42u64.to_le_bytes());
        assert_eq!(resolve_pq(0), 1);
        assert_eq!(get_mock_return_data(), alice);
    }

    #[test]
    fn test_pq_dns_blocks_legacy_auctions_and_allows_transferred_reserved_domain() {
        reset_mock_state();
        let treasury = id_to_caller(1);
        let alice = id_to_caller(2);
        let bob = id_to_caller(3);

        set_mock_caller(treasury);
        assert_eq!(init_pq(0), SUCCESS);

        // Legacy auction/target/transfer/resolve must refuse under PQ mode.
        assert_eq!(start_auction(55 * 10_000_000_000 + 2 * 100_000 + 5), ERR_UNAUTHORIZED);
        assert_eq!(finalize_auction(55), ERR_UNAUTHORIZED);
        assert_eq!(resolve(DOMAIN_VAULT), ERR_UNAUTHORIZED);
        assert_eq!(resolve(55), ERR_UNAUTHORIZED);

        // Zero target refused on set_target_pq.
        let mut zero_cd = [0u8; 40];
        zero_cd[..8].copy_from_slice(&DOMAIN_VAULT.to_le_bytes());
        set_mock_caller(treasury);
        set_mock_calldata(&zero_cd);
        assert_eq!(set_target_pq(0), ERR_INVALID_ARGUMENT);

        // Treasury transfers protocol-reserved DOMAIN_VAULT to Alice; Alice now manages it.
        let mut xfer_cd = [0u8; 40];
        xfer_cd[..8].copy_from_slice(&DOMAIN_VAULT.to_le_bytes());
        xfer_cd[8..40].copy_from_slice(&alice);
        set_mock_caller(treasury);
        set_mock_calldata(&xfer_cd);
        assert_eq!(transfer_pq(0), SUCCESS);

        // Old treasury can no longer mutate Alice's domain; Alice can set target to Bob.
        let mut tgt_cd = [0u8; 40];
        tgt_cd[..8].copy_from_slice(&DOMAIN_VAULT.to_le_bytes());
        tgt_cd[8..40].copy_from_slice(&bob);
        set_mock_caller(treasury);
        set_mock_calldata(&tgt_cd);
        assert_eq!(set_target_pq(0), ERR_UNAUTHORIZED);

        set_mock_caller(alice);
        set_mock_calldata(&tgt_cd);
        assert_eq!(set_target_pq(0), SUCCESS);
        set_mock_calldata(&DOMAIN_VAULT.to_le_bytes());
        assert_eq!(resolve_pq(0), 1);
        assert_eq!(get_mock_return_data(), bob);
    }

    #[test]
    fn test_domain_base_and_place_bid_overflow_guards() {
        reset_mock_state();
        assert_eq!(init(99), SUCCESS);

        assert_eq!(domain_base(-1), None);
        assert_eq!(domain_base(i64::MAX), None);
        assert_eq!(domain_base(i64::MAX / DOMAIN_STRIDE), None);
        assert!(domain_base(1).is_some());

        // Large domain_id in finalize_auction / resolve fails closed without wrapping.
        assert_eq!(finalize_auction(i64::MAX), ERR_INVALID_ARGUMENT);
        assert_eq!(resolve(i64::MAX), ERR_INVALID_ARGUMENT);

        // place_bid checked_add overflow guard.
        let domain_id = 55i64;
        assert_eq!(
            start_auction(domain_id * 10_000_000_000 + 10 * 100_000 + 4),
            domain_id
        );
        let base = domain_base(domain_id).unwrap();
        sstore(base + 2, i64::MAX);
        assert_eq!(
            place_bid(domain_id * 10_000_000_000 + 20 * 10_000 + 1),
            ERR_OVERFLOW
        );
    }
}
