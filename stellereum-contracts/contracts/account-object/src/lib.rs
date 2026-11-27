//! STATUS:
//! - Legacy packed-`i64` entrypoints (`init`, `transfer_ownership`,
//!   `rotate_guardian`, `initiate_recovery`, `cancel_recovery`, `set_tenant`,
//!   `revoke_rental`, `create_session`, `spend_with_session`, `revoke_session`,
//!   etc.): DEMO-GRADE compatibility shims (`caller_is` binds integer ids to
//!   canonical zero-padded `host.caller` addresses; legacy `spend_with_session` /
//!   `update_session_budget` / `revoke_session` remain bearer-style for
//!   backwards compatibility with existing tests).
//! - PQ entrypoints (`init_pq`, `get_owner_pq`, `create_session_pq`,
//!   `spend_with_session_pq`, `revoke_session_pq`, `get_session_budget_pq`,
//!   `is_session_active_pq`): authenticate full 32-byte post-quantum
//!   `host.caller` addresses via `caller()` + `calldata()`, binding every PQ
//!   session to an explicit 32-byte delegate (or owner) and closing the
//!   bearer-token gap.
//! DO NOT deploy with value without a full audit.
//!
//! NOTE (CT-P0): entry points are `extern "C-unwind"` (not `"C"`) so a native
//! test harness observes auth traps via `catch_unwind` (poc_p0_takeover pins
//! the trap). Wasm behavior is unchanged: the panic handler lowers panics to
//! `unreachable`, which the host reports as a trapped/reverted call.
//!
//! Account Object (Hardened Native Account Abstraction) Contract
//!
//! Design properties (NOT an audit; see the DEMO-GRADE status above):
//! - Protected against integer wrap-around slot collisions (bounded session_id).
//! - Protected against decimal packing bleed (strict modulus boundary assertions).
//! - Strict access controls: caller authentication on ownership, guardian, and PQ sessions.
//! - Timelocked social recovery with owner cancellation veto.
//! - Anti-inflation budget controls (budgets can only be decreased by session keys).
//! - Non-custodial rental delegation with automatic zero-cost expiration.

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use stellereum_contract_sdk::{
    blake3, block_time, calldata, caller, caller_is, emit, return_data, setup_wasm_panic_handler,
    sload, sstore, ERR_ALREADY_EXISTS, ERR_INSUFFICIENT_BALANCE, ERR_INVALID_ARGUMENT,
    ERR_NOT_FOUND, ERR_OVERFLOW, ERR_UNAUTHORIZED, SUCCESS,
};

setup_wasm_panic_handler!();

const SLOT_INITIALIZED: i64 = 0;
const SLOT_OWNER: i64 = 1;
const SLOT_GUARDIAN: i64 = 2;
const SLOT_PENDING_OWNER: i64 = 3;
const SLOT_FEE_PAID: i64 = 4;
const SLOT_SESSIONS_COUNT: i64 = 5;
const SLOT_TENANT: i64 = 6;
const SLOT_RENTAL_DEADLINE: i64 = 7;
const SLOT_RENTAL_PRICE: i64 = 8;
const SLOT_RECOVERY_TIMESTAMP: i64 = 9;
const SLOT_PQ_MODE: i64 = 10;

// Storage isolation offset & bounds
const SESSION_BASE_OFFSET: i64 = 10_000;
const SESSION_STRIDE: i64 = 16;
const MAX_SESSIONS: i64 = 1_000_000;
const MAX_OWNER_ID: i64 = 922_337_203;
const RECOVERY_TIMELOCK_SECS: i64 = 259_200; // 72-hour timelock

// Event Topics
const TOPIC_ACCOUNT_CREATED: i64 = 20;
const TOPIC_SESSION_CREATED: i64 = 21;
const TOPIC_SESSION_SPENT: i64 = 22;
const TOPIC_SESSION_REVOKED: i64 = 23;
const TOPIC_GUARDIAN_ROTATED: i64 = 24;
const TOPIC_RECOVERY_INITIATED: i64 = 25;
const TOPIC_RECOVERY_EXECUTED: i64 = 26;
const TOPIC_RENTAL_STARTED: i64 = 27;
const TOPIC_RENTAL_ENDED: i64 = 28;
const TOPIC_OWNERSHIP_TRANSFERRED: i64 = 29;
const TOPIC_SESSION_UPDATED: i64 = 30;
const TOPIC_RECOVERY_CANCELLED: i64 = 31;

#[inline(always)]
fn session_base(session_id: i64) -> i64 {
    if session_id <= 0 || session_id > MAX_SESSIONS {
        panic!("invalid session_id: out of allowed bounds [1, 1000000]");
    }
    SESSION_BASE_OFFSET + (session_id * SESSION_STRIDE)
}

#[inline(always)]
fn require_owner(caller_id: i64) {
    let owner = sload(SLOT_OWNER);
    // CT-P0: the public owner id replays nothing — the live host.caller must
    // be the canonical address of the claimed caller_id (fail-closed trap).
    if caller_id <= 0 || caller_id != owner || !caller_is(caller_id) {
        panic!("unauthorized: caller is not owner");
    }
}

/// Initialize Account Object for Owner
#[no_mangle]
pub extern "C-unwind" fn init(owner_id: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 0 {
        panic!("account already initialized");
    }
    if owner_id <= 0 || owner_id > MAX_OWNER_ID {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_OWNER, owner_id);
    sstore(SLOT_GUARDIAN, 0);
    sstore(SLOT_PENDING_OWNER, 0);
    sstore(SLOT_FEE_PAID, 2_000_000_000); // 2 STELL anti-spam fee
    sstore(SLOT_SESSIONS_COUNT, 0);
    sstore(SLOT_TENANT, 0);
    sstore(SLOT_RENTAL_DEADLINE, 0);
    sstore(SLOT_RENTAL_PRICE, 0);
    sstore(SLOT_RECOVERY_TIMESTAMP, 0);

    emit(TOPIC_ACCOUNT_CREATED, owner_id);
    owner_id
}

#[no_mangle]
pub extern "C-unwind" fn get_owner(_arg: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    sload(SLOT_OWNER)
}

#[no_mangle]
pub extern "C-unwind" fn get_guardian(_arg: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    sload(SLOT_GUARDIAN)
}

#[no_mangle]
pub extern "C-unwind" fn get_pending_owner(_arg: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    sload(SLOT_PENDING_OWNER)
}

/// Transfer Account Object to a new wallet owner
/// packed: caller_id * 10_000_000_000 + new_owner
#[no_mangle]
pub extern "C-unwind" fn transfer_ownership(packed: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    if packed <= 0 {
        panic!("invalid packed argument");
    }
    let caller_id = packed / 10_000_000_000;
    let new_owner = packed % 10_000_000_000;

    require_owner(caller_id);
    if new_owner <= 0 || new_owner > MAX_OWNER_ID {
        panic!("invalid new owner");
    }

    sstore(SLOT_OWNER, new_owner);
    sstore(SLOT_PENDING_OWNER, 0);
    sstore(SLOT_RECOVERY_TIMESTAMP, 0);
    sstore(SLOT_TENANT, 0);
    sstore(SLOT_RENTAL_DEADLINE, 0);

    emit(TOPIC_OWNERSHIP_TRANSFERRED, new_owner);
    new_owner
}

/// Rotate Guardian account
/// packed: caller_id * 10_000_000_000 + new_guardian
#[no_mangle]
pub extern "C-unwind" fn rotate_guardian(packed: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    if packed <= 0 {
        panic!("invalid packed argument");
    }
    let caller_id = packed / 10_000_000_000;
    let new_guardian = packed % 10_000_000_000;

    require_owner(caller_id);
    if new_guardian <= 0 {
        panic!("invalid guardian");
    }

    sstore(SLOT_GUARDIAN, new_guardian);
    emit(TOPIC_GUARDIAN_ROTATED, new_guardian);
    new_guardian
}

/// Social Recovery - Step 1: Propose Recovery Owner (Authorized by Guardian only)
/// packed: caller_id * 10_000_000_000 + new_owner
#[no_mangle]
pub extern "C-unwind" fn initiate_recovery(packed: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    if packed <= 0 {
        panic!("invalid packed argument");
    }
    let caller_id = packed / 10_000_000_000;
    let new_owner = packed % 10_000_000_000;

    let guardian = sload(SLOT_GUARDIAN);
    // CT-P0: guardian id is public — bind it to host.caller like require_owner.
    if guardian <= 0 || caller_id != guardian || !caller_is(caller_id) {
        panic!("unauthorized: caller is not designated guardian");
    }
    if new_owner <= 0 || new_owner > MAX_OWNER_ID {
        panic!("invalid recovery owner");
    }

    let current_ref = block_time();
    if current_ref < 0 {
        panic!("invalid block_time");
    }
    sstore(SLOT_PENDING_OWNER, new_owner);
    sstore(SLOT_RECOVERY_TIMESTAMP, current_ref);

    emit(TOPIC_RECOVERY_INITIATED, new_owner);
    new_owner
}

/// Cancel a pending social recovery (Owner veto right)
#[no_mangle]
pub extern "C-unwind" fn cancel_recovery(caller_id: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    require_owner(caller_id);
    sstore(SLOT_PENDING_OWNER, 0);
    sstore(SLOT_RECOVERY_TIMESTAMP, 0);
    emit(TOPIC_RECOVERY_CANCELLED, 0);
    SUCCESS
}

/// Social Recovery - Step 2: Finalize Recovery
#[no_mangle]
pub extern "C-unwind" fn finalize_recovery(_now_timestamp: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    let pending = sload(SLOT_PENDING_OWNER);
    if pending <= 0 {
        panic!("no pending recovery");
    }

    let init_time = sload(SLOT_RECOVERY_TIMESTAMP);
    let now = block_time();
    let unlock_time = init_time
        .checked_add(RECOVERY_TIMELOCK_SECS)
        .expect("recovery timestamp overflow");
    if now < unlock_time {
        panic!("timelock not elapsed: recovery is pending challenge period");
    }

    sstore(SLOT_OWNER, pending);
    sstore(SLOT_PENDING_OWNER, 0);
    sstore(SLOT_RECOVERY_TIMESTAMP, 0);
    sstore(SLOT_TENANT, 0);
    sstore(SLOT_RENTAL_DEADLINE, 0);

    emit(TOPIC_RECOVERY_EXECUTED, pending);
    pending
}

/// Delegate usage rights to tenant
/// packed: caller_id * 10_000_000_000 + tenant_id * 10_000 + duration_hours
#[no_mangle]
pub extern "C-unwind" fn set_tenant(packed: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    if packed <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let caller_id = packed / 10_000_000_000;
    let rem = packed % 10_000_000_000;
    let tenant_id = rem / 10_000;
    let duration_hours = rem % 10_000;

    require_owner(caller_id);
    if tenant_id <= 0 || duration_hours <= 0 || duration_hours > 8760 {
        return ERR_INVALID_ARGUMENT;
    }

    let now = block_time();
    if now < 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let deadline = match now.checked_add(duration_hours * 3600) {
        Some(v) => v,
        None => return ERR_INVALID_ARGUMENT,
    };

    sstore(SLOT_TENANT, tenant_id);
    sstore(SLOT_RENTAL_DEADLINE, deadline);

    emit(TOPIC_RENTAL_STARTED, tenant_id);
    tenant_id
}

/// Revoke rental
#[no_mangle]
pub extern "C-unwind" fn revoke_rental(caller_id: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    require_owner(caller_id);
    sstore(SLOT_TENANT, 0);
    sstore(SLOT_RENTAL_DEADLINE, 0);
    emit(TOPIC_RENTAL_ENDED, 0);
    SUCCESS
}

#[no_mangle]
pub extern "C-unwind" fn get_active_tenant(_now_timestamp: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    let deadline = sload(SLOT_RENTAL_DEADLINE);
    let now = block_time();
    if deadline == 0 || now < 0 || now >= deadline {
        return 0;
    }
    sload(SLOT_TENANT)
}

#[no_mangle]
pub extern "C-unwind" fn is_rental_active(_now_timestamp: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if get_active_tenant(0) > 0 {
        1
    } else {
        0
    }
}

/// Create a new session with strict bounds and authorization
/// packed: (session_id * 10_000_000_000) + (service_id * 100_000) + budget
#[no_mangle]
pub extern "C-unwind" fn create_session(packed: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 {
        panic!("account not initialized");
    }
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    if packed <= 0 {
        panic!("invalid packed argument");
    }
    let session_id = packed / 10_000_000_000;
    let rem1 = packed % 10_000_000_000;
    let service_id = rem1 / 100_000;
    let budget = rem1 % 100_000;

    // Strict validation preventing digit bleed
    if service_id >= 100_000 || budget >= 100_000 {
        panic!("parameter exceeds field boundary");
    }
    if session_id <= 0 || session_id > MAX_SESSIONS || budget <= 0 {
        panic!("invalid session parameters");
    }

    let base = session_base(session_id);
    if sload(base + 1) != 0 {
        panic!("session already exists");
    }
    if sload(base + 6) != 0 {
        panic!("session revoked: terminal tombstone");
    }

    sstore(base, service_id);
    sstore(base + 1, session_id);
    sstore(base + 2, 255);
    sstore(base + 3, 2_000_000_000);
    sstore(base + 4, budget);
    sstore(base + 5, 0);
    sstore(base + 6, 0);

    let count = sload(SLOT_SESSIONS_COUNT);
    let next_count = count.checked_add(1).expect("session count overflow");
    sstore(SLOT_SESSIONS_COUNT, next_count);

    emit(TOPIC_SESSION_CREATED, session_id);
    session_id
}

/// Update an existing session's budget (Restricted: budget can only be decreased)
/// packed: (session_id * 10_000_000_000) + new_budget
#[no_mangle]
pub extern "C-unwind" fn update_session_budget(packed: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    if packed <= 0 {
        panic!("invalid packed argument");
    }
    let session_id = packed / 10_000_000_000;
    let new_budget = packed % 10_000_000_000;

    if session_id <= 0 || session_id > MAX_SESSIONS || new_budget <= 0 {
        panic!("invalid session parameters");
    }

    let base = session_base(session_id);
    if sload(base + 1) == 0 {
        panic!("session does not exist");
    }
    if sload(base + 6) != 0 {
        panic!("cannot update revoked session");
    }

    let old_budget = sload(base + 4);
    let spent = sload(base + 5);

    // Prevent arbitrary inflation: budget cannot be increased above old budget
    if new_budget > old_budget {
        panic!("unauthorized budget inflation: budget can only be decreased");
    }
    if new_budget < spent {
        panic!("new budget cannot be less than already spent amount");
    }

    sstore(base + 4, new_budget);
    emit(TOPIC_SESSION_UPDATED, session_id);
    new_budget - spent
}

/// Spend using active session with strict amount boundary check
/// packed: (session_id * 1_000_000) + amount
#[no_mangle]
pub extern "C-unwind" fn spend_with_session(packed: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    if packed <= 0 {
        panic!("invalid packed argument");
    }
    let session_id = packed / 1_000_000;
    let amount = packed % 1_000_000;

    // STRICT BOUNDARY CHECK: amount cannot exceed packing modulus
    if amount <= 0 || amount >= 1_000_000 {
        panic!("invalid spend amount: exceeds boundary [1, 999999]");
    }
    if session_id <= 0 || session_id > MAX_SESSIONS {
        panic!("invalid session_id");
    }

    let base = session_base(session_id);
    if sload(base + 1) == 0 {
        panic!("session does not exist");
    }
    if sload(base + 6) != 0 {
        panic!("session revoked");
    }

    let budget = sload(base + 4);
    let spent = sload(base + 5);
    let new_spent = match spent.checked_add(amount) {
        Some(v) => v,
        None => panic!("spend overflow"),
    };

    if new_spent > budget {
        panic!("session budget exceeded");
    }

    sstore(base + 5, new_spent);
    emit(TOPIC_SESSION_SPENT, amount);

    budget - new_spent
}

/// Revoke session immediately with terminal tombstone
#[no_mangle]
pub extern "C-unwind" fn revoke_session(session_id: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        panic!("unauthorized: PQ-initialized account requires *_pq entrypoints");
    }
    if session_id <= 0 || session_id > MAX_SESSIONS {
        panic!("invalid session_id");
    }
    let base = session_base(session_id);
    // Defense against preemptive tombstone DoS: session MUST exist before being revoked
    if sload(base + 1) == 0 {
        panic!("cannot revoke non-existent session");
    }
    sstore(base + 6, 1);
    emit(TOPIC_SESSION_REVOKED, session_id);
    1
}

#[no_mangle]
pub extern "C-unwind" fn is_session_active(session_id: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if session_id <= 0 || session_id > MAX_SESSIONS {
        return 0;
    }
    let base = session_base(session_id);
    if sload(base + 1) == 0 || sload(base + 6) != 0 {
        return 0;
    }
    let budget = sload(base + 4);
    let spent = sload(base + 5);
    if spent >= budget {
        return 0;
    }
    1
}

#[no_mangle]
pub extern "C-unwind" fn get_session_budget(session_id: i64) -> i64 {
    if sload(SLOT_PQ_MODE) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if session_id <= 0 || session_id > MAX_SESSIONS {
        return 0;
    }
    let base = session_base(session_id);
    if sload(base + 6) != 0 {
        return 0;
    }
    let budget = sload(base + 4);
    let spent = sload(base + 5);
    if spent >= budget {
        return 0;
    }
    budget - spent
}

// ============================================================================
// Production 32-Byte Post-Quantum (Falcon-512) Account & Session Entrypoints
// ============================================================================

const PQ_SESS_EXISTS: u8 = 0;
const PQ_SESS_BUDGET: u8 = 1;
const PQ_SESS_SPENT: u8 = 2;
const PQ_SESS_REVOKED: u8 = 3;

#[inline(always)]
fn pq_slot_from_digest(digest: [u8; 32]) -> i64 {
    let raw = u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    (raw | (1u64 << 63)) as i64
}

#[inline(always)]
fn pq_meta_slot(tag: &[u8; 8], limb: u8) -> i64 {
    let mut preimage = [0u8; 25];
    preimage[..16].copy_from_slice(b"AA_PQ_META_V1___");
    preimage[16..24].copy_from_slice(tag);
    preimage[24] = limb;
    pq_slot_from_digest(blake3(&preimage))
}

#[inline(always)]
fn pq_session_field_slot(session_id: i64, field: u8) -> i64 {
    let mut preimage = [0u8; 25];
    preimage[..16].copy_from_slice(b"AA_PQ_SESS_V1___");
    preimage[16..24].copy_from_slice(&session_id.to_le_bytes());
    preimage[24] = field;
    pq_slot_from_digest(blake3(&preimage))
}

#[inline(always)]
fn pq_session_delegate_slot(session_id: i64, limb: u8) -> i64 {
    let mut preimage = [0u8; 25];
    preimage[..16].copy_from_slice(b"AA_PQ_SDEL_V1___");
    preimage[16..24].copy_from_slice(&session_id.to_le_bytes());
    preimage[24] = limb;
    pq_slot_from_digest(blake3(&preimage))
}

fn store_pq_addr(tag: &[u8; 8], addr: &[u8; 32]) {
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

fn load_pq_addr(tag: &[u8; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut limb = 0usize;
    while limb < 4 {
        let word = sload(pq_meta_slot(tag, limb as u8));
        let start = limb * 8;
        out[start..start + 8].copy_from_slice(&word.to_le_bytes());
        limb += 1;
    }
    out
}

fn store_pq_owner(owner: &[u8; 32]) {
    store_pq_addr(b"OWNER___", owner);
}

fn load_pq_owner() -> [u8; 32] {
    load_pq_addr(b"OWNER___")
}

fn store_session_delegate(session_id: i64, delegate: &[u8; 32]) {
    let mut limb = 0usize;
    while limb < 4 {
        let start = limb * 8;
        let word = i64::from_le_bytes([
            delegate[start],
            delegate[start + 1],
            delegate[start + 2],
            delegate[start + 3],
            delegate[start + 4],
            delegate[start + 5],
            delegate[start + 6],
            delegate[start + 7],
        ]);
        sstore(pq_session_delegate_slot(session_id, limb as u8), word);
        limb += 1;
    }
}

fn load_session_delegate(session_id: i64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut limb = 0usize;
    while limb < 4 {
        let word = sload(pq_session_delegate_slot(session_id, limb as u8));
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

/// Initialize Account Object once with the authenticated 32-byte PQ `caller()` as owner.
#[no_mangle]
pub extern "C-unwind" fn init_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) != 0 {
        return ERR_ALREADY_EXISTS;
    }
    let owner = caller();
    if owner == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    sstore(SLOT_INITIALIZED, 1);
    sstore(SLOT_PQ_MODE, 1);
    store_pq_owner(&owner);
    sstore(SLOT_GUARDIAN, 0);
    sstore(SLOT_PENDING_OWNER, 0);
    sstore(SLOT_FEE_PAID, 2_000_000_000);
    sstore(SLOT_SESSIONS_COUNT, 0);
    sstore(SLOT_TENANT, 0);
    sstore(SLOT_RENTAL_DEADLINE, 0);
    sstore(SLOT_RENTAL_PRICE, 0);
    sstore(SLOT_RECOVERY_TIMESTAMP, 0);

    emit(TOPIC_ACCOUNT_CREATED, 1);
    return_data(&owner);
    SUCCESS
}

/// Query 32-byte PQ owner (writes 32-byte owner to `return_data`; returns 1 if set, 0 otherwise).
#[no_mangle]
pub extern "C-unwind" fn get_owner_pq(_arg: i64) -> i64 {
    let owner = load_pq_owner();
    return_data(&owner);
    if owner == [0u8; 32] {
        0
    } else {
        1
    }
}

/// Create an authenticated PQ session bound to a designated 32-byte `delegate`.
/// Only the stored 32-byte PQ owner (`caller() == owner`) may create sessions.
/// `calldata()`: `session_id (8B LE u64) || delegate (32B) || budget (8B LE u64)`.
#[no_mangle]
pub extern "C-unwind" fn create_session_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    let owner = load_pq_owner();
    if who == [0u8; 32] || owner == [0u8; 32] || who != owner {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 48 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(session_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    let mut delegate = [0u8; 32];
    delegate.copy_from_slice(&buf[8..40]);
    let Ok(budget) = i64::try_from(read_u64_le(&buf[40..48])) else {
        return ERR_OVERFLOW;
    };

    if session_id <= 0 || session_id > MAX_SESSIONS || delegate == [0u8; 32] || budget <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    if sload(pq_session_field_slot(session_id, PQ_SESS_REVOKED)) != 0 {
        return ERR_UNAUTHORIZED;
    }
    if sload(pq_session_field_slot(session_id, PQ_SESS_EXISTS)) != 0 {
        return ERR_ALREADY_EXISTS;
    }

    let count = sload(SLOT_SESSIONS_COUNT);
    let next_count = match count.checked_add(1) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };

    sstore(pq_session_field_slot(session_id, PQ_SESS_EXISTS), 1);
    sstore(pq_session_field_slot(session_id, PQ_SESS_BUDGET), budget);
    sstore(pq_session_field_slot(session_id, PQ_SESS_SPENT), 0);
    sstore(pq_session_field_slot(session_id, PQ_SESS_REVOKED), 0);
    store_session_delegate(session_id, &delegate);
    sstore(SLOT_SESSIONS_COUNT, next_count);

    emit(TOPIC_SESSION_CREATED, session_id);
    return_data(&session_id.to_le_bytes());
    SUCCESS
}

/// Spend from an active PQ session. Closes the legacy bearer-token gap:
/// `caller()` MUST match either the session's designated 32-byte `delegate`
/// or the account's 32-byte `owner`.
/// `calldata()`: `session_id (8B LE u64) || amount (8B LE u64)`.
#[no_mangle]
pub extern "C-unwind" fn spend_with_session_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    if who == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 16 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(session_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    let Ok(amount) = i64::try_from(read_u64_le(&buf[8..16])) else {
        return ERR_OVERFLOW;
    };
    if session_id <= 0 || session_id > MAX_SESSIONS || amount <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    if sload(pq_session_field_slot(session_id, PQ_SESS_EXISTS)) == 0 {
        return ERR_NOT_FOUND;
    }
    if sload(pq_session_field_slot(session_id, PQ_SESS_REVOKED)) != 0 {
        return ERR_UNAUTHORIZED;
    }

    let owner = load_pq_owner();
    let delegate = load_session_delegate(session_id);
    if who != delegate && who != owner {
        return ERR_UNAUTHORIZED;
    }

    let budget = sload(pq_session_field_slot(session_id, PQ_SESS_BUDGET));
    let spent = sload(pq_session_field_slot(session_id, PQ_SESS_SPENT));
    let new_spent = match spent.checked_add(amount) {
        Some(v) => v,
        None => return ERR_OVERFLOW,
    };
    if new_spent > budget {
        return ERR_INSUFFICIENT_BALANCE;
    }

    sstore(pq_session_field_slot(session_id, PQ_SESS_SPENT), new_spent);
    let remaining = budget - new_spent;
    emit(TOPIC_SESSION_SPENT, amount);
    return_data(&remaining.to_le_bytes());
    remaining
}

/// Revoke a PQ session with terminal tombstone.
/// `caller()` MUST be the 32-byte `owner` or the session's 32-byte `delegate`.
/// `calldata()`: `session_id (8B LE u64)`.
#[no_mangle]
pub extern "C-unwind" fn revoke_session_pq(_arg: i64) -> i64 {
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
    let Ok(session_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if session_id <= 0 || session_id > MAX_SESSIONS {
        return ERR_INVALID_ARGUMENT;
    }
    if sload(pq_session_field_slot(session_id, PQ_SESS_EXISTS)) == 0 {
        return ERR_NOT_FOUND;
    }

    let owner = load_pq_owner();
    let delegate = load_session_delegate(session_id);
    if who != owner && who != delegate {
        return ERR_UNAUTHORIZED;
    }

    sstore(pq_session_field_slot(session_id, PQ_SESS_REVOKED), 1);
    emit(TOPIC_SESSION_REVOKED, session_id);
    SUCCESS
}

/// Query remaining budget of a PQ session.
/// `calldata()`: `session_id (8B LE u64)`.
#[no_mangle]
pub extern "C-unwind" fn get_session_budget_pq(_arg: i64) -> i64 {
    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(session_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if session_id <= 0 || session_id > MAX_SESSIONS {
        return_data(&0i64.to_le_bytes());
        return 0;
    }
    if sload(pq_session_field_slot(session_id, PQ_SESS_EXISTS)) == 0
        || sload(pq_session_field_slot(session_id, PQ_SESS_REVOKED)) != 0
    {
        return_data(&0i64.to_le_bytes());
        return 0;
    }
    let budget = sload(pq_session_field_slot(session_id, PQ_SESS_BUDGET));
    let spent = sload(pq_session_field_slot(session_id, PQ_SESS_SPENT));
    let rem = if spent >= budget { 0 } else { budget - spent };
    return_data(&rem.to_le_bytes());
    rem
}

/// Query whether a PQ session is active (`1`) or inactive/revoked (`0`).
/// `calldata()`: `session_id (8B LE u64)`.
#[no_mangle]
pub extern "C-unwind" fn is_session_active_pq(_arg: i64) -> i64 {
    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 8 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(session_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    if session_id <= 0 || session_id > MAX_SESSIONS {
        return 0;
    }
    if sload(pq_session_field_slot(session_id, PQ_SESS_EXISTS)) == 0
        || sload(pq_session_field_slot(session_id, PQ_SESS_REVOKED)) != 0
    {
        return 0;
    }
    let budget = sload(pq_session_field_slot(session_id, PQ_SESS_BUDGET));
    let spent = sload(pq_session_field_slot(session_id, PQ_SESS_SPENT));
    if spent >= budget {
        0
    } else {
        1
    }
}

/// Update an existing PQ session's budget (Restricted: budget can only be decreased).
/// `caller()` MUST be the 32-byte `owner` or the session's 32-byte `delegate`.
/// `calldata()`: `session_id (8B LE u64) || new_budget (8B LE u64)`.
#[no_mangle]
pub extern "C-unwind" fn update_session_budget_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    if who == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 32];
    let n = calldata(&mut buf);
    if n != 16 {
        return ERR_INVALID_ARGUMENT;
    }
    let Ok(session_id) = i64::try_from(read_u64_le(&buf[..8])) else {
        return ERR_OVERFLOW;
    };
    let Ok(new_budget) = i64::try_from(read_u64_le(&buf[8..16])) else {
        return ERR_OVERFLOW;
    };
    if session_id <= 0 || session_id > MAX_SESSIONS || new_budget <= 0 {
        return ERR_INVALID_ARGUMENT;
    }

    if sload(pq_session_field_slot(session_id, PQ_SESS_EXISTS)) == 0 {
        return ERR_NOT_FOUND;
    }
    if sload(pq_session_field_slot(session_id, PQ_SESS_REVOKED)) != 0 {
        return ERR_UNAUTHORIZED;
    }

    let owner = load_pq_owner();
    let delegate = load_session_delegate(session_id);
    if who != owner && who != delegate {
        return ERR_UNAUTHORIZED;
    }

    let old_budget = sload(pq_session_field_slot(session_id, PQ_SESS_BUDGET));
    let spent = sload(pq_session_field_slot(session_id, PQ_SESS_SPENT));
    if new_budget > old_budget {
        return ERR_UNAUTHORIZED;
    }
    if new_budget < spent {
        return ERR_INVALID_ARGUMENT;
    }

    sstore(pq_session_field_slot(session_id, PQ_SESS_BUDGET), new_budget);
    let remaining = new_budget - spent;
    emit(TOPIC_SESSION_UPDATED, session_id);
    return_data(&remaining.to_le_bytes());
    remaining
}

/// Transfer PQ account ownership to a new 32-byte owner (`caller()` must be current PQ owner).
/// `calldata()`: `new_owner (32B)`.
#[no_mangle]
pub extern "C-unwind" fn transfer_ownership_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    let owner = load_pq_owner();
    if who == [0u8; 32] || owner == [0u8; 32] || who != owner {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 32 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut new_owner = [0u8; 32];
    new_owner.copy_from_slice(&buf[..32]);
    if new_owner == [0u8; 32] {
        return ERR_INVALID_ARGUMENT;
    }

    store_pq_owner(&new_owner);
    store_pq_addr(b"PEND_OWN", &[0u8; 32]);
    sstore(pq_meta_slot(b"REC_TIME", 0), 0);
    store_pq_addr(b"TENANT__", &[0u8; 32]);
    sstore(pq_meta_slot(b"RNT_DEAD", 0), 0);

    emit(TOPIC_OWNERSHIP_TRANSFERRED, 1);
    return_data(&new_owner);
    SUCCESS
}

/// Rotate the 32-byte PQ guardian (`caller()` must be current PQ owner).
/// `calldata()`: `new_guardian (32B)`.
#[no_mangle]
pub extern "C-unwind" fn rotate_guardian_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    let owner = load_pq_owner();
    if who == [0u8; 32] || owner == [0u8; 32] || who != owner {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 32 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut new_guardian = [0u8; 32];
    new_guardian.copy_from_slice(&buf[..32]);
    if new_guardian == [0u8; 32] {
        return ERR_INVALID_ARGUMENT;
    }

    store_pq_addr(b"GUARDIAN", &new_guardian);
    emit(TOPIC_GUARDIAN_ROTATED, 1);
    return_data(&new_guardian);
    SUCCESS
}

/// Query 32-byte PQ guardian (writes 32-byte guardian to `return_data`; returns 1 if set, 0 otherwise).
#[no_mangle]
pub extern "C-unwind" fn get_guardian_pq(_arg: i64) -> i64 {
    let guardian = load_pq_addr(b"GUARDIAN");
    return_data(&guardian);
    if guardian == [0u8; 32] {
        0
    } else {
        1
    }
}

/// Social Recovery - Step 1: Propose 32-byte PQ recovery owner (`caller()` must be PQ guardian).
/// `calldata()`: `new_owner (32B)`.
#[no_mangle]
pub extern "C-unwind" fn initiate_recovery_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    let guardian = load_pq_addr(b"GUARDIAN");
    if who == [0u8; 32] || guardian == [0u8; 32] || who != guardian {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 32 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut new_owner = [0u8; 32];
    new_owner.copy_from_slice(&buf[..32]);
    if new_owner == [0u8; 32] {
        return ERR_INVALID_ARGUMENT;
    }

    let now = block_time();
    if now < 0 {
        return ERR_INVALID_ARGUMENT;
    }

    store_pq_addr(b"PEND_OWN", &new_owner);
    sstore(pq_meta_slot(b"REC_TIME", 0), now);

    emit(TOPIC_RECOVERY_INITIATED, 1);
    return_data(&new_owner);
    SUCCESS
}

/// Cancel a pending PQ social recovery (Owner veto right: `caller()` must be PQ owner).
#[no_mangle]
pub extern "C-unwind" fn cancel_recovery_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    let owner = load_pq_owner();
    if who == [0u8; 32] || owner == [0u8; 32] || who != owner {
        return ERR_UNAUTHORIZED;
    }

    store_pq_addr(b"PEND_OWN", &[0u8; 32]);
    sstore(pq_meta_slot(b"REC_TIME", 0), 0);
    emit(TOPIC_RECOVERY_CANCELLED, 0);
    SUCCESS
}

/// Social Recovery - Step 2: Finalize PQ recovery once `RECOVERY_TIMELOCK_SECS` (72h) has elapsed.
#[no_mangle]
pub extern "C-unwind" fn finalize_recovery_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    if caller() == [0u8; 32] {
        return ERR_UNAUTHORIZED;
    }

    let pending = load_pq_addr(b"PEND_OWN");
    if pending == [0u8; 32] {
        return ERR_NOT_FOUND;
    }

    let init_time = sload(pq_meta_slot(b"REC_TIME", 0));
    let now = block_time();
    let Some(unlock_time) = init_time.checked_add(RECOVERY_TIMELOCK_SECS) else {
        return ERR_OVERFLOW;
    };
    if now < 0 || now < unlock_time {
        return ERR_INVALID_ARGUMENT;
    }

    store_pq_owner(&pending);
    store_pq_addr(b"PEND_OWN", &[0u8; 32]);
    sstore(pq_meta_slot(b"REC_TIME", 0), 0);
    store_pq_addr(b"TENANT__", &[0u8; 32]);
    sstore(pq_meta_slot(b"RNT_DEAD", 0), 0);

    emit(TOPIC_RECOVERY_EXECUTED, 1);
    return_data(&pending);
    SUCCESS
}

/// Query 32-byte PQ pending recovery owner (`return_data` = 32B addr; returns 1 if set, 0 otherwise).
#[no_mangle]
pub extern "C-unwind" fn get_pending_owner_pq(_arg: i64) -> i64 {
    let pending = load_pq_addr(b"PEND_OWN");
    return_data(&pending);
    if pending == [0u8; 32] {
        0
    } else {
        1
    }
}

/// Delegate usage rights to a 32-byte PQ tenant (`caller()` must be PQ owner).
/// `calldata()`: `tenant (32B) || duration_hours (8B LE u64)`.
#[no_mangle]
pub extern "C-unwind" fn set_tenant_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    let owner = load_pq_owner();
    if who == [0u8; 32] || owner == [0u8; 32] || who != owner {
        return ERR_UNAUTHORIZED;
    }

    let mut buf = [0u8; 64];
    let n = calldata(&mut buf);
    if n != 40 {
        return ERR_INVALID_ARGUMENT;
    }
    let mut tenant = [0u8; 32];
    tenant.copy_from_slice(&buf[..32]);
    let Ok(duration_hours) = i64::try_from(read_u64_le(&buf[32..40])) else {
        return ERR_OVERFLOW;
    };
    if tenant == [0u8; 32] || duration_hours <= 0 || duration_hours > 8760 {
        return ERR_INVALID_ARGUMENT;
    }

    let now = block_time();
    if now < 0 {
        return ERR_INVALID_ARGUMENT;
    }
    let Some(duration_secs) = duration_hours.checked_mul(3600) else {
        return ERR_OVERFLOW;
    };
    let Some(deadline) = now.checked_add(duration_secs) else {
        return ERR_OVERFLOW;
    };

    store_pq_addr(b"TENANT__", &tenant);
    sstore(pq_meta_slot(b"RNT_DEAD", 0), deadline);

    emit(TOPIC_RENTAL_STARTED, 1);
    return_data(&deadline.to_le_bytes());
    SUCCESS
}

/// Revoke active PQ rental (`caller()` must be PQ owner).
#[no_mangle]
pub extern "C-unwind" fn revoke_rental_pq(_arg: i64) -> i64 {
    if sload(SLOT_INITIALIZED) == 0 || sload(SLOT_PQ_MODE) == 0 {
        return ERR_UNAUTHORIZED;
    }
    let who = caller();
    let owner = load_pq_owner();
    if who == [0u8; 32] || owner == [0u8; 32] || who != owner {
        return ERR_UNAUTHORIZED;
    }

    store_pq_addr(b"TENANT__", &[0u8; 32]);
    sstore(pq_meta_slot(b"RNT_DEAD", 0), 0);
    emit(TOPIC_RENTAL_ENDED, 0);
    SUCCESS
}

/// Query active 32-byte PQ tenant (`return_data` = 32B tenant or zero; returns 1 if active, 0 otherwise).
#[no_mangle]
pub extern "C-unwind" fn get_active_tenant_pq(_arg: i64) -> i64 {
    let deadline = sload(pq_meta_slot(b"RNT_DEAD", 0));
    let now = block_time();
    if deadline == 0 || now < 0 || now >= deadline {
        return_data(&[0u8; 32]);
        return 0;
    }
    let tenant = load_pq_addr(b"TENANT__");
    return_data(&tenant);
    if tenant == [0u8; 32] {
        0
    } else {
        1
    }
}

/// Query whether a PQ rental is currently active (`1`) or expired/unset (`0`).
#[no_mangle]
pub extern "C-unwind" fn is_rental_active_pq(_arg: i64) -> i64 {
    let deadline = sload(pq_meta_slot(b"RNT_DEAD", 0));
    let now = block_time();
    if deadline == 0 || now < 0 || now >= deadline {
        return 0;
    }
    if load_pq_addr(b"TENANT__") == [0u8; 32] {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum_contract_sdk::{
        get_mock_return_data, id_to_caller, reset_mock_state, set_mock_block_time,
        set_mock_calldata, set_mock_caller,
    };

    #[test]
    fn test_account_object_lifecycle() {
        reset_mock_state();
        assert_eq!(init(42), 42);
        assert_eq!(get_owner(0), 42);
        assert_eq!(get_guardian(0), 0);

        // Rotate guardian: owner 42 authorizes guardian 777
        set_mock_caller(id_to_caller(42));
        assert_eq!(rotate_guardian(42 * 10_000_000_000 + 777), 777);
        assert_eq!(get_guardian(0), 777);

        // Social recovery: guardian 777 proposes new owner 888 at deterministic block_time
        set_mock_block_time(1_750_000_000);
        set_mock_caller(id_to_caller(777));
        assert_eq!(initiate_recovery(777 * 10_000_000_000 + 888), 888);
        assert_eq!(get_pending_owner(0), 888);

        // Finalize recovery after timelock (72 hours elapsed on host block_time)
        let now = 1_750_000_000 + RECOVERY_TIMELOCK_SECS + 1;
        set_mock_block_time(now);
        assert_eq!(finalize_recovery(now), 888);
        assert_eq!(get_owner(0), 888);

        // Transfer ownership: owner 888 transfers to 999
        set_mock_caller(id_to_caller(888));
        assert_eq!(transfer_ownership(888 * 10_000_000_000 + 999), 999);
        assert_eq!(get_owner(0), 999);

        // Set tenant: owner 999 delegates to tenant 555 for 168 hours
        let ref_now = 1_750_000_000;
        set_mock_block_time(ref_now);
        set_mock_caller(id_to_caller(999));
        let rent_arg = 999 * 10_000_000_000 + 555 * 10_000 + 168;
        assert_eq!(set_tenant(rent_arg), 555);

        set_mock_block_time(ref_now + 3600);
        assert_eq!(get_active_tenant(ref_now + 3600), 555);
        assert_eq!(is_rental_active(ref_now + 3600), 1);

        // Auto-reclaim after deadline
        let after_deadline = ref_now + (168 * 3600) + 1;
        set_mock_block_time(after_deadline);
        assert_eq!(get_active_tenant(after_deadline), 0);
        assert_eq!(is_rental_active(after_deadline), 0);

        // Create Session 1: budget 50,000
        let s_arg = 10_000_000_000 + 10 * 100_000 + 50_000;
        assert_eq!(create_session(s_arg), 1);
        assert_eq!(is_session_active(1), 1);
        assert_eq!(get_session_budget(1), 50_000);

        // Spend 12,000 -> 38,000 left
        assert_eq!(spend_with_session(1_000_000 + 12_000), 38_000);
        assert_eq!(get_session_budget(1), 38_000);

        // Reduce budget from 50,000 to 20,000 (spent is 12,000, so 8,000 left)
        let reduce_arg = 10_000_000_000 + 20_000;
        assert_eq!(update_session_budget(reduce_arg), 8_000);
        assert_eq!(get_session_budget(1), 8_000);

        // Revoke
        assert_eq!(revoke_session(1), 1);
        assert_eq!(is_session_active(1), 0);
    }

    #[test]
    fn test_pq_account_and_session_auth() {
        reset_mock_state();
        let owner = [0x42u8; 32];
        let delegate = [0xD1u8; 32];
        let stranger = [0xEEu8; 32];

        // Zero caller cannot init
        assert_eq!(init_pq(0), ERR_UNAUTHORIZED);

        // Owner initializes
        set_mock_caller(owner);
        assert_eq!(init_pq(0), SUCCESS);
        assert_eq!(init_pq(0), ERR_ALREADY_EXISTS);
        assert_eq!(get_owner_pq(0), 1);
        assert_eq!(get_mock_return_data(), owner);

        // Stranger cannot create a session
        let mut create_cd = [0u8; 48];
        create_cd[..8].copy_from_slice(&1u64.to_le_bytes());
        create_cd[8..40].copy_from_slice(&delegate);
        create_cd[40..48].copy_from_slice(&50_000u64.to_le_bytes());
        set_mock_caller(stranger);
        set_mock_calldata(&create_cd);
        assert_eq!(create_session_pq(0), ERR_UNAUTHORIZED);

        // Owner creates session 1 for delegate with 50,000 budget
        set_mock_caller(owner);
        set_mock_calldata(&create_cd);
        assert_eq!(create_session_pq(0), SUCCESS);

        set_mock_calldata(&1u64.to_le_bytes());
        assert_eq!(is_session_active_pq(0), 1);
        assert_eq!(get_session_budget_pq(0), 50_000);

        // Bearer-token gap closed: stranger cannot spend with session 1!
        let mut spend_cd = [0u8; 16];
        spend_cd[..8].copy_from_slice(&1u64.to_le_bytes());
        spend_cd[8..16].copy_from_slice(&12_000u64.to_le_bytes());
        set_mock_caller(stranger);
        set_mock_calldata(&spend_cd);
        assert_eq!(spend_with_session_pq(0), ERR_UNAUTHORIZED);

        // Designated delegate spends 12,000 -> 38,000 left
        set_mock_caller(delegate);
        set_mock_calldata(&spend_cd);
        assert_eq!(spend_with_session_pq(0), 38_000);

        // Stranger cannot revoke session 1
        set_mock_caller(stranger);
        set_mock_calldata(&1u64.to_le_bytes());
        assert_eq!(revoke_session_pq(0), ERR_UNAUTHORIZED);

        // Owner revokes session 1 -> delegate can no longer spend or recreate
        set_mock_caller(owner);
        set_mock_calldata(&1u64.to_le_bytes());
        assert_eq!(revoke_session_pq(0), SUCCESS);
        assert_eq!(is_session_active_pq(0), 0);

        set_mock_caller(delegate);
        set_mock_calldata(&spend_cd);
        assert_eq!(spend_with_session_pq(0), ERR_UNAUTHORIZED);

        set_mock_caller(owner);
        set_mock_calldata(&create_cd);
        assert_eq!(create_session_pq(0), ERR_UNAUTHORIZED);
    }

    #[test]
    fn test_pq_init_blocks_unauthenticated_legacy_session_entrypoints() {
        reset_mock_state();
        let owner = [0x11u8; 32];
        set_mock_caller(owner);
        assert_eq!(init_pq(0), SUCCESS);

        let packed_create = 1 * 10_000_000_000 + 7 * 100_000 + 50_000;
        let create_res = std::panic::catch_unwind(|| create_session(packed_create));
        assert!(
            create_res.is_err(),
            "legacy create_session must refuse on PQ-initialized account"
        );
        let spend_res = std::panic::catch_unwind(|| spend_with_session(1_000_000 + 10));
        assert!(
            spend_res.is_err(),
            "legacy spend_with_session must refuse on PQ-initialized account"
        );
        let revoke_res = std::panic::catch_unwind(|| revoke_session(1));
        assert!(
            revoke_res.is_err(),
            "legacy revoke_session must refuse on PQ-initialized account"
        );
        let update_res = std::panic::catch_unwind(|| update_session_budget(10_000_000_000 + 10));
        assert!(
            update_res.is_err(),
            "legacy update_session_budget must refuse on PQ-initialized account"
        );
        assert!(std::panic::catch_unwind(|| transfer_ownership(10_000_000_000 + 2)).is_err());
        assert!(std::panic::catch_unwind(|| rotate_guardian(10_000_000_000 + 2)).is_err());
        assert!(std::panic::catch_unwind(|| initiate_recovery(10_000_000_000 + 2)).is_err());
        assert!(std::panic::catch_unwind(|| cancel_recovery(1)).is_err());
        assert!(std::panic::catch_unwind(|| finalize_recovery(0)).is_err());
        assert!(
            std::panic::catch_unwind(|| set_tenant(10_000_000_000 + 2 * 10_000 + 1)).is_err()
        );
        assert!(std::panic::catch_unwind(|| revoke_rental(1)).is_err());

        assert_eq!(get_owner(0), ERR_UNAUTHORIZED);
        assert_eq!(get_guardian(0), ERR_UNAUTHORIZED);
        assert_eq!(get_pending_owner(0), ERR_UNAUTHORIZED);
        assert_eq!(get_active_tenant(0), ERR_UNAUTHORIZED);
        assert_eq!(is_rental_active(0), ERR_UNAUTHORIZED);
        assert_eq!(is_session_active(1), ERR_UNAUTHORIZED);
        assert_eq!(get_session_budget(1), ERR_UNAUTHORIZED);
    }

    #[test]
    fn test_pq_lifecycle_ownership_guardian_recovery_rental_and_budget() {
        reset_mock_state();
        let owner1 = [0x11u8; 32];
        let owner2 = [0x22u8; 32];
        let guardian = [0x33u8; 32];
        let tenant = [0x44u8; 32];
        let delegate = [0x55u8; 32];
        let stranger = [0xEEu8; 32];

        set_mock_caller(owner1);
        assert_eq!(init_pq(0), SUCCESS);
        assert_eq!(get_guardian_pq(0), 0);
        assert_eq!(get_pending_owner_pq(0), 0);
        assert_eq!(is_rental_active_pq(0), 0);

        // Stranger cannot rotate guardian.
        set_mock_caller(stranger);
        set_mock_calldata(&guardian);
        assert_eq!(rotate_guardian_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(get_guardian_pq(0), 0);

        // Owner1 rotates guardian.
        set_mock_caller(owner1);
        set_mock_calldata(&guardian);
        assert_eq!(rotate_guardian_pq(0), SUCCESS);
        assert_eq!(get_guardian_pq(0), 1);
        assert_eq!(get_mock_return_data(), guardian);

        // Social recovery: stranger cannot initiate; guardian initiates at t0.
        let t0 = 1_750_000_000i64;
        set_mock_block_time(t0);
        set_mock_caller(stranger);
        set_mock_calldata(&owner2);
        assert_eq!(initiate_recovery_pq(0), ERR_UNAUTHORIZED);

        set_mock_caller(guardian);
        set_mock_calldata(&owner2);
        assert_eq!(initiate_recovery_pq(0), SUCCESS);
        assert_eq!(get_pending_owner_pq(0), 1);
        assert_eq!(get_mock_return_data(), owner2);

        // Owner1 vetoes recovery.
        set_mock_caller(owner1);
        assert_eq!(cancel_recovery_pq(0), SUCCESS);
        assert_eq!(get_pending_owner_pq(0), 0);
        assert_eq!(finalize_recovery_pq(0), ERR_NOT_FOUND);

        // Guardian re-initiates recovery; premature finalize fails; finalize after 72h succeeds.
        set_mock_caller(guardian);
        set_mock_calldata(&owner2);
        assert_eq!(initiate_recovery_pq(0), SUCCESS);

        set_mock_block_time(t0 + RECOVERY_TIMELOCK_SECS - 1);
        assert_eq!(finalize_recovery_pq(0), ERR_INVALID_ARGUMENT);

        set_mock_block_time(t0 + RECOVERY_TIMELOCK_SECS);
        assert_eq!(finalize_recovery_pq(0), SUCCESS);
        assert_eq!(get_owner_pq(0), 1);
        assert_eq!(get_mock_return_data(), owner2);
        assert_eq!(get_pending_owner_pq(0), 0);

        // Owner2 sets tenant for 2 hours, verifies active/expiry/revoke.
        let mut rent_cd = [0u8; 40];
        rent_cd[..32].copy_from_slice(&tenant);
        rent_cd[32..40].copy_from_slice(&2u64.to_le_bytes());
        set_mock_caller(owner2);
        set_mock_calldata(&rent_cd);
        assert_eq!(set_tenant_pq(0), SUCCESS);
        assert_eq!(is_rental_active_pq(0), 1);
        assert_eq!(get_active_tenant_pq(0), 1);
        assert_eq!(get_mock_return_data(), tenant);

        set_mock_block_time(t0 + RECOVERY_TIMELOCK_SECS + 2 * 3600);
        assert_eq!(is_rental_active_pq(0), 0);
        assert_eq!(get_active_tenant_pq(0), 0);

        // Re-rent and explicitly revoke.
        set_mock_caller(owner2);
        set_mock_calldata(&rent_cd);
        assert_eq!(set_tenant_pq(0), SUCCESS);
        assert_eq!(is_rental_active_pq(0), 1);
        assert_eq!(revoke_rental_pq(0), SUCCESS);
        assert_eq!(is_rental_active_pq(0), 0);

        // Session budget update: create session 5 with 10_000, spend 2_500, reduce to 6_000.
        let mut sess_cd = [0u8; 48];
        sess_cd[..8].copy_from_slice(&5u64.to_le_bytes());
        sess_cd[8..40].copy_from_slice(&delegate);
        sess_cd[40..48].copy_from_slice(&10_000u64.to_le_bytes());
        set_mock_caller(owner2);
        set_mock_calldata(&sess_cd);
        assert_eq!(create_session_pq(0), SUCCESS);

        let mut spend_cd = [0u8; 16];
        spend_cd[..8].copy_from_slice(&5u64.to_le_bytes());
        spend_cd[8..16].copy_from_slice(&2_500u64.to_le_bytes());
        set_mock_caller(delegate);
        set_mock_calldata(&spend_cd);
        assert_eq!(spend_with_session_pq(0), 7_500);

        // Inflation or below-spent refused; stranger refused; valid reduction succeeds.
        let mut upd_cd = [0u8; 16];
        upd_cd[..8].copy_from_slice(&5u64.to_le_bytes());
        upd_cd[8..16].copy_from_slice(&12_000u64.to_le_bytes());
        set_mock_caller(owner2);
        set_mock_calldata(&upd_cd);
        assert_eq!(update_session_budget_pq(0), ERR_UNAUTHORIZED);

        upd_cd[8..16].copy_from_slice(&2_000u64.to_le_bytes());
        set_mock_calldata(&upd_cd);
        assert_eq!(update_session_budget_pq(0), ERR_INVALID_ARGUMENT);

        upd_cd[8..16].copy_from_slice(&6_000u64.to_le_bytes());
        set_mock_caller(stranger);
        set_mock_calldata(&upd_cd);
        assert_eq!(update_session_budget_pq(0), ERR_UNAUTHORIZED);

        set_mock_caller(delegate);
        set_mock_calldata(&upd_cd);
        assert_eq!(update_session_budget_pq(0), 3_500);
        set_mock_calldata(&5u64.to_le_bytes());
        assert_eq!(get_session_budget_pq(0), 3_500);

        // Transfer ownership from owner2 back to owner1.
        set_mock_caller(stranger);
        set_mock_calldata(&owner1);
        assert_eq!(transfer_ownership_pq(0), ERR_UNAUTHORIZED);
        set_mock_caller(owner2);
        set_mock_calldata(&owner1);
        assert_eq!(transfer_ownership_pq(0), SUCCESS);
        assert_eq!(get_owner_pq(0), 1);
        assert_eq!(get_mock_return_data(), owner1);
    }

    #[test]
    fn test_create_session_pq_count_overflow() {
        reset_mock_state();
        let owner = [0x11u8; 32];
        let delegate = [0x22u8; 32];
        set_mock_caller(owner);
        assert_eq!(init_pq(0), SUCCESS);

        sstore(SLOT_SESSIONS_COUNT, i64::MAX);
        let mut create_cd = [0u8; 48];
        create_cd[..8].copy_from_slice(&1u64.to_le_bytes());
        create_cd[8..40].copy_from_slice(&delegate);
        create_cd[40..48].copy_from_slice(&500u64.to_le_bytes());
        set_mock_calldata(&create_cd);
        assert_eq!(create_session_pq(0), ERR_OVERFLOW);

        set_mock_calldata(&1u64.to_le_bytes());
        assert_eq!(is_session_active_pq(0), 0);
    }

    #[test]
    fn test_legacy_init_blocks_pq_entrypoints_and_budget_return_data_parity() {
        reset_mock_state();
        assert_eq!(init(42), 42);

        let caller_addr = [0xAAu8; 32];
        let delegate = [0xBBu8; 32];
        set_mock_caller(caller_addr);

        let mut create_cd = [0u8; 48];
        create_cd[..8].copy_from_slice(&1u64.to_le_bytes());
        create_cd[8..40].copy_from_slice(&delegate);
        create_cd[40..48].copy_from_slice(&1_000u64.to_le_bytes());
        set_mock_calldata(&create_cd);
        assert_eq!(create_session_pq(0), ERR_UNAUTHORIZED);

        let mut spend_cd = [0u8; 16];
        spend_cd[..8].copy_from_slice(&1u64.to_le_bytes());
        spend_cd[8..16].copy_from_slice(&100u64.to_le_bytes());
        set_mock_calldata(&spend_cd);
        assert_eq!(spend_with_session_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(update_session_budget_pq(0), ERR_UNAUTHORIZED);

        set_mock_calldata(&1u64.to_le_bytes());
        assert_eq!(revoke_session_pq(0), ERR_UNAUTHORIZED);

        set_mock_calldata(&delegate);
        assert_eq!(transfer_ownership_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(rotate_guardian_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(initiate_recovery_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(cancel_recovery_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(finalize_recovery_pq(0), ERR_UNAUTHORIZED);

        let mut rent_cd = [0u8; 40];
        rent_cd[..32].copy_from_slice(&delegate);
        rent_cd[32..40].copy_from_slice(&2u64.to_le_bytes());
        set_mock_calldata(&rent_cd);
        assert_eq!(set_tenant_pq(0), ERR_UNAUTHORIZED);
        assert_eq!(revoke_rental_pq(0), ERR_UNAUTHORIZED);

        // get_session_budget_pq emits 0i64.to_le_bytes() for missing/invalid/revoked sessions.
        reset_mock_state();
        set_mock_caller(caller_addr);
        assert_eq!(init_pq(0), SUCCESS);

        return_data(&999i64.to_le_bytes());
        set_mock_calldata(&0u64.to_le_bytes());
        assert_eq!(get_session_budget_pq(0), 0);
        assert_eq!(get_mock_return_data(), 0i64.to_le_bytes());

        return_data(&999i64.to_le_bytes());
        set_mock_calldata(&77u64.to_le_bytes());
        assert_eq!(get_session_budget_pq(0), 0);
        assert_eq!(get_mock_return_data(), 0i64.to_le_bytes());

        set_mock_calldata(&create_cd);
        assert_eq!(create_session_pq(0), SUCCESS);
        set_mock_calldata(&1u64.to_le_bytes());
        assert_eq!(revoke_session_pq(0), SUCCESS);
        return_data(&999i64.to_le_bytes());
        set_mock_calldata(&1u64.to_le_bytes());
        assert_eq!(get_session_budget_pq(0), 0);
        assert_eq!(get_mock_return_data(), 0i64.to_le_bytes());
    }
}
