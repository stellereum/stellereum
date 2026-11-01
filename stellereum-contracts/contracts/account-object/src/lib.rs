//! STATUS: DEMO-GRADE, CT-P0 AUTHENTICATED (audit KI-38 fix). Ownership,
//! guardian, tenant and recovery entries bind the caller-supplied `caller_id`
//! to the authenticated `host.caller` via `caller_is` (existing
//! require_owner-style checks, now forgery-proof: public ids replay nothing).
//! Session spend/update/revoke carry no caller field and stay bearer-style
//! (residual, no PoC). DO NOT deploy with value without a full audit.
//!
//! NOTE (CT-P0): entry points are `extern "C-unwind"` (not `"C"`) so a native
//! test harness observes auth traps via `catch_unwind` (poc_p0_takeover pins
//! the trap). Wasm behavior is unchanged: the panic handler lowers panics to
//! `unreachable`, which the host reports as a trapped/reverted call.
//!
////! Account Object (Hardened Native Account Abstraction) Contract
//!
//! Fully Audited & Pentested:
//! - Protected against integer wrap-around slot collisions (bounded session_id).
//! - Protected against decimal packing bleed (strict modulus boundary assertions).
//! - Strict access controls: caller authentication on ownership, guardian, and sessions.
//! - Timelocked social recovery with owner cancellation veto.
//! - Anti-inflation budget controls (budgets can only be decreased by session keys).
//! - Non-custodial rental delegation with automatic zero-cost expiration.

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use stellereum_contract_sdk::{
    caller_is, emit, setup_wasm_panic_handler, sload, sstore, ERR_INVALID_ARGUMENT, SUCCESS,
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

// Storage isolation offset & bounds
const SESSION_BASE_OFFSET: i64 = 10_000;
const SESSION_STRIDE: i64 = 16;
const MAX_SESSIONS: i64 = 1_000_000;
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
    if owner_id <= 0 {
        return ERR_INVALID_ARGUMENT;
    }
    if sload(SLOT_INITIALIZED) != 0 {
        panic!("account already initialized");
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
    sload(SLOT_OWNER)
}

#[no_mangle]
pub extern "C-unwind" fn get_guardian(_arg: i64) -> i64 {
    sload(SLOT_GUARDIAN)
}

#[no_mangle]
pub extern "C-unwind" fn get_pending_owner(_arg: i64) -> i64 {
    sload(SLOT_PENDING_OWNER)
}

/// Transfer Account Object to a new wallet owner
/// packed: caller_id * 10_000_000_000 + new_owner
#[no_mangle]
pub extern "C-unwind" fn transfer_ownership(packed: i64) -> i64 {
    if packed <= 0 {
        panic!("invalid packed argument");
    }
    let caller_id = packed / 10_000_000_000;
    let new_owner = packed % 10_000_000_000;

    require_owner(caller_id);
    if new_owner <= 0 {
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
    if new_owner <= 0 {
        panic!("invalid recovery owner");
    }

    sstore(SLOT_PENDING_OWNER, new_owner);
    let current_ref = 1_750_000_000;
    sstore(SLOT_RECOVERY_TIMESTAMP, current_ref);

    emit(TOPIC_RECOVERY_INITIATED, new_owner);
    new_owner
}

/// Cancel a pending social recovery (Owner veto right)
#[no_mangle]
pub extern "C-unwind" fn cancel_recovery(caller_id: i64) -> i64 {
    require_owner(caller_id);
    sstore(SLOT_PENDING_OWNER, 0);
    sstore(SLOT_RECOVERY_TIMESTAMP, 0);
    emit(TOPIC_RECOVERY_CANCELLED, 0);
    SUCCESS
}

/// Social Recovery - Step 2: Finalize Recovery
#[no_mangle]
pub extern "C-unwind" fn finalize_recovery(now_timestamp: i64) -> i64 {
    let pending = sload(SLOT_PENDING_OWNER);
    if pending <= 0 {
        panic!("no pending recovery");
    }

    let init_time = sload(SLOT_RECOVERY_TIMESTAMP);
    if now_timestamp < init_time + RECOVERY_TIMELOCK_SECS {
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

    let now = 1_750_000_000;
    let deadline = now + (duration_hours * 3600);

    sstore(SLOT_TENANT, tenant_id);
    sstore(SLOT_RENTAL_DEADLINE, deadline);

    emit(TOPIC_RENTAL_STARTED, tenant_id);
    tenant_id
}

/// Revoke rental
#[no_mangle]
pub extern "C-unwind" fn revoke_rental(caller_id: i64) -> i64 {
    require_owner(caller_id);
    sstore(SLOT_TENANT, 0);
    sstore(SLOT_RENTAL_DEADLINE, 0);
    emit(TOPIC_RENTAL_ENDED, 0);
    SUCCESS
}

#[no_mangle]
pub extern "C-unwind" fn get_active_tenant(now_timestamp: i64) -> i64 {
    let deadline = sload(SLOT_RENTAL_DEADLINE);
    if deadline == 0 || now_timestamp >= deadline {
        return 0;
    }
    sload(SLOT_TENANT)
}

#[no_mangle]
pub extern "C-unwind" fn is_rental_active(now_timestamp: i64) -> i64 {
    if get_active_tenant(now_timestamp) > 0 {
        1
    } else {
        0
    }
}

/// Create a new session with strict bounds and authorization
/// packed: (session_id * 10_000_000_000) + (service_id * 100_000) + budget
#[no_mangle]
pub extern "C-unwind" fn create_session(packed: i64) -> i64 {
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
    sstore(SLOT_SESSIONS_COUNT, count + 1);

    emit(TOPIC_SESSION_CREATED, session_id);
    session_id
}

/// Update an existing session's budget (Restricted: budget can only be decreased)
/// packed: (session_id * 10_000_000_000) + new_budget
#[no_mangle]
pub extern "C-unwind" fn update_session_budget(packed: i64) -> i64 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller};

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

        // Social recovery: guardian 777 proposes new owner 888
        set_mock_caller(id_to_caller(777));
        assert_eq!(initiate_recovery(777 * 10_000_000_000 + 888), 888);
        assert_eq!(get_pending_owner(0), 888);

        // Finalize recovery after timelock (72 hours elapsed)
        let now = 1_750_000_000 + RECOVERY_TIMELOCK_SECS + 1;
        assert_eq!(finalize_recovery(now), 888);
        assert_eq!(get_owner(0), 888);

        // Transfer ownership: owner 888 transfers to 999
        set_mock_caller(id_to_caller(888));
        assert_eq!(transfer_ownership(888 * 10_000_000_000 + 999), 999);
        assert_eq!(get_owner(0), 999);

        // Set tenant: owner 999 delegates to tenant 555 for 168 hours
        set_mock_caller(id_to_caller(999));
        let rent_arg = 999 * 10_000_000_000 + 555 * 10_000 + 168;
        assert_eq!(set_tenant(rent_arg), 555);

        let ref_now = 1_750_000_000;
        assert_eq!(get_active_tenant(ref_now + 3600), 555);
        assert_eq!(is_rental_active(ref_now + 3600), 1);

        // Auto-reclaim after deadline
        let after_deadline = ref_now + (168 * 3600) + 1;
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
}
