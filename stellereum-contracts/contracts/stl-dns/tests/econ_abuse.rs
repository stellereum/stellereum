//! HDAE economic-abuse pentest for STL-DNS (read-only vs program).
//! All attacks DEFEATED: no expiry surface, no transfer-then-bid,
//! owner-zero stays pinned, bids monotonic, fail-closed edges.

use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_INVALID_ARGUMENT, SUCCESS,
};
use stl_dns::{
    finalize_auction, get_min_bid, init, place_bid, resolve, set_target, start_auction, transfer,
};

fn start(domain: i64, bidder: i64, len: i64) -> i64 {
    domain * 10_000_000_000 + bidder * 100_000 + len
}
fn bid(domain: i64, bidder: i64) -> i64 {
    domain * 10_000_000_000 + bidder * 10_000 + 1
}
fn xfer(domain: i64, caller: i64, new_owner: i64) -> i64 {
    domain * 10_000_000_000 + caller * 100_000 + new_owner
}

/// (3a) Owner-zero re-verified: transfer to 0 refused, domain unmoved.
/// DEFEATED.
#[test]
fn owner_zero_transfer_refused() {
    reset_mock_state();
    assert_eq!(init(99), 0);
    let domain: i64 = 2002;
    assert_eq!(start_auction(start(domain, 10, 4)), domain);
    assert_eq!(finalize_auction(domain), 1);
    set_mock_caller(id_to_caller(10));
    assert_eq!(transfer(xfer(domain, 10, 0)), ERR_INVALID_ARGUMENT);
    assert_eq!(resolve(domain), 10);
    assert_eq!(transfer(xfer(domain, 10, 20)), SUCCESS);
    assert_eq!(resolve(domain), 20);
}

/// (3b) Transfer-then-bid / bid-then-transfer games: state machine is
/// strict — bids only in AUCTION, transfers only in REGISTERED.
/// DEFEATED.
#[test]
fn transfer_then_bid_games_rejected() {
    reset_mock_state();
    assert_eq!(init(99), 0);
    let domain: i64 = 3003;
    assert_eq!(start_auction(start(domain, 10, 4)), domain);
    // Cannot transfer mid-auction (not registered yet).
    set_mock_caller(id_to_caller(10));
    assert_eq!(transfer(xfer(domain, 10, 20)), ERR_INVALID_ARGUMENT);
    // Bids work mid-auction and move the lead.
    assert_eq!(place_bid(bid(domain, 20)), 220);
    assert_eq!(finalize_auction(domain), 1);
    assert_eq!(resolve(domain), 20);
    // Cannot bid after finalization (no longer an auction).
    assert_eq!(place_bid(bid(domain, 30)), ERR_INVALID_ARGUMENT);
    assert_eq!(resolve(domain), 20);
    // Owner transfer after finalization works; double-finalize refused.
    set_mock_caller(id_to_caller(20));
    assert_eq!(transfer(xfer(domain, 20, 30)), SUCCESS);
    assert_eq!(resolve(domain), 30);
    assert_eq!(finalize_auction(domain), ERR_INVALID_ARGUMENT);
}

/// (3c) Expiry-edge: contract has NO expiry/timestamp field — there is no
/// deadline to race, front-run, or snipe. Auctions stay open until
/// finalized; resolve returns 0 until then. Pinned as absent surface.
/// DEFEATED (vacuous — no code to exploit).
#[test]
fn no_expiry_surface_pending_auction_unresolvable() {
    reset_mock_state();
    assert_eq!(init(99), 0);
    let domain: i64 = 4004;
    assert_eq!(start_auction(start(domain, 10, 9)), domain);
    // Pending auction: unresolvable regardless of "time" (no clock input).
    assert_eq!(resolve(domain), 0);
    assert_eq!(place_bid(bid(domain, 11)), 16);
    assert_eq!(resolve(domain), 0, "still pending until finalize");
    assert_eq!(finalize_auction(domain), 1);
    assert_eq!(resolve(domain), 11);
}

/// (3d) Bid monotonicity: every counter-bid raises >=10% (min +1);
/// repeated bidding converges upward, never lets a late bidder steal at
/// the floor. DEFEATED.
#[test]
fn bids_monotonic_min_raise() {
    reset_mock_state();
    assert_eq!(init(99), 0);
    let domain: i64 = 5005;
    assert_eq!(start_auction(start(domain, 10, 4)), domain); // floor 200
    let b1 = place_bid(bid(domain, 11));
    assert_eq!(b1, 220);
    let b2 = place_bid(bid(domain, 12));
    assert_eq!(b2, 242); // 220 + 22
    let b3 = place_bid(bid(domain, 13));
    assert_eq!(b3, 266); // 242 + 24
    assert!(b3 > b2 && b2 > b1);
}

/// (5) Overflow / bounds edges: bad lengths fail closed at the grid
/// (`get_min_bid` returns -1; `start_auction` traps without creating an
/// auction — trap not executed here since `extern "C"` cannot be caught
/// in-process); zero-domain guards hold. DEFEATED.
#[test]
fn overflow_and_bounds_fail_closed() {
    // Length grid fail-closed pins (the trap leg mirrors these).
    assert_eq!(get_min_bid(3), -1);
    assert_eq!(get_min_bid(127), -1);
    assert_eq!(get_min_bid(4), 200);
    reset_mock_state();
    assert_eq!(init(99), 0);
    // No auction exists for the never-started domain.
    assert_eq!(resolve(6006), 0);
    // Zero-domain guards on value-adjacent entries.
    set_mock_caller(id_to_caller(10));
    assert_eq!(transfer(10 * 100_000 + 20), ERR_INVALID_ARGUMENT);
    assert_eq!(set_target(10 * 100_000 + 20), ERR_INVALID_ARGUMENT);
}
