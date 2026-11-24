//! W4 regression: `stl-dns` must reject `bidder_id >= 100_000` (and `0`) in
//! `place_bid` so winners are never locked out of `set_target`/`transfer`, and
//! `get_hue` must widen to `u128` so large `domain_id` values do not overflow.

use stellereum_contract_sdk::{
    id_to_caller, reset_mock_state, set_mock_caller, ERR_INVALID_ARGUMENT, SUCCESS,
};
use stl_dns::{
    finalize_auction, get_hue, init, place_bid, resolve, set_target, start_auction, transfer,
};

fn start_arg(domain: i64, bidder: i64, len: i64) -> i64 {
    domain * 10_000_000_000 + bidder * 100_000 + len
}

fn bid_arg(domain: i64, bidder: i64) -> i64 {
    domain * 10_000_000_000 + bidder * 10_000 + 1
}

fn owner_arg(domain: i64, caller: i64, target: i64) -> i64 {
    domain * 10_000_000_000 + caller * 100_000 + target
}

#[test]
fn w4_place_bid_rejects_unrepresentable_bidder_ids() {
    reset_mock_state();
    assert_eq!(init(99), SUCCESS);

    let domain: i64 = 1;
    assert_eq!(start_auction(start_arg(domain, 10, 4)), domain);

    // bidder_id >= 100_000 cannot be unpacked by set_target/transfer and must be rejected.
    assert_eq!(place_bid(bid_arg(domain, 100_000)), ERR_INVALID_ARGUMENT);
    assert_eq!(place_bid(bid_arg(domain, 999_999)), ERR_INVALID_ARGUMENT);
    assert_eq!(place_bid(bid_arg(domain, 0)), ERR_INVALID_ARGUMENT);

    // Max valid bidder_id (99_999) succeeds and remains controllable after finalization.
    assert_eq!(place_bid(bid_arg(domain, 99_999)), 220);
    assert_eq!(finalize_auction(domain), 1);
    assert_eq!(resolve(domain), 99_999);

    set_mock_caller(id_to_caller(99_999));
    assert_eq!(set_target(owner_arg(domain, 99_999, 777)), SUCCESS);
    assert_eq!(resolve(domain), 777);
    assert_eq!(transfer(owner_arg(domain, 99_999, 42)), SUCCESS);
    assert_eq!(resolve(domain), 42);
}

#[test]
fn w4_get_hue_u128_no_overflow_at_i64_max() {
    for domain_id in [134_654_811_482_267_517_i64, i64::MAX, -1_i64, i64::MIN] {
        let hue = get_hue(domain_id);
        assert!(
            (0..360).contains(&hue),
            "hue {hue} out of [0, 360) for domain_id={domain_id}"
        );
    }
    assert_eq!(get_hue(i64::MAX), 239);
}
