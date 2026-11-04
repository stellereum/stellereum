//! Gas-griefing in the orderbook: a single order can match against an unbounded
//! number of price levels for a FIXED gas cost. This is a DoS vector: an attacker
//! fills the book with tiny orders, then submits one large market order whose
//! matching work is O(levels) but is charged a flat fee.
//!
//! The defense is to bound the work a single order may perform per VM call
//! (a "match budget"), charge gas per level crossed, and cap book depth.

use std::collections::HashMap;
use stellereum::orderbook::{OrderSide, OrderType, OrderbookActor};
use stellereum::svm::{OpCode, Svm, VmContext, VmExecutionResult, GAS_ORDER_PLACE};

fn addr(n: u8) -> [u8; 32] {
    [n; 32]
}

/// A market order crossing N price levels does O(N) matching work.
#[test]
fn market_order_crosses_many_levels_in_one_call() {
    let mut book = OrderbookActor::new(1, 10_000);

    // Attacker seeds 500 distinct ask levels, 1 unit each.
    for i in 0..500u64 {
        book.submit_order(addr(1), OrderSide::Sell, 100 + i, 1, i);
    }
    assert_eq!(book.depth().1, 500, "500 ask levels seeded");

    // One large market buy sweeps all of them in a single submit.
    let (_order, trades) = book.submit_order_ext(
        addr(2),
        OrderSide::Buy,
        OrderType::Market,
        u64::MAX,
        500,
        1000,
    );
    let levels_crossed = trades.len();
    assert_eq!(
        levels_crossed, 500,
        "one order crossed 500 levels — O(levels) work"
    );
    // Gas for the whole sweep is a FLAT GAS_ORDER_PLACE regardless of 500 levels.
    assert_eq!(
        GAS_ORDER_PLACE, 1_200,
        "flat fee independent of matched levels (griefing)"
    );
}

/// DEFENSE: gas now scales with the number of levels matched, so a deep sweep
/// costs proportionally more — griefing is no longer free.
#[test]
fn svm_gas_scales_with_match_depth() {
    fn run(nlevels: u64) -> u64 {
        let mut books: HashMap<u32, OrderbookActor> = HashMap::new();
        let mut seed = OrderbookActor::new(1, 20_000);
        for i in 0..nlevels {
            seed.submit_order(addr(1), OrderSide::Sell, 100 + i, 1, i);
        }
        books.insert(1, seed);

        let mut ctx = VmContext {
            sender: addr(2),
            balance: u64::MAX,
            orderbooks: Some(&mut books),
            patricia_trie: None,
            session_auth: None,
            session_keys: None,
            pmm: None,
            zkml_proof: None,
            timestamp: 1,
            trades: Vec::new(),
            transfers: Vec::new(),
            token_registry: None,
            token_events: Vec::new(),
            contracts: None,
            staking: None,
            min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
            default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
            payouts: Vec::new(),
            oracle: None,
        };
        let ops = vec![
            OpCode::SysCallPlaceOrder {
                pair_id: 1,
                is_buy: true,
                price: u64::MAX,
                amount: nlevels,
            },
            OpCode::Halt,
        ];
        match Svm::execute(&ops, 10_000_000, &mut ctx) {
            VmExecutionResult::Success { gas_used, .. } => gas_used,
            other => panic!("unexpected: {other:?}"),
        }
    }

    let g_small = run(1);
    let g_large = run(40);
    assert!(
        g_large > g_small,
        "gas must scale with levels matched (small={g_small}, large={g_large})"
    );
}

/// DEFENSE: an order cannot cross more than MAX_MATCH_LEVELS in one call.
#[test]
fn svm_match_levels_are_capped() {
    let mut books: HashMap<u32, OrderbookActor> = HashMap::new();
    let mut seed = OrderbookActor::new(1, 20_000);
    for i in 0..500u64 {
        seed.submit_order(addr(1), OrderSide::Sell, 100 + i, 1, i);
    }
    books.insert(1, seed);

    let mut ctx = VmContext {
        sender: addr(2),
        balance: u64::MAX,
        orderbooks: Some(&mut books),
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1,
        trades: Vec::new(),
        transfers: Vec::new(),
        token_registry: None,
        token_events: Vec::new(),
        contracts: None,
        staking: None,
        min_validator_bond: stellereum::staking::MIN_VALIDATOR_BOND,
        default_commission_bps: stellereum::staking::DEFAULT_COMMISSION_BPS,
        payouts: Vec::new(),
        oracle: None,
    };
    let ops = vec![
        OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price: u64::MAX,
            amount: 500,
        },
        OpCode::Halt,
    ];
    match Svm::execute(&ops, 10_000_000, &mut ctx) {
        VmExecutionResult::Success { .. } => {
            assert!(
                ctx.trades.len() <= stellereum::svm::MAX_MATCH_LEVELS,
                "matching must be capped at {} levels, got {}",
                stellereum::svm::MAX_MATCH_LEVELS,
                ctx.trades.len()
            );
        }
        other => panic!("unexpected: {other:?}"),
    }
}

/// Defense check: the book enforces a depth cap, so an attacker cannot grow an
/// unbounded number of levels (which would make the sweep arbitrarily expensive).
#[test]
fn depth_cap_bounds_attacker_levels() {
    let cap = 64;
    let mut book = OrderbookActor::new(1, cap);
    for i in 0..10_000u64 {
        book.submit_order(addr(1), OrderSide::Sell, 100 + i, 1, i);
    }
    let asks = book.depth().1;
    assert!(
        asks <= cap,
        "depth cap must bound ask levels to {cap}, got {asks}"
    );
}
