//! SVM atomicity tests: orderbook mutations must roll back on VM revert,
//! exactly like token mutations. A failed transaction must leave NO side effects.

use std::collections::HashMap;
use stellereum::orderbook::OrderbookActor;
use stellereum::svm::{OpCode, Svm, VmContext, VmExecutionResult};

fn ctx_for<'a>(
    sender: [u8; 32],
    balance: u64,
    books: &'a mut HashMap<u32, OrderbookActor>,
) -> VmContext<'a> {
    VmContext {
        sender,
        balance,
        orderbooks: Some(books),
        patricia_trie: None,
        session_auth: None,
        session_keys: None,
        pmm: None,
        zkml_proof: None,
        timestamp: 1_000,
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
    }
}

/// A place-order followed by a revert must NOT leave the order in the book.
#[test]
fn order_placement_rolled_back_on_revert() {
    let sender = [1u8; 32];
    let mut books = HashMap::new();
    books.insert(1u32, OrderbookActor::new(1, 100));

    let mut ctx = ctx_for(sender, 1_000_000, &mut books);
    let ops = vec![
        OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price: 250_000,
            amount: 100,
        },
        // Force a revert: transfer far more than the balance
        OpCode::Transfer {
            recipient: [2u8; 32],
            amount: 9_999_999,
        },
    ];
    let res = Svm::execute(&ops, 500_000, &mut ctx);
    assert!(
        matches!(res, VmExecutionResult::Reverted(_)),
        "tx must revert"
    );

    let book = books.get(&1).unwrap();
    assert_eq!(
        book.depth(),
        (0, 0),
        "reverted tx must NOT leave a placed order in the orderbook (atomicity)"
    );
}

/// On success, the order must persist.
#[test]
fn order_placement_persisted_on_success() {
    let sender = [1u8; 32];
    let mut books = HashMap::new();
    books.insert(1u32, OrderbookActor::new(1, 100));

    let mut ctx = ctx_for(sender, 1_000_000, &mut books);
    let ops = vec![
        OpCode::SysCallPlaceOrder {
            pair_id: 1,
            is_buy: true,
            price: 250_000,
            amount: 100,
        },
        OpCode::Halt,
    ];
    let res = Svm::execute(&ops, 500_000, &mut ctx);
    assert!(matches!(res, VmExecutionResult::Success { .. }));

    let book = books.get(&1).unwrap();
    assert_eq!(book.depth().0, 1, "successful tx must persist the order");
}

/// A cancel-order followed by a revert must NOT remove the order.
#[test]
fn order_cancel_rolled_back_on_revert() {
    let sender = [1u8; 32];
    let mut books = HashMap::new();
    let mut book = OrderbookActor::new(1, 100);
    // Pre-place an order directly (simulating prior state)
    let (order, _) = book.submit_order(
        sender,
        stellereum::orderbook::OrderSide::Buy,
        250_000,
        100,
        1,
    );
    books.insert(1u32, book);
    let order_id = order.order_id;

    let mut ctx = ctx_for(sender, 1_000_000, &mut books);
    let ops = vec![
        OpCode::SysCallCancelOrder { order_id },
        // Force a revert
        OpCode::Transfer {
            recipient: [2u8; 32],
            amount: 9_999_999,
        },
    ];
    let res = Svm::execute(&ops, 500_000, &mut ctx);
    assert!(
        matches!(res, VmExecutionResult::Reverted(_)),
        "tx must revert"
    );

    let book = books.get(&1).unwrap();
    assert_eq!(
        book.depth().0,
        1,
        "reverted tx must NOT cancel an order (atomicity)"
    );
    let book = books.get_mut(&1).unwrap();
    assert!(
        book.cancel_order(order_id).is_some(),
        "order must still exist"
    );
}
