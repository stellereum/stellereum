//! P1 (d): live fee-market behaviour on full and overflowing blocks.
//!
//! There was no test that put pressure on the fee market at all. The one fee
//! test used a single transaction in a single block, the overflow test built
//! transactions with `gas_limit: 0` so the count cap fired and the gas cap was
//! never reached, and the anti-spam selector was documented as the producer's
//! tool while `propose()` never called it.
//!
//! Two properties are worth pinning, and one of them was a live bug:
//!
//! 1. A cheap flood cannot displace expensive transactions. Fee ordering already
//!    guarantees this, and it is worth having a test that says so.
//! 2. Transactions that cannot execute must not occupy the block. They used to:
//!    `propose()` used `select_bounded`, which only respected the caps, so a
//!    flood of spent-nonce transactions filled blocks and were paid for like
//!    real work. A zero base fee made that free.

use ed25519_dalek::SigningKey;
use stellereum::mempool::Mempool;
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn transfer(seed: u8, nonce: u64, gas: u64, amount: u64) -> Transaction {
    let k = key(seed);
    Transaction::sign(&k, [0xEE; 32], amount, gas, nonce, 0, 0)
}

fn funded(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}

#[test]
fn an_overflowing_block_keeps_the_highest_paying_transactions() {
    let mut mp = Mempool::new(1_000, 1_000);
    for n in 0..50u64 {
        // Fee is `gas_limit` today, so a bigger limit means a better bid.
        mp.add(transfer(1, n, 100 + n, 1)).expect("admit");
    }
    let picked = mp.select_bounded(10, u64::MAX);
    assert_eq!(picked.len(), 10, "the count cap must hold");
    let fees: Vec<u64> = picked.iter().map(|t| t.gas_limit).collect();
    assert_eq!(
        fees,
        vec![149, 148, 147, 146, 145, 144, 143, 142, 141, 140],
        "highest fees win"
    );
}

#[test]
fn the_gas_budget_skips_an_oversized_transaction_rather_than_truncating() {
    let mut mp = Mempool::new(1_000, 1_000);
    mp.add(transfer(1, 0, 500, 1)).expect("admit");
    mp.add(transfer(2, 0, 400, 1)).expect("admit");
    // This one alone exceeds the whole budget and must be stepped over, not
    // treated as the end of the block.
    mp.add(transfer(3, 0, 10_000, 1)).expect("admit");
    mp.add(transfer(4, 0, 300, 1)).expect("admit");

    let picked = mp.select_bounded(10, 1_500);
    let senders: Vec<[u8; 32]> = picked.iter().map(|t| t.from).collect();
    assert!(
        !senders.contains(&key(3).verifying_key().to_bytes()),
        "the oversized tx must be skipped"
    );
    assert!(
        senders.contains(&key(4).verifying_key().to_bytes()),
        "a cheaper tx behind it must still fit"
    );
    assert_eq!(picked.len(), 3, "500 + 400 + 300 = 1200 fits a 1500 budget");
}

#[tokio::test]
async fn unexecutable_transactions_do_not_occupy_the_block() {
    // The live bug: a producer selecting purely by fee would fill a block with
    // transactions whose nonces are already spent, pay for them, and only have
    // them fail at application.
    let engine = InMemoryStateEngine::new();
    let addr = funded(1);
    engine
        .update_account(AccountState::new(addr, 1_000_000))
        .await;

    let mut mp = Mempool::new(1_000, 1_000);
    // One executable transaction, then a flood of replays at a higher fee.
    mp.add(transfer(1, 0, 600, 1)).expect("admit");
    for n in 1..40u64 {
        mp.add(transfer(1, n, 1_000, 1)).expect("admit");
    }
    assert_eq!(mp.len(), 40, "the pool holds 1 real tx plus a 39-tx flood");

    // Mirror the producer's filter: a block must carry a CONTIGUOUS nonce
    // sequence per sender, so the expected nonce advances as transactions are
    // accepted. Comparing against the account's nonce alone would admit a gap.
    let account = engine.get_account(&addr).await.expect("account");
    let cursors = std::cell::RefCell::new(std::collections::HashMap::from([(
        addr,
        (account.nonce, account.balance),
    )]));
    let selected: std::cell::RefCell<Vec<Transaction>> = std::cell::RefCell::new(Vec::new());
    mp.select_for_block(50, 30_000_000, |t| {
        let Some(&(expected, balance)) = cursors.borrow().get(&t.from) else {
            return false;
        };
        if t.nonce != expected {
            return false;
        }
        let cost = t.amount.saturating_add(t.gas_limit);
        if balance < cost {
            return false;
        }
        cursors
            .borrow_mut()
            .insert(t.from, (expected + 1, balance - cost));
        selected.borrow_mut().push(t.clone());
        true
    });

    assert_eq!(
        selected.borrow().len(),
        1,
        "only the one executable transaction may occupy the block, however high the replays bid"
    );
    assert_eq!(selected.borrow()[0].nonce, 0);
}

#[tokio::test]
async fn a_drained_sender_cannot_fill_a_block() {
    let engine = InMemoryStateEngine::new();
    let addr = funded(2);
    engine.update_account(AccountState::new(addr, 1_000)).await;

    let mut mp = Mempool::new(1_000, 1_000);
    for n in 0..20u64 {
        mp.add(transfer(2, n, 600, 5_000))
            .expect("admit by signature");
    }
    let account = engine.get_account(&addr).await.expect("account");
    let picked: std::cell::RefCell<Vec<Transaction>> = std::cell::RefCell::new(Vec::new());
    let cursors = std::cell::RefCell::new(std::collections::HashMap::from([(
        addr,
        (account.nonce, account.balance),
    )]));
    mp.select_for_block(50, 30_000_000, |t| {
        let Some(&(expected, balance)) = cursors.borrow().get(&t.from) else {
            return false;
        };
        if t.nonce != expected {
            return false;
        }
        let cost = t.amount.saturating_add(t.gas_limit);
        if balance < cost {
            return false;
        }
        cursors
            .borrow_mut()
            .insert(t.from, (expected + 1, balance - cost));
        picked.borrow_mut().push(t.clone());
        true
    });
    assert!(
        picked.borrow().is_empty(),
        "a sender whose balance cannot cover amount+gas must not occupy the block"
    );
}

#[test]
fn a_base_fee_above_zero_blocks_free_spam() {
    // With `base_fee == 0` a `gas_limit: 0` transaction is free, still takes a
    // slot, and is paid for like real work.
    let open = Mempool::default();
    assert_eq!(
        open.base_fee, 0,
        "the library default stays 0 so tests are unaffected"
    );

    let mut guarded = Mempool::default().with_base_fee(560);
    let k = key(3);
    let spam = Transaction::sign(&k, [0xEE; 32], 1, 0, 0, 0, 0);
    let err = guarded
        .add_checked(spam, 1_000_000)
        .expect_err("free tx must be rejected");
    assert_eq!(err, stellereum::mempool::MempoolError::FeeTooLow);

    // And a real transfer, priced at the cheapest real operation, gets through.
    let real = Transaction::sign(&k, [0xEE; 32], 1, 560, 0, 0, 0);
    assert!(guarded.add_checked(real, 1_000_000).is_ok());
}

#[test]
fn selection_prefers_executable_work_under_pressure() {
    // Fee order, caps and the filter together: the block must be worth as much
    // as the pool can make it, not merely full.
    let mut mp = Mempool::new(1_000, 1_000);
    // Executable, varying fees.
    for n in 0..8u64 {
        mp.add(transfer(1, n, 1_000 + n * 10, 1)).expect("admit");
    }
    // Non-executable, bidding far higher.
    for n in 8..30u64 {
        mp.add(transfer(9, n, 50_000, 1)).expect("admit");
    }

    let picked = mp.select_for_block(5, u64::MAX, |t| t.from == key(1).verifying_key().to_bytes());
    assert_eq!(picked.len(), 5);
    let fees: Vec<u64> = picked.iter().map(|t| t.gas_limit).collect();
    assert_eq!(
        fees,
        vec![1_070, 1_060, 1_050, 1_040, 1_030],
        "the top five EXECUTABLE transactions win, not the top five overall"
    );
}

#[tokio::test]
async fn proposer_filter_skips_below_floor_without_rejecting() {
    // The admission floor is mirrored in the proposer filter: a below-floor
    // transaction already in the pool (admitted before the floor rose, or via
    // the unchecked path) is SKIPPED at propose time - never packed, never
    // hard-rejected. The pool keeps it, so a later lower floor can still pack
    // it; every proposer reaches the same selection deterministically.
    use std::sync::Arc;
    use stellereum::consensus::ValidatorSet;
    use stellereum::runtime::ValidatorRuntime;

    let master = key(11);
    let master_pub = master.verifying_key().to_bytes();
    let poor = key(12);
    let poor_pub = poor.verifying_key().to_bytes();
    let engine = Arc::new(InMemoryStateEngine::new());
    engine
        .update_account(AccountState::new(master_pub, 10_000_000))
        .await;
    engine
        .update_account(AccountState::new(poor_pub, 10_000_000))
        .await;
    let vset = ValidatorSet::from_list(vec![(master_pub, 1)]);
    let mut rt = ValidatorRuntime::new(master, vset, engine, 1);

    // Unchecked admission (no BALANCE check), then the floor rises past one
    // tx. The runtime's default pool already carries the operator's floor
    // (`STELL_MIN_GAS_LIMIT`), so both transactions declare at least that
    // much gas; the floor is then raised past the cheaper one.
    let ok_tx = Transaction::sign(&key(11), [0xEE; 32], 1, 560_000, 0, 0, 0);
    let low_tx = Transaction::sign(&poor, [0xEE; 32], 1, 280_000, 0, 0, 0);
    {
        let mut mp = rt.mempool.write().await;
        mp.add(ok_tx.clone()).expect("unchecked admit");
        mp.add(low_tx.clone()).expect("unchecked admit");
        mp.base_fee = 560_000;
    }

    let block = rt.propose(1_000_000).await.expect("propose must succeed");
    let packed: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|t| t.compute_tx_hash())
        .collect();
    assert!(
        packed.contains(&ok_tx.compute_tx_hash()),
        "above-floor tx is packed"
    );
    assert!(
        !packed.contains(&low_tx.compute_tx_hash()),
        "below-floor tx is skipped, not packed"
    );
    assert!(
        rt.mempool.read().await.contains(&low_tx.compute_tx_hash()),
        "a skipped tx is NOT rejected: the pool keeps it"
    );
}

#[test]
fn a_cheap_flood_cannot_displace_expensive_transactions() {
    // The spam arrives first, so a FIFO producer would take it all. Ordering is
    // by fee, so it must not.
    let mut mp = Mempool::new(1_000, 1_000);
    for n in 0..20u64 {
        mp.add(transfer(1, n, 1, 1)).expect("admit cheap");
    }
    for n in 0..3u64 {
        mp.add(transfer(2, n, 90_000, 1)).expect("admit expensive");
    }
    let picked = mp.select_bounded(5, u64::MAX);
    let expensive = key(2).verifying_key().to_bytes();
    assert_eq!(
        picked.iter().filter(|t| t.from == expensive).count(),
        3,
        "all three expensive transactions must be in the block"
    );
}
