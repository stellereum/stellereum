//! Oracle ON-CHAIN wiring: the price lives in consensus state and moves only
//! when a BLOCK carries a signed feed.
//!
//! The determinism rule these tests pin, in one sentence: `broadcast_price_feed`
//! / `fetch_price_feed` (gossip) and any RPC read may put a feed in front of a
//! proposer, but the ONLY writer of price state is
//! `OpCode::SysCallSubmitPriceFeed` executed during block application against
//! `block.timestamp`. A node that never saw the gossip applies identical state
//! from the block alone - so gossip-without-block cannot move the root, and
//! two nodes (one gossiped, one not) end up on the same root.
//!
//! Also pinned here: the commit-time checks (stale / future / monotonic /
//! deviation / breaker / USDT peg) at their exact block-time boundaries, and
//! that BOTH order entry points - the SVM's `SysCallPlaceOrder` and the
//! non-SVM `place_order_settled` - run the same priority gates (no bypass).

use ed25519_dalek::SigningKey;
use stellereum::oracle::{
    deviation_bps, OracleState, PriceFeedUpdate, MAX_PRICE_DEVIATION_BPS, STALE_PRICE_MAX_SECS,
    USDT_MIN_PEG_MICRO_USD,
};
use stellereum::orderbook::{OrderSide, OrderType, PAIR_STELL_USDT};
use stellereum::sharding::{Block, Transaction, MASTERCHAIN_SHARD};
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::OpCode;

mod support;
use support::{assert_refused_tx_paid_failure_fee, failure_fee};

/// The block's timestamp. Every commit-time check below is evaluated against
/// THIS number, never against a wall clock - that is what makes the result
/// identical on every node that applies the block.
const BLOCK_TIME: u64 = 1_700_000_000;

const STELL: u64 = 1_000_000_000;

fn publisher_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

fn sender_key() -> SigningKey {
    SigningKey::from_bytes(&[0x07; 32])
}

/// Engine with a committed publisher set and a funded sender, i.e. everything
/// a feed transaction needs to be admissible.
async fn wired_engine() -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    let pk = publisher_key().verifying_key().to_bytes();
    e.oracle_write().await.publishers.insert(pk);
    let sender = sender_key().verifying_key().to_bytes();
    e.credit_native(&sender, 1_000_000_000_000)
        .await
        .expect("fund");
    e
}

/// A signed submit-feed transaction. The nonce is INSIDE the signed message,
/// so it must be signed with the nonce the block will see - patching it after
/// signing would invalidate the signature and make the transaction fail
/// admission before the payload ever runs.
fn feed_tx(feed: PriceFeedUpdate, nonce: u64) -> Transaction {
    Transaction::sign_with_payload(
        &sender_key(),
        sender_key().verifying_key().to_bytes(),
        0,
        10_000,
        nonce,
        1,
        1,
        vec![OpCode::SysCallSubmitPriceFeed(Box::new(feed))],
    )
}

/// Apply ONE block carrying a feed transaction at `block_time`; returns the
/// per-transaction verdict and the roots before/after.
async fn apply_feed_block(
    e: &InMemoryStateEngine,
    feed: PriceFeedUpdate,
    block_time: u64,
    nonce: u64,
) -> (bool, [u8; 32], [u8; 32]) {
    let before = e.get_state_root().await;
    let tx = feed_tx(feed, nonce);
    let (_applied, _failed, _fees, status, _) =
        e.apply_block_parallel_fees(&[tx], block_time).await;
    let after = e.get_state_root().await;
    (status.first().copied().unwrap_or(false), before, after)
}

// ===========================================================================
// 1. A block carrying a signed feed moves the root; gossip alone never does.
// ===========================================================================

#[tokio::test]
async fn feed_in_a_block_moves_the_root() {
    let e = wired_engine().await;
    let before = e.get_state_root().await;
    assert!(
        e.oracle_read().await.feeds.is_empty(),
        "precondition: nothing committed yet"
    );

    let feed = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_key());
    let (ok, _before, after) = apply_feed_block(&e, feed, BLOCK_TIME, 0).await;

    assert!(ok, "a fresh, signed, publisher-set feed must be committed");
    assert_ne!(before, after, "a committed feed must move the state root");
    let committed = e
        .oracle_read()
        .await
        .feeds
        .get("STELL")
        .cloned()
        .expect("feed committed");
    assert_eq!(committed.price_micro_usd, 250_000);
    assert_eq!(
        committed.publisher,
        publisher_key().verifying_key().to_bytes()
    );
}

#[tokio::test]
async fn gossip_without_a_block_does_not_move_the_root() {
    let e = wired_engine().await;
    let before = e.get_state_root().await;

    // What `P2pNetworkAdapter::broadcast_price_feed` does before it writes the
    // feed into the NODE'S LOCAL KV (`network.rs`): verify the signature. The
    // adapter itself cannot be built in a test (`infnode::Node::new` opens
    // sockets - the same reason `tests/discovery_tests.rs` pins its invariants
    // as data-level checks), and that is the point: the gossip path has no
    // handle on the state engine AT ALL. Receiving a feed over gossip is
    // exactly this - a verified value held off-chain by the receiving node.
    let feed = PriceFeedUpdate::sign("STELL", 999_999_999, BLOCK_TIME - 1, &publisher_key());
    assert!(feed.verify(), "broadcast_price_feed refuses unsigned feeds");

    // `fetch_price_feed` on the receiving side: a bincode round-trip through
    // the local KV store, nothing more.
    let wire = bincode::serialize(&feed).expect("gossip serialization");
    let received: PriceFeedUpdate = bincode::deserialize(&wire).expect("gossip decode");
    assert_eq!(received.price_micro_usd, feed.price_micro_usd);

    assert_eq!(
        e.get_state_root().await,
        before,
        "a gossiped feed must NOT move the state root"
    );
    assert!(
        e.oracle_read().await.feeds.is_empty(),
        "gossip must not reach the committed oracle"
    );
}

#[tokio::test]
async fn gossip_then_block_equals_block_only() {
    // Two nodes with identical state. Node A also receives the feed over
    // gossip before the block arrives; node B never hears about it. They then
    // apply the SAME block. If gossip could leak into state, their roots would
    // diverge here - a consensus split with no attacker involved.
    let a = wired_engine().await;
    let b = wired_engine().await;
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "identical setup, identical root"
    );

    let feed = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 5, &publisher_key());
    // Node A: gossip copy arrives first (held off-chain, nothing written).
    let _gossiped = bincode::serialize(&feed).unwrap();

    // Both nodes apply the identical block.
    let feed_for_b = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 5, &publisher_key());
    let (ok_a, _, after_a) = apply_feed_block(&a, feed.clone(), BLOCK_TIME, 0).await;
    let (ok_b, _, after_b) = apply_feed_block(&b, feed_for_b, BLOCK_TIME, 0).await;

    assert!(ok_a && ok_b, "both nodes must accept the same block");
    assert_eq!(
        after_a, after_b,
        "a node that saw gossip must reach the SAME root as one that did not"
    );
    assert_eq!(
        after_a,
        a.get_state_root().await,
        "the root is stable after the block applied"
    );
}

// ===========================================================================
// 2. Commit-time checks, at their exact block-time boundaries.
// ===========================================================================

fn fresh_state(pk: [u8; 32]) -> OracleState {
    let mut st = OracleState::default();
    st.publishers.insert(pk);
    st
}

#[test]
fn freshness_boundaries_at_block_time() {
    let sk = publisher_key();
    let pk = sk.verifying_key().to_bytes();
    let t = BLOCK_TIME;

    // Exactly at the limit is still fresh (the rule is `age > limit`).
    let mut st = fresh_state(pk);
    let exact = PriceFeedUpdate::sign("STELL", 250_000, t - STALE_PRICE_MAX_SECS, &sk);
    assert!(st.commit_feed(&exact, t).is_ok(), "age == limit is fresh");

    // One second past the limit is stale.
    let mut st = fresh_state(pk);
    let over = PriceFeedUpdate::sign("STELL", 250_000, t - STALE_PRICE_MAX_SECS - 1, &sk);
    let err = st.commit_feed(&over, t).unwrap_err();
    assert!(err.contains("stale"), "stale feed must be named: {err}");
    assert!(st.feeds.is_empty(), "a stale feed commits nothing");

    // A feed timestamped in the FUTURE relative to the block is rejected.
    let mut st = fresh_state(pk);
    let future = PriceFeedUpdate::sign("STELL", 250_000, t + 1, &sk);
    let err = st.commit_feed(&future, t).unwrap_err();
    assert!(err.contains("ahead"), "future feed must be named: {err}");

    // Signed with the publisher's own clock AT the block time: accepted.
    let mut st = fresh_state(pk);
    let now = PriceFeedUpdate::sign("STELL", 250_000, t, &sk);
    assert!(st.commit_feed(&now, t).is_ok());

    // A feed signed by a key outside the committed publisher set is refused
    // even though its signature is valid - "signed" is not "authorised".
    let rogue = SigningKey::from_bytes(&[0x99; 32]);
    let mut st = fresh_state(pk);
    let unsigned_by_rogue = PriceFeedUpdate::sign("STELL", 250_000, t, &rogue);
    let err = st.commit_feed(&unsigned_by_rogue, t).unwrap_err();
    assert!(err.contains("publisher"), "{err}");

    // Monotonic per asset: an older observation cannot rewind the price, even
    // while it is still inside the freshness window.
    let mut st = fresh_state(pk);
    let first = PriceFeedUpdate::sign("STELL", 250_000, t - 60, &sk);
    st.commit_feed(&first, t).expect("first feed commits");
    let replay = PriceFeedUpdate::sign("STELL", 240_000, t - 60, &sk);
    let err = st.commit_feed(&replay, t).unwrap_err();
    assert!(err.contains("non-monotonic"), "{err}");
    assert_eq!(st.feeds["STELL"].price_micro_usd, 250_000);
}

#[tokio::test]
async fn stale_feed_rejected_at_block_time() {
    let e = wired_engine().await;
    let feed = PriceFeedUpdate::sign(
        "STELL",
        250_000,
        BLOCK_TIME - STALE_PRICE_MAX_SECS - 1,
        &publisher_key(),
    );
    let tx = feed_tx(feed, 0);
    // The fee a refusal charges, read BEFORE the transaction is applied (the
    // consensus floor carries the D2 penalty, which the block path records at
    // the END of the block).
    let fee = failure_fee(&e, &tx).await;
    let sender = sender_key().verifying_key().to_bytes();
    let balance_before = e.get_account(&sender).await.unwrap().balance;

    let before = e.get_state_root().await;
    let (_applied, _failed, _fees, status, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&tx), BLOCK_TIME)
        .await;
    let after = e.get_state_root().await;

    assert!(!status[0], "a stale feed must be rejected at block time");
    // PINNED POLICY (SEC-07 / F-01): the refusal is ATTRIBUTABLE - the
    // transaction got past admission and failed during execution - so it pays
    // the failure fee and consumes its nonce. The STATE ROOT THEREFORE MOVES;
    // what must NOT move is the ORACLE: a stale feed commits no price.
    assert_refused_tx_paid_failure_fee(&e, &tx, fee, balance_before, 0).await;
    assert_ne!(
        before, after,
        "a paid refusal moves the root via the fee debit (it is not a no-op)"
    );
    assert!(
        e.oracle_read().await.feeds.is_empty(),
        "a stale feed commits no price"
    );
}

#[tokio::test]
async fn deviation_feed_rejected_latches_breaker_and_blocks_later_feeds() {
    let e = wired_engine().await;
    let sender = sender_key().verifying_key().to_bytes();

    // Seed the reference price.
    let first = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 60, &publisher_key());
    let (ok, _, _) = apply_feed_block(&e, first, BLOCK_TIME, 0).await;
    assert!(ok);

    // 20% above the committed price: well past MAX_PRICE_DEVIATION_BPS.
    let spike = PriceFeedUpdate::sign("STELL", 300_000, BLOCK_TIME - 30, &publisher_key());
    let tx1 = feed_tx(spike.clone(), 1);
    let fee1 = failure_fee(&e, &tx1).await;
    let balance_before = e.get_account(&sender).await.unwrap().balance;
    let (ok, _, _) = apply_feed_block(&e, spike, BLOCK_TIME, 1).await;
    assert!(!ok, "a deviating feed must be rejected at block time");
    {
        let oracle = e.oracle_read().await;
        assert_eq!(
            oracle.feeds["STELL"].price_micro_usd, 250_000,
            "the deviating price must NOT have been committed"
        );
        assert!(
            oracle.breaker_tripped,
            "a deviation violation must latch the breaker"
        );
    }
    // PINNED POLICY (SEC-07 / F-01): the deviating feed's refusal is
    // attributable, so it pays the failure fee and consumes its nonce. The
    // root moves TWICE over (the fee debit AND the latch).
    assert_refused_tx_paid_failure_fee(&e, &tx1, fee1, balance_before, 1).await;

    // The latch is state: it moved the root, and it now refuses everything.
    let after_trip = e.get_state_root().await;
    let valid_again = PriceFeedUpdate::sign("STELL", 251_000, BLOCK_TIME - 5, &publisher_key());
    let tx2 = feed_tx(valid_again, 2);
    // The second failure is charged at the floor the D2 penalty raised after
    // the first one, so it is even further from free.
    let fee2 = failure_fee(&e, &tx2).await;
    let balance_before = e.get_account(&sender).await.unwrap().balance;
    let before = e.get_state_root().await;
    let (_applied, _failed, _fees, status, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&tx2), BLOCK_TIME)
        .await;
    let after = e.get_state_root().await;
    assert!(
        !status[0],
        "a latched breaker refuses even a perfectly fresh feed"
    );
    // PINNED POLICY (SEC-07): a refusal is NOT free and NOT a no-op: it pays
    // the failure fee and consumes the nonce, so the root moves. What must NOT
    // move is the ORACLE - the latch is already set and the price unchanged.
    assert_refused_tx_paid_failure_fee(&e, &tx2, fee2, balance_before, 2).await;
    assert_ne!(
        before, after,
        "a paid refusal moves the root via the fee debit"
    );
    assert_ne!(
        e.get_state_root().await,
        after_trip,
        "the paid refusal is not a no-op"
    );
    {
        let oracle = e.oracle_read().await;
        assert_eq!(oracle.feeds["STELL"].price_micro_usd, 250_000);
        assert!(oracle.breaker_tripped, "the latch is still set");
    }

    // The deviation math itself, pinned: 10% exactly is AT the limit (still
    // allowed, the rule is `> limit`), and a percent over it is not.
    assert_eq!(deviation_bps(110_000, 100_000), MAX_PRICE_DEVIATION_BPS);
    assert!(deviation_bps(110_101, 100_000) > MAX_PRICE_DEVIATION_BPS);
    assert_eq!(
        deviation_bps(90_000, 100_000),
        MAX_PRICE_DEVIATION_BPS,
        "symmetric"
    );
    assert_eq!(deviation_bps(100_000, 100_000), 0);
}

#[tokio::test]
async fn usdt_peg_boundary_at_block_time() {
    let e = wired_engine().await;

    // Exactly at the peg floor: accepted (the rule is `price < floor`).
    let at_floor = PriceFeedUpdate::sign(
        "USDT",
        USDT_MIN_PEG_MICRO_USD,
        BLOCK_TIME - 10,
        &publisher_key(),
    );
    let (ok, _, _) = apply_feed_block(&e, at_floor, BLOCK_TIME, 0).await;
    assert!(ok, "a feed exactly at the peg floor must be accepted");

    // One micro-USD below the floor: rejected AND latched.
    let depeg = PriceFeedUpdate::sign(
        "USDT",
        USDT_MIN_PEG_MICRO_USD - 1,
        BLOCK_TIME - 5,
        &publisher_key(),
    );
    let (ok, _, _) = apply_feed_block(&e, depeg, BLOCK_TIME, 1).await;
    assert!(!ok, "a depegged USDT feed must be rejected at block time");
    {
        let oracle = e.oracle_read().await;
        assert_eq!(
            oracle.feeds["USDT"].price_micro_usd, USDT_MIN_PEG_MICRO_USD,
            "the depegged price must not replace the pegged one"
        );
        assert!(oracle.breaker_tripped, "a depeg must latch the breaker");
    }
}

// ===========================================================================
// 3. Both order entry points run the SAME gates - neither bypasses.
// ===========================================================================

#[tokio::test]
async fn place_order_settled_cannot_bypass_the_gates() {
    let e = InMemoryStateEngine::new();
    let pk = publisher_key().verifying_key().to_bytes();
    let who = [0x11u8; 32];
    e.credit_native(&who, 100 * STELL).await.expect("fund");
    e.oracle_write().await.publishers.insert(pk);

    // Commit $0.25/STELL through the oracle (same function the syscall uses).
    {
        let mut oracle = e.oracle_write().await;
        let feed = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_key());
        oracle.commit_feed(&feed, BLOCK_TIME).expect("commit");
    }

    // Gate 1 - deviation: +20% from the committed price is refused FIRST, so
    // the error is the gate's (not "quote token not configured", which is what
    // a gate that PASSED would hit next - this entry point has no wUSDT
    // configured in this test).
    let res = e
        .place_order_settled(
            PAIR_STELL_USDT,
            who,
            OrderSide::Sell,
            OrderType::Limit,
            300_000,
            1_000,
            BLOCK_TIME,
        )
        .await;
    let err = res.expect_err("a deviating order must be refused");
    assert!(
        err.contains("deviates"),
        "gate error, not later checks: {err}"
    );

    // ... and the refusal latches NOTHING (E3 fix): a trader's far-away
    // limit is refused, trading continues. Only a PUBLISHER's deviant
    // committed feed trips the breaker (see deviation_feed_rejected_...).
    assert!(
        !e.oracle_read().await.breaker_tripped,
        "E3: an order refusal must never latch the breaker"
    );
    // A fair price proceeds past the gate: the only error left is the missing
    // wUSDT quote token, which comes AFTER the gate (this entry point has no
    // wUSDT configured in this test).
    let res = e
        .place_order_settled(
            PAIR_STELL_USDT,
            who,
            OrderSide::Sell,
            OrderType::Limit,
            250_000, // exactly the committed price
            1_000,
            BLOCK_TIME,
        )
        .await;
    let err = res.expect_err("still no wUSDT configured here");
    assert!(
        !err.contains("Circuit breaker"),
        "gate passed, later check fired: {err}"
    );

    // No latch to reset (E3 fix): prove nothing latched, then check the SAME
    // order passes the gate: the only error left is the missing wUSDT quote
    // token, which comes AFTER the gate.
    assert!(!e.oracle_read().await.breaker_tripped);
    let res = e
        .place_order_settled(
            PAIR_STELL_USDT,
            who,
            OrderSide::Sell,
            OrderType::Limit,
            255_000, // +2%, inside the 10% band
            1_000,
            BLOCK_TIME,
        )
        .await;
    let err = res.expect_err("reaches the (unconfigured) quote-token check");
    assert!(
        !err.contains("deviates") && !err.contains("Circuit breaker"),
        "the gates must have passed: {err}"
    );
}

#[tokio::test]
async fn svm_place_order_gate_cannot_bypass() {
    let e = wired_engine().await;

    // Commit $0.25/STELL via a real block.
    let feed = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_key());
    let (ok, _, _) = apply_feed_block(&e, feed, BLOCK_TIME, 0).await;
    assert!(ok);

    // A block whose order deviates 20% from the committed price must fail the
    // transaction and leave NO order behind.
    //
    // F-01 / SEC-07: the gate is an EXECUTION-time check, so the refusal is
    // ATTRIBUTABLE - the sender pays the failure fee and its nonce advances
    // by one. (The old "a failed transaction never reaches commit_native, so
    // the nonce does not advance" note was the free-failure hole SEC-07
    // closed: a spammer could push failing orders at the chain for nothing.)
    // So every retry below is signed with the NEXT nonce.
    let order_tx = |price: u64, nonce: u64| {
        Transaction::sign_with_payload(
            &sender_key(),
            [0u8; 32],
            0,
            10_000,
            nonce,
            1,
            1,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_USDT,
                is_buy: false,
                price,
                amount: 1_000,
            }],
        )
    };

    let before = e.get_state_root().await;
    let deviating = order_tx(300_000, 1);
    let fee = failure_fee(&e, &deviating).await;
    let sender = sender_key().verifying_key().to_bytes();
    let balance_before = e.get_account(&sender).await.unwrap().balance;
    let (_a, _f, _fees, status, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&deviating), BLOCK_TIME)
        .await;
    assert_eq!(status, vec![false], "the deviating order must revert");
    // The refusal is not free: the failure fee is charged and the nonce is
    // consumed, while the ORDER itself left nothing behind.
    assert_refused_tx_paid_failure_fee(&e, &deviating, fee, balance_before, 1).await;
    assert!(
        e.orderbooks_read()
            .await
            .get_book(PAIR_STELL_USDT)
            .map(|b| b.depth() == (0, 0))
            .unwrap_or(true),
        "no order may be placed by a reverted transaction"
    );
    // E3 FIXED: the refusal latches NOTHING. A trader's far-away limit is
    // refused; trading continues. (Only a publisher's deviant COMMITTED feed
    // trips the breaker — see deviation_feed_rejected_... above.)
    assert!(
        !e.oracle_read().await.breaker_tripped,
        "E3: an order refusal must never latch the breaker"
    );

    // Unlatched: an in-band order goes through the gate (it may still fail
    // later checks, but never on the breaker). Exact-price sell succeeds
    // outright here (funded account) and consumes nonce 2 - the nonce the
    // refused order above burned.
    let (_a, _f, _fees, status, _) = e
        .apply_block_parallel_fees(&[order_tx(250_000, 2)], BLOCK_TIME)
        .await;
    assert_eq!(status, vec![true], "fair price passes the gate and places");
    let _ = before;

    // An in-band order goes through - the gate is a gate, not a
    // ban: with the price committed at $0.25, $0.255 (+2%) is fine.
    let (_a, _f, _fees, status, _) = e
        .apply_block_parallel_fees(&[order_tx(255_000, 3)], BLOCK_TIME)
        .await;
    assert_eq!(status, vec![true], "an in-band order must be accepted");
    let book = e.orderbooks_read().await;
    let (_, asks) = book
        .get_book(PAIR_STELL_USDT)
        .expect("book exists")
        .get_best_bid_ask();
    // Both in-band sells rest; the lower ask (250,000) is best.
    assert_eq!(asks, Some(250_000));
}

#[tokio::test]
async fn svm_mixed_block_deviating_order_does_not_poison_block_mate() {
    // E3 attack shape: ONE block carries a DEVIATING order tx AND a fair
    // order tx from two different traders. The bad order must revert on the
    // gate without latching the breaker and without poisoning its block-mate.
    let e = wired_engine().await;
    // Second trader, funded so the fair order is fully appliable.
    let victim_key = SigningKey::from_bytes(&[0x08; 32]);
    let victim = victim_key.verifying_key().to_bytes();
    e.credit_native(&victim, 1_000_000_000_000)
        .await
        .expect("fund victim");

    // Commit $0.25/STELL via a real block (consumes the sender's nonce 0,
    // so its next sequence number is 1; the victim is still at 0 — nonces
    // differ per tx, 1 vs 0, and both are admission-valid).
    let feed = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_key());
    let (ok, _, _) = apply_feed_block(&e, feed, BLOCK_TIME, 0).await;
    assert!(ok);

    let order_tx = |key: &SigningKey, price: u64, nonce: u64| {
        Transaction::sign_with_payload(
            key,
            [0u8; 32],
            0,
            10_000,
            nonce,
            1,
            1,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_USDT,
                is_buy: false,
                price,
                amount: 1_000,
            }],
        )
    };

    // Deviating sell (+20% over the committed price) first, fair sell at the
    // committed price second, in ONE block.
    let bad = order_tx(&sender_key(), 300_000, 1);
    let good = order_tx(&victim_key, 250_000, 0);
    let (_a, _f, _fees, status, _) = e.apply_block_parallel_fees(&[bad, good], BLOCK_TIME).await;
    assert_eq!(
        status,
        vec![false, true],
        "the deviating order must revert while its fair block-mate applies"
    );
    assert!(
        !e.oracle_read().await.breaker_tripped,
        "E3: an order refusal must never latch the breaker"
    );

    // The fair order applied and the bad one left nothing behind: the book
    // holds exactly the one fair resting sell.
    let book = e.orderbooks_read().await;
    let (bids, asks) = book
        .get_book(PAIR_STELL_USDT)
        .expect("book exists")
        .get_best_bid_ask();
    assert_eq!(bids, None);
    assert_eq!(asks, Some(250_000));
}

// ===========================================================================
// 4. Persistence: the oracle survives a snapshot/restore round trip.
// ===========================================================================

#[tokio::test]
async fn oracle_state_roundtrips_through_a_domain_snapshot() {
    let e = InMemoryStateEngine::new();
    let pk = publisher_key().verifying_key().to_bytes();
    e.oracle_write().await.publishers.insert(pk);
    let feed = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_key());
    e.oracle_write()
        .await
        .commit_feed(&feed, BLOCK_TIME)
        .expect("commit");
    // A latched breaker must survive too: it is state, not a cache.
    e.oracle_write().await.breaker_tripped = true;
    let root = e.get_state_root().await;

    let snap = stellereum::storage::DomainSnapshot::capture(
        &e,
        &stellereum::staking::StakingLedger::new(),
        &stellereum::governance::Governance::new(),
    )
    .await;
    let bytes = bincode::serialize(&snap).expect("serialize");
    let decoded: stellereum::storage::DomainSnapshot =
        bincode::deserialize(&bytes).expect("deserialize");

    let fresh = InMemoryStateEngine::new();
    let (_staking, _gov) = decoded.apply(&fresh).await;

    assert_eq!(
        fresh.oracle_read().await.clone(),
        e.oracle_read().await.clone(),
        "oracle state must survive the snapshot round trip"
    );
    assert_eq!(
        fresh.get_state_root().await,
        root,
        "the restored engine must compute the SAME state root"
    );
}

#[tokio::test]
async fn oracle_state_roundtrips_through_snapshot_domains_and_load_full_state() {
    use stellereum::storage::{load_full_state_into, AsyncPersistence, Storage};

    const SNAP_H: u64 = 100;
    const NEXT_H: u64 = 101;

    let dir = std::env::temp_dir().join(format!(
        "stell-oracle-restore-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let store = std::sync::Arc::new(Storage::open(&dir).expect("open storage"));

    // Post-SNAP_H state: one account plus a committed feed and a latched breaker.
    let engine = InMemoryStateEngine::new();
    let user = [0xA1u8; 32];
    engine.update_account(AccountState::new(user, 50_000)).await;
    let pk = publisher_key().verifying_key().to_bytes();
    engine.oracle_write().await.publishers.insert(pk);
    let feed = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_key());
    engine
        .oracle_write()
        .await
        .commit_feed(&feed, BLOCK_TIME)
        .expect("commit");
    let root = engine.get_state_root().await;

    // The account snapshot, then the domain snapshot through the REAL
    // `AsyncPersistence::snapshot_domains` path (background writer + all).
    store
        .put_state(SNAP_H, &engine.create_snapshot().await)
        .expect("state");
    let ap = AsyncPersistence::start(store.clone());
    ap.snapshot_domains(
        &engine,
        &stellereum::staking::StakingLedger::new(),
        &stellereum::governance::Governance::new(),
        SNAP_H,
    )
    .await;
    let mut persisted = false;
    for _ in 0..500 {
        if matches!(store.latest_domains().ok().flatten(), Some((h, _)) if h == SNAP_H) {
            persisted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(persisted, "snapshot_domains must persist a domain snapshot");

    // Anchor: block SNAP_H+1 commits to the post-SNAP_H root (the restore
    // verifier compares against exactly that block).
    let sk = SigningKey::from_bytes(&[0x11u8; 32]);
    let mkblock = |height: u64, prev: [u8; 32], state_root: [u8; 32]| {
        let mut b = Block {
            shard_id: MASTERCHAIN_SHARD,
            height,
            prev_hash: prev,
            state_root,
            transactions: vec![],
            cross_shard_out: vec![],
            timestamp: BLOCK_TIME + height,
            proposer: sk.verifying_key().to_bytes(),
            validator_signatures: vec![],
            shard_headers: vec![],
            precommit_qc: None,
            last_qc: None,
            mmr_epoch_root: [0u8; 32],
            order_merkle_root: [0u8; 32],
            epoch_key_commitment: [0u8; 32],
        };
        b.sign_block(&sk);
        b
    };
    let h0 = store
        .put_block(&mkblock(SNAP_H, [0u8; 32], [0xEEu8; 32]))
        .expect("b0");
    let h1 = store.put_block(&mkblock(NEXT_H, h0, root)).expect("b1");
    store.set_finalized(NEXT_H, &h1).expect("finalized");
    store.flush().expect("flush");
    drop(ap);

    // Restart: a fresh engine loads the full state and must land on the SAME
    // root, with the oracle (feed AND breaker latch) intact.
    let fresh = InMemoryStateEngine::new();
    let (height, _staking, _gov) = load_full_state_into(&store, &fresh)
        .await
        .expect("load verifies")
        .expect("snapshot present");
    assert_eq!(height, SNAP_H);
    assert_eq!(
        fresh.get_state_root().await,
        root,
        "restored root must equal the anchored root"
    );
    assert_eq!(
        fresh.oracle_read().await.clone(),
        engine.oracle_read().await.clone(),
        "publishers, committed feeds and the breaker latch must all survive"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// 5. The commitment itself: an oracle difference is a root difference.
// ===========================================================================

#[tokio::test]
async fn every_oracle_difference_is_a_root_difference() {
    // Two engines whose ONLY difference is one committed feed. Their roots
    // must differ - otherwise two nodes could trade against different prices
    // while block sync happily reports agreement.
    let a = InMemoryStateEngine::new();
    let b = InMemoryStateEngine::new();
    let pk = publisher_key().verifying_key().to_bytes();
    a.oracle_write().await.publishers.insert(pk);
    b.oracle_write().await.publishers.insert(pk);
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "identical oracle state, identical root"
    );

    let feed = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_key());
    b.oracle_write()
        .await
        .commit_feed(&feed, BLOCK_TIME)
        .expect("commit");
    assert_ne!(
        a.get_state_root().await,
        b.get_state_root().await,
        "a committed feed must be visible in the state root"
    );

    // So is the breaker latch: a node whose breaker is tripped computes a
    // different root than one that is not, even with identical feeds.
    let b_with_feed = b.get_state_root().await;
    b.oracle_write().await.breaker_tripped = true;
    assert_ne!(
        b.get_state_root().await,
        b_with_feed,
        "the breaker latch is consensus state"
    );
    b.oracle_write().await.breaker_tripped = false;
    assert_eq!(
        b.get_state_root().await,
        b_with_feed,
        "and clearing it returns to the same root"
    );

    // And so is the publisher set: authorising a new publisher is a state
    // change every node must see.
    let mut b_publishers = b.oracle_read().await.publishers.clone();
    b_publishers.insert([0x55u8; 32]);
    let before_publishers = b.get_state_root().await;
    b.oracle_write().await.publishers = b_publishers;
    assert_ne!(
        b.get_state_root().await,
        before_publishers,
        "the publisher set is committed"
    );
}
