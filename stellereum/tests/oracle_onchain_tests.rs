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
    deviation_bps, pq_publisher_binding, OracleState, PqPriceFeedUpdate, MAX_PRICE_DEVIATION_BPS,
    STALE_PRICE_MAX_SECS, USDT_MIN_PEG_MICRO_USD,
};
use stellereum::orderbook::{OrderSide, OrderType, PAIR_STELL_USDT};
use stellereum::post_quantum::{derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT};
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

fn publisher_kp() -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[0x42; 32])
}

/// PQ sender: block transactions ride a Falcon-512 (PQ1 explicit) envelope —
/// a classical Ed-signed transaction is refused at admission under FULL-PQ
/// (`require_pq_tx_envelope`), before any fee, nonce or state effect.
fn sender_kp() -> FalconKeypair {
    FalconKeypair::generate_from_seed_bytes(&[0x07; 32])
}

fn sender_addr() -> [u8; 32] {
    derive_pq_address(PqScheme::Falcon512, sender_kp().pubkey(), &DEFAULT_SALT)
}

/// PQ-enveloped transaction carrying an SVM payload.
///
/// `gas_limit` covers the base fee plus the PQ activation surcharge (the
/// explicit key travels in the envelope on every spend here); the failure-fee
/// helpers price the surcharge per-tx, so expectations stay exact.
fn pq_tx(kp: &FalconKeypair, payload: Vec<OpCode>, nonce: u64) -> Transaction {
    let gas_limit = 100_000u64;
    let from = derive_pq_address(PqScheme::Falcon512, kp.pubkey(), &DEFAULT_SALT);
    let skeleton = Transaction {
        from,
        to: [0u8; 32],
        amount: 0,
        gas_limit,
        nonce,
        source_shard: 1,
        target_shard: 1,
        signature: Vec::new(),
        payload: payload.clone(),
        priority_fee_per_gas: 0,
    };
    let sig = kp.sign(&skeleton.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.pubkey().to_vec(),
        sig,
        [0u8; 32],
        0,
        gas_limit,
        nonce,
        1,
        1,
        payload,
        &DEFAULT_SALT,
    )
}

/// Engine with a committed (Falcon-bound) publisher set and a funded PQ sender.
async fn wired_engine() -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    assert!(e
        .oracle_write()
        .await
        .register_pq_publisher(publisher_kp().pubkey()));
    e.credit_native(&sender_addr(), 1_000_000_000_000)
        .await
        .expect("fund");
    e
}

/// Commit ONE feed through the engine oracle at `block_time`; returns whether
/// it committed and the roots before/after.
///
/// Engine-level admission (the committed-state half of the old block helper;
/// the apply-path fee/nonce accounting lives one layer up in `svm` and is
/// unchanged by the feed-scheme change).
async fn apply_feed_block(
    e: &InMemoryStateEngine,
    feed: PqPriceFeedUpdate,
    block_time: u64,
) -> (bool, [u8; 32], [u8; 32]) {
    let before = e.get_state_root().await;
    let ok = e
        .oracle_write()
        .await
        .commit_feed_pq(&feed, block_time)
        .is_ok();
    let after = e.get_state_root().await;
    (ok, before, after)
}

// ===========================================================================
// 1. A block carrying a signed feed moves the root; gossip alone never does.
// ===========================================================================

#[tokio::test]
async fn feed_commit_moves_the_root() {
    let e = wired_engine().await;
    let before = e.get_state_root().await;
    assert!(
        e.oracle_read().await.feeds.is_empty(),
        "precondition: nothing committed yet"
    );

    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_kp());
    let (ok, _before, after) = apply_feed_block(&e, feed, BLOCK_TIME).await;

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
        pq_publisher_binding(publisher_kp().pubkey()),
        "the committed publisher is the Falcon key binding"
    );
}

/// The frozen Ed wire fail-closes at the block boundary: a block carrying a
/// `SysCallSubmitPriceFeed` (classical `PriceFeedUpdate`, whose `verify()` is
/// hardcoded false) is refused, commits no price, and latches nothing. This
/// is the block-level half of the `pure_pq_refuses_classical_feed` pin.
#[tokio::test]
async fn ed_feed_in_a_block_is_refused_fail_closed() {
    use stellereum::oracle::PriceFeedUpdate;

    let e = wired_engine().await;
    let before = e.get_state_root().await;
    // A correctly formed, correctly SIGNED Ed feed — signed with the
    // publisher key the engine trusts — is still refused: no valid Ed feed
    // exists anymore. The WRAPPING transaction is PQ-enveloped, so it passes
    // tx admission and the refusal lands at execution.
    let ed_sk = SigningKey::from_bytes(&[0x42; 32]);
    let feed = PriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &ed_sk);
    assert!(!feed.verify(), "precondition: Ed verification fail-closes");
    let tx = pq_tx(
        &sender_kp(),
        vec![OpCode::SysCallSubmitPriceFeed(Box::new(feed))],
        0,
    );
    // The refusal is ATTRIBUTABLE (SEC-07): the transaction got past admission
    // and failed during execution, so it pays the failure fee and consumes its
    // nonce. The STATE ROOT THEREFORE MOVES; what must NOT move is the oracle.
    let fee = failure_fee(&e, &tx).await;
    let sender = sender_addr();
    let balance_before = e.get_account(&sender).await.unwrap().balance;
    let (_applied, _failed, _fees, status, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&tx), BLOCK_TIME)
        .await;
    assert_eq!(status, vec![false], "an Ed feed must be refused");
    assert_refused_tx_paid_failure_fee(&e, &tx, fee, balance_before, 0).await;
    assert_ne!(
        before,
        e.get_state_root().await,
        "a paid refusal moves the root via the fee debit (it is not a no-op)"
    );
    let oracle = e.oracle_read().await;
    assert!(
        oracle.feeds.is_empty(),
        "a refused Ed feed commits no price"
    );
    assert!(!oracle.breaker_tripped, "a refused Ed feed latches nothing");
}

/// The PQ twin: a block carrying `SysCallSubmitPqPriceFeed` (Falcon-signed
/// `PqPriceFeedUpdate`) commits the price through the SVM handler. This is
/// the live oracle path — the Ed arm above is fail-closed dead, so without
/// this opcode no feed could commit on chain at all.
#[tokio::test]
async fn pq_feed_in_a_block_commits_via_opcode() {
    let e = wired_engine().await;
    let before = e.get_state_root().await;
    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_kp());
    assert!(feed.verify(), "precondition: PQ feed verifies");
    let tx = pq_tx(
        &sender_kp(),
        vec![OpCode::SysCallSubmitPqPriceFeed(Box::new(feed))],
        0,
    );
    let (applied, failed, _fees, status, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&tx), BLOCK_TIME)
        .await;
    assert_eq!(
        (applied, failed),
        (1, 0),
        "a valid PQ feed must apply as part of a block"
    );
    assert_eq!(status, vec![true]);
    assert_ne!(
        before,
        e.get_state_root().await,
        "a committed PQ feed must move the state root"
    );
    let committed = e
        .oracle_read()
        .await
        .feeds
        .get("STELL")
        .cloned()
        .expect("PQ feed committed via opcode");
    assert_eq!(committed.price_micro_usd, 250_000);
    assert!(
        !e.oracle_read().await.breaker_tripped,
        "an in-cap PQ feed latches nothing"
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
    // handle on the state engine at ALL. Receiving a feed over gossip is
    // exactly this - a verified value held off-chain by the receiving node.
    let feed = PqPriceFeedUpdate::sign("STELL", 999_999_999, BLOCK_TIME - 1, &publisher_kp());
    assert!(feed.verify(), "broadcast_price_feed refuses unsigned feeds");

    // `fetch_price_feed` on the receiving side: a bincode round-trip through
    // the local KV store, nothing more.
    let wire = bincode::serialize(&feed).expect("gossip serialization");
    let received: PqPriceFeedUpdate = bincode::deserialize(&wire).expect("gossip decode");
    assert_eq!(received.price_micro_usd, feed.price_micro_usd);
    assert!(
        received.verify(),
        "a gossiped feed still verifies after decode"
    );

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
async fn gossip_then_commit_equals_commit_only() {
    // Two nodes with identical state. Node A also receives the feed over
    // gossip before committing; node B never hears about it. They then commit
    // the SAME feed. If gossip could leak into state, their roots would
    // diverge here - a consensus split with no attacker involved.
    let a = wired_engine().await;
    let b = wired_engine().await;
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "identical setup, identical root"
    );

    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 5, &publisher_kp());
    // Node A: gossip copy arrives first (held off-chain, nothing written).
    let wire = bincode::serialize(&feed).unwrap();
    let gossiped: PqPriceFeedUpdate = bincode::deserialize(&wire).unwrap();
    assert!(gossiped.verify(), "gossip copy verifies");

    // Both nodes commit the identical feed. Each signs its own instance (the
    // Falcon signer is randomized), so the test also proves signature bytes —
    // which are NOT committed — cannot leak into the root.
    let feed_for_b = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 5, &publisher_kp());
    let (ok_a, _, after_a) = apply_feed_block(&a, gossiped, BLOCK_TIME).await;
    let (ok_b, _, after_b) = apply_feed_block(&b, feed_for_b, BLOCK_TIME).await;

    assert!(ok_a && ok_b, "both nodes must commit the same feed");
    assert_eq!(
        after_a, after_b,
        "a node that saw gossip must reach the SAME root as one that did not"
    );
    assert_eq!(
        after_a,
        a.get_state_root().await,
        "the root is stable after the commit applied"
    );
}

// ===========================================================================
// 2. Commit-time checks, at their exact block-time boundaries.
// ===========================================================================

fn fresh_state(kp: &FalconKeypair) -> OracleState {
    let mut st = OracleState::default();
    assert!(st.register_pq_publisher(kp.pubkey()));
    st
}

#[test]
fn freshness_boundaries_at_block_time() {
    let sk = publisher_kp();
    let t = BLOCK_TIME;

    // Exactly at the limit is still fresh (the rule is `age > limit`).
    let mut st = fresh_state(&sk);
    let exact = PqPriceFeedUpdate::sign("STELL", 250_000, t - STALE_PRICE_MAX_SECS, &sk);
    assert!(
        st.commit_feed_pq(&exact, t).is_ok(),
        "age == limit is fresh"
    );

    // One second past the limit is stale.
    let mut st = fresh_state(&sk);
    let over = PqPriceFeedUpdate::sign("STELL", 250_000, t - STALE_PRICE_MAX_SECS - 1, &sk);
    let err = st.commit_feed_pq(&over, t).unwrap_err();
    assert!(err.contains("stale"), "stale feed must be named: {err}");
    assert!(st.feeds.is_empty(), "a stale feed commits nothing");

    // A feed timestamped in the FUTURE relative to the block is rejected.
    let mut st = fresh_state(&sk);
    let future = PqPriceFeedUpdate::sign("STELL", 250_000, t + 1, &sk);
    let err = st.commit_feed_pq(&future, t).unwrap_err();
    assert!(err.contains("ahead"), "future feed must be named: {err}");

    // Signed with the publisher's own clock AT the block time: accepted.
    let mut st = fresh_state(&sk);
    let now = PqPriceFeedUpdate::sign("STELL", 250_000, t, &sk);
    assert!(st.commit_feed_pq(&now, t).is_ok());

    // A feed signed by a key outside the committed publisher set is refused
    // even though its signature is valid - "signed" is not "authorised".
    let rogue = FalconKeypair::generate_from_seed_bytes(&[0x99; 32]);
    let mut st = fresh_state(&sk);
    let signed_by_rogue = PqPriceFeedUpdate::sign("STELL", 250_000, t, &rogue);
    assert!(
        signed_by_rogue.verify(),
        "the rogue signature itself is valid"
    );
    let err = st.commit_feed_pq(&signed_by_rogue, t).unwrap_err();
    assert!(err.contains("publisher"), "{err}");

    // Monotonic per asset: an older observation cannot rewind the price, even
    // while it is still inside the freshness window.
    let mut st = fresh_state(&sk);
    let first = PqPriceFeedUpdate::sign("STELL", 250_000, t - 60, &sk);
    st.commit_feed_pq(&first, t).expect("first feed commits");
    let replay = PqPriceFeedUpdate::sign("STELL", 240_000, t - 60, &sk);
    let err = st.commit_feed_pq(&replay, t).unwrap_err();
    assert!(err.contains("non-monotonic"), "{err}");
    assert_eq!(st.feeds["STELL"].price_micro_usd, 250_000);
}

#[tokio::test]
async fn stale_feed_rejected_at_block_time() {
    // Engine-level staleness refusal (the committed-state half of the old
    // block test; the apply-path fee/nonce half — SEC-07/F-01 — is pinned by
    // `ed_feed_in_a_block_is_refused_fail_closed` above and the order suites).
    let e = wired_engine().await;
    let feed = PqPriceFeedUpdate::sign(
        "STELL",
        250_000,
        BLOCK_TIME - STALE_PRICE_MAX_SECS - 1,
        &publisher_kp(),
    );

    let before = e.get_state_root().await;
    let ok = e
        .oracle_write()
        .await
        .commit_feed_pq(&feed, BLOCK_TIME)
        .is_ok();

    assert!(!ok, "a stale feed must be rejected at block time");
    assert_eq!(
        e.get_state_root().await,
        before,
        "a refused direct commit moves nothing"
    );
    assert!(
        e.oracle_read().await.feeds.is_empty(),
        "a stale feed commits no price"
    );
}

#[tokio::test]
async fn deviation_feed_rejected_latches_breaker_and_blocks_later_feeds() {
    let e = wired_engine().await;

    // Seed the reference price.
    let first = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 60, &publisher_kp());
    let (ok, _, _) = apply_feed_block(&e, first, BLOCK_TIME).await;
    assert!(ok);

    // 20% above the committed price: well past MAX_PRICE_DEVIATION_BPS.
    let spike = PqPriceFeedUpdate::sign("STELL", 300_000, BLOCK_TIME - 30, &publisher_kp());
    let (ok, _, _) = apply_feed_block(&e, spike, BLOCK_TIME).await;
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

    // The latch is state: it moved the root, and it now refuses everything. A
    // refused direct commit moves nothing further (no fee debit at this
    // layer); what must NOT move is the ORACLE — the latch is already set and
    // the price unchanged. (The apply-path fee/nonce half — SEC-07/F-01 — is
    // pinned by `ed_feed_in_a_block_is_refused_fail_closed` above and the
    // order entry-point tests below.)
    let after_trip = e.get_state_root().await;
    let valid_again = PqPriceFeedUpdate::sign("STELL", 251_000, BLOCK_TIME - 5, &publisher_kp());
    let (ok, _, _) = apply_feed_block(&e, valid_again, BLOCK_TIME).await;
    assert!(!ok, "a latched breaker refuses even a perfectly fresh feed");
    assert_eq!(
        e.get_state_root().await,
        after_trip,
        "a refused direct commit moves nothing"
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
    let at_floor = PqPriceFeedUpdate::sign(
        "USDT",
        USDT_MIN_PEG_MICRO_USD,
        BLOCK_TIME - 10,
        &publisher_kp(),
    );
    let (ok, _, _) = apply_feed_block(&e, at_floor, BLOCK_TIME).await;
    assert!(ok, "a feed exactly at the peg floor must be accepted");

    // One micro-USD below the floor: rejected AND latched.
    let depeg = PqPriceFeedUpdate::sign(
        "USDT",
        USDT_MIN_PEG_MICRO_USD - 1,
        BLOCK_TIME - 5,
        &publisher_kp(),
    );
    let (ok, _, _) = apply_feed_block(&e, depeg, BLOCK_TIME).await;
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
    let who = [0x11u8; 32];
    e.credit_native(&who, 100 * STELL).await.expect("fund");
    assert!(e
        .oracle_write()
        .await
        .register_pq_publisher(publisher_kp().pubkey()));

    // Commit $0.25/STELL through the oracle (same function the syscall uses).
    {
        let mut oracle = e.oracle_write().await;
        let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_kp());
        oracle.commit_feed_pq(&feed, BLOCK_TIME).expect("commit");
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

    // Commit $0.25/STELL through the engine oracle (the feed no longer rides
    // a block; the orders below still do, so their fee/nonce asserts stand).
    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_kp());
    let (ok, _, _) = apply_feed_block(&e, feed, BLOCK_TIME).await;
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
        pq_tx(
            &sender_kp(),
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_USDT,
                is_buy: false,
                price,
                amount: 1_000,
            }],
            nonce,
        )
    };

    let before = e.get_state_root().await;
    let deviating = order_tx(300_000, 0);
    let fee = failure_fee(&e, &deviating).await;
    let sender = sender_addr();
    let balance_before = e.get_account(&sender).await.unwrap().balance;
    let (_a, _f, _fees, status, _) = e
        .apply_block_parallel_fees(std::slice::from_ref(&deviating), BLOCK_TIME)
        .await;
    assert_eq!(status, vec![false], "the deviating order must revert");
    // The refusal is not free: the failure fee is charged and the nonce is
    // consumed, while the ORDER itself left nothing behind.
    assert_refused_tx_paid_failure_fee(&e, &deviating, fee, balance_before, 0).await;
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
    // outright here (funded account) and consumes nonce 1 - the nonce the
    // refused order above burned.
    let (_a, _f, _fees, status, _) = e
        .apply_block_parallel_fees(&[order_tx(250_000, 1)], BLOCK_TIME)
        .await;
    assert_eq!(status, vec![true], "fair price passes the gate and places");
    let _ = before;

    // An in-band order goes through - the gate is a gate, not a
    // ban: with the price committed at $0.25, $0.255 (+2%) is fine.
    let (_a, _f, _fees, status, _) = e
        .apply_block_parallel_fees(&[order_tx(255_000, 2)], BLOCK_TIME)
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
    let victim_kp = FalconKeypair::generate_from_seed_bytes(&[0x08; 32]);
    let victim = derive_pq_address(PqScheme::Falcon512, victim_kp.pubkey(), &DEFAULT_SALT);
    e.credit_native(&victim, 1_000_000_000_000)
        .await
        .expect("fund victim");

    // Commit $0.25/STELL through the engine oracle. Both traders are still at
    // nonce 0 — the feed no longer consumes the sender's first sequence
    // number — and both nonces are admission-valid.
    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_kp());
    let (ok, _, _) = apply_feed_block(&e, feed, BLOCK_TIME).await;
    assert!(ok);

    let order_tx = |key: &FalconKeypair, price: u64, nonce: u64| {
        pq_tx(
            key,
            vec![OpCode::SysCallPlaceOrder {
                pair_id: PAIR_STELL_USDT,
                is_buy: false,
                price,
                amount: 1_000,
            }],
            nonce,
        )
    };

    // Deviating sell (+20% over the committed price) first, fair sell at the
    // committed price second, in ONE block.
    let bad = order_tx(&sender_kp(), 300_000, 0);
    let good = order_tx(&victim_kp, 250_000, 0);
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
    assert!(e
        .oracle_write()
        .await
        .register_pq_publisher(publisher_kp().pubkey()));
    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_kp());
    e.oracle_write()
        .await
        .commit_feed_pq(&feed, BLOCK_TIME)
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
    assert!(engine
        .oracle_write()
        .await
        .register_pq_publisher(publisher_kp().pubkey()));
    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_kp());
    engine
        .oracle_write()
        .await
        .commit_feed_pq(&feed, BLOCK_TIME)
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
    assert!(a
        .oracle_write()
        .await
        .register_pq_publisher(publisher_kp().pubkey()));
    assert!(b
        .oracle_write()
        .await
        .register_pq_publisher(publisher_kp().pubkey()));
    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "identical oracle state, identical root"
    );

    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TIME - 10, &publisher_kp());
    b.oracle_write()
        .await
        .commit_feed_pq(&feed, BLOCK_TIME)
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
