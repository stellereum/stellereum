//! Oracle single-publisher drift cap (audit O1 MEDIUM follow-up):
//! the same key twice in a row may move an asset at most 5%/feed (HALF the
//! global 10%), fail-closed refuse + loud warn, WITHOUT latching the breaker.
//! Distinct-key feeds keep the 10% rule; the breaker still latches on true
//! moves (>10%, any key); the committed baseline math is untouched.
//!
//! Explicitly out of scope (pinned here): a TWAP-anchored commit guard would
//! need committed TWAP history — new consensus state, a
//! `COMMITMENT_VERSION` bump and a snapshot migration — for a read-path hint
//! (`DexTwapCalculator` / `OracleSafetyEngine`) that is advisory-only by
//! design and never commits. Key rotation stays Sybil-priced by the
//! governance publisher set.

use ed25519_dalek::SigningKey;
use stellereum::oracle::{
    deviation_bps, OracleState, PriceFeedUpdate, MAX_PRICE_DEVIATION_BPS,
    MAX_SAME_PUBLISHER_DEVIATION_BPS,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::InMemoryStateEngine;
use stellereum::svm::OpCode;

const BLOCK_TIME: u64 = 1_700_000_000;

fn key_a() -> SigningKey {
    SigningKey::from_bytes(&[0xA1; 32])
}
fn key_b() -> SigningKey {
    SigningKey::from_bytes(&[0xB2; 32])
}
fn sender_key() -> SigningKey {
    SigningKey::from_bytes(&[0x07; 32])
}

fn state_with_publishers() -> OracleState {
    let mut o = OracleState::default();
    assert!(o.register_publisher(key_a().verifying_key().to_bytes()));
    assert!(o.register_publisher(key_b().verifying_key().to_bytes()));
    o
}

fn feed(key: &SigningKey, price: u64, ts: u64) -> PriceFeedUpdate {
    PriceFeedUpdate::sign("STELL", price, ts, key)
}

fn committed_price(o: &OracleState) -> u64 {
    o.feeds
        .get("STELL")
        .expect("baseline committed")
        .price_micro_usd
}

// ===========================================================================
// 1. Constants + baseline math intact.
// ===========================================================================

#[test]
fn per_publisher_cap_is_half_the_global_cap() {
    assert_eq!(MAX_PRICE_DEVIATION_BPS, 1000);
    assert_eq!(MAX_SAME_PUBLISHER_DEVIATION_BPS, 500);
    assert_eq!(
        MAX_SAME_PUBLISHER_DEVIATION_BPS,
        MAX_PRICE_DEVIATION_BPS / 2
    );
}

#[test]
fn committed_baseline_math_is_intact() {
    assert_eq!(deviation_bps(1_000_000, 1_000_000), 0);
    assert_eq!(deviation_bps(1_050_000, 1_000_000), 500);
    assert_eq!(deviation_bps(1_100_000, 1_000_000), 1000);
    assert_eq!(deviation_bps(950_000, 1_000_000), 500);
    assert_eq!(deviation_bps(0, 0), 0);
    assert_eq!(deviation_bps(1, 0), u64::MAX);
}

// ===========================================================================
// 2. Same-key walk capped at 5%/step (boundary exact).
// ===========================================================================

#[test]
fn same_key_walk_is_capped_at_five_percent_per_step() {
    let mut o = state_with_publishers();
    // Baseline: key A at 1_000_000.
    o.commit_feed(&feed(&key_a(), 1_000_000, BLOCK_TIME - 20), BLOCK_TIME)
        .expect("genesis feed commits");
    // Exactly +5% (bps == 500, not > 500) from the SAME key: passes.
    o.commit_feed(&feed(&key_a(), 1_050_000, BLOCK_TIME - 10), BLOCK_TIME)
        .expect("same-key +5% exactly must pass");
    assert_eq!(committed_price(&o), 1_050_000);
    assert!(!o.breaker_tripped);
    // Baseline advanced: the next step is measured against 1_050_000.
    // +501 bps over the new baseline (1_102_605 vs 1_050_000): refused.
    let err = o
        .commit_feed(&feed(&key_a(), 1_102_605, BLOCK_TIME - 5), BLOCK_TIME)
        .expect_err("same-key +501bps must be refused");
    assert!(
        err.contains("same-publisher"),
        "refusal must name the rule: {err}"
    );
    assert!(
        !o.breaker_tripped,
        "a 5%-band refusal must NOT latch the breaker"
    );
    assert_eq!(
        committed_price(&o),
        1_050_000,
        "refused feed commits nothing"
    );
    // +500 bps over the new baseline (1_102_500): passes.
    o.commit_feed(&feed(&key_a(), 1_102_500, BLOCK_TIME - 5), BLOCK_TIME)
        .expect("same-key +500bps must pass");
    assert_eq!(committed_price(&o), 1_102_500);
    assert!(!o.breaker_tripped);
}

#[test]
fn same_key_six_percent_is_refused_without_latching() {
    let mut o = state_with_publishers();
    o.commit_feed(&feed(&key_a(), 1_000_000, BLOCK_TIME - 20), BLOCK_TIME)
        .expect("baseline");
    let err = o
        .commit_feed(&feed(&key_a(), 1_060_000, BLOCK_TIME - 10), BLOCK_TIME)
        .expect_err("same-key +6% must be refused");
    assert!(err.contains("same-publisher"), "{err}");
    assert!(!o.breaker_tripped);
    assert_eq!(committed_price(&o), 1_000_000);
    // The key is NOT burned: a later in-cap feed from it still commits.
    o.commit_feed(&feed(&key_a(), 1_040_000, BLOCK_TIME - 5), BLOCK_TIME)
        .expect("same key back in-cap must commit");
    assert_eq!(committed_price(&o), 1_040_000);
}

// ===========================================================================
// 3. Key rotation unaffected: the 10% rule still applies across keys.
// ===========================================================================

#[test]
fn key_rotation_keeps_the_ten_percent_rule() {
    let mut o = state_with_publishers();
    o.commit_feed(&feed(&key_a(), 1_000_000, BLOCK_TIME - 20), BLOCK_TIME)
        .expect("baseline from A");
    // +6% from a DIFFERENT key (B after A): commits under the 10% rule.
    o.commit_feed(&feed(&key_b(), 1_060_000, BLOCK_TIME - 10), BLOCK_TIME)
        .expect("rotated-key +6% must commit");
    assert_eq!(committed_price(&o), 1_060_000);
    assert!(!o.breaker_tripped);
    // Exactly +10% across keys (bps == 1000, not > 1000): commits.
    o.commit_feed(&feed(&key_a(), 1_166_000, BLOCK_TIME - 5), BLOCK_TIME)
        .expect("rotated-key +10% exactly must commit");
    assert_eq!(committed_price(&o), 1_166_000);
    assert!(!o.breaker_tripped);
}

// ===========================================================================
// 4. Breaker still latches at true moves (>10%), same key or rotated.
// ===========================================================================

#[test]
fn breaker_still_latches_past_ten_percent_same_key() {
    let mut o = state_with_publishers();
    o.commit_feed(&feed(&key_a(), 1_000_000, BLOCK_TIME - 20), BLOCK_TIME)
        .expect("baseline");
    let err = o
        .commit_feed(&feed(&key_a(), 1_110_000, BLOCK_TIME - 10), BLOCK_TIME)
        .expect_err("same-key +11% must trip the breaker");
    assert!(err.contains("circuit breaker tripped"), "{err}");
    assert!(o.breaker_tripped);
    assert_eq!(
        committed_price(&o),
        1_000_000,
        "tripped feed commits nothing"
    );
    // Latched: everything after is refused until governance resets.
    assert!(o
        .commit_feed(&feed(&key_b(), 1_000_000, BLOCK_TIME - 5), BLOCK_TIME)
        .is_err());
    assert!(o.reset_breaker());
    o.commit_feed(&feed(&key_b(), 1_000_000, BLOCK_TIME - 5), BLOCK_TIME)
        .expect("post-reset feed commits");
}

#[test]
fn breaker_still_latches_past_ten_percent_rotated_key() {
    let mut o = state_with_publishers();
    o.commit_feed(&feed(&key_a(), 1_000_000, BLOCK_TIME - 20), BLOCK_TIME)
        .expect("baseline");
    let err = o
        .commit_feed(&feed(&key_b(), 890_000, BLOCK_TIME - 10), BLOCK_TIME)
        .expect_err("rotated-key -11% must trip the breaker");
    assert!(err.contains("circuit breaker tripped"), "{err}");
    assert!(o.breaker_tripped);
}

#[test]
fn usdt_depeg_still_latches() {
    let mut o = state_with_publishers();
    let err = o
        .commit_feed(
            &PriceFeedUpdate::sign("USDT", 940_000, BLOCK_TIME - 10, &key_a()),
            BLOCK_TIME,
        )
        .expect_err("depeg must latch");
    assert!(err.contains("depeg"), "{err}");
    assert!(o.breaker_tripped);
}

// ===========================================================================
// 5. End to end: a same-key 6% feed transaction fails WITHOUT latching.
// ===========================================================================

async fn wired_engine() -> InMemoryStateEngine {
    let e = InMemoryStateEngine::new();
    {
        let mut oracle = e.oracle_write().await;
        oracle.publishers.insert(key_a().verifying_key().to_bytes());
        oracle.publishers.insert(key_b().verifying_key().to_bytes());
    }
    let sender = sender_key().verifying_key().to_bytes();
    e.credit_native(&sender, 1_000_000_000_000)
        .await
        .expect("fund");
    e
}

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

#[tokio::test]
async fn block_with_same_key_six_percent_feed_fails_open_breaker() {
    let e = wired_engine().await;
    let base = feed(&key_a(), 1_000_000, BLOCK_TIME - 20);
    let (ok, _, _) = {
        let tx = feed_tx(base, 0);
        let (_a, _f, _fees, status, _) = e.apply_block_parallel_fees(&[tx], BLOCK_TIME).await;
        (status[0], _a, _f)
    };
    assert!(ok, "baseline feed must commit");

    // Same key, +6%: the block refuses the transaction but the breaker stays clear.
    //
    // SEC-07 / F-01: the refusal is ATTRIBUTABLE (the transaction got past
    // admission and failed during execution), so it pays the failure fee and
    // CONSUMES ITS NONCE. The rotated feed below is therefore signed with the
    // NEXT nonce (2), not 1 - re-using 1 would be a replay, which is refused
    // at ADMISSION (and would move nothing at all).
    let walk = feed(&key_a(), 1_060_000, BLOCK_TIME - 10);
    let tx = feed_tx(walk, 1);
    let (_applied, _failed, _fees, status, _) =
        e.apply_block_parallel_fees(&[tx], BLOCK_TIME).await;
    assert_eq!(status, vec![false], "same-key +6% tx must fail");
    {
        let oracle = e.oracle_read().await;
        assert!(
            !oracle.breaker_tripped,
            "refusal must not latch the breaker"
        );
        assert_eq!(
            oracle.feeds.get("STELL").unwrap().price_micro_usd,
            1_000_000,
            "refused feed commits nothing"
        );
    } // Drop the read guard BEFORE the next apply: the block path takes the
      // oracle write lock, so holding this across it self-deadlocks.
    assert_eq!(
        e.get_account(&sender_key().verifying_key().to_bytes())
            .await
            .unwrap()
            .nonce,
        2,
        "the paid refusal consumed the sender's nonce (SEC-07)"
    );

    // Rotated key, +6% over the same baseline: commits.
    let rotated = feed(&key_b(), 1_060_000, BLOCK_TIME - 5);
    let tx = feed_tx(rotated, 2);
    let (_applied, _failed, _fees, status, _) =
        e.apply_block_parallel_fees(&[tx], BLOCK_TIME).await;
    assert_eq!(status, vec![true], "rotated-key +6% tx must apply");
    assert_eq!(
        e.oracle_read()
            .await
            .feeds
            .get("STELL")
            .unwrap()
            .price_micro_usd,
        1_060_000
    );
}

// ===========================================================================
// B-GOV/O1: single-source baseline walk. One compromised publisher key walks
// the committed baseline +5%/feed forever with no latch and no TWAP anchor.
// DESIRED: cumulative drift >10% from genesis trips the breaker or is refused.
// FAILS on current code (each +500bps step commits, breaker stays clear).
// ===========================================================================

#[test]
fn bgov_single_publisher_walk_drifts_past_ten_percent_without_latch() {
    let mut o = state_with_publishers();
    o.commit_feed(&feed(&key_a(), 1_000_000, BLOCK_TIME - 30), BLOCK_TIME)
        .expect("genesis baseline commits");
    // Three exact +5% same-key steps: each is == 500bps, not > 500, so each
    // passes the per-publisher cap; each is < 1000bps so none latches.
    for (price, ts) in [
        (1_050_000u64, BLOCK_TIME - 20),
        (1_102_500u64, BLOCK_TIME - 10),
        (1_157_625u64, BLOCK_TIME - 5),
    ] {
        o.commit_feed(&feed(&key_a(), price, ts), BLOCK_TIME)
            .unwrap_or_else(|e| panic!("same-key +5% step to {price} must commit on current code: {e}"));
    }
    let cumulative = deviation_bps(committed_price(&o), 1_000_000);
    assert!(
        cumulative > MAX_PRICE_DEVIATION_BPS,
        "test bug: three +5% steps must drift >10% cumulatively, got {cumulative}bps"
    );
    assert!(
        o.breaker_tripped,
        "B-GOV/O1 REAL: single key walked +15.8% (1M -> {}) with NO latch",
        committed_price(&o)
    );
}
