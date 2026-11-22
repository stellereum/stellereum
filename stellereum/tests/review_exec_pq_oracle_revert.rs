//! REFUTATION PIN (review execution/atomicity, claim 2): a PQ oracle feed
//! does NOT survive a revert or an out-of-gas.
//!
//! The review claimed `snapshot_payload_domains` / `oracle_before` only list
//! `SysCallSubmitPriceFeed`. In the CURRENT tree both scans include
//! `SysCallSubmitPqPriceFeed` behind `EXEC_HARDENING_V1`
//! (apply.rs:254-255 and apply.rs:672-694), and that gate is
//! `ACTIVE FROM GENESIS` (chain_spec.rs:45). On a non-Success VM result the
//! in-place oracle is restored from `oracle_before`
//! (apply.rs:921-925 -> types.rs:598-608), preserving only the sticky breaker
//! latch.
//!
//! These tests drive the two VM failure modes the review named and assert the
//! committed price is gone while the deliberate sticky-breaker policy is not
//! touched (the latch stays false because neither payload trips it).

use stellereum::bridge::{BridgeIntent, SupportedChain};
use stellereum::oracle::PqPriceFeedUpdate;
use stellereum::post_quantum::{
    derive_pq_address, FalconKeypair, PqScheme, DEFAULT_SALT, FALCON512_SIG_LEN,
};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::svm::{OpCode, GAS_SUBMIT_PQ_PRICE_FEED};

const BLOCK_TS: u64 = 1_700_000_000;

fn sign_pq_tx(
    kp: &FalconKeypair,
    to: [u8; 32],
    amount: u64,
    gas_limit: u64,
    payload: Vec<OpCode>,
) -> Transaction {
    let dummy = vec![0u8; FALCON512_SIG_LEN];
    let probe = Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        dummy,
        to,
        amount,
        gas_limit,
        0,
        1,
        1,
        payload.clone(),
        &DEFAULT_SALT,
    );
    let sig = kp.sign(&probe.signing_message());
    Transaction::new_pq_explicit(
        PqScheme::Falcon512,
        kp.public_key.clone(),
        sig,
        to,
        amount,
        gas_limit,
        0,
        1,
        1,
        payload,
        &DEFAULT_SALT,
    )
}

async fn engine_with_publisher(seed: u8) -> (InMemoryStateEngine, FalconKeypair, FalconKeypair) {
    let engine = InMemoryStateEngine::new();
    let kp = FalconKeypair::generate_from_seed(seed);
    let publisher = FalconKeypair::generate_from_seed(seed.wrapping_add(1));
    assert!(engine
        .oracle_write()
        .await
        .register_pq_publisher(&publisher.public_key));
    let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    engine
        .update_account(AccountState::new(sender, 10_000_000))
        .await;
    (engine, kp, publisher)
}

async fn committed_price(engine: &InMemoryStateEngine) -> Option<u64> {
    engine
        .oracle_read()
        .await
        .feeds
        .get("STELL")
        .map(|f| f.price_micro_usd)
}

#[tokio::test]
async fn pq_price_feed_does_not_survive_a_later_revert() {
    let (engine, kp, publisher) = engine_with_publisher(0x71).await;
    let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TS, &publisher);

    // A shape-invalid bridge intent AFTER the feed reverts the whole payload.
    let bad_withdraw = BridgeIntent::Withdraw {
        chain: SupportedChain::Ethereum,
        target_address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        amount: 0,
    };
    let tx = sign_pq_tx(
        &kp,
        sender,
        0,
        10_000,
        vec![
            OpCode::SysCallSubmitPqPriceFeed(Box::new(feed)),
            OpCode::SysCallBridge(Box::new(bad_withdraw)),
        ],
    );

    let res = engine.apply_transaction(&tx, BLOCK_TS).await;
    assert!(res.is_err(), "the payload must revert");
    assert_eq!(
        committed_price(&engine).await,
        None,
        "a reverted PQ feed must leave no committed price (pre-payload: absent)"
    );
    assert!(
        !engine.oracle_read().await.breaker_tripped,
        "no breaker was tripped by this payload"
    );
}

#[tokio::test]
async fn pq_price_feed_does_not_survive_later_out_of_gas() {
    let (engine, kp, publisher) = engine_with_publisher(0x73).await;
    let sender = derive_pq_address(PqScheme::Falcon512, &kp.public_key, &DEFAULT_SALT);
    let feed = PqPriceFeedUpdate::sign("STELL", 250_000, BLOCK_TS, &publisher);

    // The feed needs exactly GAS_SUBMIT_PQ_PRICE_FEED; the following Push(1)
    // then runs out of gas, AFTER the feed already mutated the oracle.
    let tx = sign_pq_tx(
        &kp,
        sender,
        0,
        GAS_SUBMIT_PQ_PRICE_FEED,
        vec![
            OpCode::SysCallSubmitPqPriceFeed(Box::new(feed)),
            OpCode::Push(1),
        ],
    );

    let res = engine.apply_transaction(&tx, BLOCK_TS).await;
    assert!(res.is_err(), "the payload must run out of gas");
    assert_eq!(
        committed_price(&engine).await,
        None,
        "an out-of-gas PQ feed must leave no committed price"
    );
    assert!(
        !engine.oracle_read().await.breaker_tripped,
        "no breaker was tripped by this payload"
    );
}
