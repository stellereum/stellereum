//! Bridge/oracle audit: attestation, publisher-trust, staleness and PMM-feed
//! attack tests + regression tests for the fail-closed fixes (BR-OR-01..05).
//!
//! Attack coverage (each test FAILS on the vulnerable behavior, passes fixed):
//! * forged attestation (wrong/outside key) refused at engine AND plan level;
//! * replayed attestation (same source hash twice) refused via the replay set;
//! * stale oracle feed (old timestamp) refused via per-asset monotonicity;
//! * unauthorized publisher (valid sig, unknown key) refused, no state change;
//! * frozen feed (staleness gate) and absurd price jump (deviation bound).
//!
//! Regression coverage for the fixes in this audit:
//! * BR-OR-01 read path binds the feed to the requested asset;
//! * BR-OR-02 read path refuses zero-price feeds like the commit path;
//! * BR-OR-03 committed-feed freshness gate (`gate_order_at`);
//! * BR-OR-04 watchers/adapters refuse future (unfinalized) observations;
//! * BR-OR-05 EVM release orders refuse non-EVM chains (UNK-tag transplant).

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use stellereum::bridge::{
    BridgeIntent, BridgeState, EvmDepositEvent, EvmReleaseOrder, EvmWatcher, MultisigRelayer,
    SupportedChain, TeleportBridgeEngine, TeleportDepositEvent, TonInboundTx, TonWatcher,
    ARBITRUM_FINALITY_BLOCKS, ETHEREUM_FINALITY_BLOCKS, MIN_TON_CONFIRMATIONS,
};
use stellereum::bridge::bridge_adapters as adapters;
use stellereum::oracle::{
    OracleSafetyEngine, OracleState, PriceFeedUpdate, STALE_PRICE_MAX_SECS as ORACLE_STALE_MAX,
};
use stellereum::orderbook::PAIR_STELL_USDT;

fn gen_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn pub_of(sk: &SigningKey) -> [u8; 32] {
    sk.verifying_key().to_bytes()
}

fn sign_msg(sk: &SigningKey, msg: &[u8]) -> ([u8; 32], Vec<u8>) {
    (pub_of(sk), sk.sign(msg).to_vec())
}

/// Build a deposit event skeleton (unsigned) for the given claim.
fn deposit_skeleton(chain: SupportedChain, hash: [u8; 32], amount: u64) -> TeleportDepositEvent {
    TeleportDepositEvent {
        source_chain: chain,
        source_tx_hash: hash,
        recipient: [0xABu8; 32],
        asset: stellereum::bridge::LIVE_DEPOSIT_ASSET.to_string(),
        amount,
        validator_signatures: vec![],
        zk_proof: None,
    }
}

/// Sign the deposit's canonical message with each key in `signers`.
fn quorum_sigs_for(event: &TeleportDepositEvent, signers: &[&SigningKey]) -> Vec<([u8; 32], Vec<u8>)> {
    let msg = TeleportBridgeEngine::deposit_signing_message(event);
    signers.iter().map(|sk| sign_msg(sk, &msg)).collect()
}

// ============================================================================
// 1. Forged attestation: signatures from outside the validator set refuse.
// ============================================================================

#[test]
fn forged_attestation_refused_engine_and_plan() {
    let a = gen_key();
    let b = gen_key();
    let outsider = gen_key();
    let validators = vec![pub_of(&a), pub_of(&b)];

    // Engine level: quorum of outsider signatures over the right message.
    let mut engine = TeleportBridgeEngine::new(validators.clone());
    let mut ev = deposit_skeleton(SupportedChain::Ton, [0x11u8; 32], 1_000);
    ev.validator_signatures = quorum_sigs_for(&ev, &[&outsider, &outsider]);
    assert!(
        engine.process_deposit(&ev).is_err(),
        "outsider signatures must not reach quorum"
    );

    // One valid + one forged: still sub-quorum (needs 2 of 2 distinct).
    let mut ev2 = deposit_skeleton(SupportedChain::Ton, [0x12u8; 32], 1_000);
    let msg = TeleportBridgeEngine::deposit_signing_message(&ev2);
    ev2.validator_signatures = vec![sign_msg(&a, &msg), sign_msg(&outsider, &msg)];
    assert!(
        engine.process_deposit(&ev2).is_err(),
        "1 valid + 1 forged must not reach a 2-of-2 quorum"
    );

    // Plan level: the same forgery inside a block payload is refused.
    let state = BridgeState::default();
    let mut ev3 = deposit_skeleton(SupportedChain::Ton, [0x13u8; 32], 1_000);
    ev3.validator_signatures = quorum_sigs_for(&ev3, &[&outsider, &outsider]);
    let intents = vec![
        BridgeIntent::Deposit {
            chain: SupportedChain::Ton,
            source_tx_hash: ev3.source_tx_hash,
            recipient: ev3.recipient,
            amount: ev3.amount,
        },
        BridgeIntent::Attest {
            source_tx_hash: ev3.source_tx_hash,
            signatures: ev3.validator_signatures.clone(),
        },
    ];
    let res = state.plan(&intents, &validators, [9u8; 32], 1_000);
    assert!(
        res.is_err(),
        "plan must refuse a deposit attested only by outsiders"
    );

    // Control: two genuine signatures admit the deposit.
    let mut ev4 = deposit_skeleton(SupportedChain::Ton, [0x14u8; 32], 1_000);
    ev4.validator_signatures = quorum_sigs_for(&ev4, &[&a, &b]);
    assert!(engine.process_deposit(&ev4).is_ok());
}

// ============================================================================
// 2. Replay: the same attested source hash credits exactly once.
// ============================================================================

#[test]
fn replayed_attestation_refused_engine_and_plan() {
    let a = gen_key();
    let b = gen_key();
    let validators = vec![pub_of(&a), pub_of(&b)];

    // Engine level: identical valid deposit twice.
    let mut engine = TeleportBridgeEngine::new(validators.clone());
    let mut ev = deposit_skeleton(SupportedChain::Ton, [0x21u8; 32], 500);
    ev.validator_signatures = quorum_sigs_for(&ev, &[&a, &b]);
    assert!(engine.process_deposit(&ev).is_ok());
    assert!(
        engine.process_deposit(&ev).is_err(),
        "replayed source tx must be rejected"
    );

    // Plan level: the same hash in a LATER block is refused (replay set is
    // committed state that survives across plans).
    let state0 = BridgeState::default();
    let intents = vec![
        BridgeIntent::Deposit {
            chain: SupportedChain::Ton,
            source_tx_hash: [0x22u8; 32],
            recipient: [0xABu8; 32],
            amount: 500,
        },
        BridgeIntent::Attest {
            source_tx_hash: [0x22u8; 32],
            signatures: {
                let skel = deposit_skeleton(SupportedChain::Ton, [0x22u8; 32], 500);
                quorum_sigs_for(&skel, &[&a, &b])
            },
        },
    ];
    let plan1 = state0
        .plan(&intents, &validators, [9u8; 32], 1_000)
        .expect("first credit must succeed");
    assert!(plan1.state.processed_source_txs.contains(&[0x22u8; 32]));
    let res = plan1.state.plan(&intents, &validators, [9u8; 32], 2_000);
    assert!(
        res.is_err(),
        "second credit of the same source hash must be refused"
    );
}

// ============================================================================
// 3. Stale oracle feed: monotonicity per asset refuses rewinds.
// ============================================================================

#[test]
fn replayed_stale_oracle_feed_refused() {
    let sk = gen_key();
    let mut st = OracleState::default();
    assert!(st.register_publisher(pub_of(&sk)));

    let t0 = 1_000u64;
    let fresh = PriceFeedUpdate::sign("STELL", 1_000_000, t0, &sk);
    assert!(st.commit_feed(&fresh, t0).is_ok());

    // Older timestamp for the same asset: refused even though still inside
    // the 15-minute freshness window.
    let stale = PriceFeedUpdate::sign("STELL", 1_000_000, t0 - 10, &sk);
    let err = st
        .commit_feed(&stale, t0)
        .expect_err("older feed must be refused");
    assert!(err.contains("non-monotonic"), "unexpected error: {err}");

    // Equal timestamp: also refused (must strictly exceed).
    let same = PriceFeedUpdate::sign("STELL", 1_000_000, t0, &sk);
    assert!(
        st.commit_feed(&same, t0 + 1).is_err(),
        "equal timestamp must be refused"
    );

    // The committed price is untouched by both attempts.
    assert_eq!(st.feeds.get("STELL").unwrap().price_micro_usd, 1_000_000);
    assert!(!st.breaker_tripped, "monotonicity refusal must not latch");
}

// ============================================================================
// 4. Unauthorized publisher: valid signature, unknown key -> refuse, no change.
// ============================================================================

#[test]
fn unauthorized_publisher_refused_no_state_change() {
    let admitted = gen_key();
    let rogue = gen_key();
    let mut st = OracleState::default();
    assert!(st.register_publisher(pub_of(&admitted)));

    let feed = PriceFeedUpdate::sign("STELL", 2_000_000, 5_000, &rogue);
    assert!(feed.verify(), "rogue feed is self-consistently signed");
    let before = st.clone();
    let err = st
        .commit_feed(&feed, 5_000)
        .expect_err("unknown publisher must be refused");
    assert!(err.contains("not in the committed set"), "unexpected error: {err}");
    assert_eq!(st, before, "refused feed must commit nothing");
    assert!(!st.breaker_tripped);

    // Control: the admitted publisher's feed commits.
    let good = PriceFeedUpdate::sign("STELL", 2_000_000, 5_000, &admitted);
    assert!(st.commit_feed(&good, 5_000).is_ok());
}

#[test]
fn removed_publisher_cannot_publish() {
    let sk = gen_key();
    let mut st = OracleState::default();
    assert!(st.register_publisher(pub_of(&sk)));
    assert!(st.unregister_publisher(pub_of(&sk)));

    // History stays (committed feeds are never un-observed)...
    let feed = PriceFeedUpdate::sign("STELL", 3_000_000, 6_000, &sk);
    assert!(
        st.commit_feed(&feed, 6_000).is_err(),
        "removed publisher must not commit new feeds"
    );
    // ...and re-registering is observable, not silent.
    assert!(st.register_publisher(pub_of(&sk)));
    assert!(!st.register_publisher(pub_of(&sk)), "repeat register is a no-op");
}

// ============================================================================
// 5a. Frozen feed: staleness gate fires at commit time.
// ============================================================================

#[test]
fn frozen_feed_staleness_gate_fires() {
    assert_eq!(ORACLE_STALE_MAX, stellereum::oracle::STALE_PRICE_MAX_SECS);
    let sk = gen_key();
    let mut st = OracleState::default();
    assert!(st.register_publisher(pub_of(&sk)));
    let now = 100_000u64;

    // 16 minutes old at commit time: refused.
    let frozen = PriceFeedUpdate::sign("STELL", 1_000_000, now - ORACLE_STALE_MAX - 60, &sk);
    assert!(
        st.commit_feed(&frozen, now).is_err(),
        "frozen feed must trip the staleness gate"
    );
    // From the future: refused.
    let future = PriceFeedUpdate::sign("STELL", 1_000_000, now + 1, &sk);
    assert!(
        st.commit_feed(&future, now).is_err(),
        "future-dated feed must be refused"
    );
    assert!(!st.feeds.contains_key("STELL"));
    assert!(!st.breaker_tripped, "staleness refusal must not latch");
}

// ============================================================================
// 5b. Absurd price jump: the deviation bound exists and latches correctly.
// ============================================================================

#[test]
fn absurd_price_jump_trips_breaker() {
    let a = gen_key();
    let b = gen_key();
    let mut st = OracleState::default();
    assert!(st.register_publisher(pub_of(&a)));
    assert!(st.register_publisher(pub_of(&b)));
    let t = 50_000u64;
    assert!(st.commit_feed(&PriceFeedUpdate::sign("STELL", 1_000_000, t, &a), t).is_ok());

    // +6% from the SAME key: refused WITHOUT latching (per-publisher cap 5%).
    let drift = PriceFeedUpdate::sign("STELL", 1_060_000, t + 1, &a);
    let err = st.commit_feed(&drift, t + 1).expect_err("same-key drift must refuse");
    assert!(err.contains("same-publisher drift"), "unexpected error: {err}");
    assert!(!st.breaker_tripped, "per-publisher refusal must not latch");

    // +6% from a DIFFERENT key: admitted (full 10% rule for rotation).
    let rotated = PriceFeedUpdate::sign("STELL", 1_060_000, t + 1, &b);
    assert!(st.commit_feed(&rotated, t + 1).is_ok());

    // +20% single step (any key): breaker latches, nothing commits.
    let spike = PriceFeedUpdate::sign("STELL", 1_272_000, t + 2, &b);
    let err = st.commit_feed(&spike, t + 2).expect_err("+20% must trip breaker");
    assert!(err.contains("circuit breaker tripped"), "unexpected error: {err}");
    assert!(st.breaker_tripped);
    assert_eq!(
        st.feeds.get("STELL").unwrap().price_micro_usd,
        1_060_000,
        "spike must not commit"
    );
    // Latched: everything after refuses.
    let after = PriceFeedUpdate::sign("STELL", 1_060_000, t + 3, &b);
    assert!(st.commit_feed(&after, t + 3).is_err());
}

#[test]
fn read_path_absurd_jump_trips_breaker_against_twap() {
    let sk = gen_key();
    let mut engine = OracleSafetyEngine::new(vec![pub_of(&sk)]);
    engine.set_dex_twap("TON", 5_000_000);
    let now = 10_000u64;
    let spike = PriceFeedUpdate::sign("TON", 5_750_000, now, &sk); // +15%
    assert!(engine.resolve_price(Some(&spike), "TON", now).is_err());
    assert!(engine.circuit_breaker_triggered);
}

// ============================================================================
// Regression BR-OR-01: read path must bind the feed to the requested asset.
// ============================================================================

#[test]
fn read_path_rejects_cross_asset_feed() {
    let sk = gen_key();
    let mut engine = OracleSafetyEngine::new(vec![pub_of(&sk)]);
    engine.set_dex_twap("STELL", 5_000_000);
    let now = 20_000u64;

    // Correctly signed, fresh, trusted — but for BTC, priced as STELL.
    let cross = PriceFeedUpdate::sign("BTC", 99_000_000, now, &sk);
    let price = engine
        .resolve_price(Some(&cross), "STELL", now)
        .expect("cross-asset feed must be ignored, TWAP used");
    assert_eq!(
        price, 5_000_000,
        "attacker's BTC price must never price STELL"
    );
    assert!(
        !engine.circuit_breaker_triggered,
        "ignored feed must not latch the breaker (no one-key halt)"
    );
}

// ============================================================================
// Regression BR-OR-02: read path must refuse zero-price feeds (commit parity).
// ============================================================================

#[test]
fn read_path_rejects_zero_price_feed() {
    let sk = gen_key();
    let mut engine = OracleSafetyEngine::new(vec![pub_of(&sk)]);
    let now = 30_000u64;

    // No TWAP fallback: a zero price must be an error, never a committed 0.
    let zero = PriceFeedUpdate::sign("STELL", 0, now, &sk);
    assert!(
        engine.resolve_price(Some(&zero), "STELL", now).is_err(),
        "zero price must not resolve"
    );
    assert!(!engine.circuit_breaker_triggered);

    // Commit path already refuses zero; pin the parity.
    let mut st = OracleState::default();
    assert!(st.register_publisher(pub_of(&sk)));
    assert!(st.commit_feed(&zero, now).is_err());
}

// ============================================================================
// Regression BR-OR-03: frozen committed feeds refuse order admission (fresh gate).
// ============================================================================

#[test]
fn frozen_committed_feed_refuses_orders_via_fresh_gate() {
    let sk = gen_key();
    let mut st = OracleState::default();
    assert!(st.register_publisher(pub_of(&sk)));
    let t0 = 40_000u64;
    assert!(
        st.commit_feed(&PriceFeedUpdate::sign("STELL", 1_000_000, t0, &sk), t0)
            .is_ok()
    );

    // Fresh: the time-aware gate admits a sane limit price.
    assert!(st.gate_order_at(PAIR_STELL_USDT, 1_000_000, t0 + 10).is_ok());

    // Frozen (committed feed older than the staleness window): refuse.
    let err = st
        .gate_order_at(PAIR_STELL_USDT, 1_000_000, t0 + ORACLE_STALE_MAX + 1)
        .expect_err("frozen feed must refuse order admission");
    assert!(err.contains("frozen"), "unexpected error: {err}");
    assert!(!st.breaker_tripped, "frozen refusal is a gate, not an alarm");

    // Missing feed still admits (nothing to be stale) — legacy semantics kept.
    let empty = OracleState::default();
    assert!(empty.gate_order_at(PAIR_STELL_USDT, 9_999_999, t0).is_ok());
}

// ============================================================================
// Regression BR-OR-04: watchers and depth checks refuse future observations.
// ============================================================================

#[test]
fn watchers_refuse_future_observations() {
    // TON watcher with a zero minimum would previously accept a future tx
    // (`saturating_sub` reports 0 confirmations, 0 >= 0).
    let mut w = TonWatcher::new(0);
    w.advance(100);
    let future_tx = TonInboundTx {
        tx_hash: [0xF0u8; 32],
        workchain: 0,
        masterchain_seqno: 101,
        lt: 1,
        amount_nano: 1_000,
        recipient: [2u8; 32],
        asset: "TON".into(),
    };
    assert!(!w.is_finalized(&future_tx));
    assert!(
        w.accept(&future_tx).is_err(),
        "future TON observation must be refused at any minimum"
    );

    // EVM watcher: same rule.
    let mut ew = EvmWatcher::new(SupportedChain::Ethereum, 0);
    ew.advance(500);
    let future_ev = EvmDepositEvent {
        chain: SupportedChain::Ethereum,
        tx_hash: [0xF1u8; 32],
        log_index: 0,
        block_number: 501,
        token: [0xDA; 20],
        sender: [0x11; 20],
        stell_recipient: [0x99; 32],
        amount_nano: 1_000,
    };
    assert!(!ew.is_finalized(&future_ev));
    assert!(
        ew.accept(&future_ev).is_err(),
        "future EVM observation must be refused at any minimum"
    );

    // Controls: default-minimum watchers still enforce depth then accept.
    let mut w2 = TonWatcher::new(MIN_TON_CONFIRMATIONS);
    w2.advance(100 + MIN_TON_CONFIRMATIONS);
    let buried = TonInboundTx {
        masterchain_seqno: 100,
        ..future_tx
    };
    assert_eq!(w2.accept(&buried).unwrap(), 1_000);

    let mut ew2 = EvmWatcher::new(SupportedChain::Ethereum, ETHEREUM_FINALITY_BLOCKS);
    ew2.advance(1_000 + ETHEREUM_FINALITY_BLOCKS);
    let buried_evm = EvmDepositEvent {
        block_number: 1_000,
        ..future_ev
    };
    assert_eq!(ew2.accept(&buried_evm).unwrap(), 1_000);
}

#[test]
fn spv_depth_refuses_header_ahead_of_finalized_head() {
    let a = gen_key();
    let b = gen_key();
    let c = gen_key();
    let validators = vec![pub_of(&a), pub_of(&b), pub_of(&c)];

    // A header ABOVE the watcher-claimed finalized head must not verify, even
    // with a full quorum over it (depth arithmetic alone yields 0).
    let mut header = adapters::StoredHeader {
        chain: SupportedChain::Ton,
        height: 200,
        prev_hash: [0u8; 32],
        tx_root: [0xAAu8; 32],
    };
    let msg = header.signing_message();
    let sigs = vec![sign_msg(&a, &msg), sign_msg(&b, &msg)];
    let claim = adapters::DepositClaim {
        chain: SupportedChain::Ton,
        source_tx_hash: [0xBu8; 32],
        recipient: [0xCCu8; 32],
        amount: 777,
    };
    // TonCell evidence with `finalized_seqno` BELOW the header height.
    let bad_evidence = adapters::DepositEvidence::TonCell {
        header: header.clone(),
        header_signatures: sigs.clone(),
        finalized_seqno: 199,
        boc_bytes: vec![0x01],
    };
    assert!(
        adapters::verify_evidence(&claim, &bad_evidence, &validators).is_err(),
        "header ahead of finalized head must fail the depth gate"
    );

    // Sanity: the depth gate still measures real buried headers (this fails
    // later at BoC parsing, which proves depth PASSED — the failure moved).
    header.height = 100;
    let msg2 = header.signing_message();
    let sigs2 = vec![sign_msg(&a, &msg2), sign_msg(&b, &msg2)];
    let buried_evidence = adapters::DepositEvidence::TonCell {
        header,
        header_signatures: sigs2,
        finalized_seqno: 100 + MIN_TON_CONFIRMATIONS,
        boc_bytes: vec![0x01],
    };
    let err = adapters::verify_evidence(&claim, &buried_evidence, &validators)
        .expect_err("garbage BoC must still fail, but at parsing");
    assert!(
        err.contains("BoC") || err.contains("blob"),
        "depth must pass so parsing is the failure: {err}"
    );
    let _ = ARBITRUM_FINALITY_BLOCKS;
}

// ============================================================================
// Regression BR-OR-05: EVM release orders refuse non-EVM chains.
// ============================================================================

#[test]
fn evm_release_order_refuses_non_evm_chain() {
    let keys: Vec<SigningKey> = (0..3).map(|_| gen_key()).collect();
    let pubs: Vec<[u8; 32]> = keys.iter().map(pub_of).collect();
    let relayer = MultisigRelayer::new(pubs);

    // A Ton-chain order through the EVM envelope: quorum signs the "UNK"-tagged
    // preimage. Identical fields on Solana would share that exact message.
    let mut bad = EvmReleaseOrder::new(
        SupportedChain::Ton,
        [0xDDu8; 32],
        [0xDA; 20],
        [0x22; 20],
        1_000,
        7,
        50_000,
    );
    let msg = bad.signing_message();
    bad.signatures.push(sign_msg(&keys[0], &msg));
    bad.signatures.push(sign_msg(&keys[1], &msg));
    assert!(
        !bad.is_approved(&relayer, 1_000),
        "non-EVM chain must never approve through the EVM envelope"
    );

    // Control: the same quorum on Arbitrum approves.
    let mut good = EvmReleaseOrder::new(
        SupportedChain::Arbitrum,
        [0xDDu8; 32],
        [0xDA; 20],
        [0x22; 20],
        1_000,
        7,
        50_000,
    );
    let msg2 = good.signing_message();
    good.signatures.push(sign_msg(&keys[0], &msg2));
    good.signatures.push(sign_msg(&keys[1], &msg2));
    assert!(good.is_approved(&relayer, 1_000));
    // Expiry still enforced.
    assert!(!good.is_approved(&relayer, 50_001));
}
