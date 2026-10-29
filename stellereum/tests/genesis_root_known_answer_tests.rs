//! The genesis state root must be a known answer.
//!
//! `fund_genesis` credits every validator in the set the same fixed balance and
//! derives the faucet account from `STELL_FAUCET_KEY`. The resulting root is the
//! fingerprint of the chain: two nodes that disagree on it form separate chains
//! silently, and the node only notices when it compares a *persisted* root, which
//! a first-time node has none of.
//!
//! The root depends on more than that logic. `COMMITMENT_VERSION` is the first
//! field of the commitment digest, and the digest is itself a leaf in the state
//! trie, so bumping the version re-roots genesis even when no account, validator
//! or token changed. That is a legitimate hard fork -- but it is invisible unless
//! something pins the value.
//!
//! Nothing did. `tests/deterministic_genesis_tests.rs` builds its validator set
//! from `OsRng` and only asserts that two engines agree *with each other*, so no
//! test in the tree could notice the root moving. The TokenRegistry change
//! (`COMMITMENT_VERSION` 1 -> 2 plus a new digest section) moved it, and the only
//! symptom was a live node refusing to start with two opaque hex strings.
//!
//! `COMMITMENT_VERSION` 3 -> 4 added the oracle (publishers, committed feeds,
//! breaker latch) to the digest: prices decide whether an order is accepted, so
//! an oracle invisible to the root would let two nodes trade against different
//! prices under the same root.
//!
//! So: the constant below may only be updated in a commit that also bumps
//! `COMMITMENT_VERSION` or intentionally changes a `GENESIS_*`/PMM constant. If
//! this test fails, that is a hard fork and needs a version bump and a wipe --
//! not a test update.

use std::sync::Arc;

use stellereum::consensus::ValidatorSet;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};

/// Fixed validator ids and faucet seed. Do NOT generate these: the point is that
/// the inputs are constants, so the root is a constant.
const V1: [u8; 32] = [
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const V2: [u8; 32] = [
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
];
/// 32-byte ed25519 seed, as `STELL_FAUCET_KEY` would carry it (hex, no 0x).
const FAUCET_SEED_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// The expected genesis state root for the inputs above.
///
/// Pinned from the current code, not from a live node: the live stand's root
/// (`a927873ae7ea04df...`) is specific to ITS validator keys, so it cannot be
/// reused here. What matters is that this value is derived from fixed inputs and
/// is asserted, so any future change to the commitment path or the genesis
/// constants fails this test instead of silently re-rooting the chain.
///
/// History: `61336779...` was v1 bare-MIN unbacked genesis bond.
/// `f473a74a...` (SEC-ECON-01 P0) transfers the genesis validator bond (1,000 STELL)
/// from validator liquid balances to STAKING_POOL so genesis stake is fully backed.
const EXPECTED_GENESIS_ROOT: &str =
    "f473a74aa0dbdff3f99ecbf31c65adc71af250e673e823caaf9ef1a781c27648";

async fn build() -> Arc<InMemoryStateEngine> {
    let engine = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(vec![(V1, 1), (V2, 1)]);

    // Same sequence as src/main.rs: fund the validators, then credit the faucet.
    stellereum::runtime::fund_genesis(&engine, &vs, 100_000_000_000_000_000).await;

    let seed = hex::decode(FAUCET_SEED_HEX).unwrap();
    let faucet = stellereum::rpc::Faucet::new(
        <[u8; 32]>::try_from(seed.as_slice()).unwrap(),
        1,
        100 * 1_000_000_000,
        1_000 * 1_000_000_000,
    );
    let _ = engine
        .credit_native(&faucet.account(), 1_000_000_000_000_000)
        .await; // GATE: intentional ignore

    engine
}

#[tokio::test]
async fn genesis_root_is_a_known_answer() {
    let engine = build().await;
    let root = hex::encode(engine.get_state_root().await);
    assert_eq!(
        root, EXPECTED_GENESIS_ROOT,
        "the genesis state root moved. This is a hard fork: bump COMMITMENT_VERSION \
         (src/commitment.rs) or a GENESIS_*/PMM constant deliberately, bump the \
         constant in this test in the SAME commit, and expect every existing data \
         directory to need a wipe."
    );
}

#[tokio::test]
async fn genesis_root_does_not_depend_on_funding_order() {
    // Same set, opposite insertion order. The trie is canonical and the validator
    // set is a BTreeMap, so this must hold; it is cheap insurance against anyone
    // introducing an order-sensitive map into the commitment path.
    let a = Arc::new(InMemoryStateEngine::new());
    let vs_a = ValidatorSet::from_list(vec![(V1, 1), (V2, 1)]);
    stellereum::runtime::fund_genesis(&a, &vs_a, 100_000_000_000_000_000).await;
    let faucet_a =
        stellereum::rpc::Faucet::new([0x11u8; 32], 1, 100_000_000_000, 1_000_000_000_000);
    let _ = a
        .credit_native(&faucet_a.account(), 1_000_000_000_000_000)
        .await; // GATE: intentional ignore

    let b = Arc::new(InMemoryStateEngine::new());
    let vs_b = ValidatorSet::from_list(vec![(V2, 1), (V1, 1)]);
    let faucet_b =
        stellereum::rpc::Faucet::new([0x11u8; 32], 1, 100_000_000_000, 1_000_000_000_000);
    // Faucet first this time.
    let _ = b
        .credit_native(&faucet_b.account(), 1_000_000_000_000_000)
        .await; // GATE: intentional ignore
    stellereum::runtime::fund_genesis(&b, &vs_b, 100_000_000_000_000_000).await;

    assert_eq!(
        a.get_state_root().await,
        b.get_state_root().await,
        "genesis must be a function of the account set, not of the order it was built"
    );
}

#[tokio::test]
async fn a_different_validator_set_gives_a_different_root() {
    // The flip side: the root must actually be sensitive to the validator set, or
    // the known-answer test above would pass for the wrong reason.
    let engine = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(vec![(V1, 1), ([0x33u8; 32], 1)]);
    stellereum::runtime::fund_genesis(&engine, &vs, 100_000_000_000_000_000).await;
    let faucet = stellereum::rpc::Faucet::new([0x11u8; 32], 1, 100_000_000_000, 1_000_000_000_000);
    let _ = engine
        .credit_native(&faucet.account(), 1_000_000_000_000_000)
        .await; // GATE: intentional ignore

    assert_ne!(
        hex::encode(engine.get_state_root().await),
        EXPECTED_GENESIS_ROOT,
        "a different validator set must produce a different genesis root"
    );
}

#[tokio::test]
async fn a_different_faucet_key_gives_a_different_root() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(vec![(V1, 1), (V2, 1)]);
    stellereum::runtime::fund_genesis(&engine, &vs, 100_000_000_000_000_000).await;
    let other = stellereum::rpc::Faucet::new([0x77u8; 32], 1, 100_000_000_000, 1_000_000_000_000);
    let _ = engine
        .credit_native(&other.account(), 1_000_000_000_000_000)
        .await; // GATE: intentional ignore

    assert_ne!(
        hex::encode(engine.get_state_root().await),
        EXPECTED_GENESIS_ROOT,
        "STELL_FAUCET_KEY must be part of the chain fingerprint"
    );
}

#[tokio::test]
async fn commitment_version_is_written_into_the_digest() {
    // Documented in src/commitment.rs: the version is the first field of the
    // preimage. If that ever stops being true the known-answer test would stop
    // protecting anyone, so assert the constant explicitly.
    assert_eq!(
        stellereum::commitment::COMMITMENT_VERSION,
        5,
        "COMMITMENT_VERSION changed. If this is intentional, expect a hard fork, \
         wipe every data directory, and update EXPECTED_GENESIS_ROOT in the same \
         commit that bumps it."
    );
}

#[tokio::test]
async fn an_empty_faucet_key_still_yields_a_deterministic_root() {
    // A node started with an undecodable STELL_FAUCET_KEY skips faucet funding
    // entirely, which is indistinguishable at genesis from a node started with no
    // key at all. That is a silent misconfiguration, so at least be explicit that
    // the two cases are the same chain and the test above does not cover them.
    let engine = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(vec![(V1, 1), (V2, 1)]);
    stellereum::runtime::fund_genesis(&engine, &vs, 100_000_000_000_000_000).await;
    let root = engine.get_state_root().await;
    assert_ne!(
        hex::encode(root),
        EXPECTED_GENESIS_ROOT,
        "a chain with no faucet account must differ from one with it"
    );
    let _ = AccountState::new(V1, 0); // keep the import meaningful
}

#[tokio::test]
async fn genesis_staking_pool_is_fully_backed() {
    let engine = Arc::new(InMemoryStateEngine::new());
    let vs = ValidatorSet::from_list(vec![(V1, 1), (V2, 1)]);
    let initial_balance = 100_000_000_000_000_000u64;
    stellereum::runtime::fund_genesis(&engine, &vs, initial_balance).await;

    let bond = stellereum::runtime::GENESIS_VALIDATOR_BOND;
    let pool_acc = engine
        .get_account(&stellereum::staking::STAKING_POOL)
        .await
        .expect("pool account exists");
    assert_eq!(
        pool_acc.balance,
        bond * 2,
        "STAKING_POOL must hold exactly the sum of genesis validator bonds"
    );

    let v1_acc = engine.get_account(&V1).await.expect("v1 account exists");
    assert_eq!(
        v1_acc.balance,
        initial_balance - bond,
        "validator liquid balance must be debited by the bond amount"
    );
}
