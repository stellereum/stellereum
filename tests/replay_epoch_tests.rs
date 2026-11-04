//! Replay-domain hardening differentials: chain-id BINDING + epoch/nonce pin.
//!
//! # What was enforceable without a wire change (chain-id equality)
//!
//! The transparent [`Transaction`](stellereum::sharding::Transaction) envelope
//! already CARRIES an optional chain id (`chain_id()` covers the CH1 trailer,
//! session grants, PQ chain binding, sponsor grants and EVM settlement), but
//! mempool admission only bound its PRESENCE — and only once the
//! `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` rollout gate armed
//! ([`check_admission`](stellereum::chain_binding::check_admission)). A
//! foreign-bound envelope (signed for another network) with a valid signature
//! therefore pooled on this chain and was only skipped later: the consensus
//! apply path
//! (`verify_transaction_envelope_at_height_with_activation`) and the
//! state-engine apply path both refuse a mismatched chain id at EVERY height.
//! [`check_chain_id_match`](stellereum::chain_binding::check_chain_id_match)
//! plus the mempool `insert` call site close that gap (refuse-at-admission
//! instead of admit-then-skip).
//!
//! The differentials below pin it.
//!
//! # What is blocked and why (epoch on the transparent path)
//!
//! The transparent `Transaction` struct has NO epoch field — only
//! `{from, to, amount, gas_limit, nonce, shards, signature, payload,
//! priority_fee_per_gas}` — and the wire format is frozen (AGENTS.md §7), so
//! epoch binding CANNOT be added to this envelope without a wire change.
//! Same-chain cross-epoch replay on the transparent path therefore still
//! rests on nonces alone: the state-engine apply gate refuses
//! `tx.nonce != sender.nonce` as `"Invalid nonce: ... (possible replay
//! attack)"`, the mempool sweep (`evict_unexecutable_at`) evicts consumed
//! nonces as stale once the on-chain head advances, and a byte-identical
//! resubmission is `Duplicate` while pooled. The tests below pin each of
//! those three so the residual is fenced, not assumed.
//!
//! The SEALED path is the contrast: [`SealedEnvelope`](stellereum::mev_epoch::SealedEnvelope)
//! carries `epoch`, `add_sealed` refuses envelopes for another epoch, and
//! the epoch key rotates — that path already binds epoch cryptographically
//! and is NOT re-tested here (see the mempool sealed-epoch gate).

use stellereum::chain_binding::CHAIN_ID_MISMATCH_ERR_PREFIX;
use stellereum::consensus::consensus_chain_id;
use stellereum::mempool::{Mempool, MempoolError};
use stellereum::sharding::Transaction;
use stellereum::state_engine::{AccountState, InMemoryStateEngine};
use stellereum::wallet::WalletAccount;

const FUNDING: u64 = 100_000_000;
const RECIPIENT: [u8; 32] = [0x99u8; 32];

fn wallet(seed: u8) -> WalletAccount {
    WalletAccount::from_seed(&[seed; 32])
}

/// OUR chain id: whatever this node froze (default 5757). Read dynamically
/// so the tests hold under any `STELL_CHAIN_ID` deployment value.
fn ours() -> u64 {
    consensus_chain_id()
}

/// A chain id that is guaranteed to differ from ours (no special meaning —
/// any foreign network id exercises the same predicate).
fn foreign() -> u64 {
    ours().wrapping_add(1)
}

fn own_fixture(seed: u8, nonce: u64) -> Transaction {
    let tx = wallet(seed).create_bound_transaction(RECIPIENT, 1_000, nonce, 0, 0, ours());
    assert_eq!(tx.chain_id(), Some(ours()), "own fixture must bind OUR chain");
    tx
}

fn foreign_fixture(seed: u8, nonce: u64) -> Transaction {
    let tx = wallet(seed).create_bound_transaction(RECIPIENT, 1_000, nonce, 0, 0, foreign());
    assert_eq!(
        tx.chain_id(),
        Some(foreign()),
        "foreign fixture must bind the OTHER chain"
    );
    tx
}

fn legacy_fixture(seed: u8, nonce: u64) -> Transaction {
    let tx = wallet(seed).unbound_legacy_transfer(RECIPIENT, 1_000, nonce, 0, 0);
    assert_eq!(tx.chain_id(), None, "legacy fixture must stay unbound");
    tx
}

// ============================================================================
// (a) Chain-id BINDING differential at mempool admission
// ============================================================================

/// Same pool, same funding, same nonce shape: the own-chain envelope admits,
/// the foreign-chain envelope — cryptographically VALID for its own network
/// — is refused with the pinned mismatch string and pools nothing.
#[test]
fn foreign_chain_id_refused_own_accepted_at_mempool_insert() {
    let mut mp = Mempool::new(100, 100);

    // Own-chain control first: admits (proves the pool/funding shape is good).
    let own = own_fixture(0xA1, 0);
    assert!(
        own.verify_signature(),
        "own-chain fixture must be signature-valid"
    );
    mp.add_checked(own, u64::MAX)
        .expect("own-chain envelope must admit");
    assert_eq!(mp.len(), 1);

    // Foreign differential: valid signature, wrong network → refused.
    let alien = foreign_fixture(0xA2, 0);
    assert!(
        alien.verify_signature(),
        "foreign fixture must be signature-valid on its own network \
         (otherwise the refusal would prove nothing about binding)"
    );
    let err = mp
        .add_checked(alien, u64::MAX)
        .expect_err("foreign-chain envelope must be refused at admission");
    match err {
        MempoolError::ChainIdMismatch(msg) => assert!(
            msg.starts_with(CHAIN_ID_MISMATCH_ERR_PREFIX),
            "mismatch refusal must carry the pinned prefix, got: {msg}"
        ),
        other => panic!("wrong refusal variant for a foreign chain id: {other}"),
    }
    assert_eq!(mp.len(), 1, "a refused replay must never pool");
}

/// The mismatch string names BOTH chains so the signer can see which network
/// the transaction was (mis-)bound to.
#[test]
fn chain_id_mismatch_names_both_chains() {
    let mut mp = Mempool::new(100, 100);
    let err = mp
        .add_checked(foreign_fixture(0xA3, 0), u64::MAX)
        .expect_err("foreign-chain envelope must be refused");
    let msg = err.to_string();
    assert!(
        msg.starts_with(CHAIN_ID_MISMATCH_ERR_PREFIX),
        "Display must carry the pinned prefix, got: {msg}"
    );
    assert!(
        msg.contains(&foreign().to_string()),
        "refusal must name the envelope chain, got: {msg}"
    );
    assert!(
        msg.contains(&ours().to_string()),
        "refusal must name our chain, got: {msg}"
    );
}

/// An envelope WITHOUT a chain id keeps the legacy nonce-only path:
/// admitted, unchanged, at admission (presence is the separate,
/// activation-gated rule — this predicate has nothing to compare).
#[test]
fn envelope_without_chain_id_keeps_legacy_nonce_only_path() {
    let mut mp = Mempool::new(100, 100);
    mp.add_checked(legacy_fixture(0xA4, 0), u64::MAX)
        .expect("unbound envelope must keep admitting (legacy nonce-only path)");
    assert_eq!(mp.len(), 1);
}

// ============================================================================
// (b) Epoch residual pin: no epoch field ⇒ nonces carry cross-epoch replay
// ============================================================================

/// The transparent envelope genuinely cannot carry epoch (compile-time proof
/// by construction: fixtures built through the public wallet constructors
/// expose `nonce` but no epoch setter — there is no field to set), so this
/// pins the three nonce-based fences that cover the residual instead:
///
/// 1. byte-identical resubmission while pooled → `Duplicate`;
/// 2. after the on-chain head advances past the nonce (the tx executed in an
///    earlier epoch), the sweep evicts it as stale — it cannot ride the pool
///    across epochs;
/// 3. re-applying the same bytes — or ANY tx reusing the consumed nonce —
///    at a later height fails the apply-time `Invalid nonce ... (possible
///    replay attack)` gate with no state effect.
#[test]
fn byte_identical_replay_is_duplicate_while_pooled() {
    let mut mp = Mempool::new(100, 100);
    let tx = legacy_fixture(0xB1, 0);
    mp.add_checked(tx.clone(), u64::MAX)
        .expect("first admission must succeed");
    let err = mp
        .add_checked(tx, u64::MAX)
        .expect_err("byte-identical replay must be refused while pooled");
    assert_eq!(err, MempoolError::Duplicate);
}

#[test]
fn consumed_nonce_is_swept_stale_once_the_head_advances() {
    let mut mp = Mempool::new(100, 100);
    let tx = legacy_fixture(0xB2, 0);
    let from = tx.from;
    mp.add_checked(tx, u64::MAX)
        .expect("first admission must succeed");
    assert_eq!(mp.len(), 1);

    // The transaction executes in epoch E: the on-chain nonce advances to 1.
    // The sweep (run with the new head) must evict it as stale — the pool
    // cannot carry a consumed nonce into a later epoch.
    let evicted = mp.evict_unexecutable_at(1_000_000, |addr| {
        if addr == &from {
            Some((1, u64::MAX))
        } else {
            None
        }
    });
    assert_eq!(evicted, 1, "consumed nonce must sweep as stale");
    assert!(mp.is_empty());
}

/// Same nonce presented at a LATER height — byte-identical AND rebuilt —
/// fails the apply-time replay gate; the residual "same-chain cross-epoch
/// replay rests on nonces alone" holds because the nonce is consumed by the
/// first execution and never reusable.
#[tokio::test]
async fn same_nonce_refused_at_later_height_after_first_execution() {
    let engine = InMemoryStateEngine::new().with_chain_id(ours());
    let tx = legacy_fixture(0xB3, 0);
    let from = tx.from;
    engine
        .update_account(AccountState::new(from, FUNDING))
        .await;

    // Epoch E: applies, nonce 0 → 1.
    engine
        .apply_transaction_at_height(&tx, 0, 1)
        .await
        .expect("first execution must apply");
    let acct = engine.get_account(&from).await.expect("sender exists");
    assert_eq!(acct.nonce, 1, "an applied tx consumes its nonce");

    // Epoch E+k: byte-identical replay refused as already-used.
    let balance_after = acct.balance;
    let err = engine
        .apply_transaction_at_height(&tx, 0, 1_000)
        .await
        .expect_err("cross-epoch replay of the same bytes must be refused");
    assert!(
        err.contains("Invalid nonce") && err.contains("possible replay attack"),
        "replay refusal must be the nonce gate, got: {err}"
    );
    let acct = engine.get_account(&from).await.expect("sender exists");
    assert_eq!(acct.nonce, 1, "a refused replay consumes no further nonce");
    assert_eq!(
        acct.balance, balance_after,
        "a refused replay moves no funds"
    );

    // Same consumed nonce with FRESH bytes (a separately signed transfer for
    // a different amount ⇒ different hash, valid signature) is equally
    // refused: it is the NONCE that is spent, not the hash.
    let rebuilt = wallet(0xB3).unbound_legacy_transfer(RECIPIENT, 2_000, 0, 0, 0);
    assert!(
        rebuilt.verify_signature(),
        "rebuilt tx must be signature-valid (otherwise the refusal proves nothing)"
    );
    let err = engine
        .apply_transaction_at_height(&rebuilt, 0, 2_000)
        .await
        .expect_err("any reuse of a consumed nonce must be refused");
    assert!(
        err.contains("Invalid nonce"),
        "rebuilt-nonce refusal must be the nonce gate, got: {err}"
    );
}
